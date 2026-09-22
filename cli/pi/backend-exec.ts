import { basename, dirname, posix, relative, resolve, sep } from "node:path";
import {
  createLocalBashOperations,
  type BashOperations,
  type EditOperations,
  type FindOperations,
  type LsOperations,
  type ReadOperations,
  type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import { minimatch } from "minimatch";
import { createExecutionBackend, type ExecutionBackendDependencies } from "./backends/index.js";
import { buildDockerRunArgs, resolveDockerIdentity } from "./backends/docker.js";
import {
  getComputeBackendConfigurationIssues,
  getComputeBackendLabel,
  resolveComputeBackend,
  resolveComputeDefaults,
  resolveDockerImage,
  resolveDockerWorkspacePath,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
  type ComputeBackendKind,
} from "./compute.js";
import { registerComputeSession } from "./compute-sessions.js";
import {
  assertExhaustive,
  createRedactingSink,
  createSessionId,
  ExecutionBackendError,
  type ExecutionBackend,
} from "./execution-backend.js";
import { assertParallelsSourceIsUsable } from "./parallels-sandbox.js";
import {
  createSandboxEditOperations,
  createSandboxLsOperations,
  createSandboxReadOperations,
  createSandboxWriteOperations,
  loadSandboxConfig,
} from "./sandbox.js";
import { joinBashArgs, quoteForBash } from "./shell.js";
import type { GrclankerSettings } from "./settings.js";

type StreamExecOptions = {
  onData: (chunk: Buffer) => void;
  signal?: AbortSignal;
  timeout?: number;
};

export type ComputeBackendGrepMatch = {
  filePath: string;
  lineNumber: number;
};

export type ComputeBackendGrepSearch = {
  pattern: string;
  searchPath: string;
  glob?: string;
  ignoreCase?: boolean;
  literal?: boolean;
  limit: number;
};

export type ComputeBackendGrepSearchResult = {
  isDirectory: boolean;
  matches: ComputeBackendGrepMatch[];
  matchLimitReached: boolean;
};

export type ComputeBackendGrepOperations = {
  searchMatches: (
    query: ComputeBackendGrepSearch,
  ) => Promise<ComputeBackendGrepSearchResult>;
};

export type ResolvedComputeBackendExecution = {
  kind: ComputeBackendKind;
  label: string;
  summary: string;
  sessionId: string;
  backend?: ExecutionBackend;
  teardown: () => Promise<void>;
  bashOperations: BashOperations;
  readOperations?: ReadOperations;
  writeOperations?: WriteOperations;
  editOperations?: EditOperations;
  lsOperations?: LsOperations;
  findOperations?: FindOperations;
  grepOperations?: ComputeBackendGrepOperations;
};

type BackendCommandAdapter = {
  sessionId: string;
  stream: (
    command: string,
    cwd: string,
    options: StreamExecOptions,
  ) => Promise<{ exitCode: number | null }>;
  capture: (command: string, cwd: string) => Promise<Buffer>;
  mapPath: (absolutePath: string) => Promise<string>;
  teardown: () => Promise<void>;
};

function formatBackendError(message: string): Error {
  return new ExecutionBackendError(message);
}

function ensureWorkspaceMapping(localRoot: string, cwd: string, remoteRoot: string): string {
  const root = resolve(localRoot);
  const target = resolve(cwd);
  const rel = relative(root, target);
  if (rel.startsWith("..") || rel.includes(`..${sep}`)) {
    throw formatBackendError(
      `The backend can only execute within the session root ${root}. Received cwd ${target}.`,
    );
  }

  const remoteSegments = rel
    .split(sep)
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (remoteSegments.length === 0) return remoteRoot;

  return remoteSegments.reduce((current, segment) => posix.join(current, segment), remoteRoot);
}

function buildWriteFileCommand(remotePath: string, content: string): string {
  const encoded = Buffer.from(content, "utf8").toString("base64");
  return [
    `if printf '' | base64 --decode >/dev/null 2>&1; then`,
    `  printf '%s' ${quoteForBash(encoded)} | base64 --decode > ${quoteForBash(remotePath)}`,
    "else",
    `  printf '%s' ${quoteForBash(encoded)} | base64 -D > ${quoteForBash(remotePath)}`,
    "fi",
  ].join("\n");
}

function normalizeSearchOutputLine(line: string): string | undefined {
  const trimmed = line.replace(/\r$/, "").trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed === ".") return undefined;
  return trimmed.startsWith("./") ? trimmed.slice(2) : trimmed;
}

function matchesPattern(relativePath: string, pattern: string): boolean {
  return minimatch(relativePath, pattern, { dot: true, matchBase: true });
}

function isIgnoredPath(relativePath: string, ignorePatterns: string[]): boolean {
  return ignorePatterns.some((pattern) =>
    minimatch(relativePath, pattern, { dot: true, matchBase: true }),
  );
}

function buildBackendFindCommand(pattern: string): string {
  return [
    "if command -v rg >/dev/null 2>&1; then",
    `  rg --files --hidden -g '!**/.git/**' -g '!**/node_modules/**' -g ${quoteForBash(pattern)} .`,
    "  status=$?",
    "else",
    "  find . \\( -name .git -o -name node_modules \\) -prune -o -type f -print",
    "  status=$?",
    "fi",
    "if [ \"$status\" -eq 0 ] || [ \"$status\" -eq 1 ]; then exit 0; fi",
    "exit \"$status\"",
  ].join("\n");
}

function buildRipgrepJsonCommand({
  pattern,
  target,
  glob,
  ignoreCase,
  literal,
}: {
  pattern: string;
  target: string;
  glob?: string;
  ignoreCase?: boolean;
  literal?: boolean;
}): string {
  const args = ["--json", "--line-number", "--color=never", "--hidden"];
  if (ignoreCase) args.push("--ignore-case");
  if (literal) args.push("--fixed-strings");
  if (glob) args.push("--glob", glob);
  args.push(pattern, target);

  return [
    `rg ${joinBashArgs(args)}`,
    "status=$?",
    "if [ \"$status\" -eq 0 ] || [ \"$status\" -eq 1 ]; then exit 0; fi",
    "exit \"$status\"",
  ].join("\n");
}

function buildPosixGrepCommand({
  pattern,
  target,
  isDirectory,
  glob,
  ignoreCase,
  literal,
}: {
  pattern: string;
  target: string;
  isDirectory: boolean;
  glob?: string;
  ignoreCase?: boolean;
  literal?: boolean;
}): string {
  const args = ["-n", "-H", "-I", "--binary-files=without-match"];
  if (isDirectory) args.unshift("-R");
  if (ignoreCase) args.push("-i");
  if (literal) args.push("-F");
  if (isDirectory) {
    args.push("--exclude-dir=.git", "--exclude-dir=node_modules");
    if (glob) args.push(`--include=${glob}`);
  }
  args.push("--", pattern, target);

  return [
    `grep ${joinBashArgs(args)}`,
    "status=$?",
    "if [ \"$status\" -eq 0 ] || [ \"$status\" -eq 1 ]; then exit 0; fi",
    "exit \"$status\"",
  ].join("\n");
}

function parseRipgrepJsonMatches(
  output: string,
  workingDir: string,
  searchPath: string,
  isDirectory: boolean,
  glob: string | undefined,
  limit: number,
): ComputeBackendGrepSearchResult {
  const matches: ComputeBackendGrepMatch[] = [];
  let matchLimitReached = false;

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    let event: Record<string, unknown>;
    try {
      event = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      continue;
    }

    if (event.type !== "match") continue;

    const data = event.data as {
      path?: { text?: string };
      line_number?: number;
    } | undefined;
    const rawPath = data?.path?.text;
    const lineNumber = data?.line_number;
    if (typeof rawPath !== "string" || typeof lineNumber !== "number") continue;

    const relativePath = normalizeSearchOutputLine(rawPath) ?? rawPath;
    const absolutePath = resolve(workingDir, relativePath);
    const globPath = isDirectory
      ? relative(searchPath, absolutePath).split(sep).join("/")
      : basename(absolutePath);
    if (glob && !matchesPattern(globPath, glob)) continue;

    matches.push({ filePath: absolutePath, lineNumber });
    if (matches.length > limit) {
      matchLimitReached = true;
      break;
    }
  }

  return {
    isDirectory,
    matches: matches.slice(0, limit),
    matchLimitReached,
  };
}

function parsePosixGrepMatches(
  output: string,
  workingDir: string,
  searchPath: string,
  isDirectory: boolean,
  glob: string | undefined,
  limit: number,
): ComputeBackendGrepSearchResult {
  const matches: ComputeBackendGrepMatch[] = [];
  let matchLimitReached = false;

  for (const line of output.split("\n")) {
    const trimmed = line.replace(/\r$/, "");
    if (trimmed.length === 0) continue;

    const match = /^(.*?):([0-9]+):/.exec(trimmed);
    if (!match) continue;

    const [, rawPath, lineNumberText] = match;
    const normalizedPath = normalizeSearchOutputLine(rawPath) ?? rawPath;
    const absolutePath = resolve(workingDir, normalizedPath);
    const lineNumber = Number.parseInt(lineNumberText, 10);
    if (!Number.isFinite(lineNumber) || lineNumber <= 0) continue;

    const globPath = isDirectory
      ? relative(searchPath, absolutePath).split(sep).join("/")
      : basename(absolutePath);
    if (glob && !matchesPattern(globPath, glob)) continue;

    matches.push({ filePath: absolutePath, lineNumber });
    if (matches.length > limit) {
      matchLimitReached = true;
      break;
    }
  }

  return {
    isDirectory,
    matches: matches.slice(0, limit),
    matchLimitReached,
  };
}

function createBackendReadOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): ReadOperations {
  return {
    readFile: async (absolutePath) =>
      adapter.capture(`cat -- ${quoteForBash(await adapter.mapPath(absolutePath))}`, localCwd),
    access: async (absolutePath) => {
      await adapter.capture(`test -r ${quoteForBash(await adapter.mapPath(absolutePath))}`, localCwd);
    },
    detectImageMimeType: async (absolutePath) => {
      try {
        const remotePath = await adapter.mapPath(absolutePath);
        const result = await adapter.capture(
          `file --mime-type -b -- ${quoteForBash(remotePath)}`,
          localCwd,
        );
        const mimeType = result.toString("utf8").trim();
        return ["image/jpeg", "image/png", "image/gif", "image/webp"].includes(mimeType)
          ? mimeType
          : null;
      } catch {
        return null;
      }
    },
  };
}

function createBackendWriteOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): WriteOperations {
  return {
    writeFile: async (absolutePath, content) => {
      await adapter.capture(
        buildWriteFileCommand(await adapter.mapPath(absolutePath), content),
        localCwd,
      );
    },
    mkdir: async (absolutePath) => {
      await adapter.capture(`mkdir -p -- ${quoteForBash(await adapter.mapPath(absolutePath))}`, localCwd);
    },
  };
}

function createBackendEditOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): EditOperations {
  const readOps = createBackendReadOperations(localCwd, adapter);
  const writeOps = createBackendWriteOperations(localCwd, adapter);

  return {
    readFile: readOps.readFile,
    writeFile: writeOps.writeFile,
    access: async (absolutePath) => {
      const remotePath = await adapter.mapPath(absolutePath);
      await adapter.capture(
        `test -r ${quoteForBash(remotePath)} && test -w ${quoteForBash(remotePath)}`,
        localCwd,
      );
    },
  };
}

function createBackendLsOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): LsOperations {
  return {
    exists: async (absolutePath) => {
      try {
        await adapter.capture(`test -e ${quoteForBash(await adapter.mapPath(absolutePath))}`, localCwd);
        return true;
      } catch {
        return false;
      }
    },
    stat: async (absolutePath) => {
      const remotePath = await adapter.mapPath(absolutePath);
      const output = await adapter.capture(
        `if test -d ${quoteForBash(remotePath)}; then printf dir; else printf file; fi`,
        localCwd,
      );
      const kind = output.toString("utf8").trim();
      return {
        isDirectory: () => kind === "dir",
      };
    },
    readdir: async (absolutePath) => {
      const output = await adapter.capture(
        `ls -1A -- ${quoteForBash(await adapter.mapPath(absolutePath))}`,
        localCwd,
      );
      const text = output.toString("utf8").trim();
      return text.length > 0 ? text.split("\n") : [];
    },
  };
}

function createBackendFindOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): FindOperations {
  return {
    exists: async (absolutePath) => {
      try {
        await adapter.capture(`test -e ${quoteForBash(await adapter.mapPath(absolutePath))}`, localCwd);
        return true;
      } catch {
        return false;
      }
    },
    glob: async (pattern, searchPath, options) => {
      await adapter.capture(`test -d ${quoteForBash(await adapter.mapPath(searchPath))}`, localCwd);
      const output = await adapter.capture(buildBackendFindCommand(pattern), searchPath);
      const lines = output
        .toString("utf8")
        .split("\n")
        .map((line) => normalizeSearchOutputLine(line))
        .filter((line): line is string => typeof line === "string");

      const results: string[] = [];
      for (const line of lines) {
        const relativePath = line.split(sep).join("/");
        if (isIgnoredPath(relativePath, options.ignore)) continue;
        if (!matchesPattern(relativePath, pattern)) continue;
        results.push(resolve(searchPath, relativePath));
        if (results.length >= options.limit) break;
      }

      return results;
    },
  };
}

async function backendHasRipgrep(adapter: BackendCommandAdapter, cwd: string): Promise<boolean> {
  const output = await adapter.capture(
    "if command -v rg >/dev/null 2>&1; then printf yes; else printf no; fi",
    cwd,
  );
  return output.toString("utf8").trim() === "yes";
}

function createBackendGrepOperations(
  localCwd: string,
  adapter: BackendCommandAdapter,
): ComputeBackendGrepOperations {
  return {
    async searchMatches({
      pattern,
      searchPath,
      glob,
      ignoreCase,
      literal,
      limit,
    }: ComputeBackendGrepSearch): Promise<ComputeBackendGrepSearchResult> {
      const remoteSearchPath = await adapter.mapPath(searchPath);
      const kind = await adapter.capture(
        `if test -d ${quoteForBash(remoteSearchPath)}; then printf dir; elif test -e ${quoteForBash(remoteSearchPath)}; then printf file; else printf missing; fi`,
        localCwd,
      );
      const resolvedKind = kind.toString("utf8").trim();
      if (resolvedKind === "missing") {
        throw formatBackendError(`Path not found: ${searchPath}`);
      }

      const isDirectory = resolvedKind === "dir";
      const workingDir = isDirectory ? searchPath : dirname(searchPath);
      const target = isDirectory ? "." : basename(searchPath);
      const useRipgrep = await backendHasRipgrep(adapter, workingDir);
      const command = useRipgrep
        ? buildRipgrepJsonCommand({ pattern, target, glob, ignoreCase, literal })
        : buildPosixGrepCommand({ pattern, target, isDirectory, glob, ignoreCase, literal });
      const output = await adapter.capture(command, workingDir);
      const text = output.toString("utf8");

      return useRipgrep
        ? parseRipgrepJsonMatches(text, workingDir, searchPath, isDirectory, glob, limit)
        : parsePosixGrepMatches(text, workingDir, searchPath, isDirectory, glob, limit);
    },
  };
}

export function buildDockerToolRunArgs(
  localCwd: string,
  settings: GrclankerSettings,
  cwd: string,
  command: string,
): string[] {
  const workspaceRoot = resolveDockerWorkspacePath(settings);
  const defaults = resolveComputeDefaults(settings);
  return buildDockerRunArgs({
    image: resolveDockerImage(settings),
    hostWorkspace: resolve(localCwd),
    workspaceRoot,
    workdir: ensureWorkspaceMapping(localCwd, cwd, workspaceRoot),
    command,
    mountMode: defaults.workspaceMountMode,
    networkPolicy: defaults.networkPolicy,
    identity: resolveDockerIdentity(),
  });
}

type ContractAdapterOptions = {
  preflight?: () => void;
  unavailableMessage?: string;
};

function createContractCommandAdapter(
  localCwd: string,
  backend: ExecutionBackend,
  adapterOptions: ContractAdapterOptions = {},
): BackendCommandAdapter {
  const sessionId = createSessionId();
  let stagedPromise: Promise<string> | undefined;
  let unregister: (() => void) | undefined;

  const teardown = async (): Promise<void> => {
    const pending = stagedPromise;
    stagedPromise = undefined;
    unregister?.();
    unregister = undefined;
    if (!pending) return;
    try {
      await pending;
    } catch {
      return;
    }
    await backend.teardown(sessionId);
  };

  const stage = async (): Promise<string> => {
    adapterOptions.preflight?.();
    try {
      await backend.healthcheck();
    } catch (error) {
      if (adapterOptions.unavailableMessage) throw formatBackendError(adapterOptions.unavailableMessage);
      throw error;
    }
    const staged = await backend.stageWorkspace({ localPath: localCwd, sessionId });
    return staged.remotePath;
  };

  const ensureStaged = (): Promise<string> => {
    if (!stagedPromise) {
      unregister = registerComputeSession({
        teardown,
        teardownSync: () => backend.teardownSync?.(sessionId),
      });
      stagedPromise = stage().catch((error: unknown) => {
        stagedPromise = undefined;
        unregister?.();
        unregister = undefined;
        throw error;
      });
    }
    return stagedPromise;
  };

  return {
    sessionId,
    teardown,
    mapPath: async (absolutePath) => ensureWorkspaceMapping(localCwd, absolutePath, await ensureStaged()),
    async stream(command, cwd, options) {
      const remoteRoot = await ensureStaged();
      const result = await backend.exec({
        sessionId,
        command: [command],
        cwd: ensureWorkspaceMapping(localCwd, cwd, remoteRoot),
        timeoutMs: options.timeout ? options.timeout * 1000 : undefined,
        onData: options.onData,
        signal: options.signal,
      });
      return { exitCode: result.exitCode };
    },
    async capture(command, cwd) {
      const remoteRoot = await ensureStaged();
      // File operations round-trip content through capture (read, then edit or write back),
      // so the raw bytes are kept here and only the failure text is scrubbed.
      const result = await backend.exec({
        sessionId,
        command: [command],
        cwd: ensureWorkspaceMapping(localCwd, cwd, remoteRoot),
        redactOutput: false,
      });
      if (result.exitCode !== 0) {
        throw new ExecutionBackendError(result.stderr.trim() || `Command failed (${result.exitCode}) on ${backend.kind}`);
      }
      return Buffer.from(result.stdout, "utf8");
    },
  };
}

function buildFullToolSurface(
  kind: ComputeBackendKind,
  label: string,
  summary: string,
  localCwd: string,
  adapter: BackendCommandAdapter,
  backend: ExecutionBackend,
): ResolvedComputeBackendExecution {
  return {
    kind,
    label,
    summary,
    sessionId: adapter.sessionId,
    backend,
    teardown: adapter.teardown,
    bashOperations: { exec: adapter.stream },
    readOperations: createBackendReadOperations(localCwd, adapter),
    writeOperations: createBackendWriteOperations(localCwd, adapter),
    editOperations: createBackendEditOperations(localCwd, adapter),
    lsOperations: createBackendLsOperations(localCwd, adapter),
    findOperations: createBackendFindOperations(localCwd, adapter),
    grepOperations: createBackendGrepOperations(localCwd, adapter),
  };
}

function describeRemoteSummary(kind: ComputeBackendKind): string {
  switch (kind) {
    case "modal":
      return "bash, read, write, edit, ls, grep, and find run one-shot inside a Modal container via `modal shell`; the repo is copied in per command and changes are not synced back";
    case "runpod-pod":
      return "bash, read, write, edit, ls, grep, and find run over SSH inside the configured RunPod pod after the repo is copied to a per-session directory";
    case "runpod-serverless":
      return "bash, read, write, edit, ls, grep, and find are dispatched as jobs to the configured RunPod serverless endpoint running the grclanker worker contract";
    case "cloudflare-sandbox":
    case "vercel-sandbox":
      return `${kind} is selected, but the adapter is a stub that fails fast; pick another backend`;
    case "host":
    case "sandbox-runtime":
    case "docker":
    case "parallels-vm":
      return `${kind} is a local backend`;
    default:
      return assertExhaustive(kind);
  }
}

function createRedactingBashOperations(operations: BashOperations): BashOperations {
  return {
    async exec(command, cwd, options) {
      const sink = createRedactingSink(options.onData);
      try {
        return await operations.exec(command, cwd, { ...options, onData: sink.write });
      } finally {
        sink.end();
      }
    },
  };
}

function describeParallelsSummary(settings: GrclankerSettings): string {
  const sourceKind = resolveParallelsSourceKind(settings);
  const templateName = resolveParallelsTemplateName(settings);
  const baseVmName = resolveParallelsBaseVmName(settings);
  const workspaceOverride = resolveParallelsWorkspacePath(settings);
  const clonePrefix = resolveParallelsClonePrefix(settings);
  return (sourceKind === "template" ? templateName : baseVmName)
    ? [
        `bash, read, write, edit, ls, grep, and find run inside a disposable Parallels sandbox deployed from ${
          sourceKind === "template"
            ? `template ${templateName}`
            : `stopped base VM ${baseVmName}`
        }`,
        `clone prefix ${clonePrefix}`,
        workspaceOverride
          ? `guest workspace override ${workspaceOverride}`
          : "guest workspace path auto-detected from the attached repo share",
      ].join("; ")
    : "bash is configured to run through a disposable Parallels sandbox, but template/base source settings are incomplete";
}

export function resolveComputeBackendExecution(
  localCwd: string,
  settings: GrclankerSettings,
  deps: ExecutionBackendDependencies = {},
): ResolvedComputeBackendExecution {
  const kind = resolveComputeBackend(settings);
  const label = getComputeBackendLabel(kind);

  switch (kind) {
    case "host":
      return {
        kind,
        label,
        summary: "bash runs directly on the local host shell",
        sessionId: createSessionId(),
        teardown: async () => undefined,
        bashOperations: createRedactingBashOperations(createLocalBashOperations()),
      };
    case "sandbox-runtime": {
      const sandboxConfig = loadSandboxConfig(localCwd);
      const backend = createExecutionBackend(localCwd, settings, deps, kind);
      const adapter = createContractCommandAdapter(localCwd, backend);
      return {
        kind,
        label,
        summary: sandboxConfig.enabled === false
          ? "sandbox-runtime is selected, but sandboxing is disabled by config and commands run on the host"
          : "bash, grep, and find run through sandbox-runtime and file tools enforce the same filesystem policy locally",
        sessionId: adapter.sessionId,
        backend,
        teardown: adapter.teardown,
        bashOperations: { exec: adapter.stream },
        readOperations: createSandboxReadOperations(localCwd),
        writeOperations: createSandboxWriteOperations(localCwd),
        editOperations: createSandboxEditOperations(localCwd),
        lsOperations: createSandboxLsOperations(localCwd),
        findOperations: createBackendFindOperations(localCwd, adapter),
        grepOperations: createBackendGrepOperations(localCwd, adapter),
      };
    }
    case "docker": {
      const backend = createExecutionBackend(localCwd, settings, deps, kind);
      const adapter = createContractCommandAdapter(localCwd, backend, {
        unavailableMessage: "Docker is selected, but the Docker daemon is not reachable. Run `grclanker env doctor` for details.",
      });
      return buildFullToolSurface(
        kind,
        label,
        `bash, read, write, edit, ls, grep, and find run in Docker image ${resolveDockerImage(settings)} with the host repo mounted at ${resolveDockerWorkspacePath(settings)}`,
        localCwd,
        adapter,
        backend,
      );
    }
    case "parallels-vm": {
      const backend = createExecutionBackend(localCwd, settings, deps, kind);
      const adapter = createContractCommandAdapter(localCwd, backend, {
        preflight: () => {
          assertParallelsSourceIsUsable(settings);
        },
        unavailableMessage: "Parallels VM is selected, but `prlctl` is not available on this host. Run `grclanker env doctor` for details.",
      });
      return buildFullToolSurface(kind, label, describeParallelsSummary(settings), localCwd, adapter, backend);
    }
    case "modal":
    case "runpod-pod":
    case "runpod-serverless":
    case "cloudflare-sandbox":
    case "vercel-sandbox": {
      const backend = createExecutionBackend(localCwd, settings, deps, kind);
      const adapter = createContractCommandAdapter(localCwd, backend);
      return buildFullToolSurface(kind, label, describeRemoteSummary(kind), localCwd, adapter, backend);
    }
    default:
      return assertExhaustive(kind);
  }
}

export async function withComputeBackendExecution<T>(
  localCwd: string,
  settings: GrclankerSettings,
  run: (execution: ResolvedComputeBackendExecution) => Promise<T>,
  deps: ExecutionBackendDependencies = {},
): Promise<T> {
  const execution = resolveComputeBackendExecution(localCwd, settings, deps);
  try {
    return await run(execution);
  } finally {
    await execution.teardown();
  }
}

export function buildComputeBackendSystemPromptNote(
  localCwd: string,
  settings: GrclankerSettings,
): string {
  const execution = resolveComputeBackendExecution(localCwd, settings);
  const issues = getComputeBackendConfigurationIssues(settings, execution.kind);
  const lines = [
    "Execution backend notes:",
    `- Preferred compute backend: ${execution.label} (${execution.kind}).`,
    `- ${execution.summary}.`,
    execution.readOperations && execution.findOperations && execution.grepOperations
      ? "- Bash, read, write, edit, ls, grep, and find are routed through the compute backend."
      : execution.findOperations && execution.grepOperations
        ? "- Bash, grep, and find are routed through the compute backend. Read, write, edit, and ls still use host-local tools."
        : execution.readOperations
          ? "- Bash, read, write, edit, and ls are routed through the compute backend."
          : "- For this MVP, only bash and user `!` commands are routed through the compute backend.",
    execution.findOperations && execution.grepOperations
      ? "- Search tools stay inside the selected backend instead of falling back to the host workspace."
      : execution.readOperations
        ? "- Grep and find still operate on the host workspace for now."
        : "- Read, write, edit, grep, find, and ls still operate on the host workspace.",
  ];

  if (issues.length > 0) {
    for (const issue of issues) {
      lines.push(`- Warning: ${issue}`);
    }
  }

  return `${lines.join("\n")}\n`;
}
