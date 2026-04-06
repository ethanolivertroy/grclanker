import { spawn, spawnSync } from "node:child_process";
import { basename, dirname, posix, relative, resolve, sep } from "node:path";
import {
  createLocalBashOperations,
  type BashOperations,
  type EditOperations,
  type FindOperations,
  type LsOperations,
  type ReadOperations,
  type WriteOperations,
} from "@mariozechner/pi-coding-agent";
import { minimatch } from "minimatch";
import {
  getComputeBackendConfigurationIssues,
  getComputeBackendLabel,
  isComputeBackendAvailable,
  resolveComputeBackend,
  resolveDockerImage,
  resolveDockerWorkspacePath,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
  type ComputeBackendKind,
} from "./compute.js";
import { ensureParallelsSandbox } from "./parallels-sandbox.js";
import {
  createSandboxEditOperations,
  createSandboxLsOperations,
  createSandboxReadOperations,
  createSandboxWriteOperations,
  loadSandboxConfig,
  wrapCommandWithSandbox,
} from "./sandbox.js";
import { joinBashArgs, quoteForBash } from "./shell.js";
import type { GrclankerSettings } from "./settings.js";

type StreamExecOptions = {
  onData: (chunk: Buffer) => void;
  signal?: AbortSignal;
  timeout?: number;
};

type DockerIdentity = {
  userArgs: string[];
  envArgs: string[];
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
  bashOperations: BashOperations;
  readOperations?: ReadOperations;
  writeOperations?: WriteOperations;
  editOperations?: EditOperations;
  lsOperations?: LsOperations;
  findOperations?: FindOperations;
  grepOperations?: ComputeBackendGrepOperations;
};

type BackendCommandAdapter = {
  stream: (
    command: string,
    cwd: string,
    options: StreamExecOptions,
  ) => Promise<{ exitCode: number | null }>;
  capture: (command: string, cwd: string) => Promise<Buffer>;
  mapPath: (absolutePath: string) => Promise<string>;
};

function formatBackendError(message: string): Error {
  return new Error(`Compute backend error: ${message}`);
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

function execStreamingCommand(
  executable: string,
  args: string[],
  { onData, signal, timeout }: StreamExecOptions,
  spawnOptions?: { cwd?: string },
): Promise<{ exitCode: number | null }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      cwd: spawnOptions?.cwd,
    });

    let timedOut = false;
    let timeoutHandle: NodeJS.Timeout | undefined;

    const killProcess = () => {
      if (!child.pid) return;
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };

    if (timeout !== undefined && timeout > 0) {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        killProcess();
      }, timeout * 1000);
    }

    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);

    child.on("error", (error) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      reject(error);
    });

    const onAbort = () => {
      killProcess();
    };

    signal?.addEventListener("abort", onAbort, { once: true });

    child.on("close", (code) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      signal?.removeEventListener("abort", onAbort);

      if (signal?.aborted) {
        reject(new Error("aborted"));
      } else if (timedOut) {
        reject(new Error(`timeout:${timeout}`));
      } else {
        resolvePromise({ exitCode: code });
      }
    });
  });
}

function execCapturedCommand(
  executable: string,
  args: string[],
  spawnOptions?: { cwd?: string },
): Promise<Buffer> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, {
      stdio: ["ignore", "pipe", "pipe"],
      cwd: spawnOptions?.cwd,
    });
    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];

    child.stdout?.on("data", (chunk) => chunks.push(chunk));
    child.stderr?.on("data", (chunk) => errChunks.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        const stderr = Buffer.concat(errChunks).toString("utf8").trim();
        reject(
          new Error(
            stderr.length > 0
              ? stderr
              : `Command failed (${code}) for ${executable} ${args.join(" ")}`,
          ),
        );
      } else {
        resolvePromise(Buffer.concat(chunks));
      }
    });
  });
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

function resolveDockerIdentityArgs(): DockerIdentity {
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") {
    return { userArgs: [], envArgs: [] };
  }

  return {
    userArgs: ["--user", `${process.getuid()}:${process.getgid()}`],
    envArgs: ["--env", "HOME=/tmp"],
  };
}

function createDockerCommandAdapter(
  localCwd: string,
  settings: GrclankerSettings,
): BackendCommandAdapter {
  const workspaceRoot = resolveDockerWorkspacePath(settings);
  return {
    mapPath: async (absolutePath) => ensureWorkspaceMapping(localCwd, absolutePath, workspaceRoot),
    async stream(command, cwd, options) {
      if (!isComputeBackendAvailable("docker")) {
        throw formatBackendError(
          "Docker is selected, but the Docker daemon is not reachable. Run `grclanker env doctor` for details.",
        );
      }

      const image = resolveDockerImage(settings);
      const mappedCwd = ensureWorkspaceMapping(localCwd, cwd, workspaceRoot);
      const hostWorkspace = resolve(localCwd);
      const dockerIdentity = resolveDockerIdentityArgs();

      return execStreamingCommand(
        "docker",
        [
          "run",
          "--rm",
          "-i",
          "--init",
          "--volume",
          `${hostWorkspace}:${workspaceRoot}`,
          "--workdir",
          mappedCwd,
          ...dockerIdentity.userArgs,
          "--env",
          "GRCLANKER_COMPUTE_BACKEND=docker",
          ...dockerIdentity.envArgs,
          image,
          "bash",
          "-lc",
          command,
        ],
        options,
      );
    },
    async capture(command, cwd) {
      if (!isComputeBackendAvailable("docker")) {
        throw formatBackendError(
          "Docker is selected, but the Docker daemon is not reachable. Run `grclanker env doctor` for details.",
        );
      }

      const image = resolveDockerImage(settings);
      const mappedCwd = ensureWorkspaceMapping(localCwd, cwd, workspaceRoot);
      const hostWorkspace = resolve(localCwd);
      const dockerIdentity = resolveDockerIdentityArgs();

      return execCapturedCommand("docker", [
        "run",
        "--rm",
        "-i",
        "--init",
        "--volume",
        `${hostWorkspace}:${workspaceRoot}`,
        "--workdir",
        mappedCwd,
        ...dockerIdentity.userArgs,
        "--env",
        "GRCLANKER_COMPUTE_BACKEND=docker",
        ...dockerIdentity.envArgs,
        image,
        "bash",
        "-lc",
        command,
      ]);
    },
  };
}

function createSandboxCommandAdapter(localCwd: string): BackendCommandAdapter {
  return {
    mapPath: async (absolutePath) => resolve(absolutePath),
    async stream(command, cwd, options) {
      const wrapped = await wrapCommandWithSandbox(command, localCwd);
      return execStreamingCommand("bash", ["-lc", wrapped], options, { cwd });
    },
    async capture(command, cwd) {
      const wrapped = await wrapCommandWithSandbox(command, localCwd);
      return execCapturedCommand("bash", ["-lc", wrapped], { cwd });
    },
  };
}

function createParallelsCommandAdapter(
  localCwd: string,
  settings: GrclankerSettings,
): BackendCommandAdapter {
  return {
    mapPath: async (absolutePath) => {
      const session = await ensureParallelsSandbox(localCwd, settings);
      return ensureWorkspaceMapping(localCwd, absolutePath, session.workspacePath);
    },
    async stream(command, cwd, options) {
      if (!isComputeBackendAvailable("parallels-vm")) {
        throw formatBackendError(
          "Parallels VM is selected, but `prlctl` is not available on this host. Run `grclanker env doctor` for details.",
        );
      }

      const session = await ensureParallelsSandbox(localCwd, settings);
      const mappedCwd = ensureWorkspaceMapping(localCwd, cwd, session.workspacePath);
      const wrappedCommand = `cd -- ${quoteForBash(mappedCwd)} && ${command}`;

      return execStreamingCommand(
        "prlctl",
        [
          "exec",
          session.cloneName,
          "--current-user",
          "bash",
          "-lc",
          wrappedCommand,
        ],
        options,
      );
    },
    async capture(command, cwd) {
      if (!isComputeBackendAvailable("parallels-vm")) {
        throw formatBackendError(
          "Parallels VM is selected, but `prlctl` is not available on this host. Run `grclanker env doctor` for details.",
        );
      }

      const session = await ensureParallelsSandbox(localCwd, settings);
      const mappedCwd = ensureWorkspaceMapping(localCwd, cwd, session.workspacePath);
      return execCapturedCommand("prlctl", [
        "exec",
        session.cloneName,
        "--current-user",
        "bash",
        "-lc",
        `cd -- ${quoteForBash(mappedCwd)} && ${command}`,
      ]);
    },
  };
}

export function resolveComputeBackendExecution(
  localCwd: string,
  settings: GrclankerSettings,
): ResolvedComputeBackendExecution {
  const kind = resolveComputeBackend(settings);
  const label = getComputeBackendLabel(kind);

  if (kind === "docker") {
    const image = resolveDockerImage(settings);
    const workspaceRoot = resolveDockerWorkspacePath(settings);
    const adapter = createDockerCommandAdapter(localCwd, settings);
    return {
      kind,
      label,
      summary: `bash, read, write, edit, ls, grep, and find run in Docker image ${image} with the host repo mounted at ${workspaceRoot}`,
      bashOperations: { exec: adapter.stream },
      readOperations: createBackendReadOperations(localCwd, adapter),
      writeOperations: createBackendWriteOperations(localCwd, adapter),
      editOperations: createBackendEditOperations(localCwd, adapter),
      lsOperations: createBackendLsOperations(localCwd, adapter),
      findOperations: createBackendFindOperations(localCwd, adapter),
      grepOperations: createBackendGrepOperations(localCwd, adapter),
    };
  }

  if (kind === "parallels-vm") {
    const sourceKind = resolveParallelsSourceKind(settings);
    const templateName = resolveParallelsTemplateName(settings);
    const baseVmName = resolveParallelsBaseVmName(settings);
    const workspaceOverride = resolveParallelsWorkspacePath(settings);
    const clonePrefix = resolveParallelsClonePrefix(settings);
    const adapter = createParallelsCommandAdapter(localCwd, settings);
    return {
      kind,
      label,
      summary: (sourceKind === "template" ? templateName : baseVmName)
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
        : "bash is configured to run through a disposable Parallels sandbox, but template/base source settings are incomplete",
      bashOperations: { exec: adapter.stream },
      readOperations: createBackendReadOperations(localCwd, adapter),
      writeOperations: createBackendWriteOperations(localCwd, adapter),
      editOperations: createBackendEditOperations(localCwd, adapter),
      lsOperations: createBackendLsOperations(localCwd, adapter),
      findOperations: createBackendFindOperations(localCwd, adapter),
      grepOperations: createBackendGrepOperations(localCwd, adapter),
    };
  }

  if (kind === "sandbox-runtime") {
    const sandboxConfig = loadSandboxConfig(localCwd);
    const adapter = createSandboxCommandAdapter(localCwd);
    return {
      kind,
      label,
      summary: sandboxConfig.enabled === false
        ? "sandbox-runtime is selected, but sandboxing is disabled by config and commands run on the host"
        : "bash, grep, and find run through sandbox-runtime and file tools enforce the same filesystem policy locally",
      bashOperations: {
        async exec(command, cwd, options) {
          const wrapped = await wrapCommandWithSandbox(command, localCwd);
          return createLocalBashOperations().exec(wrapped, cwd, options);
        },
      },
      readOperations: createSandboxReadOperations(localCwd),
      writeOperations: createSandboxWriteOperations(localCwd),
      editOperations: createSandboxEditOperations(localCwd),
      lsOperations: createSandboxLsOperations(localCwd),
      findOperations: createBackendFindOperations(localCwd, adapter),
      grepOperations: createBackendGrepOperations(localCwd, adapter),
    };
  }

  return {
    kind: "host",
    label,
    summary: "bash runs directly on the local host shell",
    bashOperations: createLocalBashOperations(),
  };
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
