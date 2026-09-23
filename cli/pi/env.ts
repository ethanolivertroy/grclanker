import { unlink, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { getGrclankerSettingsPath } from "../config/paths.js";
import {
  withComputeBackendExecution,
  type ResolvedComputeBackendExecution,
} from "./backend-exec.js";
import {
  COMPUTE_BACKEND_KINDS,
  describeNetworkPolicy,
  detectComputeBackendStatuses,
  getComputeBackendConfigurationIssues,
  getComputeBackendLabel,
  getComputeBackendShipState,
  getComputeProfileIssues,
  getRoutingBucket,
  parseComputeBackendKind,
  resolveComputeBackend,
  resolveComputeDefaults,
  resolveComputeProfile,
  type ComputeBackendKind,
  type ComputeBackendStatus,
  type ComputeDetectionOptions,
} from "./compute.js";
import { ExecutionBackendCleanupError, redactErrorMessage, redactSecrets } from "./execution-backend.js";
import { joinBashArgs, quoteForBash } from "./shell.js";
import { GrclankerUserError } from "./setup.js";
import {
  readGrclankerSettings,
  type GrclankerSettings,
} from "./settings.js";

export type EnvCommandOptions = {
  backend?: ComputeBackendKind;
  cwd: string;
  timeoutSeconds?: number;
};

type ParsedEnvCommand = {
  help: boolean;
  options: EnvCommandOptions;
  commandArgs: string[];
};

export type ComputeBackendListEntry = {
  kind: ComputeBackendKind;
  label: string;
  bucket: string;
  readiness: "ready" | "not detected" | "needs configuration" | "not available";
  preferred: boolean;
  detail: string;
};

function parseBackendFlag(value: string): ComputeBackendKind | undefined {
  return parseComputeBackendKind(value);
}

export function parseComputeFlag(value: string): ComputeBackendKind {
  const kind = parseComputeBackendKind(value);
  if (!kind) {
    throw new GrclankerUserError(
      `Unknown compute backend: ${value}. Expected one of: ${COMPUTE_BACKEND_KINDS.join(", ")}.`,
    );
  }
  return kind;
}

export function extractComputeFlag(args: string[]): { compute?: ComputeBackendKind; rest: string[] } {
  const rest: string[] = [];
  let compute: ComputeBackendKind | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--compute") {
      const value = args[index + 1];
      if (!value) throw new GrclankerUserError("Missing value for --compute.");
      compute = parseComputeFlag(value);
      index += 1;
      continue;
    }
    if (arg.startsWith("--compute=")) {
      compute = parseComputeFlag(arg.slice("--compute=".length));
      continue;
    }
    rest.push(arg);
  }
  return { compute, rest };
}

export function buildComputeBackendList(
  settings: GrclankerSettings,
  statuses: ComputeBackendStatus[] = detectComputeBackendStatuses(),
  options: ComputeDetectionOptions = {},
): ComputeBackendListEntry[] {
  const preferred = resolveComputeBackend(settings);
  return COMPUTE_BACKEND_KINDS.map((kind) => {
    const status = statuses.find((entry) => entry.kind === kind);
    const issues = getComputeBackendConfigurationIssues(settings, kind, options);
    const readiness: ComputeBackendListEntry["readiness"] = getComputeBackendShipState(kind) === "stub"
      ? "not available"
      : !status?.available
        ? "not detected"
        : issues.length > 0
          ? "needs configuration"
          : "ready";
    return {
      kind,
      label: getComputeBackendLabel(kind),
      bucket: getRoutingBucket(kind),
      readiness,
      preferred: kind === preferred,
      detail: issues[0] ?? status?.detail ?? "",
    };
  });
}

/**
 * Picks the backends the live smoke script exercises: every shipped non-host backend that
 * `detectComputeBackendStatuses` reports as available (credentials plus every required local tool,
 * so a runpod-pod host without `git` is skipped), narrowed to GRCLANKER_LIVE_BACKENDS when set.
 * sandbox-runtime only runs when requested explicitly.
 */
export function selectLiveSmokeCandidates(
  statuses: readonly ComputeBackendStatus[],
  requested?: readonly ComputeBackendKind[] | readonly string[],
): ComputeBackendStatus[] {
  return statuses
    .filter((status) => status.kind !== "host")
    .filter((status) => status.kind !== "sandbox-runtime" || requested?.includes("sandbox-runtime") === true)
    .filter((status) => getComputeBackendShipState(status.kind) !== "stub")
    .filter((status) => status.available)
    .filter((status) => !requested || requested.includes(status.kind));
}

export function formatComputeBackendList(
  entries: ComputeBackendListEntry[],
  settings: GrclankerSettings,
): string {
  const defaults = resolveComputeDefaults(settings);
  const lines = [
    "",
    "grclanker env list",
    "",
    `Preferred compute backend: ${resolveComputeBackend(settings)}`,
    `Compute profile:           ${resolveComputeProfile(settings)}`,
    `Network policy default:    ${describeNetworkPolicy(defaults.networkPolicy)}`,
    `Workspace mount mode:      ${defaults.workspaceMountMode}`,
    "",
    `  ${"backend".padEnd(20)} ${"bucket".padEnd(18)} ${"readiness".padEnd(20)} detail`,
  ];
  for (const entry of entries) {
    const marker = entry.preferred ? "*" : " ";
    lines.push(
      `${marker} ${entry.kind.padEnd(20)} ${entry.bucket.padEnd(18)} ${entry.readiness.padEnd(20)} ${entry.detail}`,
    );
  }
  const profileIssues = getComputeProfileIssues(settings);
  if (profileIssues.length > 0) {
    lines.push("", "Profile issues:");
    for (const issue of profileIssues) lines.push(`  - ${issue}`);
  }
  lines.push("", "* marks the preferred backend from settings.json (override per run with --compute <kind>).", "");
  return lines.join("\n");
}

export async function runComputeList(rawArgs: string[]): Promise<void> {
  const settings = readGrclankerSettings(getGrclankerSettingsPath());
  const entries = buildComputeBackendList(settings);
  if (rawArgs.includes("--json")) {
    console.log(JSON.stringify(entries, null, 2));
    return;
  }
  console.log(formatComputeBackendList(entries, settings));
}

function parseTimeoutFlag(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new GrclankerUserError(`Invalid timeout value: ${value}`);
  }
  return parsed;
}

function parseEnvCommandArgs(rawArgs: string[]): ParsedEnvCommand {
  const options: EnvCommandOptions = { cwd: process.cwd() };
  const commandArgs: string[] = [];
  let help = false;
  let parsingFlags = true;

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index]!;

    if (parsingFlags && arg === "--") {
      parsingFlags = false;
      continue;
    }

    if (parsingFlags && (arg === "--help" || arg === "-h")) {
      help = true;
      continue;
    }

    if (parsingFlags && (arg === "--backend" || arg === "-b" || arg === "--compute")) {
      const value = rawArgs[index + 1];
      if (!value) throw new GrclankerUserError("Missing value for --backend.");
      const backend = parseBackendFlag(value);
      if (!backend) throw new GrclankerUserError(`Unknown backend: ${value}`);
      options.backend = backend;
      index += 1;
      continue;
    }

    if (parsingFlags && arg === "--cwd") {
      const value = rawArgs[index + 1];
      if (!value) throw new GrclankerUserError("Missing value for --cwd.");
      options.cwd = resolve(value);
      index += 1;
      continue;
    }

    if (parsingFlags && (arg === "--timeout" || arg === "-t")) {
      const value = rawArgs[index + 1];
      if (!value) throw new GrclankerUserError("Missing value for --timeout.");
      options.timeoutSeconds = parseTimeoutFlag(value);
      index += 1;
      continue;
    }

    commandArgs.push(arg);
  }

  return { help, options, commandArgs };
}

function getEffectiveSettings(options: EnvCommandOptions): GrclankerSettings {
  const settings = readGrclankerSettings(getGrclankerSettingsPath());
  if (!options.backend) return settings;
  return { ...settings, computeBackend: options.backend };
}

function ensureBackendIsRunnable(settings: GrclankerSettings): void {
  const issues = getComputeBackendConfigurationIssues(settings);
  if (issues.length === 0) return;

  throw new GrclankerUserError(
    [
      "The selected compute backend is not ready:",
      ...issues.map((issue) => `- ${issue}`),
      "",
      "Run `grclanker env doctor` or `grclanker setup` to fix the configuration.",
    ].join("\n"),
  );
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function withEnvExecution<T>(
  options: EnvCommandOptions,
  run: (execution: ResolvedComputeBackendExecution) => Promise<T>,
): Promise<T> {
  const settings = getEffectiveSettings(options);
  ensureBackendIsRunnable(settings);
  try {
    return await withComputeBackendExecution(options.cwd, settings, run);
  } catch (error) {
    // A remnant the backend could not remove is an operator message (pod id, path, and the
    // delete command), not a stack trace.
    if (error instanceof ExecutionBackendCleanupError) throw new GrclankerUserError(error.message);
    throw error;
  }
}

async function executeOnBackend(
  command: string,
  options: EnvCommandOptions,
  execution: ResolvedComputeBackendExecution,
): Promise<{
  backend: ComputeBackendKind;
  label: string;
  summary: string;
  exitCode: number | null;
}> {
  let result: { exitCode: number | null };
  try {
    result = await execution.bashOperations.exec(command, options.cwd, {
      timeout: options.timeoutSeconds,
      onData: (chunk) => {
        process.stdout.write(chunk);
      },
    });
  } catch (error) {
    throw new GrclankerUserError(redactErrorMessage(getErrorMessage(error)));
  }

  return {
    backend: execution.kind,
    label: execution.label,
    summary: execution.summary,
    exitCode: result.exitCode,
  };
}

async function writeProbeFile(
  execution: ResolvedComputeBackendExecution,
  probePath: string,
  contents: string,
): Promise<void> {
  if (execution.writeOperations) {
    await execution.writeOperations.writeFile(probePath, contents);
    return;
  }

  await writeFile(probePath, contents, "utf8");
}

async function removeProbeFile(
  execution: ResolvedComputeBackendExecution,
  probePath: string,
  timeoutSeconds: number,
): Promise<void> {
  if (execution.writeOperations) {
    try {
      await execution.bashOperations.exec(`rm -f -- ${quoteForBash(probePath)}`, dirname(probePath), {
        onData: () => {},
        timeout: timeoutSeconds,
      });
      return;
    } catch {
      // fall through to local cleanup
    }
  }

  try {
    await unlink(probePath);
  } catch {
    // ignore cleanup failures in smoke mode
  }
}

export const ONE_SHOT_SMOKE_NOTE = "one-shot backend, stateful file operations not offered";

type SmokeLog = (line: string) => void;

function isOneShotExecution(execution: ResolvedComputeBackendExecution): boolean {
  return execution.backend?.capabilities.oneShot === true;
}

// A one-shot backend cannot pass a write-then-read check across two executions, so the stateful
// probes are reported as skipped with the reason (never as a pass) and the only thing verified is
// that a single execution can write and read back its own file.
async function runOneShotRoundTripSmokeTest(
  options: EnvCommandOptions,
  execution: ResolvedComputeBackendExecution,
  log: SmokeLog,
): Promise<void> {
  log(`tool_adapter=skipped (${ONE_SHOT_SMOKE_NOTE})`);
  const probeName = `.grclanker-one-shot-smoke-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`;
  const command = [
    `probe_file=${quoteForBash(probeName)}`,
    "printf 'alpha\\n' > \"$probe_file\" && cat \"$probe_file\"",
    "status=$?",
    "rm -f -- \"$probe_file\"",
    "exit $status",
  ].join("; ");
  const chunks: string[] = [];
  const result = await execution.bashOperations.exec(command, options.cwd, {
    onData: (chunk) => chunks.push(chunk.toString("utf8")),
    timeout: options.timeoutSeconds ?? 15,
  });
  if (result.exitCode !== 0 || !chunks.join("").includes("alpha")) {
    throw new GrclankerUserError("One-shot write-then-read verification inside a single execution failed.");
  }
  log("tool_one_shot_round_trip=ok");
}

export async function runBackendToolSmokeTest(
  options: EnvCommandOptions,
  execution: ResolvedComputeBackendExecution,
  log: SmokeLog = console.log,
): Promise<void> {
  if (isOneShotExecution(execution)) {
    await runOneShotRoundTripSmokeTest(options, execution, log);
    return;
  }
  if (
    !execution.readOperations ||
    !execution.writeOperations ||
    !execution.editOperations ||
    !execution.lsOperations
  ) {
    log("tool_adapter=skipped");
    return;
  }

  const probePath = resolve(
    options.cwd,
    `.grclanker-tool-smoke-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`,
  );
  const probeName = basename(probePath);

  try {
    await execution.writeOperations.writeFile(probePath, "alpha\n");
    log("tool_write=ok");

    const written = (await execution.readOperations.readFile(probePath)).toString("utf8");
    if (written !== "alpha\n") {
      throw new GrclankerUserError("Backend write/read verification failed.");
    }
    log("tool_read=ok");

    await execution.editOperations.access(probePath);
    await execution.editOperations.writeFile(probePath, "beta\n");
    const edited = (await execution.editOperations.readFile(probePath)).toString("utf8");
    if (edited !== "beta\n") {
      throw new GrclankerUserError("Backend edit verification failed.");
    }
    log("tool_edit=ok");

    const entries = await execution.lsOperations.readdir(options.cwd);
    if (!entries.includes(probeName)) {
      throw new GrclankerUserError("Backend ls verification failed.");
    }
    log("tool_ls=ok");
  } finally {
    await removeProbeFile(execution, probePath, options.timeoutSeconds ?? 15);
  }
}

export async function runBackendSearchSmokeTest(
  options: EnvCommandOptions,
  execution: ResolvedComputeBackendExecution,
  log: SmokeLog = console.log,
): Promise<void> {
  if (!execution.findOperations || !execution.grepOperations) {
    const reason = isOneShotExecution(execution) ? ` (${ONE_SHOT_SMOKE_NOTE})` : "";
    log(`tool_find=skipped${reason}`);
    log(`tool_grep=skipped${reason}`);
    return;
  }

  const probeName = `.grclanker-search-smoke-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`;
  const probePath = resolve(options.cwd, probeName);
  const probeNeedle = `needle-${Math.random().toString(36).slice(2, 10)}`;

  await writeProbeFile(execution, probePath, `${probeNeedle}\n`);

  try {
    const found = await execution.findOperations.glob(probeName, options.cwd, {
      ignore: ["**/.git/**", "**/node_modules/**"],
      limit: 10,
    });
    if (!found.includes(probePath)) {
      throw new GrclankerUserError("Backend find verification failed.");
    }
    log("tool_find=ok");

    const search = await execution.grepOperations.searchMatches({
      pattern: probeNeedle,
      searchPath: options.cwd,
      literal: true,
      limit: 10,
    });
    const matched = search.matches.some((match) =>
      match.filePath === probePath && match.lineNumber === 1
    );
    if (!matched) {
      throw new GrclankerUserError("Backend grep verification failed.");
    }
    log("tool_grep=ok");
  } finally {
    await removeProbeFile(execution, probePath, options.timeoutSeconds ?? 15);
  }
}

function printEnvCommandHelp(subcommand: "smoke-test" | "exec"): void {
  if (subcommand === "smoke-test") {
    console.log(`
grclanker env smoke-test

Usage:
  grclanker env smoke-test [--backend <kind>] [--cwd <path>] [--timeout <seconds>]

Options:
  --backend, -b   host | sandbox-runtime | docker | parallels-vm | modal | runpod-pod | runpod-serverless (alias: --compute)
  --cwd           Working directory to validate on the selected backend
  --timeout, -t   Command timeout in seconds (default: 30)
`);
    return;
  }

  console.log(`
grclanker env exec

Usage:
  grclanker env exec [--backend <kind>] [--cwd <path>] [--timeout <seconds>] -- <command>
  grclanker env exec [--backend <kind>] [--cwd <path>] [--timeout <seconds>] <command>

Options:
  --backend, -b   host | sandbox-runtime | docker | parallels-vm | modal | runpod-pod | runpod-serverless (alias: --compute)
  --cwd           Working directory to execute from on the selected backend
  --timeout, -t   Command timeout in seconds
`);
}

function buildSmokeTestCommand(): string {
  return [
    "set -e",
    "printf 'probe=ok\\n'",
    "printf 'pwd=%s\\n' \"$PWD\"",
    "printf 'user=%s\\n' \"$(id -un 2>/dev/null || whoami 2>/dev/null || echo unknown)\"",
    "printf 'uname=%s\\n' \"$(uname -srm 2>/dev/null || echo unknown)\"",
    "probe_file=.grclanker-backend-smoke-$$",
    "if printf 'ok\\n' > \"$probe_file\" 2>/dev/null; then printf 'write=%s\\n' ok; rm -f \"$probe_file\"; else printf 'write=%s\\n' failed; fi",
  ].join("; ");
}

export async function runComputeSmokeTest(rawArgs: string[]): Promise<void> {
  const parsed = parseEnvCommandArgs(rawArgs);
  if (parsed.help) {
    printEnvCommandHelp("smoke-test");
    return;
  }

  if (parsed.commandArgs.length > 0) {
    throw new GrclankerUserError("`env smoke-test` does not accept a trailing command.");
  }

  const options: EnvCommandOptions = {
    ...parsed.options,
    timeoutSeconds: parsed.options.timeoutSeconds ?? 30,
  };
  const settings = getEffectiveSettings(options);
  const backend = options.backend ?? resolveComputeBackend(settings);

  console.log("\ngrclanker env smoke-test\n");
  console.log(`Backend: ${getComputeBackendLabel(backend)} (${backend})`);
  console.log(`CWD: ${options.cwd}`);
  console.log("");

  await withEnvExecution(options, async (execution) => {
    const result = await executeOnBackend(buildSmokeTestCommand(), options, execution);
    const snapshotId = await runBackendSnapshotSmokeTest(execution);
    await runBackendToolSmokeTest(options, execution);
    await runBackendSearchSmokeTest(options, execution);
    if (snapshotId && execution.backend) {
      await execution.backend.restore(execution.sessionId, snapshotId);
      console.log("restore=ok");
    }
    console.log("");
    console.log(`Result: ${result.summary}`);
    console.log(`Exit code: ${result.exitCode ?? "null"}`);

    if ((result.exitCode ?? 1) !== 0) {
      throw new GrclankerUserError(`Smoke test failed with exit code ${result.exitCode}.`);
    }
  });
}

async function runBackendSnapshotSmokeTest(
  execution: ResolvedComputeBackendExecution,
): Promise<string | undefined> {
  if (!execution.backend?.capabilities.snapshot || !execution.backend.capabilities.restore) {
    console.log("snapshot=skipped");
    return undefined;
  }
  const snapshotId = await execution.backend.snapshot(execution.sessionId);
  console.log(`snapshot=ok ${snapshotId}`);
  return snapshotId;
}

export async function runComputeExec(rawArgs: string[]): Promise<void> {
  const parsed = parseEnvCommandArgs(rawArgs);
  if (parsed.help) {
    printEnvCommandHelp("exec");
    return;
  }

  if (parsed.commandArgs.length === 0) {
    throw new GrclankerUserError("`env exec` requires a command to run.");
  }

  const options = parsed.options;
  const settings = getEffectiveSettings(options);
  const backend = options.backend ?? resolveComputeBackend(settings);
  const command = joinBashArgs(parsed.commandArgs);

  console.log(`\nbackend: ${getComputeBackendLabel(backend)} (${backend})`);
  console.log(`cwd: ${options.cwd}`);
  console.log(`command: ${redactSecrets(command)}\n`);

  await withEnvExecution(options, async (execution) => {
    const result = await executeOnBackend(command, options, execution);
    if ((result.exitCode ?? 1) !== 0) {
      throw new GrclankerUserError(`Command failed with exit code ${result.exitCode}.`);
    }
  });
}
