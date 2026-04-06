import { unlink, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { getGrclankerSettingsPath } from "../config/paths.js";
import {
  resolveComputeBackendExecution,
  type ResolvedComputeBackendExecution,
} from "./backend-exec.js";
import { cleanupParallelsSandboxes } from "./parallels-sandbox.js";
import {
  getComputeBackendConfigurationIssues,
  getComputeBackendLabel,
  resolveComputeBackend,
  type ComputeBackendKind,
} from "./compute.js";
import { joinBashArgs, quoteForBash } from "./shell.js";
import { GrclankerUserError } from "./setup.js";
import {
  readGrclankerSettings,
  type GrclankerSettings,
} from "./settings.js";

type EnvCommandOptions = {
  backend?: ComputeBackendKind;
  cwd: string;
  timeoutSeconds?: number;
};

type ParsedEnvCommand = {
  help: boolean;
  options: EnvCommandOptions;
  commandArgs: string[];
};

function parseBackendFlag(value: string): ComputeBackendKind | undefined {
  switch (value.trim().toLowerCase()) {
    case "host":
      return "host";
    case "sandbox-runtime":
    case "sandbox":
    case "srt":
      return "sandbox-runtime";
    case "docker":
      return "docker";
    case "parallels-vm":
    case "parallels":
    case "vm":
      return "parallels-vm";
    default:
      return undefined;
  }
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

    if (parsingFlags && (arg === "--backend" || arg === "-b")) {
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

function getResolvedExecution(
  options: EnvCommandOptions,
): { settings: GrclankerSettings; execution: ResolvedComputeBackendExecution } {
  const settings = getEffectiveSettings(options);
  ensureBackendIsRunnable(settings);
  return {
    settings,
    execution: resolveComputeBackendExecution(options.cwd, settings),
  };
}

async function executeOnBackend(
  command: string,
  options: EnvCommandOptions,
): Promise<{
  backend: ComputeBackendKind;
  label: string;
  summary: string;
  exitCode: number | null;
}> {
  const { execution } = getResolvedExecution(options);
  let result: { exitCode: number | null };
  try {
    result = await execution.bashOperations.exec(command, options.cwd, {
      timeout: options.timeoutSeconds,
      onData: (chunk) => {
        process.stdout.write(chunk);
      },
    });
  } catch (error) {
    throw new GrclankerUserError(getErrorMessage(error));
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

async function runBackendToolSmokeTest(options: EnvCommandOptions): Promise<void> {
  const { execution } = getResolvedExecution(options);
  if (
    !execution.readOperations ||
    !execution.writeOperations ||
    !execution.editOperations ||
    !execution.lsOperations
  ) {
    console.log("tool_adapter=skipped");
    return;
  }

  const probePath = resolve(
    options.cwd,
    `.grclanker-tool-smoke-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`,
  );
  const probeName = basename(probePath);

  try {
    await execution.writeOperations.writeFile(probePath, "alpha\n");
    console.log("tool_write=ok");

    const written = (await execution.readOperations.readFile(probePath)).toString("utf8");
    if (written !== "alpha\n") {
      throw new GrclankerUserError("Backend write/read verification failed.");
    }
    console.log("tool_read=ok");

    await execution.editOperations.access(probePath);
    await execution.editOperations.writeFile(probePath, "beta\n");
    const edited = (await execution.editOperations.readFile(probePath)).toString("utf8");
    if (edited !== "beta\n") {
      throw new GrclankerUserError("Backend edit verification failed.");
    }
    console.log("tool_edit=ok");

    const entries = await execution.lsOperations.readdir(options.cwd);
    if (!entries.includes(probeName)) {
      throw new GrclankerUserError("Backend ls verification failed.");
    }
    console.log("tool_ls=ok");
  } finally {
    await removeProbeFile(execution, probePath, options.timeoutSeconds ?? 15);
  }
}

async function runBackendSearchSmokeTest(options: EnvCommandOptions): Promise<void> {
  const { execution } = getResolvedExecution(options);
  if (!execution.findOperations || !execution.grepOperations) {
    console.log("tool_find=skipped");
    console.log("tool_grep=skipped");
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
    console.log("tool_find=ok");

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
    console.log("tool_grep=ok");
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
  --backend, -b   host | sandbox-runtime | docker | parallels-vm
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
  --backend, -b   host | sandbox-runtime | docker | parallels-vm
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

  try {
    const result = await executeOnBackend(buildSmokeTestCommand(), options);
    await runBackendToolSmokeTest(options);
    await runBackendSearchSmokeTest(options);
    console.log("");
    console.log(`Result: ${result.summary}`);
    console.log(`Exit code: ${result.exitCode ?? "null"}`);

    if ((result.exitCode ?? 1) !== 0) {
      throw new GrclankerUserError(`Smoke test failed with exit code ${result.exitCode}.`);
    }
  } finally {
    if (backend === "parallels-vm") {
      await cleanupParallelsSandboxes();
    }
  }
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
  console.log(`command: ${command}\n`);

  try {
    const result = await executeOnBackend(command, options);
    if ((result.exitCode ?? 1) !== 0) {
      throw new GrclankerUserError(`Command failed with exit code ${result.exitCode}.`);
    }
  } finally {
    if (backend === "parallels-vm") {
      await cleanupParallelsSandboxes();
    }
  }
}
