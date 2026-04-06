import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { cpus, totalmem } from "node:os";
import { quoteForBash } from "./shell.js";
import type { GrclankerSettings } from "./settings.js";

const require = createRequire(import.meta.url);

export type ComputeBackendKind =
  | "host"
  | "sandbox-runtime"
  | "docker"
  | "parallels-vm";

export type ParallelsSourceKind = "template" | "base-vm";

export type ComputeBackendStatus = {
  kind: ComputeBackendKind;
  label: string;
  summary: string;
  available: boolean;
  detail: string;
};

export type ParallelsVmInfo = {
  name: string;
  uuid: string;
  status: string;
};

export type ParallelsWorkspaceValidation = {
  ok: boolean;
  detail: string;
  vmState?: string;
  startedVm?: boolean;
};

export const DEFAULT_COMPUTE_BACKEND: ComputeBackendKind = "host";
export const DEFAULT_DOCKER_IMAGE = "ubuntu:24.04";
export const DEFAULT_DOCKER_WORKSPACE_PATH = "/workspace";
export const DEFAULT_PARALLELS_AUTO_START = true;
export const DEFAULT_PARALLELS_CLONE_PREFIX = "grclanker-sandbox";
export const DEFAULT_PARALLELS_SOURCE_KIND: ParallelsSourceKind = "template";

const COMPUTE_BACKEND_OPTIONS: Record<
  ComputeBackendKind,
  { label: string; summary: string }
> = {
  host: {
    label: "Host",
    summary: "run directly in the current shell on this machine",
  },
  "sandbox-runtime": {
    label: "sandbox-runtime",
    summary: "wrap tool execution in a local filesystem/network sandbox",
  },
  docker: {
    label: "Docker",
    summary: "run work inside an isolated local container",
  },
  "parallels-vm": {
    label: "Parallels VM",
    summary: "run work inside a disposable Parallels sandbox deployed from a template or stopped base VM",
  },
};

function binaryExists(command: string): boolean {
  const locator = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(locator, [command], { stdio: "ignore" });
  return result.status === 0;
}

function packageExists(specifier: string): boolean {
  try {
    require.resolve(specifier);
    return true;
  } catch {
    return false;
  }
}

function sandboxRuntimeInstalled(): boolean {
  return packageExists("@anthropic-ai/sandbox-runtime");
}

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function normalizeWorkspacePath(value: unknown, fallback: string): string {
  const normalized = normalizeOptionalString(value)?.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!normalized) return fallback;
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function dockerDaemonReachable(): boolean {
  if (!binaryExists("docker")) return false;
  const result = spawnSync("docker", ["info"], { stdio: "ignore" });
  return result.status === 0;
}

function parseJson<T>(value: string): T | undefined {
  try {
    return JSON.parse(value) as T;
  } catch {
    return undefined;
  }
}

function runPrlctl(args: string[]): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const result = spawnSync("prlctl", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  return {
    status: result.status,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

export function getComputeBackendChoices(): Array<{
  kind: ComputeBackendKind;
  label: string;
  summary: string;
}> {
  return (Object.entries(COMPUTE_BACKEND_OPTIONS) as Array<
    [ComputeBackendKind, { label: string; summary: string }]
  >).map(([kind, metadata]) => ({ kind, ...metadata }));
}

export function normalizeComputeBackend(value: unknown): ComputeBackendKind {
  if (value === "sandbox-runtime" || value === "docker" || value === "parallels-vm") {
    return value;
  }
  return DEFAULT_COMPUTE_BACKEND;
}

export function normalizeParallelsSourceKind(value: unknown): ParallelsSourceKind {
  return value === "base-vm" ? "base-vm" : DEFAULT_PARALLELS_SOURCE_KIND;
}

export function resolveComputeBackend(settings: GrclankerSettings): ComputeBackendKind {
  return normalizeComputeBackend(settings.computeBackend);
}

export function resolveDockerImage(settings: GrclankerSettings): string {
  return normalizeOptionalString(settings.dockerImage) ?? DEFAULT_DOCKER_IMAGE;
}

export function resolveDockerWorkspacePath(settings: GrclankerSettings): string {
  return normalizeWorkspacePath(settings.dockerWorkspacePath, DEFAULT_DOCKER_WORKSPACE_PATH);
}

export function resolveParallelsBaseVmName(settings: GrclankerSettings): string | undefined {
  return normalizeOptionalString(settings.parallelsBaseVmName)
    ?? normalizeOptionalString(settings.parallelsVmName);
}

export function resolveParallelsTemplateName(settings: GrclankerSettings): string | undefined {
  return normalizeOptionalString(settings.parallelsTemplateName);
}

export function resolveParallelsSourceKind(settings: GrclankerSettings): ParallelsSourceKind {
  if (normalizeOptionalString(settings.parallelsTemplateName)) return "template";
  if (normalizeOptionalString(settings.parallelsBaseVmName) || normalizeOptionalString(settings.parallelsVmName)) {
    return normalizeParallelsSourceKind(settings.parallelsSourceKind ?? "base-vm");
  }
  return normalizeParallelsSourceKind(settings.parallelsSourceKind);
}

export function resolveParallelsVmName(settings: GrclankerSettings): string | undefined {
  return resolveParallelsBaseVmName(settings);
}

export function resolveParallelsWorkspacePath(settings: GrclankerSettings): string | undefined {
  return normalizeOptionalString(settings.parallelsWorkspacePath)
    ?.replace(/\\/g, "/")
    .replace(/\/+$/, "");
}

export function resolveParallelsAutoStart(settings: GrclankerSettings): boolean {
  return typeof settings.parallelsAutoStart === "boolean"
    ? settings.parallelsAutoStart
    : DEFAULT_PARALLELS_AUTO_START;
}

export function resolveParallelsClonePrefix(settings: GrclankerSettings): string {
  return normalizeOptionalString(settings.parallelsClonePrefix) ?? DEFAULT_PARALLELS_CLONE_PREFIX;
}

export function getComputeBackendLabel(kind: ComputeBackendKind): string {
  return COMPUTE_BACKEND_OPTIONS[kind].label;
}

export function getComputeBackendSurfaceLabel(kind: ComputeBackendKind): string {
  switch (kind) {
    case "sandbox-runtime":
      return "sandbox-runtime";
    case "docker":
      return "docker";
    case "parallels-vm":
      return "parallels vm";
    default:
      return "local shell";
  }
}

export function formatSystemResources(kind: ComputeBackendKind): string {
  const cores = cpus().length;
  const ram = `${Math.round(totalmem() / (1024 ** 3))}GB`;
  return `${cores} cores · ${ram} · ${getComputeBackendSurfaceLabel(kind)}`;
}

export function listParallelsVms(): ParallelsVmInfo[] {
  if (process.platform !== "darwin" || !binaryExists("prlctl")) return [];

  const result = spawnSync("prlctl", ["list", "-a", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0 || typeof result.stdout !== "string") return [];

  const parsed = parseJson<Array<Record<string, unknown>>>(result.stdout) ?? [];
  return parsed
    .map((entry) => ({
      name: typeof entry.name === "string" ? entry.name : "",
      uuid: typeof entry.uuid === "string" ? entry.uuid : "",
      status: typeof entry.status === "string" ? entry.status : "unknown",
    }))
    .filter((entry) => entry.name.length > 0);
}

export function listParallelsTemplates(): ParallelsVmInfo[] {
  if (process.platform !== "darwin" || !binaryExists("prlctl")) return [];

  const result = spawnSync("prlctl", ["list", "-a", "-t", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0 || typeof result.stdout !== "string") return [];

  const parsed = parseJson<Array<Record<string, unknown>>>(result.stdout) ?? [];
  return parsed
    .map((entry) => ({
      name: typeof entry.name === "string" ? entry.name : "",
      uuid: typeof entry.uuid === "string" ? entry.uuid : "",
      status: typeof entry.status === "string" ? entry.status : "unknown",
    }))
    .filter((entry) => entry.name.length > 0);
}

export function getParallelsTemplateInfo(templateName: string): ParallelsVmInfo | undefined {
  return listParallelsTemplates().find((vm) => vm.name === templateName || vm.uuid === templateName);
}

export function getParallelsVmInfo(vmName: string): ParallelsVmInfo | undefined {
  return listParallelsVms().find((vm) => vm.name === vmName || vm.uuid === vmName);
}

export function getParallelsVmState(vmName: string): string | undefined {
  return getParallelsVmInfo(vmName)?.status;
}

export function validateParallelsWorkspacePath(
  vmName: string,
  workspacePath: string,
  options?: { autoStart?: boolean },
): ParallelsWorkspaceValidation {
  if (process.platform !== "darwin") {
    return {
      ok: false,
      detail: "Parallels validation requires a macOS host.",
    };
  }

  if (!binaryExists("prlctl")) {
    return {
      ok: false,
      detail: "Parallels Desktop is not available on this host.",
    };
  }

  const vm = getParallelsVmInfo(vmName);
  if (!vm) {
    return {
      ok: false,
      detail: `Configured Parallels VM "${vmName}" was not found in \`prlctl list -a\`.`,
    };
  }

  let state = vm.status;
  let startedVm = false;
  if (state !== "running") {
    if (!options?.autoStart) {
      return {
        ok: false,
        vmState: state,
        detail: `VM "${vmName}" is ${state}. Start or resume it, or enable auto-start, before validating guest paths.`,
      };
    }

    const action = state === "suspended" ? "resume" : "start";
    const startResult = runPrlctl([action, vmName]);
    if (startResult.status !== 0) {
      const output = [startResult.stdout, startResult.stderr].filter(Boolean).join("\n").trim();
      return {
        ok: false,
        vmState: state,
        detail: `Could not ${action} "${vmName}". ${output || "Check Parallels Desktop."}`,
      };
    }

    state = "running";
    startedVm = true;
  }

  const checkResult = runPrlctl([
    "exec",
    vmName,
    "--current-user",
    "bash",
    "-lc",
    `if test -d ${quoteForBash(workspacePath)}; then printf ok; else printf missing; fi`,
  ]);

  if (checkResult.status !== 0) {
    const output = [checkResult.stdout, checkResult.stderr].filter(Boolean).join("\n").trim();
    return {
      ok: false,
      vmState: state,
      startedVm,
      detail: `Could not inspect ${workspacePath} inside "${vmName}". ${output || "Check guest shell access and the path."}`,
    };
  }

  if (checkResult.stdout.trim() !== "ok") {
    return {
      ok: false,
      vmState: state,
      startedVm,
      detail: `${workspacePath} does not exist inside "${vmName}".`,
    };
  }

  return {
    ok: true,
    vmState: state,
    startedVm,
    detail: startedVm
      ? `Started or resumed "${vmName}" and validated ${workspacePath}.`
      : `Validated ${workspacePath} inside "${vmName}".`,
  };
}

export function getComputeBackendConfigurationIssues(
  settings: GrclankerSettings,
  kind = resolveComputeBackend(settings),
): string[] {
  if (kind === "sandbox-runtime") {
    if (process.platform !== "darwin" && process.platform !== "linux") {
      return ["sandbox-runtime currently supports macOS and Linux hosts only."];
    }
    if (!sandboxRuntimeInstalled()) {
      return ["Install `@anthropic-ai/sandbox-runtime` to use the sandbox backend."];
    }
    return [];
  }

  if (kind === "docker") {
    return [];
  }

  if (kind === "parallels-vm") {
    const issues: string[] = [];
    const sourceKind = resolveParallelsSourceKind(settings);
    if (sourceKind === "template") {
      const templateName = resolveParallelsTemplateName(settings);
      if (!templateName) {
        issues.push("Set `parallelsTemplateName` to the dedicated Parallels template grclanker should deploy sandboxes from.");
      } else {
        const template = getParallelsTemplateInfo(templateName);
        if (!template && process.platform === "darwin" && binaryExists("prlctl")) {
          issues.push(`Configured Parallels template "${templateName}" was not found in \`prlctl list -a -t\`.`);
        }
      }
    } else {
      const baseVmName = resolveParallelsBaseVmName(settings);
      if (!baseVmName) {
        issues.push("Set `parallelsBaseVmName` to the stopped Parallels base VM grclanker should clone.");
      } else {
        const vm = getParallelsVmInfo(baseVmName);
        if (!vm && process.platform === "darwin" && binaryExists("prlctl")) {
          issues.push(`Configured Parallels base VM "${baseVmName}" was not found in \`prlctl list -a\`.`);
        } else if (vm && vm.status !== "stopped") {
          issues.push(
            `Parallels base VM "${baseVmName}" is ${vm.status}. Use a stopped base VM so grclanker can clone it safely.`,
          );
        }
      }
    }
    if (!resolveParallelsAutoStart(settings)) {
      issues.push(
        "Set `parallelsAutoStart` to `true`. Disposable Parallels sandboxes must be booted automatically after cloning.",
      );
    }
    return issues;
  }

  return [];
}

export function detectComputeBackendStatuses(): ComputeBackendStatus[] {
  const sandboxInstalled = sandboxRuntimeInstalled();
  const dockerInstalled = binaryExists("docker");
  const dockerReady = dockerDaemonReachable();
  const parallelsInstalled = process.platform === "darwin" && binaryExists("prlctl");

  const statuses: ComputeBackendStatus[] = [
    {
      kind: "host",
      label: getComputeBackendLabel("host"),
      summary: COMPUTE_BACKEND_OPTIONS.host.summary,
      available: true,
      detail: "Built-in local execution is always available.",
    },
    {
      kind: "sandbox-runtime",
      label: getComputeBackendLabel("sandbox-runtime"),
      summary: COMPUTE_BACKEND_OPTIONS["sandbox-runtime"].summary,
      available: (process.platform === "darwin" || process.platform === "linux") && sandboxInstalled,
      detail: process.platform !== "darwin" && process.platform !== "linux"
        ? "sandbox-runtime backends require a macOS or Linux host."
        : sandboxInstalled
          ? "Found `@anthropic-ai/sandbox-runtime` in the local runtime."
          : "Install `@anthropic-ai/sandbox-runtime` to use this backend.",
    },
    {
      kind: "docker",
      label: getComputeBackendLabel("docker"),
      summary: COMPUTE_BACKEND_OPTIONS.docker.summary,
      available: dockerReady,
      detail: !dockerInstalled
        ? "Install Docker Desktop or Docker Engine to use this backend."
        : dockerReady
          ? "Found `docker` on PATH and the Docker daemon is reachable."
          : "Found `docker` on PATH, but the Docker daemon is not reachable.",
    },
    {
      kind: "parallels-vm",
      label: getComputeBackendLabel("parallels-vm"),
      summary: COMPUTE_BACKEND_OPTIONS["parallels-vm"].summary,
      available: parallelsInstalled,
      detail: process.platform !== "darwin"
        ? "Parallels VM backends require a macOS host."
        : parallelsInstalled
          ? "Found `prlctl` on PATH."
          : "Install Parallels Desktop and ensure `prlctl` is available.",
    },
  ];

  return statuses;
}

export function isComputeBackendAvailable(kind: ComputeBackendKind): boolean {
  return detectComputeBackendStatuses().find((status) => status.kind === kind)?.available ?? false;
}
