import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { cpus, totalmem } from "node:os";
import {
  describeModalCredentialSource,
  detectModalCredentials,
  isModalCredentialSourceUsable,
} from "./backends/modal-profile.js";
import {
  assertExhaustive,
  hasEnv,
  type ExecutionBackendKind,
  type NetworkPolicy,
  type RoutingBucket,
  type WorkspaceMountMode,
} from "./execution-backend.js";
import { quoteForBash } from "./shell.js";
import type { GrclankerSettings } from "./settings.js";

const require = createRequire(import.meta.url);

export type ComputeBackendKind = ExecutionBackendKind;

export type ComputeProfile = "local-host" | "isolated-local" | "gpu-burst" | "persistent-remote";

export type ComputeDefaults = {
  networkPolicy: NetworkPolicy;
  workspaceMountMode: WorkspaceMountMode;
};

export type ComputeBackendShipState = "implemented" | "stub";

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
export const DEFAULT_COMPUTE_DEFAULTS: ComputeDefaults = {
  networkPolicy: "default",
  workspaceMountMode: "rw",
};
type ComputeBackendMetadata = {
  label: string;
  summary: string;
  bucket: RoutingBucket;
  shipState: ComputeBackendShipState;
  credentialEnv: readonly string[];
};

const COMPUTE_BACKEND_OPTIONS: Record<ComputeBackendKind, ComputeBackendMetadata> = {
  host: {
    label: "Host",
    summary: "run directly in the current shell on this machine",
    bucket: "host",
    shipState: "implemented",
    credentialEnv: [],
  },
  "sandbox-runtime": {
    label: "sandbox-runtime",
    summary: "wrap tool execution in a local filesystem/network sandbox",
    bucket: "sandboxed",
    shipState: "implemented",
    credentialEnv: [],
  },
  docker: {
    label: "Docker",
    summary: "run work inside an isolated local container",
    bucket: "sandboxed",
    shipState: "implemented",
    credentialEnv: [],
  },
  "parallels-vm": {
    label: "Parallels VM",
    summary: "run work inside a disposable Parallels sandbox deployed from a template or stopped base VM",
    bucket: "sandboxed",
    shipState: "implemented",
    credentialEnv: [],
  },
  modal: {
    label: "Modal",
    summary: "run one-shot commands in a Modal container through the modal CLI, optionally with GPUs",
    bucket: "gpu-burst",
    shipState: "implemented",
    credentialEnv: ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"],
  },
  "runpod-pod": {
    label: "RunPod Pod",
    summary: "run commands over SSH inside a persistent RunPod pod you already own",
    bucket: "persistent-remote",
    shipState: "implemented",
    credentialEnv: ["RUNPOD_API_KEY", "RUNPOD_POD_ID"],
  },
  "runpod-serverless": {
    label: "RunPod Serverless",
    summary: "dispatch stateless jobs to a RunPod serverless endpoint running the grclanker worker contract",
    bucket: "gpu-burst",
    shipState: "implemented",
    credentialEnv: ["RUNPOD_API_KEY", "RUNPOD_ENDPOINT_ID"],
  },
  "cloudflare-sandbox": {
    label: "Cloudflare Sandbox",
    summary: "remote CPU-only sandbox embedded in a Cloudflare Worker (not yet available)",
    bucket: "sandboxed",
    shipState: "stub",
    credentialEnv: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  },
  "vercel-sandbox": {
    label: "Vercel Sandbox",
    summary: "remote CPU-only sandbox on Vercel (not yet available)",
    bucket: "sandboxed",
    shipState: "stub",
    credentialEnv: ["VERCEL_TOKEN", "VERCEL_TEAM_ID", "VERCEL_PROJECT_ID"],
  },
};

const PROFILE_BUCKETS: Record<ComputeProfile, RoutingBucket> = {
  "local-host": "host",
  "isolated-local": "sandboxed",
  "gpu-burst": "gpu-burst",
  "persistent-remote": "persistent-remote",
};

// Derived from the Record keys so a new ExecutionBackendKind or ComputeProfile union member
// fails compilation until its metadata entry exists; normalization and env list then pick it up.
export const COMPUTE_BACKEND_KINDS: readonly ComputeBackendKind[] = Object.keys(
  COMPUTE_BACKEND_OPTIONS,
) as ComputeBackendKind[];
export const COMPUTE_PROFILES: readonly ComputeProfile[] = Object.keys(PROFILE_BUCKETS) as ComputeProfile[];

export function isComputeBackendKind(value: unknown): value is ComputeBackendKind {
  return typeof value === "string" && (COMPUTE_BACKEND_KINDS as readonly string[]).includes(value);
}

export function isComputeProfile(value: unknown): value is ComputeProfile {
  return typeof value === "string" && (COMPUTE_PROFILES as readonly string[]).includes(value);
}

export function getRoutingBucket(kind: ComputeBackendKind): RoutingBucket {
  return COMPUTE_BACKEND_OPTIONS[kind].bucket;
}

export function getComputeBackendShipState(kind: ComputeBackendKind): ComputeBackendShipState {
  return COMPUTE_BACKEND_OPTIONS[kind].shipState;
}

export function getComputeBackendCredentialEnv(kind: ComputeBackendKind): readonly string[] {
  return COMPUTE_BACKEND_OPTIONS[kind].credentialEnv;
}

export function getProfileRoutingBucket(profile: ComputeProfile): RoutingBucket {
  return PROFILE_BUCKETS[profile];
}

export function getDefaultComputeProfile(kind: ComputeBackendKind): ComputeProfile {
  const bucket = getRoutingBucket(kind);
  switch (bucket) {
    case "host":
      return "local-host";
    case "sandboxed":
      return "isolated-local";
    case "gpu-burst":
      return "gpu-burst";
    case "persistent-remote":
      return "persistent-remote";
    default:
      return assertExhaustive(bucket);
  }
}

export function normalizeComputeProfile(
  value: unknown,
  kind: ComputeBackendKind,
): ComputeProfile {
  return isComputeProfile(value) ? value : getDefaultComputeProfile(kind);
}

export function normalizeNetworkPolicy(value: unknown): NetworkPolicy {
  if (value === "deny-all") return "deny-all";
  if (value && typeof value === "object" && Array.isArray((value as { allowDomains?: unknown }).allowDomains)) {
    const allowDomains = ((value as { allowDomains: unknown[] }).allowDomains)
      .filter((domain): domain is string => typeof domain === "string" && domain.trim().length > 0)
      .map((domain) => domain.trim());
    return { allowDomains };
  }
  return "default";
}

export function normalizeWorkspaceMountMode(value: unknown): WorkspaceMountMode {
  return value === "ro" ? "ro" : "rw";
}

export function normalizeComputeDefaults(value: unknown): ComputeDefaults {
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  return {
    networkPolicy: normalizeNetworkPolicy(record.networkPolicy),
    workspaceMountMode: normalizeWorkspaceMountMode(record.workspaceMountMode),
  };
}

export function resolveComputeProfile(settings: GrclankerSettings): ComputeProfile {
  return normalizeComputeProfile(settings.computeProfile, resolveComputeBackend(settings));
}

export function resolveComputeDefaults(settings: GrclankerSettings): ComputeDefaults {
  return normalizeComputeDefaults(settings.computeDefaults);
}

export function describeNetworkPolicy(policy: NetworkPolicy): string {
  if (policy === "default") return "default";
  if (policy === "deny-all") return "deny-all";
  return policy.allowDomains.length > 0
    ? `allow ${policy.allowDomains.join(", ")}`
    : "allow (no domains)";
}

export function getComputeProfileIssues(settings: GrclankerSettings): string[] {
  if (!("computeProfile" in settings) || settings.computeProfile === undefined) return [];
  const kind = resolveComputeBackend(settings);
  if (!isComputeProfile(settings.computeProfile)) {
    return [
      `Unknown computeProfile "${String(settings.computeProfile)}". Use one of: ${COMPUTE_PROFILES.join(", ")}.`,
    ];
  }
  const expectedBucket = getProfileRoutingBucket(settings.computeProfile);
  const actualBucket = getRoutingBucket(kind);
  if (expectedBucket !== actualBucket) {
    return [
      `computeProfile "${settings.computeProfile}" routes to the ${expectedBucket} bucket, but computeBackend "${kind}" belongs to the ${actualBucket} bucket.`,
    ];
  }
  return [];
}

export type ComputeBackendCredentialState = {
  ok: boolean;
  /** Names and sources only; never a credential value. */
  detail: string;
};

// Modal is the one kind whose CLI reads credentials from a profile file as well as the
// environment, so its state comes from the profile detector; every other remote kind is
// configured through environment variables alone.
export function getComputeBackendCredentialState(kind: ComputeBackendKind): ComputeBackendCredentialState {
  if (kind === "modal") {
    const source = detectModalCredentials();
    return { ok: isModalCredentialSourceUsable(source), detail: describeModalCredentialSource(source) };
  }
  const names = COMPUTE_BACKEND_OPTIONS[kind].credentialEnv;
  const missing = names.filter((name) => !hasEnv(name));
  return missing.length === 0
    ? { ok: true, detail: `Found ${names.join(", ")} in the environment.` }
    : { ok: false, detail: `Set ${missing.join(", ")} to use this backend.` };
}

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
  return isComputeBackendKind(value) ? value : DEFAULT_COMPUTE_BACKEND;
}

export function parseComputeBackendKind(value: string): ComputeBackendKind | undefined {
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
    case "modal":
      return "modal";
    case "runpod-pod":
    case "runpod":
      return "runpod-pod";
    case "runpod-serverless":
      return "runpod-serverless";
    case "cloudflare-sandbox":
    case "cloudflare":
      return "cloudflare-sandbox";
    case "vercel-sandbox":
    case "vercel":
      return "vercel-sandbox";
    default:
      return undefined;
  }
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
    case "host":
      return "local shell";
    case "sandbox-runtime":
      return "sandbox-runtime";
    case "docker":
      return "docker";
    case "parallels-vm":
      return "parallels vm";
    case "modal":
      return "modal";
    case "runpod-pod":
      return "runpod pod";
    case "runpod-serverless":
      return "runpod serverless";
    case "cloudflare-sandbox":
      return "cloudflare sandbox";
    case "vercel-sandbox":
      return "vercel sandbox";
    default:
      return assertExhaustive(kind);
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

  const shipState = getComputeBackendShipState(kind);
  if (shipState === "stub") {
    return [
      `${kind} is not yet available: no documented public HTTP API or CLI lifecycle surface is wired in. Pick another backend or wait for a later release.`,
    ];
  }

  const issues: string[] = [];
  if (kind === "modal") {
    const credentials = getComputeBackendCredentialState(kind);
    if (!credentials.ok) issues.push(credentials.detail);
    if (!binaryExists("modal")) {
      issues.push("Install the modal CLI (`pip install modal`) and run `modal setup`; grclanker drives Modal through `modal shell`.");
    }
  } else {
    issues.push(
      ...getComputeBackendCredentialEnv(kind)
        .filter((name) => !hasEnv(name))
        .map((name) => `Set ${name} in the environment to use ${kind}.`),
    );
  }
  if (kind === "runpod-pod" && !binaryExists("ssh")) {
    issues.push("Install an `ssh` client; grclanker executes inside RunPod pods over SSH.");
  }
  return issues;
}

function detectRemoteBackendStatus(kind: ComputeBackendKind, binary?: string): ComputeBackendStatus {
  const metadata = COMPUTE_BACKEND_OPTIONS[kind];
  if (metadata.shipState === "stub") {
    return {
      kind,
      label: metadata.label,
      summary: metadata.summary,
      available: false,
      detail: "Not yet available: the adapter fails fast until a documented lifecycle surface is wired in.",
    };
  }

  const credentials = getComputeBackendCredentialState(kind);
  const binaryOk = binary ? binaryExists(binary) : true;
  const detail = [
    credentials.detail,
    binary ? (binaryOk ? `Found \`${binary}\` on PATH.` : `Install \`${binary}\` to use this backend.`) : undefined,
  ].filter(Boolean).join(" ");
  return {
    kind,
    label: metadata.label,
    summary: metadata.summary,
    available: credentials.ok && binaryOk,
    detail,
  };
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
    detectRemoteBackendStatus("modal", "modal"),
    detectRemoteBackendStatus("runpod-pod", "ssh"),
    detectRemoteBackendStatus("runpod-serverless"),
    detectRemoteBackendStatus("cloudflare-sandbox"),
    detectRemoteBackendStatus("vercel-sandbox"),
  ];

  return statuses;
}

export function isComputeBackendAvailable(kind: ComputeBackendKind): boolean {
  return detectComputeBackendStatuses().find((status) => status.kind === kind)?.available ?? false;
}
