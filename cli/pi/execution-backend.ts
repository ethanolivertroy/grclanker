import { spawn } from "node:child_process";

export type ExecutionBackendKind =
  | "host"
  | "sandbox-runtime"
  | "docker"
  | "parallels-vm"
  | "modal"
  | "runpod-pod"
  | "runpod-serverless"
  | "cloudflare-sandbox"
  | "vercel-sandbox";

export type RoutingBucket = "host" | "sandboxed" | "gpu-burst" | "persistent-remote";

export type NetworkPolicy = "default" | "deny-all" | { allowDomains: string[] };

export type WorkspaceMountMode = "ro" | "rw";

export type ExecutionMount = {
  localPath: string;
  remotePath: string;
  mode: WorkspaceMountMode;
};

export type ExecutionRequest = {
  sessionId: string;
  command: string[];
  cwd: string;
  env?: Record<string, string>;
  mounts?: ExecutionMount[];
  networkPolicy?: NetworkPolicy;
  timeoutMs?: number;
  interactive?: boolean;
  onData?: (chunk: Buffer) => void;
  signal?: AbortSignal;
};

export type ExecutionResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
  artifacts?: string[];
};

export type StageWorkspaceInput = {
  localPath: string;
  sessionId: string;
  mountMode?: WorkspaceMountMode;
};

export type StagedWorkspace = {
  sessionId: string;
  remotePath: string;
  detail: string;
};

export type ExecutionBackendCapabilities = {
  snapshot: boolean;
  restore: boolean;
  gpu: boolean;
  stageWorkspace: boolean;
  artifactSync: boolean;
  interactive: boolean;
};

export interface ExecutionBackend {
  readonly kind: ExecutionBackendKind;
  readonly capabilities: ExecutionBackendCapabilities;
  healthcheck(): Promise<void>;
  stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace>;
  exec(request: ExecutionRequest): Promise<ExecutionResult>;
  snapshot(sessionId: string): Promise<string>;
  restore(sessionId: string, snapshotId: string): Promise<void>;
  teardown(sessionId: string): Promise<void>;
}

export type CommandRunnerOptions = {
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  onData?: (chunk: Buffer) => void;
  signal?: AbortSignal;
};

export type CommandRunnerResult = {
  exitCode: number | null;
  stdout: string;
  stderr: string;
};

export type CommandRunner = (
  executable: string,
  args: string[],
  options?: CommandRunnerOptions,
) => Promise<CommandRunnerResult>;

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class ExecutionBackendError extends Error {
  constructor(message: string) {
    super(`Compute backend error: ${message}`);
    this.name = "ExecutionBackendError";
  }
}

export class ExecutionBackendUnsupportedError extends ExecutionBackendError {
  constructor(kind: ExecutionBackendKind, operation: string) {
    super(`${kind} does not support ${operation}.`);
    this.name = "ExecutionBackendUnsupportedError";
  }
}

export class ExecutionBackendNotAvailableError extends ExecutionBackendError {
  constructor(kind: ExecutionBackendKind, detail: string) {
    super(`${kind} is not available yet. ${detail}`);
    this.name = "ExecutionBackendNotAvailableError";
  }
}

const SECRET_ENV_KEYS = [
  "MODAL_TOKEN_SECRET",
  "MODAL_TOKEN_ID",
  "RUNPOD_API_KEY",
  "VERCEL_TOKEN",
  "CLOUDFLARE_API_TOKEN",
] as const;

export function redactSecrets(text: string, extraSecrets: Array<string | undefined> = []): string {
  let redacted = text;
  const secrets = [
    ...SECRET_ENV_KEYS.map((key) => process.env[key]),
    ...extraSecrets,
  ].filter((value): value is string => typeof value === "string" && value.trim().length >= 6);
  for (const secret of secrets) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/g, "$1[REDACTED]");
}

export function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new ExecutionBackendError(`Set ${name} in the environment before using this backend.`);
  }
  return value;
}

export function hasEnv(name: string): boolean {
  return Boolean(process.env[name]?.trim());
}

export function normalizeExitCode(exitCode: number | null): number {
  return typeof exitCode === "number" ? exitCode : 1;
}

export function buildShellCommand(command: string[]): string {
  return command.length === 1 ? command[0]! : command.map(quoteArg).join(" ");
}

function quoteArg(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

export function createProcessCommandRunner(): CommandRunner {
  return (executable, args, options = {}) =>
    new Promise<CommandRunnerResult>((resolvePromise, reject) => {
      const child = spawn(executable, args, {
        cwd: options.cwd,
        env: options.env ? { ...process.env, ...options.env } : process.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let timedOut = false;
      let timeoutHandle: NodeJS.Timeout | undefined;

      const kill = () => {
        try {
          child.kill("SIGKILL");
        } catch {
          // process already exited
        }
      };

      if (options.timeoutMs && options.timeoutMs > 0) {
        timeoutHandle = setTimeout(() => {
          timedOut = true;
          kill();
        }, options.timeoutMs);
      }

      const onAbort = () => kill();
      options.signal?.addEventListener("abort", onAbort, { once: true });

      child.stdout?.on("data", (chunk: Buffer) => {
        stdout.push(chunk);
        options.onData?.(chunk);
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        stderr.push(chunk);
        options.onData?.(chunk);
      });
      child.on("error", (error) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        options.signal?.removeEventListener("abort", onAbort);
        reject(error);
      });
      child.on("close", (code) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        options.signal?.removeEventListener("abort", onAbort);
        if (options.signal?.aborted) {
          reject(new Error("aborted"));
          return;
        }
        if (timedOut) {
          reject(new Error(`timeout:${Math.round((options.timeoutMs ?? 0) / 1000)}`));
          return;
        }
        resolvePromise({
          exitCode: code,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
        });
      });
    });
}

export function assertExhaustive(value: never): never {
  throw new Error(`Unhandled compute backend kind: ${String(value)}`);
}
