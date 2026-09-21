import { spawn, spawnSync } from "node:child_process";
import { StringDecoder } from "node:string_decoder";

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
  // Defaults to true: command output is scrubbed of credentials before it is streamed,
  // returned, or persisted. File operations that round-trip content (read, edit) set this
  // to false so a redaction marker is never written back into a file.
  redactOutput?: boolean;
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
  teardownSync?(sessionId: string): void;
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

export type CommandRunnerSync = (executable: string, args: string[]) => CommandRunnerResult;

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class ExecutionBackendError extends Error {
  constructor(message: string) {
    super(`Compute backend error: ${message}`);
    this.name = "ExecutionBackendError";
  }
}

export class ExecutionBackendTimeoutError extends ExecutionBackendError {
  readonly timeoutMs: number;

  constructor(kind: ExecutionBackendKind, detail: string, timeoutMs: number) {
    super(`${kind} timed out after ${Math.round(timeoutMs / 1000)}s: ${detail}`);
    this.name = "ExecutionBackendTimeoutError";
    this.timeoutMs = timeoutMs;
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

// Secondary, format-based patterns for the providers this runtime talks to. The primary
// mechanism is the exact values of the credential environment variables above; these
// patterns catch the same credentials when they arrive from a remote (for example a
// container echoing its own environment) without ever being set locally.
const SECRET_PATTERNS: ReadonlyArray<{ pattern: RegExp; replacement: string }> = [
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: "[REDACTED PRIVATE KEY]" },
  { pattern: /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/g, replacement: "$1[REDACTED]" },
  { pattern: /\brpa_[A-Za-z0-9]{16,}\b/g, replacement: "[REDACTED]" },
  { pattern: /\ba[ks]-[A-Za-z0-9]{12,}\b/g, replacement: "[REDACTED]" },
  {
    pattern: /((?:RUNPOD_API_KEY|MODAL_TOKEN_ID|MODAL_TOKEN_SECRET|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN)=)(?:"[^"]*"|'[^']*'|[^\s'"]+)/g,
    replacement: "$1[REDACTED]",
  },
];

export function redactSecrets(text: string, extraSecrets: Array<string | undefined> = []): string {
  let redacted = text;
  const secrets = [
    ...SECRET_ENV_KEYS.map((key) => process.env[key]),
    ...extraSecrets,
  ].filter((value): value is string => typeof value === "string" && value.trim().length >= 6);
  for (const secret of secrets) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  for (const { pattern, replacement } of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

export type RedactingSink = {
  write: (chunk: Buffer) => void;
  end: () => void;
};

// Streams are redacted per completed line so a credential split across two chunks is still
// caught; the trailing partial line is held until the next newline or `end()`.
export function createRedactingSink(
  onData: ((chunk: Buffer) => void) | undefined,
  extraSecrets: Array<string | undefined> = [],
): RedactingSink {
  const decoder = new StringDecoder("utf8");
  let pending = "";
  const emit = (text: string) => {
    if (text.length === 0 || !onData) return;
    onData(Buffer.from(redactSecrets(text, extraSecrets), "utf8"));
  };
  return {
    write(chunk) {
      if (!onData) return;
      pending += decoder.write(chunk);
      const lastNewline = pending.lastIndexOf("\n");
      if (lastNewline === -1) return;
      emit(pending.slice(0, lastNewline + 1));
      pending = pending.slice(lastNewline + 1);
    },
    end() {
      pending += decoder.end();
      emit(pending);
      pending = "";
    },
  };
}

export function redactExecutionResult(result: ExecutionResult, extraSecrets: Array<string | undefined> = []): ExecutionResult {
  return {
    ...result,
    stdout: redactSecrets(result.stdout, extraSecrets),
    stderr: redactSecrets(result.stderr, extraSecrets),
  };
}

export type ExecutionOutputGuard = {
  onData: ((chunk: Buffer) => void) | undefined;
  end: () => void;
  finish: (result: ExecutionResult) => ExecutionResult;
};

// Every adapter routes its command output through one guard so the streamed chunks and the
// returned result are scrubbed the same way, unless the caller opted out via redactOutput.
export function createExecutionOutputGuard(
  request: Pick<ExecutionRequest, "onData" | "redactOutput">,
  extraSecrets: Array<string | undefined> = [],
): ExecutionOutputGuard {
  if (request.redactOutput === false) {
    return { onData: request.onData, end: () => undefined, finish: (result) => result };
  }
  const sink = createRedactingSink(request.onData, extraSecrets);
  return {
    onData: request.onData ? sink.write : undefined,
    end: sink.end,
    finish: (result) => redactExecutionResult(result, extraSecrets),
  };
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

const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function assertSafeSessionId(sessionId: string): string {
  const trimmed = sessionId.trim();
  if (trimmed !== sessionId || !SESSION_ID_PATTERN.test(sessionId) || sessionId.includes("..")) {
    throw new ExecutionBackendError(
      `Session id ${JSON.stringify(sessionId)} is not a safe path segment; expected letters, digits, ".", "_" or "-" without "..".`,
    );
  }
  return sessionId;
}

export function createSessionId(): string {
  return `grclanker-${process.pid}-${Date.now().toString(36)}`;
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
        detached: process.platform !== "win32",
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let timedOut = false;
      let timeoutHandle: NodeJS.Timeout | undefined;

      const kill = () => {
        if (!child.pid) return;
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          try {
            child.kill("SIGKILL");
          } catch {
            // process already exited
          }
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

export function createProcessCommandRunnerSync(): CommandRunnerSync {
  return (executable, args) => {
    const result = spawnSync(executable, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return {
      exitCode: result.status,
      stdout: typeof result.stdout === "string" ? result.stdout : "",
      stderr: typeof result.stderr === "string" ? result.stderr : "",
    };
  };
}

export function assertExhaustive(value: never): never {
  throw new Error(`Unhandled compute backend kind: ${String(value)}`);
}
