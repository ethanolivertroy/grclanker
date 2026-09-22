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
  /**
   * Every exec runs in a fresh container or a stateless job, so a filesystem change made by one
   * exec is invisible to the next. The runtime offers only bash on such a backend; read, write,
   * edit, ls, grep, and find stay on the local workspace instead of pretending to persist remotely.
   */
  oneShot: boolean;
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

// The constructor is the one point every adapter error passes through, so a message assembled
// from a provider body, a CLI's stderr, or a job error string is scrubbed even when the throw
// site forgot to. Subclasses inherit it through super().
export class ExecutionBackendError extends Error {
  constructor(message: string) {
    super(`Compute backend error: ${redactErrorMessage(message)}`);
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

// A remote resource the adapter created survived its removal command. The session that owns it
// stays tracked so the next teardown retries the removal, and the message names the resource so
// an operator can delete it by hand if the retries keep failing.
export class ExecutionBackendCleanupError extends ExecutionBackendError {
  readonly resource: string;

  constructor(kind: ExecutionBackendKind, resource: string, detail: string) {
    super(`${kind} could not remove ${resource}. ${detail}`);
    this.name = "ExecutionBackendCleanupError";
    this.resource = redactErrorMessage(resource);
  }
}

const SECRET_ENV_KEYS = [
  "MODAL_TOKEN_SECRET",
  "MODAL_TOKEN_ID",
  "RUNPOD_API_KEY",
  "VERCEL_TOKEN",
  "CLOUDFLARE_API_TOKEN",
] as const;

const PEM_BEGIN_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const PEM_END_PATTERN = /-----END [A-Z ]*PRIVATE KEY-----/;
const PEM_REDACTION = "[REDACTED PRIVATE KEY]";

// A BEGIN marker whose END never arrived, together with the contiguous run of body-shaped lines
// after it (base64 of 16 or more characters, each ending the line) and a trailing base64 fragment
// cut off by the end of the text. Stops at the first line that is not body shaped, so ordinary
// output after a truncated key survives. Group 1 is the body, group 2 the line break after it.
const PEM_OPEN_BLOCK_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----((?:\r?\n[A-Za-z0-9+/=]{16,}(?=\r?\n|$))*(?:\r?\n[A-Za-z0-9+/=]{1,15}$)?)(\r?\n)?/g;
const PEM_OPEN_REDACTION = "[REDACTED PRIVATE KEY: unterminated block]";
const PEM_OPEN_BODY_REDACTION = "[REDACTED PRIVATE KEY: unterminated block, body withheld]";

// Scrubs text that may hold a PEM block whose END never arrived: complete blocks go first through
// the regular patterns, then any surviving marker is replaced together with its body. The
// replacement says when body text was withheld, because that truncation is otherwise invisible.
export function redactUnterminatedPemBlocks(text: string): string {
  return text.replace(PEM_OPEN_BLOCK_PATTERN, (_match, body: string, lineBreak: string | undefined) =>
    `${body.length > 0 ? PEM_OPEN_BODY_REDACTION : PEM_OPEN_REDACTION}${lineBreak ?? ""}`);
}

// Any scheme://... substring, unanchored, so a URL embedded mid-sentence in a provider error
// message is found. The character class stops at whitespace, quotes, angle brackets, and closing
// punctuation so the surrounding text survives.
const URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{},;]+/gi;
const URL_USERINFO_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^/@]+@/i;

// Credentials travel in URLs as userinfo, query values, and fragments. Every query value is
// redacted (not only credential-named parameters) because a session token does not announce
// itself by name; the parameter names and the path stay so the URL remains recognizable.
function redactUrl(url: string): string {
  const cut = url.search(/[?#]/);
  const base = (cut === -1 ? url : url.slice(0, cut)).replace(URL_USERINFO_PATTERN, "$1[REDACTED]@");
  if (cut === -1) return base;
  const rest = url.slice(cut);
  const hash = rest.indexOf("#");
  const query = hash === -1 ? rest : rest.slice(0, hash);
  const fragment = hash === -1 ? "" : "#[REDACTED]";
  const redactedQuery = query.length <= 1
    ? query
    : `?${query.slice(1).split("&").map((part) => (part.includes("=") ? `${part.slice(0, part.indexOf("="))}=[REDACTED]` : "[REDACTED]")).join("&")}`;
  return `${base}${redactedQuery}${fragment}`;
}

// A credential-named header or parameter followed by its value, in header (`X-Api-Key: v`),
// assignment (`token=v`), or JSON (`"session": "v"`) form. Quoted values keep their quotes so
// JSON stays parseable.
const CREDENTIAL_FIELD_PATTERN = /\b((?:x-)?(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|sessionid|session|sid|cookie|client[_-]?secret|secret|password|passwd|token|signature|sig)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s;,&"'<>]{4,})/gi;

function redactCredentialField(_match: string, prefix: string, value: string): string {
  const quote = value.startsWith("\"") || value.startsWith("'") ? value[0] : "";
  return `${prefix}${quote}[REDACTED]${quote}`;
}

type SecretPattern = {
  pattern: RegExp;
  replacement: string | ((match: string, ...groups: string[]) => string);
};

// Secondary, format-based patterns for the providers this runtime talks to. The primary
// mechanism is the exact values of the credential environment variables above; these
// patterns catch the same credentials when they arrive from a remote (for example a
// container echoing its own environment, or an upstream error page quoting request headers)
// without ever being set locally.
const SECRET_PATTERNS: ReadonlyArray<SecretPattern> = [
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: PEM_REDACTION },
  { pattern: /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/g, replacement: "$1[REDACTED]" },
  { pattern: /\brpa_[A-Za-z0-9]{16,}\b/g, replacement: "[REDACTED]" },
  { pattern: /\ba[ks]-[A-Za-z0-9]{12,}\b/g, replacement: "[REDACTED]" },
  {
    pattern: /((?:RUNPOD_API_KEY|MODAL_TOKEN_ID|MODAL_TOKEN_SECRET|VERCEL_TOKEN|CLOUDFLARE_API_TOKEN)=)(?:"[^"]*"|'[^']*'|[^\s'"]+)/g,
    replacement: "$1[REDACTED]",
  },
  { pattern: URL_PATTERN, replacement: redactUrl },
  { pattern: /\b((?:set-)?cookie\s*:\s*)[^\r\n<>"']+/gi, replacement: "$1[REDACTED]" },
  { pattern: CREDENTIAL_FIELD_PATTERN, replacement: redactCredentialField },
];

function applySecretPattern(text: string, { pattern, replacement }: SecretPattern): string {
  return typeof replacement === "string" ? text.replace(pattern, replacement) : text.replace(pattern, replacement);
}

export function redactSecrets(text: string, extraSecrets: Array<string | undefined> = []): string {
  let redacted = text;
  const secrets = [
    ...SECRET_ENV_KEYS.map((key) => process.env[key]),
    ...extraSecrets,
  ].filter((value): value is string => typeof value === "string" && value.trim().length >= 6);
  for (const secret of secrets) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  for (const entry of SECRET_PATTERNS) {
    redacted = applySecretPattern(redacted, entry);
  }
  return redacted;
}

// An HTML document has no place in an error message: it is an upstream error page, and the
// cookies or keys it may quote come in shapes no pattern can promise to know.
const HTML_DOCUMENT_PATTERN = /<!doctype\s+html[^>]*>[\s\S]*?(?:<\/html\s*>|$)|<html\b[\s\S]*?(?:<\/html\s*>|$)/gi;

// The single scrub for text that becomes an error message: every ExecutionBackendError runs its
// message through this in the constructor, and the CLI applies it to messages it re-throws. It
// withholds HTML documents wholesale, then applies the same value and pattern redaction as
// command output, then neutralizes a truncated PEM block.
export function redactErrorMessage(message: string): string {
  const withoutHtml = message.replace(HTML_DOCUMENT_PATTERN, (document) => `[HTML document withheld (${document.length} chars)]`);
  return redactUnterminatedPemBlocks(redactSecrets(withoutHtml));
}

function parseJson(text: string): unknown | undefined {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

const MESSAGE_FIELDS = ["error", "message", "detail", "details", "reason", "title", "description"] as const;
const MAX_QUOTED_DETAIL = 400;

function truncateDetail(text: string): string {
  const trimmed = text.trim();
  return trimmed.length > MAX_QUOTED_DETAIL ? `${trimmed.slice(0, MAX_QUOTED_DETAIL)}... (${trimmed.length} chars)` : trimmed;
}

// Describes a parsed JSON value for an error message by quoting only its message-bearing string
// fields (which the ExecutionBackendError constructor then scrubs) and naming the other keys, so
// an unexpected field carrying a credential is never copied into the message.
export function summarizeJsonBody(value: unknown, depth = 0): string {
  if (value === undefined || value === null) return "no detail";
  if (typeof value === "string") return truncateDetail(value) || "empty string";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `JSON array with ${value.length} entries`;
  if (typeof value !== "object") return "no detail";
  const record = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const field of MESSAGE_FIELDS) {
    const entry = record[field];
    if (typeof entry === "string" && entry.trim().length > 0) {
      parts.push(`${field}: ${truncateDetail(entry)}`);
    } else if (depth === 0 && entry && typeof entry === "object" && !Array.isArray(entry)) {
      parts.push(`${field}: ${summarizeJsonBody(entry, depth + 1)}`);
    }
  }
  if (parts.length > 0) return parts.join("; ");
  const keys = Object.keys(record);
  return keys.length > 0 ? `JSON body with keys ${keys.join(", ")}` : "empty JSON body";
}

export type ProviderBody = {
  json?: unknown;
  detail: string;
};

// Reads a provider response body once and describes it for error messages. A body that does not
// parse as JSON is reported by content type and length only, never quoted, because an upstream
// error page (a 502 from a gateway, a login page) can carry session cookies or keys in shapes no
// pattern knows. JSON bodies are summarized by summarizeJsonBody.
export async function readProviderBody(response: Response): Promise<ProviderBody> {
  const text = await response.text();
  const json = parseJson(text);
  if (json === undefined) {
    const contentType = response.headers.get("content-type")?.split(";")[0].trim() || "unknown content type";
    return { detail: `non-JSON ${contentType} body (${Buffer.byteLength(text, "utf8")} bytes) withheld` };
  }
  return { json, detail: summarizeJsonBody(json) };
}

// Host and path of a request URL for error messages: no query, no fragment, no userinfo.
export function describeEndpoint(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.host}${parsed.pathname}`;
  } catch {
    return "the provider endpoint";
  }
}

export type RedactingSink = {
  write: (chunk: Buffer) => void;
  end: () => void;
};

// Upper bound on text the sink holds back before it flushes regardless of an open block or a
// missing newline. Real private keys are a few KB, so a block still open at this size is not
// a key; flushing it (marker and body-shaped lines withheld, everything else kept) keeps a
// hostile stream from pinning memory.
export const REDACTING_SINK_MAX_HELD_CHARS = 256 * 1024;

// How far back the incremental END search re-reads, so an END marker straddling two writes is
// still found. Longer than any realistic "-----END <label> PRIVATE KEY-----" marker.
const PEM_MARKER_OVERLAP = 128;

// A PEM block that cannot be flushed yet: `closedAt` is where it ends once its END marker has
// arrived (the block still crosses the flush boundary), undefined while END is missing.
type HeldPemBlock = { start: number; searched: number; closedAt?: number };

// Finds the first PEM private key block that starts at or after `cursor` and before `boundary`
// and is not complete before the boundary.
function findUnflushablePemBlock(text: string, boundary: number, cursor = 0): HeldPemBlock | undefined {
  while (cursor < boundary) {
    const begin = PEM_BEGIN_PATTERN.exec(text.slice(cursor, boundary));
    if (!begin) return undefined;
    const start = cursor + begin.index;
    const bodyStart = start + begin[0].length;
    const end = PEM_END_PATTERN.exec(text.slice(bodyStart));
    if (!end) return { start, searched: text.length };
    const blockEnd = bodyStart + end.index + end[0].length;
    if (blockEnd > boundary) return { start, searched: text.length, closedAt: blockEnd };
    cursor = blockEnd;
  }
  return undefined;
}

// The Bearer pattern allows whitespace (including a newline) between the word and the token, so
// a line that ends in "Bearer" is held until the next line arrives. Only the tail of the
// flushable text can match, so only the tail is examined.
const BEARER_TAIL_WINDOW = 64;

function findDanglingBearerStart(text: string, boundary: number): number | undefined {
  const windowStart = Math.max(0, boundary - BEARER_TAIL_WINDOW);
  const tail = /Bearer\s*$/.exec(text.slice(windowStart, boundary));
  return tail ? windowStart + tail.index : undefined;
}

// Streams are redacted per completed line so a credential split across two chunks is still
// caught, and the sink never flushes through an open PEM block: from a `-----BEGIN ... PRIVATE
// KEY-----` marker onward, text is held until the matching END marker arrives (so a
// line-at-a-time producer cannot leak the header and body one line at a time), until `end()`,
// or until the held buffer reaches the cap. A block still open at that point (a truncated key
// file, a command killed by its timeout mid-key) is flushed with its marker and body-shaped lines
// withheld, so neither the header nor the key material can be emitted verbatim.
export function createRedactingSink(
  onData: ((chunk: Buffer) => void) | undefined,
  extraSecrets: Array<string | undefined> = [],
): RedactingSink {
  const decoder = new StringDecoder("utf8");
  let pending = "";
  // Set while a PEM block is being held: where it starts in `pending`, how far the END search has
  // already looked (so a long body is not rescanned on every write), and once END has arrived,
  // where the block ends (it stays held until the line break after END lands).
  let heldBlock: HeldPemBlock | undefined;

  const emit = (text: string) => {
    if (text.length === 0 || !onData) return;
    onData(Buffer.from(redactSecrets(text, extraSecrets), "utf8"));
  };

  const flushEverything = () => {
    heldBlock = undefined;
    if (pending.length === 0 || !onData) {
      pending = "";
      return;
    }
    const scrubbed = redactUnterminatedPemBlocks(redactSecrets(pending, extraSecrets));
    pending = "";
    onData(Buffer.from(scrubbed, "utf8"));
  };

  // Returns the index from which `pending` must be held back, or undefined when everything up to
  // `boundary` may be flushed.
  const findHoldStart = (boundary: number): number | undefined => {
    let scanFrom = 0;
    if (heldBlock) {
      if (heldBlock.closedAt === undefined) {
        const from = Math.max(heldBlock.start, heldBlock.searched - PEM_MARKER_OVERLAP);
        const end = PEM_END_PATTERN.exec(pending.slice(from));
        if (!end) {
          heldBlock.searched = pending.length;
          return heldBlock.start;
        }
        heldBlock.closedAt = from + end.index + end[0].length;
      }
      if (heldBlock.closedAt > boundary) return heldBlock.start;
      scanFrom = heldBlock.closedAt;
      heldBlock = undefined;
    }
    heldBlock = findUnflushablePemBlock(pending, boundary, scanFrom);
    return heldBlock?.start;
  };

  const flushCompletedLines = () => {
    const lastNewline = pending.lastIndexOf("\n");
    if (lastNewline === -1) return;
    let boundary = lastNewline + 1;
    const holdStart = findHoldStart(boundary);
    if (holdStart !== undefined) boundary = holdStart;
    const danglingBearer = findDanglingBearerStart(pending, boundary);
    if (danglingBearer !== undefined) boundary = danglingBearer;
    if (boundary === 0) return;
    emit(pending.slice(0, boundary));
    pending = pending.slice(boundary);
    if (heldBlock) {
      heldBlock.start -= boundary;
      heldBlock.searched -= boundary;
      if (heldBlock.closedAt !== undefined) heldBlock.closedAt -= boundary;
    }
  };

  return {
    write(chunk) {
      if (!onData) return;
      const text = decoder.write(chunk);
      if (text.length === 0) return;
      pending += text;
      // Only a newline can complete a flush group, so chunks without one skip the scan and the
      // string flattening it forces.
      if (text.includes("\n")) flushCompletedLines();
      if (pending.length >= REDACTING_SINK_MAX_HELD_CHARS) flushEverything();
    },
    end() {
      pending += decoder.end();
      flushEverything();
    },
  };
}

// The returned result is scrubbed exactly as the sink scrubs the stream at end(): complete
// patterns first, then a PEM block whose END never arrived is withheld with its body, so the two
// halves of the guard never disagree about the same output.
function redactCompletedOutput(text: string, extraSecrets: Array<string | undefined>): string {
  return redactUnterminatedPemBlocks(redactSecrets(text, extraSecrets));
}

export function redactExecutionResult(result: ExecutionResult, extraSecrets: Array<string | undefined> = []): ExecutionResult {
  return {
    ...result,
    stdout: redactCompletedOutput(result.stdout, extraSecrets),
    stderr: redactCompletedOutput(result.stderr, extraSecrets),
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
