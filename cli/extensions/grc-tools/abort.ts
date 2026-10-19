/**
 * Abort support for the domain tools' API collection. A tool passes its
 * execute signal to its API client, and the client wraps its fetch and its
 * retry wait with these helpers: aborting the call cancels the request in
 * flight, ends the wait before a retry, and fails every later request at once.
 * A credential lookup that asks a cloud CLI for a token runs its commands
 * through resolveWithCommands, so the abort kills the command in flight too.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

/** One tool call in flight, and whether it has published its output yet. */
export interface ToolCallState {
  committed: boolean;
}

// Per call rather than per signal: the calls of one turn can share a signal.
const runningCall = new AsyncLocalStorage<ToolCallState>();

/** Runs `run` as the tool call `call`, so output it commits is recorded on `call`. */
export function runToolCall<T>(call: ToolCallState, run: () => Promise<T>): Promise<T> {
  return runningCall.run(call, run);
}

/**
 * Records that the running tool call published its output. An abort that lands
 * afterwards can no longer undo the output, so the call reports it instead of
 * rejecting.
 */
export function markOutputCommitted(): void {
  const call = runningCall.getStore();
  if (call) call.committed = true;
}

/**
 * The tool call's abort signal fired. Its name is not "AbortError", so a client
 * that reports an AbortError from its own request timeout as a timeout never
 * reports an abort as one.
 */
export class ToolCallAbortedError extends Error {
  constructor(signal: AbortSignal) {
    super("The tool call was aborted.", { cause: signal.reason });
    this.name = "ToolCallAbortedError";
  }
}

/**
 * Rethrows `error` when it is the tool call's abort. A collector that records a
 * failed read and moves on calls this first, so an abort ends the collection at
 * the read it interrupted instead of failing every read after it.
 */
export function rethrowIfAborted(error: unknown): void {
  if (error instanceof ToolCallAbortedError) throw error;
}

/** A rejection handler for an optional read: it settles on `fallback` unless the read was aborted. */
export function fallbackUnlessAborted<T>(fallback: T): (error: unknown) => T {
  return (error) => {
    rethrowIfAborted(error);
    return fallback;
  };
}

/**
 * Settle as `promise` does, or reject with ToolCallAbortedError as soon as
 * `signal` aborts, whether or not the work behind `promise` stops.
 */
export function unlessAborted<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) {
    promise.catch(() => undefined);
    return Promise.reject(new ToolCallAbortedError(signal));
  }
  // A signal derived per call carries the listener, so requests in flight at once do not pile listeners onto the
  // tool call's signal, which Node reports as a leak past ten.
  const watched = AbortSignal.any([signal]);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new ToolCallAbortedError(signal));
    watched.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        watched.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        watched.removeEventListener("abort", onAbort);
        reject(signal.aborted ? new ToolCallAbortedError(signal) : error);
      },
    );
  });
}

type AnyFetch = (input: never, init?: RequestInit) => Promise<Response>;

/**
 * `fetchImpl`, cancelled by `signal` as well: each request gets a signal that
 * aborts on either its own (a client's timeout) or `signal`, a request made
 * after the abort is never sent, and the call rejects with
 * ToolCallAbortedError the moment `signal` aborts, even if `fetchImpl` ignores
 * its signal.
 */
export function abortableFetch<F extends AnyFetch>(fetchImpl: F, signal: AbortSignal | undefined): F {
  if (!signal) return fetchImpl;
  const send = fetchImpl as unknown as (input: unknown, init?: RequestInit) => Promise<Response>;
  const wrapped = async (input: unknown, init?: RequestInit): Promise<Response> => {
    if (signal.aborted) throw new ToolCallAbortedError(signal);
    const requestSignal = init?.signal ? AbortSignal.any([init.signal, signal]) : AbortSignal.any([signal]);
    return await unlessAborted(send(input, { ...init, signal: requestSignal }), signal);
  };
  return wrapped as unknown as F;
}

/**
 * A wait that ends when `signal` aborts, rejecting with ToolCallAbortedError.
 * Without `sleep` it waits on a timer the abort clears, so an aborted retry wait
 * does not hold the process open; an injected `sleep` is raced against the
 * signal instead.
 */
export function abortableSleep(
  signal: AbortSignal | undefined,
  sleep?: (ms: number) => Promise<void>,
): (ms: number) => Promise<void> {
  const wait = sleep ?? ((ms: number) => delay(ms, undefined, signal ? { signal: AbortSignal.any([signal]) } : {}));
  if (!signal) return wait;
  return (ms) => (signal.aborted ? Promise.reject(new ToolCallAbortedError(signal)) : unlessAborted(wait(ms), signal));
}

/** A command a credential lookup runs for its output, such as `az account show`. */
export interface CommandLookup {
  command: string;
  args: string[];
}

/**
 * Runs a lookup written as a generator that yields each command it needs and
 * resumes with that command's output. Each command runs as a child process
 * that aborting `signal` kills, where execFileSync would hold the event loop
 * until the command exited, so the abort went unseen while it ran. As with the
 * lookups' synchronous runners, a command that cannot start, exits non-zero,
 * prints nothing, or runs past `timeoutMs` resumes the lookup with undefined.
 */
export async function resolveWithCommands<T>(
  steps: Generator<CommandLookup, T, string | undefined>,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<T> {
  let step = steps.next();
  while (!step.done) step = steps.next(await commandOutput(step.value, timeoutMs, signal));
  return step.value;
}

function commandOutput({ command, args }: CommandLookup, timeoutMs: number, signal: AbortSignal | undefined): Promise<string | undefined> {
  if (signal?.aborted) return Promise.reject(new ToolCallAbortedError(signal));
  return new Promise((resolve, reject) => {
    const settle = (output: string | undefined) => (signal?.aborted ? reject(new ToolCallAbortedError(signal)) : resolve(output));
    try {
      const child = spawn(command, args, {
        stdio: ["ignore", "pipe", "ignore"],
        timeout: timeoutMs,
        signal: signal && AbortSignal.any([signal]),
      });
      let output = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        output += chunk;
      });
      child.on("error", () => settle(undefined));
      child.on("close", (code) => {
        const trimmed = output.trim();
        settle(code === 0 && trimmed.length > 0 ? trimmed : undefined);
      });
    } catch {
      resolve(undefined);
    }
  });
}
