/**
 * Abort support for the domain tools' API collection. A tool passes its
 * execute signal to its API client, and the client wraps its fetch and its
 * retry wait with these helpers: aborting the call cancels the request in
 * flight, ends the wait before a retry, and fails every later request at once.
 */
import { AsyncLocalStorage } from "node:async_hooks";
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
