/**
 * Bounded retries for the Azure and GCP REST clients. A request is attempted at most CLOUD_MAX_RETRIES + 1 times,
 * each attempt limited to the policy's timeout. A 429 or 5xx response, a transport failure, or an attempt that runs
 * past its timeout is retried after the response's Retry-After delay or the exponential backoff, and whatever the
 * last attempt produced comes back with the attempt count, so the client fails closed on it and says how hard it
 * tried. The tool call's abort is never retried: it ends the request, or the wait before the next attempt, at once.
 */
import { abortableSleep, rethrowIfAborted, ToolCallAbortedError } from "./abort.js";

export const CLOUD_RETRYABLE_STATUSES: readonly number[] = Object.freeze([429, 500, 502, 503, 504]);
export const CLOUD_MAX_RETRIES = 3;
export const CLOUD_REQUEST_TIMEOUT_MS = 30_000;
export const CLOUD_RETRY_BASE_DELAY_MS = 1_000;
export const CLOUD_MAX_RETRY_WAIT_MS = 30_000;

export interface CloudRetryPolicy {
  /** Waits before the next attempt; rejects with ToolCallAbortedError when the tool call aborts. */
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => Date;
  readonly requestTimeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface CloudRetryOptions {
  signal?: AbortSignal;
  sleepImpl?: (ms: number) => Promise<void>;
  now?: () => Date;
  requestTimeoutMs?: number;
}

export function cloudRetryPolicy(options: CloudRetryOptions = {}): CloudRetryPolicy {
  const requestTimeoutMs = options.requestTimeoutMs ?? CLOUD_REQUEST_TIMEOUT_MS;
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
    throw new Error(`requestTimeoutMs must be a positive number of milliseconds, not ${requestTimeoutMs}.`);
  }
  return {
    sleep: abortableSleep(options.signal, options.sleepImpl),
    now: options.now ?? (() => new Date()),
    requestTimeoutMs,
    signal: options.signal,
  };
}

const DELTA_SECONDS = /^\d+$/;
// The three HTTP-date forms of RFC 9110 section 5.6.7: IMF-fixdate, the obsolete RFC 850 form, and asctime.
const IMF_OR_RFC850_DATE = /^[A-Z][a-z]{2,8}, \d{2}[ -][A-Z][a-z]{2}[ -]\d{2}(?:\d{2})? \d{2}:\d{2}:\d{2} GMT$/;
const ASCTIME_DATE = /^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}$/;

/**
 * The wait a Retry-After value asks for, in milliseconds: delta-seconds, or an HTTP-date measured from `now` (a date
 * already past asks for none). Undefined when the header is absent or is neither form, so the backoff applies.
 */
export function retryAfterMs(value: string | null, now: Date): number | undefined {
  const text = value?.trim();
  if (!text) return undefined;
  if (DELTA_SECONDS.test(text)) return Math.min(Number(text) * 1000, Number.MAX_SAFE_INTEGER);
  // asctime carries no zone but is UTC by definition, where Date.parse would read it as local time.
  const at = IMF_OR_RFC850_DATE.test(text) ? Date.parse(text) : ASCTIME_DATE.test(text) ? Date.parse(`${text} GMT`) : Number.NaN;
  return Number.isNaN(at) ? undefined : Math.max(0, at - now.getTime());
}

/** The wait before retry `retry` (1-based) when the response named none: 1 s, 2 s, 4 s, capped at CLOUD_MAX_RETRY_WAIT_MS. */
export function backoffDelayMs(retry: number): number {
  return Math.min(CLOUD_RETRY_BASE_DELAY_MS * 2 ** (retry - 1), CLOUD_MAX_RETRY_WAIT_MS);
}

export type CloudExchange =
  | { kind: "response"; response: Response; text: string; attempts: number; refusedRetryAfterMs?: number }
  | { kind: "failure"; error: unknown; timedOut: boolean; attempts: number };

/**
 * Sends one request with bounded retries and reads its body. A response that is not retryable returns at once, as
 * does a retryable one that arrives on the last attempt or whose Retry-After asks for more than
 * CLOUD_MAX_RETRY_WAIT_MS (`refusedRetryAfterMs`, with no wait). A transport failure or an attempt past the timeout
 * is retried the same way and comes back as a failure once the attempts run out; any other rejection comes back as a
 * failure at once. The tool call's abort rejects with ToolCallAbortedError and is never returned.
 */
export async function exchangeWithRetries(
  fetchImpl: (url: string, init: RequestInit) => Promise<Response>,
  url: string,
  init: RequestInit,
  policy: CloudRetryPolicy,
): Promise<CloudExchange> {
  for (let attempt = 1; ; attempt += 1) {
    const sent = await sendOnce(fetchImpl, url, init, policy.requestTimeoutMs);
    if (policy.signal?.aborted) throw new ToolCallAbortedError(policy.signal);
    let wait: number;
    if (sent.kind === "failure") {
      if (attempt > CLOUD_MAX_RETRIES || !(sent.timedOut || isTransportFailure(sent.error))) return { ...sent, attempts: attempt };
      wait = backoffDelayMs(attempt);
    } else {
      if (!CLOUD_RETRYABLE_STATUSES.includes(sent.response.status) || attempt > CLOUD_MAX_RETRIES) return { ...sent, attempts: attempt };
      const asked = retryAfterMs(sent.response.headers.get("retry-after"), policy.now());
      if (asked !== undefined && asked > CLOUD_MAX_RETRY_WAIT_MS) return { ...sent, attempts: attempt, refusedRetryAfterMs: asked };
      wait = asked ?? backoffDelayMs(attempt);
    }
    await policy.sleep(wait);
  }
}

type SentOnce =
  | { kind: "response"; response: Response; text: string }
  | { kind: "failure"; error: unknown; timedOut: boolean };

/** One attempt: the request and its body, both inside the attempt's timeout, whose timer is cleared before any retry wait. */
async function sendOnce(
  fetchImpl: (url: string, init: RequestInit) => Promise<Response>,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<SentOnce> {
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new DOMException(`The request did not complete within ${timeoutMs} ms.`, "TimeoutError")), timeoutMs);
  try {
    const response = await beforeDeadline(fetchImpl(url, { ...init, signal: deadline.signal }), deadline.signal);
    // An error status is already the outcome, so a body cut off after it does not turn it into a transport failure.
    const text = response.ok
      ? await beforeDeadline(response.text(), deadline.signal)
      : await beforeDeadline(response.text(), deadline.signal).catch(() => "");
    return { kind: "response", response, text };
  } catch (error) {
    rethrowIfAborted(error);
    return { kind: "failure", error, timedOut: deadline.signal.aborted };
  } finally {
    clearTimeout(timer);
  }
}

/** Settles as `work` does unless `deadline` fires first, so a transport or body stream that ignores its signal still times out. */
function beforeDeadline<T>(work: T | Promise<T>, deadline: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onTimeout = () => reject(deadline.reason);
    if (deadline.aborted) onTimeout();
    else deadline.addEventListener("abort", onTimeout, { once: true });
    Promise.resolve(work).then(
      (value) => {
        deadline.removeEventListener("abort", onTimeout);
        resolve(value);
      },
      (error: unknown) => {
        deadline.removeEventListener("abort", onTimeout);
        reject(error);
      },
    );
  });
}

/** fetch rejects with a TypeError when the network fails (DNS, TLS, a reset connection, a body cut off mid-stream); a lower layer's own timeout is a TimeoutError. */
function isTransportFailure(error: unknown): boolean {
  return error instanceof TypeError || (error instanceof Error && error.name === "TimeoutError");
}

/** " after 4 attempts" once a request was retried, so a failure says how hard the client tried. */
export function attemptsNote(attempts: number): string {
  return attempts > 1 ? ` after ${attempts} attempts` : "";
}

/** The attempts note, plus why the retries stopped early when the server asked for a wait above the limit. */
export function retryStopNote(exchange: { attempts: number; refusedRetryAfterMs?: number }): string {
  const refused = exchange.refusedRetryAfterMs === undefined
    ? ""
    : ` (the server asked to retry after ${formatWait(exchange.refusedRetryAfterMs)}, more than the ${formatWait(CLOUD_MAX_RETRY_WAIT_MS)} limit)`;
  return `${attemptsNote(exchange.attempts)}${refused}`;
}

/**
 * The access-check note for probes whose retries ran out without an answer about access (throttling, a service fault,
 * or no response): whether those surfaces are readable is unknown, which is not the same as denied.
 */
export function unansweredProbesNote(names: readonly string[]): string[] {
  if (names.length === 0) return [];
  const which = names.length === 1 ? "that surface is" : "those surfaces are";
  return [`This check is incomplete: the probes for ${names.join(", ")} ran out of retries without an answer (each surface records its last error), so whether ${which} readable is unknown.`];
}

/** What an attempt that ran past its timeout records, worded like the TimeoutError fetch raises for its own timeouts. */
export function timeoutReason(timeoutMs: number): string {
  return `TimeoutError: the request did not complete within ${formatWait(timeoutMs)}`;
}

function formatWait(ms: number): string {
  return ms >= 1000 ? `${Math.ceil(ms / 1000)} s` : `${Math.ceil(ms)} ms`;
}

/** The retry contract as the Azure and GCP specs state it, built from the constants the clients run on. */
export const CLOUD_RETRY_POLICY_TEXT = [
  `Retry ${CLOUD_RETRYABLE_STATUSES.join(", ")} responses, transport failures, and attempts that run past the ${formatWait(CLOUD_REQUEST_TIMEOUT_MS)} per-request timeout up to ${CLOUD_MAX_RETRIES} times (${CLOUD_MAX_RETRIES + 1} attempts in all), token requests included.`,
  `Wait the Retry-After delay when the response gives one (delta-seconds or HTTP-date), otherwise ${[1, 2, 3].map((retry) => formatWait(backoffDelayMs(retry))).join(", ")}.`,
  `A Retry-After above ${formatWait(CLOUD_MAX_RETRY_WAIT_MS)} ends the retries at once, and the error names the wait the server asked for.`,
  "A read whose retries run out is unreadable, and its error names the last status or failure and the attempt count; a list that fails on a later page keeps none of its earlier pages.",
].join(" ");
