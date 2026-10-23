/** Shared utilities for GRC extension tools */
import { AsyncLocalStorage } from "node:async_hooks";
import { abortableFetch, abortableSleep, rethrowIfAborted, ToolCallAbortedError, unlessAborted } from "./abort.js";
import { describeErrorBody, errorMessage, isCredentialKey, scrubErrorText } from "./hardening/index.js";

interface CacheEntry<T> {
  data: T;
  expires: number;
}

const cache = new Map<string, CacheEntry<unknown>>();

interface PersistencePolicy {
  persistentCaches: boolean;
}

/**
 * Per-call persistence policy. Tools that mirror public data sets to the
 * grclanker state directory consult it before touching the filesystem, so a
 * host that must not mutate the user's disk (an Agent SDK dry-run session)
 * can run those tools for real while keeping their caches in memory only.
 */
const persistencePolicy = new AsyncLocalStorage<PersistencePolicy>();

/** True unless the surrounding async context disabled on-disk caches. */
export function persistentCachesEnabled(): boolean {
  return persistencePolicy.getStore()?.persistentCaches !== false;
}

/** Run `fn` with on-disk caches disabled. In-memory caches still apply. */
export function runWithoutPersistentCaches<T>(fn: () => Promise<T>): Promise<T> {
  return persistencePolicy.run({ persistentCaches: false }, fn);
}

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_ATTEMPTS = 4;
const FIRST_RETRY_WAIT_MS = 1_000;
const MAX_RETRY_WAIT_MS = 30_000;
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

/** The clock and the retry wait behind the shared fetch helpers. */
export interface GrcFetchTiming {
  now: () => number;
  /** Unset in production, where the wait is a timer the tool call's abort clears. */
  sleep?: (ms: number) => Promise<void>;
}

const REAL_TIMING: GrcFetchTiming = { now: () => Date.now() };
let fetchTiming: GrcFetchTiming = REAL_TIMING;

/** How a failed response is retried: after the wait the server asked for, on the default backoff, or not at all. */
export type RetryPlan = { waitMs: number } | "backoff" | "stop";

export interface RetryingFetchOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Values removed from error text wherever they appear, such as a token the request sends. */
  secrets?: string[];
  beforeAttempt?: () => Promise<void>;
  retryPlan?: (response: Response, nowMs: number) => RetryPlan;
  /** A sentence added to the error for a failed response, such as how to lift a rate limit. */
  failureDetail?: (response: Response) => string | null;
}

type Attempt = { response: Response; body: string } | { error: string };

/**
 * The wait a Retry-After value asks for in ms: delta-seconds, or an HTTP date
 * measured from `nowMs`. Null when the value is absent or unreadable.
 */
export function retryAfterMs(value: string | null, nowMs: number): number | null {
  const text = value?.trim();
  if (!text) return null;
  if (/^\d+$/.test(text)) return Number(text) * 1000;
  // Date.parse also accepts bare numbers such as "1.5", which are not HTTP dates.
  if (!/[a-z]/i.test(text)) return null;
  const retryAt = Date.parse(text);
  return Number.isFinite(retryAt) ? Math.max(0, retryAt - nowMs) : null;
}

export function defaultRetryPlan(response: Response, nowMs: number): RetryPlan {
  if (!RETRYABLE_STATUSES.has(response.status)) return "stop";
  const waitMs = retryAfterMs(response.headers.get("retry-after"), nowMs);
  return waitMs === null ? "backoff" : { waitMs };
}

/** The request URL without its query string or fragment, for error text. */
function requestEndpoint(url: string): string {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

function backoffMs(attempt: number): number {
  return Math.min(FIRST_RETRY_WAIT_MS * 2 ** (attempt - 1), MAX_RETRY_WAIT_MS);
}

/**
 * The status code with the server's reason phrase, kept on the terms
 * describeFailedResponse keeps it: short plain text whose last word does not
 * name a credential. Anything else is server text the error does not need.
 */
function statusLine(response: Response): string {
  const reason = response.statusText.trim();
  const lastWord = /[A-Za-z0-9_.-]+$/.exec(reason)?.[0];
  const plain = /^[A-Za-z0-9 '._-]{1,64}$/.test(reason) && !(lastWord && isCredentialKey(lastWord));
  return plain ? `${response.status} ${reason}` : String(response.status);
}

async function attemptRequest(
  send: typeof fetch,
  url: string,
  options: RetryingFetchOptions,
): Promise<Attempt> {
  const timeout = new AbortController();
  const timer = setTimeout(
    () => timeout.abort(new DOMException(`timed out after ${REQUEST_TIMEOUT_MS} ms`, "TimeoutError")),
    REQUEST_TIMEOUT_MS,
  );
  try {
    const response = await send(url, { headers: options.headers, signal: timeout.signal });
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      return { response, body: "" };
    }
    return { response, body: await unlessAborted(response.text(), options.signal) };
  } catch (error) {
    rethrowIfAborted(error);
    if (options.signal?.aborted) throw new ToolCallAbortedError(options.signal);
    const timedOut = timeout.signal.aborted || (error instanceof Error && error.name === "TimeoutError");
    return { error: timedOut ? `timed out after ${REQUEST_TIMEOUT_MS} ms` : errorMessage(error, { secrets: options.secrets }) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * GET `url` and parse its JSON body. Each attempt has its own timeout; a 429,
 * a 5xx gateway or server error, a timeout, or a transport failure is retried
 * up to three times, after the wait Retry-After asks for or an exponential
 * backoff. A failure that cannot be retried, a server that asks for a wait
 * longer than MAX_RETRY_WAIT_MS, or the last failed attempt rejects with an
 * error that names the endpoint without its query string. The tool call's
 * abort is never retried.
 */
export async function retryingFetch<T>(url: string, options: RetryingFetchOptions = {}): Promise<T> {
  const { now, sleep } = fetchTiming;
  const endpoint = requestEndpoint(url);
  const send = abortableFetch(fetch, options.signal);
  const wait = abortableSleep(options.signal, sleep);
  const planRetry = options.retryPlan ?? defaultRetryPlan;
  const scrub = (text: string) => scrubErrorText(text, { secrets: options.secrets });
  const failure = (reason: string, attempts: number, detail: string | null = null): Error => {
    const count = attempts > 1 ? ` after ${attempts} attempts` : "";
    // The endpoint carries no query or userinfo, and the scrub's heuristics can read a plain path as a credential.
    return new Error(`Fetch failed: ${endpoint} (${scrub(reason)})${count}${detail ? `. ${scrub(detail)}` : ""}`);
  };

  for (let attempt = 1; ; attempt += 1) {
    await options.beforeAttempt?.();
    const outcome = await attemptRequest(send, url, options);
    let waitMs: number;
    if ("error" in outcome) {
      if (attempt >= MAX_ATTEMPTS) throw failure(outcome.error, attempt);
      waitMs = backoffMs(attempt);
    } else if (outcome.response.ok) {
      try {
        return JSON.parse(outcome.body) as T;
      } catch {
        const contentType = outcome.response.headers.get("content-type");
        throw failure(`unreadable JSON: ${describeErrorBody(contentType, outcome.body, { secrets: options.secrets })}`, attempt);
      }
    } else {
      const { response } = outcome;
      const status = statusLine(response);
      const detail = options.failureDetail?.(response) ?? null;
      const plan = planRetry(response, now());
      if (plan === "stop" || attempt >= MAX_ATTEMPTS) throw failure(status, attempt, detail);
      waitMs = plan === "backoff" ? backoffMs(attempt) : plan.waitMs;
      if (waitMs > MAX_RETRY_WAIT_MS) {
        const asked = `the server asked to wait ${Math.ceil(waitMs / 1000)} s before retrying, longer than the ${MAX_RETRY_WAIT_MS / 1000} s limit`;
        throw failure(`${status}; ${asked}`, attempt, detail);
      }
    }
    await wait(waitMs);
  }
}

/**
 * Fetch JSON with in-memory TTL cache.
 * GRC data sources update infrequently (weekly for CMVP, daily for KEV),
 * so aggressive caching is safe and avoids hammering public APIs.
 */
export async function cachedFetch<T>(
  url: string,
  ttlMs: number = 60 * 60 * 1000, // 1 hour default
  signal?: AbortSignal,
): Promise<T> {
  if (signal?.aborted) throw new ToolCallAbortedError(signal);
  const entry = cache.get(url) as CacheEntry<T> | undefined;
  if (entry && Date.now() < entry.expires) {
    return entry.data;
  }

  const data = await retryingFetch<T>(url, { signal });
  cache.set(url, { data, expires: Date.now() + ttlMs });
  return data;
}

/**
 * Rate-limited fetch for APIs that throttle (NVD, EPSS).
 * Enforces minimum delay between requests to the same base URL.
 */
const lastRequestTime = new Map<string, number>();

export function clearGrcSharedCachesForTests(): void {
  cache.clear();
  lastRequestTime.clear();
}

/** Replace the clock and the retry wait of the shared fetch helpers; call with no argument to restore the real ones. */
export function setGrcFetchTimingForTests(timing?: Partial<GrcFetchTiming>): void {
  fetchTiming = timing ? { ...REAL_TIMING, ...timing } : REAL_TIMING;
}

export async function throttledFetch<T>(
  url: string,
  minDelayMs: number = 100,
  signal?: AbortSignal,
): Promise<T> {
  const base = new URL(url).origin;
  const { now, sleep } = fetchTiming;
  const spaceRequests = async () => {
    const elapsed = now() - (lastRequestTime.get(base) ?? 0);
    if (elapsed < minDelayMs) {
      await abortableSleep(signal, sleep)(minDelayMs - elapsed);
    }
    lastRequestTime.set(base, now());
  };

  return retryingFetch<T>(url, { signal, beforeAttempt: spaceRequests });
}

/**
 * Runs `worker` over `items`, at most `limit` at a time, and returns the results
 * in input order. Once a worker fails no further item starts, and the call
 * rejects with that failure after the items already running settle, so an
 * aborted call neither starts the rest of the list nor leaves work running.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  let failure: { error: unknown } | undefined;
  const run = async (): Promise<void> => {
    while (!failure && next < items.length) {
      const index = next;
      next += 1;
      try {
        results[index] = await worker(items[index], index);
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, run));
  if (failure) throw failure.error;
  return results;
}

/** Format a table for terminal output */
export function formatTable(
  headers: string[],
  rows: string[][],
): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)),
  );

  const sep = widths.map((w) => "─".repeat(w + 2)).join("┼");
  const fmtRow = (row: string[]) =>
    row.map((cell, i) => ` ${(cell ?? "").padEnd(widths[i])} `).join("│");

  return [fmtRow(headers), sep, ...rows.map(fmtRow)].join("\n");
}

export function textResult(
  text: string,
  details: Record<string, unknown> = {},
) {
  return {
    content: [{ type: "text" as const, text }],
    details,
  };
}

export function errorResult(
  text: string,
  details: Record<string, unknown> = {},
) {
  return {
    content: [{ type: "text" as const, text }],
    details,
    isError: true,
  };
}
