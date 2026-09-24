/** Shared utilities for GRC extension tools */
import { AsyncLocalStorage } from "node:async_hooks";

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

/**
 * Fetch JSON with in-memory TTL cache.
 * GRC data sources update infrequently (weekly for CMVP, daily for KEV),
 * so aggressive caching is safe and avoids hammering public APIs.
 */
export async function cachedFetch<T>(
  url: string,
  ttlMs: number = 60 * 60 * 1000, // 1 hour default
): Promise<T> {
  const entry = cache.get(url) as CacheEntry<T> | undefined;
  if (entry && Date.now() < entry.expires) {
    return entry.data;
  }

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Fetch failed: ${url} (${res.status} ${res.statusText})`);
  }

  const data = (await res.json()) as T;
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

export async function throttledFetch<T>(
  url: string,
  minDelayMs: number = 100,
): Promise<T> {
  const base = new URL(url).origin;
  const last = lastRequestTime.get(base) ?? 0;
  const elapsed = Date.now() - last;

  if (elapsed < minDelayMs) {
    await new Promise((r) => setTimeout(r, minDelayMs - elapsed));
  }

  lastRequestTime.set(base, Date.now());

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Fetch failed: ${url} (${res.status} ${res.statusText})`);
  }

  return (await res.json()) as T;
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
