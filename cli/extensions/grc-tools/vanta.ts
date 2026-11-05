/**
 * Vanta auditor tools for grclanker.
 *
 * V1 stays audit-first and read-only:
 * - check auditor access
 * - list accessible audits
 * - export one audit into an offline evidence package
 *
 * The implementation is native TypeScript and keeps auth/token handling
 * intentionally separate from the later Manage Vanta surface.
 */
import { createHash } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  chmodSync,
} from "node:fs";
import { chmod, readdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import { Type } from "typebox";
import { ToolCallAbortedError, abortableFetch, abortableSleep, rethrowIfAborted, unlessAborted } from "./abort.js";
import { writeBundleAtomically } from "./atomic-output.js";
import { errorResult, formatTable, mapWithConcurrency, textResult } from "./shared.js";
import { createZipArchive } from "./zip-archive.js";

const VANTA_TOKEN_URL = "https://api.vanta.com/oauth/token";
const VANTA_BASE_URL = "https://api.vanta.com/v1";
const VANTA_AUDITOR_READ_SCOPE = "auditor-api.audit:read auditor-api.auditor:read";
const PAGE_SIZE = 100;
const MAX_LIST_PAGES = 500;
const DEFAULT_AUDIT_LIMIT = 10;
const DEFAULT_OUTPUT_DIR = "./export/vanta";
const DOWNLOAD_REDIRECT_LIMIT = 5;
const TOKEN_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 500;
const MAX_RETRY_WAIT_MS = 30_000;
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);
const MAX_LISTED_GAPS = 10;

interface PaginatedResults<T> {
  results: {
    data: T[];
    pageInfo: {
      endCursor?: string | null;
      hasNextPage: boolean;
    };
  };
}

export interface VantaAudit {
  id: string;
  customerDisplayName: string | null;
  customerOrganizationName: string;
  framework: string;
  auditStartDate: string;
  auditEndDate: string;
  creationDate?: string;
}

export interface VantaEvidenceControl {
  name: string;
  sectionNames?: string[];
}

export interface VantaEvidence {
  id: string;
  evidenceId: string;
  name: string;
  status: string;
  description: string | null;
  evidenceType: string;
  testStatus: string | null;
  relatedControls: VantaEvidenceControl[];
  creationDate: string;
  statusUpdatedDate: string;
}

export interface VantaEvidenceUrl {
  id: string;
  url: string;
  filename: string;
  isDownloadable: boolean;
}

export interface VantaAuditorCredentials {
  clientId: string;
  clientSecret: string;
}

/** An evidence item the package does not fully hold: its file URLs could not be listed, or files failed to download. */
export interface VantaIncompleteEvidence {
  id: string;
  name: string;
  status: "urls_unknown" | "files_missing";
  /** Bundle-relative paths of the files that were listed but not downloaded. */
  missingFiles: string[];
  reason: string;
}

export interface VantaExportResult {
  outputDir: string;
  zipPath: string;
  totalEvidenceItems: number;
  totalFilesExported: number;
  totalControlFolders: number;
  totalSizeBytes: number;
  errorCount: number;
  complete: boolean;
  evidenceWithUnknownUrls: number;
  evidenceWithMissingFiles: number;
  filesNotDownloaded: number;
  incompleteEvidence: VantaIncompleteEvidence[];
}

export interface VantaAccessCheckResult {
  status: "healthy" | "authorized_no_audits";
  visibleAuditCount: number;
  sampleAudits: VantaAudit[];
  notes: string[];
  recommendedNextStep: string;
}

type CheckAccessArgs = {
  client_id?: string;
  client_secret?: string;
};

type ListAuditsArgs = {
  query?: string;
  limit?: number;
  client_id?: string;
  client_secret?: string;
};

type ExportAuditArgs = {
  audit_id: string;
  output_dir?: string;
  client_id?: string;
  client_secret?: string;
};

type FetchImpl = typeof fetch;
type SleepImpl = (ms: number) => Promise<void>;

export interface VantaRetryOptions {
  timeoutMs?: number;
  maxRetries?: number;
  sleep?: SleepImpl;
  /** Clock for token expiry and HTTP-date Retry-After values. */
  now?: () => number;
}

type RetryPolicy = {
  timeoutMs: number;
  maxRetries: number;
  sleep: SleepImpl;
  now: () => number;
  signal?: AbortSignal;
};

type RetriedResponse = {
  /** Absent when every attempt timed out or failed in transport. */
  response?: Response;
  body: string;
  attempts: number;
  /** Why the last attempt failed when no response explains it, or why retrying stopped early. */
  failure?: string;
};

type DownloadTask = {
  url: VantaEvidenceUrl;
  evidence: VantaEvidence;
  controlName: string;
  controlDir: string;
  filePath: string;
  fileName: string;
};

type TokenCacheEntry = {
  token?: string;
  expiresAt?: number;
  pending?: Promise<string>;
};

const tokenCache = new Map<string, TokenCacheEntry>();

export function clearVantaTokenCacheForTests(): void {
  tokenCache.clear();
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return undefined;
}

function clampLimit(value: number | undefined, fallback = DEFAULT_AUDIT_LIMIT): number {
  const parsed = value ?? fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), 100);
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      client_id: asString(value.client_id) ?? asString(value.clientId),
      client_secret: asString(value.client_secret) ?? asString(value.clientSecret),
    };
  }

  return {};
}

function normalizeListAuditsArgs(args: unknown): ListAuditsArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), limit: DEFAULT_AUDIT_LIMIT };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query: asString(value.query),
      limit: clampLimit(asNumber(value.limit)),
      client_id: asString(value.client_id) ?? asString(value.clientId),
      client_secret: asString(value.client_secret) ?? asString(value.clientSecret),
    };
  }

  return { limit: DEFAULT_AUDIT_LIMIT };
}

function normalizeExportAuditArgs(args: unknown): ExportAuditArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { audit_id: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      audit_id:
        asString(value.audit_id) ??
        asString(value.auditId) ??
        asString(value.id) ??
        asString(value.audit) ??
        "",
      output_dir: asString(value.output_dir) ?? asString(value.output) ?? asString(value.dir),
      client_id: asString(value.client_id) ?? asString(value.clientId),
      client_secret: asString(value.client_secret) ?? asString(value.clientSecret),
    };
  }

  return { audit_id: "" };
}

export function resolveVantaCredentials(
  input: { clientId?: string; clientSecret?: string },
  env: NodeJS.ProcessEnv = process.env,
): VantaAuditorCredentials {
  const clientId = input.clientId?.trim() || env.VANTA_CLIENT_ID?.trim();
  const clientSecret = input.clientSecret?.trim() || env.VANTA_CLIENT_SECRET?.trim();

  if (!clientId || !clientSecret) {
    throw new Error(
      "Vanta credentials are required. Set VANTA_CLIENT_ID and VANTA_CLIENT_SECRET, or pass client_id and client_secret explicitly.",
    );
  }

  return { clientId, clientSecret };
}

function buildTokenCacheKey(clientId: string, clientSecret: string, scope: string): string {
  return createHash("sha256")
    .update(clientId)
    .update("\0")
    .update(clientSecret)
    .update("\0")
    .update(scope)
    .digest("hex");
}

function limitErrorBody(body: string): string {
  const compact = body.replace(/\s+/g, " ").trim();
  if (compact.length <= 240) return compact;
  return `${compact.slice(0, 237)}...`;
}

function redactKnownSecrets(message: string, secrets: Array<string | undefined>): string {
  let redacted = message;
  for (const secret of secrets) {
    if (secret === undefined || secret.length < 4) continue;
    redacted = redacted.split(secret).join("[redacted]");
  }
  return redacted;
}

/** Host and path only: signed download URLs keep the signature in the query string. */
function urlForError(url: URL): string {
  return `${url.protocol}//${url.host}${url.pathname}`;
}

function formatDate(dateText: string): string {
  const timestamp = Date.parse(dateText);
  if (!Number.isFinite(timestamp)) return dateText;
  return new Date(timestamp).toISOString().slice(0, 10);
}

function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = units[0]!;
  for (const candidate of units) {
    unit = candidate;
    if (size < 1024 || candidate === units[units.length - 1]) break;
    size /= 1024;
  }
  return unit === "B" ? `${Math.trunc(size)} ${unit}` : `${size.toFixed(1)} ${unit}`;
}

function getAuditCustomerName(audit: VantaAudit): string {
  return audit.customerDisplayName?.trim() || audit.customerOrganizationName;
}

function buildAuditDirectoryName(audit: VantaAudit): string {
  return sanitizeFilename(
    `${getAuditCustomerName(audit)}_${audit.framework}_${audit.id.slice(0, 8)}`,
  );
}

function* auditOutputNames(audit: VantaAudit): Generator<string> {
  const directoryName = buildAuditDirectoryName(audit);
  yield directoryName;
  for (let index = 1; ; index += 1) {
    yield `${directoryName}_${index}`;
  }
}

function buildAuditSearchText(audit: VantaAudit): string {
  return [
    audit.id,
    getAuditCustomerName(audit),
    audit.customerOrganizationName,
    audit.framework,
    audit.auditStartDate,
    audit.auditEndDate,
  ].join(" ").toLowerCase();
}

function sortAuditsByEndDateDesc(a: VantaAudit, b: VantaAudit): number {
  return b.auditEndDate.localeCompare(a.auditEndDate);
}

export async function checkVantaAuditorAccess(
  client: Pick<VantaAuditorClient, "listAudits">,
): Promise<VantaAccessCheckResult> {
  const audits = (await client.listAudits()).sort(sortAuditsByEndDateDesc);
  const notes = [
    "Vanta allows only one active access token per application at a time, so avoid sharing the same credentials across multiple concurrent clients.",
  ];

  if (audits.length === 0) {
    notes.unshift(
      "No audits were returned for these credentials. If this is unexpected, verify that the app is an Auditor application with auditor-api.audit:read and auditor-api.auditor:read scopes, and that at least one audit is active for this auditor context.",
    );

    return {
      status: "authorized_no_audits",
      visibleAuditCount: 0,
      sampleAudits: [],
      notes,
      recommendedNextStep:
        "Verify the Vanta app type, auditor scopes, and whether any active audits are available to this auditor context.",
    };
  }

  return {
    status: "healthy",
    visibleAuditCount: audits.length,
    sampleAudits: audits.slice(0, 5),
    notes,
    recommendedNextStep:
      "Use vanta_list_audits to inspect scope or vanta_export_audit to pull one audit into an offline evidence package.",
  };
}

export function escapeCsvCell(value: string): string {
  const trimmed = value.trimStart();
  if (!trimmed) return value;

  switch (trimmed[0]) {
    case "=":
    case "+":
    case "-":
    case "@":
      return `'${value}`;
    default:
      return value;
  }
}

export function sanitizeFilename(name: string): string {
  let result = basename(name);
  result = result.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_");
  result = result.trim().replace(/^[. ]+|[. ]+$/g, "");

  if (result.length > 200) {
    result = result.slice(0, 200);
  }

  if (!result || result === "." || result === "..") {
    return "unnamed";
  }

  return result;
}

export function ensurePrivateDir(path: string): void {
  if (existsSync(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked directory: ${path}`);
    }
    if (!info.isDirectory()) {
      throw new Error(`Path is not a directory: ${path}`);
    }
  }

  mkdirSync(path, { recursive: true, mode: 0o700 });

  const info = lstatSync(path);
  if (info.isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked directory: ${path}`);
  }
  if (!info.isDirectory()) {
    throw new Error(`Path is not a directory: ${path}`);
  }

  chmodSync(path, 0o700);
}

export function resolveSecureOutputPath(baseDir: string, destPath: string): string {
  const resolvedBase = realpathSync(resolve(baseDir));
  const absoluteDest = resolve(destPath);

  if (existsSync(absoluteDest)) {
    const info = lstatSync(absoluteDest);
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to write through symlink: ${absoluteDest}`);
    }
  }

  const resolvedDestDir = realpathSync(resolve(dirname(absoluteDest)));
  const resolvedDest = join(resolvedDestDir, basename(absoluteDest));
  const relPath = relative(resolvedBase, resolvedDest);
  if (relPath.startsWith("..") || relPath === "" && resolvedDest !== resolvedBase) {
    throw new Error("Invalid output path: path traversal detected");
  }
  if (relative(resolvedBase, resolvedDest).startsWith("..")) {
    throw new Error("Invalid output path: path traversal detected");
  }

  return resolvedDest;
}

async function writeSecureFile(baseDir: string, destPath: string, data: string | Buffer): Promise<void> {
  const resolvedPath = resolveSecureOutputPath(baseDir, destPath);
  await writeFile(resolvedPath, data, { mode: 0o600 });
  await chmod(resolvedPath, 0o600);
}

function normalizeHostname(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

function sameHostOrSubdomain(host: string, expected: string): boolean {
  const normalizedHost = normalizeHostname(host);
  const normalizedExpected = normalizeHostname(expected);
  return normalizedHost === normalizedExpected || normalizedHost.endsWith(`.${normalizedExpected}`);
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function parseJsonBody<T>(body: string, label: string): T {
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new Error(`${label} was not valid JSON.`);
  }
}

function retryPolicy(options: VantaRetryOptions, signal: AbortSignal | undefined): RetryPolicy {
  return {
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxRetries: Math.min(Math.max(Math.trunc(options.maxRetries ?? DEFAULT_MAX_RETRIES), 0), 10),
    sleep: abortableSleep(signal, options.sleep),
    now: options.now ?? Date.now,
    signal,
  };
}

/** Retry-After in milliseconds: delta-seconds, or an HTTP-date measured against the policy clock. */
function retryAfterMs(value: string | null, now: number): number | undefined {
  if (value === null) return undefined;
  const seconds = asNumber(value);
  if (seconds !== undefined) return Math.max(seconds * 1000, 0);
  if (!/^(mon|tue|wed|thu|fri|sat|sun)/i.test(value.trim())) return undefined;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(date - now, 0) : undefined;
}

function attemptsSuffix(attempts: number): string {
  return attempts > 1 ? ` after ${attempts} attempts` : "";
}

/** One attempt under the per-request timeout; with readBody the body is read before the timer stops. */
async function attemptRequest(
  send: (signal: AbortSignal) => Promise<Response>,
  policy: RetryPolicy,
  readBody: boolean,
): Promise<Omit<RetriedResponse, "attempts">> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
  try {
    const response = await send(controller.signal);
    return { response, body: readBody ? await response.text() : "" };
  } catch (error) {
    rethrowIfAborted(error);
    if (policy.signal?.aborted) throw new ToolCallAbortedError(policy.signal);
    const timedOut = controller.signal.aborted || (error instanceof Error && error.name === "AbortError");
    return { body: "", failure: timedOut ? `timed out after ${policy.timeoutMs} ms` : errorMessage(error) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Sends until a response is neither 429 nor a retryable 5xx, the retry budget is spent, or the server asks
 * for a longer wait than MAX_RETRY_WAIT_MS. Every Vanta request is a read or the token grant, so timeouts
 * and transport failures are retried too.
 */
async function sendWithRetries(
  send: (signal: AbortSignal) => Promise<Response>,
  policy: RetryPolicy,
  readBody: boolean,
): Promise<RetriedResponse> {
  for (let attempt = 1; ; attempt += 1) {
    const result = await attemptRequest(send, policy, readBody);
    const { response } = result;
    if ((response && !RETRYABLE_STATUSES.has(response.status)) || attempt > policy.maxRetries) {
      return { ...result, attempts: attempt };
    }
    const askedMs = response ? retryAfterMs(response.headers.get("retry-after"), policy.now()) : undefined;
    if (askedMs !== undefined && askedMs > MAX_RETRY_WAIT_MS) {
      const failure = `the server asked to retry after ${Math.ceil(askedMs / 1000)} s, more than the ${MAX_RETRY_WAIT_MS / 1000} s limit`;
      return { ...result, attempts: attempt, failure };
    }
    if (!readBody) await response?.body?.cancel().catch(() => undefined);
    await policy.sleep(askedMs ?? Math.min(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1), MAX_RETRY_WAIT_MS));
  }
}

export class VantaAuditorClient {
  private readonly credentials: VantaAuditorCredentials;
  private readonly fetchImpl: FetchImpl;
  private readonly baseUrl: string;
  private readonly tokenUrl: string;
  private readonly scope: string;
  private readonly now: () => number;
  private readonly signal?: AbortSignal;
  private readonly retry: RetryPolicy;

  constructor(
    credentials: VantaAuditorCredentials,
    options: {
      fetchImpl?: FetchImpl;
      baseUrl?: string;
      tokenUrl?: string;
      scope?: string;
      signal?: AbortSignal;
    } & VantaRetryOptions = {},
  ) {
    this.credentials = credentials;
    this.fetchImpl = abortableFetch(options.fetchImpl ?? fetch, options.signal);
    this.baseUrl = options.baseUrl ?? VANTA_BASE_URL;
    this.tokenUrl = options.tokenUrl ?? VANTA_TOKEN_URL;
    this.scope = options.scope ?? VANTA_AUDITOR_READ_SCOPE;
    this.now = options.now ?? Date.now;
    this.signal = options.signal;
    this.retry = retryPolicy(options, options.signal);
  }

  private get cacheKey(): string {
    return buildTokenCacheKey(
      this.credentials.clientId,
      this.credentials.clientSecret,
      this.scope,
    );
  }

  private isTokenValid(entry: TokenCacheEntry | undefined): entry is Required<Pick<TokenCacheEntry, "token" | "expiresAt">> {
    return Boolean(entry?.token && entry.expiresAt && (entry.expiresAt - TOKEN_SKEW_MS) > this.now());
  }

  private async requestToken(): Promise<string> {
    const result = await sendWithRetries((signal) => this.fetchImpl(this.tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        client_id: this.credentials.clientId,
        client_secret: this.credentials.clientSecret,
        scope: this.scope,
        grant_type: "client_credentials",
      }),
      signal,
    }), this.retry, true);
    const { response } = result;

    if (!response) {
      throw new Error(this.redact(`Vanta authentication failed${attemptsSuffix(result.attempts)}: ${result.failure}`));
    }

    if (!response.ok) {
      const detail = this.redactErrorDetail(result.body);
      throw new Error([
        `Vanta authentication failed (${response.status} ${response.statusText})${attemptsSuffix(result.attempts)}`,
        result.failure,
        detail,
      ].filter(Boolean).join(": "));
    }

    const payload = parseJsonBody<{
      access_token: string;
      expires_in?: number;
    } | null>(result.body, "Vanta authentication response");

    if (!payload?.access_token) {
      throw new Error("Vanta authentication succeeded but did not return an access token.");
    }

    const entry = tokenCache.get(this.cacheKey) ?? {};
    entry.token = payload.access_token;
    entry.expiresAt = this.now() + ((payload.expires_in ?? 3600) * 1000);
    tokenCache.set(this.cacheKey, entry);
    return payload.access_token;
  }

  private async authenticate(forceRefresh = false): Promise<string> {
    const entry = tokenCache.get(this.cacheKey) ?? {};
    tokenCache.set(this.cacheKey, entry);

    if (!forceRefresh && this.isTokenValid(entry)) {
      return entry.token;
    }

    if (!forceRefresh && entry.pending) {
      try {
        return await unlessAborted(entry.pending, this.signal);
      } catch (error) {
        // The shared request carries the signal of the call that started it; that call's abort is not this call's failure.
        if (!(error instanceof ToolCallAbortedError) || this.signal?.aborted) throw error;
        return this.authenticate();
      }
    }

    entry.pending = unlessAborted(this.requestToken(), this.signal).finally(() => {
      const current = tokenCache.get(this.cacheKey);
      if (current) {
        delete current.pending;
      }
    });

    return entry.pending;
  }

  private invalidateToken(): void {
    tokenCache.delete(this.cacheKey);
  }

  private redact(message: string, extra: Array<string | undefined> = []): string {
    return redactKnownSecrets(message, [
      this.credentials.clientId,
      this.credentials.clientSecret,
      ...extra,
    ]);
  }

  /** Redact known secrets in the raw body, then shorten it for display. */
  private redactErrorDetail(body: string, extra: Array<string | undefined> = []): string {
    return limitErrorBody(this.redact(body, extra));
  }

  private async requestJson<T>(
    path: string,
    options: {
      params?: Record<string, string | number | undefined>;
      allow404?: boolean;
      retryOnUnauthorized?: boolean;
    } = {},
  ): Promise<T | null> {
    const token = await this.authenticate();
    const url = `${this.baseUrl}${path}${buildQuery(options.params ?? {})}`;
    const result = await sendWithRetries((signal) => this.fetchImpl(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
      },
      signal,
    }), this.retry, true);
    const { response } = result;

    if (!response) {
      throw new Error(this.redact(`Vanta API request failed for ${path}${attemptsSuffix(result.attempts)}: ${result.failure}`, [token]));
    }

    if (response.status === 401 && options.retryOnUnauthorized !== false) {
      this.invalidateToken();
      await this.authenticate(true);
      return this.requestJson<T>(path, { ...options, retryOnUnauthorized: false });
    }

    if (response.status === 404 && options.allow404) {
      return null;
    }

    if (!response.ok) {
      const detail = this.redactErrorDetail(result.body, [token]);
      throw new Error([
        `Vanta API request failed for ${path} (${response.status} ${response.statusText})${attemptsSuffix(result.attempts)}`,
        result.failure,
        detail,
      ].filter(Boolean).join(": "));
    }

    return parseJsonBody<T>(result.body, `Vanta API response for ${path}`);
  }

  private async listPaginated<T>(
    path: string,
    options: {
      params?: Record<string, string | number | undefined>;
      allow404?: boolean;
    } = {},
  ): Promise<T[]> {
    const items: T[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;

    for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
      const payload = await this.requestJson<PaginatedResults<T>>(path, {
        params: {
          pageSize: PAGE_SIZE,
          ...options.params,
          pageCursor: cursor,
        },
        allow404: options.allow404,
      });

      if (payload === null) {
        if (page === 0) return [];
        throw new Error(
          `Vanta API request for ${path} returned 404 after ${page} fetched page(s); refusing to treat a partial page as a complete list.`,
        );
      }

      const data = payload.results?.data;
      const pageInfo = payload.results?.pageInfo;
      if (!Array.isArray(data) || !pageInfo || typeof pageInfo.hasNextPage !== "boolean") {
        throw new Error(`Vanta API response for ${path} did not include a results page.`);
      }

      items.push(...data);
      if (!pageInfo.hasNextPage) return items;

      const next = pageInfo.endCursor;
      if (typeof next !== "string" || next.trim().length === 0) {
        throw new Error(
          `Vanta API pagination for ${path} reported another page but no endCursor after ${items.length} item(s).`,
        );
      }
      if (seenCursors.has(next)) {
        throw new Error(
          `Vanta API pagination for ${path} repeated a page cursor after ${items.length} item(s).`,
        );
      }
      seenCursors.add(next);
      cursor = next;
    }

    throw new Error(
      `Vanta API pagination for ${path} exceeded ${MAX_LIST_PAGES} pages after ${items.length} item(s).`,
    );
  }

  async listAudits(): Promise<VantaAudit[]> {
    return this.listPaginated<VantaAudit>("/audits");
  }

  async listEvidence(auditId: string): Promise<VantaEvidence[]> {
    return this.listPaginated<VantaEvidence>(`/audits/${encodeURIComponent(auditId)}/evidence`);
  }

  async listEvidenceUrls(auditId: string, auditEvidenceId: string): Promise<VantaEvidenceUrl[]> {
    return this.listPaginated<VantaEvidenceUrl>(
      `/audits/${encodeURIComponent(auditId)}/evidence/${encodeURIComponent(auditEvidenceId)}/urls`,
      { allow404: true },
    );
  }
}

function collectControlMap(evidence: VantaEvidence[]): Map<string, VantaEvidence[]> {
  const controlMap = new Map<string, VantaEvidence[]>();
  for (const entry of evidence) {
    if (entry.relatedControls.length === 0) {
      const bucket = controlMap.get("_Unassigned") ?? [];
      bucket.push(entry);
      controlMap.set("_Unassigned", bucket);
      continue;
    }

    for (const control of entry.relatedControls) {
      const bucket = controlMap.get(control.name) ?? [];
      bucket.push(entry);
      controlMap.set(control.name, bucket);
    }
  }
  return controlMap;
}

function reserveUniquePath(path: string, usedPaths: Set<string>): string {
  let candidate = path;
  const extension = extname(path);
  const stem = basename(path, extension);
  let index = 1;

  while (usedPaths.has(candidate) || existsSync(candidate)) {
    candidate = join(dirname(path), `${stem}_${index}${extension}`);
    index += 1;
  }

  usedPaths.add(candidate);
  return candidate;
}

/** The timeout covers each hop up to its response headers; writeDownloadBody applies it to the body as an idle limit. */
async function followDownloadRedirects(
  rawUrl: string,
  fetchImpl: FetchImpl,
  policy: RetryPolicy,
): Promise<RetriedResponse> {
  const initial = new URL(rawUrl);
  if (initial.protocol !== "https:") {
    throw new Error(`Only HTTPS download URLs are allowed, got ${initial.protocol}`);
  }

  const expectedHost = normalizeHostname(initial.hostname);
  let current = initial;

  for (let redirectCount = 0; redirectCount <= DOWNLOAD_REDIRECT_LIMIT; redirectCount += 1) {
    const target = current;
    const result = await sendWithRetries((signal) => fetchImpl(target, {
      method: "GET",
      redirect: "manual",
      signal,
    }), policy, false);
    const { response } = result;

    if (response && response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error("Redirect response missing Location header");
      }

      const next = new URL(location, current);
      if (next.protocol !== "https:") {
        throw new Error(`Redirected to non-HTTPS URL: ${urlForError(next)}`);
      }
      if (!sameHostOrSubdomain(next.hostname, expectedHost)) {
        throw new Error(`Redirected to unexpected host: ${next.hostname}`);
      }
      current = next;
      continue;
    }

    return result;
  }

  throw new Error("Too many download redirects");
}

/**
 * Streams a download body to disk, failing once no data has arrived for the policy timeout. The body is not
 * retried; on failure the partial file is removed so the package never holds a truncated file under its name.
 */
async function writeDownloadBody(
  body: ReadableStream<Uint8Array>,
  resolvedPath: string,
  policy: RetryPolicy,
): Promise<void> {
  const stalled = new AbortController();
  const timer = setTimeout(() => stalled.abort(), policy.timeoutMs);
  const watchdog = new Transform({
    transform(chunk, _encoding, callback) {
      timer.refresh();
      callback(null, chunk);
    },
  });
  const signal = policy.signal ? AbortSignal.any([policy.signal, stalled.signal]) : stalled.signal;
  try {
    // Awaited, not raced with unlessAborted: the pipeline stops on the signal and settles only once the file is closed,
    // and the export removes its staging directory as soon as this call rejects.
    await pipeline(
      Readable.fromWeb(body as NodeReadableStream),
      watchdog,
      createWriteStream(resolvedPath, { mode: 0o600 }),
      { signal },
    );
  } catch (error) {
    if (policy.signal?.aborted) throw new ToolCallAbortedError(policy.signal);
    await rm(resolvedPath, { force: true });
    throw new Error(stalled.signal.aborted
      ? `Download stalled: no data for ${policy.timeoutMs} ms`
      : `Download failed partway: ${errorMessage(error)}`);
  } finally {
    clearTimeout(timer);
  }
}

async function downloadFile(
  rawUrl: string,
  destPath: string,
  baseDir: string,
  fetchImpl: FetchImpl,
  policy: RetryPolicy,
): Promise<number> {
  const result = await followDownloadRedirects(rawUrl, fetchImpl, policy);
  const { response } = result;
  if (!response) {
    throw new Error(`Download failed${attemptsSuffix(result.attempts)}: ${result.failure}`);
  }
  if (!response.ok) {
    throw new Error([
      `Download failed (${response.status} ${response.statusText})${attemptsSuffix(result.attempts)}`,
      result.failure,
    ].filter(Boolean).join(": "));
  }
  if (!response.body) {
    throw new Error("Download response did not include a response body");
  }

  const resolvedPath = resolveSecureOutputPath(baseDir, destPath);
  await writeDownloadBody(response.body, resolvedPath, policy);
  await chmod(resolvedPath, 0o600);

  const contentLength = response.headers.get("content-length");
  if (contentLength) {
    const size = Number(contentLength);
    if (Number.isFinite(size) && size >= 0) {
      return size;
    }
  }

  return existsSync(resolvedPath) ? lstatSync(resolvedPath).size : 0;
}

async function collectRegularFiles(rootDir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(rootDir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(rootDir, entry.name);
    const info = lstatSync(fullPath);
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to zip symlinked path: ${fullPath}`);
    }

    if (entry.isDirectory()) {
      files.push(...await collectRegularFiles(fullPath));
      continue;
    }

    if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files.sort();
}

async function zipAuditPackage(sourceDir: string, zipPath: string, baseDir: string, signal?: AbortSignal): Promise<void> {
  const zipRoot = basename(sourceDir);
  const files = await collectRegularFiles(sourceDir);
  await createZipArchive(
    files.map((filePath) => ({ path: filePath, name: join(zipRoot, relative(sourceDir, filePath)) })),
    resolveSecureOutputPath(baseDir, zipPath),
    signal,
  );
}

type MissingFile = {
  fileName: string;
  /** Relative to the bundle root, with forward slashes. */
  path: string;
  reason: string;
};

function distinctReasons(files: MissingFile[]): string {
  return [...new Set(files.map((file) => file.reason))].sort().join("; ");
}

function collectIncompleteEvidence(
  evidence: VantaEvidence[],
  unlistedEvidence: Map<string, string>,
  missingFilesByEvidence: Map<string, MissingFile[]>,
): VantaIncompleteEvidence[] {
  const entries: VantaIncompleteEvidence[] = [];
  for (const item of evidence) {
    const listingError = unlistedEvidence.get(item.id);
    const missing = missingFilesByEvidence.get(item.id) ?? [];
    if (listingError !== undefined) {
      entries.push({ id: item.id, name: item.name, status: "urls_unknown", missingFiles: [], reason: listingError });
    } else if (missing.length > 0) {
      entries.push({
        id: item.id,
        name: item.name,
        status: "files_missing",
        missingFiles: missing.map((file) => file.path).sort(),
        reason: distinctReasons(missing),
      });
    }
  }
  return entries;
}

function exportCompleteness(entries: VantaIncompleteEvidence[]) {
  return {
    complete: entries.length === 0,
    evidence_items_with_unknown_urls: entries.filter((entry) => entry.status === "urls_unknown").length,
    evidence_items_with_missing_files: entries.filter((entry) => entry.status === "files_missing").length,
    files_not_downloaded: entries.reduce((total, entry) => total + entry.missingFiles.length, 0),
  };
}

export async function exportVantaAuditPackage(
  client: Pick<VantaAuditorClient, "listEvidence" | "listEvidenceUrls">,
  audit: VantaAudit,
  baseOutputDir: string,
  options: {
    fetchImpl?: FetchImpl;
    downloadConcurrency?: number;
    signal?: AbortSignal;
  } & VantaRetryOptions = {},
): Promise<VantaExportResult> {
  const fetchImpl = abortableFetch(options.fetchImpl ?? fetch, options.signal);
  const retry = retryPolicy(options, options.signal);
  const errors: string[] = [];

  options.signal?.throwIfAborted();

  const evidence = await client.listEvidence(audit.id);
  const controlMap = collectControlMap(evidence);
  const uniqueEvidenceUrls = new Map<string, VantaEvidenceUrl[]>();
  // Evidence whose URL listing failed: its files are unknown, which is not the same as having none.
  const unlistedEvidence = new Map<string, string>();

  for (const item of evidence) {
    if (uniqueEvidenceUrls.has(item.id) || unlistedEvidence.has(item.id)) continue;
    try {
      const urls = await client.listEvidenceUrls(audit.id, item.id);
      uniqueEvidenceUrls.set(item.id, urls.filter((entry) => entry.isDownloadable));
    } catch (error) {
      rethrowIfAborted(error);
      unlistedEvidence.set(item.id, errorMessage(error));
      errors.push(`Failed to list evidence URLs for ${item.name} (${item.id}): ${errorMessage(error)}`);
    }
  }

  const listingErrorCount = errors.length;
  let totalFilesExported = 0;
  let totalSizeBytes = 0;
  let incompleteEvidence: VantaIncompleteEvidence[] = [];
  const { outputDir, zipPath } = await writeBundleAtomically({
    root: baseOutputDir,
    createRoot: (root) => {
      ensurePrivateDir(root);
      return root;
    },
    names: auditOutputNames(audit),
    zip: true,
    signal: options.signal,
  }, async (staged) => {
    // The writer runs again under the next free name if another process takes this one first.
    errors.splice(listingErrorCount);
    totalFilesExported = 0;
    totalSizeBytes = 0;
    const usedControlPaths = new Set<string>();
    const usedFilePaths = new Set<string>();
    const evidenceFilesByControlKey = new Map<string, string[]>();
    const missingFilesByControlKey = new Map<string, MissingFile[]>();
    const missingFilesByEvidence = new Map<string, MissingFile[]>();
    const controlDirByName = new Map<string, string>();
    for (const controlName of controlMap.keys()) {
      const preferred = join(staged.dir, sanitizeFilename(controlName));
      const controlDir = reserveUniquePath(preferred, usedControlPaths);
      ensurePrivateDir(controlDir);
      controlDirByName.set(controlName, controlDir);
    }

    const downloads: DownloadTask[] = [];
    for (const [controlName, evidenceList] of controlMap.entries()) {
      const controlDir = controlDirByName.get(controlName)!;
      for (const item of evidenceList) {
        const files: string[] = [];
        for (const file of uniqueEvidenceUrls.get(item.id) ?? []) {
          const preferredName = sanitizeFilename(file.filename) || `file_${file.id.slice(0, 8)}`;
          const reservedPath = reserveUniquePath(join(controlDir, preferredName), usedFilePaths);
          const fileName = basename(reservedPath);
          files.push(fileName);
          downloads.push({
            url: file,
            evidence: item,
            controlName,
            controlDir,
            filePath: reservedPath,
            fileName,
          });
        }
        evidenceFilesByControlKey.set(`${controlName}\0${item.id}`, files);
      }
    }

    await mapWithConcurrency(downloads, options.downloadConcurrency ?? 5, async (task) => {
      try {
        const size = await downloadFile(task.url.url, task.filePath, staged.dir, fetchImpl, retry);
        totalFilesExported += 1;
        totalSizeBytes += size;
      } catch (error) {
        rethrowIfAborted(error);
        const missing: MissingFile = {
          fileName: task.fileName,
          path: `${basename(task.controlDir)}/${task.fileName}`,
          reason: errorMessage(error),
        };
        const controlKey = `${task.controlName}\0${task.evidence.id}`;
        missingFilesByControlKey.set(controlKey, [...(missingFilesByControlKey.get(controlKey) ?? []), missing]);
        missingFilesByEvidence.set(task.evidence.id, [...(missingFilesByEvidence.get(task.evidence.id) ?? []), missing]);
        errors.push(`Failed to download ${task.fileName} for ${task.evidence.name} (${task.controlName}): ${missing.reason}`);
      }
    });
    options.signal?.throwIfAborted();

    const uniqueEvidence = Array.from(new Map(evidence.map((item) => [item.id, item])).values());
    incompleteEvidence = collectIncompleteEvidence(uniqueEvidence, unlistedEvidence, missingFilesByEvidence);
    const gapStatusById = new Map(incompleteEvidence.map((entry) => [entry.id, entry.status]));
    const indexRows = uniqueEvidence.map((item) => [
      escapeCsvCell(item.id),
      escapeCsvCell(item.evidenceId),
      escapeCsvCell(item.name),
      escapeCsvCell(item.evidenceType),
      escapeCsvCell(item.status),
      escapeCsvCell(item.testStatus ?? ""),
      escapeCsvCell(item.relatedControls.map((control) => control.name).join("; ")),
      unlistedEvidence.has(item.id) ? "unknown" : String((uniqueEvidenceUrls.get(item.id) ?? []).length),
      escapeCsvCell(formatDate(item.creationDate)),
      escapeCsvCell(formatDate(item.statusUpdatedDate)),
      gapStatusById.get(item.id) ?? "complete",
    ]);

    for (const [controlName, evidenceList] of controlMap.entries()) {
      const controlDir = controlDirByName.get(controlName)!;
      const metadata = {
        control_name: controlName,
        evidence_items: evidenceList.map((item) => {
          const controlKey = `${controlName}\0${item.id}`;
          const listingError = unlistedEvidence.get(item.id);
          const missing = missingFilesByControlKey.get(controlKey) ?? [];
          return {
            id: item.id,
            evidence_id: item.evidenceId,
            name: item.name,
            type: item.evidenceType,
            status: item.status,
            description: item.description ?? "",
            test_status: item.testStatus ?? "",
            files: listingError === undefined ? evidenceFilesByControlKey.get(controlKey) ?? [] : null,
            export_status: listingError !== undefined ? "urls_unknown" : missing.length > 0 ? "files_missing" : "complete",
            ...(missing.length > 0 ? { missing_files: missing.map((file) => file.fileName).sort() } : {}),
            ...(listingError !== undefined || missing.length > 0
              ? { export_error: listingError ?? distinctReasons(missing) }
              : {}),
            creation_date: item.creationDate,
            status_updated_date: item.statusUpdatedDate,
          };
        }),
      };

      await writeSecureFile(controlDir, join(controlDir, "metadata.json"), JSON.stringify(metadata, null, 2) + "\n");
    }

    await writeSecureFile(
      staged.dir,
      join(staged.dir, "_audit_info.json"),
      JSON.stringify({
        id: audit.id,
        customer_name: getAuditCustomerName(audit),
        organization_name: audit.customerOrganizationName,
        framework: audit.framework,
        audit_start_date: audit.auditStartDate,
        audit_end_date: audit.auditEndDate,
        export_date: new Date().toISOString(),
        total_evidence_items: evidence.length,
        total_files_exported: totalFilesExported,
        total_control_folders: controlMap.size,
        ...exportCompleteness(incompleteEvidence),
        incomplete_evidence: incompleteEvidence.map((entry) => ({
          id: entry.id,
          name: entry.name,
          export_status: entry.status,
          missing_files: entry.missingFiles,
          reason: entry.reason,
        })),
      }, null, 2) + "\n",
    );

    const csvContent = [
      [
        "audit_evidence_id",
        "evidence_id",
        "name",
        "type",
        "status",
        "test_status",
        "controls",
        "file_count",
        "created",
        "updated",
        "export_status",
      ],
      ...indexRows,
    ]
      .map((row) => row.map((cell) => `"${cell.replaceAll("\"", "\"\"")}"`).join(","))
      .join("\n") + "\n";

    await writeSecureFile(staged.dir, join(staged.dir, "_index.csv"), csvContent);

    if (errors.length > 0) {
      await writeSecureFile(staged.dir, join(staged.dir, "_errors.log"), `${errors.join("\n")}\n`);
    }

    try {
      await zipAuditPackage(staged.dir, staged.zipPath, baseOutputDir, options.signal);
    } catch (error) {
      rethrowIfAborted(error);
      // A half-written archive must not be committed next to the bundle.
      await rm(staged.zipPath, { force: true });
      errors.push(`Failed to create zip archive: ${error instanceof Error ? error.message : String(error)}`);
      await writeSecureFile(staged.dir, join(staged.dir, "_errors.log"), `${errors.join("\n")}\n`);
    }
  });

  const completeness = exportCompleteness(incompleteEvidence);
  return {
    outputDir,
    zipPath,
    totalEvidenceItems: evidence.length,
    totalFilesExported,
    totalControlFolders: controlMap.size,
    totalSizeBytes,
    errorCount: errors.length,
    complete: completeness.complete,
    evidenceWithUnknownUrls: completeness.evidence_items_with_unknown_urls,
    evidenceWithMissingFiles: completeness.evidence_items_with_missing_files,
    filesNotDownloaded: completeness.files_not_downloaded,
    incompleteEvidence,
  };
}

function buildAccessCheckText(result: VantaAccessCheckResult): string {
  const lines = [
    result.status === "healthy"
      ? "Vanta auditor access looks healthy."
      : "Vanta auditor authentication succeeded, but no audits were returned.",
    `  Visible audits: ${result.visibleAuditCount}`,
    `  Next step:     ${result.recommendedNextStep}`,
  ];

  if (result.sampleAudits.length === 0) {
    return `${lines.join("\n")}\n\nNotes:\n${result.notes.map((note) => `- ${note}`).join("\n")}`;
  }

  const rows = result.sampleAudits.map((audit) => [
    audit.id,
    getAuditCustomerName(audit),
    audit.framework,
    formatDate(audit.auditStartDate),
    formatDate(audit.auditEndDate),
  ]);
  const table = formatTable(["audit_id", "customer", "framework", "start", "end"], rows);

  return [
    lines.join("\n"),
    "Sample audits:",
    table,
    "Notes:",
    ...result.notes.map((note) => `- ${note}`),
  ].join("\n\n");
}

function buildAuditListText(
  audits: VantaAudit[],
  query: string | undefined,
  total: number,
): string {
  const rows = audits.map((audit) => [
    audit.id,
    getAuditCustomerName(audit),
    audit.framework,
    formatDate(audit.auditStartDate),
    formatDate(audit.auditEndDate),
  ]);
  const table = formatTable(["audit_id", "customer", "framework", "start", "end"], rows);
  const qualifier = query?.trim()
    ? `matching "${query.trim()}"`
    : "accessible to the provided credentials";
  const summary = total > audits.length
    ? `Showing ${audits.length} of ${total} Vanta audit(s) ${qualifier}.`
    : `Found ${audits.length} Vanta audit(s) ${qualifier}.`;
  return `${summary}\n\n${table}`;
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/** Why the package does not hold every evidence file; undefined when it does. */
function incompleteExportReason(result: VantaExportResult): string | undefined {
  if (result.complete) return undefined;
  const parts: string[] = [];
  const unknown = result.evidenceWithUnknownUrls;
  if (unknown > 0) {
    parts.push(unknown === 1
      ? "1 evidence item has unknown files because its file URL listing failed"
      : `${unknown} evidence items have unknown files because their file URL listings failed`);
  }
  if (result.evidenceWithMissingFiles > 0) {
    parts.push(`${plural(result.filesNotDownloaded, "file")} for ${plural(result.evidenceWithMissingFiles, "evidence item")} could not be downloaded`);
  }
  return `The package is incomplete: ${parts.join(", and ")}. See _errors.log and _audit_info.json.`;
}

function describeIncompleteEvidence(entry: VantaIncompleteEvidence): string {
  const gap = entry.status === "urls_unknown"
    ? "file URLs unknown"
    : `${plural(entry.missingFiles.length, "file")} not downloaded (${entry.missingFiles.join(", ")})`;
  return `${entry.name} (${entry.id}): ${gap}: ${entry.reason}`;
}

function buildExportText(audit: VantaAudit, result: VantaExportResult): string {
  const lines = [
    result.complete
      ? `Exported Vanta audit "${getAuditCustomerName(audit)} - ${audit.framework}".`
      : `Exported Vanta audit "${getAuditCustomerName(audit)} - ${audit.framework}" as an incomplete package.`,
    `  Audit ID:         ${audit.id}`,
    `  Output directory: ${result.outputDir}`,
    `  Zip archive:      ${result.zipPath}`,
    `  Evidence items:   ${result.totalEvidenceItems}`,
    `  Files exported:   ${result.totalFilesExported}`,
    `  Control folders:  ${result.totalControlFolders}`,
    `  Total size:       ${formatBytes(result.totalSizeBytes)}`,
  ];

  if (result.errorCount > 0) {
    lines.push(`  Warnings:         ${result.errorCount} (see _errors.log)`);
  }

  const reason = incompleteExportReason(result);
  if (reason) {
    lines.push("", reason);
    for (const entry of result.incompleteEvidence.slice(0, MAX_LISTED_GAPS)) {
      lines.push(`  - ${describeIncompleteEvidence(entry)}`);
    }
    const unlisted = result.incompleteEvidence.length - MAX_LISTED_GAPS;
    if (unlisted > 0) lines.push(`  - ${plural(unlisted, "more evidence item")} listed in _audit_info.json`);
  }

  return lines.join("\n");
}

export function registerVantaTools(pi: any): void {
  pi.registerTool({
    name: "vanta_check_access",
    label: "Check Vanta auditor access",
    description:
      "Validate Vanta auditor credentials, confirm the Auditor API is reachable, and report whether any audits are visible for these credentials.",
    parameters: Type.Object({
      client_id: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client ID. Prefer environment variable VANTA_CLIENT_ID when possible.",
        }),
      ),
      client_secret: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client secret. Prefer environment variable VANTA_CLIENT_SECRET when possible.",
        }),
      ),
    }),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs, signal?: AbortSignal) {
      let credentials: VantaAuditorCredentials;
      try {
        credentials = resolveVantaCredentials({
          clientId: args.client_id,
          clientSecret: args.client_secret,
        });
      } catch (error) {
        return errorResult(
          error instanceof Error ? error.message : String(error),
          { tool: "vanta_check_access" },
        );
      }

      try {
        const client = new VantaAuditorClient(credentials, { signal });
        const result = await checkVantaAuditorAccess(client);

        return textResult(buildAccessCheckText(result), {
          tool: "vanta_check_access",
          status: result.status,
          visible_audit_count: result.visibleAuditCount,
          has_visible_audits: result.visibleAuditCount > 0,
          recommended_next_step: result.recommendedNextStep,
          notes: result.notes,
          sample_audits: result.sampleAudits.map((audit) => ({
            id: audit.id,
            customer_name: getAuditCustomerName(audit),
            organization_name: audit.customerOrganizationName,
            framework: audit.framework,
            audit_start_date: audit.auditStartDate,
            audit_end_date: audit.auditEndDate,
          })),
        });
      } catch (error) {
        return errorResult(
          `Vanta access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "vanta_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "vanta_list_audits",
    label: "List Vanta audits",
    description:
      "List accessible Vanta audits for the provided auditor credentials. Supports local filtering by customer, framework, or audit ID.",
    parameters: Type.Object({
      query: Type.Optional(
        Type.String({
          description:
            "Optional search string for customer name, organization, framework, or audit ID.",
        }),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Maximum audits to return (default: 10).",
          default: DEFAULT_AUDIT_LIMIT,
        }),
      ),
      client_id: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client ID. Prefer environment variable VANTA_CLIENT_ID when possible.",
        }),
      ),
      client_secret: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client secret. Prefer environment variable VANTA_CLIENT_SECRET when possible.",
        }),
      ),
    }),
    prepareArguments: normalizeListAuditsArgs,
    async execute(_toolCallId: string, args: ListAuditsArgs, signal?: AbortSignal) {
      let credentials: VantaAuditorCredentials;
      try {
        credentials = resolveVantaCredentials({
          clientId: args.client_id,
          clientSecret: args.client_secret,
        });
      } catch (error) {
        return errorResult(
          error instanceof Error ? error.message : String(error),
          { tool: "vanta_list_audits" },
        );
      }

      try {
        const client = new VantaAuditorClient(credentials, { signal });
        const audits = (await client.listAudits()).sort(sortAuditsByEndDateDesc);
        const query = args.query?.trim().toLowerCase();
        const filtered = query
          ? audits.filter((audit) => buildAuditSearchText(audit).includes(query))
          : audits;
        const limit = clampLimit(args.limit);
        const shown = filtered.slice(0, limit);

        if (shown.length === 0) {
          return textResult(
            query
              ? `No Vanta audits matched "${args.query}".`
              : "No Vanta audits were returned for the provided credentials.",
            {
              tool: "vanta_list_audits",
              query: args.query ?? null,
              count: 0,
              audits: [],
            },
          );
        }

        return textResult(buildAuditListText(shown, args.query, filtered.length), {
          tool: "vanta_list_audits",
          query: args.query ?? null,
          count: shown.length,
          total_count: filtered.length,
          audits: shown.map((audit) => ({
            id: audit.id,
            customer_name: getAuditCustomerName(audit),
            organization_name: audit.customerOrganizationName,
            framework: audit.framework,
            audit_start_date: audit.auditStartDate,
            audit_end_date: audit.auditEndDate,
          })),
        });
      } catch (error) {
        return errorResult(
          `Vanta audit discovery failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "vanta_list_audits", query: args.query ?? null },
        );
      }
    },
  });

  pi.registerTool({
    name: "vanta_export_audit",
    label: "Export Vanta audit evidence",
    description:
      "Export one Vanta audit into an offline evidence package with per-control folders, metadata, a CSV index, and a zip archive.",
    parameters: Type.Object({
      audit_id: Type.String({
        description: "The Vanta audit ID to export. Use vanta_list_audits first if needed.",
      }),
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root (default: ${DEFAULT_OUTPUT_DIR}).`,
        }),
      ),
      client_id: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client ID. Prefer environment variable VANTA_CLIENT_ID when possible.",
        }),
      ),
      client_secret: Type.Optional(
        Type.String({
          description:
            "Optional Vanta client secret. Prefer environment variable VANTA_CLIENT_SECRET when possible.",
        }),
      ),
    }),
    prepareArguments: normalizeExportAuditArgs,
    async execute(_toolCallId: string, args: ExportAuditArgs, signal?: AbortSignal) {
      if (!args.audit_id.trim()) {
        return errorResult(
          'vanta_export_audit requires a non-empty audit_id. Example: {"audit_id":"audit_123"}',
          { tool: "vanta_export_audit" },
        );
      }

      let credentials: VantaAuditorCredentials;
      try {
        credentials = resolveVantaCredentials({
          clientId: args.client_id,
          clientSecret: args.client_secret,
        });
      } catch (error) {
        return errorResult(
          error instanceof Error ? error.message : String(error),
          { tool: "vanta_export_audit", audit_id: args.audit_id },
        );
      }

      try {
        const client = new VantaAuditorClient(credentials, { signal });
        const audits = await client.listAudits();
        const audit = audits.find((entry) => entry.id === args.audit_id.trim());
        if (!audit) {
          return errorResult(
            `No Vanta audit with ID "${args.audit_id}" was returned for the provided credentials.`,
            { tool: "vanta_export_audit", audit_id: args.audit_id },
          );
        }

        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportVantaAuditPackage(client, audit, outputRoot, { signal });

        return textResult(buildExportText(audit, result), {
          tool: "vanta_export_audit",
          audit_id: audit.id,
          customer_name: getAuditCustomerName(audit),
          framework: audit.framework,
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          total_evidence_items: result.totalEvidenceItems,
          total_files_exported: result.totalFilesExported,
          total_control_folders: result.totalControlFolders,
          total_size_bytes: result.totalSizeBytes,
          error_count: result.errorCount,
          complete: result.complete,
          incomplete_reason: incompleteExportReason(result) ?? null,
          evidence_items_with_unknown_urls: result.evidenceWithUnknownUrls,
          evidence_items_with_missing_files: result.evidenceWithMissingFiles,
          files_not_downloaded: result.filesNotDownloaded,
          incomplete_evidence: result.incompleteEvidence.slice(0, MAX_LISTED_GAPS).map((entry) => ({
            id: entry.id,
            name: entry.name,
            export_status: entry.status,
            missing_files: entry.missingFiles,
            reason: entry.reason,
          })),
        });
      } catch (error) {
        return errorResult(
          `Vanta audit export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "vanta_export_audit", audit_id: args.audit_id },
        );
      }
    },
  });
}
