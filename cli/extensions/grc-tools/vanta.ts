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
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

const VANTA_TOKEN_URL = "https://api.vanta.com/oauth/token";
const VANTA_BASE_URL = "https://api.vanta.com/v1";
const VANTA_AUDITOR_READ_SCOPE = "auditor-api.audit:read auditor-api.auditor:read";
const PAGE_SIZE = 100;
const DEFAULT_AUDIT_LIMIT = 10;
const DEFAULT_OUTPUT_DIR = "./export/vanta";
const DOWNLOAD_REDIRECT_LIMIT = 5;
const TOKEN_SKEW_MS = 5 * 60 * 1000;

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

export interface VantaExportResult {
  outputDir: string;
  zipPath: string;
  totalEvidenceItems: number;
  totalFilesExported: number;
  totalControlFolders: number;
  totalSizeBytes: number;
  errorCount: number;
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

async function readResponseBody(response: Response): Promise<string> {
  try {
    return limitErrorBody(await response.text());
  } catch {
    return "";
  }
}

export class VantaAuditorClient {
  private readonly credentials: VantaAuditorCredentials;
  private readonly fetchImpl: FetchImpl;
  private readonly baseUrl: string;
  private readonly tokenUrl: string;
  private readonly scope: string;
  private readonly now: () => number;

  constructor(
    credentials: VantaAuditorCredentials,
    options: {
      fetchImpl?: FetchImpl;
      baseUrl?: string;
      tokenUrl?: string;
      scope?: string;
      now?: () => number;
    } = {},
  ) {
    this.credentials = credentials;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.baseUrl = options.baseUrl ?? VANTA_BASE_URL;
    this.tokenUrl = options.tokenUrl ?? VANTA_TOKEN_URL;
    this.scope = options.scope ?? VANTA_AUDITOR_READ_SCOPE;
    this.now = options.now ?? Date.now;
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
    const response = await this.fetchImpl(this.tokenUrl, {
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
    });

    if (!response.ok) {
      const detail = await readResponseBody(response);
      throw new Error(
        `Vanta authentication failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
      );
    }

    const payload = await response.json() as {
      access_token: string;
      expires_in?: number;
    };

    if (!payload.access_token) {
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
      return entry.pending;
    }

    entry.pending = this.requestToken().finally(() => {
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

  private async requestJson<T>(
    path: string,
    options: {
      params?: Record<string, string | number | undefined>;
      allow404?: boolean;
      retryOnUnauthorized?: boolean;
    } = {},
  ): Promise<T | null> {
    const token = await this.authenticate();
    const response = await this.fetchImpl(
      `${this.baseUrl}${path}${buildQuery(options.params ?? {})}`,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${token}`,
        },
      },
    );

    if (response.status === 401 && options.retryOnUnauthorized !== false) {
      this.invalidateToken();
      await this.authenticate(true);
      return this.requestJson<T>(path, { ...options, retryOnUnauthorized: false });
    }

    if (response.status === 404 && options.allow404) {
      return null;
    }

    if (!response.ok) {
      const detail = await readResponseBody(response);
      throw new Error(
        `Vanta API request failed for ${path} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
      );
    }

    return response.json() as Promise<T>;
  }

  private async listPaginated<T>(
    path: string,
    options: {
      params?: Record<string, string | number | undefined>;
      allow404?: boolean;
    } = {},
  ): Promise<T[]> {
    const items: T[] = [];
    let cursor: string | undefined;

    for (;;) {
      const payload = await this.requestJson<PaginatedResults<T>>(path, {
        params: {
          pageSize: PAGE_SIZE,
          ...options.params,
          pageCursor: cursor,
        },
        allow404: options.allow404,
      });

      if (payload === null) {
        return [];
      }

      items.push(...payload.results.data);
      if (!payload.results.pageInfo.hasNextPage) {
        return items;
      }
      cursor = payload.results.pageInfo.endCursor ?? undefined;
      if (!cursor) {
        return items;
      }
    }
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

async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;

  const size = Math.max(1, Math.min(limit, items.length));
  let cursor = 0;

  await Promise.all(
    Array.from({ length: size }, async () => {
      for (;;) {
        const index = cursor;
        cursor += 1;
        if (index >= items.length) return;
        await worker(items[index]!, index);
      }
    }),
  );
}

async function followDownloadRedirects(
  rawUrl: string,
  fetchImpl: FetchImpl,
): Promise<Response> {
  const initial = new URL(rawUrl);
  if (initial.protocol !== "https:") {
    throw new Error(`Only HTTPS download URLs are allowed, got ${initial.protocol}`);
  }

  const expectedHost = normalizeHostname(initial.hostname);
  let current = initial;

  for (let redirectCount = 0; redirectCount <= DOWNLOAD_REDIRECT_LIMIT; redirectCount += 1) {
    const response = await fetchImpl(current, {
      method: "GET",
      redirect: "manual",
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error("Redirect response missing Location header");
      }

      const next = new URL(location, current);
      if (next.protocol !== "https:") {
        throw new Error(`Redirected to non-HTTPS URL: ${next.toString()}`);
      }
      if (!sameHostOrSubdomain(next.hostname, expectedHost)) {
        throw new Error(`Redirected to unexpected host: ${next.hostname}`);
      }
      current = next;
      continue;
    }

    return response;
  }

  throw new Error("Too many download redirects");
}

async function downloadFile(
  rawUrl: string,
  destPath: string,
  baseDir: string,
  fetchImpl: FetchImpl,
): Promise<number> {
  const response = await followDownloadRedirects(rawUrl, fetchImpl);
  if (!response.ok) {
    throw new Error(`Download failed (${response.status} ${response.statusText})`);
  }
  if (!response.body) {
    throw new Error("Download response did not include a response body");
  }

  const resolvedPath = resolveSecureOutputPath(baseDir, destPath);
  const output = createWriteStream(resolvedPath, { mode: 0o600 });
  try {
    await pipeline(Readable.fromWeb(response.body as NodeReadableStream), output);
  } finally {
    await chmod(resolvedPath, 0o600);
  }

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

async function createZipArchive(sourceDir: string, zipPath: string, baseDir: string): Promise<void> {
  const files = await collectRegularFiles(sourceDir);
  const resolvedZipPath = resolveSecureOutputPath(baseDir, zipPath);

  await new Promise<void>((resolvePromise, rejectPromise) => {
    const output = createWriteStream(resolvedZipPath, { mode: 0o600 });
    const archive = archiver("zip", { zlib: { level: 9 } });

    output.on("close", () => resolvePromise());
    output.on("error", rejectPromise);
    archive.on("error", rejectPromise);
    archive.pipe(output);

    const zipRoot = basename(sourceDir);
    for (const filePath of files) {
      archive.file(filePath, {
        name: join(zipRoot, relative(sourceDir, filePath)),
      });
    }

    void archive.finalize();
  });

  await chmod(resolvedZipPath, 0o600);
}

export async function exportVantaAuditPackage(
  client: Pick<VantaAuditorClient, "listEvidence" | "listEvidenceUrls">,
  audit: VantaAudit,
  baseOutputDir: string,
  options: {
    fetchImpl?: FetchImpl;
    downloadConcurrency?: number;
  } = {},
): Promise<VantaExportResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const errors: string[] = [];
  const usedControlPaths = new Set<string>();
  const usedFilePaths = new Set<string>();
  const evidenceFilesByControlKey = new Map<string, string[]>();

  ensurePrivateDir(baseOutputDir);

  const outputDir = join(baseOutputDir, buildAuditDirectoryName(audit));
  ensurePrivateDir(outputDir);

  const evidence = await client.listEvidence(audit.id);
  const controlMap = collectControlMap(evidence);
  const uniqueEvidenceUrls = new Map<string, VantaEvidenceUrl[]>();

  for (const item of evidence) {
    if (uniqueEvidenceUrls.has(item.id)) continue;
    try {
      const urls = await client.listEvidenceUrls(audit.id, item.id);
      uniqueEvidenceUrls.set(item.id, urls.filter((entry) => entry.isDownloadable));
    } catch (error) {
      uniqueEvidenceUrls.set(item.id, []);
      errors.push(
        `Failed to list evidence URLs for ${item.name} (${item.id}): ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const controlDirByName = new Map<string, string>();
  for (const controlName of controlMap.keys()) {
    const preferred = join(outputDir, sanitizeFilename(controlName));
    const controlDir = reserveUniquePath(preferred, usedControlPaths);
    ensurePrivateDir(controlDir);
    controlDirByName.set(controlName, controlDir);
  }

  const downloads: DownloadTask[] = [];
  for (const [controlName, evidenceList] of controlMap.entries()) {
    const controlDir = controlDirByName.get(controlName)!;
    for (const item of evidenceList) {
      const urls = uniqueEvidenceUrls.get(item.id) ?? [];
      const files: string[] = [];
      for (const file of urls) {
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

  let totalFilesExported = 0;
  let totalSizeBytes = 0;
  await runWithConcurrency(downloads, options.downloadConcurrency ?? 5, async (task) => {
    try {
      const size = await downloadFile(task.url.url, task.filePath, outputDir, fetchImpl);
      totalFilesExported += 1;
      totalSizeBytes += size;
    } catch (error) {
      errors.push(
        `Failed to download ${task.fileName} for ${task.evidence.name} (${task.controlName}): ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  const uniqueEvidence = Array.from(new Map(evidence.map((item) => [item.id, item])).values());
  const indexRows = uniqueEvidence.map((item) => [
    escapeCsvCell(item.id),
    escapeCsvCell(item.evidenceId),
    escapeCsvCell(item.name),
    escapeCsvCell(item.evidenceType),
    escapeCsvCell(item.status),
    escapeCsvCell(item.testStatus ?? ""),
    escapeCsvCell(item.relatedControls.map((control) => control.name).join("; ")),
    String((uniqueEvidenceUrls.get(item.id) ?? []).length),
    escapeCsvCell(formatDate(item.creationDate)),
    escapeCsvCell(formatDate(item.statusUpdatedDate)),
  ]);

  const indexTable = formatTable(
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
    ],
    indexRows,
  );

  for (const [controlName, evidenceList] of controlMap.entries()) {
    const controlDir = controlDirByName.get(controlName)!;
    const metadata = {
      control_name: controlName,
      evidence_items: evidenceList.map((item) => ({
        id: item.id,
        evidence_id: item.evidenceId,
        name: item.name,
        type: item.evidenceType,
        status: item.status,
        description: item.description ?? "",
        test_status: item.testStatus ?? "",
        files: evidenceFilesByControlKey.get(`${controlName}\0${item.id}`) ?? [],
        creation_date: item.creationDate,
        status_updated_date: item.statusUpdatedDate,
      })),
    };

    await writeSecureFile(controlDir, join(controlDir, "metadata.json"), JSON.stringify(metadata, null, 2) + "\n");
  }

  await writeSecureFile(
    outputDir,
    join(outputDir, "_audit_info.json"),
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
    ],
    ...indexRows,
  ]
    .map((row) => row.map((cell) => `"${cell.replaceAll("\"", "\"\"")}"`).join(","))
    .join("\n") + "\n";

  await writeSecureFile(outputDir, join(outputDir, "_index.csv"), csvContent);

  if (errors.length > 0) {
    await writeSecureFile(outputDir, join(outputDir, "_errors.log"), `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
  try {
    await createZipArchive(outputDir, zipPath, baseOutputDir);
  } catch (error) {
    errors.push(`Failed to create zip archive: ${error instanceof Error ? error.message : String(error)}`);
    await writeSecureFile(outputDir, join(outputDir, "_errors.log"), `${errors.join("\n")}\n`);
  }

  return {
    outputDir,
    zipPath,
    totalEvidenceItems: evidence.length,
    totalFilesExported,
    totalControlFolders: controlMap.size,
    totalSizeBytes,
    errorCount: errors.length,
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

function buildExportText(audit: VantaAudit, result: VantaExportResult): string {
  const lines = [
    `Exported Vanta audit "${getAuditCustomerName(audit)} - ${audit.framework}".`,
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
    async execute(_toolCallId: string, args: CheckAccessArgs) {
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
        const client = new VantaAuditorClient(credentials);
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
    async execute(_toolCallId: string, args: ListAuditsArgs) {
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
        const client = new VantaAuditorClient(credentials);
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
    async execute(_toolCallId: string, args: ExportAuditArgs) {
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
        const client = new VantaAuditorClient(credentials);
        const audits = await client.listAudits();
        const audit = audits.find((entry) => entry.id === args.audit_id.trim());
        if (!audit) {
          return errorResult(
            `No Vanta audit with ID "${args.audit_id}" was returned for the provided credentials.`,
            { tool: "vanta_export_audit", audit_id: args.audit_id },
          );
        }

        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportVantaAuditPackage(client, audit, outputRoot);

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
