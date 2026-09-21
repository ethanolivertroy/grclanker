/**
 * Zendesk security inspector tools for grclanker.
 *
 * Read-only Zendesk Support API access covering the 25 controls in
 * specs/zendesk-sec-inspector.spec.md. Controls that the published API
 * reference cannot verify are emitted as manual findings that name the
 * Admin Center evidence a reviewer must collect.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/zendesk";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_ITEMS = 2000;
const DEFAULT_MAX_PAGES = 100;
const DEFAULT_RATE_LIMIT_RETRIES = 3;
const DEFAULT_SERVER_ERROR_RETRIES = 2;
const DEFAULT_ADMIN_THRESHOLD = 5;
const DEFAULT_SUSPENDED_TICKET_AGE_DAYS = 30;
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_RETENTION_DAYS = 365;
const DEFAULT_AUDIT_LOG_SAMPLE = 100;
const DAY_MS = 86_400_000;

export type ZendeskAuthMode = "api_token" | "oauth";

export interface ZendeskResolvedConfig {
  subdomain: string;
  baseUrl: string;
  authMode: ZendeskAuthMode;
  email?: string;
  apiToken?: string;
  oauthToken?: string;
  timeoutMs: number;
  sourceChain: string[];
}

export type ZendeskSnapshotStatus = "ok" | "forbidden" | "not_found" | "error";

export interface ZendeskSnapshot<T> {
  status: ZendeskSnapshotStatus;
  data?: T;
  error?: string;
  httpStatus?: number;
}

export interface ZendeskListResult {
  items: JsonRecord[];
  truncated: boolean;
  pages: number;
}

export interface ZendeskAccessSurface {
  name: string;
  endpoint: string;
  requiredRole: "agent" | "admin" | "admin-enterprise";
  status: "readable" | "forbidden" | "not_found" | "error";
  count?: number;
  error?: string;
}

export interface ZendeskAccessCheckResult {
  status: "healthy" | "limited";
  subdomain: string;
  authMode: ZendeskAuthMode;
  currentUserRole?: string;
  surfaces: ZendeskAccessSurface[];
  missingPermissions: string[];
  notes: string[];
  recommendedNextStep: string;
}

export type ZendeskFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface ZendeskFinding {
  id: string;
  control: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: ZendeskFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface ZendeskAssessmentResult {
  category: string;
  title: string;
  summary: JsonRecord;
  findings: ZendeskFinding[];
  errors: string[];
  snapshots: Record<string, unknown>;
}

export interface ZendeskAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface ZendeskAssessmentOptions {
  adminThreshold?: number;
  suspendedTicketAgeDays?: number;
  staleDays?: number;
  retentionDays?: number;
  maxItems?: number;
  now?: () => Date;
}

type AuthArgs = {
  subdomain?: string;
  email?: string;
  api_token?: string;
  oauth_token?: string;
  base_url?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AssessArgs = AuthArgs & {
  admin_threshold?: number;
  suspended_ticket_age_days?: number;
  stale_days?: number;
  retention_days?: number;
  max_items?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

const CONTROL_MAPPINGS: Record<number, string[]> = {
  1: ["FedRAMP IA-2", "CMMC IA.L2-3.5.1", "SOC 2 CC6.1", "CIS 4.1", "PCI-DSS 8.3.1", "DISA STIG SRG-APP-000148", "IRAP ISM-1557", "ISMAP 8.2.1"],
  2: ["FedRAMP IA-2(1)", "CMMC IA.L2-3.5.3", "SOC 2 CC6.1", "CIS 4.5", "PCI-DSS 8.3.2", "DISA STIG SRG-APP-000149", "IRAP ISM-1401", "ISMAP 8.2.2"],
  3: ["FedRAMP IA-5(1)", "CMMC IA.L2-3.5.7", "SOC 2 CC6.1", "CIS 5.1", "PCI-DSS 8.2.3", "DISA STIG SRG-APP-000164", "IRAP ISM-0421", "ISMAP 8.2.3"],
  4: ["FedRAMP SC-7", "CMMC SC.L2-3.13.6", "SOC 2 CC6.6", "CIS 4.4", "PCI-DSS 1.3.2", "DISA STIG SRG-APP-000383", "IRAP ISM-1284", "ISMAP 10.2.2"],
  5: ["FedRAMP AC-12", "CMMC AC.L2-3.1.10", "SOC 2 CC6.1", "CIS 5.6", "PCI-DSS 8.1.8", "DISA STIG SRG-APP-000295", "IRAP ISM-1164", "ISMAP 8.3.1"],
  6: ["FedRAMP AC-6(1)", "CMMC AC.L2-3.1.5", "SOC 2 CC6.3", "CIS 6.1", "PCI-DSS 7.1.1", "DISA STIG SRG-APP-000340", "IRAP ISM-1508", "ISMAP 8.1.2"],
  7: ["FedRAMP AC-6(5)", "CMMC AC.L2-3.1.5", "SOC 2 CC6.3", "CIS 6.2", "PCI-DSS 7.1.2", "DISA STIG SRG-APP-000340", "IRAP ISM-1508", "ISMAP 8.1.3"],
  8: ["FedRAMP AC-3", "CMMC AC.L2-3.1.2", "SOC 2 CC6.1", "CIS 6.1", "PCI-DSS 7.1.1", "DISA STIG SRG-APP-000033", "IRAP ISM-1508", "ISMAP 8.1.1"],
  9: ["FedRAMP AU-2", "CMMC AU.L2-3.3.1", "SOC 2 CC7.2", "CIS 8.1", "PCI-DSS 10.1", "DISA STIG SRG-APP-000089", "IRAP ISM-0580", "ISMAP 12.1.1"],
  10: ["FedRAMP AU-11", "CMMC AU.L2-3.3.1", "SOC 2 CC7.2", "CIS 8.3", "PCI-DSS 10.7", "DISA STIG SRG-APP-000515", "IRAP ISM-0859", "ISMAP 12.1.2"],
  11: ["FedRAMP SC-28", "CMMC SC.L2-3.13.16", "SOC 2 CC6.1", "CIS 14.7", "PCI-DSS 3.4", "DISA STIG SRG-APP-000231", "IRAP ISM-0457", "ISMAP 10.1.2"],
  12: ["FedRAMP SI-12", "CMMC MP.L2-3.8.3", "SOC 2 CC6.5", "CIS 3.1", "PCI-DSS 3.1", "DISA STIG SRG-APP-000504", "IRAP ISM-0261", "ISMAP 7.1.1"],
  13: ["FedRAMP IA-5(1)", "CMMC IA.L2-3.5.10", "SOC 2 CC6.1", "CIS 4.4", "PCI-DSS 8.2.4", "DISA STIG SRG-APP-000174", "IRAP ISM-1557", "ISMAP 8.2.4"],
  14: ["FedRAMP AC-6", "CMMC AC.L2-3.1.1", "SOC 2 CC6.3", "CIS 6.1", "PCI-DSS 7.1.1", "DISA STIG SRG-APP-000033", "IRAP ISM-1508", "ISMAP 8.1.1"],
  15: ["FedRAMP CM-7", "CMMC CM.L2-3.4.7", "SOC 2 CC6.6", "CIS 13.5", "PCI-DSS 2.2.2", "DISA STIG SRG-APP-000141", "IRAP ISM-1284", "ISMAP 6.1.1"],
  16: ["FedRAMP CM-7", "CMMC CM.L2-3.4.7", "SOC 2 CC6.6", "CIS 13.5", "PCI-DSS 2.2.2", "DISA STIG SRG-APP-000141", "IRAP ISM-1284", "ISMAP 6.1.1"],
  17: ["FedRAMP CM-3", "CMMC CM.L2-3.4.3", "SOC 2 CC8.1", "CIS 2.3", "PCI-DSS 6.4.1", "DISA STIG SRG-APP-000128", "IRAP ISM-1211", "ISMAP 6.2.1"],
  18: ["FedRAMP SC-8", "CMMC SC.L2-3.13.1", "SOC 2 CC6.7", "CIS 14.4", "PCI-DSS 4.1", "DISA STIG SRG-APP-000439", "IRAP ISM-0487", "ISMAP 10.1.1"],
  19: ["FedRAMP SC-7", "CMMC SC.L2-3.13.6", "SOC 2 CC6.6", "CIS 13.1", "PCI-DSS 1.3.1", "DISA STIG SRG-APP-000383", "IRAP ISM-1284", "ISMAP 10.2.1"],
  20: ["FedRAMP SI-4", "CMMC SI.L2-3.14.6", "SOC 2 CC7.2", "CIS 8.5", "PCI-DSS 10.6.1", "DISA STIG SRG-APP-000095", "IRAP ISM-0580", "ISMAP 12.1.3"],
  21: ["FedRAMP IA-2", "CMMC IA.L2-3.5.1", "SOC 2 CC6.1", "CIS 4.1", "PCI-DSS 8.3.1", "DISA STIG SRG-APP-000148", "IRAP ISM-1557", "ISMAP 8.2.1"],
  22: ["FedRAMP CM-2", "CMMC CM.L2-3.4.1", "SOC 2 CC6.1", "CIS 2.1", "PCI-DSS 2.2", "DISA STIG SRG-APP-000128", "IRAP ISM-1211", "ISMAP 6.1.1"],
  23: ["FedRAMP AC-4", "CMMC AC.L2-3.1.3", "SOC 2 CC6.6", "CIS 13.4", "PCI-DSS 7.1.2", "DISA STIG SRG-APP-000039", "IRAP ISM-1284", "ISMAP 8.1.3"],
  24: ["FedRAMP SC-8(1)", "CMMC SC.L2-3.13.8", "SOC 2 CC6.7", "CIS 14.4", "PCI-DSS 4.1", "DISA STIG SRG-APP-000441", "IRAP ISM-0487", "ISMAP 10.1.1"],
  25: ["FedRAMP AC-4", "CMMC AC.L2-3.1.3", "SOC 2 CC6.6", "CIS 13.4", "PCI-DSS 1.3.4", "DISA STIG SRG-APP-000039", "IRAP ISM-1284", "ISMAP 8.1.3"],
};

const FRAMEWORK_REPORTS: Array<{ slug: string; title: string; prefix: string }> = [
  { slug: "fedramp", title: "FedRAMP / NIST 800-53 Compliance Report", prefix: "FedRAMP " },
  { slug: "cmmc", title: "CMMC Compliance Report", prefix: "CMMC " },
  { slug: "soc2", title: "SOC 2 Compliance Report", prefix: "SOC 2 " },
  { slug: "cis", title: "CIS Controls Compliance Report", prefix: "CIS " },
  { slug: "pci_dss", title: "PCI-DSS Compliance Report", prefix: "PCI-DSS " },
  { slug: "disa_stig", title: "DISA STIG Compliance Checklist", prefix: "DISA STIG " },
  { slug: "irap", title: "IRAP / ISM Compliance Report", prefix: "IRAP " },
  { slug: "ismap", title: "ISMAP Compliance Report", prefix: "ISMAP " },
];

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecordArray(value: unknown): JsonRecord[] {
  return asArray(value).map(asObject).filter((item): item is JsonRecord => Boolean(item));
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/^(true|1|yes)$/i.test(value.trim())) return true;
    if (/^(false|0|no)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function parseDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function ageInDays(value: unknown, now: Date): number | undefined {
  const parsed = parseDate(value);
  if (!parsed) return undefined;
  return Math.floor((now.getTime() - parsed.getTime()) / DAY_MS);
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "zendesk";
}

function normalizeSubdomain(value: string): string {
  const trimmed = value.trim().toLowerCase();
  const hostMatch = trimmed.match(/^(?:https?:\/\/)?([a-z0-9-]+)\.zendesk\.com/);
  const candidate = hostMatch?.[1] ?? trimmed;
  if (!/^[a-z0-9-]+$/.test(candidate)) {
    throw new Error(`Invalid Zendesk subdomain: ${value}`);
  }
  return candidate;
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function readConfigFile(pathname: string): JsonRecord | undefined {
  if (!existsSync(pathname)) return undefined;
  const raw = readFileSync(pathname, "utf8");
  if (raw.trim().length === 0) return undefined;
  const parsed = JSON.parse(raw) as unknown;
  const object = asObject(parsed);
  if (!object) {
    throw new Error(`Zendesk config file ${pathname} must contain a JSON object.`);
  }
  return object;
}

export function resolveZendeskConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
): ZendeskResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file)
    ?? asString(env.ZENDESK_CONFIG_FILE)
    ?? join(homeDir, ".zendesk", "config.json");
  const fileConfig = readConfigFile(configPath) ?? {};
  if (Object.keys(fileConfig).length > 0) sourceChain.push(`config:${configPath}`);

  const pick = (argKey: string, envKeys: string[], fileKeys: string[]): { value?: string; source?: string } => {
    const argValue = asString(input[argKey]);
    if (argValue) return { value: argValue, source: "arguments" };
    for (const key of envKeys) {
      const envValue = asString(env[key]);
      if (envValue) return { value: envValue, source: "environment" };
    }
    for (const key of fileKeys) {
      const fileValue = asString(fileConfig[key]);
      if (fileValue) return { value: fileValue, source: "config-file" };
    }
    return {};
  };

  const subdomain = pick("subdomain", ["ZENDESK_SUBDOMAIN"], ["subdomain"]);
  const email = pick("email", ["ZENDESK_EMAIL"], ["email"]);
  const apiToken = pick("api_token", ["ZENDESK_API_TOKEN"], ["api_token", "apiToken"]);
  const oauthToken = pick("oauth_token", ["ZENDESK_OAUTH_TOKEN", "ZENDESK_ACCESS_TOKEN"], ["oauth_token", "oauthToken"]);
  const baseUrl = pick("base_url", ["ZENDESK_BASE_URL"], ["base_url", "baseUrl"]);
  const timeout = asNumber(input.timeout_seconds) ?? asNumber(env.ZENDESK_TIMEOUT) ?? asNumber(fileConfig.timeout_seconds);

  if (!subdomain.value) {
    throw new Error("Zendesk subdomain is required. Set ZENDESK_SUBDOMAIN, add subdomain to the config file, or pass subdomain explicitly.");
  }
  sourceChain.push(`subdomain:${subdomain.source}`);

  let authMode: ZendeskAuthMode;
  if (oauthToken.value && !(asString(input.api_token) && asString(input.email))) {
    authMode = "oauth";
    sourceChain.push(`oauth-token:${oauthToken.source}`);
  } else if (apiToken.value && email.value) {
    authMode = "api_token";
    sourceChain.push(`api-token:${apiToken.source}`, `email:${email.source}`);
  } else if (apiToken.value && !email.value) {
    throw new Error("Zendesk API token auth requires ZENDESK_EMAIL (or an email argument) alongside ZENDESK_API_TOKEN.");
  } else {
    throw new Error("Zendesk credentials are required. Provide ZENDESK_EMAIL plus ZENDESK_API_TOKEN, or ZENDESK_OAUTH_TOKEN.");
  }

  const normalizedSubdomain = normalizeSubdomain(subdomain.value);
  return {
    subdomain: normalizedSubdomain,
    baseUrl: normalizeBaseUrl(baseUrl.value ?? `https://${normalizedSubdomain}.zendesk.com/api/v2`),
    authMode,
    email: authMode === "api_token" ? email.value : undefined,
    apiToken: authMode === "api_token" ? apiToken.value : undefined,
    oauthToken: authMode === "oauth" ? oauthToken.value : undefined,
    timeoutMs: parseTimeoutSeconds(timeout),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class ZendeskApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ZendeskApiError";
    this.status = status;
  }
}

function redactSecrets(text: string, secrets: Array<string | undefined>): string {
  let output = text;
  for (const secret of secrets) {
    if (secret && secret.length >= 4) {
      output = output.split(secret).join("[REDACTED]");
    }
  }
  return output;
}

function zendeskErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const parts = [
    asString(object.error),
    asString(object.description),
    asString(object.message),
    asString(asObject(object.error)?.title),
    asString(asObject(object.error)?.message),
    ...asRecordArray(object.errors).map((item) => asString(item.title) ?? asString(item.detail)),
  ].filter((item): item is string => Boolean(item));
  return parts.length > 0 ? [...new Set(parts)].join("; ") : undefined;
}

function retryDelayMs(response: Response): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30_000);
    const asDate = new Date(retryAfter);
    if (!Number.isNaN(asDate.getTime())) {
      return Math.min(Math.max(asDate.getTime() - Date.now(), 0), 30_000);
    }
  }
  return 1000;
}

export class ZendeskApiClient {
  private readonly config: ZendeskResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    config: ZendeskResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: (ms: number) => Promise<void>;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
  }

  getResolvedConfig(): ZendeskResolvedConfig {
    return this.config;
  }

  private authorizationHeader(): string {
    switch (this.config.authMode) {
      case "api_token":
        return `Basic ${Buffer.from(`${this.config.email}/token:${this.config.apiToken}`).toString("base64")}`;
      case "oauth":
        return `Bearer ${this.config.oauthToken}`;
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unsupported Zendesk auth mode: ${String(exhaustive)}`);
      }
    }
  }

  private redact(text: string): string {
    return redactSecrets(text, [this.config.apiToken, this.config.oauthToken]);
  }

  buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async request(url: string, attempt = 0, serverErrors = 0): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: this.authorizationHeader(),
        },
        signal: controller.signal,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(this.redact(`Zendesk request failed for ${url}: ${message}`));
    } finally {
      clearTimeout(timeout);
    }

    if (response.status === 429 && attempt < DEFAULT_RATE_LIMIT_RETRIES) {
      await this.sleep(retryDelayMs(response));
      return this.request(url, attempt + 1, serverErrors);
    }
    if (response.status >= 500 && serverErrors < DEFAULT_SERVER_ERROR_RETRIES) {
      await this.sleep(500 * (serverErrors + 1));
      return this.request(url, attempt, serverErrors + 1);
    }
    return response;
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path, query);
    const response = await this.request(url);
    const rawText = await response.text();
    let payload: JsonRecord = {};
    if (rawText.length > 0) {
      try {
        payload = asObject(JSON.parse(rawText)) ?? {};
      } catch {
        payload = {};
      }
    }
    if (!response.ok) {
      const detail = zendeskErrorSummary(payload) ?? rawText.slice(0, 200);
      throw new ZendeskApiError(
        this.redact(`Zendesk request failed for ${path} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`),
        response.status,
      );
    }
    return payload;
  }

  async listCursor(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { pageSize?: number; maxItems?: number } = {},
  ): Promise<ZendeskListResult> {
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 100);
    const maxItems = clampNumber(options.maxItems, DEFAULT_MAX_ITEMS, 1, 100_000);
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = this.buildUrl(path, { ...query, "page[size]": pageSize });
    let pages = 0;
    let truncated = false;

    while (nextUrl) {
      const payload: JsonRecord = await this.get(nextUrl);
      pages += 1;
      const pageItems = asRecordArray(payload[collectionKey]);
      items.push(...pageItems);
      const meta = asObject(payload.meta);
      const hasMore = asBoolean(meta?.has_more) === true;
      const links = asObject(payload.links);
      const linkNext = asString(links?.next);
      const afterCursor = asString(meta?.after_cursor);
      if (!hasMore || pageItems.length === 0) break;
      if (items.length >= maxItems || pages >= DEFAULT_MAX_PAGES) {
        truncated = true;
        break;
      }
      nextUrl = linkNext ?? (afterCursor ? this.buildUrl(path, { ...query, "page[size]": pageSize, "page[after]": afterCursor }) : undefined);
      if (!nextUrl) {
        truncated = true;
      }
    }

    return { items, truncated, pages };
  }

  async listOffset(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { perPage?: number; maxItems?: number } = {},
  ): Promise<ZendeskListResult> {
    const perPage = clampNumber(options.perPage, DEFAULT_PAGE_SIZE, 1, 100);
    const maxItems = clampNumber(options.maxItems, DEFAULT_MAX_ITEMS, 1, 10_000);
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = this.buildUrl(path, { ...query, per_page: perPage });
    let pages = 0;
    let truncated = false;

    while (nextUrl) {
      const payload: JsonRecord = await this.get(nextUrl);
      pages += 1;
      const pageItems = asRecordArray(payload[collectionKey]);
      items.push(...pageItems);
      const nextPage = asString(payload.next_page);
      if (!nextPage || pageItems.length === 0) break;
      if (items.length >= maxItems || pages >= DEFAULT_MAX_PAGES) {
        truncated = true;
        break;
      }
      nextUrl = nextPage;
    }

    return { items, truncated, pages };
  }

  async listUnpaginated(path: string, collectionKey: string, query: JsonRecord = {}): Promise<ZendeskListResult> {
    const payload = await this.get(path, query);
    return { items: asRecordArray(payload[collectionKey]), truncated: false, pages: 1 };
  }

  async getCurrentUser(): Promise<JsonRecord> {
    const payload = await this.get("/users/me");
    return asObject(payload.user) ?? {};
  }

  async getAccountSettings(): Promise<JsonRecord> {
    const payload = await this.get("/account/settings");
    return asObject(payload.settings) ?? {};
  }

  async listTeamMembers(maxItems?: number): Promise<ZendeskListResult> {
    const url = `${this.buildUrl("/users")}?role[]=agent&role[]=admin`;
    return this.listCursor(url, "users", {}, { maxItems });
  }

  async listCustomRoles(): Promise<ZendeskListResult> {
    return this.listUnpaginated("/custom_roles", "custom_roles");
  }

  async listGroups(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/groups", "groups", {}, { maxItems });
  }

  async listGroupMemberships(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/group_memberships", "group_memberships", {}, { maxItems });
  }

  async listRecentAuditLogs(limit = DEFAULT_AUDIT_LOG_SAMPLE): Promise<ZendeskListResult> {
    return this.listCursor("/audit_logs", "audit_logs", { sort: "-created_at" }, { pageSize: Math.min(limit, 100), maxItems: limit });
  }

  async getOldestAuditLog(): Promise<JsonRecord | undefined> {
    const payload = await this.get("/audit_logs", { sort: "created_at", "page[size]": 1 });
    return asRecordArray(payload.audit_logs)[0];
  }

  async listOAuthClients(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/oauth/clients", "clients", {}, { maxItems });
  }

  async listOAuthTokens(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/oauth/tokens", "tokens", { all: "true" }, { maxItems });
  }

  async listAppInstallations(): Promise<ZendeskListResult> {
    return this.listUnpaginated("/apps/installations", "installations");
  }

  async listOwnedApps(): Promise<ZendeskListResult> {
    return this.listUnpaginated("/apps/owned", "apps");
  }

  async listBrands(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/brands", "brands", {}, { maxItems });
  }

  async listWebhooks(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/webhooks", "webhooks", {}, { maxItems });
  }

  async listTargets(): Promise<ZendeskListResult> {
    return this.listUnpaginated("/targets", "targets");
  }

  async listTriggers(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/triggers", "triggers", {}, { maxItems });
  }

  async listAutomations(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/automations", "automations", {}, { maxItems });
  }

  async listSharingAgreements(): Promise<ZendeskListResult> {
    return this.listUnpaginated("/sharing_agreements", "sharing_agreements");
  }

  async listSuspendedTickets(maxItems?: number): Promise<ZendeskListResult> {
    return this.listCursor("/suspended_tickets", "suspended_tickets", { sort_by: "created_at", sort_order: "asc" }, { maxItems });
  }
}

export type ZendeskReadClient = Pick<
  ZendeskApiClient,
  | "getResolvedConfig"
  | "getCurrentUser"
  | "getAccountSettings"
  | "listTeamMembers"
  | "listCustomRoles"
  | "listGroups"
  | "listGroupMemberships"
  | "listRecentAuditLogs"
  | "getOldestAuditLog"
  | "listOAuthClients"
  | "listOAuthTokens"
  | "listAppInstallations"
  | "listOwnedApps"
  | "listBrands"
  | "listWebhooks"
  | "listTargets"
  | "listTriggers"
  | "listAutomations"
  | "listSharingAgreements"
  | "listSuspendedTickets"
>;

async function snapshot<T>(load: () => Promise<T>): Promise<ZendeskSnapshot<T>> {
  try {
    return { status: "ok", data: await load() };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (error instanceof ZendeskApiError) {
      if (error.status === 401 || error.status === 403) return { status: "forbidden", error: message, httpStatus: error.status };
      if (error.status === 404) return { status: "not_found", error: message, httpStatus: error.status };
      return { status: "error", error: message, httpStatus: error.status };
    }
    return { status: "error", error: message };
  }
}

function snapshotCause(name: string, snap: ZendeskSnapshot<unknown>): string {
  switch (snap.status) {
    case "ok":
      return `${name} was readable.`;
    case "forbidden":
      return `${name} returned ${snap.httpStatus ?? 403} (credential lacks permission).`;
    case "not_found":
      return `${name} returned 404 (endpoint unavailable on this account or plan).`;
    case "error":
      return `${name} could not be read: ${snap.error ?? "unknown error"}.`;
    default: {
      const exhaustive: never = snap.status;
      return String(exhaustive);
    }
  }
}

function snapshotErrors(entries: Array<[string, ZendeskSnapshot<unknown>]>): string[] {
  return entries
    .filter(([, snap]) => snap.status !== "ok")
    .map(([name, snap]) => `${name}: ${snap.error ?? snap.status}`);
}

function finding(
  control: number,
  title: string,
  severity: ZendeskFinding["severity"],
  status: ZendeskFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): ZendeskFinding {
  return {
    id: `ZD-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity,
    status,
    summary,
    evidence,
    mappings: CONTROL_MAPPINGS[control] ?? [],
  };
}

function manualFinding(
  control: number,
  title: string,
  severity: ZendeskFinding["severity"],
  cause: string,
  evidenceInstruction: string,
  evidence?: JsonRecord,
): ZendeskFinding {
  return finding(control, title, severity, "manual", `${cause} Manual evidence: ${evidenceInstruction}`, evidence);
}

function listSnapshotItems(snap: ZendeskSnapshot<ZendeskListResult>): JsonRecord[] {
  return snap.data?.items ?? [];
}

function isTruncated(snap: ZendeskSnapshot<ZendeskListResult>): boolean {
  return snap.data?.truncated === true;
}

function truncationNote(name: string, snap: ZendeskSnapshot<ZendeskListResult>): string {
  return isTruncated(snap)
    ? ` The ${name} inventory was truncated after ${listSnapshotItems(snap).length} items (more pages exist), so the verdict is limited to the seen population.`
    : "";
}

function partitionByDate(
  items: JsonRecord[],
  field: string,
  thresholdDays: number,
  now: Date,
): { recent: JsonRecord[]; stale: JsonRecord[]; undated: JsonRecord[] } {
  const recent: JsonRecord[] = [];
  const stale: JsonRecord[] = [];
  const undated: JsonRecord[] = [];
  for (const item of items) {
    const age = ageInDays(item[field], now);
    if (age === undefined) undated.push(item);
    else if (age > thresholdDays) stale.push(item);
    else recent.push(item);
  }
  return { recent, stale, undated };
}

function userLabel(user: JsonRecord): string {
  return asString(user.email) ?? asString(user.name) ?? asString(user.id) ?? "user";
}

function isActiveTeamMember(user: JsonRecord): boolean {
  const role = asString(user.role);
  return (role === "agent" || role === "admin")
    && asBoolean(user.active) !== false
    && asBoolean(user.suspended) !== true;
}

function customRoleIsAdminEquivalent(role: JsonRecord): string[] {
  const configuration = asObject(role.configuration) ?? {};
  const reasons: string[] = [];
  if (asString(configuration.manage_roles) === "all-except-self") reasons.push("manage_roles=all-except-self");
  if (asString(configuration.manage_team_members) === "all-with-self-restriction") reasons.push("manage_team_members=all-with-self-restriction");
  if (asBoolean(configuration.manage_api_credentials) === true) reasons.push("manage_api_credentials=true");
  if (asBoolean(configuration.manage_business_rules) === true && asBoolean(configuration.manage_triggers) === true && asString(configuration.ticket_access) === "all") {
    reasons.push("ticket_access=all with business rule and trigger management");
  }
  return reasons;
}

function urlScheme(value: unknown): string | undefined {
  const text = asString(value);
  if (!text) return undefined;
  try {
    return new URL(text).protocol.replace(/:$/, "");
  } catch {
    return undefined;
  }
}

function urlHost(value: unknown): string | undefined {
  const text = asString(value);
  if (!text) return undefined;
  try {
    return new URL(text).host;
  } catch {
    return undefined;
  }
}

function externalNotificationActions(rule: JsonRecord): Array<{ field: string; destination: string }> {
  return asRecordArray(rule.actions)
    .map((action) => ({ field: asString(action.field) ?? "", value: action.value }))
    .filter((action) => action.field === "notification_target" || action.field === "notification_webhook" || action.field === "share_ticket")
    .map((action) => ({
      field: action.field,
      destination: asString(asArray(action.value)[0]) ?? asString(action.value) ?? "unknown",
    }));
}

export async function checkZendeskAccess(client: ZendeskReadClient): Promise<ZendeskAccessCheckResult> {
  const config = client.getResolvedConfig();
  const currentUser = await snapshot(() => client.getCurrentUser());
  const currentUserRole = asString(currentUser.data?.role);

  const probes: Array<{
    name: string;
    endpoint: string;
    requiredRole: ZendeskAccessSurface["requiredRole"];
    load: () => Promise<unknown>;
    count?: (value: unknown) => number | undefined;
  }> = [
    { name: "current_user", endpoint: "/api/v2/users/me", requiredRole: "agent", load: () => client.getCurrentUser(), count: () => 1 },
    { name: "account_settings", endpoint: "/api/v2/account/settings", requiredRole: "agent", load: () => client.getAccountSettings(), count: () => 1 },
    { name: "team_members", endpoint: "/api/v2/users?role[]=agent&role[]=admin", requiredRole: "agent", load: () => client.listTeamMembers(200) },
    { name: "custom_roles", endpoint: "/api/v2/custom_roles", requiredRole: "admin-enterprise", load: () => client.listCustomRoles() },
    { name: "groups", endpoint: "/api/v2/groups", requiredRole: "agent", load: () => client.listGroups(200) },
    { name: "group_memberships", endpoint: "/api/v2/group_memberships", requiredRole: "agent", load: () => client.listGroupMemberships(200) },
    { name: "audit_logs", endpoint: "/api/v2/audit_logs", requiredRole: "admin-enterprise", load: () => client.listRecentAuditLogs(1) },
    { name: "oauth_clients", endpoint: "/api/v2/oauth/clients", requiredRole: "admin", load: () => client.listOAuthClients(100) },
    { name: "oauth_tokens", endpoint: "/api/v2/oauth/tokens?all=true", requiredRole: "admin", load: () => client.listOAuthTokens(100) },
    { name: "app_installations", endpoint: "/api/v2/apps/installations", requiredRole: "agent", load: () => client.listAppInstallations() },
    { name: "owned_apps", endpoint: "/api/v2/apps/owned", requiredRole: "admin", load: () => client.listOwnedApps() },
    { name: "brands", endpoint: "/api/v2/brands", requiredRole: "admin", load: () => client.listBrands(100) },
    { name: "webhooks", endpoint: "/api/v2/webhooks", requiredRole: "agent", load: () => client.listWebhooks(100) },
    { name: "targets", endpoint: "/api/v2/targets", requiredRole: "agent", load: () => client.listTargets() },
    { name: "triggers", endpoint: "/api/v2/triggers", requiredRole: "agent", load: () => client.listTriggers(100) },
    { name: "automations", endpoint: "/api/v2/automations", requiredRole: "agent", load: () => client.listAutomations(100) },
    { name: "sharing_agreements", endpoint: "/api/v2/sharing_agreements", requiredRole: "agent", load: () => client.listSharingAgreements() },
    { name: "suspended_tickets", endpoint: "/api/v2/suspended_tickets", requiredRole: "admin", load: () => client.listSuspendedTickets(100) },
  ];

  const surfaces: ZendeskAccessSurface[] = [];
  for (const probe of probes) {
    const snap = probe.name === "current_user" ? currentUser : await snapshot(probe.load);
    const items = asObject(snap.data)?.items;
    surfaces.push({
      name: probe.name,
      endpoint: probe.endpoint,
      requiredRole: probe.requiredRole,
      status: snap.status === "ok" ? "readable" : snap.status,
      count: snap.status === "ok" ? (probe.count ? probe.count(snap.data) : Array.isArray(items) ? items.length : undefined) : undefined,
      error: snap.error,
    });
  }

  const coreReadable = ["current_user", "account_settings", "team_members"].every((name) =>
    surfaces.find((surface) => surface.name === name)?.status === "readable");
  const missingPermissions = surfaces
    .filter((surface) => surface.status === "forbidden")
    .map((surface) => `${surface.name} requires ${surface.requiredRole === "agent" ? "an agent" : surface.requiredRole === "admin" ? "an admin" : "an Enterprise admin"} credential (${surface.endpoint}).`);
  const unavailable = surfaces.filter((surface) => surface.status === "not_found").map((surface) => surface.name);
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = coreReadable && missingPermissions.length === 0 ? "healthy" : "limited";

  return {
    status,
    subdomain: config.subdomain,
    authMode: config.authMode,
    currentUserRole,
    surfaces,
    missingPermissions,
    notes: [
      `Using Zendesk subdomain ${config.subdomain} with ${config.authMode === "oauth" ? "an OAuth bearer token" : "API token basic auth"}.`,
      `Authenticated as ${currentUser.status === "ok" ? `${userLabel(currentUser.data ?? {})} (role: ${currentUserRole ?? "unknown"})` : "an unknown principal (current user lookup failed)"}.`,
      `${readableCount}/${surfaces.length} Zendesk audit surfaces are readable.`,
      ...(unavailable.length > 0 ? [`Unavailable on this account or plan: ${unavailable.join(", ")}.`] : []),
      ...(currentUserRole && currentUserRole !== "admin" ? ["The credential is not an admin, so admin-only inventories (OAuth clients and tokens, audit logs, owned apps, brands, suspended tickets) will render as manual findings."] : []),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run zendesk_assess_authentication, zendesk_assess_access_control, zendesk_assess_data_protection, zendesk_assess_integrations, or zendesk_export_audit_bundle."
      : "Use an admin API token or OAuth token with read scope so the admin-only surfaces become readable, then rerun zendesk_check_access.",
  };
}

function resolveOptions(options: ZendeskAssessmentOptions): Required<Omit<ZendeskAssessmentOptions, "now">> & { now: () => Date } {
  return {
    adminThreshold: clampNumber(options.adminThreshold, DEFAULT_ADMIN_THRESHOLD, 1, 10_000),
    suspendedTicketAgeDays: clampNumber(options.suspendedTicketAgeDays, DEFAULT_SUSPENDED_TICKET_AGE_DAYS, 1, 3650),
    staleDays: clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650),
    retentionDays: clampNumber(options.retentionDays, DEFAULT_RETENTION_DAYS, 1, 36_500),
    maxItems: clampNumber(options.maxItems, DEFAULT_MAX_ITEMS, 1, 100_000),
    now: options.now ?? (() => new Date()),
  };
}

function summarizeStatuses(findings: ZendeskFinding[]): JsonRecord {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

function roleCeilingReason(currentUser: ZendeskSnapshot<JsonRecord>): string | undefined {
  const role = asString(currentUser.data?.role);
  if (currentUser.status === "ok" && role === "admin") return undefined;
  return currentUser.status === "ok"
    ? `the credential's role is ${role ?? "unknown"} rather than admin, so it may only see a partial view of the account`
    : `the current user lookup (/users/me) failed (${currentUser.error ?? currentUser.status}), so the credential's role could not be confirmed`;
}

function finalizeFindings(findings: ZendeskFinding[], currentUser: ZendeskSnapshot<JsonRecord>): ZendeskFinding[] {
  const reason = roleCeilingReason(currentUser);
  const capped = reason
    ? findings.map((item): ZendeskFinding => item.status === "pass"
      ? {
        ...item,
        status: "warn",
        summary: `${item.summary} Verdict capped at warn because ${reason}.`,
        evidence: { ...(item.evidence ?? {}), verdict_capped_by_role: asString(currentUser.data?.role) ?? null },
      }
      : item)
    : findings;
  return [...capped].sort((left, right) => left.control - right.control);
}

export async function assessZendeskAuthentication(
  client: ZendeskReadClient,
  options: ZendeskAssessmentOptions = {},
): Promise<ZendeskAssessmentResult> {
  const config = client.getResolvedConfig();
  const resolved = resolveOptions(options);
  const currentUserSnap = await snapshot(() => client.getCurrentUser());
  const settingsSnap = await snapshot(() => client.getAccountSettings());
  const teamSnap = await snapshot(() => client.listTeamMembers(resolved.maxItems));
  const settings = settingsSnap.data ?? {};
  const activeFeatures = asObject(settings.active_features) ?? {};
  const apiSettings = asObject(settings.api) ?? {};
  const settingsEvidence: JsonRecord = {
    settings_readable: settingsSnap.status === "ok",
    end_user_social_logins: {
      google_login: asBoolean(activeFeatures.google_login) ?? null,
      facebook_login: asBoolean(activeFeatures.facebook_login) ?? null,
      twitter_login: asBoolean(activeFeatures.twitter_login) ?? null,
    },
    google_apps_connected: asBoolean(asObject(settings.google_apps)?.has_google_apps) ?? null,
  };
  const teamMembers = listSnapshotItems(teamSnap).filter(isActiveTeamMember);
  const adminCenterAuth = "Admin Center > Account > Security > Team member authentication (and End user authentication)";

  const findings: ZendeskFinding[] = [];

  findings.push(manualFinding(
    1,
    "SSO enforcement enabled",
    "critical",
    settingsSnap.status === "ok"
      ? "The published Account Settings reference exposes no SSO enforcement field, so SSO cannot be verified through the API."
      : `${snapshotCause("Account settings", settingsSnap)} SSO enforcement is not exposed by the published API in any case.`,
    `capture ${adminCenterAuth} showing SAML or JWT single sign-on enabled and Zendesk password sign-in disabled for team members.`,
    settingsEvidence,
  ));

  const twoFactorTitle = "Two-factor authentication required for agents";
  if (teamSnap.status !== "ok") {
    findings.push(manualFinding(2, twoFactorTitle, "critical", snapshotCause("Team member list (/users?role[]=agent&role[]=admin)", teamSnap), `export the team member list from Admin Center > People > Team > Team members and capture ${adminCenterAuth} showing two-factor authentication required.`));
  } else if (teamMembers.length === 0) {
    findings.push(manualFinding(2, twoFactorTitle, "critical", "Zero active agents or admins were visible although every Zendesk account has at least one admin, so the credential sees only a partial population.", `use an admin credential and capture ${adminCenterAuth} showing two-factor authentication required.`, { seen_team_members: 0 }));
  } else {
    const withoutTwoFactor = teamMembers.filter((user) => asBoolean(user.two_factor_auth_enabled) === false);
    const unknownTwoFactor = teamMembers.filter((user) => asBoolean(user.two_factor_auth_enabled) === undefined);
    const truncated = isTruncated(teamSnap);
    const evidence: JsonRecord = {
      seen_team_members: teamMembers.length,
      inventory_truncated: truncated,
      without_two_factor: withoutTwoFactor.slice(0, 50).map(userLabel),
      two_factor_flag_missing: unknownTwoFactor.slice(0, 50).map(userLabel),
    };
    if (withoutTwoFactor.length > 0) {
      findings.push(finding(2, twoFactorTitle, "critical", "fail", `${withoutTwoFactor.length}/${teamMembers.length} active team members report two_factor_auth_enabled=false.${truncationNote("team member", teamSnap)}`, evidence));
    } else if (unknownTwoFactor.length > 0 || truncated) {
      findings.push(finding(2, twoFactorTitle, "critical", "warn", `${teamMembers.length - unknownTwoFactor.length}/${teamMembers.length} seen team members report two_factor_auth_enabled=true; ${unknownTwoFactor.length} did not expose the flag.${truncationNote("team member", teamSnap)} Confirm the account-level requirement in ${adminCenterAuth}.`, evidence));
    } else {
      findings.push(finding(2, twoFactorTitle, "critical", "pass", `All ${teamMembers.length} active team members report two_factor_auth_enabled=true and the inventory was read to completion. Confirm the account-level requirement toggle in ${adminCenterAuth} for audit evidence.`, evidence));
    }
  }

  findings.push(manualFinding(3, "Password policy meets complexity requirements", "high", "The published Account Settings reference exposes no password level or policy field.", "capture Admin Center > Account > Security > Team member authentication > Password level (Recommended, High, or Custom) and the custom policy details.", { settings_readable: settingsSnap.status === "ok" }));
  findings.push(manualFinding(4, "IP restrictions configured for agent access", "high", "The published Account Settings reference exposes no IP restriction field.", "capture Admin Center > Account > Security > Advanced > IP restrictions showing the allowed ranges and whether customers are exempt.", { settings_readable: settingsSnap.status === "ok" }));
  findings.push(manualFinding(5, "Session timeout configured and reasonable", "medium", "The published Account Settings reference exposes no session expiration field.", "capture Admin Center > Account > Security > Advanced > Authentication showing the team member and end user session expiration values.", { settings_readable: settingsSnap.status === "ok" }));

  const endUserTitle = "End-user authentication required (no anonymous tickets)";
  if (settingsSnap.status !== "ok") {
    findings.push(manualFinding(21, endUserTitle, "high", snapshotCause("Account settings", settingsSnap), "capture Admin Center > Account > Security > End user authentication and Admin Center > People > Configuration > End users (require sign-in, anybody can submit tickets)."));
  } else {
    const passwordApiAccess = asBoolean(apiSettings.api_password_access_end_users);
    findings.push(manualFinding(
      21,
      endUserTitle,
      "high",
      `The end user sign-in requirement is not exposed by the published Account Settings reference.${passwordApiAccess === true ? " Note: api.api_password_access_end_users=true, so end users may call the API with email and password; review whether that is intended." : passwordApiAccess === false ? " api.api_password_access_end_users=false (end users cannot call the API with a password)." : ""}`,
      "capture Admin Center > People > Configuration > End users showing 'Require sign-in' (or that 'Anybody can submit tickets' is disabled) and the end user authentication methods.",
      { ...settingsEvidence, api_password_access_end_users: passwordApiAccess ?? null },
    ));
  }

  const finalFindings = finalizeFindings(findings, currentUserSnap);
  const entries: Array<[string, ZendeskSnapshot<unknown>]> = [
    ["current_user", currentUserSnap],
    ["account_settings", settingsSnap],
    ["team_members", teamSnap],
  ];
  return {
    category: "authentication",
    title: "Zendesk authentication and network access",
    summary: {
      subdomain: config.subdomain,
      current_user_role: asString(currentUserSnap.data?.role) ?? null,
      seen_team_members: teamMembers.length,
      ...summarizeStatuses(finalFindings),
    },
    findings: finalFindings,
    errors: snapshotErrors(entries),
    snapshots: Object.fromEntries(entries.map(([name, snap]) => [name, snap.data ?? null])),
  };
}

export async function assessZendeskAccessControl(
  client: ZendeskReadClient,
  options: ZendeskAssessmentOptions = {},
): Promise<ZendeskAssessmentResult> {
  const config = client.getResolvedConfig();
  const resolved = resolveOptions(options);
  const now = resolved.now();
  const currentUserSnap = await snapshot(() => client.getCurrentUser());
  const settingsSnap = await snapshot(() => client.getAccountSettings());
  const teamSnap = await snapshot(() => client.listTeamMembers(resolved.maxItems));
  const rolesSnap = await snapshot(() => client.listCustomRoles());
  const groupsSnap = await snapshot(() => client.listGroups(resolved.maxItems));
  const membershipsSnap = await snapshot(() => client.listGroupMemberships(resolved.maxItems));
  const clientsSnap = await snapshot(() => client.listOAuthClients(resolved.maxItems));
  const tokensSnap = await snapshot(() => client.listOAuthTokens(resolved.maxItems));

  const teamMembers = listSnapshotItems(teamSnap).filter(isActiveTeamMember);
  const admins = teamMembers.filter((user) => asString(user.role) === "admin");
  const agents = teamMembers.filter((user) => asString(user.role) === "agent");
  const findings: ZendeskFinding[] = [];

  const leastPrivilegeTitle = "Agent roles follow least privilege";
  if (teamSnap.status !== "ok") {
    findings.push(manualFinding(6, leastPrivilegeTitle, "critical", snapshotCause("Team member list", teamSnap), "export Admin Center > People > Team > Team members with role assignments and Admin Center > People > Team > Roles."));
  } else if (teamMembers.length === 0) {
    findings.push(manualFinding(6, leastPrivilegeTitle, "critical", "Zero active team members were visible, which indicates a partial view of the account.", "use an admin credential and export the team member and role lists from Admin Center.", { seen_team_members: 0 }));
  } else {
    const customRoles = listSnapshotItems(rolesSnap);
    const adminEquivalent = customRoles
      .map((role) => ({ name: asString(role.name) ?? asString(role.id) ?? "role", members: asNumber(role.team_member_count) ?? 0, reasons: customRoleIsAdminEquivalent(role) }))
      .filter((role) => role.reasons.length > 0);
    const unrestrictedAgents = agents.filter((user) => asBoolean(user.restricted_agent) === false);
    const evidence: JsonRecord = {
      seen_team_members: teamMembers.length,
      admins: admins.length,
      agents: agents.length,
      unrestricted_agents: unrestrictedAgents.length,
      custom_roles_status: rolesSnap.status,
      custom_roles: customRoles.length,
      admin_equivalent_custom_roles: adminEquivalent.slice(0, 25),
      inventory_truncated: isTruncated(teamSnap),
    };
    if (rolesSnap.status !== "ok") {
      findings.push(manualFinding(6, leastPrivilegeTitle, "critical", `${snapshotCause("Custom roles (/custom_roles, Enterprise plan)", rolesSnap)} Built-in roles seen: ${admins.length} admins, ${agents.length} agents (${unrestrictedAgents.length} unrestricted).`, "capture Admin Center > People > Team > Roles and confirm agents are assigned the least-privileged built-in or custom role.", evidence));
    } else if (adminEquivalent.some((role) => role.members > 0)) {
      findings.push(finding(6, leastPrivilegeTitle, "critical", "fail", `${adminEquivalent.filter((role) => role.members > 0).length} custom roles grant admin-equivalent permissions (${adminEquivalent.map((role) => `${role.name}: ${role.reasons.join(", ")}`).join("; ")}).${truncationNote("team member", teamSnap)}`, evidence));
    } else if (isTruncated(teamSnap) || adminEquivalent.length > 0 || (agents.length > 0 && unrestrictedAgents.length === agents.length)) {
      findings.push(finding(6, leastPrivilegeTitle, "critical", "warn", `${customRoles.length} custom roles reviewed; ${adminEquivalent.length} admin-equivalent roles have no members; ${unrestrictedAgents.length}/${agents.length} agents are unrestricted.${truncationNote("team member", teamSnap)} Review whether unrestricted agents need account-wide ticket access.`, evidence));
    } else {
      findings.push(finding(6, leastPrivilegeTitle, "critical", "pass", `${teamMembers.length} team members (${admins.length} admins, ${agents.length} agents, ${unrestrictedAgents.length} unrestricted) and ${customRoles.length} custom roles were read to completion with no admin-equivalent custom roles.`, evidence));
    }
  }

  const adminTitle = "No excessive admin accounts";
  if (teamSnap.status !== "ok") {
    findings.push(manualFinding(7, adminTitle, "high", snapshotCause("Team member list", teamSnap), "export the admin list from Admin Center > People > Team > Team members filtered to the Administrator role."));
  } else if (admins.length === 0) {
    findings.push(manualFinding(7, adminTitle, "high", "Zero admins were visible although every account has at least one admin (account owner), so the inventory is partial.", "use an admin credential and export the Administrator list from Admin Center.", { seen_admins: 0, seen_team_members: teamMembers.length }));
  } else {
    const loginBuckets = partitionByDate(admins, "last_login_at", resolved.staleDays, now);
    const evidence: JsonRecord = {
      seen_admins: admins.length,
      admin_threshold: resolved.adminThreshold,
      admins: admins.slice(0, 50).map(userLabel),
      dormant_admins: loginBuckets.stale.slice(0, 25).map(userLabel),
      admins_without_last_login: loginBuckets.undated.slice(0, 25).map(userLabel),
      inventory_truncated: isTruncated(teamSnap),
    };
    if (admins.length > resolved.adminThreshold) {
      findings.push(finding(7, adminTitle, "high", "fail", `${admins.length} active admins exceed the threshold of ${resolved.adminThreshold}.${truncationNote("team member", teamSnap)}`, evidence));
    } else if (isTruncated(teamSnap) || loginBuckets.stale.length > 0 || loginBuckets.undated.length > 0) {
      findings.push(finding(7, adminTitle, "high", "warn", `${admins.length} active admins are within the threshold of ${resolved.adminThreshold}, but ${loginBuckets.stale.length} have not signed in for more than ${resolved.staleDays} days and ${loginBuckets.undated.length} have no last_login_at value.${truncationNote("team member", teamSnap)}`, evidence));
    } else {
      findings.push(finding(7, adminTitle, "high", "pass", `${admins.length} active admins are within the threshold of ${resolved.adminThreshold}; all signed in within ${resolved.staleDays} days and the inventory was read to completion.`, evidence));
    }
  }

  const groupsTitle = "Group-based access controls configured";
  const groups = listSnapshotItems(groupsSnap).filter((group) => asBoolean(group.deleted) !== true);
  const memberships = listSnapshotItems(membershipsSnap);
  if (groupsSnap.status !== "ok" || membershipsSnap.status !== "ok") {
    findings.push(manualFinding(8, groupsTitle, "medium", `${snapshotCause("Groups", groupsSnap)} ${snapshotCause("Group memberships", membershipsSnap)}`, "capture Admin Center > People > Team > Groups with member counts."));
  } else if (groups.length === 0) {
    findings.push(manualFinding(8, groupsTitle, "medium", "Zero groups were visible although every account has a default group, so the inventory is partial.", "use an admin credential and capture Admin Center > People > Team > Groups.", { seen_groups: 0 }));
  } else {
    const privateGroups = groups.filter((group) => asBoolean(group.is_public) === false);
    const evidence: JsonRecord = {
      seen_groups: groups.length,
      private_groups: privateGroups.length,
      seen_memberships: memberships.length,
      groups: groups.slice(0, 50).map((group) => asString(group.name) ?? asString(group.id) ?? "group"),
      inventory_truncated: isTruncated(groupsSnap) || isTruncated(membershipsSnap),
    };
    if (groups.length === 1 || memberships.length === 0) {
      findings.push(finding(8, groupsTitle, "medium", "warn", `${groups.length} group(s) and ${memberships.length} memberships were visible, so ticket access is not segmented by group.${truncationNote("group", groupsSnap)}`, evidence));
    } else if (isTruncated(groupsSnap) || isTruncated(membershipsSnap)) {
      findings.push(finding(8, groupsTitle, "medium", "warn", `${groups.length} groups and ${memberships.length} memberships were seen but the inventory was truncated, so segmentation could not be fully confirmed.`, evidence));
    } else {
      findings.push(finding(8, groupsTitle, "medium", "pass", `${groups.length} groups (${privateGroups.length} private) with ${memberships.length} memberships were read to completion, showing group-based segmentation is configured.`, evidence));
    }
  }

  const apiTokenTitle = "API tokens are minimal and reviewed";
  const apiTokenAccess = asBoolean(asObject(settingsSnap.data?.api)?.api_token_access);
  const apiTokenEvidence: JsonRecord = { api_token_access: apiTokenAccess ?? null, auth_mode: config.authMode };
  if (settingsSnap.status !== "ok") {
    findings.push(manualFinding(13, apiTokenTitle, "high", snapshotCause("Account settings", settingsSnap), "capture Admin Center > Apps and integrations > APIs > API tokens showing each token, its description, creation date, and owner."));
  } else if (apiTokenAccess === false) {
    findings.push(finding(13, apiTokenTitle, "high", "pass", "settings.api.api_token_access=false, so API tokens cannot be used to authenticate to this account.", apiTokenEvidence));
  } else {
    findings.push(manualFinding(13, apiTokenTitle, "high", `settings.api.api_token_access=${apiTokenAccess === true ? "true" : "absent"}; the API token inventory is not part of the published API reference, and Zendesk is retiring API tokens (unused tokens deactivated from July 28, 2026; all tokens stop working April 30, 2027).`, "capture Admin Center > Apps and integrations > APIs > API tokens, confirm each token has an owner and purpose, delete unused tokens, and record the migration plan to OAuth.", apiTokenEvidence));
  }

  const oauthTitle = "OAuth application permissions are scoped";
  if (clientsSnap.status !== "ok") {
    findings.push(manualFinding(14, oauthTitle, "high", snapshotCause("OAuth clients (/oauth/clients, admin only)", clientsSnap), "capture Admin Center > Apps and integrations > APIs > OAuth clients with each client's scopes, kind, and redirect URLs."));
  } else {
    const clients = listSnapshotItems(clientsSnap);
    const tokens = listSnapshotItems(tokensSnap);
    const unscoped = clients.filter((item) => !asString(item.scope));
    const publicClients = clients.filter((item) => asString(item.kind) === "public");
    const insecureRedirects = clients.filter((item) => asArray(item.redirect_uri).some((uri) => urlScheme(uri) === "http" && !/^(localhost|127\.0\.0\.1)$/.test(urlHost(uri)?.split(":")[0] ?? "")));
    const privilegedTokens = tokens.filter((token) => asArray(token.scopes).some((scope) => /write|impersonate/i.test(asString(scope) ?? "")));
    const nonExpiringTokens = tokens.filter((token) => !asString(token.expires_at));
    const usage = partitionByDate(tokens, "used_at", resolved.staleDays, now);
    const evidence: JsonRecord = {
      oauth_clients: clients.length,
      clients_without_scope_restriction: unscoped.slice(0, 25).map((item) => asString(item.name) ?? asString(item.identifier) ?? "client"),
      public_clients: publicClients.slice(0, 25).map((item) => asString(item.name) ?? asString(item.identifier) ?? "client"),
      clients_with_http_redirects: insecureRedirects.slice(0, 25).map((item) => asString(item.name) ?? asString(item.identifier) ?? "client"),
      oauth_tokens_status: tokensSnap.status,
      oauth_tokens: tokens.length,
      tokens_with_write_or_impersonate: privilegedTokens.length,
      tokens_without_expiry: nonExpiringTokens.length,
      tokens_unused_over_stale_days: usage.stale.length,
      tokens_without_used_at: usage.undated.length,
      inventory_truncated: isTruncated(clientsSnap) || isTruncated(tokensSnap),
    };
    if (unscoped.length > 0 || insecureRedirects.length > 0) {
      findings.push(finding(14, oauthTitle, "high", "fail", `${unscoped.length}/${clients.length} OAuth clients have no scope restriction and ${insecureRedirects.length} use http:// redirect URIs.${truncationNote("OAuth client", clientsSnap)}`, evidence));
    } else if (clients.length === 0) {
      findings.push(finding(14, oauthTitle, "high", tokens.length > 0 ? "warn" : "pass", tokens.length > 0 ? `Zero OAuth clients were returned but ${tokens.length} OAuth tokens exist (global clients or partial view); review token ownership.` : "The OAuth client endpoint was readable and returned zero clients, so no third-party OAuth applications are registered on this account.", evidence));
    } else if (publicClients.length > 0 || privilegedTokens.length > 0 || nonExpiringTokens.length > 0 || usage.stale.length > 0 || usage.undated.length > 0 || isTruncated(clientsSnap) || isTruncated(tokensSnap) || tokensSnap.status !== "ok") {
      findings.push(finding(14, oauthTitle, "high", "warn", `${clients.length} OAuth clients all declare allowed scopes; review ${publicClients.length} public clients, ${privilegedTokens.length} tokens with write or impersonate scope, ${nonExpiringTokens.length} non-expiring tokens, ${usage.stale.length} tokens unused for more than ${resolved.staleDays} days, and ${usage.undated.length} tokens with no used_at value.${tokensSnap.status !== "ok" ? ` ${snapshotCause("OAuth tokens", tokensSnap)}` : ""}${truncationNote("OAuth client", clientsSnap)}`, evidence));
    } else {
      findings.push(finding(14, oauthTitle, "high", "pass", `${clients.length} OAuth clients all declare allowed scopes and https redirect URIs; ${tokens.length} tokens were read to completion with expiries and recent usage.`, evidence));
    }
  }

  const finalFindings = finalizeFindings(findings, currentUserSnap);
  const entries: Array<[string, ZendeskSnapshot<unknown>]> = [
    ["current_user", currentUserSnap],
    ["account_settings", settingsSnap],
    ["team_members", teamSnap],
    ["custom_roles", rolesSnap],
    ["groups", groupsSnap],
    ["group_memberships", membershipsSnap],
    ["oauth_clients", clientsSnap],
    ["oauth_tokens", tokensSnap],
  ];
  return {
    category: "access-control",
    title: "Zendesk access control and API credentials",
    summary: {
      subdomain: config.subdomain,
      current_user_role: asString(currentUserSnap.data?.role) ?? null,
      seen_team_members: teamMembers.length,
      admins: admins.length,
      custom_roles: listSnapshotItems(rolesSnap).length,
      groups: groups.length,
      oauth_clients: listSnapshotItems(clientsSnap).length,
      ...summarizeStatuses(finalFindings),
    },
    findings: finalFindings,
    errors: snapshotErrors(entries),
    snapshots: Object.fromEntries(entries.map(([name, snap]) => [name, snap.data ?? null])),
  };
}

export async function assessZendeskDataProtection(
  client: ZendeskReadClient,
  options: ZendeskAssessmentOptions = {},
): Promise<ZendeskAssessmentResult> {
  const config = client.getResolvedConfig();
  const resolved = resolveOptions(options);
  const now = resolved.now();
  const currentUserSnap = await snapshot(() => client.getCurrentUser());
  const settingsSnap = await snapshot(() => client.getAccountSettings());
  const auditSnap = await snapshot(() => client.listRecentAuditLogs(DEFAULT_AUDIT_LOG_SAMPLE));
  const oldestSnap: ZendeskSnapshot<JsonRecord | undefined> = auditSnap.status === "ok"
    ? await snapshot(() => client.getOldestAuditLog())
    : { status: auditSnap.status, data: undefined, error: auditSnap.error, httpStatus: auditSnap.httpStatus };
  const rolesSnap = await snapshot(() => client.listCustomRoles());
  const suspendedSnap = await snapshot(() => client.listSuspendedTickets(resolved.maxItems));
  const settings = settingsSnap.data ?? {};
  const tickets = asObject(settings.tickets) ?? {};
  const limits = asObject(settings.limits) ?? {};
  const findings: ZendeskFinding[] = [];

  const auditTitle = "Audit logging enabled and accessible";
  const auditEntries = listSnapshotItems(auditSnap);
  if (auditSnap.status !== "ok") {
    findings.push(manualFinding(9, auditTitle, "high", `${snapshotCause("Audit logs (/audit_logs, Enterprise plan and admin role)", auditSnap)} This is a plan or permission limitation, not a pass.`, "capture Admin Center > Account > Audit log showing recent entries, or record that the plan does not include the audit log.", { audit_log_status: auditSnap.status }));
  } else if (auditEntries.length === 0) {
    findings.push(manualFinding(9, auditTitle, "high", "The audit log endpoint was readable but returned zero entries, which is unexpected for an active account.", "open Admin Center > Account > Audit log and confirm entries are being recorded.", { audit_log_entries: 0 }));
  } else {
    const newest = parseDate(auditEntries[0]?.created_at);
    findings.push(finding(9, auditTitle, "high", "pass", `The audit log is readable with ${auditEntries.length} recent entries sampled; newest entry ${newest ? newest.toISOString() : "has no created_at"}.`, {
      audit_log_entries_sampled: auditEntries.length,
      newest_entry: newest?.toISOString() ?? null,
      actions_seen: [...new Set(auditEntries.map((entry) => asString(entry.action)).filter(Boolean))],
    }));
  }

  const retentionTitle = "Audit log retention meets compliance requirements";
  if (oldestSnap.status !== "ok") {
    findings.push(manualFinding(10, retentionTitle, "medium", snapshotCause("Audit logs (oldest record lookup)", oldestSnap), "record the audit log retention statement from Zendesk documentation (records are kept indefinitely on Enterprise) and capture the oldest visible entry in Admin Center > Account > Audit log."));
  } else {
    const oldest = oldestSnap.data;
    const oldestAge = oldest ? ageInDays(oldest.created_at, now) : undefined;
    const evidence: JsonRecord = { oldest_entry: asString(oldest?.created_at) ?? null, oldest_entry_age_days: oldestAge ?? null, required_retention_days: resolved.retentionDays };
    if (!oldest || oldestAge === undefined) {
      findings.push(manualFinding(10, retentionTitle, "medium", "The oldest audit log entry could not be dated (missing created_at or empty log).", "capture the oldest entry in Admin Center > Account > Audit log.", evidence));
    } else if (oldestAge >= resolved.retentionDays) {
      findings.push(finding(10, retentionTitle, "medium", "pass", `The oldest audit log entry is ${oldestAge} days old, meeting the ${resolved.retentionDays}-day retention requirement (Zendesk documents indefinite audit log retention).`, evidence));
    } else {
      findings.push(finding(10, retentionTitle, "medium", "warn", `The oldest audit log entry is ${oldestAge} days old, less than the ${resolved.retentionDays}-day requirement; this is expected if the account or audit log is younger than the requirement, so confirm the account age.`, evidence));
    }
  }

  findings.push(manualFinding(11, "HIPAA compliance mode enabled (if applicable)", "critical", "HIPAA and Advanced Data Privacy and Protection settings are not exposed by the published Account Settings reference.", "capture Admin Center > Account > Security > Advanced showing the HIPAA-enabled configuration (or the executed BAA) if the account processes PHI; otherwise record not applicable.", { settings_readable: settingsSnap.status === "ok" }));

  const deletionTitle = "Data deletion/redaction policies configured";
  const customRoles = listSnapshotItems(rolesSnap);
  const redactionRoles = customRoles.filter((role) => asBoolean(asObject(role.configuration)?.ticket_redaction) === true).length;
  const deletionScheduleRoles = customRoles.filter((role) => asString(asObject(role.configuration)?.manage_deletion_schedules) === "all").length;
  const agentTicketDeletion = asBoolean(tickets.agent_ticket_deletion);
  findings.push(manualFinding(
    12,
    deletionTitle,
    "high",
    `Deletion schedules and retention policies are not exposed by the published API.${settingsSnap.status === "ok" ? ` settings.tickets.agent_ticket_deletion=${agentTicketDeletion ?? "absent"}${agentTicketDeletion === true ? " (agents can delete tickets; review whether that is intended)" : ""}.` : ` ${snapshotCause("Account settings", settingsSnap)}`}${rolesSnap.status === "ok" ? ` ${redactionRoles}/${customRoles.length} custom roles allow ticket redaction and ${deletionScheduleRoles} can manage deletion schedules.` : ""}`,
    "capture Admin Center > Account > Security > Deletion schedules (or Objects and rules > Tickets > Deletion schedules) showing the active schedules and the redaction policy.",
    { settings_readable: settingsSnap.status === "ok", agent_ticket_deletion: agentTicketDeletion ?? null, custom_roles_with_ticket_redaction: redactionRoles, custom_roles_managing_deletion_schedules: deletionScheduleRoles, custom_roles_status: rolesSnap.status },
  ));

  const cdnTitle = "CDN security (attachment hosting) configured";
  const privateAttachments = asBoolean(tickets.private_attachments);
  const cdnHosts = asRecordArray(asObject(settings.cdn)?.hosts).map((host) => asString(host.url)).filter((url): url is string => Boolean(url));
  const insecureCdnHosts = cdnHosts.filter((url) => urlScheme(url) !== "https");
  const cdnEvidence: JsonRecord = { private_attachments: privateAttachments ?? null, cdn_hosts: cdnHosts, insecure_cdn_hosts: insecureCdnHosts };
  if (settingsSnap.status !== "ok") {
    findings.push(manualFinding(18, cdnTitle, "medium", snapshotCause("Account settings", settingsSnap), "capture Admin Center > Objects and rules > Tickets > Settings > Attachments showing 'Require authentication to download'."));
  } else if (privateAttachments === true && insecureCdnHosts.length === 0) {
    findings.push(finding(18, cdnTitle, "medium", "pass", `settings.tickets.private_attachments=true, so users must sign in to download attachments${cdnHosts.length > 0 ? ` and all ${cdnHosts.length} CDN hosts use https` : ""}.`, cdnEvidence));
  } else if (privateAttachments === true) {
    findings.push(finding(18, cdnTitle, "medium", "warn", `Attachments require authentication, but ${insecureCdnHosts.length} CDN hosts do not use https.`, cdnEvidence));
  } else if (privateAttachments === false) {
    findings.push(finding(18, cdnTitle, "medium", "fail", "settings.tickets.private_attachments=false, so attachment links can be downloaded without signing in.", cdnEvidence));
  } else {
    findings.push(manualFinding(18, cdnTitle, "medium", "settings.tickets.private_attachments was absent from the response.", "capture Admin Center > Objects and rules > Tickets > Settings > Attachments.", cdnEvidence));
  }

  const attachmentTitle = "File attachment restrictions configured";
  const attachmentSize = asNumber(limits.attachment_size);
  findings.push(manualFinding(
    19,
    attachmentTitle,
    "medium",
    settingsSnap.status === "ok"
      ? `settings.limits.attachment_size=${attachmentSize !== undefined ? `${Math.round(attachmentSize / 1_048_576)} MB` : "absent"} and settings.tickets.email_attachments=${asBoolean(tickets.email_attachments) ?? "absent"}; allowed file types and malicious attachment detection are not exposed by the published API.`
      : snapshotCause("Account settings", settingsSnap),
    "capture Admin Center > Objects and rules > Tickets > Settings > Attachments (customer attachment settings, malicious attachment detection) and Security settings for allowed file types.",
    { attachment_size_bytes: attachmentSize ?? null, email_attachments: asBoolean(tickets.email_attachments) ?? null },
  ));

  const suspendedTitle = "Suspended ticket handling automated";
  if (suspendedSnap.status !== "ok") {
    findings.push(manualFinding(20, suspendedTitle, "low", snapshotCause("Suspended tickets (/suspended_tickets, admin or manage_suspended_tickets permission)", suspendedSnap), "capture the Suspended tickets view in Support showing the queue size and oldest item, and the automation that recovers or deletes them."));
  } else {
    const suspended = listSnapshotItems(suspendedSnap);
    const buckets = partitionByDate(suspended, "created_at", resolved.suspendedTicketAgeDays, now);
    const evidence: JsonRecord = {
      seen_suspended_tickets: suspended.length,
      older_than_threshold: buckets.stale.length,
      without_created_at: buckets.undated.length,
      age_threshold_days: resolved.suspendedTicketAgeDays,
      causes: [...new Set(suspended.map((ticket) => asString(ticket.cause)).filter(Boolean))].slice(0, 20),
      inventory_truncated: isTruncated(suspendedSnap),
    };
    if (suspended.length === 0) {
      findings.push(finding(20, suspendedTitle, "low", "pass", "The suspended ticket endpoint was readable and the queue is empty (0 suspended tickets).", evidence));
    } else if (buckets.stale.length > 0 || isTruncated(suspendedSnap)) {
      findings.push(finding(20, suspendedTitle, "low", "warn", `${suspended.length} suspended tickets are queued and ${buckets.stale.length} are older than ${resolved.suspendedTicketAgeDays} days (${buckets.undated.length} undated).${truncationNote("suspended ticket", suspendedSnap)}`, evidence));
    } else if (buckets.undated.length > 0) {
      findings.push(finding(20, suspendedTitle, "low", "warn", `${suspended.length} suspended tickets are queued; ${buckets.undated.length} have no created_at and cannot be aged.`, evidence));
    } else {
      findings.push(finding(20, suspendedTitle, "low", "pass", `${suspended.length} suspended tickets are queued and all are newer than ${resolved.suspendedTicketAgeDays} days.`, evidence));
    }
  }

  const finalFindings = finalizeFindings(findings, currentUserSnap);
  const entries: Array<[string, ZendeskSnapshot<unknown>]> = [
    ["current_user", currentUserSnap],
    ["account_settings", settingsSnap],
    ["audit_logs_recent", auditSnap],
    ["audit_log_oldest", oldestSnap],
    ["custom_roles", rolesSnap],
    ["suspended_tickets", suspendedSnap],
  ];
  return {
    category: "data-protection",
    title: "Zendesk audit logging and data protection",
    summary: {
      subdomain: config.subdomain,
      current_user_role: asString(currentUserSnap.data?.role) ?? null,
      audit_log_status: auditSnap.status,
      audit_log_entries_sampled: auditEntries.length,
      private_attachments: privateAttachments ?? null,
      suspended_tickets: listSnapshotItems(suspendedSnap).length,
      ...summarizeStatuses(finalFindings),
    },
    findings: finalFindings,
    errors: snapshotErrors(entries),
    snapshots: Object.fromEntries(entries.map(([name, snap]) => [name, snap.data ?? null])),
  };
}

export async function assessZendeskIntegrations(
  client: ZendeskReadClient,
  options: ZendeskAssessmentOptions = {},
): Promise<ZendeskAssessmentResult> {
  const config = client.getResolvedConfig();
  const resolved = resolveOptions(options);
  const settingsSnap = await snapshot(() => client.getAccountSettings());
  const currentUserSnap = await snapshot(() => client.getCurrentUser());
  const installationsSnap = await snapshot(() => client.listAppInstallations());
  const ownedSnap = await snapshot(() => client.listOwnedApps());
  const brandsSnap = await snapshot(() => client.listBrands(resolved.maxItems));
  const sharingSnap = await snapshot(() => client.listSharingAgreements());
  const targetsSnap = await snapshot(() => client.listTargets());
  const webhooksSnap = await snapshot(() => client.listWebhooks(resolved.maxItems));
  const triggersSnap = await snapshot(() => client.listTriggers(resolved.maxItems));
  const automationsSnap = await snapshot(() => client.listAutomations(resolved.maxItems));
  const findings: ZendeskFinding[] = [];

  const installations = listSnapshotItems(installationsSnap);
  const ownedApps = listSnapshotItems(ownedSnap);
  const ownedIds = new Set(ownedApps.map((app) => asString(app.id)).filter(Boolean));
  const installationName = (item: JsonRecord): string => asString(asObject(item.settings)?.title) ?? asString(asObject(item.settings)?.name) ?? `app ${asString(item.app_id) ?? "unknown"}`;

  const marketplaceTitle = "Marketplace apps reviewed for permissions";
  if (installationsSnap.status !== "ok") {
    findings.push(manualFinding(15, marketplaceTitle, "medium", snapshotCause("App installations (/apps/installations)", installationsSnap), "capture Admin Center > Apps and integrations > Zendesk Support apps > Currently installed with each app's permissions and role or group restrictions."));
  } else {
    const marketplace = installations.filter((item) => !ownedIds.has(asString(item.app_id) ?? ""));
    const enabled = marketplace.filter((item) => asBoolean(item.enabled) !== false);
    const evidence: JsonRecord = {
      app_installations: installations.length,
      marketplace_installations: marketplace.length,
      enabled_marketplace_installations: enabled.length,
      owned_apps_status: ownedSnap.status,
      apps: marketplace.slice(0, 50).map((item) => ({ name: installationName(item), enabled: asBoolean(item.enabled) ?? null, product: asString(item.product) ?? null, role_restrictions: asArray(item.role_restrictions).length, group_restrictions: asArray(item.group_restrictions).length })),
    };
    if (installations.length === 0) {
      findings.push(finding(15, marketplaceTitle, "medium", "pass", "The app installation endpoint was readable and returned zero installed apps, so there are no marketplace apps to review.", evidence));
    } else {
      findings.push(manualFinding(15, marketplaceTitle, "medium", `${marketplace.length} marketplace app installations (${enabled.length} enabled) were inventoried${ownedSnap.status !== "ok" ? ", but owned apps could not be separated because " + snapshotCause("/apps/owned", ownedSnap).toLowerCase() : ""}; app permission reviews cannot be verified through the API.`, "record the reviewer, date, and outcome of the permission review for each installed app in Admin Center > Apps and integrations > Zendesk Support apps.", evidence));
    }
  }

  const customAppTitle = "Private/custom apps have appropriate scope";
  if (ownedSnap.status !== "ok") {
    findings.push(manualFinding(16, customAppTitle, "medium", snapshotCause("Owned apps (/apps/owned, admin or manage apps permission)", ownedSnap), "capture the private apps list in Admin Center > Apps and integrations > Zendesk Support apps > Private apps with their manifests."));
  } else {
    const retired = ownedApps.filter((app) => asBoolean(app.deprecated) === true || asBoolean(app.obsolete) === true);
    const evidence: JsonRecord = {
      owned_apps: ownedApps.length,
      deprecated_or_obsolete: retired.slice(0, 25).map((app) => asString(app.name) ?? asString(app.id) ?? "app"),
      apps: ownedApps.slice(0, 50).map((app) => ({ name: asString(app.name) ?? null, visibility: asString(app.visibility) ?? null, framework_version: asString(app.framework_version) ?? null, parameters: asArray(app.parameters).length })),
    };
    if (ownedApps.length === 0) {
      findings.push(finding(16, customAppTitle, "medium", "pass", "The owned apps endpoint was readable and returned zero private or custom apps.", evidence));
    } else if (retired.length > 0) {
      findings.push(finding(16, customAppTitle, "medium", "warn", `${retired.length}/${ownedApps.length} owned apps are deprecated or obsolete and should be removed or updated; scope review of the remaining apps is manual.`, evidence));
    } else {
      findings.push(manualFinding(16, customAppTitle, "medium", `${ownedApps.length} private or custom apps were inventoried; requested locations and secure parameters must be reviewed against the manifest.`, "record the scope review for each private app (manifest locations, secure parameters, external domains).", evidence));
    }
  }

  const sandboxTitle = "Sandbox environment used for testing";
  const sandbox = asBoolean(asObject(settingsSnap.data?.active_features)?.sandbox);
  if (settingsSnap.status !== "ok") {
    findings.push(manualFinding(17, sandboxTitle, "low", snapshotCause("Account settings", settingsSnap), "capture Admin Center > Account > Sandbox showing the provisioned sandbox."));
  } else if (sandbox === true) {
    findings.push(finding(17, sandboxTitle, "low", "pass", "settings.active_features.sandbox=true, so a sandbox is provisioned for testing changes before production.", { sandbox: true }));
  } else if (sandbox === false) {
    findings.push(finding(17, sandboxTitle, "low", "warn", "settings.active_features.sandbox=false; no sandbox is provisioned. Confirm whether the plan includes a sandbox and whether configuration changes are tested elsewhere.", { sandbox: false }));
  } else {
    findings.push(manualFinding(17, sandboxTitle, "low", "settings.active_features.sandbox was absent from the response.", "capture Admin Center > Account > Sandbox.", { sandbox: null }));
  }

  const brandTitle = "Brand security settings consistent across brands";
  const currentRole = asString(currentUserSnap.data?.role);
  if (brandsSnap.status !== "ok") {
    findings.push(manualFinding(22, brandTitle, "medium", snapshotCause("Brands (/brands)", brandsSnap), "capture Admin Center > Account > Brand management showing each brand's help center state and host mapping."));
  } else {
    const brands = listSnapshotItems(brandsSnap).filter((brand) => asBoolean(brand.is_deleted) !== true);
    const activeBrands = brands.filter((brand) => asBoolean(brand.active) !== false);
    const states = [...new Set(activeBrands.map((brand) => asString(brand.help_center_state) ?? "unknown"))];
    const evidence: JsonRecord = {
      brands: brands.length,
      active_brands: activeBrands.length,
      help_center_states: states,
      current_user_role: currentRole ?? null,
      brands_detail: brands.slice(0, 50).map((brand) => ({ name: asString(brand.name) ?? null, active: asBoolean(brand.active) ?? null, help_center_state: asString(brand.help_center_state) ?? null, has_help_center: asBoolean(brand.has_help_center) ?? null, host_mapping: asString(brand.host_mapping) ?? null })),
      inventory_truncated: isTruncated(brandsSnap),
    };
    if (brands.length === 0) {
      findings.push(manualFinding(22, brandTitle, "medium", "Zero brands were visible although every account has a default brand, so the view is partial.", "use an admin credential and capture Admin Center > Account > Brand management.", evidence));
    } else if (currentRole !== "admin") {
      findings.push(finding(22, brandTitle, "medium", "warn", `${brands.length} brands were visible to a non-admin credential (role ${currentRole ?? "unknown"}), which only lists brands the agent belongs to, so cross-brand consistency cannot be confirmed.`, evidence));
    } else if (isTruncated(brandsSnap)) {
      findings.push(finding(22, brandTitle, "medium", "warn", `${brands.length} brands were seen but the inventory was truncated, so cross-brand consistency cannot be confirmed.`, evidence));
    } else if (states.length > 1 || states.includes("unknown")) {
      findings.push(finding(22, brandTitle, "medium", "warn", `${activeBrands.length} active brands expose mixed help center states (${states.join(", ")}); confirm each public or restricted help center is intentional.`, evidence));
    } else {
      findings.push(finding(22, brandTitle, "medium", "pass", `${activeBrands.length} active brand(s) were read to completion by an admin and share the same help center state (${states[0] ?? "none"}).`, evidence));
    }
  }

  const sharingTitle = "External sharing agreements reviewed";
  if (sharingSnap.status !== "ok") {
    findings.push(manualFinding(23, sharingTitle, "medium", snapshotCause("Sharing agreements (/sharing_agreements)", sharingSnap), "capture Admin Center > Objects and rules > Tickets > Ticket sharing showing every agreement and its status."));
  } else {
    const agreements = listSnapshotItems(sharingSnap);
    const active = agreements.filter((item) => ["accepted", "pending"].includes(asString(item.status) ?? ""));
    const broken = agreements.filter((item) => ["failed", "ssl_error", "configuration_error"].includes(asString(item.status) ?? ""));
    const evidence: JsonRecord = {
      sharing_agreements: agreements.length,
      active_agreements: active.slice(0, 25).map((item) => ({ name: asString(item.name) ?? null, remote_subdomain: asString(item.remote_subdomain) ?? null, partner_name: asString(item.partner_name) ?? null, status: asString(item.status) ?? null, type: asString(item.type) ?? null })),
      broken_agreements: broken.length,
    };
    if (agreements.length === 0) {
      findings.push(finding(23, sharingTitle, "medium", "pass", "The sharing agreement endpoint was readable and returned zero agreements, so tickets are not shared with external Zendesk accounts.", evidence));
    } else if (broken.length > 0) {
      findings.push(finding(23, sharingTitle, "medium", "warn", `${broken.length}/${agreements.length} sharing agreements are in a failed, ssl_error, or configuration_error state and ${active.length} are active; review each remote account.`, evidence));
    } else {
      findings.push(manualFinding(23, sharingTitle, "medium", `${active.length}/${agreements.length} sharing agreements are accepted or pending with external accounts (${active.map((item) => asString(item.remote_subdomain) ?? asString(item.partner_name) ?? asString(item.name) ?? "unnamed").join(", ")}).`, "record the business justification and data handling agreement for each remote account.", evidence));
    }
  }

  const httpsTitle = "External notification targets use HTTPS";
  const targets = listSnapshotItems(targetsSnap);
  const webhooks = listSnapshotItems(webhooksSnap);
  if (targetsSnap.status !== "ok" && webhooksSnap.status !== "ok") {
    findings.push(manualFinding(24, httpsTitle, "high", `${snapshotCause("Targets", targetsSnap)} ${snapshotCause("Webhooks", webhooksSnap)}`, "capture Admin Center > Apps and integrations > Webhooks and Targets showing every destination URL and authentication method."));
  } else {
    const activeTargets = targets.filter((target) => asBoolean(target.active) !== false);
    const urlTargets = activeTargets.filter((target) => asString(target.target_url));
    const insecureTargets = urlTargets.filter((target) => urlScheme(target.target_url) !== "https");
    const activeWebhooks = webhooks.filter((hook) => asString(hook.status) === "active");
    const insecureWebhooks = activeWebhooks.filter((hook) => urlScheme(hook.endpoint) !== "https");
    const unauthenticatedWebhooks = activeWebhooks.filter((hook) => !asObject(hook.authentication) && !asObject(hook.signing_secret));
    const evidence: JsonRecord = {
      targets_status: targetsSnap.status,
      active_targets: activeTargets.length,
      insecure_targets: insecureTargets.slice(0, 25).map((target) => asString(target.title) ?? asString(target.id) ?? "target"),
      webhooks_status: webhooksSnap.status,
      active_webhooks: activeWebhooks.length,
      insecure_webhooks: insecureWebhooks.slice(0, 25).map((hook) => asString(hook.name) ?? asString(hook.id) ?? "webhook"),
      webhooks_without_authentication: unauthenticatedWebhooks.slice(0, 25).map((hook) => asString(hook.name) ?? asString(hook.id) ?? "webhook"),
      inventory_truncated: isTruncated(webhooksSnap),
    };
    if (insecureTargets.length > 0 || insecureWebhooks.length > 0) {
      findings.push(finding(24, httpsTitle, "high", "fail", `${insecureTargets.length} active targets and ${insecureWebhooks.length} active webhooks deliver to non-https endpoints.${truncationNote("webhook", webhooksSnap)}`, evidence));
    } else if (targetsSnap.status !== "ok" || webhooksSnap.status !== "ok" || isTruncated(webhooksSnap) || unauthenticatedWebhooks.length > 0) {
      findings.push(finding(24, httpsTitle, "high", "warn", `All seen destinations use https, but ${unauthenticatedWebhooks.length} active webhooks have no authentication or signing secret visible${targetsSnap.status !== "ok" ? `, and ${snapshotCause("targets", targetsSnap).toLowerCase()}` : ""}${webhooksSnap.status !== "ok" ? `, and ${snapshotCause("webhooks", webhooksSnap).toLowerCase()}` : ""}.${truncationNote("webhook", webhooksSnap)}`, evidence));
    } else {
      findings.push(finding(24, httpsTitle, "high", "pass", `${activeTargets.length} active targets (${urlTargets.length} URL-based) and ${activeWebhooks.length} active webhooks were read to completion; every destination uses https and every webhook carries authentication.`, evidence));
    }
  }

  const exfilTitle = "Triggers/automations do not send data to external URLs";
  if (triggersSnap.status !== "ok" || automationsSnap.status !== "ok") {
    findings.push(manualFinding(25, exfilTitle, "high", `${snapshotCause("Triggers", triggersSnap)} ${snapshotCause("Automations", automationsSnap)}`, "export the trigger and automation lists from Admin Center > Objects and rules and record every 'Notify webhook', 'Notify target', and 'Share ticket' action."));
  } else {
    const rules = [
      ...listSnapshotItems(triggersSnap).map((rule) => ({ kind: "trigger", rule })),
      ...listSnapshotItems(automationsSnap).map((rule) => ({ kind: "automation", rule })),
    ].filter((entry) => asBoolean(entry.rule.active) !== false);
    const targetIndex = new Map(targets.map((target) => [asString(target.id) ?? "", target]));
    const webhookIndex = new Map(webhooks.map((hook) => [asString(hook.id) ?? "", hook]));
    const external = rules.flatMap((entry) => externalNotificationActions(entry.rule).map((action) => {
      const destination = action.field === "notification_target"
        ? asString(targetIndex.get(action.destination)?.target_url) ?? asString(targetIndex.get(action.destination)?.email) ?? `target ${action.destination}`
        : action.field === "notification_webhook"
          ? asString(webhookIndex.get(action.destination)?.endpoint) ?? `webhook ${action.destination}`
          : `sharing agreement ${action.destination}`;
      return { kind: entry.kind, title: asString(entry.rule.title) ?? asString(entry.rule.id) ?? "rule", action: action.field, destination };
    }));
    const insecure = external.filter((item) => urlScheme(item.destination) === "http");
    const truncated = isTruncated(triggersSnap) || isTruncated(automationsSnap);
    const evidence: JsonRecord = {
      active_triggers: listSnapshotItems(triggersSnap).filter((rule) => asBoolean(rule.active) !== false).length,
      active_automations: listSnapshotItems(automationsSnap).filter((rule) => asBoolean(rule.active) !== false).length,
      external_notification_actions: external.slice(0, 50),
      insecure_destinations: insecure.length,
      inventory_truncated: truncated,
    };
    if (insecure.length > 0) {
      findings.push(finding(25, exfilTitle, "high", "fail", `${insecure.length}/${external.length} external notification actions deliver ticket data to http:// destinations.${truncationNote("trigger", triggersSnap)}${truncationNote("automation", automationsSnap)}`, evidence));
    } else if (external.length > 0) {
      findings.push(finding(25, exfilTitle, "high", "warn", `${external.length} active rule actions send ticket data to external destinations (${[...new Set(external.map((item) => urlHost(item.destination) ?? item.destination))].slice(0, 10).join(", ")}); confirm each destination is an approved processor.${truncated ? " The rule inventory was truncated." : ""}`, evidence));
    } else if (truncated) {
      findings.push(finding(25, exfilTitle, "high", "warn", "No external notification actions were found in the seen rules, but the trigger or automation inventory was truncated, so the full population was not reviewed.", evidence));
    } else {
      findings.push(finding(25, exfilTitle, "high", "pass", `${rules.length} active triggers and automations were read to completion and none notify external targets, webhooks, or sharing agreements.`, evidence));
    }
  }

  const finalFindings = finalizeFindings(findings, currentUserSnap);
  const entries: Array<[string, ZendeskSnapshot<unknown>]> = [
    ["current_user", currentUserSnap],
    ["account_settings", settingsSnap],
    ["app_installations", installationsSnap],
    ["owned_apps", ownedSnap],
    ["brands", brandsSnap],
    ["sharing_agreements", sharingSnap],
    ["targets", targetsSnap],
    ["webhooks", webhooksSnap],
    ["triggers", triggersSnap],
    ["automations", automationsSnap],
  ];
  return {
    category: "integrations",
    title: "Zendesk apps, brands, and external communications",
    summary: {
      subdomain: config.subdomain,
      current_user_role: currentRole ?? null,
      app_installations: installations.length,
      owned_apps: ownedApps.length,
      brands: listSnapshotItems(brandsSnap).length,
      webhooks: webhooks.length,
      targets: targets.length,
      ...summarizeStatuses(finalFindings),
    },
    findings: finalFindings,
    errors: snapshotErrors(entries),
    snapshots: Object.fromEntries(entries.map(([name, snap]) => [name, snap.data ?? null])),
  };
}

function ensurePrivateDir(pathname: string): void {
  mkdirSync(pathname, { recursive: true, mode: 0o700 });
  const realPath = realpathSync(pathname);
  const stat = lstatSync(realPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Refusing to use non-directory or symlink path: ${pathname}`);
  }
}

export function resolveSecureOutputPath(baseDir: string, targetDir: string): string {
  ensurePrivateDir(baseDir);
  const realBase = realpathSync(baseDir);
  const resolvedTarget = resolve(realBase, targetDir);
  const relativeTarget = relative(realBase, resolvedTarget);
  if (relativeTarget === ".." || relativeTarget.startsWith(`..${join("/")}`) || relativeTarget.startsWith("..")) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
  }

  const pathSegments = relativeTarget.split(/[\\/]+/).filter(Boolean);
  let currentPath = realBase;
  for (const segment of pathSegments) {
    currentPath = join(currentPath, segment);
    if (!existsSync(currentPath)) break;
    if (lstatSync(currentPath).isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked parent directory: ${currentPath}`);
    }
  }

  const parent = dirname(resolvedTarget);
  ensurePrivateDir(parent);
  if (lstatSync(realpathSync(parent)).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }
  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  for (let index = 1; index <= 50; index += 1) {
    const candidate = resolveSecureOutputPath(root, index === 1 ? preferredName : `${preferredName}-${index}`);
    if (!existsSync(candidate) && !existsSync(`${candidate}.zip`)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return candidate;
    }
  }
  throw new Error(`Unable to allocate output directory under ${root}`);
}

async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, content, { encoding: "utf8", mode: 0o600 });
}

async function createZipArchive(sourceDir: string, zipPath: string): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const output = createWriteStream(zipPath, { mode: 0o600 });
    const archive = new ZipArchive({ zlib: { level: 9 } });
    output.on("close", () => resolvePromise());
    output.on("error", rejectPromise);
    archive.on("error", rejectPromise);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    void archive.finalize();
  });
  await chmod(zipPath, 0o600);
}

async function countFilesRecursively(rootDir: string): Promise<number> {
  let total = 0;
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) total += await countFilesRecursively(pathname);
    else if (entry.isFile()) total += 1;
  }
  return total;
}

function formatAccessCheckText(result: ZendeskAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.requiredRole,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Zendesk access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Needs", "Status", "Count", "Note"], rows),
    ...(result.missingPermissions.length > 0 ? ["", "Missing permissions:", ...result.missingPermissions.map((item) => `- ${item}`)] : []),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ZendeskAssessmentResult): string {
  const rows = result.findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.summary]);
  const summary = Object.entries(result.summary).map(([key, value]) => `- ${key}: ${String(value)}`).join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: ZendeskResolvedConfig, assessments: ZendeskAssessmentResult[], errors: string[], generatedAt: string): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeStatuses(findings);
  const lines = [
    "# Zendesk Security Inspection Executive Summary",
    "",
    `Subdomain: ${config.subdomain}`,
    `Generated: ${generatedAt}`,
    `Auth mode: ${config.authMode}`,
    "",
    "## Result Counts",
    "",
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    "",
    "## Failing and Warning Findings",
    "",
  ];
  const attention = findings.filter((item) => item.status === "fail" || item.status === "warn");
  lines.push(...(attention.length > 0 ? attention.map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`) : ["- No failing or warning findings."]));
  lines.push("", "## Manual Evidence Required", "");
  const manual = findings.filter((item) => item.status === "manual");
  lines.push(...(manual.length > 0 ? manual.map((item) => `- ${item.id} ${item.title}: ${item.summary}`) : ["- None."]));
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "", ...errors.map((item) => `- ${item}`));
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: ZendeskFinding[]): string {
  const rows = findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.mappings.join(", ")]);
  return `# Zendesk Unified Compliance Matrix\n\n${formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows)}\n`;
}

function buildFrameworkReport(title: string, prefix: string, findings: ZendeskFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length)).join(", ") || "-",
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  return `# ${title}\n\nStatus semantics: PASS was verified from documented API fields read to completion; WARN needs review; FAIL is a verified gap; MANUAL requires Admin Center evidence.\n\n${formatTable(["Control", "Requirement", "Status", "Title", "Summary"], rows)}\n`;
}

function buildQuickReference(): string {
  return [
    "# Zendesk Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw Zendesk API snapshots used during this assessment (credentials are never written).",
    "- `analysis/` contains normalized findings (`findings.json`) and one JSON file per assessment category.",
    "- `compliance/` contains the executive summary, the unified matrix, and one report per framework (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP).",
    "- `_errors.log` appears only when some reads failed but the bundle still completed.",
    "- Manual findings name the Admin Center evidence a reviewer must collect; they never count as passing.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/*.json` for the evidence behind each finding",
    "",
  ].join("\n");
}

export async function exportZendeskAuditBundle(
  client: ZendeskReadClient,
  config: ZendeskResolvedConfig,
  outputRoot: string,
  options: ZendeskAssessmentOptions = {},
): Promise<ZendeskAuditBundleResult> {
  const generatedAt = (options.now ?? (() => new Date()))().toISOString();
  const access = await checkZendeskAccess(client);
  const assessments = [
    await assessZendeskAuthentication(client, options),
    await assessZendeskAccessControl(client, options),
    await assessZendeskDataProtection(client, options),
    await assessZendeskIntegrations(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];

  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(config.subdomain)}-zendesk-audit-bundle`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: generatedAt,
    subdomain: config.subdomain,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    finding_count: findings.length,
    error_count: errors.length,
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, value] of Object.entries(assessment.snapshots)) {
      if (value !== null && value !== undefined) {
        await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(value));
      }
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.slug}_compliance_report.md`, buildFrameworkReport(framework.title, framework.prefix, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
  };
}

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    subdomain: asString(value.subdomain),
    email: asString(value.email),
    api_token: asString(value.api_token),
    oauth_token: asString(value.oauth_token),
    base_url: asString(value.base_url),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    admin_threshold: asNumber(value.admin_threshold),
    suspended_ticket_age_days: asNumber(value.suspended_ticket_age_days),
    stale_days: asNumber(value.stale_days),
    retention_days: asNumber(value.retention_days),
    max_items: asNumber(value.max_items),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toOptions(args: AssessArgs): ZendeskAssessmentOptions {
  return {
    adminThreshold: args.admin_threshold,
    suspendedTicketAgeDays: args.suspended_ticket_age_days,
    staleDays: args.stale_days,
    retentionDays: args.retention_days,
    maxItems: args.max_items,
  };
}

function createClient(args: AuthArgs): ZendeskApiClient {
  return new ZendeskApiClient(resolveZendeskConfiguration(args as JsonRecord));
}

const authParams = {
  subdomain: Type.Optional(Type.String({ description: "Zendesk subdomain (the {subdomain} in https://{subdomain}.zendesk.com). Defaults to ZENDESK_SUBDOMAIN or the config file." })),
  email: Type.Optional(Type.String({ description: "Email of the admin or agent that owns the API token. Defaults to ZENDESK_EMAIL." })),
  api_token: Type.Optional(Type.String({ description: "Zendesk API token used with email as Basic auth ({email}/token:{api_token}). Defaults to ZENDESK_API_TOKEN." })),
  oauth_token: Type.Optional(Type.String({ description: "Zendesk OAuth access token (Bearer). Defaults to ZENDESK_OAUTH_TOKEN. Preferred over API tokens, which Zendesk is retiring." })),
  base_url: Type.Optional(Type.String({ description: "API base URL override. Defaults to https://{subdomain}.zendesk.com/api/v2." })),
  config_file: Type.Optional(Type.String({ description: "JSON config file with subdomain, email, api_token, or oauth_token keys. Defaults to ZENDESK_CONFIG_FILE or ~/.zendesk/config.json." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const assessParams = {
  ...authParams,
  admin_threshold: Type.Optional(Type.Number({ description: "Maximum acceptable number of admins before failing control 7. Defaults to 5.", default: 5 })),
  suspended_ticket_age_days: Type.Optional(Type.Number({ description: "Suspended tickets older than this many days are flagged. Defaults to 30.", default: 30 })),
  stale_days: Type.Optional(Type.Number({ description: "Days without sign-in or token use before an admin or token counts as dormant. Defaults to 90.", default: 90 })),
  retention_days: Type.Optional(Type.Number({ description: "Required audit log retention in days. Defaults to 365.", default: 365 })),
  max_items: Type.Optional(Type.Number({ description: "Maximum items to page through per inventory before recording truncation. Defaults to 2000.", default: 2000 })),
};

function registerAssessmentTool(
  pi: any,
  name: string,
  label: string,
  description: string,
  run: (client: ZendeskApiClient, options: ZendeskAssessmentOptions) => Promise<ZendeskAssessmentResult>,
): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object(assessParams),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await run(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(`${label} failed: ${error instanceof Error ? error.message : String(error)}`, { tool: name });
      }
    },
  });
}

export function registerZendeskTools(pi: any): void {
  pi.registerTool({
    name: "zendesk_check_access",
    label: "Check Zendesk audit access",
    description:
      "Validate read-only Zendesk Support API access across account settings, team members, custom roles, groups, audit logs, OAuth clients and tokens, apps, brands, webhooks, targets, triggers, automations, sharing agreements, and suspended tickets, reporting which admin-only surfaces the credential cannot read.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkZendeskAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "zendesk_check_access", ...result });
      } catch (error) {
        return errorResult(`Zendesk access check failed: ${error instanceof Error ? error.message : String(error)}`, { tool: "zendesk_check_access" });
      }
    },
  });

  registerAssessmentTool(
    pi,
    "zendesk_assess_authentication",
    "Assess Zendesk authentication",
    "Assess Zendesk authentication controls (spec controls 1-5 and 21): SSO enforcement, agent two-factor coverage from documented user flags, password policy, IP restrictions, session expiration, and end-user authentication. Settings that the published API does not expose are returned as manual findings naming the Admin Center evidence.",
    (client, options) => assessZendeskAuthentication(client, options),
  );

  registerAssessmentTool(
    pi,
    "zendesk_assess_access_control",
    "Assess Zendesk access control",
    "Assess Zendesk access control (spec controls 6-8, 13, 14): least-privilege custom roles, admin count and dormant admins, group segmentation, API token exposure, and OAuth client scope and token hygiene, with partial or truncated inventories downgraded instead of passing.",
    (client, options) => assessZendeskAccessControl(client, options),
  );

  registerAssessmentTool(
    pi,
    "zendesk_assess_data_protection",
    "Assess Zendesk data protection",
    "Assess Zendesk audit logging and data protection (spec controls 9-12, 18-20): audit log availability and retention (Enterprise), HIPAA mode, deletion and redaction policies, authenticated attachment downloads, attachment limits, and suspended ticket backlog age.",
    (client, options) => assessZendeskDataProtection(client, options),
  );

  registerAssessmentTool(
    pi,
    "zendesk_assess_integrations",
    "Assess Zendesk integrations",
    "Assess Zendesk apps, brands, and external communications (spec controls 15-17, 22-25): marketplace and private app inventories, sandbox provisioning, cross-brand help center consistency, sharing agreements, https-only targets and webhooks, and trigger or automation actions that send ticket data externally.",
    (client, options) => assessZendeskIntegrations(client, options),
  );

  pi.registerTool({
    name: "zendesk_export_audit_bundle",
    label: "Export Zendesk audit bundle",
    description:
      "Export a Zendesk audit bundle with raw API snapshots (core_data/), normalized findings (analysis/), an executive summary, a unified compliance matrix, per-framework reports (compliance/), a QUICK_REFERENCE.md, an _errors.log when collection was partial, and a paired .zip archive. Reruns allocate a new directory instead of overwriting.",
    parameters: Type.Object({
      ...assessParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveZendeskConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportZendeskAuditBundle(new ZendeskApiClient(config), config, outputRoot, toOptions(args));
        return textResult(
          [
            "Zendesk audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "zendesk_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Zendesk audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`, { tool: "zendesk_export_audit_bundle" });
      }
    },
  });
}
