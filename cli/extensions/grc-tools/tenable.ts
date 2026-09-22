/**
 * Tenable security inspector tools for grclanker.
 *
 * Read-only assessment of a Tenable Vulnerability Management tenant (cloud.tenable.com
 * or fedcloud.tenable.com) with optional Tenable Security Center equivalents. The only
 * POST calls are the documented asset and vulnerability export requests.
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
import { parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type SleepImpl = (ms: number) => Promise<void>;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/tenable";
const DEFAULT_CLOUD_URL = "https://cloud.tenable.com";
const FEDRAMP_CLOUD_URL = "https://fedcloud.tenable.com";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_LIMIT = 4;
const DEFAULT_EXPORT_TIMEOUT_MS = 300_000;
const DEFAULT_EXPORT_POLL_MS = 2_000;
const DEFAULT_MAX_CHUNKS = 50;
const DEFAULT_PAGE_LIMIT = 1000;
const DEFAULT_MAX_PAGES = 200;
const DEFAULT_STALE_SCAN_DAYS = 30;
const DEFAULT_STALE_ASSET_DAYS = 30;
const DEFAULT_AGENT_OFFLINE_DAYS = 7;
const DEFAULT_PLUGIN_STALE_HOURS = 24;
const DEFAULT_INACTIVE_USER_DAYS = 90;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_CREDENTIAL_THRESHOLD = 0.8;
const DEFAULT_TAGGED_THRESHOLD = 0.9;
const DEFAULT_AUDIT_LOOKBACK_DAYS = 30;
const DEFAULT_VULN_LOOKBACK_DAYS = 90;
const DEFAULT_SLA_DAYS = { critical: 15, high: 30, medium: 90, low: 180 };
const DAY_MS = 86_400_000;
const ADMINISTRATOR_PERMISSION = 64;
const EXPORT_JOB_WINDOW_DAYS = 3;
const OWN_VULN_EXPORT_NUM_ASSETS = 5000;
const OWN_VULN_EXPORT_STATES = ["open", "reopened", "fixed"];
const OWN_ASSET_EXPORT_CHUNK_SIZE = 10000;
const MAX_POLICY_DETAILS = 100;

export type TenableFindingStatus = "pass" | "warn" | "fail" | "manual";
export type TenableSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface TenableVmConfig {
  baseUrl: string;
  accessKey: string;
  secretKey: string;
  fedramp: boolean;
}

export interface TenableSecurityCenterConfig {
  baseUrl: string;
  accessKey: string;
  secretKey: string;
}

export interface TenableResolvedConfig {
  platform: "vm" | "sc";
  vm?: TenableVmConfig;
  securityCenter?: TenableSecurityCenterConfig;
  timeoutMs: number;
  sourceChain: string[];
}

export interface TenableDataset<T> {
  data: T;
  status: "ok" | "forbidden" | "error" | "not_configured";
  error?: string;
  seen: number;
  total?: number;
  truncated: boolean;
}

export interface TenableAccessSurface {
  name: string;
  endpoint: string;
  requiredRole: string;
  status: "readable" | "forbidden" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface TenableAccessCheckResult {
  status: "healthy" | "limited";
  platform: string;
  callerIsAdministrator: boolean | undefined;
  surfaces: TenableAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface TenableFinding {
  id: string;
  title: string;
  severity: TenableSeverity;
  status: TenableFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface TenableAssessmentResult {
  title: string;
  category: string;
  summary: JsonRecord;
  findings: TenableFinding[];
  errors: string[];
}

export interface TenableAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface TenableAssessmentOptions {
  now?: number;
  staleScanDays?: number;
  staleAssetDays?: number;
  agentOfflineDays?: number;
  pluginStaleHours?: number;
  inactiveUserDays?: number;
  maxAdmins?: number;
  credentialThreshold?: number;
  taggedThreshold?: number;
  auditLookbackDays?: number;
  vulnLookbackDays?: number;
  slaCriticalDays?: number;
  slaHighDays?: number;
  slaMediumDays?: number;
  slaLowDays?: number;
  expectedAssetCount?: number;
  maxChunks?: number;
}

type CheckAccessArgs = {
  access_key?: string;
  secret_key?: string;
  url?: string;
  sc_url?: string;
  sc_access_key?: string;
  sc_secret_key?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AssessArgs = CheckAccessArgs & {
  stale_scan_days?: number;
  stale_asset_days?: number;
  agent_offline_days?: number;
  plugin_stale_hours?: number;
  inactive_user_days?: number;
  max_admins?: number;
  credential_threshold?: number;
  tagged_threshold?: number;
  audit_lookback_days?: number;
  vuln_lookback_days?: number;
  sla_critical_days?: number;
  sla_high_days?: number;
  sla_medium_days?: number;
  sla_low_days?: number;
  expected_asset_count?: number;
  max_chunks?: number;
};

type ExportAuditBundleArgs = AssessArgs & {
  output_dir?: string;
};

const CONTROL_MAPPINGS: Record<number, string[]> = {
  1: ["FedRAMP RA-5", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.3", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  2: ["FedRAMP RA-5(2)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  3: ["FedRAMP CM-8", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  4: ["FedRAMP RA-5(1)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.2", "PCI-DSS 11.3.2", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  5: ["FedRAMP CM-8(1)", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  6: ["FedRAMP CM-8(5)", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  7: ["FedRAMP SI-2(2)", "CMMC 3.14.1", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000456", "IRAP ISM-1163", "ISMAP CPS.SI-2"],
  8: ["FedRAMP SI-2(2)", "CMMC 3.14.1", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP CPS.SI-2"],
  9: ["FedRAMP SC-7(5)", "CMMC 3.13.5", "SOC 2 CC6.6", "PCI-DSS 1.3.1", "STIG SRG-APP-000001", "IRAP ISM-1528", "ISMAP CPS.SC-7"],
  10: ["FedRAMP AC-6(5)", "CMMC 3.1.5", "SOC 2 CC6.3", "PCI-DSS 7.1.1", "STIG SRG-APP-000340", "IRAP ISM-1507", "ISMAP CPS.AC-6"],
  11: ["FedRAMP AC-6(1)", "CMMC 3.1.5", "SOC 2 CC6.3", "PCI-DSS 7.1.2", "STIG SRG-APP-000340", "IRAP ISM-1507", "ISMAP CPS.AC-6"],
  12: ["FedRAMP IA-5(1)", "CMMC 3.5.10", "SOC 2 CC6.1", "PCI-DSS 8.6.3", "STIG SRG-APP-000175", "IRAP ISM-1557", "ISMAP CPS.IA-5"],
  13: ["FedRAMP RA-5(2)", "CMMC 3.11.1", "SOC 2 CC7.1", "CIS 7.3", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  14: ["FedRAMP RA-5(3)", "CMMC 3.11.1", "SOC 2 CC7.1", "CIS 7.6", "PCI-DSS 6.1", "STIG SRG-APP-000456", "IRAP ISM-1690", "ISMAP CPS.RA-5"],
  15: ["FedRAMP RA-5(3)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.4", "PCI-DSS 6.1", "STIG SRG-APP-000456", "IRAP ISM-1690", "ISMAP CPS.RA-5"],
  16: ["FedRAMP CM-8(5)", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  17: ["FedRAMP CM-6(1)", "CMMC 3.4.2", "SOC 2 CC8.1", "CIS 4.1", "PCI-DSS 2.2.1", "STIG SRG-APP-000384", "IRAP ISM-1624", "ISMAP CPS.CM-6"],
  18: ["FedRAMP AU-6", "CMMC 3.3.5", "SOC 2 CC7.2", "CIS 8.2", "PCI-DSS 10.6.1", "STIG SRG-APP-000516", "IRAP ISM-0580", "ISMAP CPS.AU-6"],
  19: ["FedRAMP RA-5(4)", "CMMC 3.11.3", "SOC 2 CC7.2", "PCI-DSS 11.3.4", "STIG SRG-APP-000516", "IRAP ISM-0109", "ISMAP CPS.RA-5"],
  20: ["FedRAMP RA-5", "CMMC 3.11.2", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
};

const CONTROL_TITLES: Record<number, string> = {
  1: "Scan policy configuration",
  2: "Scan schedule discipline",
  3: "Asset discovery coverage",
  4: "Credentialed scan ratio",
  5: "Agent deployment status",
  6: "Agent group organization",
  7: "Scanner health and version",
  8: "Plugin update currency",
  9: "Network zone configuration",
  10: "User role and permission audit",
  11: "Access group review",
  12: "Managed credential hygiene",
  13: "Scan exclusion audit",
  14: "Vulnerability prioritization (VPR)",
  15: "Vulnerability SLA tracking",
  16: "Asset tagging strategy",
  17: "Compliance audit templates",
  18: "Audit log review",
  19: "Export and reporting automation",
  20: "Target group management",
};

const FRAMEWORK_REPORTS: Array<{ prefix: string; slug: string; title: string }> = [
  { prefix: "FedRAMP", slug: "fedramp", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { prefix: "CMMC", slug: "cmmc", title: "CMMC Compliance Report" },
  { prefix: "SOC 2", slug: "soc2", title: "SOC 2 Compliance Report" },
  { prefix: "CIS", slug: "cis", title: "CIS Controls Compliance Report" },
  { prefix: "PCI-DSS", slug: "pci_dss", title: "PCI-DSS Compliance Report" },
  { prefix: "STIG", slug: "disa_stig", title: "DISA STIG Compliance Checklist" },
  { prefix: "IRAP", slug: "irap", title: "IRAP / ISM Compliance Report" },
  { prefix: "ISMAP", slug: "ismap", title: "ISMAP Compliance Report" },
];

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecords(value: unknown): JsonRecord[] {
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
    if (/^(true|1)$/i.test(value.trim())) return true;
    if (/^(false|0)$/i.test(value.trim())) return false;
  }
  if (value === 1) return true;
  if (value === 0) return false;
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = value === undefined || !Number.isFinite(value) ? fallback : value;
  return Math.min(Math.max(parsed, min), max);
}

function clampInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  return Math.trunc(clampNumber(value, fallback, min, max));
}

function normalizeBaseUrl(rawUrl: string): string {
  const candidate = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(candidate);
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function isTenableCloudHost(baseUrl: string): boolean {
  const host = new URL(baseUrl).hostname.toLowerCase();
  return host === "cloud.tenable.com" || host === "fedcloud.tenable.com" || host.endsWith(".cloud.tenable.com");
}

function isFedrampHost(baseUrl: string): boolean {
  return new URL(baseUrl).hostname.toLowerCase() === new URL(FEDRAMP_CLOUD_URL).hostname;
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
  return normalized || "tenable";
}

const REDACTED = "[REDACTED]";

// Unanchored patterns for credential-shaped text that an upstream body, proxy page, or
// transport error may echo regardless of what this tool sent. Applied to every error
// string at the sink (errorMessage) and again in the TenableApiError constructor.
const ERROR_TEXT_PATTERNS: Array<[RegExp, string]> = [
  [/\b(bearer|basic|digest|negotiate)\s+[a-z0-9._~+/=-]{8,}/gi, `$1 ${REDACTED}`],
  [/\b(authorization|x-api-key|x-apikeys?|x-cookie|set-cookie|cookie|x-redlock-auth)\s*:\s*[^\r\n]+/gi, `$1: ${REDACTED}`],
  // Keys that contain a credential word anywhere (TNS_SESSIONID, x_auth_token, apiKey).
  [/\b([a-z0-9_-]*(?:session|token|secret|password|passwd|passphrase|api[_-]?key|accesskey|secretkey|access_key|secret_key|private_key|signature|registration_code|activation_code|authorization|credential)[a-z0-9_-]*)\s*[=:]\s*["']?[^\s"';,&<>]{4,}/gi, `$1=${REDACTED}`],
  // Short keys that are only credentials as whole words.
  [/\b(key|auth|sig|sid|pwd|pin|otp)\s*[=:]\s*["']?[^\s"';,&<>]{4,}/gi, `$1=${REDACTED}`],
  [/\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}(?:\.[a-z0-9_-]{8,})?/gi, REDACTED],
  [/(https?:\/\/)[^\s/@"'<>]+:[^\s/@"'<>]+@/gi, `$1${REDACTED}@`],
];

function redactErrorText(text: string): string {
  let redacted = text;
  for (const [pattern, replacement] of ERROR_TEXT_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

function redactSecrets(message: string, secrets: string[]): string {
  let redacted = message;
  for (const secret of secrets) {
    if (secret.length >= 4) redacted = redacted.split(secret).join(REDACTED);
  }
  return redactErrorText(redacted);
}

// Property names whose values are credentials wherever they appear in a vendor payload.
// Matched on the flattened name (snake_case, kebab-case, camelCase, and header forms) or
// on the final camelCase or snake_case segment.
const CREDENTIAL_PROPERTY_NAMES = new Set([
  "password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens",
  "apikey", "apikeys", "xapikey", "xapikeys", "accesskey", "secretkey", "privatekey", "clientsecret",
  "apisecret", "sharedsecret", "registrationcode", "activationcode", "linkingkey", "authtoken",
  "accesstoken", "refreshtoken", "idtoken", "sessionid", "sessiontoken", "authorization", "cookie", "xcookie",
]);
const CREDENTIAL_LAST_SEGMENTS = new Set(["password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens", "authorization", "cookie"]);

function propertyNameIsCredential(name: string): boolean {
  if (CREDENTIAL_PROPERTY_NAMES.has(name.toLowerCase().replace(/[^a-z0-9]/g, ""))) return true;
  const segments = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const last = segments.at(-1);
  return last !== undefined && CREDENTIAL_LAST_SEGMENTS.has(last);
}

// Credentials carried inside string values: URL query parameters, URL userinfo, and
// JSON-encoded credential fields inside a string.
function redactCredentialValueText(text: string): string {
  return text
    .replace(/([?&](?:token|key|api_key|apikey|secret|password|access_token|auth|signature|sig|client_secret|access_key|secret_key)=)[^&#\s"']+/gi, `$1${REDACTED}`)
    .replace(/(https?:\/\/)[^\s/@"'<>]+:[^\s/@"'<>]+@/gi, `$1${REDACTED}@`)
    .replace(/("(?:token|secret|password|passwd|api_key|apikey|access_token|refresh_token|client_secret|private_key|secret_key|access_key|registration_code)"\s*:\s*")[^"]*(")/gi, `$1${REDACTED}$2`);
}

function redactCredentialNode(value: unknown): unknown {
  if (typeof value === "string") return redactCredentialValueText(value);
  if (Array.isArray(value)) return value.map(redactCredentialNode);
  const record = asObject(value);
  if (!record) return value;
  const pairName = typeof record.name === "string" ? record.name : undefined;
  const pairIsCredential = (pairName !== undefined && propertyNameIsCredential(pairName)) || record.secure === true;
  const result: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    if (entry === null || entry === undefined) {
      result[key] = entry;
    } else if (propertyNameIsCredential(key) || (pairIsCredential && (key === "value" || key === "default"))) {
      result[key] = REDACTED;
    } else {
      result[key] = redactCredentialNode(entry);
    }
  }
  return result;
}

// Applied to every collected dataset before it can reach a finding, a tool result, or a
// bundle file, so credential-bearing properties are redacted by construction.
function redactCredentialProperties<T>(value: T): T {
  return redactCredentialNode(value) as T;
}

// Scanner records carry the linking key, registration code, and license block; none is
// read by any finding, so they are replaced at collection time.
const SCANNER_CREDENTIAL_FIELDS = ["key", "registration_code", "license"];

function stripScannerCredentials(scanner: JsonRecord): JsonRecord {
  const stripped: JsonRecord = { ...scanner };
  for (const field of SCANNER_CREDENTIAL_FIELDS) {
    if (stripped[field] !== undefined && stripped[field] !== null) stripped[field] = REDACTED;
  }
  return stripped;
}

// Only the fields the scan policy verdict reads are kept from GET /policies/{policy_id};
// the credentials block, audits, and every other section are dropped before storage.
function projectPolicyDetails(payload: JsonRecord): JsonRecord {
  const projected: JsonRecord = {};
  if (payload.uuid !== undefined) projected.uuid = payload.uuid;
  if (payload.name !== undefined) projected.name = payload.name;
  projected.settings = redactCredentialProperties(asObject(payload.settings) ?? {});
  projected.plugins = asObject(payload.plugins) ?? {};
  return projected;
}

// Non-JSON bodies (HTML error pages, SSO interstitials, WAF blocks) are described by
// status and length only; JSON bodies contribute their documented error fields.
function describeErrorBody(response: Response, rawText: string): string {
  const base = `${response.status} ${response.statusText}`.trim();
  if (rawText.length === 0) return base;
  const contentType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() || "unknown";
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return `${base}; non-JSON ${contentType} response body (${rawText.length} bytes, not echoed)`;
  }
  const record = asObject(parsed);
  const fields = record
    ? [asString(record.error), asString(asObject(record.error)?.message), asString(record.message), asString(record.error_msg)]
      .filter((item): item is string => Boolean(item))
    : [];
  if (fields.length === 0) return `${base}; JSON response body without documented error fields (${rawText.length} bytes, not echoed)`;
  return `${base}; ${fields.map((field) => redactErrorText(field.replace(/\s+/g, " ")).slice(0, 200)).join("; ")}`;
}

function parseTimestampMs(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric > 0 ? parseTimestampMs(numeric) : undefined;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function parsePluginSetMs(value: unknown): number | undefined {
  const text = asString(value);
  if (!text || !/^\d{12}$/.test(text)) return undefined;
  const year = Number(text.slice(0, 4));
  const month = Number(text.slice(4, 6)) - 1;
  const day = Number(text.slice(6, 8));
  const hour = Number(text.slice(8, 10));
  const minute = Number(text.slice(10, 12));
  const stamp = Date.UTC(year, month, day, hour, minute);
  return Number.isFinite(stamp) ? stamp : undefined;
}

function daysBetween(now: number, thenMs: number): number {
  return Math.max(0, (now - thenMs) / DAY_MS);
}

function ratio(part: number, whole: number): number {
  return whole > 0 ? Number((part / whole).toFixed(4)) : 0;
}

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
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
  if (
    relativeTarget === ".."
    || relativeTarget.startsWith(`..${join("/")}`)
    || relativeTarget.startsWith("..")
  ) {
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
  for (let index = 0; index < 50; index += 1) {
    const suffix = index === 0 ? "" : `-${index + 1}`;
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
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
    const output = createWriteStream(zipPath, { mode: 0o600, flags: "wx" });
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

function readConfigFile(pathname: string | undefined): { values: JsonRecord; source?: string } {
  if (!pathname) return { values: {} };
  const resolvedPath = pathname.startsWith("~") ? join(homedir(), pathname.slice(1)) : resolve(pathname);
  if (!existsSync(resolvedPath)) return { values: {} };
  const parsed = asObject(parseYaml(readFileSync(resolvedPath, "utf8"))) ?? {};
  return { values: parsed, source: `config:${resolvedPath}` };
}

function pick(input: JsonRecord, env: NodeJS.ProcessEnv, file: JsonRecord, argKeys: string[], envKeys: string[], fileKeys: string[]): { value?: string; source?: string } {
  for (const key of argKeys) {
    const value = asString(input[key]);
    if (value) return { value, source: `arguments-${key}` };
  }
  for (const key of envKeys) {
    const value = asString(env[key]);
    if (value) return { value, source: `environment-${key}` };
  }
  for (const key of fileKeys) {
    const value = asString(file[key]);
    if (value) return { value, source: `config-file-${key}` };
  }
  return {};
}

export function resolveTenableConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): TenableResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file) ?? asString(env.TENABLE_CONFIG_FILE) ?? join(homedir(), ".tenable", "config.yaml");
  const file = readConfigFile(configPath);
  if (file.source) sourceChain.push(file.source);

  const url = pick(input, env, file.values, ["url", "base_url"], ["TENABLE_URL", "TENABLE_BASE_URL"], ["url", "base_url"]);
  const accessKey = pick(input, env, file.values, ["access_key"], ["TENABLE_ACCESS_KEY"], ["access_key", "accessKey"]);
  const secretKey = pick(input, env, file.values, ["secret_key"], ["TENABLE_SECRET_KEY"], ["secret_key", "secretKey"]);
  const scUrl = pick(input, env, file.values, ["sc_url"], ["TENABLE_SC_URL"], ["sc_url"]);
  const scAccessKey = pick(input, env, file.values, ["sc_access_key"], ["TENABLE_SC_ACCESS_KEY"], ["sc_access_key"]);
  const scSecretKey = pick(input, env, file.values, ["sc_secret_key"], ["TENABLE_SC_SECRET_KEY"], ["sc_secret_key"]);
  const timeout = pick(input, env, file.values, ["timeout_seconds"], ["TENABLE_TIMEOUT"], ["timeout_seconds"]);

  const primaryUrl = normalizeBaseUrl(url.value ?? DEFAULT_CLOUD_URL);
  sourceChain.push(url.source ?? "default-url");
  const primaryIsCloud = isTenableCloudHost(primaryUrl);

  let vm: TenableVmConfig | undefined;
  let securityCenter: TenableSecurityCenterConfig | undefined;

  if (primaryIsCloud) {
    if (!accessKey.value || !secretKey.value) {
      throw new Error("TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY (or access_key and secret_key arguments) are required for Tenable Vulnerability Management.");
    }
    sourceChain.push(accessKey.source ?? "", secretKey.source ?? "");
    vm = { baseUrl: primaryUrl, accessKey: accessKey.value, secretKey: secretKey.value, fedramp: isFedrampHost(primaryUrl) };
  }

  const resolvedScUrl = scUrl.value ? normalizeBaseUrl(scUrl.value) : primaryIsCloud ? undefined : primaryUrl;
  if (resolvedScUrl) {
    const scAccess = scAccessKey.value ?? (primaryIsCloud ? undefined : accessKey.value);
    const scSecret = scSecretKey.value ?? (primaryIsCloud ? undefined : secretKey.value);
    if (!scAccess || !scSecret) {
      throw new Error(`Tenable Security Center at ${resolvedScUrl} needs API keys: set TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY (or TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY when TENABLE_URL points at Security Center).`);
    }
    if (scUrl.source) sourceChain.push(scUrl.source);
    sourceChain.push(scAccessKey.source ?? accessKey.source ?? "", scSecretKey.source ?? secretKey.source ?? "");
    securityCenter = { baseUrl: resolvedScUrl, accessKey: scAccess, secretKey: scSecret };
  }

  if (!vm && !securityCenter) {
    throw new Error("No Tenable platform resolved. Set TENABLE_URL to cloud.tenable.com, fedcloud.tenable.com, or a Tenable Security Center URL.");
  }

  return {
    platform: vm ? "vm" : "sc",
    vm,
    securityCenter,
    timeoutMs: clampInteger(asNumber(timeout.value), DEFAULT_TIMEOUT_MS / 1000, 1, 600) * 1000,
    sourceChain: [...new Set(sourceChain.filter(Boolean))],
  };
}

export class TenableApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(redactErrorText(message));
    this.name = "TenableApiError";
    this.status = status;
  }
}

function retryDelayMs(response: Response, attempt: number): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30_000);
    const dateMs = Date.parse(retryAfter);
    if (Number.isFinite(dateMs)) return Math.min(Math.max(dateMs - Date.now(), 250), 30_000);
  }
  return Math.min(500 * 2 ** attempt, 15_000);
}

async function defaultSleep(ms: number): Promise<void> {
  await new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

interface HttpClientOptions {
  fetchImpl?: FetchImpl;
  sleepImpl?: SleepImpl;
  retryLimit?: number;
}

abstract class TenableHttpClient {
  protected readonly baseUrl: string;
  protected readonly timeoutMs: number;
  protected readonly fetchImpl: FetchImpl;
  protected readonly sleepImpl: SleepImpl;
  protected readonly retryLimit: number;
  protected readonly secrets: string[];

  constructor(baseUrl: string, timeoutMs: number, secrets: string[], options: HttpClientOptions = {}) {
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? defaultSleep;
    this.retryLimit = options.retryLimit ?? DEFAULT_RETRY_LIMIT;
    this.secrets = secrets;
  }

  protected abstract authHeaders(): Record<string, string>;

  // Every error this client throws is built here so the configured keys and the
  // credential text patterns are scrubbed before the message exists.
  protected fail(message: string, status: number): TenableApiError {
    return new TenableApiError(redactSecrets(message, this.secrets), status);
  }

  protected buildUrl(path: string, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): string {
    const url = new URL(`${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined) continue;
      if (Array.isArray(value)) {
        for (const item of value) url.searchParams.append(key, String(item));
      } else {
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  protected async requestJson(path: string, init: RequestInit = {}, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<unknown> {
    const url = this.buildUrl(path, query);
    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          ...init,
          headers: { accept: "application/json", ...this.authHeaders(), ...(init.headers as Record<string, string> | undefined ?? {}) },
          signal: controller.signal,
        });
      } catch (error) {
        clearTimeout(timer);
        const message = redactSecrets(error instanceof Error ? error.message : String(error), this.secrets);
        const aborted = (error instanceof Error && error.name === "AbortError") || /abort/i.test(message);
        if (aborted) throw this.fail(`Tenable request to ${path} timed out after ${this.timeoutMs}ms.`, 0);
        if (attempt < this.retryLimit) {
          await this.sleepImpl(Math.min(500 * 2 ** attempt, 15_000));
          continue;
        }
        throw this.fail(`Tenable request to ${path} failed: ${message}`, 0);
      }
      clearTimeout(timer);

      if ((response.status === 429 || response.status >= 500) && attempt < this.retryLimit) {
        await this.sleepImpl(retryDelayMs(response, attempt));
        continue;
      }

      const rawText = await response.text();
      if (!response.ok) {
        throw this.fail(`Tenable request to ${path} failed (${describeErrorBody(response, rawText)})`, response.status);
      }
      if (rawText.length === 0) return {};
      try {
        return JSON.parse(rawText) as unknown;
      } catch {
        const contentType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() || "unknown";
        throw this.fail(`Tenable request to ${path} returned a non-JSON ${contentType} body (${rawText.length} bytes, not echoed).`, response.status);
      }
    }
  }
}

export interface TenableExportResult {
  exportUuid: string;
  status: string;
  records: JsonRecord[];
  totalChunks: number;
  fetchedChunks: number;
  failedChunks: number;
  truncated: boolean;
  reason?: string;
}

export class TenableApiClient extends TenableHttpClient {
  private readonly config: TenableVmConfig;
  private readonly exportTimeoutMs: number;
  private readonly exportPollMs: number;

  constructor(
    config: TenableVmConfig,
    timeoutMs: number,
    options: HttpClientOptions & { exportTimeoutMs?: number; exportPollMs?: number } = {},
  ) {
    super(config.baseUrl, timeoutMs, [config.accessKey, config.secretKey], options);
    this.config = config;
    this.exportTimeoutMs = options.exportTimeoutMs ?? DEFAULT_EXPORT_TIMEOUT_MS;
    this.exportPollMs = options.exportPollMs ?? DEFAULT_EXPORT_POLL_MS;
  }

  getConfig(): TenableVmConfig {
    return this.config;
  }

  protected authHeaders(): Record<string, string> {
    return { "X-ApiKeys": `accessKey=${this.config.accessKey};secretKey=${this.config.secretKey}` };
  }

  async get(path: string, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<JsonRecord> {
    return asObject(await this.requestJson(path, {}, query)) ?? {};
  }

  async getRaw(path: string, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<unknown> {
    return this.requestJson(path, {}, query);
  }

  async post(path: string, body: JsonRecord): Promise<JsonRecord> {
    return asObject(await this.requestJson(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })) ?? {};
  }

  async listPaginated(
    path: string,
    collectionKey: string,
    query: Record<string, string | number | boolean | undefined | Array<string | number>> = {},
    options: { pageLimit?: number; maxPages?: number } = {},
  ): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    const pageLimit = options.pageLimit ?? DEFAULT_PAGE_LIMIT;
    const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
    const items: JsonRecord[] = [];
    let offset = 0;
    let total: number | undefined;
    // Set only when the endpoint signalled the end of the collection (an empty or
    // short page, or the reported total reached). Leaving the loop at maxPages
    // without it means the inventory is partial even when no total was reported.
    let complete = false;
    let previousPageKey: string | undefined;
    for (let page = 0; page < maxPages; page += 1) {
      const payload = await this.get(path, { ...query, limit: pageLimit, offset });
      const pageItems = asRecords(payload[collectionKey]);
      const first = pageItems[0];
      const pageKey = first ? asString(first.uuid) ?? asString(first.id) ?? JSON.stringify(first) : undefined;
      // A page that opens with the same record as the previous one means the endpoint
      // ignored the offset; the walk cannot advance, so it stops as partial.
      if (pageKey !== undefined && pageKey === previousPageKey) break;
      previousPageKey = pageKey;
      items.push(...pageItems);
      total = asNumber(asObject(payload.pagination)?.total) ?? total;
      offset += pageItems.length;
      if (pageItems.length === 0 || (total !== undefined && items.length >= total) || (total === undefined && pageItems.length < pageLimit)) {
        complete = true;
        break;
      }
    }
    return { items, total, truncated: !complete || (total !== undefined && items.length < total) };
  }

  async getServerProperties(): Promise<JsonRecord> {
    return this.get("/server/properties");
  }

  async listScans(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/scans")).scans);
  }

  async getScanDetails(scanId: string | number): Promise<JsonRecord> {
    return this.get(`/scans/${encodeURIComponent(String(scanId))}`);
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/policies")).policies);
  }

  async getPolicyDetails(policyId: string | number): Promise<JsonRecord> {
    return this.get(`/policies/${encodeURIComponent(String(policyId))}`);
  }

  async listScanTemplates(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/editor/scan/templates")).templates);
  }

  async listScanners(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/scanners")).scanners).map(stripScannerCredentials);
  }

  async listAgents(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/scanners/null/agents", "agents");
  }

  async listAgentGroups(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/scanners/null/agent-groups")).groups);
  }

  async listNetworks(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/networks", "networks", {}, { pageLimit: 50 });
  }

  async listExclusions(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/exclusions", "exclusions", {}, { pageLimit: 200 });
  }

  async listCredentials(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/credentials", "credentials", {}, { pageLimit: 200 });
  }

  async listUsers(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/users", { withRoles: true })).users);
  }

  async listGroups(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/groups")).groups);
  }

  async listRoles(): Promise<JsonRecord[]> {
    return asRecords(await this.getRaw("/access-control/v1/roles"));
  }

  async listPermissions(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/api/v3/access-control/permissions")).permissions);
  }

  async listAccessGroups(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/v2/access-groups", "access_groups", {}, { pageLimit: 200 });
  }

  async listAuditLogEvents(sinceIso: string): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/audit-log/v1/events", "events", { f: [`date.gte:${sinceIso}`] }, { pageLimit: 5000, maxPages: 20 });
  }

  async listTagCategories(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/tags/categories", "categories", {}, { pageLimit: 5000 });
  }

  async listTagValues(): Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }> {
    return this.listPaginated("/tags/values", "values", {}, { pageLimit: 5000 });
  }

  async listTargetGroups(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/target-groups")).target_groups);
  }

  async listVulnExportJobs(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/vulns/export/status")).exports);
  }

  async listAssetExportJobs(): Promise<JsonRecord[]> {
    return asRecords((await this.get("/assets/export/status")).exports);
  }

  private async runExport(kind: "assets" | "vulns", body: JsonRecord, maxChunks: number): Promise<TenableExportResult> {
    const started = await this.post(`/${kind}/export`, body);
    const exportUuid = asString(started.export_uuid);
    if (!exportUuid) throw this.fail(`Tenable ${kind} export did not return export_uuid.`, 0);

    const deadline = Date.now() + this.exportTimeoutMs;
    let status: JsonRecord = {};
    for (;;) {
      status = await this.get(`/${kind}/export/${encodeURIComponent(exportUuid)}/status`);
      const state = asString(status.status)?.toUpperCase();
      if (state === "FINISHED" || state === "ERROR" || state === "CANCELLED") break;
      if (Date.now() >= deadline) {
        return { exportUuid, status: `TIMEOUT(${redactErrorText(state ?? "unknown")})`, records: [], totalChunks: 0, fetchedChunks: 0, failedChunks: 0, truncated: true, reason: `Export did not finish within ${Math.round(this.exportTimeoutMs / 1000)}s.` };
      }
      await this.sleepImpl(this.exportPollMs);
    }

    const state = redactErrorText(asString(status.status)?.toUpperCase() ?? "UNKNOWN");
    const reason = asString(status.reason);
    const available = asArray(status.chunks_available).map(asNumber).filter((item): item is number => item !== undefined);
    const failed = asArray(status.chunks_failed).length;
    const totalChunks = asNumber(status.total_chunks) ?? available.length;
    const records: JsonRecord[] = [];
    let fetchedChunks = 0;
    for (const chunkId of available.slice(0, maxChunks)) {
      const chunk = await this.getRaw(`/${kind}/export/${encodeURIComponent(exportUuid)}/chunks/${chunkId}`);
      records.push(...asRecords(chunk));
      fetchedChunks += 1;
    }
    return {
      exportUuid,
      status: state,
      records,
      totalChunks,
      fetchedChunks,
      failedChunks: failed,
      truncated: state !== "FINISHED" || fetchedChunks < available.length || failed > 0 || (totalChunks > available.length),
      reason: reason ? redactErrorText(reason) : undefined,
    };
  }

  async exportAssets(maxChunks = DEFAULT_MAX_CHUNKS): Promise<TenableExportResult> {
    return this.runExport("assets", { chunk_size: OWN_ASSET_EXPORT_CHUNK_SIZE }, maxChunks);
  }

  async exportVulnerabilities(sinceUnixSeconds: number, maxChunks = DEFAULT_MAX_CHUNKS): Promise<TenableExportResult> {
    return this.runExport("vulns", {
      num_assets: OWN_VULN_EXPORT_NUM_ASSETS,
      include_plugin_output: false,
      filters: { since: sinceUnixSeconds, state: OWN_VULN_EXPORT_STATES },
    }, maxChunks);
  }
}

export class TenableSecurityCenterClient extends TenableHttpClient {
  private readonly config: TenableSecurityCenterConfig;

  constructor(config: TenableSecurityCenterConfig, timeoutMs: number, options: HttpClientOptions = {}) {
    super(config.baseUrl, timeoutMs, [config.accessKey, config.secretKey], options);
    this.config = config;
  }

  getConfig(): TenableSecurityCenterConfig {
    return this.config;
  }

  protected authHeaders(): Record<string, string> {
    return { "x-apikey": `accesskey=${this.config.accessKey}; secretkey=${this.config.secretKey};` };
  }

  private async rest(resource: string, query: Record<string, string | number | undefined> = {}): Promise<unknown> {
    const payload = asObject(await this.requestJson(`/rest/${resource}`, {}, query)) ?? {};
    const errorCode = asNumber(payload.error_code);
    if (errorCode !== undefined && errorCode !== 0) {
      throw this.fail(`Tenable Security Center /rest/${resource} returned error_code ${errorCode}: ${asString(payload.error_msg) ?? "unknown"}`, 0);
    }
    return payload.response;
  }

  private static usableList(response: unknown): JsonRecord[] {
    if (Array.isArray(response)) return asRecords(response);
    const object = asObject(response);
    if (!object) return [];
    const usable = asRecords(object.usable);
    const manageable = asRecords(object.manageable);
    const seen = new Set<string>();
    return [...usable, ...manageable].filter((item) => {
      const id = asString(item.id) ?? JSON.stringify(item);
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  }

  async getCurrentUser(): Promise<JsonRecord> {
    return asObject(await this.rest("currentUser", { fields: "id,username,role,lastLogin" })) ?? {};
  }

  async listScans(): Promise<JsonRecord[]> {
    return TenableSecurityCenterClient.usableList(await this.rest("scan", { fields: "id,name,status,schedule,policy,repository,credentials,modifiedTime" }));
  }

  async listScanResults(startTimeUnix: number): Promise<JsonRecord[]> {
    return TenableSecurityCenterClient.usableList(await this.rest("scanResult", { fields: "id,name,status,startTime,finishTime,scannedIPs,totalIPs", startTime: startTimeUnix }));
  }

  async listScanners(): Promise<JsonRecord[]> {
    return TenableSecurityCenterClient.usableList(await this.rest("scanner", { fields: "id,name,status,statusMessage,enabled,version,pluginSet,loadedPluginSet,lastCheckinTime,agentCapable" }));
  }

  async listUsers(): Promise<JsonRecord[]> {
    return TenableSecurityCenterClient.usableList(await this.rest("user", { fields: "id,username,status,role,lastLogin,locked,failedLogins,authType" }));
  }

  async getFeed(): Promise<JsonRecord> {
    return asObject(await this.rest("feed")) ?? {};
  }
}

export interface TenableClients {
  vm?: TenableApiClient;
  securityCenter?: TenableSecurityCenterClient;
  config: TenableResolvedConfig;
}

export function createTenableClients(config: TenableResolvedConfig, options: HttpClientOptions & { exportTimeoutMs?: number; exportPollMs?: number } = {}): TenableClients {
  return {
    config,
    vm: config.vm ? new TenableApiClient(config.vm, config.timeoutMs, options) : undefined,
    securityCenter: config.securityCenter ? new TenableSecurityCenterClient(config.securityCenter, config.timeoutMs, options) : undefined,
  };
}

// The single sink for error text: every dataset error, access surface error, policy
// detail error, and tool error passes through here, so messages built outside the
// Tenable clients (parser errors, transport errors) are scrubbed as well.
function errorMessage(error: unknown): string {
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

function errorStatus(error: unknown): number | undefined {
  return error instanceof TenableApiError ? error.status : undefined;
}

function isForbiddenError(error: unknown): boolean {
  const status = errorStatus(error);
  return status === 401 || status === 403;
}

function okDataset<T>(data: T, seen: number, total?: number, truncated = false): TenableDataset<T> {
  return { data: redactCredentialProperties(data), status: "ok", seen, total, truncated };
}

function failedDataset<T>(data: T, error: unknown): TenableDataset<T> {
  return { data, status: isForbiddenError(error) ? "forbidden" : "error", error: errorMessage(error), seen: 0, truncated: true };
}

function notConfiguredDataset<T>(data: T, message: string): TenableDataset<T> {
  return { data, status: "not_configured", error: message, seen: 0, truncated: true };
}

async function collectList(load: () => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  try {
    const items = await load();
    return okDataset(items, items.length, items.length);
  } catch (error) {
    return failedDataset<JsonRecord[]>([], error);
  }
}

async function collectPaginated(load: () => Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }>): Promise<TenableDataset<JsonRecord[]>> {
  try {
    const page = await load();
    // A walk that stopped at the page cap without a reported total has an unknown
    // size; only a complete walk may use its own length as the total.
    const total = page.total ?? (page.truncated ? undefined : page.items.length);
    return okDataset(page.items, page.items.length, total, page.truncated);
  } catch (error) {
    return failedDataset<JsonRecord[]>([], error);
  }
}

async function collectObject(load: () => Promise<JsonRecord>): Promise<TenableDataset<JsonRecord>> {
  try {
    const value = await load();
    return okDataset(value, 1, 1);
  } catch (error) {
    return failedDataset<JsonRecord>({}, error);
  }
}

async function collectExport(load: () => Promise<TenableExportResult>): Promise<TenableDataset<TenableExportResult>> {
  const empty: TenableExportResult = { exportUuid: "", status: "NOT_RUN", records: [], totalChunks: 0, fetchedChunks: 0, failedChunks: 0, truncated: true };
  try {
    const result = await load();
    const dataset = okDataset(result, result.records.length, undefined, result.truncated);
    if (result.status !== "FINISHED") {
      dataset.status = "error";
      dataset.error = redactErrorText(`Export ${result.exportUuid || "(none)"} ended with status ${result.status}${result.reason ? `: ${result.reason}` : ""}.`);
    }
    return dataset;
  } catch (error) {
    return failedDataset<TenableExportResult>(empty, error);
  }
}

function datasetErrors(label: string, dataset: TenableDataset<unknown>): string[] {
  const errors: string[] = [];
  if (dataset.error && dataset.status !== "not_configured") errors.push(`${label}: ${dataset.error}`);
  if (dataset.status === "ok" && dataset.truncated) errors.push(`${label}: partial view (${dataset.seen} of ${dataset.total ?? "unknown"} records retrieved).`);
  return errors;
}

function finding(
  control: number,
  status: TenableFindingStatus,
  severity: TenableSeverity,
  summary: string,
  evidence: JsonRecord = {},
  idSuffix = "",
): TenableFinding {
  return {
    id: `TENABLE-${String(control).padStart(2, "0")}${idSuffix}`,
    title: CONTROL_TITLES[control] + (idSuffix ? " (Tenable Security Center)" : ""),
    severity,
    status,
    summary,
    evidence,
    mappings: CONTROL_MAPPINGS[control],
  };
}

function unreadableFinding(control: number, severity: TenableSeverity, dataset: TenableDataset<unknown>, endpoint: string, manualEvidence: string, idSuffix = ""): TenableFinding {
  const cause = dataset.status === "forbidden"
    ? `the API key was refused (${dataset.error ?? "401/403"})`
    : dataset.status === "not_configured"
      ? dataset.error ?? "the platform is not configured"
      : `the read failed (${dataset.error ?? "unknown error"})`;
  return finding(
    control,
    "manual",
    severity,
    `Unknown: ${endpoint} could not be read because ${cause}. A human must collect ${manualEvidence}.`,
    { endpoint, dataset_status: dataset.status, error: dataset.error ?? null },
    idSuffix,
  );
}

function partialNote(dataset: TenableDataset<unknown>): string {
  return dataset.truncated && dataset.status === "ok"
    ? ` Only ${dataset.seen} of ${dataset.total ?? "unknown"} records were retrieved, so the verdict is capped at warn.`
    : "";
}

// A pass never survives a capped, stuck, or unreadable inventory it depends on.
function capForPartial(status: TenableFindingStatus, dataset: TenableDataset<unknown>): TenableFindingStatus {
  if (status === "pass" && (dataset.status !== "ok" || dataset.truncated)) return "warn";
  return status;
}

// Rule 1 corollary: a finding that reads several inventories cannot pass while any of
// them is unreadable, even when the unreadable one only feeds evidence.
function capForUnreadable(status: TenableFindingStatus, ...datasets: Array<TenableDataset<unknown>>): TenableFindingStatus {
  if (status === "pass" && datasets.some((dataset) => dataset.status !== "ok")) return "warn";
  return status;
}

function unreadableNote(entries: Array<[string, TenableDataset<unknown>]>): string {
  const unread = entries.filter(([, dataset]) => dataset.status !== "ok");
  if (unread.length === 0) return "";
  return ` ${unread.map(([endpoint, dataset]) => `${endpoint} could not be read (${dataset.error ?? dataset.status})`).join("; ")}, so that part of the evidence is unknown and the verdict is capped at warn.`;
}

function countOrNull(dataset: TenableDataset<unknown[]>): number | null {
  return dataset.status === "ok" ? dataset.data.length : null;
}

function capForNonAdmin(status: TenableFindingStatus, callerIsAdministrator: boolean | undefined): TenableFindingStatus {
  if (status === "pass" && callerIsAdministrator !== true) return "warn";
  return status;
}

function nonAdminNote(callerIsAdministrator: boolean | undefined): string {
  return callerIsAdministrator === true ? "" : " The API key is not confirmed as Administrator, so only objects shared with it are visible and the verdict is capped at warn.";
}

function detectAdministrator(users: TenableDataset<JsonRecord[]>): boolean | undefined {
  if (users.status !== "ok" || users.data.length === 0) return undefined;
  return users.data.some((user) => asNumber(user.permissions) !== undefined);
}

function scanIsRecurring(scan: JsonRecord): boolean {
  const rrules = asString(scan.rrules);
  return Boolean(rrules) && !/FREQ=ONETIME/i.test(rrules ?? "");
}

function scanIsEnabled(scan: JsonRecord): boolean {
  return asBoolean(scan.enabled) === true;
}

function templateLooksCompliance(template: JsonRecord): boolean {
  const text = `${asString(template.name) ?? ""} ${asString(template.title) ?? ""}`;
  return /compliance|pci|scap|audit|offline config|stig/i.test(text);
}

function templateLooksDiscovery(template: JsonRecord): boolean {
  const text = `${asString(template.name) ?? ""} ${asString(template.title) ?? ""}`;
  return /discovery/i.test(text);
}

function portscanRangeIsFull(range: string): boolean {
  return /^all$/i.test(range) || /^1-65535$/.test(range.replace(/\s+/g, ""));
}

function evaluatePolicyDetail(detail: TenablePolicyDetail, policyNames: Map<string, string>): PolicyEvaluation {
  const settings = asObject(detail.details.settings) ?? {};
  const plugins = asObject(detail.details.plugins) ?? {};
  const families = Object.values(plugins).map((family) => asString(asObject(family)?.status)?.toLowerCase());
  const familiesEnabled = families.filter((status) => status === "enabled").length;
  const familiesDisabled = families.filter((status) => status === "disabled").length;
  const familiesMixed = families.filter((status) => status === "mixed").length;
  const safeChecks = asString(settings.safe_checks)?.toLowerCase() ?? null;
  const portscanRange = asString(settings.portscan_range) ?? null;
  const evaluation: PolicyEvaluation = {
    policyId: detail.policyId,
    name: policyNames.get(detail.policyId) ?? asString(detail.details.name) ?? `policy ${detail.policyId}`,
    scanNames: detail.scanNames,
    verdict: "ok",
    reasons: [],
    safeChecks,
    portscanRange,
    familiesEnabled,
    familiesDisabled,
    familiesMixed,
    performance: {
      max_hosts_per_scan: asString(settings.max_hosts_per_scan) ?? null,
      max_checks_per_host: asString(settings.max_checks_per_host) ?? null,
      thorough_tests: asString(settings.thorough_tests) ?? null,
      report_paranoia: asString(settings.report_paranoia) ?? null,
    },
  };
  if (detail.status !== "ok") {
    evaluation.verdict = "unreadable";
    evaluation.reasons.push(`GET /policies/${detail.policyId} ${detail.status === "forbidden" ? "was refused" : "failed"} (${detail.error ?? "unknown"})`);
    return evaluation;
  }
  if (safeChecks === "no") {
    evaluation.verdict = "fail";
    evaluation.reasons.push("safe_checks is no (unsafe plugins may disrupt hosts)");
  }
  if (families.length > 0 && familiesEnabled + familiesMixed === 0) {
    evaluation.verdict = "fail";
    evaluation.reasons.push(`all ${families.length} plugin families are disabled`);
  }
  if (evaluation.verdict === "fail") return evaluation;
  if (safeChecks === null || families.length === 0) {
    evaluation.verdict = "unverified";
    if (safeChecks === null) evaluation.reasons.push("settings.safe_checks is not exposed for this policy");
    if (families.length === 0) evaluation.reasons.push("plugins family map is empty or not exposed for this policy");
    return evaluation;
  }
  if (safeChecks !== "yes") {
    evaluation.verdict = "warn";
    evaluation.reasons.push(`safe_checks has unexpected value ${safeChecks}`);
  }
  if (portscanRange === null) {
    evaluation.verdict = "warn";
    evaluation.reasons.push("settings.portscan_range is not exposed");
  } else if (!/^default$/i.test(portscanRange) && !portscanRangeIsFull(portscanRange)) {
    evaluation.verdict = "warn";
    evaluation.reasons.push(`portscan_range is a custom range (${portscanRange}) rather than default or all ports`);
  }
  if (familiesDisabled > families.length / 2) {
    evaluation.verdict = "warn";
    evaluation.reasons.push(`${familiesDisabled} of ${families.length} plugin families are disabled`);
  }
  return evaluation;
}

function exclusionIsBroad(members: string | undefined): boolean {
  if (!members) return false;
  return members.split(",").some((member) => {
    const trimmed = member.trim();
    const cidr = /\/(\d{1,2})$/.exec(trimmed);
    if (cidr) return Number(cidr[1]) <= 16;
    return /^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$/.test(trimmed) && trimmed.split("-")[0].split(".")[1] !== trimmed.split("-")[1].split(".")[1];
  });
}

export interface TenablePolicyDetail {
  policyId: string;
  scanNames: string[];
  status: "ok" | "forbidden" | "error";
  error?: string;
  details: JsonRecord;
}

interface PolicyEvaluation {
  policyId: string;
  name: string;
  scanNames: string[];
  verdict: "ok" | "warn" | "fail" | "unverified" | "unreadable";
  reasons: string[];
  safeChecks: string | null;
  portscanRange: string | null;
  familiesEnabled: number;
  familiesDisabled: number;
  familiesMixed: number;
  performance: JsonRecord;
}

export interface TenableScanProgramData {
  scans: TenableDataset<JsonRecord[]>;
  policies: TenableDataset<JsonRecord[]>;
  policyDetails: TenableDataset<TenablePolicyDetail[]>;
  templates: TenableDataset<JsonRecord[]>;
  exclusions: TenableDataset<JsonRecord[]>;
  targetGroups: TenableDataset<JsonRecord[]>;
  users: TenableDataset<JsonRecord[]>;
  assetExport: TenableDataset<TenableExportResult>;
  scScans: TenableDataset<JsonRecord[]>;
  scScanResults: TenableDataset<JsonRecord[]>;
}

const SC_NOT_CONFIGURED = "Tenable Security Center is not configured (set TENABLE_SC_URL with TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY, or point TENABLE_URL at the Security Center host)";
const VM_NOT_CONFIGURED = "Tenable Vulnerability Management is not configured (TENABLE_URL points at a Tenable Security Center host, so cloud-only controls do not apply)";

async function scDataset(clients: TenableClients, load: (client: TenableSecurityCenterClient) => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.securityCenter) return notConfiguredDataset<JsonRecord[]>([], SC_NOT_CONFIGURED);
  return collectList(() => load(clients.securityCenter as TenableSecurityCenterClient));
}

async function vmList(clients: TenableClients, load: (client: TenableApiClient) => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord[]>([], VM_NOT_CONFIGURED);
  return collectList(() => load(clients.vm as TenableApiClient));
}

async function vmPaginated(clients: TenableClients, load: (client: TenableApiClient) => Promise<{ items: JsonRecord[]; total?: number; truncated: boolean }>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord[]>([], VM_NOT_CONFIGURED);
  return collectPaginated(() => load(clients.vm as TenableApiClient));
}

async function vmObject(clients: TenableClients, load: (client: TenableApiClient) => Promise<JsonRecord>): Promise<TenableDataset<JsonRecord>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord>({}, VM_NOT_CONFIGURED);
  return collectObject(() => load(clients.vm as TenableApiClient));
}

async function vmExport(clients: TenableClients, load: (client: TenableApiClient) => Promise<TenableExportResult>): Promise<TenableDataset<TenableExportResult>> {
  const empty: TenableExportResult = { exportUuid: "", status: "NOT_RUN", records: [], totalChunks: 0, fetchedChunks: 0, failedChunks: 0, truncated: true };
  if (!clients.vm) return notConfiguredDataset<TenableExportResult>(empty, VM_NOT_CONFIGURED);
  return collectExport(() => load(clients.vm as TenableApiClient));
}

async function mapWithConcurrency<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index]);
    }
  });
  await Promise.all(runners);
  return results;
}

async function collectPolicyDetails(clients: TenableClients, scans: TenableDataset<JsonRecord[]>): Promise<TenableDataset<TenablePolicyDetail[]>> {
  if (!clients.vm) return notConfiguredDataset<TenablePolicyDetail[]>([], VM_NOT_CONFIGURED);
  if (scans.status !== "ok") {
    return { data: [], status: scans.status === "forbidden" ? "forbidden" : "error", error: `policy details were not requested because GET /scans failed: ${scans.error ?? "unknown"}`, seen: 0, truncated: true };
  }
  const scanNamesByPolicy = new Map<string, string[]>();
  for (const scan of scans.data) {
    const policyId = asString(scan.policy_id);
    if (!policyId) continue;
    scanNamesByPolicy.set(policyId, [...(scanNamesByPolicy.get(policyId) ?? []), asString(scan.name) ?? asString(scan.id) ?? "scan"]);
  }
  const policyIds = [...scanNamesByPolicy.keys()];
  const requested = policyIds.slice(0, MAX_POLICY_DETAILS);
  const client = clients.vm;
  const details = await mapWithConcurrency(requested, 4, async (policyId): Promise<TenablePolicyDetail> => {
    try {
      const payload = await client.getPolicyDetails(policyId);
      return { policyId, scanNames: scanNamesByPolicy.get(policyId) ?? [], status: "ok", details: projectPolicyDetails(payload) };
    } catch (error) {
      return { policyId, scanNames: scanNamesByPolicy.get(policyId) ?? [], status: isForbiddenError(error) ? "forbidden" : "error", error: errorMessage(error), details: {} };
    }
  });
  const readable = details.filter((detail) => detail.status === "ok");
  const failed = details.filter((detail) => detail.status !== "ok");
  const dataset: TenableDataset<TenablePolicyDetail[]> = {
    data: details,
    status: readable.length > 0 || details.length === 0 ? "ok" : failed.every((detail) => detail.status === "forbidden") ? "forbidden" : "error",
    seen: readable.length,
    total: policyIds.length,
    truncated: policyIds.length > requested.length,
  };
  if (failed.length > 0) {
    dataset.error = `${failed.length} of ${details.length} GET /policies/{policy_id} reads failed: ${failed.slice(0, 5).map((detail) => `${detail.policyId} (${detail.error ?? detail.status})`).join("; ")}`;
  }
  return dataset;
}

export async function collectTenableScanProgramData(clients: TenableClients, options: TenableAssessmentOptions = {}): Promise<TenableScanProgramData> {
  const now = options.now ?? Date.now();
  const maxChunks = clampInteger(options.maxChunks, DEFAULT_MAX_CHUNKS, 1, 1000);
  const [scans, policies, templates, exclusions, targetGroups, users, assetExport, scScans, scScanResults] = await Promise.all([
    vmList(clients, (client) => client.listScans()),
    vmList(clients, (client) => client.listPolicies()),
    vmList(clients, (client) => client.listScanTemplates()),
    vmPaginated(clients, (client) => client.listExclusions()),
    vmList(clients, (client) => client.listTargetGroups()),
    vmList(clients, (client) => client.listUsers()),
    vmExport(clients, (client) => client.exportAssets(maxChunks)),
    scDataset(clients, (client) => client.listScans()),
    scDataset(clients, (client) => client.listScanResults(Math.floor((now - DEFAULT_STALE_SCAN_DAYS * DAY_MS) / 1000))),
  ]);
  const policyDetails = await collectPolicyDetails(clients, scans);
  return { scans, policies, policyDetails, templates, exclusions, targetGroups, users, assetExport, scScans, scScanResults };
}

export function assessTenableScanProgram(data: TenableScanProgramData, options: TenableAssessmentOptions = {}): TenableAssessmentResult {
  const now = options.now ?? Date.now();
  const staleScanDays = clampInteger(options.staleScanDays, DEFAULT_STALE_SCAN_DAYS, 1, 365);
  const credentialThreshold = clampNumber(options.credentialThreshold, DEFAULT_CREDENTIAL_THRESHOLD, 0, 1);
  const callerIsAdministrator = detectAdministrator(data.users);
  const findings: TenableFinding[] = [];

  const templatesById = new Map<string, JsonRecord>();
  for (const template of data.templates.data) {
    const uuid = asString(template.uuid);
    if (uuid) templatesById.set(uuid, template);
  }
  const templateFor = (item: JsonRecord): JsonRecord | undefined =>
    templatesById.get(asString(item.wizard_uuid) ?? "") ?? templatesById.get(asString(item.template_uuid) ?? "");

  if (data.scans.status !== "ok") {
    findings.push(unreadableFinding(1, "high", data.scans, "GET /scans", "the scan template list, port ranges, plugin families, and safe-check settings from the Tenable UI"));
    findings.push(unreadableFinding(2, "high", data.scans, "GET /scans", "the scan schedule list and last run dates from the Tenable UI"));
    findings.push(unreadableFinding(17, "medium", data.scans, "GET /scans", "the list of scheduled compliance audit scans (CIS, DISA STIG, PCI) from the Tenable UI"));
  } else {
    const scans = data.scans.data;
    const templateNames = new Map<string, number>();
    let discoveryOnly = 0;
    for (const scan of scans) {
      const template = templateFor(scan);
      const label = template ? asString(template.title) ?? asString(template.name) ?? "unknown template" : "unresolved template";
      templateNames.set(label, (templateNames.get(label) ?? 0) + 1);
      if (template && templateLooksDiscovery(template)) discoveryOnly += 1;
    }
    const policyTemplates = data.policies.status === "ok"
      ? data.policies.data.map((policy) => asString(templatesById.get(asString(policy.template_uuid) ?? "")?.title) ?? "unresolved template")
      : [];
    const allDiscovery = scans.length > 0 && discoveryOnly === scans.length;
    const policyNames = new Map<string, string>();
    for (const policy of data.policies.data) {
      const id = asString(policy.id);
      const name = asString(policy.name);
      if (id && name) policyNames.set(id, name);
    }
    const evaluations = data.policyDetails.data.map((detail) => evaluatePolicyDetail(detail, policyNames));
    const failingPolicies = evaluations.filter((item) => item.verdict === "fail");
    const warningPolicies = evaluations.filter((item) => item.verdict === "warn");
    const unreadablePolicies = evaluations.filter((item) => item.verdict === "unreadable");
    const unverifiedPolicies = evaluations.filter((item) => item.verdict === "unverified");
    const scansWithoutPolicy = scans.filter((scan) => asString(scan.policy_id) === undefined);
    const describe = (items: PolicyEvaluation[]): string => items.slice(0, 10).map((item) => `${item.name} [${item.reasons.join("; ")}]`).join(", ");
    const scanTypes = Object.fromEntries(scans.reduce((map, scan) => {
      const key = asString(scan.type) ?? "unknown";
      map.set(key, (map.get(key) ?? 0) + 1);
      return map;
    }, new Map<string, number>()));
    // The template list decides discovery-only detection and the policy list supplies
    // names; when either is unreadable a pass is capped and the cause is stated.
    const templateNote = (data.templates.status !== "ok"
      ? ` GET /editor/scan/templates could not be read (${data.templates.error ?? data.templates.status}), so discovery-only scan detection was not possible and the verdict is capped at warn.`
      : "") + unreadableNote([["GET /policies", data.policies]]);
    let policyStatus: TenableFindingStatus;
    let policySummary: string;
    if (scans.length === 0) {
      policyStatus = "fail";
      policySummary = `No scans are visible to this API key (GET /scans returned zero scans), so no scan policy configuration exists to audit; emptiness fails this control.${nonAdminNote(callerIsAdministrator)}`;
    } else if (allDiscovery) {
      policyStatus = "fail";
      policySummary = `All ${scans.length} visible scans use host discovery templates; no vulnerability assessment policy is configured.`;
    } else if (failingPolicies.length > 0) {
      policyStatus = "fail";
      policySummary = `${failingPolicies.length} of ${evaluations.length} scan policies referenced by scans have unsafe settings: ${describe(failingPolicies)}. Settings were read from GET /policies/{policy_id} (settings.safe_checks, settings.portscan_range, plugins family status).`;
    } else if (data.policyDetails.status !== "ok" || (evaluations.length === 0 && scansWithoutPolicy.length === scans.length)) {
      policyStatus = "manual";
      policySummary = evaluations.length === 0 && data.policyDetails.status === "ok"
        ? `Unknown: none of the ${scans.length} visible scans exposes a policy_id, so GET /policies/{policy_id} could not be called; a human must review port range, plugin families, and safe checks for each scan template in the Tenable UI (Scans > Scan Templates).`
        : `Unknown: GET /policies/{policy_id} could not be read for the ${evaluations.length} policies referenced by scans because ${data.policyDetails.status === "forbidden" ? "the API key was refused (requires the Standard [32] role and Can View on each scan template)" : `the read failed (${data.policyDetails.error ?? "unknown"})`}. A human must collect safe_checks, portscan_range, and enabled plugin families for each template from the Tenable UI.`;
    } else if (unreadablePolicies.length > 0 || unverifiedPolicies.length > 0 || data.policyDetails.truncated) {
      policyStatus = "manual";
      policySummary = `Unknown: ${evaluations.length - unreadablePolicies.length - unverifiedPolicies.length} of ${evaluations.length} referenced scan policies were verified from GET /policies/{policy_id}, but ${unreadablePolicies.length} could not be read and ${unverifiedPolicies.length} do not expose safe_checks or a plugin family map${data.policyDetails.truncated ? `, and only ${data.policyDetails.seen} of ${data.policyDetails.total ?? "unknown"} referenced policies were requested` : ""}: ${describe([...unreadablePolicies, ...unverifiedPolicies])}. A human must review those templates in the Tenable UI before this control can pass.`;
    } else if (warningPolicies.length > 0) {
      policyStatus = "warn";
      policySummary = `All ${evaluations.length} scan policies referenced by scans enable safe checks and at least one plugin family, but ${warningPolicies.length} need review: ${describe(warningPolicies)}.${templateNote}`;
    } else {
      policyStatus = capForNonAdmin(capForUnreadable("pass", data.templates, data.policies), callerIsAdministrator);
      policySummary = `All ${evaluations.length} scan policies referenced by the ${scans.length} visible scans enable safe checks (safe_checks=yes), scan the default or full port range, and keep more than half of their plugin families enabled, per GET /policies/{policy_id}.${scansWithoutPolicy.length > 0 ? ` ${scansWithoutPolicy.length} scans expose no policy_id and were not evaluated.` : ""}${templateNote}${nonAdminNote(callerIsAdministrator)}`;
      if (scansWithoutPolicy.length > 0 && policyStatus === "pass") policyStatus = "warn";
    }
    findings.push(finding(1, policyStatus, "high", policySummary, {
      scan_count: scans.length,
      scan_types: scanTypes,
      policy_count: countOrNull(data.policies),
      policy_templates: data.policies.status === "ok" && data.templates.status === "ok" ? policyTemplates.slice(0, 50) : null,
      scan_templates_in_use: data.templates.status === "ok" ? Object.fromEntries(templateNames) : null,
      scan_templates_status: data.templates.status,
      discovery_only_scans: data.templates.status === "ok" ? discoveryOnly : null,
      scans_without_policy_id: scansWithoutPolicy.map((scan) => asString(scan.name) ?? asString(scan.id)).slice(0, 50),
      policies_evaluated: evaluations.slice(0, 50).map((item) => ({
        policy_id: item.policyId,
        name: item.name,
        scans: item.scanNames.slice(0, 10),
        verdict: item.verdict,
        reasons: item.reasons,
        safe_checks: item.safeChecks,
        portscan_range: item.portscanRange,
        plugin_families: { enabled: item.familiesEnabled, disabled: item.familiesDisabled, mixed: item.familiesMixed },
        performance: item.performance,
      })),
      policy_details_status: data.policyDetails.status,
      policy_details_requested: data.policyDetails.data.length,
      caller_is_administrator: callerIsAdministrator ?? null,
    }));

    const recurring = scans.filter((scan) => scanIsEnabled(scan) && scanIsRecurring(scan));
    const disabledRecurring = scans.filter((scan) => !scanIsEnabled(scan) && scanIsRecurring(scan));
    const stale = recurring.filter((scan) => {
      const lastLaunch = parseTimestampMs(scan.last_modification_date);
      return lastLaunch !== undefined && daysBetween(now, lastLaunch) > staleScanDays;
    });
    const neverRun = recurring.filter((scan) => asString(scan.status) === "empty" || parseTimestampMs(scan.last_modification_date) === undefined);
    let scheduleStatus: TenableFindingStatus;
    let scheduleSummary: string;
    if (scans.length === 0) {
      scheduleStatus = "fail";
      scheduleSummary = `No scans are visible, so no recurring scan schedule exists; emptiness fails this control.${nonAdminNote(callerIsAdministrator)}`;
    } else if (recurring.length === 0) {
      scheduleStatus = "fail";
      scheduleSummary = `${scans.length} scans are visible but none has an enabled recurring schedule (enabled=true with non-null rrules).`;
    } else if (stale.length > 0) {
      scheduleStatus = "fail";
      scheduleSummary = `${stale.length} of ${recurring.length} enabled recurring scans last launched more than ${staleScanDays} days ago.`;
    } else if (neverRun.length > 0) {
      scheduleStatus = "warn";
      scheduleSummary = `${recurring.length} enabled recurring scans exist, but ${neverRun.length} have never run or expose no launch date, so they are not counted as fresh.`;
    } else {
      scheduleStatus = capForNonAdmin("pass", callerIsAdministrator);
      scheduleSummary = `All ${recurring.length} enabled recurring scans launched within the last ${staleScanDays} days.${nonAdminNote(callerIsAdministrator)}`;
    }
    findings.push(finding(2, scheduleStatus, "high", scheduleSummary, {
      scan_count: scans.length,
      enabled_recurring_scans: recurring.length,
      disabled_recurring_scans: disabledRecurring.length,
      stale_recurring_scans: stale.map((scan) => asString(scan.name) ?? asString(scan.id)).slice(0, 50),
      never_run_or_undated_scans: neverRun.map((scan) => asString(scan.name) ?? asString(scan.id)).slice(0, 50),
      stale_scan_days: staleScanDays,
      caller_is_administrator: callerIsAdministrator ?? null,
    }));

    if (data.templates.status !== "ok") {
      findings.push(unreadableFinding(17, "medium", data.templates, "GET /editor/scan/templates", "the list of scheduled compliance audit scans (CIS, DISA STIG, PCI) from the Tenable UI"));
    } else {
      const complianceScans = scans.filter((scan) => {
        const template = templateFor(scan);
        return Boolean(template && templateLooksCompliance(template));
      });
      const activeCompliance = complianceScans.filter((scan) => scanIsEnabled(scan) && scanIsRecurring(scan));
      findings.push(finding(
        17,
        scans.length === 0 ? "fail" : activeCompliance.length > 0 ? capForNonAdmin("pass", callerIsAdministrator) : "fail",
        "medium",
        scans.length === 0
          ? "No scans are visible, so no compliance audit scan is configured; emptiness fails this control."
          : activeCompliance.length > 0
            ? `${activeCompliance.length} enabled recurring scans use compliance audit templates (${complianceScans.length} compliance scans total). Confirm the audit files target the in-scope assets.${nonAdminNote(callerIsAdministrator)}`
            : `${complianceScans.length} scans use compliance audit templates but none is enabled with a recurring schedule.`,
        {
          compliance_scans: complianceScans.map((scan) => asString(scan.name) ?? asString(scan.id)).slice(0, 50),
          enabled_recurring_compliance_scans: activeCompliance.length,
          compliance_templates_available: data.templates.data.filter(templateLooksCompliance).map((template) => asString(template.title) ?? asString(template.name)).slice(0, 50),
        },
      ));
    }
  }

  if (data.assetExport.status !== "ok") {
    findings.push(unreadableFinding(4, "high", data.assetExport, "POST /assets/export", "the credentialed scan ratio from the Tenable asset inventory (Last Authenticated Scan filter)"));
  } else {
    const assets = data.assetExport.data.records;
    const credentialed = assets.filter((asset) => asString(asset.last_authentication_scan_status) === "Success" || asBoolean(asset.has_agent) === true);
    const failures = assets.filter((asset) => asString(asset.last_authentication_scan_status) === "Failure");
    const never = assets.filter((asset) => {
      const status = asString(asset.last_authentication_scan_status);
      return asBoolean(asset.has_agent) !== true && (status === undefined || status === "N/A");
    });
    const coverage = ratio(credentialed.length, assets.length);
    let status: TenableFindingStatus;
    let summary: string;
    if (assets.length === 0) {
      status = "manual";
      summary = "The asset export finished but returned zero assets, so the credentialed scan ratio cannot be computed; verify the key's asset visibility (All Assets Can View) and that scans have run.";
    } else if (coverage < credentialThreshold) {
      status = "fail";
      summary = `${percent(coverage)} of ${assets.length} exported assets had a successful credentialed or agent scan, below the ${percent(credentialThreshold)} threshold.`;
    } else {
      status = capForPartial("pass", data.assetExport);
      summary = `${percent(coverage)} of ${assets.length} exported assets had a successful credentialed or agent scan (threshold ${percent(credentialThreshold)}).${partialNote(data.assetExport)}`;
    }
    findings.push(finding(4, status, "high", summary, {
      asset_count: assets.length,
      credentialed_or_agent_assets: credentialed.length,
      authentication_failures: failures.length,
      never_attempted_or_unknown: never.length,
      coverage_ratio: coverage,
      threshold: credentialThreshold,
      export_status: data.assetExport.data.status,
      chunks_fetched: `${data.assetExport.data.fetchedChunks}/${data.assetExport.data.totalChunks}`,
    }));
  }

  if (data.exclusions.status !== "ok") {
    findings.push(unreadableFinding(13, "medium", data.exclusions, "GET /exclusions", "the scan exclusion list with schedules, targets, and justifications from Settings > Exclusions"));
  } else {
    const exclusions = data.exclusions.data;
    const permanent = exclusions.filter((item) => asBoolean(asObject(item.schedule)?.enabled) !== true);
    const undocumented = exclusions.filter((item) => !asString(item.description));
    const broad = exclusions.filter((item) => exclusionIsBroad(asString(item.members)));
    const issues = new Set([...permanent, ...undocumented, ...broad].map((item) => asString(item.name) ?? asString(item.id) ?? "exclusion"));
    findings.push(finding(
      13,
      exclusions.length === 0 ? capForPartial("pass", data.exclusions) : issues.size === 0 ? capForPartial("pass", data.exclusions) : permanent.length > 0 || broad.length > 0 ? "fail" : "warn",
      "medium",
      exclusions.length === 0
        ? `GET /exclusions returned pagination.total 0, so nothing is excluded from scanning; emptiness is compliant for this control.${partialNote(data.exclusions)}`
        : issues.size === 0
          ? `All ${exclusions.length} exclusions are scheduled, documented, and scoped to narrow targets.${partialNote(data.exclusions)}`
          : `${issues.size} of ${exclusions.length} exclusions need review: ${permanent.length} always-on (schedule.enabled=false), ${undocumented.length} without a description, ${broad.length} covering /16 or wider ranges.`,
      {
        exclusion_count: exclusions.length,
        pagination_total: data.exclusions.total ?? null,
        permanent_exclusions: permanent.map((item) => asString(item.name)).slice(0, 50),
        undocumented_exclusions: undocumented.map((item) => asString(item.name)).slice(0, 50),
        broad_exclusions: broad.map((item) => asString(item.name)).slice(0, 50),
      },
    ));
  }

  if (data.targetGroups.status !== "ok") {
    findings.push(unreadableFinding(20, "low", data.targetGroups, "GET /target-groups", "the legacy target group list (deprecated feature) or confirmation that tags replaced target groups"));
  } else {
    const groups = data.targetGroups.data;
    const stale = groups.filter((group) => {
      const modified = parseTimestampMs(group.last_modification_date);
      return modified === undefined || daysBetween(now, modified) > 365;
    });
    const memberIndex = new Map<string, string[]>();
    for (const group of groups) {
      for (const member of (asString(group.members) ?? "").split(",").map((item) => item.trim()).filter(Boolean)) {
        memberIndex.set(member, [...(memberIndex.get(member) ?? []), asString(group.name) ?? "group"]);
      }
    }
    const overlapping = [...memberIndex.entries()].filter(([, owners]) => owners.length > 1);
    findings.push(finding(
      20,
      groups.length === 0 ? capForNonAdmin("pass", callerIsAdministrator) : stale.length === 0 && overlapping.length === 0 ? capForNonAdmin("pass", callerIsAdministrator) : "warn",
      "low",
      groups.length === 0
        ? `No legacy target groups are visible (GET /target-groups returned an empty list); target groups were deprecated in February 2022 in favor of tags, so emptiness is compliant.${nonAdminNote(callerIsAdministrator)}`
        : stale.length === 0 && overlapping.length === 0
          ? `${groups.length} legacy target groups exist, all modified within the last year with no overlapping members. Plan a migration to tags.${nonAdminNote(callerIsAdministrator)}`
          : `${groups.length} legacy target groups exist: ${stale.length} unmodified for over a year or undated, ${overlapping.length} member targets appear in more than one group.`,
      {
        target_group_count: groups.length,
        stale_or_undated_groups: stale.map((group) => asString(group.name)).slice(0, 50),
        overlapping_targets: overlapping.slice(0, 25).map(([member, owners]) => ({ member, groups: owners })),
      },
    ));
  }

  findings.push(assessSecurityCenterSchedule(data.scScans, data.scScanResults, now, staleScanDays));

  const errors = [
    ...datasetErrors("scans", data.scans),
    ...datasetErrors("policies", data.policies),
    ...datasetErrors("policy_details", data.policyDetails),
    ...datasetErrors("templates", data.templates),
    ...datasetErrors("exclusions", data.exclusions),
    ...datasetErrors("target_groups", data.targetGroups),
    ...datasetErrors("users", data.users),
    ...datasetErrors("asset_export", data.assetExport),
    ...datasetErrors("sc_scans", data.scScans),
    ...datasetErrors("sc_scan_results", data.scScanResults),
  ];

  return {
    title: "Tenable scan program",
    category: "scan_program",
    summary: {
      scan_count: countOrNull(data.scans),
      policy_count: countOrNull(data.policies),
      exclusion_count: countOrNull(data.exclusions),
      target_group_count: countOrNull(data.targetGroups),
      exported_assets: data.assetExport.status === "ok" ? data.assetExport.data.records.length : null,
      caller_is_administrator: callerIsAdministrator ?? null,
      ...statusCounts(findings),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterSchedule(scans: TenableDataset<JsonRecord[]>, results: TenableDataset<JsonRecord[]>, now: number, staleScanDays: number): TenableFinding {
  if (scans.status !== "ok") {
    return unreadableFinding(2, "high", scans, "GET /rest/scan", "the Security Center scan schedule list and recent scan results", "-SC");
  }
  const scheduled = scans.data.filter((scan) => asString(asObject(scan.schedule)?.type) === "ical");
  const completed = results.status === "ok"
    ? results.data.filter((result) => /completed/i.test(asString(result.status) ?? "") && parseTimestampMs(result.finishTime) !== undefined && daysBetween(now, parseTimestampMs(result.finishTime) as number) <= staleScanDays)
    : [];
  let status: TenableFindingStatus;
  let summary: string;
  if (scans.data.length === 0) {
    status = "fail";
    summary = "Security Center returned zero scans for this API key, so no recurring schedule exists; emptiness fails this control.";
  } else if (scheduled.length === 0) {
    status = "fail";
    summary = `${scans.data.length} Security Center scans are visible but none uses an ical (recurring) schedule.`;
  } else if (results.status !== "ok") {
    status = "manual";
    summary = `${scheduled.length} recurring Security Center scans exist but GET /rest/scanResult could not be read (${results.error ?? "unknown"}), so recent completion cannot be confirmed.`;
  } else if (completed.length === 0) {
    status = "fail";
    summary = `${scheduled.length} recurring Security Center scans exist but no scan result completed in the last ${staleScanDays} days.`;
  } else {
    status = "pass";
    summary = `${scheduled.length} recurring Security Center scans exist and ${completed.length} scan results completed in the last ${staleScanDays} days.`;
  }
  return finding(2, status, "high", summary, {
    sc_scan_count: scans.data.length,
    sc_recurring_scans: scheduled.length,
    sc_completed_results_in_window: results.status === "ok" ? completed.length : null,
    sc_scan_results_status: results.status,
  }, "-SC");
}

export interface TenableSensorCoverageData {
  serverProperties: TenableDataset<JsonRecord>;
  scanners: TenableDataset<JsonRecord[]>;
  agents: TenableDataset<JsonRecord[]>;
  agentGroups: TenableDataset<JsonRecord[]>;
  networks: TenableDataset<JsonRecord[]>;
  tagCategories: TenableDataset<JsonRecord[]>;
  tagValues: TenableDataset<JsonRecord[]>;
  assetExport: TenableDataset<TenableExportResult>;
  users: TenableDataset<JsonRecord[]>;
  scScanners: TenableDataset<JsonRecord[]>;
  scFeed: TenableDataset<JsonRecord>;
}

export async function collectTenableSensorCoverageData(clients: TenableClients, options: TenableAssessmentOptions = {}): Promise<TenableSensorCoverageData> {
  const maxChunks = clampInteger(options.maxChunks, DEFAULT_MAX_CHUNKS, 1, 1000);
  const [serverProperties, scanners, agents, agentGroups, networks, tagCategories, tagValues, assetExport, users, scScanners, scFeed] = await Promise.all([
    vmObject(clients, (client) => client.getServerProperties()),
    vmList(clients, (client) => client.listScanners()),
    vmPaginated(clients, (client) => client.listAgents()),
    vmList(clients, (client) => client.listAgentGroups()),
    vmPaginated(clients, (client) => client.listNetworks()),
    vmPaginated(clients, (client) => client.listTagCategories()),
    vmPaginated(clients, (client) => client.listTagValues()),
    vmExport(clients, (client) => client.exportAssets(maxChunks)),
    vmList(clients, (client) => client.listUsers()),
    scDataset(clients, (client) => client.listScanners()),
    clients.securityCenter ? collectObject(() => (clients.securityCenter as TenableSecurityCenterClient).getFeed()) : Promise.resolve(notConfiguredDataset<JsonRecord>({}, SC_NOT_CONFIGURED)),
  ]);
  return { serverProperties, scanners, agents, agentGroups, networks, tagCategories, tagValues, assetExport, users, scScanners, scFeed };
}

function compareVersions(left: string, right: string): number {
  const a = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const b = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const diff = (a[index] ?? 0) - (b[index] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function newestVersion(versions: string[]): string | undefined {
  return versions.filter((item) => /^\d+(\.\d+)+/.test(item)).sort(compareVersions).at(-1);
}

export function assessTenableSensorCoverage(data: TenableSensorCoverageData, options: TenableAssessmentOptions = {}): TenableAssessmentResult {
  const now = options.now ?? Date.now();
  const staleAssetDays = clampInteger(options.staleAssetDays, DEFAULT_STALE_ASSET_DAYS, 1, 365);
  const agentOfflineDays = clampInteger(options.agentOfflineDays, DEFAULT_AGENT_OFFLINE_DAYS, 1, 365);
  const pluginStaleHours = clampInteger(options.pluginStaleHours, DEFAULT_PLUGIN_STALE_HOURS, 1, 24 * 30);
  const taggedThreshold = clampNumber(options.taggedThreshold, DEFAULT_TAGGED_THRESHOLD, 0, 1);
  const callerIsAdministrator = detectAdministrator(data.users);
  const findings: TenableFinding[] = [];
  const assets = data.assetExport.status === "ok" ? data.assetExport.data.records : [];

  if (data.assetExport.status !== "ok") {
    findings.push(unreadableFinding(3, "high", data.assetExport, "POST /assets/export", "the asset inventory per network and the expected network ranges"));
    findings.push(unreadableFinding(16, "medium", data.assetExport, "POST /assets/export", "the asset tag coverage report from the Tenable UI"));
  } else {
    const fresh = assets.filter((asset) => {
      const lastSeen = parseTimestampMs(asset.last_seen);
      return lastSeen !== undefined && daysBetween(now, lastSeen) <= staleAssetDays;
    });
    const undated = assets.filter((asset) => parseTimestampMs(asset.last_seen) === undefined);
    const stale = assets.length - fresh.length - undated.length;
    const perNetwork = new Map<string, number>();
    for (const asset of assets) {
      const network = asString(asset.network_name) ?? asString(asset.network_id) ?? "unknown";
      perNetwork.set(network, (perNetwork.get(network) ?? 0) + 1);
    }
    const emptyNetworks = data.networks.status === "ok"
      ? data.networks.data.filter((network) => !perNetwork.has(asString(network.name) ?? "") && !perNetwork.has(asString(network.uuid) ?? "")).map((network) => asString(network.name) ?? asString(network.uuid) ?? "network")
      : [];
    const expected = options.expectedAssetCount;
    const networkNote = data.networks.status === "ok"
      ? (emptyNetworks.length > 0 ? ` Networks without assets: ${emptyNetworks.slice(0, 10).join(", ")}.` : "")
      : ` GET /networks could not be read (${data.networks.error ?? data.networks.status}), so networks without assets are unknown.`;
    let status: TenableFindingStatus;
    let summary: string;
    if (assets.length === 0) {
      status = "fail";
      summary = "The asset export finished with zero assets, so no asset inventory exists to compare against expected ranges; emptiness fails this control.";
    } else if (expected !== undefined && expected > 0) {
      const coverage = ratio(fresh.length, expected);
      status = coverage >= 0.95 ? capForUnreadable(capForPartial("pass", data.assetExport), data.networks) : "fail";
      summary = `${fresh.length} assets seen within ${staleAssetDays} days against an expected population of ${expected} (${percent(coverage)} coverage).${undated.length > 0 ? ` ${undated.length} assets have no last_seen date and were not counted.` : ""}${partialNote(data.assetExport)}${unreadableNote([["GET /networks", data.networks]])}`;
    } else {
      status = "manual";
      summary = `${assets.length} assets exported (${fresh.length} seen within ${staleAssetDays} days, ${stale} stale, ${undated.length} without last_seen). The API does not know the expected network ranges; pass expected_asset_count or compare the per-network counts in the evidence against the authoritative inventory.${networkNote}`;
    }
    findings.push(finding(3, status, "high", summary, {
      asset_count: assets.length,
      fresh_assets: fresh.length,
      stale_assets: stale,
      undated_assets: undated.length,
      assets_per_network: Object.fromEntries(perNetwork),
      networks_without_assets: data.networks.status === "ok" ? emptyNetworks.slice(0, 50) : null,
      networks_status: data.networks.status,
      expected_asset_count: expected ?? null,
      export_status: data.assetExport.data.status,
    }));

    const tagged = assets.filter((asset) => asRecords(asset.tags).length > 0);
    const categories = data.tagCategories.status === "ok" ? data.tagCategories.data.map((item) => asString(item.name) ?? "category") : [];
    const taggedRatio = ratio(tagged.length, assets.length);
    let tagStatus: TenableFindingStatus;
    let tagSummary: string;
    if (data.tagCategories.status !== "ok") {
      tagStatus = "manual";
      tagSummary = `GET /tags/categories could not be read (${data.tagCategories.error ?? "unknown"}); a human must confirm the tag taxonomy for compliance scope, business unit, and environment.`;
    } else if (assets.length === 0) {
      tagStatus = "manual";
      tagSummary = "Zero assets were exported, so tag coverage cannot be measured.";
    } else if (categories.length === 0) {
      tagStatus = "fail";
      tagSummary = "No tag categories are defined, so assets are not classified for compliance scope, business unit, or environment.";
    } else if (taggedRatio < taggedThreshold) {
      tagStatus = "fail";
      tagSummary = `${percent(taggedRatio)} of ${assets.length} assets carry at least one tag, below the ${percent(taggedThreshold)} threshold (${categories.length} categories defined).`;
    } else {
      tagStatus = capForUnreadable(capForPartial("pass", data.assetExport), data.tagValues);
      tagSummary = `${percent(taggedRatio)} of ${assets.length} assets carry at least one tag across ${categories.length} categories. Confirm the categories cover compliance scope, business unit, and environment.${partialNote(data.assetExport)}${unreadableNote([["GET /tags/values", data.tagValues]])}`;
    }
    findings.push(finding(16, tagStatus, "medium", tagSummary, {
      asset_count: assets.length,
      tagged_assets: tagged.length,
      tagged_ratio: taggedRatio,
      threshold: taggedThreshold,
      tag_categories: data.tagCategories.status === "ok" ? categories.slice(0, 50) : null,
      tag_value_count: countOrNull(data.tagValues),
    }));
  }

  const licensedAgents = asNumber(asObject(asObject(data.serverProperties.data)?.license)?.agents);
  if (data.agents.status !== "ok") {
    findings.push(unreadableFinding(5, "high", data.agents, "GET /scanners/null/agents", "the agent inventory with status, last connect, and version from Sensors > Agents"));
    findings.push(unreadableFinding(6, "medium", data.agents, "GET /scanners/null/agents", "the agent group membership report from Sensors > Agents"));
  } else {
    const agents = data.agents.data;
    const offline = agents.filter((agent) => asString(agent.status) === "off");
    const staleConnect = agents.filter((agent) => {
      const lastConnect = parseTimestampMs(agent.last_connect);
      return lastConnect !== undefined && daysBetween(now, lastConnect) > agentOfflineDays;
    });
    const undated = agents.filter((agent) => parseTimestampMs(agent.last_connect) === undefined);
    const newest = newestVersion(agents.map((agent) => asString(agent.core_version) ?? ""));
    const outdated = newest ? agents.filter((agent) => {
      const version = asString(agent.core_version);
      return version !== undefined && compareVersions(version, newest) < 0 && (version.split(".")[0] !== newest.split(".")[0] || Number(version.split(".")[1] ?? 0) < Number(newest.split(".")[1] ?? 0));
    }) : [];
    const unhealthy = new Set([...offline, ...staleConnect].map((agent) => asString(agent.uuid) ?? asString(agent.id) ?? asString(agent.name) ?? "agent"));
    let status: TenableFindingStatus;
    let summary: string;
    if (agents.length === 0) {
      status = "manual";
      summary = licensedAgents === 0
        ? "Unlicensed: the license reports zero agents and no agents are linked, so agent deployment does not apply to this tenant."
        : `No agents are linked (pagination.total ${data.agents.total ?? 0}). Confirm whether agent deployment is in scope; emptiness cannot pass this control.`;
    } else if (ratio(unhealthy.size, agents.length) > 0.1) {
      status = "fail";
      summary = `${unhealthy.size} of ${agents.length} agents are offline or have not connected in ${agentOfflineDays} days (more than 10%).`;
    } else if (undated.length > 0 || outdated.length > 0 || data.agents.truncated) {
      status = "warn";
      summary = `${agents.length} agents inventoried; ${unhealthy.size} offline or stale, ${undated.length} without last_connect (not counted as healthy), ${outdated.length} below the newest linked version ${newest ?? "unknown"}.${partialNote(data.agents)}`;
    } else {
      status = capForUnreadable("pass", data.serverProperties);
      summary = `All ${agents.length} agents connected within ${agentOfflineDays} days and run version ${newest ?? "unknown"}; ${unhealthy.size} offline.${unreadableNote([["GET /server/properties (license.agents)", data.serverProperties]])}`;
    }
    findings.push(finding(5, status, "high", summary, {
      agent_count: agents.length,
      pagination_total: data.agents.total ?? null,
      licensed_agents: licensedAgents ?? null,
      server_properties_status: data.serverProperties.status,
      offline_agents: offline.length,
      stale_connect_agents: staleConnect.length,
      undated_agents: undated.length,
      newest_version: newest ?? null,
      outdated_agents: outdated.map((agent) => `${asString(agent.name) ?? agent.id} (${asString(agent.core_version)})`).slice(0, 50),
      agent_offline_days: agentOfflineDays,
    }));

    const ungrouped = agents.filter((agent) => asRecords(agent.groups).length === 0);
    const groupCount = data.agentGroups.status === "ok" ? data.agentGroups.data.length : null;
    let groupStatus: TenableFindingStatus;
    let groupSummary: string;
    if (agents.length === 0) {
      groupStatus = "manual";
      groupSummary = "No agents are linked, so there is no agent group organization to evaluate.";
    } else if (data.agentGroups.status !== "ok") {
      groupStatus = "manual";
      groupSummary = `GET /scanners/null/agent-groups could not be read (${data.agentGroups.error ?? "unknown"}); ${ungrouped.length} of ${agents.length} agents report no group membership.`;
    } else if (groupCount === 0 || ratio(ungrouped.length, agents.length) > 0.1) {
      groupStatus = "fail";
      groupSummary = `${ungrouped.length} of ${agents.length} agents belong to no agent group (${groupCount} groups defined).`;
    } else if (ungrouped.length > 0 || data.agents.truncated) {
      groupStatus = "warn";
      groupSummary = `${ungrouped.length} of ${agents.length} agents are ungrouped across ${groupCount} groups.${partialNote(data.agents)}`;
    } else {
      groupStatus = "pass";
      groupSummary = `All ${agents.length} agents belong to at least one of ${groupCount} agent groups. Confirm the groups mirror network segments or business units.`;
    }
    findings.push(finding(6, groupStatus, "medium", groupSummary, {
      agent_count: agents.length,
      agent_group_count: groupCount,
      ungrouped_agents: ungrouped.map((agent) => asString(agent.name) ?? asString(agent.id)).slice(0, 50),
      groups: data.agentGroups.status === "ok" ? data.agentGroups.data.map((group) => ({ name: asString(group.name), agents_count: asNumber(group.agents_count) ?? null })).slice(0, 50) : null,
      agent_groups_status: data.agentGroups.status,
    }));
  }

  const linkedScanners = data.scanners.data.filter((scanner) => asString(scanner.type) !== "local" && asBoolean(scanner.pool) !== true && asBoolean(scanner.group) !== true);
  if (data.scanners.status !== "ok") {
    findings.push(unreadableFinding(7, "high", data.scanners, "GET /scanners", "the linked scanner list with status, last connect, and Nessus version from Sensors > Nessus Scanners"));
  } else if (data.scanners.data.length === 0) {
    findings.push(finding(7, "manual", "high", "GET /scanners returned zero scanners; even cloud scanners were not visible, so the key cannot see sensors. Collect the scanner inventory from Sensors > Nessus Scanners.", { scanner_count: 0 }));
  } else if (linkedScanners.length === 0) {
    findings.push(finding(7, "manual", "high", `Not applicable to linked appliances: ${data.scanners.data.length} scanner entries are visible but all are Tenable-managed cloud scanners or groups. Confirm the tenant intentionally relies only on cloud scanners.`, {
      scanner_count: data.scanners.data.length,
      cloud_scanners: data.scanners.data.map((scanner) => asString(scanner.name)).slice(0, 50),
    }));
  } else {
    const unlinked = linkedScanners.filter((scanner) => asNumber(scanner.linked) !== 1);
    const off = linkedScanners.filter((scanner) => asString(scanner.status) !== "on");
    const staleConnect = linkedScanners.filter((scanner) => {
      const lastConnect = parseTimestampMs(scanner.last_connect);
      return lastConnect !== undefined && daysBetween(now, lastConnect) > 1;
    });
    const undated = linkedScanners.filter((scanner) => parseTimestampMs(scanner.last_connect) === undefined);
    const newest = newestVersion(linkedScanners.map((scanner) => asString(scanner.ui_version) ?? ""));
    const outdated = newest ? linkedScanners.filter((scanner) => {
      const version = asString(scanner.ui_version);
      return version !== undefined && compareVersions(version, newest) < 0;
    }) : [];
    const unhealthy = new Set([...unlinked, ...off, ...staleConnect].map((scanner) => asString(scanner.name) ?? asString(scanner.id) ?? "scanner"));
    findings.push(finding(
      7,
      unhealthy.size > 0 ? "fail" : undated.length > 0 || outdated.length > 0 ? "warn" : capForNonAdmin(capForPartial("pass", data.scanners), callerIsAdministrator),
      "high",
      unhealthy.size > 0
        ? `${unhealthy.size} of ${linkedScanners.length} linked scanners are unlinked, off, or have not connected in 24 hours: ${[...unhealthy].slice(0, 10).join(", ")}.`
        : undated.length > 0 || outdated.length > 0
          ? `${linkedScanners.length} linked scanners are on and linked, but ${undated.length} have no last_connect and ${outdated.length} run a version older than ${newest ?? "unknown"}.`
          : `All ${linkedScanners.length} linked scanners are on, linked, connected within 24 hours, and run version ${newest ?? "unknown"}.${partialNote(data.scanners)}${nonAdminNote(callerIsAdministrator)}`,
      {
        linked_scanner_count: linkedScanners.length,
        total_scanner_entries: data.scanners.data.length,
        caller_is_administrator: callerIsAdministrator ?? null,
        unlinked: unlinked.map((scanner) => asString(scanner.name)).slice(0, 50),
        off: off.map((scanner) => asString(scanner.name)).slice(0, 50),
        stale_connect: staleConnect.map((scanner) => asString(scanner.name)).slice(0, 50),
        undated: undated.map((scanner) => asString(scanner.name)).slice(0, 50),
        newest_version: newest ?? null,
        outdated: outdated.map((scanner) => `${asString(scanner.name)} (${asString(scanner.ui_version)})`).slice(0, 50),
      },
    ));
  }

  if (data.serverProperties.status !== "ok") {
    findings.push(unreadableFinding(8, "high", data.serverProperties, "GET /server/properties", "the current plugin set date from Settings > About and each scanner's plugin set"));
  } else {
    const serverPluginMs = parsePluginSetMs(data.serverProperties.data.plugin_set) ?? parsePluginSetMs(data.serverProperties.data.loaded_plugin_set);
    const datedScanners = data.scanners.data.filter((scanner) => parsePluginSetMs(scanner.loaded_plugin_set) !== undefined);
    const staleScanners = datedScanners.filter((scanner) => {
      const stamp = parsePluginSetMs(scanner.loaded_plugin_set);
      return stamp !== undefined && now - stamp > pluginStaleHours * 3_600_000;
    });
    const undatedScanners = data.scanners.data.filter((scanner) => asBoolean(scanner.pool) !== true && asBoolean(scanner.group) !== true && parsePluginSetMs(scanner.loaded_plugin_set) === undefined);
    const staleAgents = data.agents.status === "ok" ? data.agents.data.filter((agent) => {
      const stamp = parsePluginSetMs(agent.plugin_feed_id);
      return stamp !== undefined && now - stamp > pluginStaleHours * 3_600_000 && asString(agent.status) === "on";
    }) : [];
    const serverFresh = serverPluginMs !== undefined && now - serverPluginMs <= pluginStaleHours * 3_600_000;
    let status: TenableFindingStatus;
    let summary: string;
    if (serverPluginMs === undefined) {
      status = "manual";
      summary = "GET /server/properties did not expose a parseable plugin_set, so plugin currency cannot be confirmed; collect the plugin set date from Settings > About.";
    } else if (!serverFresh || staleScanners.length > 0) {
      status = "fail";
      summary = `The container plugin set ${asString(data.serverProperties.data.plugin_set) ?? "unknown"} is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and ${staleScanners.length} of ${datedScanners.length} scanner entries exposing loaded_plugin_set load a set older than ${pluginStaleHours} hours${staleScanners.length > 0 ? ` (${staleScanners.map((scanner) => asString(scanner.name) ?? asString(scanner.id)).slice(0, 10).join(", ")})` : ""}.`;
    } else if (data.scanners.status !== "ok") {
      status = "manual";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old, but GET /scanners failed (${data.scanners.error ?? "unknown"}), so no scanner plugin set could be evaluated; collect each scanner's plugin set from Settings > Sensors.`;
    } else if (datedScanners.length === 0) {
      status = "manual";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old, but ${data.scanners.data.length === 0 ? "GET /scanners returned zero scanners" : `none of the ${data.scanners.data.length} scanner entries exposes a parseable loaded_plugin_set (${undatedScanners.length} scanner instances without one, the rest are cloud scanner pools or groups)`}, so per-scanner plugin currency is not applicable or unverifiable and cannot pass; confirm scanner plugin sets in Settings > Sensors.`;
    } else if (undatedScanners.length > 0 || staleAgents.length > 0) {
      status = "warn";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and ${datedScanners.length} scanner entries load a fresh plugin set, but ${undatedScanners.length} scanner instances expose no parseable plugin set (not counted as current) and ${staleAgents.length} online agents load a plugin set older than ${pluginStaleHours} hours.`;
    } else if (data.agents.status !== "ok") {
      // Agent plugin currency is a verdict input; an unreadable agent list cannot pass.
      status = "warn";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and all ${datedScanners.length} scanner entries exposing loaded_plugin_set load a set newer than ${pluginStaleHours} hours, but GET /scanners/null/agents could not be read (${data.agents.error ?? data.agents.status}), so agent plugin currency is unknown and the verdict is capped at warn.`;
    } else {
      status = capForPartial("pass", data.agents);
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and all ${datedScanners.length} scanner entries exposing loaded_plugin_set (${linkedScanners.length} linked appliances) load a set newer than ${pluginStaleHours} hours.${partialNote(data.agents)}`;
    }
    findings.push(finding(8, status, "high", summary, {
      plugin_set: asString(data.serverProperties.data.plugin_set) ?? null,
      plugin_set_age_hours: serverPluginMs === undefined ? null : Math.round((now - serverPluginMs) / 3_600_000),
      scanner_entries: countOrNull(data.scanners),
      evaluated_scanners: datedScanners.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loaded_plugin_set)})`).slice(0, 50),
      stale_scanners: staleScanners.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loaded_plugin_set)})`).slice(0, 50),
      undated_scanners: undatedScanners.map((scanner) => asString(scanner.name)).slice(0, 50),
      stale_online_agents: data.agents.status === "ok" ? staleAgents.length : null,
      agents_status: data.agents.status,
      threshold_hours: pluginStaleHours,
    }));
  }

  if (data.networks.status !== "ok") {
    findings.push(unreadableFinding(9, "medium", data.networks, "GET /networks", "the network object list with assigned scanners from Settings > Sensors > Networks"));
  } else {
    const networks = data.networks.data;
    const withoutScanners = networks.filter((network) => asNumber(network.scanner_count) === 0);
    const unknownCount = networks.filter((network) => asNumber(network.scanner_count) === undefined);
    findings.push(finding(
      9,
      networks.length === 0 ? "manual" : withoutScanners.length > 0 ? "fail" : unknownCount.length > 0 ? "warn" : capForPartial("pass", data.networks),
      "medium",
      networks.length === 0
        ? "GET /networks returned zero network objects; the default network should always exist, so the view is incomplete. Collect the network list from Settings > Sensors > Networks."
        : withoutScanners.length > 0
          ? `${withoutScanners.length} of ${networks.length} network objects have no assigned scanners: ${withoutScanners.map((network) => asString(network.name)).slice(0, 10).join(", ")}.`
          : unknownCount.length > 0
            ? `${networks.length} network objects exist but ${unknownCount.length} did not expose scanner_count, so scanner assignment cannot be confirmed for them.`
            : `All ${networks.length} network objects have at least one assigned scanner.${partialNote(data.networks)}`,
      {
        network_count: networks.length,
        pagination_total: data.networks.total ?? null,
        networks: networks.map((network) => ({ name: asString(network.name), scanner_count: asNumber(network.scanner_count) ?? null, assets_ttl_days: asNumber(network.assets_ttl_days) ?? null, is_default: asBoolean(network.is_default) ?? null })).slice(0, 50),
      },
    ));
  }

  findings.push(assessSecurityCenterScanners(data.scScanners, data.scFeed, now, pluginStaleHours));

  const errors = [
    ...datasetErrors("server_properties", data.serverProperties),
    ...datasetErrors("scanners", data.scanners),
    ...datasetErrors("agents", data.agents),
    ...datasetErrors("agent_groups", data.agentGroups),
    ...datasetErrors("networks", data.networks),
    ...datasetErrors("tag_categories", data.tagCategories),
    ...datasetErrors("tag_values", data.tagValues),
    ...datasetErrors("asset_export", data.assetExport),
    ...datasetErrors("users", data.users),
    ...datasetErrors("sc_scanners", data.scScanners),
    ...datasetErrors("sc_feed", data.scFeed),
  ];

  return {
    title: "Tenable sensor and asset coverage",
    category: "sensor_coverage",
    summary: {
      exported_assets: data.assetExport.status === "ok" ? assets.length : null,
      agent_count: countOrNull(data.agents),
      scanner_entries: countOrNull(data.scanners),
      linked_scanners: data.scanners.status === "ok" ? linkedScanners.length : null,
      network_count: countOrNull(data.networks),
      tag_categories: countOrNull(data.tagCategories),
      caller_is_administrator: callerIsAdministrator ?? null,
      ...statusCounts(findings),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterScanners(scanners: TenableDataset<JsonRecord[]>, feed: TenableDataset<JsonRecord>, now: number, pluginStaleHours: number): TenableFinding {
  if (scanners.status !== "ok") {
    return unreadableFinding(7, "high", scanners, "GET /rest/scanner", "the Security Center scanner list with status, version, plugin set, and last check-in", "-SC");
  }
  const enabled = scanners.data.filter((scanner) => asBoolean(scanner.enabled) !== false);
  const unhealthy = enabled.filter((scanner) => asString(scanner.status) !== "1");
  const staleCheckin = enabled.filter((scanner) => {
    const stamp = parseTimestampMs(scanner.lastCheckinTime);
    return stamp !== undefined && daysBetween(now, stamp) > 1;
  });
  const undated = enabled.filter((scanner) => parseTimestampMs(scanner.lastCheckinTime) === undefined);
  const stalePlugins = enabled.filter((scanner) => {
    const stamp = parsePluginSetMs(scanner.loadedPluginSet) ?? parsePluginSetMs(scanner.pluginSet);
    return stamp !== undefined && now - stamp > pluginStaleHours * 3_600_000;
  });
  const feedActive = asObject(feed.data.active);
  const feedStale = feed.status === "ok" ? asBoolean(feedActive?.stale) : undefined;
  let status: TenableFindingStatus;
  let summary: string;
  if (scanners.data.length === 0) {
    status = "manual";
    summary = "Security Center returned zero scanners for this API key (organization users only see agent-capable scanners); collect the scanner list as an administrator.";
  } else if (unhealthy.length > 0 || staleCheckin.length > 0 || stalePlugins.length > 0 || feedStale === true) {
    status = "fail";
    summary = `${unhealthy.length} of ${enabled.length} enabled Security Center scanners report a non-working status, ${staleCheckin.length} have not checked in for 24 hours, ${stalePlugins.length} load a plugin set older than ${pluginStaleHours} hours${feedStale === true ? ", and the active plugin feed is marked stale" : ""}.`;
  } else if (undated.length > 0 || feed.status !== "ok") {
    status = "warn";
    summary = `${enabled.length} enabled Security Center scanners report a working status; ${undated.length} expose no lastCheckinTime${feed.status !== "ok" ? ` and GET /rest/feed could not be read (${feed.error ?? "unknown"})` : ""}.`;
  } else {
    status = "pass";
    summary = `All ${enabled.length} enabled Security Center scanners report status 1, checked in within 24 hours, load a plugin set newer than ${pluginStaleHours} hours, and the active plugin feed is not stale.`;
  }
  return finding(7, status, "high", summary, {
    sc_scanner_count: scanners.data.length,
    sc_enabled_scanners: enabled.length,
    sc_unhealthy: unhealthy.map((scanner) => `${asString(scanner.name)} (status ${asString(scanner.status)})`).slice(0, 50),
    sc_stale_checkin: staleCheckin.map((scanner) => asString(scanner.name)).slice(0, 50),
    sc_undated: undated.map((scanner) => asString(scanner.name)).slice(0, 50),
    sc_stale_plugins: stalePlugins.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loadedPluginSet) ?? asString(scanner.pluginSet)})`).slice(0, 50),
    sc_feed_active_stale: feedStale ?? null,
    sc_feed_active_update_time: asString(feedActive?.updateTime) ?? null,
  }, "-SC");
}

export interface TenableAccessControlData {
  users: TenableDataset<JsonRecord[]>;
  groups: TenableDataset<JsonRecord[]>;
  roles: TenableDataset<JsonRecord[]>;
  permissions: TenableDataset<JsonRecord[]>;
  accessGroups: TenableDataset<JsonRecord[]>;
  credentials: TenableDataset<JsonRecord[]>;
  auditLog: TenableDataset<JsonRecord[]>;
  scUsers: TenableDataset<JsonRecord[]>;
}

export async function collectTenableAccessControlData(clients: TenableClients, options: TenableAssessmentOptions = {}): Promise<TenableAccessControlData> {
  const now = options.now ?? Date.now();
  const lookbackDays = clampInteger(options.auditLookbackDays, DEFAULT_AUDIT_LOOKBACK_DAYS, 1, 365);
  const sinceIso = new Date(now - lookbackDays * DAY_MS).toISOString();
  const [users, groups, roles, permissions, accessGroups, credentials, auditLog, scUsers] = await Promise.all([
    vmList(clients, (client) => client.listUsers()),
    vmList(clients, (client) => client.listGroups()),
    vmList(clients, (client) => client.listRoles()),
    vmList(clients, (client) => client.listPermissions()),
    vmPaginated(clients, (client) => client.listAccessGroups()),
    vmPaginated(clients, (client) => client.listCredentials()),
    vmPaginated(clients, (client) => client.listAuditLogEvents(sinceIso)),
    scDataset(clients, (client) => client.listUsers()),
  ]);
  return { users, groups, roles, permissions, accessGroups, credentials, auditLog, scUsers };
}

const ALL_USERS_GROUP_UUID = "00000000-0000-0000-0000-000000000000";

function exportJobMatchesOwnShape(job: JsonRecord, kind: "assets" | "vulns"): boolean {
  const filters = asObject(job.filters) ?? {};
  const perChunk = asNumber(job.num_assets_per_chunk);
  switch (kind) {
    case "vulns": {
      const states = asArray(filters.state).map((state) => asString(state)?.toLowerCase() ?? "").sort();
      return perChunk === OWN_VULN_EXPORT_NUM_ASSETS && states.join(",") === [...OWN_VULN_EXPORT_STATES].sort().join(",");
    }
    case "assets":
      return perChunk === OWN_ASSET_EXPORT_CHUNK_SIZE && Object.keys(filters).length === 0;
    default: {
      const exhaustive: never = kind;
      throw new Error(`Unhandled export kind: ${String(exhaustive)}`);
    }
  }
}

function subjectIsAllUsers(subject: JsonRecord): boolean {
  const type = asString(subject.type);
  if (type === "AllUsers") return true;
  return type === "UserGroup" && (asString(subject.uuid) === ALL_USERS_GROUP_UUID || asString(subject.name) === "All Users");
}

function userHasStrongAuth(user: JsonRecord): boolean {
  return asBoolean(user.ui_saml_only) === true || asNumber(asObject(user.two_factor)?.sms_enabled) === 1;
}

export function assessTenableAccessControl(data: TenableAccessControlData, options: TenableAssessmentOptions = {}): TenableAssessmentResult {
  const now = options.now ?? Date.now();
  const inactiveDays = clampInteger(options.inactiveUserDays, DEFAULT_INACTIVE_USER_DAYS, 1, 3650);
  const maxAdmins = clampInteger(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10000);
  const lookbackDays = clampInteger(options.auditLookbackDays, DEFAULT_AUDIT_LOOKBACK_DAYS, 1, 365);
  const callerIsAdministrator = detectAdministrator(data.users);
  const findings: TenableFinding[] = [];

  if (data.users.status !== "ok") {
    findings.push(unreadableFinding(10, "high", data.users, "GET /users", "the user list with roles, last login, MFA, and enabled state from Settings > Access Control > Users"));
  } else if (data.users.data.length === 0) {
    findings.push(finding(10, "manual", "high", "GET /users returned zero users, which cannot be a complete view because the calling user must exist; collect the user list from Settings > Access Control > Users.", { user_count: 0 }));
  } else if (callerIsAdministrator !== true) {
    findings.push(finding(10, "manual", "high", `Partial view: GET /users returned ${data.users.data.length} users but only uuid, id, username, and email are exposed because the API key does not hold the Administrator [64] role. Role, last login, MFA, and enabled attributes require an Administrator key.`, {
      user_count: data.users.data.length,
      caller_is_administrator: false,
    }));
  } else {
    const users = data.users.data;
    const enabledUsers = users.filter((user) => asBoolean(user.enabled) === true);
    const admins = enabledUsers.filter((user) => asNumber(user.permissions) === ADMINISTRATOR_PERMISSION);
    const inactive = enabledUsers.filter((user) => {
      const lastLogin = parseTimestampMs(user.lastlogin);
      return lastLogin !== undefined && daysBetween(now, lastLogin) > inactiveDays;
    });
    const neverLoggedIn = enabledUsers.filter((user) => parseTimestampMs(user.lastlogin) === undefined);
    const adminsWithoutStrongAuth = admins.filter((user) => asBoolean(user.ui_permitted) !== false && !userHasStrongAuth(user));
    const lockedOut = enabledUsers.filter((user) => asNumber(user.lockout) === 1);
    const repeatedFailures = enabledUsers.filter((user) => (asNumber(user.login_fail_count) ?? 0) >= 5);
    const staleApiKeys = enabledUsers.filter((user) => {
      const lastAccess = parseTimestampMs(user.last_apikey_access);
      return lastAccess !== undefined && daysBetween(now, lastAccess) > inactiveDays;
    });
    const missingEnabledFlag = users.filter((user) => asBoolean(user.enabled) === undefined);
    let status: TenableFindingStatus;
    let summary: string;
    if (adminsWithoutStrongAuth.length > 0 || inactive.length > 0 || admins.length > maxAdmins) {
      status = "fail";
      summary = `${admins.length} enabled Administrator accounts (threshold ${maxAdmins}); ${adminsWithoutStrongAuth.length} UI-permitted administrators lack SAML-only or two-factor enforcement; ${inactive.length} enabled users have not logged in for ${inactiveDays} days.`;
    } else if (enabledUsers.length === 0) {
      status = "manual";
      summary = `GET /users returned ${users.length} users but none has enabled=true (${missingEnabledFlag.length} expose no enabled flag), so no enabled population exists to verify and the calling user itself is unaccounted for; collect the user list with enabled state, role, and MFA from Settings > Access Control > Users.`;
    } else if (neverLoggedIn.length > 0 || staleApiKeys.length > 0 || lockedOut.length > 0 || repeatedFailures.length > 0 || missingEnabledFlag.length > 0) {
      status = "warn";
      summary = `${admins.length} administrators all enforce SAML or two-factor and no enabled user is inactive past ${inactiveDays} days, but ${neverLoggedIn.length} enabled users have never logged in (not counted as active), ${staleApiKeys.length} have API keys unused for ${inactiveDays} days, ${lockedOut.length} are locked out, ${repeatedFailures.length} show 5 or more failed logins, and ${missingEnabledFlag.length} expose no enabled flag (not counted as enabled).`;
    } else {
      status = capForUnreadable("pass", data.roles);
      summary = `${enabledUsers.length} enabled users, ${admins.length} administrators (threshold ${maxAdmins}) all enforcing SAML-only or two-factor authentication, none inactive past ${inactiveDays} days.${unreadableNote([["GET /access-control/v1/roles", data.roles]])}`;
    }
    findings.push(finding(10, status, "high", summary, {
      user_count: users.length,
      enabled_users: enabledUsers.length,
      users_without_enabled_flag: missingEnabledFlag.length,
      administrators: admins.map((user) => asString(user.username) ?? asString(user.email)).slice(0, 50),
      administrators_without_strong_auth: adminsWithoutStrongAuth.map((user) => asString(user.username)).slice(0, 50),
      inactive_users: inactive.map((user) => asString(user.username)).slice(0, 50),
      never_logged_in_users: neverLoggedIn.map((user) => asString(user.username)).slice(0, 50),
      stale_api_key_users: staleApiKeys.map((user) => asString(user.username)).slice(0, 50),
      locked_out_users: lockedOut.length,
      repeated_login_failures: repeatedFailures.length,
      role_distribution: Object.fromEntries(users.reduce((map, user) => {
        const key = String(asNumber(user.permissions) ?? "unknown");
        map.set(key, (map.get(key) ?? 0) + 1);
        return map;
      }, new Map<string, number>())),
      custom_roles: data.roles.status === "ok" ? data.roles.data.filter((role) => asString(role.type) === "CUSTOM").map((role) => asString(role.name)).slice(0, 50) : null,
      roles_status: data.roles.status,
      max_admins: maxAdmins,
    }));
  }

  if (data.permissions.status !== "ok") {
    findings.push(unreadableFinding(11, "high", data.permissions, "GET /api/v3/access-control/permissions", "the access control permission list (Settings > Access Control > Permissions) and any legacy access groups"));
  } else if (data.permissions.data.length === 0) {
    findings.push(finding(11, "manual", "high", "GET /api/v3/access-control/permissions returned zero permissions, but Tenable always generates administrator permissions, so the view is incomplete; collect the permission list from Settings > Access Control > Permissions.", { permission_count: 0 }));
  } else {
    const permissions = data.permissions.data;
    const broad = permissions.filter((permission) => {
      const subjects = asRecords(permission.subjects);
      const objects = asRecords(permission.objects);
      const actions = asArray(permission.actions).map((action) => asString(action) ?? "");
      const allUsers = subjects.some(subjectIsAllUsers);
      const allObjects = objects.some((object) => ["AllAssets", "AllObjects", "AllTags"].includes(asString(object.type) ?? ""));
      const writeActions = actions.some((action) => /CanEdit|CanScan|CanUse/i.test(action));
      return allUsers && allObjects && writeActions;
    });
    const legacyAccessGroups = data.accessGroups.status === "ok" ? data.accessGroups.data.filter((group) => asBoolean(group.all_assets) !== true) : [];
    findings.push(finding(
      11,
      broad.length > 0 ? "fail" : legacyAccessGroups.length > 0 || data.accessGroups.status !== "ok" ? "warn" : capForNonAdmin(capForUnreadable(capForPartial("pass", data.accessGroups), data.groups), callerIsAdministrator),
      "high",
      broad.length > 0
        ? `${broad.length} of ${permissions.length} permissions grant every user (AllUsers or the tenant-wide All Users group ${ALL_USERS_GROUP_UUID}) write-style actions (CanEdit, CanScan, or CanUse) on all assets, objects, or tags: ${broad.map((permission) => asString(permission.name)).slice(0, 10).join(", ")}. Narrow these to specific groups and tags.`
        : legacyAccessGroups.length > 0
          ? `${permissions.length} permissions follow least privilege for AllUsers, but ${legacyAccessGroups.length} deprecated access groups still exist and should be migrated to permissions.`
          : data.accessGroups.status !== "ok"
            ? `${permissions.length} permissions follow least privilege for AllUsers, but GET /v2/access-groups could not be read (${data.accessGroups.error ?? "unreadable"}), so legacy access groups are unverified and the verdict is capped at warn.`
            : `${permissions.length} permissions are defined and none grants AllUsers write-style actions on all assets; no legacy access groups remain.${partialNote(data.accessGroups)}${unreadableNote([["GET /groups", data.groups]])}${nonAdminNote(callerIsAdministrator)}`,
      {
        permission_count: permissions.length,
        broad_permissions: broad.map((permission) => asString(permission.name)).slice(0, 50),
        legacy_access_groups: data.accessGroups.status === "ok" ? legacyAccessGroups.map((group) => asString(group.name)).slice(0, 50) : null,
        access_groups_status: data.accessGroups.status,
        user_groups: countOrNull(data.groups),
      },
    ));
  }

  if (data.credentials.status !== "ok") {
    findings.push(unreadableFinding(12, "medium", data.credentials, "GET /credentials", "the managed credential inventory with types, owners, and last use from Settings > Credentials"));
  } else if (data.credentials.data.length === 0) {
    findings.push(finding(12, "manual", "medium", "GET /credentials returned zero managed credentials (pagination.total 0). Scan-embedded credentials are not listed by the API, so a human must confirm how scan credentials are managed and rotated.", { credential_count: 0 }));
  } else {
    const credentials = data.credentials.data;
    const unused = credentials.filter((credential) => asNumber(asObject(credential.last_used_by)?.id) === undefined);
    const old = credentials.filter((credential) => {
      const created = parseTimestampMs(credential.created_date);
      return created !== undefined && daysBetween(now, created) > 365;
    });
    const undated = credentials.filter((credential) => parseTimestampMs(credential.created_date) === undefined);
    const types = new Map<string, number>();
    for (const credential of credentials) {
      const type = asString(asObject(credential.type)?.name) ?? asString(asObject(credential.type)?.id) ?? "unknown";
      types.set(type, (types.get(type) ?? 0) + 1);
    }
    findings.push(finding(
      12,
      unused.length > 0 || old.length > 0 ? "warn" : undated.length > 0 ? "warn" : capForPartial("pass", data.credentials),
      "medium",
      unused.length > 0 || old.length > 0
        ? `${credentials.length} managed credentials: ${unused.length} have never been used in a scan, ${old.length} were created over a year ago (the API exposes created_date but no rotation date, so confirm rotation manually).`
        : undated.length > 0
          ? `${credentials.length} managed credentials are all in use, but ${undated.length} expose no created_date.`
          : `All ${credentials.length} managed credentials are in use and were created within the last year across ${types.size} credential types.${partialNote(data.credentials)}`,
      {
        credential_count: credentials.length,
        pagination_total: data.credentials.total ?? null,
        types: Object.fromEntries(types),
        unused_credentials: unused.map((credential) => asString(credential.name)).slice(0, 50),
        older_than_one_year: old.map((credential) => asString(credential.name)).slice(0, 50),
        undated_credentials: undated.length,
      },
    ));
  }

  if (data.auditLog.status !== "ok") {
    findings.push(unreadableFinding(18, "medium", data.auditLog, "GET /audit-log/v1/events", `the activity log for the last ${lookbackDays} days from Settings > Activity Logs (Administrator role required)`));
  } else {
    const events = data.auditLog.data;
    const deletes = events.filter((event) => asString(event.crud) === "d");
    const privilege = events.filter((event) => /user|role|permission|apikey|api_key|key/i.test(asString(event.action) ?? "") && asString(event.crud) !== "r");
    const exclusionOrPolicy = events.filter((event) => /exclusion|policy|template/i.test(asString(event.action) ?? "") && asString(event.crud) !== "r");
    const failures = events.filter((event) => asBoolean(event.is_failure) === true);
    const sensitive = new Set([...deletes, ...privilege, ...exclusionOrPolicy].map((event) => asString(event.id) ?? JSON.stringify(event)));
    let status: TenableFindingStatus;
    let summary: string;
    if (events.length === 0) {
      status = "warn";
      summary = `The activity log returned zero events for the last ${lookbackDays} days (pagination.total ${data.auditLog.total ?? 0}); an active tenant should record logins and API calls, so confirm logging and the date filter.`;
    } else if (data.auditLog.truncated) {
      status = "warn";
      summary = `Only ${events.length} of ${data.auditLog.total ?? "unknown"} activity log events were retrieved for the last ${lookbackDays} days, so the review is partial; ${sensitive.size} sensitive events were seen.`;
    } else if (sensitive.size > 0) {
      status = "warn";
      summary = `${events.length} activity log events were retrieved for the last ${lookbackDays} days; ${sensitive.size} sensitive events (${deletes.length} deletions, ${privilege.length} user or permission changes, ${exclusionOrPolicy.length} exclusion or template changes) need reviewer sign-off.`;
    } else {
      status = "pass";
      summary = `${events.length} activity log events were retrieved completely for the last ${lookbackDays} days with no deletions, privilege changes, or exclusion changes; ${failures.length} failed actions recorded.`;
    }
    findings.push(finding(18, status, "medium", summary, {
      event_count: events.length,
      pagination_total: data.auditLog.total ?? null,
      lookback_days: lookbackDays,
      deletions: deletes.length,
      privilege_changes: privilege.length,
      exclusion_or_template_changes: exclusionOrPolicy.length,
      failed_actions: failures.length,
      sensitive_samples: [...deletes, ...privilege, ...exclusionOrPolicy].slice(0, 25).map((event) => ({
        received: asString(event.received),
        action: asString(event.action),
        actor: asString(asObject(event.actor)?.name),
        target: asString(asObject(event.target)?.name),
      })),
    }));
  }

  findings.push(assessSecurityCenterUsers(data.scUsers, now, inactiveDays));

  const errors = [
    ...datasetErrors("users", data.users),
    ...datasetErrors("groups", data.groups),
    ...datasetErrors("roles", data.roles),
    ...datasetErrors("permissions", data.permissions),
    ...datasetErrors("access_groups", data.accessGroups),
    ...datasetErrors("credentials", data.credentials),
    ...datasetErrors("audit_log", data.auditLog),
    ...datasetErrors("sc_users", data.scUsers),
  ];

  return {
    title: "Tenable access control",
    category: "access_control",
    summary: {
      user_count: countOrNull(data.users),
      permission_count: countOrNull(data.permissions),
      credential_count: countOrNull(data.credentials),
      audit_events: countOrNull(data.auditLog),
      caller_is_administrator: callerIsAdministrator ?? null,
      ...statusCounts(findings),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterUsers(users: TenableDataset<JsonRecord[]>, now: number, inactiveDays: number): TenableFinding {
  if (users.status !== "ok") {
    return unreadableFinding(10, "high", users, "GET /rest/user", "the Security Center user list with roles, last login, and lock state", "-SC");
  }
  const active = users.data.filter((user) => asString(user.status) === "0");
  const admins = active.filter((user) => asString(asObject(user.role)?.id) === "1" || /administrator/i.test(asString(asObject(user.role)?.name) ?? ""));
  const inactive = active.filter((user) => {
    const lastLogin = parseTimestampMs(user.lastLogin);
    return lastLogin !== undefined && daysBetween(now, lastLogin) > inactiveDays;
  });
  const neverLoggedIn = active.filter((user) => parseTimestampMs(user.lastLogin) === undefined);
  const locked = active.filter((user) => asBoolean(user.locked) === true);
  let status: TenableFindingStatus;
  let summary: string;
  if (users.data.length === 0) {
    status = "manual";
    summary = "Security Center returned zero users for this API key, which cannot be complete because the calling user exists; collect the user list as an administrator.";
  } else if (inactive.length > 0) {
    status = "fail";
    summary = `${inactive.length} of ${active.length} active Security Center users have not logged in for ${inactiveDays} days; ${admins.length} hold the Administrator role.`;
  } else if (neverLoggedIn.length > 0 || locked.length > 0) {
    status = "warn";
    summary = `${active.length} active Security Center users; ${neverLoggedIn.length} have never logged in (not counted as active) and ${locked.length} are locked; ${admins.length} hold the Administrator role.`;
  } else {
    status = "pass";
    summary = `All ${active.length} active Security Center users logged in within ${inactiveDays} days; ${admins.length} hold the Administrator role.`;
  }
  return finding(10, status, "high", summary, {
    sc_user_count: users.data.length,
    sc_active_users: active.length,
    sc_administrators: admins.map((user) => asString(user.username)).slice(0, 50),
    sc_inactive_users: inactive.map((user) => asString(user.username)).slice(0, 50),
    sc_never_logged_in: neverLoggedIn.map((user) => asString(user.username)).slice(0, 50),
    sc_locked_users: locked.length,
  }, "-SC");
}

export interface TenableVulnerabilityData {
  vulnExport: TenableDataset<TenableExportResult>;
  assetExport: TenableDataset<TenableExportResult>;
  vulnExportJobs: TenableDataset<JsonRecord[]>;
  assetExportJobs: TenableDataset<JsonRecord[]>;
  users: TenableDataset<JsonRecord[]>;
}

export async function collectTenableVulnerabilityData(clients: TenableClients, options: TenableAssessmentOptions = {}): Promise<TenableVulnerabilityData> {
  const now = options.now ?? Date.now();
  const lookbackDays = clampInteger(options.vulnLookbackDays, DEFAULT_VULN_LOOKBACK_DAYS, 1, 730);
  const maxChunks = clampInteger(options.maxChunks, DEFAULT_MAX_CHUNKS, 1, 1000);
  const [vulnExportJobs, assetExportJobs, users] = await Promise.all([
    vmList(clients, (client) => client.listVulnExportJobs()),
    vmList(clients, (client) => client.listAssetExportJobs()),
    vmList(clients, (client) => client.listUsers()),
  ]);
  const [vulnExport, assetExport] = await Promise.all([
    vmExport(clients, (client) => client.exportVulnerabilities(Math.floor((now - lookbackDays * DAY_MS) / 1000), maxChunks)),
    vmExport(clients, (client) => client.exportAssets(maxChunks)),
  ]);
  return { vulnExport, assetExport, vulnExportJobs, assetExportJobs, users };
}

export function assessTenableVulnerabilityManagement(data: TenableVulnerabilityData, options: TenableAssessmentOptions = {}): TenableAssessmentResult {
  const now = options.now ?? Date.now();
  const sla = {
    critical: clampInteger(options.slaCriticalDays, DEFAULT_SLA_DAYS.critical, 1, 3650),
    high: clampInteger(options.slaHighDays, DEFAULT_SLA_DAYS.high, 1, 3650),
    medium: clampInteger(options.slaMediumDays, DEFAULT_SLA_DAYS.medium, 1, 3650),
    low: clampInteger(options.slaLowDays, DEFAULT_SLA_DAYS.low, 1, 3650),
  };
  const lookbackDays = clampInteger(options.vulnLookbackDays, DEFAULT_VULN_LOOKBACK_DAYS, 1, 730);
  const findings: TenableFinding[] = [];
  const callerIsAdministrator = detectAdministrator(data.users);
  const assetCount = data.assetExport.status === "ok" ? data.assetExport.data.records.length : undefined;
  const capPopulation = (status: TenableFindingStatus): TenableFindingStatus => capForNonAdmin(capForPartial(status, data.assetExport), callerIsAdministrator);
  const populationNote = `${partialNote(data.assetExport)}${nonAdminNote(callerIsAdministrator)}`;

  if (data.vulnExport.status !== "ok") {
    findings.push(unreadableFinding(14, "high", data.vulnExport, "POST /vulns/export", "the VPR distribution of open findings from Findings > Vulnerabilities"));
    findings.push(unreadableFinding(15, "high", data.vulnExport, "POST /vulns/export", "the open finding age by severity and remediation times from Findings > Vulnerabilities"));
  } else {
    const records = data.vulnExport.data.records;
    const open = records.filter((record) => ["OPEN", "REOPENED"].includes(asString(record.state)?.toUpperCase() ?? ""));
    const fixed = records.filter((record) => asString(record.state)?.toUpperCase() === "FIXED");
    const scored = open.filter((record) => asNumber(asObject(asObject(record.plugin)?.vpr)?.score) !== undefined);
    const vprCritical = scored.filter((record) => (asNumber(asObject(asObject(record.plugin)?.vpr)?.score) ?? 0) >= 9);
    const vprHigh = scored.filter((record) => {
      const score = asNumber(asObject(asObject(record.plugin)?.vpr)?.score) ?? 0;
      return score >= 7 && score < 9;
    });
    const rated = open.filter((record) => ["low", "medium", "high", "critical"].includes(asString(record.severity)?.toLowerCase() ?? ""));
    const vprCoverage = ratio(scored.length, rated.length);
    let vprStatus: TenableFindingStatus;
    let vprSummary: string;
    if (assetCount === undefined) {
      vprStatus = "manual";
      vprSummary = `The vulnerability export finished with ${open.length} open findings but the asset export failed (${data.assetExport.error ?? "unknown"}), so the population cannot be validated.`;
    } else if (assetCount === 0) {
      vprStatus = "manual";
      vprSummary = "The asset export returned zero assets, so an empty vulnerability set does not demonstrate VPR-based prioritization.";
    } else if (open.length === 0) {
      vprStatus = "manual";
      vprSummary = `No open findings were exported for the last ${lookbackDays} days across ${assetCount} assets, so VPR usage cannot be evaluated; confirm scans are producing findings.`;
    } else if (data.vulnExport.truncated) {
      vprStatus = "warn";
      vprSummary = `Partial export: ${data.vulnExport.data.fetchedChunks} of ${data.vulnExport.data.totalChunks} chunks were downloaded, covering ${open.length} open findings; ${percent(vprCoverage)} of rated findings carry a VPR score.`;
    } else if (vprCoverage < 0.5) {
      vprStatus = "warn";
      vprSummary = `Only ${percent(vprCoverage)} of ${rated.length} rated open findings carry a VPR score, so VPR-based prioritization has limited coverage.`;
    } else {
      vprStatus = capPopulation("pass");
      vprSummary = `${percent(vprCoverage)} of ${rated.length} rated open findings carry a VPR score across ${assetCount} assets; ${vprCritical.length} findings have VPR 9 or higher and ${vprHigh.length} are VPR 7 to 8.9. Confirm remediation workflows sort by VPR.${populationNote}`;
    }
    findings.push(finding(14, vprStatus, "high", vprSummary, {
      exported_records: records.length,
      open_findings: open.length,
      fixed_findings_in_window: fixed.length,
      vpr_scored_open_findings: scored.length,
      vpr_coverage: vprCoverage,
      vpr_critical_open: vprCritical.length,
      vpr_high_open: vprHigh.length,
      asset_count: assetCount ?? null,
      export_status: data.vulnExport.data.status,
      chunks: `${data.vulnExport.data.fetchedChunks}/${data.vulnExport.data.totalChunks}`,
    }));

    const overdue: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const openBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let undated = 0;
    for (const record of open) {
      const severity = asString(record.severity)?.toLowerCase() ?? "info";
      openBySeverity[severity] = (openBySeverity[severity] ?? 0) + 1;
      const firstFound = parseTimestampMs(record.first_found);
      if (firstFound === undefined) {
        undated += 1;
        continue;
      }
      const limit = sla[severity as keyof typeof sla];
      if (limit !== undefined && daysBetween(now, firstFound) > limit) overdue[severity] += 1;
    }
    const fixTimes = fixed.map((record) => asNumber(record.time_taken_to_fix)).filter((value): value is number => value !== undefined);
    const mttrDays = fixTimes.length > 0 ? Number((fixTimes.reduce((sum, value) => sum + value, 0) / fixTimes.length / 86_400).toFixed(1)) : null;
    const overdueTotal = overdue.critical + overdue.high + overdue.medium + overdue.low;
    let slaStatus: TenableFindingStatus;
    let slaSummary: string;
    if (assetCount === undefined || assetCount === 0) {
      slaStatus = "manual";
      slaSummary = assetCount === 0
        ? "The asset export returned zero assets, so zero overdue findings does not demonstrate SLA compliance."
        : `The asset export failed (${data.assetExport.error ?? "unknown"}), so the finding population cannot be validated.`;
    } else if (data.vulnExport.truncated) {
      slaStatus = "warn";
      slaSummary = `Partial export (${data.vulnExport.data.fetchedChunks} of ${data.vulnExport.data.totalChunks} chunks): ${overdueTotal} of ${open.length} retrieved open findings exceed their SLA, but unseen chunks may contain more.`;
    } else if (overdue.critical > 0 || overdue.high > 0) {
      slaStatus = "fail";
      slaSummary = `${overdue.critical} critical findings exceed ${sla.critical} days and ${overdue.high} high findings exceed ${sla.high} days (${overdue.medium} medium and ${overdue.low} low also overdue) out of ${open.length} open findings.`;
    } else if (overdue.medium > 0 || overdue.low > 0 || undated > 0) {
      slaStatus = "warn";
      slaSummary = `No critical or high findings exceed SLA, but ${overdue.medium} medium and ${overdue.low} low findings are overdue and ${undated} open findings have no first_found date (not counted as compliant).`;
    } else if (open.length === 0) {
      slaStatus = capPopulation("pass");
      slaSummary = `Zero open findings were exported for the last ${lookbackDays} days; this passes only because the export FINISHED completely and the asset export returned ${assetCount} assets.${populationNote}`;
    } else {
      slaStatus = capPopulation("pass");
      slaSummary = `All ${open.length} open findings are within SLA (critical ${sla.critical}d, high ${sla.high}d, medium ${sla.medium}d, low ${sla.low}d) across ${assetCount} assets${mttrDays !== null ? `; mean time to remediate over ${fixTimes.length} fixed findings is ${mttrDays} days` : ""}.${populationNote}`;
    }
    findings.push(finding(15, slaStatus, "high", slaSummary, {
      open_by_severity: openBySeverity,
      overdue_by_severity: overdue,
      undated_open_findings: undated,
      sla_days: sla,
      fixed_findings_in_window: fixed.length,
      mttr_days: mttrDays,
      asset_count: assetCount ?? null,
      chunks: `${data.vulnExport.data.fetchedChunks}/${data.vulnExport.data.totalChunks}`,
    }));
  }

  if (data.vulnExportJobs.status !== "ok" && data.assetExportJobs.status !== "ok") {
    findings.push(unreadableFinding(19, "medium", data.vulnExportJobs, "GET /vulns/export/status", "evidence of scheduled exports or report schedules from the Tenable UI (Reports) and integration logs"));
  } else {
    const ownUuids = new Set([data.vulnExport.data.exportUuid, data.assetExport.data.exportUuid].filter(Boolean));
    const inWindow = (job: JsonRecord): boolean => {
      const created = parseTimestampMs(job.created);
      return created !== undefined && daysBetween(now, created) <= EXPORT_JOB_WINDOW_DAYS;
    };
    const ownShaped = [
      ...data.vulnExportJobs.data.filter((job) => !ownUuids.has(asString(job.uuid) ?? "") && exportJobMatchesOwnShape(job, "vulns")),
      ...data.assetExportJobs.data.filter((job) => !ownUuids.has(asString(job.uuid) ?? "") && exportJobMatchesOwnShape(job, "assets")),
    ];
    const externalJobs = [
      ...data.vulnExportJobs.data.filter((job) => !exportJobMatchesOwnShape(job, "vulns")),
      ...data.assetExportJobs.data.filter((job) => !exportJobMatchesOwnShape(job, "assets")),
    ].filter((job) => !ownUuids.has(asString(job.uuid) ?? "") && inWindow(job));
    const externalDays = new Set(externalJobs.map((job) => new Date(parseTimestampMs(job.created) ?? 0).toISOString().slice(0, 10)));
    const limitation = `The export job lists include completed jobs only from the previous ${EXPORT_JOB_WINDOW_DAYS} days, so this is a point-in-time signal of export activity, and report schedules are not exposed by the API, so they need a manual check in Reports.`;
    const unreadJobLists = unreadableNote([["GET /vulns/export/status", data.vulnExportJobs], ["GET /assets/export/status", data.assetExportJobs]]);
    let status: TenableFindingStatus;
    let summary: string;
    if (externalDays.size >= 2) {
      status = capForNonAdmin(capForUnreadable("pass", data.vulnExportJobs, data.assetExportJobs), callerIsAdministrator);
      summary = `${externalJobs.length} export jobs not created by this tool ran on ${externalDays.size} distinct days within the last ${EXPORT_JOB_WINDOW_DAYS} days, indicating recurring automated exports. ${limitation}${unreadJobLists}${nonAdminNote(callerIsAdministrator)}`;
    } else if (externalJobs.length > 0) {
      status = "warn";
      summary = `${externalJobs.length} export jobs not created by this tool ran within the last ${EXPORT_JOB_WINDOW_DAYS} days, all on one day, so recurring automation is not demonstrated. ${limitation}${unreadJobLists}`;
    } else {
      status = "manual";
      summary = `No export jobs other than this tool's own runs (${ownUuids.size} from this assessment and ${ownShaped.length} matching this tool's export shape) appear within the last ${EXPORT_JOB_WINDOW_DAYS} days, so automated exports are not evident in the observable window; a human must collect the integration or report schedule that distributes results. ${limitation}${unreadJobLists}`;
    }
    findings.push(finding(19, status, "medium", summary, {
      external_export_jobs_in_window: externalJobs.length,
      external_export_days: [...externalDays].sort(),
      window_days: EXPORT_JOB_WINDOW_DAYS,
      vuln_export_jobs_listed: countOrNull(data.vulnExportJobs),
      asset_export_jobs_listed: countOrNull(data.assetExportJobs),
      excluded_own_exports: [...ownUuids],
      excluded_own_shaped_jobs: ownShaped.map((job) => asString(job.uuid)).slice(0, 50),
    }));
  }

  const errors = [
    ...datasetErrors("vuln_export", data.vulnExport),
    ...datasetErrors("asset_export", data.assetExport),
    ...datasetErrors("vuln_export_jobs", data.vulnExportJobs),
    ...datasetErrors("asset_export_jobs", data.assetExportJobs),
    ...datasetErrors("users", data.users),
  ];

  return {
    title: "Tenable vulnerability management",
    category: "vulnerability_management",
    summary: {
      exported_findings: data.vulnExport.status === "ok" ? data.vulnExport.data.records.length : null,
      exported_assets: assetCount ?? null,
      vuln_export_status: data.vulnExport.data.status,
      ...statusCounts(findings),
    },
    findings,
    errors,
  };
}

function statusCounts(findings: TenableFinding[]): JsonRecord {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

async function probeSurface(
  name: string,
  endpoint: string,
  requiredRole: string,
  load: (() => Promise<unknown>) | undefined,
  count?: (value: unknown) => number | undefined,
): Promise<TenableAccessSurface> {
  if (!load) return { name, endpoint, requiredRole, status: "not_configured" };
  try {
    const value = await load();
    return { name, endpoint, requiredRole, status: "readable", count: count?.(value) };
  } catch (error) {
    return {
      name,
      endpoint,
      requiredRole,
      status: isForbiddenError(error) ? "forbidden" : "not_readable",
      error: errorMessage(error),
    };
  }
}

const listCount = (value: unknown): number | undefined => (Array.isArray(value) ? value.length : undefined);
const pageCount = (value: unknown): number | undefined => asNumber(asObject(value)?.total) ?? listCount(asObject(value)?.items);

export async function checkTenableAccess(clients: TenableClients): Promise<TenableAccessCheckResult> {
  const vm = clients.vm;
  const sc = clients.securityCenter;
  const usersProbe = await probeSurface("users", "GET /users", "Basic (full attributes need Administrator)", vm ? () => vm.listUsers() : undefined, listCount);
  const users = vm && usersProbe.status === "readable" ? await vm.listUsers().catch(() => []) : [];
  const callerIsAdministrator = users.length > 0 ? users.some((user) => asNumber(user.permissions) !== undefined) : undefined;

  const surfaces: TenableAccessSurface[] = [
    await probeSurface("server_properties", "GET /server/properties", "Basic", vm ? () => vm.getServerProperties() : undefined, () => 1),
    await probeSurface("scans", "GET /scans", "Basic with Can View on scans", vm ? () => vm.listScans() : undefined, listCount),
    await probeSurface("policies", "GET /policies", "Standard", vm ? () => vm.listPolicies() : undefined, listCount),
    await probeSurface("scan_templates", "GET /editor/scan/templates", "Standard", vm ? () => vm.listScanTemplates() : undefined, listCount),
    await probeSurface("asset_export_jobs", "GET /assets/export/status", "Basic with export privilege", vm ? () => vm.listAssetExportJobs() : undefined, listCount),
    await probeSurface("vuln_export_jobs", "GET /vulns/export/status", "Basic with export privilege", vm ? () => vm.listVulnExportJobs() : undefined, listCount),
    await probeSurface("scanners", "GET /scanners", "Scan Manager", vm ? () => vm.listScanners() : undefined, listCount),
    await probeSurface("agents", "GET /scanners/null/agents", "Scan Manager", vm ? () => vm.listAgents() : undefined, pageCount),
    await probeSurface("agent_groups", "GET /scanners/null/agent-groups", "Scan Manager", vm ? () => vm.listAgentGroups() : undefined, listCount),
    await probeSurface("networks", "GET /networks", "Basic", vm ? () => vm.listNetworks() : undefined, pageCount),
    await probeSurface("exclusions", "GET /exclusions", "Scan Manager", vm ? () => vm.listExclusions() : undefined, pageCount),
    await probeSurface("credentials", "GET /credentials", "Basic with Can Use on credentials", vm ? () => vm.listCredentials() : undefined, pageCount),
    usersProbe,
    await probeSurface("groups", "GET /groups", "Basic", vm ? () => vm.listGroups() : undefined, listCount),
    await probeSurface("roles", "GET /access-control/v1/roles", "Administrator", vm ? () => vm.listRoles() : undefined, listCount),
    await probeSurface("permissions", "GET /api/v3/access-control/permissions", "Administrator", vm ? () => vm.listPermissions() : undefined, listCount),
    await probeSurface("audit_log", "GET /audit-log/v1/events", "Administrator", vm ? () => vm.listAuditLogEvents(new Date(Date.now() - DAY_MS).toISOString()) : undefined, pageCount),
    await probeSurface("tag_categories", "GET /tags/categories", "Basic", vm ? () => vm.listTagCategories() : undefined, pageCount),
    await probeSurface("target_groups", "GET /target-groups", "Basic (deprecated feature)", vm ? () => vm.listTargetGroups() : undefined, listCount),
    await probeSurface("sc_current_user", "GET /rest/currentUser", "Security Center user", sc ? () => sc.getCurrentUser() : undefined, () => 1),
    await probeSurface("sc_scans", "GET /rest/scan", "Security Center organization user", sc ? () => sc.listScans() : undefined, listCount),
    await probeSurface("sc_scanners", "GET /rest/scanner", "Security Center administrator for full fields", sc ? () => sc.listScanners() : undefined, listCount),
    await probeSurface("sc_users", "GET /rest/user", "Security Center administrator or security manager", sc ? () => sc.listUsers() : undefined, listCount),
  ];

  const configured = surfaces.filter((surface) => surface.status !== "not_configured");
  const readable = configured.filter((surface) => surface.status === "readable");
  const forbidden = configured.filter((surface) => surface.status === "forbidden");
  const status = configured.length > 0 && readable.length === configured.length && callerIsAdministrator !== false ? "healthy" : "limited";
  const platform = [vm ? `Tenable Vulnerability Management ${vm.getConfig().baseUrl}${vm.getConfig().fedramp ? " (FedRAMP)" : ""}` : undefined, sc ? `Tenable Security Center ${sc.getConfig().baseUrl}` : undefined].filter(Boolean).join(" + ");

  return {
    status,
    platform,
    callerIsAdministrator,
    surfaces,
    notes: [
      `Platform: ${platform}.`,
      `${readable.length}/${configured.length} configured audit surfaces are readable; ${forbidden.length} refused the API key (401/403).`,
      callerIsAdministrator === undefined
        ? "Caller role could not be determined because GET /users was not readable."
        : callerIsAdministrator
          ? "GET /users exposed full user attributes, so the API key holds the Administrator [64] role."
          : "GET /users exposed only uuid, id, username, and email, so the API key is below Administrator; scans, users, permissions, and audit log views will be partial.",
      ...forbidden.map((surface) => `${surface.name} needs the ${surface.requiredRole} role: ${surface.error ?? "forbidden"}`),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run tenable_assess_scan_program, tenable_assess_sensor_coverage, tenable_assess_access_control, tenable_assess_vulnerability_management, or tenable_export_audit_bundle."
      : "Generate API keys for an Administrator [64] user (Settings > My Account > API Keys) so every surface is readable, or accept manual verdicts for refused surfaces.",
  };
}

function formatAccessCheckText(result: TenableAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.requiredRole,
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Tenable access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Required role", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: TenableAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: TenableResolvedConfig, assessments: TenableAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = statusCounts(findings);
  const lines = [
    "# Tenable Audit Executive Summary",
    "",
    `Platform: ${config.vm ? `${config.vm.baseUrl}${config.vm.fedramp ? " (FedRAMP)" : ""}` : "Tenable Vulnerability Management not configured"}${config.securityCenter ? `; Tenable Security Center ${config.securityCenter.baseUrl}` : ""}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Passing: ${counts.pass}`,
    `- Warning: ${counts.warn}`,
    `- Failing: ${counts.fail}`,
    `- Manual (unknown or not applicable): ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  const priority = findings.filter((item) => item.status === "fail" || item.status === "warn");
  if (priority.length === 0) {
    lines.push("- No failing or warning findings were generated.");
  } else {
    for (const item of priority.slice(0, 15)) {
      lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`);
    }
  }
  const manual = findings.filter((item) => item.status === "manual");
  if (manual.length > 0) {
    lines.push("", "## Manual Follow-up", "");
    for (const item of manual) lines.push(`- ${item.id}: ${item.summary}`);
  }
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "");
    for (const error of errors) lines.push(`- ${error}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: TenableFinding[]): string {
  const rows = findings.map((item) => [item.id, item.status.toUpperCase(), item.severity.toUpperCase(), item.title, item.mappings.join(", ")]);
  return `# Tenable Unified Compliance Matrix\n\n${formatTable(["Control", "Status", "Severity", "Title", "Mappings"], rows)}\n`;
}

function buildFrameworkReport(title: string, prefix: string, findings: TenableFinding[]): string {
  const lines = [`# ${title}`, "", `Findings mapped to ${prefix} controls. Manual findings require human evidence before asserting compliance.`, ""];
  for (const item of findings) {
    const mapped = item.mappings.filter((mapping) => mapping.startsWith(prefix));
    if (mapped.length === 0) continue;
    lines.push(`## ${item.id}: ${item.title}`, "", `- ${prefix} controls: ${mapped.map((mapping) => mapping.slice(prefix.length).trim()).join(", ")}`, `- Status: ${item.status.toUpperCase()} (${item.severity})`, `- Summary: ${item.summary}`, "");
  }
  return `${lines.join("\n")}\n`;
}

function buildQuickReference(): string {
  return [
    "# Tenable Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains the Tenable API responses used during this assessment. API keys are never written; policy details are projected to uuid, name, settings, and plugins; scanner linking keys, registration codes, and license blocks are replaced with [REDACTED]; every property whose name denotes a credential is redacted; error strings are scrubbed and non-JSON error bodies are described by status and length only.",
    "- `analysis/` contains normalized findings and per-category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads failed or returned partial data; the affected controls carry manual or warn verdicts.",
    "- Review manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
  ].join("\n");
}

export async function exportTenableAuditBundle(
  clients: TenableClients,
  outputRoot: string,
  options: TenableAssessmentOptions = {},
): Promise<TenableAuditBundleResult> {
  const config = clients.config;
  const access = await checkTenableAccess(clients);
  const scanProgramData = await collectTenableScanProgramData(clients, options);
  const sensorData = await collectTenableSensorCoverageData(clients, options);
  const accessData = await collectTenableAccessControlData(clients, options);
  const vulnData = await collectTenableVulnerabilityData(clients, options);
  const assessments = [
    assessTenableScanProgram(scanProgramData, options),
    assessTenableSensorCoverage(sensorData, options),
    assessTenableAccessControl(accessData, options),
    assessTenableVulnerabilityManagement(vulnData, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors);

  const hostLabel = config.vm ? new URL(config.vm.baseUrl).hostname : new URL(config.securityCenter?.baseUrl ?? DEFAULT_CLOUD_URL).hostname;
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(hostLabel)}-audit-bundle`);

  const coreData: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/scans.json", scanProgramData.scans.data],
    ["core_data/policies.json", scanProgramData.policies.data],
    ["core_data/policy_details.json", scanProgramData.policyDetails.data],
    ["core_data/scan_templates.json", scanProgramData.templates.data],
    ["core_data/exclusions.json", scanProgramData.exclusions.data],
    ["core_data/target_groups.json", scanProgramData.targetGroups.data],
    ["core_data/assets_export.json", sensorData.assetExport.data.records],
    ["core_data/server_properties.json", sensorData.serverProperties.data],
    ["core_data/scanners.json", sensorData.scanners.data],
    ["core_data/agents.json", sensorData.agents.data],
    ["core_data/agent_groups.json", sensorData.agentGroups.data],
    ["core_data/networks.json", sensorData.networks.data],
    ["core_data/tag_categories.json", sensorData.tagCategories.data],
    ["core_data/tag_values.json", sensorData.tagValues.data],
    ["core_data/users.json", accessData.users.data],
    ["core_data/groups.json", accessData.groups.data],
    ["core_data/roles.json", accessData.roles.data],
    ["core_data/permissions.json", accessData.permissions.data],
    ["core_data/access_groups.json", accessData.accessGroups.data],
    ["core_data/credentials.json", accessData.credentials.data],
    ["core_data/audit_log_events.json", accessData.auditLog.data],
    ["core_data/vulns_export.json", vulnData.vulnExport.data.records],
    ["core_data/export_jobs.json", { vulns: vulnData.vulnExportJobs.data, assets: vulnData.assetExportJobs.data }],
    ["core_data/security_center.json", {
      scans: scanProgramData.scScans.data,
      scan_results: scanProgramData.scScanResults.data,
      scanners: sensorData.scScanners.data,
      feed: sensorData.scFeed.data,
      users: accessData.scUsers.data,
    }],
  ];
  for (const [pathname, value] of coreData) {
    await writeSecureTextFile(outputDir, pathname, serializeJson(value));
  }
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    platform: access.platform,
    source_chain: config.sourceChain,
    caller_is_administrator: access.callerIsAdministrator ?? null,
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.slug}/${framework.slug}_compliance_report.md`, buildFrameworkReport(framework.title, framework.prefix, findings));
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

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    access_key: asString(value.access_key),
    secret_key: asString(value.secret_key),
    url: asString(value.url) ?? asString(value.base_url),
    sc_url: asString(value.sc_url),
    sc_access_key: asString(value.sc_access_key),
    sc_secret_key: asString(value.sc_secret_key),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    stale_scan_days: asNumber(value.stale_scan_days),
    stale_asset_days: asNumber(value.stale_asset_days),
    agent_offline_days: asNumber(value.agent_offline_days),
    plugin_stale_hours: asNumber(value.plugin_stale_hours),
    inactive_user_days: asNumber(value.inactive_user_days),
    max_admins: asNumber(value.max_admins),
    credential_threshold: asNumber(value.credential_threshold),
    tagged_threshold: asNumber(value.tagged_threshold),
    audit_lookback_days: asNumber(value.audit_lookback_days),
    vuln_lookback_days: asNumber(value.vuln_lookback_days),
    sla_critical_days: asNumber(value.sla_critical_days),
    sla_high_days: asNumber(value.sla_high_days),
    sla_medium_days: asNumber(value.sla_medium_days),
    sla_low_days: asNumber(value.sla_low_days),
    expected_asset_count: asNumber(value.expected_asset_count),
    max_chunks: asNumber(value.max_chunks),
  };
}

function normalizeExportArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAssessArgs(args), output_dir: asString(value.output_dir) ?? asString(value.output) };
}

function toAssessmentOptions(args: AssessArgs): TenableAssessmentOptions {
  return {
    staleScanDays: args.stale_scan_days,
    staleAssetDays: args.stale_asset_days,
    agentOfflineDays: args.agent_offline_days,
    pluginStaleHours: args.plugin_stale_hours,
    inactiveUserDays: args.inactive_user_days,
    maxAdmins: args.max_admins,
    credentialThreshold: args.credential_threshold,
    taggedThreshold: args.tagged_threshold,
    auditLookbackDays: args.audit_lookback_days,
    vulnLookbackDays: args.vuln_lookback_days,
    slaCriticalDays: args.sla_critical_days,
    slaHighDays: args.sla_high_days,
    slaMediumDays: args.sla_medium_days,
    slaLowDays: args.sla_low_days,
    expectedAssetCount: args.expected_asset_count,
    maxChunks: args.max_chunks,
  };
}

function createClients(args: CheckAccessArgs): TenableClients {
  return createTenableClients(resolveTenableConfiguration(args as JsonRecord));
}

const authParams = {
  access_key: Type.Optional(Type.String({ description: "Tenable Vulnerability Management API access key. Defaults to TENABLE_ACCESS_KEY or the config file." })),
  secret_key: Type.Optional(Type.String({ description: "Tenable Vulnerability Management API secret key. Defaults to TENABLE_SECRET_KEY or the config file." })),
  url: Type.Optional(Type.String({ description: "Platform URL: https://cloud.tenable.com (default), https://fedcloud.tenable.com for FedRAMP, or a Tenable Security Center host. Defaults to TENABLE_URL." })),
  sc_url: Type.Optional(Type.String({ description: "Optional Tenable Security Center URL assessed alongside the cloud tenant. Defaults to TENABLE_SC_URL." })),
  sc_access_key: Type.Optional(Type.String({ description: "Tenable Security Center API access key (x-apikey). Defaults to TENABLE_SC_ACCESS_KEY." })),
  sc_secret_key: Type.Optional(Type.String({ description: "Tenable Security Center API secret key (x-apikey). Defaults to TENABLE_SC_SECRET_KEY." })),
  config_file: Type.Optional(Type.String({ description: "Optional YAML or JSON config file with access_key, secret_key, url, sc_url, sc_access_key, and sc_secret_key. Defaults to TENABLE_CONFIG_FILE or ~/.tenable/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const thresholdParams = {
  stale_scan_days: Type.Optional(Type.Number({ description: "Days since last launch before a recurring scan is stale. Defaults to 30.", default: 30 })),
  stale_asset_days: Type.Optional(Type.Number({ description: "Days since last_seen before an asset is stale. Defaults to 30.", default: 30 })),
  agent_offline_days: Type.Optional(Type.Number({ description: "Days since last_connect before an agent is stale. Defaults to 7.", default: 7 })),
  plugin_stale_hours: Type.Optional(Type.Number({ description: "Hours before a plugin set is stale. Defaults to 24.", default: 24 })),
  inactive_user_days: Type.Optional(Type.Number({ description: "Days without login before a user is inactive. Defaults to 90.", default: 90 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Administrator accounts. Defaults to 5.", default: 5 })),
  credential_threshold: Type.Optional(Type.Number({ description: "Minimum credentialed or agent scan ratio (0 to 1). Defaults to 0.8.", default: 0.8 })),
  tagged_threshold: Type.Optional(Type.Number({ description: "Minimum ratio of tagged assets (0 to 1). Defaults to 0.9.", default: 0.9 })),
  audit_lookback_days: Type.Optional(Type.Number({ description: "Activity log lookback in days. Defaults to 30.", default: 30 })),
  vuln_lookback_days: Type.Optional(Type.Number({ description: "Vulnerability export lookback in days. Defaults to 90.", default: 90 })),
  sla_critical_days: Type.Optional(Type.Number({ description: "Critical finding SLA in days. Defaults to 15.", default: 15 })),
  sla_high_days: Type.Optional(Type.Number({ description: "High finding SLA in days. Defaults to 30.", default: 30 })),
  sla_medium_days: Type.Optional(Type.Number({ description: "Medium finding SLA in days. Defaults to 90.", default: 90 })),
  sla_low_days: Type.Optional(Type.Number({ description: "Low finding SLA in days. Defaults to 180.", default: 180 })),
  expected_asset_count: Type.Optional(Type.Number({ description: "Expected asset population for discovery coverage; without it control 3 stays manual." })),
  max_chunks: Type.Optional(Type.Number({ description: "Maximum export chunks to download per export. Defaults to 50; exceeding it downgrades verdicts to partial.", default: 50 })),
};

type AssessmentKind = "scan_program" | "sensor_coverage" | "access_control" | "vulnerability_management";

async function runAssessment(kind: AssessmentKind, clients: TenableClients, options: TenableAssessmentOptions): Promise<TenableAssessmentResult> {
  switch (kind) {
    case "scan_program":
      return assessTenableScanProgram(await collectTenableScanProgramData(clients, options), options);
    case "sensor_coverage":
      return assessTenableSensorCoverage(await collectTenableSensorCoverageData(clients, options), options);
    case "access_control":
      return assessTenableAccessControl(await collectTenableAccessControlData(clients, options), options);
    case "vulnerability_management":
      return assessTenableVulnerabilityManagement(await collectTenableVulnerabilityData(clients, options), options);
    default: {
      const exhaustive: never = kind;
      throw new Error(`Unhandled assessment kind: ${String(exhaustive)}`);
    }
  }
}

function registerAssessmentTool(pi: any, kind: AssessmentKind, name: string, label: string, description: string): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object({ ...authParams, ...thresholdParams }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await runAssessment(kind, createClients(args), toAssessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(`${label} failed: ${errorMessage(error)}`, { tool: name });
      }
    },
  });
}

export function registerTenableTools(pi: any): void {
  pi.registerTool({
    name: "tenable_check_access",
    label: "Check Tenable audit access",
    description:
      "Validate read-only Tenable Vulnerability Management (cloud or FedRAMP) and optional Tenable Security Center access across scans, templates, exports, sensors, networks, exclusions, credentials, users, permissions, audit log, and tags, reporting the role each refused surface needs.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkTenableAccess(createClients(args));
        return textResult(formatAccessCheckText(result), { tool: "tenable_check_access", ...result });
      } catch (error) {
        return errorResult(`Tenable access check failed: ${errorMessage(error)}`, { tool: "tenable_check_access" });
      }
    },
  });

  registerAssessmentTool(
    pi,
    "scan_program",
    "tenable_assess_scan_program",
    "Assess Tenable scan program",
    "Assess Tenable scan policy configuration, scan schedule discipline, credentialed scan ratio, scan exclusions, compliance audit templates, and legacy target groups (spec controls 1, 2, 4, 13, 17, 20) plus the Security Center schedule equivalent.",
  );
  registerAssessmentTool(
    pi,
    "sensor_coverage",
    "tenable_assess_sensor_coverage",
    "Assess Tenable sensor and asset coverage",
    "Assess Tenable asset discovery coverage, agent deployment and grouping, linked scanner health, plugin currency, network zones, and asset tagging (spec controls 3, 5, 6, 7, 8, 9, 16) plus the Security Center scanner equivalent.",
  );
  registerAssessmentTool(
    pi,
    "access_control",
    "tenable_assess_access_control",
    "Assess Tenable access control",
    "Assess Tenable user roles, MFA and SAML enforcement, API key usage, access control permissions and legacy access groups, managed credential hygiene, and activity log review (spec controls 10, 11, 12, 18) plus the Security Center user equivalent.",
  );
  registerAssessmentTool(
    pi,
    "vulnerability_management",
    "tenable_assess_vulnerability_management",
    "Assess Tenable vulnerability management",
    "Run the documented vulnerability and asset exports to assess VPR prioritization coverage, severity SLA backlog and remediation times, and export automation evidence (spec controls 14, 15, 19).",
  );

  pi.registerTool({
    name: "tenable_export_audit_bundle",
    label: "Export Tenable audit bundle",
    description:
      "Export a Tenable audit package with raw API snapshots (core_data), normalized findings (analysis), executive summary, unified compliance matrix, per-framework reports (compliance), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip archive paired with the output directory.",
    parameters: Type.Object({
      ...authParams,
      ...thresholdParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const clients = createClients(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportTenableAuditBundle(clients, outputRoot, toAssessmentOptions(args));
        return textResult(
          [
            "Tenable audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "tenable_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Tenable audit bundle export failed: ${errorMessage(error)}`, { tool: "tenable_export_audit_bundle" });
      }
    },
  });
}
