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
import { parse as parseYaml, YAMLError } from "yaml";
import { REDACTED_VALUE, scrubSensitiveValues } from "../../flue/redact.js";
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

/**
 * One collected inventory. seen, total, and truncated describe a walk that ran;
 * they are null whenever the read was refused, failed, or never attempted so a
 * consumer cannot mistake "not collected" for "collected zero, complete".
 * endpoint names the request that produced the data or the request that actually
 * failed (which may differ from the nominal one, for example a chunk download
 * inside an export), and is null when no request was made. httpStatus is the
 * observed status of a failed request and null when none was observed.
 */
export interface TenableDataset<T> {
  data: T;
  status: "ok" | "forbidden" | "error" | "not_configured";
  endpoint: string | null;
  error?: string;
  httpStatus: number | null;
  seen: number | null;
  total: number | null;
  truncated: boolean | null;
}

export interface TenableAccessSurface {
  name: string;
  endpoint: string | null;
  requiredRole: string;
  status: "readable" | "forbidden" | "not_readable" | "not_configured";
  count: number | null;
  httpStatus: number | null;
  error?: string;
}

export interface TenableAccessCheckResult {
  status: "healthy" | "limited";
  platform: string;
  callerIsAdministrator: boolean | null;
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

// A configured URL keeps its scheme, host, port, and path prefix for requests; its
// user-and-secret prefix, query, and fragment are dropped here so no request, label,
// or bundle file ever carries them.
function normalizeBaseUrl(rawUrl: string): string {
  const candidate = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(candidate);
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

/** The scheme and host of a configured URL, which is all a platform label or summary line writes. */
function displayOrigin(url: string): string {
  return new URL(url).origin;
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

export const CREDENTIAL_REDACTION_MARKER = "[REDACTED]";
const REDACTED = CREDENTIAL_REDACTION_MARKER;

/**
 * Scrub boundary. A bare value shaped like a name (words joined by hyphens or
 * underscores with at most one digit group per segment: prod-us-east-2026,
 * fw-dc1-01, sess-canary-COOKIE-31415926535897) standing alone in prose is
 * indistinguishable from a resource name and stays, because a summary that names
 * the unread inventory is itself a verdict-safety requirement. Two guards make
 * that safe and both hold by construction:
 *
 * 1. A value inside a carrier is removed whatever its shape: the Authorization and
 *    Proxy-Authorization header lines, keeping the scheme word the credentials follow
 *    (Bearer, Basic, Digest, ...) and removing the one token after it, or the whole
 *    parameter list after a Digest or AWS4-HMAC-SHA256 scheme; the Cookie, Set-Cookie,
 *    X-Cookie, and X-ApiKeys lines to the end of the line; the X-Api-Key,
 *    X-SecurityCenter, X-Auth-Token and similar single-token header lines to the end
 *    of their first token; the userinfo of every embedded URL, bare or with its slashes
 *    escaped by a stringify; credential-named query and fragment pairs of every URL
 *    and bare query string (the ?token= an audit-log field or a webhook target may
 *    carry) and any query value shaped like a token; the schemes Bearer, Basic, Digest,
 *    Token, OAuth, Negotiate, NTLM, SSWS, ApiKey, Splunk, Snowflake, and
 *    AWS4-HMAC-SHA256 in any casing (only a listed prose word after the scheme, "Basic
 *    authentication", or an auth-param name, Bearer realm=, stays; after the nouns
 *    Token, OAuth, Splunk, and Snowflake any short plain lowercase word does);
 *    credential-named key=value pairs (to the next delimiter, wherever the key starts:
 *    after --, -D, or a path slash; the accessKey= and secretKey= halves of an echoed
 *    X-ApiKeys header), key: value pairs (to the end of the line, or one token after a
 *    path slash), --key value flags, "key":"value" pairs, and key="value" XML or HTML
 *    attributes; the path and query of a URL under a webhook or webhook_url key; and
 *    webhook services whose URL path is the secret. Nothing this module renders puts a
 *    credential word in front of a colon or an equals sign, so every fixed text
 *    survives the scrub.
 * 2. A configured secret (the Vulnerability Management access key and secret key,
 *    and the Security Center access key and secret key) is removed whatever its
 *    shape and in every encoded form (JSON-escaped, URL-encoded, form-encoded,
 *    base64, base64url, re-flowed PEM lines), down to MIN_CONFIGURED_SECRET_LENGTH
 *    (cli/flue/redact.ts owns the forms). redactSecrets applies it at every client
 *    throw site; the tool boundary and the bundle writer apply it to the whole
 *    payload and every written file.
 *
 * Real token shapes are still removed bare: PEM blocks, JWTs, LUFRPT-prefixed
 * PAN-OS keys (a proxy page may echo any vendor's key), AWS access key ids, GitHub,
 * Stripe, and Slack prefixed tokens, and (in error text) any run of
 * LONG_TOKEN_MIN_LENGTH or more token characters that carries base64 symbols,
 * digits scattered through its letters (0f9e8d7c6b5a4938), or token casing
 * (Kq7Zx2Vw9Lm4Tp8R). The rule is path-safe: "/", ".", ":", "@", "=", and
 * whitespace end a run, so URL path segments, dotted hostnames, colon-separated
 * ARNs, and the two sides of a key=value pair are judged piece by piece, while
 * "-" and "_" split a run into name segments; uppercase codes (ENOENT, PCI-DSS-4),
 * digit strings, and canonical UUIDs are names outright. Data values and bundle
 * content go through redactCredentialValueText, every carrier rule without the
 * long-token one (an opaque identifier in evidence is not a secret) and with
 * public PEM blocks (certificates, public keys, CSRs) kept as evidence. Every rule
 * is unanchored and idempotent.
 */
export const MIN_CONFIGURED_SECRET_LENGTH = 4;
export const LONG_TOKEN_MIN_LENGTH = 16;

// Which PEM blocks a scrub removes: every block in error text, where a block is never
// evidence; only non-public blocks in data values, where a certificate is.
type PemScope = "all" | "private";

const PEM_BLOCK_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
// A block whose END was cut off (a truncated message) runs to the end of the text.
const PEM_OPEN_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----(?:(?!-----END )[\s\S])*$/;
// Labels of PEM blocks that carry public material only; every other label (PRIVATE KEY,
// ENCRYPTED PRIVATE KEY, RSA/EC/DSA/OPENSSH PRIVATE KEY, PGP PRIVATE KEY BLOCK) is a secret.
const PUBLIC_PEM_LABELS = new Set(["CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CRL", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "PUBLIC KEY", "RSA PUBLIC KEY", "PKCS7", "CMS"]);
// Any scheme-prefixed URL: the userinfo is dropped; its query and fragment pairs are
// judged by the pair rule below, so the scheme, host, path, and ordinary pairs stay. The
// userinfo ends where the authority does, at "/", "?", or "#", so an "@" inside a query or
// fragment (https://h?e=a@x.com&token=..., https://h#f@x.com) is never read as userinfo: the
// host stays "h", and the query is left to the pair rule and the origin reducer instead of
// being carried on as if it were the host.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
const URL_USERINFO_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^\s\/?#@"'<>\\]+@/i;
// A query or fragment pair, in a URL or a bare query string: a credential-named pair or a
// token-shaped value loses the value. A value ends at "&", "#", whitespace, a quote, a
// backslash (no token carries one; the escape after it, \" or \n inside a JSON string, is
// kept so the string still parses and the text after it is still read), or the ";" and ","
// that end a URL inside a sentence. A recognised header line is read before this rule, so a
// cookie pair whose name holds "&" or "#" goes with its cookie.
// A quote with a value character on both sides (O'hunter2) is content of the value.
const QUERY_PAIR_PATTERN = /([?&#])([A-Za-z0-9_.[\]-]+)=((?!\[REDACTED\])[^&#\s"'<>;,\\]+(?:["'](?![:)}\]])[^&#\s"'<>;,\\]+)*)/g;
// A credential-bearing header line: the whole value goes, whatever its shape. The name and
// separator are matched here (the name may be quoted as a JSON member name, with its quotes
// escaped to any depth: "Cookie": ..., \"Cookie\": ..., \\\"Cookie\\\": ...) and the value
// is consumed by headerValueEnd, which carries a quoted value through its closing quote at
// the same depth, so Cookie: sid="value" loses value and quotes together instead of
// stopping at the first quote, and ends an unquoted value before the next header on a
// compound line, so the next header keeps its name. A value that already opens with a
// marker is left alone so the rule is idempotent. The name starts where no word character
// precedes it, or right after a JSON string escape left in place by one stringify (\n, \r,
// \t, \b, \f, \v, \0, \uXXXX, \xHH): "request failed\nX-SecurityCenter: value" is a header
// line inside a JSON string, and the escape letter is not part of the name that follows it.
const HEADER_LINE_PATTERN = /(?:(?<![A-Za-z0-9_])|(?<=\\[nrtbfv0]|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}))(authorization|proxy-authorization|cookie|set-cookie|x-cookie|x-api-key|x-apikeys?|api-key|apikey|x-securitycenter|x-pan-key|x-redlock-auth|x-auth-token|x-access-token|x-amz-security-token|x-vault-token|private-token|x-goog-api-key|x-csrf-token|x-xsrf-token)((?:\\*["'])?\s*:\s*)/gi;
// The escape letters that can sit between a backslash and the key or header name after it.
const ESCAPE_LETTER_PATTERN = /^(?:[nrtbfv0]|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2})/;
// Inside a header value a quote opens a quoted segment only where a value can start: at the
// start of the value or after "=", ":", ",", ";", "(", or whitespace. A quote with a token
// character on both sides (sid=O'hunter2, my'pref=value, my"pref=value) is content of the
// value, since RFC 6265 lets a cookie name or value carry an apostrophe. A quote anywhere
// else, at the end of a token, is the quote that closes the text the header line was quoted
// in.
const HEADER_VALUE_OPENER_PATTERN = /[=:,;(\s]/;
// What follows a quote that opens or closes something: whitespace, a delimiter, a closing
// bracket, a tag, another quote, or an escape. Any other character continues the token.
const QUOTE_BOUNDARY_PATTERN = /[\s,;:)}\]<>"'\\]/;
const HEADER_VALUE_TERMINATOR_PATTERN = /[\r\n<>]/;
// The "Name:" token of the next header after ";" or "," on a compound line (the name may be
// quoted, as in a JSON object, with the quotes escaped to any depth, and may hold dots, as
// X.Api.Key does when a proxy rewrites hyphens); a colon followed by "//" is a URL scheme,
// not a header. The token is looked for within FOLLOWING_HEADER_LOOKAHEAD characters of the
// separator.
const FOLLOWING_HEADER_PATTERN = /^\s*(?:\\*["'])?[A-Za-z][A-Za-z0-9.-]*(?:\\*["'])?\s*:(?!\/\/)/;
const FOLLOWING_HEADER_LOOKAHEAD = 96;
// Header classes. An Authorization or Proxy-Authorization value opens with the scheme word
// its credentials follow (Bearer, Basic, Digest, and the rest of AUTH_SCHEME_WORDS, in any
// casing): the word stays as spelled and the one token (or one quoted string) after it
// goes, so the operator still reads which scheme was replayed and prose after the token
// stays; a parameter list after the scheme (Digest username=..., realm=...) goes whole, as
// does a value that opens with anything else (a scheme word the list does not know, such
// as GenieKey, SharedKey, or Bot, a bare token, a digit), to the end of the line: an
// unknown first word may be a scheme with its credentials after it, so nothing after it
// is trusted. A cookie header, or Tenable's X-ApiKeys (accessKey=...; secretKey=...), is
// a list of pairs and goes whole. Every other header (X-Api-Key, X-Auth-Token,
// X-Vault-Token, ...) carries one token: an unquoted value ends at the first whitespace,
// so a JSON fragment or prose after it on the same line ({"status":"denied"}, "rejected")
// is still read; a value that opens with a listed scheme word (X-Auth-Token: Bearer <v>)
// is the word and the token after it together, and both go under the one marker, as the
// scheme word is part of the value under any key but Authorization; a quoted value ends
// at its closing quote whatever it holds.
const AUTHORIZATION_HEADERS = new Set(["authorization", "proxy-authorization"]);
const LIST_VALUE_HEADERS = new Set(["cookie", "set-cookie", "x-cookie", "x-apikeys", "x-apikey"]);
const AUTH_SCHEME_WORDS = new Set([
  "basic", "bearer", "digest", "hoba", "mutual", "negotiate", "oauth", "scram-sha-1", "scram-sha-256", "vapid", "dpop", "gnap",
  "privatetoken", "concealed", "ntlm", "token", "ssws", "apikey", "api-key", "splunk", "snowflake", "aws4-hmac-sha256",
]);
const AUTH_SCHEME_PATTERN = /^([A-Za-z][A-Za-z0-9-]*)(?:\s+|$)/;
// A header value the header rule already treated, as the pair rules then see it: the scheme
// word and, after whitespace and an optional quote, the marker.
const REDACTED_SCHEME_VALUE_PATTERN = /^([A-Za-z][A-Za-z0-9-]*)\s+((?:\\*["'])?)\[REDACTED\]/;
const AUTH_PARAM_LIST_PATTERN = /^[A-Za-z][A-Za-z0-9_-]*=/;
// A scheme and its credentials: the value is removed whatever its shape, except the
// prose words that follow a scheme name in a sentence ("Basic authentication is
// required", "Bearer token") and a Titlecase word, which makes the scheme name an
// adjective in a title ("Basic Network Scan", "Bearer Token", "Token Hygiene"): a Basic
// credential is base64 and a bearer token or API key carries digits, symbols, or token
// casing, so neither is ever one capitalized word of letters. "Token", "OAuth", "Splunk",
// and "Snowflake" are also nouns of this module's own prose and of product names ("Token
// hygiene", "OAuth clients", "Splunk index", "Snowflake account"), so after them any plain
// lowercase word shorter than LONG_TOKEN_MIN_LENGTH is prose. An auth-param name before
// "=" (Bearer realm="api", Digest qop="auth") is the challenge's grammar, not a credential;
// the quoted value after it is judged by the attribute rule under its own name. OAuth 1.0
// carries its credentials as key="value" attributes, which that rule removes.
const SCHEME_VALUE_PATTERN = /\b(Bearer|Basic|Digest|Token|OAuth|Negotiate|NTLM|SSWS|ApiKey|Api-Key|Splunk|Snowflake|AWS4-HMAC-SHA256)\s+((?!\[REDACTED\])[A-Za-z0-9._~+/=-]{4,})/gi;
const NOUN_SCHEME_WORDS = new Set(["token", "oauth", "splunk", "snowflake"]);
const AUTH_PARAM_PATTERN = /^([A-Za-z][A-Za-z0-9_-]*)=$/;
const AUTH_PARAM_NAMES = new Set([
  "realm", "error", "error_description", "error_uri", "scope", "charset", "nonce", "opaque", "qop", "algorithm", "stale", "domain",
  "uri", "response", "cnonce", "nc", "username", "credential", "signedheaders", "signature", "oauth_consumer_key", "oauth_token",
  "oauth_signature_method", "oauth_signature", "oauth_timestamp", "oauth_nonce", "oauth_version", "oauth_callback", "oauth_verifier",
]);
const PLAIN_WORD_PATTERN = /^[a-z]+$/;
const TITLE_WORD_PATTERN = /^[A-Z][a-z]{1,19}$/;
const SCHEME_PROSE_WORDS = new Set([
  "authentication", "authorization", "auth", "token", "tokens", "credential", "credentials", "scheme", "schemes", "header", "headers",
  "realm", "challenge", "access", "mode", "method", "login", "flow", "grant", "type", "string", "value", "values", "user", "users",
  "account", "client", "clients", "error", "request", "requests", "response", "with", "without", "and", "or", "is", "was", "are",
  "not", "the", "this", "that", "these", "those", "to", "in", "for", "from", "on", "of", "by", "as", "at", "if", "then", "but", "so",
  "than", "when", "where", "over", "via", "per", "only", "still", "also", "use", "used", "using", "required", "requires", "failed",
  "rejected", "expired", "invalid", "missing", "unsupported", "supported", "unauthorized", "forbidden", "denied", "allowed", "enabled",
  "disabled", "preferred", "deprecated", "retired", "retiring", "must", "should", "can", "cannot", "could", "will", "would", "may",
  "has", "have", "does", "did", "do", "be", "been",
]);
// "key":"value" and key="value" carriers keep the whole quoted value together so a
// value with spaces is removed as one; the unquoted pair rule below takes the rest.
// Keys may start with "_" (_upstream_session, _token), so a key begins wherever no key
// character precedes it rather than at a word boundary.
const JSON_QUOTED_PAIR_PATTERN = /"([A-Za-z_][A-Za-z0-9_.-]{0,63})"(\s*:\s*)"((?!\[REDACTED\])[^"\r\n]+)"/g;
// The same pair inside a JSON text that was itself stringified into a string value, so its
// quotes arrive behind a run of backslashes (\" one level down, \\\" two levels down): the
// run is captured and the pair's four quotes must all carry it, so the value ends at the
// quote of its own depth.
const JSON_ESCAPED_PAIR_PATTERN = /(\\+)"([A-Za-z_][A-Za-z0-9_.-]{0,63})\1"(\s*:\s*)\1"((?!\[REDACTED\])(?:(?!\1")[^\r\n])+?)\1"/g;
// A quoted attribute or pair value: the quote may be escaped to any depth, and the value
// ends at the quote of its own depth.
// A quote with a value character on both sides (O'hunter2) is content of the value.
const QUOTED_ATTRIBUTE_PATTERN = /(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]{0,63})\s*=\s*(\\*["'])((?!\[REDACTED\])(?:[^"'\r\n]|["'](?=[^\s"'\r\n<>;,&:)}\]\\]))+)\2/g;
// An unquoted pair: key=value runs to the next delimiter, key: value (a header or
// YAML-style line) to the end of the line, where a brace or bracket ends it so a JSON
// structure after a credential-named key (compact "password":{...}, "auth":null}) is
// never taken for a value. The key and the value may be quoted with the quotes escaped to
// any depth; a value never runs into the escaped quote that closes it. A key starts where
// no word character precedes it: after the "--" of a command-line flag (--password=v), the
// "-D" of a Java system property (-Dpassword=v, where the D is read as part of the key and
// the credential word is still its tail), a "/" path separator, or a "." (the tail of a
// dotted name is scanned only when no key match started earlier on the name); or right
// after a \0 escape, whose digit cannot start a key (the letter escapes, \n and the rest,
// are read as part of the key and removed by keyAfterEscape).
const ASSIGNMENT_KEY_PATTERN = /(?:(?<![A-Za-z0-9_])|(?<=\\0))((?:\\*["'])?)([A-Za-z_][A-Za-z0-9_.-]{0,63})((?:\\*["'])?\s*([:=])\s*(?:\\*["'])?)/g;
// The escape one stringify leaves for a control character: \n, \r, \t, \b, \f, \v, \0, or a
// \uXXXX or \xHH code of a control (U+0000 to U+001F, U+007F, and the line and paragraph
// separators U+2028 and U+2029). An escape of a printable character (\u00e9) is content.
const ESCAPED_CONTROL_SOURCE = String.raw`\\(?:[nrtbfv0]|u(?:00[01][0-9a-fA-F]|007[fF]|202[89])|x(?:[01][0-9a-fA-F]|7[fF]))`;
// A credential name after "--" with its value as the next argument (psql --password value):
// the flag starts where no word character or "-" precedes it (at the start of a quoted
// command line too), its name may open with a letter or an underscore (a cookie name such as
// _zendesk_session is a credential name too), and the value is the one token after it, never
// another flag, ending where an unquoted pair value does.
const FLAG_VALUE_PATTERN = new RegExp(String.raw`(?<![A-Za-z0-9_-])--([A-Za-z_][A-Za-z0-9_.-]{0,63})([ \t]+)((?!\[REDACTED\])(?!-)(?:(?!${ESCAPED_CONTROL_SOURCE})[^\s\x00-\x1f\x7f"'<>;,&])+)`, "g");
// After a credential-named path segment and ":" (kv/password: value) the value is at most
// one token. A singular label (password, token, key) takes that token whatever its shape
// and whatever follows it (/etc/app/password: <value> was rejected); a plural label names a
// collection (/api/v1/api-tokens: request failed with 403), so prose after the token means
// there was no value, while a lone token after a plural label is one.
const PROSE_CONTINUATION_PATTERN = /^[ \t]+[A-Za-z]/;
// A key whose last word is a plural credential word, in the segment split (api-tokens, keys,
// oauth_tokens) or concatenated (apikeys, sshkeys).
const PLURAL_CREDENTIAL_LABEL_PATTERN = /(?:token|secret|key|cookie|password|credential|passphrase|signature|session)s$/;
// The "-D" of a Java system property (java -Dkey=value) is not part of the key.
const JAVA_PROPERTY_PREFIX_PATTERN = /(?:^|\s)-$/;
// A delimited (key=value) value ends at whitespace or a control character, raw or left
// escaped by one stringify (\n, \r, \t, \b, \f, \v, \0, \u0009 and the other \u00XX control
// codes, \x09), as an unquoted header token does, so a pair or header chained after the
// escape (api_key=<v>\tpassword: <v>) is read on its own and loses its own value. A key:
// value line ends at a line break only, raw or escaped (\n, \r, \u000a, \u000d), as the raw
// line does, so the header or pair on the next escaped line is read on its own.
// A quote with a value character on both sides (O'hunter2, my'pref) is content of the value;
// a quote at the end of a token, or an escaped quote, ends it, as does a value's first quote.
const DELIMITED_VALUE_PATTERN = new RegExp(String.raw`(?!\[REDACTED\])(?!["'])(?:(?!\\+["'])(?!${ESCAPED_CONTROL_SOURCE})[^\s\x00-\x1f\x7f"'<>;,&]|["'](?=[^\s"'<>;,&:)}\]\\]))+`, "y");
const LINE_VALUE_PATTERN = /(?!\[REDACTED\])(?!["'])(?:(?!\\+["'])(?!\\(?:[nr]|u000[adAD]|x0[adAD]))[^\r\n<>"',;{}[\]]|["'](?=[^\s\r\n<>"',;{}[\]:)\\]))*(?!\\+["'])(?!\\(?:[nr]|u000[adAD]|x0[adAD]))[^\s\r\n<>"',;{}[\]]/y;
const TOKEN_IN_PATH_WEBHOOK_PATTERN = /(https?:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks|[a-z0-9.-]*webhook\.office\.com\/webhookb2)\/)(?!\[REDACTED\])(?:[^\s"'<>\\]|["'](?=[^\s"'<>\\,;:)}\]]))+/gi;
// A URL whose slashes arrive escaped by a stringify (https:\/\/user:secret@host\/path): the
// userinfo goes as it does from a bare URL and ends at the same "/", "?", or "#"; the query
// pairs are read by the pair rule.
const SLASH_ESCAPED_URL_USERINFO_PATTERN = /\b([a-z][a-z0-9+.-]*:\\\/\\\/)[^\s\/?#@"'<>\\]+@/gi;
// A key naming a webhook URL: the incoming webhooks of Slack, Discord, Teams, and PagerDuty
// carry their token in the path or query, so under webhook, webhook_url, webhookUrl, or
// WEBHOOK_URL a URL value keeps its scheme and host only, whatever the host. webhook_count,
// webhook_id, and webhook_name are not URL-valued and stay; a webhook key whose value is not
// a URL (a name, an id) stays too.
const WEBHOOK_URL_TAIL_WORDS = new Set(["url", "uri", "endpoint", "address", "link"]);
const URL_VALUE_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;
const WEBHOOK_VALUE_PATTERN = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/iy;
const URL_ORIGIN_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^/?#@]*@)?([^/?#]*)/i;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const PANOS_API_KEY_PATTERN = /\bLUFRPT[A-Za-z0-9+/=_-]{16,}/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
// Vendor token prefixes that name a credential on their own, on both sides: GitHub (ghp_,
// gho_, ghu_, ghs_, ghr_, github_pat_), Stripe (sk_live_, sk_test_, rk_live_, rk_test_), and
// Slack (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-, xoxe-, xoxo-).
const GITHUB_TOKEN_PATTERN = /\b(?:gh[oprsu]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g;
const STRIPE_KEY_PATTERN = /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g;
const SLACK_TOKEN_PATTERN = /\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g;
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&]))?/g;
const TOKEN_VALUE_PATTERN = /^[A-Za-z0-9+_-]{16,}={0,2}$/;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const DIGITS_ONLY_PATTERN = /^\d+$/;
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Below this many letters a segment's casing is not judged: eBay, iOS, McD are names.
const MIN_LETTERS_FOR_CASING = 6;
// A segment this long that is not name-shaped makes the whole run a token on its own.
const MIN_TOKEN_SEGMENT_LENGTH = 8;
// A carrier is named by its last word: api_key, access_token, client_secret, X-PAN-KEY,
// _upstream_session, oauth_signature, Set-Cookie, password1. A key whose last word names
// something else (credentialID, keyId, tokenCount, auth_mode, credentials_file,
// passwordPolicy, password_complexity_by_device, credential-enforcement) is not one, nor is
// a max/min bound; a session id (session_id, PHPSESSID, JSESSIONID) is, whatever its tail.
const CREDENTIAL_KEY_WORDS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "passcode", "phash",
  "apikey", "authorization", "credential", "credentials", "key", "keys", "cookie", "cookies", "sid", "sig", "signature",
  "auth", "nonce", "sas", "community", "authpwd", "privpwd", "pin", "otp", "totp", "jwt", "assertion", "bearer", "hmac",
  "session", "sessid", "kubeconfig", "dsn", "pem", "ikey", "skey",
]);
// Concatenated spellings the segment split cannot see (authtoken, sharedsecret, privatekey).
const CREDENTIAL_KEY_SUFFIX_PATTERN = /(?:token|secret|passw(?:or)?d|passphrase|passcode|phash|authorization|credential|signature|nonce|community|assertion|session|sessid|authpwd|privpwd|(?:api|private|secret|access|signing|encryption|master|shared|account|client|service|session|license|ssh|hmac)keys?)$/;
// A key whose last word names the form of a value (password_hash, token_value,
// authorization_header, secret_plain) carries a credential when an earlier word names one.
const CREDENTIAL_VALUE_FORM_WORDS = new Set(["value", "values", "plain", "plaintext", "data", "string", "text", "header", "raw", "encrypted", "hash", "digest", "blob", "content"]);
const SESSION_ID_PATTERN = /sess(?:ion)?[_.-]?id$/i;
const BOUND_KEY_SEGMENTS = new Set(["max", "min"]);
const EXTRA_CREDENTIAL_KEYS = new Set(["x-pan-key", "x-redlock-auth", "proxy-authorization", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "oauth_signature", "oauth_token", "oauth_verifier"]);
// "pass" names a credential in a query string or an = assignment (user=a&pass=b), while a
// "pass" count or verdict in a key: value pair is this module's own vocabulary.
const ASSIGNMENT_ONLY_CREDENTIAL_WORDS = new Set(["pass"]);
// JSON structure and literals after a key are never a credential value.
const STRUCTURAL_VALUE_PATTERN = /^(?:[{[]|\{\}|\[\]|true|false|null)$/;
// A bare integer under a plural credential word ("api_keys": 1, keys=3, secrets: 0) is
// a count, this module's own summary vocabulary, not a credential; the digits end at
// whitespace, raw or left escaped by a stringify (keys: 3\tcookies: 0), or at the end.
const PLURAL_CREDENTIAL_WORDS = new Set(["tokens", "secrets", "keys", "cookies", "passwords", "credentials"]);
const COUNT_VALUE_PATTERN = new RegExp(String.raw`^\d+(?:\s|${ESCAPED_CONTROL_SOURCE}|$)`);
const NON_CREDENTIAL_KEY_QUALIFIERS = new Set(["public"]);
// "code" names a credential only behind one of these words (registration_code,
// activation_code, authorization_code, recovery_code); status_code, error_code, and
// country_code stay evidence.
const CREDENTIAL_CODE_QUALIFIERS = new Set(["registration", "activation", "linking", "auth", "authorization", "access", "verification", "recovery", "backup", "security", "mfa", "otp", "pairing", "enrollment", "license"]);
// A secret id or token id is the bearer credential itself (a Vault AppRole secret_id, an
// API token_id, roleSecretId), unlike client_id, tenant_id, key_id, or access_key_id, which
// name a public identifier; secret_id_ttl, secret_id_accessor, and token_accessor end in a
// setting word and stay. The qualifier is tested by its tail so -Dsecret_id is read too.
const BEARER_ID_QUALIFIER_PATTERN = /(?:secret|token)$/;

function propertyNameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}

function credentialKeyWord(segment: string): boolean {
  return CREDENTIAL_KEY_WORDS.has(segment) || CREDENTIAL_KEY_SUFFIX_PATTERN.test(segment);
}

// The words of a key with trailing digits removed from each (password1, key2).
function keyWords(key: string): string[] {
  return propertyNameSegments(key).map((segment) => segment.replace(/\d+$/, "")).filter((segment) => segment.length > 0);
}

/** True when a name in a query string, header, attribute, or name-value pair carries a credential. */
export function isCredentialKey(key: string): boolean {
  if (SESSION_ID_PATTERN.test(key) || EXTRA_CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
  const words = keyWords(key);
  const last = words[words.length - 1];
  if (last === undefined || BOUND_KEY_SEGMENTS.has(words[0])) return false;
  if ((last === "key" || last === "keys") && words.length > 1 && NON_CREDENTIAL_KEY_QUALIFIERS.has(words[words.length - 2])) return false;
  if (last === "code" || last === "codes") return words.length > 1 && CREDENTIAL_CODE_QUALIFIERS.has(words[words.length - 2]);
  if (last === "id") return words.length > 1 && BEARER_ID_QUALIFIER_PATTERN.test(words[words.length - 2]);
  // A connection string (connection_string, connectionString, DB_CONNECTION_STRING) embeds
  // the password of the account it connects as.
  if (last === "string" && words[words.length - 2] === "connection") return true;
  if (credentialKeyWord(last)) return true;
  return CREDENTIAL_VALUE_FORM_WORDS.has(last) && words.slice(0, -1).some(credentialKeyWord);
}

/** True when a key names a webhook URL whose path and query carry the webhook's token. */
function isWebhookUrlKey(key: string): boolean {
  const words = keyWords(key);
  const last = words[words.length - 1];
  if (last === "webhook") return true;
  return last !== undefined && WEBHOOK_URL_TAIL_WORDS.has(last) && words[words.length - 2] === "webhook";
}

// The URL under a webhook key with its userinfo, path, query, and fragment replaced: the
// scheme and host stay, so the destination is still read.
function redactedWebhookUrl(url: string): string {
  const origin = URL_ORIGIN_PATTERN.exec(url);
  return `${origin ? `${origin[1]}${origin[2]}` : ""}/${REDACTED}`;
}

// True for a value that opens with a bare integer under a plural credential word: a count,
// not a carrier (the rest of a key: value line is rescanned for pairs of its own).
function isCountValue(key: string, value: string): boolean {
  if (!COUNT_VALUE_PATTERN.test(value)) return false;
  const words = keyWords(key);
  return words.length > 0 && PLURAL_CREDENTIAL_WORDS.has(words[words.length - 1]);
}

// True for a key whose last word is a plural credential word (api-tokens, keys, apikeys): a
// collection, so as a path label it is a pair only when a lone token follows.
function isPluralCredentialKey(key: string): boolean {
  const words = keyWords(key);
  const last = words[words.length - 1];
  return last !== undefined && (PLURAL_CREDENTIAL_WORDS.has(last) || PLURAL_CREDENTIAL_LABEL_PATTERN.test(last));
}

/** isCredentialKey plus the words that name a credential only in a query string or = assignment. */
function isCredentialAssignmentKey(key: string): boolean {
  if (isCredentialKey(key)) return true;
  const words = keyWords(key);
  return words.length > 0 && ASSIGNMENT_ONLY_CREDENTIAL_WORDS.has(words[words.length - 1]);
}

// Token-shaped casing: the case changes more often than once every three letters
// (bPxRfiCYcanaryKEY); words, acronyms, camelCase, and PascalCase change case at word
// boundaries only (AWSLambdaBasicExecutionRole).
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  let changes = 0;
  for (let index = 1; index < letters.length; index += 1) {
    const previousLower = letters[index - 1] >= "a" && letters[index - 1] <= "z";
    const currentLower = letters[index] >= "a" && letters[index] <= "z";
    if (previousLower !== currentLower) changes += 1;
  }
  return changes * 3 > letters.length;
}

// A "-" or "_" separated segment shaped like part of a name: empty, digits alone, or letters
// with at most one digit group (west2, sha256, vsys1, ethernet1) whose casing is not token-shaped.
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || DIGITS_ONLY_PATTERN.test(segment)) return true;
  const digitGroups = segment.match(DIGIT_GROUP_PATTERN) ?? [];
  if (digitGroups.length > 1) return false;
  return !hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, ""));
}

// A run is a token when it carries base64 symbols ("+" anywhere; "=" padding only where the
// run is base64-shaped: a multiple of four characters with no "-" or "_", so "key=" left
// in front of a marker is never padding and the rule stays idempotent), or when a
// segment of MIN_TOKEN_SEGMENT_LENGTH or more is not name-shaped, or when at least half
// of its segments are not. One short random-looking segment beside several names (the
// six-character mkdtemp suffix of a temp path, a build id) does not make a token.
function looksLikeToken(run: string): boolean {
  const padding = /=+$/.exec(run)?.[0] ?? "";
  const body = run.slice(0, run.length - padding.length);
  if (UPPERCASE_CODE_PATTERN.test(body) || DIGITS_ONLY_PATTERN.test(body) || UUID_PATTERN.test(body)) return false;
  if (body.includes("+")) return true;
  if (padding.length > 0) return run.length % 4 === 0 && !/[-_]/.test(body);
  const segments = body.split(/[-_]/).filter((segment) => segment.length > 0);
  const tokenSegments = segments.filter((segment) => !isNameSegment(segment));
  if (tokenSegments.length === 0) return false;
  return tokenSegments.some((segment) => segment.length >= MIN_TOKEN_SEGMENT_LENGTH) || tokenSegments.length * 2 >= segments.length;
}

// A whole query value that is one token-shaped run (no path, dot, or percent escape inside).
function isTokenShapedValue(value: string): boolean {
  return TOKEN_VALUE_PATTERN.test(value) && looksLikeToken(value);
}

// The word after a scheme name is prose when it is a Titlecase word, an auth-param name
// before its "=", a plain lowercase word from the list above, or, after a noun scheme
// word (Token, OAuth, Splunk, Snowflake), any plain lowercase word too short to be a real
// token.
function isSchemeProse(scheme: string, value: string): boolean {
  if (TITLE_WORD_PATTERN.test(value)) return true;
  const authParam = AUTH_PARAM_PATTERN.exec(value);
  if (authParam) return AUTH_PARAM_NAMES.has(authParam[1].toLowerCase());
  if (!PLAIN_WORD_PATTERN.test(value)) return false;
  if (SCHEME_PROSE_WORDS.has(value)) return true;
  return NOUN_SCHEME_WORDS.has(scheme.toLowerCase()) && value.length < LONG_TOKEN_MIN_LENGTH;
}

function isPublicPemLabel(label: string): boolean {
  return PUBLIC_PEM_LABELS.has(label.trim());
}

function scrubPem(text: string, scope: PemScope): string {
  const keeps = (label: string): boolean => {
    switch (scope) {
      case "all":
        return false;
      case "private":
        return isPublicPemLabel(label);
      default: {
        const exhaustive: never = scope;
        return exhaustive;
      }
    }
  };
  return text
    .replace(PEM_BLOCK_PATTERN, (match, label: string) => (keeps(label) ? match : CREDENTIAL_REDACTION_MARKER))
    .replace(PEM_OPEN_PATTERN, (match, label: string) => (keeps(label) ? match : CREDENTIAL_REDACTION_MARKER));
}

function scrubUrlUserinfo(url: string): string {
  return url.replace(URL_USERINFO_PATTERN, `$1${CREDENTIAL_REDACTION_MARKER}@`);
}

// The run of backslashes at index.
function backslashRun(text: string, index: number): number {
  let run = 0;
  while (text[index + run] === "\\") run += 1;
  return run;
}

// The quote token at index: a bare quote, or a quote behind the odd run of backslashes that
// JSON escaping puts before it at some nesting depth (\" one level down, \\\" two levels
// down, and so on). An even run escapes backslashes and leaves the quote bare, so it is no
// token here; the caller steps over the run and reads the quote on its own.
function quoteTokenAt(text: string, index: number): string | undefined {
  const run = backslashRun(text, index);
  const quote = text[index + run];
  if ((quote !== '"' && quote !== "'") || (run > 0 && run % 2 === 0)) return undefined;
  return text.slice(index, index + run + 1);
}

// True when the quote token at index sits inside a token, a value character before it and
// another after it, so it is content of the value and neither opens nor closes a segment.
function midTokenQuoteAt(text: string, index: number, tokenLength: number): boolean {
  const before = text[index - 1];
  const after = text[index + tokenLength];
  if (before === undefined || after === undefined) return false;
  if (HEADER_VALUE_OPENER_PATTERN.test(before) || before === '"' || before === "'" || before === "\\") return false;
  return !QUOTE_BOUNDARY_PATTERN.test(after);
}

// True when the quote token at index, though a value could start there, is followed by
// nothing a quoted value starts with (whitespace, a delimiter, a bracket, a tag, or the
// end of the text): it is the quote closing the enclosing text, as after a base64 value
// that ends in "=" (Basic dXNlcjpwYXNz=","code":401), not one opening a segment.
function closingQuoteAfterOpener(text: string, index: number, tokenLength: number): boolean {
  const after = text[index + tokenLength];
  return after === undefined || /[\s,;:)}\]<>]/.test(after);
}

// The first line end or HTML tag at or after start, or the end of the text.
function lineEndFrom(text: string, start: number): number {
  const terminator = HEADER_VALUE_TERMINATOR_PATTERN.exec(text.slice(start));
  return terminator ? start + terminator.index : text.length;
}

// The control characters the one-letter escapes stand for.
const CONTROL_ESCAPE_LETTERS = new Map<string, number>([["n", 0x0a], ["r", 0x0d], ["t", 0x09], ["b", 0x08], ["f", 0x0c], ["v", 0x0b], ["0", 0x00]]);

// True for the code of a control character: U+0000 to U+001F, U+007F, or the line and
// paragraph separators U+2028 and U+2029.
function isControlCode(code: number): boolean {
  return code <= 0x1f || code === 0x7f || code === 0x2028 || code === 0x2029;
}

// The code of the control character an escape at index stands for (\n, \r, \t, \b, \f, \v,
// \0, \uXXXX, or \xHH behind an odd run of backslashes, as one stringify leaves it), or -1
// when the text at index is no such escape: an even run escapes backslashes, and the escape
// of a printable character (\u00e9) is content.
function escapedControlCodeAt(text: string, index: number): number {
  const run = backslashRun(text, index);
  if (run === 0 || run % 2 === 0) return -1;
  const letter = text[index + run];
  if (letter === undefined) return -1;
  const simple = CONTROL_ESCAPE_LETTERS.get(letter);
  if (simple !== undefined) return simple;
  const digits = letter === "u" ? 4 : letter === "x" ? 2 : 0;
  if (digits === 0) return -1;
  const hex = text.slice(index + run + 1, index + run + 1 + digits);
  if (hex.length !== digits || !/^[0-9a-f]+$/i.test(hex)) return -1;
  const code = parseInt(hex, 16);
  return isControlCode(code) ? code : -1;
}

// True at a line break left escaped by one stringify (\n, \r, \u000a, \u000d, \x0a, \x0d): a
// line end for an unquoted header value, as the raw character is.
function escapedLineBreakAt(text: string, index: number): boolean {
  const code = escapedControlCodeAt(text, index);
  return code === 0x0a || code === 0x0d;
}

// Where the unquoted token that starts at start ends: at the first whitespace or raw control
// character, at a control the stringify left escaped (\t, \u0009, \f, \b, and a line break
// among them), or at limit. A token never carries a control, so the pair or header chained
// after the escape is read on its own.
function unquotedTokenEnd(text: string, start: number, limit: number): number {
  let index = start;
  while (index < limit) {
    const char = text[index];
    if (/\s/.test(char) || isControlCode(char.charCodeAt(0))) break;
    if (char === "\\") {
      if (escapedControlCodeAt(text, index) !== -1) break;
      index += backslashRun(text, index);
      continue;
    }
    index += 1;
  }
  return index;
}

// The key without the escape letter in front of it: after an escaping backslash the letter
// belongs to the escape (\napi_key is a newline and then api_key), not to the key. Only the
// credential test uses the result; the text itself is left as it arrived.
function keyAfterEscape(text: string, keyStart: number, key: string): string {
  let run = 0;
  while (keyStart - 1 - run >= 0 && text[keyStart - 1 - run] === "\\") run += 1;
  if (run % 2 === 0) return key;
  const letter = ESCAPE_LETTER_PATTERN.exec(key);
  return letter ? key.slice(letter[0].length) : key;
}

// The index of the token that closes a quoted segment opened with token, before limit, or
// -1. A token inside a token (sid="O'hunter2") is content of the segment, as is a token at a
// deeper depth (more backslashes); a token nearer the surface closes the text the segment
// sits in, so the segment is unterminated.
function closingQuoteIndex(text: string, from: number, token: string, limit: number): number {
  let index = from;
  while (index < limit) {
    const candidate = quoteTokenAt(text, index);
    if (candidate === undefined) {
      index += text[index] === "\\" ? backslashRun(text, index) : 1;
      continue;
    }
    if (midTokenQuoteAt(text, index, candidate.length)) {
      index += candidate.length;
      continue;
    }
    if (candidate === token) return index;
    if (candidate.length < token.length) return -1;
    index += candidate.length;
  }
  return -1;
}

// Where the value of a header line that starts at start ends. A value that opens with a
// quote token ends at the token that closes it on the same line, whatever it carries (a
// "; Name:" inside a quoted cookie is content); when nothing closes it, the quote is content
// and the value ends as an unquoted one does. An unquoted value ends at the end of the line,
// at an HTML tag, at the ";" or "," before the "Name:" token of the next header on a
// compound line (on "Cookie: sid=value; X-ApiKeys: value" the next header keeps its name
// and gets its own carrier treatment, and a Content-Type or Date after a cookie keeps its
// name and value), at a line break left escaped inside a JSON string (\n, \r, \u000a), or
// at the quote that closes the text the line sits in. Inside an unquoted value a quote
// where a value can start opens a quoted segment carried through its closing token; a
// quote inside a token (sid=O'hunter2, my'pref=value) is content; a quote at the end of a
// token, or one after "=" that only a delimiter or the end follows (sid=abc==",), closes
// the enclosing text. Trailing whitespace is not part of the value.
function headerValueEnd(text: string, start: number): number {
  const limit = lineEndFrom(text, start);
  const opening = quoteTokenAt(text, start);
  if (opening !== undefined) {
    const close = closingQuoteIndex(text, start + opening.length, opening, limit);
    if (close !== -1) return close + opening.length;
  }
  let index = opening === undefined ? start : start + opening.length;
  while (index < limit) {
    const char = text[index];
    if ((char === ";" || char === ",") && FOLLOWING_HEADER_PATTERN.test(text.slice(index + 1, index + 1 + FOLLOWING_HEADER_LOOKAHEAD))) break;
    if (char === "\\" && escapedLineBreakAt(text, index)) break;
    const token = quoteTokenAt(text, index);
    if (token === undefined) {
      index += char === "\\" ? backslashRun(text, index) : 1;
      continue;
    }
    if (!HEADER_VALUE_OPENER_PATTERN.test(text[index - 1])) {
      if (!midTokenQuoteAt(text, index, token.length)) break;
      index += token.length;
      continue;
    }
    if (closingQuoteAfterOpener(text, index, token.length)) break;
    const close = closingQuoteIndex(text, index + token.length, token, limit);
    index = close === -1 ? index + token.length : close + token.length;
  }
  while (index > start && /\s/.test(text[index - 1])) index -= 1;
  return index;
}

// The quote token a header value is wrapped in as a whole (bare or escaped to any depth), or
// "" when it is not one quoted string.
function enclosingQuote(value: string): string {
  const token = quoteTokenAt(value, 0);
  return token !== undefined && value.length >= token.length * 2 && value.endsWith(token) ? token : "";
}

// True for an Authorization pair whose value reads "Bearer [REDACTED]" or the like: the header
// rule already treated it, and the pair rules leave the scheme word standing. Under any other
// credential-named key the scheme word is part of the value and goes with it.
function keepsSchemeWord(key: string, value: string): boolean {
  if (!AUTHORIZATION_HEADERS.has(key.toLowerCase())) return false;
  const scheme = REDACTED_SCHEME_VALUE_PATTERN.exec(value);
  return scheme !== null && AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase());
}

// The listed scheme word a header value opens with, when a token follows it, or undefined:
// for a bare scheme word, a word the list does not know, or a value that opens with anything
// but a word.
function leadingSchemeWord(value: string): RegExpExecArray | undefined {
  const scheme = AUTH_SCHEME_PATTERN.exec(value);
  if (!scheme || scheme[0].length === value.length || !AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase())) return undefined;
  return scheme;
}

// Where the credentials after a scheme word end, credentialsStart being the index after the
// word and the whitespace behind it: a parameter list (username=..., realm=...) runs to end,
// a quoted string to the quote that closes it (or to end when nothing does), and a bare
// token to its first whitespace or escaped control.
function schemeCredentialsEnd(text: string, credentialsStart: number, end: number): number {
  const credentials = text.slice(credentialsStart, end);
  if (AUTH_PARAM_LIST_PATTERN.test(credentials)) return end;
  const quote = quoteTokenAt(credentials, 0);
  if (quote !== undefined) {
    const close = closingQuoteIndex(text, credentialsStart + quote.length, quote, end);
    return close === -1 ? end : close + quote.length;
  }
  return unquotedTokenEnd(text, credentialsStart, end);
}

// Where the value of a single-token header ends: an unquoted value at its first whitespace
// or escaped control, a quoted one where headerValueEnd put it. A value that opens with a
// listed scheme word and a token (X-Auth-Token: Bearer <token>) is the word and the
// credentials after it, as it would be under Authorization, so the token is never left
// standing after the marker.
function singleTokenEnd(text: string, start: number, end: number): number {
  const value = text.slice(start, end);
  if (enclosingQuote(value) !== "") return end;
  const scheme = leadingSchemeWord(value);
  if (scheme !== undefined) return schemeCredentialsEnd(text, start + scheme[0].length, end);
  return unquotedTokenEnd(text, start, end);
}

// Where an Authorization value ends: after the listed scheme word and the one token (or one
// quoted string) of credentials that follows it, so prose after the token on a free-text
// line stays; a parameter list after the scheme (Digest username=..., realm=...) goes to the
// end of the line, as does a value quoted as a whole, a bare scheme word, and a value that
// opens with anything but a listed scheme word (GenieKey <token>, SharedKey account:<sig>,
// a bare token): the first word may be a scheme the list does not know, with its credentials
// after it, so the whole line goes.
function authorizationValueEnd(text: string, start: number, end: number): number {
  const value = text.slice(start, end);
  if (enclosingQuote(value) !== "") return end;
  const scheme = leadingSchemeWord(value);
  if (scheme === undefined) return end;
  return schemeCredentialsEnd(text, start + scheme[0].length, end);
}

// The replacement for a header value, or undefined when nothing is left to remove: the value
// already opens with the marker (bare, inside its quotes, or after its scheme word), or an
// Authorization value is a bare scheme word with no credentials after it. An Authorization
// value keeps its scheme word as spelled; the credentials after it go whole, inside their own
// quotes when they were quoted (Bearer "value" becomes Bearer "[REDACTED]"). A value that is
// one quoted string keeps its quotes around the replacement so quoted text stays quoted.
function redactedHeaderValue(header: string, value: string): string | undefined {
  const quote = enclosingQuote(value);
  const inner = quote === "" ? value : value.slice(quote.length, value.length - quote.length);
  if (inner.startsWith(CREDENTIAL_REDACTION_MARKER)) return undefined;
  if (AUTHORIZATION_HEADERS.has(header)) {
    const scheme = AUTH_SCHEME_PATTERN.exec(inner);
    if (scheme && AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase())) {
      const credentials = inner.slice(scheme[0].length);
      if (credentials.length === 0) return undefined;
      const credentialQuote = enclosingQuote(credentials);
      if (credentials.slice(credentialQuote.length).startsWith(CREDENTIAL_REDACTION_MARKER)) return undefined;
      return `${quote}${scheme[1]} ${credentialQuote}${CREDENTIAL_REDACTION_MARKER}${credentialQuote}${quote}`;
    }
  }
  return `${quote}${CREDENTIAL_REDACTION_MARKER}${quote}`;
}

// Every credential-bearing header line loses its credentials whatever their shape, by the
// header's class: an Authorization value keeps its listed scheme word and loses the token
// after it (or its whole parameter list), or goes whole when it opens with anything else; a
// cookie or key list goes whole; and a single-token header loses its first token, or the
// listed scheme word and the token after it when it opens with one. On a compound line each
// header is its own line: the value of one ends before the name of the next, which is then
// matched and treated on its own.
function scrubHeaderLines(text: string): string {
  HEADER_LINE_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = HEADER_LINE_PATTERN.exec(text)) !== null) {
    const header = match[1].toLowerCase();
    const start = match.index + match[0].length;
    const lineEnd = headerValueEnd(text, start);
    const end = LIST_VALUE_HEADERS.has(header) ? lineEnd : AUTHORIZATION_HEADERS.has(header) ? authorizationValueEnd(text, start, lineEnd) : singleTokenEnd(text, start, lineEnd);
    const value = text.slice(start, end);
    if (value.length === 0) continue;
    const replacement = redactedHeaderValue(header, value);
    if (replacement === undefined) continue;
    out += `${text.slice(last, start)}${replacement}`;
    last = end;
    HEADER_LINE_PATTERN.lastIndex = end;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

// The key and separator are matched on their own and the value is consumed only when the
// key names a credential, so the value of an ordinary pair is rescanned and a credential
// pair nested inside it (data=token=...) is still caught. A value the scheme rule already
// reduced to "<scheme> [REDACTED]" keeps its scheme word under an Authorization key and loses
// it under any other credential key, where the scheme word was the start of the value. A
// colon-terminated key that ends a path segment is a label whose value is at most one token:
// a singular label (/etc/app/password: <value> was rejected) takes that token whatever its
// shape and whatever follows, and a plural label (/api/v1/api-tokens: request failed) takes
// it only when no prose continues after it, since prose means there was no value at all; an
// escaped slash (\/) before the key is a line break, not a path.
function replaceCredentialAssignments(text: string): string {
  ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator, operator] = match;
    const spelledName = keyAfterEscape(text, match.index + openingQuote.length, key);
    const name = openingQuote === "" && spelledName.startsWith("D") && JAVA_PROPERTY_PREFIX_PATTERN.test(text.slice(Math.max(0, match.index - 2), match.index)) ? spelledName.slice(1) : spelledName;
    const valueStart = match.index + whole.length;
    if (isWebhookUrlKey(name)) {
      WEBHOOK_VALUE_PATTERN.lastIndex = valueStart;
      const url = WEBHOOK_VALUE_PATTERN.exec(text)?.[0];
      if (url === undefined) continue;
      out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${redactedWebhookUrl(url)}`;
      last = valueStart + url.length;
      ASSIGNMENT_KEY_PATTERN.lastIndex = last;
      continue;
    }
    if (!(operator === "=" ? isCredentialAssignmentKey(name) : isCredentialKey(name))) continue;
    const redactedScheme = REDACTED_SCHEME_VALUE_PATTERN.exec(text.slice(valueStart));
    if (redactedScheme !== null && AUTH_SCHEME_WORDS.has(redactedScheme[1].toLowerCase())) {
      if (AUTHORIZATION_HEADERS.has(name.toLowerCase())) continue;
      out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${redactedScheme[2]}${CREDENTIAL_REDACTION_MARKER}`;
      last = valueStart + redactedScheme[0].length;
      ASSIGNMENT_KEY_PATTERN.lastIndex = last;
      continue;
    }
    const pathLabel = operator === ":" && text[match.index - 1] === "/" && text[match.index - 2] !== "\\";
    const valuePattern = operator === ":" && !pathLabel ? LINE_VALUE_PATTERN : DELIMITED_VALUE_PATTERN;
    valuePattern.lastIndex = valueStart;
    const value = valuePattern.exec(text)?.[0];
    if (value === undefined || STRUCTURAL_VALUE_PATTERN.test(value) || isCountValue(name, value)) continue;
    if (pathLabel && isPluralCredentialKey(name) && PROSE_CONTINUATION_PATTERN.test(text.slice(valueStart + value.length))) continue;
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${CREDENTIAL_REDACTION_MARKER}`;
    last = valueStart + value.length;
    ASSIGNMENT_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

// A credential-named flag with its value as the next argument loses that argument.
function replaceFlagValues(text: string): string {
  return text.replace(FLAG_VALUE_PATTERN, (match, flag: string, space: string) => (isCredentialKey(flag) ? `--${flag}${space}${CREDENTIAL_REDACTION_MARKER}` : match));
}

/** Every carrier rule (guard 1) plus the token shapes a prefix identifies on its own; the long-token rule is left to redactErrorText. */
// Header lines go first: a recognised header line takes its whole value, so the URL and
// query rules never split a cookie pair whose name holds "&" or "#" off its cookie.
function scrubCarriers(text: string, pemScope: PemScope): string {
  const quotedValue = (key: string, value: string, redacted: () => string, webhook: (url: string) => string, match: string): string => {
    if (isWebhookUrlKey(key) && URL_VALUE_PATTERN.test(value)) return webhook(redactedWebhookUrl(value));
    return isCredentialKey(key) && !isCountValue(key, value) && !keepsSchemeWord(key, value) ? redacted() : match;
  };
  const scrubbed = scrubHeaderLines(scrubPem(text, pemScope))
    .replace(TOKEN_IN_PATH_WEBHOOK_PATTERN, `$1${CREDENTIAL_REDACTION_MARKER}`)
    .replace(EMBEDDED_URL_PATTERN, scrubUrlUserinfo)
    .replace(SLASH_ESCAPED_URL_USERINFO_PATTERN, `$1${CREDENTIAL_REDACTION_MARKER}@`)
    .replace(QUERY_PAIR_PATTERN, (match, separator: string, key: string, value: string) => (isCredentialAssignmentKey(key) || isTokenShapedValue(value) ? `${separator}${key}=${CREDENTIAL_REDACTION_MARKER}` : match))
    .replace(SCHEME_VALUE_PATTERN, (match, scheme: string, value: string) => (isSchemeProse(scheme, value) ? match : `${scheme} ${CREDENTIAL_REDACTION_MARKER}`))
    .replace(JSON_QUOTED_PAIR_PATTERN, (match, key: string, separator: string, value: string) => quotedValue(key, value, () => `"${key}"${separator}"${CREDENTIAL_REDACTION_MARKER}"`, (url) => `"${key}"${separator}"${url}"`, match))
    .replace(JSON_ESCAPED_PAIR_PATTERN, (match, run: string, key: string, separator: string, value: string) => quotedValue(key, value, () => `${run}"${key}${run}"${separator}${run}"${CREDENTIAL_REDACTION_MARKER}${run}"`, (url) => `${run}"${key}${run}"${separator}${run}"${url}${run}"`, match))
    .replace(QUOTED_ATTRIBUTE_PATTERN, (match, key: string, quote: string, value: string, offset: number, whole: string) => quotedValue(keyAfterEscape(whole, offset, key), value, () => `${key}=${quote}${CREDENTIAL_REDACTION_MARKER}${quote}`, (url) => `${key}=${quote}${url}${quote}`, match));
  return replaceCredentialAssignments(replaceFlagValues(scrubbed))
    .replace(JWT_PATTERN, CREDENTIAL_REDACTION_MARKER)
    .replace(PANOS_API_KEY_PATTERN, CREDENTIAL_REDACTION_MARKER)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, CREDENTIAL_REDACTION_MARKER)
    .replace(GITHUB_TOKEN_PATTERN, CREDENTIAL_REDACTION_MARKER)
    .replace(STRIPE_KEY_PATTERN, CREDENTIAL_REDACTION_MARKER)
    .replace(SLACK_TOKEN_PATTERN, CREDENTIAL_REDACTION_MARKER);
}

/** The general scrub for error text: every carrier rule, every PEM block, and the long-token rule. Idempotent. */
export function redactErrorText(text: string): string {
  return scrubCarriers(text, "all").replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? CREDENTIAL_REDACTION_MARKER : run));
}

/** Guard 2 on its own: every configured secret in every encoded form, for whole payloads and bundle files where the general scrub would remove evidence. */
export function redactConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
  const values = secrets.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
  if (values.length === 0) return text;
  return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(CREDENTIAL_REDACTION_MARKER);
}

/**
 * Every string inside a tool result or other plain value, with the configured secrets
 * removed; a number whose decimal form is a configured secret becomes the marker too.
 * Structure is never touched, so a short secret that matches a whole token (a PIN, a
 * word) cannot break the JSON the value is serialized to.
 */
function sealValue<T>(value: T, secrets: ReadonlyArray<string | undefined>): T {
  if (typeof value === "string") return redactConfiguredSecrets(value, secrets) as T;
  if (typeof value === "number") return (secrets.includes(String(value)) ? CREDENTIAL_REDACTION_MARKER : value) as T;
  if (Array.isArray(value)) return value.map((item) => sealValue(item, secrets)) as T;
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const output: JsonRecord = {};
    for (const [key, entry] of Object.entries(value as JsonRecord)) output[key] = sealValue(entry, secrets);
    return output as T;
  }
  return value;
}

/** The client-side scrub for a thrown message: the configured secrets in every form (guard 2), then the general scrub. */
export function redactSecrets(message: string, secrets: ReadonlyArray<string | undefined>): string {
  return redactErrorText(redactConfiguredSecrets(message, secrets));
}

/** The secrets a resolved configuration puts on the wire: both halves of the X-ApiKeys header and of the Security Center x-apikey header. */
export function configuredTenableSecrets(config: TenableResolvedConfig): string[] {
  return [config.vm?.accessKey, config.vm?.secretKey, config.securityCenter?.accessKey, config.securityCenter?.secretKey]
    .filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
}

// Property names whose values are credentials wherever they appear in a vendor payload.
// Matched on the flattened name (snake_case, kebab-case, camelCase, and header forms) or
// on the final camelCase or snake_case segment. A bare "key" is not one: Tenable tags are
// {key, value} pairs and the asset tag key is evidence.
const CREDENTIAL_PROPERTY_NAMES = new Set([
  "password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens",
  "apikey", "apikeys", "xapikey", "xapikeys", "accesskey", "secretkey", "privatekey", "clientsecret",
  "apisecret", "sharedsecret", "registrationcode", "activationcode", "linkingkey", "authtoken",
  "accesstoken", "refreshtoken", "idtoken", "sessionid", "sessiontoken", "authorization", "cookie", "xcookie",
]);
const CREDENTIAL_LAST_SEGMENTS = new Set(["password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens", "authorization", "cookie"]);

export function propertyNameIsCredential(name: string): boolean {
  if (SESSION_ID_PATTERN.test(name) || CREDENTIAL_PROPERTY_NAMES.has(name.toLowerCase().replace(/[^a-z0-9]/g, ""))) return true;
  const segments = propertyNameSegments(name);
  const last = segments.at(-1);
  return last !== undefined && CREDENTIAL_LAST_SEGMENTS.has(last);
}

/**
 * The scrub for credentials carried inside string values rather than under a
 * credential-named key: every carrier rule of redactErrorText (URL userinfo and
 * credential query pairs; webhook services whose URL path is the secret; header,
 * cookie, scheme, and credential-pair carriers; JSON encoded as a string; private
 * PEM blocks) without the long-token rule, because an id, a plugin set, or a hash in
 * evidence is not a secret, and with public PEM blocks kept because a certificate
 * is evidence. Applied to every string kept in a dataset, so audit-log field values,
 * webhook targets, and free-text settings are covered without naming them.
 */
export function redactCredentialValueText(text: string): string {
  return scrubCarriers(text, "private");
}

function redactCredentialNode(value: unknown): unknown {
  if (typeof value === "string") return redactCredentialValueText(value);
  if (Array.isArray(value)) return value.map(redactCredentialNode);
  const record = asObject(value);
  if (!record) return value;
  // A {name, value} pair is a credential pair when flagged secure: true or when its name is
  // a credential in either vocabulary, the walker's or the text rules' (auth, X-Auth, a
  // header name such as Cookie), whatever the secure flag says.
  const pairName = typeof record.name === "string" ? record.name : undefined;
  const pairIsCredential = (pairName !== undefined && (propertyNameIsCredential(pairName) || isCredentialKey(pairName))) || record.secure === true;
  const result: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    if (entry === null || entry === undefined) {
      result[key] = entry;
    } else if (propertyNameIsCredential(key) || (pairIsCredential && (key === "value" || key === "default"))) {
      result[key] = REDACTED;
    } else if (typeof entry === "string" && isWebhookUrlKey(key) && URL_VALUE_PATTERN.test(entry)) {
      // A URL under a webhook key keeps its origin only: the path and query are the secret.
      result[key] = redactedWebhookUrl(entry);
    } else {
      result[key] = redactCredentialNode(entry);
    }
  }
  return result;
}

// Applied to every collected dataset before it can reach a finding, a tool result, or a
// bundle file, so credential-bearing properties are redacted by construction.
export function redactCredentialProperties<T>(value: T): T {
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

// The media type of a response is server-controlled text: it is quoted only when it has
// the shape of a media type, otherwise it is described as unknown.
const MEDIA_TYPE_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,31}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,39}$/;

function mediaTypeOf(response: Response): string {
  const value = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
  return MEDIA_TYPE_PATTERN.test(value) ? value : "unknown";
}

// JSON.parse's own message quotes a window of the source, so it is never kept: a body
// that is not JSON parses to undefined and is described by media type and size only.
function parseJsonBody(rawText: string): { parsed: unknown } | undefined {
  try {
    return { parsed: JSON.parse(rawText) };
  } catch {
    return undefined;
  }
}

function jsonValueKind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function statusLine(response: Response): string {
  return `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
}

// Non-JSON bodies (HTML error pages, SSO interstitials, WAF blocks) are described by
// status and length only; JSON bodies contribute Tenable's documented error fields
// (error, error.message, message, error_msg), each scrubbed before it is shortened, with
// the caller's scrub when it knows the configured secrets, so the cut never leaves a
// fragment of a secret behind.
export function describeErrorBody(response: Response, rawText: string, scrub: (text: string) => string = redactErrorText): string {
  const base = statusLine(response);
  if (rawText.length === 0) return base;
  const body = parseJsonBody(rawText);
  if (body === undefined) return `${base}; non-JSON ${mediaTypeOf(response)} response body (${rawText.length} bytes, not echoed)`;
  const record = asObject(body.parsed);
  const fields = record
    ? [asString(record.error), asString(asObject(record.error)?.message), asString(record.message), asString(record.error_msg)]
      .filter((item): item is string => Boolean(item))
    : [];
  if (fields.length === 0) return `${base}; JSON response body without documented error fields (${rawText.length} bytes, not echoed)`;
  return `${base}; ${fields.map((field) => scrub(field.replace(/\s+/g, " ")).slice(0, 200)).join("; ")}`;
}

// What a 2xx answer was expected to carry: the documented JSON document of any kind, a
// JSON object, a JSON array, one documented member of a JSON object (an array, an
// object, a Security Center list, or the member's mere presence), any one of the
// members that identify a documented object, or an array at least one of whose records
// carries a member that identifies a documented record.
type DocumentExpectation =
  | { kind: "document" }
  | { kind: "object" }
  | { kind: "array" }
  | { kind: "member"; key: string; type: "array" | "object" | "list" | "member" }
  | { kind: "members"; keys: string[] }
  | { kind: "records"; keys: string[]; count: number };

/**
 * A 2xx answer whose body is not the documented JSON document (an empty body, the HTML
 * page a proxy or captive portal serves in place of the API, a foreign JSON value, a
 * JSON object without the documented member) is described like an error body, by
 * status, media type, and size only, and is recorded as an unreadable surface: its
 * missing members are never read as an empty inventory or a disabled setting.
 */
export function describeNonDocumentBody(response: Response, rawText: string, expected: DocumentExpectation = { kind: "document" }): string {
  const base = statusLine(response);
  const size = `${rawText.length} bytes, not echoed`;
  let what: string;
  switch (expected.kind) {
    case "member":
      return `${base} with a JSON response body without the documented "${expected.key}" ${expected.type} (${size})`;
    case "members":
      return `${base} with a JSON response body without any of the documented members ${expected.keys.map((key) => `"${key}"`).join(", ")} (${size})`;
    case "records":
      return `${base} with a JSON array of ${expected.count} records none of which carries any of the documented members ${expected.keys.map((key) => `"${key}"`).join(", ")} (${size})`;
    case "document":
      what = "the documented JSON document";
      break;
    case "object":
      what = "the documented JSON object";
      break;
    case "array":
      what = "the documented JSON array";
      break;
    default: {
      const exhaustive: never = expected;
      throw new Error(`Unhandled document expectation: ${String(exhaustive)}`);
    }
  }
  if (rawText.length === 0) return `${base} with an empty response body where ${what} was expected`;
  const body = parseJsonBody(rawText);
  if (body === undefined) return `${base} with a non-JSON ${mediaTypeOf(response)} response body (${size}) where ${what} was expected`;
  return `${base} with a JSON ${jsonValueKind(body.parsed)} response body (${size}) where ${what} was expected`;
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

/** Writes one bundle file with the configured secrets removed from its text in every encoded form (guard 2). */
async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string, secrets: ReadonlyArray<string | undefined> = []): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, redactConfiguredSecrets(content, secrets), { encoding: "utf8", mode: 0o600 });
}

/** Writes one JSON bundle file; the configured secrets are removed value by value before serialization so the file stays valid JSON. */
async function writeSecureJsonFile(rootDir: string, relativePathname: string, value: unknown, secrets: ReadonlyArray<string | undefined>): Promise<void> {
  const plain: unknown = JSON.parse(JSON.stringify(value ?? null));
  await writeSecureTextFile(rootDir, relativePathname, serializeJson(sealValue(plain, secrets)));
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

const ERRNO_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;

/**
 * Two-step config loader guard with fixed text per step. Neither the filesystem
 * message (which echoes the path and the operation) nor the parser message is
 * ever interpolated: the yaml parser quotes the offending source line, and an
 * unresolved alias (`token: *VALUE`) throws a plain ReferenceError whose message
 * starts with the value itself. The read step carries the path and a validated
 * errno code; the parse step catches every thrown value and carries the path plus
 * a line number taken only from a YAMLError's structured linePos.
 */
function readConfigText(resolvedPath: string): string {
  try {
    return readFileSync(resolvedPath, "utf8");
  } catch (error) {
    const code = asString(asObject(error)?.code);
    const suffix = code !== undefined && ERRNO_CODE_PATTERN.test(code) ? ` (${code})` : "";
    throw new Error(`Unable to read Tenable config file ${resolvedPath}${suffix}`);
  }
}

function parseConfigYaml(resolvedPath: string, raw: string): unknown {
  try {
    return parseYaml(raw) as unknown;
  } catch (error) {
    const linePos = error instanceof YAMLError && Array.isArray(error.linePos) ? asObject(error.linePos[0]) : undefined;
    const line = asNumber(linePos?.line);
    throw new Error(`Unable to parse Tenable config file: invalid YAML in ${resolvedPath}${line === undefined ? "" : ` at line ${line}`} (INVALID_YAML)`);
  }
}

/**
 * An explicitly named file (config_file argument or TENABLE_CONFIG_FILE) must be
 * readable, so a missing one surfaces as ENOENT; the default ~/.tenable/config.yaml
 * is optional and is skipped silently when absent.
 */
function readConfigFile(pathname: string, explicit: boolean): { values: JsonRecord; source?: string } {
  const resolvedPath = pathname.startsWith("~") ? join(homedir(), pathname.slice(1)) : resolve(pathname);
  if (!explicit && !existsSync(resolvedPath)) return { values: {} };
  const parsed = parseConfigYaml(resolvedPath, readConfigText(resolvedPath));
  if (parsed === null || parsed === undefined) return { values: {}, source: `config:${resolvedPath}` };
  const values = asObject(parsed);
  if (!values) {
    throw new Error(`Unable to parse Tenable config file: ${resolvedPath} must contain a YAML mapping of settings (INVALID_CONFIG_SHAPE)`);
  }
  return { values, source: `config:${resolvedPath}` };
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
  const explicitConfigPath = asString(input.config_file) ?? asString(env.TENABLE_CONFIG_FILE);
  const file = readConfigFile(explicitConfigPath ?? join(homedir(), ".tenable", "config.yaml"), explicitConfigPath !== undefined);
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
      // A full stop, not a colon, after "keys": the pair rule reads "keys: <text>" as a
      // credential assignment and would withhold the remediation sentence.
      throw new Error(`Tenable Security Center at ${resolvedScUrl} needs API keys. Set TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY (or TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY when TENABLE_URL points at Security Center).`);
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

/**
 * status is the observed HTTP status (0 when no response arrived) and endpoint
 * is the "METHOD /path" of the request that actually failed, so every consumer
 * can name the real request rather than the nominal one it set out to make.
 */
export class TenableApiError extends Error {
  readonly status: number;
  readonly endpoint: string;

  constructor(message: string, status: number, endpoint: string) {
    super(redactErrorText(message));
    this.name = "TenableApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

function endpointLabel(method: string | undefined, path: string): string {
  return `${(method ?? "GET").toUpperCase()} ${path.startsWith("/") ? path : `/${path}`}`;
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

  /** The configured keys this client puts on the wire, for the tool boundary and bundle writer to remove from whole payloads (guard 2). */
  get knownSecrets(): string[] {
    return this.secrets.filter((secret) => secret.length >= MIN_CONFIGURED_SECRET_LENGTH);
  }

  /** The client-side scrub: the configured keys in every form, then the general scrub. */
  protected scrub(text: string): string {
    return redactSecrets(text, this.secrets);
  }

  // Every error this client throws is built here so the configured keys and the
  // credential text patterns are scrubbed before the message exists.
  protected fail(message: string, status: number, endpoint: string): TenableApiError {
    return new TenableApiError(this.scrub(message), status, endpoint);
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
    return (await this.requestDocument(path, init, query)).value;
  }

  /**
   * One request, with the shape guard every 2xx answer passes: a body that is empty
   * or not JSON is not the documented document and is thrown as an unreadable surface
   * carrying the status the request observed, never returned as an empty object. The
   * JSON value is returned with the response so a caller can describe a missing
   * documented member the same way.
   */
  protected async requestDocument(path: string, init: RequestInit = {}, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<TenableDocument> {
    const url = this.buildUrl(path, query);
    const endpoint = endpointLabel(init.method, path);
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
        const message = this.scrub(error instanceof Error ? error.message : String(error));
        const aborted = (error instanceof Error && error.name === "AbortError") || /abort/i.test(message);
        if (aborted) throw this.fail(`Tenable request ${endpoint} timed out after ${this.timeoutMs}ms.`, 0, endpoint);
        if (attempt < this.retryLimit) {
          await this.sleepImpl(Math.min(500 * 2 ** attempt, 15_000));
          continue;
        }
        throw this.fail(`Tenable request ${endpoint} failed without an HTTP response: ${message}`, 0, endpoint);
      }
      clearTimeout(timer);

      if ((response.status === 429 || response.status >= 500) && attempt < this.retryLimit) {
        await this.sleepImpl(retryDelayMs(response, attempt));
        continue;
      }

      const rawText = await response.text();
      if (!response.ok) {
        throw this.fail(`Tenable request ${endpoint} failed (${describeErrorBody(response, rawText, (text) => this.scrub(text))})`, response.status, endpoint);
      }
      const body = rawText.length === 0 ? undefined : parseJsonBody(rawText);
      if (body === undefined) throw this.nonDocument({ value: undefined, response, rawText, endpoint }, { kind: "document" });
      return { value: body.parsed, response, rawText, endpoint };
    }
  }

  protected nonDocument(document: TenableDocument, expected: DocumentExpectation): TenableApiError {
    return this.fail(`Tenable request ${document.endpoint} returned ${describeNonDocumentBody(document.response, document.rawText, expected)}`, document.response.status, document.endpoint);
  }

  // The documented answer is a JSON object; any other JSON value is a foreign document.
  protected async requestObject(path: string, init: RequestInit = {}, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<TenableObjectDocument> {
    const document = await this.requestDocument(path, init, query);
    const payload = asObject(document.value);
    if (payload === undefined) throw this.nonDocument(document, { kind: "object" });
    return { ...document, payload };
  }

  // The documented collection member must be present on every page: an array of records,
  // or null, which Tenable serves for an empty collection on some list endpoints. A 2xx
  // object without the member is a foreign document, not an empty inventory.
  protected documentedRecords(document: TenableObjectDocument, key: string): JsonRecord[] {
    const value = document.payload[key];
    if (!(key in document.payload) || (value !== null && !Array.isArray(value))) throw this.nonDocument(document, { kind: "member", key, type: "array" });
    return asRecords(value);
  }

  // The documented answer is a JSON array of records (a role list, an export chunk).
  protected documentedList(document: TenableDocument): JsonRecord[] {
    if (!Array.isArray(document.value)) throw this.nonDocument(document, { kind: "array" });
    return asRecords(document.value);
  }

  // A documented list is recognised by its records: an array none of whose records
  // carries a member that identifies a documented record (a portal's JSON, another API's
  // list) is a foreign document, never an inventory. An empty array is the documented
  // empty answer.
  protected documentedListOf(document: TenableDocument, members: string[]): JsonRecord[] {
    const records = this.documentedList(document);
    if (records.length > 0 && !records.some((record) => isDocumentedRecord(record, members))) {
      throw this.nonDocument(document, { kind: "records", keys: members, count: records.length });
    }
    return records;
  }

  // A documented object is recognised by any one of the members that identify it; an
  // object carrying none of them (a health page, a portal's JSON) is a foreign document.
  protected documentedObject(document: TenableObjectDocument, keys: string[]): JsonRecord {
    if (!keys.some((key) => key in document.payload)) throw this.nonDocument(document, { kind: "members", keys });
    return document.payload;
  }
}

// One 2xx answer that passed the shape guard, kept with what the request observed so a
// missing documented member can be described by status, media type, and size.
interface TenableDocument {
  value: unknown;
  response: Response;
  rawText: string;
  endpoint: string;
}

interface TenableObjectDocument extends TenableDocument {
  payload: JsonRecord;
}

/**
 * The members that identify a documented record of each array surface: the identity and
 * status fields the verdicts read. A 2xx array none of whose records carries any of them
 * is a foreign document (a portal's JSON, another API's list) and is a failed read (for
 * an export chunk, a failed download), never an empty inventory; a record carrying none
 * of them inside an otherwise documented export chunk is unevaluable and is kept out of
 * the export's records with its count recorded, which caps every verdict that reads the
 * export.
 */
const DOCUMENTED_RECORD_MEMBERS: Record<"roles" | "assets" | "vulns", string[]> = {
  roles: ["uuid", "id", "name", "type", "privileges"],
  assets: ["id", "uuid", "has_agent", "last_seen", "network_id", "tags"],
  vulns: ["state", "severity", "plugin", "asset", "first_found", "last_found"],
};

/** Whether a record carries at least one of the members that identify a documented record of the surface. */
function isDocumentedRecord(record: JsonRecord, members: string[]): boolean {
  return members.some((member) => member in record);
}

/**
 * Outcome of one export workflow. Counters are null when the workflow never
 * observed them (the export was not started, or polling ended before a chunk
 * list was reported). fetchedChunks and downloadFailures count this client's
 * own chunk downloads; failedChunks is Tenable's chunks_failed; unevaluableRecords
 * counts the records of downloaded chunks that carried none of the documented
 * members and were kept out of records. endpoint names the request that reported
 * the final state or the one that failed.
 */
export interface TenableExportResult {
  kind: "assets" | "vulns" | null;
  exportUuid: string | null;
  status: string | null;
  records: JsonRecord[];
  totalChunks: number | null;
  availableChunks: number | null;
  fetchedChunks: number | null;
  failedChunks: number | null;
  downloadFailures: number | null;
  unevaluableRecords: number | null;
  truncated: boolean | null;
  reason?: string;
  endpoint: string | null;
  httpStatus: number | null;
}

export interface TenablePage {
  items: JsonRecord[];
  total: number | null;
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
    return (await this.requestObject(path, {}, query)).payload;
  }

  async getRaw(path: string, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<unknown> {
    return this.requestJson(path, {}, query);
  }

  // A read whose documented answer is a JSON array of records recognised by the members
  // that identify them.
  private async getList(path: string, members: string[]): Promise<JsonRecord[]> {
    return this.documentedListOf(await this.requestDocument(path), members);
  }

  // A read whose documented answer is a JSON object carrying the named array member.
  private async getRecords(path: string, key: string, query: Record<string, string | number | boolean | undefined | Array<string | number>> = {}): Promise<JsonRecord[]> {
    return this.documentedRecords(await this.requestObject(path, {}, query), key);
  }

  async post(path: string, body: JsonRecord): Promise<JsonRecord> {
    return (await this.requestObject(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })).payload;
  }

  async listPaginated(
    path: string,
    collectionKey: string,
    query: Record<string, string | number | boolean | undefined | Array<string | number>> = {},
    options: { pageLimit?: number; maxPages?: number } = {},
  ): Promise<TenablePage> {
    const pageLimit = options.pageLimit ?? DEFAULT_PAGE_LIMIT;
    const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
    const items: JsonRecord[] = [];
    let offset = 0;
    let total: number | null = null;
    // Set only when the endpoint signalled the end of the collection (an empty or
    // short page, or the reported total reached). Leaving the loop at maxPages
    // without it means the inventory is partial even when no total was reported.
    let complete = false;
    let reason: string | undefined;
    let previousPageKey: string | undefined;
    for (let page = 0; page < maxPages; page += 1) {
      const document = await this.requestObject(path, {}, { ...query, limit: pageLimit, offset });
      const payload = document.payload;
      const pageItems = this.documentedRecords(document, collectionKey);
      const first = pageItems[0];
      const pageKey = first ? asString(first.uuid) ?? asString(first.id) ?? JSON.stringify(first) : undefined;
      // A page that opens with the same record as the previous one means the endpoint
      // ignored the offset; the walk cannot advance, so it stops as partial.
      if (pageKey !== undefined && pageKey === previousPageKey) {
        reason = `GET ${path} replayed the same page at offset ${offset}, so the walk could not advance`;
        break;
      }
      previousPageKey = pageKey;
      items.push(...pageItems);
      total = asNumber(asObject(payload.pagination)?.total) ?? total;
      offset += pageItems.length;
      if (pageItems.length === 0 || (total !== null && items.length >= total) || (total === null && pageItems.length < pageLimit)) {
        complete = true;
        break;
      }
    }
    if (!complete && reason === undefined) reason = `the walk stopped at the ${maxPages}-page cap`;
    const truncated = !complete || (total !== null && items.length < total);
    return truncated ? { items, total, truncated, reason: reason ?? `only ${items.length} of the reported ${total} records were returned` } : { items, total, truncated };
  }

  async getServerProperties(): Promise<JsonRecord> {
    return this.documentedObject(await this.requestObject("/server/properties"), ["plugin_set", "loaded_plugin_set", "server_version", "nessus_type", "nessus_ui_version", "license"]);
  }

  async listScans(): Promise<JsonRecord[]> {
    return this.getRecords("/scans", "scans");
  }

  async getScanDetails(scanId: string | number): Promise<JsonRecord> {
    return this.documentedObject(await this.requestObject(`/scans/${encodeURIComponent(String(scanId))}`), ["info", "hosts", "history"]);
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return this.getRecords("/policies", "policies");
  }

  async getPolicyDetails(policyId: string | number): Promise<JsonRecord> {
    return this.documentedObject(await this.requestObject(`/policies/${encodeURIComponent(String(policyId))}`), ["uuid", "settings", "plugins", "credentials"]);
  }

  async listScanTemplates(): Promise<JsonRecord[]> {
    return this.getRecords("/editor/scan/templates", "templates");
  }

  async listScanners(): Promise<JsonRecord[]> {
    return (await this.getRecords("/scanners", "scanners")).map(stripScannerCredentials);
  }

  async listAgents(): Promise<TenablePage> {
    return this.listPaginated("/scanners/null/agents", "agents");
  }

  async listAgentGroups(): Promise<JsonRecord[]> {
    return this.getRecords("/scanners/null/agent-groups", "groups");
  }

  async listNetworks(): Promise<TenablePage> {
    return this.listPaginated("/networks", "networks", {}, { pageLimit: 50 });
  }

  async listExclusions(): Promise<TenablePage> {
    return this.listPaginated("/exclusions", "exclusions", {}, { pageLimit: 200 });
  }

  async listCredentials(): Promise<TenablePage> {
    return this.listPaginated("/credentials", "credentials", {}, { pageLimit: 200 });
  }

  async listUsers(): Promise<JsonRecord[]> {
    return this.getRecords("/users", "users", { withRoles: true });
  }

  async listGroups(): Promise<JsonRecord[]> {
    return this.getRecords("/groups", "groups");
  }

  async listRoles(): Promise<JsonRecord[]> {
    return this.getList("/access-control/v1/roles", DOCUMENTED_RECORD_MEMBERS.roles);
  }

  async listPermissions(): Promise<JsonRecord[]> {
    return this.getRecords("/api/v3/access-control/permissions", "permissions");
  }

  async listAccessGroups(): Promise<TenablePage> {
    return this.listPaginated("/v2/access-groups", "access_groups", {}, { pageLimit: 200 });
  }

  async listAuditLogEvents(sinceIso: string): Promise<TenablePage> {
    return this.listPaginated("/audit-log/v1/events", "events", { f: [`date.gte:${sinceIso}`] }, { pageLimit: 5000, maxPages: 20 });
  }

  async listTagCategories(): Promise<TenablePage> {
    return this.listPaginated("/tags/categories", "categories", {}, { pageLimit: 5000 });
  }

  async listTagValues(): Promise<TenablePage> {
    return this.listPaginated("/tags/values", "values", {}, { pageLimit: 5000 });
  }

  async listTargetGroups(): Promise<JsonRecord[]> {
    return this.getRecords("/target-groups", "target_groups");
  }

  async listVulnExportJobs(): Promise<JsonRecord[]> {
    return this.getRecords("/vulns/export/status", "exports");
  }

  async listAssetExportJobs(): Promise<JsonRecord[]> {
    return this.getRecords("/assets/export/status", "exports");
  }

  /**
   * Request, poll, and download an export. Once the export id is known the
   * workflow stops throwing: a status poll that fails, a poll deadline, or a
   * chunk that cannot be downloaded is reported in the result with the request
   * that failed and its observed status, so the caller keeps the export id and
   * every record that did arrive.
   */
  private async runExport(kind: "assets" | "vulns", body: JsonRecord, maxChunks: number): Promise<TenableExportResult> {
    const started = await this.requestObject(`/${kind}/export`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const exportUuid = asString(started.payload.export_uuid);
    if (!exportUuid) throw this.nonDocument(started, { kind: "member", key: "export_uuid", type: "member" });

    const statusPath = `/${kind}/export/${encodeURIComponent(exportUuid)}/status`;
    const statusEndpoint = `GET ${statusPath}`;
    const notRun = (status: string, reason: string, endpoint: string, httpStatus: number | null): TenableExportResult => ({
      kind,
      exportUuid,
      status,
      records: [],
      totalChunks: null,
      availableChunks: null,
      fetchedChunks: null,
      failedChunks: null,
      downloadFailures: null,
      unevaluableRecords: null,
      truncated: null,
      reason,
      endpoint,
      httpStatus,
    });
    const deadline = Date.now() + this.exportTimeoutMs;
    let status: JsonRecord = {};
    for (;;) {
      try {
        // The documented status document always carries the status string; a 2xx object
        // without it is a foreign document and is reported as an unreadable poll rather
        // than polled until the deadline.
        const document = await this.requestObject(statusPath);
        if (typeof document.payload.status !== "string") throw this.nonDocument(document, { kind: "member", key: "status", type: "member" });
        status = document.payload;
      } catch (error) {
        return notRun("STATUS_UNREADABLE", errorMessage(error), errorEndpoint(error) ?? statusEndpoint, errorStatus(error) ?? null);
      }
      const state = asString(status.status)?.toUpperCase();
      if (state === "FINISHED" || state === "ERROR" || state === "CANCELLED") break;
      if (Date.now() >= deadline) {
        return notRun(`TIMEOUT(${redactErrorText(state ?? "unknown")})`, `Export ${exportUuid} did not finish within ${Math.round(this.exportTimeoutMs / 1000)}s; the last ${statusEndpoint} poll reported ${state ?? "no status"}.`, statusEndpoint, null);
      }
      await this.sleepImpl(this.exportPollMs);
    }

    const state = redactErrorText(asString(status.status)?.toUpperCase() ?? "UNKNOWN");
    const reason = asString(status.reason);
    const available = asArray(status.chunks_available).map(asNumber).filter((item): item is number => item !== undefined);
    const failed = asArray(status.chunks_failed).length;
    const totalChunks = asNumber(status.total_chunks) ?? available.length;
    const records: JsonRecord[] = [];
    const downloadErrors: string[] = [];
    const members = DOCUMENTED_RECORD_MEMBERS[kind];
    let fetchedChunks = 0;
    let unevaluableRecords = 0;
    let failedEndpoint: string | undefined;
    let failedStatus: number | undefined;
    for (const chunkId of available.slice(0, maxChunks)) {
      const chunkPath = `/${kind}/export/${encodeURIComponent(exportUuid)}/chunks/${chunkId}`;
      try {
        // A chunk is the documented JSON array of records; a 2xx answer of any other
        // shape, or an array none of whose records carries a documented member, is a
        // failed download, never an empty chunk. Inside a documented chunk a record
        // that carries none of the members is unevaluable: it is kept out of the
        // records and counted, so the verdicts that read the export are capped
        // rather than passed on it.
        const chunkRecords = await this.getList(chunkPath, members);
        const documented = chunkRecords.filter((record) => isDocumentedRecord(record, members));
        records.push(...documented);
        unevaluableRecords += chunkRecords.length - documented.length;
        fetchedChunks += 1;
      } catch (error) {
        downloadErrors.push(errorMessage(error));
        failedEndpoint = failedEndpoint ?? errorEndpoint(error) ?? `GET ${chunkPath}`;
        failedStatus = failedStatus ?? errorStatus(error);
      }
    }
    const reasons = [
      reason ? redactErrorText(reason) : undefined,
      available.length > maxChunks ? `only the first ${maxChunks} of ${available.length} available chunks were requested (max_chunks)` : undefined,
      failed > 0 ? `Tenable reported ${failed} failed chunks` : undefined,
      downloadErrors.length > 0 ? `${downloadErrors.length} chunk downloads failed: ${downloadErrors.slice(0, 3).join("; ")}` : undefined,
    ].filter((item): item is string => Boolean(item));
    return {
      kind,
      exportUuid,
      status: state,
      records,
      totalChunks,
      availableChunks: available.length,
      fetchedChunks,
      failedChunks: failed,
      downloadFailures: downloadErrors.length,
      unevaluableRecords,
      truncated: state !== "FINISHED" || fetchedChunks < available.length || failed > 0 || totalChunks > available.length,
      reason: reasons.length > 0 ? reasons.join("; ") : undefined,
      endpoint: failedEndpoint ?? statusEndpoint,
      httpStatus: failedStatus ?? null,
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

  // Security Center wraps every answer in { type, response, error_code, error_msg, ... }:
  // a non-zero error_code is Security Center's own refusal, and a 2xx object without the
  // response member is a foreign document, not an empty answer.
  private async rest(resource: string, query: Record<string, string | number | undefined> = {}): Promise<{ response: unknown; document: TenableObjectDocument }> {
    const document = await this.requestObject(`/rest/${resource}`, {}, query);
    const payload = document.payload;
    const errorCode = asNumber(payload.error_code);
    if (errorCode !== undefined && errorCode !== 0) {
      throw this.fail(`Tenable Security Center GET /rest/${resource} returned error_code ${errorCode}: ${asString(payload.error_msg) ?? "unknown"}`, 0, `GET /rest/${resource}`);
    }
    if (!("response" in payload)) throw this.nonDocument(document, { kind: "member", key: "response", type: "member" });
    return { response: payload.response, document };
  }

  private async restObject(resource: string, query: Record<string, string | number | undefined> = {}): Promise<JsonRecord> {
    const { response, document } = await this.rest(resource, query);
    const object = asObject(response);
    if (object === undefined) throw this.nonDocument(document, { kind: "member", key: "response", type: "object" });
    return object;
  }

  // A Security Center list arrives either as a bare array or as { usable, manageable }
  // arrays deduplicated by id; a response of any other shape is a foreign document.
  private async restList(resource: string, query: Record<string, string | number | undefined> = {}): Promise<JsonRecord[]> {
    const { response, document } = await this.rest(resource, query);
    if (Array.isArray(response)) return asRecords(response);
    const object = asObject(response);
    if (!object || (!Array.isArray(object.usable) && !Array.isArray(object.manageable))) {
      throw this.nonDocument(document, { kind: "member", key: "response", type: "list" });
    }
    const seen = new Set<string>();
    return [...asRecords(object.usable), ...asRecords(object.manageable)].filter((item) => {
      const id = asString(item.id) ?? JSON.stringify(item);
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  }

  async getCurrentUser(): Promise<JsonRecord> {
    return this.restObject("currentUser", { fields: "id,username,role,lastLogin" });
  }

  async listScans(): Promise<JsonRecord[]> {
    return this.restList("scan", { fields: "id,name,status,schedule,policy,repository,credentials,modifiedTime" });
  }

  async listScanResults(startTimeUnix: number): Promise<JsonRecord[]> {
    return this.restList("scanResult", { fields: "id,name,status,startTime,finishTime,scannedIPs,totalIPs", startTime: startTimeUnix });
  }

  async listScanners(): Promise<JsonRecord[]> {
    return this.restList("scanner", { fields: "id,name,status,statusMessage,enabled,version,pluginSet,loadedPluginSet,lastCheckinTime,agentCapable" });
  }

  async listUsers(): Promise<JsonRecord[]> {
    return this.restList("user", { fields: "id,username,status,role,lastLogin,locked,failedLogins,authType" });
  }

  async getFeed(): Promise<JsonRecord> {
    return this.restObject("feed");
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
  return error instanceof TenableApiError && error.status > 0 ? error.status : undefined;
}

function errorEndpoint(error: unknown): string | undefined {
  return error instanceof TenableApiError ? error.endpoint : undefined;
}

function isForbiddenStatus(status: number | undefined | null): boolean {
  return status === 401 || status === 403;
}

function isForbiddenError(error: unknown): boolean {
  return isForbiddenStatus(errorStatus(error));
}

function okDataset<T>(endpoint: string, data: T, seen: number, total: number | null, truncated = false, reason?: string): TenableDataset<T> {
  const dataset: TenableDataset<T> = { data: redactCredentialProperties(data), status: "ok", endpoint, httpStatus: null, seen, total, truncated };
  if (reason) dataset.error = reason;
  return dataset;
}

/**
 * A refused or failed read. The endpoint is the request that actually failed
 * (which may differ from the nominal one, for example a chunk download inside
 * an export) and every collection counter is null because no walk completed.
 */
function failedDataset<T>(endpoint: string, data: T, error: unknown): TenableDataset<T> {
  return {
    data,
    status: isForbiddenError(error) ? "forbidden" : "error",
    endpoint: errorEndpoint(error) ?? endpoint,
    error: errorMessage(error),
    httpStatus: errorStatus(error) ?? null,
    seen: null,
    total: null,
    truncated: null,
  };
}

function notConfiguredDataset<T>(data: T, message: string): TenableDataset<T> {
  return { data, status: "not_configured", endpoint: null, error: message, httpStatus: null, seen: null, total: null, truncated: null };
}

const EMPTY_EXPORT: TenableExportResult = {
  kind: null,
  exportUuid: null,
  status: null,
  records: [],
  totalChunks: null,
  availableChunks: null,
  fetchedChunks: null,
  failedChunks: null,
  downloadFailures: null,
  unevaluableRecords: null,
  truncated: null,
  endpoint: null,
  httpStatus: null,
};

async function collectList(endpoint: string, load: () => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  try {
    const items = await load();
    return okDataset(endpoint, items, items.length, items.length);
  } catch (error) {
    return failedDataset<JsonRecord[]>(endpoint, [], error);
  }
}

async function collectPaginated(endpoint: string, load: () => Promise<TenablePage>): Promise<TenableDataset<JsonRecord[]>> {
  try {
    const page = await load();
    // A walk that stopped at the page cap without a reported total has an unknown
    // size; only a complete walk may use its own length as the total.
    const total = page.total ?? (page.truncated ? null : page.items.length);
    return okDataset(endpoint, page.items, page.items.length, total, page.truncated, page.reason);
  } catch (error) {
    return failedDataset<JsonRecord[]>(endpoint, [], error);
  }
}

async function collectObject(endpoint: string, load: () => Promise<JsonRecord>): Promise<TenableDataset<JsonRecord>> {
  try {
    const value = await load();
    return okDataset(endpoint, value, 1, 1);
  } catch (error) {
    return failedDataset<JsonRecord>(endpoint, {}, error);
  }
}

/**
 * An export that FINISHED with every available chunk downloaded is ok; one that
 * FINISHED but lost chunks (max_chunks, chunks_failed, download errors) is ok
 * and truncated; one that never FINISHED, or FINISHED with chunks none of which
 * could be downloaded, is an error so its emptiness is never judged.
 */
async function collectExport(endpoint: string, load: () => Promise<TenableExportResult>): Promise<TenableDataset<TenableExportResult>> {
  try {
    const result = await load();
    const dataset = okDataset(result.endpoint ?? endpoint, result, result.records.length, null, result.truncated ?? true, result.reason);
    const nothingDownloaded = (result.fetchedChunks ?? 0) === 0 && (result.availableChunks ?? 0) > 0;
    if (result.status !== "FINISHED" || nothingDownloaded) {
      dataset.status = isForbiddenStatus(result.httpStatus) ? "forbidden" : "error";
      dataset.httpStatus = result.httpStatus;
      dataset.error = redactErrorText(result.status !== "FINISHED"
        ? `Export ${result.exportUuid} ended with status ${result.status}${result.reason ? `: ${result.reason}` : ""}.`
        : `Export ${result.exportUuid} FINISHED with ${result.availableChunks} available chunks but none could be downloaded: ${result.reason ?? "unknown"}.`);
      dataset.seen = null;
      dataset.truncated = null;
    }
    return dataset;
  } catch (error) {
    return failedDataset<TenableExportResult>(endpoint, EMPTY_EXPORT, error);
  }
}

/**
 * Collection warnings for one dataset: the failure of an unread one, the partial
 * view of a truncated one, or the per-item failures of a readable one (for
 * example policy details that were refused for some policies).
 */
// The line reads "<label> dataset: <error>", never "<label>: <error>": a dataset named for
// what it holds (credentials) followed by a colon is a credential pair to the scrub, and
// the whole message after it would be replaced.
function datasetErrors(label: string, dataset: TenableDataset<unknown>): string[] {
  if (dataset.status === "not_configured") return [];
  if (dataset.status !== "ok") return dataset.error ? [`${label} dataset: ${dataset.error}`] : [];
  const lines: string[] = [];
  if (dataset.truncated) {
    lines.push(`${label} dataset: partial view (${dataset.seen ?? "unknown"} of ${dataset.total ?? "unknown"} records retrieved${dataset.error ? `; ${dataset.error}` : ""}).`);
  } else if (dataset.error) {
    lines.push(`${label} dataset: ${dataset.error}`);
  }
  if (unevaluableRecordsOf(dataset) > 0) lines.push(`${label} dataset:${unevaluableRecordsNote(dataset)}`);
  return lines;
}

/*
 * Incomplete inventories. An inventory is incomplete when it was not read (refused or
 * failed) or when its page walk was truncated (a page cap, a stalled or replayed page,
 * or fewer records delivered than pagination.total reports). A count over an incomplete
 * inventory is a lower bound: a positive count is rendered as observed, and a count of
 * zero renders null, because the unread remainder may hold what the seen population did
 * not. Item-level detail (names, labels, per-record entries) is withheld as null while an
 * inventory is incomplete, so no consumer reads a partial list as the population. No
 * finding passes over an inventory it did not read to completion, and a fail that rests
 * on the absence of records becomes warn when the walk was truncated. A platform that is
 * not configured is not an incomplete inventory: no read was attempted and its findings
 * say so.
 */
function isIncomplete(dataset: TenableDataset<unknown>): boolean {
  return dataset.status === "forbidden" || dataset.status === "error" || (dataset.status === "ok" && dataset.truncated === true);
}

function anyIncomplete(datasets: Record<string, TenableDataset<unknown>>): boolean {
  return Object.values(datasets).some(isIncomplete);
}

/** A count over inventories: null when any was not read, null in place of 0 when any is incomplete, otherwise the observed count. */
function boundedCount(count: number, ...datasets: Array<TenableDataset<unknown>>): number | null {
  if (datasets.some((dataset) => dataset.status !== "ok")) return null;
  return count === 0 && datasets.some(isIncomplete) ? null : count;
}

/** Item-level detail over inventories: withheld as null while any is incomplete. */
function detailOrNull<T>(values: T, ...datasets: Array<TenableDataset<unknown>>): T | null {
  return datasets.some(isIncomplete) ? null : values;
}

/** Records in a readable list dataset; null when the list was not collected or was truncated before delivering any. */
function countOrNull(dataset: TenableDataset<unknown[]>): number | null {
  return boundedCount(dataset.status === "ok" ? dataset.data.length : 0, dataset);
}

function recordCount(dataset: TenableDataset<TenableExportResult>): number | null {
  return boundedCount(dataset.status === "ok" ? dataset.data.records.length : 0, dataset);
}

/** The records-seen figure of a collection status: null when a truncated walk delivered none. */
function seenOrNull(dataset: TenableDataset<unknown>): number | null {
  return dataset.status === "ok" && dataset.truncated === true && dataset.seen === 0 ? null : dataset.seen;
}

function isExportResult(value: unknown): value is TenableExportResult {
  const record = asObject(value);
  return record !== undefined && "exportUuid" in record && "unevaluableRecords" in record && Array.isArray(record.records);
}

/** Records of a readable export that carried none of the documented members and were kept out; 0 for any other dataset. */
function unevaluableRecordsOf(dataset: TenableDataset<unknown>): number {
  return dataset.status === "ok" && isExportResult(dataset.data) ? dataset.data.unevaluableRecords ?? 0 : 0;
}

/**
 * The sentence a verdict appends for export records that carried none of the documented
 * members: how many of the exported records were not evaluated, which members would have
 * identified them, and (when given) what that does to the verdict. Empty when every
 * record was documented.
 */
function unevaluableRecordsNote(dataset: TenableDataset<unknown>, consequence?: string): string {
  const unevaluable = unevaluableRecordsOf(dataset);
  if (unevaluable === 0 || !isExportResult(dataset.data)) return "";
  const members = dataset.data.kind === null ? [] : DOCUMENTED_RECORD_MEMBERS[dataset.data.kind];
  return ` ${unevaluable} of ${unevaluable + dataset.data.records.length} exported records carry none of the documented members (${members.join(", ")}) and were not evaluated${consequence ? `, ${consequence}` : ""}.`;
}

const CAPPED_AT_WARN = "so the verdict is capped at warn";

/** "fetched/total" chunk ratio of an export that ran; null when it did not. */
function chunkRatio(dataset: TenableDataset<TenableExportResult>): string | null {
  const { fetchedChunks, totalChunks } = dataset.data;
  return dataset.status === "ok" && fetchedChunks !== null && totalChunks !== null ? `${fetchedChunks}/${totalChunks}` : null;
}

/**
 * Marker written in place of a list or object that was refused, failed, or
 * never requested, so a bundle consumer cannot mistake a denial for an empty
 * inventory. status is the observed HTTP status of the failed request.
 */
function notCollectedMarker(dataset: TenableDataset<unknown>): JsonRecord {
  return {
    collected: false,
    status: dataset.httpStatus,
    dataset_status: dataset.status,
    endpoint: dataset.endpoint,
    error: dataset.error ?? null,
  };
}

function collectedOrMarker<T>(dataset: TenableDataset<T>, project: (data: T) => unknown = (data) => data): unknown {
  return dataset.status === "ok" ? project(dataset.data) : notCollectedMarker(dataset);
}

/**
 * What a readable export writes to core_data: its records when every available chunk
 * was downloaded and every record was documented; otherwise a partial marker around the
 * records it did evaluate (chunks lost to max_chunks, chunks_failed, or failed downloads,
 * and records kept out as unevaluable), so the file is never read as the whole inventory.
 */
function partialExportOrRecords(result: TenableExportResult): unknown {
  const unevaluable = result.unevaluableRecords ?? 0;
  if (!result.truncated && unevaluable === 0) return result.records;
  return {
    collected: true,
    complete: false,
    truncated: result.truncated,
    total_chunks: result.totalChunks,
    available_chunks: result.availableChunks,
    fetched_chunks: result.fetchedChunks,
    failed_chunks: result.failedChunks,
    download_failures: result.downloadFailures,
    unevaluable_records: unevaluable,
    reason: result.reason ?? null,
    records: result.records,
  };
}

// unevaluable_records counts the records of a readable export that carried none of the
// documented members and were kept out of its records; null for a dataset that is not an
// export or was not read.
function collectionStatusOf(dataset: TenableDataset<unknown>): JsonRecord {
  return {
    status: dataset.status,
    endpoint: dataset.endpoint,
    http_status: dataset.httpStatus,
    seen: seenOrNull(dataset),
    total: dataset.total,
    truncated: dataset.truncated,
    unevaluable_records: dataset.status === "ok" && isExportResult(dataset.data) ? dataset.data.unevaluableRecords : null,
    error: dataset.error ?? null,
  };
}

function collectionSummary(datasets: Record<string, TenableDataset<unknown>>): JsonRecord {
  return Object.fromEntries(Object.entries(datasets).map(([name, dataset]) => [name, collectionStatusOf(dataset)]));
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

/**
 * Phrase describing why a dataset is unusable, naming only the request that
 * actually failed and the status that was observed; empty for a readable one.
 */
function describeUnread(dataset: TenableDataset<unknown>): string {
  const observed = dataset.httpStatus === null ? "" : ` with HTTP ${dataset.httpStatus}`;
  switch (dataset.status) {
    case "ok":
      return "";
    case "forbidden":
      return `${dataset.endpoint} refused the API key${observed} (${dataset.error ?? "no error detail"})`;
    case "error":
      return `${dataset.endpoint} failed${observed} (${dataset.error ?? "no error detail"})`;
    case "not_configured":
      return dataset.error ?? "the platform is not configured";
    default: {
      const exhaustive: never = dataset.status;
      throw new Error(`Unhandled dataset status: ${String(exhaustive)}`);
    }
  }
}

/**
 * Manual verdict for a primary inventory that was not collected. A platform
 * that is not configured is described without naming any endpoint, because no
 * request was made; otherwise the summary names the request that failed.
 */
function unreadableFinding(control: number, severity: TenableSeverity, dataset: TenableDataset<unknown>, manualEvidence: string, idSuffix = ""): TenableFinding {
  const summary = dataset.status === "not_configured"
    ? `Not applicable: ${describeUnread(dataset)}, so this control was not assessed. A human must collect ${manualEvidence}.`
    : `Unknown: ${dataset.endpoint} could not be read because ${describeUnread(dataset)}. A human must collect ${manualEvidence}.`;
  // The evidence states the absence in the positive form (not_collected: true): a false
  // leaf appearing under a denied read is the shape an empty or disabled setting takes.
  return finding(control, "manual", severity, summary, {
    not_collected: true,
    endpoint: dataset.endpoint,
    dataset_status: dataset.status,
    http_status: dataset.httpStatus,
    error: dataset.error ?? null,
  }, idSuffix);
}

// The partial-view sentence of a truncated inventory, followed by the unevaluable-record
// sentence of an export some of whose records could not be evaluated.
function partialNote(dataset: TenableDataset<unknown>): string {
  const truncatedNote = dataset.truncated && dataset.status === "ok"
    ? ` Only ${dataset.seen ?? "an unknown number"} of ${dataset.total ?? "unknown"} records were retrieved${dataset.error ? ` (${dataset.error})` : ""}, ${CAPPED_AT_WARN}.`
    : "";
  return `${truncatedNote}${unevaluableRecordsNote(dataset, CAPPED_AT_WARN)}`;
}

// A pass never survives a capped, stuck, or unreadable inventory it depends on, nor an
// export whose chunks carried records that could not be evaluated.
function capForPartial(status: TenableFindingStatus, dataset: TenableDataset<unknown>): TenableFindingStatus {
  if (status === "pass" && (dataset.status !== "ok" || dataset.truncated || unevaluableRecordsOf(dataset) > 0)) return "warn";
  return status;
}

// The partial-view statement of a truncated inventory appears on every branch, not only
// the pass branch the author appended it to: a fail or warn read from a capped or stuck
// walk says how many records it rests on, and the evidence carries the collection flags.
function withPartialView(item: TenableFinding, dataset: TenableDataset<unknown>): TenableFinding {
  const readable = dataset.status === "ok";
  const evidence: JsonRecord = {
    ...item.evidence,
    inventory_truncated: readable ? dataset.truncated : null,
    records_seen: readable ? seenOrNull(dataset) ?? null : null,
    records_total: readable ? dataset.total ?? null : null,
  };
  if (!readable || !dataset.truncated || item.summary.includes(" records were retrieved")) return { ...item, evidence };
  const partial = ` Only ${dataset.seen ?? "an unknown number"} of ${dataset.total ?? "unknown"} records were retrieved${dataset.error ? ` (${dataset.error})` : ""}; the verdict rests on the records retrieved.`;
  return { ...item, summary: `${item.summary}${partial}`, evidence };
}

// Rule 1 corollary: a finding that reads several inventories cannot pass while any of
// them is unreadable, even when the unreadable one only feeds evidence.
function capForUnreadable(status: TenableFindingStatus, ...datasets: Array<TenableDataset<unknown>>): TenableFindingStatus {
  if (status === "pass" && datasets.some((dataset) => dataset.status !== "ok")) return "warn";
  return status;
}

// The corollary extended to truncation: a pass does not survive a secondary inventory
// that was unreadable or truncated, since its unread remainder may hold what the pass
// ruled out.
function capForIncomplete(status: TenableFindingStatus, ...datasets: Array<TenableDataset<unknown>>): TenableFindingStatus {
  if (status === "pass" && datasets.some((dataset) => dataset.status !== "ok" || dataset.truncated === true)) return "warn";
  return status;
}

interface SecondaryInventory {
  dataset: TenableDataset<unknown>;
  consequence: string;
}

/** Note for every unreadable secondary inventory, naming the request that failed and what stays unknown. */
function unreadableNote(inventories: SecondaryInventory[]): string {
  const unread = inventories.filter((inventory) => inventory.dataset.status !== "ok");
  if (unread.length === 0) return "";
  return ` ${unread.map((inventory) => `${describeUnread(inventory.dataset)}, so ${inventory.consequence}`).join("; ")}; the verdict is capped at warn.`;
}

function capForNonAdmin(status: TenableFindingStatus, callerIsAdministrator: boolean | null): TenableFindingStatus {
  if (status === "pass" && callerIsAdministrator !== true) return "warn";
  return status;
}

function nonAdminNote(callerIsAdministrator: boolean | null): string {
  return callerIsAdministrator === true ? "" : " The API key is not confirmed as Administrator, so only objects shared with it are visible and the verdict is capped at warn.";
}

/** true when GET /users exposed full attributes, false when it exposed the reduced shape, null when the list was unread or empty. */
function detectAdministrator(users: TenableDataset<JsonRecord[]>): boolean | null {
  if (users.status !== "ok" || users.data.length === 0) return null;
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
    evaluation.reasons.push(`${detail.endpoint} ${detail.status === "forbidden" ? "was refused" : "failed"}${detail.httpStatus === null ? "" : ` with HTTP ${detail.httpStatus}`} (${detail.error ?? "unknown"})`);
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
  endpoint: string;
  status: "ok" | "forbidden" | "error";
  httpStatus: number | null;
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

const POLICY_DETAILS_ENDPOINT = "GET /policies/{policy_id}";
const SC_NOT_CONFIGURED = "Tenable Security Center is not configured (set TENABLE_SC_URL with TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY, or point TENABLE_URL at the Security Center host)";
const VM_NOT_CONFIGURED = "Tenable Vulnerability Management is not configured (TENABLE_URL points at a Tenable Security Center host, so cloud-only controls do not apply)";

// Each collector is labelled with the request it issues, so a dataset can name
// the request that produced it (or, on failure, the request that actually failed).
async function scDataset(clients: TenableClients, endpoint: string, load: (client: TenableSecurityCenterClient) => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.securityCenter) return notConfiguredDataset<JsonRecord[]>([], SC_NOT_CONFIGURED);
  return collectList(endpoint, () => load(clients.securityCenter as TenableSecurityCenterClient));
}

async function scObject(clients: TenableClients, endpoint: string, load: (client: TenableSecurityCenterClient) => Promise<JsonRecord>): Promise<TenableDataset<JsonRecord>> {
  if (!clients.securityCenter) return notConfiguredDataset<JsonRecord>({}, SC_NOT_CONFIGURED);
  return collectObject(endpoint, () => load(clients.securityCenter as TenableSecurityCenterClient));
}

async function vmList(clients: TenableClients, endpoint: string, load: (client: TenableApiClient) => Promise<JsonRecord[]>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord[]>([], VM_NOT_CONFIGURED);
  return collectList(endpoint, () => load(clients.vm as TenableApiClient));
}

async function vmPaginated(clients: TenableClients, endpoint: string, load: (client: TenableApiClient) => Promise<TenablePage>): Promise<TenableDataset<JsonRecord[]>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord[]>([], VM_NOT_CONFIGURED);
  return collectPaginated(endpoint, () => load(clients.vm as TenableApiClient));
}

async function vmObject(clients: TenableClients, endpoint: string, load: (client: TenableApiClient) => Promise<JsonRecord>): Promise<TenableDataset<JsonRecord>> {
  if (!clients.vm) return notConfiguredDataset<JsonRecord>({}, VM_NOT_CONFIGURED);
  return collectObject(endpoint, () => load(clients.vm as TenableApiClient));
}

async function vmExport(clients: TenableClients, endpoint: string, load: (client: TenableApiClient) => Promise<TenableExportResult>): Promise<TenableDataset<TenableExportResult>> {
  if (!clients.vm) return notConfiguredDataset<TenableExportResult>(EMPTY_EXPORT, VM_NOT_CONFIGURED);
  return collectExport(endpoint, () => load(clients.vm as TenableApiClient));
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

/**
 * One GET /policies/{policy_id} per policy referenced by a visible scan. The
 * dataset is ok while at least one detail was read (per-policy failures stay on
 * the detail records); when every read failed it takes the status of the first
 * failed request, and when the scan list itself was unread no request is made
 * and the dataset mirrors the scan list's failure.
 */
async function collectPolicyDetails(clients: TenableClients, scans: TenableDataset<JsonRecord[]>): Promise<TenableDataset<TenablePolicyDetail[]>> {
  if (!clients.vm) return notConfiguredDataset<TenablePolicyDetail[]>([], VM_NOT_CONFIGURED);
  if (scans.status !== "ok") {
    return {
      data: [],
      status: scans.status === "forbidden" ? "forbidden" : "error",
      endpoint: scans.endpoint,
      error: `policy details were not requested because ${describeUnread(scans)}`,
      httpStatus: scans.httpStatus,
      seen: null,
      total: null,
      truncated: null,
    };
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
    const endpoint = `GET /policies/${encodeURIComponent(policyId)}`;
    const scanNames = scanNamesByPolicy.get(policyId) ?? [];
    try {
      const payload = await client.getPolicyDetails(policyId);
      return { policyId, scanNames, endpoint, status: "ok", httpStatus: null, details: projectPolicyDetails(payload) };
    } catch (error) {
      return {
        policyId,
        scanNames,
        endpoint: errorEndpoint(error) ?? endpoint,
        status: isForbiddenError(error) ? "forbidden" : "error",
        httpStatus: errorStatus(error) ?? null,
        error: errorMessage(error),
        details: {},
      };
    }
  });
  const readable = details.filter((detail) => detail.status === "ok");
  const failed = details.filter((detail) => detail.status !== "ok");
  const allFailed = details.length > 0 && readable.length === 0;
  const dataset: TenableDataset<TenablePolicyDetail[]> = {
    data: details,
    status: allFailed ? (failed.every((detail) => detail.status === "forbidden") ? "forbidden" : "error") : "ok",
    endpoint: allFailed ? failed[0].endpoint : details.length === 0 ? null : POLICY_DETAILS_ENDPOINT,
    httpStatus: allFailed ? failed[0].httpStatus : null,
    seen: allFailed ? null : readable.length,
    total: allFailed ? null : policyIds.length,
    truncated: allFailed ? null : policyIds.length > requested.length,
  };
  if (failed.length > 0) {
    dataset.error = `${failed.length} of ${details.length} policy detail reads failed: ${failed.slice(0, 5).map((detail) => `${detail.endpoint}${detail.httpStatus === null ? "" : ` (HTTP ${detail.httpStatus})`}: ${detail.error ?? detail.status}`).join("; ")}`;
  }
  return dataset;
}

export async function collectTenableScanProgramData(clients: TenableClients, options: TenableAssessmentOptions = {}): Promise<TenableScanProgramData> {
  const now = options.now ?? Date.now();
  const maxChunks = clampInteger(options.maxChunks, DEFAULT_MAX_CHUNKS, 1, 1000);
  const [scans, policies, templates, exclusions, targetGroups, users, assetExport, scScans, scScanResults] = await Promise.all([
    vmList(clients, "GET /scans", (client) => client.listScans()),
    vmList(clients, "GET /policies", (client) => client.listPolicies()),
    vmList(clients, "GET /editor/scan/templates", (client) => client.listScanTemplates()),
    vmPaginated(clients, "GET /exclusions", (client) => client.listExclusions()),
    vmList(clients, "GET /target-groups", (client) => client.listTargetGroups()),
    vmList(clients, "GET /users", (client) => client.listUsers()),
    vmExport(clients, "POST /assets/export", (client) => client.exportAssets(maxChunks)),
    scDataset(clients, "GET /rest/scan", (client) => client.listScans()),
    scDataset(clients, "GET /rest/scanResult", (client) => client.listScanResults(Math.floor((now - DEFAULT_STALE_SCAN_DAYS * DAY_MS) / 1000))),
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
    findings.push(unreadableFinding(1, "high", data.scans, "the scan template list, port ranges, plugin families, and safe-check settings from the Tenable UI"));
    findings.push(unreadableFinding(2, "high", data.scans, "the scan schedule list and last run dates from the Tenable UI"));
    findings.push(unreadableFinding(17, "medium", data.scans, "the list of scheduled compliance audit scans (CIS, DISA STIG, PCI) from the Tenable UI"));
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
    const policySecondaries: SecondaryInventory[] = [
      { dataset: data.templates, consequence: "discovery-only scan detection was not possible" },
      { dataset: data.policies, consequence: "policy names are unknown" },
    ];
    const templateNote = unreadableNote(policySecondaries);
    let policyStatus: TenableFindingStatus;
    let policySummary: string;
    if (scans.length === 0) {
      policyStatus = "fail";
      policySummary = `No scans are visible to this API key (${data.scans.endpoint} returned zero scans), so no scan policy configuration exists to audit; emptiness fails this control.${nonAdminNote(callerIsAdministrator)}`;
    } else if (allDiscovery) {
      policyStatus = "fail";
      policySummary = `All ${scans.length} visible scans use host discovery templates; no vulnerability assessment policy is configured.`;
    } else if (failingPolicies.length > 0) {
      policyStatus = "fail";
      policySummary = `${failingPolicies.length} of ${evaluations.length} scan policies referenced by scans have unsafe settings: ${describe(failingPolicies)}. Settings were read from ${POLICY_DETAILS_ENDPOINT} (settings.safe_checks, settings.portscan_range, plugins family status).`;
    } else if (data.policyDetails.status !== "ok" || (evaluations.length === 0 && scansWithoutPolicy.length === scans.length)) {
      policyStatus = "manual";
      policySummary = evaluations.length === 0 && data.policyDetails.status === "ok"
        ? `Unknown: none of the ${scans.length} visible scans exposes a policy_id, so no policy details could be requested; a human must review port range, plugin families, and safe checks for each scan template in the Tenable UI (Scans > Scan Templates).`
        : `Unknown: policy details could not be read for the ${evaluations.length} policies referenced by scans because ${describeUnread(data.policyDetails)}${data.policyDetails.status === "forbidden" ? "; the details read requires the Standard [32] role and Can View on each scan template" : ""}. A human must collect safe_checks, portscan_range, and enabled plugin families for each template from the Tenable UI.`;
    } else if (unreadablePolicies.length > 0 || unverifiedPolicies.length > 0 || data.policyDetails.truncated) {
      policyStatus = "manual";
      policySummary = `Unknown: ${evaluations.length - unreadablePolicies.length - unverifiedPolicies.length} of ${evaluations.length} referenced scan policies were verified from ${POLICY_DETAILS_ENDPOINT}, but ${unreadablePolicies.length} could not be read and ${unverifiedPolicies.length} do not expose safe_checks or a plugin family map${data.policyDetails.truncated ? `, and only ${data.policyDetails.seen} of ${data.policyDetails.total ?? "unknown"} referenced policies were requested` : ""}: ${describe([...unreadablePolicies, ...unverifiedPolicies])}. A human must review those templates in the Tenable UI before this control can pass.`;
    } else if (warningPolicies.length > 0) {
      policyStatus = "warn";
      policySummary = `All ${evaluations.length} scan policies referenced by scans enable safe checks and at least one plugin family, but ${warningPolicies.length} need review: ${describe(warningPolicies)}.${templateNote}`;
    } else {
      policyStatus = capForNonAdmin(capForUnreadable("pass", data.templates, data.policies), callerIsAdministrator);
      policySummary = `All ${evaluations.length} scan policies referenced by the ${scans.length} visible scans enable safe checks (safe_checks=yes), scan the default or full port range, and keep more than half of their plugin families enabled, per ${POLICY_DETAILS_ENDPOINT}.${scansWithoutPolicy.length > 0 ? ` ${scansWithoutPolicy.length} scans expose no policy_id and were not evaluated.` : ""}${templateNote}${nonAdminNote(callerIsAdministrator)}`;
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
      policy_details_http_status: data.policyDetails.httpStatus,
      policy_details_requested: data.policyDetails.data.length,
      caller_is_administrator: callerIsAdministrator,
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
      caller_is_administrator: callerIsAdministrator,
    }));

    if (data.templates.status !== "ok") {
      findings.push(unreadableFinding(17, "medium", data.templates, "the list of scheduled compliance audit scans (CIS, DISA STIG, PCI) from the Tenable UI"));
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
    findings.push(unreadableFinding(4, "high", data.assetExport, "the credentialed scan ratio from the Tenable asset inventory (Last Authenticated Scan filter)"));
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
      chunks_fetched: chunkRatio(data.assetExport),
      unevaluable_records: unevaluableRecordsOf(data.assetExport),
    }));
  }

  if (data.exclusions.status !== "ok") {
    findings.push(unreadableFinding(13, "medium", data.exclusions, "the scan exclusion list with schedules, targets, and justifications from Settings > Exclusions"));
  } else {
    const exclusions = data.exclusions.data;
    const permanent = exclusions.filter((item) => asBoolean(asObject(item.schedule)?.enabled) !== true);
    const undocumented = exclusions.filter((item) => !asString(item.description));
    const broad = exclusions.filter((item) => exclusionIsBroad(asString(item.members)));
    const issues = new Set([...permanent, ...undocumented, ...broad].map((item) => asString(item.name) ?? asString(item.id) ?? "exclusion"));
    findings.push(withPartialView(finding(
      13,
      exclusions.length === 0 ? capForPartial("pass", data.exclusions) : issues.size === 0 ? capForPartial("pass", data.exclusions) : permanent.length > 0 || broad.length > 0 ? "fail" : "warn",
      "medium",
      exclusions.length === 0
        ? data.exclusions.truncated
          // Zero delivered records under a larger reported total is an unread list, not an empty one.
          ? `${data.exclusions.endpoint} delivered zero exclusions although pagination.total reports ${data.exclusions.total ?? "an unknown count"}, so the exclusion list was not reviewed.${partialNote(data.exclusions)}`
          : `${data.exclusions.endpoint} returned zero exclusions (pagination.total ${data.exclusions.total ?? "not reported"}), so nothing is excluded from scanning; emptiness is compliant for this control.`
        : issues.size === 0
          ? `All ${exclusions.length} exclusions are scheduled, documented, and scoped to narrow targets.${partialNote(data.exclusions)}`
          : `${issues.size} of ${exclusions.length} exclusions need review: ${permanent.length} always-on (schedule.enabled=false), ${undocumented.length} without a description, ${broad.length} covering /16 or wider ranges.`,
      {
        exclusion_count: boundedCount(exclusions.length, data.exclusions),
        pagination_total: data.exclusions.total ?? null,
        permanent_exclusions_count: boundedCount(permanent.length, data.exclusions),
        undocumented_exclusions_count: boundedCount(undocumented.length, data.exclusions),
        broad_exclusions_count: boundedCount(broad.length, data.exclusions),
        permanent_exclusions: detailOrNull(permanent.map((item) => asString(item.name)).slice(0, 50), data.exclusions),
        undocumented_exclusions: detailOrNull(undocumented.map((item) => asString(item.name)).slice(0, 50), data.exclusions),
        broad_exclusions: detailOrNull(broad.map((item) => asString(item.name)).slice(0, 50), data.exclusions),
      },
    ), data.exclusions));
  }

  if (data.targetGroups.status !== "ok") {
    findings.push(unreadableFinding(20, "low", data.targetGroups, "the legacy target group list (deprecated feature) or confirmation that tags replaced target groups"));
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
        ? `No legacy target groups are visible (${data.targetGroups.endpoint} returned an empty list); target groups were deprecated in February 2022 in favor of tags, so emptiness is compliant.${nonAdminNote(callerIsAdministrator)}`
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

  const datasets = {
    scans: data.scans,
    policies: data.policies,
    policy_details: data.policyDetails,
    templates: data.templates,
    exclusions: data.exclusions,
    target_groups: data.targetGroups,
    users: data.users,
    asset_export: data.assetExport,
    sc_scans: data.scScans,
    sc_scan_results: data.scScanResults,
  };
  return {
    title: "Tenable scan program",
    category: "scan_program",
    summary: {
      scan_count: countOrNull(data.scans),
      policy_count: countOrNull(data.policies),
      exclusion_count: countOrNull(data.exclusions),
      target_group_count: countOrNull(data.targetGroups),
      exported_assets: recordCount(data.assetExport),
      caller_is_administrator: callerIsAdministrator,
      ...statusCounts(findings, anyIncomplete(datasets)),
      collection: collectionSummary(datasets),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterSchedule(scans: TenableDataset<JsonRecord[]>, results: TenableDataset<JsonRecord[]>, now: number, staleScanDays: number): TenableFinding {
  if (scans.status !== "ok") {
    return unreadableFinding(2, "high", scans, "the Security Center scan schedule list and recent scan results", "-SC");
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
    summary = `${scheduled.length} recurring Security Center scans exist but ${describeUnread(results)}, so recent completion cannot be confirmed.`;
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
    vmObject(clients, "GET /server/properties", (client) => client.getServerProperties()),
    vmList(clients, "GET /scanners", (client) => client.listScanners()),
    vmPaginated(clients, "GET /scanners/null/agents", (client) => client.listAgents()),
    vmList(clients, "GET /scanners/null/agent-groups", (client) => client.listAgentGroups()),
    vmPaginated(clients, "GET /networks", (client) => client.listNetworks()),
    vmPaginated(clients, "GET /tags/categories", (client) => client.listTagCategories()),
    vmPaginated(clients, "GET /tags/values", (client) => client.listTagValues()),
    vmExport(clients, "POST /assets/export", (client) => client.exportAssets(maxChunks)),
    vmList(clients, "GET /users", (client) => client.listUsers()),
    scDataset(clients, "GET /rest/scanner", (client) => client.listScanners()),
    scObject(clients, "GET /rest/feed", (client) => client.getFeed()),
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
    findings.push(unreadableFinding(3, "high", data.assetExport, "the asset inventory per network and the expected network ranges"));
    findings.push(unreadableFinding(16, "medium", data.assetExport, "the asset tag coverage report from the Tenable UI"));
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
    // Networks are named only when the network inventory was read to completion; over a
    // truncated walk the note counts them and says why they are not named.
    const networkNote = data.networks.status === "ok"
      ? emptyNetworks.length === 0
        ? ""
        : data.networks.truncated
          ? ` ${emptyNetworks.length} of the ${data.networks.data.length} network objects retrieved have no assets; the network inventory was truncated (${data.networks.seen ?? "an unknown number"} of ${data.networks.total ?? "unknown"} records), so they are not named until it is read to completion.`
          : ` Networks without assets: ${emptyNetworks.slice(0, 10).join(", ")}.`
      : ` ${describeUnread(data.networks)}, so networks without assets are unknown.`;
    let status: TenableFindingStatus;
    let summary: string;
    if (assets.length === 0) {
      status = "fail";
      summary = "The asset export finished with zero assets, so no asset inventory exists to compare against expected ranges; emptiness fails this control.";
    } else if (expected !== undefined && expected > 0) {
      const coverage = ratio(fresh.length, expected);
      status = coverage >= 0.95 ? capForIncomplete(capForPartial("pass", data.assetExport), data.networks) : "fail";
      summary = `${fresh.length} assets seen within ${staleAssetDays} days against an expected population of ${expected} (${percent(coverage)} coverage).${undated.length > 0 ? ` ${undated.length} assets have no last_seen date and were not counted.` : ""}${partialNote(data.assetExport)}${partialNote(data.networks)}${unreadableNote([{ dataset: data.networks, consequence: "networks without assets are unknown" }])}`;
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
      networks_without_assets_count: boundedCount(emptyNetworks.length, data.networks),
      networks_without_assets: detailOrNull(emptyNetworks.slice(0, 50), data.networks),
      networks_status: data.networks.status,
      expected_asset_count: expected ?? null,
      export_status: data.assetExport.data.status,
      unevaluable_records: unevaluableRecordsOf(data.assetExport),
    }));

    const tagged = assets.filter((asset) => asRecords(asset.tags).length > 0);
    const categories = data.tagCategories.status === "ok" ? data.tagCategories.data.map((item) => asString(item.name) ?? "category") : [];
    const taggedRatio = ratio(tagged.length, assets.length);
    let tagStatus: TenableFindingStatus;
    let tagSummary: string;
    if (data.tagCategories.status !== "ok") {
      tagStatus = "manual";
      tagSummary = `${describeUnread(data.tagCategories)}; a human must confirm the tag taxonomy for compliance scope, business unit, and environment.`;
    } else if (assets.length === 0) {
      tagStatus = "manual";
      tagSummary = "Zero assets were exported, so tag coverage cannot be measured.";
    } else if (categories.length === 0 && data.tagCategories.truncated) {
      // Zero delivered records under a truncated walk is an unread taxonomy, not an absent one.
      tagStatus = "warn";
      tagSummary = `${data.tagCategories.endpoint} delivered zero tag categories although pagination.total reports ${data.tagCategories.total ?? "an unknown count"}, so the tag taxonomy was not reviewed.${partialNote(data.tagCategories)}`;
    } else if (categories.length === 0) {
      tagStatus = "fail";
      tagSummary = "No tag categories are defined, so assets are not classified for compliance scope, business unit, or environment.";
    } else if (taggedRatio < taggedThreshold) {
      tagStatus = "fail";
      tagSummary = `${percent(taggedRatio)} of ${assets.length} assets carry at least one tag, below the ${percent(taggedThreshold)} threshold (${categories.length} categories defined).`;
    } else {
      tagStatus = capForIncomplete(capForPartial("pass", data.assetExport), data.tagCategories, data.tagValues);
      tagSummary = `${percent(taggedRatio)} of ${assets.length} assets carry at least one tag across ${categories.length} categories. Confirm the categories cover compliance scope, business unit, and environment.${partialNote(data.assetExport)}${partialNote(data.tagCategories)}${partialNote(data.tagValues)}${unreadableNote([{ dataset: data.tagValues, consequence: "the tag value population is unknown" }])}`;
    }
    findings.push(finding(16, tagStatus, "medium", tagSummary, {
      asset_count: assets.length,
      tagged_assets: tagged.length,
      tagged_ratio: taggedRatio,
      threshold: taggedThreshold,
      tag_category_count: countOrNull(data.tagCategories),
      tag_categories: detailOrNull(categories.slice(0, 50), data.tagCategories),
      tag_categories_truncated: data.tagCategories.status === "ok" ? data.tagCategories.truncated : null,
      tag_value_count: countOrNull(data.tagValues),
      tag_values_truncated: data.tagValues.status === "ok" ? data.tagValues.truncated : null,
      unevaluable_records: unevaluableRecordsOf(data.assetExport),
    }));
  }

  const licensedAgents = asNumber(asObject(asObject(data.serverProperties.data)?.license)?.agents);
  if (data.agents.status !== "ok") {
    findings.push(unreadableFinding(5, "high", data.agents, "the agent inventory with status, last connect, and version from Sensors > Agents"));
    findings.push(unreadableFinding(6, "medium", data.agents, "the agent group membership report from Sensors > Agents"));
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
        : `No agents are linked (pagination.total ${data.agents.total ?? "unknown"}). Confirm whether agent deployment is in scope; emptiness cannot pass this control.`;
    } else if (ratio(unhealthy.size, agents.length) > 0.1) {
      status = "fail";
      summary = `${unhealthy.size} of ${agents.length} agents are offline or have not connected in ${agentOfflineDays} days (more than 10%).`;
    } else if (undated.length > 0 || outdated.length > 0 || data.agents.truncated) {
      status = "warn";
      summary = `${agents.length} agents inventoried; ${unhealthy.size} offline or stale, ${undated.length} without last_connect (not counted as healthy), ${outdated.length} below the newest linked version ${newest ?? "unknown"}.${partialNote(data.agents)}`;
    } else {
      status = capForUnreadable("pass", data.serverProperties);
      summary = `All ${agents.length} agents connected within ${agentOfflineDays} days and run version ${newest ?? "unknown"}; ${unhealthy.size} offline.${unreadableNote([{ dataset: data.serverProperties, consequence: "the licensed agent count (license.agents) is unknown" }])}`;
    }
    findings.push(withPartialView(finding(5, status, "high", summary, {
      agent_count: boundedCount(agents.length, data.agents),
      pagination_total: data.agents.total ?? null,
      licensed_agents: licensedAgents ?? null,
      server_properties_status: data.serverProperties.status,
      offline_agents: boundedCount(offline.length, data.agents),
      stale_connect_agents: boundedCount(staleConnect.length, data.agents),
      undated_agents: boundedCount(undated.length, data.agents),
      newest_version: newest ?? null,
      outdated_agents_count: boundedCount(outdated.length, data.agents),
      outdated_agents: detailOrNull(outdated.map((agent) => `${asString(agent.name) ?? agent.id} (${asString(agent.core_version)})`).slice(0, 50), data.agents),
      agent_offline_days: agentOfflineDays,
    }), data.agents));

    const ungrouped = agents.filter((agent) => asRecords(agent.groups).length === 0);
    const groupCount = data.agentGroups.status === "ok" ? data.agentGroups.data.length : null;
    let groupStatus: TenableFindingStatus;
    let groupSummary: string;
    if (agents.length === 0) {
      groupStatus = "manual";
      groupSummary = "No agents are linked, so there is no agent group organization to evaluate.";
    } else if (data.agentGroups.status !== "ok") {
      groupStatus = "manual";
      groupSummary = `${describeUnread(data.agentGroups)}; ${ungrouped.length} of ${agents.length} agents report no group membership.`;
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
    findings.push(withPartialView(finding(6, groupStatus, "medium", groupSummary, {
      agent_count: boundedCount(agents.length, data.agents),
      agent_group_count: groupCount,
      ungrouped_agents_count: boundedCount(ungrouped.length, data.agents),
      ungrouped_agents: detailOrNull(ungrouped.map((agent) => asString(agent.name) ?? asString(agent.id)).slice(0, 50), data.agents),
      groups: detailOrNull(data.agentGroups.status === "ok" ? data.agentGroups.data.map((group) => ({ name: asString(group.name), agents_count: asNumber(group.agents_count) ?? null })).slice(0, 50) : null, data.agentGroups),
      agent_groups_status: data.agentGroups.status,
    }), data.agents));
  }

  const linkedScanners = data.scanners.data.filter((scanner) => asString(scanner.type) !== "local" && asBoolean(scanner.pool) !== true && asBoolean(scanner.group) !== true);
  if (data.scanners.status !== "ok") {
    findings.push(unreadableFinding(7, "high", data.scanners, "the linked scanner list with status, last connect, and Nessus version from Sensors > Nessus Scanners"));
  } else if (data.scanners.data.length === 0) {
    findings.push(finding(7, "manual", "high", `${data.scanners.endpoint} returned zero scanners; even cloud scanners were not visible, so the key cannot see sensors. Collect the scanner inventory from Sensors > Nessus Scanners.`, { scanner_count: 0 }));
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
    findings.push(withPartialView(finding(
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
        caller_is_administrator: callerIsAdministrator,
        unlinked: unlinked.map((scanner) => asString(scanner.name)).slice(0, 50),
        off: off.map((scanner) => asString(scanner.name)).slice(0, 50),
        stale_connect: staleConnect.map((scanner) => asString(scanner.name)).slice(0, 50),
        undated: undated.map((scanner) => asString(scanner.name)).slice(0, 50),
        newest_version: newest ?? null,
        outdated: outdated.map((scanner) => `${asString(scanner.name)} (${asString(scanner.ui_version)})`).slice(0, 50),
      },
    ), data.scanners));
  }

  if (data.serverProperties.status !== "ok") {
    findings.push(unreadableFinding(8, "high", data.serverProperties, "the current plugin set date from Settings > About and each scanner's plugin set"));
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
      summary = `${data.serverProperties.endpoint} did not expose a parseable plugin_set, so plugin currency cannot be confirmed; collect the plugin set date from Settings > About.`;
    } else if (!serverFresh || staleScanners.length > 0) {
      // A stale container plugin set fails on its own; when the scanner list was not read,
      // the scanner clause names the unread read instead of counting zero of zero entries.
      status = "fail";
      const scannerClause = data.scanners.status !== "ok"
        ? `${describeUnread(data.scanners)}, so scanner plugin sets are unverified`
        : `${staleScanners.length} of ${datedScanners.length} scanner entries exposing loaded_plugin_set load a set older than ${pluginStaleHours} hours${staleScanners.length > 0 ? ` (${staleScanners.map((scanner) => asString(scanner.name) ?? asString(scanner.id)).slice(0, 10).join(", ")})` : ""}`;
      summary = `The container plugin set ${asString(data.serverProperties.data.plugin_set) ?? "unknown"} is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old${serverFresh ? "" : ` (older than ${pluginStaleHours} hours)`} and ${scannerClause}.`;
    } else if (data.scanners.status !== "ok") {
      status = "manual";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old, but ${describeUnread(data.scanners)}, so no scanner plugin set could be evaluated; collect each scanner's plugin set from Settings > Sensors.`;
    } else if (datedScanners.length === 0) {
      status = "manual";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old, but ${data.scanners.data.length === 0 ? `${data.scanners.endpoint} returned zero scanners` : `none of the ${data.scanners.data.length} scanner entries exposes a parseable loaded_plugin_set (${undatedScanners.length} scanner instances without one, the rest are cloud scanner pools or groups)`}, so per-scanner plugin currency is not applicable or unverifiable and cannot pass; confirm scanner plugin sets in Settings > Sensors.`;
    } else if (undatedScanners.length > 0 || staleAgents.length > 0) {
      status = "warn";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and ${datedScanners.length} scanner entries load a fresh plugin set, but ${undatedScanners.length} scanner instances expose no parseable plugin set (not counted as current) and ${staleAgents.length} online agents load a plugin set older than ${pluginStaleHours} hours.`;
    } else if (data.agents.status !== "ok") {
      // Agent plugin currency is a verdict input; an unreadable agent list cannot pass.
      status = "warn";
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and all ${datedScanners.length} scanner entries exposing loaded_plugin_set load a set newer than ${pluginStaleHours} hours, but ${describeUnread(data.agents)}, so agent plugin currency is unknown and the verdict is capped at warn.`;
    } else {
      status = capForPartial("pass", data.agents);
      summary = `The container plugin set is ${Math.round((now - serverPluginMs) / 3_600_000)} hours old and all ${datedScanners.length} scanner entries exposing loaded_plugin_set (${linkedScanners.length} linked appliances) load a set newer than ${pluginStaleHours} hours.${partialNote(data.agents)}`;
    }
    findings.push(withPartialView(finding(8, status, "high", summary, {
      plugin_set: asString(data.serverProperties.data.plugin_set) ?? null,
      plugin_set_age_hours: serverPluginMs === undefined ? null : Math.round((now - serverPluginMs) / 3_600_000),
      scanner_entries: countOrNull(data.scanners),
      scanners_status: data.scanners.status,
      evaluated_scanners: data.scanners.status === "ok" ? datedScanners.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loaded_plugin_set)})`).slice(0, 50) : null,
      stale_scanners: data.scanners.status === "ok" ? staleScanners.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loaded_plugin_set)})`).slice(0, 50) : null,
      undated_scanners: data.scanners.status === "ok" ? undatedScanners.map((scanner) => asString(scanner.name)).slice(0, 50) : null,
      stale_online_agents: boundedCount(staleAgents.length, data.agents),
      agents_status: data.agents.status,
      threshold_hours: pluginStaleHours,
    }), data.agents));
  }

  if (data.networks.status !== "ok") {
    findings.push(unreadableFinding(9, "medium", data.networks, "the network object list with assigned scanners from Settings > Sensors > Networks"));
  } else {
    const networks = data.networks.data;
    const withoutScanners = networks.filter((network) => asNumber(network.scanner_count) === 0);
    const unknownCount = networks.filter((network) => asNumber(network.scanner_count) === undefined);
    findings.push(withPartialView(finding(
      9,
      networks.length === 0 ? "manual" : withoutScanners.length > 0 ? "fail" : unknownCount.length > 0 ? "warn" : capForPartial("pass", data.networks),
      "medium",
      networks.length === 0
        ? `${data.networks.endpoint} returned zero network objects; the default network should always exist, so the view is incomplete. Collect the network list from Settings > Sensors > Networks.`
        : withoutScanners.length > 0
          // Names are given only over a network inventory read to completion.
          ? `${withoutScanners.length} of ${networks.length} network objects have no assigned scanners${data.networks.truncated ? "" : `: ${withoutScanners.map((network) => asString(network.name)).slice(0, 10).join(", ")}`}.`
          : unknownCount.length > 0
            ? `${networks.length} network objects exist but ${unknownCount.length} did not expose scanner_count, so scanner assignment cannot be confirmed for them.`
            : `All ${networks.length} network objects have at least one assigned scanner.${partialNote(data.networks)}`,
      {
        network_count: boundedCount(networks.length, data.networks),
        pagination_total: data.networks.total ?? null,
        networks_without_scanners: boundedCount(withoutScanners.length, data.networks),
        networks_without_scanner_count: boundedCount(unknownCount.length, data.networks),
        networks: detailOrNull(networks.map((network) => ({ name: asString(network.name), scanner_count: asNumber(network.scanner_count) ?? null, assets_ttl_days: asNumber(network.assets_ttl_days) ?? null, is_default: asBoolean(network.is_default) ?? null })).slice(0, 50), data.networks),
      },
    ), data.networks));
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

  const datasets = {
    server_properties: data.serverProperties,
    scanners: data.scanners,
    agents: data.agents,
    agent_groups: data.agentGroups,
    networks: data.networks,
    tag_categories: data.tagCategories,
    tag_values: data.tagValues,
    asset_export: data.assetExport,
    users: data.users,
    sc_scanners: data.scScanners,
    sc_feed: data.scFeed,
  };
  return {
    title: "Tenable sensor and asset coverage",
    category: "sensor_coverage",
    summary: {
      exported_assets: recordCount(data.assetExport),
      agent_count: countOrNull(data.agents),
      scanner_entries: countOrNull(data.scanners),
      linked_scanners: boundedCount(linkedScanners.length, data.scanners),
      network_count: countOrNull(data.networks),
      tag_categories: countOrNull(data.tagCategories),
      caller_is_administrator: callerIsAdministrator,
      ...statusCounts(findings, anyIncomplete(datasets)),
      collection: collectionSummary(datasets),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterScanners(scanners: TenableDataset<JsonRecord[]>, feed: TenableDataset<JsonRecord>, now: number, pluginStaleHours: number): TenableFinding {
  if (scanners.status !== "ok") {
    return unreadableFinding(7, "high", scanners, "the Security Center scanner list with status, version, plugin set, and last check-in", "-SC");
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
    summary = `${enabled.length} enabled Security Center scanners report a working status; ${undated.length} expose no lastCheckinTime${feed.status !== "ok" ? ` and ${describeUnread(feed)}` : ""}.`;
  } else {
    status = "pass";
    summary = `All ${enabled.length} enabled Security Center scanners report status 1, checked in within 24 hours, load a plugin set newer than ${pluginStaleHours} hours, and the active plugin feed is not stale.`;
  }
  return withPartialView(finding(7, status, "high", summary, {
    sc_scanner_count: scanners.data.length,
    sc_enabled_scanners: enabled.length,
    sc_unhealthy: unhealthy.map((scanner) => `${asString(scanner.name)} (status ${asString(scanner.status)})`).slice(0, 50),
    sc_stale_checkin: staleCheckin.map((scanner) => asString(scanner.name)).slice(0, 50),
    sc_undated: undated.map((scanner) => asString(scanner.name)).slice(0, 50),
    sc_stale_plugins: stalePlugins.map((scanner) => `${asString(scanner.name)} (${asString(scanner.loadedPluginSet) ?? asString(scanner.pluginSet)})`).slice(0, 50),
    sc_feed_active_stale: feedStale ?? null,
    sc_feed_active_update_time: asString(feedActive?.updateTime) ?? null,
  }, "-SC"), scanners);
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
    vmList(clients, "GET /users", (client) => client.listUsers()),
    vmList(clients, "GET /groups", (client) => client.listGroups()),
    vmList(clients, "GET /access-control/v1/roles", (client) => client.listRoles()),
    vmList(clients, "GET /api/v3/access-control/permissions", (client) => client.listPermissions()),
    vmPaginated(clients, "GET /v2/access-groups", (client) => client.listAccessGroups()),
    vmPaginated(clients, "GET /credentials", (client) => client.listCredentials()),
    vmPaginated(clients, "GET /audit-log/v1/events", (client) => client.listAuditLogEvents(sinceIso)),
    scDataset(clients, "GET /rest/user", (client) => client.listUsers()),
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
    findings.push(unreadableFinding(10, "high", data.users, "the user list with roles, last login, MFA, and enabled state from Settings > Access Control > Users"));
  } else if (data.users.data.length === 0) {
    findings.push(finding(10, "manual", "high", `${data.users.endpoint} returned zero users, which cannot be a complete view because the calling user must exist; collect the user list from Settings > Access Control > Users.`, { user_count: 0 }));
  } else if (callerIsAdministrator !== true) {
    findings.push(finding(10, "manual", "high", `Partial view: ${data.users.endpoint} returned ${data.users.data.length} users but only uuid, id, username, and email are exposed because the API key does not hold the Administrator [64] role. Role, last login, MFA, and enabled attributes require an Administrator key.`, {
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
      summary = `${data.users.endpoint} returned ${users.length} users but none has enabled=true (${missingEnabledFlag.length} expose no enabled flag), so no enabled population exists to verify and the calling user itself is unaccounted for; collect the user list with enabled state, role, and MFA from Settings > Access Control > Users.`;
    } else if (neverLoggedIn.length > 0 || staleApiKeys.length > 0 || lockedOut.length > 0 || repeatedFailures.length > 0 || missingEnabledFlag.length > 0) {
      status = "warn";
      summary = `${admins.length} administrators all enforce SAML or two-factor and no enabled user is inactive past ${inactiveDays} days, but ${neverLoggedIn.length} enabled users have never logged in (not counted as active), ${staleApiKeys.length} have API keys unused for ${inactiveDays} days, ${lockedOut.length} are locked out, ${repeatedFailures.length} show 5 or more failed logins, and ${missingEnabledFlag.length} expose no enabled flag (not counted as enabled).`;
    } else {
      status = capForUnreadable("pass", data.roles);
      summary = `${enabledUsers.length} enabled users, ${admins.length} administrators (threshold ${maxAdmins}) all enforcing SAML-only or two-factor authentication, none inactive past ${inactiveDays} days.${unreadableNote([{ dataset: data.roles, consequence: "custom roles are unknown" }])}`;
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
    findings.push(unreadableFinding(11, "high", data.permissions, "the access control permission list (Settings > Access Control > Permissions) and any legacy access groups"));
  } else if (data.permissions.data.length === 0) {
    findings.push(finding(11, "manual", "high", `${data.permissions.endpoint} returned zero permissions, but Tenable always generates administrator permissions, so the view is incomplete; collect the permission list from Settings > Access Control > Permissions.`, { permission_count: boundedCount(0, data.permissions) }));
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
            ? `${permissions.length} permissions follow least privilege for AllUsers, but ${describeUnread(data.accessGroups)}, so legacy access groups are unverified and the verdict is capped at warn.`
            : `${permissions.length} permissions are defined and none grants AllUsers write-style actions on all assets; no legacy access groups remain.${partialNote(data.accessGroups)}${unreadableNote([{ dataset: data.groups, consequence: "user group membership is unknown" }])}${nonAdminNote(callerIsAdministrator)}`,
      {
        permission_count: boundedCount(permissions.length, data.permissions),
        broad_permissions: detailOrNull(broad.map((permission) => asString(permission.name)).slice(0, 50), data.permissions),
        legacy_access_group_count: boundedCount(legacyAccessGroups.length, data.accessGroups),
        legacy_access_groups: detailOrNull(legacyAccessGroups.map((group) => asString(group.name)).slice(0, 50), data.accessGroups),
        access_groups_status: data.accessGroups.status,
        access_groups_truncated: data.accessGroups.status === "ok" ? data.accessGroups.truncated : null,
        user_groups: countOrNull(data.groups),
      },
    ));
  }

  if (data.credentials.status !== "ok") {
    findings.push(unreadableFinding(12, "medium", data.credentials, "the managed credential inventory with types, owners, and last use from Settings > Credentials"));
  } else if (data.credentials.data.length === 0) {
    findings.push(finding(12, "manual", "medium", `${data.credentials.endpoint} returned zero managed credentials (pagination.total ${data.credentials.total ?? "not reported"}).${data.credentials.truncated ? " The walk was truncated before any record arrived, so the credential list was not reviewed." : ""} Scan-embedded credentials are not listed by the API, so a human must confirm how scan credentials are managed and rotated.`, { credential_count: boundedCount(0, data.credentials), pagination_total: data.credentials.total ?? null, inventory_truncated: data.credentials.truncated }));
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
    findings.push(withPartialView(finding(
      12,
      unused.length > 0 || old.length > 0 ? "warn" : undated.length > 0 ? "warn" : capForPartial("pass", data.credentials),
      "medium",
      unused.length > 0 || old.length > 0
        ? `${credentials.length} managed credentials: ${unused.length} have never been used in a scan, ${old.length} were created over a year ago (the API exposes created_date but no rotation date, so confirm rotation manually).`
        : undated.length > 0
          ? `${credentials.length} managed credentials are all in use, but ${undated.length} expose no created_date.`
          : `All ${credentials.length} managed credentials are in use and were created within the last year across ${types.size} credential types.${partialNote(data.credentials)}`,
      {
        credential_count: boundedCount(credentials.length, data.credentials),
        pagination_total: data.credentials.total ?? null,
        types: Object.fromEntries(types),
        unused_credentials_count: boundedCount(unused.length, data.credentials),
        older_than_one_year_count: boundedCount(old.length, data.credentials),
        unused_credentials: detailOrNull(unused.map((credential) => asString(credential.name)).slice(0, 50), data.credentials),
        older_than_one_year: detailOrNull(old.map((credential) => asString(credential.name)).slice(0, 50), data.credentials),
        undated_credentials: boundedCount(undated.length, data.credentials),
      },
    ), data.credentials));
  }

  if (data.auditLog.status !== "ok") {
    findings.push(unreadableFinding(18, "medium", data.auditLog, `the activity log for the last ${lookbackDays} days from Settings > Activity Logs (Administrator role required)`));
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
      summary = `The activity log returned zero events for the last ${lookbackDays} days (pagination.total ${data.auditLog.total ?? "not reported"}); an active tenant should record logins and API calls, so confirm logging and the date filter.`;
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
      event_count: boundedCount(events.length, data.auditLog),
      pagination_total: data.auditLog.total ?? null,
      inventory_truncated: data.auditLog.truncated,
      lookback_days: lookbackDays,
      deletions: boundedCount(deletes.length, data.auditLog),
      privilege_changes: boundedCount(privilege.length, data.auditLog),
      exclusion_or_template_changes: boundedCount(exclusionOrPolicy.length, data.auditLog),
      failed_actions: boundedCount(failures.length, data.auditLog),
      sensitive_events: boundedCount(sensitive.size, data.auditLog),
      sensitive_samples: detailOrNull([...deletes, ...privilege, ...exclusionOrPolicy].slice(0, 25).map((event) => ({
        received: asString(event.received),
        action: asString(event.action),
        actor: asString(asObject(event.actor)?.name),
        target: asString(asObject(event.target)?.name),
      })), data.auditLog),
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

  const datasets = {
    users: data.users,
    groups: data.groups,
    roles: data.roles,
    permissions: data.permissions,
    access_groups: data.accessGroups,
    credentials: data.credentials,
    audit_log: data.auditLog,
    sc_users: data.scUsers,
  };
  return {
    title: "Tenable access control",
    category: "access_control",
    summary: {
      user_count: countOrNull(data.users),
      permission_count: countOrNull(data.permissions),
      credential_count: countOrNull(data.credentials),
      audit_events: countOrNull(data.auditLog),
      caller_is_administrator: callerIsAdministrator,
      ...statusCounts(findings, anyIncomplete(datasets)),
      collection: collectionSummary(datasets),
    },
    findings,
    errors,
  };
}

function assessSecurityCenterUsers(users: TenableDataset<JsonRecord[]>, now: number, inactiveDays: number): TenableFinding {
  if (users.status !== "ok") {
    return unreadableFinding(10, "high", users, "the Security Center user list with roles, last login, and lock state", "-SC");
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
    vmList(clients, "GET /vulns/export/status", (client) => client.listVulnExportJobs()),
    vmList(clients, "GET /assets/export/status", (client) => client.listAssetExportJobs()),
    vmList(clients, "GET /users", (client) => client.listUsers()),
  ]);
  const [vulnExport, assetExport] = await Promise.all([
    vmExport(clients, "POST /vulns/export", (client) => client.exportVulnerabilities(Math.floor((now - lookbackDays * DAY_MS) / 1000), maxChunks)),
    vmExport(clients, "POST /assets/export", (client) => client.exportAssets(maxChunks)),
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
  // A pass over the two exports never survives a partial asset population, a vulnerability
  // export some of whose records could not be evaluated, or a non-administrator caller.
  const capPopulation = (status: TenableFindingStatus): TenableFindingStatus => capForNonAdmin(capForPartial(capForPartial(status, data.assetExport), data.vulnExport), callerIsAdministrator);
  const populationNote = `${partialNote(data.assetExport)}${unevaluableRecordsNote(data.vulnExport, CAPPED_AT_WARN)}${nonAdminNote(callerIsAdministrator)}`;

  if (data.vulnExport.status !== "ok") {
    findings.push(unreadableFinding(14, "high", data.vulnExport, "the VPR distribution of open findings from Findings > Vulnerabilities"));
    findings.push(unreadableFinding(15, "high", data.vulnExport, "the open finding age by severity and remediation times from Findings > Vulnerabilities"));
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
      vprSummary = `The vulnerability export finished with ${open.length} open findings but ${describeUnread(data.assetExport)}, so the asset population cannot be validated.`;
    } else if (assetCount === 0) {
      vprStatus = "manual";
      vprSummary = "The asset export returned zero assets, so an empty vulnerability set does not demonstrate VPR-based prioritization.";
    } else if (open.length === 0) {
      vprStatus = "manual";
      vprSummary = `No open findings were exported for the last ${lookbackDays} days across ${assetCount} assets, so VPR usage cannot be evaluated; confirm scans are producing findings.${unevaluableRecordsNote(data.vulnExport)}`;
    } else if (data.vulnExport.truncated) {
      vprStatus = "warn";
      vprSummary = `Partial export: ${data.vulnExport.data.fetchedChunks ?? "unknown"} of ${data.vulnExport.data.totalChunks ?? "unknown"} chunks were downloaded (${data.vulnExport.error ?? "partial"}), covering ${open.length} open findings; ${percent(vprCoverage)} of rated findings carry a VPR score.`;
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
      chunks: chunkRatio(data.vulnExport),
      unevaluable_records: unevaluableRecordsOf(data.vulnExport),
      asset_unevaluable_records: unevaluableRecordsOf(data.assetExport),
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
        : `${describeUnread(data.assetExport)}, so the finding population cannot be validated.`;
    } else if (data.vulnExport.truncated) {
      slaStatus = "warn";
      slaSummary = `Partial export (${data.vulnExport.data.fetchedChunks ?? "unknown"} of ${data.vulnExport.data.totalChunks ?? "unknown"} chunks; ${data.vulnExport.error ?? "partial"}): ${overdueTotal} of ${open.length} retrieved open findings exceed their SLA, but unseen chunks may contain more.`;
    } else if (overdue.critical > 0 || overdue.high > 0) {
      slaStatus = "fail";
      slaSummary = `${overdue.critical} critical findings exceed ${sla.critical} days and ${overdue.high} high findings exceed ${sla.high} days (${overdue.medium} medium and ${overdue.low} low also overdue) out of ${open.length} open findings.`;
    } else if (overdue.medium > 0 || overdue.low > 0 || undated > 0) {
      slaStatus = "warn";
      slaSummary = `No critical or high findings exceed SLA, but ${overdue.medium} medium and ${overdue.low} low findings are overdue and ${undated} open findings have no first_found date (not counted as compliant).`;
    } else if (open.length === 0) {
      slaStatus = capPopulation("pass");
      slaSummary = `Zero open findings were exported for the last ${lookbackDays} days from an export that FINISHED completely, against an asset export of ${assetCount} assets.${populationNote}`;
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
      chunks: chunkRatio(data.vulnExport),
      unevaluable_records: unevaluableRecordsOf(data.vulnExport),
      asset_unevaluable_records: unevaluableRecordsOf(data.assetExport),
    }));
  }

  if (data.vulnExportJobs.status !== "ok" && data.assetExportJobs.status !== "ok") {
    const manualEvidence = "evidence of scheduled exports or report schedules from the Tenable UI (Reports) and integration logs";
    findings.push(data.vulnExportJobs.status === "not_configured"
      ? unreadableFinding(19, "medium", data.vulnExportJobs, manualEvidence)
      : finding(19, "manual", "medium", `Unknown: the export job lists could not be read because ${describeUnread(data.vulnExportJobs)} and ${describeUnread(data.assetExportJobs)}. A human must collect ${manualEvidence}.`, {
        not_collected: true,
        vuln_export_jobs: collectionStatusOf(data.vulnExportJobs),
        asset_export_jobs: collectionStatusOf(data.assetExportJobs),
      }));
  } else {
    const ownUuids = new Set([data.vulnExport.data.exportUuid, data.assetExport.data.exportUuid].filter((uuid): uuid is string => typeof uuid === "string" && uuid.length > 0));
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
    const unreadJobLists = unreadableNote([{ dataset: data.vulnExportJobs, consequence: "vulnerability export jobs are unobserved" }, { dataset: data.assetExportJobs, consequence: "asset export jobs are unobserved" }]);
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

  const datasets = {
    vuln_export: data.vulnExport,
    asset_export: data.assetExport,
    vuln_export_jobs: data.vulnExportJobs,
    asset_export_jobs: data.assetExportJobs,
    users: data.users,
  };
  return {
    title: "Tenable vulnerability management",
    category: "vulnerability_management",
    summary: {
      exported_findings: recordCount(data.vulnExport),
      exported_assets: assetCount ?? null,
      vuln_export_status: data.vulnExport.data.status,
      caller_is_administrator: callerIsAdministrator,
      ...statusCounts(findings, anyIncomplete(datasets)),
      collection: collectionSummary(datasets),
    },
    findings,
    errors,
  };
}

// Status counts over a set of findings. With incomplete=true (an inventory the findings
// read was unreadable or truncated) a count of zero renders null: a finding over that
// inventory may be undetermined, so 0 would claim that no finding has the status when
// one may (see "Incomplete inventories"). A positive count is rendered as observed.
function statusCounts(findings: TenableFinding[], incomplete: boolean): JsonRecord {
  const count = (status: TenableFindingStatus): number | null => {
    const total = findings.filter((item) => item.status === status).length;
    return total === 0 && incomplete ? null : total;
  };
  return { pass: count("pass"), warn: count("warn"), fail: count("fail"), manual: count("manual") };
}

/**
 * One access probe. A surface that was not configured carries no endpoint and
 * no count because no request was made; a refused or failed surface names the
 * request that actually failed and the status that was observed, with count
 * null; a readable surface reports the count the response exposed, or null
 * when the response carried no countable collection.
 */
async function probeSurface(
  name: string,
  endpoint: string,
  requiredRole: string,
  load: (() => Promise<unknown>) | undefined,
  count?: (value: unknown) => number | undefined,
): Promise<{ surface: TenableAccessSurface; value: unknown }> {
  if (!load) return { surface: { name, endpoint: null, requiredRole, status: "not_configured", count: null, httpStatus: null }, value: undefined };
  try {
    const value = await load();
    return { surface: { name, endpoint, requiredRole, status: "readable", count: count?.(value) ?? null, httpStatus: null }, value };
  } catch (error) {
    return {
      surface: {
        name,
        endpoint: errorEndpoint(error) ?? endpoint,
        requiredRole,
        status: isForbiddenError(error) ? "forbidden" : "not_readable",
        count: null,
        httpStatus: errorStatus(error) ?? null,
        error: errorMessage(error),
      },
      value: undefined,
    };
  }
}

const listCount = (value: unknown): number | undefined => (Array.isArray(value) ? value.length : undefined);
const pageCount = (value: unknown): number | undefined => asNumber(asObject(value)?.total) ?? listCount(asObject(value)?.items);

function describeSurfaceFailure(surface: TenableAccessSurface): string {
  const observed = surface.httpStatus === null ? "" : ` with HTTP ${surface.httpStatus}`;
  return `${surface.endpoint} ${surface.status === "forbidden" ? "refused the API key" : "failed"}${observed}: ${surface.error ?? "no error detail"}`;
}

export async function checkTenableAccess(clients: TenableClients): Promise<TenableAccessCheckResult> {
  const vm = clients.vm;
  const sc = clients.securityCenter;
  const usersProbe = await probeSurface("users", "GET /users", "Basic (full attributes need Administrator)", vm ? () => vm.listUsers() : undefined, listCount);
  const users = usersProbe.surface.status === "readable" ? asRecords(usersProbe.value) : [];
  const callerIsAdministrator = users.length > 0 ? users.some((user) => asNumber(user.permissions) !== undefined) : null;

  const probes = [
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
  const surfaces = probes.map((probe) => probe.surface);

  const configured = surfaces.filter((surface) => surface.status !== "not_configured");
  const readable = configured.filter((surface) => surface.status === "readable");
  const forbidden = configured.filter((surface) => surface.status === "forbidden");
  const failed = configured.filter((surface) => surface.status === "not_readable");
  const observedRefusals = [...new Set(forbidden.map((surface) => surface.httpStatus).filter((code): code is number => code !== null))].sort();
  const status = configured.length > 0 && readable.length === configured.length && callerIsAdministrator !== false ? "healthy" : "limited";
  const platform = [vm ? `Tenable Vulnerability Management ${displayOrigin(vm.getConfig().baseUrl)}${vm.getConfig().fedramp ? " (FedRAMP)" : ""}` : undefined, sc ? `Tenable Security Center ${displayOrigin(sc.getConfig().baseUrl)}` : undefined].filter(Boolean).join(" + ");
  const roleNote = usersProbe.surface.status === "not_configured"
    ? "Caller role could not be determined because no Tenable Vulnerability Management tenant is configured."
    : usersProbe.surface.status !== "readable"
      ? `Caller role could not be determined because ${describeSurfaceFailure(usersProbe.surface)}.`
      : callerIsAdministrator === null
        ? `Caller role could not be determined because ${usersProbe.surface.endpoint} returned zero users.`
        : callerIsAdministrator
          ? `${usersProbe.surface.endpoint} exposed full user attributes, so the API key holds the Administrator [64] role.`
          : `${usersProbe.surface.endpoint} exposed only uuid, id, username, and email, so the API key is below Administrator; scans, users, permissions, and audit log views will be partial.`;

  return {
    status,
    platform,
    callerIsAdministrator,
    surfaces,
    notes: [
      `Platform: ${platform}.`,
      `${readable.length}/${configured.length} configured audit surfaces are readable; ${forbidden.length} refused the API key${observedRefusals.length > 0 ? ` (HTTP ${observedRefusals.join(", ")})` : ""} and ${failed.length} failed for other reasons.`,
      roleNote,
      // "requires role Basic ...;" never "needs the Basic role:" nor "role ...credentials:": Basic is
      // a Tenable role name and an authentication scheme, so the scrub reads the plain word after
      // it as its value, and a role phrase ending in a credential word before a colon is a pair.
      ...forbidden.map((surface) => `${surface.name} requires role ${surface.requiredRole}; ${describeSurfaceFailure(surface)}`),
      ...failed.map((surface) => `${surface.name} could not be read: ${describeSurfaceFailure(surface)}`),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run tenable_assess_scan_program, tenable_assess_sensor_coverage, tenable_assess_access_control, tenable_assess_vulnerability_management, or tenable_export_audit_bundle."
      : forbidden.length > 0 || callerIsAdministrator === false
        ? "Generate API keys for an Administrator [64] user (Settings > My Account > API Keys) so every surface is readable, or accept manual verdicts for refused surfaces."
        : "Investigate the failed surfaces (the base URL, a proxy or portal answering in place of the API, or a transport fault) before relying on the assessments; findings that read them are demoted to warn or manual.",
  };
}

/** A count is only ever a number for a readable surface; anything else renders as what it is. */
function renderSurfaceCount(surface: TenableAccessSurface): string {
  if (surface.count !== null) return String(surface.count);
  switch (surface.status) {
    case "readable":
      return "unknown";
    case "not_configured":
      return "n/a";
    case "forbidden":
    case "not_readable":
      return "unread";
    default: {
      const exhaustive: never = surface.status;
      throw new Error(`Unhandled surface status: ${String(exhaustive)}`);
    }
  }
}

function formatAccessCheckText(result: TenableAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    renderSurfaceCount(surface),
    surface.httpStatus === null ? "" : String(surface.httpStatus),
    surface.requiredRole,
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Tenable access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "HTTP", "Required role", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function renderSummaryValue(value: unknown): string {
  if (value === null || value === undefined) return "unknown";
  if (typeof value === "number") return String(Number(value.toFixed(2)));
  return String(value);
}

function renderCollectionLine(name: string, status: unknown): string {
  const record = asObject(status) ?? {};
  const detail = record.status === "ok"
    ? `${renderSummaryValue(record.seen)} seen of ${renderSummaryValue(record.total)}${record.truncated === true ? ", truncated" : ""}`
    : `${String(record.status)}${record.http_status !== null && record.http_status !== undefined ? ` (HTTP ${String(record.http_status)})` : ""}`;
  return `  - ${name}: ${detail}`;
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
    .flatMap(([key, value]) => {
      if (key === "collection") {
        return ["- collection:", ...Object.entries(asObject(value) ?? {}).map(([name, status]) => renderCollectionLine(name, status))];
      }
      return [`- ${key}: ${renderSummaryValue(value)}`];
    })
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
  // A category renders a null status count only when an inventory its findings read was
  // incomplete, so the roll-up inherits that state from the category summaries.
  const incomplete = assessments.some((assessment) => ["pass", "warn", "fail", "manual"].some((key) => assessment.summary[key] === null));
  const counts = statusCounts(findings, incomplete);
  const renderCount = (value: unknown): string => value === null ? "none seen (not asserted: an inventory the findings read was incomplete)" : String(value);
  const lines = [
    "# Tenable Audit Executive Summary",
    "",
    `Platform: ${config.vm ? `${displayOrigin(config.vm.baseUrl)}${config.vm.fedramp ? " (FedRAMP)" : ""}` : "Tenable Vulnerability Management not configured"}${config.securityCenter ? `; Tenable Security Center ${displayOrigin(config.securityCenter.baseUrl)}` : ""}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Passing: ${renderCount(counts.pass)}`,
    `- Warning: ${renderCount(counts.warn)}`,
    `- Failing: ${renderCount(counts.fail)}`,
    `- Manual (unknown or not applicable): ${renderCount(counts.manual)}`,
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
    `- \`core_data/\` contains the Tenable API responses used during this assessment. API keys are never written: the configured access and secret keys are removed from every file in every encoded form; policy details are projected to uuid, name, settings, and plugins; scanner linking keys, registration codes, and license blocks are replaced with ${CREDENTIAL_REDACTION_MARKER}; every property whose name denotes a credential is redacted; inside every string value, URL userinfo, credential-named or token-shaped query pairs such as ?token=, token-in-path webhook URLs, header, cookie, and scheme carriers, and private PEM blocks are replaced while the scheme, host, and path are kept; error strings are scrubbed and non-JSON error bodies are described by status and length only.`,
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
  // Guard 2 for every written file: the configured keys in every encoded form.
  const secrets = configuredTenableSecrets(config);
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

  // Every list or object that was refused, failed, or never requested is written
  // as a not-collected marker instead of an empty inventory; a readable but empty
  // list stays []. Readable data was redacted at collection time and is scrubbed
  // once more here before it touches disk.
  const exportRecords = (result: TenableExportResult) => partialExportOrRecords(result);
  const coreData: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/scans.json", collectedOrMarker(scanProgramData.scans)],
    ["core_data/policies.json", collectedOrMarker(scanProgramData.policies)],
    ["core_data/policy_details.json", collectedOrMarker(scanProgramData.policyDetails)],
    ["core_data/scan_templates.json", collectedOrMarker(scanProgramData.templates)],
    ["core_data/exclusions.json", collectedOrMarker(scanProgramData.exclusions)],
    ["core_data/target_groups.json", collectedOrMarker(scanProgramData.targetGroups)],
    ["core_data/assets_export.json", collectedOrMarker(sensorData.assetExport, exportRecords)],
    ["core_data/server_properties.json", collectedOrMarker(sensorData.serverProperties)],
    ["core_data/scanners.json", collectedOrMarker(sensorData.scanners)],
    ["core_data/agents.json", collectedOrMarker(sensorData.agents)],
    ["core_data/agent_groups.json", collectedOrMarker(sensorData.agentGroups)],
    ["core_data/networks.json", collectedOrMarker(sensorData.networks)],
    ["core_data/tag_categories.json", collectedOrMarker(sensorData.tagCategories)],
    ["core_data/tag_values.json", collectedOrMarker(sensorData.tagValues)],
    ["core_data/users.json", collectedOrMarker(accessData.users)],
    ["core_data/groups.json", collectedOrMarker(accessData.groups)],
    ["core_data/roles.json", collectedOrMarker(accessData.roles)],
    ["core_data/permissions.json", collectedOrMarker(accessData.permissions)],
    ["core_data/access_groups.json", collectedOrMarker(accessData.accessGroups)],
    ["core_data/credentials.json", collectedOrMarker(accessData.credentials)],
    ["core_data/audit_log_events.json", collectedOrMarker(accessData.auditLog)],
    ["core_data/vulns_export.json", collectedOrMarker(vulnData.vulnExport, exportRecords)],
    ["core_data/export_jobs.json", {
      vulns: collectedOrMarker(vulnData.vulnExportJobs),
      assets: collectedOrMarker(vulnData.assetExportJobs),
    }],
    ["core_data/security_center.json", {
      scans: collectedOrMarker(scanProgramData.scScans),
      scan_results: collectedOrMarker(scanProgramData.scScanResults),
      scanners: collectedOrMarker(sensorData.scScanners),
      feed: collectedOrMarker(sensorData.scFeed),
      users: collectedOrMarker(accessData.scUsers),
    }],
  ];
  for (const [pathname, value] of coreData) {
    await writeSecureJsonFile(outputDir, pathname, redactCredentialProperties(value), secrets);
  }
  for (const assessment of assessments) {
    await writeSecureJsonFile(outputDir, `analysis/${assessment.category}.json`, redactCredentialProperties(assessment), secrets);
  }
  await writeSecureJsonFile(outputDir, "analysis/findings.json", redactCredentialProperties(findings), secrets);
  await writeSecureJsonFile(outputDir, "metadata.json", {
    generated_at: new Date().toISOString(),
    platform: access.platform,
    source_chain: config.sourceChain,
    caller_is_administrator: access.callerIsAdministrator,
  }, secrets);
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors), secrets);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings), secrets);
  for (const framework of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.slug}/${framework.slug}_compliance_report.md`, buildFrameworkReport(framework.title, framework.prefix, findings), secrets);
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference(), secrets);
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`, secrets);
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

type ToolResult = ReturnType<typeof textResult> & { isError?: boolean };

/** Credentials passed as arguments or present in the environment, known before the clients exist. */
function argumentSecrets(args: CheckAccessArgs): string[] {
  return [
    args.access_key, args.secret_key, args.sc_access_key, args.sc_secret_key,
    process.env.TENABLE_ACCESS_KEY, process.env.TENABLE_SECRET_KEY, process.env.TENABLE_SC_ACCESS_KEY, process.env.TENABLE_SC_SECRET_KEY,
  ].filter((value): value is string => typeof value === "string");
}

/**
 * Runs one tool and removes every configured secret from the whole result (guard 2):
 * the text rendering and the structured details alike, whether the run succeeded or
 * the catch block rendered the error. The clients' secrets include the keys a config
 * file supplied, which the argument list alone cannot name.
 */
async function runSealed(label: string, tool: string, args: CheckAccessArgs, run: (clients: TenableClients) => Promise<ToolResult>): Promise<ToolResult> {
  const secrets = new Set<string>(argumentSecrets(args));
  let clients: TenableClients | undefined;
  try {
    clients = createClients(args);
    for (const secret of configuredTenableSecrets(clients.config)) secrets.add(secret);
    return sealValue(await run(clients), [...secrets]);
  } catch (error) {
    for (const secret of clients ? configuredTenableSecrets(clients.config) : []) secrets.add(secret);
    return sealValue(errorResult(`${label} failed: ${errorMessage(error)}`, { tool }), [...secrets]);
  }
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
      return runSealed(label, name, args, async (clients) => {
        const result = await runAssessment(kind, clients, toAssessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      });
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
      return runSealed("Tenable access check", "tenable_check_access", args, async (clients) => {
        const result = await checkTenableAccess(clients);
        return textResult(formatAccessCheckText(result), { tool: "tenable_check_access", ...result });
      });
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
      return runSealed("Tenable audit bundle export", "tenable_export_audit_bundle", args, async (clients) => {
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
      });
    },
  });
}
