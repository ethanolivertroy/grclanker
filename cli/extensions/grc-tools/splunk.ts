/**
 * Splunk security inspector tools for grclanker.
 *
 * Read-only inspection of Splunk Enterprise and Splunk Cloud Platform through
 * the splunkd management REST API and, when configured, the Splunk Cloud Admin
 * Config Service (ACS). The only POST requests issued are the session-key
 * login and read-only oneshot searches used to confirm audit event flow.
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
import { request as httpsRequest } from "node:https";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../flue/redact.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/splunk";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_ENTRIES = 5000;
const DEFAULT_MAX_ADMINS = 3;
const DEFAULT_MAX_TOKEN_AGE_DAYS = 90;
const DEFAULT_MAX_SESSION_MINUTES = 60;
const DEFAULT_MIN_AUDIT_RETENTION_DAYS = 365;
const DEFAULT_ACS_BASE_URL = "https://admin.splunk.com";
const DEFAULT_CONFIG_FILE = join(homedir(), ".config", "grclanker", "splunk.json");
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 400;
const ADMIN_ROLE_NAMES = new Set(["admin", "sc_admin", "splunk-system-role", "can_delete"]);
const ACS_ALLOWLIST_FEATURES = ["search-api", "hec", "s2s", "search-ui"] as const;
const CORE_APP_PREFIXES = ["splunk_", "splunk-", "SplunkForwarder", "SplunkLightForwarder", "SA-", "DA-", "TA-"];
const CORE_APP_NAMES = new Set([
  "alert_logevent", "alert_webhook", "appsbrowser", "introspection_generator_addon", "launcher", "learned",
  "legacy", "sample_app", "search", "user-prefs", "journald_input", "python_upgrade_readiness_app",
]);

export type SplunkFindingStatus = "pass" | "warn" | "fail" | "manual";
export type SplunkSeverity = "critical" | "high" | "medium" | "low" | "info";
export type SplunkFramework = "fedramp" | "cmmc" | "soc2" | "cis" | "pci" | "stig" | "irap" | "ismap";

export interface SplunkResolvedConfig {
  url: string;
  token?: string;
  username?: string;
  password?: string;
  stack?: string;
  acsToken?: string;
  acsBaseUrl: string;
  verifyTls: boolean;
  timeoutMs: number;
  sourceChain: string[];
}

export interface SplunkFinding {
  id: string;
  control: number;
  title: string;
  severity: SplunkSeverity;
  status: SplunkFindingStatus;
  summary: string;
  evidence: JsonRecord;
  mappings: string[];
}

export interface SplunkAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: SplunkFinding[];
  errors: string[];
}

export interface SplunkAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  /** Entries seen on a readable surface; null when the probe did not succeed or was not configured. */
  count: number | null;
  /** The total splunkd reported for a readable list; null when it was omitted or the probe did not succeed. */
  total: number | null;
  /** Whether a readable list was cut short; null when the probe did not succeed or the surface is not a list. */
  truncated: boolean | null;
  /** The observed HTTP status of a failed probe; null when the probe succeeded or failed before a response. */
  httpStatus: number | null;
  error?: string;
}

/** What a bundle consumer reads in place of a snapshot that was never collected. */
export interface SplunkNotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string;
  error: string;
}

export interface SplunkAccessCheckResult {
  status: "healthy" | "limited";
  url: string;
  deployment: SplunkDeploymentInfo;
  authenticatedAs?: string;
  /** Null when current-context was unreadable, so an unread capability list never renders as empty. */
  capabilities: string[] | null;
  missingCapabilities: string[];
  acsConfigured: boolean;
  surfaces: SplunkAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface SplunkAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface SplunkDeploymentInfo {
  version?: string;
  productType?: string;
  instanceType?: string;
  serverName?: string;
  /** Roles from /services/server/info; null when that endpoint was not read, never an empty list. */
  serverRoles: string[] | null;
  isCloud: boolean;
  source: "server_info" | "url_heuristic" | "unknown";
}

export interface SplunkEntry {
  name: string;
  content: JsonRecord;
  acl: JsonRecord;
}

export interface SplunkListResult {
  entries: SplunkEntry[];
  total: number;
  truncated: boolean;
  /** False when splunkd omitted paging.total, so `total` is only the number of entries seen. */
  totalKnown: boolean;
}

const EMPTY_LIST: SplunkListResult = { entries: [], total: 0, truncated: false, totalKnown: true };

export interface SplunkSearchResult {
  results: JsonRecord[];
}

/** A failed collection names the endpoint whose request failed, when the error carried one. */
type Collected<T> =
  | { ok: true; value: T }
  | { ok: false; error: string; httpStatus?: number; endpoint?: string };

interface ControlDefinition {
  number: number;
  id: string;
  title: string;
  severity: SplunkSeverity;
  mappings: Record<SplunkFramework, string>;
}

export const SPLUNK_FRAMEWORK_LABELS: Record<SplunkFramework, string> = {
  fedramp: "FedRAMP (NIST 800-53 r5)",
  cmmc: "CMMC 2.0",
  soc2: "SOC 2 (TSC)",
  cis: "CIS Splunk Benchmark",
  pci: "PCI-DSS 4.0",
  stig: "DISA STIG",
  irap: "IRAP (ISM)",
  ismap: "ISMAP",
};

function control(
  number: number,
  id: string,
  title: string,
  severity: SplunkSeverity,
  mappings: [string, string, string, string, string, string, string, string],
): ControlDefinition {
  return {
    number,
    id,
    title,
    severity,
    mappings: {
      fedramp: mappings[0],
      cmmc: mappings[1],
      soc2: mappings[2],
      cis: mappings[3],
      pci: mappings[4],
      stig: mappings[5],
      irap: mappings[6],
      ismap: mappings[7],
    },
  };
}

export const SPLUNK_CONTROLS: ControlDefinition[] = [
  control(1, "SPLUNK-AUTH-01", "Authentication method enforcement", "critical", ["IA-2, IA-8", "AC.L2-3.1.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "5.1.1"]),
  control(2, "SPLUNK-AUTH-02", "Password policy compliance", "high", ["IA-5(1)", "IA.L2-3.5.7", "CC6.1", "4.2", "8.3.6", "SRG-APP-000166", "ISM-0421", "5.1.2"]),
  control(3, "SPLUNK-AUTH-03", "Multi-factor authentication", "critical", ["IA-2(1), IA-2(2)", "IA.L2-3.5.3", "CC6.1", "4.3", "8.4.2", "SRG-APP-000149", "ISM-1401", "5.1.3"]),
  control(4, "SPLUNK-AUTH-04", "Session timeout configuration", "medium", ["AC-12", "AC.L2-3.1.10", "CC6.1", "4.5", "8.2.8", "SRG-APP-000295", "ISM-1164", "5.1.4"]),
  control(5, "SPLUNK-AUTH-05", "Concurrent session limits", "medium", ["AC-10", "AC.L2-3.1.11", "CC6.1", "4.6", "8.2.7", "SRG-APP-000190", "ISM-1380", "5.1.5"]),
  control(6, "SPLUNK-AUTH-06", "Authentication token hygiene", "high", ["IA-5(13), SC-12", "IA.L2-3.5.10", "CC6.1, CC6.6", "4.7", "8.6.3", "SRG-APP-000175", "ISM-1590", "5.1.6"]),
  control(7, "SPLUNK-AC-07", "Role-based access control", "critical", ["AC-3, AC-6", "AC.L2-3.1.5", "CC6.3", "5.1", "7.2.1", "SRG-APP-000033", "ISM-1508", "5.2.1"]),
  control(8, "SPLUNK-AC-08", "Admin role minimization", "high", ["AC-6(5)", "AC.L2-3.1.6", "CC6.3", "5.2", "7.2.2", "SRG-APP-000340", "ISM-1509", "5.2.2"]),
  control(9, "SPLUNK-AC-09", "Search head access controls", "high", ["AC-3(7)", "AC.L2-3.1.3", "CC6.1, CC6.3", "5.3", "7.2.3", "SRG-APP-000328", "ISM-0405", "5.2.3"]),
  control(10, "SPLUNK-AC-10", "Index access control", "high", ["AC-3, AC-6(1)", "AC.L2-3.1.4", "CC6.3", "5.4", "7.2.4", "SRG-APP-000340", "ISM-1510", "5.2.4"]),
  control(11, "SPLUNK-AC-11", "Knowledge object permissions", "medium", ["AC-3, AC-6", "AC.L2-3.1.5", "CC6.3, CC6.8", "5.5", "7.2.5", "SRG-APP-000033", "ISM-0405", "5.2.5"]),
  control(12, "SPLUNK-AC-12", "User capabilities audit", "high", ["AC-6(10)", "AC.L2-3.1.7", "CC6.3", "5.6", "7.2.6", "SRG-APP-000342", "ISM-1511", "5.2.6"]),
  control(13, "SPLUNK-DP-13", "TLS/SSL configuration", "critical", ["SC-8, SC-8(1)", "SC.L2-3.13.8", "CC6.1, CC6.7", "6.1", "4.2.1", "SRG-APP-000439", "ISM-1139", "5.3.1"]),
  control(14, "SPLUNK-DP-14", "Data encryption at rest", "high", ["SC-28, SC-28(1)", "SC.L2-3.13.16", "CC6.1, CC6.7", "6.2", "3.5.1", "SRG-APP-000429", "ISM-1080", "5.3.2"]),
  control(15, "SPLUNK-DP-15", "Forwarding encryption", "high", ["SC-8, SC-8(1)", "SC.L2-3.13.8", "CC6.7", "6.3", "4.2.1", "SRG-APP-000442", "ISM-1139", "5.3.3"]),
  control(16, "SPLUNK-DP-16", "HEC token security", "high", ["IA-5, SC-8", "SC.L2-3.13.8", "CC6.6", "6.4", "8.6.2", "SRG-APP-000175", "ISM-1590", "5.3.4"]),
  control(17, "SPLUNK-AUD-17", "Audit logging enabled", "critical", ["AU-2, AU-3, AU-12", "AU.L2-3.3.1", "CC7.2, CC7.3", "7.1", "10.2.1", "SRG-APP-000095", "ISM-0580", "5.4.1"]),
  control(18, "SPLUNK-AUD-18", "Audit log integrity", "high", ["AU-9, AU-9(4)", "AU.L2-3.3.8", "CC7.2", "7.2", "10.3.2", "SRG-APP-000119", "ISM-0859", "5.4.2"]),
  control(19, "SPLUNK-PLAT-19", "IP allow listing", "high", ["SC-7, AC-17", "SC.L2-3.13.1", "CC6.1, CC6.6", "8.1", "1.3.1", "SRG-APP-000142", "ISM-1416", "5.5.1"]),
  control(20, "SPLUNK-PLAT-20", "App installation restrictions", "medium", ["CM-7(5), CM-11", "CM.L2-3.4.8", "CC6.8, CC8.1", "8.2", "6.3.2", "SRG-APP-000386", "ISM-1490", "5.5.2"]),
  control(21, "SPLUNK-PLAT-21", "KV Store access controls", "medium", ["AC-3", "AC.L2-3.1.3", "CC6.3", "8.3", "7.2.1", "SRG-APP-000033", "ISM-0405", "5.5.3"]),
  control(22, "SPLUNK-PLAT-22", "Saved search permissions", "medium", ["AC-3, AC-6", "AC.L2-3.1.5", "CC6.3, CC6.8", "5.7", "7.2.5", "SRG-APP-000033", "ISM-0405", "5.2.7"]),
  control(23, "SPLUNK-PLAT-23", "Splunk-to-Splunk port security", "high", ["SC-8(1), SC-23", "SC.L2-3.13.8", "CC6.7", "6.5", "4.2.1", "SRG-APP-000439", "ISM-1139", "5.3.5"]),
];

const CONTROLS_BY_NUMBER = new Map(SPLUNK_CONTROLS.map((item) => [item.number, item]));

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
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
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value === "string") {
    if (/^(true|1|yes|on|enabled)$/i.test(value.trim())) return true;
    if (/^(false|0|no|off|disabled)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }
  const single = asString(value);
  return single ? single.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("SPLUNK_URL must be an http(s) URL such as https://splunk.example.com:8089.");
  }
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "splunk";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------------------------
// Error-text hygiene (rule 9). Every error string this module records passes through
// scrubErrorText when the API error is constructed and again where the error is recorded. Two
// guards are construction requirements: a value inside any carrier (Authorization, Cookie,
// Set-Cookie, x-api-key and similar headers, cookie or session assignments, URL userinfo and query
// pairs, the Bearer, Basic, SSWS, Token, and ApiKey schemes, credential-named pairs) is removed
// whatever its shape, and a configured secret is removed whatever its shape in its raw,
// JSON-escaped, URL-encoded, base64, and base64url forms. Real token shapes (JWTs, PEM blocks, vendor
// prefixes, hex digests, runs of 16 or more token characters with base64 symbols, scattered digits,
// or token casing) are removed bare. A bare value shaped like a name (words joined by hyphens or
// underscores with at most one digit group, such as prod-us-east-2026) is indistinguishable from a
// resource name and stays; it is caught only inside a carrier or as a configured secret. A
// token-shaped segment of a bare path (preceded by "/" outside a URL: a request target such as
// /api/v1/users/<id>/factors or a config file path) is an identifier the run itself named and stays
// so the endpoint reported is the one requested; inside a URL with a scheme every path segment keeps
// the rule because webhook URLs carry their token there.
// ---------------------------------------------------------------------------------------------

const MIN_CONFIGURED_SECRET_LENGTH = 4;
const LONG_TOKEN_MIN_LENGTH = 16;
const MIN_LETTERS_FOR_CASING = 6;

const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/@"'<>]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=([^&#\s"'<>)\]}]+)/g;
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookies?)(["']?\s*[:=]\s*)(?!\[REDACTED\])[^\s<>"'][^\r\n<>"']*/gi;
// A scheme word spelled as a header scheme followed by a run of 8 or more token characters is a
// credential whatever the run's shape; only the mechanism words vendor prose puts there ("Basic
// authentication", "Bearer credentials") are kept. Lowercase spellings in prose ("token provided")
// are not schemes; inside an Authorization carrier the scheme word is matched case-insensitively.
const SCHEME_VALUE_PATTERN =
  /\b(Bearer|BEARER|Basic|BASIC|Digest|DIGEST|Token|TOKEN|OAuth|OAUTH|Negotiate|NEGOTIATE|NTLM|SSWS|ApiKey|APIKEY|Api-Key|API-KEY)\s+([A-Za-z0-9._~+/=-]{8,})/g;
const SCHEME_PROSE_WORDS = new Set(["authentication", "authorization", "authenticated", "authorized", "credential", "credentials", "challenge"]);
const SCHEME_WORD_PATTERN = /^(?:bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|splunk|hmac)$/i;
const SCHEME_TOKEN_PATTERN = /^(\s+)(?!\[REDACTED\])([^\s"'<>;,()[\]{}]+)/;
const ASSIGNMENT_KEY_PATTERN = /(["']?)\b([A-Za-z][A-Za-z0-9_.-]{0,63})\b(["']?\s*([:=])\s*(["']?))/g;
const ASSIGNMENT_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"'<>;,&()[\]{}]+/y;
const CLAUSE_END_PATTERN = /(?:[)\]}]|[.,;!?](?=\s|$)|[ \t]*(?:\r?\n|$))/y;
const HEADER_NAME_PATTERN = /^(?:[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+|authorization|cookies?)$/i;
const JWT_IN_TEXT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_PATTERN = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;
const HEX_DIGEST_PATTERN = /\b[A-Fa-f0-9]{32,}\b/g;
const VENDOR_TOKEN_PATTERNS: readonly RegExp[] = [
  /\b00[A-Za-z0-9_-]{40}\b/g,
  /\bxox[abopers]-[A-Za-z0-9-]{10,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bya29\.[0-9A-Za-z._-]{20,}/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{10,}/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
];
// "/", ".", ":", "@", "=", and whitespace end a run, so URL path segments, dotted hostnames, and the
// two sides of a pair are judged on their own; "=" joins a run only as trailing base64 padding.
const LONG_TOKEN_RUN_PATTERN = new RegExp(`[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&]))?`, "g");
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_KEY_SHAPE_PATTERN = /^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i;
const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set(["sid", "sig", "pwd", "passwd", "pass", "session", "sessid", "phpsessid", "auth", "nonce", "sas"]);
const EXTRA_CREDENTIAL_KEYS = new Set(["x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-goog-signature", "x-goog-credential", "oauth_signature", "oauth_token", "oauth_verifier", "proxy-authorization"]);

function keySegments(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True when a header, query parameter, or pair name carries a credential; thresholds and file references are exempt. */
function isCredentialCarrierKey(key: string): boolean {
  if (isSensitiveArgumentKey(key)) return true;
  if (SAFE_KEY_SHAPE_PATTERN.test(key)) return false;
  if (EXTRA_CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
  return keySegments(key).some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
}

/** An unquoted value after `word:` is the credential unless it is a short plain word inside running prose ("InvalidAuthenticationToken: Access token has expired"). */
function looksLikeCredentialValue(value: string): boolean {
  if (value.length < 6) return false;
  if (/\d/.test(value) || value.length >= 12 || /[^A-Za-z]/.test(value)) return true;
  return /[a-z][A-Z]/.test(value);
}

/** True when only a closing bracket, clause punctuation, or the end of the line follows `index`, so the word before it stands as a pair value rather than as prose. */
function endsClause(text: string, index: number): boolean {
  CLAUSE_END_PATTERN.lastIndex = index;
  return CLAUSE_END_PATTERN.test(text);
}

function looksLikeAwsSecret(run: string): boolean {
  if (/[/+]/.test(run)) return true;
  return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
}

/** MD5, SHA-1, and SHA-256 digests and hex-encoded keys: 32 or more hex characters mixing letters and digits. */
function looksLikeHexDigest(run: string): boolean {
  return /[A-Fa-f]/.test(run) && /\d/.test(run);
}

/** Token casing changes more often than once every three letters; words, acronyms, and camelCase change at word boundaries only. */
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

/** The long-token rule: a UUID is an identifier; a base64 symbol, a second digit group anywhere in the run, or a "-" or "_" separated segment with token casing makes a token; words joined by "-" or "_" with at most one digit group are a name. */
function looksLikeToken(run: string): boolean {
  if (UUID_PATTERN.test(run)) return false;
  if (/[+=]/.test(run)) return true;
  if ((run.match(DIGIT_GROUP_PATTERN) ?? []).length > 1) return true;
  return run.split(/[-_]/).some((segment) => hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, "")));
}

/** True when the run at `index` is a segment of a bare path: preceded by a path separator and not inside a URL that carries a scheme. */
function isBarePathSegment(text: string, index: number, urlSpans: ReadonlyArray<readonly [number, number]>): boolean {
  if (index === 0 || (text[index - 1] !== "/" && text[index - 1] !== "\\")) return false;
  return !urlSpans.some(([start, end]) => index >= start && index < end);
}

function scrubBareTokens(text: string): string {
  const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
  return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string, offset: number) =>
    looksLikeToken(run) && !isBarePathSegment(text, offset, urlSpans) ? REDACTED : run,
  );
}

function scrubConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
  const values = secrets.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
  if (values.length === 0) return text;
  return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTED);
}

function scrubEmbeddedUrl(match: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(match)?.[0] ?? "";
  const url = match.slice(0, match.length - trailing.length);
  const parts = URL_PARTS_PATTERN.exec(url);
  if (!parts) return match;
  const [, scheme, hostAndPath, query, fragment] = parts;
  return `${scheme}${hostAndPath}${query ? `?${REDACTED}` : ""}${fragment ? `#${REDACTED}` : ""}${trailing}`;
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialCarrierKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

function scrubSchemeValue(match: string, scheme: string, value: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(value)?.[0] ?? "";
  const word = value.slice(0, value.length - trailing.length);
  return SCHEME_PROSE_WORDS.has(word.toLowerCase()) ? match : `${scheme} ${REDACTED}${trailing}`;
}

/**
 * Replaces the value of every credential-named pair: `key=value`, `"key": "value"`, and
 * `Header-Name: value`. Inside a carrier the value goes whatever its shape (an `=` pair, a quoted
 * value, a header name, or a scheme word such as `Authorization: Bearer <token>`, where the scheme is
 * kept and the token removed); only an unquoted word after a plain `name:` that runs on into more
 * prose is judged by shape, so "InvalidAuthenticationToken: Access token has expired" stays legible
 * while "(session_id: value)" and "token: value" at the end of a clause lose the value.
 */
function replaceCredentialAssignments(text: string): string {
  ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator, separatorChar, valueQuote] = match;
    if (whole.length === 0) {
      ASSIGNMENT_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    if (!isCredentialCarrierKey(key)) continue;
    const valueStart = match.index + whole.length;
    ASSIGNMENT_VALUE_PATTERN.lastIndex = valueStart;
    const value = ASSIGNMENT_VALUE_PATTERN.exec(text)?.[0];
    if (value === undefined) continue;
    let kept = "";
    let consumed = value.length;
    if (SCHEME_WORD_PATTERN.test(value)) {
      const token = SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + value.length));
      if (!token) continue;
      kept = `${value}${token[1]}`;
      consumed += token[0].length;
    } else if (
      separatorChar === ":" &&
      valueQuote === "" &&
      !HEADER_NAME_PATTERN.test(key) &&
      !looksLikeCredentialValue(value) &&
      !endsClause(text, valueStart + value.length)
    ) {
      continue;
    }
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${kept}${REDACTED}`;
    last = valueStart + consumed;
    ASSIGNMENT_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * The single redaction pass for error text. Idempotent: text that has been scrubbed once comes
 * back unchanged because `[REDACTED]` matches none of the patterns.
 */
export function scrubErrorText(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
  let scrubbed = text.replace(PEM_BLOCK_PATTERN, REDACTED).replace(PEM_OPEN_PATTERN, REDACTED);
  scrubbed = scrubConfiguredSecrets(scrubbed, secrets)
    .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
    .replace(QUERY_PAIR_PATTERN, scrubQueryPair)
    .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`);
  scrubbed = replaceCredentialAssignments(scrubbed)
    .replace(SCHEME_VALUE_PATTERN, scrubSchemeValue)
    .replace(JWT_IN_TEXT_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
    .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run))
    .replace(HEX_DIGEST_PATTERN, (run) => (looksLikeHexDigest(run) ? REDACTED : run));
  for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
  return scrubBareTokens(scrubbed);
}

/** Describes a response body that is not JSON without copying any of it. */
function describeNonJsonBody(response: Response, rawText: string): string {
  const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() || "unknown content type";
  return `non-JSON body (${contentType}, ${Buffer.byteLength(rawText)} bytes)`;
}

interface ParsedResponseBody {
  payload: JsonRecord;
  /** Set when the body was not a JSON object; the text itself is never kept. */
  nonJsonBody?: string;
}

function parseResponseBody(response: Response, rawText: string): ParsedResponseBody {
  if (rawText.length === 0) return { payload: {} };
  try {
    return { payload: asObject(JSON.parse(rawText)) ?? {} };
  } catch {
    return { payload: {}, nonJsonBody: describeNonJsonBody(response, rawText) };
  }
}

function errorStatus(error: unknown): number | undefined {
  const status = asNumber(asObject(error)?.status ?? asObject(error)?.httpStatus);
  return status;
}

function errorEndpoint(error: unknown): string | undefined {
  return error instanceof SplunkApiError ? error.endpoint : undefined;
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
  if (relativeTarget === ".." || relativeTarget.startsWith("..")) {
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
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const suffix = attempt === 0 ? "" : `-${attempt + 1}`;
    const candidate = resolveSecureOutputPath(root, `${preferredName}-${stamp}${suffix}`);
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

const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
const JSON_ERROR_POSITION_PATTERN = /\bat position (\d+)\b/;

interface ConfigFilePosition {
  line: number;
  column: number;
}

function thrownCode(error: unknown, pattern: RegExp): string | undefined {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  return typeof code === "string" && pattern.test(code) ? code : undefined;
}

/**
 * Read step of the config loader: a missing file is simply absent, every
 * other failure is reported by path and errno code only, never by the
 * filesystem's own wording.
 */
function readConfigFileText(pathname: string): string | undefined {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const code = thrownCode(error, FS_ERROR_CODE_PATTERN);
    if (code === "ENOENT") return undefined;
    throw new Error(`Unable to read Splunk config file ${pathname} (${code ?? "UNREADABLE"})`);
  }
}

/**
 * JSON.parse messages quote a window of the source (or all of it when the
 * file is short), so only an offset matched by a strict pattern is taken
 * from them, and it is turned into a line and column over the text we read.
 */
function jsonErrorPosition(error: unknown, text: string): ConfigFilePosition | undefined {
  if (!(error instanceof SyntaxError)) return undefined;
  const match = JSON_ERROR_POSITION_PATTERN.exec(error.message);
  if (!match) return undefined;
  const offset = Math.min(Number(match[1]), text.length);
  const before = text.slice(0, offset);
  const lineStart = before.lastIndexOf("\n") + 1;
  return { line: before.split("\n").length, column: offset - lineStart + 1 };
}

/** Parse step: fixed text plus path, position, and a fixed code; nothing JSON.parse said or quoted. */
function configFileParseError(pathname: string, position: ConfigFilePosition | undefined): Error {
  const where = position ? ` at line ${position.line}, column ${position.column}` : "";
  return new Error(`Unable to parse Splunk config file: invalid JSON in ${pathname}${where} (INVALID_JSON)`);
}

function readConfigFile(pathname: string | undefined): JsonRecord {
  if (!pathname) return {};
  const text = readConfigFileText(pathname);
  if (text === undefined) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw configFileParseError(pathname, jsonErrorPosition(error, text));
  }
  return asObject(parsed) ?? {};
}

function pickSetting(
  sourceChain: string[],
  key: string,
  argValue: unknown,
  envValue: unknown,
  fileValue: unknown,
): string | undefined {
  const fromArgs = asString(argValue);
  if (fromArgs) {
    sourceChain.push(`arguments-${key}`);
    return fromArgs;
  }
  const fromEnv = asString(envValue);
  if (fromEnv) {
    sourceChain.push(`environment-${key}`);
    return fromEnv;
  }
  const fromFile = asString(fileValue);
  if (fromFile) {
    sourceChain.push(`config-file-${key}`);
    return fromFile;
  }
  return undefined;
}

export function resolveSplunkConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): SplunkResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file) ?? asString(env.SPLUNK_CONFIG_FILE) ?? DEFAULT_CONFIG_FILE;
  const file = readConfigFile(configPath);

  const url = pickSetting(sourceChain, "url", input.url, env.SPLUNK_URL, file.url);
  if (!url) {
    throw new Error("SPLUNK_URL, a url argument, or a config file url is required (for example https://splunk.example.com:8089).");
  }

  const token = pickSetting(sourceChain, "token", input.token, env.SPLUNK_TOKEN, file.token);
  const username = pickSetting(sourceChain, "username", input.username, env.SPLUNK_USERNAME, file.username);
  const password = pickSetting(sourceChain, "password", input.password, env.SPLUNK_PASSWORD, file.password);
  if (!token && !(username && password)) {
    throw new Error("Provide SPLUNK_TOKEN or both SPLUNK_USERNAME and SPLUNK_PASSWORD (arguments or config file also work).");
  }

  const stack = pickSetting(sourceChain, "stack", input.stack, env.SPLUNK_STACK, file.stack);
  const acsToken = pickSetting(sourceChain, "acs-token", input.acs_token, env.SPLUNK_ACS_TOKEN, file.acs_token) ?? token;
  const acsBaseUrl = normalizeBaseUrl(
    pickSetting(sourceChain, "acs-base-url", input.acs_base_url, env.SPLUNK_ACS_BASE_URL, file.acs_base_url) ?? DEFAULT_ACS_BASE_URL,
  );
  const verifyRaw = pickSetting(sourceChain, "verify-ssl", input.verify_ssl, env.SPLUNK_VERIFY_SSL, file.verify_ssl);
  const verifyTls = asBoolean(verifyRaw) !== false;
  const timeoutRaw = asNumber(input.timeout_seconds) ?? asNumber(env.SPLUNK_TIMEOUT) ?? asNumber(file.timeout_seconds);

  return {
    url: normalizeBaseUrl(url),
    token,
    username,
    password,
    stack,
    acsToken: stack ? acsToken : undefined,
    acsBaseUrl,
    verifyTls,
    timeoutMs: parseTimeoutSeconds(timeoutRaw),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class SplunkApiError extends Error {
  readonly status?: number;
  readonly endpoint: string;

  /**
   * The message is scrubbed here as well as at the record point, so an error
   * built anywhere in the client never carries a credential even if a caller
   * stores error.message directly.
   */
  constructor(message: string, endpoint: string, status?: number) {
    super(scrubErrorText(message));
    this.name = "SplunkApiError";
    this.status = status;
    this.endpoint = endpoint;
  }

  /**
   * Builds the error for a response that cannot be used: a body that is not
   * JSON becomes a status-and-length note whatever its content type, a JSON
   * body contributes only splunkd's documented messages[].text (or message)
   * field, and the configured secrets are removed before the pattern pass.
   */
  static fromResponse(endpoint: string, response: Response, body: ParsedResponseBody, secrets: Array<string | undefined>): SplunkApiError {
    const messages = asArray(body.payload.messages)
      .map((item) => asString(asObject(item)?.text))
      .filter((item): item is string => Boolean(item));
    const detail = body.nonJsonBody ?? (messages.join("; ") || asString(body.payload.message) || "");
    const outcome = response.ok ? "returned an unreadable response" : "failed";
    const statusLine = `${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
    return new SplunkApiError(
      scrubErrorText(`Splunk request to ${endpoint} ${outcome} (${statusLine})${detail ? `: ${detail}` : ""}`, secrets),
      endpoint,
      response.status,
    );
  }
}

function headersToRecord(headers: Headers): Record<string, string> {
  const record: Record<string, string> = {};
  headers.forEach((value, key) => {
    record[key] = value;
  });
  return record;
}

/**
 * fetch-compatible implementation that disables TLS verification for a single
 * request through node:https. It never touches process.env.
 */
export function createInsecureTlsFetch(): FetchImpl {
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    if (url.protocol !== "https:") return fetch(input, init);
    const headers = headersToRecord(new Headers(init.headers ?? {}));
    const body = typeof init.body === "string" ? init.body : undefined;
    return new Promise<Response>((resolvePromise, rejectPromise) => {
      const req = httpsRequest(
        url,
        { method: init.method ?? "GET", headers, rejectUnauthorized: false },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const status = res.statusCode ?? 0;
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(res.headers)) {
              if (typeof value === "string") responseHeaders.set(key, value);
            }
            resolvePromise(new Response(status === 204 ? null : Buffer.concat(chunks), {
              status,
              statusText: res.statusMessage ?? "",
              headers: responseHeaders,
            }));
          });
          res.on("error", rejectPromise);
        },
      );
      req.on("error", rejectPromise);
      if (init.signal) {
        init.signal.addEventListener("abort", () => req.destroy(new Error("Request aborted")), { once: true });
      }
      if (body !== undefined) req.write(body);
      req.end();
    });
  };
}

function parseEntry(value: unknown): SplunkEntry | undefined {
  const object = asObject(value);
  if (!object) return undefined;
  return {
    name: asString(object.name) ?? "",
    content: asObject(object.content) ?? {},
    acl: asObject(object.acl) ?? {},
  };
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export class SplunkApiClient {
  private readonly config: SplunkResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly retryAttempts: number;
  private readonly retryDelayMs: number;
  private readonly pageSize: number;
  private readonly maxEntries: number;
  private sessionKey?: string;
  private sessionPromise?: Promise<string>;

  constructor(
    config: SplunkResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      retryAttempts?: number;
      retryDelayMs?: number;
      pageSize?: number;
      maxEntries?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? (config.verifyTls ? fetch : createInsecureTlsFetch());
    this.retryAttempts = clampNumber(options.retryAttempts, DEFAULT_RETRY_ATTEMPTS, 1, 10);
    this.retryDelayMs = clampNumber(options.retryDelayMs, DEFAULT_RETRY_DELAY_MS, 0, 30_000);
    this.pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000);
    this.maxEntries = clampNumber(options.maxEntries, DEFAULT_MAX_ENTRIES, 1, 1_000_000);
  }

  getResolvedConfig(): SplunkResolvedConfig {
    return this.config;
  }

  hasAcs(): boolean {
    return Boolean(this.config.stack && this.config.acsToken);
  }

  private configuredSecrets(): Array<string | undefined> {
    return [this.config.token, this.config.password, this.config.acsToken, this.sessionKey];
  }

  redact(text: string): string {
    return scrubErrorText(text, this.configuredSecrets());
  }

  private buildUrl(base: string, path: string, query: JsonRecord): string {
    const url = new URL(`${base}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async rawRequest(url: string, init: RequestInit, endpoint: string): Promise<Response> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= this.retryAttempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const response = await this.fetchImpl(url, { ...init, signal: controller.signal });
        if (isRetryableStatus(response.status) && attempt < this.retryAttempts) {
          await response.text().catch(() => "");
          await sleep(this.retryDelayMs * 2 ** (attempt - 1));
          continue;
        }
        return response;
      } catch (error) {
        lastError = error;
        if (attempt < this.retryAttempts) {
          await sleep(this.retryDelayMs * 2 ** (attempt - 1));
          continue;
        }
      } finally {
        clearTimeout(timeout);
      }
    }
    throw new SplunkApiError(`Splunk request to ${endpoint} failed: ${this.redact(errorMessage(lastError))}`, endpoint);
  }

  private async readJson(response: Response, endpoint: string): Promise<JsonRecord> {
    // A body that is not JSON (a proxy error page, an HTML sign-in form) is
    // never copied into an error string: SplunkApiError.fromResponse
    // describes it by content type and size only, and a 2xx non-JSON body is
    // an unreadable surface rather than an empty inventory.
    const body = parseResponseBody(response, await response.text());
    if (!response.ok || body.nonJsonBody !== undefined) {
      throw SplunkApiError.fromResponse(endpoint, response, body, this.configuredSecrets());
    }
    return body.payload;
  }

  private async login(): Promise<string> {
    if (!this.config.username || !this.config.password) {
      throw new SplunkApiError("Splunk session login requires SPLUNK_USERNAME and SPLUNK_PASSWORD.", "/services/auth/login");
    }
    const body = new URLSearchParams({
      username: this.config.username,
      password: this.config.password,
      output_mode: "json",
    });
    const response = await this.rawRequest(this.buildUrl(this.config.url, "/services/auth/login", {}), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
    }, "/services/auth/login");
    const payload = await this.readJson(response, "/services/auth/login");
    const sessionKey = asString(payload.sessionKey);
    if (!sessionKey) {
      throw new SplunkApiError("Splunk login response did not include a sessionKey.", "/services/auth/login");
    }
    this.sessionKey = sessionKey;
    return sessionKey;
  }

  private async authorizationHeader(): Promise<string> {
    if (this.config.token) return `Bearer ${this.config.token}`;
    if (this.sessionKey) return `Splunk ${this.sessionKey}`;
    if (!this.sessionPromise) {
      this.sessionPromise = this.login().finally(() => {
        this.sessionPromise = undefined;
      });
    }
    return `Splunk ${await this.sessionPromise}`;
  }

  async getJson(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(this.config.url, path, { ...query, output_mode: "json" });
    const response = await this.rawRequest(url, {
      method: "GET",
      headers: { accept: "application/json", authorization: await this.authorizationHeader() },
    }, path);
    return this.readJson(response, path);
  }

  async postJson(path: string, form: Record<string, string>): Promise<JsonRecord> {
    const url = this.buildUrl(this.config.url, path, { output_mode: "json" });
    const response = await this.rawRequest(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        authorization: await this.authorizationHeader(),
      },
      body: new URLSearchParams(form).toString(),
    }, path);
    return this.readJson(response, path);
  }

  /**
   * Pages with count/offset until paging.total is reached. Every early exit
   * (item cap, a page repeating the previous one because the server ignored
   * offset, or a full page with no paging.total) is reported as truncated so
   * consumers demote; `totalKnown` is false whenever splunkd omitted the total.
   */
  async list(path: string, query: JsonRecord = {}): Promise<SplunkListResult> {
    const entries: SplunkEntry[] = [];
    let offset = 0;
    let total: number | undefined;
    let previousPage: string | undefined;
    const cappedResult = (): SplunkListResult => ({ entries, total: Math.max(total ?? 0, entries.length), truncated: true, totalKnown: total !== undefined });
    for (;;) {
      const payload = await this.getJson(path, { ...query, count: this.pageSize, offset });
      const pageEntries = asArray(payload.entry).map(parseEntry).filter((item): item is SplunkEntry => Boolean(item));
      total = asNumber(asObject(payload.paging)?.total) ?? total;
      const pageKey = pageEntries.map((item) => item.name).join("\n");
      if (pageEntries.length > 0 && pageKey === previousPage) return cappedResult();
      previousPage = pageKey;
      entries.push(...pageEntries);
      offset += pageEntries.length;
      if (pageEntries.length === 0) break;
      if (total !== undefined ? offset >= total : pageEntries.length < this.pageSize) break;
      if (entries.length >= this.maxEntries) return cappedResult();
    }
    const known = total !== undefined;
    return { entries, total: Math.max(total ?? 0, entries.length), truncated: known && entries.length < (total as number), totalKnown: known };
  }

  async getEntry(path: string): Promise<SplunkEntry | undefined> {
    const payload = await this.getJson(path);
    return asArray(payload.entry).map(parseEntry).find((item): item is SplunkEntry => Boolean(item));
  }

  async getServerInfo(): Promise<SplunkEntry | undefined> {
    return this.getEntry("/services/server/info");
  }

  async getCurrentContext(): Promise<SplunkEntry | undefined> {
    return this.getEntry("/services/authentication/current-context");
  }

  async listUsers(): Promise<SplunkListResult> {
    return this.list("/services/authentication/users");
  }

  async listRoles(): Promise<SplunkListResult> {
    return this.list("/services/authorization/roles");
  }

  async listTokens(): Promise<SplunkListResult> {
    return this.list("/services/authorization/tokens");
  }

  async getConfStanzas(file: string): Promise<SplunkListResult> {
    return this.list(`/services/configs/conf-${encodeURIComponent(file)}`);
  }

  async listSamlProviders(): Promise<SplunkListResult> {
    return this.list("/services/authentication/providers/SAML");
  }

  async listLdapProviders(): Promise<SplunkListResult> {
    return this.list("/services/authentication/providers/LDAP");
  }

  async listMfaProviders(vendor: "Duo-MFA" | "Rsa-MFA"): Promise<SplunkListResult> {
    return this.list(`/services/admin/${vendor}`);
  }

  async listIndexes(): Promise<SplunkListResult> {
    return this.list("/services/data/indexes");
  }

  async listHecInputs(): Promise<SplunkListResult> {
    return this.list("/services/data/inputs/http");
  }

  async listCookedTcpInputs(): Promise<SplunkListResult> {
    return this.list("/services/data/inputs/tcp/cooked");
  }

  async listSavedSearches(): Promise<SplunkListResult> {
    return this.list("/servicesNS/-/-/saved/searches");
  }

  async listLookupTableFiles(): Promise<SplunkListResult> {
    return this.list("/servicesNS/-/-/data/lookup-table-files");
  }

  async listApps(): Promise<SplunkListResult> {
    return this.list("/services/apps/local");
  }

  async listKvCollections(): Promise<SplunkListResult> {
    return this.list("/servicesNS/-/-/storage/collections/config");
  }

  async runOneshotSearch(search: string, earliest = "-24h"): Promise<SplunkSearchResult> {
    const payload = await this.postJson("/services/search/jobs", {
      search: search.startsWith("|") || search.startsWith("search ") ? search : `search ${search}`,
      exec_mode: "oneshot",
      earliest_time: earliest,
      latest_time: "now",
      count: "0",
    });
    return { results: asArray(payload.results).map(asObject).filter((item): item is JsonRecord => Boolean(item)) };
  }

  async acsGet(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    if (!this.config.stack || !this.config.acsToken) {
      throw new SplunkApiError("Splunk Cloud ACS is not configured (SPLUNK_STACK and SPLUNK_ACS_TOKEN).", path);
    }
    const base = `${this.config.acsBaseUrl}/${encodeURIComponent(this.config.stack)}/adminconfig/v2`;
    const url = this.buildUrl(base, path, query);
    const response = await this.rawRequest(url, {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${this.config.acsToken}` },
    }, `acs:${path}`);
    return this.readJson(response, `acs:${path}`);
  }

  async acsListAll(path: string, key: string): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    const items: JsonRecord[] = [];
    const keys = [key, key.replace(/-/g, "_"), key.replace(/_/g, "-")];
    let offset = 0;
    let previousPage: string | undefined;
    for (;;) {
      const payload = await this.acsGet(path, { count: this.pageSize, offset });
      const list = keys.map((candidate) => payload[candidate]).find((value) => Array.isArray(value));
      if (list === undefined) {
        throw new SplunkApiError(`ACS response for ${path} did not include a ${key} list (keys: ${Object.keys(payload).join(", ") || "none"}), so the inventory could not be read.`, `acs:${path}`);
      }
      const page = asArray(list).map(asObject).filter((item): item is JsonRecord => Boolean(item));
      const pageKey = JSON.stringify(page.map((item) => asString(item.name) ?? asString(asObject(item.spec)?.name) ?? JSON.stringify(item)));
      if (page.length > 0 && pageKey === previousPage) return { items, truncated: true };
      previousPage = pageKey;
      items.push(...page);
      if (page.length < this.pageSize) return { items, truncated: false };
      offset += page.length;
      if (items.length >= this.maxEntries) return { items, truncated: true };
    }
  }
}

export type SplunkInspectorClient = Pick<
  SplunkApiClient,
  | "getResolvedConfig"
  | "hasAcs"
  | "getServerInfo"
  | "getCurrentContext"
  | "listUsers"
  | "listRoles"
  | "listTokens"
  | "getConfStanzas"
  | "listSamlProviders"
  | "listLdapProviders"
  | "listMfaProviders"
  | "listIndexes"
  | "listHecInputs"
  | "listCookedTcpInputs"
  | "listSavedSearches"
  | "listLookupTableFiles"
  | "listApps"
  | "listKvCollections"
  | "runOneshotSearch"
  | "acsGet"
  | "acsListAll"
>;

function configuredSecretsOf(client: SplunkInspectorClient): Array<string | undefined> {
  const config = client.getResolvedConfig();
  return [config.token, config.password, config.acsToken];
}

/**
 * Every dataset error is recorded here (and in readableSurface for the access
 * check) and nowhere else, so this is where the redaction pass has to run
 * for findings and the bundle, whichever constructor or throw site built the
 * message.
 */
async function collect<T>(client: SplunkInspectorClient, load: () => Promise<T>): Promise<Collected<T>> {
  try {
    return { ok: true, value: await load() };
  } catch (error) {
    return { ok: false, error: scrubErrorText(errorMessage(error), configuredSecretsOf(client)), httpStatus: errorStatus(error), endpoint: errorEndpoint(error) };
  }
}

/**
 * The object written in place of a snapshot that was never collected, so a
 * bundle consumer cannot mistake a denied or failed read for an empty
 * inventory; the endpoint is the one the error came from when it named one.
 */
function notCollectedMarker(item: { error: string; httpStatus?: number; endpoint?: string }, declaredEndpoint: string): SplunkNotCollectedMarker {
  return { collected: false, status: item.httpStatus ?? null, endpoint: item.endpoint ?? declaredEndpoint, error: item.error };
}

async function collectOptionalConf(client: SplunkInspectorClient, file: string): Promise<Collected<SplunkListResult>> {
  const result = await collect(client, () => client.getConfStanzas(file));
  if (!result.ok && result.httpStatus === 404) {
    return { ok: true, value: EMPTY_LIST };
  }
  return result;
}

/**
 * Rule 1 corollary: a finding that read a secondary inventory it could not
 * fully trust (unreadable, or a deployment classification guessed from the
 * URL) keeps its warn, fail, or manual verdict but never stays at pass; each
 * caveat is appended to the summary and listed in the evidence.
 */
function capWithCaveats(item: SplunkFinding, caveats: string[]): SplunkFinding {
  const notes = caveats.filter((caveat) => caveat.length > 0);
  if (notes.length === 0) return item;
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary} ${notes.join(" ")}`,
    evidence: { ...item.evidence, caveats: [...asArray(item.evidence.caveats), ...notes] },
  };
}

function deploymentCaveat(deployment: { info: SplunkDeploymentInfo; collected: Collected<unknown> }): string {
  if (deployment.collected.ok) return "";
  const classification = deployment.info.isCloud ? "Splunk Cloud" : "Splunk Enterprise";
  const basis = deployment.info.source === "url_heuristic" ? "the URL matches *.splunkcloud.com" : "the URL carries no splunkcloud.com marker";
  return `The deployment was classified as ${classification} from the URL heuristic (${basis}) because /services/server/info could not be read (${unreadableCause(deployment.collected)}); confirm the product type before relying on this verdict.`;
}

function collectedErrors(items: Array<[string, Collected<unknown>]>): string[] {
  return items.filter(([, item]) => !item.ok).map(([name, item]) => `${name}: ${item.ok ? "" : item.error}`);
}

function unreadableCause(item: { error: string; httpStatus?: number }): string {
  if (item.httpStatus === 401) return "the credential was rejected (401)";
  if (item.httpStatus === 403) return "the credential lacks the required capability (403)";
  if (item.httpStatus === 404) return "the endpoint was not found on this deployment (404)";
  return `the endpoint could not be read (${item.error.slice(0, 160)})`;
}

function finding(
  controlNumber: number,
  status: SplunkFindingStatus,
  summary: string,
  evidence: JsonRecord = {},
): SplunkFinding {
  const definition = CONTROLS_BY_NUMBER.get(controlNumber);
  if (!definition) throw new Error(`Unknown Splunk control ${controlNumber}`);
  return {
    id: definition.id,
    control: definition.number,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: (Object.keys(SPLUNK_FRAMEWORK_LABELS) as SplunkFramework[]).map(
      (framework) => `${SPLUNK_FRAMEWORK_LABELS[framework]} ${definition.mappings[framework]}`,
    ),
  };
}

/**
 * The endpoint named in the summary is the one the failed request actually
 * went to when the error carried it; the caller's label is only a fallback
 * for errors that did not name their endpoint.
 */
function manualUnreadable(controlNumber: number, endpoint: string, item: { error: string; httpStatus?: number; endpoint?: string }, evidenceNeeded: string): SplunkFinding {
  const named = item.endpoint ?? endpoint;
  return finding(
    controlNumber,
    "manual",
    `Unknown: ${named} could not be evaluated because ${unreadableCause(item)}. Collect manually: ${evidenceNeeded}`,
    { endpoint: named, error: item.error, http_status: item.httpStatus ?? null },
  );
}

function inventoryNote(result: SplunkListResult): JsonRecord {
  return { seen: result.entries.length, total: result.totalKnown ? result.total : null, total_known: result.totalKnown, truncated: result.truncated };
}

function seenVersusTotal(result: SplunkListResult, noun: string): string {
  return result.totalKnown ? `${result.entries.length} of ${result.total} ${noun}` : `${result.entries.length} ${noun} (total unknown)`;
}

function partialView(result: SplunkListResult): boolean {
  return result.truncated || result.total > result.entries.length;
}

function stanza(conf: SplunkListResult, name: string): JsonRecord | undefined {
  return conf.entries.find((entry) => entry.name === name)?.content;
}

function isAdminRoleName(name: string): boolean {
  return ADMIN_ROLE_NAMES.has(name);
}

function roleCapabilities(role: SplunkEntry): string[] {
  return [...new Set([...asStringList(role.content.capabilities), ...asStringList(role.content.imported_capabilities)])];
}

function roleAllowedIndexes(role: SplunkEntry): string[] {
  return [...new Set([...asStringList(role.content.srchIndexesAllowed), ...asStringList(role.content.imported_srchIndexesAllowed)])];
}

function nonAdminRoles(roles: SplunkListResult): SplunkEntry[] {
  return roles.entries.filter((role) => !isAdminRoleName(role.name));
}

function rolesWithoutIndexScope(roles: SplunkEntry[]): string[] {
  return roles.filter((role) => role.content.srchIndexesAllowed === undefined && role.content.imported_srchIndexesAllowed === undefined).map((role) => role.name);
}

function indexPatternCovers(patterns: string[], indexName: string): boolean {
  return patterns.some((pattern) => {
    if (pattern === indexName || pattern === "*") return true;
    if (pattern === "_*") return indexName.startsWith("_");
    if (pattern.endsWith("*")) return indexName.startsWith(pattern.slice(0, -1));
    return false;
  });
}

export function deploymentInfoFrom(serverInfo: SplunkEntry | undefined, url: string): SplunkDeploymentInfo {
  const content = serverInfo?.content ?? {};
  const productType = asString(content.product_type);
  const instanceType = asString(content.instance_type);
  const cloudByInfo = /cloud/i.test(productType ?? "") || /cloud/i.test(instanceType ?? "");
  const cloudByUrl = /\.splunkcloud\.com(:\d+)?$/i.test(new URL(url).host);
  return {
    version: asString(content.version),
    productType,
    instanceType,
    serverName: asString(content.serverName),
    serverRoles: serverInfo ? asStringList(content.server_roles) : null,
    isCloud: serverInfo ? cloudByInfo : cloudByUrl,
    source: serverInfo ? "server_info" : cloudByUrl ? "url_heuristic" : "unknown",
  };
}

function parseSplunkDurationMinutes(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const match = /^(\d+)\s*([smhd]?)$/i.exec(value.trim());
  if (!match) return undefined;
  const amount = Number(match[1]);
  switch (match[2].toLowerCase()) {
    case "s":
      return amount / 60;
    case "m":
      return amount;
    case "h":
    case "":
      return amount * 60;
    case "d":
      return amount * 1440;
    default:
      return undefined;
  }
}

function downgradePassOnPartialInventory(
  findings: SplunkFinding[],
  sources: Array<[string, Collected<SplunkListResult> | undefined]>,
): SplunkFinding[] {
  const partialSources: Array<[string, SplunkListResult]> = [];
  for (const [name, item] of sources) {
    if (item?.ok && partialView(item.value)) partialSources.push([name, item.value]);
  }
  if (partialSources.length === 0) return findings;
  const described = partialSources.map(([name, result]) => `${name} (${seenVersusTotal(result, "entries")})`);
  return findings.map((item) => item.status === "pass"
    ? { ...item, status: "warn", summary: `${item.summary} Downgraded: the ${described.join(", ")} inventory was only partially retrieved, so the verdict cannot be pass.`, evidence: { ...item.evidence, partial_sources: partialSources.map(([name]) => name) } }
    : item);
}

function summarizeStatuses(findings: SplunkFinding[]): JsonRecord {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

async function loadDeployment(client: SplunkInspectorClient): Promise<{ info: SplunkDeploymentInfo; collected: Collected<SplunkEntry | undefined> }> {
  const collected = await collect(client, () => client.getServerInfo());
  return { info: deploymentInfoFrom(collected.ok ? collected.value : undefined, client.getResolvedConfig().url), collected };
}

export interface SplunkAuthenticationOptions {
  maxTokenAgeDays?: number;
  maxSessionMinutes?: number;
}

export async function assessSplunkAuthentication(
  client: SplunkInspectorClient,
  options: SplunkAuthenticationOptions = {},
): Promise<SplunkAssessmentResult> {
  const maxTokenAgeDays = clampNumber(options.maxTokenAgeDays, DEFAULT_MAX_TOKEN_AGE_DAYS, 1, 3650);
  const maxSessionMinutes = clampNumber(options.maxSessionMinutes, DEFAULT_MAX_SESSION_MINUTES, 1, 100_000);
  const deployment = await loadDeployment(client);
  const [authConf, webConf, serverConf, users, tokens, roles] = await Promise.all([
    collect(client, () => client.getConfStanzas("authentication")),
    collect(client, () => client.getConfStanzas("web")),
    collect(client, () => client.getConfStanzas("server")),
    collect(client, () => client.listUsers()),
    collect(client, () => client.listTokens()),
    collect(client, () => client.listRoles()),
  ]);
  const findings: SplunkFinding[] = [];

  const authStanza = authConf.ok ? stanza(authConf.value, "authentication") : undefined;
  const authType = asString(authStanza?.authType);

  if (!authConf.ok) {
    findings.push(manualUnreadable(1, "/services/configs/conf-authentication", authConf, "authentication.conf [authentication] authType and the SAML or LDAP stanza from the search head."));
  } else if (!authStanza || !authType) {
    findings.push(finding(1, "manual", "Unknown: authentication.conf was readable but the [authentication] stanza or its authType setting was absent; the documented default authType is Splunk (local), so confirm the effective authentication scheme manually.", inventoryNote(authConf.value)));
  } else if (authType === "SAML" || authType === "LDAP") {
    const providers = authType === "SAML" ? await collect(client, () => client.listSamlProviders()) : await collect(client, () => client.listLdapProviders());
    const settingsNames = asStringList(authStanza.authSettings);
    const providerStanzas = settingsNames.map((name) => stanza(authConf.value, name)).filter((item): item is JsonRecord => Boolean(item));
    const disabledProviders = providerStanzas.filter((item) => asBoolean(item.disabled) === true);
    const localUsers = users.ok ? users.value.entries.filter((user) => /^splunk$/i.test(asString(user.content.type) ?? "")) : [];
    const evidence = {
      auth_type: authType,
      auth_settings: settingsNames,
      provider_endpoint_readable: providers.ok,
      provider_entries: providers.ok ? providers.value.entries.map((entry) => entry.name) : null,
      provider_stanzas_in_conf: providerStanzas.length,
      disabled_provider_stanzas: disabledProviders.length,
      local_splunk_users: users.ok ? localUsers.map((user) => user.name).slice(0, 50) : null,
    };
    if (settingsNames.length === 0 || (providerStanzas.length === 0 && !(providers.ok && providers.value.entries.length > 0))) {
      findings.push(finding(1, "fail", `authType=${authType} is set but no ${authType} provider stanza was readable in authentication.conf or the provider endpoint, so enforcement cannot be confirmed.`, evidence));
    } else if (disabledProviders.length > 0) {
      findings.push(finding(1, "fail", `authType=${authType} but ${disabledProviders.length} referenced provider stanza(s) are disabled.`, evidence));
    } else if (!providers.ok) {
      findings.push(finding(1, "warn", `authType=${authType} with provider stanza ${settingsNames.join(", ")} present, but the provider endpoint could not be read (${unreadableCause(providers)}); verify the provider is active.`, evidence));
    } else if (!users.ok) {
      findings.push(finding(1, "warn", `authType=${authType} with an active provider, but the user list could not be read so local break-glass accounts could not be enumerated.`, evidence));
    } else {
      findings.push(finding(1, localUsers.length > 3 ? "warn" : "pass", `authType=${authType} with active provider ${settingsNames.join(", ")}; ${localUsers.length} local Splunk-type accounts remain${localUsers.length > 3 ? " (more than 3, review break-glass scope)" : ""}.`, evidence));
    }
  } else if (authType === "ProxySSO" || authType === "Scripted") {
    findings.push(finding(1, "manual", `authType=${authType}: enforcement depends on the external proxy or script; collect the upstream identity provider configuration manually.`, { auth_type: authType }));
  } else {
    findings.push(finding(1, "fail", `authType=${authType}: local Splunk authentication is the primary method; SAML or LDAP is not enforced.`, { auth_type: authType, local_users: users.ok ? users.value.entries.length : null }));
  }

  const passwordStanza = authConf.ok ? stanza(authConf.value, "splunk_auth") : undefined;
  if (!authConf.ok) {
    findings.push(manualUnreadable(2, "/services/configs/conf-authentication", authConf, "authentication.conf [splunk_auth] password settings."));
  } else if (!passwordStanza) {
    findings.push(finding(2, "manual", "Unknown: the [splunk_auth] stanza was not returned, so no password policy setting could be read; collect authentication.conf [splunk_auth] manually.", inventoryNote(authConf.value)));
  } else {
    const checks: Array<{ key: string; ok: (value: number | boolean) => boolean; expectation: string; numeric: boolean }> = [
      { key: "minPasswordLength", ok: (value) => typeof value === "number" && value >= 8, expectation: ">= 8", numeric: true },
      { key: "minPasswordUppercase", ok: (value) => typeof value === "number" && value >= 1, expectation: ">= 1", numeric: true },
      { key: "minPasswordLowercase", ok: (value) => typeof value === "number" && value >= 1, expectation: ">= 1", numeric: true },
      { key: "minPasswordDigit", ok: (value) => typeof value === "number" && value >= 1, expectation: ">= 1", numeric: true },
      { key: "minPasswordSpecial", ok: (value) => typeof value === "number" && value >= 1, expectation: ">= 1", numeric: true },
      { key: "expirePasswordDays", ok: (value) => typeof value === "number" && value >= 1 && value <= 90, expectation: "1..90", numeric: true },
      { key: "forceWeakPasswordChange", ok: (value) => value === true, expectation: "true", numeric: false },
      { key: "lockoutUsers", ok: (value) => value === true, expectation: "true", numeric: false },
    ];
    const absent: string[] = [];
    const noncompliant: string[] = [];
    const compliant: string[] = [];
    for (const check of checks) {
      const raw = passwordStanza[check.key];
      const value = check.numeric ? asNumber(raw) : asBoolean(raw);
      if (value === undefined) absent.push(check.key);
      else if (check.ok(value)) compliant.push(`${check.key}=${String(raw)}`);
      else noncompliant.push(`${check.key}=${String(raw)} (expected ${check.expectation})`);
    }
    const evidence = { compliant, noncompliant, absent, auth_type: authType ?? null };
    if (noncompliant.length > 0) {
      findings.push(finding(2, "fail", `${noncompliant.length} password policy settings are non-compliant: ${noncompliant.join("; ")}.`, evidence));
    } else if (absent.length > 0) {
      findings.push(finding(2, "warn", `No explicit non-compliant values, but ${absent.length} settings were absent (${absent.join(", ")}); an absent setting is not treated as compliant.`, evidence));
    } else {
      findings.push(finding(2, "pass", `All ${compliant.length} evaluated [splunk_auth] password settings were explicitly compliant${authType && authType !== "Splunk" ? ` (applies to local accounts; primary authType is ${authType})` : ""}.`, evidence));
    }
  }

  const mfaVendor = asString(authStanza?.externalTwoFactorAuthVendor);
  if (!authConf.ok) {
    findings.push(manualUnreadable(3, "/services/configs/conf-authentication", authConf, "authentication.conf externalTwoFactorAuthVendor and the Duo or RSA stanza, or the SAML IdP MFA policy."));
  } else if (mfaVendor && /duo|rsa/i.test(mfaVendor)) {
    const vendorEndpoint = /duo/i.test(mfaVendor) ? "Duo-MFA" : "Rsa-MFA";
    const mfa = await collect(client, () => client.listMfaProviders(vendorEndpoint));
    const evidence = { vendor: mfaVendor, endpoint: `/services/admin/${vendorEndpoint}`, entries: mfa.ok ? mfa.value.entries.map((entry) => entry.name) : null };
    if (mfa.ok && mfa.value.entries.length > 0) {
      findings.push(finding(3, "pass", `externalTwoFactorAuthVendor=${mfaVendor} and the ${vendorEndpoint} configuration is present.`, evidence));
    } else if (mfa.ok) {
      findings.push(finding(3, "fail", `externalTwoFactorAuthVendor=${mfaVendor} but no ${vendorEndpoint} configuration stanza exists.`, evidence));
    } else {
      findings.push(finding(3, "warn", `externalTwoFactorAuthVendor=${mfaVendor} but /services/admin/${vendorEndpoint} could not be read (${unreadableCause(mfa)}); verify the MFA stanza manually.`, evidence));
    }
  } else if (authType === "SAML") {
    findings.push(finding(3, "manual", "authType=SAML with no Splunk-native MFA vendor: MFA is enforced by the identity provider. Collect the IdP MFA policy for the Splunk application manually.", { auth_type: authType, external_two_factor_vendor: mfaVendor ?? null }));
  } else if (authType) {
    findings.push(finding(3, "fail", `No externalTwoFactorAuthVendor (Duo or RSA) is configured and authType=${authType} does not delegate MFA to an identity provider.`, { auth_type: authType, external_two_factor_vendor: mfaVendor ?? null }));
  } else {
    findings.push(finding(3, "manual", "Unknown: neither authType nor externalTwoFactorAuthVendor could be read from authentication.conf; collect the MFA configuration manually.", {}));
  }

  if (!webConf.ok || !serverConf.ok) {
    const failed = !webConf.ok ? webConf : serverConf;
    findings.push(manualUnreadable(4, !webConf.ok ? "/services/configs/conf-web" : "/services/configs/conf-server", failed as { error: string; httpStatus?: number }, "web.conf tools.sessions.timeout and server.conf [general] sessionTimeout."));
  } else {
    const webSettings = stanza(webConf.value, "settings");
    const general = stanza(serverConf.value, "general");
    const webTimeoutRaw = asNumber(webSettings?.["tools.sessions.timeout"]);
    const serverTimeoutRaw = asString(general?.sessionTimeout);
    const webTimeout = webTimeoutRaw ?? 60;
    const serverTimeout = parseSplunkDurationMinutes(serverTimeoutRaw) ?? 60;
    const assumed: string[] = [];
    if (webTimeoutRaw === undefined) assumed.push("web.conf tools.sessions.timeout absent, documented default 60 minutes assumed");
    if (serverTimeoutRaw === undefined) assumed.push("server.conf sessionTimeout absent, documented default 1h assumed");
    const evidence = { web_tools_sessions_timeout_minutes: webTimeoutRaw ?? null, server_session_timeout: serverTimeoutRaw ?? null, threshold_minutes: maxSessionMinutes, assumed_defaults: assumed };
    if (webTimeout > maxSessionMinutes || serverTimeout > maxSessionMinutes) {
      findings.push(finding(4, "fail", `Session timeout exceeds ${maxSessionMinutes} minutes (web ${webTimeout} min, splunkd ${serverTimeout} min).`, evidence));
    } else if (!webSettings && !general) {
      findings.push(finding(4, "manual", "Unknown: web.conf [settings] and server.conf [general] stanzas were not returned; collect the session timeout settings manually.", evidence));
    } else {
      findings.push(finding(4, "pass", `Session timeouts are within ${maxSessionMinutes} minutes (web ${webTimeout} min, splunkd ${serverTimeout} min)${assumed.length > 0 ? `; ${assumed.join("; ")}` : ""}.`, evidence));
    }
  }

  findings.push(finding(
    5,
    "manual",
    "Splunk does not expose a per-user concurrent session limit through the REST API or web.conf. Collect the reverse proxy or identity provider session policy manually; role search quotas are reported as related evidence only.",
    {
      roles_readable: roles.ok,
      role_search_quotas: roles.ok
        ? roles.value.entries.slice(0, 50).map((role) => ({ role: role.name, srchJobsQuota: asNumber(role.content.srchJobsQuota) ?? null, rtSrchJobsQuota: asNumber(role.content.rtSrchJobsQuota) ?? null }))
        : null,
    },
  ));

  if (!tokens.ok) {
    findings.push(manualUnreadable(6, "/services/authorization/tokens", tokens, "the token inventory (requires list_tokens_all) with expiry, issue date, subject, and status for each token."));
  } else if (tokens.value.entries.length === 0) {
    findings.push(finding(6, "manual", "No authentication tokens were visible. Emptiness is treated as unknown: confirm token authentication is disabled or that the credential holds list_tokens_all rather than list_tokens_own.", inventoryNote(tokens.value)));
  } else {
    const nowSeconds = Date.now() / 1000;
    const knownUsers = users.ok ? new Set(users.value.entries.map((user) => user.name)) : undefined;
    const noExpiry: string[] = [];
    const stale: string[] = [];
    const missingDates: string[] = [];
    const orphaned: string[] = [];
    let enabledCount = 0;
    for (const token of tokens.value.entries) {
      const claims = asObject(token.content.claims) ?? {};
      const status = asString(token.content.status) ?? "unknown";
      if (status === "enabled") enabledCount += 1;
      const exp = asNumber(claims.exp);
      const iat = asNumber(claims.iat);
      const subject = asString(claims.sub) ?? "unknown";
      const label = `${token.name.slice(0, 12)} (${subject}, ${status})`;
      if (exp === undefined || iat === undefined) missingDates.push(label);
      if (exp === 0) noExpiry.push(label);
      if (iat !== undefined && iat > 0 && nowSeconds - iat > maxTokenAgeDays * 86400) stale.push(label);
      if (knownUsers && subject !== "unknown" && !knownUsers.has(subject)) orphaned.push(label);
    }
    const evidence = {
      ...inventoryNote(tokens.value),
      enabled: enabledCount,
      no_expiry: noExpiry.slice(0, 50),
      older_than_days: maxTokenAgeDays,
      stale: stale.slice(0, 50),
      missing_dates: missingDates.slice(0, 50),
      subject_not_in_user_list: users.ok ? orphaned.slice(0, 50) : null,
      users_readable: users.ok,
    };
    const usersCaveat = users.ok ? "" : `The subject-to-user check was skipped because the user list could not be read (${unreadableCause(users)}); confirm each token subject is a current user.`;
    const orphanedText = users.ok ? `${orphaned.length} tokens belong to subjects not present in the user list` : "the subject-to-user check was skipped because the user list was unreadable";
    if (noExpiry.length > 0 || orphaned.length > 0) {
      findings.push(capWithCaveats(finding(6, "fail", `${noExpiry.length} tokens never expire and ${orphanedText} (of ${tokens.value.entries.length} seen).`, evidence), [usersCaveat]));
    } else if (stale.length > 0 || missingDates.length > 0 || partialView(tokens.value)) {
      findings.push(capWithCaveats(finding(6, "warn", `${stale.length} tokens are older than ${maxTokenAgeDays} days, ${missingDates.length} lack issue or expiry claims${partialView(tokens.value) ? `, and only ${seenVersusTotal(tokens.value, "tokens")} were retrieved` : ""}.`, evidence), [usersCaveat]));
    } else if (!users.ok) {
      findings.push(capWithCaveats(finding(6, "pass", `All ${tokens.value.entries.length} tokens expire and are newer than ${maxTokenAgeDays} days, but whether every subject maps to a known user was not checked.`, evidence), [usersCaveat]));
    } else {
      findings.push(finding(6, "pass", `All ${tokens.value.entries.length} tokens expire, are newer than ${maxTokenAgeDays} days, and map to known users.`, evidence));
    }
  }

  const finalFindings = downgradePassOnPartialInventory(findings, [["conf-authentication", authConf], ["conf-web", webConf], ["conf-server", serverConf], ["users", users], ["tokens", tokens]]);
  return {
    title: "Splunk authentication and identity",
    summary: { url: client.getResolvedConfig().url, deployment: deployment.info.isCloud ? "splunk_cloud" : "enterprise", auth_type: authType ?? null, ...summarizeStatuses(finalFindings) },
    findings: finalFindings,
    errors: collectedErrors([["server/info", deployment.collected], ["conf-authentication", authConf], ["conf-web", webConf], ["conf-server", serverConf], ["users", users], ["tokens", tokens], ["roles", roles]]),
  };
}

export interface SplunkAccessControlOptions {
  maxAdmins?: number;
}

const HIGH_RISK_CAPABILITIES = ["admin_all_objects", "delete_by_keyword", "edit_tcp", "edit_user", "edit_roles", "edit_roles_grantable", "change_authentication", "edit_server"];
const ELEVATED_CAPABILITIES = ["edit_server", "change_authentication", "run_debug_commands", "edit_forwarders", "edit_deployment_server", "edit_deployment_client", "restart_splunkd", "edit_tokens_all", "edit_httpauths", "edit_storage_passwords", "list_storage_passwords", "install_apps", "edit_local_apps", "rest_apps_management", "edit_indexer_cluster", "edit_search_server"];

function rolesAssessmentGuard(controlNumber: number, roles: Collected<SplunkListResult>, evidenceNeeded: string): SplunkFinding | undefined {
  if (!roles.ok) return manualUnreadable(controlNumber, "/services/authorization/roles", roles, evidenceNeeded);
  if (roles.value.entries.length === 0) {
    return finding(controlNumber, "manual", "No roles were visible. Splunk always ships built-in roles, so an empty list means the credential sees a partial view; collect the role inventory manually.", inventoryNote(roles.value));
  }
  return undefined;
}

function partialSuffix(result: SplunkListResult, noun: string): string {
  return partialView(result) ? ` Only ${seenVersusTotal(result, noun)} were retrieved before the walk stopped, so the verdict is downgraded.` : "";
}

function withPartial(status: SplunkFindingStatus, result: SplunkListResult): SplunkFindingStatus {
  return status === "pass" && partialView(result) ? "warn" : status;
}

export async function assessSplunkAccessControl(
  client: SplunkInspectorClient,
  options: SplunkAccessControlOptions = {},
): Promise<SplunkAssessmentResult> {
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10_000);
  const [roles, users, savedSearches, lookups] = await Promise.all([
    collect(client, () => client.listRoles()),
    collect(client, () => client.listUsers()),
    collect(client, () => client.listSavedSearches()),
    collect(client, () => client.listLookupTableFiles()),
  ]);
  const findings: SplunkFinding[] = [];

  const rbacGuard = rolesAssessmentGuard(7, roles, "each role's capabilities and imported roles from Settings > Roles.");
  if (rbacGuard) {
    findings.push(rbacGuard);
  } else if (roles.ok) {
    const offenders = roles.value.entries
      .filter((role) => !isAdminRoleName(role.name))
      .map((role) => ({ role: role.name, capabilities: roleCapabilities(role).filter((cap) => HIGH_RISK_CAPABILITIES.includes(cap)), imported_roles: asStringList(role.content.imported_roles) }))
      .filter((item) => item.capabilities.length > 0);
    const evidence = { ...inventoryNote(roles.value), high_risk_capabilities: HIGH_RISK_CAPABILITIES, non_admin_roles_with_high_risk: offenders.slice(0, 50) };
    if (offenders.length > 0) {
      findings.push(finding(7, "fail", `${offenders.length} non-admin roles hold high-risk capabilities (${[...new Set(offenders.flatMap((item) => item.capabilities))].join(", ")}).${partialSuffix(roles.value, "roles")}`, evidence));
    } else {
      findings.push(finding(7, withPartial("pass", roles.value), `None of the ${roles.value.entries.length} non-admin roles hold high-risk capabilities.${partialSuffix(roles.value, "roles")}`, evidence));
    }
  }

  if (!users.ok) {
    findings.push(manualUnreadable(8, "/services/authentication/users", users, "the user list with role assignments (requires edit_user) to count admin and sc_admin holders."));
  } else if (users.value.entries.length === 0) {
    findings.push(finding(8, "manual", "No users were visible. The credential can always see itself, so an empty list indicates a partial view; collect the user-to-role list manually.", inventoryNote(users.value)));
  } else {
    const admins = users.value.entries.filter((user) => asStringList(user.content.roles).some((role) => role === "admin" || role === "sc_admin"));
    const evidence = { ...inventoryNote(users.value), threshold: maxAdmins, admin_users: admins.map((user) => user.name).slice(0, 100) };
    if (admins.length === 0) {
      findings.push(finding(8, "manual", `None of the ${users.value.entries.length} visible users hold admin or sc_admin; at least one administrator must exist, so the credential sees a partial view.${partialSuffix(users.value, "users")}`, evidence));
    } else if (admins.length > maxAdmins) {
      findings.push(finding(8, "fail", `${admins.length} users hold admin or sc_admin, above the threshold of ${maxAdmins}.${partialSuffix(users.value, "users")}`, evidence));
    } else {
      findings.push(finding(8, withPartial("pass", users.value), `${admins.length} of ${users.value.entries.length} users hold admin or sc_admin (threshold ${maxAdmins}).${partialSuffix(users.value, "users")}`, evidence));
    }
  }

  const searchGuard = rolesAssessmentGuard(9, roles, "each role's srchIndexesAllowed, srchIndexesDefault, and srchFilter.");
  if (searchGuard) {
    findings.push(searchGuard);
  } else if (roles.ok) {
    const nonAdmin = nonAdminRoles(roles.value);
    const wildcard = nonAdmin
      .map((role) => ({
        role: role.name,
        allowed: roleAllowedIndexes(role),
        defaults: asStringList(role.content.srchIndexesDefault),
        filter: asString(role.content.srchFilter) ?? asString(role.content.imported_srchFilter) ?? null,
      }))
      .filter((item) => item.allowed.some((pattern) => pattern === "*") && !item.filter);
    const missingAllowed = rolesWithoutIndexScope(nonAdmin);
    const evidence = { ...inventoryNote(roles.value), wildcard_roles: wildcard.slice(0, 50), roles_without_srchIndexesAllowed_field: missingAllowed.slice(0, 50) };
    if (wildcard.length > 0) {
      findings.push(finding(9, "fail", `${wildcard.length} non-admin roles can search every index (srchIndexesAllowed contains * with no srchFilter).${partialSuffix(roles.value, "roles")}`, evidence));
    } else if (missingAllowed.length === nonAdmin.length && missingAllowed.length > 0) {
      findings.push(finding(9, "manual", "Unknown: no non-admin role exposed the srchIndexesAllowed field, so search restrictions could not be read.", evidence));
    } else if (missingAllowed.length > 0) {
      findings.push(finding(9, "warn", `${missingAllowed.length} of ${nonAdmin.length} non-admin roles did not expose srchIndexesAllowed (${missingAllowed.slice(0, 10).join(", ")}), so their search scope is unknown and was not counted as unrestricted; the remaining roles have no unrestricted (*) scope.${partialSuffix(roles.value, "roles")}`, evidence));
    } else {
      findings.push(finding(9, withPartial("pass", roles.value), `No non-admin role has unrestricted (*) index search scope.${partialSuffix(roles.value, "roles")}`, evidence));
    }
  }

  const indexGuard = rolesAssessmentGuard(10, roles, "each role's srchIndexesAllowed and importRoles to confirm _audit and _internal access.");
  if (indexGuard) {
    findings.push(indexGuard);
  } else if (roles.ok) {
    const sensitive = ["_audit", "_internal"];
    const nonAdmin = nonAdminRoles(roles.value);
    const exposed = nonAdmin
      .map((role) => ({ role: role.name, allowed: roleAllowedIndexes(role), sensitive: sensitive.filter((index) => indexPatternCovers(roleAllowedIndexes(role), index)) }))
      .filter((item) => item.sensitive.length > 0);
    const missingAllowed = rolesWithoutIndexScope(nonAdmin);
    const evidence = { ...inventoryNote(roles.value), non_admin_roles_with_internal_index_access: exposed.slice(0, 50), roles_without_srchIndexesAllowed_field: missingAllowed.slice(0, 50) };
    if (exposed.length > 0) {
      findings.push(finding(10, "fail", `${exposed.length} non-admin roles can search _audit or _internal.${partialSuffix(roles.value, "roles")}`, evidence));
    } else if (missingAllowed.length === nonAdmin.length && missingAllowed.length > 0) {
      findings.push(finding(10, "manual", "Unknown: no non-admin role exposed the srchIndexesAllowed field, so _audit and _internal access could not be read.", evidence));
    } else if (missingAllowed.length > 0) {
      findings.push(finding(10, "warn", `${missingAllowed.length} of ${nonAdmin.length} non-admin roles did not expose srchIndexesAllowed (${missingAllowed.slice(0, 10).join(", ")}), so their _audit and _internal access is unknown and was not counted as granted; no other non-admin role can search those indexes.${partialSuffix(roles.value, "roles")}`, evidence));
    } else {
      findings.push(finding(10, withPartial("pass", roles.value), `Only admin roles can search _audit and _internal across ${roles.value.entries.length} roles.${partialSuffix(roles.value, "roles")}`, evidence));
    }
  }

  if (!savedSearches.ok) {
    findings.push(manualUnreadable(11, "/servicesNS/-/-/saved/searches", savedSearches, "sharing and write permissions of saved searches, reports, dashboards, and lookups."));
  } else if (savedSearches.value.entries.length === 0 && (!lookups.ok || lookups.value.entries.length === 0)) {
    findings.push(finding(11, "manual", "No knowledge objects were visible. Splunk ships saved searches in core apps, so an empty list indicates a scoped view; collect knowledge object permissions manually.", { saved_searches: inventoryNote(savedSearches.value), lookups_readable: lookups.ok }));
  } else {
    const objects = [...savedSearches.value.entries.map((entry) => ({ kind: "saved_search", entry })), ...(lookups.ok ? lookups.value.entries.map((entry) => ({ kind: "lookup_table_file", entry })) : [])];
    const open = objects
      .map(({ kind, entry }) => {
        const perms = asObject(entry.acl.perms) ?? {};
        return { kind, name: entry.name, app: asString(entry.acl.app) ?? null, sharing: asString(entry.acl.sharing) ?? null, write: asStringList(perms.write) };
      })
      .filter((item) => item.sharing === "global" && item.write.some((role) => role === "*" || role === "user"));
    const evidence = { saved_searches: inventoryNote(savedSearches.value), lookups: lookups.ok ? inventoryNote(lookups.value) : null, globally_writable: open.slice(0, 50) };
    if (open.length > 0) {
      findings.push(finding(11, "fail", `${open.length} globally shared knowledge objects are writable by every user (* or user role).${partialSuffix(savedSearches.value, "saved searches")}`, evidence));
    } else {
      findings.push(finding(11, withPartial(lookups.ok ? "pass" : "warn", savedSearches.value), `No globally shared knowledge object grants write to * or user across ${objects.length} objects${lookups.ok ? "" : " (lookup table files were not readable)"}.${partialSuffix(savedSearches.value, "saved searches")}`, evidence));
    }
  }

  const capabilityGuard = rolesAssessmentGuard(12, roles, "the full capability list per role to review elevated platform capabilities.");
  if (capabilityGuard) {
    findings.push(capabilityGuard);
  } else if (roles.ok) {
    const elevated = roles.value.entries
      .filter((role) => !isAdminRoleName(role.name))
      .map((role) => ({ role: role.name, elevated: roleCapabilities(role).filter((cap) => ELEVATED_CAPABILITIES.includes(cap)), total_capabilities: roleCapabilities(role).length }))
      .filter((item) => item.elevated.length > 0);
    const evidence = { ...inventoryNote(roles.value), elevated_capabilities_checked: ELEVATED_CAPABILITIES, non_admin_roles_with_elevated: elevated.slice(0, 50), capability_counts: roles.value.entries.map((role) => ({ role: role.name, count: roleCapabilities(role).length })).slice(0, 100) };
    if (elevated.length > 0) {
      findings.push(finding(12, "fail", `${elevated.length} non-admin roles hold elevated platform capabilities (${[...new Set(elevated.flatMap((item) => item.elevated))].join(", ")}).${partialSuffix(roles.value, "roles")}`, evidence));
    } else {
      findings.push(finding(12, withPartial("pass", roles.value), `No non-admin role holds elevated platform capabilities.${partialSuffix(roles.value, "roles")}`, evidence));
    }
  }

  const finalFindings = downgradePassOnPartialInventory(findings, [["roles", roles], ["users", users], ["saved-searches", savedSearches], ["lookup-table-files", lookups]]);
  return {
    title: "Splunk authorization and access control",
    summary: { url: client.getResolvedConfig().url, roles: roles.ok ? roles.value.entries.length : null, users: users.ok ? users.value.entries.length : null, ...summarizeStatuses(finalFindings) },
    findings: finalFindings,
    errors: collectedErrors([["roles", roles], ["users", users], ["saved-searches", savedSearches], ["lookup-table-files", lookups]]),
  };
}

function tlsVersionsAllowLegacy(versions: string[]): boolean {
  const included = versions.filter((item) => !item.startsWith("-"));
  const excluded = new Set(versions.filter((item) => item.startsWith("-")).map((item) => item.slice(1)));
  if (included.includes("*") || included.includes("tls")) {
    return !(excluded.has("tls1.0") && excluded.has("tls1.1"));
  }
  return included.some((item) => /^(tls1\.0|tls1\.1|ssl[23])$/i.test(item));
}

function hecEntryIsGlobal(entry: SplunkEntry): boolean {
  return entry.name === "http";
}

type ForwarderTlsMode = "explicit_tls" | "inferred_from_clientCert" | "plaintext" | "unrecognized";

interface ForwarderTargetTls {
  target: string;
  useSSL: string | null;
  useSSL_source: string;
  clientCert: string | null;
  clientCert_source: string;
  sslPassword_present: boolean;
  mode: ForwarderTlsMode;
  reason: string;
}

interface ForwarderTlsView {
  global: JsonRecord | undefined;
  groups: ForwarderTargetTls[];
  servers: ForwarderTargetTls[];
}

type SettingLevels = Array<[source: string, content: JsonRecord | undefined]>;

function resolveLayeredSetting(key: string, levels: SettingLevels): { value: string | undefined; source: string } {
  for (const [source, content] of levels) {
    const value = asString(content?.[key]);
    if (value !== undefined) return { value, source };
  }
  return { value: undefined, source: "unset" };
}

function forwarderTlsMode(useSsl: string | undefined, clientCert: string | undefined): { mode: ForwarderTlsMode; reason: string } {
  const explicit = useSsl === undefined ? undefined : asBoolean(useSsl);
  if (explicit === true) return { mode: "explicit_tls", reason: `useSSL=${useSsl}` };
  if (explicit === false) return { mode: "plaintext", reason: `useSSL=${useSsl} explicitly disables TLS regardless of certificate settings` };
  const legacyLabel = useSsl === undefined ? "useSSL unset (documented default legacy)" : `useSSL=${useSsl}`;
  if (useSsl === undefined || useSsl.toLowerCase() === "legacy") {
    return clientCert
      ? { mode: "inferred_from_clientCert", reason: `${legacyLabel}: TLS is inferred from clientCert=${clientCert}, whose validity the REST view cannot verify` }
      : { mode: "plaintext", reason: `${legacyLabel} with no clientCert, so the forwarder does not use TLS` };
  }
  return { mode: "unrecognized", reason: `useSSL=${useSsl} is not a documented value (true, false, legacy)` };
}

function forwarderTlsStatus(mode: ForwarderTlsMode): SplunkFindingStatus {
  switch (mode) {
    case "explicit_tls":
      return "pass";
    case "inferred_from_clientCert":
    case "unrecognized":
      return "warn";
    case "plaintext":
      return "fail";
    default: {
      const exhaustive: never = mode;
      throw new Error(`Unhandled forwarder TLS mode ${String(exhaustive)}`);
    }
  }
}

function evaluateForwarderTarget(target: string, levels: SettingLevels): ForwarderTargetTls {
  const useSsl = resolveLayeredSetting("useSSL", levels);
  const clientCert = resolveLayeredSetting("clientCert", levels);
  const certificate = clientCert.value === undefined ? resolveLayeredSetting("sslCertPath", levels) : clientCert;
  const password = resolveLayeredSetting("sslPassword", levels);
  const { mode, reason } = forwarderTlsMode(useSsl.value, certificate.value);
  return {
    target,
    useSSL: useSsl.value ?? null,
    useSSL_source: useSsl.source,
    clientCert: certificate.value ?? null,
    clientCert_source: certificate.source,
    sslPassword_present: password.value !== undefined,
    mode,
    reason,
  };
}

function evaluateForwarderTls(outputs: SplunkListResult): ForwarderTlsView {
  const global = stanza(outputs, "tcpout");
  const groupEntries = outputs.entries.filter((entry) => /^tcpout:/.test(entry.name));
  const serverEntries = outputs.entries.filter((entry) => /^tcpout-server:\/\//.test(entry.name));
  const groups = groupEntries.map((group) => evaluateForwarderTarget(group.name, [["group", group.content], ["global [tcpout]", global]]));
  const servers = serverEntries.map((server) => {
    const address = server.name.replace(/^tcpout-server:\/\//, "");
    const owner = groupEntries.find((group) => asStringList(group.content.server).includes(address));
    return evaluateForwarderTarget(server.name, [["server", server.content], ["group", owner?.content], ["global [tcpout]", global]]);
  });
  return { global, groups, servers };
}

function describeTargets(targets: ForwarderTargetTls[]): string {
  return targets.slice(0, 10).map((item) => `${item.target} (${item.reason})`).join("; ");
}

export async function assessSplunkDataProtection(client: SplunkInspectorClient): Promise<SplunkAssessmentResult> {
  const deployment = await loadDeployment(client);
  const [serverConf, webConf, outputsConf, inputsConf, hecInputs, indexes] = await Promise.all([
    collect(client, () => client.getConfStanzas("server")),
    collect(client, () => client.getConfStanzas("web")),
    collect(client, () => client.getConfStanzas("outputs")),
    collect(client, () => client.getConfStanzas("inputs")),
    collect(client, () => client.listHecInputs()),
    collect(client, () => client.listIndexes()),
  ]);
  const acsHec = client.hasAcs() && deployment.info.isCloud ? await collect(client, () => client.acsListAll("/inputs/http-event-collectors", "http-event-collectors")) : undefined;
  const deploymentNote = deploymentCaveat(deployment);
  const findings: SplunkFinding[] = [];

  if (!serverConf.ok) {
    findings.push(manualUnreadable(13, "/services/configs/conf-server", serverConf, "server.conf [sslConfig] enableSplunkdSSL, sslVersions, cipherSuite, requireClientCert and web.conf enableSplunkWebSSL."));
  } else {
    const ssl = stanza(serverConf.value, "sslConfig");
    const webSettings = webConf.ok ? stanza(webConf.value, "settings") : undefined;
    const splunkdSslRaw = asBoolean(ssl?.enableSplunkdSSL);
    const sslVersions = asStringList(ssl?.sslVersions);
    const requireClientCert = asBoolean(ssl?.requireClientCert);
    const webSslRaw = asBoolean(webSettings?.enableSplunkWebSSL);
    const assumed: string[] = [];
    const problems: string[] = [];
    const unknowns: string[] = [];
    const unknownDefaults: string[] = [];
    if (!ssl) unknowns.push("server.conf [sslConfig] stanza not returned");
    if (splunkdSslRaw === false) problems.push("enableSplunkdSSL=false");
    if (ssl && splunkdSslRaw === undefined) assumed.push("enableSplunkdSSL absent, documented default true assumed");
    if (sslVersions.length === 0 && ssl) unknownDefaults.push("sslVersions absent and its documented default varies by release (see etc/system/default/server.conf), so the accepted TLS versions are unknown");
    if (sslVersions.length > 0 && tlsVersionsAllowLegacy(sslVersions)) problems.push(`sslVersions=${sslVersions.join(",")} permits TLS below 1.2`);
    if (!webConf.ok) {
      unknowns.push(`web.conf unreadable (${unreadableCause(webConf)})`);
    } else if (webSslRaw === false || (webSettings && webSslRaw === undefined)) {
      problems.push(webSslRaw === false ? "enableSplunkWebSSL=false" : "enableSplunkWebSSL absent (documented default false)");
    } else if (!webSettings) {
      unknowns.push("web.conf [settings] stanza not returned");
    }
    const evidence = { enableSplunkdSSL: ssl?.enableSplunkdSSL ?? null, sslVersions, cipherSuite: asString(ssl?.cipherSuite) ?? null, requireClientCert: ssl?.requireClientCert ?? null, enableSplunkWebSSL: webSettings?.enableSplunkWebSSL ?? null, web_sslVersions: webConf.ok ? asStringList(webSettings?.sslVersions) : null, assumed_defaults: assumed, unknown_defaults: unknownDefaults, problems, unknowns };
    if (problems.length > 0) {
      findings.push(finding(13, "fail", `TLS configuration problems: ${problems.join("; ")}.`, evidence));
    } else if (unknowns.length > 0) {
      findings.push(finding(13, "manual", `Unknown: ${unknowns.join("; ")}${deployment.info.isCloud ? " (Splunk Cloud manages TLS on these ports; record the Splunk Cloud TLS attestation)" : ""}. Collect server.conf [sslConfig] and web.conf [settings] manually.`, evidence));
    } else if (unknownDefaults.length > 0) {
      findings.push(finding(13, "warn", `splunkd and Splunk Web use TLS but ${unknownDefaults.join("; ")}${requireClientCert === true ? "; requireClientCert=true" : "; requireClientCert is not enabled"}. Set sslVersions explicitly to tls1.2 or newer.`, evidence));
    } else {
      findings.push(finding(13, requireClientCert === true ? "pass" : "warn", `splunkd and Splunk Web use TLS with sslVersions ${sslVersions.join(",")}${requireClientCert === true ? " and requireClientCert=true" : "; requireClientCert is not enabled"}${assumed.length > 0 ? `; ${assumed.join("; ")}` : ""}.`, evidence));
    }
  }

  const indexEvidence = indexes.ok
    ? indexes.value.entries.slice(0, 100).map((index) => ({ name: index.name, homePath: asString(index.content.homePath) ?? null, coldPath: asString(index.content.coldPath) ?? null, frozenTimePeriodInSecs: asNumber(index.content.frozenTimePeriodInSecs) ?? null }))
    : null;
  if (deployment.info.isCloud) {
    findings.push(capWithCaveats(finding(14, "manual", client.hasAcs()
      ? "Splunk Cloud encrypts indexes at rest by default; the ACS EMEK endpoints (GET /emek/key-policy, GET /emek/waiver, PUT /emek/key) only generate onboarding artifacts and do not report whether Enterprise Managed Encryption Keys are active. Collect the EMEK provisioning record or the Splunk Cloud encryption attestation manually."
      : "Splunk Cloud encrypts indexes at rest by default, but ACS is not configured, so no cloud-side evidence could be retrieved. Collect the EMEK provisioning record or the Splunk Cloud encryption attestation manually.", { acs_configured: client.hasAcs(), indexes: indexEvidence }), [deploymentNote]));
  } else {
    findings.push(capWithCaveats(finding(14, "manual", "Splunk Enterprise has no index-level encryption setting; at-rest protection depends on volume or filesystem encryption under homePath and coldPath. Collect the storage encryption evidence for the listed index paths manually.", { indexes_readable: indexes.ok, indexes: indexEvidence }), [deploymentNote]));
  }

  if (deployment.info.isCloud) {
    findings.push(capWithCaveats(finding(15, "manual", "Splunk Cloud enforces TLS between forwarders and its indexers through the Universal Forwarder credentials package; outputs.conf lives on the forwarders, not on this search head. Collect a sample forwarder outputs.conf (useSSL, clientCert, sslRootCAPath) manually.", { deployment: "splunk_cloud" }), [deploymentNote]));
  } else if (!outputsConf.ok) {
    findings.push(capWithCaveats(manualUnreadable(15, "/services/configs/conf-outputs", outputsConf, "outputs.conf [tcpout] and [tcpout:*] useSSL, clientCert, sslRootCAPath and inputs.conf [SSL] serverCert, requireClientCert from the forwarding tier."), [deploymentNote]));
  } else {
    const view = evaluateForwarderTls(outputsConf.value);
    const targets = [...view.groups, ...view.servers];
    const plaintext = targets.filter((item) => forwarderTlsStatus(item.mode) === "fail");
    const inferred = targets.filter((item) => forwarderTlsStatus(item.mode) === "warn");
    const inherited = targets.filter((item) => item.useSSL_source === "global [tcpout]").length;
    const inputsSsl = inputsConf.ok ? stanza(inputsConf.value, "SSL") : undefined;
    const evidence = {
      global_tcpout: { useSSL: asString(view.global?.useSSL) ?? null, clientCert: asString(view.global?.clientCert) ?? null },
      targets: targets.slice(0, 50),
      sslPassword_note: "sslPassword is the CA certificate password and is not treated as TLS evidence",
      inputs_conf_readable: inputsConf.ok,
      inputs_ssl_serverCert: asString(inputsSsl?.serverCert) ?? null,
      inputs_ssl_requireClientCert: inputsSsl?.requireClientCert ?? null,
    };
    const inputsCaveat = inputsConf.ok ? "" : `inputs.conf [SSL] could not be read (${unreadableCause(inputsConf)}), so the receiving-side serverCert and requireClientCert were not checked.`;
    let forwardingFinding: SplunkFinding;
    if (view.groups.length === 0) {
      forwardingFinding = finding(15, "manual", "This node has no outputs.conf [tcpout:*] target groups, so it does not forward data; collect outputs.conf from the forwarders and inputs.conf [SSL] from the indexers manually.", evidence);
    } else if (plaintext.length > 0) {
      forwardingFinding = finding(15, "fail", `${plaintext.length} of ${targets.length} forwarding targets do not use TLS: ${describeTargets(plaintext)}.`, evidence);
    } else if (inferred.length > 0) {
      forwardingFinding = finding(15, "warn", `${inferred.length} of ${targets.length} forwarding targets only infer TLS: ${describeTargets(inferred)}. Set useSSL=true explicitly to confirm encryption.`, evidence);
    } else {
      forwardingFinding = finding(15, "pass", `All ${targets.length} forwarding targets set useSSL=true explicitly${inherited > 0 ? ` (${inherited} inherit it from the global [tcpout] stanza)` : ""}.`, evidence);
    }
    findings.push(capWithCaveats(forwardingFinding, [inputsCaveat, deploymentNote]));
  }

  const acsCaveat = acsHec && !acsHec.ok
    ? `The ACS HEC token inventory (acs:/inputs/http-event-collectors) could not be read (${unreadableCause(acsHec)}), so this verdict rests on the local /services/data/inputs/http view alone and the Splunk Cloud token settings were not checked.`
    : "";
  if (acsHec && acsHec.ok) {
    const tokens = acsHec.value.items.map((item) => asObject(item.spec) ?? item);
    const enabled = tokens.filter((token) => asBoolean(token.disabled) !== true);
    const noAck = enabled.filter((token) => asBoolean(token.useACK) !== true && asBoolean(token.useAck) !== true);
    const anyIndex = enabled.filter((token) => asStringList(token.allowedIndexes).length === 0);
    const noSourcetype = enabled.filter((token) => !asString(token.defaultSourcetype));
    const evidence = { source: "acs:/inputs/http-event-collectors", tokens: tokens.length, enabled: enabled.length, truncated: acsHec.value.truncated, no_useACK: noAck.map((token) => asString(token.name)).slice(0, 50), any_index_allowed: anyIndex.map((token) => asString(token.name)).slice(0, 50), no_default_sourcetype: noSourcetype.map((token) => asString(token.name)).slice(0, 50) };
    let hecFinding: SplunkFinding;
    if (tokens.length === 0) {
      hecFinding = finding(16, "manual", "ACS returned no HEC tokens. Emptiness is treated as unknown: confirm HEC is unused on this stack or that the ACS token can list HEC tokens.", evidence);
    } else if (anyIndex.length > 0) {
      hecFinding = finding(16, "fail", `${anyIndex.length} enabled HEC tokens have no allowedIndexes restriction (any index accepted); ${noAck.length} lack useACK and ${noSourcetype.length} lack a default sourcetype.`, evidence);
    } else if (noAck.length > 0 || noSourcetype.length > 0 || acsHec.value.truncated) {
      hecFinding = finding(16, "warn", `All enabled HEC tokens restrict indexes, but ${noAck.length} lack useACK and ${noSourcetype.length} lack a default sourcetype${acsHec.value.truncated ? `; the token list was truncated (${tokens.length} seen, total unknown)` : ""}. Splunk Cloud terminates HEC over TLS on port 443.`, evidence);
    } else {
      hecFinding = finding(16, "pass", `All ${enabled.length} enabled HEC tokens restrict indexes, enable useACK, and set a default sourcetype (Splunk Cloud HEC is TLS-only).`, evidence);
    }
    findings.push(capWithCaveats(hecFinding, [deploymentNote]));
  } else if (!hecInputs.ok) {
    findings.push(capWithCaveats(manualUnreadable(16, acsHec ? "acs:/inputs/http-event-collectors and /services/data/inputs/http" : "/services/data/inputs/http", acsHec && !acsHec.ok ? acsHec : hecInputs, "the HEC token inventory with indexes, sourcetype, useACK, disabled flag, and the global [http] enableSSL setting."), [deploymentNote]));
  } else {
    const globalEntry = hecInputs.value.entries.find(hecEntryIsGlobal);
    const tokens = hecInputs.value.entries.filter((entry) => !hecEntryIsGlobal(entry));
    const hecDisabled = asBoolean(globalEntry?.content.disabled);
    const enableSsl = asBoolean(globalEntry?.content.enableSSL);
    const enabled = tokens.filter((token) => asBoolean(token.content.disabled) !== true);
    const noAck = enabled.filter((token) => asBoolean(token.content.useACK) !== true);
    const anyIndex = enabled.filter((token) => asStringList(token.content.indexes).length === 0);
    const noSourcetype = enabled.filter((token) => !asString(token.content.sourcetype));
    const evidence = { ...inventoryNote(hecInputs.value), global_entry_present: Boolean(globalEntry), hec_disabled: globalEntry?.content.disabled ?? null, enableSSL: globalEntry?.content.enableSSL ?? null, tokens: tokens.length, enabled: enabled.length, no_useACK: noAck.map((token) => token.name).slice(0, 50), any_index_allowed: anyIndex.map((token) => token.name).slice(0, 50), no_sourcetype: noSourcetype.map((token) => token.name).slice(0, 50) };
    let hecFinding: SplunkFinding;
    if (hecInputs.value.entries.length === 0) {
      hecFinding = finding(16, "manual", "The HEC input list was empty, including the global [http] entry, so neither the disabled flag nor enableSSL could be read. Confirm the credential holds list_inputs and whether HEC is in use.", evidence);
    } else if (!globalEntry) {
      hecFinding = finding(16, "manual", `Unknown: ${tokens.length} HEC tokens were listed but the global [http] entry (disabled, enableSSL) was not returned; collect inputs.conf [http] manually.`, evidence);
    } else if (hecDisabled === true && tokens.length === 0) {
      hecFinding = finding(16, "pass", "HEC is globally disabled (inputs.conf [http] disabled=1 read explicitly) and no tokens are defined.", evidence);
    } else if (tokens.length === 0) {
      hecFinding = finding(16, "manual", "HEC is enabled but no tokens were visible. Emptiness is treated as unknown: confirm the credential can list HEC tokens or that HEC is unused.", evidence);
    } else if (enableSsl === false || anyIndex.length > 0) {
      hecFinding = finding(16, "fail", `${enableSsl === false ? "HEC enableSSL=false; " : ""}${anyIndex.length} enabled tokens accept any index.${partialSuffix(hecInputs.value, "HEC inputs")}`, evidence);
    } else if (noAck.length > 0 || noSourcetype.length > 0 || enableSsl === undefined || partialView(hecInputs.value)) {
      hecFinding = finding(16, "warn", `${noAck.length} enabled tokens lack useACK and ${noSourcetype.length} lack a sourcetype${enableSsl === undefined ? "; enableSSL absent (documented default true assumed)" : ""}.${partialSuffix(hecInputs.value, "HEC inputs")}`, evidence);
    } else {
      hecFinding = finding(16, "pass", `HEC enableSSL=true and all ${enabled.length} enabled tokens restrict indexes, enable useACK, and set a sourcetype.`, evidence);
    }
    findings.push(capWithCaveats(hecFinding, [acsCaveat, deploymentNote]));
  }

  const finalFindings = downgradePassOnPartialInventory(findings, [["conf-server", serverConf], ["conf-web", webConf], ["conf-outputs", outputsConf], ["conf-inputs", inputsConf], ["hec-inputs", hecInputs], ["indexes", indexes]]);
  return {
    title: "Splunk data protection and encryption",
    summary: { url: client.getResolvedConfig().url, deployment: deployment.info.isCloud ? "splunk_cloud" : "enterprise", acs_configured: client.hasAcs(), ...summarizeStatuses(finalFindings) },
    findings: finalFindings,
    errors: collectedErrors([["server/info", deployment.collected], ["conf-server", serverConf], ["conf-web", webConf], ["conf-outputs", outputsConf], ["conf-inputs", inputsConf], ["hec-inputs", hecInputs], ["indexes", indexes], ...(acsHec ? [["acs-hec", acsHec] as [string, Collected<unknown>]] : [])]),
  };
}

export interface SplunkAuditMonitoringOptions {
  runSearches?: boolean;
  minAuditRetentionDays?: number;
}

export async function assessSplunkAuditMonitoring(
  client: SplunkInspectorClient,
  options: SplunkAuditMonitoringOptions = {},
): Promise<SplunkAssessmentResult> {
  const runSearches = options.runSearches !== false;
  const minRetentionDays = clampNumber(options.minAuditRetentionDays, DEFAULT_MIN_AUDIT_RETENTION_DAYS, 1, 36_500);
  const [indexes, roles, users, auditConf] = await Promise.all([
    collect(client, () => client.listIndexes()),
    collect(client, () => client.listRoles()),
    collect(client, () => client.listUsers()),
    collectOptionalConf(client, "audit"),
  ]);
  const findings: SplunkFinding[] = [];
  const auditIndex = indexes.ok ? indexes.value.entries.find((index) => index.name === "_audit") : undefined;
  const auditTrail = auditConf.ok ? stanza(auditConf.value, "auditTrail") : undefined;
  const queueing = asBoolean(auditTrail?.queueing);
  const auditTrailNote = !auditConf.ok
    ? `audit.conf could not be read (${unreadableCause(auditConf)})`
    : queueing === undefined
      ? "audit.conf [auditTrail] queueing absent (there is no default audit.conf), documented default true assumed"
      : `audit.conf [auditTrail] queueing=${String(auditTrail?.queueing)}`;

  if (!indexes.ok) {
    findings.push(manualUnreadable(17, "/services/data/indexes", indexes, "the _audit index status (disabled flag, event count) and a sample of index=_audit events covering login, search, and configuration changes."));
  } else if (indexes.value.entries.length === 0) {
    findings.push(finding(17, "manual", "No indexes were visible. Splunk always has internal indexes, so an empty list indicates a partial view; collect the _audit index status manually.", inventoryNote(indexes.value)));
  } else if (!auditIndex) {
    findings.push(finding(17, "manual", `Unknown: _audit was not among the ${indexes.value.entries.length} visible indexes${partialView(indexes.value) ? " (list was partial)" : ""}; confirm the credential can see internal indexes and that _audit is enabled.`, inventoryNote(indexes.value)));
  } else {
    const disabled = asBoolean(auditIndex.content.disabled);
    const eventCount = asNumber(auditIndex.content.totalEventCount);
    const search = runSearches ? await collect(client, () => client.runOneshotSearch("index=_audit | stats count by action", "-24h")) : undefined;
    const actions = search?.ok ? search.value.results.map((row) => asString(row.action) ?? "").filter(Boolean) : [];
    const hasLogin = actions.some((action) => /login/i.test(action));
    const hasSearch = actions.some((action) => /^search$/i.test(action));
    const hasConfigChange = actions.some((action) => /edit|create|delete|update|change/i.test(action));
    const evidence = {
      disabled: auditIndex.content.disabled ?? null,
      totalEventCount: eventCount ?? null,
      search_run: runSearches,
      search_readable: search ? search.ok : null,
      actions_last_24h: search?.ok ? actions.slice(0, 50) : null,
      covers_login: hasLogin,
      covers_search: hasSearch,
      covers_config_change: hasConfigChange,
      audit_conf_readable: auditConf.ok,
      audit_trail_queueing: auditTrail?.queueing ?? null,
      audit_trail_logging_format: asString(auditTrail?.logging_format) ?? null,
      audit_trail_note: auditTrailNote,
    };
    if (disabled === true) {
      findings.push(finding(17, "fail", "The _audit index is disabled.", evidence));
    } else if (disabled === undefined) {
      findings.push(finding(17, "manual", "Unknown: the _audit index entry did not expose its disabled flag; collect the index status manually.", evidence));
    } else if (search && !search.ok) {
      findings.push(finding(17, "warn", `The _audit index is enabled${eventCount !== undefined ? ` with ${eventCount} events` : ""}, but the read-only audit search failed (${unreadableCause(search)}), so recent event coverage is unconfirmed.`, evidence));
    } else if (!search) {
      findings.push(finding(17, "warn", `The _audit index is enabled${eventCount !== undefined ? ` with ${eventCount} events` : ""}; audit searches were skipped, so recent event coverage is unconfirmed.`, evidence));
    } else if (actions.length === 0) {
      findings.push(finding(17, "fail", "The _audit index is enabled but returned no events in the last 24 hours.", evidence));
    } else if (!hasLogin || !hasSearch) {
      findings.push(finding(17, "warn", `_audit received events in the last 24 hours but coverage is incomplete (login: ${hasLogin}, search: ${hasSearch}, configuration change: ${hasConfigChange}).`, evidence));
    } else if (!auditConf.ok) {
      findings.push(finding(17, "warn", `_audit recorded login and search events in the last 24 hours, but ${auditTrailNote}, so the [auditTrail] queueing setting could not be confirmed.`, evidence));
    } else if (queueing === false) {
      findings.push(finding(17, "warn", `_audit recorded login and search events in the last 24 hours, but ${auditTrailNote}, so audit events reach the index only through a separate tailing input; confirm that input is monitored.`, evidence));
    } else {
      findings.push(finding(17, "pass", `_audit is enabled and recorded login, search${hasConfigChange ? ", and configuration change" : ""} events in the last 24 hours; ${auditTrailNote}.`, evidence));
    }
  }

  if (!roles.ok) {
    findings.push(manualUnreadable(18, "/services/authorization/roles", roles, "roles holding delete_by_keyword with _audit in their searchable indexes, plus the _audit retention setting."));
  } else if (roles.value.entries.length === 0) {
    findings.push(finding(18, "manual", "No roles were visible, so audit deletion rights could not be evaluated; collect the roles holding delete_by_keyword manually.", inventoryNote(roles.value)));
  } else {
    const deleters = roles.value.entries
      .filter((role) => roleCapabilities(role).includes("delete_by_keyword") && indexPatternCovers(roleAllowedIndexes(role), "_audit"))
      .map((role) => ({ role: role.name, admin_like: isAdminRoleName(role.name) || role.name === "can_delete", users: users.ok ? users.value.entries.filter((user) => asStringList(user.content.roles).includes(role.name)).map((user) => user.name).slice(0, 50) : null }));
    const nonAdminDeleters = deleters.filter((item) => !item.admin_like);
    const assignedDeleteUsers = deleters.flatMap((item) => item.users ?? []);
    const retentionSeconds = auditIndex ? asNumber(auditIndex.content.frozenTimePeriodInSecs) : undefined;
    const retentionDays = retentionSeconds === undefined ? undefined : Math.floor(retentionSeconds / 86400);
    const evidence = { ...inventoryNote(roles.value), roles_that_can_delete_audit: deleters.slice(0, 50), users_readable: users.ok, users_with_delete_roles: users.ok ? assignedDeleteUsers.slice(0, 100) : null, indexes_readable: indexes.ok, audit_frozenTimePeriodInSecs: retentionSeconds ?? null, audit_retention_days: retentionDays ?? null, min_retention_days: minRetentionDays };
    const concerns: string[] = [];
    if (users.ok && assignedDeleteUsers.length > 0) concerns.push(`${assignedDeleteUsers.length} users hold roles able to delete _audit events`);
    if (!users.ok) concerns.push(`role assignments could not be enumerated because the user list could not be read (${unreadableCause(users)}), so whether anyone holds a delete-capable role is unknown`);
    if (retentionDays === undefined) concerns.push(indexes.ok ? "_audit frozenTimePeriodInSecs was not readable" : `_audit frozenTimePeriodInSecs was not readable because the index list could not be read (${unreadableCause(indexes)})`);
    if (nonAdminDeleters.length > 0) {
      findings.push(finding(18, "fail", `${nonAdminDeleters.length} non-admin roles can delete _audit events (delete_by_keyword with _audit access).${partialSuffix(roles.value, "roles")}`, evidence));
    } else if (retentionDays !== undefined && retentionDays < minRetentionDays) {
      findings.push(finding(18, "fail", `_audit retention is ${retentionDays} days (frozenTimePeriodInSecs=${retentionSeconds}), below the ${minRetentionDays}-day minimum.`, evidence));
    } else if (concerns.length > 0 || partialView(roles.value)) {
      findings.push(finding(18, "warn", `Only admin-like roles can delete _audit events${retentionDays !== undefined ? ` and _audit retention is ${retentionDays} days` : ""}${concerns.length > 0 ? `, but ${concerns.join("; ")}` : ""}.${partialSuffix(roles.value, "roles")}`, evidence));
    } else {
      findings.push(finding(18, "pass", `Only unassigned admin-like roles can delete _audit events and _audit retention is ${retentionDays} days.`, evidence));
    }
  }

  const finalFindings = downgradePassOnPartialInventory(findings, [["indexes", indexes], ["roles", roles], ["users", users], ["conf-audit", auditConf]]);
  return {
    title: "Splunk audit and monitoring",
    summary: { url: client.getResolvedConfig().url, audit_index_visible: Boolean(auditIndex), ...summarizeStatuses(finalFindings) },
    findings: finalFindings,
    errors: collectedErrors([["indexes", indexes], ["roles", roles], ["users", users], ["conf-audit", auditConf]]),
  };
}

function appProvenance(app: SplunkEntry): "core" | "splunkbase" | "third_party" {
  const author = asString(app.content.author) ?? "";
  const details = asString(app.content.details) ?? "";
  if (CORE_APP_NAMES.has(app.name) || CORE_APP_PREFIXES.some((prefix) => app.name.startsWith(prefix)) || /^splunk(,| inc| llc|$)/i.test(author)) return "core";
  if (/splunkbase\.splunk\.com/i.test(details)) return "splunkbase";
  return "third_party";
}

type S2sListenerState = "tls" | "plaintext" | "unconfirmed";

interface S2sTlsSettings {
  serverCert: string | null;
  serverCert_source: string;
  requireClientCert: string | null;
  requireClientCert_source: string;
  sslVersions: string[];
  sslVersions_source: string;
  cipherSuite: string | null;
  cipherSuite_source: string;
}

interface S2sListener {
  port: string;
  state: S2sListenerState;
  sources: string[];
  tlsStanza?: JsonRecord;
  tls?: S2sTlsSettings;
}

/** Evidence keeps the resolved TLS settings only; the raw [splunktcp-ssl:<port>] stanza may carry sslPassword or password. */
function listenerEvidence(listener: S2sListener): JsonRecord {
  return { port: listener.port, state: listener.state, sources: listener.sources, tls: listener.tls ?? null };
}

const REQUIRE_CLIENT_CERT_DEFAULT_NOTE = 'documented default: "false" if using self-signed and third-party certificates, "true" if using the default certificates, and the REST view cannot tell which certificates are in use';

function listenerPort(name: string): string {
  const match = /(\d+)\s*$/.exec(name);
  return match ? match[1] : name;
}

function resolveS2sTlsSettings(listener: S2sListener, globalSsl: JsonRecord | undefined): S2sTlsSettings {
  const levels: SettingLevels = [[`[splunktcp-ssl:${listener.port}]`, listener.tlsStanza], ["[SSL]", globalSsl]];
  const serverCert = resolveLayeredSetting("serverCert", levels);
  const requireClientCert = resolveLayeredSetting("requireClientCert", levels);
  const sslVersions = resolveLayeredSetting("sslVersions", levels);
  const cipherSuite = resolveLayeredSetting("cipherSuite", levels);
  return {
    serverCert: serverCert.value ?? null,
    serverCert_source: serverCert.source,
    requireClientCert: requireClientCert.value ?? null,
    requireClientCert_source: requireClientCert.source,
    sslVersions: asStringList(sslVersions.value),
    sslVersions_source: sslVersions.source,
    cipherSuite: cipherSuite.value ?? null,
    cipherSuite_source: cipherSuite.source,
  };
}

function describeRequireClientCert(listener: S2sListener, globalSsl: JsonRecord | undefined): string {
  const tls = listener.tls;
  if (!tls || tls.requireClientCert === null) {
    return `port ${listener.port} requireClientCert absent from both [splunktcp-ssl:${listener.port}] and [SSL] (${REQUIRE_CLIENT_CERT_DEFAULT_NOTE})`;
  }
  const globalValue = asString(globalSsl?.requireClientCert);
  const overriding = tls.requireClientCert_source !== "[SSL]" && globalValue !== undefined ? `, overriding [SSL] requireClientCert=${globalValue}` : "";
  return `port ${listener.port} requireClientCert=${tls.requireClientCert} from ${tls.requireClientCert_source}${overriding}`;
}

function s2sListenerStatus(state: S2sListenerState): SplunkFindingStatus {
  switch (state) {
    case "tls":
      return "pass";
    case "unconfirmed":
      return "manual";
    case "plaintext":
      return "fail";
    default: {
      const exhaustive: never = state;
      throw new Error(`Unhandled S2S listener state ${String(exhaustive)}`);
    }
  }
}

function s2sListeners(cooked: SplunkListResult, inputs: SplunkListResult): S2sListener[] {
  const byPort = new Map<string, S2sListener>();
  const record = (name: string, source: string, state: S2sListenerState | undefined): void => {
    const port = listenerPort(name);
    const current = byPort.get(port) ?? { port, state: "unconfirmed", sources: [] };
    current.sources.push(source);
    if (state === "plaintext" || (state === "tls" && current.state === "unconfirmed")) current.state = state;
    byPort.set(port, current);
  };
  for (const entry of cooked.entries) {
    if (asBoolean(entry.content.disabled) !== true) record(entry.name, `data/inputs/tcp/cooked ${entry.name}`, undefined);
  }
  for (const entry of inputs.entries) {
    if (asBoolean(entry.content.disabled) === true) continue;
    if (/^splunktcp-ssl:/.test(entry.name)) {
      record(entry.name, `inputs.conf [${entry.name}]`, "tls");
      const listener = byPort.get(listenerPort(entry.name));
      if (listener && !listener.tlsStanza) listener.tlsStanza = entry.content;
    } else if (/^splunktcp:/.test(entry.name)) {
      record(entry.name, `inputs.conf [${entry.name}]`, "plaintext");
    }
  }
  return [...byPort.values()];
}

export async function assessSplunkPlatformHardening(client: SplunkInspectorClient): Promise<SplunkAssessmentResult> {
  const deployment = await loadDeployment(client);
  const [apps, roles, kvCollections, savedSearches, users, cookedInputs, inputsConf] = await Promise.all([
    collect(client, () => client.listApps()),
    collect(client, () => client.listRoles()),
    collect(client, () => client.listKvCollections()),
    collect(client, () => client.listSavedSearches()),
    collect(client, () => client.listUsers()),
    collect(client, () => client.listCookedTcpInputs()),
    collect(client, () => client.getConfStanzas("inputs")),
  ]);
  const deploymentNote = deploymentCaveat(deployment);
  const findings: SplunkFinding[] = [];

  if (!deployment.info.isCloud) {
    findings.push(capWithCaveats(finding(19, "manual", "Not applicable through the API: IP allow lists are a Splunk Cloud ACS feature. For Splunk Enterprise, collect firewall or load balancer restrictions for the management, web, HEC, and S2S ports manually.", { deployment: "enterprise", deployment_source: deployment.info.source }), [deploymentNote]));
  } else if (!client.hasAcs()) {
    findings.push(capWithCaveats(finding(19, "manual", "Splunk Cloud ACS is not configured (SPLUNK_STACK and SPLUNK_ACS_TOKEN), so IP allow lists could not be read. Collect GET /access/{feature}/ipallowlists for search-api, hec, s2s, and search-ui manually.", { acs_configured: false }), [deploymentNote]));
  } else {
    const results = await Promise.all(ACS_ALLOWLIST_FEATURES.map(async (feature) => ({ feature, result: await collect(client, () => client.acsGet(`/access/${feature}/ipallowlists`)) })));
    const evaluated = results.map(({ feature, result }) => {
      if (!result.ok) return { feature, readable: false, subnets: null as string[] | null, verdict: "manual" as SplunkFindingStatus, note: unreadableCause(result) };
      const subnets = asStringList(result.value.subnets);
      if (subnets.some((subnet) => /^(0\.0\.0\.0\/0|::\/0)$/.test(subnet))) return { feature, readable: true, subnets, verdict: "fail" as SplunkFindingStatus, note: "allow list contains 0.0.0.0/0" };
      if (subnets.length === 0) {
        return feature === "search-api"
          ? { feature, readable: true, subnets, verdict: "warn" as SplunkFindingStatus, note: "no subnets returned; search-api is documented as closed by default, confirm the effective policy" }
          : { feature, readable: true, subnets, verdict: "fail" as SplunkFindingStatus, note: "no subnets returned; this feature is documented as open to all IPs by default" };
      }
      return { feature, readable: true, subnets, verdict: "pass" as SplunkFindingStatus, note: `${subnets.length} subnets` };
    });
    const evidence = { features: evaluated, deployment_source: deployment.info.source };
    let allowlistFinding: SplunkFinding;
    if (evaluated.some((item) => item.verdict === "fail")) {
      allowlistFinding = finding(19, "fail", `IP allow listing is open for ${evaluated.filter((item) => item.verdict === "fail").map((item) => item.feature).join(", ")}.`, evidence);
    } else if (evaluated.some((item) => item.verdict === "manual")) {
      allowlistFinding = finding(19, "manual", `Unknown: ${evaluated.filter((item) => item.verdict === "manual").map((item) => `${item.feature} (${item.note})`).join("; ")}; collect the allow lists manually.`, evidence);
    } else if (evaluated.some((item) => item.verdict === "warn")) {
      allowlistFinding = finding(19, "warn", `Allow lists are restricted except: ${evaluated.filter((item) => item.verdict === "warn").map((item) => `${item.feature} (${item.note})`).join("; ")}.`, evidence);
    } else {
      allowlistFinding = finding(19, "pass", `All ${evaluated.length} inspected ACS features have explicit IP allow lists.`, evidence);
    }
    findings.push(capWithCaveats(allowlistFinding, [deploymentNote]));
  }

  if (!apps.ok) {
    findings.push(manualUnreadable(20, "/services/apps/local", apps, "the installed app inventory with author and Splunkbase provenance, plus roles holding install_apps, edit_local_apps, or rest_apps_management."));
  } else if (apps.value.entries.length === 0) {
    findings.push(finding(20, "manual", "No apps were visible. Splunk always ships core apps, so an empty list indicates a partial view; collect the app inventory manually.", inventoryNote(apps.value)));
  } else {
    const classified = apps.value.entries.map((app) => ({ name: app.name, label: asString(app.content.label) ?? null, author: asString(app.content.author) ?? null, version: asString(app.content.version) ?? null, disabled: asBoolean(app.content.disabled) ?? null, provenance: appProvenance(app) }));
    const thirdParty = classified.filter((app) => app.provenance === "third_party" && app.disabled !== true);
    const installers = roles.ok ? roles.value.entries.filter((role) => !isAdminRoleName(role.name) && roleCapabilities(role).some((cap) => ["install_apps", "edit_local_apps", "rest_apps_management"].includes(cap))).map((role) => role.name) : null;
    const evidence = { ...inventoryNote(apps.value), splunk_version: deployment.info.version ?? null, third_party_apps: thirdParty.slice(0, 100), splunkbase_apps: classified.filter((app) => app.provenance === "splunkbase").length, core_apps: classified.filter((app) => app.provenance === "core").length, non_admin_roles_that_can_install_apps: installers };
    if (installers && installers.length > 0) {
      findings.push(finding(20, "fail", `${installers.length} non-admin roles can install or manage apps (${installers.join(", ")}); ${thirdParty.length} enabled apps lack Splunk or Splunkbase provenance.`, evidence));
    } else if (!roles.ok) {
      findings.push(finding(20, "manual", `Unknown: ${thirdParty.length} enabled apps lack Splunk or Splunkbase provenance and role capabilities could not be read to confirm installation is admin-only.`, evidence));
    } else if (thirdParty.length > 0 || partialView(apps.value)) {
      findings.push(finding(20, "warn", `${thirdParty.length} enabled apps lack Splunk or Splunkbase provenance and need review (${thirdParty.slice(0, 10).map((app) => app.name).join(", ")}); only admin roles can install apps.${partialSuffix(apps.value, "apps")}`, evidence));
    } else {
      findings.push(finding(20, "pass", `All ${classified.length} apps are Splunk core or Splunkbase-linked and only admin roles can install apps.`, evidence));
    }
  }

  if (!kvCollections.ok) {
    findings.push(manualUnreadable(21, "/servicesNS/-/-/storage/collections/config", kvCollections, "KV Store collection ACLs (sharing and read/write role lists)."));
  } else if (kvCollections.value.entries.length === 0) {
    findings.push(finding(21, "manual", "No KV Store collections were visible. Emptiness is treated as unknown: confirm whether the deployment uses KV Store and that the credential can list collections across apps.", inventoryNote(kvCollections.value)));
  } else {
    const evaluated = kvCollections.value.entries.map((collection) => {
      const perms = asObject(collection.acl.perms) ?? {};
      return { name: collection.name, app: asString(collection.acl.app) ?? null, sharing: asString(collection.acl.sharing) ?? null, read: asStringList(perms.read), write: asStringList(perms.write) };
    });
    const globalWrite = evaluated.filter((item) => item.sharing === "global" && item.write.includes("*"));
    const globalRead = evaluated.filter((item) => item.sharing === "global" && item.read.includes("*") && !item.write.includes("*"));
    const evidence = { ...inventoryNote(kvCollections.value), global_write_all: globalWrite.slice(0, 50), global_read_all: globalRead.slice(0, 50) };
    if (globalWrite.length > 0) {
      findings.push(finding(21, "fail", `${globalWrite.length} KV Store collections are globally shared with write access for every role.${partialSuffix(kvCollections.value, "collections")}`, evidence));
    } else if (globalRead.length > 0 || partialView(kvCollections.value)) {
      findings.push(finding(21, "warn", `${globalRead.length} KV Store collections are globally readable by every role; none are globally writable.${partialSuffix(kvCollections.value, "collections")}`, evidence));
    } else {
      findings.push(finding(21, "pass", `None of the ${evaluated.length} KV Store collections grant global read or write to every role.`, evidence));
    }
  }

  if (!savedSearches.ok) {
    findings.push(manualUnreadable(22, "/servicesNS/-/-/saved/searches", savedSearches, "scheduled searches with dispatchAs, owner roles, search scope, and dispatch.earliest_time."));
  } else if (savedSearches.value.entries.length === 0) {
    findings.push(finding(22, "manual", "No saved searches were visible. Splunk ships saved searches in core apps, so an empty list indicates a scoped view; collect scheduled search permissions manually.", inventoryNote(savedSearches.value)));
  } else {
    const adminUsers = users.ok ? new Set(users.value.entries.filter((user) => asStringList(user.content.roles).some((role) => role === "admin" || role === "sc_admin")).map((user) => user.name)) : undefined;
    const scheduled = savedSearches.value.entries.filter((search) => asBoolean(search.content.is_scheduled) === true && asBoolean(search.content.disabled) !== true);
    const evaluated = scheduled.map((search) => {
      const owner = asString(search.acl.owner) ?? "unknown";
      const spl = asString(search.content.search) ?? "";
      const earliest = asString(search.content["dispatch.earliest_time"]) ?? "";
      return {
        name: search.name,
        app: asString(search.acl.app) ?? null,
        owner,
        dispatchAs: asString(search.content.dispatchAs) ?? null,
        owner_is_admin: adminUsers ? adminUsers.has(owner) : null,
        all_indexes: /index\s*=\s*\*/.test(spl) || !/index\s*=/.test(spl),
        all_time: earliest === "" || earliest === "0" || /^-0s?$/.test(earliest),
      };
    });
    const risky = evaluated.filter((item) => item.dispatchAs === "owner" && item.owner_is_admin !== false && item.all_indexes && item.all_time);
    const ownerAdmin = evaluated.filter((item) => item.dispatchAs === "owner" && item.owner_is_admin === true);
    // Whether an owner is an admin is read from the user list: with that list
    // unreadable the admin-owner count and the risky list render null with a
    // note, and the owner-dispatched searches that could not be verified are
    // listed under their own name so a fail stays grounded.
    const evidence = {
      ...inventoryNote(savedSearches.value),
      scheduled: scheduled.length,
      users_readable: users.ok,
      risky_scheduled_searches: users.ok ? risky.slice(0, 50) : null,
      owner_dispatched_by_admins: users.ok ? ownerAdmin.length : null,
      ...(users.ok
        ? {}
        : {
            owner_roles_note: `owner roles were not verified because the user list could not be read (${unreadableCause(users)})`,
            unverified_owner_searches: risky.slice(0, 50),
          }),
    };
    if (risky.length > 0) {
      findings.push(finding(22, "fail", `${risky.length} scheduled searches run as their (${users.ok ? "admin" : "unverified"}) owner across all indexes with no time bound.${users.ok ? "" : ` Owner roles were not verified because the user list could not be read (${unreadableCause(users)}).`}${partialSuffix(savedSearches.value, "saved searches")}`, evidence));
    } else if (scheduled.length === 0) {
      const usersCaveat = users.ok ? "" : `The user list could not be read (${unreadableCause(users)}), so owner roles were not available for verification.`;
      findings.push(capWithCaveats(finding(22, withPartial("pass", savedSearches.value), `${savedSearches.value.entries.length} saved searches were inspected and none are scheduled, so no scheduled search runs with elevated scope.${partialSuffix(savedSearches.value, "saved searches")}`, evidence), [usersCaveat]));
    } else if (!users.ok) {
      findings.push(finding(22, "warn", `Owner roles of the ${scheduled.length} scheduled searches could not be verified because the user list could not be read (${unreadableCause(users)}); none combine all indexes with an unbounded time range.${partialSuffix(savedSearches.value, "saved searches")}`, evidence));
    } else if (ownerAdmin.length > 0 || partialView(savedSearches.value)) {
      findings.push(finding(22, "warn", `${ownerAdmin.length} of ${scheduled.length} scheduled searches dispatch as an admin owner; none combine all indexes with an unbounded time range.${partialSuffix(savedSearches.value, "saved searches")}`, evidence));
    } else {
      findings.push(finding(22, "pass", `None of the ${scheduled.length} scheduled searches run as an admin owner over all indexes without a time bound.`, evidence));
    }
  }

  if (deployment.info.isCloud) {
    findings.push(finding(23, "manual", "Splunk Cloud indexers are managed by Splunk; S2S listeners are not exposed through this search head. Collect the s2s IP allow list and Splunk Cloud forwarder TLS attestation manually.", { deployment: "splunk_cloud" }));
  } else if (!cookedInputs.ok) {
    findings.push(capWithCaveats(manualUnreadable(23, "/services/data/inputs/tcp/cooked", cookedInputs, "inputs.conf [splunktcp://*] and [splunktcp-ssl:*] receiving stanzas plus the [SSL] stanza serverCert and requireClientCert from each indexer."), [deploymentNote]));
  } else {
    const sslStanza = inputsConf.ok ? stanza(inputsConf.value, "SSL") : undefined;
    const listeners = s2sListeners(cookedInputs.value, inputsConf.ok ? inputsConf.value : EMPTY_LIST);
    for (const listener of listeners) {
      if (listener.state === "tls") listener.tls = resolveS2sTlsSettings(listener, sslStanza);
    }
    const plaintext = listeners.filter((item) => s2sListenerStatus(item.state) === "fail");
    const unconfirmed = listeners.filter((item) => s2sListenerStatus(item.state) === "manual");
    const withoutClientCert = listeners.filter((item) => item.state === "tls" && asBoolean(item.tls?.requireClientCert) !== true);
    const withoutServerCert = listeners.filter((item) => item.state === "tls" && !item.tls?.serverCert);
    const evidence = {
      ...inventoryNote(cookedInputs.value),
      listeners: listeners.map(listenerEvidence),
      inputs_conf_readable: inputsConf.ok,
      ssl_stanza_present: inputsConf.ok ? Boolean(sslStanza) : null,
      ssl_stanza: inputsConf.ok
        ? { serverCert: asString(sslStanza?.serverCert) ?? null, requireClientCert: sslStanza?.requireClientCert ?? null, sslVersions: asStringList(sslStanza?.sslVersions) }
        : null,
      note: "data/inputs/tcp/cooked does not report TLS; encryption is decided from inputs.conf [splunktcp-ssl:*] stanzas, and serverCert and requireClientCert are resolved per port from [splunktcp-ssl:<port>] first, then [SSL]",
    };
    const ports = (items: S2sListener[]): string => items.map((item) => item.port).join(", ");
    let s2sFinding: SplunkFinding;
    if (listeners.length === 0) {
      s2sFinding = finding(23, "manual", "This node has no enabled splunktcp receiving ports, so S2S security must be collected from the indexers manually.", evidence);
    } else if (plaintext.length > 0) {
      s2sFinding = finding(23, "fail", `${plaintext.length} of ${listeners.length} enabled S2S listeners are plaintext [splunktcp://] receivers (ports ${ports(plaintext)}).`, evidence);
    } else if (!inputsConf.ok) {
      s2sFinding = finding(23, "manual", `Unknown: ${listeners.length} enabled splunktcp listeners exist (ports ${ports(listeners)}) but /services/configs/conf-inputs could not be read because ${unreadableCause(inputsConf)}, and the data/inputs/tcp/cooked REST view does not report TLS. Collect inputs.conf [splunktcp-ssl:*] and [SSL] from each indexer manually.`, evidence);
    } else if (unconfirmed.length > 0) {
      s2sFinding = finding(23, "manual", `Unknown: ${unconfirmed.length} of ${listeners.length} enabled splunktcp listeners (ports ${ports(unconfirmed)}) have no [splunktcp-ssl:<port>] stanza in the readable inputs.conf, so the REST view cannot confirm TLS. Collect inputs.conf from each indexer manually.`, evidence);
    } else if (withoutClientCert.length > 0) {
      s2sFinding = finding(23, "warn", `All ${listeners.length} listeners are [splunktcp-ssl:*] receivers but requireClientCert is not true for ${withoutClientCert.length} of them: ${withoutClientCert.map((item) => describeRequireClientCert(item, sslStanza)).join("; ")}. Forwarders on those ports are not certificate-authenticated.`, evidence);
    } else if (withoutServerCert.length > 0) {
      s2sFinding = finding(23, "warn", `All ${listeners.length} listeners are [splunktcp-ssl:*] receivers with requireClientCert=true but serverCert is absent from both [splunktcp-ssl:<port>] and [SSL] for ports ${ports(withoutServerCert)}, so the receiving certificate cannot be confirmed.`, evidence);
    } else {
      s2sFinding = finding(23, "pass", `All ${listeners.length} enabled S2S listeners are [splunktcp-ssl:*] receivers (ports ${ports(listeners)}) with serverCert set and requireClientCert=true, resolved per port from [splunktcp-ssl:<port>] first and [SSL] second.`, evidence);
    }
    findings.push(capWithCaveats(s2sFinding, [deploymentNote]));
  }

  const finalFindings = downgradePassOnPartialInventory(findings, [["apps", apps], ["roles", roles], ["kv-collections", kvCollections], ["saved-searches", savedSearches], ["users", users], ["tcp-cooked-inputs", cookedInputs], ["conf-inputs", inputsConf]]);
  return {
    title: "Splunk network and platform hardening",
    summary: { url: client.getResolvedConfig().url, deployment: deployment.info.isCloud ? "splunk_cloud" : "enterprise", version: deployment.info.version ?? null, acs_configured: client.hasAcs(), ...summarizeStatuses(finalFindings) },
    findings: finalFindings,
    errors: collectedErrors([["server/info", deployment.collected], ["apps", apps], ["roles", roles], ["kv-collections", kvCollections], ["saved-searches", savedSearches], ["users", users], ["tcp-cooked-inputs", cookedInputs], ["conf-inputs", inputsConf]]),
  };
}

const REQUIRED_CAPABILITIES: Array<{ capability: string; purpose: string }> = [
  { capability: "edit_user", purpose: "list users (/services/authentication/users)" },
  { capability: "list_tokens_all", purpose: "list every authentication token (/services/authorization/tokens)" },
  { capability: "rest_properties_get", purpose: "read configuration files (/services/configs/conf-*)" },
  { capability: "list_settings", purpose: "read server settings" },
  { capability: "list_inputs", purpose: "list HEC and TCP inputs (/services/data/inputs/*)" },
  { capability: "rest_apps_view", purpose: "list installed apps (/services/apps/local)" },
  { capability: "search", purpose: "run the read-only index=_audit confirmation search" },
];

async function readableSurface(
  client: SplunkInspectorClient,
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
): Promise<SplunkAccessSurface> {
  try {
    const value = await load();
    const list = asObject(value);
    const entries = Array.isArray(list?.entries) ? list?.entries : undefined;
    const totalKnown = list?.totalKnown !== false;
    return {
      name,
      endpoint,
      status: "readable",
      count: entries ? entries.length : value === undefined ? 0 : 1,
      total: entries && totalKnown ? asNumber(list?.total) ?? null : null,
      truncated: entries && typeof list?.truncated === "boolean" ? list.truncated : null,
      httpStatus: null,
    };
  } catch (error) {
    return {
      name,
      endpoint: errorEndpoint(error) ?? endpoint,
      status: "not_readable",
      count: null,
      total: null,
      truncated: null,
      httpStatus: errorStatus(error) ?? null,
      error: scrubErrorText(errorMessage(error), configuredSecretsOf(client)),
    };
  }
}

function collectedSurface(name: string, endpoint: string, collected: Collected<unknown>): SplunkAccessSurface {
  if (collected.ok) return { name, endpoint, status: "readable", count: 1, total: null, truncated: null, httpStatus: null };
  return { name, endpoint: collected.endpoint ?? endpoint, status: "not_readable", count: null, total: null, truncated: null, httpStatus: collected.httpStatus ?? null, error: collected.error };
}

export async function checkSplunkAccess(client: SplunkInspectorClient): Promise<SplunkAccessCheckResult> {
  const config = client.getResolvedConfig();
  const deployment = await loadDeployment(client);
  const context = await collect(client, () => client.getCurrentContext());
  const capabilities = context.ok ? asStringList(context.value?.content.capabilities) : null;
  const authenticatedAs = context.ok ? asString(context.value?.content.username) ?? context.value?.name : undefined;

  const surfaces: SplunkAccessSurface[] = [
    collectedSurface("server_info", "/services/server/info", deployment.collected),
    collectedSurface("current_context", "/services/authentication/current-context", context),
    await readableSurface(client, "users", "/services/authentication/users", () => client.listUsers()),
    await readableSurface(client, "roles", "/services/authorization/roles", () => client.listRoles()),
    await readableSurface(client, "tokens", "/services/authorization/tokens", () => client.listTokens()),
    await readableSurface(client, "conf_authentication", "/services/configs/conf-authentication", () => client.getConfStanzas("authentication")),
    await readableSurface(client, "conf_server", "/services/configs/conf-server", () => client.getConfStanzas("server")),
    await readableSurface(client, "conf_web", "/services/configs/conf-web", () => client.getConfStanzas("web")),
    await readableSurface(client, "indexes", "/services/data/indexes", () => client.listIndexes()),
    await readableSurface(client, "hec_inputs", "/services/data/inputs/http", () => client.listHecInputs()),
    await readableSurface(client, "tcp_cooked_inputs", "/services/data/inputs/tcp/cooked", () => client.listCookedTcpInputs()),
    await readableSurface(client, "saved_searches", "/servicesNS/-/-/saved/searches", () => client.listSavedSearches()),
    await readableSurface(client, "apps", "/services/apps/local", () => client.listApps()),
    await readableSurface(client, "kv_collections", "/servicesNS/-/-/storage/collections/config", () => client.listKvCollections()),
    client.hasAcs()
      ? await readableSurface(client, "acs_ip_allowlist", "acs:/access/search-api/ipallowlists", () => client.acsGet("/access/search-api/ipallowlists"))
      : { name: "acs_ip_allowlist", endpoint: "acs:/access/search-api/ipallowlists", status: "not_configured", count: null, total: null, truncated: null, httpStatus: null },
  ];

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const coreReadable = surfaces.filter((surface) => ["server_info", "users", "roles", "conf_authentication", "conf_server", "indexes"].includes(surface.name)).every((surface) => surface.status === "readable");
  const missingCapabilities = capabilities
    ? REQUIRED_CAPABILITIES.filter((item) => !capabilities.includes(item.capability) && !capabilities.includes("admin_all_objects")).map((item) => `${item.capability} (${item.purpose})`)
    : REQUIRED_CAPABILITIES.map((item) => `${item.capability} (${item.purpose}; capability list unreadable)`);
  const status = coreReadable && readableCount >= 11 ? "healthy" : "limited";

  return {
    status,
    url: config.url,
    deployment: deployment.info,
    authenticatedAs,
    capabilities,
    missingCapabilities,
    acsConfigured: client.hasAcs(),
    surfaces,
    notes: [
      `Splunk ${deployment.info.isCloud ? "Cloud Platform" : "Enterprise"}${deployment.info.version ? ` ${deployment.info.version}` : ""} at ${config.url} (auth: ${config.token ? "bearer token" : "session key"}, TLS verification ${config.verifyTls ? "on" : "OFF"}).`,
      `Authenticated as ${authenticatedAs ?? "unknown (current-context unreadable)"} with ${capabilities ? `${capabilities.length} capabilities` : "an unread capability list"}.`,
      `${readableCount}/${surfaces.length} audit surfaces are readable; ACS ${client.hasAcs() ? "configured" : "not configured"}.`,
    ],
    recommendedNextStep: status === "healthy"
      ? "Run splunk_assess_authentication, splunk_assess_access_control, splunk_assess_data_protection, splunk_assess_audit_monitoring, splunk_assess_platform_hardening, or splunk_export_audit_bundle."
      : `Grant the audit role the missing capabilities (${missingCapabilities.slice(0, 4).join("; ") || "see surfaces"}) or use an admin-scoped token; unreadable surfaces will render as manual findings.`,
  };
}

function formatAccessCheckText(result: SplunkAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === null ? "-" : surface.total !== null && surface.total !== surface.count ? `${surface.count}/${surface.total}` : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Splunk access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    result.missingCapabilities.length > 0 ? `Missing capabilities: ${result.missingCapabilities.join("; ")}` : "All expected capabilities are present.",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SplunkAssessmentResult): string {
  const rows = result.findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.summary.slice(0, 160)]);
  const summary = Object.entries(result.summary).map(([key, value]) => `- ${key}: ${String(value)}`).join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", `Collection errors (${result.errors.length}):`, ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: SplunkResolvedConfig, assessments: SplunkAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeStatuses(findings);
  return [
    "# Splunk Security Inspector Executive Summary",
    "",
    `Target: ${config.url}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${String(counts.fail)}`,
    `- Warning controls: ${String(counts.warn)}`,
    `- Manual (unknown or scoped out) controls: ${String(counts.manual)}`,
    `- Passing controls: ${String(counts.pass)}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings.filter((item) => item.status === "fail" || item.status === "warn").slice(0, 15).map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedMatrix(findings: SplunkFinding[]): string {
  const frameworks = Object.keys(SPLUNK_FRAMEWORK_LABELS) as SplunkFramework[];
  const rows = findings.map((item) => {
    const definition = CONTROLS_BY_NUMBER.get(item.control);
    return [String(item.control), item.id, item.status.toUpperCase(), ...frameworks.map((framework) => definition?.mappings[framework] ?? "")];
  });
  return ["# Unified Compliance Matrix", "", formatTable(["#", "Control", "Status", ...frameworks.map((framework) => SPLUNK_FRAMEWORK_LABELS[framework])], rows)].join("\n");
}

function buildFrameworkReport(framework: SplunkFramework, findings: SplunkFinding[]): string {
  const rows = findings.map((item) => [CONTROLS_BY_NUMBER.get(item.control)?.mappings[framework] ?? "", item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.summary.slice(0, 200)]);
  return [
    `# ${SPLUNK_FRAMEWORK_LABELS[framework]} Report`,
    "",
    `Controls evaluated: ${findings.length}`,
    "",
    formatTable(["Requirement", "Finding", "Severity", "Status", "Summary"], rows),
  ].join("\n");
}

function buildQuickReference(result: { outputDir: string; findings: SplunkFinding[]; errors: string[] }): string {
  return [
    "# Splunk Audit Bundle Quick Reference",
    "",
    "- `core_data/`: raw REST and ACS snapshots (JSON, credentials never written)",
    "- `analysis/findings.json`: all normalized findings; `analysis/<area>.json`: per-area assessments",
    "- `compliance/executive_summary.md`: prioritized summary",
    "- `compliance/unified_compliance_matrix.md`: cross-framework matrix",
    "- `compliance/<framework>.md`: one report per framework",
    result.errors.length > 0 ? "- `_errors.log`: endpoints that could not be collected (findings for them are manual)" : "- No collection errors were recorded",
    "",
    "Status semantics: pass = evidence read and compliant; warn = compliant with caveats or partial view; fail = non-compliant evidence; manual = unknown, scoped out, or requires human-collected evidence. Manual never counts as pass.",
    "",
    `Findings: ${result.findings.length} (${JSON.stringify(summarizeStatuses(result.findings))})`,
  ].join("\n");
}

export interface SplunkExportOptions extends SplunkAuthenticationOptions, SplunkAccessControlOptions, SplunkAuditMonitoringOptions {}

export async function exportSplunkAuditBundle(
  client: SplunkInspectorClient,
  config: SplunkResolvedConfig,
  outputRoot: string,
  options: SplunkExportOptions = {},
): Promise<SplunkAuditBundleResult> {
  const access = await checkSplunkAccess(client);
  const assessments = [
    await assessSplunkAuthentication(client, options),
    await assessSplunkAccessControl(client, options),
    await assessSplunkDataProtection(client),
    await assessSplunkAuditMonitoring(client, options),
    await assessSplunkPlatformHardening(client),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];
  const rawSnapshots: Array<[string, string, () => Promise<unknown>]> = [
    ["server_info", "/services/server/info", () => client.getServerInfo()],
    ["current_context", "/services/authentication/current-context", () => client.getCurrentContext()],
    ["users", "/services/authentication/users", () => client.listUsers()],
    ["roles", "/services/authorization/roles", () => client.listRoles()],
    ["tokens", "/services/authorization/tokens", () => client.listTokens()],
    ["conf_authentication", "/services/configs/conf-authentication", () => client.getConfStanzas("authentication")],
    ["conf_server", "/services/configs/conf-server", () => client.getConfStanzas("server")],
    ["conf_web", "/services/configs/conf-web", () => client.getConfStanzas("web")],
    ["conf_outputs", "/services/configs/conf-outputs", () => client.getConfStanzas("outputs")],
    ["conf_inputs", "/services/configs/conf-inputs", () => client.getConfStanzas("inputs")],
    ["indexes", "/services/data/indexes", () => client.listIndexes()],
    ["hec_inputs", "/services/data/inputs/http", () => client.listHecInputs()],
    ["saved_searches", "/servicesNS/-/-/saved/searches", async () => projectSavedSearchSnapshot(await client.listSavedSearches())],
    ["apps", "/services/apps/local", () => client.listApps()],
    ["kv_collections", "/servicesNS/-/-/storage/collections/config", () => client.listKvCollections()],
    ["tcp_cooked_inputs", "/services/data/inputs/tcp/cooked", () => client.listCookedTcpInputs()],
  ];

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(new URL(config.url).host)}-splunk-audit`);

  // A snapshot that could not be collected is still written, as a marker
  // naming the endpoint, status, and error, so the file's absence or an empty
  // list can never stand in for a denial; readable-but-empty lists stay [].
  for (const [name, endpoint, load] of rawSnapshots) {
    const snapshot = await collect(client, load);
    if (snapshot.ok) {
      await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(redactSnapshot(snapshot.value)));
    } else {
      await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(notCollectedMarker(snapshot, endpoint)));
      errors.push(`core_data/${name}: ${snapshot.error}`);
    }
  }

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({ generated_at: new Date().toISOString(), url: config.url, stack: config.stack ?? null, acs_configured: Boolean(config.stack && config.acsToken), source_chain: config.sourceChain, tls_verification: config.verifyTls }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(redactSnapshot(access)));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(redactSnapshot(findings)));
  const areaFiles = ["authentication", "access_control", "data_protection", "audit_monitoring", "platform_hardening"];
  for (const [index, assessment] of assessments.entries()) {
    await writeSecureTextFile(outputDir, `analysis/${areaFiles[index]}.json`, serializeJson(redactSnapshot(assessment)));
  }
  await writeSecureTextFile(outputDir, "analysis/summary.md", [formatAccessCheckText(access), "", ...assessments.map(formatAssessmentText)].join("\n"));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of Object.keys(SPLUNK_FRAMEWORK_LABELS) as SplunkFramework[]) {
    await writeSecureTextFile(outputDir, `compliance/${framework}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference({ outputDir, findings, errors })}\n`);
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);

  return { outputDir, zipPath, fileCount: await countFilesRecursively(outputDir), findingCount: findings.length, errorCount: errors.length };
}

const REDACTED = "[REDACTED]";

/**
 * Credential-bearing setting names, tested against the lowercased key with
 * dots, underscores, and hyphens removed so compound and dotted conf keys
 * match: pass4SymmKey, sslKeysfilePassword, attributeQuerySoapPassword,
 * bindDNpassword, httpEventCollectorToken, accessKey, appSecretKey,
 * action.slack.param.webhook_url, action.pagerduty.param.integration_key.
 * Password policy keys (minPasswordLength, passwordHistoryCount) do not end
 * in "password" and stay legible.
 */
const CREDENTIAL_KEY_PATTERN = /(password|passwd|passphrase|token)$|secret|pass4symmkey|accesskey|apikey|authkey|privatekey|sessionkey|integrationkey|routingkey|webhook|credential/;

/** splunkd stores encrypted settings as $1$ or $7$ ciphertext; a JWT is three base64url segments starting with eyJ. */
const CIPHERTEXT_OR_JWT_PATTERN = /^\$[17]\$|^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;

function isCredentialKey(key: string): boolean {
  return CREDENTIAL_KEY_PATTERN.test(key.toLowerCase().replace(/[._-]/g, ""));
}

/**
 * Keeps scheme, host, port, and path of a URL whose userinfo or query string
 * could carry a token. Values without either (including URL-shaped stanza
 * names such as http://app-token or splunktcp://9997) are left verbatim.
 */
function scrubUrlValue(value: string): string {
  const match = /^[a-z][a-z0-9+.-]*:\/\/(.*)$/i.exec(value);
  if (!match || !/[@?]/.test(match[1])) return value;
  try {
    const url = new URL(value);
    const userinfo = url.username || url.password ? `${REDACTED}@` : "";
    const query = url.search.length > 1 ? `?${REDACTED}` : "";
    return `${url.protocol}//${userinfo}${url.host}${url.pathname}${query}`;
  } catch {
    return value.replace(/\/\/[^/@]*@/, `//${REDACTED}@`).replace(/\?.*$/, `?${REDACTED}`);
  }
}

function redactLeaf(value: string): string {
  return CIPHERTEXT_OR_JWT_PATTERN.test(value) ? REDACTED : scrubUrlValue(value);
}

/**
 * Rule 9 deny list applied to every core_data snapshot: redacts the value of
 * every credential-named key (including {name, value} and {key, value} pair
 * shapes), every $1$ or $7$ ciphertext or JWT-shaped string, and the userinfo
 * and query string of every URL-valued string. Key names are kept so the
 * evidence stays legible.
 */
function redactSnapshot(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSnapshot);
  const object = asObject(value);
  if (!object) return typeof value === "string" ? redactLeaf(value) : value;
  const pairName = asString(object.name) ?? asString(object.key);
  const output: JsonRecord = {};
  for (const [key, item] of Object.entries(object)) {
    if (isCredentialKey(key) || (key === "value" && pairName !== undefined && isCredentialKey(pairName))) {
      output[key] = item === null || item === undefined ? item : REDACTED;
    } else {
      output[key] = redactSnapshot(item);
    }
  }
  return output;
}

/**
 * Rule 9 projection for core_data/saved_searches.json: keeps the fields the
 * verdicts read (SPLUNK-AC-11 sharing and write permissions, SPLUNK-PLAT-22
 * schedule, dispatchAs, and index scope) and drops the SPL text plus every
 * action.<name>.param.* value, which carry webhook URLs, API keys, and routing
 * keys verbatim on GET.
 */
function projectSavedSearchSnapshot(result: SplunkListResult): JsonRecord {
  const entries = result.entries.map((entry) => {
    const perms = asObject(entry.acl.perms) ?? {};
    const spl = asString(entry.content.search) ?? "";
    const actionNames = Object.keys(entry.content)
      .filter((key) => /^action\.[^.]+$/.test(key) && asBoolean(entry.content[key]) === true)
      .map((key) => key.slice("action.".length));
    return {
      name: entry.name,
      acl: {
        app: asString(entry.acl.app) ?? null,
        owner: asString(entry.acl.owner) ?? null,
        sharing: asString(entry.acl.sharing) ?? null,
        perms: { read: asStringList(perms.read), write: asStringList(perms.write) },
      },
      content: {
        is_scheduled: asBoolean(entry.content.is_scheduled) ?? null,
        disabled: asBoolean(entry.content.disabled) ?? null,
        dispatchAs: asString(entry.content.dispatchAs) ?? null,
        "dispatch.earliest_time": asString(entry.content["dispatch.earliest_time"]) ?? null,
        cron_schedule: asString(entry.content.cron_schedule) ?? null,
        search: spl.length > 0 ? REDACTED : null,
        search_index_scope: spl.length === 0 ? null : /index\s*=\s*\*/.test(spl) || !/index\s*=/.test(spl) ? "all_indexes" : "index_bound",
        action_names: actionNames,
        action_params_dropped: Object.keys(entry.content).filter((key) => /^action\.[^.]+\.param\./.test(key)).length,
      },
    };
  });
  return { entries, total: result.total, truncated: result.truncated, totalKnown: result.totalKnown };
}

type CommonArgs = {
  url?: string;
  token?: string;
  username?: string;
  password?: string;
  stack?: string;
  acs_token?: string;
  acs_base_url?: string;
  verify_ssl?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AuthenticationArgs = CommonArgs & { max_token_age_days?: number; max_session_minutes?: number };
type AccessControlArgs = CommonArgs & { max_admins?: number };
type AuditArgs = CommonArgs & { run_searches?: boolean; min_audit_retention_days?: number };
type ExportArgs = AuthenticationArgs & AccessControlArgs & AuditArgs & { output_dir?: string };

function normalizeCommonArgs(args: unknown): CommonArgs {
  const value = asObject(args) ?? {};
  return {
    url: asString(value.url),
    token: asString(value.token),
    username: asString(value.username),
    password: asString(value.password),
    stack: asString(value.stack),
    acs_token: asString(value.acs_token),
    acs_base_url: asString(value.acs_base_url),
    verify_ssl: value.verify_ssl === undefined ? undefined : String(value.verify_ssl),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAuthenticationArgs(args: unknown): AuthenticationArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCommonArgs(args), max_token_age_days: asNumber(value.max_token_age_days), max_session_minutes: asNumber(value.max_session_minutes) };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCommonArgs(args), max_admins: asNumber(value.max_admins) };
}

function normalizeAuditArgs(args: unknown): AuditArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCommonArgs(args), run_searches: asBoolean(value.run_searches), min_audit_retention_days: asNumber(value.min_audit_retention_days) };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthenticationArgs(args), ...normalizeAccessControlArgs(args), ...normalizeAuditArgs(args), output_dir: asString(value.output_dir) ?? asString(value.output) };
}

function createClient(args: CommonArgs): SplunkApiClient {
  return new SplunkApiClient(resolveSplunkConfiguration(args as JsonRecord));
}

const authParams = {
  url: Type.Optional(Type.String({ description: "splunkd management URL such as https://splunk.example.com:8089. Defaults to SPLUNK_URL." })),
  token: Type.Optional(Type.String({ description: "Splunk authentication token sent as Authorization: Bearer. Defaults to SPLUNK_TOKEN." })),
  username: Type.Optional(Type.String({ description: "Username for session-key login via POST /services/auth/login. Defaults to SPLUNK_USERNAME." })),
  password: Type.Optional(Type.String({ description: "Password for session-key login. Defaults to SPLUNK_PASSWORD." })),
  stack: Type.Optional(Type.String({ description: "Splunk Cloud stack name for ACS calls. Defaults to SPLUNK_STACK." })),
  acs_token: Type.Optional(Type.String({ description: "JWT for the Admin Config Service. Defaults to SPLUNK_ACS_TOKEN, then SPLUNK_TOKEN." })),
  acs_base_url: Type.Optional(Type.String({ description: "ACS base URL. Defaults to https://admin.splunk.com." })),
  verify_ssl: Type.Optional(Type.String({ description: "Set to false to skip TLS certificate verification for this request only (opt-out, not recommended). Defaults to SPLUNK_VERIFY_SSL or true." })),
  config_file: Type.Optional(Type.String({ description: "JSON config file with url, token, username, password, stack, acs_token, verify_ssl. Defaults to SPLUNK_CONFIG_FILE or ~/.config/grclanker/splunk.json." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

function runTool<T>(toolName: string, failurePrefix: string, run: () => Promise<{ text: string; details: JsonRecord }>) {
  return async () => {
    try {
      const result = await run();
      return textResult(result.text, { tool: toolName, ...result.details });
    } catch (error) {
      return errorResult(`${failurePrefix}: ${scrubErrorText(errorMessage(error))}`, { tool: toolName });
    }
  };
}

export function registerSplunkTools(pi: any): void {
  pi.registerTool({
    name: "splunk_check_access",
    label: "Check Splunk audit access",
    description: "Validate read-only Splunk access across server info, current-context capabilities, users, roles, tokens, authentication/server/web configuration, indexes, HEC and TCP inputs, saved searches, apps, KV Store collections, and Splunk Cloud ACS, reporting missing capabilities.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCommonArgs,
    async execute(_toolCallId: string, args: CommonArgs) {
      return runTool("splunk_check_access", "Splunk access check failed", async () => {
        const result = await checkSplunkAccess(createClient(args));
        return { text: formatAccessCheckText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_assess_authentication",
    label: "Assess Splunk authentication and identity",
    description: "Assess Splunk controls 1-6: SAML or LDAP enforcement, authentication.conf password policy, Duo/RSA or IdP MFA, session timeouts, concurrent session limits (manual), and authentication token hygiene.",
    parameters: Type.Object({
      ...authParams,
      max_token_age_days: Type.Optional(Type.Number({ description: "Tokens issued more than this many days ago are flagged. Defaults to 90.", default: 90 })),
      max_session_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable session timeout in minutes. Defaults to 60.", default: 60 })),
    }),
    prepareArguments: normalizeAuthenticationArgs,
    async execute(_toolCallId: string, args: AuthenticationArgs) {
      return runTool("splunk_assess_authentication", "Splunk authentication assessment failed", async () => {
        const result = await assessSplunkAuthentication(createClient(args), { maxTokenAgeDays: args.max_token_age_days, maxSessionMinutes: args.max_session_minutes });
        return { text: formatAssessmentText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_assess_access_control",
    label: "Assess Splunk authorization and access control",
    description: "Assess Splunk controls 7-12: high-risk role capabilities, admin role minimization, search index scope, _audit and _internal access, knowledge object sharing, and elevated capability audit.",
    parameters: Type.Object({
      ...authParams,
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin or sc_admin users. Defaults to 3.", default: 3 })),
    }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      return runTool("splunk_assess_access_control", "Splunk access control assessment failed", async () => {
        const result = await assessSplunkAccessControl(createClient(args), { maxAdmins: args.max_admins });
        return { text: formatAssessmentText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_assess_data_protection",
    label: "Assess Splunk data protection",
    description: "Assess Splunk controls 13-16: splunkd and Splunk Web TLS settings, encryption at rest (manual evidence), forwarder TLS in outputs.conf, and HEC token hygiene via REST or Splunk Cloud ACS.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCommonArgs,
    async execute(_toolCallId: string, args: CommonArgs) {
      return runTool("splunk_assess_data_protection", "Splunk data protection assessment failed", async () => {
        const result = await assessSplunkDataProtection(createClient(args));
        return { text: formatAssessmentText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_assess_audit_monitoring",
    label: "Assess Splunk audit logging",
    description: "Assess Splunk controls 17-18: _audit index status with a read-only oneshot search confirming login, search, and configuration-change events, plus audit deletion rights and _audit retention.",
    parameters: Type.Object({
      ...authParams,
      run_searches: Type.Optional(Type.Boolean({ description: "Run the read-only index=_audit oneshot search (creates a search job). Defaults to true.", default: true })),
      min_audit_retention_days: Type.Optional(Type.Number({ description: "Minimum acceptable _audit retention in days. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeAuditArgs,
    async execute(_toolCallId: string, args: AuditArgs) {
      return runTool("splunk_assess_audit_monitoring", "Splunk audit monitoring assessment failed", async () => {
        const result = await assessSplunkAuditMonitoring(createClient(args), { runSearches: args.run_searches, minAuditRetentionDays: args.min_audit_retention_days });
        return { text: formatAssessmentText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_assess_platform_hardening",
    label: "Assess Splunk platform hardening",
    description: "Assess Splunk controls 19-23: Splunk Cloud ACS IP allow lists, app provenance and installation rights, KV Store collection ACLs, scheduled search privileges, and splunktcp (S2S) listener TLS.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCommonArgs,
    async execute(_toolCallId: string, args: CommonArgs) {
      return runTool("splunk_assess_platform_hardening", "Splunk platform hardening assessment failed", async () => {
        const result = await assessSplunkPlatformHardening(createClient(args));
        return { text: formatAssessmentText(result), details: { ...result } };
      })();
    },
  });

  pi.registerTool({
    name: "splunk_export_audit_bundle",
    label: "Export Splunk audit bundle",
    description: "Export a Splunk evidence bundle: raw REST/ACS snapshots (core_data), normalized findings (analysis), executive summary, unified matrix and per-framework reports (compliance), QUICK_REFERENCE.md, _errors.log for partial collection, and a zip archive paired with the output directory.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_token_age_days: Type.Optional(Type.Number({ description: "Tokens issued more than this many days ago are flagged. Defaults to 90.", default: 90 })),
      max_session_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable session timeout in minutes. Defaults to 60.", default: 60 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin or sc_admin users. Defaults to 3.", default: 3 })),
      run_searches: Type.Optional(Type.Boolean({ description: "Run the read-only index=_audit oneshot search. Defaults to true.", default: true })),
      min_audit_retention_days: Type.Optional(Type.Number({ description: "Minimum acceptable _audit retention in days. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      return runTool("splunk_export_audit_bundle", "Splunk audit bundle export failed", async () => {
        const config = resolveSplunkConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSplunkAuditBundle(new SplunkApiClient(config), config, outputRoot, {
          maxTokenAgeDays: args.max_token_age_days,
          maxSessionMinutes: args.max_session_minutes,
          maxAdmins: args.max_admins,
          runSearches: args.run_searches,
          minAuditRetentionDays: args.min_audit_retention_days,
        });
        return {
          text: ["Splunk audit bundle exported.", `Output dir: ${result.outputDir}`, `Zip archive: ${result.zipPath}`, `Findings: ${result.findingCount}`, `Files: ${result.fileCount}`, `Collection errors: ${result.errorCount}`].join("\n"),
          details: { output_dir: result.outputDir, zip_path: result.zipPath, finding_count: result.findingCount, file_count: result.fileCount, error_count: result.errorCount },
        };
      })();
    },
  });
}
