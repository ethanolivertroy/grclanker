/**
 * Veracode security inspector tools for grclanker.
 *
 * Read-only inspection of a Veracode account through the HMAC-signed REST
 * APIs: application inventory, policy compliance, finding hygiene, SCA
 * posture, and identity hygiene, mapped to the frameworks in the spec.
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
import { basename, dirname, join, relative, resolve } from "node:path";
import { createHmac, randomBytes } from "node:crypto";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../flue/redact.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/veracode";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 50;
const DEFAULT_MAX_APPLICATIONS = 100;
const DEFAULT_MAX_WORKSPACES = 25;
const DEFAULT_MAX_ANALYSES = 25;
const MAX_DYNAMIC_SCANS_PER_ANALYSIS = 10;
const DEFAULT_MAX_SCAN_AGE_DAYS = 90;
const DEFAULT_CRITICAL_SCAN_INTERVAL_DAYS = 7;
const DEFAULT_STANDARD_SCAN_INTERVAL_DAYS = 31;
const DEFAULT_MAX_FP_RATE_PERCENT = 20;
const DEFAULT_MAX_FLAW_DENSITY_PER_KLOC = 1;
const DEFAULT_SCA_CVSS_THRESHOLD = 7;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_MAX_UNRESTRICTED_USERS = 10;
const DEFAULT_INACTIVE_DAYS = 90;
const DEFAULT_MAX_CREDENTIAL_AGE_DAYS = 365;
const DEFAULT_RETRIES = 3;
const DAY_MS = 86_400_000;
const REQUEST_VERSION = "vcode_request_version_1";
const AUTH_SCHEME = "VERACODE-HMAC-SHA-256";

export const VERACODE_REGION_HOSTS: Readonly<Record<string, string>> = {
  us: "api.veracode.com",
  commercial: "api.veracode.com",
  eu: "api.veracode.eu",
  europe: "api.veracode.eu",
  european: "api.veracode.eu",
  fedramp: "api.veracode.us",
  "us-fed": "api.veracode.us",
  federal: "api.veracode.us",
};

export interface VeracodeResolvedConfig {
  apiKeyId: string;
  apiKeySecret: string;
  region: string;
  baseUrl: string;
  timeoutMs: number;
  retries: number;
  profile: string;
  sourceChain: string[];
}

export interface FrameworkDescriptor {
  key: string;
  label: string;
  file: string;
}

export const VERACODE_FRAMEWORKS: ReadonlyArray<FrameworkDescriptor> = [
  { key: "fedramp", label: "FedRAMP", file: "fedramp.md" },
  { key: "cmmc", label: "CMMC", file: "cmmc.md" },
  { key: "soc2", label: "SOC 2", file: "soc2.md" },
  { key: "cis", label: "CIS Controls v8", file: "cis-controls-v8.md" },
  { key: "pci", label: "PCI-DSS", file: "pci-dss.md" },
  { key: "stig", label: "STIG", file: "stig.md" },
  { key: "irap", label: "IRAP", file: "irap.md" },
  { key: "ismap", label: "ISMAP", file: "ismap.md" },
];

interface ControlDescriptor {
  number: number;
  title: string;
  mappings: string[];
}

export const VERACODE_CONTROLS: ReadonlyArray<ControlDescriptor> = [
  { number: 1, title: "Application scan coverage", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-01"] },
  { number: 2, title: "Policy compliance status", mappings: ["FedRAMP SA-11(1)", "CMMC L2 3.14.3", "SOC 2 CC7.1", "CIS Controls v8 16.2", "PCI-DSS 6.3", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-02"] },
  { number: 3, title: "Flaw aging", mappings: ["FedRAMP SI-2", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 7.4", "PCI-DSS 6.3.3", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-03"] },
  { number: 4, title: "Scan frequency compliance", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5.6", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-01"] },
  { number: 5, title: "SCA library currency", mappings: ["FedRAMP SA-11(2)", "CMMC L2 3.14.2", "SOC 2 CC7.1", "CIS Controls v8 16.4", "PCI-DSS 6.3.2", "STIG SRG-APP-000454", "IRAP ISM-1490", "ISMAP VM-04"] },
  { number: 6, title: "SCA license risk", mappings: ["FedRAMP SA-4(2)", "CMMC L2 3.4.2", "SOC 2 CC3.2", "CIS Controls v8 2.2", "PCI-DSS 6.3.2", "STIG SRG-APP-000516", "IRAP ISM-1490", "ISMAP RM-01"] },
  { number: 7, title: "Team access controls", mappings: ["FedRAMP AC-6", "CMMC L2 3.1.5", "SOC 2 CC6.3", "CIS Controls v8 6.8", "PCI-DSS 7.2.2", "STIG SRG-APP-000340", "IRAP ISM-0432", "ISMAP AC-01"] },
  { number: 8, title: "User role audit", mappings: ["FedRAMP AC-6(5)", "CMMC L2 3.1.5", "SOC 2 CC6.3", "CIS Controls v8 5.4", "PCI-DSS 7.2.1", "STIG SRG-APP-000340", "IRAP ISM-0432", "ISMAP AC-02"] },
  { number: 9, title: "API credential management", mappings: ["FedRAMP IA-5(1)", "CMMC L2 3.5.8", "SOC 2 CC6.1", "CIS Controls v8 5.2", "PCI-DSS 8.6.3", "STIG SRG-APP-000174", "IRAP ISM-1590", "ISMAP AM-01"] },
  { number: 10, title: "Sandbox usage", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC8.1", "CIS Controls v8 16.7", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP SD-01"] },
  { number: 11, title: "Prescan module coverage", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-01"] },
  { number: 12, title: "Mitigation approval workflow", mappings: ["FedRAMP SI-2", "CMMC L2 3.14.1", "SOC 2 CC7.4", "CIS Controls v8 7.2", "PCI-DSS 6.3.3", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-05"] },
  { number: 13, title: "Dynamic scan configuration", mappings: ["FedRAMP SA-11(8)", "CMMC L2 3.14.6", "SOC 2 CC7.1", "CIS Controls v8 16.6", "PCI-DSS 6.6", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-06"] },
  { number: 14, title: "Pipeline integration status", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC8.1", "CIS Controls v8 16.12", "PCI-DSS 6.5.6", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP SD-02"] },
  { number: 15, title: "Custom policy profiles", mappings: ["FedRAMP SA-11(1)", "CMMC L2 3.14.3", "SOC 2 CC7.1", "CIS Controls v8 16.2", "PCI-DSS 6.3", "STIG SRG-APP-000516", "IRAP ISM-1143", "ISMAP VM-02"] },
  { number: 16, title: "Finding false positive rate", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-07"] },
  { number: 17, title: "Very High/High flaw density", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-03"] },
  { number: 18, title: "SCA workspace coverage", mappings: ["FedRAMP SA-11(2)", "CMMC L2 3.14.2", "SOC 2 CC7.1", "CIS Controls v8 16.4", "PCI-DSS 6.3.2", "STIG SRG-APP-000454", "IRAP ISM-1490", "ISMAP VM-04"] },
  { number: 19, title: "Scan completion rate", mappings: ["FedRAMP SA-11", "CMMC L2 3.14.1", "SOC 2 CC7.1", "CIS Controls v8 16.12", "PCI-DSS 6.5", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-01"] },
  { number: 20, title: "Collections compliance posture", mappings: ["FedRAMP SA-11(1)", "CMMC L2 3.14.3", "SOC 2 CC7.1", "CIS Controls v8 16.2", "PCI-DSS 6.3", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP VM-02"] },
];

export interface VeracodeFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface VeracodeAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: VeracodeFinding[];
  errors: string[];
  rawData: JsonRecord;
}

export interface VeracodeAccessSurface {
  name: string;
  /** The path the probe read, or the path whose request failed when the probe was not readable. */
  endpoint: string;
  status: "readable" | "not_readable";
  /** Items the probe saw; null, never 0, when the surface was not read. */
  count: number | null;
  /** Set when the probe's single page carried no vendor total, so `count` is the first page only. */
  countNote?: string;
  /** HTTP status of the failed request; null when the failure carried no HTTP status. Absent on a readable surface. */
  statusCode?: number | null;
  error?: string;
  requiredRole: string;
}

export interface VeracodeAccessCheckResult {
  status: "healthy" | "limited";
  region: string;
  baseUrl: string;
  principal?: string;
  surfaces: VeracodeAccessSurface[];
  missingRoles: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface VeracodeAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface HalListResult {
  items: JsonRecord[];
  pagesFetched: number;
  totalPages?: number;
  totalElements?: number;
  complete: boolean;
  notes?: string[];
}

/** A failed surface names the endpoint whose request failed, when the error carried one. */
type Surface<T> =
  | { status: "ok"; value: T }
  | { status: "error"; error: string; statusCode?: number; endpoint?: string };

/** What a bundle consumer reads in place of a dataset that was never collected. */
export interface VeracodeNotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string | null;
  error: string;
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
// A cookie header's value runs to the end of the line and may hold quoted pair or attribute values in
// plain, single, or JSON-escaped quotes; every quoted segment is part of the value, never its end.
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookies?)(\\?["']?\s*[:=]\s*)(?!\[REDACTED\])(?=\S)(?:[^\r\n<>"'\\]|\\?["'][^"'\r\n\\]*\\?["'])+/gi;
// A scheme word spelled as a header scheme followed by a run of 8 or more token characters is a
// credential whatever the run's shape; only the mechanism words vendor prose puts there ("Basic
// authentication", "Bearer credentials") are kept. Lowercase spellings in prose ("token provided")
// are not schemes; inside an Authorization carrier the scheme word is matched case-insensitively.
// The token after a scheme word may be quoted (plain, single, or JSON-escaped); the quote is kept and the token removed.
const SCHEME_VALUE_PATTERN =
  /\b(Bearer|BEARER|Basic|BASIC|Digest|DIGEST|Token|TOKEN|OAuth|OAUTH|Negotiate|NEGOTIATE|NTLM|SSWS|ApiKey|APIKEY|Api-Key|API-KEY|VERACODE-HMAC-SHA-256)\s+(\\?["']?)([A-Za-z0-9._~+/=-]{8,})/g;
const SCHEME_PROSE_WORDS = new Set(["authentication", "authorization", "authenticated", "authorized", "credential", "credentials", "challenge"]);
const SCHEME_WORD_PATTERN = /^(?:bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|splunk|hmac|veracode-hmac-sha-256)$/i;
const SCHEME_TOKEN_PATTERN = /^(\s+)(?!\[REDACTED\])(\\?["']?)([^\s"'<>;,()[\]{}\\]+)/;
// A pair key or value may sit in plain, single, or JSON-escaped quotes; the value ends at a quote or the escaping backslash.
const ASSIGNMENT_KEY_PATTERN = /(\\?["']?)\b([A-Za-z][A-Za-z0-9_.-]{0,63})\b(\\?["']?\s*([:=])\s*(\\?["']?))/g;
const ASSIGNMENT_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"'<>;,&()[\]{}\\]+/y;
const CLAUSE_END_PATTERN = /(?:[)\]}]|[.,;!?](?=\s|$)|[ \t]*(?:\r?\n|$))/y;
const HEADER_NAME_PATTERN = /^(?:[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+|authorization|cookies?)$/i;
const JWT_IN_TEXT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_PATTERN = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;
const HEX_DIGEST_PATTERN = /\b[A-Fa-f0-9]{32,}\b/g;
// The signed header value ("id=...,ts=...,nonce=...,sig=...") holds "," and so escapes the scheme
// value rule; whatever run follows the scheme word goes, quoted or not, and the scheme word and the
// opening quote stay so the header remains legible.
const HMAC_HEADER_PATTERN = /\b(VERACODE-HMAC-SHA-256)\s+(?!\\?["']?\[REDACTED\])(\\?["']?)[^\s"'\\]+/g;
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
// two sides of a pair are judged on their own; "=" joins a run only as trailing base64 padding, so a
// key whose value was already replaced ("httpEventCollectorToken=[REDACTED]") keeps its name.
const LONG_TOKEN_RUN_PATTERN = new RegExp(`[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&\\[]))?`, "g");
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

/** A 40-character base64 run is an AWS secret access key when it is random-looking; a bare path of word segments ("/api/v1/users/<id>/roles") that happens to span 40 characters is a request target and stays. */
function looksLikeAwsSecret(run: string): boolean {
  if (run.startsWith("/") || run.split("/").some((segment) => /^(?:[a-z]+|v\d+)$/.test(segment))) return false;
  if (/[/+]/.test(run)) return true;
  return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
}

/** MD5, SHA-1, and SHA-256 digests and hex-encoded keys: 32 or more hex characters mixing letters and digits. */
function looksLikeHexDigest(run: string): boolean {
  return /[A-Fa-f]/.test(run) && /\d/.test(run);
}

// camelCase and PascalCase identifiers: an optional lowercase head, capitalized words, and at most a
// short trailing acronym ("frozenTimePeriodInSecs", "maxTotalDataSizeMB").
const CAMEL_CASE_PATTERN = /^[a-z]*(?:[A-Z][a-z]+)*[A-Z]{0,4}$/;

/**
 * Token casing changes more often than once every three letters. Words and acronyms change at word
 * boundaries only, and a camelCase identifier whose words average three or more letters is a name
 * even when its case changes often ("frozenTimePeriodInSecs"); an alternating run of capitalized
 * one- or two-letter fragments ("xKqZvBnMwLpRtYsHdG") has no such word structure and is a token.
 */
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  let changes = 0;
  for (let index = 1; index < letters.length; index += 1) {
    const previousLower = letters[index - 1] >= "a" && letters[index - 1] <= "z";
    const currentLower = letters[index] >= "a" && letters[index] <= "z";
    if (previousLower !== currentLower) changes += 1;
  }
  if (changes * 3 <= letters.length) return false;
  if (!CAMEL_CASE_PATTERN.test(letters)) return true;
  const words = (letters.match(/[A-Z]/g) ?? []).length + (/^[a-z]/.test(letters) ? 1 : 0);
  return words * 3 > letters.length;
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

function scrubSchemeValue(match: string, scheme: string, quote: string, value: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(value)?.[0] ?? "";
  const word = value.slice(0, value.length - trailing.length);
  return SCHEME_PROSE_WORDS.has(word.toLowerCase()) ? match : `${scheme} ${quote}${REDACTED}${trailing}`;
}

/**
 * Replaces the value of every credential-named pair: `key=value`, `"key": "value"`, and
 * `Header-Name: value`. Inside a carrier the value goes whatever its shape (an `=` pair, a quoted
 * value, a header name, or a scheme word such as `Authorization: Bearer <token>`, where the scheme is
 * kept and the token removed); only an unquoted word after a plain `name:` that runs on into more
 * prose is judged by shape, so "InvalidAuthenticationToken: Access token has expired" stays legible
 * while "(session_id: value)" and "token: value" at the end of a clause lose the value. The last
 * segment of a bare path used as a label ("/api/authn/v2/api_credentials: <detail>") is a request
 * target, not a pair key, so the text after it is kept; inside a URL with a scheme the pair rule
 * still applies.
 */
function replaceCredentialAssignments(text: string): string {
  const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
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
    if (openingQuote === "" && separatorChar === ":" && isBarePathSegment(text, match.index, urlSpans)) continue;
    const valueStart = match.index + whole.length;
    ASSIGNMENT_VALUE_PATTERN.lastIndex = valueStart;
    const value = ASSIGNMENT_VALUE_PATTERN.exec(text)?.[0];
    if (value === undefined) continue;
    let kept = "";
    let consumed = value.length;
    if (SCHEME_WORD_PATTERN.test(value)) {
      const token = SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + value.length));
      if (!token) continue;
      kept = `${value}${token[1]}${token[2]}`;
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
    .replace(HMAC_HEADER_PATTERN, `$1 $2${REDACTED}`)
    .replace(JWT_IN_TEXT_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
    .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run))
    .replace(HEX_DIGEST_PATTERN, (run) => (looksLikeHexDigest(run) ? REDACTED : run));
  for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
  return scrubBareTokens(scrubbed);
}

export class VeracodeApiError extends Error {
  readonly statusCode?: number;
  readonly endpoint?: string;

  /**
   * The message is scrubbed here as well as at the record point, so an error
   * built anywhere in the client never carries a credential even if a caller
   * stores error.message directly.
   */
  constructor(message: string, statusCode?: number, endpoint?: string) {
    super(scrubErrorText(message));
    this.name = "VeracodeApiError";
    this.statusCode = statusCode;
    this.endpoint = endpoint;
  }
}

type AuthArgs = {
  api_key_id?: string;
  api_key_secret?: string;
  region?: string;
  base_url?: string;
  profile?: string;
  credentials_file?: string;
  timeout_seconds?: number;
};

type ScanCoverageArgs = AuthArgs & {
  max_applications?: number;
  max_scan_age_days?: number;
  max_analyses?: number;
  critical_scan_interval_days?: number;
  standard_scan_interval_days?: number;
};

type PolicyArgs = AuthArgs & {
  max_applications?: number;
};

type FindingsArgs = AuthArgs & {
  max_applications?: number;
  max_fp_rate_percent?: number;
  max_flaw_density_per_kloc?: number;
};

type ScaArgs = AuthArgs & {
  max_applications?: number;
  max_workspaces?: number;
  sca_cvss_threshold?: number;
};

type AccessControlArgs = AuthArgs & {
  max_admins?: number;
  max_unrestricted_users?: number;
  inactive_days?: number;
  max_credential_age_days?: number;
};

type ExportArgs = ScanCoverageArgs & FindingsArgs & ScaArgs & AccessControlArgs & {
  output_dir?: string;
};

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
    if (/^true$/i.test(value.trim())) return true;
    if (/^false$/i.test(value.trim())) return false;
  }
  return undefined;
}

function parseDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysSince(date: Date, now: Date): number {
  return Math.floor((now.getTime() - date.getTime()) / DAY_MS);
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function clampFloat(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = value ?? fallback;
  return Math.min(Math.max(parsed, min), max);
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
  return normalized || "veracode";
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
  for (let attempt = 1; attempt <= 50; attempt += 1) {
    const suffix = attempt === 1 ? "" : `-${attempt}`;
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

export function parseIniProfiles(contents: string): Record<string, Record<string, string>> {
  const profiles: Record<string, Record<string, string>> = {};
  let current: string | undefined;
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const section = /^\[(.+)\]$/.exec(line);
    if (section) {
      current = section[1].trim();
      profiles[current] ??= {};
      continue;
    }
    const separator = line.indexOf("=");
    if (separator === -1 || !current) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    profiles[current][key] = value;
  }
  return profiles;
}

const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;

function thrownCode(error: unknown, pattern: RegExp): string | undefined {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  return typeof code === "string" && pattern.test(code) ? code : undefined;
}

/**
 * Read step of the credentials loader: a missing file is simply absent,
 * every other failure is reported by path and errno code only, never by the
 * filesystem's own wording.
 */
function readCredentialsFileText(pathname: string): string | undefined {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const code = thrownCode(error, FS_ERROR_CODE_PATTERN);
    if (code === "ENOENT") return undefined;
    throw new Error(`Unable to read Veracode credentials file ${pathname} (${code ?? "UNREADABLE"})`);
  }
}

/** Parse step: catches every thrown value and reports the path with a fixed code; the file holds API secrets, so nothing from it is repeated. */
function readCredentialsProfile(pathname: string, profile: string): Record<string, string> | undefined {
  const text = readCredentialsFileText(pathname);
  if (text === undefined) return undefined;
  try {
    return parseIniProfiles(text)[profile];
  } catch {
    throw new Error(`Unable to parse Veracode credentials file: invalid INI in ${pathname} (INVALID_INI)`);
  }
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

export function resolveVeracodeRegionHost(region: string): string {
  const host = VERACODE_REGION_HOSTS[region.trim().toLowerCase()];
  if (!host) {
    throw new Error(`Unknown Veracode region "${region}". Use us, eu, or us-fed.`);
  }
  return host;
}

export function resolveVeracodeConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDir?: string } = {},
): VeracodeResolvedConfig {
  const sourceChain: string[] = [];
  const profile = asString(input.profile) ?? asString(env.VERACODE_API_PROFILE) ?? "default";
  const credentialsFile = asString(input.credentials_file)
    ?? asString(env.VERACODE_API_CREDENTIALS_FILE)
    ?? join(options.homeDir ?? homedir(), ".veracode", "credentials");

  let apiKeyId = asString(input.api_key_id);
  let apiKeySecret = asString(input.api_key_secret);
  if (apiKeyId) sourceChain.push("arguments-api-key-id");
  if (apiKeySecret) sourceChain.push("arguments-api-key-secret");

  if (!apiKeyId && asString(env.VERACODE_API_KEY_ID)) {
    apiKeyId = asString(env.VERACODE_API_KEY_ID);
    sourceChain.push("environment-api-key-id");
  }
  if (!apiKeySecret && asString(env.VERACODE_API_KEY_SECRET)) {
    apiKeySecret = asString(env.VERACODE_API_KEY_SECRET);
    sourceChain.push("environment-api-key-secret");
  }

  if (!apiKeyId || !apiKeySecret) {
    const fileProfile = readCredentialsProfile(credentialsFile, profile);
    if (fileProfile) {
      if (!apiKeyId && asString(fileProfile.veracode_api_key_id)) {
        apiKeyId = asString(fileProfile.veracode_api_key_id);
        sourceChain.push(`credentials-file-api-key-id (${profile})`);
      }
      if (!apiKeySecret && asString(fileProfile.veracode_api_key_secret)) {
        apiKeySecret = asString(fileProfile.veracode_api_key_secret);
        sourceChain.push(`credentials-file-api-key-secret (${profile})`);
      }
    }
  }

  if (!apiKeyId || !apiKeySecret) {
    throw new Error(
      "Veracode API credentials are required: pass api_key_id and api_key_secret, set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET, "
      + `or add veracode_api_key_id and veracode_api_key_secret to the [${profile}] profile in ${credentialsFile}.`,
    );
  }
  if (!/^[0-9a-f]+$/i.test(apiKeySecret)) {
    throw new Error("The Veracode API key secret must be a hex string; check the credential value.");
  }

  const region = (asString(input.region) ?? asString(env.VERACODE_REGION) ?? "us").toLowerCase();
  const explicitBaseUrl = asString(input.base_url) ?? asString(env.VERACODE_API_BASE_URL);
  const baseUrl = normalizeBaseUrl(explicitBaseUrl ?? `https://${resolveVeracodeRegionHost(region)}`);
  sourceChain.push(explicitBaseUrl ? "explicit-base-url" : `region-${region}`);

  return {
    apiKeyId,
    apiKeySecret,
    region,
    baseUrl,
    timeoutMs: clampNumber(asNumber(input.timeout_seconds) ?? asNumber(env.VERACODE_TIMEOUT), DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000,
    retries: clampNumber(asNumber(input.retries), DEFAULT_RETRIES, 0, 8),
    profile,
    sourceChain: [...new Set(sourceChain)],
  };
}

export interface VeracodeSignatureInput {
  apiKeyId: string;
  apiKeySecret: string;
  host: string;
  urlPathWithQuery: string;
  method: string;
  timestampMs: number;
  nonceHex: string;
}

export function computeVeracodeSignature(input: VeracodeSignatureInput): string {
  const data = `id=${input.apiKeyId}&host=${input.host}&url=${input.urlPathWithQuery}&method=${input.method.toUpperCase()}`;
  const keyBytes = Buffer.from(input.apiKeySecret, "hex");
  const nonceBytes = Buffer.from(input.nonceHex, "hex");
  const encryptedNonce = createHmac("sha256", keyBytes).update(nonceBytes).digest();
  const encryptedTimestamp = createHmac("sha256", encryptedNonce).update(String(input.timestampMs), "utf8").digest();
  const signingKey = createHmac("sha256", encryptedTimestamp).update(REQUEST_VERSION, "utf8").digest();
  return createHmac("sha256", signingKey).update(data, "utf8").digest("hex");
}

export function buildVeracodeAuthorizationHeader(
  input: Omit<VeracodeSignatureInput, "timestampMs" | "nonceHex"> & { timestampMs?: number; nonceHex?: string },
): string {
  const timestampMs = input.timestampMs ?? Date.now();
  const nonceHex = input.nonceHex ?? randomBytes(16).toString("hex");
  const signature = computeVeracodeSignature({ ...input, timestampMs, nonceHex });
  return `${AUTH_SCHEME} id=${input.apiKeyId},ts=${timestampMs},nonce=${nonceHex},sig=${signature}`;
}

/** The caller's API key pair; every form of each is removed from error text. */
function configuredSecretsOf(config: Pick<VeracodeResolvedConfig, "apiKeyId" | "apiKeySecret">): string[] {
  return [config.apiKeyId, config.apiKeySecret];
}

/** Describes a body that is not JSON by size only; the text itself is never kept. */
function describeNonJsonBody(rawText: string): string {
  return `non-JSON response body (${Buffer.byteLength(rawText)} bytes, not recorded)`;
}

/** Keeps only the vendor's message fields from an error body; a non-JSON body is described by size, never quoted. */
function errorDetailFrom(rawText: string): string {
  if (rawText.length === 0) return "";
  try {
    const payload = asObject(JSON.parse(rawText)) ?? {};
    const embeddedErrors = asRecords(asObject(payload._embedded)?.errors).map((item) => asString(item.detail) ?? asString(item.message)).filter((item): item is string => Boolean(item));
    const message = [asString(payload.message), asString(payload.error_description), asString(payload.error), ...embeddedErrors].filter((item): item is string => Boolean(item)).join("; ");
    return message.length > 0 ? message.replace(/\s+/g, " ").slice(0, 240) : `JSON response body (${rawText.length} bytes) carried no message field`;
  } catch {
    return describeNonJsonBody(rawText);
  }
}

/**
 * Parses a 2xx body. A body that is not a JSON object (an HTML sign-in page,
 * a proxy notice) is an unreadable surface, not an empty result, and is
 * described by size: JSON.parse's own message quotes a window of the text and
 * is never interpolated.
 */
function parseSuccessBody(response: Response, rawText: string, endpoint: string): JsonRecord {
  if (rawText.length === 0) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new VeracodeApiError(
      `Veracode request to ${endpoint} returned an unreadable response (${response.status} ${response.statusText}): ${describeNonJsonBody(rawText)}`,
      response.status,
      endpoint,
    );
  }
  return asObject(parsed) ?? {};
}

function extractEmbedded(payload: JsonRecord, embeddedKey: string): JsonRecord[] {
  const embedded = payload._embedded;
  if (Array.isArray(embedded)) return asRecords(embedded);
  const object = asObject(embedded);
  if (!object) return [];
  return asRecords(object[embeddedKey]);
}

function readPageMetadata(payload: JsonRecord): { totalPages?: number; totalElements?: number } {
  const page = asObject(payload.page) ?? {};
  return {
    totalPages: asNumber(page.total_pages) ?? asNumber(page.totalPages),
    totalElements: asNumber(page.total_elements) ?? asNumber(page.totalElements),
  };
}

export class VeracodeApiClient {
  private readonly config: VeracodeResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    config: VeracodeResolvedConfig,
    options: { fetchImpl?: FetchImpl; sleep?: (ms: number) => Promise<void> } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
  }

  getResolvedConfig(): VeracodeResolvedConfig {
    return this.config;
  }

  buildUrl(path: string, query: JsonRecord = {}): URL {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url;
  }

  authorizationHeaderFor(url: URL, method = "GET"): string {
    return buildVeracodeAuthorizationHeader({
      apiKeyId: this.config.apiKeyId,
      apiKeySecret: this.config.apiKeySecret,
      host: url.host,
      urlPathWithQuery: `${url.pathname}${url.search}`,
      method,
    });
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path, query);
    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const response = await this.fetchImpl(url.toString(), {
          method: "GET",
          headers: {
            accept: "application/json",
            authorization: this.authorizationHeaderFor(url, "GET"),
          },
          signal: controller.signal,
        });
        const rawText = await response.text();
        if (response.ok) return parseSuccessBody(response, rawText, url.pathname);
        const retryable = response.status === 429 || response.status >= 500;
        if (retryable && attempt < this.config.retries) {
          attempt += 1;
          await this.sleep(Math.min(250 * 2 ** attempt, 8_000));
          continue;
        }
        const detail = scrubErrorText(errorDetailFrom(rawText), configuredSecretsOf(this.config));
        throw new VeracodeApiError(
          `Veracode request failed (${response.status} ${response.statusText}) for ${url.pathname}${detail ? `: ${detail}` : ""}`,
          response.status,
          url.pathname,
        );
      } catch (error) {
        if (error instanceof VeracodeApiError) throw error;
        const message = scrubErrorText(error instanceof Error ? error.message : String(error), configuredSecretsOf(this.config));
        if (attempt < this.config.retries) {
          attempt += 1;
          await this.sleep(Math.min(250 * 2 ** attempt, 8_000));
          continue;
        }
        throw new VeracodeApiError(`Veracode request failed for ${url.pathname}: ${message}`, undefined, url.pathname);
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  async listHal(
    path: string,
    embeddedKey: string,
    query: JsonRecord = {},
    options: { maxPages?: number; pageSize?: number } = {},
  ): Promise<HalListResult> {
    const maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 1000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 500);
    const items: JsonRecord[] = [];
    let pagesFetched = 0;
    let totalPages: number | undefined;
    let totalElements: number | undefined;
    let exhausted = false;
    let previousPage: string | undefined;

    for (let page = 0; page < maxPages; page += 1) {
      const payload = await this.get(path, { ...query, page, size: pageSize });
      pagesFetched += 1;
      const pageItems = extractEmbedded(payload, embeddedKey);
      const pageKey = JSON.stringify(pageItems.map((item) => item.guid ?? item.id ?? item.user_id ?? item.team_id ?? item.issue_id ?? item.scan_id ?? item));
      if (pageItems.length > 0 && pageKey === previousPage) {
        // The server ignored the page parameter, so the walk can never advance; report it as truncated.
        return { items, pagesFetched, totalPages, totalElements, complete: false, notes: [`${path} returned the same page twice, so pagination stopped after ${items.length} items.`] };
      }
      previousPage = pageKey;
      items.push(...pageItems);
      const metadata = readPageMetadata(payload);
      totalPages = metadata.totalPages ?? totalPages;
      totalElements = metadata.totalElements ?? totalElements;
      if (totalPages !== undefined ? page + 1 >= totalPages : pageItems.length < pageSize) {
        exhausted = true;
        break;
      }
    }

    // A page-cap exit without page metadata leaves the total unknown, so the partial-inventory note prints "an unknown total".
    const complete = exhausted || (totalPages !== undefined && pagesFetched >= totalPages);
    return { items, pagesFetched, totalPages, totalElements, complete: complete && (totalElements === undefined || items.length >= totalElements) };
  }

  async getSelf(): Promise<JsonRecord> {
    return this.get("/api/authn/v2/users/self");
  }

  async getSelfApiCredentials(): Promise<JsonRecord> {
    return this.get("/api/authn/v2/api_credentials");
  }

  async listApplications(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/appsec/v1/applications", "applications", {}, options);
  }

  async listSandboxes(applicationGuid: string): Promise<HalListResult> {
    return this.listHal(`/appsec/v1/applications/${encodeURIComponent(applicationGuid)}/sandboxes`, "sandboxes", {}, { maxPages: 10 });
  }

  async listFindings(applicationGuid: string, query: JsonRecord = {}, options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal(`/appsec/v2/applications/${encodeURIComponent(applicationGuid)}/findings`, "findings", query, { pageSize: 500, ...options });
  }

  async getSummaryReport(applicationGuid: string): Promise<JsonRecord> {
    return this.get(`/appsec/v2/applications/${encodeURIComponent(applicationGuid)}/summary_report`);
  }

  async listPolicies(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/appsec/v1/policies", "policy_versions", {}, options);
  }

  async listUsers(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/api/authn/v2/users", "users", { detailed: "true", include_roles: "true", include_teams: "true" }, options);
  }

  async listTeams(options: { maxPages?: number } = {}): Promise<HalListResult> {
    try {
      return await this.listHal("/api/authn/v2/teams", "teams", { all_for_org: "true" }, options);
    } catch (error) {
      if (!(error instanceof VeracodeApiError) || (error.statusCode !== 400 && error.statusCode !== 403)) throw error;
      const memberTeams = await this.listHal("/api/authn/v2/teams", "teams", {}, options);
      return {
        ...memberTeams,
        notes: [
          ...(memberTeams.notes ?? []),
          `all_for_org=true was refused (${error.statusCode}), so only teams the API user is a member of were listed and the team inventory is a partial view.`,
        ],
      };
    }
  }

  async listRoles(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/api/authn/v2/roles", "roles", {}, options);
  }

  async getUserApiCredentials(userId: string): Promise<JsonRecord> {
    return this.get(`/api/authn/v2/api_credentials/user_id/${encodeURIComponent(userId)}`);
  }

  async listScaWorkspaces(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/srcclr/v3/workspaces", "workspaces", {}, options);
  }

  async listScaWorkspaceIssues(workspaceId: string, type: "vulnerability" | "license" | "library"): Promise<HalListResult> {
    return this.listHal(`/srcclr/v3/workspaces/${encodeURIComponent(workspaceId)}/issues`, "issues", { type, status: "open" }, { maxPages: 20 });
  }

  async listScaWorkspaceLibraries(workspaceId: string): Promise<HalListResult> {
    return this.listHal(`/srcclr/v3/workspaces/${encodeURIComponent(workspaceId)}/libraries`, "libraries", {}, { maxPages: 5 });
  }

  async getScaApplicationProjects(applicationGuid: string): Promise<JsonRecord> {
    return this.get(`/srcclr/v3/applications/${encodeURIComponent(applicationGuid)}/projects`);
  }

  async listDynamicAnalyses(options: { maxPages?: number } = {}): Promise<HalListResult> {
    return this.listHal("/was/configservice/v1/analyses", "analyses", {}, options);
  }

  async listDynamicAnalysisScans(analysisId: string): Promise<HalListResult> {
    return this.listHal(`/was/configservice/v1/analyses/${encodeURIComponent(analysisId)}/scans`, "scans", {}, { maxPages: 5 });
  }

  async getDynamicScanConfiguration(scanId: string): Promise<JsonRecord> {
    return this.get(`/was/configservice/v1/scans/${encodeURIComponent(scanId)}/configuration`);
  }
}

type ClientLike = Pick<
  VeracodeApiClient,
  | "getResolvedConfig"
  | "getSelf"
  | "getSelfApiCredentials"
  | "listApplications"
  | "listSandboxes"
  | "listFindings"
  | "getSummaryReport"
  | "listPolicies"
  | "listUsers"
  | "listTeams"
  | "listRoles"
  | "getUserApiCredentials"
  | "listScaWorkspaces"
  | "listScaWorkspaceIssues"
  | "listScaWorkspaceLibraries"
  | "getScaApplicationProjects"
  | "listDynamicAnalyses"
  | "listDynamicAnalysisScans"
  | "getDynamicScanConfiguration"
>;

/**
 * The record point for every surface error: the message is scrubbed here as
 * well as in VeracodeApiError, so an error thrown by anything other than the
 * client (a mocked reader, a JSON parse) is recorded without a credential too.
 */
async function surface<T>(load: () => Promise<T>): Promise<Surface<T>> {
  try {
    return { status: "ok", value: await load() };
  } catch (error) {
    const statusCode = asNumber(asObject(error)?.statusCode);
    return {
      status: "error",
      error: toolErrorText(error),
      statusCode,
      endpoint: asString(asObject(error)?.endpoint),
    };
  }
}

/** The text a tool result or a surface keeps for a thrown value: scrubbed here as well as in the VeracodeApiError constructor. */
function toolErrorText(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

/**
 * The single serializer for a surface on every raw-data path: a surface that
 * was never collected is written as { collected: false, status, endpoint,
 * error } so a bundle consumer cannot mistake a denial for an empty
 * inventory; readable-but-empty lists keep []. `project` narrows a readable
 * value to the part the snapshot keeps.
 */
function rawSurface<T, R = T>(item: Surface<T>, project: (value: T) => R = (value) => value as unknown as R): R | VeracodeNotCollectedMarker {
  if (item.status === "ok") return project(item.value);
  return { collected: false, status: item.statusCode ?? null, endpoint: item.endpoint ?? null, error: item.error };
}

/** The marker for a dataset whose requests were never issued because an inventory it depends on was not readable. */
function notAttempted(reason: string): VeracodeNotCollectedMarker {
  return { collected: false, status: null, endpoint: null, error: `Not requested: ${reason}` };
}

/** A count derived from a surface: null, never 0, when the surface was not read. */
function countIfRead(item: Surface<HalListResult>): number | null {
  return item.status === "ok" ? item.value.items.length : null;
}

/** The vendor total when the list carried one, the seen count when the walk finished, otherwise null: a capped walk has no known total. */
function knownTotal(list: HalListResult): number | null {
  return list.totalElements ?? (list.complete ? list.items.length : null);
}

function surfaceErrors(name: string, item: Surface<unknown>): string[] {
  return item.status === "error" ? [`${name}: ${item.error}`] : [];
}

function isForbidden(item: Surface<unknown>): boolean {
  return item.status === "error" && (item.statusCode === 401 || item.statusCode === 403);
}

function isUnavailable(item: Surface<unknown>): boolean {
  return item.status === "error" && (item.statusCode === 404 || isForbidden(item));
}

function unreadableReason(name: string, item: Surface<unknown>): string {
  if (item.status !== "error") return `The ${name} surface was not read.`;
  const cause = item.statusCode === 401 || item.statusCode === 403
    ? `was forbidden (${item.statusCode})`
    : item.statusCode
      ? `returned an error (${item.statusCode})`
      : "could not be read";
  return `The ${name} endpoint ${cause}, so the control could not be verified: ${item.error}`;
}

function controlDescriptor(number: number): ControlDescriptor {
  const control = VERACODE_CONTROLS.find((item) => item.number === number);
  if (!control) throw new Error(`Unknown Veracode control ${number}`);
  return control;
}

function controlId(number: number): string {
  return `VERACODE-${String(number).padStart(2, "0")}`;
}

function finding(
  number: number,
  severity: VeracodeFinding["severity"],
  status: VeracodeFinding["status"],
  summary: string,
  evidence?: JsonRecord,
): VeracodeFinding {
  const control = controlDescriptor(number);
  return { id: controlId(number), title: control.title, severity, status, summary, mappings: [...control.mappings], evidence };
}

function manualFinding(
  number: number,
  severity: VeracodeFinding["severity"],
  reason: string,
  evidenceToCollect: string[],
  evidence: JsonRecord = {},
  caveats: Array<string | undefined> = [],
): VeracodeFinding {
  return finding(number, severity, "manual", joinNotes(reason, ...caveats, `Manual evidence required: ${evidenceToCollect.join(" ")}`), {
    ...evidence,
    manual_evidence: evidenceToCollect,
  });
}

type UnreadableLinkedProjectList = { application: string; status: number | null; endpoint: string | null };

const HTTP_REASON_PHRASES: Record<number, string> = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests",
  500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
};

/** A status the run observed with its reason phrase, so a summary reads "403 Forbidden" rather than a bare number. */
function statusPhrase(status: number): string {
  const phrase = HTTP_REASON_PHRASES[status];
  return phrase ? `${status} ${phrase}` : String(status);
}

/**
 * Names the linked project lists that could not be read from the observed surfaces only: how many
 * of the requested lists, the endpoint they were requested from when the client reported it (the
 * per-application family is rendered with a {guid} placeholder once more than one list is named),
 * and every status the run observed for them.
 */
function describeUnreadableLinkedProjectLists(lists: UnreadableLinkedProjectList[], requested: number): { count: string; observed: string } {
  const endpoints = [...new Set(lists.map((item) => item.endpoint).filter((endpoint): endpoint is string => Boolean(endpoint)))];
  const family = /\/applications\/[^/]+\/projects$/;
  let subject = "the requests";
  if (endpoints.length === 1) subject = `GET ${endpoints[0]}`;
  else if (endpoints.length > 1 && endpoints.every((endpoint) => family.test(endpoint))) subject = `GET ${endpoints[0].replace(family, "/applications/{guid}/projects")}`;
  else if (endpoints.length > 1) subject = `GET ${endpoints.slice(0, 2).join(" and ")}${endpoints.length > 2 ? ` and ${endpoints.length - 2} more` : ""}`;
  const outcomes = new Map<string, number>();
  for (const item of lists) {
    const label = item.status === null ? "no status" : statusPhrase(item.status);
    outcomes.set(label, (outcomes.get(label) ?? 0) + 1);
  }
  const rendered = [...outcomes.entries()].map(([label, count]) => (outcomes.size > 1 ? `${label} (${count})` : label));
  const observed = outcomes.size === 1 && outcomes.has("no status") ? `${subject} returned no status` : `${subject} returned ${rendered.join(" and ")}`;
  return { count: `${lists.length} of ${requested}`, observed };
}

function partialInventoryNote(list: HalListResult, noun: string): string | undefined {
  if (list.complete) return undefined;
  return `Only ${list.items.length} of ${list.totalElements ?? "an unknown total of"} ${noun} were read (${list.pagesFetched}/${list.totalPages ?? "?"} pages), so the verdict reflects a partial inventory.`;
}

function scopeNote(sampled: number, total: number, noun: string): string | undefined {
  return sampled < total ? `Only ${sampled} of ${total} ${noun} were sampled, so the verdict reflects a partial view.` : undefined;
}

function limitedStatus(
  desired: VeracodeFinding["status"],
  caveats: Array<string | undefined>,
): VeracodeFinding["status"] {
  if (desired === "pass" && caveats.some(Boolean)) return "warn";
  return desired;
}

function joinNotes(...parts: Array<string | undefined>): string {
  return parts.filter((part): part is string => Boolean(part)).join(" ");
}

function applicationName(app: JsonRecord): string {
  return asString(asObject(app.profile)?.name) ?? asString(app.guid) ?? "application";
}

function applicationGuid(app: JsonRecord): string | undefined {
  return asString(app.guid);
}

function applicationPolicies(app: JsonRecord): JsonRecord[] {
  return asRecords(asObject(app.profile)?.policies);
}

function applicationTeams(app: JsonRecord): JsonRecord[] {
  return asRecords(asObject(app.profile)?.teams);
}

function applicationScans(app: JsonRecord): JsonRecord[] {
  return asRecords(app.scans);
}

function businessCriticality(app: JsonRecord): string | undefined {
  return asString(asObject(app.profile)?.business_criticality)?.toUpperCase();
}

const FAILED_SCAN_STATUSES = new Set([
  "ANALYSIS_ERRORS",
  "SCAN_CANCELED",
  "PRE_SCAN_FAILED",
  "PRE_SCAN_CANCELED",
  "NTO_PRE_SCAN_CANCELED",
  "INCOMPLETE",
  "MODULE_SELECTION_REQUIRED",
]);

const COMPLETED_SCAN_STATUSES = new Set([
  "PUBLISHED",
  "PUBLISHED_TO_VENDOR",
  "PUBLISHED_TO_ENTERPRISE",
  "PUBLISHED_TO_ENTERPRISEINT",
]);

type LatestScanState =
  | { kind: "none" }
  | { kind: "not_completed"; status: string }
  | { kind: "missing_date" }
  | { kind: "completed"; date: Date };

function latestScanState(app: JsonRecord, scanType: string): LatestScanState {
  const scans = applicationScans(app).filter((scan) => asString(scan.scan_type)?.toUpperCase() === scanType);
  if (scans.length === 0) return { kind: "none" };
  const completed = scans.filter((scan) => COMPLETED_SCAN_STATUSES.has(asString(scan.status)?.toUpperCase() ?? ""));
  if (completed.length === 0) return { kind: "not_completed", status: asString(scans[0].status)?.toUpperCase() ?? "UNKNOWN" };
  const dates = completed.map((scan) => parseDate(scan.modified_date)).filter((date): date is Date => date !== undefined);
  if (dates.length === 0) return { kind: "missing_date" };
  return { kind: "completed", date: new Date(Math.max(...dates.map((date) => date.getTime()))) };
}

const FREQUENCY_DAYS: Readonly<Record<string, number>> = {
  WEEKLY: 7,
  MONTHLY: 31,
  QUARTERLY: 92,
  SEMI_ANNUALLY: 183,
  ANNUALLY: 366,
  EVERY_18_MONTHS: 548,
  EVERY_2_YEARS: 731,
  EVERY_3_YEARS: 1096,
};

const MITIGATION_ACTIONS = new Set(["FP", "APPDESIGN", "OSENV", "NETENV", "ACCEPTRISK", "BYENV", "BYDESIGN", "LIBRARY", "DEFER", "CUSTOMCLEANSERPROPOSED"]);

const FLAW_AGE_THRESHOLDS: Readonly<Record<number, number>> = { 5: 30, 4: 60, 3: 90, 2: 180 };

interface ApplicationSnapshot {
  applications: Surface<HalListResult>;
  self: Surface<JsonRecord>;
}

async function collectApplications(client: ClientLike): Promise<ApplicationSnapshot> {
  const [applications, self] = await Promise.all([
    surface(() => client.listApplications()),
    surface(() => client.getSelf()),
  ]);
  return { applications, self };
}

function applicationInventoryBlocker(
  number: number,
  severity: VeracodeFinding["severity"],
  snapshot: ApplicationSnapshot,
  evidenceToCollect: string[],
): VeracodeFinding | undefined {
  if (snapshot.applications.status === "error") {
    return manualFinding(number, severity, unreadableReason("applications (Security Insights or Reviewer role)", snapshot.applications), evidenceToCollect, {
      status_code: snapshot.applications.statusCode ?? null,
    });
  }
  if (snapshot.applications.value.items.length === 0) {
    return manualFinding(
      number,
      severity,
      "The applications endpoint returned zero application profiles, which cannot be treated as a compliant inventory: either the account has no applications or the credential's team scoping hides them.",
      ["Confirm the application inventory in the Veracode Platform and grant the API user a team-unrestricted read role (Security Insights).", ...evidenceToCollect],
    );
  }
  return undefined;
}

function evaluateScanCoverage(snapshot: ApplicationSnapshot, maxScanAgeDays: number, now: Date): VeracodeFinding {
  const blocker = applicationInventoryBlocker(1, "critical", snapshot, ["Export the application list with the latest published static scan date per application from the Platform."]);
  if (blocker) return blocker;
  const list = (snapshot.applications as { value: HalListResult }).value;
  const stale: Array<{ application: string; days_since_published_static_scan: number; last_completed_scan_date: string | null }> = [];
  const noStaticScan: Array<{ application: string; scan_types_present: string[]; last_completed_scan_date: string | null }> = [];
  const notPublished: Array<{ application: string; latest_static_status: string }> = [];
  const missingDate: string[] = [];
  let fresh = 0;
  for (const app of list.items) {
    const state = latestScanState(app, "STATIC");
    switch (state.kind) {
      case "none":
        noStaticScan.push({ application: applicationName(app), scan_types_present: applicationScans(app).map((scan) => asString(scan.scan_type) ?? "UNKNOWN"), last_completed_scan_date: asString(app.last_completed_scan_date) ?? null });
        break;
      case "not_completed":
        notPublished.push({ application: applicationName(app), latest_static_status: state.status });
        break;
      case "missing_date":
        missingDate.push(applicationName(app));
        break;
      case "completed": {
        const age = daysSince(state.date, now);
        if (age > maxScanAgeDays) stale.push({ application: applicationName(app), days_since_published_static_scan: age, last_completed_scan_date: asString(app.last_completed_scan_date) ?? null });
        else fresh += 1;
        break;
      }
      default: {
        const exhaustive: never = state;
        throw new Error(`Unhandled scan state ${String(exhaustive)}`);
      }
    }
  }
  const partial = partialInventoryNote(list, "applications");
  const evidence = {
    applications_seen: list.items.length,
    applications_total: list.totalElements ?? null,
    fresh_applications: fresh,
    stale_applications: stale.slice(0, 50),
    applications_without_static_scan: noStaticScan.slice(0, 50),
    applications_with_unpublished_latest_static_scan: notPublished.slice(0, 50),
    applications_without_static_scan_date: missingDate.slice(0, 50),
    max_scan_age_days: maxScanAgeDays,
    date_source: "scans[].modified_date of the latest STATIC scan in a published status",
  };
  if (stale.length > 0 || noStaticScan.length > 0) {
    return finding(1, "critical", "fail", joinNotes(
      `${stale.length}/${list.items.length} applications have no published static scan within ${maxScanAgeDays} days and ${noStaticScan.length} applications expose no static scan at all (dynamic, manual, or SCA scans and the scan-type agnostic last_completed_scan_date do not satisfy this control).`,
      partial,
    ), evidence);
  }
  if (notPublished.length > 0 || missingDate.length > 0) {
    return finding(1, "critical", "warn", joinNotes(
      `${notPublished.length}/${list.items.length} applications expose a latest static scan that is not in a published status and ${missingDate.length} expose no modified_date on their published static scan, so they are not counted as covered; ${fresh} applications have a published static scan within ${maxScanAgeDays} days.`,
      partial,
    ), evidence);
  }
  return finding(1, "critical", limitedStatus("pass", [partial]), joinNotes(`All ${fresh} applications read have a published static scan within ${maxScanAgeDays} days.`, partial), evidence);
}

interface FrequencyRequirement {
  scanType: string;
  days: number;
  source: string;
}

interface CriticalityIntervals {
  criticalDays: number;
  standardDays: number;
}

type RequirementOutcome =
  | { kind: "met" }
  | { kind: "overdue"; detail: string }
  | { kind: "unconfirmed"; detail: string };

function describeInterval(days: number): string {
  return Number.isFinite(days) ? `every ${days} days` : "at least once";
}

function policyFrequencyRequirements(policy: JsonRecord): FrequencyRequirement[] {
  const name = asString(policy.name) ?? asString(policy.guid) ?? "policy";
  return asRecords(policy.scan_frequency_rules).flatMap((rule) => {
    const frequency = asString(rule.frequency)?.toUpperCase() ?? "";
    const days = frequency === "ONCE" ? Number.POSITIVE_INFINITY : FREQUENCY_DAYS[frequency];
    if (days === undefined) return [];
    return [{ scanType: asString(rule.scan_type)?.toUpperCase() ?? "ANY", days, source: `policy ${name} (${frequency})` }];
  });
}

function criticalityRequirement(app: JsonRecord, intervals: CriticalityIntervals): FrequencyRequirement | undefined {
  const criticality = businessCriticality(app);
  if (!criticality) return undefined;
  const days = criticality === "VERY_HIGH" ? intervals.criticalDays : intervals.standardDays;
  return { scanType: "ANY", days, source: `business criticality ${criticality}` };
}

function strictestRequirements(requirements: FrequencyRequirement[]): FrequencyRequirement[] {
  const byScanType = new Map<string, FrequencyRequirement>();
  for (const requirement of requirements) {
    const current = byScanType.get(requirement.scanType);
    if (!current || requirement.days < current.days) byScanType.set(requirement.scanType, requirement);
  }
  return [...byScanType.values()];
}

function evaluateRequirement(app: JsonRecord, requirement: FrequencyRequirement, now: Date): RequirementOutcome {
  const interval = describeInterval(requirement.days);
  if (requirement.scanType === "ANY") {
    const last = parseDate(app.last_completed_scan_date);
    if (!last) return { kind: "unconfirmed", detail: `${requirement.source} requires a scan ${interval} but the profile exposes no last_completed_scan_date` };
    const age = daysSince(last, now);
    return age > requirement.days ? { kind: "overdue", detail: `${requirement.source} requires a scan ${interval}; the last completed scan was ${age} days ago` } : { kind: "met" };
  }
  const state = latestScanState(app, requirement.scanType);
  switch (state.kind) {
    case "none":
      return { kind: "overdue", detail: `${requirement.source} requires a ${requirement.scanType} scan ${interval} but the profile exposes no ${requirement.scanType} scan` };
    case "not_completed":
      return { kind: "unconfirmed", detail: `${requirement.source} requires a ${requirement.scanType} scan ${interval} but the latest ${requirement.scanType} scan status is ${state.status}, not published` };
    case "missing_date":
      return { kind: "unconfirmed", detail: `${requirement.source} requires a ${requirement.scanType} scan ${interval} but the published ${requirement.scanType} scan exposes no modified_date` };
    case "completed": {
      const age = daysSince(state.date, now);
      return age > requirement.days ? { kind: "overdue", detail: `${requirement.source} requires a ${requirement.scanType} scan ${interval}; the last published ${requirement.scanType} scan was ${age} days ago` } : { kind: "met" };
    }
    default: {
      const exhaustive: never = state;
      throw new Error(`Unhandled scan state ${String(exhaustive)}`);
    }
  }
}

function evaluateScanFrequency(snapshot: ApplicationSnapshot, policies: Surface<HalListResult>, intervals: CriticalityIntervals, now: Date): VeracodeFinding {
  const blocker = applicationInventoryBlocker(4, "high", snapshot, ["Export the policy scan frequency requirements, business criticality, and last scan dates per application."]);
  if (blocker) return blocker;
  if (policies.status === "error") {
    return manualFinding(4, "high", unreadableReason("policies", policies), ["Export the assigned policies for each application and their scan frequency rules from the Platform."]);
  }
  const list = (snapshot.applications as { value: HalListResult }).value;
  const policyByGuid = new Map(policies.value.items.map((policy) => [asString(policy.guid) ?? "", policy]));
  const overdue: Array<{ application: string; details: string[] }> = [];
  const unconfirmed: Array<{ application: string; details: string[] }> = [];
  const noRequirement: string[] = [];
  const requirementsByApplication: Record<string, string[]> = {};
  let compliant = 0;
  for (const app of list.items) {
    const name = applicationName(app);
    const assigned = applicationPolicies(app);
    const resolvedPolicies = assigned.map((policy) => policyByGuid.get(asString(policy.guid) ?? "")).filter((policy): policy is JsonRecord => policy !== undefined);
    const unresolvedPolicies = assigned.length - resolvedPolicies.length;
    const criticality = criticalityRequirement(app, intervals);
    const requirements = strictestRequirements([
      ...resolvedPolicies.flatMap(policyFrequencyRequirements),
      ...(criticality ? [criticality] : []),
    ]);
    if (requirements.length === 0 && unresolvedPolicies === 0) {
      noRequirement.push(name);
      continue;
    }
    requirementsByApplication[name] = requirements.map((requirement) => `${requirement.scanType} ${describeInterval(requirement.days)} from ${requirement.source}`);
    const outcomes = requirements.map((requirement) => evaluateRequirement(app, requirement, now));
    const overdueDetails = outcomes.flatMap((outcome) => (outcome.kind === "overdue" ? [outcome.detail] : []));
    const unconfirmedDetails = [
      ...outcomes.flatMap((outcome) => (outcome.kind === "unconfirmed" ? [outcome.detail] : [])),
      ...(unresolvedPolicies > 0 ? [`${unresolvedPolicies} assigned policies were not found in the readable policy inventory, so their scan frequency rules were not evaluated`] : []),
    ];
    if (overdueDetails.length > 0) overdue.push({ application: name, details: overdueDetails });
    else if (unconfirmedDetails.length > 0) unconfirmed.push({ application: name, details: unconfirmedDetails });
    else compliant += 1;
  }
  const partial = joinNotes(partialInventoryNote(list, "applications"), partialInventoryNote(policies.value, "policies")) || undefined;
  const tiers = `VERY_HIGH ${describeInterval(intervals.criticalDays)}, other criticality tiers ${describeInterval(intervals.standardDays)}`;
  const evidence = {
    applications_seen: list.items.length,
    compliant_applications: compliant,
    overdue_applications: overdue.slice(0, 50),
    unconfirmed_applications: unconfirmed.slice(0, 50),
    applications_without_frequency_requirement: noRequirement.slice(0, 50),
    critical_scan_interval_days: intervals.criticalDays,
    standard_scan_interval_days: intervals.standardDays,
    requirement_basis: "strictest scan_frequency_rules across every assigned policy per scan type plus the business criticality tier against last_completed_scan_date",
    requirements_by_application: Object.fromEntries(Object.entries(requirementsByApplication).slice(0, 50)),
  };
  if (overdue.length > 0) {
    return finding(4, "high", "fail", joinNotes(`${overdue.length}/${list.items.length} applications are overdue against their strictest scan frequency requirement from assigned policies and business criticality (${tiers}).`, partial), evidence);
  }
  if (noRequirement.length > 0 || unconfirmed.length > 0) {
    return finding(4, "high", "warn", joinNotes(
      `${noRequirement.length} applications have neither a policy scan frequency rule nor a business criticality tier and ${unconfirmed.length} could not be confirmed (unpublished latest scan, missing scan date, or unresolved assigned policy), so frequency compliance is not established for them; ${compliant} applications meet their strictest requirement (${tiers}).`,
      partial,
    ), evidence);
  }
  return finding(4, "high", limitedStatus("pass", [partial]), joinNotes(`All ${compliant} applications meet their strictest scan frequency requirement from assigned policies and business criticality (${tiers}).`, partial), evidence);
}

function evaluateScanCompletion(snapshot: ApplicationSnapshot): VeracodeFinding {
  const blocker = applicationInventoryBlocker(19, "medium", snapshot, ["Review scan history per application for failed or canceled scans."]);
  if (blocker) return blocker;
  const list = (snapshot.applications as { value: HalListResult }).value;
  const failed: Array<{ application: string; statuses: string[] }> = [];
  const noScans: string[] = [];
  let healthy = 0;
  for (const app of list.items) {
    const scans = applicationScans(app);
    if (scans.length === 0) {
      noScans.push(applicationName(app));
      continue;
    }
    const statuses = scans.map((scan) => asString(scan.status)?.toUpperCase() ?? "UNKNOWN");
    const failures = statuses.filter((status) => FAILED_SCAN_STATUSES.has(status));
    if (failures.length > 0) failed.push({ application: applicationName(app), statuses: failures });
    else healthy += 1;
  }
  const partial = partialInventoryNote(list, "applications");
  const evidence = { applications_seen: list.items.length, healthy_applications: healthy, failed_scan_applications: failed.slice(0, 50), applications_without_scans: noScans.slice(0, 50) };
  if (failed.length > 0) {
    return finding(19, "medium", "fail", joinNotes(`${failed.length}/${list.items.length} applications expose a latest scan in a failed, canceled, or incomplete status.`, partial), evidence);
  }
  if (healthy === 0) {
    return manualFinding(19, "medium", "No application exposed a scan record, so the completion rate could not be measured.", ["Review scan history in the Platform for failed scans."], evidence);
  }
  if (noScans.length > 0) {
    return finding(19, "medium", "warn", joinNotes(`${healthy} applications expose only healthy scan statuses, but ${noScans.length} applications expose no scan records and were not counted as healthy.`, partial), evidence);
  }
  return finding(19, "medium", limitedStatus("pass", [partial]), joinNotes(`All ${healthy} applications with scan records expose no failed or canceled latest scans.`, partial), evidence);
}

async function evaluateSandboxUsage(client: ClientLike, snapshot: ApplicationSnapshot, maxApplications: number): Promise<{ finding: VeracodeFinding; raw: JsonRecord; errors: string[] }> {
  const blocker = applicationInventoryBlocker(10, "medium", snapshot, ["Confirm sandbox usage per application in the Platform."]);
  if (blocker) return { finding: blocker, raw: { sandboxes_by_application: notAttempted("the application inventory was not readable, so no sandbox list was requested.") }, errors: [] };
  const list = (snapshot.applications as { value: HalListResult }).value;
  const sampled = list.items.slice(0, maxApplications);
  const results = await Promise.all(sampled.map(async (app) => ({
    application: applicationName(app),
    guid: applicationGuid(app) ?? "",
    sandboxes: await surface(() => client.listSandboxes(applicationGuid(app) ?? "")),
  })));
  const errors = results.flatMap((item) => surfaceErrors(`sandboxes ${item.application}`, item.sandboxes));
  const unreadable = results.filter((item) => item.sandboxes.status === "error");
  const withoutSandboxes = results.filter((item) => item.sandboxes.status === "ok" && item.sandboxes.value.items.length === 0).map((item) => item.application);
  const withSandboxes = results.filter((item) => item.sandboxes.status === "ok" && item.sandboxes.value.items.length > 0).length;
  const raw = { sandboxes_by_application: Object.fromEntries(results.map((item) => [item.guid, rawSurface(item.sandboxes, (value) => value.items)])) };
  const caveats = [partialInventoryNote(list, "applications"), scopeNote(sampled.length, list.items.length, "applications")];
  // With no sandbox list readable the counts are unknown, not 0.
  const anyReadable = results.some((item) => item.sandboxes.status === "ok");
  const evidence = { applications_sampled: sampled.length, applications_total: knownTotal(list), applications_with_sandboxes: anyReadable ? withSandboxes : null, applications_without_sandboxes: anyReadable ? withoutSandboxes.slice(0, 50) : null, unreadable_applications: unreadable.length };
  if (unreadable.length === results.length) {
    return { finding: manualFinding(10, "medium", unreadableReason("sandboxes", unreadable[0].sandboxes), ["Confirm sandbox usage per application in the Platform."], evidence), raw, errors };
  }
  if (withoutSandboxes.length > 0) {
    return { finding: finding(10, "medium", "warn", joinNotes(`${withoutSandboxes.length}/${sampled.length} sampled applications have no development sandboxes, so pre-policy scanning is not evidenced for them.`, ...caveats), evidence), raw, errors };
  }
  const status = limitedStatus("pass", [...caveats, unreadable.length > 0 ? "some sandbox lists were unreadable" : undefined]);
  return { finding: finding(10, "medium", status, joinNotes(`All ${withSandboxes} sampled applications with readable sandbox lists use at least one development sandbox.`, ...caveats, unreadable.length > 0 ? `${unreadable.length} sandbox lists were unreadable.` : undefined), evidence), raw, errors };
}

/**
 * Rule 9 projection of GET /was/configservice/v1/scans/{id}/configuration:
 * the verdict reads only the authentication types and crawl.disabled, while
 * auth_configuration.authentications carries usernames, passwords, login
 * script bodies, and client certificates verbatim, so only the keys are kept.
 */
function projectDynamicScanConfiguration(analysisId: string, scanId: string, configuration: JsonRecord): JsonRecord {
  const authentications = asObject(asObject(configuration.auth_configuration)?.authentications) ?? {};
  const crawl = asObject(configuration.crawl_configuration);
  const allowedHosts = asRecords(asObject(configuration.scan_setting)?.allowed_hosts ?? configuration.allowed_hosts);
  const targetUrl = asString(asObject(configuration.target_url)?.url) ?? asString(configuration.target_url);
  return {
    analysis_id: analysisId,
    scan_id: scanId,
    target_url: targetUrl === undefined ? null : scrubUrlValue(targetUrl),
    authentication_types: Object.keys(authentications),
    authentication_details: Object.keys(authentications).length > 0 ? "[REDACTED]" : null,
    crawl_disabled: asBoolean(crawl?.disabled) ?? null,
    crawl_script_present: Boolean(asObject(crawl?.crawl_script_data)),
    allowed_host_count: allowedHosts.length,
  };
}

async function evaluateDynamicScanConfiguration(client: ClientLike, maxAnalyses: number): Promise<{ finding: VeracodeFinding; raw: JsonRecord; errors: string[] }> {
  const analyses = await surface(() => client.listDynamicAnalyses());
  const manualEvidence = ["Export each Dynamic Analysis configuration (authentication, allowed hosts, crawl settings) from the Platform."];
  if (analyses.status === "error") {
    const reason = isUnavailable(analyses)
      ? `The Dynamic Analysis API was not available to this credential (${analyses.statusCode}); Dynamic Analysis may be unlicensed or the API user lacks a Dynamic Analysis role, so the control is not applicable through the API.`
      : unreadableReason("Dynamic Analysis analyses", analyses);
    const skipped = notAttempted("the Dynamic Analysis list was not readable, so no scan list or scan configuration was requested.");
    return { finding: manualFinding(13, "medium", reason, manualEvidence, { status_code: analyses.statusCode ?? null }), raw: { analyses: rawSurface(analyses), scans_by_analysis: skipped, scan_configurations: skipped }, errors: surfaceErrors("dynamic analyses", analyses) };
  }
  if (analyses.value.items.length === 0) {
    return { finding: manualFinding(13, "medium", "No Dynamic Analysis configurations exist, so there is no DAST configuration to evaluate; the empty inventory is treated as not applicable rather than compliant.", ["Confirm whether Dynamic Analysis is in scope and document DAST coverage decisions."]), raw: { analyses: [], scans_by_analysis: {}, scan_configurations: [] }, errors: [] };
  }
  const sampled = analyses.value.items.slice(0, maxAnalyses);
  const errors: string[] = [];
  const unauthenticated: string[] = [];
  const crawlDisabled: string[] = [];
  const unreadable: string[] = [];
  const scanCaveats: string[] = [];
  const scanCoverage: JsonRecord[] = [];
  let configured = 0;
  let configurationsRequested = 0;
  const rawScansByAnalysis: JsonRecord = {};
  const rawScans: JsonRecord[] = [];
  for (const analysis of sampled) {
    const analysisId = asString(analysis.analysis_id) ?? "";
    const analysisLabel = asString(analysis.name) ?? analysisId;
    const scans = await surface(() => client.listDynamicAnalysisScans(analysisId));
    errors.push(...surfaceErrors(`dynamic scans ${analysisId}`, scans));
    rawScansByAnalysis[analysisId] = rawSurface(scans, (value) => value.items.map((scan) => ({ scan_id: asString(scan.scan_id) ?? null, target_url: scrubUrlValue(asString(scan.target_url) ?? "") || null })));
    if (scans.status === "error") {
      unreadable.push(analysisLabel);
      continue;
    }
    const inspected = scans.value.items.slice(0, MAX_DYNAMIC_SCANS_PER_ANALYSIS);
    const scanListNote = partialInventoryNote(scans.value, `scans of ${analysisLabel}`);
    const scanSampleNote = scopeNote(inspected.length, scans.value.items.length, `scans of ${analysisLabel}`);
    scanCaveats.push(...[scanListNote, scanSampleNote].filter((note): note is string => Boolean(note)));
    scanCoverage.push({ analysis_id: analysisId, scans_inspected: inspected.length, scans_seen: scans.value.items.length, scans_total: scans.value.totalElements ?? null, scan_list_complete: scans.value.complete });
    for (const scan of inspected) {
      const scanId = asString(scan.scan_id) ?? "";
      configurationsRequested += 1;
      const configuration = await surface(() => client.getDynamicScanConfiguration(scanId));
      errors.push(...surfaceErrors(`dynamic scan configuration ${scanId}`, configuration));
      const label = `${analysisLabel}:${scrubUrlValue(asString(scan.target_url) ?? scanId)}`;
      if (configuration.status === "error") {
        unreadable.push(label);
        rawScans.push({ analysis_id: analysisId, scan_id: scanId, ...rawSurface(configuration) });
        continue;
      }
      const authentications = asObject(asObject(configuration.value.auth_configuration)?.authentications);
      const crawl = asObject(configuration.value.crawl_configuration);
      rawScans.push(projectDynamicScanConfiguration(analysisId, scanId, configuration.value));
      if (!authentications || Object.keys(authentications).length === 0) unauthenticated.push(label);
      else if (asBoolean(crawl?.disabled) === true) crawlDisabled.push(label);
      else configured += 1;
    }
  }
  const caveats = [partialInventoryNote(analyses.value, "analyses"), scopeNote(sampled.length, analyses.value.items.length, "analyses"), ...scanCaveats, unreadable.length > 0 ? `${unreadable.length} scan configurations were unreadable.` : undefined];
  // No readable scan list means no configuration request was issued, so the list carries a marker rather than [].
  const scanListsUnreadable = sampled.length > 0 && scanCoverage.length === 0;
  // The configuration counts are unknown, not 0 or [], when no scan list was readable or every requested configuration failed; a readable but empty scan inventory keeps its real zeros.
  const configurationsRead = configured + unauthenticated.length + crawlDisabled.length;
  const configurationsUnknown = scanListsUnreadable || (configurationsRequested > 0 && configurationsRead === 0);
  const evidence = {
    analyses_seen: analyses.value.items.length,
    analyses_sampled: sampled.length,
    scan_coverage: scanListsUnreadable ? null : scanCoverage.slice(0, 50),
    configured_scans: configurationsUnknown ? null : configured,
    unauthenticated_scans: configurationsUnknown ? null : unauthenticated.slice(0, 50),
    crawl_disabled_scans: configurationsUnknown ? null : crawlDisabled.slice(0, 50),
    unreadable: unreadable.slice(0, 50),
  };
  const raw = { analyses: analyses.value.items, scans_by_analysis: rawScansByAnalysis, scan_configurations: scanListsUnreadable ? notAttempted("no scan list was readable, so no scan configuration was requested.") : rawScans };
  if (configurationsRead === 0) {
    return { finding: manualFinding(13, "medium", "No Dynamic Analysis scan configuration could be read, so authentication and crawl settings are unknown.", manualEvidence, evidence), raw, errors };
  }
  if (unauthenticated.length > 0 || crawlDisabled.length > 0) {
    return { finding: finding(13, "medium", "fail", joinNotes(`${unauthenticated.length} dynamic scans have no authentication configured and ${crawlDisabled.length} have crawling disabled, out of ${configured + unauthenticated.length + crawlDisabled.length} readable scan configurations.`, ...caveats), evidence), raw, errors };
  }
  return { finding: finding(13, "medium", limitedStatus("pass", caveats), joinNotes(`All ${configured} readable dynamic scan configurations include authentication and keep crawling enabled.`, ...caveats), evidence), raw, errors };
}

function prescanManualFinding(snapshot: ApplicationSnapshot): VeracodeFinding {
  const seen = countIfRead(snapshot.applications);
  return manualFinding(
    11,
    "low",
    "Prescan module selection results are only exposed by the XML getprescanresults.do API, which this read-only REST inspector does not call; module selection coverage cannot be verified through the REST APIs.",
    ["Export the prescan module selection (selected versus available modules) for the latest static scan of each application and confirm at least 80 percent of relevant modules are selected."],
    { applications_seen: seen },
  );
}

function pipelineManualFinding(snapshot: ApplicationSnapshot): VeracodeFinding {
  const seen = countIfRead(snapshot.applications);
  return manualFinding(
    14,
    "low",
    "Pipeline Scan and IDE scan results are not persisted on application profiles, and the Applications API scans array only exposes STATIC, DYNAMIC, MANUAL, and SCA platform scans, so CI/CD integration cannot be verified through the REST APIs.",
    ["Collect CI/CD pipeline configuration or Veracode CLI and Pipeline Scan job logs showing recent automated scans per application."],
    { applications_seen: seen },
  );
}

export async function assessVeracodeScanCoverage(
  client: ClientLike,
  options: { maxApplications?: number; maxScanAgeDays?: number; maxAnalyses?: number; criticalScanIntervalDays?: number; standardScanIntervalDays?: number; now?: Date } = {},
): Promise<VeracodeAssessmentResult> {
  const now = options.now ?? new Date();
  const maxApplications = clampNumber(options.maxApplications, DEFAULT_MAX_APPLICATIONS, 1, 5000);
  const maxScanAgeDays = clampNumber(options.maxScanAgeDays, DEFAULT_MAX_SCAN_AGE_DAYS, 1, 3650);
  const maxAnalyses = clampNumber(options.maxAnalyses, DEFAULT_MAX_ANALYSES, 1, 500);
  const intervals: CriticalityIntervals = {
    criticalDays: clampNumber(options.criticalScanIntervalDays, DEFAULT_CRITICAL_SCAN_INTERVAL_DAYS, 1, 3650),
    standardDays: clampNumber(options.standardScanIntervalDays, DEFAULT_STANDARD_SCAN_INTERVAL_DAYS, 1, 3650),
  };
  const snapshot = await collectApplications(client);
  const policies = await surface(() => client.listPolicies());
  const sandbox = await evaluateSandboxUsage(client, snapshot, maxApplications);
  const dynamic = await evaluateDynamicScanConfiguration(client, maxAnalyses);
  const findings = [
    evaluateScanCoverage(snapshot, maxScanAgeDays, now),
    evaluateScanFrequency(snapshot, policies, intervals, now),
    sandbox.finding,
    prescanManualFinding(snapshot),
    dynamic.finding,
    pipelineManualFinding(snapshot),
    evaluateScanCompletion(snapshot),
  ];
  const errors = [
    ...surfaceErrors("applications", snapshot.applications),
    ...surfaceErrors("policies", policies),
    ...sandbox.errors,
    ...dynamic.errors,
  ];
  return {
    title: "Veracode scan coverage",
    summary: {
      base_url: client.getResolvedConfig().baseUrl,
      applications_seen: countIfRead(snapshot.applications),
      applications_total: snapshot.applications.status === "ok" ? snapshot.applications.value.totalElements ?? null : null,
      max_scan_age_days: maxScanAgeDays,
      ...countByStatus(findings),
    },
    findings,
    errors,
    rawData: {
      applications: rawSurface(snapshot.applications),
      policies: rawSurface(policies),
      ...sandbox.raw,
      dynamic_analysis: dynamic.raw,
    },
  };
}

function evaluatePolicyCompliance(snapshot: ApplicationSnapshot): VeracodeFinding {
  const blocker = applicationInventoryBlocker(2, "critical", snapshot, ["Export the policy compliance status for every application from the Platform."]);
  if (blocker) return blocker;
  const list = (snapshot.applications as { value: HalListResult }).value;
  const failing: string[] = [];
  const conditional: string[] = [];
  const unassessed: string[] = [];
  const unassigned: string[] = [];
  let passing = 0;
  for (const app of list.items) {
    const policies = applicationPolicies(app);
    if (policies.length === 0) {
      unassigned.push(applicationName(app));
      continue;
    }
    const statuses = policies.map((policy) => asString(policy.policy_compliance_status)?.toUpperCase());
    if (statuses.includes("DID_NOT_PASS")) failing.push(applicationName(app));
    else if (statuses.includes("CONDITIONAL_PASS")) conditional.push(applicationName(app));
    else if (statuses.every((status) => status === "PASSED")) passing += 1;
    else unassessed.push(applicationName(app));
  }
  const partial = partialInventoryNote(list, "applications");
  const evidence = { applications_seen: list.items.length, passing_applications: passing, failing_applications: failing.slice(0, 50), conditional_pass_applications: conditional.slice(0, 50), unassessed_applications: unassessed.slice(0, 50), applications_without_policy: unassigned.slice(0, 50) };
  if (failing.length > 0 || unassigned.length > 0) {
    return finding(2, "critical", "fail", joinNotes(`${failing.length}/${list.items.length} applications did not pass their assigned policy and ${unassigned.length} have no policy assigned.`, partial), evidence);
  }
  if (conditional.length > 0 || unassessed.length > 0) {
    return finding(2, "critical", "warn", joinNotes(`${conditional.length} applications are in conditional pass (grace period) and ${unassessed.length} expose a policy_compliance_status other than PASSED (NOT_ASSESSED, DETERMINING, VENDOR_REVIEW, or missing); ${passing} applications passed.`, partial), evidence);
  }
  return finding(2, "critical", limitedStatus("pass", [partial]), joinNotes(`All ${passing} applications expose policy_compliance_status PASSED for every assigned policy.`, partial), evidence);
}

function evaluateCustomPolicies(snapshot: ApplicationSnapshot, policies: Surface<HalListResult>): VeracodeFinding {
  const manualEvidence = ["Export policy definitions (type, finding rules, grace periods) and the policy assignment per application from the Platform."];
  if (policies.status === "error") {
    return manualFinding(15, "high", unreadableReason("policies", policies), manualEvidence, { status_code: policies.statusCode ?? null });
  }
  if (policies.value.items.length === 0) {
    return manualFinding(15, "high", "The policies endpoint returned zero policies, which cannot be a complete inventory because every Veracode account exposes the built-in policies; the empty list is treated as unverifiable rather than compliant.", manualEvidence);
  }
  const customPolicies = policies.value.items.filter((policy) => asString(policy.type)?.toUpperCase() === "CUSTOMER");
  const customWithoutRules = customPolicies.filter((policy) => asRecords(policy.finding_rules).length === 0).map((policy) => asString(policy.name) ?? asString(policy.guid) ?? "policy");
  const customWithoutGrace = customPolicies.filter((policy) => [0, 1, 2, 3, 4, 5].every((level) => asNumber(policy[`sev${level}_grace_period`]) === undefined)).map((policy) => asString(policy.name) ?? asString(policy.guid) ?? "policy");
  const policyByGuid = new Map(policies.value.items.map((policy) => [asString(policy.guid) ?? "", policy]));
  const appsOnDefaultPolicies: string[] = [];
  let appsOnCustom = 0;
  let appsSeen = 0;
  if (snapshot.applications.status === "ok") {
    for (const app of snapshot.applications.value.items) {
      appsSeen += 1;
      const assigned = applicationPolicies(app);
      const usesCustom = assigned.some((policy) => asString(policyByGuid.get(asString(policy.guid) ?? "")?.type)?.toUpperCase() === "CUSTOMER");
      if (usesCustom) appsOnCustom += 1;
      else appsOnDefaultPolicies.push(applicationName(app));
    }
  }
  const applicationsRead = snapshot.applications.status === "ok";
  const caveats = [partialInventoryNote(policies.value, "policies"), snapshot.applications.status === "ok" ? partialInventoryNote(snapshot.applications.value, "applications") : "The application inventory was unreadable, so policy assignment per application was not verified."];
  // Per-application assignment counts come from the application inventory: null, never 0 or [], when it was not read.
  const evidence = { policies_seen: policies.value.items.length, custom_policies: customPolicies.length, custom_policies_without_finding_rules: customWithoutRules, custom_policies_without_grace_periods: customWithoutGrace, applications_on_default_policies: applicationsRead ? appsOnDefaultPolicies.slice(0, 50) : null, applications_on_custom_policies: applicationsRead ? appsOnCustom : null };
  if (customPolicies.length === 0) {
    return finding(15, "high", "fail", joinNotes(`None of the ${policies.value.items.length} policies is a customer-defined (CUSTOMER type) policy, so applications rely on Veracode default policies.`, ...caveats), evidence);
  }
  if (appsOnDefaultPolicies.length > 0 || customWithoutRules.length > 0) {
    return finding(15, "high", "warn", joinNotes(`${customPolicies.length} custom policies exist, but ${appsOnDefaultPolicies.length}/${appsSeen} applications are assigned only built-in or Veracode Level policies and ${customWithoutRules.length} custom policies define no finding rules.`, ...caveats), evidence);
  }
  const assignmentNote = applicationsRead ? `all ${appsOnCustom} applications read are assigned a custom policy` : "the assignment per application is unknown";
  return finding(15, "high", limitedStatus("pass", caveats), joinNotes(`${customPolicies.length} custom policies with finding rules exist and ${assignmentNote}.`, ...caveats), evidence);
}

function evaluateCollectionsPosture(snapshot: ApplicationSnapshot): VeracodeFinding {
  const evidence: JsonRecord = {};
  if (snapshot.applications.status === "ok") {
    const groups = new Map<string, { total: number; nonCompliant: number }>();
    for (const app of snapshot.applications.value.items) {
      const unit = asString(asObject(asObject(app.profile)?.business_unit)?.name) ?? "(no business unit)";
      const entry = groups.get(unit) ?? { total: 0, nonCompliant: 0 };
      entry.total += 1;
      if (applicationPolicies(app).some((policy) => asString(policy.policy_compliance_status)?.toUpperCase() === "DID_NOT_PASS")) entry.nonCompliant += 1;
      groups.set(unit, entry);
    }
    evidence.business_unit_posture = Object.fromEntries([...groups.entries()].slice(0, 50));
  }
  return manualFinding(
    20,
    "medium",
    "The Collections API is not part of the published Veracode REST API reference used by this inspector, so collection-level compliance posture was not evaluated through the API; business-unit grouping of application policy status is provided as supporting evidence only.",
    ["Export each application collection and its aggregate compliance from the Platform and flag collections where more than 20 percent of applications do not pass policy."],
    evidence,
  );
}

export async function assessVeracodePolicyCompliance(
  client: ClientLike,
  _options: { maxApplications?: number } = {},
): Promise<VeracodeAssessmentResult> {
  const snapshot = await collectApplications(client);
  const policies = await surface(() => client.listPolicies());
  const findings = [
    evaluatePolicyCompliance(snapshot),
    evaluateCustomPolicies(snapshot, policies),
    evaluateCollectionsPosture(snapshot),
  ];
  return {
    title: "Veracode policy compliance",
    summary: {
      base_url: client.getResolvedConfig().baseUrl,
      applications_seen: countIfRead(snapshot.applications),
      policies_seen: countIfRead(policies),
      ...countByStatus(findings),
    },
    findings,
    errors: [...surfaceErrors("applications", snapshot.applications), ...surfaceErrors("policies", policies)],
    rawData: {
      applications: rawSurface(snapshot.applications),
      policies: rawSurface(policies),
    },
  };
}

interface ApplicationFindingsSample {
  application: string;
  guid: string;
  findings: Surface<HalListResult>;
  summaryReport: Surface<JsonRecord>;
}

function findingSeverity(item: JsonRecord): number | undefined {
  return asNumber(asObject(item.finding_details)?.severity);
}

function findingStatus(item: JsonRecord): JsonRecord {
  return asObject(item.finding_status) ?? {};
}

function isOpenUnresolved(item: JsonRecord): boolean {
  const status = findingStatus(item);
  return asString(status.status)?.toUpperCase() === "OPEN" && asString(status.resolution)?.toUpperCase() === "UNRESOLVED";
}

function evaluateFlawAging(samples: ApplicationFindingsSample[], inventory: HalListResult, now: Date): VeracodeFinding {
  const readable = samples.filter((sample) => sample.findings.status === "ok");
  const unreadable = samples.filter((sample) => sample.findings.status === "error");
  const manualEvidence = ["Export open findings with first found dates per application and compute days open against the SLA thresholds."];
  if (readable.length === 0) {
    return manualFinding(3, "high", unreadable.length > 0 ? unreadableReason("findings", unreadable[0].findings) : "No application findings were sampled.", manualEvidence, { applications_sampled: samples.length });
  }
  const overdue: Array<{ application: string; issue_id: string | null; severity: number; days_open: number }> = [];
  const missingDate: number[] = [];
  let openEvaluated = 0;
  let incompletePagination = 0;
  for (const sample of readable) {
    const list = (sample.findings as { value: HalListResult }).value;
    if (!list.complete) incompletePagination += 1;
    for (const item of list.items) {
      if (!isOpenUnresolved(item)) continue;
      const severity = findingSeverity(item);
      if (severity === undefined) continue;
      const threshold = FLAW_AGE_THRESHOLDS[severity];
      if (threshold === undefined) continue;
      const firstFound = parseDate(findingStatus(item).first_found_date);
      if (!firstFound) {
        missingDate.push(severity);
        continue;
      }
      openEvaluated += 1;
      const days = daysSince(firstFound, now);
      if (days > threshold) overdue.push({ application: sample.application, issue_id: asString(item.issue_id) ?? null, severity, days_open: days });
    }
  }
  const caveats = [partialInventoryNote(inventory, "applications"), scopeNote(samples.length, inventory.items.length, "applications"), unreadable.length > 0 ? `${unreadable.length} application finding lists were unreadable.` : undefined, incompletePagination > 0 ? `${incompletePagination} finding lists were truncated before the last page.` : undefined];
  const evidence = { applications_sampled: samples.length, applications_readable: readable.length, open_findings_evaluated: openEvaluated, overdue_findings: overdue.slice(0, 100), overdue_count: overdue.length, findings_without_first_found_date: missingDate.length, thresholds_days: FLAW_AGE_THRESHOLDS };
  if (overdue.length > 0) {
    const critical = overdue.filter((item) => item.severity === 5).length;
    return finding(3, "high", "fail", joinNotes(`${overdue.length} open unmitigated findings exceed their severity SLA (${critical} Very High over 30 days) across ${readable.length} sampled applications.`, ...caveats), evidence);
  }
  if (missingDate.length > 0) {
    return finding(3, "high", "warn", joinNotes(`No open finding exceeds its SLA, but ${missingDate.length} open findings expose no first_found_date and could not be aged.`, ...caveats), evidence);
  }
  if (openEvaluated === 0) {
    const scanned = readable.filter((sample) => sample.findings.status === "ok" && sample.findings.value.items.length > 0).length;
    if (scanned === 0) {
      return manualFinding(3, "high", `The ${readable.length} sampled applications returned zero findings, so there is no aging population to evaluate; confirm the applications have published scans before treating this as compliant.`, manualEvidence, evidence);
    }
  }
  return finding(3, "high", limitedStatus("pass", caveats), joinNotes(`All ${openEvaluated} open unmitigated findings across ${readable.length} fully read applications are within their severity SLA.`, ...caveats), evidence);
}

function evaluateMitigationWorkflow(samples: ApplicationFindingsSample[], inventory: HalListResult): VeracodeFinding {
  const readable = samples.filter((sample) => sample.findings.status === "ok");
  const unreadable = samples.filter((sample) => sample.findings.status === "error");
  const manualEvidence = ["Export proposed and approved mitigations with reviewer comments from the Platform mitigation workflow."];
  if (readable.length === 0) {
    return manualFinding(12, "high", unreadable.length > 0 ? unreadableReason("findings", unreadable[0].findings) : "No application findings were sampled.", manualEvidence);
  }
  const pendingReview: Array<{ application: string; issue_id: string | null }> = [];
  const unjustified: Array<{ application: string; issue_id: string | null; action: string }> = [];
  let mitigationsSeen = 0;
  let findingsSeen = 0;
  let incomplete = 0;
  for (const sample of readable) {
    const list = (sample.findings as { value: HalListResult }).value;
    if (!list.complete) incomplete += 1;
    for (const item of list.items) {
      findingsSeen += 1;
      const status = findingStatus(item);
      const resolutionStatus = asString(status.resolution_status)?.toUpperCase();
      if (resolutionStatus === "PROPOSED") pendingReview.push({ application: sample.application, issue_id: asString(item.issue_id) ?? null });
      for (const annotation of asRecords(item.annotations)) {
        const action = asString(annotation.action)?.toUpperCase() ?? "";
        if (!MITIGATION_ACTIONS.has(action)) continue;
        mitigationsSeen += 1;
        if (!asString(annotation.comment)) unjustified.push({ application: sample.application, issue_id: asString(item.issue_id) ?? null, action });
      }
    }
  }
  const caveats = [partialInventoryNote(inventory, "applications"), scopeNote(samples.length, inventory.items.length, "applications"), unreadable.length > 0 ? `${unreadable.length} application finding lists were unreadable.` : undefined, incomplete > 0 ? `${incomplete} finding lists were truncated.` : undefined];
  const evidence = { applications_sampled: samples.length, findings_seen: findingsSeen, mitigation_annotations_seen: mitigationsSeen, proposed_not_reviewed: pendingReview.slice(0, 100), proposed_not_reviewed_count: pendingReview.length, mitigations_without_justification: unjustified.slice(0, 100) };
  if (findingsSeen === 0) {
    return manualFinding(12, "high", "The sampled applications returned zero findings, so there are no mitigations to audit; the empty population is treated as unverifiable rather than compliant.", manualEvidence, evidence);
  }
  if (pendingReview.length > 0 || unjustified.length > 0) {
    return finding(12, "high", "fail", joinNotes(`${pendingReview.length} mitigations are proposed but not reviewed and ${unjustified.length} mitigation annotations carry no justification comment.`, ...caveats), evidence);
  }
  return finding(12, "high", limitedStatus("pass", caveats), joinNotes(`No proposed-but-unreviewed mitigations and no unjustified mitigation annotations across ${findingsSeen} findings (${mitigationsSeen} mitigation annotations read with include_annot=TRUE).`, ...caveats), evidence);
}

function hasAnnotationAction(item: JsonRecord, action: string): boolean {
  return asRecords(item.annotations).some((annotation) => asString(annotation.action)?.toUpperCase() === action);
}

function countValues(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function evaluateFalsePositiveRate(samples: ApplicationFindingsSample[], inventory: HalListResult, maxRatePercent: number): VeracodeFinding {
  const readable = samples.filter((sample) => sample.findings.status === "ok");
  const unreadable = samples.filter((sample) => sample.findings.status === "error");
  const manualEvidence = ["Export findings with their mitigation annotations per application and compute the share carrying a false positive (FP) mitigation."];
  if (readable.length === 0) {
    return manualFinding(16, "medium", unreadable.length > 0 ? unreadableReason("findings", unreadable[0].findings) : "No application findings were sampled.", manualEvidence);
  }
  const exceeding: Array<{ application: string; rate_percent: number; findings: number; fp_annotated_findings: number }> = [];
  const perApplication: Array<{ application: string; findings_seen: number; findings_total: number | null; list_complete: boolean; fp_annotated_findings: number; fp_approved_findings: number; resolution_values: Record<string, number> }> = [];
  let evaluated = 0;
  let incomplete = 0;
  for (const sample of readable) {
    const list = (sample.findings as { value: HalListResult }).value;
    if (list.items.length === 0) continue;
    evaluated += 1;
    if (!list.complete) incomplete += 1;
    const fpFindings = list.items.filter((item) => hasAnnotationAction(item, "FP"));
    const fpApproved = fpFindings.filter((item) => hasAnnotationAction(item, "APPROVED")).length;
    perApplication.push({
      application: sample.application,
      findings_seen: list.items.length,
      findings_total: list.totalElements ?? null,
      list_complete: list.complete,
      fp_annotated_findings: fpFindings.length,
      fp_approved_findings: fpApproved,
      resolution_values: countValues(list.items.map((item) => asString(findingStatus(item).resolution) ?? "absent")),
    });
    const rate = (fpFindings.length / list.items.length) * 100;
    if (rate > maxRatePercent) exceeding.push({ application: sample.application, rate_percent: Number(rate.toFixed(1)), findings: list.items.length, fp_annotated_findings: fpFindings.length });
  }
  const caveats = [partialInventoryNote(inventory, "applications"), scopeNote(samples.length, inventory.items.length, "applications"), unreadable.length > 0 ? `${unreadable.length} application finding lists were unreadable.` : undefined, incomplete > 0 ? `${incomplete} finding lists were truncated, so the rate was computed over the findings seen (total unknown or larger).` : undefined];
  const evidence = {
    applications_sampled: samples.length,
    applications_with_findings: evaluated,
    applications_exceeding: exceeding.slice(0, 50),
    max_rate_percent: maxRatePercent,
    signal: "annotations[].action FP (include_annot=TRUE); finding_status.resolution is recorded as evidence only",
    per_application: perApplication.slice(0, 50),
  };
  if (evaluated === 0) {
    return manualFinding(16, "medium", "No sampled application returned findings, so a false positive rate cannot be computed; the empty population is treated as unverifiable rather than compliant.", manualEvidence, evidence);
  }
  if (exceeding.length > 0) {
    return finding(16, "medium", "warn", joinNotes(`${exceeding.length}/${evaluated} applications exceed a ${maxRatePercent} percent false positive rate (findings carrying an FP mitigation annotation), which may indicate scan tuning issues.`, ...caveats), evidence);
  }
  return finding(16, "medium", limitedStatus("pass", caveats), joinNotes(`All ${evaluated} applications with findings stay at or below a ${maxRatePercent} percent false positive rate (findings carrying an FP mitigation annotation read with include_annot=TRUE).`, ...caveats), evidence);
}

function evaluateFlawDensity(samples: ApplicationFindingsSample[], inventory: HalListResult, maxDensity: number): VeracodeFinding {
  const readable = samples.filter((sample) => sample.summaryReport.status === "ok");
  const unreadable = samples.filter((sample) => sample.summaryReport.status === "error");
  const manualEvidence = ["Export the summary report (module lines of code and Very High/High flaw counts) per application and compute flaws per KLOC."];
  if (readable.length === 0) {
    return manualFinding(17, "medium", unreadable.length > 0 ? unreadableReason("summary report", unreadable[0].summaryReport) : "No summary reports were sampled.", manualEvidence);
  }
  const exceeding: Array<{ application: string; density: number; kloc: number; high_flaws: number }> = [];
  const missingLoc: string[] = [];
  let evaluated = 0;
  for (const sample of readable) {
    const report = (sample.summaryReport as { value: JsonRecord }).value;
    const modules = asRecords(asObject(asObject(report.static_analysis)?.modules)?.module);
    const loc = modules.reduce((total, module) => total + (asNumber(module.loc) ?? 0), 0);
    if (modules.length === 0 || loc <= 0) {
      missingLoc.push(sample.application);
      continue;
    }
    const highFlaws = modules.reduce((total, module) => total + (asNumber(module.numflawssev5) ?? 0) + (asNumber(module.numflawssev4) ?? 0), 0);
    const density = highFlaws / (loc / 1000);
    evaluated += 1;
    if (density > maxDensity) exceeding.push({ application: sample.application, density: Number(density.toFixed(3)), kloc: Number((loc / 1000).toFixed(1)), high_flaws: highFlaws });
  }
  const caveats = [partialInventoryNote(inventory, "applications"), scopeNote(samples.length, inventory.items.length, "applications"), unreadable.length > 0 ? `${unreadable.length} summary reports were unreadable.` : undefined];
  const evidence = { applications_sampled: samples.length, applications_evaluated: evaluated, applications_exceeding: exceeding.slice(0, 50), applications_without_loc: missingLoc.slice(0, 50), max_density_per_kloc: maxDensity };
  if (exceeding.length > 0) {
    return finding(17, "medium", "fail", joinNotes(`${exceeding.length}/${evaluated} applications exceed ${maxDensity} Very High/High flaws per KLOC.`, ...caveats), evidence);
  }
  if (evaluated === 0) {
    return manualFinding(17, "medium", "No summary report exposed static module lines of code, so flaw density cannot be computed.", manualEvidence, evidence);
  }
  if (missingLoc.length > 0) {
    return finding(17, "medium", "warn", joinNotes(`${evaluated} applications stay within ${maxDensity} Very High/High flaws per KLOC, but ${missingLoc.length} applications expose no static module lines of code and were not evaluated.`, ...caveats), evidence);
  }
  return finding(17, "medium", limitedStatus("pass", caveats), joinNotes(`All ${evaluated} applications with static module data stay within ${maxDensity} Very High/High flaws per KLOC.`, ...caveats), evidence);
}

export async function assessVeracodeFindingsHygiene(
  client: ClientLike,
  options: { maxApplications?: number; maxFpRatePercent?: number; maxFlawDensityPerKloc?: number; now?: Date } = {},
): Promise<VeracodeAssessmentResult> {
  const now = options.now ?? new Date();
  const maxApplications = clampNumber(options.maxApplications, DEFAULT_MAX_APPLICATIONS, 1, 5000);
  const maxFpRate = clampFloat(options.maxFpRatePercent, DEFAULT_MAX_FP_RATE_PERCENT, 0, 100);
  const maxDensity = clampFloat(options.maxFlawDensityPerKloc, DEFAULT_MAX_FLAW_DENSITY_PER_KLOC, 0, 1000);
  const snapshot = await collectApplications(client);
  const manualEvidence = ["Export findings and summary reports per application from the Platform."];
  const blocker = applicationInventoryBlocker(3, "high", snapshot, manualEvidence);
  if (blocker) {
    const findings = [3, 12, 16, 17].map((number) => ({ ...blocker, ...finding(number, blocker.severity, "manual", blocker.summary, blocker.evidence) }));
    const skipped = notAttempted("the application inventory was not readable or empty, so no per-application list was requested.");
    return {
      title: "Veracode findings hygiene",
      summary: { base_url: client.getResolvedConfig().baseUrl, applications_seen: countIfRead(snapshot.applications), applications_sampled: null, ...countByStatus(findings) },
      findings,
      errors: surfaceErrors("applications", snapshot.applications),
      rawData: { applications: rawSurface(snapshot.applications), findings_by_application: skipped, summary_reports_by_application: skipped },
    };
  }
  const inventory = (snapshot.applications as { value: HalListResult }).value;
  const sampled = inventory.items.slice(0, maxApplications);
  const samples: ApplicationFindingsSample[] = [];
  for (const app of sampled) {
    const guid = applicationGuid(app) ?? "";
    samples.push({
      application: applicationName(app),
      guid,
      findings: await surface(() => client.listFindings(guid, { include_annot: "TRUE" })),
      summaryReport: await surface(() => client.getSummaryReport(guid)),
    });
  }
  const findings = [
    evaluateFlawAging(samples, inventory, now),
    evaluateMitigationWorkflow(samples, inventory),
    evaluateFalsePositiveRate(samples, inventory, maxFpRate),
    evaluateFlawDensity(samples, inventory, maxDensity),
  ];
  const errors = [
    ...surfaceErrors("applications", snapshot.applications),
    ...samples.flatMap((sample) => [...surfaceErrors(`findings ${sample.application}`, sample.findings), ...surfaceErrors(`summary report ${sample.application}`, sample.summaryReport)]),
  ];
  return {
    title: "Veracode findings hygiene",
    summary: { base_url: client.getResolvedConfig().baseUrl, applications_seen: inventory.items.length, applications_sampled: samples.length, ...countByStatus(findings) },
    findings,
    errors,
    rawData: {
      applications: inventory,
      findings_by_application: Object.fromEntries(samples.map((sample) => [sample.guid, rawSurface(sample.findings)])),
      summary_reports_by_application: Object.fromEntries(samples.map((sample) => [sample.guid, rawSurface(sample.summaryReport)])),
    },
  };
}

interface ScaWorkspaceSample {
  workspace: string;
  id: string;
  vulnerabilities: Surface<HalListResult>;
  licenses: Surface<HalListResult>;
  libraries: Surface<HalListResult>;
}

function scaUnavailableFinding(number: number, severity: VeracodeFinding["severity"], workspaces: Surface<HalListResult>, evidenceToCollect: string[]): VeracodeFinding | undefined {
  if (workspaces.status === "error") {
    const reason = isUnavailable(workspaces)
      ? `The SCA Agent API was not available to this credential (${workspaces.statusCode}); agent-based SCA may be unlicensed or the API user lacks a Workspace role, so the control is not applicable through the API.`
      : unreadableReason("SCA workspaces", workspaces);
    return manualFinding(number, severity, reason, evidenceToCollect, { status_code: workspaces.statusCode ?? null });
  }
  if (workspaces.value.items.length === 0) {
    return manualFinding(number, severity, "The SCA Agent API returned zero workspaces, so there is no agent-based SCA inventory to evaluate; the empty inventory is treated as not applicable rather than compliant.", ["Confirm whether agent-based SCA is licensed and in use.", ...evidenceToCollect]);
  }
  return undefined;
}

function evaluateScaCurrency(workspaces: Surface<HalListResult>, samples: ScaWorkspaceSample[], cvssThreshold: number): VeracodeFinding {
  const blocker = scaUnavailableFinding(5, "high", workspaces, ["Export SCA vulnerability issues per workspace with CVSS scores."]);
  if (blocker) return blocker;
  const list = (workspaces as { value: HalListResult }).value;
  const readable = samples.filter((sample) => sample.vulnerabilities.status === "ok");
  const unreadable = samples.filter((sample) => sample.vulnerabilities.status === "error");
  if (readable.length === 0) {
    return manualFinding(5, "high", unreadable.length > 0 ? unreadableReason("SCA workspace issues", unreadable[0].vulnerabilities) : "No workspaces were sampled.", ["Export SCA vulnerability issues per workspace."]);
  }
  const high: Array<{ workspace: string; library: string; severity: number; cve: string | null }> = [];
  let issues = 0;
  let librariesSeen = 0;
  let incomplete = 0;
  let libraryListsUnreadable = 0;
  let libraryListsIncomplete = 0;
  for (const sample of readable) {
    const issueList = (sample.vulnerabilities as { value: HalListResult }).value;
    if (!issueList.complete) incomplete += 1;
    if (sample.libraries.status === "ok") {
      librariesSeen += sample.libraries.value.items.length;
      if (!sample.libraries.value.complete) libraryListsIncomplete += 1;
    } else {
      libraryListsUnreadable += 1;
    }
    for (const issue of issueList.items) {
      issues += 1;
      const severity = asNumber(issue.severity) ?? asNumber(asObject(issue.vulnerability)?.cvss3_score) ?? asNumber(asObject(issue.vulnerability)?.cvss2_score);
      if (severity !== undefined && severity >= cvssThreshold) {
        high.push({ workspace: sample.workspace, library: asString(asObject(issue.library)?.name) ?? "library", severity, cve: asString(asObject(issue.vulnerability)?.cve) ?? null });
      }
    }
  }
  const caveats = [
    partialInventoryNote(list, "workspaces"),
    scopeNote(samples.length, list.items.length, "workspaces"),
    unreadable.length > 0 ? `${unreadable.length} workspace issue lists were unreadable.` : undefined,
    incomplete > 0 ? `${incomplete} issue lists were truncated.` : undefined,
    libraryListsUnreadable > 0 ? `${libraryListsUnreadable} workspace library lists were unreadable, so libraries_seen undercounts the scanned libraries.` : undefined,
    libraryListsIncomplete > 0 ? `${libraryListsIncomplete} library lists were truncated, so libraries_seen is a lower bound.` : undefined,
  ];
  const anyLibraryListRead = readable.some((sample) => sample.libraries.status === "ok");
  const evidence = { workspaces_seen: list.items.length, workspaces_sampled: samples.length, open_vulnerability_issues: issues, libraries_seen: anyLibraryListRead ? librariesSeen : null, library_lists_unreadable: libraryListsUnreadable, library_lists_truncated: libraryListsIncomplete, high_severity_issues: high.slice(0, 100), high_severity_count: high.length, cvss_threshold: cvssThreshold };
  if (high.length > 0) {
    return finding(5, "high", "fail", joinNotes(`${high.length} open SCA vulnerability issues at or above CVSS ${cvssThreshold} across ${readable.length} sampled workspaces.`, ...caveats), evidence);
  }
  if (librariesSeen === 0) {
    return manualFinding(5, "high", "No open vulnerability issues were returned, but no libraries were readable in the sampled workspaces, so it is unknown whether any scan has populated them.", ["Confirm the workspaces contain scanned projects and libraries."], evidence);
  }
  return finding(5, "high", limitedStatus("pass", caveats), joinNotes(`No open SCA vulnerability issues at or above CVSS ${cvssThreshold} across ${readable.length} sampled workspaces (${librariesSeen} libraries read).`, ...caveats), evidence);
}

function evaluateScaLicenseRisk(workspaces: Surface<HalListResult>, samples: ScaWorkspaceSample[]): VeracodeFinding {
  const blocker = scaUnavailableFinding(6, "medium", workspaces, ["Export SCA license issues per workspace with license risk ratings."]);
  if (blocker) return blocker;
  const list = (workspaces as { value: HalListResult }).value;
  const readable = samples.filter((sample) => sample.licenses.status === "ok");
  const unreadable = samples.filter((sample) => sample.licenses.status === "error");
  if (readable.length === 0) {
    return manualFinding(6, "medium", unreadable.length > 0 ? unreadableReason("SCA license issues", unreadable[0].licenses) : "No workspaces were sampled.", ["Export SCA license issues per workspace."]);
  }
  const highRisk: Array<{ workspace: string; library: string; license: string; risk: string }> = [];
  const unknownRisk: number[] = [];
  let issues = 0;
  let incomplete = 0;
  for (const sample of readable) {
    const issueList = (sample.licenses as { value: HalListResult }).value;
    if (!issueList.complete) incomplete += 1;
    for (const issue of issueList.items) {
      issues += 1;
      const license = asObject(issue.license) ?? {};
      const risk = asString(license.risk)?.toUpperCase();
      if (risk === "HIGH") highRisk.push({ workspace: sample.workspace, library: asString(asObject(issue.library)?.name) ?? "library", license: asString(license.name) ?? "license", risk });
      else if (!risk || risk === "UNKNOWN") unknownRisk.push(1);
    }
  }
  const caveats = [partialInventoryNote(list, "workspaces"), scopeNote(samples.length, list.items.length, "workspaces"), unreadable.length > 0 ? `${unreadable.length} workspace license lists were unreadable.` : undefined, incomplete > 0 ? `${incomplete} issue lists were truncated.` : undefined];
  const evidence = { workspaces_sampled: samples.length, open_license_issues: issues, high_risk_license_issues: highRisk.slice(0, 100), high_risk_count: highRisk.length, unknown_risk_count: unknownRisk.length };
  if (highRisk.length > 0) {
    return finding(6, "medium", "fail", joinNotes(`${highRisk.length} open SCA license issues carry HIGH license risk (restrictive or copyleft) across ${readable.length} sampled workspaces.`, ...caveats), evidence);
  }
  if (unknownRisk.length > 0) {
    return finding(6, "medium", "warn", joinNotes(`No HIGH risk license issues are open, but ${unknownRisk.length} open license issues expose UNKNOWN or missing risk and need review.`, ...caveats), evidence);
  }
  return finding(6, "medium", limitedStatus("pass", caveats), joinNotes(`No open HIGH risk license issues across ${readable.length} sampled workspaces (${issues} open license issues read).`, ...caveats), evidence);
}

async function evaluateScaWorkspaceCoverage(client: ClientLike, snapshot: ApplicationSnapshot, workspaces: Surface<HalListResult>, maxApplications: number): Promise<{ finding: VeracodeFinding; raw: JsonRecord; errors: string[] }> {
  const blocker = applicationInventoryBlocker(18, "medium", snapshot, ["Map each application with third-party dependencies to an SCA workspace or upload-and-scan SCA."]);
  if (blocker) return { finding: blocker, raw: { sca_projects_by_application: notAttempted("the application inventory was not readable, so no linked project list was requested.") }, errors: [] };
  const scaBlocker = scaUnavailableFinding(18, "medium", workspaces, ["Map each application to an SCA workspace or confirm upload-and-scan SCA is enabled."]);
  const scaAgentNote = scaBlocker ? scaAgentUnavailableCause(workspaces) : undefined;
  const list = (snapshot.applications as { value: HalListResult }).value;
  const sampled = list.items.slice(0, maxApplications);
  const errors: string[] = [];
  const covered: string[] = [];
  const uncovered: string[] = [];
  const unreadable: string[] = [];
  const unreadableLists: UnreadableLinkedProjectList[] = [];
  const unchecked: string[] = [];
  const rawProjects: JsonRecord = {};
  const linkedProjectsByApplication: JsonRecord = {};
  let linkedProjectListsRead = 0;
  for (const app of sampled) {
    const guid = applicationGuid(app) ?? "";
    if (asBoolean(asObject(app.profile)?.upload_and_scan_sca_enabled) === true) {
      covered.push(applicationName(app));
      continue;
    }
    if (scaBlocker) {
      // No linked project list is requested while the SCA Agent API is unreadable, so the application is unchecked, never uncovered.
      unchecked.push(applicationName(app));
      continue;
    }
    const projects = await surface(() => client.getScaApplicationProjects(guid));
    errors.push(...surfaceErrors(`sca projects ${applicationName(app)}`, projects));
    rawProjects[guid] = rawSurface(projects);
    if (projects.status === "error") {
      // The evidence map keeps the same marker as the snapshot for a list that failed, so it never reads as "no linked projects".
      unreadable.push(applicationName(app));
      unreadableLists.push({ application: applicationName(app), status: projects.statusCode ?? null, endpoint: projects.endpoint ?? null });
      linkedProjectsByApplication[applicationName(app)] = rawSurface(projects);
      continue;
    }
    linkedProjectListsRead += 1;
    const linked = asRecords(projects.value.linked_projects);
    linkedProjectsByApplication[applicationName(app)] = linked.slice(0, 20).map((project) => ({
      name: asString(project.name) ?? asString(project.id) ?? null,
      workspace: asString(asObject(project.workspace)?.name) ?? null,
      last_scan_date: asString(project.last_scan_date) ?? null,
    }));
    if (linked.length > 0) covered.push(applicationName(app));
    else uncovered.push(applicationName(app));
  }
  const listsRequested = linkedProjectListsRead + unreadableLists.length;
  const unreadableDetail = unreadableLists.length > 0 ? describeUnreadableLinkedProjectLists(unreadableLists, listsRequested) : undefined;
  const inventoryCaveats = [partialInventoryNote(list, "applications"), scopeNote(sampled.length, list.items.length, "applications")];
  const caveats = [...inventoryCaveats, unreadableDetail ? `${unreadableDetail.count} requested linked project lists could not be read (${unreadableDetail.observed}).` : undefined];
  // With the SCA Agent API unreadable no project list is requested: the uncovered set and the linked project map were never determined, so they render null and the snapshot carries a marker rather than an empty map.
  // The map also renders null, never {}, when no linked project list was read (every requested list failed, or none was needed); with some lists read the failed ones sit beside them as markers.
  const evidence = {
    applications_sampled: sampled.length,
    covered_applications: covered.length,
    uncovered_applications: scaBlocker ? null : uncovered.slice(0, 50),
    unreadable_applications: unreadable.slice(0, 50),
    unreadable_linked_project_lists: unreadableLists.slice(0, 50),
    linked_project_lists_requested: listsRequested,
    unchecked_applications: unchecked.slice(0, 50),
    linked_projects_by_application: linkedProjectListsRead > 0 ? linkedProjectsByApplication : null,
    sca_agent_api_available: !scaBlocker,
    sca_agent_api_status: workspaces.status === "error" ? workspaces.statusCode ?? null : null,
  };
  // The snapshot dataset is a marker, never {}, whenever no list was requested: the SCA Agent API was unreadable, or no sampled application needed one.
  const raw = {
    sca_projects_by_application: scaBlocker
      ? notAttempted("the SCA Agent API was not readable, so no linked project list was requested.")
      : listsRequested === 0
        ? notAttempted("every sampled application has upload_and_scan_sca_enabled, so no linked project list was requested.")
        : rawProjects,
  };
  if (scaBlocker && covered.length === 0) {
    return { finding: { ...scaBlocker, evidence: { ...scaBlocker.evidence, ...evidence } }, raw, errors };
  }
  if (unchecked.length > 0) {
    return { finding: finding(18, "medium", "warn", joinNotes(`${unchecked.length}/${sampled.length} sampled applications have no upload-and-scan SCA and their linked SCA agent projects were not checked because ${scaAgentNote}, so their coverage is unknown.`, ...caveats), evidence), raw, errors };
  }
  if (uncovered.length > 0) {
    return { finding: finding(18, "medium", "warn", joinNotes(`${uncovered.length}/${sampled.length} sampled applications have neither upload-and-scan SCA enabled nor a linked SCA agent project.`, ...caveats), evidence), raw, errors };
  }
  if (covered.length === 0) {
    // Every list requested was unreadable: the reason names the lists, their count, the endpoint, and the observed status, so the manual verdict says what could not be read.
    const reason = unreadableDetail
      ? `No application could be evaluated for SCA coverage: every linked project list requested was unreadable (${unreadableDetail.count}; ${unreadableDetail.observed}).`
      : "No application could be evaluated for SCA coverage.";
    return { finding: manualFinding(18, "medium", reason, ["Map each application to an SCA workspace."], evidence, inventoryCaveats), raw, errors };
  }
  const agentlessNote = scaAgentNote ? `Linked agent projects were not checked because ${scaAgentNote}; every sampled application is covered by upload-and-scan SCA alone.` : undefined;
  const coveredCount = covered.length === sampled.length ? `All ${covered.length}` : `${covered.length} of ${sampled.length}`;
  return { finding: finding(18, "medium", limitedStatus("pass", caveats), joinNotes(`${coveredCount} sampled applications have upload-and-scan SCA enabled or a linked SCA agent project (linked_projects from the SCA Agent API).`, agentlessNote, ...caveats), evidence), raw, errors };
}

/** Names the observed cause when the SCA Agent API workspace list could not be used: its own status code, or the empty inventory. */
function scaAgentUnavailableCause(workspaces: Surface<HalListResult>): string {
  if (workspaces.status === "error") {
    if (isForbidden(workspaces)) return `the SCA Agent API workspace list was forbidden (${workspaces.statusCode})`;
    return workspaces.statusCode ? `the SCA Agent API workspace list returned an error (${workspaces.statusCode})` : "the SCA Agent API workspace list could not be read";
  }
  return "the SCA Agent API returned zero workspaces";
}

export async function assessVeracodeScaPosture(
  client: ClientLike,
  options: { maxApplications?: number; maxWorkspaces?: number; scaCvssThreshold?: number } = {},
): Promise<VeracodeAssessmentResult> {
  const maxApplications = clampNumber(options.maxApplications, DEFAULT_MAX_APPLICATIONS, 1, 5000);
  const maxWorkspaces = clampNumber(options.maxWorkspaces, DEFAULT_MAX_WORKSPACES, 1, 500);
  const cvssThreshold = clampFloat(options.scaCvssThreshold, DEFAULT_SCA_CVSS_THRESHOLD, 0, 10);
  const snapshot = await collectApplications(client);
  const workspaces = await surface(() => client.listScaWorkspaces());
  const samples: ScaWorkspaceSample[] = [];
  if (workspaces.status === "ok") {
    for (const workspace of workspaces.value.items.slice(0, maxWorkspaces)) {
      const id = asString(workspace.id) ?? "";
      samples.push({
        workspace: asString(workspace.name) ?? id,
        id,
        vulnerabilities: await surface(() => client.listScaWorkspaceIssues(id, "vulnerability")),
        licenses: await surface(() => client.listScaWorkspaceIssues(id, "license")),
        libraries: await surface(() => client.listScaWorkspaceLibraries(id)),
      });
    }
  }
  const coverage = await evaluateScaWorkspaceCoverage(client, snapshot, workspaces, maxApplications);
  const findings = [
    evaluateScaCurrency(workspaces, samples, cvssThreshold),
    evaluateScaLicenseRisk(workspaces, samples),
    coverage.finding,
  ];
  const errors = [
    ...surfaceErrors("applications", snapshot.applications),
    ...surfaceErrors("sca workspaces", workspaces),
    ...samples.flatMap((sample) => [...surfaceErrors(`sca vulnerabilities ${sample.workspace}`, sample.vulnerabilities), ...surfaceErrors(`sca licenses ${sample.workspace}`, sample.licenses), ...surfaceErrors(`sca libraries ${sample.workspace}`, sample.libraries)]),
    ...coverage.errors,
  ];
  return {
    title: "Veracode SCA posture",
    summary: { base_url: client.getResolvedConfig().baseUrl, workspaces_seen: countIfRead(workspaces), workspaces_sampled: workspaces.status === "ok" ? samples.length : null, cvss_threshold: cvssThreshold, ...countByStatus(findings) },
    findings,
    errors,
    rawData: {
      applications: rawSurface(snapshot.applications),
      sca_workspaces: rawSurface(workspaces),
      sca_issues_by_workspace: workspaces.status === "ok"
        ? Object.fromEntries(samples.map((sample) => [sample.id, {
          vulnerabilities: rawSurface(sample.vulnerabilities),
          licenses: rawSurface(sample.licenses),
          libraries: rawSurface(sample.libraries),
        }]))
        : notAttempted("the SCA workspace list was not readable, so no workspace issue or library list was requested."),
      ...coverage.raw,
    },
  };
}

interface IdentitySnapshot {
  users: Surface<HalListResult>;
  teams: Surface<HalListResult>;
  roles: Surface<HalListResult>;
  self: Surface<JsonRecord>;
  applications: Surface<HalListResult>;
}

function userLabel(user: JsonRecord): string {
  return asString(user.user_name) ?? asString(user.email_address) ?? asString(user.user_id) ?? "user";
}

function userRoleNames(user: JsonRecord): string[] {
  return asRecords(user.roles).map((role) => asString(role.role_name) ?? "").filter(Boolean);
}

function isActiveHuman(user: JsonRecord): boolean {
  return asBoolean(user.active) === true && asBoolean(user.login_enabled) === true && asString(user.account_type)?.toUpperCase() !== "API" && asBoolean(user.api_user) !== true;
}

function isApiAccount(user: JsonRecord): boolean {
  return asString(user.account_type)?.toUpperCase() === "API" || asBoolean(user.api_user) === true;
}

function evaluateTeamAccess(snapshot: IdentitySnapshot, maxUnrestricted: number): VeracodeFinding {
  const manualEvidence = ["Export team membership and application-to-team assignments from the Platform and confirm least privilege."];
  if (snapshot.users.status === "error") return manualFinding(7, "high", unreadableReason("users (Administrator role)", snapshot.users), manualEvidence, { status_code: snapshot.users.statusCode ?? null });
  if (snapshot.roles.status === "error") return manualFinding(7, "high", unreadableReason("roles (Administrator role)", snapshot.roles), manualEvidence, { status_code: snapshot.roles.statusCode ?? null });
  if (snapshot.teams.status === "error") return manualFinding(7, "high", unreadableReason("teams (Administrator role)", snapshot.teams), manualEvidence, { status_code: snapshot.teams.statusCode ?? null });
  if (snapshot.users.value.items.length === 0) return manualFinding(7, "high", "The users endpoint returned zero users, which cannot be a complete inventory because the API credential belongs to a user; the empty list is treated as unverifiable rather than compliant.", manualEvidence);
  if (snapshot.roles.value.items.length === 0) return manualFinding(7, "high", "The roles endpoint returned zero roles, which cannot be a complete inventory because Veracode ships built-in roles; the empty list is treated as unverifiable rather than compliant.", manualEvidence);
  const unrestrictedRoles = new Set(snapshot.roles.value.items.filter((role) => asBoolean(role.ignore_team_restrictions) === true).map((role) => asString(role.role_name) ?? ""));
  const unrestrictedUsers = snapshot.users.value.items.filter((user) => isActiveHuman(user) && userRoleNames(user).some((role) => unrestrictedRoles.has(role))).map(userLabel);
  const applicationsRead = snapshot.applications.status === "ok";
  const appsWithoutTeams = snapshot.applications.status === "ok" ? snapshot.applications.value.items.filter((app) => applicationTeams(app).length === 0).map(applicationName) : [];
  const teamScopeNotes = snapshot.teams.value.notes ?? [];
  const caveats = [partialInventoryNote(snapshot.users.value, "users"), partialInventoryNote(snapshot.roles.value, "roles"), partialInventoryNote(snapshot.teams.value, "teams"), ...teamScopeNotes, snapshot.applications.status === "ok" ? partialInventoryNote(snapshot.applications.value, "applications") : "The application inventory was unreadable, so application team assignment was not verified."];
  // The team assignment list comes from the application inventory: null, never [], when it was not read.
  const evidence = { users_seen: snapshot.users.value.items.length, roles_seen: snapshot.roles.value.items.length, roles_complete: snapshot.roles.value.complete, teams_seen: snapshot.teams.value.items.length, teams_scope: teamScopeNotes.length > 0 ? "member_only" : "organization", team_unrestricted_roles: [...unrestrictedRoles].filter(Boolean), users_with_all_application_access: unrestrictedUsers.slice(0, 100), users_with_all_application_access_count: unrestrictedUsers.length, applications_without_team: applicationsRead ? appsWithoutTeams.slice(0, 50) : null, max_unrestricted_users: maxUnrestricted };
  if (snapshot.teams.value.items.length === 0 && teamScopeNotes.length > 0) {
    return manualFinding(7, "high", joinNotes("The organization-wide team list was refused and the API user is a member of no teams, so team scoping could not be verified.", ...teamScopeNotes), manualEvidence, evidence);
  }
  if (snapshot.teams.value.items.length === 0) {
    return finding(7, "high", "fail", joinNotes("No teams exist (all_for_org=true was accepted), so every user with application visibility sees the whole portfolio and team-based least privilege is not in place.", ...caveats), evidence);
  }
  if (unrestrictedUsers.length > maxUnrestricted) {
    return finding(7, "high", "fail", joinNotes(`${unrestrictedUsers.length} active users hold roles that ignore team restrictions (all-application access), exceeding the threshold of ${maxUnrestricted}.`, ...caveats), evidence);
  }
  if (appsWithoutTeams.length > 0) {
    return finding(7, "high", "warn", joinNotes(`${appsWithoutTeams.length} applications have no team assigned, so only team-unrestricted roles can see them; ${unrestrictedUsers.length} active users hold team-unrestricted roles.`, ...caveats), evidence);
  }
  return finding(7, "high", limitedStatus("pass", caveats), joinNotes(`${snapshot.teams.value.items.length} teams scope access, every application read has a team, and ${unrestrictedUsers.length} active users hold team-unrestricted roles (threshold ${maxUnrestricted}).`, ...caveats), evidence);
}

function evaluateUserRoles(snapshot: IdentitySnapshot, maxAdmins: number, inactiveDays: number, now: Date): VeracodeFinding {
  const manualEvidence = ["Export the user list with roles, last login, and team assignments from the Platform."];
  if (snapshot.users.status === "error") return manualFinding(8, "high", unreadableReason("users (Administrator role)", snapshot.users), manualEvidence, { status_code: snapshot.users.statusCode ?? null });
  if (snapshot.users.value.items.length === 0) return manualFinding(8, "high", "The users endpoint returned zero users, which cannot be a complete inventory because the API credential belongs to a user; the empty list is treated as unverifiable rather than compliant.", manualEvidence);
  const users = snapshot.users.value.items;
  const active = users.filter((user) => asBoolean(user.active) === true);
  const admins = active.filter((user) => userRoleNames(user).some((role) => /^administrator$/i.test(role))).map(userLabel);
  const inactive: string[] = [];
  const neverLoggedIn: string[] = [];
  for (const user of active.filter(isActiveHuman)) {
    const lastLogin = parseDate(user.last_login);
    if (!lastLogin) neverLoggedIn.push(userLabel(user));
    else if (daysSince(lastLogin, now) > inactiveDays) inactive.push(userLabel(user));
  }
  const serviceWithoutTeam = active.filter((user) => isApiAccount(user) && asRecords(user.teams).length === 0 && asBoolean(user.no_teams_required) !== true).map(userLabel);
  const nonSaml = active.filter(isActiveHuman).filter((user) => asBoolean(user.saml_user) !== true).map(userLabel);
  const partial = partialInventoryNote(snapshot.users.value, "users");
  const evidence = { users_seen: users.length, active_users: active.length, administrators: admins.slice(0, 50), administrator_count: admins.length, max_admins: maxAdmins, inactive_users: inactive.slice(0, 100), inactive_count: inactive.length, users_without_last_login: neverLoggedIn.slice(0, 100), users_without_last_login_count: neverLoggedIn.length, api_accounts_without_team: serviceWithoutTeam.slice(0, 50), non_saml_human_users: nonSaml.length, inactive_days: inactiveDays };
  if (inactive.length > 0 || serviceWithoutTeam.length > 0 || admins.length > maxAdmins) {
    return finding(8, "high", "fail", joinNotes(`${admins.length} Administrator accounts (threshold ${maxAdmins}), ${inactive.length} active human users with no login in ${inactiveDays} days, and ${serviceWithoutTeam.length} API accounts without a team assignment.`, partial), evidence);
  }
  if (neverLoggedIn.length > 0) {
    return finding(8, "high", "warn", joinNotes(`${neverLoggedIn.length} active human users expose no last_login and were not counted as active; ${admins.length} Administrator accounts are within the threshold of ${maxAdmins}.`, partial), evidence);
  }
  return finding(8, "high", limitedStatus("pass", [partial]), joinNotes(`${admins.length} Administrator accounts (threshold ${maxAdmins}), no active human users inactive beyond ${inactiveDays} days, and every API account has a team assignment.`, partial), evidence);
}

async function evaluateApiCredentials(client: ClientLike, snapshot: IdentitySnapshot, maxAgeDays: number, now: Date): Promise<{ finding: VeracodeFinding; raw: JsonRecord; errors: string[] }> {
  const manualEvidence = ["Export API credential creation and expiration dates per API service account from the Platform."];
  const skipped = (reason: string) => ({ api_credentials_by_user: notAttempted(reason) });
  if (snapshot.users.status === "error") return { finding: manualFinding(9, "high", unreadableReason("users (Administrator role)", snapshot.users), manualEvidence, { status_code: snapshot.users.statusCode ?? null }), raw: skipped("the user list was not readable, so no credential record was requested."), errors: [] };
  const apiUsers = snapshot.users.value.items.filter((user) => isApiAccount(user) && asBoolean(user.active) === true);
  if (snapshot.users.value.items.length === 0) return { finding: manualFinding(9, "high", "The users endpoint returned zero users, so API credentials could not be inventoried; the empty list is treated as unverifiable rather than compliant.", manualEvidence), raw: skipped("the user list was empty, so no credential record was requested."), errors: [] };
  if (apiUsers.length === 0) return { finding: manualFinding(9, "high", "No active API service accounts were returned even though this request is authenticated with API credentials, so the credential inventory is unverifiable.", manualEvidence, { users_seen: snapshot.users.value.items.length }), raw: skipped("the user list carried no active API account, so no credential record was requested."), errors: [] };
  const sampled = apiUsers.slice(0, 200);
  const results = await Promise.all(sampled.map(async (user) => ({ user: userLabel(user), userId: asString(user.user_id) ?? "", credentials: await surface(() => client.getUserApiCredentials(asString(user.user_id) ?? "")) })));
  const errors = results.flatMap((item) => surfaceErrors(`api credentials ${item.user}`, item.credentials));
  const readable = results.filter((item) => item.credentials.status === "ok");
  const unreadable = results.filter((item) => item.credentials.status === "error");
  const aged: Array<{ user: string; api_id: string | null; age_days: number }> = [];
  const expired: string[] = [];
  const missingDates: string[] = [];
  let current = 0;
  const projectCredential = (credential: JsonRecord): JsonRecord => ({ api_id: asString(credential.api_id) ?? null, created_ts: asString(credential.created_ts) ?? null, expiration_ts: asString(credential.expiration_ts) ?? null, revocation_ts: asString(credential.revocation_ts) ?? null, last_used_ts: asString(credential.last_used_ts) ?? null });
  const rawCredentials: JsonRecord = Object.fromEntries(results.map((item) => [item.userId, rawSurface(item.credentials, projectCredential)]));
  for (const item of readable) {
    const credential = (item.credentials as { value: JsonRecord }).value;
    if (asString(credential.revocation_ts)) continue;
    const created = parseDate(credential.created_ts);
    const expiration = parseDate(credential.expiration_ts);
    if (!created || !expiration) {
      missingDates.push(item.user);
      continue;
    }
    if (expiration.getTime() < now.getTime()) expired.push(item.user);
    const age = daysSince(created, now);
    if (age > maxAgeDays) aged.push({ user: item.user, api_id: asString(credential.api_id) ?? null, age_days: age });
    else current += 1;
  }
  const caveats = [partialInventoryNote(snapshot.users.value, "users"), scopeNote(sampled.length, apiUsers.length, "API accounts"), unreadable.length > 0 ? `${unreadable.length} credential records were unreadable.` : undefined];
  // With no credential record readable the age classification is unknown, not 0 or []; credentials_readable stays the honest count of records read.
  const anyReadable = readable.length > 0;
  const evidence = { api_accounts: apiUsers.length, api_accounts_sampled: sampled.length, credentials_readable: readable.length, credentials_current: anyReadable ? current : null, credentials_over_max_age: anyReadable ? aged.slice(0, 100) : null, credentials_over_max_age_count: anyReadable ? aged.length : null, credentials_expired: anyReadable ? expired.slice(0, 50) : null, credentials_missing_dates: anyReadable ? missingDates.slice(0, 50) : null, max_credential_age_days: maxAgeDays };
  if (readable.length === 0) {
    return { finding: manualFinding(9, "high", unreadableReason("api_credentials (Administrator role)", unreadable[0].credentials), manualEvidence, evidence), raw: { api_credentials_by_user: rawCredentials }, errors };
  }
  if (aged.length > 0) {
    return { finding: finding(9, "high", "fail", joinNotes(`${aged.length}/${readable.length} readable API credentials were created more than ${maxAgeDays} days ago and have not been revoked${expired.length > 0 ? ` (${expired.length} are expired but still not revoked)` : ""}.`, ...caveats), evidence), raw: { api_credentials_by_user: rawCredentials }, errors };
  }
  if (missingDates.length > 0 || expired.length > 0) {
    return { finding: finding(9, "high", "warn", joinNotes(`${missingDates.length} credentials expose no created_ts or expiration_ts and were not counted as current, and ${expired.length} are expired but not revoked; ${current} credentials are within ${maxAgeDays} days.`, ...caveats), evidence), raw: { api_credentials_by_user: rawCredentials }, errors };
  }
  return { finding: finding(9, "high", limitedStatus("pass", caveats), joinNotes(`All ${current} readable, unrevoked API credentials were created within ${maxAgeDays} days and carry an expiration_ts.`, ...caveats), evidence), raw: { api_credentials_by_user: rawCredentials }, errors };
}

export async function assessVeracodeAccessControls(
  client: ClientLike,
  options: { maxAdmins?: number; maxUnrestrictedUsers?: number; inactiveDays?: number; maxCredentialAgeDays?: number; now?: Date } = {},
): Promise<VeracodeAssessmentResult> {
  const now = options.now ?? new Date();
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10000);
  const maxUnrestricted = clampNumber(options.maxUnrestrictedUsers, DEFAULT_MAX_UNRESTRICTED_USERS, 0, 10000);
  const inactiveDays = clampNumber(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650);
  const maxCredentialAge = clampNumber(options.maxCredentialAgeDays, DEFAULT_MAX_CREDENTIAL_AGE_DAYS, 1, 3650);
  const [users, teams, roles, self, applications] = await Promise.all([
    surface(() => client.listUsers()),
    surface(() => client.listTeams()),
    surface(() => client.listRoles()),
    surface(() => client.getSelf()),
    surface(() => client.listApplications()),
  ]);
  const snapshot: IdentitySnapshot = { users, teams, roles, self, applications };
  const credentials = await evaluateApiCredentials(client, snapshot, maxCredentialAge, now);
  const findings = [
    evaluateTeamAccess(snapshot, maxUnrestricted),
    evaluateUserRoles(snapshot, maxAdmins, inactiveDays, now),
    credentials.finding,
  ];
  return {
    title: "Veracode access controls",
    summary: { base_url: client.getResolvedConfig().baseUrl, users_seen: countIfRead(users), teams_seen: countIfRead(teams), roles_seen: countIfRead(roles), ...countByStatus(findings) },
    findings,
    errors: [...surfaceErrors("users", users), ...surfaceErrors("teams", teams), ...surfaceErrors("roles", roles), ...surfaceErrors("self", self), ...surfaceErrors("applications", applications), ...credentials.errors],
    rawData: {
      users: rawSurface(users),
      teams: rawSurface(teams),
      roles: rawSurface(roles),
      self: rawSurface(self),
      ...credentials.raw,
    },
  };
}

function countByStatus(findings: VeracodeFinding[]): { pass: number; warn: number; fail: number; manual: number } {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) {
    switch (item.status) {
      case "pass":
        counts.pass += 1;
        break;
      case "warn":
        counts.warn += 1;
        break;
      case "fail":
        counts.fail += 1;
        break;
      case "manual":
        counts.manual += 1;
        break;
      default: {
        const exhaustive: never = item.status;
        throw new Error(`Unhandled finding status ${String(exhaustive)}`);
      }
    }
  }
  return counts;
}

function severityRank(severity: VeracodeFinding["severity"]): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default: {
      const exhaustive: never = severity;
      throw new Error(`Unhandled severity ${String(exhaustive)}`);
    }
  }
}

export async function checkVeracodeAccess(client: ClientLike): Promise<VeracodeAccessCheckResult> {
  const config = client.getResolvedConfig();
  const probeNotes: string[] = [];
  // Probes read one page; the vendor total is reported when the page carries it, otherwise the count is marked as first page only.
  const listProbe = (list: HalListResult): { count: number; countNote?: string } => (list.totalElements !== undefined
    ? { count: list.totalElements }
    : { count: list.items.length, countNote: list.complete ? undefined : "first page only, total unknown" });
  const probes: Array<{ name: string; endpoint: string; requiredRole: string; load: () => Promise<{ count: number; countNote?: string }> }> = [
    { name: "self", endpoint: "/api/authn/v2/users/self", requiredRole: "any API user", load: async () => ({ count: (await client.getSelf()) ? 1 : 0 }) },
    { name: "applications", endpoint: "/appsec/v1/applications", requiredRole: "Security Insights or Reviewer", load: async () => listProbe(await client.listApplications({ maxPages: 1 })) },
    { name: "policies", endpoint: "/appsec/v1/policies", requiredRole: "Security Insights or Reviewer", load: async () => listProbe(await client.listPolicies({ maxPages: 1 })) },
    { name: "users", endpoint: "/api/authn/v2/users", requiredRole: "Administrator", load: async () => listProbe(await client.listUsers({ maxPages: 1 })) },
    {
      name: "teams",
      endpoint: "/api/authn/v2/teams?all_for_org=true",
      requiredRole: "Administrator",
      load: async () => {
        const teams = await client.listTeams({ maxPages: 1 });
        probeNotes.push(...(teams.notes ?? []));
        return listProbe(teams);
      },
    },
    { name: "roles", endpoint: "/api/authn/v2/roles", requiredRole: "Administrator", load: async () => listProbe(await client.listRoles({ maxPages: 1 })) },
    { name: "api_credentials", endpoint: "/api/authn/v2/api_credentials", requiredRole: "any API user", load: async () => ({ count: (await client.getSelfApiCredentials()) ? 1 : 0 }) },
    { name: "sca_workspaces", endpoint: "/srcclr/v3/workspaces", requiredRole: "Workspace Administrator or Workspace Editor (SCA license)", load: async () => listProbe(await client.listScaWorkspaces({ maxPages: 1 })) },
    { name: "dynamic_analyses", endpoint: "/was/configservice/v1/analyses", requiredRole: "Security Insights (Dynamic Analysis license)", load: async () => listProbe(await client.listDynamicAnalyses({ maxPages: 1 })) },
  ];
  const surfaces: VeracodeAccessSurface[] = [];
  for (const probe of probes) {
    const result = await surface(probe.load);
    surfaces.push(result.status === "ok"
      ? { name: probe.name, endpoint: probe.endpoint, status: "readable", count: result.value.count, ...(result.value.countNote ? { countNote: result.value.countNote } : {}), requiredRole: probe.requiredRole }
      : { name: probe.name, endpoint: result.endpoint ?? probe.endpoint, status: "not_readable", count: null, statusCode: result.statusCode ?? null, error: result.error, requiredRole: probe.requiredRole });
  }
  const self = await surface(() => client.getSelf());
  const principal = self.status === "ok" ? userLabel(self.value) : undefined;
  const roles = self.status === "ok" ? userRoleNames(self.value) : [];
  const coreSurfaces = new Set(["self", "applications", "policies", "users", "teams", "roles", "api_credentials"]);
  const readableCore = surfaces.filter((item) => coreSurfaces.has(item.name) && item.status === "readable").length;
  const missingRoles = [...new Set(surfaces.filter((item) => item.status === "not_readable" && (item.statusCode === 401 || item.statusCode === 403) && coreSurfaces.has(item.name)).map((item) => item.requiredRole))];
  const status = readableCore === coreSurfaces.size ? "healthy" : "limited";
  const optionalUnavailable = surfaces.filter((item) => !coreSurfaces.has(item.name) && item.status === "not_readable").map((item) => item.name);
  return {
    status,
    region: config.region,
    baseUrl: config.baseUrl,
    principal,
    surfaces,
    missingRoles,
    notes: [
      `Using Veracode API base ${config.baseUrl} (region ${config.region}, credentials from ${config.sourceChain.join(" -> ")}).`,
      principal ? `Authenticated as ${principal}${roles.length > 0 ? ` with roles ${roles.join(", ")}` : ""}.` : "The principal could not be read from /api/authn/v2/users/self.",
      `${readableCore}/${coreSurfaces.size} core audit surfaces are readable.`,
      ...probeNotes,
      ...(optionalUnavailable.length > 0 ? [`Optional license-gated surfaces not readable: ${optionalUnavailable.join(", ")} (their controls will render as manual).`] : []),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run veracode_assess_scan_coverage, veracode_assess_policy_compliance, veracode_assess_findings_hygiene, veracode_assess_sca_posture, veracode_assess_access_controls, or veracode_export_audit_bundle."
      : `Grant the API service account the missing roles (${missingRoles.join(", ") || "Security Insights, Reviewer, Administrator"}) and confirm the region matches the account.`,
  };
}

function formatAccessCheckText(result: VeracodeAccessCheckResult): string {
  const rows = result.surfaces.map((item) => [
    item.name,
    item.status,
    item.count === null ? "-" : `${item.count}${item.countNote ? ` (${item.countNote})` : ""}`,
    item.requiredRole,
    item.error ? item.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Veracode access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Required role", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: VeracodeAssessmentResult): string {
  const rows = result.findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.summary]);
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

function markdownEscape(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function mappingsForFramework(item: VeracodeFinding, framework: FrameworkDescriptor): string[] {
  const prefix = `${framework.label} `;
  return item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length));
}

function buildExecutiveSummary(config: VeracodeResolvedConfig, assessments: VeracodeAssessmentResult[], errors: string[], generatedAt: Date): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => (left.status === right.status ? severityRank(left.severity) - severityRank(right.severity) : left.status === "fail" ? -1 : 1))
    .slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");
  return [
    "# Veracode Security Inspector Executive Summary",
    "",
    `- API base: ${config.baseUrl} (region ${config.region})`,
    `- Generated: ${generatedAt.toISOString()}`,
    `- Credential source: ${config.sourceChain.join(" -> ")}`,
    `- Controls assessed: ${findings.length} of ${VERACODE_CONTROLS.length}`,
    "",
    "## Result Counts",
    "",
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.map((item) => `- ${item.id} ${item.title} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`)
      : ["- No failing or warning findings were generated."]),
    "",
    "## Manual Evidence Required",
    "",
    ...(manual.length > 0 ? manual.map((item) => `- ${item.id} ${item.title}: ${item.summary}`) : ["- Every control was verified through the API."]),
    ...(errors.length > 0 ? ["", "## Collection Warnings", "", ...errors.map((error) => `- ${error}`)] : []),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: VeracodeFinding[]): string {
  const header = ["Control", "Title", "Status", "Severity", ...VERACODE_FRAMEWORKS.map((framework) => framework.label)];
  return [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...findings.map((item) => `| ${[item.id, item.title, item.status, item.severity, ...VERACODE_FRAMEWORKS.map((framework) => mappingsForFramework(item, framework).join(", ") || "N/A")].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildFrameworkReport(framework: FrameworkDescriptor, findings: VeracodeFinding[], generatedAt: Date): string {
  const mapped = findings.filter((item) => mappingsForFramework(item, framework).length > 0);
  const counts = countByStatus(mapped);
  return [
    `# ${framework.label} Compliance Report (Veracode)`,
    "",
    `Generated: ${generatedAt.toISOString()}`,
    "",
    `Mapped controls: ${mapped.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    `| ${framework.label} requirement | Control | Title | Status | Summary |`,
    "| --- | --- | --- | --- | --- |",
    ...mapped.map((item) => `| ${[mappingsForFramework(item, framework).join(", "), item.id, item.title, item.status.toUpperCase(), item.summary].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildQuickReference(result: { outputDir: string; findings: VeracodeFinding[]; errors: string[] }): string {
  const counts = countByStatus(result.findings);
  return [
    "# Veracode Audit Bundle Quick Reference",
    "",
    "This bundle was generated by grclanker's read-only Veracode tools. Credentials are never written into the bundle.",
    "",
    "## Contents",
    "",
    "- `core_data/*.json`: raw API snapshots (applications, policies, findings, summary reports, SCA, Dynamic Analysis, identity)",
    "- `analysis/findings.json`: normalized findings with framework mappings",
    "- `analysis/*.json`: per-assessment results and summaries",
    "- `compliance/executive_summary.md`: prioritized summary and manual evidence list",
    "- `compliance/unified_compliance_matrix.md`: all controls across FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, STIG, IRAP, and ISMAP",
    "- `compliance/<framework>.md`: one report per framework",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "## Result Counts",
    "",
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    `- Collection warnings: ${result.errors.length}`,
    "",
    "## Status Semantics",
    "",
    "- pass: verified through the API with a complete inventory",
    "- warn: partially verified, partial inventory, or items missing dates",
    "- fail: verified non-compliance",
    "- manual: unreadable, unlicensed, empty, or out of API scope; the summary states the evidence a human must collect",
    "",
  ].join("\n");
}

const REDACTED = "[REDACTED]";

/**
 * Rule 9 deny list for the whole-resource snapshots in core_data: matched on
 * the lowercased key with dots, underscores, and hyphens removed. Suffix
 * matches keep evidence keys such as credentials_readable and api_id legible
 * while catching password, api_token, client_secret, login_script_data, and
 * certificate material wherever an operator-authored record carries them.
 */
const CREDENTIAL_KEY_PATTERN = /(password|passwd|passphrase|secret|token|apikey|privatekey|scriptdata|scriptbody|certificate)$/;

const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;

function isCredentialKey(key: string): boolean {
  return CREDENTIAL_KEY_PATTERN.test(key.toLowerCase().replace(/[._-]/g, ""));
}

/** Rewrites only URLs whose userinfo or query string could carry a token (git_repo_url with user:token@, target URLs with session parameters). */
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

/**
 * Applied to every JSON object written into the bundle: redacts the value of
 * every credential-named key (including {name, value} pair shapes such as
 * application profile custom_fields), every JWT-shaped string, and the
 * userinfo and query string of every URL-valued string, keeping key names so
 * the evidence stays legible.
 */
function redactSnapshot(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSnapshot);
  const object = asObject(value);
  if (!object) return typeof value === "string" ? (JWT_PATTERN.test(value) ? REDACTED : scrubUrlValue(value)) : value;
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

export async function exportVeracodeAuditBundle(
  client: ClientLike,
  config: VeracodeResolvedConfig,
  outputRoot: string,
  options: {
    maxApplications?: number;
    maxScanAgeDays?: number;
    maxAnalyses?: number;
    criticalScanIntervalDays?: number;
    standardScanIntervalDays?: number;
    maxFpRatePercent?: number;
    maxFlawDensityPerKloc?: number;
    maxWorkspaces?: number;
    scaCvssThreshold?: number;
    maxAdmins?: number;
    maxUnrestrictedUsers?: number;
    inactiveDays?: number;
    maxCredentialAgeDays?: number;
    now?: Date;
  } = {},
): Promise<VeracodeAuditBundleResult> {
  const generatedAt = options.now ?? new Date();
  const access = await checkVeracodeAccess(client);
  const scanCoverage = await assessVeracodeScanCoverage(client, options);
  const policyCompliance = await assessVeracodePolicyCompliance(client, options);
  const findingsHygiene = await assessVeracodeFindingsHygiene(client, options);
  const scaPosture = await assessVeracodeScaPosture(client, options);
  const accessControls = await assessVeracodeAccessControls(client, options);
  const assessments = [scanCoverage, policyCompliance, findingsHygiene, scaPosture, accessControls];
  const findings = assessments.flatMap((assessment) => assessment.findings).sort((left, right) => left.id.localeCompare(right.id));
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(new URL(config.baseUrl).host)}-audit-bundle`);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference({ outputDir, findings, errors }));
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({ generated_at: generatedAt.toISOString(), base_url: config.baseUrl, region: config.region, profile: config.profile, source_chain: config.sourceChain, principal: access.principal ?? null }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(redactSnapshot(access)));
  const assessmentFiles: Array<[string, VeracodeAssessmentResult]> = [
    ["scan-coverage", scanCoverage],
    ["policy-compliance", policyCompliance],
    ["findings-hygiene", findingsHygiene],
    ["sca-posture", scaPosture],
    ["access-controls", accessControls],
  ];
  for (const [name, assessment] of assessmentFiles) {
    await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(redactSnapshot(assessment.rawData)));
    await writeSecureTextFile(outputDir, `analysis/${name}.json`, serializeJson(redactSnapshot({ title: assessment.title, summary: assessment.summary, findings: assessment.findings, errors: assessment.errors })));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(redactSnapshot(findings)));
  await writeSecureTextFile(outputDir, "analysis/summary.md", [formatAccessCheckText(access), "", ...assessments.map(formatAssessmentText)].join("\n\n"));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of VERACODE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.file}`, buildFrameworkReport(framework, findings, generatedAt));
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.map((error) => `${generatedAt.toISOString()} ${error}`).join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);
  return { outputDir, zipPath, fileCount: await countFilesRecursively(outputDir), findingCount: findings.length, errorCount: errors.length };
}

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    api_key_id: asString(value.api_key_id),
    api_key_secret: asString(value.api_key_secret),
    region: asString(value.region),
    base_url: asString(value.base_url),
    profile: asString(value.profile),
    credentials_file: asString(value.credentials_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeScanCoverageArgs(args: unknown): ScanCoverageArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    max_applications: asNumber(value.max_applications),
    max_scan_age_days: asNumber(value.max_scan_age_days),
    max_analyses: asNumber(value.max_analyses),
    critical_scan_interval_days: asNumber(value.critical_scan_interval_days),
    standard_scan_interval_days: asNumber(value.standard_scan_interval_days),
  };
}

function normalizePolicyArgs(args: unknown): PolicyArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_applications: asNumber(value.max_applications) };
}

function normalizeFindingsArgs(args: unknown): FindingsArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_applications: asNumber(value.max_applications), max_fp_rate_percent: asNumber(value.max_fp_rate_percent), max_flaw_density_per_kloc: asNumber(value.max_flaw_density_per_kloc) };
}

function normalizeScaArgs(args: unknown): ScaArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_applications: asNumber(value.max_applications), max_workspaces: asNumber(value.max_workspaces), sca_cvss_threshold: asNumber(value.sca_cvss_threshold) };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_admins: asNumber(value.max_admins), max_unrestricted_users: asNumber(value.max_unrestricted_users), inactive_days: asNumber(value.inactive_days), max_credential_age_days: asNumber(value.max_credential_age_days) };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeScanCoverageArgs(args), ...normalizeFindingsArgs(args), ...normalizeScaArgs(args), ...normalizeAccessControlArgs(args), output_dir: asString(value.output_dir) ?? asString(value.output) };
}

function createClient(args: AuthArgs): VeracodeApiClient {
  return new VeracodeApiClient(resolveVeracodeConfiguration(args));
}

function exportOptions(args: ExportArgs) {
  return {
    maxApplications: args.max_applications,
    maxScanAgeDays: args.max_scan_age_days,
    maxAnalyses: args.max_analyses,
    criticalScanIntervalDays: args.critical_scan_interval_days,
    standardScanIntervalDays: args.standard_scan_interval_days,
    maxFpRatePercent: args.max_fp_rate_percent,
    maxFlawDensityPerKloc: args.max_flaw_density_per_kloc,
    maxWorkspaces: args.max_workspaces,
    scaCvssThreshold: args.sca_cvss_threshold,
    maxAdmins: args.max_admins,
    maxUnrestrictedUsers: args.max_unrestricted_users,
    inactiveDays: args.inactive_days,
    maxCredentialAgeDays: args.max_credential_age_days,
  };
}

const authParams = {
  api_key_id: Type.Optional(Type.String({ description: "Veracode API key ID. Defaults to VERACODE_API_KEY_ID, then the credentials file profile." })),
  api_key_secret: Type.Optional(Type.String({ description: "Veracode API key secret (hex). Defaults to VERACODE_API_KEY_SECRET, then the credentials file profile." })),
  region: Type.Optional(Type.String({ description: "Veracode region: us (api.veracode.com), eu (api.veracode.eu), or us-fed (api.veracode.us). Defaults to VERACODE_REGION or us." })),
  base_url: Type.Optional(Type.String({ description: "Explicit REST API base URL override. Defaults to the region host." })),
  profile: Type.Optional(Type.String({ description: "Profile name inside ~/.veracode/credentials. Defaults to VERACODE_API_PROFILE or default." })),
  credentials_file: Type.Optional(Type.String({ description: "Path to the INI credentials file. Defaults to ~/.veracode/credentials." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const applicationParams = {
  max_applications: Type.Optional(Type.Number({ description: "Maximum applications to sample for per-application calls. Defaults to 100; the verdict flags partial sampling.", default: 100 })),
};

export function registerVeracodeTools(pi: any): void {
  pi.registerTool({
    name: "veracode_check_access",
    label: "Check Veracode audit access",
    description:
      "Validate HMAC-signed read-only Veracode access across applications, policies, identity (users, teams, roles, API credentials), SCA Agent, and Dynamic Analysis surfaces, and report which roles are missing.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkVeracodeAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "veracode_check_access", ...result });
      } catch (error) {
        return errorResult(`Veracode access check failed: ${toolErrorText(error)}`, { tool: "veracode_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_assess_scan_coverage",
    label: "Assess Veracode scan coverage",
    description:
      "Assess Veracode scan coverage (controls 1, 4, 10, 11, 13, 14, 19): recent scan coverage, policy scan frequency, sandbox usage, prescan module coverage (manual), Dynamic Analysis configuration, pipeline integration (manual), and scan completion.",
    parameters: Type.Object({
      ...authParams,
      ...applicationParams,
      max_scan_age_days: Type.Optional(Type.Number({ description: "Maximum days since the latest published static scan before an application is stale. Defaults to 90.", default: 90 })),
      max_analyses: Type.Optional(Type.Number({ description: "Maximum Dynamic Analysis configurations to inspect. Defaults to 25.", default: 25 })),
      critical_scan_interval_days: Type.Optional(Type.Number({ description: "Required scan interval in days for VERY_HIGH business criticality applications (control 4). Defaults to 7.", default: 7 })),
      standard_scan_interval_days: Type.Optional(Type.Number({ description: "Required scan interval in days for every other business criticality tier (control 4). Defaults to 31.", default: 31 })),
    }),
    prepareArguments: normalizeScanCoverageArgs,
    async execute(_toolCallId: string, args: ScanCoverageArgs) {
      try {
        const result = await assessVeracodeScanCoverage(createClient(args), {
          maxApplications: args.max_applications,
          maxScanAgeDays: args.max_scan_age_days,
          maxAnalyses: args.max_analyses,
          criticalScanIntervalDays: args.critical_scan_interval_days,
          standardScanIntervalDays: args.standard_scan_interval_days,
        });
        return textResult(formatAssessmentText(result), { tool: "veracode_assess_scan_coverage", title: result.title, summary: result.summary, findings: result.findings, errors: result.errors });
      } catch (error) {
        return errorResult(`Veracode scan coverage assessment failed: ${toolErrorText(error)}`, { tool: "veracode_assess_scan_coverage" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_assess_policy_compliance",
    label: "Assess Veracode policy compliance",
    description:
      "Assess Veracode policy compliance (controls 2, 15, 20): application policy_compliance_status, custom policy adoption with finding rules and grace periods, and collections posture (manual, with business-unit evidence).",
    parameters: Type.Object({ ...authParams, ...applicationParams }),
    prepareArguments: normalizePolicyArgs,
    async execute(_toolCallId: string, args: PolicyArgs) {
      try {
        const result = await assessVeracodePolicyCompliance(createClient(args), { maxApplications: args.max_applications });
        return textResult(formatAssessmentText(result), { tool: "veracode_assess_policy_compliance", title: result.title, summary: result.summary, findings: result.findings, errors: result.errors });
      } catch (error) {
        return errorResult(`Veracode policy compliance assessment failed: ${toolErrorText(error)}`, { tool: "veracode_assess_policy_compliance" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_assess_findings_hygiene",
    label: "Assess Veracode findings hygiene",
    description:
      "Assess Veracode findings hygiene (controls 3, 12, 16, 17): open flaw aging against severity SLAs, mitigation approval workflow, false positive rate from FP mitigation annotations, and Very High/High flaw density per KLOC from summary reports.",
    parameters: Type.Object({
      ...authParams,
      ...applicationParams,
      max_fp_rate_percent: Type.Optional(Type.Number({ description: "Maximum acceptable false positive rate per application (findings carrying an FP mitigation annotation). Defaults to 20.", default: 20 })),
      max_flaw_density_per_kloc: Type.Optional(Type.Number({ description: "Maximum Very High/High flaws per KLOC. Defaults to 1.", default: 1 })),
    }),
    prepareArguments: normalizeFindingsArgs,
    async execute(_toolCallId: string, args: FindingsArgs) {
      try {
        const result = await assessVeracodeFindingsHygiene(createClient(args), { maxApplications: args.max_applications, maxFpRatePercent: args.max_fp_rate_percent, maxFlawDensityPerKloc: args.max_flaw_density_per_kloc });
        return textResult(formatAssessmentText(result), { tool: "veracode_assess_findings_hygiene", title: result.title, summary: result.summary, findings: result.findings, errors: result.errors });
      } catch (error) {
        return errorResult(`Veracode findings hygiene assessment failed: ${toolErrorText(error)}`, { tool: "veracode_assess_findings_hygiene" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_assess_sca_posture",
    label: "Assess Veracode SCA posture",
    description:
      "Assess Veracode Software Composition Analysis posture (controls 5, 6, 18): open high-CVSS library vulnerabilities, HIGH risk license issues, and application SCA coverage through upload-and-scan SCA or linked agent projects.",
    parameters: Type.Object({
      ...authParams,
      ...applicationParams,
      max_workspaces: Type.Optional(Type.Number({ description: "Maximum SCA workspaces to inspect. Defaults to 25.", default: 25 })),
      sca_cvss_threshold: Type.Optional(Type.Number({ description: "Minimum severity score that flags an open SCA vulnerability issue. Defaults to 7.", default: 7 })),
    }),
    prepareArguments: normalizeScaArgs,
    async execute(_toolCallId: string, args: ScaArgs) {
      try {
        const result = await assessVeracodeScaPosture(createClient(args), { maxApplications: args.max_applications, maxWorkspaces: args.max_workspaces, scaCvssThreshold: args.sca_cvss_threshold });
        return textResult(formatAssessmentText(result), { tool: "veracode_assess_sca_posture", title: result.title, summary: result.summary, findings: result.findings, errors: result.errors });
      } catch (error) {
        return errorResult(`Veracode SCA posture assessment failed: ${toolErrorText(error)}`, { tool: "veracode_assess_sca_posture" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_assess_access_controls",
    label: "Assess Veracode access controls",
    description:
      "Assess Veracode identity hygiene (controls 7, 8, 9): team-scoped least privilege, Administrator and inactive user audit with SAML evidence, and API credential age and expiration.",
    parameters: Type.Object({
      ...authParams,
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Administrator accounts. Defaults to 5.", default: 5 })),
      max_unrestricted_users: Type.Optional(Type.Number({ description: "Maximum acceptable active users holding team-unrestricted roles. Defaults to 10.", default: 10 })),
      inactive_days: Type.Optional(Type.Number({ description: "Days without login before a human user is inactive. Defaults to 90.", default: 90 })),
      max_credential_age_days: Type.Optional(Type.Number({ description: "Maximum API credential age in days. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await assessVeracodeAccessControls(createClient(args), { maxAdmins: args.max_admins, maxUnrestrictedUsers: args.max_unrestricted_users, inactiveDays: args.inactive_days, maxCredentialAgeDays: args.max_credential_age_days });
        return textResult(formatAssessmentText(result), { tool: "veracode_assess_access_controls", title: result.title, summary: result.summary, findings: result.findings, errors: result.errors });
      } catch (error) {
        return errorResult(`Veracode access controls assessment failed: ${toolErrorText(error)}`, { tool: "veracode_assess_access_controls" });
      }
    },
  });

  pi.registerTool({
    name: "veracode_export_audit_bundle",
    label: "Export Veracode audit bundle",
    description:
      "Export a Veracode audit bundle with raw API snapshots (core_data/), normalized findings (analysis/), framework reports (compliance/), QUICK_REFERENCE.md, _errors.log on partial failure, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      ...applicationParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_scan_age_days: Type.Optional(Type.Number({ description: "Maximum days since the latest published static scan. Defaults to 90.", default: 90 })),
      max_analyses: Type.Optional(Type.Number({ description: "Maximum Dynamic Analysis configurations to inspect. Defaults to 25.", default: 25 })),
      critical_scan_interval_days: Type.Optional(Type.Number({ description: "Required scan interval in days for VERY_HIGH business criticality applications. Defaults to 7.", default: 7 })),
      standard_scan_interval_days: Type.Optional(Type.Number({ description: "Required scan interval in days for other business criticality tiers. Defaults to 31.", default: 31 })),
      max_fp_rate_percent: Type.Optional(Type.Number({ description: "Maximum false positive rate (findings carrying an FP mitigation annotation). Defaults to 20.", default: 20 })),
      max_flaw_density_per_kloc: Type.Optional(Type.Number({ description: "Maximum Very High/High flaws per KLOC. Defaults to 1.", default: 1 })),
      max_workspaces: Type.Optional(Type.Number({ description: "Maximum SCA workspaces to inspect. Defaults to 25.", default: 25 })),
      sca_cvss_threshold: Type.Optional(Type.Number({ description: "Minimum severity that flags an SCA vulnerability. Defaults to 7.", default: 7 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Administrator accounts. Defaults to 5.", default: 5 })),
      max_unrestricted_users: Type.Optional(Type.Number({ description: "Maximum active users with team-unrestricted roles. Defaults to 10.", default: 10 })),
      inactive_days: Type.Optional(Type.Number({ description: "Days without login before a user is inactive. Defaults to 90.", default: 90 })),
      max_credential_age_days: Type.Optional(Type.Number({ description: "Maximum API credential age in days. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveVeracodeConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportVeracodeAuditBundle(new VeracodeApiClient(config), config, outputRoot, exportOptions(args));
        return textResult(
          ["Veracode audit bundle exported.", `Output dir: ${result.outputDir}`, `Zip archive: ${result.zipPath}`, `Findings: ${result.findingCount}`, `Files: ${result.fileCount}`, `Collection warnings: ${result.errorCount}`].join("\n"),
          { tool: "veracode_export_audit_bundle", output_dir: result.outputDir, zip_path: result.zipPath, finding_count: result.findingCount, file_count: result.fileCount, error_count: result.errorCount },
        );
      } catch (error) {
        return errorResult(`Veracode audit bundle export failed: ${toolErrorText(error)}`, { tool: "veracode_export_audit_bundle" });
      }
    },
  });
}
