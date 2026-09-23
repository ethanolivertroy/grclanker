/**
 * Snowflake security inspector tools for grclanker.
 *
 * Read-only posture checks executed through the Snowflake SQL REST API
 * (SHOW commands and SNOWFLAKE.ACCOUNT_USAGE views) with key-pair JWT or
 * OAuth bearer authentication.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  randomUUID,
  type KeyObject,
} from "node:crypto";
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
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../flue/redact.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;
type SqlRow = Record<string, string | null>;

const DEFAULT_OUTPUT_DIR = "./export/snowflake";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_STATEMENT_TIMEOUT_SECONDS = 120;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_MS = 500;
const DEFAULT_MAX_PARTITIONS = 50;
const DEFAULT_ROW_LIMIT = 20_000;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_STALE_USER_DAYS = 90;
const DEFAULT_FAILED_LOGIN_THRESHOLD = 10;
const DEFAULT_MAX_ACCOUNTADMINS = 3;
const DEFAULT_MAX_AUTO_SUSPEND_SECONDS = 600;
const DEFAULT_MAX_SESSION_IDLE_MINUTES = 60;
const DEFAULT_MIN_PASSWORD_LENGTH = 14;
const DEFAULT_MIN_RETENTION_DAYS = 1;
const JWT_LIFETIME_SECONDS = 55 * 60;
const JWT_REFRESH_SKEW_SECONDS = 60;
const FULL_VISIBILITY_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN"]);
const SYSTEM_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "ORGADMIN", "PUBLIC", "GLOBALORGADMIN"]);
const PRIVILEGED_SYSTEM_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN"]);
const PERSON_USER_TYPES = new Set(["", "NULL", "PERSON"]);
const SERVICE_USER_TYPES = new Set(["SERVICE", "SERVICE_AGENT", "LEGACY_SERVICE"]);
const SNOWFLAKE_MANAGED_USER_TYPES = new Set(["SNOWFLAKE_SERVICE"]);
const SHARE_INVENTORY_ROLE = "ACCOUNTADMIN";
const SENSITIVE_OBJECT_DOMAINS = new Set([
  "TABLE",
  "VIEW",
  "SCHEMA",
  "DATABASE",
  "STAGE",
  "MATERIALIZED_VIEW",
  "MATERIALIZED VIEW",
  "EXTERNAL_TABLE",
  "EXTERNAL TABLE",
  "DYNAMIC_TABLE",
  "DYNAMIC TABLE",
  "STREAM",
]);
const ROUTINE_QUERY_TYPES = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "MERGE",
  "COPY",
  "UNLOAD",
  "CREATE_TABLE_AS_SELECT",
  "CALL",
];

export type SnowflakeTokenType = "KEYPAIR_JWT" | "OAUTH" | "PROGRAMMATIC_ACCESS_TOKEN";

export interface SnowflakeResolvedConfig {
  account: string;
  user: string;
  baseUrl: string;
  tokenType: SnowflakeTokenType;
  privateKeyPem?: string;
  privateKeyPassphrase?: string;
  token?: string;
  role?: string;
  warehouse?: string;
  database?: string;
  schema?: string;
  timeoutMs: number;
  statementTimeoutSeconds: number;
  pollIntervalMs: number;
  maxRetries: number;
  retryBaseMs: number;
  maxPartitions: number;
  rowLimit: number;
  connectionName?: string;
  sourceChain: string[];
}

export interface SnowflakeResultSet {
  statement: string;
  columns: string[];
  rows: SqlRow[];
  numRows: number;
  partitionCount: number;
  fetchedPartitions: number;
  truncated: boolean;
  statementHandle?: string;
}

/**
 * `not_requested` is the outcome of a statement that was never sent because
 * the bearer token could not be built (a private key that does not load, a
 * missing token): no endpoint was called, so no HTTP status, statement text,
 * or server error is recorded for it.
 */
export type SnowflakeStatementStatus = "ok" | "denied" | "error" | "timeout" | "not_requested";

export interface SnowflakeStatementOutcome {
  key: string;
  statement: string;
  status: SnowflakeStatementStatus;
  columns: string[];
  rows: SqlRow[];
  /** Null when the statement did not complete, so an unread inventory never renders as zero rows. */
  numRows: number | null;
  partitionCount: number | null;
  fetchedPartitions: number | null;
  truncated: boolean | null;
  rowLimit?: number;
  error?: string;
  /** The local failure code of a statement that was never sent (an OpenSSL code such as ERR_OSSL_UNSUPPORTED). */
  code?: string;
}

/** What a bundle consumer reads in place of the rows of a statement that did not complete. */
export interface SnowflakeNotCollectedMarker {
  collected: false;
  status: Exclude<SnowflakeStatementStatus, "ok">;
  /** The statement that was actually executed; null when it was never sent. */
  statement: string | null;
  error: string | null;
}

/**
 * The serialized form of a statement outcome: core_data files and the
 * statements echoed by the assess tools. A statement that did not complete
 * carries a not-collected marker in place of its rows and null columns, so a
 * denial can never be mistaken for an empty result set; a readable statement
 * with no rows keeps []. A statement that was never sent has `statement: null`
 * on both levels, so the bundle names only statements the run executed.
 */
export interface SnowflakeStatementSnapshot {
  key: string;
  statement: string | null;
  status: SnowflakeStatementStatus;
  columns: string[] | null;
  rows: SqlRow[] | SnowflakeNotCollectedMarker;
  numRows: number | null;
  partitionCount: number | null;
  fetchedPartitions: number | null;
  truncated: boolean | null;
  rowLimit?: number;
  error?: string;
  code?: string;
}

export interface SnowflakeAccessSurface {
  name: string;
  /** The statement that was executed; null when it was never sent. */
  statement: string | null;
  status: "readable" | "denied" | "error" | "timeout" | "not_requested";
  /** Rows seen on a readable surface; null when the statement did not complete. */
  rowCount: number | null;
  error?: string;
}

/**
 * Whether the run observed its own identity: `confirmed` when the session
 * context statement returned the user and role, `unconfirmed` when statements
 * were sent but the session context did not complete (the user and role are
 * the configured values), `not_authenticated` when no request was sent at all.
 */
export type SnowflakeAuthenticationStatus = "confirmed" | "unconfirmed" | "not_authenticated";

export interface SnowflakeAccessCheckResult {
  status: "healthy" | "limited";
  account: string;
  /** The session user, the configured user when unconfirmed, null when not authenticated. */
  user: string | null;
  role?: string;
  authentication: SnowflakeAuthenticationStatus;
  /** The one-sentence authentication statement also carried in notes. */
  authenticationNote: string;
  fullVisibility: boolean;
  surfaces: SnowflakeAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type SnowflakeFindingStatus = "pass" | "warn" | "fail" | "manual";
export type SnowflakeSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SnowflakeFinding {
  id: string;
  control: number;
  title: string;
  severity: SnowflakeSeverity;
  status: SnowflakeFindingStatus;
  summary: string;
  evidence: JsonRecord;
  mappings: string[];
}

export interface SnowflakeAssessmentResult {
  title: string;
  area: string;
  summary: JsonRecord;
  findings: SnowflakeFinding[];
  statements: SnowflakeStatementSnapshot[];
}

export interface SnowflakeAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface SnowflakeAssessmentOptions {
  lookbackDays?: number;
  staleUserDays?: number;
  failedLoginThreshold?: number;
  maxAccountAdmins?: number;
  maxAutoSuspendSeconds?: number;
  maxSessionIdleMinutes?: number;
  minPasswordLength?: number;
  minRetentionDays?: number;
}

interface SessionContext {
  account?: string;
  user?: string;
  role?: string;
  warehouse?: string;
  region?: string;
  version?: string;
  outcome: SnowflakeStatementOutcome;
}

interface ControlDefinition {
  control: number;
  id: string;
  title: string;
  severity: SnowflakeSeverity;
  mappings: string[];
}

type SnowflakeQueryClient = Pick<SnowflakeSqlClient, "getResolvedConfig" | "execute">;

type CommonArgs = {
  account?: string;
  user?: string;
  private_key_path?: string;
  private_key?: string;
  private_key_passphrase?: string;
  token?: string;
  token_type?: string;
  role?: string;
  warehouse?: string;
  database?: string;
  schema?: string;
  base_url?: string;
  connection?: string;
  timeout_seconds?: number;
  statement_timeout_seconds?: number;
  row_limit?: number;
};

type AssessArgs = CommonArgs & {
  lookback_days?: number;
  stale_user_days?: number;
  failed_login_threshold?: number;
  max_accountadmins?: number;
  max_auto_suspend_seconds?: number;
  max_session_idle_minutes?: number;
  min_password_length?: number;
  min_retention_days?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

function mapping(
  fedramp: string,
  cmmc: string,
  soc2: string,
  cis: string,
  pci: string,
  stig: string,
  irap: string,
  ismap: string,
): string[] {
  return [
    `FedRAMP ${fedramp}`,
    `CMMC ${cmmc}`,
    `SOC 2 ${soc2}`,
    `CIS ${cis}`,
    `PCI-DSS ${pci}`,
    `STIG ${stig}`,
    `IRAP ${irap}`,
    `ISMAP ${ismap}`,
  ];
}

export const SNOWFLAKE_CONTROLS: Record<number, ControlDefinition> = {
  1: { control: 1, id: "SNOWFLAKE-01", title: "Network policy configured and applied to account", severity: "critical", mappings: mapping("SC-7", "SC.L2-3.13.1", "CC6.6", "4.1", "1.3.1", "SRG-APP-000383", "ISM-1284", "10.2.1") },
  2: { control: 2, id: "SNOWFLAKE-02", title: "Network policy IP allowlist is restrictive", severity: "critical", mappings: mapping("SC-7(5)", "SC.L2-3.13.6", "CC6.6", "4.4", "1.3.2", "SRG-APP-000383", "ISM-1284", "10.2.2") },
  3: { control: 3, id: "SNOWFLAKE-03", title: "MFA enforced for all human users", severity: "critical", mappings: mapping("IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.5", "8.3.2", "SRG-APP-000149", "ISM-1401", "8.2.2") },
  4: { control: 4, id: "SNOWFLAKE-04", title: "Password policy meets complexity requirements", severity: "high", mappings: mapping("IA-5(1)", "IA.L2-3.5.7", "CC6.1", "5.1", "8.2.3", "SRG-APP-000164", "ISM-0421", "8.2.3") },
  5: { control: 5, id: "SNOWFLAKE-05", title: "Key pair authentication used for service accounts", severity: "high", mappings: mapping("IA-5(2)", "IA.L2-3.5.10", "CC6.1", "4.6", "8.6.1", "SRG-APP-000177", "ISM-1557", "8.2.4") },
  6: { control: 6, id: "SNOWFLAKE-06", title: "SSO/SAML integration configured", severity: "high", mappings: mapping("IA-2(12)", "IA.L2-3.5.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "8.2.1") },
  7: { control: 7, id: "SNOWFLAKE-07", title: "Role hierarchy follows least privilege", severity: "critical", mappings: mapping("AC-6(1)", "AC.L2-3.1.5", "CC6.3", "6.1", "7.1.1", "SRG-APP-000340", "ISM-1508", "8.1.2") },
  8: { control: 8, id: "SNOWFLAKE-08", title: "ACCOUNTADMIN role has minimal members", severity: "critical", mappings: mapping("AC-6(5)", "AC.L2-3.1.5", "CC6.3", "6.2", "7.1.2", "SRG-APP-000340", "ISM-1508", "8.1.3") },
  9: { control: 9, id: "SNOWFLAKE-09", title: "ACCOUNTADMIN not used for routine queries", severity: "high", mappings: mapping("AC-6(2)", "AC.L2-3.1.6", "CC6.3", "6.2", "7.1.2", "SRG-APP-000343", "ISM-1508", "8.1.3") },
  10: { control: 10, id: "SNOWFLAKE-10", title: "No direct object grants to users", severity: "medium", mappings: mapping("AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1") },
  11: { control: 11, id: "SNOWFLAKE-11", title: "Failed login monitoring", severity: "high", mappings: mapping("SI-4", "AU.L2-3.3.1", "CC7.2", "8.5", "10.2.4", "SRG-APP-000095", "ISM-0580", "12.1.1") },
  12: { control: 12, id: "SNOWFLAKE-12", title: "Stale users disabled", severity: "medium", mappings: mapping("AC-2(3)", "AC.L2-3.1.1", "CC6.2", "4.2", "8.1.4", "SRG-APP-000025", "ISM-1631", "8.1.4") },
  13: { control: 13, id: "SNOWFLAKE-13", title: "History and data retention configured", severity: "medium", mappings: mapping("AU-11", "AU.L2-3.3.1", "CC7.2", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "12.1.2") },
  14: { control: 14, id: "SNOWFLAKE-14", title: "Dynamic data masking policies applied", severity: "high", mappings: mapping("SC-28", "SC.L2-3.13.16", "CC6.1", "14.7", "3.4", "SRG-APP-000231", "ISM-0457", "10.1.2") },
  15: { control: 15, id: "SNOWFLAKE-15", title: "Row access policies applied", severity: "high", mappings: mapping("AC-3", "AC.L2-3.1.2", "CC6.1", "14.6", "7.1.1", "SRG-APP-000033", "ISM-0508", "8.1.1") },
  16: { control: 16, id: "SNOWFLAKE-16", title: "No PUBLIC grants on sensitive objects", severity: "high", mappings: mapping("AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1") },
  17: { control: 17, id: "SNOWFLAKE-17", title: "Storage integration required for stages", severity: "high", mappings: mapping("AC-3", "AC.L2-3.1.2", "CC6.1", "14.2", "3.4.1", "SRG-APP-000033", "ISM-1284", "8.1.1") },
  18: { control: 18, id: "SNOWFLAKE-18", title: "Stage unload restrictions", severity: "medium", mappings: mapping("AC-4", "AC.L2-3.1.3", "CC6.6", "14.2", "3.4.1", "SRG-APP-000039", "ISM-1284", "8.1.3") },
  19: { control: 19, id: "SNOWFLAKE-19", title: "Time Travel retention for databases", severity: "medium", mappings: mapping("CP-9", "RE.L2-3.8.9", "CC6.5", "3.1", "3.1", "SRG-APP-000504", "ISM-1515", "7.1.1") },
  20: { control: 20, id: "SNOWFLAKE-20", title: "Tri-Secret Secure", severity: "high", mappings: mapping("SC-12(1)", "SC.L2-3.13.10", "CC6.7", "14.4", "3.5.2", "SRG-APP-000514", "ISM-0487", "10.1.1") },
  21: { control: 21, id: "SNOWFLAKE-21", title: "Customer-managed keys configured", severity: "high", mappings: mapping("SC-12(1)", "SC.L2-3.13.10", "CC6.7", "14.4", "3.5.2", "SRG-APP-000514", "ISM-0487", "10.1.1") },
  22: { control: 22, id: "SNOWFLAKE-22", title: "Outbound shares reviewed", severity: "medium", mappings: mapping("AC-4", "AC.L2-3.1.3", "CC6.6", "13.4", "7.1.2", "SRG-APP-000039", "ISM-1284", "8.1.3") },
  23: { control: 23, id: "SNOWFLAKE-23", title: "External functions and API integrations reviewed", severity: "medium", mappings: mapping("CM-7", "CM.L2-3.4.7", "CC6.6", "13.5", "2.2.2", "SRG-APP-000141", "ISM-1284", "6.1.1") },
  24: { control: 24, id: "SNOWFLAKE-24", title: "Warehouse auto-suspend configured", severity: "low", mappings: mapping("AC-12", "AC.L2-3.1.10", "CC6.1", "5.6", "8.1.8", "SRG-APP-000295", "ISM-1164", "8.3.1") },
  25: { control: 25, id: "SNOWFLAKE-25", title: "Session policies configured", severity: "medium", mappings: mapping("AC-12", "AC.L2-3.1.11", "CC6.1", "5.6", "8.1.8", "SRG-APP-000295", "ISM-1164", "8.3.1") },
};

export const SNOWFLAKE_FRAMEWORKS = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"] as const;

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
  if (typeof value === "string") {
    if (/^(true|1|yes|y|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|n|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function upper(value: string | null | undefined): string {
  return (value ?? "").trim().toUpperCase();
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function parseSnowflakeTimestamp(value: string | null | undefined): Date | undefined {
  if (value === null || value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || /^null$/i.test(trimmed)) return undefined;
  const epochMatch = /^(-?\d+)(?:\.(\d+))?(?:\s+\d+)?$/.exec(trimmed);
  if (epochMatch) {
    const seconds = Number(epochMatch[1]);
    const fraction = epochMatch[2] ? Number(`0.${epochMatch[2]}`) : 0;
    if (Number.isFinite(seconds)) return new Date((seconds + fraction) * 1000);
  }
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : new Date(parsed);
}

function daysSince(date: Date, now: Date): number {
  return Math.floor((now.getTime() - date.getTime()) / 86_400_000);
}

function rowValue(row: SqlRow, ...names: string[]): string | null {
  for (const name of names) {
    if (name in row) return row[name];
    const lower = name.toLowerCase();
    if (lower in row) return row[lower];
    const upperName = name.toUpperCase();
    if (upperName in row) return row[upperName];
  }
  return null;
}

function rowBoolean(row: SqlRow, ...names: string[]): boolean | undefined {
  return asBoolean(rowValue(row, ...names));
}

function rowNumber(row: SqlRow, ...names: string[]): number | undefined {
  return asNumber(rowValue(row, ...names));
}

// ---------------------------------------------------------------------------------------------
// Error-text hygiene (rule 9). Every error string this module records passes through
// redactSecrets when the API error is constructed and again where the error is recorded. Two
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
//
// The pair rule (reviewer C, item G): the value under a credential-named key (a credential word
// anywhere in the name, compound and vendor environment names included: DB_PASSWORD,
// SPLUNK_PASSWORD, OKTA_CLIENT_TOKEN) is removed whatever its shape and length in the "key=value",
// "key: value", "key:value", and JSON forms, in prose and inside a JSON string alike; no plain-word
// shape exempts it. Three key classes refine that:
// - bearer ids: a key ending in "secret_id" (VAULT_SECRET_ID, role_secret_id, secretId) or naming a
//   session id (session_id, sid, jsessionid, phpsessid, sessid) carries a bearer credential, so its
//   value goes whatever the shape, a UUID included; this is decided before the setting test;
// - settings: a credential-named key whose final segment is url, uri, endpoint, method, algorithm,
//   audience, issuer, shape, type, mode, path, file, dir, limit, count, id, name, policy, or policies
//   (token_endpoint, auth_method, token_type, api_key_id, password_policies,
//   X-Snowflake-Authorization-Token-Type) names a setting, and
//   its value stays unless it is token-shaped or a configured secret;
// - webhooks: webhook*, *hook_url, and callback_url values lose their path and query and keep the
//   origin, because the token of a webhook URL sits in its path.
// Identifier keys without a credential word (OKTA_CLIENT_ID, SUMO_ACCESS_ID, SNOWFLAKE_ACCOUNT,
// X-Request-Id) are not pairs under this rule; their values are judged by shape only.
//
// The escape rule (reviewer C, item H): a literal JSON escape is a boundary before every carrier
// opener, so a header line that begins after one ("request headers:\u000aAuthorization: Splunk
// <key>", "proxy:\n\tpassword: hunter2") is scrubbed as a header line, never as the value of the
// word before the escape; see the note above ESCAPE_LETTER.
//
// The quote rule (reviewer C, items F and L): a quoted carrier value is read to the closing quote that
// matches its opener (the same quote character behind the same backslash run), so an escaped inner
// quote at any JSON depth is inner content and goes with the value; an unterminated quote and an
// unquoted value end at a ";" or "," before the next header token, whose name may carry any RFC 7230
// token character, so the following header keeps its name and its own treatment; see
// readQuotedContent and scrubCookieHeaders.
// ---------------------------------------------------------------------------------------------

const REDACTED = "[REDACTED]";
const MIN_CONFIGURED_SECRET_LENGTH = 4;
const LONG_TOKEN_MIN_LENGTH = 16;
const MIN_LETTERS_FOR_CASING = 6;

// A literal JSON escape ("\n", "\r", "\t", "\b", "\f", "\/", "\uXXXX": the two- or six-character
// sequence, not the control character) is a boundary before every carrier opener. A header name,
// scheme word, pair key, URL, or token that begins right after one is read on its own, never as the
// value of the word before the escape and never with the escape letter as its first character, and
// a value, URL, or query pair ends at the backslash that opens the next escape. A backslash joins a
// quote only as its escape, so a lone backslash is never read as an opening quote.
const ESCAPE_LETTER = String.raw`(?:[nrtbf/]|u[0-9A-Fa-f]{4})`;
/** The start of a carrier or token: outside a word (none of `wordCharacters` before it) or right after a literal escape, and not on an escape letter. */
function carrierStart(wordCharacters: string): string {
  return String.raw`(?:(?<![${wordCharacters}])|(?<=\\[nrtbf/]|\\u[0-9A-Fa-f]{4}))(?!(?<=\\)${ESCAPE_LETTER})`;
}
const CARRIER_START = carrierStart("A-Za-z0-9_");
/** A quote unit at any JSON depth: the quote character and the backslashes that escape it (`"`, `\"`, `\\\"`). */
const QUOTE_UNIT = String.raw`(?:\\*["'])`;

const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;
// A URL wherever it sits in the text, spelled with "://" or with the JSON-escaped slashes a serialized
// body carries ("https:\/\/host\/path"). In the escaped spelling "\/" is the URL's own path separator
// and goes with it; after "://" it is the boundary every literal escape is, and the URL ends there.
// The escaped form is unescaped for reading and written back escaped.
const ESCAPED_SLASH = "\\/";
const EMBEDDED_URL_PATTERN = new RegExp(String.raw`${CARRIER_START}[a-z][a-z0-9+.-]*:(?:\/\/[^\s"'<>()[\]{}\\]+|\\\/\\\/(?:\\\/|[^\s"'<>()[\]{}\\])+)`, "gi");
const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/@"'<>]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;
// A query pair's value ends at ";" too, so a pair inside a cookie header ("my&sid=<v>; Content-Type: ...") never consumes the cookie separator before the cookie reader runs.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=([^&#;\s"'<>)\]}\\]+)/g;
// The authorization scheme words, matched in any casing on both sides: a peer's error text may spell
// "bearer" or "BASIC", and an Authorization carrier may carry "sNoWfLaKe". In prose, a scheme word
// followed by a run of 8 or more token characters is a credential unless the run is prose: a mechanism
// word ("Basic authentication"), a dotted version ("OAuth 2.0"), an auth-param of a challenge
// (`Bearer realm="api"`), or one plain word or hyphenated lowercase compound after a spelling that is
// as often an English word or a product name as a scheme: a lowercase spelling ("token provided", "the
// bearer presented") or a product name in any casing ("Splunk Enterprise", "Snowflake statement
// failed", "HMAC signature"). After a header-cased or upper-cased authorization scheme ("Bearer",
// "BASIC", "SSWS") the run is the credential whatever its shape. A run with a digit, a symbol, or mixed
// casing inside a word is never prose. The token after a scheme word may be quoted (plain, single, or
// JSON-escaped); the quote is kept and the token removed.
const SCHEME_WORDS = "bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|splunk|snowflake|hmac|aws4-hmac-sha256|veracode-hmac-sha-256";
const SCHEME_VALUE_PATTERN = new RegExp(String.raw`${CARRIER_START}(${SCHEME_WORDS})\s+(${QUOTE_UNIT}?)([A-Za-z0-9._~+/=-]{8,})`, "gi");
const SCHEME_PROSE_WORDS = new Set(["authentication", "authorization", "authenticated", "authorized", "credential", "credentials", "challenge"]);
const PRODUCT_SCHEME_WORDS = new Set(["splunk", "snowflake", "hmac"]);
const SCHEME_WORD_PATTERN = new RegExp(`^(?:${SCHEME_WORDS})$`, "i");
const PLAIN_WORD_PATTERN = /^(?:[A-Z]?[a-z]+(?:-[a-z]+)*|[A-Z]+)$/;
const VERSION_PATTERN = /^\d+(?:\.\d+)+$/;
const AUTH_PARAM_PATTERN = /^(?:realm|error|error_description|error_uri|scope|charset|algorithm|qop|stale|domain|opaque|title|resource|client_id|authorization_uri|as_uri|ticket)=/i;
// A value may begin with backslashes that open no escape and no quote (a Windows path, a stray
// backslash); they go with the value rather than hiding it.
const STRAY_BACKSLASHES = String.raw`(?:\\+(?![nrtbf/u"']))?`;
const SCHEME_TOKEN_PATTERN = new RegExp(String.raw`^(\s+)(?!\[REDACTED\])(${QUOTE_UNIT}?)(${STRAY_BACKSLASHES}[^\s"'<>;,()[\]{}\\]+)`);
// A pair key or value may sit in plain, single, or JSON-escaped quotes at any depth; the value ends at a quote or the escaping backslash.
const ASSIGNMENT_KEY_PATTERN = new RegExp(String.raw`(${QUOTE_UNIT}?)${CARRIER_START}([A-Za-z][A-Za-z0-9_.-]{0,63})\b(${QUOTE_UNIT}?\s*([:=])\s*(${QUOTE_UNIT}?))`, "g");
const ASSIGNMENT_VALUE_PATTERN = new RegExp(String.raw`(?!\[REDACTED\])${STRAY_BACKSLASHES}[^\s"'<>;,&()[\]{}\\]+`, "y");
const URL_ORIGIN_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/[^\s/?#@"'<>]+(?=[/?#]|$)/i;
const SINGLE_RUN_PATTERN = /^[A-Za-z0-9+=_-]+$/;
const BEARER_ID_KEY_PATTERN = /(?:secret|session|token)[_.-]?id$/i;
const BEARER_ID_KEY_SEGMENTS = new Set(["sid", "jsessionid", "phpsessid", "sessid"]);
const BEARER_ID_KEY_TAILS = new Set(["secret_id", "session_id", "token_id"]);
// The final segments that name a setting rather than a credential, the AppRole settings an assessment
// reports included (secret_id_ttl, token_max_ttl, secret_id_num_uses, token_bound_cidrs, token_accessor).
const SETTING_KEY_SUFFIXES = new Set(["url", "uri", "endpoint", "method", "algorithm", "audience", "issuer", "shape", "type", "mode", "path", "file", "dir", "limit", "count", "id", "name", "policy", "policies", "ttl", "uses", "cidrs", "accessor"]);
// A webhook key is URL-valued: the bare word, or a *_url, *_uri, or *_endpoint key with a hook word
// before the suffix (webhook_url, slack_hook_uri, callback_url). webhook_count and webhook_secret are
// not URLs and follow the pair rule for their own final segment.
const WEBHOOK_KEYS = new Set(["webhook", "webhooks", "hook", "hooks"]);
const WEBHOOK_URL_WORDS = new Set(["webhook", "webhooks", "hook", "hooks", "callback"]);
const URL_KEY_SUFFIXES = new Set(["url", "uri", "endpoint"]);
// Every token shape starts at a carrier start, so a token glued to a literal escape ("\neyJ...",
// "\u000aAKIA...") is read after the escape and never with the escape letter as its first character.
const JWT_IN_TEXT_PATTERN = new RegExp(String.raw`${CARRIER_START}eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*`, "g");
const AWS_ACCESS_KEY_ID_PATTERN = new RegExp(String.raw`${CARRIER_START}(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b`, "g");
const AWS_SECRET_PATTERN = new RegExp(String.raw`${carrierStart("A-Za-z0-9/+=")}[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])`, "g");
const HEX_DIGEST_PATTERN = new RegExp(String.raw`${CARRIER_START}[A-Fa-f0-9]{32,}\b`, "g");
const VENDOR_TOKEN_SHAPES: readonly string[] = [
  String.raw`00[A-Za-z0-9_-]{40}\b`,
  String.raw`xox[abopers]-[A-Za-z0-9-]{10,}`,
  String.raw`gh[pousr]_[A-Za-z0-9]{20,}`,
  String.raw`github_pat_[A-Za-z0-9_]{20,}`,
  String.raw`glpat-[A-Za-z0-9_-]{20,}`,
  String.raw`AIza[0-9A-Za-z_-]{35}\b`,
  String.raw`ya29\.[0-9A-Za-z._-]{20,}`,
  String.raw`sk_(?:live|test)_[A-Za-z0-9]{10,}`,
  String.raw`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`,
];
const VENDOR_TOKEN_PATTERNS: readonly RegExp[] = VENDOR_TOKEN_SHAPES.map((shape) => new RegExp(`${CARRIER_START}${shape}`, "g"));
// "/", ".", ":", "@", "=", "\", and whitespace end a run, so URL path segments, dotted hostnames, the
// two sides of a pair, and the text on either side of a literal escape are judged on their own; "="
// joins a run only as trailing base64 padding that no value follows, so a key whose value was already
// replaced or is quoted ("httpEventCollectorToken=[REDACTED]", "SPLUNK_ACS_TOKEN='[REDACTED]'") keeps its name.
const LONG_TOKEN_RUN_PATTERN = new RegExp(String.raw`${carrierStart("A-Za-z0-9+_-")}[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&\["'\\]))?`, "g");
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_KEY_SHAPE_PATTERN = /^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i;
const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set(["sid", "sig", "pwd", "passwd", "pass", "sessid", "phpsessid", "auth", "nonce", "sas"]);
// "session" carries a credential only as the final segment (session=, user_session=); session_context and session_policy name settings.
const FINAL_CREDENTIAL_KEY_SEGMENTS = new Set(["session"]);
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
  const segments = keySegments(key);
  if (FINAL_CREDENTIAL_KEY_SEGMENTS.has(segments[segments.length - 1] ?? "")) return true;
  return segments.some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
}

type PairRule = "credential" | "setting" | "webhook" | "none";

/** A key ending in "secret_id", "token_id", or a session id name carries a bearer credential whatever the value's shape: a Vault secret id is a UUID, a token id is the token, a session id is the session. */
function isBearerIdKey(key: string, segments: readonly string[]): boolean {
  if (BEARER_ID_KEY_PATTERN.test(key)) return true;
  return BEARER_ID_KEY_TAILS.has(segments.slice(-2).join("_")) || BEARER_ID_KEY_SEGMENTS.has(segments[segments.length - 1] ?? "");
}

/** A URL-valued webhook key (webhook, webhook_url, slack_hook_uri, callback_url) whose path carries the token; see WEBHOOK_KEYS. */
function isWebhookKey(segments: readonly string[]): boolean {
  if (segments.length === 1) return WEBHOOK_KEYS.has(segments[0] ?? "");
  return URL_KEY_SUFFIXES.has(segments[segments.length - 1] ?? "") && segments.slice(0, -1).some((segment) => WEBHOOK_URL_WORDS.has(segment));
}

/** Whether a key's last word is a credential noun or the key is a bearer id: the test a bare path label must pass to be read as a pair. */
function namesCredential(key: string): boolean {
  const segments = keySegments(key);
  return CREDENTIAL_NOUN_PATTERN.test(segments[segments.length - 1] ?? "") || isBearerIdKey(key, segments);
}

/** Authorization, Proxy-Authorization, and WWW-Authenticate carry a scheme word in front of the credential; every other key's value goes whatever word it starts with. */
function isAuthorizationStyleKey(segments: readonly string[]): boolean {
  return segments[segments.length - 1] === "authorization" || segments.slice(-2).join("_") === "www_authenticate";
}

/** The final segment names a setting; a concatenated key id or key name (OKTA_CLIENT_PRIVATEKEYID) counts as one. */
function isSettingSegment(segment: string): boolean {
  return SETTING_KEY_SUFFIXES.has(segment) || /key(?:id|name)$/.test(segment);
}

/** How the value of a `key=value` or `key: value` pair is treated; see the pair rule above. */
function pairRuleFor(key: string): PairRule {
  const segments = keySegments(key);
  if (isBearerIdKey(key, segments)) return "credential";
  if (isWebhookKey(segments)) return "webhook";
  if (!isCredentialCarrierKey(key)) return "none";
  return isSettingSegment(segments[segments.length - 1] ?? "") ? "setting" : "credential";
}

/** A setting value is removed only when it is a single run with a real token shape (base64 symbols, scattered digits, or token casing); a UUID, a scheme word, a mode name, or a URL stays for the later shape rules to judge. */
function isTokenShapedValue(value: string): boolean {
  return SINGLE_RUN_PATTERN.test(value) && looksLikeToken(value);
}

/** A webhook value keeps its origin and loses its path and query; a value that is not a URL goes whole. */
function webhookReplacement(value: string): string {
  const origin = URL_ORIGIN_PATTERN.exec(value)?.[0];
  return origin === undefined ? REDACTED : `${origin}/${REDACTED}`;
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

/** True when the run at `index` is a segment of a bare path: preceded by a path separator ("/" or a lone "\"; the escape "\/" is a boundary, not a separator) and not inside a URL that carries a scheme. */
function isBarePathSegment(text: string, index: number, urlSpans: ReadonlyArray<readonly [number, number]>): boolean {
  const before = text[index - 1];
  if (before === "/" ? text[index - 2] === "\\" : before !== "\\") return false;
  return !urlSpans.some(([start, end]) => index >= start && index < end);
}

/** The long-token rule over the text; a scheme word that happens to carry digits ("aws4-hmac-sha256") names a mechanism and stays. */
function scrubBareTokens(text: string): string {
  const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
  return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string, offset: number) =>
    looksLikeToken(run) && !SCHEME_WORD_PATTERN.test(run) && !isBarePathSegment(text, offset, urlSpans) ? REDACTED : run,
  );
}

function scrubConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
  const values = secrets.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
  if (values.length === 0) return text;
  return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTED);
}

/** A URL keeps its scheme, host, and path and loses its userinfo, query, and fragment; a slash-escaped URL is written back with its slashes escaped. */
function scrubEmbeddedUrl(match: string): string {
  const escaped = match.includes(ESCAPED_SLASH);
  const spelled = escaped ? match.split(ESCAPED_SLASH).join("/") : match;
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(spelled)?.[0] ?? "";
  const url = spelled.slice(0, spelled.length - trailing.length);
  const parts = URL_PARTS_PATTERN.exec(url);
  if (!parts) return match;
  const [, scheme, hostAndPath, query, fragment] = parts;
  const kept = `${scheme}${hostAndPath}`;
  return `${escaped ? kept.split("/").join(ESCAPED_SLASH) : kept}${query ? `?${REDACTED}` : ""}${fragment ? `#${REDACTED}` : ""}${trailing}`;
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialCarrierKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

/** The word after a scheme word in prose is prose, not a credential, when it is a mechanism word, a dotted version, an auth-param, or one plain word after a lowercase spelling or a product name. */
function isSchemeProse(scheme: string, word: string): boolean {
  if (SCHEME_PROSE_WORDS.has(word.toLowerCase())) return true;
  if (PLAIN_WORD_PATTERN.test(word) && (scheme === scheme.toLowerCase() || PRODUCT_SCHEME_WORDS.has(scheme.toLowerCase()))) return true;
  return VERSION_PATTERN.test(word) || AUTH_PARAM_PATTERN.test(word);
}

function scrubSchemeValue(match: string, scheme: string, quote: string, value: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(value)?.[0] ?? "";
  const word = value.slice(0, value.length - trailing.length);
  return isSchemeProse(scheme, word) ? match : `${scheme} ${quote}${REDACTED}${trailing}`;
}

// The RFC 7230 token characters, so a following header whose name carries a "." or other token
// punctuation (X.Api.Key) is recognised as the next header rather than swallowed (item L).
const NEXT_HEADER_NAME = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
// A ";" or "," ends a carrier value when the text after it (past optional spaces) opens the next
// header "Name:" token or a JSON fragment.
const NEXT_HEADER_AFTER_SEPARATOR = new RegExp(String.raw`^[ \t]*(?:[{[]|${QUOTE_UNIT}?${NEXT_HEADER_NAME}${QUOTE_UNIT}?[ \t]*:)`);
// A quoted value that opens with a scheme word keeps the scheme and its gap and loses the rest, except
// that a scheme followed by a pair list (an HMAC signature header: "id=...,ts=...,nonce=...,sig=...")
// is read pair by pair so each key's own rule applies and a timestamp stays legible.
const LEADING_SCHEME_IN_VALUE = /^([A-Za-z][A-Za-z0-9-]*)(\s+)(\S[\s\S]*)$/;
const PAIR_LIST_START = /^[A-Za-z][A-Za-z0-9_.-]*=/;
// After a bare path label the text is prose ("/api/v1/api-tokens: request failed with 403",
// "/oauth/token-request: invalid_client") and stays, unless the segment itself names a credential
// (its last word is password, key, secret, token, or passphrase, or it is a bearer id) and a single
// token ends the line there ("kv/password: <value>"), which is the value.
const SOLE_VALUE_PATTERN = new RegExp(String.raw`^(?!\[REDACTED\])[^\s"'<>;,&()[\]{}\\]+[ \t]*(?:$|[\r\n]|\\[nr]|\\u000[adAD])`);
const CREDENTIAL_NOUN_PATTERN = /(?:password|passwd|passphrase|pwd|secret|token|key)$/;
// A credential-named flag whose value is the next argument (`psql --password <value> -h db`), as a
// spawned CLI echoes its command line; `--name=value` is a pair and is read by the pair rule.
const FLAG_VALUE_PATTERN = new RegExp(String.raw`(?<![A-Za-z0-9_-])--([A-Za-z][A-Za-z0-9_.-]{0,63})([ \t]+)(?!\[REDACTED\])(?!-)([^\s"'<>;,&()[\]{}\\]+)`, "g");

/** The number of backslashes in the run ending immediately before `index`. */
function backslashRunBefore(text: string, index: number): number {
  let count = 0;
  while (index - count - 1 >= 0 && text[index - count - 1] === "\\") count += 1;
  return count;
}

/** True when a ";" or "," at `index` precedes the next header "Name:" token or a JSON fragment. */
function endsAtNextHeader(text: string, index: number): boolean {
  const ch = text[index];
  if (ch !== ";" && ch !== ",") return false;
  return NEXT_HEADER_AFTER_SEPARATOR.test(text.slice(index + 1));
}

interface QuotedRead {
  /** The value content between the opener and the closer (or the unterminated stop), to be redacted. */
  content: string;
  /** The index just past the value: past the closing quote unit when terminated, at the stop otherwise. */
  end: number;
  /** True when a matching closer was found; false when a raw newline, an outer string, or the next header token ended the value. */
  terminated: boolean;
}

/** A quote unit opening a value at `start`: its leading backslash run and quote character, or undefined when `start` is not on a quote unit. */
function openingQuoteUnit(text: string, start: number): { backslashes: number; quoteChar: string; contentStart: number } | undefined {
  let backslashes = 0;
  while (text[start + backslashes] === "\\") backslashes += 1;
  const quoteChar = text[start + backslashes];
  if (quoteChar !== '"' && quoteChar !== "'") return undefined;
  return { backslashes, quoteChar, contentStart: start + backslashes + 1 };
}

/**
 * Reads the content of a quoted value that opened with `openBackslashes` backslashes and quote char
 * `quoteChar`. A quote of the same char preceded by the same backslash run closes it, so a deeper
 * quote (more backslashes: an escaped inner quote at any JSON depth) is inner content; a raw newline,
 * a shallower quote (an outer string closing), or a ";"/"," before the next header token ends it
 * unterminated so the following header keeps its name.
 */
function readQuotedContent(text: string, contentStart: number, openBackslashes: number, quoteChar: string): QuotedRead {
  let i = contentStart;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\n" || ch === "\r") return { content: text.slice(contentStart, i), end: i, terminated: false };
    if (ch === quoteChar) {
      const run = backslashRunBefore(text, i);
      if (run === openBackslashes) return { content: text.slice(contentStart, i - run), end: i + 1, terminated: true };
      if (run < openBackslashes) return { content: text.slice(contentStart, i - run), end: i - run, terminated: false };
    }
    if (endsAtNextHeader(text, i)) return { content: text.slice(contentStart, i), end: i, terminated: false };
    i += 1;
  }
  return { content: text.slice(contentStart, i), end: i, terminated: false };
}

// A cookie header value that is not wholly quoted runs across ";"/"," separated pairs; these are the
// characters that make up a bare pair name or value (everything but the delimiters handled below). An
// apostrophe is an RFC 6265 token character ("my'pref=", "sid=O'..."), so it is content, not a quote.
const COOKIE_PLAIN_CHAR = /[^\r\n\t <>"\\;,=]/;
const SPACE_BEFORE_JSON = /^[ \t]*[{[]/;

/**
 * Reads an unquoted cookie header value from `start`: it runs across ";"/"," separated pairs whose
 * values may themselves be quoted, and ends before a ";"/"," or a space that precedes the next header
 * token or a JSON fragment, at a raw newline or tab, at a literal escape, or at a bare quote. A pair
 * value opened with a quote is read quote-aware, and an unterminated one ends the whole value there so
 * the following header keeps its name. Returns the index just past the value.
 */
function readUnquotedCookieValue(text: string, start: number): number {
  if (!COOKIE_PLAIN_CHAR.test(text[start] ?? "")) return start;
  let i = start + 1;
  while (i < text.length) {
    const ch = text[i];
    if (COOKIE_PLAIN_CHAR.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === "=") {
      i += 1;
      while (text[i] === " " || text[i] === "\t") i += 1;
      const opener = openingQuoteUnit(text, i);
      if (opener) {
        const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
        if (!read.terminated) return read.end;
        i = read.end;
      }
      continue;
    }
    if (ch === ";" || ch === ",") {
      if (endsAtNextHeader(text, i)) break;
      i += 1;
      continue;
    }
    if (ch === " " || ch === "\t") {
      if (SPACE_BEFORE_JSON.test(text.slice(i + 1))) break;
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

// A cookie or session header at a carrier start, up to the separator; the value is read procedurally.
const COOKIE_HEADER_START = new RegExp(String.raw`${CARRIER_START}(set-cookie|cookies?)(${QUOTE_UNIT}?\s*[:=]\s*)`, "gi");

/**
 * Removes the value of every Cookie and Set-Cookie header. A wholly quoted value is read to its
 * matching closer (an escaped inner quote at any JSON depth is inner content); an unquoted value runs
 * across its pairs and ends before the next header token, so the following header keeps its name. The
 * marker `[REDACTED]` is left untouched so the pass is idempotent.
 */
function scrubCookieHeaders(text: string): string {
  COOKIE_HEADER_START.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = COOKIE_HEADER_START.exec(text)) !== null) {
    const [whole, header, separator] = match;
    if (whole.length === 0) {
      COOKIE_HEADER_START.lastIndex += 1;
      continue;
    }
    const valueStart = match.index + whole.length;
    const opener = openingQuoteUnit(text, valueStart);
    let prefix: string;
    let redacted: string;
    let end: number;
    if (opener) {
      const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
      if (read.content.length === 0 || read.content === REDACTED) {
        COOKIE_HEADER_START.lastIndex = valueStart;
        continue;
      }
      const openerText = text.slice(valueStart, opener.contentStart);
      const closerText = read.terminated ? text.slice(read.end - (opener.backslashes + 1), read.end) : "";
      prefix = openerText;
      redacted = `${REDACTED}${closerText}`;
      end = read.end;
    } else {
      const valueEnd = readUnquotedCookieValue(text, valueStart);
      if (valueEnd === valueStart) {
        COOKIE_HEADER_START.lastIndex = valueStart;
        continue;
      }
      let contentEnd = valueEnd;
      while (contentEnd > valueStart && (text[contentEnd - 1] === " " || text[contentEnd - 1] === "\t")) contentEnd -= 1;
      if (text.slice(valueStart, contentEnd) === REDACTED) {
        COOKIE_HEADER_START.lastIndex = valueStart;
        continue;
      }
      prefix = "";
      redacted = `${REDACTED}${text.slice(contentEnd, valueEnd)}`;
      end = valueEnd;
    }
    out += `${text.slice(last, match.index)}${header}${separator}${prefix}${redacted}`;
    last = end;
    COOKIE_HEADER_START.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Replaces the value of every credential-named pair: `key=value`, `key: value`, `"key": "value"`,
 * and `Header-Name: value`. The value goes whatever its shape (an `=` pair, a quoted value, a header
 * value, a plain word in prose, or a word that happens to be a scheme word: `sslPassword=splunk
 * rejected` and `db_password: token` lose their value). Only an Authorization-style key
 * (Authorization, Proxy-Authorization, WWW-Authenticate) carries a scheme word in front of its
 * credential, where the scheme is kept and the token removed (`Authorization: Bearer <token>`). A
 * setting key keeps a value that is not token-shaped, a bearer-id key loses a UUID, and a webhook
 * key keeps only the origin. The last segment of a bare path used as a label
 * ("/api/authn/v2/api_credentials: <detail>") is a request target, not a pair key, so the prose
 * after it is kept, unless a single token ends the line there ("kv/password: <value>"); inside a URL
 * with a scheme the pair rule still applies.
 */
function replaceCredentialAssignments(text: string): string {
  const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
  ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator, separatorChar, valueOpenQuote] = match;
    if (whole.length === 0) {
      ASSIGNMENT_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    const rule = pairRuleFor(key);
    if (rule === "none") continue;
    const valueStart = match.index + whole.length;
    const barePathLabel = openingQuote === "" && separatorChar === ":" && isBarePathSegment(text, match.index, urlSpans);
    if (barePathLabel && (!namesCredential(key) || (valueOpenQuote === "" && !SOLE_VALUE_PATTERN.test(text.slice(valueStart))))) continue;
    const schemeCarrier = isAuthorizationStyleKey(keySegments(key));
    let kept = "";
    let consumed: number;
    let replacement = REDACTED;
    if (valueOpenQuote !== "") {
      // The value is quoted; read to its matching closer so an escaped inner quote at any JSON depth stays inner content and the value never ends early.
      const { content } = readQuotedContent(text, valueStart, valueOpenQuote.length - 1, valueOpenQuote[valueOpenQuote.length - 1] ?? '"');
      if (content.length === 0 || content === REDACTED) {
        ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
        continue;
      }
      consumed = content.length;
      const lead = LEADING_SCHEME_IN_VALUE.exec(content);
      if (schemeCarrier && lead && SCHEME_WORD_PATTERN.test(lead[1])) {
        if (lead[3].startsWith(REDACTED)) {
          ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
          continue;
        }
        kept = `${lead[1]}${lead[2]}`;
        const firstPair = PAIR_LIST_START.test(lead[3]) ? SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + lead[1].length)) : null;
        if (firstPair) {
          kept = `${lead[1]}${firstPair[1]}${firstPair[2]}`;
          consumed = lead[1].length + firstPair[0].length;
        }
      } else if (rule === "setting") {
        if (!isTokenShapedValue(content)) {
          ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
          continue;
        }
      } else if (rule === "webhook") {
        replacement = webhookReplacement(content);
      }
    } else {
      ASSIGNMENT_VALUE_PATTERN.lastIndex = valueStart;
      const value = ASSIGNMENT_VALUE_PATTERN.exec(text)?.[0];
      if (value === undefined) continue;
      consumed = value.length;
      if (schemeCarrier && SCHEME_WORD_PATTERN.test(value)) {
        const token = SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + value.length));
        if (!token) continue;
        // `Snowflake Token="<jwt>"`: the run after the scheme opens a quoted pair, which the pair rule reads as the next match.
        if (PAIR_LIST_START.test(token[3]) && openingQuoteUnit(text, valueStart + value.length + token[0].length)) {
          ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart + value.length;
          continue;
        }
        kept = `${value}${token[1]}${token[2]}`;
        consumed += token[0].length;
      } else if (rule === "setting") {
        if (!isTokenShapedValue(value)) continue;
      } else if (rule === "webhook") {
        replacement = webhookReplacement(value);
        if (text.startsWith(REDACTED, valueStart + consumed)) consumed += REDACTED.length;
      }
    }
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${kept}${replacement}`;
    last = valueStart + consumed;
    ASSIGNMENT_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/** Replaces the value argument of every credential-named flag (`--password <value>`); a setting flag (`--token-type bearer`) keeps its value. */
function replaceFlagValues(text: string): string {
  return text.replace(FLAG_VALUE_PATTERN, (match: string, name: string, gap: string) => (pairRuleFor(name) === "credential" ? `--${name}${gap}${REDACTED}` : match));
}

/**
 * The carrier and shape rules shared by the error and data passes: PEM blocks, configured secrets,
 * URLs, query pairs, cookie headers, credential pairs and flags, scheme words in prose, JWTs, AWS
 * keys, and vendor-prefixed tokens. `longTokens` adds the generic long-token and hex-digest rules,
 * which the error pass runs and the data pass leaves off so identifiers survive in evidence.
 */
function scrubText(text: string, secrets: ReadonlyArray<string | undefined>, longTokens: boolean): string {
  let scrubbed = text.replace(PEM_BLOCK_PATTERN, REDACTED).replace(PEM_OPEN_PATTERN, REDACTED);
  scrubbed = scrubConfiguredSecrets(scrubbed, secrets)
    .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
    .replace(QUERY_PAIR_PATTERN, scrubQueryPair);
  scrubbed = scrubCookieHeaders(scrubbed);
  scrubbed = replaceFlagValues(replaceCredentialAssignments(scrubbed))
    .replace(SCHEME_VALUE_PATTERN, scrubSchemeValue)
    .replace(JWT_IN_TEXT_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
    .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run));
  if (longTokens) scrubbed = scrubbed.replace(HEX_DIGEST_PATTERN, (run) => (looksLikeHexDigest(run) ? REDACTED : run));
  for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
  return longTokens ? scrubBareTokens(scrubbed) : scrubbed;
}

/**
 * The single redaction pass for error text. Idempotent: text that has been scrubbed once comes
 * back unchanged because `[REDACTED]` matches none of the patterns.
 */
export function redactSecrets(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
  return scrubText(text, secrets, true);
}

/**
 * The redaction pass for data-side text: every string a snapshot walker visits. A credential carrier
 * (`Authorization: Bearer <token>`, `password=<value>`, a webhook URL) or an unambiguous credential
 * shape (a vendor-prefixed token, a JWT, a PEM block, an AWS key) inside a free-text field is
 * removed on the data side too, while the generic long-token rule stays off so a name or an id that
 * merely looks random survives. Idempotent like the error pass.
 */
export function scrubDataText(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
  return scrubText(text, secrets, false);
}

/** Describes a response body that is not JSON without copying any of it. */
function describeNonJsonBody(response: Response, rawText: string): string {
  const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() || "unknown content type";
  return `non-JSON body (${contentType}, ${Buffer.byteLength(rawText)} bytes)`;
}

/** A TOML line the simple reader cannot accept; it records the line number only, never the line. */
export class SnowflakeTomlSyntaxError extends Error {
  readonly line: number;

  constructor(line: number) {
    super(`Invalid TOML at line ${line}`);
    this.name = "SnowflakeTomlSyntaxError";
    this.line = line;
  }
}

/**
 * Reads the subset of TOML that Snowflake connection files use: comments,
 * section headers, and single-line key = value pairs. A line that is none of
 * those, or a quoted value that does not close on its own line, is a syntax
 * error reported by line number, so a stray or continued credential line
 * never reaches a value or an error message.
 */
export function parseSimpleToml(text: string): Record<string, JsonRecord> {
  const sections: Record<string, JsonRecord> = { "": {} };
  let current = "";
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = lines[index].trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const sectionMatch = /^\[\s*([^\]]+?)\s*\](?:\s+#.*)?$/.exec(line);
    if (sectionMatch) {
      current = sectionMatch[1].replace(/"/g, "").trim();
      sections[current] = sections[current] ?? {};
      continue;
    }
    const keyMatch = /^("[^"]+"|'[^']+'|[A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
    if (!keyMatch) throw new SnowflakeTomlSyntaxError(lineNumber);
    const key = keyMatch[1].replace(/^["']|["']$/g, "");
    sections[current][key] = parseTomlValue(keyMatch[2].trim(), lineNumber);
  }
  return sections;
}

function findClosingQuote(raw: string, quote: string, start: number): number {
  for (let index = start; index < raw.length; index += 1) {
    if (raw[index] === "\\" && quote === "\"") {
      index += 1;
      continue;
    }
    if (raw[index] === quote) return index;
  }
  return -1;
}

function parseTomlValue(raw: string, lineNumber: number): unknown {
  if (raw.startsWith("\"\"\"") || raw.startsWith("'''")) {
    const delimiter = raw.slice(0, 3);
    const end = raw.indexOf(delimiter, 3);
    if (end < 0) throw new SnowflakeTomlSyntaxError(lineNumber);
    return raw.slice(3, end);
  }
  if (raw.startsWith("\"")) {
    const end = findClosingQuote(raw, "\"", 1);
    if (end < 0) throw new SnowflakeTomlSyntaxError(lineNumber);
    return raw.slice(1, end).replace(/\\n/g, "\n").replace(/\\"/g, "\"").replace(/\\\\/g, "\\");
  }
  if (raw.startsWith("'")) {
    const end = findClosingQuote(raw, "'", 1);
    if (end < 0) throw new SnowflakeTomlSyntaxError(lineNumber);
    return raw.slice(1, end);
  }
  const withoutComment = raw.replace(/\s+#.*$/, "").trim();
  if (/^(true|false)$/i.test(withoutComment)) return withoutComment.toLowerCase() === "true";
  const numeric = Number(withoutComment);
  if (withoutComment.length > 0 && Number.isFinite(numeric)) return numeric;
  return withoutComment;
}

const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
const CRYPTO_ERROR_CODE_PATTERN = /^ERR_[A-Z0-9_]{1,60}$/;

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
    throw new Error(`Unable to read Snowflake config file ${pathname} (${code ?? "UNREADABLE"})`);
  }
}

/** Parse step: catches every thrown value and reports path, line, and a fixed code; nothing from the line itself. */
function readSnowflakeTomlFile(pathname: string): Record<string, JsonRecord> | undefined {
  const text = readConfigFileText(pathname);
  if (text === undefined) return undefined;
  try {
    return parseSimpleToml(text);
  } catch (error) {
    const where = error instanceof SnowflakeTomlSyntaxError ? ` at line ${error.line}` : "";
    throw new Error(`Unable to parse Snowflake config file: invalid TOML in ${pathname}${where} (INVALID_TOML)`);
  }
}

/** The private key file is credential-bearing, so a read failure names the path and errno code only. */
function readPrivateKeyFile(pathname: string): string {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const code = thrownCode(error, FS_ERROR_CODE_PATTERN);
    if (code === "ENOENT") throw new Error(`Snowflake private key file was not found: ${pathname} (ENOENT)`);
    throw new Error(`Unable to read Snowflake private key file ${pathname} (${code ?? "UNREADABLE"})`);
  }
}

export interface SnowflakeTomlConnection {
  name: string;
  values: JsonRecord;
  source: string;
}

export function loadSnowflakeTomlConnection(
  env: NodeJS.ProcessEnv = process.env,
  connectionName?: string,
  homeDirectory: string = homedir(),
): SnowflakeTomlConnection | undefined {
  const configDir = asString(env.SNOWFLAKE_HOME) ?? join(homeDirectory, ".snowflake");
  const configPath = join(configDir, "config.toml");
  const connectionsPath = join(configDir, "connections.toml");
  const configSections = readSnowflakeTomlFile(configPath);
  const name = connectionName
    ?? asString(env.SNOWFLAKE_CONNECTION_NAME)
    ?? asString(env.SNOWFLAKE_DEFAULT_CONNECTION_NAME)
    ?? asString(configSections?.[""]?.default_connection_name)
    ?? "default";

  const sections = readSnowflakeTomlFile(connectionsPath);
  if (sections) {
    const values = sections[name] ?? sections[`connections.${name}`];
    if (values) return { name, values, source: connectionsPath };
  }
  if (configSections) {
    const values = configSections[`connections.${name}`];
    if (values) return { name, values, source: configPath };
  }
  return undefined;
}

function expandHome(pathname: string, homeDirectory: string): string {
  if (pathname === "~") return homeDirectory;
  if (pathname.startsWith("~/")) return join(homeDirectory, pathname.slice(2));
  return pathname;
}

export function normalizeAccountHost(account: string): string {
  return account.trim().replace(/_/g, "-").toLowerCase();
}

export function normalizeJwtAccountIdentifier(account: string): string {
  let identifier = account.trim();
  if (identifier.toLowerCase().includes(".global")) {
    const hyphenIndex = identifier.indexOf("-");
    if (hyphenIndex > 0) identifier = identifier.slice(0, hyphenIndex);
  } else {
    const dotIndex = identifier.indexOf(".");
    if (dotIndex > 0) identifier = identifier.slice(0, dotIndex);
  }
  return identifier.toUpperCase();
}

function parseTokenType(value: string | undefined): SnowflakeTokenType | undefined {
  const normalized = upper(value);
  if (normalized === "KEYPAIR_JWT" || normalized === "SNOWFLAKE_JWT" || normalized === "JWT") return "KEYPAIR_JWT";
  if (normalized === "OAUTH") return "OAUTH";
  if (normalized === "PROGRAMMATIC_ACCESS_TOKEN" || normalized === "PAT") return "PROGRAMMATIC_ACCESS_TOKEN";
  return undefined;
}

export function resolveSnowflakeConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDirectory?: string } = {},
): SnowflakeResolvedConfig {
  const homeDirectory = options.homeDirectory ?? homedir();
  const sourceChain: string[] = [];
  const explicitConnection = asString(input.connection);
  const toml = loadSnowflakeTomlConnection(env, explicitConnection, homeDirectory);
  const tomlValues = toml?.values ?? {};
  if (toml) sourceChain.push(`config-file:${toml.source}#${toml.name}`);

  const pick = (
    label: string,
    argValue: unknown,
    envKeys: string[],
    tomlKeys: string[],
  ): string | undefined => {
    const fromArgs = asString(argValue);
    if (fromArgs) {
      sourceChain.push(`arguments-${label}`);
      return fromArgs;
    }
    for (const key of envKeys) {
      const fromEnv = asString(env[key]);
      if (fromEnv) {
        sourceChain.push(`environment-${label}`);
        return fromEnv;
      }
    }
    for (const key of tomlKeys) {
      const fromToml = asString(tomlValues[key]);
      if (fromToml) {
        sourceChain.push(`config-file-${label}`);
        return fromToml;
      }
    }
    return undefined;
  };

  const account = pick("account", input.account, ["SNOWFLAKE_ACCOUNT"], ["account", "account_name", "accountname"]);
  if (!account) {
    throw new Error("SNOWFLAKE_ACCOUNT, an account argument, or a connections.toml account entry is required.");
  }
  const user = pick("user", input.user, ["SNOWFLAKE_USER"], ["user", "username"]);
  if (!user) {
    throw new Error("SNOWFLAKE_USER, a user argument, or a connections.toml user entry is required.");
  }

  const privateKeyPath = pick(
    "private-key-path",
    input.private_key_path,
    ["SNOWFLAKE_PRIVATE_KEY_PATH", "SNOWFLAKE_PRIVATE_KEY_FILE"],
    ["private_key_file", "private_key_path"],
  );
  const inlinePrivateKey = pick(
    "private-key",
    input.private_key,
    ["SNOWFLAKE_PRIVATE_KEY", "SNOWFLAKE_PRIVATE_KEY_RAW"],
    ["private_key_raw", "private_key"],
  );
  const privateKeyPassphrase = pick(
    "private-key-passphrase",
    input.private_key_passphrase,
    ["SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "PRIVATE_KEY_PASSPHRASE"],
    ["private_key_passphrase", "private_key_file_pwd"],
  );
  const token = pick("token", input.token, ["SNOWFLAKE_TOKEN", "SNOWFLAKE_OAUTH_TOKEN", "SNOWFLAKE_ACCESS_TOKEN"], ["token", "oauth_token"]);
  const authenticator = pick("authenticator", input.token_type, ["SNOWFLAKE_TOKEN_TYPE", "SNOWFLAKE_AUTHENTICATOR"], ["authenticator", "token_type"]);

  let privateKeyPem: string | undefined;
  if (inlinePrivateKey) {
    privateKeyPem = inlinePrivateKey.replace(/\\n/g, "\n");
  } else if (privateKeyPath) {
    privateKeyPem = readPrivateKeyFile(expandHome(privateKeyPath, homeDirectory));
  }

  const explicitTokenType = parseTokenType(authenticator);
  let tokenType: SnowflakeTokenType;
  if (privateKeyPem && (!explicitTokenType || explicitTokenType === "KEYPAIR_JWT")) {
    tokenType = "KEYPAIR_JWT";
  } else if (token) {
    tokenType = explicitTokenType && explicitTokenType !== "KEYPAIR_JWT" ? explicitTokenType : "OAUTH";
  } else if (privateKeyPem) {
    tokenType = "KEYPAIR_JWT";
  } else {
    throw new Error(
      "Provide key-pair credentials (SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY) or a bearer token (SNOWFLAKE_TOKEN). Username/password authentication is not supported by the Snowflake SQL REST API.",
    );
  }

  const role = pick("role", input.role, ["SNOWFLAKE_ROLE"], ["role"]);
  const warehouse = pick("warehouse", input.warehouse, ["SNOWFLAKE_WAREHOUSE"], ["warehouse"]);
  const database = pick("database", input.database, ["SNOWFLAKE_DATABASE"], ["database"]);
  const schema = pick("schema", input.schema, ["SNOWFLAKE_SCHEMA"], ["schema"]);
  const host = pick("host", input.base_url, ["SNOWFLAKE_BASE_URL", "SNOWFLAKE_HOST"], ["host"]);
  const baseUrl = host
    ? (host.startsWith("http://") || host.startsWith("https://") ? host : `https://${host}`).replace(/\/+$/, "")
    : `https://${normalizeAccountHost(account)}.snowflakecomputing.com`;

  return {
    account,
    user,
    baseUrl,
    tokenType,
    privateKeyPem,
    privateKeyPassphrase,
    token,
    role,
    warehouse,
    database,
    schema,
    timeoutMs: clampNumber(asNumber(input.timeout_seconds) ?? asNumber(env.SNOWFLAKE_TIMEOUT), DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000,
    statementTimeoutSeconds: clampNumber(
      asNumber(input.statement_timeout_seconds) ?? asNumber(env.SNOWFLAKE_STATEMENT_TIMEOUT),
      DEFAULT_STATEMENT_TIMEOUT_SECONDS,
      5,
      3600,
    ),
    pollIntervalMs: clampNumber(asNumber(input.poll_interval_ms) ?? asNumber(env.SNOWFLAKE_POLL_INTERVAL_MS), DEFAULT_POLL_INTERVAL_MS, 0, 30_000),
    maxRetries: clampNumber(asNumber(input.max_retries), DEFAULT_MAX_RETRIES, 0, 10),
    retryBaseMs: clampNumber(asNumber(input.retry_base_ms), DEFAULT_RETRY_BASE_MS, 0, 30_000),
    maxPartitions: clampNumber(asNumber(input.max_partitions), DEFAULT_MAX_PARTITIONS, 1, 10_000),
    rowLimit: clampNumber(asNumber(input.row_limit), DEFAULT_ROW_LIMIT, 100, 1_000_000),
    connectionName: toml?.name,
    sourceChain: [...new Set(sourceChain)],
  };
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

export function computePublicKeyFingerprint(privateKey: KeyObject): string {
  const publicKeyDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(publicKeyDer).digest("base64")}`;
}

/**
 * A private key that cannot be turned into a bearer token. The message is
 * fixed text plus a validated code (OpenSSL's ERR_OSSL_* code, or
 * INVALID_PRIVATE_KEY when the library gave none); the key material, the
 * passphrase, and the library's own wording never reach it.
 */
export class SnowflakePrivateKeyError extends Error {
  readonly code: string;

  constructor(code: string, detail: string = "Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.") {
    super(`Unable to load the Snowflake private key (${code}). ${detail}`);
    this.name = "SnowflakePrivateKeyError";
    this.code = code;
  }
}

export function buildSnowflakeKeyPairJwt(
  config: Pick<SnowflakeResolvedConfig, "account" | "user" | "privateKeyPem" | "privateKeyPassphrase">,
  now: Date = new Date(),
  lifetimeSeconds: number = JWT_LIFETIME_SECONDS,
): { token: string; expiresAt: number; issuer: string; subject: string } {
  if (!config.privateKeyPem) {
    throw new SnowflakePrivateKeyError("MISSING_PRIVATE_KEY", "Snowflake key-pair authentication requires a private key.");
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({
      key: config.privateKeyPem,
      format: "pem",
      passphrase: config.privateKeyPassphrase,
    });
  } catch (error) {
    throw new SnowflakePrivateKeyError(thrownCode(error, CRYPTO_ERROR_CODE_PATTERN) ?? "INVALID_PRIVATE_KEY");
  }
  const qualifiedUser = `${normalizeJwtAccountIdentifier(config.account)}.${config.user.trim().toUpperCase()}`;
  const issuer = `${qualifiedUser}.${computePublicKeyFingerprint(privateKey)}`;
  const issuedAt = Math.floor(now.getTime() / 1000);
  const expiresAt = issuedAt + Math.min(lifetimeSeconds, 3600);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({ iss: issuer, sub: qualifiedUser, iat: issuedAt, exp: expiresAt }));
  const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKey).toString("base64url");
  return { token: `${header}.${payload}.${signature}`, expiresAt: expiresAt * 1000, issuer, subject: qualifiedUser };
}

/** What the SQL API returned for one request; a non-JSON body is described, never kept. */
interface SnowflakeApiResponse {
  status: number;
  statusText: string;
  payload: JsonRecord;
  headers: Headers;
  nonJsonBody?: string;
}

export type SnowflakeStatementErrorKind = Exclude<SnowflakeStatementStatus, "ok">;

export class SnowflakeStatementError extends Error {
  readonly statusCode?: number;
  readonly sqlCode?: string;
  readonly sqlState?: string;
  readonly kind: SnowflakeStatementErrorKind;
  /** The local failure code when the statement was never sent. */
  readonly code?: string;

  /**
   * The message and codes are scrubbed here as well as at the record point,
   * so an error built anywhere in the client never carries a credential even
   * if a caller stores error.message directly.
   */
  constructor(message: string, options: { statusCode?: number; sqlCode?: string; sqlState?: string; kind?: SnowflakeStatementErrorKind; code?: string } = {}) {
    super(redactSecrets(message));
    this.name = "SnowflakeStatementError";
    this.statusCode = options.statusCode;
    this.sqlCode = options.sqlCode === undefined ? undefined : redactSecrets(options.sqlCode);
    this.sqlState = options.sqlState === undefined ? undefined : redactSecrets(options.sqlState);
    this.kind = options.kind ?? classifyErrorMessage(this.message, options.statusCode);
    this.code = options.code;
  }

  /**
   * The error for a statement that is never sent because no bearer token can
   * be built: the message names the local failure and its code, never an
   * endpoint, and the request loop does not retry it.
   */
  static notRequested(reason: string, code: string, remediation?: string): SnowflakeStatementError {
    return new SnowflakeStatementError(
      `Not requested: ${reason} (${code}); no statement was sent.${remediation ? ` ${remediation}` : ""}`,
      { kind: "not_requested", code },
    );
  }

  /**
   * Builds the error for a response that cannot be used as a result set: a
   * body that is not JSON becomes a status-and-length note whatever its
   * content type, a JSON body contributes only the documented message, code,
   * and sqlState fields, and the configured secrets are removed before the
   * pattern pass runs.
   */
  static fromResponse(response: SnowflakeApiResponse, secrets: Array<string | undefined>): SnowflakeStatementError {
    return new SnowflakeStatementError(redactSecrets(extractApiError(response), secrets), {
      statusCode: response.status,
      sqlCode: response.nonJsonBody === undefined ? asString(response.payload.code) : undefined,
      sqlState: response.nonJsonBody === undefined ? asString(response.payload.sqlState) : undefined,
    });
  }
}

/** A URL resolved onto the configured account origin, or the fixed reason it was refused before any request. */
type OriginResolution = { url: string; refusal?: undefined } | { url?: undefined; refusal: string };

/** A root path (`/...` but not `//...` or `/\...`); any other slash or backslash form is a protocol-relative or relative reference. */
const ROOT_PATH_PATTERN = /^\/(?![/\\])/;
/** An absolute URL: a scheme (any casing) followed by a colon. */
const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:/i;

/**
 * The origin a URL names, spelled as scheme and host (`https://host:8443`) or,
 * for a URL without a host (`javascript:`, `data:`, `file:`, `blob:`), as its
 * bare scheme. `URL.origin` would spell the first three as the opaque string
 * "null" and a blob: URL as the origin of the URL inside it, so a blob: link
 * carrying the configured host would compare equal to it.
 */
function originLabel(url: URL): string {
  return url.host.length > 0 ? `${url.protocol}//${url.host}` : url.protocol;
}

/**
 * Where a URL may lead, decided before any credential is built or any request
 * is sent. A client-built path or the server-supplied statementStatusUrl of an
 * asynchronous statement is followed only when it is a root path on the
 * configured account origin or an absolute URL that resolves, as a browser
 * would, onto that origin (scheme and host compared after URL normalization,
 * so casing never matters) and carries no userinfo. A relative reference such
 * as `@other.example/x`, a protocol-relative (`//host`) form, or a backslash
 * (`\\host`) form is refused whatever host it names, since concatenating it
 * onto the account URL would move the host or request a path the server never
 * meant; a link on a hostless scheme (`javascript:`, `data:`, `blob:`, `file:`)
 * is refused by its scheme. Each refusal is fixed text naming only the
 * configured origin and the rejected origin: no path, query, fragment, or
 * userinfo of the link reaches any text, so the bearer token never leaves for
 * another host and no window of the link is echoed.
 */
function resolveOnConfiguredOrigin(candidate: string, baseUrl: string): OriginResolution {
  const configured = originLabel(new URL(baseUrl));
  let resolved: URL;
  try {
    resolved = new URL(candidate, baseUrl);
  } catch {
    return { refusal: `could not be parsed against the configured account origin ${configured}` };
  }
  const origin = originLabel(resolved);
  if (resolved.username !== "" || resolved.password !== "") {
    return { refusal: `carries userinfo for origin ${origin} (configured account origin ${configured})` };
  }
  if (origin !== configured) {
    return { refusal: `is on origin ${origin}, not the configured account origin ${configured}` };
  }
  if (!ROOT_PATH_PATTERN.test(candidate) && !ABSOLUTE_URL_PATTERN.test(candidate)) {
    return { refusal: `is a protocol-relative or relative reference rather than a root path on the configured account origin ${configured} or an absolute URL on it` };
  }
  return { url: resolved.href };
}

function classifyErrorMessage(message: string, statusCode?: number): "denied" | "error" | "timeout" {
  if (/insufficient privileges|not authorized|access control error|does not exist or not authorized|unauthorized|forbidden/i.test(message)) {
    return "denied";
  }
  if (statusCode === 401 || statusCode === 403) return "denied";
  if (/timed out|timeout|aborted|deadline/i.test(message)) return "timeout";
  return "error";
}

function extractApiError(response: SnowflakeApiResponse): string {
  const outcome = response.status >= 200 && response.status < 300 ? "returned an unreadable response" : "failed";
  const statusLine = `${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
  if (response.nonJsonBody !== undefined) {
    return `Snowflake SQL API request ${outcome} (${statusLine}): ${response.nonJsonBody}`;
  }
  const message = asString(response.payload.message) ?? asString(response.payload.error) ?? "";
  const code = asString(response.payload.code);
  const sqlState = asString(response.payload.sqlState);
  const detail = [code ? `code ${code}` : undefined, sqlState ? `sqlState ${sqlState}` : undefined].filter(Boolean).join(", ");
  return `Snowflake SQL API request ${outcome} (${statusLine})${message ? `: ${message}` : ""}${detail ? ` [${detail}]` : ""}`;
}

export class SnowflakeSqlClient {
  private readonly config: SnowflakeResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private jwt?: { token: string; expiresAt: number };

  constructor(config: SnowflakeResolvedConfig, options: { fetchImpl?: FetchImpl; now?: () => Date } = {}) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): SnowflakeResolvedConfig {
    return this.config;
  }

  /**
   * The bearer token for the next request. When none can be built, the
   * statement is reported as not requested with the local failure code; no
   * endpoint is named because none was called.
   */
  private getBearerToken(): string {
    if (this.config.tokenType === "KEYPAIR_JWT") {
      const nowMs = this.now().getTime();
      if (!this.jwt || this.jwt.expiresAt - JWT_REFRESH_SKEW_SECONDS * 1000 <= nowMs) {
        let built: ReturnType<typeof buildSnowflakeKeyPairJwt>;
        try {
          built = buildSnowflakeKeyPairJwt(this.config, this.now());
        } catch (error) {
          const code = error instanceof SnowflakePrivateKeyError ? error.code : "INVALID_PRIVATE_KEY";
          throw SnowflakeStatementError.notRequested(
            "the Snowflake private key could not be loaded",
            code,
            "Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.",
          );
        }
        this.jwt = { token: built.token, expiresAt: built.expiresAt };
      }
      return this.jwt.token;
    }
    if (!this.config.token) {
      throw SnowflakeStatementError.notRequested("no Snowflake bearer token is configured", "MISSING_TOKEN");
    }
    return this.config.token;
  }

  /** The caller's token, the JWT built from the key pair, the private key, and its passphrase; every form of each is removed from error text. */
  private configuredSecrets(): Array<string | undefined> {
    return [this.config.token, this.jwt?.token, this.config.privateKeyPem, this.config.privateKeyPassphrase];
  }

  private redact(message: string): string {
    return redactSecrets(message, this.configuredSecrets());
  }

  private async request(
    method: "GET" | "POST",
    pathname: string,
    body?: JsonRecord,
  ): Promise<SnowflakeApiResponse> {
    // The URL is resolved onto the configured origin before any credential is
    // built or attached, so a path that would move the host is refused with
    // fixed text naming only the two origins and nothing leaves.
    const resolution = resolveOnConfiguredOrigin(pathname, this.config.baseUrl);
    if (resolution.url === undefined) {
      throw new SnowflakeStatementError(`Snowflake SQL API request refused: the request URL ${resolution.refusal}, so no request was sent.`, { kind: "error" });
    }
    const url = resolution.url;
    let attempt = 0;
    for (;;) {
      // A credential that cannot be turned into a bearer token is a
      // configuration error, not a transport failure: the not-requested error
      // propagates before any fetch and is never retried.
      const authorization = `Bearer ${this.getBearerToken()}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const headers = new Headers({
          accept: "application/json",
          "content-type": "application/json",
          "user-agent": "grclanker-snowflake-inspector/1.0",
          authorization,
          "x-snowflake-authorization-token-type": this.config.tokenType,
        });
        const response = await this.fetchImpl(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        // A body that is not JSON (a proxy error page, an HTML sign-in form) is
        // never copied into the payload or an error string: it is described by
        // content type and size only, because such pages can echo credentials.
        const rawText = await response.text();
        let payload: JsonRecord = {};
        let nonJsonBody: string | undefined;
        if (rawText.length > 0) {
          try {
            const parsed: unknown = JSON.parse(rawText);
            payload = asObject(parsed) ?? { data: parsed };
          } catch {
            nonJsonBody = describeNonJsonBody(response, rawText);
          }
        }
        const retryable = response.status === 429 || response.status >= 500;
        if (retryable && attempt < this.config.maxRetries && !(response.status === 429 && method === "GET" && asString(payload.statementHandle))) {
          attempt += 1;
          await sleep(this.retryDelay(attempt, response.headers));
          continue;
        }
        return { status: response.status, statusText: response.statusText, payload, headers: response.headers, nonJsonBody };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (controller.signal.aborted) {
          throw new SnowflakeStatementError(`Snowflake SQL API request timed out after ${this.config.timeoutMs}ms (${method} ${pathname})`, { kind: "timeout" });
        }
        if (error instanceof SnowflakeStatementError) throw error;
        if (attempt < this.config.maxRetries) {
          attempt += 1;
          await sleep(this.retryDelay(attempt));
          continue;
        }
        throw new SnowflakeStatementError(`Snowflake SQL API request failed (${method} ${pathname}): ${this.redact(message)}`);
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  private retryDelay(attempt: number, headers?: Headers): number {
    const retryAfter = asNumber(headers?.get("retry-after"));
    if (retryAfter !== undefined) return Math.min(retryAfter * 1000, 30_000);
    return Math.min(this.config.retryBaseMs * 2 ** (attempt - 1), 15_000);
  }

  async execute(statement: string, options: { timeoutSeconds?: number } = {}): Promise<SnowflakeResultSet> {
    assertReadOnlyStatement(statement);
    const body: JsonRecord = {
      statement,
      timeout: options.timeoutSeconds ?? this.config.statementTimeoutSeconds,
    };
    if (this.config.role) body.role = this.config.role;
    if (this.config.warehouse) body.warehouse = this.config.warehouse;
    if (this.config.database) body.database = this.config.database;
    if (this.config.schema) body.schema = this.config.schema;

    const submit = await this.request("POST", `/api/v2/statements?async=true&requestId=${randomUUID()}`, body);
    let latest = submit;
    let handle = asString(latest.payload.statementHandle);
    const statusUrl = asString(latest.payload.statementStatusUrl) ?? (handle ? `/api/v2/statements/${handle}` : undefined);
    const deadline = this.now().getTime() + (options.timeoutSeconds ?? this.config.statementTimeoutSeconds) * 1000 + this.config.timeoutMs;

    while (latest.nonJsonBody === undefined && (latest.status === 202 || (latest.status === 429 && handle))) {
      if (!statusUrl) break;
      const statusResolution = resolveOnConfiguredOrigin(statusUrl, this.config.baseUrl);
      if (statusResolution.url === undefined) {
        throw new SnowflakeStatementError(`Snowflake SQL API returned a statement status URL that ${statusResolution.refusal}; the statement was not polled and its result was not read.`, { kind: "error" });
      }
      if (this.now().getTime() > deadline) {
        throw new SnowflakeStatementError(`Snowflake statement ${handle ?? ""} did not complete before the ${this.config.statementTimeoutSeconds}s statement timeout.`, { kind: "timeout" });
      }
      await sleep(this.pollDelay(submit.headers));
      latest = await this.request("GET", statusUrl);
      handle = asString(latest.payload.statementHandle) ?? handle;
    }

    // A 2xx with a non-JSON body is an unreadable statement, not an empty
    // result set, so it is reported like any other failed response.
    if (latest.status !== 200 || latest.nonJsonBody !== undefined) {
      throw SnowflakeStatementError.fromResponse(latest, this.configuredSecrets());
    }

    return this.materializeResultSet(statement, latest.payload, handle);
  }

  private pollDelay(headers: Headers): number {
    const retryAfter = asNumber(headers.get("retry-after"));
    if (retryAfter !== undefined) return Math.min(retryAfter * 1000, 30_000);
    return this.config.pollIntervalMs;
  }

  private async materializeResultSet(statement: string, payload: JsonRecord, handle?: string): Promise<SnowflakeResultSet> {
    const metadata = asObject(payload.resultSetMetaData) ?? {};
    const columns = asArray(metadata.rowType)
      .map((column) => asString(asObject(column)?.name))
      .filter((name): name is string => Boolean(name));
    const partitionInfo = asArray(metadata.partitionInfo);
    const partitionCount = Math.max(partitionInfo.length, 1);
    const numRows = asNumber(metadata.numRows) ?? asArray(payload.data).length;
    const rawRows: unknown[][] = asArray(payload.data).map((row) => asArray(row));
    let fetchedPartitions = 1;

    if (handle) {
      const partitionsToFetch = Math.min(partitionCount, this.config.maxPartitions);
      for (let partition = 1; partition < partitionsToFetch; partition += 1) {
        const response = await this.request("GET", `/api/v2/statements/${handle}?partition=${partition}`);
        if (response.status !== 200 || response.nonJsonBody !== undefined) {
          throw SnowflakeStatementError.fromResponse(response, this.configuredSecrets());
        }
        rawRows.push(...asArray(response.payload.data).map((row) => asArray(row)));
        fetchedPartitions += 1;
      }
    }

    const rows: SqlRow[] = rawRows.map((values) => {
      const row: SqlRow = {};
      columns.forEach((column, index) => {
        const value = values[index];
        row[column] = value === null || value === undefined ? null : String(value);
      });
      return row;
    });

    return {
      statement,
      columns,
      rows,
      numRows,
      partitionCount,
      fetchedPartitions,
      truncated: fetchedPartitions < partitionCount || rows.length < numRows,
      statementHandle: handle,
    };
  }
}

const READ_ONLY_PREFIXES = ["SHOW ", "DESCRIBE ", "DESC ", "SELECT ", "WITH ", "EXPLAIN "];
const FORBIDDEN_STATEMENT_PATTERN = /\b(CREATE|ALTER|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE|MERGE|TRUNCATE|COPY|PUT|GET|REMOVE|CALL|USE|UNDROP|EXECUTE|BEGIN|COMMIT|ROLLBACK|SET|UNSET|LIST)\b/i;
const STRING_LITERAL_PATTERN = /'(?:[^']|'')*'/g;
const ROLE_USAGE_ROW_LIMIT = 500;
const FAILED_LOGIN_ROW_LIMIT = 500;
const TAG_REFERENCE_ROW_LIMIT = 200;
const MAX_POLICY_REFERENCE_LOOKUPS = 20;
/**
 * Snowflake returns at most 10,000 rows from a SHOW command and reports no
 * total, so a full page is the only signal that the inventory was cut off.
 */
export const SHOW_ROW_CAP = 10_000;

function stripStringLiterals(statement: string): string {
  return statement.replace(STRING_LITERAL_PATTERN, "''");
}

export function assertReadOnlyStatement(statement: string): void {
  const normalized = statement.trim().replace(/\s+/g, " ").toUpperCase();
  const refusal = `Refusing to execute a non read-only Snowflake statement: ${statement.slice(0, 80)}`;
  if (!READ_ONLY_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    throw new Error(refusal);
  }
  const withoutLiterals = stripStringLiterals(normalized);
  if (withoutLiterals.includes(";")) {
    throw new Error(refusal);
  }
  if (FORBIDDEN_STATEMENT_PATTERN.test(withoutLiterals)) {
    throw new Error(refusal);
  }
}

function accountUsageView(view: string): string {
  return `SNOWFLAKE.ACCOUNT_USAGE.${view}`;
}

type AccountUsagePolicyKind = "NETWORK_POLICY" | "MASKING_POLICY" | "ROW_ACCESS_POLICY";

function quoteIdentifier(identifier: string): string {
  return /^[A-Z_][A-Z0-9_$]*$/.test(identifier) ? identifier : `"${identifier.replace(/"/g, "\"\"")}"`;
}

function escapeStringLiteral(value: string): string {
  return value.replace(/'/g, "''");
}

export interface QualifiedPolicyName {
  database: string;
  schema: string;
  name: string;
}

export function qualifiedPolicyName(row: SqlRow): QualifiedPolicyName | undefined {
  const database = rowValue(row, "DATABASE");
  const schema = rowValue(row, "SCHEMA");
  const name = rowValue(row, "NAME");
  if (!database || !schema || !name) return undefined;
  return { database, schema, name };
}

function formatQualifiedPolicyName(policy: QualifiedPolicyName): string {
  return `${quoteIdentifier(policy.database)}.${quoteIdentifier(policy.schema)}.${quoteIdentifier(policy.name)}`;
}

export const SNOWFLAKE_STATEMENTS = {
  sessionContext: "SELECT CURRENT_ACCOUNT() AS ACCOUNT_NAME, CURRENT_USER() AS USER_NAME, CURRENT_ROLE() AS ROLE_NAME, CURRENT_WAREHOUSE() AS WAREHOUSE_NAME, CURRENT_REGION() AS REGION_NAME, CURRENT_VERSION() AS VERSION",
  showNetworkPolicies: "SHOW NETWORK POLICIES",
  accountNetworkPolicyParameter: "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT",
  networkPolicies: (limit: number) => `SELECT NAME, OWNER, ALLOWED_IP_LIST, BLOCKED_IP_LIST, CREATED, LAST_ALTERED FROM ${accountUsageView("NETWORK_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  policyReferences: (kind: AccountUsagePolicyKind, limit: number) => `SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN, REF_COLUMN_NAME, TAG_NAME, POLICY_STATUS FROM ${accountUsageView("POLICY_REFERENCES")} WHERE POLICY_KIND = '${kind}' LIMIT ${limit}`,
  policyReferencesByName: (policy: QualifiedPolicyName) => `SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN FROM TABLE(${quoteIdentifier(policy.database)}.INFORMATION_SCHEMA.POLICY_REFERENCES(POLICY_NAME => '${escapeStringLiteral(formatQualifiedPolicyName(policy))}'))`,
  users: (limit: number) => `SELECT NAME, LOGIN_NAME, TYPE, DISABLED, HAS_PASSWORD, HAS_MFA, EXT_AUTHN_DUO, HAS_RSA_PUBLIC_KEY, HAS_PAT, HAS_WORKLOAD_IDENTITY, LAST_SUCCESS_LOGIN, PASSWORD_LAST_SET_TIME, CREATED_ON, DEFAULT_ROLE, OWNER FROM ${accountUsageView("USERS")} WHERE DELETED_ON IS NULL LIMIT ${limit}`,
  passwordPolicies: (limit: number) => `SELECT NAME, DATABASE, SCHEMA, OWNER, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_UPPER_CASE_CHARS, PASSWORD_MIN_LOWER_CASE_CHARS, PASSWORD_MIN_NUMERIC_CHARS, PASSWORD_MIN_SPECIAL_CHARS, PASSWORD_MIN_AGE_DAYS, PASSWORD_MAX_AGE_DAYS, PASSWORD_MAX_RETRIES, PASSWORD_LOCKOUT_TIME_MINS, PASSWORD_HISTORY FROM ${accountUsageView("PASSWORD_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  sessionPolicies: (limit: number) => `SELECT NAME, DATABASE, SCHEMA, OWNER, SESSION_IDLE_TIMEOUT_MINS, SESSION_UI_IDLE_TIMEOUT_MINS, SESSION_MAX_LIFESPAN_MINS, SESSION_UI_MAX_LIFESPAN_MINS FROM ${accountUsageView("SESSION_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  showIntegrations: "SHOW INTEGRATIONS",
  roleGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTED_TO, GRANTEE_NAME, GRANT_OPTION, GRANTED_BY FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_ON = 'ROLE' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  globalPrivilegeGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, GRANTED_TO, GRANTEE_NAME, GRANT_OPTION FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_ON = 'ACCOUNT' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  adminRoleGrantsToUsers: (limit: number) => `SELECT ROLE, GRANTEE_NAME, GRANTED_BY, CREATED_ON FROM ${accountUsageView("GRANTS_TO_USERS")} WHERE DELETED_ON IS NULL AND ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') LIMIT ${limit}`,
  roleUsageByQueries: (lookbackDays: number) => `SELECT ROLE_NAME, COUNT(*) AS QUERY_COUNT, COUNT(DISTINCT USER_NAME) AS USER_COUNT FROM ${accountUsageView("QUERY_HISTORY")} WHERE START_TIME >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) AND QUERY_TYPE IN (${ROUTINE_QUERY_TYPES.map((type) => `'${type}'`).join(", ")}) GROUP BY ROLE_NAME ORDER BY QUERY_COUNT DESC LIMIT ${ROLE_USAGE_ROW_LIMIT}`,
  directUserGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTEE_NAME FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_TO = 'USER' AND GRANTED_ON <> 'ROLE' LIMIT ${limit}`,
  publicGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTED_BY FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTEE_NAME = 'PUBLIC' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  loginOutcomes: (lookbackDays: number) => `SELECT IS_SUCCESS, COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) GROUP BY IS_SUCCESS`,
  failedLogins: (lookbackDays: number) => `SELECT USER_NAME, CLIENT_IP, REPORTED_CLIENT_TYPE, COUNT(*) AS FAILURE_COUNT, MAX(ERROR_MESSAGE) AS LAST_ERROR FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) AND IS_SUCCESS = 'NO' GROUP BY USER_NAME, CLIENT_IP, REPORTED_CLIENT_TYPE ORDER BY FAILURE_COUNT DESC LIMIT ${FAILED_LOGIN_ROW_LIMIT}`,
  accessHistoryProbe: `SELECT COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("ACCESS_HISTORY")} WHERE QUERY_START_TIME >= DATEADD(day, -7, CURRENT_TIMESTAMP())`,
  dataRetentionParameter: "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT",
  showWarehouses: "SHOW WAREHOUSES",
  maskingPolicyCount: `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("MASKING_POLICIES")} WHERE DELETED IS NULL`,
  rowAccessPolicyCount: `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("ROW_ACCESS_POLICIES")} WHERE DELETED IS NULL`,
  tagReferenceSummary: `SELECT TAG_DATABASE, TAG_SCHEMA, TAG_NAME, COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("TAG_REFERENCES")} GROUP BY TAG_DATABASE, TAG_SCHEMA, TAG_NAME ORDER BY REFERENCE_COUNT DESC LIMIT ${TAG_REFERENCE_ROW_LIMIT}`,
  stageParameters: "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%' IN ACCOUNT",
  unloadParameters: "SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%' IN ACCOUNT",
  showDatabases: "SHOW DATABASES",
  showShares: "SHOW SHARES",
  showReplicationGroups: "SHOW REPLICATION GROUPS",
} as const;

function emptyOutcome(key: string, statement: string): SnowflakeStatementOutcome {
  return { key, statement, status: "ok", columns: [], rows: [], numRows: 0, partitionCount: 1, fetchedPartitions: 1, truncated: false };
}

/** The outcome of a statement that did not complete: no row count, no partition count, no truncation flag. */
function unreadOutcome(key: string, statement: string): SnowflakeStatementOutcome {
  return { key, statement, status: "error", columns: [], rows: [], numRows: null, partitionCount: null, fetchedPartitions: null, truncated: null };
}

/** Row count for evidence and summaries: null when the statement was not read. */
export function rowsSeen(outcome: SnowflakeStatementOutcome): number | null {
  return outcome.status === "ok" ? outcome.rows.length : null;
}

/** True when the statement completed and every partition was fetched within the row limit, so a count over its rows describes the whole inventory. */
function fullyRead(outcome: SnowflakeStatementOutcome): boolean {
  return outcome.status === "ok" && outcome.truncated !== true;
}

/**
 * A count judged over a statement's rows describes the whole inventory only
 * when the read was complete: under a partial read it renders null rather than
 * the count of the rows read, since a 0 there would claim an absence from the
 * unread partitions (reviewer C, item I). The seen-of-total sits in the
 * finding's statements list and partial_inventory note beside it.
 */
function countIfFullyRead(outcome: SnowflakeStatementOutcome, count: number): number | null {
  return fullyRead(outcome) ? count : null;
}

/** The suffix a summary gives a population under a partial read, so a count of the rows read never reads as a count for the account. */
function amongRowsRead(outcome: SnowflakeStatementOutcome): string {
  return fullyRead(outcome) ? "" : " among the rows read";
}

/** The service-class remark in a stale-login pass: under a partial read an empty class is unread, not a count of zero for the account. */
function serviceClassLoginNote(users: SnowflakeStatementOutcome, serviceCount: number): string {
  if (fullyRead(users)) return `${serviceCount} service-class users showed no stale logins`;
  return serviceCount === 0 ? "no service-class user was among the rows read" : `${serviceCount} service-class users among the rows read showed no stale logins`;
}

/**
 * Rule 9 deny list for the rows every statement returns: matched on the
 * lowercased key with dots, underscores, and hyphens removed, so PASSWORD,
 * OAUTH_CLIENT_SECRET, and a parameter named *_TOKEN match while the
 * boolean and policy columns that merely mention a credential (HAS_PASSWORD,
 * MUST_CHANGE_PASSWORD, PASSWORD_MIN_LENGTH, SESSION_MAX_LIFESPAN_MINS) and
 * every identifier (NAME, LOGIN_NAME, OWNER, ROLE_NAME) stay legible.
 */
const CREDENTIAL_COLUMN_PATTERN = /(password|passwd|passphrase|secret|token|privatekey|apikey|clientsecret)$/;
const CREDENTIAL_COLUMN_EXEMPT_PREFIX = /^(has|is|must|uses|min|max|require)/;
const JSON_LITERAL_PATTERN = /^(?:true|false|null)$/i;
const PAIR_NAME_COLUMNS = ["name", "key", "property"];
const PAIR_VALUE_COLUMNS = new Set(["value", "property_value"]);

function isCredentialColumn(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[._-]/g, "");
  return CREDENTIAL_COLUMN_PATTERN.test(normalized) && !CREDENTIAL_COLUMN_EXEMPT_PREFIX.test(normalized);
}

function pairNameOf(record: JsonRecord): string | undefined {
  for (const column of PAIR_NAME_COLUMNS) {
    const name = asString(record[column]);
    if (name !== undefined) return name;
  }
  return undefined;
}

/**
 * Applied to the rows of every completed statement before they are written to
 * core_data or echoed in a tool payload: removes the value of every
 * credential-named column (and of the value column of a {key, value} or
 * {property, property_value} row whose name is credential-named, unless it is
 * a JSON literal such as a parameter's "false"), keeps only the origin of a
 * webhook-named column's URL, and passes every other string through the
 * data-side text pass, so a vendor-prefixed token, a JWT, a PEM block, or a
 * credential carrier inside a comment, a query text, or an error message is
 * removed there too. Column names and nulls are kept so the evidence stays
 * legible, and containers are kept at every depth.
 */
export function redactSnapshot(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSnapshot);
  const record = asObject(value);
  if (!record) return typeof value === "string" ? scrubDataText(value) : value;
  const pairName = pairNameOf(record);
  const output: JsonRecord = {};
  for (const [key, item] of Object.entries(record)) {
    const credentialPair = PAIR_VALUE_COLUMNS.has(key.toLowerCase()) && pairName !== undefined && isCredentialColumn(pairName);
    if (isCredentialColumn(key) || credentialPair) {
      output[key] = item === null || item === undefined || (typeof item === "string" && JSON_LITERAL_PATTERN.test(item)) ? item : REDACTED;
    } else if (typeof item === "string" && pairRuleFor(key) === "webhook") {
      output[key] = webhookReplacement(item);
    } else {
      output[key] = redactSnapshot(item);
    }
  }
  return output;
}

/**
 * The single serializer for a statement outcome on every output path: the
 * rows of a statement that did not complete are replaced by a marker naming
 * the statement, its outcome, and the error, and its columns become null; the
 * rows of one that completed pass through the rule 9 walk above.
 */
export function snapshotStatement(outcome: SnowflakeStatementOutcome): SnowflakeStatementSnapshot {
  if (outcome.status === "ok") return { ...outcome, rows: redactSnapshot(outcome.rows) as SqlRow[] };
  // A statement that was never sent is not named: the key identifies what
  // would have been collected, and the error names the local failure.
  const statement = outcome.status === "not_requested" ? null : outcome.statement;
  return {
    key: outcome.key,
    statement,
    status: outcome.status,
    columns: null,
    rows: { collected: false, status: outcome.status, statement, error: outcome.error ?? null },
    numRows: null,
    partitionCount: null,
    fetchedPartitions: null,
    truncated: null,
    rowLimit: outcome.rowLimit,
    error: outcome.error,
    ...(outcome.code === undefined ? {} : { code: outcome.code }),
  };
}

function configuredSecretsOf(client: SnowflakeQueryClient): Array<string | undefined> {
  const config = client.getResolvedConfig();
  return [config.token, config.privateKeyPem, config.privateKeyPassphrase];
}

export async function collectStatement(
  client: SnowflakeQueryClient,
  key: string,
  statement: string,
  rowLimit?: number,
): Promise<SnowflakeStatementOutcome> {
  try {
    const result = await client.execute(statement);
    const hitRowLimit = rowLimit !== undefined && result.rows.length >= rowLimit;
    return {
      key,
      statement,
      status: "ok",
      columns: result.columns,
      rows: result.rows,
      numRows: result.numRows,
      partitionCount: result.partitionCount,
      fetchedPartitions: result.fetchedPartitions,
      truncated: result.truncated || hitRowLimit,
      rowLimit,
    };
  } catch (error) {
    // Every statement error is recorded here and nowhere else, so this is the
    // one place the redaction pass has to run for findings and the bundle,
    // whichever constructor or throw site built the message.
    const message = redactSecrets(error instanceof Error ? error.message : String(error), configuredSecretsOf(client));
    const kind = error instanceof SnowflakeStatementError ? error.kind : classifyErrorMessage(message);
    const code = error instanceof SnowflakeStatementError ? error.code : undefined;
    return {
      ...unreadOutcome(key, statement),
      status: kind,
      error: message,
      ...(code === undefined ? {} : { code }),
    };
  }
}

export interface PolicyReferenceLookups {
  outcomes: SnowflakeStatementOutcome[];
  unchecked: string[];
  accountLevel: SqlRow[];
}

export async function collectPolicyReferencesByName(
  client: SnowflakeQueryClient,
  keyPrefix: string,
  policies: SnowflakeStatementOutcome,
): Promise<PolicyReferenceLookups> {
  const lookups: PolicyReferenceLookups = { outcomes: [], unchecked: [], accountLevel: [] };
  if (policies.status !== "ok") return lookups;
  for (const [index, row] of policies.rows.entries()) {
    const policy = qualifiedPolicyName(row);
    if (!policy) {
      lookups.unchecked.push(rowValue(row, "NAME") ?? `(row ${index + 1} without a fully qualified name)`);
      continue;
    }
    const qualified = formatQualifiedPolicyName(policy);
    if (lookups.outcomes.length >= MAX_POLICY_REFERENCE_LOOKUPS) {
      lookups.unchecked.push(qualified);
      continue;
    }
    const outcome = await collectStatement(client, `${keyPrefix}_${index + 1}`, SNOWFLAKE_STATEMENTS.policyReferencesByName(policy));
    lookups.outcomes.push(outcome);
    for (const reference of outcome.rows) {
      if (upper(rowValue(reference, "REF_ENTITY_DOMAIN")) === "ACCOUNT") lookups.accountLevel.push(reference);
    }
  }
  return lookups;
}

function policyReferenceEvidence(lookups: PolicyReferenceLookups): JsonRecord {
  return {
    reference_lookups: lookups.outcomes.length,
    reference_lookup_failures: lookups.outcomes.filter((outcome) => outcome.status !== "ok").length,
    account_level_attachments: lookups.accountLevel.length,
    account_level_policies: lookups.accountLevel.map((row) => rowValue(row, "POLICY_NAME")).filter((name): name is string => Boolean(name)),
    unchecked_policies: lookups.unchecked,
  };
}

async function collectSessionContext(client: SnowflakeQueryClient): Promise<SessionContext> {
  const outcome = await collectStatement(client, "session_context", SNOWFLAKE_STATEMENTS.sessionContext);
  const row = outcome.rows[0] ?? {};
  return {
    account: rowValue(row, "ACCOUNT_NAME") ?? undefined,
    user: rowValue(row, "USER_NAME") ?? undefined,
    role: rowValue(row, "ROLE_NAME") ?? undefined,
    warehouse: rowValue(row, "WAREHOUSE_NAME") ?? undefined,
    region: rowValue(row, "REGION_NAME") ?? undefined,
    version: rowValue(row, "VERSION") ?? undefined,
    outcome,
  };
}

/**
 * The role the statements ran under: the session's when it was read, else the
 * configured role that every request carried. When no request was sent there
 * is no such role, so the configured name is not reported as active.
 */
function effectiveRole(config: SnowflakeResolvedConfig, session: SessionContext): string | undefined {
  if (session.outcome.status === "not_requested") return undefined;
  return upper(session.role) || upper(config.role) || undefined;
}

function hasFullVisibility(role: string | undefined): boolean {
  return Boolean(role && FULL_VISIBILITY_ROLES.has(role));
}

function describeOutcomeProblem(outcome: Pick<SnowflakeStatementOutcome, "key" | "status" | "error">): string {
  switch (outcome.status) {
    case "ok":
      return "";
    case "denied":
      return `${outcome.key} was denied (insufficient privileges): ${outcome.error ?? "no detail"}`;
    case "timeout":
      return `${outcome.key} timed out: ${outcome.error ?? "no detail"}`;
    case "error":
      return `${outcome.key} failed: ${outcome.error ?? "no detail"}`;
    case "not_requested":
      return `${outcome.key}: ${outcome.error ?? "Not requested: no detail"}`;
    default: {
      const exhaustive: never = outcome.status;
      return String(exhaustive);
    }
  }
}

function truncationNote(outcomes: SnowflakeStatementOutcome[]): string | undefined {
  const truncated = outcomes.filter((outcome) => outcome.status === "ok" && outcome.truncated);
  if (truncated.length === 0) return undefined;
  return truncated
    .map((outcome) =>
      outcome.rowLimit !== undefined && outcome.rows.length >= outcome.rowLimit
        ? `${outcome.key} hit the ${outcome.rowLimit}-row limit (${outcome.rows.length} rows seen)`
        : `${outcome.key} returned ${outcome.fetchedPartitions}/${outcome.partitionCount} partitions (${outcome.rows.length}/${outcome.numRows} rows seen)`,
    )
    .join("; ");
}

function finding(
  control: number,
  status: SnowflakeFindingStatus,
  summary: string,
  evidence: JsonRecord = {},
): SnowflakeFinding {
  const definition = SNOWFLAKE_CONTROLS[control];
  return {
    id: definition.id,
    control,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: definition.mappings,
  };
}

/**
 * A secondary inventory the verdict reads without requiring it: the control
 * can still be judged when it is unreadable, but never as a pass.
 */
interface OptionalStatement {
  outcome: SnowflakeStatementOutcome;
  /** What went unchecked because the inventory was unreadable, phrased for the summary. */
  unchecked: string;
  /** Verdict replacing pass when the inventory is unreadable; warn unless the inventory is essential. */
  demoteTo?: "warn" | "manual";
}

/**
 * Wraps a verdict so that failed, denied, or timed-out required statements
 * become manual findings, an unreadable optional inventory demotes a pass to
 * warn or manual while naming what was not checked, and truncated inventories
 * can never pass outright.
 */
function evaluateControl(
  control: number,
  required: SnowflakeStatementOutcome[],
  manualEvidence: string,
  evaluate: () => { status: SnowflakeFindingStatus; summary: string; evidence?: JsonRecord },
  options: { optional?: OptionalStatement[] } = {},
): SnowflakeFinding {
  const optional = options.optional ?? [];
  const problems = required.filter((outcome) => outcome.status !== "ok");
  const statementEvidence = {
    statements: [...required, ...optional.map((entry) => entry.outcome)].map((outcome) => ({
      key: outcome.key,
      status: outcome.status,
      rows: rowsSeen(outcome),
      truncated: outcome.status === "ok" ? outcome.truncated : null,
      error: outcome.error,
    })),
  };
  if (problems.length > 0) {
    return finding(
      control,
      "manual",
      `Unknown: ${problems.map(describeOutcomeProblem).join("; ")}. Collect manually: ${manualEvidence}`,
      statementEvidence,
    );
  }
  const verdict = evaluate();
  let status = verdict.status;
  let summary = verdict.summary;
  const evidence: JsonRecord = { ...(verdict.evidence ?? {}), ...statementEvidence };
  const unreadable = optional.filter((entry) => entry.outcome.status !== "ok");
  if (unreadable.length > 0) {
    evidence.unreadable_inventories = unreadable.map((entry) => entry.outcome.key);
    if (status === "pass") {
      status = unreadable.some((entry) => entry.demoteTo === "manual") ? "manual" : "warn";
      const notes = unreadable.map((entry) => `${describeOutcomeProblem(entry.outcome)}, so ${entry.unchecked}`).join("; ");
      summary = `${summary} Unreadable inventory: ${notes}. The verdict cannot be pass while an inventory it reads is unreadable; collect manually: ${manualEvidence}`;
    } else {
      summary = `${summary} Unreadable inventory: ${unreadable.map((entry) => `${entry.outcome.key} (${entry.outcome.status})`).join(", ")}.`;
    }
  }
  const truncation = truncationNote([...required, ...optional.map((entry) => entry.outcome)]);
  if (truncation) {
    evidence.partial_inventory = truncation;
    if (status === "pass") {
      return finding(control, "warn", `${summary} Partial inventory: ${truncation}; the verdict cannot be pass on a partial result.`, evidence);
    }
    return finding(control, status, `${summary} Partial inventory: ${truncation}.`, evidence);
  }
  return finding(control, status, summary, evidence);
}

function unverifiedRoleNote(inventory: string): string {
  return `the active role could not be verified and ${inventory} may be scoped to a role with narrower visibility`;
}

function partialVisibilityNote(role: string | undefined, subject: string): string {
  return `The active role ${role ?? "(unknown)"} lacks MANAGE GRANTS, so ${subject} may list only objects granted to that role.`;
}

export type SnowflakeUserClass = "person" | "service" | "snowflake_managed" | "unrecognized";

export function classifyUserType(type: string | null | undefined): SnowflakeUserClass {
  const normalized = upper(type);
  if (PERSON_USER_TYPES.has(normalized)) return "person";
  if (SERVICE_USER_TYPES.has(normalized)) return "service";
  if (SNOWFLAKE_MANAGED_USER_TYPES.has(normalized)) return "snowflake_managed";
  return "unrecognized";
}

function classifyUser(row: SqlRow): SnowflakeUserClass {
  return classifyUserType(rowValue(row, "TYPE"));
}

function isHumanUser(row: SqlRow): boolean {
  return classifyUser(row) === "person";
}

function isServiceUser(row: SqlRow): boolean {
  return classifyUser(row) === "service";
}

interface UserClassSummary {
  person: number;
  service: number;
  snowflake_managed: number;
  unrecognized: number;
  unrecognized_types: string[];
}

function summarizeUserClasses(rows: SqlRow[]): UserClassSummary {
  const summary: UserClassSummary = { person: 0, service: 0, snowflake_managed: 0, unrecognized: 0, unrecognized_types: [] };
  for (const row of rows) {
    const userClass = classifyUser(row);
    switch (userClass) {
      case "person":
        summary.person += 1;
        break;
      case "service":
        summary.service += 1;
        break;
      case "snowflake_managed":
        summary.snowflake_managed += 1;
        break;
      case "unrecognized": {
        summary.unrecognized += 1;
        const type = upper(rowValue(row, "TYPE")) || "(blank)";
        if (!summary.unrecognized_types.includes(type)) summary.unrecognized_types.push(type);
        break;
      }
      default: {
        const exhaustive: never = userClass;
        throw new Error(`Unhandled user class: ${String(exhaustive)}`);
      }
    }
  }
  return summary;
}

function countBy(rows: SqlRow[], keyOf: (row: SqlRow) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of rows) {
    const key = keyOf(row) || "(blank)";
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function unrecognizedUserNote(summary: UserClassSummary): string | undefined {
  if (summary.unrecognized === 0) return undefined;
  return `${summary.unrecognized} users carry an unrecognized TYPE (${summary.unrecognized_types.join(", ")}) and were not classified; review them manually`;
}

/** User class counts for evidence: null under a partial user read, since a 0 there would claim an absence from the unread rows; the unrecognized type names seen stay. */
function userClassesEvidence(users: SnowflakeStatementOutcome, summary: UserClassSummary): JsonRecord {
  return {
    person: countIfFullyRead(users, summary.person),
    service: countIfFullyRead(users, summary.service),
    snowflake_managed: countIfFullyRead(users, summary.snowflake_managed),
    unrecognized: countIfFullyRead(users, summary.unrecognized),
    unrecognized_types: summary.unrecognized_types,
  };
}

function isDisabledUser(row: SqlRow): boolean {
  return rowBoolean(row, "DISABLED") === true;
}

function userName(row: SqlRow): string {
  return rowValue(row, "NAME") ?? rowValue(row, "LOGIN_NAME") ?? "(unnamed)";
}

function parseIpList(value: string | null): string[] {
  if (!value) return [];
  return value
    .replace(/^\[|\]$/g, "")
    .split(",")
    .map((entry) => entry.replace(/["']/g, "").trim())
    .filter((entry) => entry.length > 0);
}

function isPermissiveCidr(entry: string): boolean {
  const normalized = entry.trim();
  if (normalized === "0.0.0.0/0" || normalized === "0.0.0.0" || normalized === "::/0") return true;
  const cidrMatch = /\/(\d{1,3})$/.exec(normalized);
  return Boolean(cidrMatch && Number(cidrMatch[1]) < 8);
}

function parameterValue(outcome: SnowflakeStatementOutcome, key: string): { value?: string; level?: string; found: boolean } {
  const row = outcome.rows.find((candidate) => upper(rowValue(candidate, "key")) === key.toUpperCase());
  if (!row) return { found: false };
  return { value: rowValue(row, "value") ?? undefined, level: rowValue(row, "level") ?? undefined, found: true };
}

export async function checkSnowflakeAccess(client: SnowflakeQueryClient): Promise<SnowflakeAccessCheckResult> {
  const config = client.getResolvedConfig();
  const session = await collectSessionContext(client);
  const probes: Array<[string, string]> = [
    ["show_network_policies", SNOWFLAKE_STATEMENTS.showNetworkPolicies],
    ["show_parameters", SNOWFLAKE_STATEMENTS.accountNetworkPolicyParameter],
    ["show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations],
    ["show_warehouses", SNOWFLAKE_STATEMENTS.showWarehouses],
    ["show_databases", SNOWFLAKE_STATEMENTS.showDatabases],
    ["show_shares", SNOWFLAKE_STATEMENTS.showShares],
    ["show_replication_groups", SNOWFLAKE_STATEMENTS.showReplicationGroups],
    ["account_usage_users", `SELECT COUNT(*) AS USER_COUNT FROM ${accountUsageView("USERS")} WHERE DELETED_ON IS NULL`],
    ["account_usage_login_history", `SELECT COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP())`],
    ["account_usage_query_history", `SELECT COUNT(*) AS QUERY_COUNT FROM ${accountUsageView("QUERY_HISTORY")} WHERE START_TIME >= DATEADD(day, -1, CURRENT_TIMESTAMP())`],
    ["account_usage_access_history", SNOWFLAKE_STATEMENTS.accessHistoryProbe],
    ["account_usage_grants_to_roles", `SELECT COUNT(*) AS GRANT_COUNT FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL`],
    ["account_usage_grants_to_users", `SELECT COUNT(*) AS GRANT_COUNT FROM ${accountUsageView("GRANTS_TO_USERS")} WHERE DELETED_ON IS NULL`],
    ["account_usage_network_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("NETWORK_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_password_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("PASSWORD_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_session_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("SESSION_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_masking_policies", SNOWFLAKE_STATEMENTS.maskingPolicyCount],
    ["account_usage_row_access_policies", SNOWFLAKE_STATEMENTS.rowAccessPolicyCount],
    ["account_usage_policy_references", `SELECT COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("POLICY_REFERENCES")}`],
    ["account_usage_tag_references", `SELECT COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("TAG_REFERENCES")}`],
  ];

  const surfaces: SnowflakeAccessSurface[] = [toSurface("session_context", session.outcome)];
  for (const [name, statement] of probes) {
    surfaces.push(toSurface(name, await collectStatement(client, name, statement)));
  }

  const role = effectiveRole(config, session);
  const readable = surfaces.filter((surface) => surface.status === "readable").length;
  const accountUsageReadable = surfaces.filter((surface) => surface.name.startsWith("account_usage_") && surface.status === "readable").length;
  const status = session.outcome.status === "ok" && accountUsageReadable >= 10 && readable >= surfaces.length - 3 ? "healthy" : "limited";
  const authentication = describeAuthentication(config, session, role);
  const notes = [
    `Using Snowflake account ${session.account ?? config.account} via ${config.baseUrl} (${config.tokenType}).`,
    authentication.note,
    `${readable}/${surfaces.length} Snowflake audit surfaces are readable; ${accountUsageReadable} ACCOUNT_USAGE views responded.`,
  ];
  if (authentication.status !== "not_authenticated" && !hasFullVisibility(role)) {
    notes.push(partialVisibilityNote(role, "SHOW commands"));
  }
  if (config.sourceChain.length > 0) {
    notes.push(`Credential sources: ${config.sourceChain.join(", ")}.`);
  }

  return {
    status,
    account: session.account ?? config.account,
    user: authentication.user,
    role,
    authentication: authentication.status,
    authenticationNote: authentication.note,
    fullVisibility: hasFullVisibility(role),
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run snowflake_assess_network_and_authentication, snowflake_assess_access_control, snowflake_assess_monitoring_and_lifecycle, snowflake_assess_data_protection, or snowflake_export_audit_bundle."
        : "Grant the audit role IMPORTED PRIVILEGES on the SNOWFLAKE database plus MANAGE GRANTS (or use SECURITYADMIN/ACCOUNTADMIN) and a small warehouse, then re-run snowflake_check_access.",
  };
}

/**
 * What the run can say about its own identity. Only a session context row is
 * an observation; the configured user and role are reported as configured
 * values when statements were sent without that row, and nothing is claimed
 * when no request was sent.
 */
function describeAuthentication(
  config: SnowflakeResolvedConfig,
  session: SessionContext,
  role: string | undefined,
): { status: SnowflakeAuthenticationStatus; user: string | null; note: string } {
  switch (session.outcome.status) {
    case "ok": {
      const user = session.user ?? config.user;
      return {
        status: "confirmed",
        user,
        note: `Authenticated as ${user} with role ${role ?? "(default role)"}${session.warehouse ? ` and warehouse ${session.warehouse}` : ""}.`,
      };
    }
    case "not_requested":
      return {
        status: "not_authenticated",
        user: null,
        note: `Not authenticated: ${notRequestedReason(session.outcome)}; no request was sent.`,
      };
    default:
      return {
        status: "unconfirmed",
        user: config.user,
        note: `Authentication not confirmed: the session context statement ${session.outcome.status === "denied" ? "was denied" : session.outcome.status === "timeout" ? "timed out" : "failed"}, so the configured user ${config.user} and role ${role ?? "(default role)"} are reported as configured, not as observed.`,
      };
  }
}

/** The reason clause of a not-requested error ("<reason> (<code>)"), which SnowflakeStatementError.notRequested writes before the first semicolon. */
function notRequestedReason(outcome: SnowflakeStatementOutcome): string {
  const reason = (outcome.error ?? "").replace(/^Not requested: /, "").split(";")[0].trim();
  return reason || `the bearer token could not be built (${outcome.code ?? "UNKNOWN"})`;
}

function toSurface(name: string, outcome: SnowflakeStatementOutcome): SnowflakeAccessSurface {
  switch (outcome.status) {
    case "ok":
      return { name, statement: outcome.statement, status: "readable", rowCount: outcome.rows.length };
    case "denied":
      return { name, statement: outcome.statement, status: "denied", rowCount: null, error: outcome.error };
    case "timeout":
      return { name, statement: outcome.statement, status: "timeout", rowCount: null, error: outcome.error };
    case "error":
      return { name, statement: outcome.statement, status: "error", rowCount: null, error: outcome.error };
    case "not_requested":
      return { name, statement: null, status: "not_requested", rowCount: null, error: outcome.error };
    default: {
      const exhaustive: never = outcome.status;
      return exhaustive;
    }
  }
}

function summarizeStatuses(findings: SnowflakeFinding[]): JsonRecord {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

export async function assessSnowflakeNetworkAndAuthentication(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const minPasswordLength = clampNumber(options.minPasswordLength, DEFAULT_MIN_PASSWORD_LENGTH, 8, 256);
  const maxSessionIdleMinutes = clampNumber(options.maxSessionIdleMinutes, DEFAULT_MAX_SESSION_IDLE_MINUTES, 1, 1440);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const showNetworkPolicies = await collectStatement(client, "show_network_policies", SNOWFLAKE_STATEMENTS.showNetworkPolicies, SHOW_ROW_CAP);
  const networkParameter = await collectStatement(client, "account_network_policy_parameter", SNOWFLAKE_STATEMENTS.accountNetworkPolicyParameter);
  const networkReferences = await collectStatement(client, "network_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("NETWORK_POLICY", limit), limit);
  const networkPolicies = await collectStatement(client, "network_policies", SNOWFLAKE_STATEMENTS.networkPolicies(limit), limit);
  const users = await collectStatement(client, "users", SNOWFLAKE_STATEMENTS.users(limit), limit);
  const passwordPolicies = await collectStatement(client, "password_policies", SNOWFLAKE_STATEMENTS.passwordPolicies(limit), limit);
  const passwordReferences = await collectPolicyReferencesByName(client, "password_policy_references", passwordPolicies);
  const integrations = await collectStatement(client, "show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations, SHOW_ROW_CAP);
  const sessionPolicies = await collectStatement(client, "session_policies", SNOWFLAKE_STATEMENTS.sessionPolicies(limit), limit);
  const sessionReferences = await collectPolicyReferencesByName(client, "session_policy_references", sessionPolicies);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(1, [showNetworkPolicies, networkParameter, networkReferences], "Snowsight Admin > Security > Network Policies: confirm a policy exists and is activated for the account (SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT).", () => {
    const policyNames = showNetworkPolicies.rows.map((row) => rowValue(row, "name")).filter((name): name is string => Boolean(name));
    const accountParameter = parameterValue(networkParameter, "NETWORK_POLICY");
    const accountAttached = Boolean(accountParameter.value) && upper(accountParameter.level) === "ACCOUNT";
    const userAttachments = networkReferences.rows.filter((row) => upper(rowValue(row, "REF_ENTITY_DOMAIN")) === "USER");
    const evidence = {
      policy_count: policyNames.length,
      policies: policyNames.slice(0, 25),
      account_policy: accountParameter.value ?? null,
      account_policy_level: accountParameter.level ?? null,
      user_level_attachments: userAttachments.length,
    };
    if (policyNames.length === 0 && accountAttached && !hasFullVisibility(role)) {
      return { status: "warn", summary: `The account parameter reports network policy ${accountParameter.value} activated at ACCOUNT level, but SHOW NETWORK POLICIES returned zero policies under role ${role ?? "(unknown)"}; confirm the policy definition as ACCOUNTADMIN.`, evidence };
    }
    if (policyNames.length === 0) {
      return { status: "fail", summary: `SHOW NETWORK POLICIES returned zero policies; an empty inventory fails this control.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW NETWORK POLICIES")}`}`, evidence };
    }
    if (accountAttached) {
      return { status: "pass", summary: `Network policy ${accountParameter.value} is activated at ACCOUNT level (${policyNames.length} policies defined, ${userAttachments.length} user-level attachments).`, evidence };
    }
    if (userAttachments.length > 0) {
      return { status: "warn", summary: `${policyNames.length} network policies exist and ${userAttachments.length} user-level attachments were found, but no policy is activated at ACCOUNT level.`, evidence };
    }
    return { status: "fail", summary: `${policyNames.length} network policies exist but none is activated at ACCOUNT level and no user-level attachment was found in POLICY_REFERENCES.`, evidence };
  }));

  findings.push(evaluateControl(2, [networkPolicies], "Snowsight Admin > Security > Network Policies: review ALLOWED_IP_LIST entries for 0.0.0.0/0 or very broad CIDR ranges.", () => {
    const permissive: string[] = [];
    const emptyAllowLists: string[] = [];
    for (const row of networkPolicies.rows) {
      const name = rowValue(row, "NAME") ?? "(unnamed)";
      const allowed = parseIpList(rowValue(row, "ALLOWED_IP_LIST"));
      if (allowed.length === 0) emptyAllowLists.push(name);
      if (allowed.some(isPermissiveCidr)) permissive.push(name);
    }
    const evidence = { policy_count: networkPolicies.rows.length, permissive_policies: permissive, policies_without_allowed_ips: emptyAllowLists };
    if (networkPolicies.rows.length === 0) {
      return { status: "fail", summary: "NETWORK_POLICIES returned zero active policies, so no IP allowlist restricts access; an empty inventory fails this control.", evidence };
    }
    if (permissive.length > 0) {
      return { status: "fail", summary: `${permissive.length}/${networkPolicies.rows.length} network policies allow 0.0.0.0/0 or a CIDR broader than /8: ${permissive.slice(0, 10).join(", ")}.`, evidence };
    }
    if (emptyAllowLists.length === networkPolicies.rows.length) {
      return { status: "warn", summary: `All ${networkPolicies.rows.length} network policies have an empty ALLOWED_IP_LIST; they may rely on network rules that this view does not expose, so review the rules manually.`, evidence };
    }
    return { status: "pass", summary: `All ${networkPolicies.rows.length} network policies define restrictive allowlists without 0.0.0.0/0 entries.`, evidence };
  }));

  findings.push(evaluateControl(3, [users], "Snowsight Admin > Users & Roles: confirm MFA enrollment (HAS_MFA) for every enabled person user with a password, or an authentication policy with MFA_ENROLLMENT = REQUIRED.", () => {
    const userClasses = summarizeUserClasses(users.rows);
    const humans = users.rows.filter((row) => isHumanUser(row) && !isDisabledUser(row));
    const passwordHumans = humans.filter((row) => rowBoolean(row, "HAS_PASSWORD") === true);
    const withoutMfa = passwordHumans.filter((row) => rowBoolean(row, "HAS_MFA") !== true && rowBoolean(row, "EXT_AUTHN_DUO") !== true);
    const unknownFlags = passwordHumans.filter((row) => rowBoolean(row, "HAS_MFA") === undefined && rowBoolean(row, "EXT_AUTHN_DUO") === undefined);
    const evidence = {
      enabled_human_users: countIfFullyRead(users, humans.length),
      password_human_users: countIfFullyRead(users, passwordHumans.length),
      users_without_mfa: withoutMfa.slice(0, 50).map(userName),
      users_with_unknown_mfa_flags: countIfFullyRead(users, unknownFlags.length),
      user_classes: userClassesEvidence(users, userClasses),
    };
    const unrecognized = unrecognizedUserNote(userClasses);
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; MFA coverage cannot be established from an empty inventory (check ACCOUNT_USAGE latency and IMPORTED PRIVILEGES).", evidence };
    }
    if (withoutMfa.length > 0) {
      return { status: "fail", summary: `${withoutMfa.length}/${passwordHumans.length} enabled person users with passwords have neither HAS_MFA nor EXT_AUTHN_DUO set: ${withoutMfa.slice(0, 10).map(userName).join(", ")}.`, evidence };
    }
    if (unrecognized) {
      return { status: "warn", summary: `Every classified person user with a password reports MFA, but ${unrecognized}.`, evidence };
    }
    if (passwordHumans.length === 0) {
      return { status: "pass", summary: `No enabled person users${amongRowsRead(users)} hold a password (${humans.length} enabled person users rely on SSO, key pair, or other factors; ${userClasses.service} service-class users${amongRowsRead(users)} are assessed under control 5), so password MFA enforcement is not applicable and no unprotected password login exists.`, evidence };
    }
    return { status: "pass", summary: `All ${passwordHumans.length} enabled person users with passwords${amongRowsRead(users)} report HAS_MFA or EXT_AUTHN_DUO = true.`, evidence };
  }));

  findings.push(evaluateControl(4, [passwordPolicies, ...passwordReferences.outcomes], "the ACCOUNT_USAGE PASSWORD_POLICIES view and each policy's INFORMATION_SCHEMA POLICY_REFERENCES lookup, or Snowsight Admin > Security: confirm an account-level password policy with length, complexity, retry, and lockout settings.", () => {
    const accountRefs = passwordReferences.accountLevel;
    const attachedNames = new Set(accountRefs.map((row) => upper(rowValue(row, "POLICY_NAME"))));
    const weak: string[] = [];
    let strongAttached = 0;
    for (const row of passwordPolicies.rows) {
      const name = rowValue(row, "NAME") ?? "(unnamed)";
      const minLength = rowNumber(row, "PASSWORD_MIN_LENGTH") ?? 0;
      const complexity = [
        rowNumber(row, "PASSWORD_MIN_UPPER_CASE_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_LOWER_CASE_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_NUMERIC_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_SPECIAL_CHARS") ?? 0,
      ];
      const retries = rowNumber(row, "PASSWORD_MAX_RETRIES");
      const strong = minLength >= minPasswordLength && complexity.every((value) => value >= 1) && retries !== undefined && retries <= 10;
      if (!strong) weak.push(name);
      if (strong && attachedNames.has(upper(name))) strongAttached += 1;
    }
    const evidence = {
      policy_count: passwordPolicies.rows.length,
      ...policyReferenceEvidence(passwordReferences),
      weak_policies: weak,
      min_password_length_threshold: minPasswordLength,
    };
    if (passwordPolicies.rows.length === 0) {
      return { status: "fail", summary: "PASSWORD_POLICIES returned zero policies, so only Snowflake defaults apply; an empty inventory fails this control.", evidence };
    }
    if (accountRefs.length === 0 && passwordReferences.unchecked.length > 0) {
      return { status: "manual", summary: `${passwordPolicies.rows.length} password policies exist and no ACCOUNT-level attachment was found among the ${passwordReferences.outcomes.length} checked, but ${passwordReferences.unchecked.length} policies were not checked (lookup cap ${MAX_POLICY_REFERENCE_LOOKUPS} or missing qualified name); run POLICY_REFERENCES for the unchecked policies.`, evidence };
    }
    if (accountRefs.length === 0 && !hasFullVisibility(role)) {
      return { status: "manual", summary: `${passwordPolicies.rows.length} password policies exist but INFORMATION_SCHEMA.POLICY_REFERENCES returned no ACCOUNT-level attachment under role ${role ?? "(unknown)"}, which may lack APPLY PASSWORD POLICY visibility; confirm the account assignment as ACCOUNTADMIN.`, evidence };
    }
    if (accountRefs.length === 0) {
      return { status: "fail", summary: `${passwordPolicies.rows.length} password policies exist but INFORMATION_SCHEMA.POLICY_REFERENCES shows none attached at ACCOUNT level.`, evidence };
    }
    if (strongAttached === 0) {
      return { status: "warn", summary: `Account-level password policy is attached but does not meet the threshold (min length ${minPasswordLength}, one of each character class, retries <= 10): ${weak.join(", ")}.`, evidence };
    }
    if (passwordReferences.unchecked.length > 0) {
      return { status: "warn", summary: `An account-level password policy is attached and meets complexity thresholds, but ${passwordReferences.unchecked.length} of ${passwordPolicies.rows.length} policies were not checked for additional attachments.`, evidence };
    }
    return { status: "pass", summary: `An account-level password policy is attached and meets complexity thresholds (${accountRefs.length} account attachments across ${passwordReferences.outcomes.length} POLICY_REFERENCES lookups, ${passwordPolicies.rows.length} policies).`, evidence };
  }));

  findings.push(evaluateControl(5, [users], "Snowsight Admin > Users & Roles: confirm service-class users (TYPE = SERVICE, SERVICE_AGENT, or LEGACY_SERVICE) have RSA public keys or workload identity and no passwords.", () => {
    const userClasses = summarizeUserClasses(users.rows);
    const serviceUsers = users.rows.filter((row) => isServiceUser(row) && !isDisabledUser(row));
    const managedUsers = users.rows.filter((row) => classifyUser(row) === "snowflake_managed" && !isDisabledUser(row));
    const withoutKey = serviceUsers.filter((row) => rowBoolean(row, "HAS_RSA_PUBLIC_KEY") !== true && rowBoolean(row, "HAS_WORKLOAD_IDENTITY") !== true);
    const withPassword = serviceUsers.filter((row) => rowBoolean(row, "HAS_PASSWORD") === true);
    const evidence = {
      service_users: countIfFullyRead(users, serviceUsers.length),
      service_users_by_type: countBy(serviceUsers, (row) => upper(rowValue(row, "TYPE"))),
      snowflake_managed_service_users: managedUsers.slice(0, 50).map(userName),
      service_users_without_key_pair: withoutKey.slice(0, 50).map(userName),
      service_users_with_password: withPassword.slice(0, 50).map(userName),
      user_classes: userClassesEvidence(users, userClasses),
    };
    const unrecognized = unrecognizedUserNote(userClasses);
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; service account authentication cannot be assessed from an empty inventory.", evidence };
    }
    if (serviceUsers.length === 0 && !fullyRead(users)) {
      return { status: "manual", summary: `No user typed SERVICE, SERVICE_AGENT, or LEGACY_SERVICE was among the ${users.rows.length} user rows read, and the read stopped early, so the service account inventory is unread rather than empty. Read the full USERS view, then confirm each service-class user uses key-pair or workload identity authentication.${unrecognized ? ` ${unrecognized}.` : ""}`, evidence };
    }
    if (serviceUsers.length === 0) {
      return { status: "manual", summary: `None of the ${users.rows.length} users are typed SERVICE, SERVICE_AGENT, or LEGACY_SERVICE (${managedUsers.length} SNOWFLAKE_SERVICE users are Snowflake managed); classify automation accounts with TYPE = SERVICE and confirm each uses key-pair or workload identity authentication.${unrecognized ? ` ${unrecognized}.` : ""}`, evidence };
    }
    if (withoutKey.length > 0 || withPassword.length > 0) {
      return { status: "fail", summary: `${withoutKey.length}/${serviceUsers.length} service-class users lack an RSA public key or workload identity and ${withPassword.length} still hold a password.`, evidence };
    }
    if (unrecognized) {
      return { status: "warn", summary: `All ${serviceUsers.length} enabled service-class users${amongRowsRead(users)} authenticate with key pairs or workload identity, but ${unrecognized}.`, evidence };
    }
    return { status: "pass", summary: `All ${serviceUsers.length} enabled service-class users${amongRowsRead(users)} (SERVICE, SERVICE_AGENT, LEGACY_SERVICE) authenticate with key pairs or workload identity and hold no password${managedUsers.length > 0 ? `; ${managedUsers.length} SNOWFLAKE_SERVICE users are Snowflake managed and listed in evidence` : ""}.`, evidence };
  }));

  findings.push(evaluateControl(6, [integrations], "SHOW SECURITY INTEGRATIONS in Snowsight: confirm an enabled SAML2 (or External OAuth) security integration and SCIM provisioning.", () => {
    const security = integrations.rows.filter((row) => upper(rowValue(row, "category")) === "SECURITY");
    const saml = security.filter((row) => /SAML2/i.test(rowValue(row, "type") ?? ""));
    const enabledSaml = saml.filter((row) => rowBoolean(row, "enabled") === true);
    const scim = security.filter((row) => /SCIM/i.test(rowValue(row, "type") ?? "") && rowBoolean(row, "enabled") === true);
    const evidence = {
      security_integrations: security.map((row) => ({ name: rowValue(row, "name"), type: rowValue(row, "type"), enabled: rowValue(row, "enabled") })),
      enabled_saml_integrations: enabledSaml.map((row) => rowValue(row, "name")),
      enabled_scim_integrations: scim.map((row) => rowValue(row, "name")),
    };
    const visibility = hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`;
    if (saml.length === 0) {
      return { status: hasFullVisibility(role) ? "fail" : "manual", summary: `No SAML2 security integration was visible (${security.length} security integrations seen); an empty inventory does not satisfy SSO.${visibility}`, evidence };
    }
    if (enabledSaml.length === 0) {
      return { status: "fail", summary: `${saml.length} SAML2 integrations exist but none reports enabled = true.`, evidence };
    }
    return { status: "pass", summary: `${enabledSaml.length} enabled SAML2 integration(s) found${scim.length > 0 ? ` with ${scim.length} enabled SCIM integration(s)` : "; no enabled SCIM integration was visible"}.`, evidence };
  }));

  findings.push(evaluateControl(25, [sessionPolicies, ...sessionReferences.outcomes], "the ACCOUNT_USAGE SESSION_POLICIES view and each policy's INFORMATION_SCHEMA POLICY_REFERENCES lookup, or Snowsight Admin > Security: confirm an account-level session policy with idle timeouts.", () => {
    const accountRefs = sessionReferences.accountLevel;
    const attached = new Set(accountRefs.map((row) => upper(rowValue(row, "POLICY_NAME"))));
    const compliantAttached = sessionPolicies.rows.filter((row) => {
      const idle = rowNumber(row, "SESSION_IDLE_TIMEOUT_MINS");
      const uiIdle = rowNumber(row, "SESSION_UI_IDLE_TIMEOUT_MINS");
      return attached.has(upper(rowValue(row, "NAME"))) && idle !== undefined && idle <= maxSessionIdleMinutes && (uiIdle === undefined || uiIdle <= maxSessionIdleMinutes);
    });
    const evidence = {
      policy_count: sessionPolicies.rows.length,
      ...policyReferenceEvidence(sessionReferences),
      max_session_idle_minutes: maxSessionIdleMinutes,
      policies: sessionPolicies.rows.slice(0, 25).map((row) => ({ name: rowValue(row, "NAME"), idle: rowValue(row, "SESSION_IDLE_TIMEOUT_MINS"), ui_idle: rowValue(row, "SESSION_UI_IDLE_TIMEOUT_MINS") })),
    };
    if (sessionPolicies.rows.length === 0) {
      return { status: "fail", summary: "SESSION_POLICIES returned zero policies, so default 4-hour idle timeouts apply; an empty inventory fails this control.", evidence };
    }
    if (accountRefs.length === 0 && sessionReferences.unchecked.length > 0) {
      return { status: "manual", summary: `${sessionPolicies.rows.length} session policies exist and no ACCOUNT-level attachment was found among the ${sessionReferences.outcomes.length} checked, but ${sessionReferences.unchecked.length} policies were not checked (lookup cap ${MAX_POLICY_REFERENCE_LOOKUPS} or missing qualified name); run POLICY_REFERENCES for the unchecked policies.`, evidence };
    }
    if (accountRefs.length === 0 && !hasFullVisibility(role)) {
      return { status: "manual", summary: `${sessionPolicies.rows.length} session policies exist but INFORMATION_SCHEMA.POLICY_REFERENCES returned no ACCOUNT-level attachment under role ${role ?? "(unknown)"}, which may lack APPLY SESSION POLICY visibility; confirm the account assignment as ACCOUNTADMIN.`, evidence };
    }
    if (accountRefs.length === 0) {
      return { status: "fail", summary: `${sessionPolicies.rows.length} session policies exist but INFORMATION_SCHEMA.POLICY_REFERENCES shows none attached at ACCOUNT level.`, evidence };
    }
    if (compliantAttached.length === 0) {
      return { status: "warn", summary: `An account-level session policy is attached but its idle timeout exceeds ${maxSessionIdleMinutes} minutes or is unset.`, evidence };
    }
    if (sessionReferences.unchecked.length > 0) {
      return { status: "warn", summary: `Account-level session policy enforces idle timeouts within ${maxSessionIdleMinutes} minutes, but ${sessionReferences.unchecked.length} of ${sessionPolicies.rows.length} policies were not checked for attachments.`, evidence };
    }
    return { status: "pass", summary: `Account-level session policy enforces idle timeouts within ${maxSessionIdleMinutes} minutes (${accountRefs.length} account attachments across ${sessionReferences.outcomes.length} POLICY_REFERENCES lookups).`, evidence };
  }));

  return {
    title: "Snowflake network and authentication posture",
    area: "network-and-authentication",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      users_seen: rowsSeen(users),
      network_policies_seen: rowsSeen(networkPolicies),
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [
      session.outcome,
      showNetworkPolicies,
      networkParameter,
      networkReferences,
      networkPolicies,
      users,
      passwordPolicies,
      ...passwordReferences.outcomes,
      integrations,
      sessionPolicies,
      ...sessionReferences.outcomes,
    ].map(snapshotStatement),
  };
}

export async function assessSnowflakeAccessControl(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const maxAccountAdmins = clampNumber(options.maxAccountAdmins, DEFAULT_MAX_ACCOUNTADMINS, 1, 100);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const roleGrants = await collectStatement(client, "role_hierarchy_grants", SNOWFLAKE_STATEMENTS.roleGrants(limit), limit);
  const globalGrants = await collectStatement(client, "global_privilege_grants", SNOWFLAKE_STATEMENTS.globalPrivilegeGrants(limit), limit);
  const adminGrants = await collectStatement(client, "admin_role_grants_to_users", SNOWFLAKE_STATEMENTS.adminRoleGrantsToUsers(limit), limit);
  const roleUsage = await collectStatement(client, "role_usage_by_queries", SNOWFLAKE_STATEMENTS.roleUsageByQueries(lookbackDays), ROLE_USAGE_ROW_LIMIT);
  const directGrants = await collectStatement(client, "direct_user_grants", SNOWFLAKE_STATEMENTS.directUserGrants(limit), limit);
  const publicGrants = await collectStatement(client, "public_grants", SNOWFLAKE_STATEMENTS.publicGrants(limit), limit);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(7, [roleGrants, globalGrants], "Review the role graph in Snowsight (Admin > Users & Roles > Roles graph): no custom role should inherit ACCOUNTADMIN/SECURITYADMIN, every custom role should roll up to SYSADMIN, and MANAGE GRANTS should stay with SECURITYADMIN.", () => {
    const customRoles = new Set<string>();
    const grantedTo = new Map<string, Set<string>>();
    for (const row of roleGrants.rows) {
      const granted = upper(rowValue(row, "NAME"));
      const grantee = upper(rowValue(row, "GRANTEE_NAME"));
      if (!granted || !grantee) continue;
      if (!SYSTEM_ROLES.has(granted)) customRoles.add(granted);
      if (!SYSTEM_ROLES.has(grantee)) customRoles.add(grantee);
      const set = grantedTo.get(granted) ?? new Set<string>();
      set.add(grantee);
      grantedTo.set(granted, set);
    }
    const adminInheritedByCustom = [...PRIVILEGED_SYSTEM_ROLES].flatMap((adminRole) => [...(grantedTo.get(adminRole) ?? [])].filter((grantee) => !SYSTEM_ROLES.has(grantee)).map((grantee) => `${adminRole} -> ${grantee}`));
    const rolledUpToSysadmin = new Set<string>();
    const visit = (roleName: string, seen: Set<string>) => {
      for (const [granted, grantees] of grantedTo) {
        if (grantees.has(roleName) && !seen.has(granted)) {
          seen.add(granted);
          rolledUpToSysadmin.add(granted);
          visit(granted, seen);
        }
      }
    };
    visit("SYSADMIN", new Set());
    visit("ACCOUNTADMIN", new Set());
    const orphanRoles = [...customRoles].filter((custom) => !rolledUpToSysadmin.has(custom) && !(grantedTo.get(custom)?.size));
    const riskyGlobal = globalGrants.rows.filter((row) => {
      const grantee = upper(rowValue(row, "GRANTEE_NAME"));
      return !SYSTEM_ROLES.has(grantee) && /MANAGE GRANTS|CREATE USER|CREATE ROLE|MANAGE ACCOUNT|APPLY MASKING POLICY|APPLY ROW ACCESS POLICY|EXECUTE TASK|MONITOR USAGE|IMPORT SHARE/i.test(rowValue(row, "PRIVILEGE") ?? "");
    });
    const evidence = {
      role_to_role_grants: roleGrants.rows.length,
      custom_roles: customRoles.size,
      admin_roles_inherited_by_custom_roles: adminInheritedByCustom,
      custom_roles_not_rolled_up: orphanRoles.slice(0, 50),
      sensitive_global_privileges_on_custom_roles: riskyGlobal.slice(0, 50).map((row) => `${rowValue(row, "PRIVILEGE")} -> ${rowValue(row, "GRANTEE_NAME")}`),
    };
    if (roleGrants.rows.length === 0) {
      return { status: "manual", summary: "GRANTS_TO_ROLES returned zero role-to-role grants; a hierarchy cannot be evaluated from an empty graph (check ACCOUNT_USAGE latency and IMPORTED PRIVILEGES).", evidence };
    }
    if (adminInheritedByCustom.length > 0) {
      return { status: "fail", summary: `${adminInheritedByCustom.length} custom roles inherit ACCOUNTADMIN or SECURITYADMIN: ${adminInheritedByCustom.slice(0, 10).join(", ")}.`, evidence };
    }
    if (riskyGlobal.length > 0 || orphanRoles.length > 0) {
      return { status: "warn", summary: `${riskyGlobal.length} sensitive global privileges sit on custom roles and ${orphanRoles.length} custom roles do not roll up to SYSADMIN.`, evidence };
    }
    return { status: "pass", summary: `Role graph with ${customRoles.size} custom roles has no admin inheritance, no orphaned roles, and no sensitive global privileges on custom roles.`, evidence };
  }));

  findings.push(evaluateControl(8, [adminGrants], "SHOW GRANTS OF ROLE ACCOUNTADMIN in Snowsight: confirm at least two and no more than a handful of named users hold ACCOUNTADMIN.", () => {
    const accountAdmins = adminGrants.rows.filter((row) => upper(rowValue(row, "ROLE")) === "ACCOUNTADMIN").map((row) => rowValue(row, "GRANTEE_NAME") ?? "(unknown)");
    const securityAdmins = adminGrants.rows.filter((row) => upper(rowValue(row, "ROLE")) === "SECURITYADMIN").map((row) => rowValue(row, "GRANTEE_NAME") ?? "(unknown)");
    const evidence = { accountadmin_users: accountAdmins, securityadmin_users: securityAdmins, max_accountadmins: maxAccountAdmins };
    if (accountAdmins.length === 0) {
      return { status: "manual", summary: "GRANTS_TO_USERS shows zero ACCOUNTADMIN grantees; Snowflake always has at least one, so the view is latent or restricted and the membership must be confirmed manually.", evidence };
    }
    if (accountAdmins.length > maxAccountAdmins) {
      return { status: "fail", summary: `${accountAdmins.length} users hold ACCOUNTADMIN, above the threshold of ${maxAccountAdmins}: ${accountAdmins.slice(0, 10).join(", ")}.`, evidence };
    }
    if (accountAdmins.length === 1) {
      return { status: "warn", summary: `Only one user holds ACCOUNTADMIN (${accountAdmins[0]}); Snowflake recommends at least two to avoid lockout.`, evidence };
    }
    return { status: "pass", summary: `${accountAdmins.length} users hold ACCOUNTADMIN, within the threshold of ${maxAccountAdmins}.`, evidence };
  }));

  findings.push(evaluateControl(9, [roleUsage], `Query QUERY_HISTORY for the last ${lookbackDays} days grouped by ROLE_NAME and confirm ACCOUNTADMIN is not used for routine SELECT/DML workloads.`, () => {
    const total = roleUsage.rows.reduce((sum, row) => sum + (rowNumber(row, "QUERY_COUNT") ?? 0), 0);
    const adminRow = roleUsage.rows.find((row) => upper(rowValue(row, "ROLE_NAME")) === "ACCOUNTADMIN");
    const adminCount = adminRow ? rowNumber(adminRow, "QUERY_COUNT") ?? 0 : 0;
    const adminUsers = adminRow ? rowNumber(adminRow, "USER_COUNT") ?? 0 : 0;
    const share = total > 0 ? adminCount / total : 0;
    const evidence = { lookback_days: lookbackDays, routine_queries: total, accountadmin_queries: adminCount, accountadmin_users: adminUsers, accountadmin_share: Number(share.toFixed(4)) };
    if (total === 0) {
      return { status: "manual", summary: `QUERY_HISTORY shows zero routine queries in the last ${lookbackDays} days; usage cannot be assessed from an empty window (view latency is up to 45 minutes).`, evidence };
    }
    if (adminCount === 0) {
      return { status: "pass", summary: `ACCOUNTADMIN ran none of the ${total} routine queries in the last ${lookbackDays} days.`, evidence };
    }
    if (share >= 0.1 || adminCount >= 100) {
      return { status: "fail", summary: `ACCOUNTADMIN ran ${adminCount}/${total} routine queries (${(share * 100).toFixed(1)}%) across ${adminUsers} users in the last ${lookbackDays} days.`, evidence };
    }
    return { status: "warn", summary: `ACCOUNTADMIN ran ${adminCount}/${total} routine queries (${(share * 100).toFixed(1)}%) in the last ${lookbackDays} days; move that work to functional roles.`, evidence };
  }));

  findings.push(evaluateControl(10, [directGrants], "Review GRANTS_TO_ROLES WHERE GRANTED_TO = 'USER' in Snowsight and confirm no privileges are granted directly to users.", () => {
    const evidence = { direct_grants: directGrants.rows.length, samples: directGrants.rows.slice(0, 25).map((row) => `${rowValue(row, "PRIVILEGE")} ON ${rowValue(row, "GRANTED_ON")} ${rowValue(row, "NAME")} -> ${rowValue(row, "GRANTEE_NAME")}`) };
    if (directGrants.rows.length === 0) {
      return { status: "pass", summary: "GRANTS_TO_ROLES was readable and lists no privileges granted directly to users; for this control an empty result is the compliant state.", evidence };
    }
    return { status: "fail", summary: `${directGrants.rows.length} privileges are granted directly to users instead of roles.`, evidence };
  }));

  findings.push(evaluateControl(16, [publicGrants], "Review grants to the PUBLIC role in Snowsight and confirm no data objects are exposed to every user.", () => {
    const sensitive = publicGrants.rows.filter((row) => SENSITIVE_OBJECT_DOMAINS.has(upper(rowValue(row, "GRANTED_ON"))));
    const evidence = { public_grants: publicGrants.rows.length, sensitive_public_grants: sensitive.slice(0, 50).map((row) => `${rowValue(row, "PRIVILEGE")} ON ${rowValue(row, "GRANTED_ON")} ${rowValue(row, "NAME")}`) };
    if (publicGrants.rows.length === 0) {
      return { status: "pass", summary: "GRANTS_TO_ROLES was readable and lists no privileges granted to PUBLIC; for this control an empty result is the compliant state.", evidence };
    }
    if (sensitive.length > 0) {
      return { status: "fail", summary: `${sensitive.length}/${publicGrants.rows.length} PUBLIC grants target data objects (tables, views, schemas, databases, or stages).`, evidence };
    }
    return { status: "warn", summary: `${publicGrants.rows.length} PUBLIC grants exist on non-data objects (for example warehouses); review whether they are intentional.`, evidence };
  }));

  return {
    title: "Snowflake access control posture",
    area: "access-control",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      lookback_days: lookbackDays,
      role_grants_seen: rowsSeen(roleGrants),
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, roleGrants, globalGrants, adminGrants, roleUsage, directGrants, publicGrants].map(snapshotStatement),
  };
}

export async function assessSnowflakeMonitoringAndLifecycle(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const staleUserDays = clampNumber(options.staleUserDays, DEFAULT_STALE_USER_DAYS, 1, 3650);
  const failedLoginThreshold = clampNumber(options.failedLoginThreshold, DEFAULT_FAILED_LOGIN_THRESHOLD, 1, 100_000);
  const maxAutoSuspendSeconds = clampNumber(options.maxAutoSuspendSeconds, DEFAULT_MAX_AUTO_SUSPEND_SECONDS, 1, 86_400);
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 0, 90);
  const limit = config.rowLimit;
  const now = new Date();
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const loginOutcomes = await collectStatement(client, "login_outcomes", SNOWFLAKE_STATEMENTS.loginOutcomes(lookbackDays));
  const failedLogins = await collectStatement(client, "failed_logins", SNOWFLAKE_STATEMENTS.failedLogins(lookbackDays), FAILED_LOGIN_ROW_LIMIT);
  const users = await collectStatement(client, "users", SNOWFLAKE_STATEMENTS.users(limit), limit);
  const retention = await collectStatement(client, "data_retention_parameter", SNOWFLAKE_STATEMENTS.dataRetentionParameter);
  const accessHistory = await collectStatement(client, "access_history_probe", SNOWFLAKE_STATEMENTS.accessHistoryProbe);
  const warehouses = await collectStatement(client, "show_warehouses", SNOWFLAKE_STATEMENTS.showWarehouses, SHOW_ROW_CAP);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(11, [loginOutcomes, failedLogins], `Query LOGIN_HISTORY for the last ${lookbackDays} days (IS_SUCCESS = 'NO') and confirm failed logins are monitored and alerted.`, () => {
    const successes = loginOutcomes.rows.filter((row) => upper(rowValue(row, "IS_SUCCESS")) === "YES").reduce((sum, row) => sum + (rowNumber(row, "EVENT_COUNT") ?? 0), 0);
    const failures = loginOutcomes.rows.filter((row) => upper(rowValue(row, "IS_SUCCESS")) === "NO").reduce((sum, row) => sum + (rowNumber(row, "EVENT_COUNT") ?? 0), 0);
    const excessive = failedLogins.rows.filter((row) => (rowNumber(row, "FAILURE_COUNT") ?? 0) >= failedLoginThreshold);
    const evidence = {
      lookback_days: lookbackDays,
      successful_logins: countIfFullyRead(loginOutcomes, successes),
      failed_logins: countIfFullyRead(loginOutcomes, failures),
      threshold: failedLoginThreshold,
      excessive_sources: excessive.slice(0, 50).map((row) => ({ user: rowValue(row, "USER_NAME"), ip: rowValue(row, "CLIENT_IP"), failures: rowValue(row, "FAILURE_COUNT"), last_error: rowValue(row, "LAST_ERROR") })),
    };
    if (successes + failures === 0 && !fullyRead(loginOutcomes)) {
      return { status: "manual", summary: `No LOGIN_HISTORY outcome row for the last ${lookbackDays} days was among the rows read, and the read stopped early, so the login window is unread rather than empty.`, evidence };
    }
    if (successes + failures === 0) {
      return { status: "manual", summary: `LOGIN_HISTORY returned zero events for the last ${lookbackDays} days; monitoring cannot be evaluated from an empty window (view latency is up to 2 hours).`, evidence };
    }
    if (excessive.length > 0) {
      return { status: "fail", summary: `${excessive.length} user/IP sources exceeded ${failedLoginThreshold} failed logins in ${lookbackDays} days (${failures} failures${amongRowsRead(loginOutcomes)}).`, evidence };
    }
    return { status: "pass", summary: `${failures} failed logins across ${successes + failures} login events${amongRowsRead(loginOutcomes)} in ${lookbackDays} days; no source${amongRowsRead(failedLogins)} exceeded the ${failedLoginThreshold}-failure threshold.`, evidence };
  }));

  findings.push(evaluateControl(12, [users], `Review enabled users whose LAST_SUCCESS_LOGIN is older than ${staleUserDays} days or NULL and disable or remove them.`, () => {
    const userClasses = summarizeUserClasses(users.rows);
    const humans = users.rows.filter((row) => isHumanUser(row) && !isDisabledUser(row));
    const staleServiceUsers = users.rows.filter((row) => {
      if (!isServiceUser(row) || isDisabledUser(row)) return false;
      const lastLogin = parseSnowflakeTimestamp(rowValue(row, "LAST_SUCCESS_LOGIN"));
      return lastLogin !== undefined && daysSince(lastLogin, now) > staleUserDays;
    });
    const stale: string[] = [];
    const neverOrUnknown: string[] = [];
    for (const row of humans) {
      const lastLogin = parseSnowflakeTimestamp(rowValue(row, "LAST_SUCCESS_LOGIN"));
      if (!lastLogin) {
        neverOrUnknown.push(userName(row));
        continue;
      }
      if (daysSince(lastLogin, now) > staleUserDays) stale.push(userName(row));
    }
    const evidence = {
      enabled_human_users: countIfFullyRead(users, humans.length),
      stale_user_days: staleUserDays,
      stale_users: stale.slice(0, 50),
      users_without_login_timestamp: neverOrUnknown.slice(0, 50),
      users_without_login_timestamp_count: countIfFullyRead(users, neverOrUnknown.length),
      stale_service_class_users: staleServiceUsers.slice(0, 50).map(userName),
      user_classes: userClassesEvidence(users, userClasses),
    };
    const unrecognized = unrecognizedUserNote(userClasses);
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; stale-user review cannot be performed on an empty inventory.", evidence };
    }
    if (stale.length > 0) {
      return { status: "fail", summary: `${stale.length}/${humans.length} enabled person users have not logged in for more than ${staleUserDays} days; ${neverOrUnknown.length} more have no LAST_SUCCESS_LOGIN and were not counted as active.`, evidence };
    }
    if (neverOrUnknown.length > 0) {
      return { status: "warn", summary: `No enabled person user${amongRowsRead(users)} exceeded ${staleUserDays} days since login, but ${neverOrUnknown.length}/${humans.length} have a NULL LAST_SUCCESS_LOGIN (never logged in or outside the one-year retention) and must be reviewed.`, evidence };
    }
    if (unrecognized) {
      return { status: "warn", summary: `All ${humans.length} enabled person users${amongRowsRead(users)} logged in within ${staleUserDays} days, but ${unrecognized}.`, evidence };
    }
    if (staleServiceUsers.length > 0) {
      return { status: "warn", summary: `All ${humans.length} enabled person users${amongRowsRead(users)} logged in within ${staleUserDays} days, but ${staleServiceUsers.length} enabled service-class users have not authenticated in that window and should be reviewed for decommissioning.`, evidence };
    }
    return { status: "pass", summary: `All ${humans.length} enabled person users${amongRowsRead(users)} logged in within ${staleUserDays} days (${serviceClassLoginNote(users, userClasses.service)}).`, evidence };
  }));

  findings.push(evaluateControl(13, [retention], "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT and confirm ACCESS_HISTORY/QUERY_HISTORY (365-day fixed retention) are exported to long-term storage if longer retention is required.", () => {
    const parameter = parameterValue(retention, "DATA_RETENTION_TIME_IN_DAYS");
    const value = asNumber(parameter.value);
    const evidence = { data_retention_time_in_days: parameter.value ?? null, level: parameter.level ?? null, min_retention_days: minRetentionDays, access_history_readable: accessHistory.status === "ok", access_history_events_7d: accessHistory.rows[0] ? rowValue(accessHistory.rows[0], "EVENT_COUNT") : null };
    if (!parameter.found || value === undefined) {
      return { status: "manual", summary: "DATA_RETENTION_TIME_IN_DAYS was not present in the SHOW PARAMETERS output; confirm the account retention setting manually.", evidence };
    }
    if (value < minRetentionDays) {
      return { status: "fail", summary: `Account DATA_RETENTION_TIME_IN_DAYS is ${value}, below the ${minRetentionDays}-day threshold.`, evidence };
    }
    const accessHistoryNote = accessHistory.status === "ok" ? " and ACCESS_HISTORY plus QUERY_HISTORY are readable with Snowflake's fixed 365-day retention" : "";
    return { status: "pass", summary: `Account DATA_RETENTION_TIME_IN_DAYS is ${value}${accessHistoryNote}.`, evidence };
  }, { optional: [{ outcome: accessHistory, unchecked: "ACCESS_HISTORY was not readable and object access auditing could not be confirmed (needs Enterprise Edition and IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE)" }] }));

  findings.push(evaluateControl(24, [warehouses], `SHOW WAREHOUSES: confirm every warehouse has auto_suspend set to ${maxAutoSuspendSeconds} seconds or less.`, () => {
    const never: string[] = [];
    const tooLong: string[] = [];
    for (const row of warehouses.rows) {
      const name = rowValue(row, "name") ?? "(unnamed)";
      const autoSuspend = rowValue(row, "auto_suspend");
      const seconds = asNumber(autoSuspend);
      if (autoSuspend === null || /^null$/i.test(autoSuspend) || seconds === 0) {
        never.push(name);
      } else if (seconds === undefined || seconds > maxAutoSuspendSeconds) {
        tooLong.push(name);
      }
    }
    const evidence = { warehouses: warehouses.rows.length, never_suspend: never, auto_suspend_above_threshold: tooLong, max_auto_suspend_seconds: maxAutoSuspendSeconds };
    if (warehouses.rows.length === 0) {
      return { status: "manual", summary: `SHOW WAREHOUSES returned zero warehouses visible to role ${role ?? "(unknown)"}; confirm the inventory with a role that can see all warehouses.`, evidence };
    }
    if (never.length > 0) {
      return { status: "fail", summary: `${never.length}/${warehouses.rows.length} warehouses never auto-suspend: ${never.slice(0, 10).join(", ")}.`, evidence };
    }
    if (tooLong.length > 0) {
      return { status: "warn", summary: `${tooLong.length}/${warehouses.rows.length} warehouses auto-suspend after more than ${maxAutoSuspendSeconds} seconds.`, evidence };
    }
    return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `All ${warehouses.rows.length} visible warehouses auto-suspend within ${maxAutoSuspendSeconds} seconds.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW WAREHOUSES")}`}`, evidence };
  }, { optional: [{ outcome: session.outcome, unchecked: unverifiedRoleNote("SHOW WAREHOUSES") }] }));

  return {
    title: "Snowflake monitoring and lifecycle posture",
    area: "monitoring-and-lifecycle",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      lookback_days: lookbackDays,
      users_seen: rowsSeen(users),
      warehouses_seen: rowsSeen(warehouses),
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, loginOutcomes, failedLogins, users, retention, accessHistory, warehouses].map(snapshotStatement),
  };
}

export async function assessSnowflakeDataProtection(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 0, 90);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const maskingCount = await collectStatement(client, "masking_policy_count", SNOWFLAKE_STATEMENTS.maskingPolicyCount);
  const maskingReferences = await collectStatement(client, "masking_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("MASKING_POLICY", limit), limit);
  const rowAccessCount = await collectStatement(client, "row_access_policy_count", SNOWFLAKE_STATEMENTS.rowAccessPolicyCount);
  const rowAccessReferences = await collectStatement(client, "row_access_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("ROW_ACCESS_POLICY", limit), limit);
  const tagReferences = await collectStatement(client, "tag_references", SNOWFLAKE_STATEMENTS.tagReferenceSummary, TAG_REFERENCE_ROW_LIMIT);
  const stageParameters = await collectStatement(client, "stage_parameters", SNOWFLAKE_STATEMENTS.stageParameters);
  const unloadParameters = await collectStatement(client, "unload_parameters", SNOWFLAKE_STATEMENTS.unloadParameters);
  const databases = await collectStatement(client, "show_databases", SNOWFLAKE_STATEMENTS.showDatabases, SHOW_ROW_CAP);
  const shares = await collectStatement(client, "show_shares", SNOWFLAKE_STATEMENTS.showShares, SHOW_ROW_CAP);
  const integrations = await collectStatement(client, "show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations, SHOW_ROW_CAP);
  const replicationGroups = await collectStatement(client, "show_replication_groups", SNOWFLAKE_STATEMENTS.showReplicationGroups, SHOW_ROW_CAP);

  const findings: SnowflakeFinding[] = [];
  const tagSummary = tagReferences.status === "ok" ? tagReferences.rows.slice(0, 25).map((row) => ({ tag: `${rowValue(row, "TAG_DATABASE")}.${rowValue(row, "TAG_SCHEMA")}.${rowValue(row, "TAG_NAME")}`, references: rowValue(row, "REFERENCE_COUNT") })) : null;

  findings.push(evaluateControl(14, [maskingCount, maskingReferences], "Snowsight Data > Governance: confirm masking policies exist and are assigned to every sensitive column (POLICY_REFERENCES WHERE POLICY_KIND = 'MASKING_POLICY').", () => {
    const policies = rowNumber(maskingCount.rows[0] ?? {}, "POLICY_COUNT") ?? 0;
    const active = maskingReferences.rows.filter((row) => upper(rowValue(row, "POLICY_STATUS")) === "ACTIVE" || rowValue(row, "POLICY_STATUS") === null);
    const broken = maskingReferences.rows.length - active.length;
    const evidence = { masking_policies: policies, masking_references: maskingReferences.rows.length, references_with_problems: broken, tag_classification_summary: tagSummary, tag_references_readable: tagReferences.status === "ok" };
    if (policies === 0) {
      return { status: "fail", summary: "MASKING_POLICIES lists zero active masking policies, so no column is protected by dynamic data masking; an empty inventory fails this control.", evidence };
    }
    if (maskingReferences.rows.length === 0) {
      return { status: "fail", summary: `${policies} masking policies exist but POLICY_REFERENCES shows none assigned to any column or tag.`, evidence };
    }
    if (broken > 0) {
      return { status: "warn", summary: `${maskingReferences.rows.length} masking policy references exist but ${broken} are not ACTIVE (conflicting or mismatched assignments).`, evidence };
    }
    return { status: "pass", summary: `${policies} masking policies are assigned through ${maskingReferences.rows.length} active column or tag references${tagSummary && tagSummary.length > 0 ? ` alongside ${tagSummary.length} classification tags` : ""}.`, evidence };
  }, { optional: [{ outcome: tagReferences, unchecked: "classification tag coverage (TAG_REFERENCES) was not checked and tag-based masking assignments could not be confirmed" }] }));

  findings.push(evaluateControl(15, [rowAccessCount, rowAccessReferences], "Snowsight Data > Governance: confirm row access policies exist and are assigned to sensitive tables (POLICY_REFERENCES WHERE POLICY_KIND = 'ROW_ACCESS_POLICY').", () => {
    const policies = rowNumber(rowAccessCount.rows[0] ?? {}, "POLICY_COUNT") ?? 0;
    const evidence = { row_access_policies: policies, row_access_references: rowAccessReferences.rows.length, protected_objects: rowAccessReferences.rows.slice(0, 25).map((row) => `${rowValue(row, "REF_DATABASE_NAME")}.${rowValue(row, "REF_SCHEMA_NAME")}.${rowValue(row, "REF_ENTITY_NAME")}`) };
    if (policies === 0) {
      return { status: "fail", summary: "ROW_ACCESS_POLICIES lists zero active policies, so no table has row-level security; an empty inventory fails this control.", evidence };
    }
    if (rowAccessReferences.rows.length === 0) {
      return { status: "fail", summary: `${policies} row access policies exist but none is assigned to a table or view.`, evidence };
    }
    return { status: "pass", summary: `${policies} row access policies protect ${rowAccessReferences.rows.length} table or view references.`, evidence };
  }));

  findings.push(evaluateControl(17, [stageParameters], "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%' IN ACCOUNT: confirm both creation and operation parameters are true.", () => {
    const creation = parameterValue(stageParameters, "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION");
    const operation = parameterValue(stageParameters, "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION");
    const evidence = { require_storage_integration_for_stage_creation: creation.value ?? null, require_storage_integration_for_stage_operation: operation.value ?? null };
    if (!creation.found && !operation.found) {
      return { status: "manual", summary: "Neither REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_* parameter appeared in SHOW PARAMETERS output; confirm them manually.", evidence };
    }
    const creationOn = asBoolean(creation.value) === true;
    const operationOn = asBoolean(operation.value) === true;
    if (creationOn && operationOn) {
      return { status: "pass", summary: "Storage integrations are required for both stage creation and stage operations.", evidence };
    }
    if (creationOn || operationOn) {
      return { status: "warn", summary: `Only one storage integration requirement is enabled (creation=${creation.value ?? "unset"}, operation=${operation.value ?? "unset"}).`, evidence };
    }
    return { status: "fail", summary: "Storage integrations are not required for stage creation or operations, so stages can use raw cloud credentials.", evidence };
  }));

  findings.push(evaluateControl(18, [unloadParameters], "SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%' IN ACCOUNT: confirm PREVENT_UNLOAD_TO_INLINE_URL and PREVENT_UNLOAD_TO_INTERNAL_STAGES are true.", () => {
    const inlineUrl = parameterValue(unloadParameters, "PREVENT_UNLOAD_TO_INLINE_URL");
    const internalStages = parameterValue(unloadParameters, "PREVENT_UNLOAD_TO_INTERNAL_STAGES");
    const evidence = { prevent_unload_to_inline_url: inlineUrl.value ?? null, prevent_unload_to_internal_stages: internalStages.value ?? null };
    if (!inlineUrl.found && !internalStages.found) {
      return { status: "manual", summary: "Neither PREVENT_UNLOAD_TO_* parameter appeared in SHOW PARAMETERS output; confirm them manually.", evidence };
    }
    const inlineOn = asBoolean(inlineUrl.value) === true;
    const internalOn = asBoolean(internalStages.value) === true;
    if (inlineOn && internalOn) {
      return { status: "pass", summary: "Unloads to inline URLs and internal stages are both prevented.", evidence };
    }
    if (inlineOn || internalOn) {
      return { status: "warn", summary: `Only one unload restriction is enabled (inline_url=${inlineUrl.value ?? "unset"}, internal_stages=${internalStages.value ?? "unset"}).`, evidence };
    }
    return { status: "fail", summary: "Neither PREVENT_UNLOAD_TO_INLINE_URL nor PREVENT_UNLOAD_TO_INTERNAL_STAGES is enabled.", evidence };
  }));

  findings.push(evaluateControl(19, [databases], `SHOW DATABASES: confirm retention_time is at least ${minRetentionDays} day(s) for every customer database.`, () => {
    const customer = databases.rows.filter((row) => !/IMPORTED DATABASE|APPLICATION/i.test(rowValue(row, "kind") ?? "") && upper(rowValue(row, "name")) !== "SNOWFLAKE");
    const below = customer.filter((row) => (asNumber(rowValue(row, "retention_time")) ?? 0) < minRetentionDays).map((row) => rowValue(row, "name") ?? "(unnamed)");
    const evidence = { databases_seen: databases.rows.length, customer_databases: customer.length, below_threshold: below.slice(0, 50), min_retention_days: minRetentionDays };
    if (databases.rows.length === 0) {
      return { status: "manual", summary: `SHOW DATABASES returned zero databases visible to role ${role ?? "(unknown)"}; confirm Time Travel retention with a role that can see all databases.`, evidence };
    }
    if (below.length > 0) {
      return { status: "fail", summary: `${below.length}/${customer.length} customer databases have retention_time below ${minRetentionDays}: ${below.slice(0, 10).join(", ")}.`, evidence };
    }
    return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `All ${customer.length} visible customer databases retain Time Travel for at least ${minRetentionDays} day(s).${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW DATABASES")}`}`, evidence };
  }, { optional: [{ outcome: session.outcome, unchecked: unverifiedRoleNote("SHOW DATABASES") }] }));

  findings.push(finding(20, "manual", "Not verifiable through SQL: Tri-Secret Secure is enabled by Snowflake Support for Business Critical (or higher) accounts. Collect the Snowflake Support case or Snowsight Admin > Accounts edition evidence and the composite master key confirmation.", { edition_requirement: "Business Critical or higher", sql_verifiable: false }));

  findings.push(finding(21, "manual", "Not verifiable through SQL: customer-managed key enrollment is confirmed through Snowflake Support and your cloud KMS; the platform-info and CMK system functions only return VPC or VNet identifiers and setup templates, so none was run. Collect the KMS key policy and rotation evidence from AWS KMS, Azure Key Vault, or Google Cloud KMS.", { edition_requirement: "Business Critical or higher", sql_verifiable: false }));

  findings.push(evaluateControl(22, [shares], "SHOW SHARES as ACCOUNTADMIN: review every OUTBOUND share, its consumer accounts (to column), and any listing_global_name exposure.", () => {
    const outbound = shares.rows.filter((row) => upper(rowValue(row, "kind")) === "OUTBOUND");
    const listings = outbound.filter((row) => Boolean(rowValue(row, "listing_global_name")));
    const evidence = {
      shares_seen: shares.rows.length,
      outbound_shares: outbound.slice(0, 50).map((row) => ({ name: rowValue(row, "name"), database: rowValue(row, "database_name"), to: rowValue(row, "to"), listing: rowValue(row, "listing_global_name") })),
      listing_backed_shares: listings.length,
      replication_groups_visible: replicationGroups.status === "ok" ? replicationGroups.rows.length : null,
    };
    const fullShareInventory = role === SHARE_INVENTORY_ROLE;
    if (outbound.length > 0) {
      return { status: "warn", summary: `${outbound.length} OUTBOUND shares expose data to other accounts${listings.length > 0 ? ` and ${listings.length} are attached to marketplace or private listings` : ""}; confirm each consumer is approved.${fullShareInventory ? "" : ` Only shares owned by role ${role ?? "(unknown)"} are listed, so the inventory is partial; re-run as ${SHARE_INVENTORY_ROLE}.`}`, evidence };
    }
    if (!fullShareInventory) {
      return { status: "manual", summary: `SHOW SHARES under role ${role ?? "(unknown)"} returned ${shares.rows.length} rows and no OUTBOUND share, but only ${SHARE_INVENTORY_ROLE} lists every outbound share: other roles see only shares they own and roles without IMPORT SHARE receive empty results, so this is indistinguishable from a denied read. Re-run SHOW SHARES as ${SHARE_INVENTORY_ROLE} to confirm the outbound inventory.`, evidence };
    }
    return { status: "pass", summary: `SHOW SHARES was readable under ${SHARE_INVENTORY_ROLE} and lists no OUTBOUND shares (${shares.rows.length} inbound shares seen); for this control an empty outbound inventory is compliant.`, evidence };
  }, {
    optional: [
      { outcome: replicationGroups, unchecked: "replication groups that copy data to other accounts (SHOW REPLICATION GROUPS) were not checked" },
      { outcome: session.outcome, unchecked: `the active role could not be verified as ${SHARE_INVENTORY_ROLE}, the only role that lists every outbound share`, demoteTo: "manual" },
    ],
  }));

  findings.push(evaluateControl(23, [integrations], "SHOW API INTEGRATIONS and SHOW EXTERNAL ACCESS INTEGRATIONS: confirm every enabled integration and external function is approved.", () => {
    const external = integrations.rows.filter((row) => /^(API|EXTERNAL_ACCESS|EXTERNAL ACCESS)$/i.test(rowValue(row, "category") ?? "") || /API|EXTERNAL_ACCESS/i.test(rowValue(row, "type") ?? ""));
    const enabled = external.filter((row) => rowBoolean(row, "enabled") === true);
    const evidence = { integrations_seen: integrations.rows.length, external_integrations: external.map((row) => ({ name: rowValue(row, "name"), type: rowValue(row, "type"), category: rowValue(row, "category"), enabled: rowValue(row, "enabled") })) };
    if (integrations.rows.length === 0 && !hasFullVisibility(role)) {
      return { status: "manual", summary: `SHOW INTEGRATIONS returned zero rows under role ${role ?? "(unknown)"}; ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`, evidence };
    }
    if (enabled.length === 0) {
      return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `No enabled API or external access integrations were found among ${integrations.rows.length} integrations; for this control an empty inventory is compliant when read with full visibility.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`}`, evidence };
    }
    return { status: "warn", summary: `${enabled.length} enabled API or external access integrations allow outbound calls: ${enabled.slice(0, 10).map((row) => rowValue(row, "name")).join(", ")}; confirm each is approved.`, evidence };
  }, { optional: [{ outcome: session.outcome, unchecked: unverifiedRoleNote("SHOW INTEGRATIONS") }] }));

  return {
    title: "Snowflake data protection posture",
    area: "data-protection",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      databases_seen: rowsSeen(databases),
      shares_seen: rowsSeen(shares),
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, maskingCount, maskingReferences, rowAccessCount, rowAccessReferences, tagReferences, stageParameters, unloadParameters, databases, shares, integrations, replicationGroups].map(snapshotStatement),
  };
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "snowflake";
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

function formatAccessCheckText(result: SnowflakeAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.rowCount === undefined ? "-" : String(surface.rowCount),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Snowflake access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Rows", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SnowflakeAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary.length > 160 ? `${item.summary.slice(0, 157)}...` : item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  const problems = result.statements.filter((statement) => statement.status !== "ok");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(problems.length > 0 ? ["", "Statements that did not complete:", ...problems.map((problem) => `- ${describeOutcomeProblem(problem)}`)] : []),
  ].join("\n");
}

function frameworkPrefix(framework: (typeof SNOWFLAKE_FRAMEWORKS)[number]): string {
  return `${framework} `;
}

function buildFrameworkReport(framework: (typeof SNOWFLAKE_FRAMEWORKS)[number], findings: SnowflakeFinding[]): string {
  const rows = findings.map((item) => [
    item.mappings.find((entry) => entry.startsWith(frameworkPrefix(framework)))?.slice(framework.length + 1) ?? "-",
    item.id,
    item.status.toUpperCase(),
    item.severity.toUpperCase(),
    item.title,
  ]);
  return [
    `# ${framework} Mapping Report`,
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    formatTable([`${framework} Requirement`, "Finding", "Status", "Severity", "Title"], rows),
    "",
    "Statuses: PASS (evidence observed), WARN (partial or review needed), FAIL (control not met), MANUAL (evidence must be collected by a human).",
  ].join("\n");
}

function buildUnifiedMatrix(findings: SnowflakeFinding[]): string {
  const rows = findings.map((item) => [item.id, item.status.toUpperCase(), item.title, ...SNOWFLAKE_FRAMEWORKS.map((framework) => item.mappings.find((entry) => entry.startsWith(frameworkPrefix(framework)))?.slice(framework.length + 1) ?? "-")]);
  return ["# Unified Compliance Matrix", "", formatTable(["Finding", "Status", "Title", ...SNOWFLAKE_FRAMEWORKS], rows)].join("\n");
}

function buildExecutiveSummary(config: SnowflakeResolvedConfig, access: SnowflakeAccessCheckResult, assessments: SnowflakeAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeStatuses(findings);
  return [
    "# Snowflake Security Inspector Executive Summary",
    "",
    `Account: ${access.account}`,
    access.authentication === "confirmed"
      ? `Authenticated as: ${access.user} (role ${access.role ?? "default"}, ${config.tokenType})`
      : `Authentication: ${access.authenticationNote}`,
    `Generated: ${new Date().toISOString()}`,
    `Access check: ${access.status}${access.fullVisibility || access.authentication === "not_authenticated" ? "" : " (partial visibility: role lacks MANAGE GRANTS)"}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual controls: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function severityRank(severity: SnowflakeSeverity): number {
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
      return exhaustive;
    }
  }
}

function buildQuickReference(result: { outputDir: string }, assessments: SnowflakeAssessmentResult[], errorCount: number): string {
  return [
    "# Snowflake Evidence Bundle Quick Reference",
    "",
    `Bundle directory: ${basename(result.outputDir)}`,
    "",
    "## Contents",
    "",
    "- `core_data/*.json`: raw result sets for every SHOW command and ACCOUNT_USAGE query (statement, columns, rows, partition metadata)",
    "- `analysis/findings.json`: all normalized findings with framework mappings",
    "- `analysis/<area>.json`: per-assessment summaries and findings",
    "- `compliance/executive_summary.md`: prioritized readout",
    "- `compliance/unified_compliance_matrix.md`: one row per finding across every framework",
    "- `compliance/<framework>.md`: framework-specific mapping reports",
    "- `core_data/access_check.json`: readable surface inventory",
    "- `metadata.json`: non-secret run metadata",
    errorCount > 0 ? "- `_errors.log`: statements that were denied, failed, timed out, or were never sent during collection" : "- `_errors.log`: not written because every statement completed",
    "",
    "## Assessments",
    "",
    ...assessments.map((assessment) => `- ${assessment.title}: ${assessment.findings.length} findings (${JSON.stringify(summarizeStatuses(assessment.findings))})`),
    "",
    "Credentials, tokens, and private keys are never written into the bundle.",
  ].join("\n");
}

export async function exportSnowflakeAuditBundle(
  client: SnowflakeQueryClient,
  config: SnowflakeResolvedConfig,
  outputRoot: string,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAuditBundleResult> {
  const access = await checkSnowflakeAccess(client);
  const assessments = [
    await assessSnowflakeNetworkAndAuthentication(client, options),
    await assessSnowflakeAccessControl(client, options),
    await assessSnowflakeMonitoringAndLifecycle(client, options),
    await assessSnowflakeDataProtection(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const statements = assessments.flatMap((assessment) => assessment.statements);
  const failedStatements = statements.filter((statement) => statement.status !== "ok");
  const notRequestedStatements = statements.filter((statement) => statement.status === "not_requested");

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(access.account || config.account)}-audit-bundle`);

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    account: access.account,
    user: access.user,
    role: access.role ?? null,
    authentication: access.authentication,
    token_type: config.tokenType,
    base_url: config.baseUrl,
    source_chain: config.sourceChain,
    statement_count: statements.length,
    requested_statement_count: statements.length - notRequestedStatements.length,
    not_requested_statement_count: notRequestedStatements.length,
    failed_statement_count: failedStatements.length,
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  const seenKeys = new Set<string>();
  for (const assessment of assessments) {
    for (const statement of assessment.statements) {
      const fileKey = seenKeys.has(statement.key) ? `${assessment.area}-${statement.key}` : statement.key;
      seenKeys.add(statement.key);
      await writeSecureTextFile(outputDir, `core_data/${safeDirName(fileKey)}.json`, serializeJson(statement));
    }
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson({ title: assessment.title, summary: assessment.summary, findings: assessment.findings }));
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.md`, `${formatAssessmentText(assessment)}\n`);
  }
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, access, assessments)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of SNOWFLAKE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${safeDirName(framework)}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference({ outputDir }, assessments, failedStatements.length)}\n`);
  if (failedStatements.length > 0) {
    // A statement that was never sent has no statement line: the log names only statements the run executed.
    await writeSecureTextFile(outputDir, "_errors.log", `${failedStatements.map((statement) => `[${statement.status}] ${statement.key}: ${statement.error ?? "no detail"}${statement.statement === null ? "" : `\n  ${statement.statement}`}`).join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: failedStatements.length,
  };
}

function normalizeCommonArgs(args: unknown): CommonArgs {
  const value = asObject(args) ?? {};
  return {
    account: asString(value.account),
    user: asString(value.user),
    private_key_path: asString(value.private_key_path),
    private_key: asString(value.private_key),
    private_key_passphrase: asString(value.private_key_passphrase),
    token: asString(value.token),
    token_type: asString(value.token_type),
    role: asString(value.role),
    warehouse: asString(value.warehouse),
    database: asString(value.database),
    schema: asString(value.schema),
    base_url: asString(value.base_url),
    connection: asString(value.connection),
    timeout_seconds: asNumber(value.timeout_seconds),
    statement_timeout_seconds: asNumber(value.statement_timeout_seconds),
    row_limit: asNumber(value.row_limit),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCommonArgs(args),
    lookback_days: asNumber(value.lookback_days),
    stale_user_days: asNumber(value.stale_user_days),
    failed_login_threshold: asNumber(value.failed_login_threshold),
    max_accountadmins: asNumber(value.max_accountadmins),
    max_auto_suspend_seconds: asNumber(value.max_auto_suspend_seconds),
    max_session_idle_minutes: asNumber(value.max_session_idle_minutes),
    min_password_length: asNumber(value.min_password_length),
    min_retention_days: asNumber(value.min_retention_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toAssessmentOptions(args: AssessArgs): SnowflakeAssessmentOptions {
  return {
    lookbackDays: args.lookback_days,
    staleUserDays: args.stale_user_days,
    failedLoginThreshold: args.failed_login_threshold,
    maxAccountAdmins: args.max_accountadmins,
    maxAutoSuspendSeconds: args.max_auto_suspend_seconds,
    maxSessionIdleMinutes: args.max_session_idle_minutes,
    minPasswordLength: args.min_password_length,
    minRetentionDays: args.min_retention_days,
  };
}

function createClient(args: CommonArgs): SnowflakeSqlClient {
  return new SnowflakeSqlClient(resolveSnowflakeConfiguration(args as JsonRecord));
}

const authParams = {
  account: Type.Optional(Type.String({ description: "Snowflake account identifier (orgname-accountname or legacy locator). Defaults to SNOWFLAKE_ACCOUNT or the connections.toml entry." })),
  user: Type.Optional(Type.String({ description: "Snowflake user name. Defaults to SNOWFLAKE_USER or the connections.toml entry." })),
  private_key_path: Type.Optional(Type.String({ description: "Path to the RSA private key (PKCS#8 PEM) for key-pair JWT auth. Defaults to SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY_FILE." })),
  private_key: Type.Optional(Type.String({ description: "Inline RSA private key PEM. Defaults to SNOWFLAKE_PRIVATE_KEY or SNOWFLAKE_PRIVATE_KEY_RAW." })),
  private_key_passphrase: Type.Optional(Type.String({ description: "Passphrase for an encrypted private key. Defaults to SNOWFLAKE_PRIVATE_KEY_PASSPHRASE or PRIVATE_KEY_PASSPHRASE." })),
  token: Type.Optional(Type.String({ description: "OAuth access token or programmatic access token. Defaults to SNOWFLAKE_TOKEN." })),
  token_type: Type.Optional(Type.String({ description: "Bearer token type: OAUTH (default for tokens), PROGRAMMATIC_ACCESS_TOKEN, or KEYPAIR_JWT. Defaults to SNOWFLAKE_TOKEN_TYPE or SNOWFLAKE_AUTHENTICATOR." })),
  role: Type.Optional(Type.String({ description: "Role for the statements (read-only audit role, SECURITYADMIN, or ACCOUNTADMIN). Defaults to SNOWFLAKE_ROLE." })),
  warehouse: Type.Optional(Type.String({ description: "Warehouse for ACCOUNT_USAGE queries (X-Small recommended). Defaults to SNOWFLAKE_WAREHOUSE." })),
  database: Type.Optional(Type.String({ description: "Optional session database. Defaults to SNOWFLAKE_DATABASE." })),
  schema: Type.Optional(Type.String({ description: "Optional session schema. Defaults to SNOWFLAKE_SCHEMA." })),
  base_url: Type.Optional(Type.String({ description: "Override the SQL API base URL (for example a PrivateLink host). Defaults to https://<account>.snowflakecomputing.com." })),
  connection: Type.Optional(Type.String({ description: "Connection name in ~/.snowflake/connections.toml or config.toml. Defaults to SNOWFLAKE_CONNECTION_NAME, default_connection_name, or 'default'." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout per request in seconds. Defaults to 30.", default: 30 })),
  statement_timeout_seconds: Type.Optional(Type.Number({ description: "Server-side statement timeout in seconds. Defaults to 120.", default: 120 })),
  row_limit: Type.Optional(Type.Number({ description: "Row limit for ACCOUNT_USAGE inventory queries; hitting it flags a partial result. Defaults to 20000.", default: 20000 })),
};

const thresholdParams = {
  lookback_days: Type.Optional(Type.Number({ description: "History window in days for LOGIN_HISTORY and QUERY_HISTORY. Defaults to 30.", default: 30 })),
  stale_user_days: Type.Optional(Type.Number({ description: "Days since last login before a user is stale. Defaults to 90.", default: 90 })),
  failed_login_threshold: Type.Optional(Type.Number({ description: "Failed logins per user/IP that trigger a failure. Defaults to 10.", default: 10 })),
  max_accountadmins: Type.Optional(Type.Number({ description: "Maximum acceptable ACCOUNTADMIN members. Defaults to 3.", default: 3 })),
  max_auto_suspend_seconds: Type.Optional(Type.Number({ description: "Maximum acceptable warehouse auto_suspend in seconds. Defaults to 600.", default: 600 })),
  max_session_idle_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable session idle timeout in minutes. Defaults to 60.", default: 60 })),
  min_password_length: Type.Optional(Type.Number({ description: "Minimum password length expected from the account password policy. Defaults to 14.", default: 14 })),
  min_retention_days: Type.Optional(Type.Number({ description: "Minimum Time Travel retention in days. Defaults to 1.", default: 1 })),
};

function registerAssessTool(
  pi: any,
  name: string,
  label: string,
  description: string,
  assess: (client: SnowflakeSqlClient, options: SnowflakeAssessmentOptions) => Promise<SnowflakeAssessmentResult>,
): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object({ ...authParams, ...thresholdParams }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assess(createClient(args), toAssessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(`${label} failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: name });
      }
    },
  });
}

export function registerSnowflakeTools(pi: any): void {
  pi.registerTool({
    name: "snowflake_check_access",
    label: "Check Snowflake audit access",
    description:
      "Validate read-only Snowflake SQL API access (key-pair JWT or OAuth) across SHOW NETWORK POLICIES, SHOW PARAMETERS, SHOW INTEGRATIONS, SHOW WAREHOUSES, SHOW DATABASES, SHOW SHARES, SHOW REPLICATION GROUPS, and the ACCOUNT_USAGE views used by the assessments, reporting denied surfaces and partial visibility.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCommonArgs,
    async execute(_toolCallId: string, args: CommonArgs) {
      try {
        const result = await checkSnowflakeAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "snowflake_check_access", ...result });
      } catch (error) {
        return errorResult(`Snowflake access check failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: "snowflake_check_access" });
      }
    },
  });

  registerAssessTool(
    pi,
    "snowflake_assess_network_and_authentication",
    "Assess Snowflake network and authentication",
    "Assess spec controls 1-6 and 25: network policy activation, IP allowlist restrictiveness, MFA for person users, account password policy, key-pair auth for service users, SAML2/SCIM integrations, and account session policies. Statements that fail or return partial inventories yield manual or warn verdicts, never pass.",
    assessSnowflakeNetworkAndAuthentication,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_access_control",
    "Assess Snowflake access control",
    "Assess spec controls 7-10 and 16: role hierarchy least privilege, ACCOUNTADMIN membership, ACCOUNTADMIN routine query usage, direct grants to users, and PUBLIC grants on data objects, using GRANTS_TO_ROLES, GRANTS_TO_USERS, and QUERY_HISTORY.",
    assessSnowflakeAccessControl,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_monitoring_and_lifecycle",
    "Assess Snowflake monitoring and lifecycle",
    "Assess spec controls 11-13 and 24: failed login monitoring from LOGIN_HISTORY, stale person users (NULL last login is reported separately and never counted as active), data retention parameter plus ACCESS_HISTORY readability, and warehouse auto-suspend.",
    assessSnowflakeMonitoringAndLifecycle,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_data_protection",
    "Assess Snowflake data protection",
    "Assess spec controls 14-15 and 17-23: masking and row access policy assignment, storage integration and unload parameters, Time Travel retention, Tri-Secret Secure and customer-managed keys (manual evidence), outbound shares and listings, and API or external access integrations.",
    assessSnowflakeDataProtection,
  );

  pi.registerTool({
    name: "snowflake_export_audit_bundle",
    label: "Export Snowflake audit bundle",
    description:
      "Export a Snowflake evidence bundle with raw result sets (core_data), normalized findings and per-area analysis, compliance reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP, a QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a paired zip archive that never overwrites a prior bundle.",
    parameters: Type.Object({
      ...authParams,
      ...thresholdParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveSnowflakeConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSnowflakeAuditBundle(new SnowflakeSqlClient(config), config, outputRoot, toAssessmentOptions(args));
        return textResult(
          [
            "Snowflake audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Statements with errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "snowflake_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Snowflake audit bundle export failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: "snowflake_export_audit_bundle" });
      }
    },
  });
}
