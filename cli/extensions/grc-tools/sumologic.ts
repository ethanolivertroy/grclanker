/**
 * Sumo Logic organization security inspector for grclanker.
 *
 * Read-only Management API coverage for identity, access control, data
 * governance, and content sharing controls, mapped to compliance frameworks.
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
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { parseDocument as parseYamlDocument, YAMLError } from "yaml";
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues, scrubbedFormsOf } from "../../flue/redact.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
const YAML_ERROR_CODE_PATTERN = /^[A-Z_]+$/;

interface ConfigFilePosition {
  line: number;
  column?: number;
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
    throw new Error(`Unable to read Sumo Logic config file ${pathname} (${code ?? "UNREADABLE"})`);
  }
}

/** Parse step: fixed text plus path, position, and validated code; nothing the parser said, quoted, or named. */
function configFileParseError(pathname: string, code: string, position: ConfigFilePosition | undefined): Error {
  const where = position ? ` at line ${position.line}${position.column ? `, column ${position.column}` : ""}` : "";
  return new Error(`Unable to parse Sumo Logic config file: invalid YAML in ${pathname}${where} (${code})`);
}

/** The yaml package's own error code when the thrown value is a YAMLError (an unresolved alias throws a plain ReferenceError), otherwise a fixed code. */
function yamlErrorCode(error: unknown): string {
  return error instanceof YAMLError && YAML_ERROR_CODE_PATTERN.test(error.code) ? error.code : "INVALID_YAML";
}

function yamlErrorPosition(error: unknown): ConfigFilePosition | undefined {
  if (!(error instanceof YAMLError)) return undefined;
  const start = error.linePos?.[0];
  if (!start || !Number.isInteger(start.line) || start.line < 1) return undefined;
  return { line: start.line, column: Number.isInteger(start.col) && start.col > 0 ? start.col : undefined };
}

/** Parses config YAML without logging warnings (their pretty text quotes the source line) and throws the document's first error. */
function parseConfigYaml(text: string): unknown {
  const document = parseYamlDocument(text);
  if (document.errors.length > 0) throw document.errors[0];
  return document.toJS();
}

const DEFAULT_OUTPUT_DIR = "./export/sumologic";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 1000;
const DASHBOARDS_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 50;
const DEFAULT_MAX_RETRIES = 4;
const DEFAULT_KEY_MAX_AGE_DAYS = 90;
const DEFAULT_KEY_INACTIVE_DAYS = 90;
const DEFAULT_USER_INACTIVE_DAYS = 90;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_MAX_ALLOWLISTED_USERS = 2;
const DEFAULT_MIN_PASSWORD_LENGTH = 12;
const DEFAULT_MAX_PASSWORD_AGE_DAYS = 90;
const DEFAULT_MAX_SESSION_TIMEOUT_MINUTES = 15;
const DEFAULT_MIN_RETENTION_DAYS = 365;
const DEFAULT_COLLECTOR_OFFLINE_DAYS = 30;
const DEFAULT_CONTENT_SAMPLE = 25;
const DEFAULT_CONFIG_FILE = join(homedir(), ".sumologic-sec-inspector", "config.yaml");

export const SUMOLOGIC_DEPLOYMENTS: Readonly<Record<string, string>> = {
  au: "https://api.au.sumologic.com/api",
  ca: "https://api.ca.sumologic.com/api",
  ch: "https://api.ch.sumologic.com/api",
  de: "https://api.de.sumologic.com/api",
  esc: "https://api.esc.sumologic.com/api",
  eu: "https://api.eu.sumologic.com/api",
  fed: "https://api.fed.sumologic.com/api",
  in: "https://api.in.sumologic.com/api",
  jp: "https://api.jp.sumologic.com/api",
  kr: "https://api.kr.sumologic.com/api",
  us1: "https://api.sumologic.com/api",
  us2: "https://api.us2.sumologic.com/api",
};

const FRAMEWORKS = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"] as const;
type Framework = (typeof FRAMEWORKS)[number];

interface ControlDefinition {
  id: string;
  number: number;
  title: string;
  mappings: Record<Framework, string>;
}

function control(number: number, title: string, refs: string[]): ControlDefinition {
  const mappings = Object.fromEntries(FRAMEWORKS.map((framework, index) => [framework, refs[index]])) as Record<Framework, string>;
  return { id: `SUMO-${String(number).padStart(2, "0")}`, number, title, mappings };
}

export const SUMOLOGIC_CONTROLS: readonly ControlDefinition[] = [
  control(1, "SAML SSO Enforcement", ["IA-2", "AC.L2-3.1.1", "CC6.1", "1.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "CPS-04"]),
  control(2, "SAML Allowlisted Users Minimized", ["IA-2(1)", "AC.L2-3.1.1", "CC6.1", "1.2", "8.3.2", "SRG-APP-000149", "ISM-1558", "CPS-04"]),
  control(3, "Password Policy Strength", ["IA-5(1)", "IA.L2-3.5.7", "CC6.1", "5.1", "8.3.6", "SRG-APP-000166", "ISM-0421", "CPS-05"]),
  control(4, "Password Expiration Policy", ["IA-5(1)", "IA.L2-3.5.8", "CC6.1", "5.2", "8.3.9", "SRG-APP-000174", "ISM-0422", "CPS-05"]),
  control(5, "MFA Enforcement", ["IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.1", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-06"]),
  control(6, "Role-Based Access Control", ["AC-2", "AC.L2-3.1.1", "CC6.3", "6.1", "7.2.1", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  control(7, "Access Key Rotation", ["IA-5(1)", "IA.L2-3.5.8", "CC6.1", "5.3", "8.6.3", "SRG-APP-000175", "ISM-1590", "CPS-05"]),
  control(8, "Inactive Access Keys", ["AC-2(3)", "AC.L2-3.1.1", "CC6.2", "5.4", "8.1.4", "SRG-APP-000025", "ISM-1404", "CPS-07"]),
  control(9, "Audit Index Enabled", ["AU-2", "AU.L2-3.3.1", "CC7.2", "8.1", "10.2.1", "SRG-APP-000089", "ISM-0580", "CPS-10"]),
  control(10, "Data Forwarding Destinations Reviewed", ["SC-7", "SC.L2-3.13.1", "CC6.6", "9.1", "1.3.1", "SRG-APP-000383", "ISM-1148", "CPS-11"]),
  control(11, "Content Sharing Permissions", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.2", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  control(12, "Collector Management", ["CM-8", "CM.L2-3.4.1", "CC8.1", "10.1", "6.3.2", "SRG-APP-000456", "ISM-1490", "CPS-12"]),
  control(13, "Service Allowlist Configured", ["SC-7", "SC.L2-3.13.1", "CC6.6", "9.2", "1.3.2", "SRG-APP-000383", "ISM-1148", "CPS-11"]),
  control(14, "Session Timeout Policy", ["AC-11", "AC.L2-3.1.10", "CC6.1", "7.1", "8.2.8", "SRG-APP-000190", "ISM-0853", "CPS-08"]),
  control(15, "Scheduled Search Permissions", ["AC-6", "AC.L2-3.1.5", "CC6.3", "6.3", "7.2.2", "SRG-APP-000340", "ISM-0432", "CPS-07"]),
  control(16, "Ingest Budget Controls", ["SC-5", "SC.L2-3.13.6", "CC7.2", "9.3", "6.5.10", "SRG-APP-000246", "ISM-1020", "CPS-11"]),
  control(17, "Data Retention Policies", ["AU-11", "AU.L2-3.3.1", "CC7.4", "8.2", "3.1", "SRG-APP-000515", "ISM-0859", "CPS-10"]),
  control(18, "Lookup Table Access", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.4", "7.2.3", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  control(19, "Dashboard Sharing Restrictions", ["AC-3", "AC.L2-3.1.3", "CC6.3", "6.5", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  control(20, "Monitor Alert Routing", ["AU-5", "AU.L2-3.3.4", "CC7.3", "8.3", "10.6.1", "SRG-APP-000108", "ISM-0580", "CPS-10"]),
];

const ADMIN_CAPABILITIES = new Set([
  "manageUsersAndRoles",
  "manageOrgSettings",
  "manageSaml",
  "managePasswordPolicy",
  "manageAccessKeys",
  "ipAllowlisting",
  "manageSupportAccountAccess",
  "manageAuditDataFeed",
  "changeEmail",
].map((capability) => capability.toLowerCase()));

export interface SumologicResolvedConfig {
  accessId: string;
  accessKey: string;
  baseUrl: string;
  deployment?: string;
  timeoutMs: number;
  sourceChain: string[];
}

/**
 * One collected dataset. `complete` and `scope` describe a read that
 * happened, so they are null (not false or "org") when the read failed;
 * `endpoint` names the path whose request failed so the bundle can carry a
 * not-collected marker instead of an empty inventory.
 */
export interface SumologicCollection<T> {
  ok: boolean;
  data?: T;
  error?: string;
  httpStatus?: number;
  endpoint?: string;
  complete: boolean | null;
  scope: "org" | "personal" | null;
  count?: number;
}

/** What a bundle consumer reads in place of a list that was never collected. */
export interface SumologicNotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string | null;
  error: string | null;
}

export type SumologicPolicyName =
  | "audit"
  | "searchAudit"
  | "shareDashboardsOutsideOrganization"
  | "dataAccessLevel"
  | "userConcurrentSessionsLimit"
  | "maxUserSessionTimeout"
  | "accessKeysLifetime";

/**
 * The members each documented object resource carries. A 200 body with none
 * of them is not the resource (a proxy page, a foreign API's JSON) and is
 * recorded as a not-collected marker rather than read as evidence.
 */
const POLICY_MEMBERS: Readonly<Record<SumologicPolicyName, readonly string[]>> = {
  audit: ["enabled"],
  searchAudit: ["enabled"],
  shareDashboardsOutsideOrganization: ["enabled"],
  dataAccessLevel: ["enabled"],
  userConcurrentSessionsLimit: ["enabled", "maxConcurrentSessions"],
  maxUserSessionTimeout: ["maxUserSessionTimeout"],
  accessKeysLifetime: ["accessKeysLifetimeInDays"],
};
const ACCOUNT_STATUS_MEMBERS: readonly string[] = ["pricingModel", "planType", "applicationUse", "canUpdatePlan"];
const PASSWORD_POLICY_MEMBERS: readonly string[] = ["minLength", "maxLength", "requireMfa", "maxPasswordAgeInDays"];
const SERVICE_ALLOWLIST_STATUS_MEMBERS: readonly string[] = ["loginEnabled", "contentEnabled"];
const FOLDER_MEMBERS: readonly string[] = ["id", "itemType", "children"];
const CONTENT_PERMISSIONS_MEMBERS: readonly string[] = ["explicitPermissions", "implicitPermissions"];

export interface SumologicReader {
  getResolvedConfig(): SumologicResolvedConfig;
  getAccountStatus(): Promise<SumologicCollection<JsonRecord>>;
  listUsers(): Promise<SumologicCollection<JsonRecord[]>>;
  listRoles(): Promise<SumologicCollection<JsonRecord[]>>;
  listAccessKeys(): Promise<SumologicCollection<JsonRecord[]>>;
  listSamlIdentityProviders(): Promise<SumologicCollection<JsonRecord[]>>;
  listSamlAllowlistedUsers(): Promise<SumologicCollection<JsonRecord[]>>;
  getPasswordPolicy(): Promise<SumologicCollection<JsonRecord>>;
  getServiceAllowlistStatus(): Promise<SumologicCollection<JsonRecord>>;
  listServiceAllowlistAddresses(): Promise<SumologicCollection<JsonRecord[]>>;
  getPolicy(name: SumologicPolicyName): Promise<SumologicCollection<JsonRecord>>;
  listPartitions(): Promise<SumologicCollection<JsonRecord[]>>;
  listScheduledViews(): Promise<SumologicCollection<JsonRecord[]>>;
  listIngestBudgets(): Promise<SumologicCollection<JsonRecord[]>>;
  listConnections(): Promise<SumologicCollection<JsonRecord[]>>;
  listCollectors(): Promise<SumologicCollection<JsonRecord[]>>;
  listMonitors(): Promise<SumologicCollection<JsonRecord[]>>;
  getPersonalFolder(): Promise<SumologicCollection<JsonRecord>>;
  listDashboards(): Promise<SumologicCollection<JsonRecord[]>>;
  getContentPermissions(contentId: string): Promise<SumologicCollection<JsonRecord>>;
}

export interface SumologicAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  /** Items seen on a readable surface; null when the probe did not succeed. */
  count: number | null;
  /** Whether pagination finished on a readable surface; null when the probe did not succeed. */
  complete: boolean | null;
  /** The observed HTTP status of a failed probe; null when the probe succeeded or failed before a response. */
  httpStatus: number | null;
  error?: string;
  capabilityHint: string;
}

export interface SumologicAccessCheckResult {
  status: "healthy" | "limited";
  baseUrl: string;
  surfaces: SumologicAccessSurface[];
  missingCapabilities: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface SumologicFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface SumologicAssessmentResult {
  title: string;
  area: string;
  summary: JsonRecord;
  findings: SumologicFinding[];
  errors: string[];
  rawData: Record<string, unknown>;
}

export interface SumologicAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type AuthArgs = {
  access_id?: string;
  access_key?: string;
  endpoint?: string;
  deployment?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type IdentityArgs = AuthArgs & {
  max_allowlisted_users?: number;
  min_password_length?: number;
  max_password_age_days?: number;
};

type AccessControlArgs = AuthArgs & {
  max_admins?: number;
  key_max_age_days?: number;
  key_inactive_days?: number;
  user_inactive_days?: number;
  max_session_timeout_minutes?: number;
};

type DataGovernanceArgs = AuthArgs & {
  min_retention_days?: number;
  collector_offline_days?: number;
  approved_destination_domains?: string[];
};

type ContentSharingArgs = AuthArgs & {
  approved_email_domains?: string[];
  content_sample?: number;
};

type ExportAuditBundleArgs = IdentityArgs & AccessControlArgs & DataGovernanceArgs & ContentSharingArgs & {
  output_dir?: string;
};

export interface SumologicAssessmentOptions {
  maxAllowlistedUsers?: number;
  minPasswordLength?: number;
  maxPasswordAgeDays?: number;
  maxAdmins?: number;
  keyMaxAgeDays?: number;
  keyInactiveDays?: number;
  userInactiveDays?: number;
  maxSessionTimeoutMinutes?: number;
  minRetentionDays?: number;
  collectorOfflineDays?: number;
  approvedDestinationDomains?: string[];
  approvedEmailDomains?: string[];
  contentSample?: number;
  now?: Date;
}

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

function asStringList(value: unknown): string[] {
  if (typeof value === "string") {
    return value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  }
  return asArray(value).map((item) => asString(item)?.toLowerCase()).filter((item): item is string => Boolean(item));
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function parseDate(value: unknown): Date | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return new Date(value > 1e12 ? value : value * 1000);
  }
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function ageInDays(value: unknown, now: Date): number | undefined {
  const parsed = parseDate(value);
  if (!parsed) return undefined;
  return Math.floor((now.getTime() - parsed.getTime()) / 86_400_000);
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
  return normalized || "sumologic";
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
  const realParent = realpathSync(parent);
  if (lstatSync(realParent).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }
  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const suffix = attempt === 0 ? "" : `-${attempt + 1}`;
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    const zipCandidate = resolveSecureOutputPath(root, `${preferredName}${suffix}.zip`);
    if (!existsSync(candidate) && !existsSync(zipCandidate)) {
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
// The userinfo ends at the first "/", "?", or "#": an "@" inside a query or fragment ("https://h?e=a@x.com&q=v") never turns the query into the host.
const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s\/?#@"'<>\\]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;
// A ";" inside a query value is part of the value (URLSearchParams semantics), so "?token=<v>;<rest>"
// loses the whole value with no tail. The ";" separator belongs to Cookie and Set-Cookie parsing alone,
// and the cookie reader runs before this pass, so a pair inside a cookie header is already gone. A pair
// whose value is already the marker is left alone, so a second pass never grows it to "[REDACTED]]".
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>)\]}\\]+)/g;
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
// Trailing base64 padding is judged apart from the run it follows: `private_key_file=` is a setting
// key whose value starts with a symbol, not a padded token.
const BASE64_PADDING_PATTERN = /={1,2}$/;
// A setting suffix concatenated onto another word (OKTA_CLIENT_AUTHORIZATIONMODE, OKTA_CLIENT_PRIVATEKEYID) still names the setting.
const SETTING_KEY_SUFFIX_PATTERN = new RegExp(`(?:${[...SETTING_KEY_SUFFIXES].join("|")})$`);
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
  const last = segments[segments.length - 1] ?? "";
  const noun = CREDENTIAL_ENCODING_WORDS.has(last) ? segments[segments.length - 2] ?? "" : last;
  return CREDENTIAL_NOUN_PATTERN.test(noun) || isBearerIdKey(key, segments);
}

/** Authorization, Proxy-Authorization, and WWW-Authenticate carry a scheme word in front of the credential; every other key's value goes whatever word it starts with. */
function isAuthorizationStyleKey(segments: readonly string[]): boolean {
  return segments[segments.length - 1] === "authorization" || segments.slice(-2).join("_") === "www_authenticate";
}

/** The final segment names a setting, as its own word or concatenated onto another (OKTA_CLIENT_AUTHORIZATIONMODE, OKTA_CLIENT_PRIVATEKEYID); a bearer id is read before this test. */
function isSettingSegment(segment: string): boolean {
  return SETTING_KEY_SUFFIXES.has(segment) || SETTING_KEY_SUFFIX_PATTERN.test(segment);
}

/** How the value of a `key=value` or `key: value` pair is treated; see the pair rule above. */
function pairRuleFor(key: string): PairRule {
  const segments = keySegments(key);
  if (isBearerIdKey(key, segments)) return "credential";
  if (isWebhookKey(segments)) return "webhook";
  if (!isCredentialCarrierKey(key)) return "none";
  return isSettingSegment(segments[segments.length - 1] ?? "") ? "setting" : "credential";
}

/** A setting value is removed only when it is a single run of 16 or more characters with a real token shape (base64 symbols, scattered digits, or token casing); an identifier (0oa1audit, key-2024-01), a UUID, a scheme word, a mode name, or a URL stays for the later shape rules to judge. */
function isTokenShapedValue(value: string): boolean {
  return value.length >= LONG_TOKEN_MIN_LENGTH && SINGLE_RUN_PATTERN.test(value) && looksLikeToken(value);
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
    looksLikeToken(run.replace(BASE64_PADDING_PATTERN, "")) && !SCHEME_WORD_PATTERN.test(run) && !isBarePathSegment(text, offset, urlSpans) ? REDACTED : run,
  );
}

// The credentials this process has configured or minted (a client's token, private key, client
// assertion, and the access token or session it obtained), so every scrub pass removes them without
// being handed the client: redactSnapshot on a string leaf, an error text built outside the client.
// Each entry keeps its encoded forms, lower-cased, so a leaf that carries none of them is passed over
// with a substring check; bounded so a long-lived process that mints tokens does not grow it without limit.
const REGISTERED_SECRET_LIMIT = 64;
interface RegisteredSecret {
  readonly value: string;
  readonly forms: readonly string[];
}
const registeredSecrets: RegisteredSecret[] = [];

/** Registers the credentials a client was configured with or minted; a value under the configured-secret minimum is ignored. */
export function registerConfiguredSecrets(values: ReadonlyArray<string | undefined>): void {
  for (const value of values) {
    if (typeof value !== "string" || value.length < MIN_CONFIGURED_SECRET_LENGTH || registeredSecrets.some((entry) => entry.value === value)) continue;
    const forms = [...new Set(scrubbedFormsOf(value).map((form) => form.toLowerCase()))].filter((form) => form.length >= MIN_CONFIGURED_SECRET_LENGTH);
    registeredSecrets.push({ value, forms });
    if (registeredSecrets.length > REGISTERED_SECRET_LIMIT) registeredSecrets.shift();
  }
}

/** The registered credentials whose encoded forms may occur in the text; a text that carries none skips the full pass. */
function registeredSecretsIn(text: string): string[] {
  if (registeredSecrets.length === 0) return [];
  const lower = text.toLowerCase();
  if (lower.length !== text.length) return registeredSecrets.map((entry) => entry.value);
  return registeredSecrets.filter((entry) => entry.forms.some((form) => lower.includes(form))).map((entry) => entry.value);
}

/** Removes the secrets handed in and every registered credential in each encoded form. */
function scrubConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
  const values = [...new Set([...secrets, ...registeredSecretsIn(text)])].filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
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
  return `${escaped ? kept.split("/").join(ESCAPED_SLASH) : kept}${redactedUrlPart(query)}${redactedUrlPart(fragment)}${trailing}`;
}

/** A query or fragment with content becomes its delimiter and the marker; a bare delimiter (what an earlier pass left before its marker) carries nothing and stays, so a second pass adds no second marker. */
function redactedUrlPart(part: string | undefined): string {
  if (!part) return "";
  return part.length > 1 ? `${part[0]}${REDACTED}` : part;
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

function scrubSchemeValue(match: string, scheme: string, quote: string, value: string, offset: number, text: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(value)?.[0] ?? "";
  const word = value.slice(0, value.length - trailing.length);
  if (isSchemeProse(scheme, word) || isRedactedPairKey(word, text, offset + match.length)) return match;
  return `${scheme} ${quote}${REDACTED}${trailing}`;
}

/** A run that is a bare pair key with the marker right after it (`username="[REDACTED]"`, `access_token=[REDACTED]`) names a pair whose value an earlier pass removed, and keeps its name. */
function isRedactedPairKey(word: string, text: string, index: number): boolean {
  if (!PAIR_KEY_ONLY_PATTERN.test(word)) return false;
  REDACTED_PAIR_VALUE_PATTERN.lastIndex = index;
  return REDACTED_PAIR_VALUE_PATTERN.test(text);
}

// The RFC 7230 token characters, so a following header whose name carries a "." or other token
// punctuation (X.Api.Key) is recognised as the next header rather than swallowed (item L).
const NEXT_HEADER_NAME = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
// A ";" or "," ends a carrier value when the text after it (past optional spaces) opens the next
// header "Name:" token or a JSON fragment.
const NEXT_HEADER_AFTER_SEPARATOR = new RegExp(String.raw`^[ \t]*(?:[{[]|${QUOTE_UNIT}?${NEXT_HEADER_NAME}${QUOTE_UNIT}?[ \t]*:)`);
// A quoted value that opens with a scheme word keeps the scheme and its gap and loses the rest, except
// that a scheme followed by a pair list is read pair by pair. The pairs are the credential: a quoted
// value goes whatever its key (`Snowflake Token="<v>"`, `Digest response="<v>"`, `Bearer blob="<v>"`)
// unless the key is a descriptive parameter (realm, qop, algorithm, ...), and a bare value follows its
// key's own rule, so an HMAC header's "id=...,ts=...,nonce=...,sig=..." keeps its timestamp. A
// challenge header (WWW-Authenticate) is read the same way, so its `realm="api"` stays and its nonce goes.
const LEADING_SCHEME_IN_VALUE = /^([A-Za-z][A-Za-z0-9-]*)(\s+)(\S[\s\S]*)$/;
const PAIR_LIST_START = /^[A-Za-z][A-Za-z0-9_.-]*=/;
// The run after the scheme is a bare key ("Token=", "username=") whose value follows it.
const PAIR_KEY_ONLY_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]*=$/;
// The pairs of a request credential's list: a key up to its "=", a bare value, and the separator before
// the next pair ("," with optional spaces, or spaces alone).
const LIST_PAIR_KEY_PATTERN = /[A-Za-z][A-Za-z0-9_.-]*=/y;
// A bare value that is already the marker reads as one value, so the list goes on past a pair an earlier pass removed.
const LIST_BARE_VALUE_PATTERN = /\[REDACTED\]|[^\s"'<>;,()[\]{}\\]*/y;
const LIST_PAIR_SEPARATOR_PATTERN = /[ \t]*,[ \t]*|[ \t]+/y;
// The descriptive parameters of a credential's pair list, whose quoted value stays (`realm="api"`,
// `qop="auth"`, `algorithm="SHA-256"`, a challenge's `error="invalid_token"`); every other quoted value
// in the list is the credential.
const LIST_KEPT_PARAM_PATTERN = /^(?:realm|qop|algorithm|charset|error|error_description|error_uri|scope)$/i;
// The proof parameters of an authentication exchange: Digest's `response`, an HTTP Signatures or
// OAuth 1.0 `signature` and `oauth_signature`, the MAC and Hawk schemes' `mac`, and an HMAC header's
// `sig`. A proof's value is the credential wherever its pair sits in a list with a challenge parameter
// (realm, nonce, cnonce, opaque, qop, or an oauth_* name), with or without a scheme word or a header in
// front of the list, so `realm="api", nonce="n", response="<proof>"` is never read as a bare challenge;
// a proof-free challenge (`realm="api", qop="auth"`) and a pair list of another kind (`status=500
// response=slow`) keep their values. Inside a scheme word's list a bare proof goes whatever its neighbours.
const PROOF_PARAM_PATTERN = /^(?:response|signature|oauth_signature|mac|sig)$/i;
const CHALLENGE_PARAM_PATTERN = /^(?:realm|nonce|cnonce|opaque|qop|oauth_[a-z0-9_]+)$/i;
// The first key of a pair list, at a carrier start; the keys after it are read past the list separator.
const PAIR_LIST_KEY_PATTERN = new RegExp(String.raw`${CARRIER_START}[A-Za-z][A-Za-z0-9_.-]*=`, "g");
// The marker, in quotes or bare, where a pair's value stood before an earlier pass removed it.
const REDACTED_PAIR_VALUE_PATTERN = new RegExp(String.raw`${QUOTE_UNIT}?\[REDACTED\]`, "y");
// In prose, an authorization scheme word followed by a quoted pair opens a credential's pair list
// ("Digest username="...", response="..."", "Bearer blob="..."") and the list rule applies; a product
// name (Splunk, Snowflake, HMAC) followed by a quoted pair is prose about the product.
const SCHEME_PAIR_LIST_PATTERN = new RegExp(String.raw`${CARRIER_START}(?:bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|aws4-hmac-sha256|veracode-hmac-sha-256)\s+(?=[A-Za-z][A-Za-z0-9_.-]*=${QUOTE_UNIT})`, "gi");
// After a bare path label the text is prose ("/api/v1/api-tokens: request failed with 403",
// "/oauth/token-request: invalid_client") and stays, unless the segment itself names a credential
// in the singular (its last word is password, key, secret, token, passphrase, or assertion, alone
// or followed by an encoding word such as pem or base64, or it is a bearer id): then the next token
// is the value whatever its shape and whatever follows it ("kv/password: <value> [code 003001]",
// "kv/privateKeyPem: <value>"), while a plural label ("api-tokens", "secrets") names a collection
// and its colon continues as prose, and so does a label whose last word names a file or path
// ("kv/private_key_file: /x/y.pem").
const CREDENTIAL_NOUN_PATTERN = /(?:password|passwd|passphrase|pwd|secret|token|key|assertion)$/;
const CREDENTIAL_ENCODING_WORDS = new Set(["pem", "der", "b64", "base64", "jwk"]);
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

interface ListRead {
  /** The text written in place of the list, from its first key to `end`. */
  replacement: string;
  /** The index just past the last pair read. */
  end: number;
}

/** The bare value of a pair in a request credential's list follows its key's own rule: a credential or proof key loses it, a setting key loses a token-shaped one, a webhook key keeps its origin, and any other key keeps it. */
function scrubBareListValue(key: string, value: string): string {
  if (value.length === 0 || value === REDACTED) return value;
  if (PROOF_PARAM_PATTERN.test(key)) return REDACTED;
  const rule = pairRuleFor(key);
  switch (rule) {
    case "credential":
      return REDACTED;
    case "setting":
      return isTokenShapedValue(value) ? REDACTED : value;
    case "webhook":
      return webhookReplacement(value);
    case "none":
      return value;
    default: {
      const unhandled: never = rule;
      return unhandled;
    }
  }
}

/**
 * Reads one pair's value at `valueStart`, up to `limit`. The pairs of a credential's list are the
 * credential, so a quoted value is removed whatever its key (`Snowflake Token="<v>"`, `Digest
 * response="<v>"`, `Bearer blob="<v>"`) unless the key is a descriptive parameter (`realm="api"`),
 * while a bare value follows its key's own rule so `qop=auth`, `nc=00000001`, and an HMAC header's
 * timestamp stay legible and a bare proof (`response=<v>`, `sig=<v>`) goes. `terminated` is false when a
 * quoted value never closed, which ends the list there.
 */
function readListPairValue(text: string, valueStart: number, key: string, limit: number): ListRead & { terminated: boolean } {
  const opener = openingQuoteUnit(text, valueStart);
  if (!opener) {
    LIST_BARE_VALUE_PATTERN.lastIndex = valueStart;
    const run = LIST_BARE_VALUE_PATTERN.exec(text)?.[0] ?? "";
    const value = text.slice(valueStart, Math.min(valueStart + run.length, limit));
    return { replacement: scrubBareListValue(key, value), end: valueStart + value.length, terminated: true };
  }
  const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
  const terminated = read.terminated && read.end <= limit;
  const end = Math.min(read.end, limit);
  const content = terminated ? read.content : text.slice(opener.contentStart, end);
  const closer = terminated ? text.slice(read.end - opener.backslashes - 1, read.end) : "";
  const value = content.length === 0 || content === REDACTED || LIST_KEPT_PARAM_PATTERN.test(key) ? content : REDACTED;
  return { replacement: `${text.slice(valueStart, opener.contentStart)}${value}${closer}`, end, terminated };
}

/** Reads a credential's pair list from `start`, its first key, up to `limit`; the list ends at the first text that is not another pair. */
function scrubRequestPairList(text: string, start: number, limit: number): ListRead {
  let replacement = "";
  let end = start;
  let position = start;
  while (position < limit) {
    LIST_PAIR_KEY_PATTERN.lastIndex = position;
    const key = LIST_PAIR_KEY_PATTERN.exec(text)?.[0];
    if (key === undefined || position + key.length > limit) break;
    const pair = readListPairValue(text, position + key.length, key.slice(0, -1), limit);
    replacement += `${text.slice(end, position)}${key}${pair.replacement}`;
    end = pair.end;
    if (!pair.terminated) break;
    LIST_PAIR_SEPARATOR_PATTERN.lastIndex = end;
    const separator = LIST_PAIR_SEPARATOR_PATTERN.exec(text)?.[0];
    if (separator === undefined) break;
    position = end + separator.length;
  }
  return { replacement, end };
}

/**
 * The run after a scheme word under an Authorization-style key, when it is a bare key whose value
 * follows ("Token=", "username="). A quoted value opens the credential's pair list, read with the list
 * rule under a request header and a challenge header alike. A key whose value is already the
 * marker stays as it is, so a second pass adds nothing. Undefined when the run is the credential
 * itself, which goes whole.
 */
function readSchemePairList(text: string, start: number, run: string, limit: number): ListRead | undefined {
  if (!PAIR_KEY_ONLY_PATTERN.test(run)) return undefined;
  const valueStart = start + run.length;
  if (valueStart < limit && openingQuoteUnit(text, valueStart)) return scrubRequestPairList(text, start, limit);
  if (text.startsWith(REDACTED, valueStart)) return { replacement: `${run}${REDACTED}`, end: valueStart + REDACTED.length };
  return undefined;
}

/** Reads the quoted pair list after every authorization scheme word in prose (see SCHEME_PAIR_LIST_PATTERN) with the list rule; a list under a header was read by the assignment pass and reads the same a second time. */
function scrubSchemePairLists(text: string): string {
  SCHEME_PAIR_LIST_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = SCHEME_PAIR_LIST_PATTERN.exec(text)) !== null) {
    if (match[0].length === 0) {
      SCHEME_PAIR_LIST_PATTERN.lastIndex += 1;
      continue;
    }
    const list = scrubRequestPairList(text, match.index + match[0].length, text.length);
    out += `${text.slice(last, match.index + match[0].length)}${list.replacement}`;
    last = list.end;
    SCHEME_PAIR_LIST_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

interface ListPair {
  /** The pair's key, without its "=". */
  key: string;
  /** The value's content: between the quote units when quoted, the bare run otherwise. */
  content: string;
  /** The index of the content's first character. */
  contentStart: number;
}

/**
 * Reads the pair list whose first key starts at `start`: pairs separated by "," or spaces, with values
 * quoted at any depth or bare. The list ends at the first text that is not another pair, and an
 * unterminated quoted value ends it there.
 */
function readPairList(text: string, start: number): { pairs: ListPair[]; end: number } {
  const pairs: ListPair[] = [];
  let position = start;
  let end = start;
  while (position < text.length) {
    LIST_PAIR_KEY_PATTERN.lastIndex = position;
    const key = LIST_PAIR_KEY_PATTERN.exec(text)?.[0];
    if (key === undefined) break;
    const valueStart = position + key.length;
    const opener = openingQuoteUnit(text, valueStart);
    if (opener) {
      const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
      pairs.push({ key: key.slice(0, -1), content: read.content, contentStart: opener.contentStart });
      end = read.end;
      if (!read.terminated) break;
    } else {
      LIST_BARE_VALUE_PATTERN.lastIndex = valueStart;
      const content = LIST_BARE_VALUE_PATTERN.exec(text)?.[0] ?? "";
      pairs.push({ key: key.slice(0, -1), content, contentStart: valueStart });
      end = valueStart + content.length;
    }
    LIST_PAIR_SEPARATOR_PATTERN.lastIndex = end;
    const separator = LIST_PAIR_SEPARATOR_PATTERN.exec(text)?.[0];
    if (separator === undefined) break;
    position = end + separator.length;
  }
  return { pairs, end };
}

/**
 * Removes the value of every proof parameter (see PROOF_PARAM_PATTERN) in a pair list that also carries
 * a challenge parameter, whatever the value's shape and whether or not a scheme word or a header
 * precedes the list: `realm="api", nonce="n", response="<proof>"` as a data value, after a literal
 * escape, or inside a JSON string. The other pairs keep their own rule, so `realm="api"` stays.
 */
function scrubProofPairLists(text: string): string {
  PAIR_LIST_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = PAIR_LIST_KEY_PATTERN.exec(text)) !== null) {
    const list = readPairList(text, match.index);
    if (list.pairs.some((pair) => CHALLENGE_PARAM_PATTERN.test(pair.key))) {
      for (const pair of list.pairs) {
        if (!PROOF_PARAM_PATTERN.test(pair.key) || pair.content.length === 0 || pair.content === REDACTED) continue;
        out += `${text.slice(last, pair.contentStart)}${REDACTED}`;
        last = pair.contentStart + pair.content.length;
      }
    }
    PAIR_LIST_KEY_PATTERN.lastIndex = list.end;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Replaces the value of every credential-named pair: `key=value`, `key: value`, `"key": "value"`,
 * and `Header-Name: value`. The value goes whatever its shape (an `=` pair, a quoted value, a header
 * value, a plain word in prose, or a word that happens to be a scheme word: `sslPassword=splunk
 * rejected` and `db_password: token` lose their value). Only an Authorization-style key
 * (Authorization, Proxy-Authorization, WWW-Authenticate) carries a scheme word in front of its
 * credential, where the scheme is kept and the token removed (`Authorization: Bearer <token>`); a
 * pair list after the scheme is read pair by pair, see LEADING_SCHEME_IN_VALUE. A setting key keeps
 * a value that is not token-shaped, a bearer-id key loses a UUID, and a webhook key keeps only the
 * origin. The last segment of a bare path used as a label
 * ("/api/authn/v2/api_credentials: <detail>") is a request target, not a pair key, so the prose
 * after it is kept, unless the segment names a credential in the singular ("kv/password: <value>"),
 * whose next token is the value; inside a URL with a scheme the pair rule still applies.
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
    if (barePathLabel && !namesCredential(key)) continue;
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
          const list = readSchemePairList(text, valueStart + lead[1].length + firstPair[1].length, firstPair[3], valueStart + content.length);
          kept = `${lead[1]}${firstPair[1]}${firstPair[2]}`;
          if (list) {
            replacement = list.replacement;
            consumed = list.end - valueStart;
          } else {
            consumed = lead[1].length + firstPair[0].length;
          }
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
        const list = token[2] === "" ? readSchemePairList(text, valueStart + value.length + token[1].length, token[3], text.length) : undefined;
        kept = `${value}${token[1]}${token[2]}`;
        if (list) {
          replacement = list.replacement;
          consumed = list.end - valueStart;
        } else {
          consumed += token[0].length;
        }
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
 * cookie headers, URLs, query pairs, the proof parameters of a pair list, credential pairs and flags,
 * pair lists and scheme words in prose, JWTs, AWS keys, and vendor-prefixed tokens. `longTokens` adds the
 * generic long-token and hex-digest rules, which the error pass runs and the data pass leaves off so
 * identifiers survive in evidence.
 */
function scrubText(text: string, secrets: ReadonlyArray<string | undefined>, longTokens: boolean): string {
  let scrubbed = text.replace(PEM_BLOCK_PATTERN, REDACTED).replace(PEM_OPEN_PATTERN, REDACTED);
  scrubbed = scrubCookieHeaders(scrubConfiguredSecrets(scrubbed, secrets))
    .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
    .replace(QUERY_PAIR_PATTERN, scrubQueryPair);
  scrubbed = scrubSchemePairLists(replaceFlagValues(replaceCredentialAssignments(scrubProofPairLists(scrubbed))))
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
export function scrubErrorText(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
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

function statusLine(response: Response): string {
  return `${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
}

interface ParsedResponseBody {
  payload: unknown;
  /** Set when the body was not JSON; the text itself is never kept. */
  nonJsonBody?: string;
}

function parseResponseBody(response: Response, rawText: string): ParsedResponseBody {
  if (rawText.length === 0) return { payload: {} };
  try {
    return { payload: JSON.parse(rawText) as unknown };
  } catch {
    return { payload: {}, nonJsonBody: describeNonJsonBody(response, rawText) };
  }
}

export function resolveSumologicBaseUrl(endpointOrDeployment: string): { baseUrl: string; deployment?: string } {
  const trimmed = endpointOrDeployment.trim();
  const code = trimmed.toLowerCase();
  if (SUMOLOGIC_DEPLOYMENTS[code]) {
    return { baseUrl: SUMOLOGIC_DEPLOYMENTS[code], deployment: code };
  }
  if (!/^https?:\/\//i.test(trimmed)) {
    throw new Error(
      `Unknown Sumo Logic deployment "${trimmed}". Use one of ${Object.keys(SUMOLOGIC_DEPLOYMENTS).join(", ")} or a full API URL.`,
    );
  }
  const parsed = new URL(trimmed);
  parsed.hash = "";
  parsed.search = "";
  let pathname = parsed.pathname.replace(/\/+$/, "");
  pathname = pathname.replace(/\/v[12](\/.*)?$/, "");
  if (!pathname.endsWith("/api")) pathname = `${pathname}/api`;
  parsed.pathname = pathname;
  const baseUrl = parsed.toString().replace(/\/+$/, "");
  const deployment = Object.entries(SUMOLOGIC_DEPLOYMENTS).find(([, url]) => url === baseUrl)?.[0];
  return { baseUrl, deployment };
}

function readConfigFile(pathname: string | undefined): JsonRecord {
  const target = pathname ?? DEFAULT_CONFIG_FILE;
  const text = readConfigFileText(target);
  if (text === undefined) return {};
  let parsed: unknown;
  try {
    parsed = parseConfigYaml(text);
  } catch (error) {
    throw configFileParseError(target, yamlErrorCode(error), yamlErrorPosition(error));
  }
  return asObject(parsed) ?? {};
}

function configFileValue(file: JsonRecord, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = asString(file[key]);
    if (value) return value;
  }
  return undefined;
}

export function resolveSumologicConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { configFile?: string } = {},
): SumologicResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file) ?? asString(env.SUMOLOGIC_CONFIG_FILE) ?? options.configFile;
  const file = readConfigFile(configPath);

  const accessIdSources: Array<[string, string | undefined]> = [
    ["arguments", asString(input.access_id)],
    ["environment", asString(env.SUMOLOGIC_ACCESS_ID)],
    ["config-file", configFileValue(file, ["access_id", "accessId", "access-id"])],
  ];
  const accessKeySources: Array<[string, string | undefined]> = [
    ["arguments", asString(input.access_key)],
    ["environment", asString(env.SUMOLOGIC_ACCESS_KEY)],
    ["config-file", configFileValue(file, ["access_key", "accessKey", "access-key"])],
  ];
  const endpointSources: Array<[string, string | undefined]> = [
    ["arguments", asString(input.endpoint) ?? asString(input.deployment)],
    ["environment", asString(env.SUMOLOGIC_ENDPOINT) ?? asString(env.SUMOLOGIC_DEPLOYMENT)],
    ["config-file", configFileValue(file, ["endpoint", "deployment"])],
  ];

  const accessId = accessIdSources.find(([, value]) => value);
  const accessKey = accessKeySources.find(([, value]) => value);
  if (!accessId?.[1] || !accessKey?.[1]) {
    throw new Error("SUMOLOGIC_ACCESS_ID and SUMOLOGIC_ACCESS_KEY (or access_id and access_key arguments, or a config file) are required.");
  }
  sourceChain.push(`${accessId[0]}-access-id`, `${accessKey[0]}-access-key`);

  const endpoint = endpointSources.find(([, value]) => value);
  const { baseUrl, deployment } = resolveSumologicBaseUrl(endpoint?.[1] ?? "us1");
  sourceChain.push(endpoint ? `${endpoint[0]}-endpoint` : "default-endpoint");

  return {
    accessId: accessId[1],
    accessKey: accessKey[1],
    baseUrl,
    deployment,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.SUMOLOGIC_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class SumologicApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly endpoint?: string;

  /**
   * The message and code are scrubbed in the constructor as well as at the
   * record point, so an error built anywhere in the client never carries a
   * credential even if a caller stores error.message directly.
   */
  constructor(message: string, status: number, code?: string, endpoint?: string) {
    super(scrubErrorText(message));
    this.name = "SumologicApiError";
    this.status = status;
    this.code = code === undefined ? undefined : scrubErrorText(code);
    this.endpoint = endpoint;
  }

  /**
   * Builds the error for a response that cannot be used: a body that is not
   * JSON becomes a status-and-length note whatever its content type, a JSON
   * body contributes only the documented message, detail, and code fields,
   * and the configured secrets are removed before the pattern pass runs.
   */
  static fromResponse(path: string, response: Response, body: ParsedResponseBody, secrets: Array<string | undefined>): SumologicApiError {
    const { message, code } = body.nonJsonBody === undefined ? sumologicErrorSummary(body.payload) : {};
    const detail = body.nonJsonBody ?? message;
    const outcome = response.ok ? "returned an unreadable response" : "failed";
    return new SumologicApiError(
      scrubErrorText(`Sumo Logic request to ${path} ${outcome} (${statusLine(response)}${code ? ` ${code}` : ""})${detail ? `: ${detail}` : ""}`, secrets),
      response.status,
      code,
      path,
    );
  }
}

/** A request that never produced a response (network failure, timeout); it still names its endpoint. */
export class SumologicTransportError extends Error {
  readonly endpoint: string;

  constructor(message: string, endpoint: string) {
    super(scrubErrorText(message));
    this.name = "SumologicTransportError";
    this.endpoint = endpoint;
  }
}

function sumologicErrorSummary(payload: unknown): { message?: string; code?: string } {
  const object = asObject(payload);
  if (!object) return {};
  const errors = asRecords(object.errors);
  const first = errors[0];
  return {
    message: [asString(object.message), ...errors.map((item) => asString(item.message) ?? asString(item.detail))]
      .filter((item): item is string => Boolean(item))
      .join("; ") || undefined,
    code: asString(first?.code) ?? asString(object.code),
  };
}

function retryDelayMs(response: Response, attempt: number): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30_000);
    const at = Date.parse(retryAfter);
    if (!Number.isNaN(at)) return Math.min(Math.max(at - Date.now(), 0), 30_000);
  }
  const reset = response.headers.get("x-ratelimit-reset");
  if (reset) {
    const seconds = Number(reset);
    if (Number.isFinite(seconds) && seconds > 0 && seconds < 3600) return Math.min(seconds * 1000, 30_000);
  }
  return Math.min(250 * 2 ** attempt, 8_000);
}

export class SumologicApiClient implements SumologicReader {
  private readonly config: SumologicResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: (ms: number) => Promise<void>;
  private readonly maxRetries: number;
  private readonly maxPages: number;

  constructor(
    config: SumologicResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleepImpl?: (ms: number) => Promise<void>;
      maxRetries?: number;
      maxPages?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
    this.maxRetries = clampNumber(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
    this.maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 1000);
    registerConfiguredSecrets([config.accessKey, this.basicCredential()]);
  }

  getResolvedConfig(): SumologicResolvedConfig {
    return this.config;
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private basicCredential(): string {
    return Buffer.from(`${this.config.accessId}:${this.config.accessKey}`).toString("base64");
  }

  private authorizationHeader(): string {
    return `Basic ${this.basicCredential()}`;
  }

  /** The caller's access key pair and the Basic credential built from it; every form of each is removed from error text. */
  private configuredSecrets(): string[] {
    return [this.config.accessId, this.config.accessKey, this.basicCredential()];
  }

  private scrubError(error: unknown): string {
    return scrubErrorText(error instanceof Error ? error.message : String(error), this.configuredSecrets());
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    const url = this.buildUrl(path, query);
    for (let attempt = 0; ; attempt += 1) {
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
        clearTimeout(timeout);
        if (attempt < this.maxRetries) {
          await this.sleepImpl(Math.min(250 * 2 ** attempt, 8_000));
          continue;
        }
        throw new SumologicTransportError(`Sumo Logic request to ${path} failed: ${this.scrubError(error)}`, path);
      }
      clearTimeout(timeout);

      // A body that is not JSON (a proxy error page, an HTML sign-in form) is
      // never copied into an error string: SumologicApiError.fromResponse
      // describes it by content type and size only, because such pages can
      // echo the request credentials, and a 2xx non-JSON body is an
      // unreadable surface rather than an empty inventory.
      const body = parseResponseBody(response, await response.text());
      if (response.ok && body.nonJsonBody === undefined) return body.payload;

      const retryable = !response.ok && (response.status === 429 || response.status >= 500);
      if (retryable && attempt < this.maxRetries) {
        await this.sleepImpl(retryDelayMs(response, attempt));
        continue;
      }
      throw SumologicApiError.fromResponse(path, response, body, this.configuredSecrets());
    }
  }

  /**
   * `endpoint` is the path the collector reads; a failed collection records
   * the endpoint the error actually came from when the error names one (the
   * access key fallback reads a second path), and this declared path
   * otherwise. Pagination and scope flags are null on failure because no
   * read happened that they could describe.
   */
  private async collect<T>(
    endpoint: string,
    load: () => Promise<{ data: T; complete: boolean; count?: number; scope?: "org" | "personal" }>,
  ): Promise<SumologicCollection<T>> {
    try {
      const result = await load();
      return {
        ok: true,
        data: result.data,
        complete: result.complete,
        scope: result.scope ?? "org",
        count: result.count ?? (Array.isArray(result.data) ? result.data.length : 1),
      };
    } catch (error) {
      // Every dataset error is recorded here and nowhere else, so this is the
      // one place the redaction pass has to run for findings and the bundle.
      return {
        ok: false,
        error: this.scrubError(error),
        httpStatus: error instanceof SumologicApiError ? error.status : undefined,
        endpoint: error instanceof SumologicApiError || error instanceof SumologicTransportError ? error.endpoint ?? endpoint : endpoint,
        complete: null,
        scope: null,
      };
    }
  }

  private async listWithToken(
    path: string,
    query: JsonRecord = {},
    collectionKey = "data",
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<{ data: JsonRecord[]; complete: boolean }> {
    const items: JsonRecord[] = [];
    let token: string | undefined;
    for (let page = 0; page < this.maxPages; page += 1) {
      const payload = asObject(await this.get(path, { ...query, limit: pageSize, token })) ?? {};
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems);
      const nextToken = asString(payload.next);
      if (!nextToken) return { data: items, complete: true };
      // A repeated cursor or an empty page that still advertises a next page
      // means the server is not advancing; stop and report the inventory as
      // incomplete instead of spending the page budget on identical requests.
      if (nextToken === token || pageItems.length === 0) return { data: items, complete: false };
      token = nextToken;
    }
    return { data: items, complete: false };
  }

  private async listWithOffset(
    path: string,
    query: JsonRecord,
    extract: (payload: unknown) => JsonRecord[],
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<{ data: JsonRecord[]; complete: boolean }> {
    const items: JsonRecord[] = [];
    for (let page = 0; page < this.maxPages; page += 1) {
      const pageItems = extract(await this.get(path, { ...query, limit: pageSize, offset: page * pageSize }));
      items.push(...pageItems);
      if (pageItems.length < pageSize) return { data: items, complete: true };
    }
    return { data: items, complete: false };
  }

  /**
   * A single object is kept only when it carries at least one member the
   * documented resource has; a 200 body with none of them is another document
   * (a proxy page, a foreign API's JSON) and is recorded as a not-collected
   * marker naming the endpoint, never as evidence, so the verdicts that read it
   * render manual.
   */
  private async getObject(path: string, members: readonly string[], query: JsonRecord = {}): Promise<{ data: JsonRecord; complete: boolean }> {
    const data = asObject(await this.get(path, query));
    if (!data || !members.some((member) => member in data)) {
      throw new SumologicApiError(
        `Sumo Logic request to ${path} returned a 200 body that is not the expected object (none of ${members.join(", ")} present), so the response was not recorded`,
        200,
        undefined,
        path,
      );
    }
    return { data, complete: true };
  }

  private async getArray(path: string): Promise<{ data: JsonRecord[]; complete: boolean }> {
    return { data: asRecords(await this.get(path)), complete: true };
  }

  getAccountStatus() {
    return this.collect("/v1/account/status", () => this.getObject("/v1/account/status", ACCOUNT_STATUS_MEMBERS));
  }

  listUsers() {
    return this.collect("/v1/users", () => this.listWithToken("/v1/users", { includeServiceAccounts: false }));
  }

  listRoles() {
    return this.collect("/v1/roles", () => this.listWithToken("/v1/roles"));
  }

  listAccessKeys() {
    return this.collect("/v1/accessKeys", async () => {
      try {
        return await this.listWithToken("/v1/accessKeys");
      } catch (error) {
        if (!(error instanceof SumologicApiError) || error.status !== 403) throw error;
        const personal = asRecords(asObject(await this.get("/v1/accessKeys/personal"))?.data);
        return { data: personal, complete: true, scope: "personal" as const };
      }
    });
  }

  listSamlIdentityProviders() {
    return this.collect("/v1/saml/identityProviders", () => this.getArray("/v1/saml/identityProviders"));
  }

  listSamlAllowlistedUsers() {
    return this.collect("/v1/saml/allowlistedUsers", () => this.getArray("/v1/saml/allowlistedUsers"));
  }

  getPasswordPolicy() {
    return this.collect("/v1/passwordPolicy", () => this.getObject("/v1/passwordPolicy", PASSWORD_POLICY_MEMBERS));
  }

  getServiceAllowlistStatus() {
    return this.collect("/v1/serviceAllowlist/status", () => this.getObject("/v1/serviceAllowlist/status", SERVICE_ALLOWLIST_STATUS_MEMBERS));
  }

  listServiceAllowlistAddresses() {
    return this.collect("/v1/serviceAllowlist/addresses", async () => ({
      data: asRecords(asObject(await this.get("/v1/serviceAllowlist/addresses"))?.data),
      complete: true,
    }));
  }

  getPolicy(name: SumologicPolicyName) {
    return this.collect(`/v1/policies/${name}`, () => this.getObject(`/v1/policies/${name}`, POLICY_MEMBERS[name]));
  }

  listPartitions() {
    return this.collect("/v1/partitions", () => this.listWithToken("/v1/partitions", { viewTypes: "DefaultView,Partition,AuditIndex" }));
  }

  listScheduledViews() {
    return this.collect("/v1/scheduledViews", () => this.listWithToken("/v1/scheduledViews"));
  }

  listIngestBudgets() {
    return this.collect("/v2/ingestBudgets", () => this.listWithToken("/v2/ingestBudgets"));
  }

  listConnections() {
    return this.collect("/v1/connections", () => this.listWithToken("/v1/connections"));
  }

  listCollectors() {
    return this.collect("/v1/collectors", () => this.listWithOffset("/v1/collectors", {}, (payload) => asRecords(asObject(payload)?.collectors)));
  }

  listMonitors() {
    return this.collect("/v1/monitors/search", () => this.listWithOffset(
      "/v1/monitors/search",
      { query: "type:monitor" },
      (payload) => asRecords(payload).map((entry) => ({ ...(asObject(entry.item) ?? {}), path: entry.path })),
    ));
  }

  getPersonalFolder() {
    return this.collect("/v2/content/folders/personal", () => this.getObject("/v2/content/folders/personal", FOLDER_MEMBERS));
  }

  listDashboards() {
    return this.collect("/v2/dashboards", () => this.listWithToken("/v2/dashboards", { mode: "allViewableByUser" }, "dashboards", DASHBOARDS_PAGE_SIZE));
  }

  getContentPermissions(contentId: string) {
    const path = `/v2/content/${encodeURIComponent(contentId)}/permissions`;
    return this.collect(path, () => this.getObject(path, CONTENT_PERMISSIONS_MEMBERS, { explicitOnly: false }));
  }
}

export function collectionOf<T>(data: T, options: Partial<SumologicCollection<T>> = {}): SumologicCollection<T> {
  return {
    ok: true,
    data,
    complete: true,
    scope: "org",
    count: Array.isArray(data) ? data.length : 1,
    ...options,
  };
}

export function failedCollection<T>(error: string, httpStatus?: number, endpoint?: string): SumologicCollection<T> {
  return { ok: false, error, httpStatus, endpoint, complete: null, scope: null };
}

interface ContentPermissionLookup {
  item: JsonRecord;
  permissions: SumologicCollection<JsonRecord>;
}

/**
 * The content_permissions dataset hangs off the personal folder listing. When
 * that listing could not be read no lookup is issued and the dataset is a
 * not-requested marker naming the folder's failure; when every issued lookup
 * failed it is not collected either (the error names each failed request, and
 * no single status or endpoint is invented for the set); otherwise it carries
 * one row per sampled item and is complete only when every lookup succeeded.
 */
function contentPermissionsCollection(
  personalFolder: SumologicCollection<JsonRecord>,
  lookups: ContentPermissionLookup[],
  failed: ContentPermissionLookup[],
): SumologicCollection<JsonRecord[]> {
  if (!personalFolder.ok) {
    return failedCollection(`Not requested: no content permission lookups were issued because the personal folder could not be read (${personalFolder.error ?? "unknown error"}).`);
  }
  const describe = (entry: ContentPermissionLookup): string => `${asString(entry.item.name) ?? asString(entry.item.id) ?? "item"}: ${entry.permissions.error ?? "unknown error"}`;
  if (lookups.length > 0 && failed.length === lookups.length) {
    return failedCollection(`every content permission lookup failed (${failed.length} of ${lookups.length}): ${failed.map(describe).join("; ")}`);
  }
  return collectionOf(
    lookups.map((entry) => ({ id: entry.item.id, name: entry.item.name, itemType: entry.item.itemType, ok: entry.permissions.ok, permissions: entry.permissions.data ?? null })),
    { complete: failed.length === 0 },
  );
}

/**
 * The object written in place of a dataset that was never collected, so a
 * bundle consumer cannot mistake a denied or failed read for an empty
 * inventory: readable-but-empty lists stay [].
 */
export function notCollectedMarker(collection: SumologicCollection<unknown>): SumologicNotCollectedMarker {
  return {
    collected: false,
    status: collection.httpStatus ?? null,
    endpoint: collection.endpoint ?? null,
    error: collection.error ?? null,
  };
}

function controlById(number: number): ControlDefinition {
  const found = SUMOLOGIC_CONTROLS.find((item) => item.number === number);
  if (!found) throw new Error(`Unknown Sumo Logic control ${number}`);
  return found;
}

function mappingsFor(definition: ControlDefinition): string[] {
  return FRAMEWORKS.map((framework) => `${framework} ${definition.mappings[framework]}`);
}

function finding(
  number: number,
  severity: SumologicFinding["severity"],
  status: SumologicFinding["status"],
  summary: string,
  evidence: JsonRecord = {},
): SumologicFinding {
  const definition = controlById(number);
  return { id: definition.id, title: definition.title, severity, status, summary, evidence, mappings: mappingsFor(definition) };
}

const UNEXPECTED_SHAPE_PATTERN = /returned a 200 body that is not the expected object/;

function unreadableCause(collection: SumologicCollection<unknown>): string {
  return collection.httpStatus === 401
    ? "credentials were rejected (401)"
    : collection.httpStatus === 403
      ? "the access key lacks the role capability (403)"
      : UNEXPECTED_SHAPE_PATTERN.test(collection.error ?? "")
        ? `the endpoint returned a 200 body that is not the expected object (${collection.error})`
        : `the endpoint returned an error (${collection.error ?? "unknown error"})`;
}

function unreadableSummary(what: string, collection: SumologicCollection<unknown>, evidenceToCollect: string): string {
  return `Unknown: ${what} could not be read because ${unreadableCause(collection)}. Collect manually: ${evidenceToCollect}`;
}

function unreadable(number: number, severity: SumologicFinding["severity"], what: string, collection: SumologicCollection<unknown>, evidenceToCollect: string): SumologicFinding {
  return finding(number, severity, "manual", unreadableSummary(what, collection, evidenceToCollect), {
    endpoint: collection.endpoint ?? null,
    endpoint_error: collection.error ?? null,
    http_status: collection.httpStatus ?? null,
  });
}

function partialNote(collection: SumologicCollection<unknown[]>): string {
  if (!collection.ok || collection.complete) return "";
  return ` Pagination stopped before the last page, so only ${collection.data?.length ?? 0} items were seen and the population is incomplete.`;
}

function withPartialDowngrade(item: SumologicFinding, collection: SumologicCollection<unknown[]>): SumologicFinding {
  if (!collection.ok || collection.complete || item.status !== "pass") return item;
  return { ...item, status: "warn", summary: `${item.summary}${partialNote(collection)}` };
}

/**
 * Uniform null rendering: a count or list derived from an unreadable
 * collection is rendered as null, never as 0 or [], so evidence cannot read
 * as "nothing found" when nothing could be read.
 */
function whenReadable<T>(collection: SumologicCollection<unknown>, value: T): T | null {
  return collection.ok ? value : null;
}

/**
 * A count judged over a paginated collection describes the whole inventory only when the walk
 * was complete: under a partial walk it renders null rather than the count of the part read,
 * since a 0 there would claim an absence from the unread part (reviewer C, item I). The seen
 * count and the completeness flag sit beside it.
 */
function whenComplete<T>(collection: SumologicCollection<unknown>, value: T): T | null {
  return collection.ok && collection.complete !== false ? value : null;
}

/**
 * Rule 10 for findings that read several paginated inventories: every
 * inventory whose pagination stopped early is named in the summary, and a
 * pass becomes warn because the population it was judged on is incomplete.
 */
function withPartialDowngrades(item: SumologicFinding, inventories: Array<[string, SumologicCollection<unknown[]>]>): SumologicFinding {
  const incomplete = inventories.filter(([, collection]) => collection.ok && !collection.complete);
  if (incomplete.length === 0) return item;
  const notes = incomplete
    .map(([label, collection]) => ` Pagination of the ${label} stopped before the last page, so only ${collection.data?.length ?? 0} were seen and that population is incomplete.`)
    .join("");
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary}${notes}`,
    evidence: { ...item.evidence, incomplete_inventories: incomplete.map(([label]) => label) },
  };
}

/**
 * Rule 1 corollary: a finding that reads several inventories never passes when
 * one of them was unreadable, even if the primary inventory supports pass. The
 * summary names the unreadable inventory and the evidence a human must collect;
 * `status` is the verdict a pass drops to (manual when the inventory is
 * essential to the control, warn when the control can still be judged from
 * the readable inventories). Existing warn/fail/manual verdicts keep their
 * status and only gain the note.
 */
function withUnreadableDowngrade(
  item: SumologicFinding,
  label: string,
  collection: SumologicCollection<unknown>,
  evidenceToCollect: string,
  status: "warn" | "manual" = "warn",
): SumologicFinding {
  if (collection.ok) return item;
  const previous = asArray(item.evidence?.unreadable_inventories).map((entry) => String(entry));
  return {
    ...item,
    status: item.status === "pass" ? status : item.status,
    summary: `${item.summary} Not checked: the ${label} could not be read because ${unreadableCause(collection)}; collect manually: ${evidenceToCollect}`,
    evidence: { ...item.evidence, unreadable_inventories: [...previous, label] },
  };
}

function names(items: JsonRecord[], key = "name", limit = 25): string[] {
  return items.slice(0, limit).map((item) => asString(item[key]) ?? asString(item.id) ?? asString(item.email) ?? "unnamed");
}

function flagText(value: unknown): string {
  return typeof value === "boolean" ? String(value) : "absent";
}

interface UserActivityBuckets {
  locked: JsonRecord[];
  recentLogin: JsonRecord[];
  dormant: JsonRecord[];
  undatedLogin: JsonRecord[];
}

function userActivityBuckets(users: JsonRecord[], now: Date, inactiveDays: number): UserActivityBuckets {
  const active = users.filter((user) => user.isActive === true);
  const loginAge = (user: JsonRecord) => ageInDays(user.lastLoginTimestamp, now);
  return {
    locked: users.filter((user) => user.isLocked === true),
    recentLogin: active.filter((user) => (loginAge(user) ?? Number.POSITIVE_INFINITY) <= inactiveDays),
    dormant: active.filter((user) => (loginAge(user) ?? -1) > inactiveDays),
    undatedLogin: active.filter((user) => loginAge(user) === undefined),
  };
}

type KeyLifetimeState = "enforced" | "never-expire" | "absent" | "unreadable";

interface KeyLifetimePolicy {
  state: KeyLifetimeState;
  days: number | null;
  text: string;
}

function keyLifetimePolicy(policy: SumologicCollection<JsonRecord>): KeyLifetimePolicy {
  if (!policy.ok) {
    return { state: "unreadable", days: null, text: `The access key lifetime policy was unreadable (${policy.error ?? "unknown error"}).` };
  }
  const days = asNumber(policy.data?.accessKeysLifetimeInDays);
  if (days === undefined) {
    return { state: "absent", days: null, text: "The access key lifetime policy response did not include accessKeysLifetimeInDays." };
  }
  if (days <= 0) {
    return { state: "never-expire", days, text: "The access key lifetime policy is 0 (keys never expire)." };
  }
  return { state: "enforced", days, text: `The access key lifetime policy is ${days} days.` };
}

function collectErrors(collections: Array<[string, SumologicCollection<unknown>]>): string[] {
  return collections.filter(([, item]) => !item.ok).map(([name, item]) => `${name}: ${item.error ?? "unknown error"}`);
}

const REDACTED = "[REDACTED]";

function pick(record: JsonRecord, keys: readonly string[]): JsonRecord {
  return Object.fromEntries(keys.filter((key) => record[key] !== undefined).map((key) => [key, record[key]]));
}

function redactionMarker(value: unknown): string | undefined {
  return value === undefined || value === null ? undefined : REDACTED;
}

function redactedHeaderPairs(value: unknown): JsonRecord[] | undefined {
  if (value === undefined || value === null) return undefined;
  return asRecords(value).map((pair) => ({ name: asString(pair.name) ?? null, value: REDACTED }));
}

function withoutUndefined(record: JsonRecord): JsonRecord {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

type SnapshotProjector = (record: JsonRecord) => JsonRecord;

/**
 * Rule 9 allowlist projections applied to every raw snapshot before it is
 * written to core_data or echoed in a tool payload. Each projector keeps the
 * fields the verdicts read plus identifying metadata, and replaces every
 * credential-bearing or free-text field with a marker so the evidence stays
 * legible without carrying the value.
 */
const SNAPSHOT_PROJECTIONS: Readonly<Record<string, SnapshotProjector>> = {
  connections: (connection) => withoutUndefined({
    ...pick(connection, ["id", "name", "type", "webhookType", "connectionSubtype", "createdBy", "createdAt", "modifiedBy", "modifiedAt"]),
    url_host: hostOf(asString(connection.url)) ?? null,
    url: redactionMarker(connection.url),
    username: redactionMarker(connection.username),
    headers: redactedHeaderPairs(connection.headers),
    customHeaders: redactedHeaderPairs(connection.customHeaders),
    defaultPayload: redactionMarker(connection.defaultPayload),
    resolutionPayload: redactionMarker(connection.resolutionPayload),
  }),
  monitors: (monitor) => withoutUndefined({
    ...pick(monitor, ["id", "name", "path", "type", "monitorType", "contentType", "isDisabled", "isSystem", "isMutable", "status", "createdBy", "createdAt", "modifiedBy", "modifiedAt"]),
    runAs: monitor.runAs === undefined ? undefined : { runAsId: asString(asObject(monitor.runAs)?.runAsId) ?? null },
    notifications: monitor.notifications === undefined ? undefined : asRecords(monitor.notifications).map((entry) => {
      const notification = asObject(entry.notification) ?? {};
      return withoutUndefined({
        runForTriggerTypes: entry.runForTriggerTypes,
        notification: withoutUndefined({
          ...pick(notification, ["connectionType", "connectionId", "recipients"]),
          subject: redactionMarker(notification.subject),
          messageBody: redactionMarker(notification.messageBody),
          payloadOverride: redactionMarker(notification.payloadOverride),
          resolutionPayloadOverride: redactionMarker(notification.resolutionPayloadOverride),
        }),
      });
    }),
  }),
  access_keys: (key) => ({
    ...pick(key, ["label", "disabled", "createdAt", "createdBy", "modifiedAt", "lastUsed", "scopes"]),
    id_prefix: asString(key.id)?.slice(0, 4) ?? null,
    cors_header_count: asArray(key.corsHeaders).length,
  }),
  saml_identity_providers: (idp) => withoutUndefined({
    ...pick(idp, [
      "id", "configurationName", "issuer", "authnRequestUrl", "spInitiatedLoginEnabled", "spInitiatedLoginPath", "signAuthnRequest",
      "disableRequestedAuthnContext", "debugMode", "isRedirectBinding", "rolesAttribute", "emailAttribute", "logoutEnabled", "logoutUrl",
      "onDemandProvisioningEnabled", "createdBy", "createdAt", "modifiedBy", "modifiedAt",
    ]),
    x509cert1: redactionMarker(idp.x509cert1),
    x509cert2: redactionMarker(idp.x509cert2),
    x509cert3: redactionMarker(idp.x509cert3),
    certificate: redactionMarker(idp.certificate),
  }),
  password_policy: (policy) => pick(policy, [
    "minLength", "maxLength", "mustContainLowercase", "mustContainUppercase", "mustContainDigits", "mustContainSpecialChars",
    "maxPasswordAgeInDays", "minUniquePasswords", "accountLockoutThreshold", "failedLoginResetDurationInMins", "accountLockoutDurationInMins",
    "requireMfa", "rememberMfa", "disallowWeakPasswords",
  ]),
  users: (user) => pick(user, ["id", "email", "firstName", "lastName", "isActive", "isLocked", "isMfaEnabled", "lastLoginTimestamp", "createdAt", "createdBy", "modifiedAt", "roleIds"]),
  collectors: (collector) => pick(collector, [
    "id", "name", "collectorType", "alive", "ephemeral", "collectorVersion", "lastSeenAlive", "hostName", "osName", "osVersion", "category", "timeZone", "sourceSyncMode",
  ]),
  dashboards: (dashboard) => pick(dashboard, ["id", "title", "folderId", "contentId", "isPublic", "domain", "createdBy", "createdAt", "modifiedBy", "modifiedAt"]),
  personal_folder: (folder) => withoutUndefined({
    ...pick(folder, ["id", "name", "itemType", "parentId", "createdBy", "createdAt", "modifiedBy", "modifiedAt"]),
    children: folder.children === undefined ? undefined : asRecords(folder.children).map((child) => pick(child, ["id", "name", "itemType", "parentId", "isScheduled", "permissions", "createdBy", "createdAt", "modifiedBy", "modifiedAt"])),
  }),
};

function projectSnapshotData(name: string, data: unknown): unknown {
  const projector = SNAPSHOT_PROJECTIONS[name];
  if (!projector || data === undefined || data === null) return data ?? null;
  if (Array.isArray(data)) return asRecords(data).map(projector);
  const record = asObject(data);
  return record ? projector(record) : data;
}

/**
 * Rule 9 deny list for the datasets the projections above pass through
 * (roles, partitions, scheduled views, policies): matched on the lowercased
 * key with dots, underscores, and hyphens removed, so accessKey, client_secret,
 * and authorization match while accessId, roleIds, and label stay legible.
 */
const CREDENTIAL_KEY_PATTERN = /(password|passwd|passphrase|secret|token|apikey|privatekey|secretkey|accesskey|authorization)$/;

function isCredentialKey(key: string): boolean {
  return CREDENTIAL_KEY_PATTERN.test(key.toLowerCase().replace(/[._-]/g, ""));
}

/**
 * Applied to every projected snapshot before it is written to core_data or
 * echoed in a tool payload: redacts the value of every credential-named key
 * (including {name, value} and {key, value} pair shapes), keeps only the
 * origin of a webhook-named key's URL, and passes every other string leaf
 * through the data-side text pass, so a vendor-prefixed token, a JWT, a PEM
 * block, or a credential carrier inside a free-text field (a role description,
 * a query, a serialized snapshot) is removed there too. Key names are kept so
 * the evidence stays legible.
 */
export function redactSnapshot(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSnapshot);
  const object = asObject(value);
  if (!object) return typeof value === "string" ? scrubDataText(value) : value;
  const pairName = asString(object.name) ?? asString(object.key);
  const output: JsonRecord = {};
  for (const [key, item] of Object.entries(object)) {
    if (isCredentialKey(key) || (key === "value" && pairName !== undefined && isCredentialKey(pairName))) {
      output[key] = item === null || item === undefined ? item : REDACTED;
    } else if (typeof item === "string" && pairRuleFor(key) === "webhook") {
      output[key] = webhookReplacement(item);
    } else {
      output[key] = redactSnapshot(item);
    }
  }
  return output;
}

/**
 * The single serializer for every raw snapshot: core_data/<area>.json and the
 * rawData echoed by the assess tools both come from here, so the rule 9
 * projection above and the deny-list walk are applied exactly once and on
 * every path.
 */
function rawSnapshot(collections: Array<[string, SumologicCollection<unknown>]>): Record<string, unknown> {
  return Object.fromEntries(collections.map(([name, item]) => [name, {
    ok: item.ok,
    complete: item.ok ? item.complete : null,
    scope: item.ok ? item.scope : null,
    count: item.ok ? item.count ?? null : null,
    error: item.error ?? null,
    http_status: item.httpStatus ?? null,
    endpoint: item.endpoint ?? null,
    data: item.ok ? redactSnapshot(projectSnapshotData(name, item.data)) : notCollectedMarker(item),
  }]));
}

function parseSessionTimeoutMinutes(value: unknown): number | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const match = /^(\d+)\s*(m|h|d)$/i.exec(text);
  if (!match) return asNumber(text);
  const amount = Number(match[1]);
  switch (match[2].toLowerCase()) {
    case "m":
      return amount;
    case "h":
      return amount * 60;
    case "d":
      return amount * 1440;
    default:
      return undefined;
  }
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function domainMatches(host: string, approved: string[]): boolean {
  return approved.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

export async function checkSumologicAccess(client: SumologicReader): Promise<SumologicAccessCheckResult> {
  const config = client.getResolvedConfig();
  const probes: Array<[string, string, string, () => Promise<SumologicCollection<unknown>>]> = [
    ["account_status", "/v1/account/status", "viewAccountOverview", () => client.getAccountStatus()],
    ["users", "/v1/users", "manageUsersAndRoles", () => client.listUsers()],
    ["roles", "/v1/roles", "manageUsersAndRoles", () => client.listRoles()],
    ["access_keys", "/v1/accessKeys", "manageAccessKeys (falls back to createAccessKeys for personal keys)", () => client.listAccessKeys()],
    ["saml_identity_providers", "/v1/saml/identityProviders", "manageSaml", () => client.listSamlIdentityProviders()],
    ["saml_allowlisted_users", "/v1/saml/allowlistedUsers", "manageSaml", () => client.listSamlAllowlistedUsers()],
    ["password_policy", "/v1/passwordPolicy", "managePasswordPolicy", () => client.getPasswordPolicy()],
    ["service_allowlist_status", "/v1/serviceAllowlist/status", "ipAllowlisting", () => client.getServiceAllowlistStatus()],
    ["service_allowlist_addresses", "/v1/serviceAllowlist/addresses", "ipAllowlisting", () => client.listServiceAllowlistAddresses()],
    ["audit_policy", "/v1/policies/audit", "manageOrgSettings", () => client.getPolicy("audit")],
    ["partitions", "/v1/partitions", "viewPartitions", () => client.listPartitions()],
    ["scheduled_views", "/v1/scheduledViews", "viewScheduledViews", () => client.listScheduledViews()],
    ["ingest_budgets", "/v2/ingestBudgets", "manageBudgets", () => client.listIngestBudgets()],
    ["connections", "/v1/connections", "viewConnections", () => client.listConnections()],
    ["collectors", "/v1/collectors", "viewCollectors", () => client.listCollectors()],
    ["monitors", "/v1/monitors/search", "viewMonitorsV2", () => client.listMonitors()],
    ["personal_folder", "/v2/content/folders/personal", "manageContent", () => client.getPersonalFolder()],
    ["dashboards", "/v2/dashboards", "manageContent", () => client.listDashboards()],
  ];

  const surfaces: SumologicAccessSurface[] = [];
  for (const [name, endpoint, capabilityHint, load] of probes) {
    const collection = await load();
    surfaces.push({
      name,
      endpoint: collection.ok ? endpoint : collection.endpoint ?? endpoint,
      status: collection.ok ? "readable" : "not_readable",
      count: collection.ok ? collection.count ?? null : null,
      complete: collection.ok ? collection.complete : null,
      httpStatus: collection.ok ? null : collection.httpStatus ?? null,
      error: collection.error,
      capabilityHint,
    });
  }

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const missingCapabilities = [...new Set(surfaces.filter((surface) => surface.status === "not_readable").map((surface) => surface.capabilityHint))];
  const status = readableCount === surfaces.length ? "healthy" : "limited";

  return {
    status,
    baseUrl: config.baseUrl,
    surfaces,
    missingCapabilities,
    notes: [
      `Using Sumo Logic API ${config.baseUrl}${config.deployment ? ` (deployment ${config.deployment})` : ""}.`,
      `Access ID ${config.accessId.slice(0, 4)}... resolved from ${config.sourceChain.join(", ")}.`,
      `${readableCount}/${surfaces.length} Sumo Logic audit surfaces are readable.`,
    ],
    recommendedNextStep: status === "healthy"
      ? "Run sumologic_assess_identity, sumologic_assess_access_control, sumologic_assess_data_governance, sumologic_assess_content_sharing, or sumologic_export_audit_bundle."
      : `Grant the access key owner a role with: ${missingCapabilities.join(", ")}. Unreadable surfaces render as manual findings, never as passes.`,
  };
}

export async function assessSumologicIdentity(
  client: SumologicReader,
  options: SumologicAssessmentOptions = {},
): Promise<SumologicAssessmentResult> {
  const now = options.now ?? new Date();
  const maxAllowlisted = clampNumber(options.maxAllowlistedUsers, DEFAULT_MAX_ALLOWLISTED_USERS, 0, 1000);
  const minPasswordLength = clampNumber(options.minPasswordLength, DEFAULT_MIN_PASSWORD_LENGTH, 1, 128);
  const maxPasswordAge = clampNumber(options.maxPasswordAgeDays, DEFAULT_MAX_PASSWORD_AGE_DAYS, 1, 3650);
  const userInactiveDays = clampNumber(options.userInactiveDays, DEFAULT_USER_INACTIVE_DAYS, 1, 3650);

  const [identityProviders, allowlisted, passwordPolicy, users] = await Promise.all([
    client.listSamlIdentityProviders(),
    client.listSamlAllowlistedUsers(),
    client.getPasswordPolicy(),
    client.listUsers(),
  ]);
  const collections: Array<[string, SumologicCollection<unknown>]> = [
    ["saml_identity_providers", identityProviders],
    ["saml_allowlisted_users", allowlisted],
    ["password_policy", passwordPolicy],
    ["users", users],
  ];
  const findings: SumologicFinding[] = [];

  const idps = identityProviders.data ?? [];
  if (!identityProviders.ok) {
    findings.push(unreadable(1, "critical", "SAML identity providers", identityProviders, "export Administration > Security > SAML and confirm 'Require SAML sign-in' is enabled."));
  } else if (idps.length === 0) {
    findings.push(finding(1, "critical", "fail", "Zero SAML identity providers are configured (endpoint readable), so users authenticate with local passwords only.", { identity_providers: 0 }));
  } else {
    const debugProviders = idps.filter((idp) => idp.debugMode === true);
    const unsignedProviders = idps.filter((idp) => idp.signAuthnRequest !== true);
    const missingCert = idps.filter((idp) => !asString(idp.x509cert1) && !asString(idp.certificate));
    const evidence = {
      identity_providers: names(idps, "configurationName"),
      debug_mode_enabled: names(debugProviders, "configurationName"),
      sign_authn_request_disabled: names(unsignedProviders, "configurationName"),
      disable_requested_authn_context: idps.map((idp) => idp.disableRequestedAuthnContext === true),
      sp_initiated_login_enabled: idps.map((idp) => idp.spInitiatedLoginEnabled === true),
      missing_certificate: names(missingCert, "configurationName"),
    };
    if (debugProviders.length > 0 || missingCert.length > 0) {
      findings.push(finding(1, "critical", "warn", `${idps.length} SAML identity provider(s) configured, but ${debugProviders.length} run in debug mode and ${missingCert.length} expose no signing certificate. SAML lockdown state is not exposed by the API; confirm 'Require SAML sign-in' in Administration > Security > SAML.`, evidence));
    } else {
      findings.push(finding(1, "critical", "manual", `${idps.length} SAML identity provider(s) configured (${names(idps, "configurationName").join(", ")}). The API does not expose whether SAML sign-in is required (lockdown), so a human must confirm 'Require SAML sign-in' is enabled in Administration > Security > SAML and that no local-password users remain outside the allowlist.`, evidence));
    }
  }

  const allowlistedUsers = allowlisted.data ?? [];
  if (!allowlisted.ok) {
    findings.push(unreadable(2, "high", "SAML allowlisted users", allowlisted, "screenshot Administration > Security > SAML > allowlisted users and justify each break-glass account."));
  } else if (identityProviders.ok && idps.length === 0) {
    findings.push(finding(2, "high", "manual", "Not applicable: no SAML identity provider is configured, so the SAML bypass allowlist has no effect. Re-run after SSO is configured.", { allowlisted_users: allowlistedUsers.length }));
  } else {
    const inactive = allowlistedUsers.filter((user) => user.isActive === false);
    const evidence = { allowlisted_users: names(allowlistedUsers, "email"), inactive_allowlisted_users: names(inactive, "email"), threshold: maxAllowlisted, identity_providers_readable: identityProviders.ok, identity_providers: whenReadable(identityProviders, idps.length) };
    let allowlistFinding: SumologicFinding;
    if (allowlistedUsers.length > maxAllowlisted) {
      allowlistFinding = finding(2, "high", "fail", `${allowlistedUsers.length} users bypass SAML (threshold ${maxAllowlisted}); reduce the allowlist to break-glass accounts only.`, evidence);
    } else if (inactive.length > 0) {
      allowlistFinding = finding(2, "high", "warn", `${allowlistedUsers.length} allowlisted users are within the threshold of ${maxAllowlisted}, but ${inactive.length} are inactive accounts that should be removed.`, evidence);
    } else {
      allowlistFinding = finding(2, "high", "pass", `${allowlistedUsers.length} SAML allowlisted user(s) (endpoint readable, threshold ${maxAllowlisted}); emptiness here is compliant because the control asks for a minimized allowlist.`, evidence);
    }
    findings.push(withUnreadableDowngrade(allowlistFinding, "SAML identity provider list", identityProviders, "export Administration > Security > SAML to confirm SAML is configured so that this allowlist is actually in effect."));
  }

  const policy = passwordPolicy.data ?? {};
  if (!passwordPolicy.ok) {
    findings.push(unreadable(3, "high", "the password policy", passwordPolicy, "screenshot Administration > Security > Password Policy showing length, complexity, and lockout settings."));
    findings.push(unreadable(4, "medium", "the password policy", passwordPolicy, "screenshot the password expiration (maximum age) setting."));
  } else {
    const minLength = asNumber(policy.minLength);
    const complexity = ["mustContainLowercase", "mustContainUppercase", "mustContainDigits", "mustContainSpecialChars"].filter((key) => policy[key] !== true);
    const lockout = asNumber(policy.accountLockoutThreshold);
    const weakDisallowed = policy.disallowWeakPasswords === true;
    const evidence = { min_length: minLength ?? null, missing_complexity_flags: complexity, account_lockout_threshold: lockout ?? null, disallow_weak_passwords: weakDisallowed, required_min_length: minPasswordLength };
    if (minLength === undefined || lockout === undefined) {
      findings.push(finding(3, "high", "manual", "The password policy response did not include minLength or accountLockoutThreshold, so strength cannot be confirmed; verify the policy in the UI.", evidence));
    } else if (minLength < minPasswordLength || lockout <= 0) {
      findings.push(finding(3, "high", "fail", `Password minimum length is ${minLength} (required ${minPasswordLength}) and lockout threshold is ${lockout}; both must be enforced.`, evidence));
    } else if (complexity.length > 0 || !weakDisallowed) {
      findings.push(finding(3, "high", "warn", `Minimum length ${minLength} and lockout after ${lockout} attempts are enforced, but complexity flags ${complexity.join(", ") || "(none missing)"} or weak-password rejection (${weakDisallowed}) are not all enabled.`, evidence));
    } else {
      findings.push(finding(3, "high", "pass", `Password policy enforces minimum length ${minLength}, all four complexity classes, weak-password rejection, and lockout after ${lockout} failed attempts.`, evidence));
    }

    const maxAge = asNumber(policy.maxPasswordAgeInDays);
    const ageEvidence = { max_password_age_days: maxAge ?? null, threshold_days: maxPasswordAge };
    if (maxAge === undefined) {
      findings.push(finding(4, "medium", "manual", "The password policy response did not include maxPasswordAgeInDays; confirm the rotation setting in Administration > Security > Password Policy.", ageEvidence));
    } else if (maxAge <= 0) {
      findings.push(finding(4, "medium", "fail", "Password expiration is disabled (maxPasswordAgeInDays is 0), so local passwords never rotate.", ageEvidence));
    } else if (maxAge > maxPasswordAge) {
      findings.push(finding(4, "medium", "fail", `Passwords expire after ${maxAge} days, exceeding the ${maxPasswordAge}-day threshold.`, ageEvidence));
    } else {
      findings.push(finding(4, "medium", "pass", `Passwords expire after ${maxAge} days (threshold ${maxPasswordAge}).`, ageEvidence));
    }
  }

  const userList = users.data ?? [];
  const activeUsers = userList.filter((user) => user.isActive === true);
  const activeWithoutMfa = activeUsers.filter((user) => user.isMfaEnabled !== true);
  const usersMissingActiveFlag = userList.filter((user) => typeof user.isActive !== "boolean");
  const activity = userActivityBuckets(userList, now, userInactiveDays);
  const requireMfaFlag = passwordPolicy.ok ? policy.requireMfa : undefined;
  const requireMfa = requireMfaFlag === true;
  const mfaEvidence = {
    require_mfa_policy: passwordPolicy.ok ? flagText(requireMfaFlag) : null,
    users_readable: users.ok,
    users_seen: whenReadable(users, userList.length),
    users_complete: whenReadable(users, users.complete),
    active_users: whenReadable(users, activeUsers.length),
    active_users_without_mfa: whenReadable(users, names(activeWithoutMfa, "email")),
    users_missing_is_active_flag: whenReadable(users, usersMissingActiveFlag.length),
    locked_users: whenReadable(users, names(activity.locked, "email")),
    active_users_with_recent_login: whenReadable(users, activity.recentLogin.length),
    dormant_active_users: whenReadable(users, names(activity.dormant, "email")),
    active_users_without_last_login: whenReadable(users, names(activity.undatedLogin, "email")),
    user_inactive_threshold_days: userInactiveDays,
  };
  const perUserMfaText = users.ok
    ? `${activeWithoutMfa.length}/${activeUsers.length} seen active users report MFA disabled`
    : `per-user MFA status is unknown because the user list could not be read (${unreadableCause(users)})`;
  if (!passwordPolicy.ok && !users.ok) {
    findings.push(unreadable(5, "critical", "the MFA policy and user list", passwordPolicy, "screenshot the Require MFA setting and export the user list with MFA status."));
  } else if (!passwordPolicy.ok) {
    findings.push(finding(5, "critical", "manual", `The password policy was unreadable, so org-wide MFA enforcement is unknown; ${perUserMfaText}. Confirm Require MFA in Administration > Security > Password Policy.`, mfaEvidence));
  } else if (!requireMfa) {
    findings.push(finding(5, "critical", "fail", `The password policy does not require MFA (requireMfa=${flagText(requireMfaFlag)}); ${perUserMfaText}.`, mfaEvidence));
  } else if (!users.ok) {
    findings.push(finding(5, "critical", "manual", `Require MFA is enabled, but the user list was unreadable (${users.error ?? "unknown error"}), so per-user coverage cannot be confirmed; export the user list with MFA status.`, mfaEvidence));
  } else if (userList.length === 0) {
    findings.push(finding(5, "critical", "manual", "Require MFA is enabled, but zero users were returned, which indicates a capability-limited key; export the user list with MFA status.", mfaEvidence));
  } else if (activeWithoutMfa.length > 0) {
    findings.push(finding(5, "critical", "warn", `Require MFA is enabled, but ${activeWithoutMfa.length}/${activeUsers.length} seen active users report isMfaEnabled=false (SAML-only users may legitimately lack local MFA; confirm each).${partialNote(users)}`, mfaEvidence));
  } else {
    findings.push(withPartialDowngrade(finding(5, "critical", "pass", `Require MFA is enabled and all ${activeUsers.length} active users (of ${userList.length} seen) report MFA enabled.`, mfaEvidence), users));
  }

  return {
    title: "Sumo Logic identity posture",
    area: "identity",
    summary: {
      identity_providers: whenReadable(identityProviders, idps.length),
      allowlisted_users: whenReadable(allowlisted, allowlistedUsers.length),
      users_seen: whenReadable(users, userList.length),
      users_complete: whenReadable(users, users.complete),
      active_users_without_mfa: whenComplete(users, activeWithoutMfa.length),
      locked_users: whenComplete(users, activity.locked.length),
      dormant_active_users: whenComplete(users, activity.dormant.length),
      active_users_without_last_login: whenComplete(users, activity.undatedLogin.length),
      unreadable_surfaces: collectErrors(collections).length,
    },
    findings,
    errors: collectErrors(collections),
    rawData: rawSnapshot(collections),
  };
}

export async function assessSumologicAccessControl(
  client: SumologicReader,
  options: SumologicAssessmentOptions = {},
): Promise<SumologicAssessmentResult> {
  const now = options.now ?? new Date();
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10000);
  const keyMaxAge = clampNumber(options.keyMaxAgeDays, DEFAULT_KEY_MAX_AGE_DAYS, 1, 3650);
  const keyInactive = clampNumber(options.keyInactiveDays, DEFAULT_KEY_INACTIVE_DAYS, 1, 3650);
  const userInactiveDays = clampNumber(options.userInactiveDays, DEFAULT_USER_INACTIVE_DAYS, 1, 3650);
  const maxSessionMinutes = clampNumber(options.maxSessionTimeoutMinutes, DEFAULT_MAX_SESSION_TIMEOUT_MINUTES, 1, 10080);

  const [roles, users, accessKeys, allowlistStatus, allowlistAddresses, sessionTimeout, concurrentSessions, keyLifetime] = await Promise.all([
    client.listRoles(),
    client.listUsers(),
    client.listAccessKeys(),
    client.getServiceAllowlistStatus(),
    client.listServiceAllowlistAddresses(),
    client.getPolicy("maxUserSessionTimeout"),
    client.getPolicy("userConcurrentSessionsLimit"),
    client.getPolicy("accessKeysLifetime"),
  ]);
  const collections: Array<[string, SumologicCollection<unknown>]> = [
    ["roles", roles],
    ["users", users],
    ["access_keys", accessKeys],
    ["service_allowlist_status", allowlistStatus],
    ["service_allowlist_addresses", allowlistAddresses],
    ["max_user_session_timeout_policy", sessionTimeout],
    ["user_concurrent_sessions_limit_policy", concurrentSessions],
    ["access_keys_lifetime_policy", keyLifetime],
  ];
  const findings: SumologicFinding[] = [];

  const roleList = roles.data ?? [];
  const userList = users.data ?? [];
  const activity = userActivityBuckets(userList, now, userInactiveDays);
  if (!roles.ok) {
    findings.push(unreadable(6, "high", "the role list", roles, "export Administration > Users and Roles > Roles with capabilities and member counts."));
  } else if (roleList.length === 0) {
    findings.push(finding(6, "high", "manual", "Zero roles were returned even though every org has a system Administrator role, so the key sees a partial inventory; export the role list manually.", { roles_seen: 0 }));
  } else {
    const adminRoles = roleList.filter((role) => asStringList(role.capabilities).some((capability) => ADMIN_CAPABILITIES.has(capability)) || /^administrator$/i.test(asString(role.name) ?? ""));
    const customAdminRoles = adminRoles.filter((role) => role.systemDefined !== true);
    const adminUserIds = new Set<string>();
    for (const role of adminRoles) for (const id of asArray(role.users)) if (asString(id)) adminUserIds.add(asString(id) as string);
    const unscopedRoles = roleList.filter((role) => !asString(role.filterPredicate) && role.systemDefined !== true);
    const adminMembers = userList.filter((user) => adminUserIds.has(asString(user.id) ?? ""));
    const adminActivity = userActivityBuckets(adminMembers, now, userInactiveDays);
    const evidence = {
      roles_seen: roleList.length,
      roles_complete: roles.complete,
      admin_roles: names(adminRoles),
      custom_roles_with_admin_capabilities: names(customAdminRoles),
      admin_role_members: adminUserIds.size,
      max_admins: maxAdmins,
      custom_roles_without_filter_predicate: names(unscopedRoles),
      users_readable: users.ok,
      users_complete: whenReadable(users, users.complete),
      locked_users: whenReadable(users, names(activity.locked, "email")),
      dormant_active_users: whenReadable(users, names(activity.dormant, "email")),
      active_users_without_last_login: whenReadable(users, names(activity.undatedLogin, "email")),
      admin_members_seen_in_user_list: whenReadable(users, adminMembers.length),
      dormant_admin_members: whenReadable(users, names(adminActivity.dormant, "email")),
      admin_members_without_last_login: whenReadable(users, names(adminActivity.undatedLogin, "email")),
      user_inactive_threshold_days: userInactiveDays,
    };
    const concerns: string[] = [];
    if (customAdminRoles.length > 0) {
      concerns.push(`${customAdminRoles.length} custom role(s) carry administrative capabilities (${names(customAdminRoles).join(", ")})`);
    }
    if (unscopedRoles.length > 0) {
      concerns.push(`${unscopedRoles.length} custom role(s) have no filterPredicate and grant unrestricted search scope (${names(unscopedRoles).join(", ")})`);
    }
    if (!users.ok) {
      concerns.push("the user list was unreadable, so admin member activity could not be checked");
    } else if (!users.complete) {
      concerns.push("user list pagination was incomplete, so admin member activity was checked on a partial population");
    }
    if (adminActivity.dormant.length > 0) {
      concerns.push(`${adminActivity.dormant.length} admin role member(s) have not logged in for over ${userInactiveDays} days (${names(adminActivity.dormant, "email").join(", ")})`);
    }
    if (adminActivity.undatedLogin.length > 0) {
      concerns.push(`${adminActivity.undatedLogin.length} admin role member(s) have no lastLoginTimestamp and are not counted as active (${names(adminActivity.undatedLogin, "email").join(", ")})`);
    }
    if (adminUserIds.size > maxAdmins) {
      findings.push(finding(6, "high", "fail", `${adminUserIds.size} users hold roles with administrative capabilities (threshold ${maxAdmins}) across ${adminRoles.length} admin-like roles.${concerns.length > 0 ? ` Also: ${concerns.join("; ")}.` : ""}${partialNote(roles)}`, evidence));
    } else if (concerns.length > 0) {
      findings.push(finding(6, "high", "warn", `${concerns.join("; ")}; ${adminUserIds.size} admin members are within the threshold of ${maxAdmins}. Least privilege requires scoped custom roles and active, individually owned admin accounts.${partialNote(roles)}`, evidence));
    } else {
      findings.push(withPartialDowngrade(finding(6, "high", "pass", `${roleList.length} roles reviewed: administrative capabilities are limited to ${adminRoles.length} system role(s) with ${adminUserIds.size} members (threshold ${maxAdmins}), every custom role carries a filterPredicate, and all admin members logged in within ${userInactiveDays} days.`, evidence), roles));
    }
  }

  const keys = accessKeys.data ?? [];
  const keyEvidenceBase = { keys_seen: whenReadable(accessKeys, keys.length), keys_complete: whenReadable(accessKeys, accessKeys.complete), scope: whenReadable(accessKeys, accessKeys.scope) };
  if (!accessKeys.ok) {
    findings.push(unreadable(7, "high", "the access key inventory", accessKeys, "export Administration > Security > Access Keys with created dates."));
    findings.push(unreadable(8, "medium", "the access key inventory", accessKeys, "export Administration > Security > Access Keys with last-used dates."));
  } else {
    const enabledKeys = keys.filter((key) => key.disabled !== true);
    const disabledKeys = keys.filter((key) => key.disabled === true);
    const staleKeys = enabledKeys.filter((key) => (ageInDays(key.createdAt, now) ?? -1) > keyMaxAge);
    const undatedKeys = enabledKeys.filter((key) => ageInDays(key.createdAt, now) === undefined);
    const corsKeys = enabledKeys.filter((key) => asArray(key.corsHeaders).length > 0);
    const lifetime = keyLifetimePolicy(keyLifetime);
    const rotationEvidence = {
      ...keyEvidenceBase,
      enabled_keys: enabledKeys.length,
      disabled_keys: disabledKeys.length,
      keys_older_than_threshold: names(staleKeys, "label"),
      keys_missing_created_at: names(undatedKeys, "label"),
      keys_with_cors_headers: names(corsKeys, "label"),
      access_keys_lifetime_policy_days: lifetime.days,
      access_keys_lifetime_policy_state: lifetime.state,
      threshold_days: keyMaxAge,
    };
    const scopeNote = accessKeys.scope === "personal" ? " Only the caller's personal keys were visible (manageAccessKeys missing), so the org-wide population is unknown." : "";
    if (keys.length === 0) {
      findings.push(finding(7, "high", "manual", `Zero access keys were returned even though the calling key must appear in the inventory, so the view is partial; export Administration > Security > Access Keys manually. ${lifetime.text}`, rotationEvidence));
      findings.push(finding(8, "medium", "manual", "Zero access keys were returned even though the calling key must appear in the inventory, so the view is partial; export the key list with last-used dates manually.", { ...keyEvidenceBase }));
    } else if (accessKeys.scope === "personal") {
      findings.push(finding(7, "high", "manual", `Partial view: ${keys.length} personal access key(s) seen, ${staleKeys.length} older than ${keyMaxAge} days.${scopeNote} Grant manageAccessKeys or export the org-wide key list. ${lifetime.text}`, rotationEvidence));
      findings.push(finding(8, "medium", "manual", `Partial view: ${keys.length} personal access key(s) seen.${scopeNote} Grant manageAccessKeys or export the org-wide key list with last-used dates.`, { ...keyEvidenceBase }));
    } else {
      if (staleKeys.length > 0) {
        findings.push(finding(7, "high", "fail", `${staleKeys.length}/${enabledKeys.length} enabled access keys were created more than ${keyMaxAge} days ago and have not been rotated. ${lifetime.text}${partialNote(accessKeys)}`, rotationEvidence));
      } else if (undatedKeys.length > 0) {
        findings.push(finding(7, "high", "warn", `No enabled key is older than ${keyMaxAge} days, but ${undatedKeys.length} key(s) lack a createdAt timestamp and cannot be counted as fresh. ${lifetime.text}${partialNote(accessKeys)}`, rotationEvidence));
      } else if (lifetime.state !== "enforced") {
        findings.push(finding(7, "high", "warn", `All ${enabledKeys.length} enabled access key(s) were created within ${keyMaxAge} days, but the platform does not enforce expiry. ${lifetime.text} Set the access key lifetime policy so rotation does not depend on manual review.${partialNote(accessKeys)}`, rotationEvidence));
      } else {
        findings.push(withPartialDowngrade(finding(7, "high", "pass", `${enabledKeys.length} enabled access key(s) seen (org scope, endpoint readable); all were created within ${keyMaxAge} days. ${lifetime.text}`, rotationEvidence), accessKeys));
      }

      const inactiveKeys = enabledKeys.filter((key) => (ageInDays(key.lastUsed, now) ?? -1) > keyInactive);
      const neverUsedKeys = enabledKeys.filter((key) => ageInDays(key.lastUsed, now) === undefined);
      const inactiveEvidence = {
        ...keyEvidenceBase,
        enabled_keys: enabledKeys.length,
        keys_inactive_beyond_threshold: names(inactiveKeys, "label"),
        keys_without_last_used: names(neverUsedKeys, "label"),
        threshold_days: keyInactive,
      };
      if (inactiveKeys.length > 0) {
        findings.push(finding(8, "medium", "fail", `${inactiveKeys.length}/${enabledKeys.length} enabled access keys have not been used in over ${keyInactive} days.${partialNote(accessKeys)}`, inactiveEvidence));
      } else if (neverUsedKeys.length > 0) {
        findings.push(finding(8, "medium", "warn", `No key exceeded ${keyInactive} idle days, but ${neverUsedKeys.length} enabled key(s) have no lastUsed timestamp and are not counted as active.${partialNote(accessKeys)}`, inactiveEvidence));
      } else {
        findings.push(withPartialDowngrade(finding(8, "medium", "pass", `${enabledKeys.length} enabled access key(s) seen (org scope, endpoint readable); all were used within ${keyInactive} days.`, inactiveEvidence), accessKeys));
      }
    }
  }

  const status = allowlistStatus.data ?? {};
  const addresses = allowlistAddresses.data ?? [];
  if (!allowlistStatus.ok) {
    findings.push(unreadable(13, "high", "the service allowlist status", allowlistStatus, "screenshot Administration > Security > Service Allowlist showing enablement and CIDR entries."));
  } else {
    const loginEnabled = status.loginEnabled === true;
    const contentEnabled = status.contentEnabled === true;
    const evidence = { login_enabled: loginEnabled, content_enabled: contentEnabled, addresses_seen: whenReadable(allowlistAddresses, addresses.length), addresses_readable: allowlistAddresses.ok, cidrs: whenReadable(allowlistAddresses, names(addresses, "cidr")) };
    if (!loginEnabled) {
      findings.push(finding(13, "high", "fail", `Service allowlist login enforcement is disabled (loginEnabled=false${contentEnabled ? ", contentEnabled=true" : ""}), so API and UI access is not restricted by source IP.`, evidence));
    } else if (!allowlistAddresses.ok) {
      findings.push(finding(13, "high", "manual", `Login allowlisting is enabled but the CIDR list was unreadable (${allowlistAddresses.error ?? "unknown error"}); export the allowlist entries manually.`, evidence));
    } else if (addresses.length === 0) {
      findings.push(finding(13, "high", "fail", "Login allowlisting is enabled but zero CIDR entries were returned, so the restriction is not effective; emptiness fails this control.", evidence));
    } else {
      findings.push(finding(13, "high", contentEnabled ? "pass" : "warn", `Login allowlisting is enabled with ${addresses.length} CIDR entrie(s)${contentEnabled ? " and content sharing allowlisting is enabled" : ", but content sharing allowlisting is disabled"}.`, evidence));
    }
  }

  if (!sessionTimeout.ok) {
    findings.push(unreadable(14, "medium", "the maximum session timeout policy", sessionTimeout, "screenshot Administration > Security > Policies > Maximum Web Session Timeout."));
  } else {
    const rawTimeout = sessionTimeout.data?.maxUserSessionTimeout;
    const minutes = parseSessionTimeoutMinutes(rawTimeout);
    const concurrent = concurrentSessions.ok ? concurrentSessions.data ?? {} : {};
    const evidence = { max_user_session_timeout: asString(rawTimeout) ?? null, minutes: minutes ?? null, threshold_minutes: maxSessionMinutes, concurrent_sessions_policy_readable: concurrentSessions.ok, concurrent_sessions_limit_enabled: concurrentSessions.ok ? concurrent.enabled === true : null, max_concurrent_sessions: asNumber(concurrent.maxConcurrentSessions) ?? null };
    let sessionFinding: SumologicFinding;
    if (minutes === undefined) {
      sessionFinding = finding(14, "medium", "manual", "The maxUserSessionTimeout policy did not return a parsable value, so session timeout is unknown; confirm it in Administration > Security > Policies.", evidence);
    } else if (minutes > maxSessionMinutes) {
      sessionFinding = finding(14, "medium", "fail", `Maximum web session timeout is ${asString(rawTimeout)} (${minutes} minutes), above the ${maxSessionMinutes}-minute threshold.`, evidence);
    } else {
      const concurrentText = !concurrentSessions.ok ? "" : concurrent.enabled === true ? " and concurrent session limits are enabled" : ", but the concurrent sessions limit policy is not enabled";
      sessionFinding = finding(14, "medium", concurrent.enabled === true ? "pass" : "warn", `Maximum web session timeout is ${asString(rawTimeout)} (${minutes} minutes, threshold ${maxSessionMinutes})${concurrentText}.`, evidence);
    }
    findings.push(withUnreadableDowngrade(sessionFinding, "concurrent sessions limit policy", concurrentSessions, "screenshot Administration > Security > Policies > User Concurrent Sessions Limit."));
  }

  return {
    title: "Sumo Logic access control",
    area: "access-control",
    summary: {
      roles_seen: whenReadable(roles, roleList.length),
      users_seen: whenReadable(users, userList.length),
      access_keys_seen: whenReadable(accessKeys, keys.length),
      access_key_scope: whenReadable(accessKeys, accessKeys.scope),
      allowlist_addresses: whenReadable(allowlistAddresses, addresses.length),
      unreadable_surfaces: collectErrors(collections).length,
    },
    findings,
    errors: collectErrors(collections),
    rawData: rawSnapshot(collections),
  };
}

export async function assessSumologicDataGovernance(
  client: SumologicReader,
  options: SumologicAssessmentOptions = {},
): Promise<SumologicAssessmentResult> {
  const now = options.now ?? new Date();
  const minRetention = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 1, 36500);
  const offlineDays = clampNumber(options.collectorOfflineDays, DEFAULT_COLLECTOR_OFFLINE_DAYS, 1, 3650);
  const approvedDestinations = (options.approvedDestinationDomains ?? []).map((item) => item.toLowerCase());

  const [auditPolicy, searchAuditPolicy, partitions, scheduledViews, connections, ingestBudgets, collectors, accountStatus] = await Promise.all([
    client.getPolicy("audit"),
    client.getPolicy("searchAudit"),
    client.listPartitions(),
    client.listScheduledViews(),
    client.listConnections(),
    client.listIngestBudgets(),
    client.listCollectors(),
    client.getAccountStatus(),
  ]);
  const collections: Array<[string, SumologicCollection<unknown>]> = [
    ["audit_policy", auditPolicy],
    ["search_audit_policy", searchAuditPolicy],
    ["partitions", partitions],
    ["scheduled_views", scheduledViews],
    ["connections", connections],
    ["ingest_budgets", ingestBudgets],
    ["collectors", collectors],
    ["account_status", accountStatus],
  ];
  const findings: SumologicFinding[] = [];
  const partitionList = partitions.data ?? [];
  const auditIndexes = partitionList.filter((partition) => asString(partition.indexType) === "AuditIndex" || /audit/i.test(asString(partition.name) ?? ""));
  const activeAuditIndexes = auditIndexes.filter((partition) => partition.isActive === true);
  const planType = asString(accountStatus.data?.planType);

  if (!auditPolicy.ok) {
    findings.push(unreadable(9, "high", "the audit policy", auditPolicy, "screenshot Administration > Security > Policies > Audit and run `_index=sumologic_audit_events` for the last 24 hours."));
  } else if (auditPolicy.data?.enabled !== true) {
    findings.push(finding(9, "high", "fail", `The audit policy is not enabled (enabled=${String(auditPolicy.data?.enabled ?? "absent")}), so account events are not written to the audit index.`, { audit_policy_enabled: auditPolicy.data?.enabled ?? null, plan_type: planType ?? null }));
  } else {
    const evidence = {
      audit_policy_enabled: true,
      search_audit_policy_readable: searchAuditPolicy.ok,
      search_audit_enabled: searchAuditPolicy.ok ? searchAuditPolicy.data?.enabled === true : null,
      partitions_readable: partitions.ok,
      audit_index_partitions: whenReadable(partitions, names(auditIndexes)),
      active_audit_index_partitions: whenComplete(partitions, activeAuditIndexes.length),
      partitions_seen: whenReadable(partitions, partitionList.length),
      partitions_complete: whenReadable(partitions, partitions.complete),
      plan_type: planType ?? null,
    };
    if (!partitions.ok) {
      findings.push(finding(9, "high", "manual", `The audit policy is enabled but the partition list was unreadable (${partitions.error ?? "unknown error"}), so the audit index state is unverified; run \`_index=sumologic_audit_events\` for the last 24 hours to prove events flow.`, evidence));
    } else if (activeAuditIndexes.length === 0 && partitions.complete === false) {
      findings.push(finding(9, "high", "manual", `The audit policy is enabled but no active AuditIndex partition was among the ${partitionList.length} partitions seen before pagination stopped, so the audit index is unread rather than absent. Read the full partition list and run \`_index=sumologic_audit_events\` to confirm events are received.${partialNote(partitions)}`, evidence));
    } else if (activeAuditIndexes.length === 0) {
      findings.push(finding(9, "high", "manual", `The audit policy is enabled but no active AuditIndex partition was visible${planType ? ` (plan ${planType})` : ""}; the audit index may be unavailable on this plan. Run \`_index=sumologic_audit_events\` to confirm events are received.${partialNote(partitions)}`, evidence));
    } else if (searchAuditPolicy.ok && searchAuditPolicy.data?.enabled !== true) {
      findings.push(finding(9, "high", "warn", `The audit policy is enabled and ${activeAuditIndexes.length} active audit index partition(s) exist, but the search audit policy is disabled, so query activity is not logged. Event flow still requires a manual search of _index=sumologic_audit_events.${partialNote(partitions)}`, evidence));
    } else {
      const policyText = searchAuditPolicy.ok ? "Audit and search audit policies are enabled" : "The audit policy is enabled";
      findings.push(withUnreadableDowngrade(
        withPartialDowngrade(
          finding(9, "high", "pass", `${policyText} and ${activeAuditIndexes.length} active audit index partition(s) exist (${names(activeAuditIndexes).join(", ")}). Confirm event flow with a search of _index=sumologic_audit_events.`, evidence),
          partitions,
        ),
        "search audit policy",
        searchAuditPolicy,
        "screenshot Administration > Security > Policies > Search Audit to confirm query activity is logged.",
      ));
    }
  }

  const connectionList = connections.data ?? [];
  const scheduledViewList = scheduledViews.data ?? [];
  const forwardingPartitions = partitionList.filter((partition) => asString(partition.dataForwardingId));
  const forwardingViews = scheduledViewList.filter((view) => asString(view.dataForwardingId));
  if (!connections.ok) {
    findings.push(unreadable(10, "medium", "the connection list", connections, "export Manage Data > Monitoring > Connections and Manage Data > Logs > Data Forwarding destinations with owner approvals."));
  } else {
    const destinations = connectionList.map((connection) => ({ name: asString(connection.name) ?? asString(connection.id) ?? "connection", type: asString(connection.type) ?? "unknown", host: hostOf(asString(connection.url)) ?? null }));
    const unapproved = approvedDestinations.length > 0 ? destinations.filter((item) => !item.host || !domainMatches(item.host, approvedDestinations)) : [];
    const evidence = {
      connections_seen: connectionList.length,
      connections_complete: connections.complete,
      partitions_readable: partitions.ok,
      partitions_seen: whenReadable(partitions, partitionList.length),
      partitions_complete: whenReadable(partitions, partitions.complete),
      scheduled_views_readable: scheduledViews.ok,
      scheduled_views_seen: whenReadable(scheduledViews, scheduledViewList.length),
      scheduled_views_complete: whenReadable(scheduledViews, scheduledViews.complete),
      destinations,
      partitions_forwarding: whenReadable(partitions, names(forwardingPartitions)),
      scheduled_views_forwarding: whenReadable(scheduledViews, names(forwardingViews, "indexName")),
      approved_destination_domains: approvedDestinations,
      unapproved_destinations: unapproved.map((item) => item.name),
    };
    const forwardingCount = forwardingPartitions.length + forwardingViews.length;
    let forwardingFinding: SumologicFinding;
    if (connectionList.length === 0 && forwardingCount === 0 && partitions.ok && scheduledViews.ok && partitionList.length > 0) {
      forwardingFinding = finding(10, "medium", "pass", "Zero outbound connections and zero data forwarding destinations are configured (endpoints readable), so no external destination review is pending; emptiness is compliant for this control.", evidence);
    } else if (approvedDestinations.length > 0 && unapproved.length > 0) {
      forwardingFinding = finding(10, "medium", "fail", `${unapproved.length}/${connectionList.length} connections point outside the approved destination domains (${unapproved.map((item) => item.name).join(", ")}).`, evidence);
    } else if (approvedDestinations.length > 0 && connectionList.length === 0) {
      // The approved-domain check only ever covers connections, so with none
      // to check there is nothing to pass on: the forwarding destinations on
      // partitions and scheduled views (or an empty partition inventory) still
      // need a human.
      const remaining = forwardingCount > 0
        ? `${forwardingCount} data forwarding destination(s) on ${forwardingPartitions.length} partition(s) and ${forwardingViews.length} scheduled view(s) remain unchecked against the approved domains`
        : "no data forwarding destination was seen but the partition inventory is empty, so that absence cannot be confirmed";
      forwardingFinding = finding(10, "medium", "manual", `No outbound connections were found to check against the approved destination domains; ${remaining}, so a human must confirm each forwarding destination is approved.`, evidence);
    } else if (approvedDestinations.length > 0) {
      forwardingFinding = finding(10, "medium", "pass", `All ${connectionList.length} connections resolve to approved destination domains; ${forwardingCount} data forwarding destination(s) still require owner review.`, evidence);
    } else {
      forwardingFinding = finding(10, "medium", "manual", `${connectionList.length} outbound connection(s) and ${forwardingCount} data forwarding destination(s) exist; no approved destination list was supplied, so a human must confirm each destination is approved (pass approved_destination_domains to automate).`, evidence);
    }
    // The data forwarding destinations live on partitions and scheduled views,
    // so those inventories are essential: unreadable drops a pass to manual and
    // a capped page drops it to warn, naming the inventory either way.
    forwardingFinding = withPartialDowngrades(forwardingFinding, [["connection list", connections], ["partition list", partitions], ["scheduled view list", scheduledViews]]);
    forwardingFinding = withUnreadableDowngrade(forwardingFinding, "partition list", partitions, "export Manage Data > Logs > Partitions with each data forwarding destination.", "manual");
    forwardingFinding = withUnreadableDowngrade(forwardingFinding, "scheduled view list", scheduledViews, "export Manage Data > Logs > Scheduled Views with each data forwarding destination.", "manual");
    findings.push(forwardingFinding);
  }

  const collectorList = collectors.data ?? [];
  if (!collectors.ok) {
    findings.push(unreadable(12, "medium", "the collector inventory", collectors, "export Manage Data > Collection with status, version, and last-seen columns."));
  } else if (collectorList.length === 0) {
    findings.push(finding(12, "medium", "manual", "Zero collectors were returned (endpoint readable); confirm whether ingestion relies on hosted or cloud-to-cloud sources, or whether the key cannot see installed collectors.", { collectors_seen: 0 }));
  } else {
    const installed = collectorList.filter((collector) => /installable/i.test(asString(collector.collectorType) ?? ""));
    const offline = installed.filter((collector) => collector.alive === false && collector.ephemeral !== true);
    const longOffline = offline.filter((collector) => (ageInDays(collector.lastSeenAlive, now) ?? Number.POSITIVE_INFINITY) > offlineDays);
    const ephemeral = collectorList.filter((collector) => collector.ephemeral === true);
    const versions = [...new Set(installed.map((collector) => asString(collector.collectorVersion)).filter((item): item is string => Boolean(item)))].sort();
    const missingVersion = installed.filter((collector) => !asString(collector.collectorVersion));
    const evidence = { collectors_seen: collectorList.length, collectors_complete: collectors.complete, installed: whenComplete(collectors, installed.length), hosted: whenComplete(collectors, collectorList.length - installed.length), offline_non_ephemeral: names(offline), offline_beyond_threshold: names(longOffline), ephemeral: whenComplete(collectors, ephemeral.length), collector_versions: versions, installed_missing_version: names(missingVersion), offline_threshold_days: offlineDays };
    if (longOffline.length > 0) {
      findings.push(finding(12, "medium", "fail", `${longOffline.length} installed collector(s) have been offline for more than ${offlineDays} days (or have no last-seen timestamp) and remain registered.${partialNote(collectors)}`, evidence));
    } else if (offline.length > 0 || versions.length > 1 || missingVersion.length > 0) {
      findings.push(finding(12, "medium", "warn", `${offline.length} installed collector(s) are currently offline, ${versions.length} distinct collector versions are deployed, and ${missingVersion.length} report no version; review for drift.${partialNote(collectors)}`, evidence));
    } else {
      findings.push(withPartialDowngrade(finding(12, "medium", "pass", `${collectorList.length} collector(s) seen: all ${installed.length} installed collectors are alive on version ${versions[0] ?? "n/a"}; ${ephemeral.length} ephemeral.`, evidence), collectors));
    }
  }

  const budgets = ingestBudgets.data ?? [];
  if (!ingestBudgets.ok) {
    findings.push(unreadable(16, "medium", "the ingest budget list", ingestBudgets, "export Manage Data > Collection > Ingest Budgets with capacity and action."));
  } else if (budgets.length === 0) {
    findings.push(finding(16, "medium", "fail", "Zero ingest budgets are configured (endpoint readable), so nothing caps runaway ingestion; the control intent requires at least one budget.", { budgets_seen: 0 }));
  } else {
    const enforcing = budgets.filter((budget) => asString(budget.action) === "stopCollecting");
    const exceeded = budgets.filter((budget) => asString(budget.usageStatus) === "Exceeded");
    const evidence = { budgets_seen: budgets.length, budgets_complete: ingestBudgets.complete, enforcing_budgets: names(enforcing), audit_only_budgets: names(budgets.filter((budget) => asString(budget.action) !== "stopCollecting")), exceeded_budgets: names(exceeded) };
    if (enforcing.length === 0) {
      findings.push(finding(16, "medium", "warn", `${budgets.length} ingest budget(s) exist but none use stopCollecting, so overruns are only audited.${partialNote(ingestBudgets)}`, evidence));
    } else {
      findings.push(withPartialDowngrade(finding(16, "medium", "pass", `${budgets.length} ingest budget(s) seen, ${enforcing.length} enforce stopCollecting; ${exceeded.length} currently exceeded.`, evidence), ingestBudgets));
    }
  }

  if (!partitions.ok) {
    findings.push(unreadable(17, "medium", "the partition list", partitions, "export Manage Data > Logs > Partitions with retention periods."));
  } else if (partitionList.length === 0) {
    findings.push(finding(17, "medium", "manual", "Zero partitions were returned even though the default index always exists, so the key sees a partial inventory; export the partition list with retention periods.", { partitions_seen: 0 }));
  } else {
    const active = partitionList.filter((partition) => partition.isActive !== false);
    const explicit = active.filter((partition) => (asNumber(partition.retentionPeriod) ?? -1) >= 0);
    const accountDefault = active.filter((partition) => (asNumber(partition.retentionPeriod) ?? -1) < 0);
    const belowThreshold = explicit.filter((partition) => (asNumber(partition.retentionPeriod) ?? 0) < minRetention);
    const auditBelow = belowThreshold.filter((partition) => auditIndexes.includes(partition));
    const evidence = { partitions_seen: partitionList.length, partitions_complete: partitions.complete, active_partitions: active.length, partitions_below_threshold: belowThreshold.map((partition) => `${asString(partition.name) ?? partition.id}=${asNumber(partition.retentionPeriod)}d`), partitions_using_account_default: names(accountDefault), compliant_locked_partitions: names(active.filter((partition) => partition.isCompliant === true)), threshold_days: minRetention };
    if (auditBelow.length > 0) {
      findings.push(finding(17, "medium", "fail", `Audit index partition(s) ${names(auditBelow).join(", ")} retain data for less than ${minRetention} days.${partialNote(partitions)}`, evidence));
    } else if (belowThreshold.length > 0) {
      findings.push(finding(17, "medium", "warn", `${belowThreshold.length}/${active.length} active partitions retain data for less than ${minRetention} days; confirm each is out of compliance scope.${partialNote(partitions)}`, evidence));
    } else if (accountDefault.length > 0) {
      findings.push(finding(17, "medium", "warn", `No explicit retention is below ${minRetention} days, but ${accountDefault.length} partition(s) inherit the account default (retentionPeriod -1), which the API does not resolve; confirm the account retention setting.${partialNote(partitions)}`, evidence));
    } else {
      findings.push(withPartialDowngrade(finding(17, "medium", "pass", `All ${active.length} active partitions declare explicit retention of at least ${minRetention} days.`, evidence), partitions));
    }
  }

  return {
    title: "Sumo Logic data governance",
    area: "data-governance",
    summary: {
      partitions_seen: whenReadable(partitions, partitionList.length),
      partitions_complete: whenReadable(partitions, partitions.complete),
      active_audit_indexes: whenComplete(partitions, activeAuditIndexes.length),
      connections_seen: whenReadable(connections, connectionList.length),
      collectors_seen: whenReadable(collectors, collectorList.length),
      ingest_budgets_seen: whenReadable(ingestBudgets, budgets.length),
      plan_type: planType ?? null,
      unreadable_surfaces: collectErrors(collections).length,
    },
    findings,
    errors: collectErrors(collections),
    rawData: rawSnapshot(collections),
  };
}

export async function assessSumologicContentSharing(
  client: SumologicReader,
  options: SumologicAssessmentOptions = {},
): Promise<SumologicAssessmentResult> {
  const sample = clampNumber(options.contentSample, DEFAULT_CONTENT_SAMPLE, 1, 200);
  const [dataAccessPolicy, sharePolicy, personalFolder, dashboards, monitors, connections, users] = await Promise.all([
    client.getPolicy("dataAccessLevel"),
    client.getPolicy("shareDashboardsOutsideOrganization"),
    client.getPersonalFolder(),
    client.listDashboards(),
    client.listMonitors(),
    client.listConnections(),
    client.listUsers(),
  ]);
  const allChildren = asRecords(personalFolder.data?.children);
  const children = allChildren.slice(0, sample);
  const unsampledChildren = allChildren.length - children.length;
  const permissionResults: Array<{ item: JsonRecord; permissions: SumologicCollection<JsonRecord> }> = [];
  for (const item of children) {
    const id = asString(item.id);
    if (!id) continue;
    permissionResults.push({ item, permissions: await client.getContentPermissions(id) });
  }
  const unreadablePermissions = permissionResults.filter((entry) => !entry.permissions.ok);
  const collections: Array<[string, SumologicCollection<unknown>]> = [
    ["data_access_level_policy", dataAccessPolicy],
    ["share_dashboards_outside_organization_policy", sharePolicy],
    ["personal_folder", personalFolder],
    ["dashboards", dashboards],
    ["monitors", monitors],
    ["connections", connections],
    ["users", users],
    ["content_permissions", contentPermissionsCollection(personalFolder, permissionResults, unreadablePermissions)],
  ];
  const findings: SumologicFinding[] = [];

  // Items shared org-wide are only known when at least one permission lookup
  // succeeded; when every lookup failed the count and list render null.
  const permissionsAllFailed = permissionResults.length > 0 && unreadablePermissions.length === permissionResults.length;
  const orgShared = permissionResults.filter((entry) => [...asRecords(entry.permissions.data?.explicitPermissions), ...asRecords(entry.permissions.data?.implicitPermissions)].some((permission) => asString(permission.sourceType) === "org"));
  const whenPermissionsRead = <T>(value: T): T | null => (personalFolder.ok && !permissionsAllFailed ? value : null);
  const sampleNote = unsampledChildren > 0 ? ` Only ${children.length} of ${allChildren.length} personal-folder items were sampled (content_sample=${sample}); ${unsampledChildren} were not evaluated.` : "";
  const sharingEvidence = {
    data_access_level_enabled: dataAccessPolicy.ok ? dataAccessPolicy.data?.enabled === true : null,
    personal_folder_readable: personalFolder.ok,
    personal_folder_items_total: whenReadable(personalFolder, allChildren.length),
    personal_folder_items_sampled: whenReadable(personalFolder, permissionResults.length),
    personal_folder_items_unsampled: whenReadable(personalFolder, unsampledChildren),
    content_sample: sample,
    org_shared_items: whenPermissionsRead(names(orgShared.map((entry) => entry.item))),
    permission_lookups_failed: whenReadable(personalFolder, unreadablePermissions.length),
  };
  const sampledShareText = personalFolder.ok ? `${orgShared.length} sampled item(s) are shared org-wide` : "the personal folder could not be read, so no items were sampled";
  const personalFolderEvidence = "export the key owner's personal folder listing and the content permissions of each item to review org-wide shares.";
  const permissionLookupNote = unreadablePermissions.length > 0 ? ` ${unreadablePermissions.length} content permission lookup(s) failed (${unreadablePermissions.slice(0, 5).map((entry) => `${asString(entry.item.name) ?? asString(entry.item.id) ?? "item"}: ${entry.permissions.error ?? "unknown error"}`).join("; ")}), so those items were not checked.` : "";
  let sharingFinding: SumologicFinding;
  if (!dataAccessPolicy.ok) {
    sharingFinding = unreadable(11, "medium", "the data access level policy", dataAccessPolicy, "screenshot Administration > Security > Policies > Data Access Level and review Library sharing for org-wide shares.");
  } else if (dataAccessPolicy.data?.enabled !== true) {
    sharingFinding = finding(11, "medium", "fail", `The Data Access Level policy is not enabled (enabled=${String(dataAccessPolicy.data?.enabled ?? "absent")}), so content can be shared with users whose role filters expose more data than the owner's; ${sampledShareText}.${sampleNote}${permissionLookupNote}`, sharingEvidence);
  } else if (orgShared.length > 0) {
    sharingFinding = finding(11, "medium", "warn", `The Data Access Level policy is enabled, but ${orgShared.length}/${permissionResults.length} sampled personal-folder items are shared with the whole org (${names(orgShared.map((entry) => entry.item)).join(", ")}); review whether org-wide sharing is required.${sampleNote}${permissionLookupNote}`, sharingEvidence);
  } else if (!personalFolder.ok) {
    sharingFinding = finding(11, "medium", "manual", "The Data Access Level policy is enabled, but content permissions could not be sampled because the personal folder could not be read; review Library sharing for org-wide shares manually.", sharingEvidence);
  } else if (permissionResults.length === 0 || unreadablePermissions.length > 0) {
    sharingFinding = finding(11, "medium", "manual", `The Data Access Level policy is enabled, but content permissions could not be sampled (${unreadablePermissions.length} lookups failed, ${permissionResults.length} items sampled); review Library sharing for org-wide shares manually.${sampleNote}${permissionLookupNote}`, sharingEvidence);
  } else if (unsampledChildren > 0) {
    sharingFinding = finding(11, "medium", "warn", `The Data Access Level policy is enabled and none of the ${permissionResults.length} sampled personal-folder items are shared org-wide, but the population is incomplete.${sampleNote} Raise content_sample or review the remaining items in the Library before treating this control as satisfied.`, sharingEvidence);
  } else {
    sharingFinding = finding(11, "medium", "pass", `The Data Access Level policy is enabled and none of the ${permissionResults.length} sampled personal-folder items are shared org-wide (all ${allChildren.length} items in the folder were evaluated); the sample covers the key owner's folder only, so Admin Recommended and Global folders still merit periodic review.`, sharingEvidence);
  }
  findings.push(withUnreadableDowngrade(sharingFinding, "personal folder", personalFolder, personalFolderEvidence, "manual"));

  const monitorList = monitors.data ?? [];
  const monitorsWithRunAs = monitorList.filter((monitor) => asString(asObject(monitor.runAs)?.runAsId));
  const scheduledContent = children.filter((item) => item.isScheduled === true);
  const scheduleEvidence = {
    monitors_seen: whenReadable(monitors, monitorList.length),
    monitors_complete: whenReadable(monitors, monitors.complete),
    monitors_with_run_as: whenReadable(monitors, monitorsWithRunAs.length),
    scheduled_searches_in_sampled_folder: whenReadable(personalFolder, names(scheduledContent)),
    personal_folder_items_total: whenReadable(personalFolder, allChildren.length),
    personal_folder_items_sampled: whenReadable(personalFolder, children.length),
    monitors_readable: monitors.ok,
    personal_folder_readable: personalFolder.ok,
  };
  if (!monitors.ok && !personalFolder.ok) {
    findings.push(unreadable(15, "medium", "the monitor and content inventories", monitors, "list scheduled searches and monitors with their owners and runAs identities, and confirm none run under shared administrator accounts."));
  } else {
    const monitorText = monitors.ok ? `${monitorList.length} monitor(s) seen (${monitorsWithRunAs.length} with an explicit runAs identity)` : "the monitor list could not be read";
    const scheduledText = personalFolder.ok ? `${scheduledContent.length} scheduled search(es) in the sampled folder` : "the personal folder could not be read so no scheduled searches were sampled";
    let scheduleFinding = finding(15, "medium", "manual", `Scheduled search role bindings are not exposed by the API: ${monitorText} and ${scheduledText}. A human must confirm each scheduled search and monitor runs under a scoped user, not a shared admin credential.${partialNote(monitors)}`, scheduleEvidence);
    scheduleFinding = withUnreadableDowngrade(scheduleFinding, "monitor list", monitors, "export Alerts > Monitors with each monitor's runAs identity.", "manual");
    scheduleFinding = withUnreadableDowngrade(scheduleFinding, "personal folder", personalFolder, "list the scheduled searches in the key owner's folder with their owners.", "manual");
    findings.push(scheduleFinding);
  }

  const lookupItems = children.filter((item) => /lookup/i.test(asString(item.itemType) ?? ""));
  const lookupOrgShared = orgShared.filter((entry) => /lookup/i.test(asString(entry.item.itemType) ?? ""));
  const lookupEvidence = {
    lookup_tables_in_sampled_folder: whenReadable(personalFolder, names(lookupItems)),
    lookup_tables_shared_org_wide: whenPermissionsRead(names(lookupOrgShared.map((entry) => entry.item))),
    personal_folder_items_total: whenReadable(personalFolder, allChildren.length),
    personal_folder_items_sampled: whenReadable(personalFolder, children.length),
    personal_folder_readable: personalFolder.ok,
    permission_lookups_failed: whenReadable(personalFolder, unreadablePermissions.length),
  };
  let lookupFinding: SumologicFinding;
  if (lookupOrgShared.length > 0) {
    lookupFinding = finding(18, "medium", "warn", `${lookupOrgShared.length} lookup table(s) in the sampled folder are shared org-wide (${names(lookupOrgShared.map((entry) => entry.item)).join(", ")}); confirm they contain no sensitive data.${permissionLookupNote}`, lookupEvidence);
  } else {
    const sampledText = personalFolder.ok ? `${lookupItems.length} lookup table(s) were seen in the sampled folder` : "the personal folder could not be read, so no lookup tables were sampled";
    lookupFinding = finding(18, "medium", "manual", `The API has no lookup table listing endpoint (lookup tables are only readable one at a time by id); ${sampledText}. A human must inventory lookup tables in the Library, identify those with sensitive data, and export the content permissions of each.${permissionLookupNote}`, lookupEvidence);
  }
  findings.push(withUnreadableDowngrade(lookupFinding, "personal folder", personalFolder, personalFolderEvidence, "manual"));

  const dashboardList = dashboards.data ?? [];
  const publicDashboards = dashboardList.filter((dashboard) => dashboard.isPublic === true);
  const dashboardEvidence = {
    share_outside_org_enabled: sharePolicy.ok ? sharePolicy.data?.enabled === true : null,
    dashboards_readable: dashboards.ok,
    dashboards_seen: whenReadable(dashboards, dashboardList.length),
    dashboards_complete: whenReadable(dashboards, dashboards.complete),
    public_dashboards: whenReadable(dashboards, names(publicDashboards, "title")),
  };
  if (!sharePolicy.ok) {
    findings.push(unreadable(19, "medium", "the share-dashboards-outside-organization policy", sharePolicy, "screenshot Administration > Security > Policies > Share Dashboards Outside Organization and list externally shared dashboards."));
  } else if (sharePolicy.data?.enabled === true) {
    const publicText = dashboards.ok ? `${publicDashboards.length}/${dashboardList.length} seen dashboards are flagged public` : `the dashboard list could not be read (${unreadableCause(dashboards)}), so per-dashboard exposure is unknown`;
    findings.push(finding(19, "medium", "fail", `Sharing dashboards outside the organization is enabled; ${publicText}.`, dashboardEvidence));
  } else if (sharePolicy.data?.enabled !== false) {
    findings.push(finding(19, "medium", "manual", "The share-dashboards-outside-organization policy response did not include an enabled flag, so the external sharing state is unknown; confirm it in Administration > Security > Policies.", dashboardEvidence));
  } else if (!dashboards.ok) {
    findings.push(finding(19, "medium", "manual", `External dashboard sharing is disabled at the policy level, but the dashboard list was unreadable (${dashboards.error ?? "unknown error"}); review dashboard sharing in the Library manually.`, dashboardEvidence));
  } else if (dashboardList.length === 0) {
    findings.push(finding(19, "medium", "manual", "External dashboard sharing is disabled at the policy level, but zero dashboards were viewable by the key owner, so per-dashboard sharing could not be sampled; review Library dashboards manually.", dashboardEvidence));
  } else if (publicDashboards.length > 0) {
    findings.push(finding(19, "medium", "warn", `External sharing is disabled, but ${publicDashboards.length} dashboard(s) carry isPublic=true (${names(publicDashboards, "title").join(", ")}).${partialNote(dashboards)}`, dashboardEvidence));
  } else {
    findings.push(withPartialDowngrade(finding(19, "medium", "pass", `External dashboard sharing is disabled and none of the ${dashboardList.length} viewable dashboards are public (the list covers dashboards viewable by the key owner).`, dashboardEvidence), dashboards));
  }

  const orgDomains = new Set<string>([...(options.approvedEmailDomains ?? []).map((item) => item.toLowerCase()), ...(users.data ?? []).map((user) => asString(user.email)?.split("@")[1]?.toLowerCase()).filter((item): item is string => Boolean(item))]);
  const connectionIds = new Set((connections.data ?? []).map((connection) => asString(connection.id)).filter((item): item is string => Boolean(item)));
  const externalRecipients: string[] = [];
  const unknownConnections: string[] = [];
  let notificationCount = 0;
  let connectionNotificationCount = 0;
  for (const monitor of monitorList) {
    for (const entry of asRecords(monitor.notifications)) {
      const notification = asObject(entry.notification) ?? {};
      notificationCount += 1;
      if (asString(notification.connectionType) === "Email") {
        for (const recipient of asArray(notification.recipients)) {
          const domain = asString(recipient)?.split("@")[1]?.toLowerCase();
          if (domain && orgDomains.size > 0 && !domainMatches(domain, [...orgDomains])) externalRecipients.push(asString(recipient) as string);
        }
      } else {
        connectionNotificationCount += 1;
        const connectionId = asString(notification.connectionId);
        if (connectionId && connections.ok && !connectionIds.has(connectionId)) unknownConnections.push(`${asString(monitor.name) ?? monitor.id}:${connectionId}`);
      }
    }
  }
  const disabledMonitors = monitorList.filter((monitor) => monitor.isDisabled === true);
  const routingEvidence = {
    monitors_seen: monitorList.length,
    monitors_complete: monitors.complete,
    notifications_seen: notificationCount,
    connection_notifications_seen: connectionNotificationCount,
    users_readable: users.ok,
    users_seen: whenReadable(users, (users.data ?? []).length),
    connections_readable: connections.ok,
    connections_seen: whenReadable(connections, connectionIds.size),
    org_email_domains: users.ok || orgDomains.size > 0 ? [...orgDomains].slice(0, 25) : null,
    external_email_recipients: orgDomains.size > 0 ? externalRecipients.slice(0, 25) : null,
    notifications_to_unknown_connections: whenReadable(connections, unknownConnections.slice(0, 25)),
    disabled_monitors: names(disabledMonitors),
  };
  if (!monitors.ok) {
    findings.push(unreadable(20, "medium", "the monitor list", monitors, "export Alerts > Monitors with notification destinations and confirm each routes to an approved channel."));
  } else {
    let routingFinding: SumologicFinding;
    if (monitorList.length === 0) {
      routingFinding = finding(20, "medium", "manual", "Zero monitors were returned (endpoint readable), so no alert routing exists to evaluate; confirm whether security alerting is implemented elsewhere.", routingEvidence);
    } else if (externalRecipients.length > 0 || unknownConnections.length > 0) {
      routingFinding = finding(20, "medium", "fail", `${externalRecipients.length} email recipient(s) fall outside the org domains and ${unknownConnections.length} notification(s) reference connections not in the connection inventory.${partialNote(monitors)}`, routingEvidence);
    } else if (orgDomains.size === 0) {
      routingFinding = finding(20, "medium", "manual", `${notificationCount} notification(s) across ${monitorList.length} monitors were seen, but no org email domains could be derived (${users.ok ? "no user emails were returned" : "user list unreadable"} and no approved_email_domains supplied), so recipient review is manual.`, routingEvidence);
    } else if (disabledMonitors.length > 0 || notificationCount === 0) {
      routingFinding = finding(20, "medium", "warn", `Alert routing stays within org domains and known connections, but ${disabledMonitors.length} monitor(s) are disabled and ${notificationCount} notification(s) exist; confirm security monitors are active.${partialNote(monitors)}`, routingEvidence);
    } else {
      routingFinding = withPartialDowngrade(finding(20, "medium", "pass", `${notificationCount} notification(s) across ${monitorList.length} monitors route to org email domains or known connections, and no monitors are disabled.`, routingEvidence), monitors);
    }
    // The user list supplies the org email domains and the connection list
    // validates webhook targets; either being unreadable means part of the
    // routing was judged blind, so a pass cannot stand.
    routingFinding = withUnreadableDowngrade(routingFinding, "user list", users, "export Administration > Users and Roles > Users to confirm the org email domains that recipients were judged against.");
    routingFinding = withUnreadableDowngrade(
      routingFinding,
      "connection list",
      connections,
      "export Manage Data > Monitoring > Connections and confirm every webhook notification targets an approved connection.",
      connectionNotificationCount > 0 ? "manual" : "warn",
    );
    findings.push(routingFinding);
  }

  return {
    title: "Sumo Logic content sharing and alerting",
    area: "content-sharing",
    summary: {
      personal_folder_items_total: whenReadable(personalFolder, allChildren.length),
      personal_folder_items_sampled: whenReadable(personalFolder, permissionResults.length),
      personal_folder_items_unsampled: whenReadable(personalFolder, unsampledChildren),
      org_shared_items: whenPermissionsRead(orgShared.length),
      dashboards_seen: whenReadable(dashboards, dashboardList.length),
      monitors_seen: whenReadable(monitors, monitorList.length),
      monitors_complete: whenReadable(monitors, monitors.complete),
      external_email_recipients: orgDomains.size > 0 ? whenComplete(monitors, externalRecipients.length) : null,
      unreadable_surfaces: collectErrors(collections).length,
    },
    findings,
    errors: collectErrors(collections),
    rawData: rawSnapshot(collections),
  };
}

function formatAccessCheckText(result: SumologicAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.status === "readable" ? surface.capabilityHint : `needs ${surface.capabilityHint}`,
  ]);
  return [
    `Sumo Logic access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Capability"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SumologicAssessmentResult): string {
  const rows = result.findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.summary]);
  const summary = Object.entries(result.summary).map(([key, value]) => `- ${key}: ${String(value)}`).join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function statusCounts(findings: SumologicFinding[]): Record<SumologicFinding["status"], number> {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

function buildExecutiveSummary(config: SumologicResolvedConfig, findings: SumologicFinding[], errors: string[]): string {
  const counts = statusCounts(findings);
  return [
    "# Sumo Logic Security Inspector: Executive Summary",
    "",
    `API endpoint: ${config.baseUrl}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual verification required: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    `- Collection errors: ${errors.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings.filter((item) => item.status === "fail" || item.status === "warn").slice(0, 10).map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Verification Queue",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id} ${item.title}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedMatrix(findings: SumologicFinding[]): string {
  const header = ["Control", "Title", "Status", ...FRAMEWORKS];
  const rows = findings.map((item) => {
    const definition = SUMOLOGIC_CONTROLS.find((entry) => entry.id === item.id);
    return [item.id, item.title, item.status.toUpperCase(), ...FRAMEWORKS.map((framework) => definition?.mappings[framework] ?? "")];
  });
  return [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `|${header.map(() => "---").join("|")}|`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
}

function buildFrameworkReport(framework: Framework, findings: SumologicFinding[]): string {
  const rows = findings.map((item) => {
    const definition = SUMOLOGIC_CONTROLS.find((entry) => entry.id === item.id);
    return `| ${definition?.mappings[framework] ?? ""} | ${item.id} | ${item.title} | ${item.status.toUpperCase()} | ${item.summary.replace(/\|/g, "/")} |`;
  });
  return [
    `# ${framework} Control Report`,
    "",
    "Generated by grclanker sumologic_export_audit_bundle. Findings marked MANUAL require human evidence and are not passes.",
    "",
    `| ${framework} reference | Finding | Title | Status | Summary |`,
    "|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}

function buildQuickReference(result: { findings: SumologicFinding[]; errors: string[] }): string {
  const counts = statusCounts(result.findings);
  return [
    "# Sumo Logic Audit Bundle: Quick Reference",
    "",
    "## Layout",
    "",
    "- `core_data/`: raw API snapshots per assessment area (credentials are never written)",
    "- `analysis/findings.json`: normalized findings; `analysis/<area>.json`: per-area assessment details",
    "- `compliance/executive_summary.md`: prioritized summary",
    "- `compliance/unified_compliance_matrix.md`: all framework references per control",
    `- \`compliance/<framework>.md\`: one report per framework (${FRAMEWORKS.join(", ")})`,
    "- `_errors.log`: present only when some API surfaces could not be collected",
    "",
    "## Status Semantics",
    "",
    "- PASS: the enabling flag was read and the full population satisfied the control",
    "- WARN: partial evidence, incomplete pagination, or undated items prevented a pass",
    "- FAIL: the control is violated",
    "- MANUAL: unreadable endpoint, not applicable, or outside API scope; the summary names the evidence to collect",
    "",
    `Totals: ${counts.pass} pass, ${counts.warn} warn, ${counts.fail} fail, ${counts.manual} manual, ${result.errors.length} collection errors.`,
  ].join("\n");
}

export async function exportSumologicAuditBundle(
  client: SumologicReader,
  config: SumologicResolvedConfig,
  outputRoot: string,
  options: SumologicAssessmentOptions = {},
): Promise<SumologicAuditBundleResult> {
  const access = await checkSumologicAccess(client);
  const assessments = [
    await assessSumologicIdentity(client, options),
    await assessSumologicAccessControl(client, options),
    await assessSumologicDataGovernance(client, options),
    await assessSumologicContentSharing(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors.map((error) => `${assessment.area}: ${error}`)))];

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(config.deployment ?? new URL(config.baseUrl).hostname)}-sumologic-audit-bundle`);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference({ findings, errors })}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    base_url: config.baseUrl,
    deployment: config.deployment ?? null,
    access_id_prefix: config.accessId.slice(0, 4),
    source_chain: config.sourceChain,
    finding_count: findings.length,
    status_counts: statusCounts(findings),
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `core_data/${assessment.area}.json`, serializeJson(assessment.rawData));
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson({ title: assessment.title, summary: assessment.summary, findings: assessment.findings, errors: assessment.errors }));
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.md`, `${formatAssessmentText(assessment)}\n`);
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, findings, errors)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${safeDirName(framework)}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
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
    access_id: asString(value.access_id),
    access_key: asString(value.access_key),
    endpoint: asString(value.endpoint),
    deployment: asString(value.deployment),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    max_allowlisted_users: asNumber(value.max_allowlisted_users),
    min_password_length: asNumber(value.min_password_length),
    max_password_age_days: asNumber(value.max_password_age_days),
  };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    max_admins: asNumber(value.max_admins),
    key_max_age_days: asNumber(value.key_max_age_days),
    key_inactive_days: asNumber(value.key_inactive_days),
    user_inactive_days: asNumber(value.user_inactive_days),
    max_session_timeout_minutes: asNumber(value.max_session_timeout_minutes),
  };
}

function normalizeDataGovernanceArgs(args: unknown): DataGovernanceArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    min_retention_days: asNumber(value.min_retention_days),
    collector_offline_days: asNumber(value.collector_offline_days),
    approved_destination_domains: asStringList(value.approved_destination_domains),
  };
}

function normalizeContentSharingArgs(args: unknown): ContentSharingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    approved_email_domains: asStringList(value.approved_email_domains),
    content_sample: asNumber(value.content_sample),
  };
}

function normalizeExportArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeAccessControlArgs(args),
    ...normalizeDataGovernanceArgs(args),
    ...normalizeContentSharingArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toOptions(args: ExportAuditBundleArgs): SumologicAssessmentOptions {
  return {
    maxAllowlistedUsers: args.max_allowlisted_users,
    minPasswordLength: args.min_password_length,
    maxPasswordAgeDays: args.max_password_age_days,
    maxAdmins: args.max_admins,
    keyMaxAgeDays: args.key_max_age_days,
    keyInactiveDays: args.key_inactive_days,
    userInactiveDays: args.user_inactive_days,
    maxSessionTimeoutMinutes: args.max_session_timeout_minutes,
    minRetentionDays: args.min_retention_days,
    collectorOfflineDays: args.collector_offline_days,
    approvedDestinationDomains: args.approved_destination_domains,
    approvedEmailDomains: args.approved_email_domains,
    contentSample: args.content_sample,
  };
}

function createClient(args: AuthArgs): SumologicApiClient {
  return new SumologicApiClient(resolveSumologicConfiguration(args as JsonRecord));
}

function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

const authParams = {
  access_id: Type.Optional(Type.String({ description: "Sumo Logic access ID. Defaults to SUMOLOGIC_ACCESS_ID, then the config file." })),
  access_key: Type.Optional(Type.String({ description: "Sumo Logic access key. Defaults to SUMOLOGIC_ACCESS_KEY, then the config file." })),
  endpoint: Type.Optional(Type.String({ description: "Deployment code (us1, us2, eu, au, ca, ch, de, esc, fed, in, jp, kr) or full API URL such as https://api.us2.sumologic.com/api. Defaults to SUMOLOGIC_ENDPOINT, then SUMOLOGIC_DEPLOYMENT, then us1." })),
  deployment: Type.Optional(Type.String({ description: "Alias for endpoint when passing a deployment code." })),
  config_file: Type.Optional(Type.String({ description: "YAML config file with access_id, access_key, and endpoint. Defaults to SUMOLOGIC_CONFIG_FILE or ~/.sumologic-sec-inspector/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const identityParams = {
  max_allowlisted_users: Type.Optional(Type.Number({ description: "Maximum SAML bypass allowlist size before failing control 2. Defaults to 2.", default: 2 })),
  min_password_length: Type.Optional(Type.Number({ description: "Required password minimum length. Defaults to 12.", default: 12 })),
  max_password_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable password age in days. Defaults to 90.", default: 90 })),
};

const accessControlParams = {
  max_admins: Type.Optional(Type.Number({ description: "Maximum users holding administrative roles before failing control 6. Defaults to 5.", default: 5 })),
  key_max_age_days: Type.Optional(Type.Number({ description: "Access key age in days before rotation is required. Defaults to 90.", default: 90 })),
  key_inactive_days: Type.Optional(Type.Number({ description: "Idle days before an access key is inactive. Defaults to 90.", default: 90 })),
  user_inactive_days: Type.Optional(Type.Number({ description: "Days since last login before an active user (and any admin role member) is reported dormant. Defaults to 90.", default: 90 })),
  max_session_timeout_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable web session timeout in minutes. Defaults to 15.", default: 15 })),
};

const dataGovernanceParams = {
  min_retention_days: Type.Optional(Type.Number({ description: "Minimum partition retention in days. Defaults to 365.", default: 365 })),
  collector_offline_days: Type.Optional(Type.Number({ description: "Days offline before an installed collector fails control 12. Defaults to 30.", default: 30 })),
  approved_destination_domains: Type.Optional(Type.Array(Type.String(), { description: "Approved hostnames or domains for outbound connections; when supplied, control 10 is evaluated automatically." })),
};

const contentSharingParams = {
  approved_email_domains: Type.Optional(Type.Array(Type.String(), { description: "Additional approved email domains for monitor notifications; org user domains are always included." })),
  content_sample: Type.Optional(Type.Number({ description: "Maximum personal-folder items whose permissions are sampled. Defaults to 25.", default: 25 })),
};

export function registerSumologicTools(pi: any): void {
  pi.registerTool({
    name: "sumologic_check_access",
    label: "Check Sumo Logic audit access",
    description:
      "Validate read-only Sumo Logic Management API access across users, roles, access keys, SAML, password policy, service allowlist, policies, partitions, scheduled views, ingest budgets, connections, collectors, monitors, and content surfaces, reporting missing role capabilities.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkSumologicAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "sumologic_check_access", ...result });
      } catch (error) {
        return errorResult(`Sumo Logic access check failed: ${errorMessage(error)}`, { tool: "sumologic_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "sumologic_assess_identity",
    label: "Assess Sumo Logic identity posture",
    description:
      "Assess Sumo Logic SAML SSO configuration, SAML bypass allowlist size, password policy strength, password expiration, and MFA enforcement (spec controls 1 to 5).",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessSumologicIdentity(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "sumologic_assess_identity", ...result });
      } catch (error) {
        return errorResult(`Sumo Logic identity assessment failed: ${errorMessage(error)}`, { tool: "sumologic_assess_identity" });
      }
    },
  });

  pi.registerTool({
    name: "sumologic_assess_access_control",
    label: "Assess Sumo Logic access control",
    description:
      "Assess Sumo Logic role least privilege, access key rotation, inactive access keys, service allowlist enforcement, and session timeout policy (spec controls 6, 7, 8, 13, 14).",
    parameters: Type.Object({ ...authParams, ...accessControlParams }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await assessSumologicAccessControl(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "sumologic_assess_access_control", ...result });
      } catch (error) {
        return errorResult(`Sumo Logic access control assessment failed: ${errorMessage(error)}`, { tool: "sumologic_assess_access_control" });
      }
    },
  });

  pi.registerTool({
    name: "sumologic_assess_data_governance",
    label: "Assess Sumo Logic data governance",
    description:
      "Assess Sumo Logic audit index enablement, data forwarding destinations, collector hygiene, ingest budgets, and partition retention (spec controls 9, 10, 12, 16, 17).",
    parameters: Type.Object({ ...authParams, ...dataGovernanceParams }),
    prepareArguments: normalizeDataGovernanceArgs,
    async execute(_toolCallId: string, args: DataGovernanceArgs) {
      try {
        const result = await assessSumologicDataGovernance(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "sumologic_assess_data_governance", ...result });
      } catch (error) {
        return errorResult(`Sumo Logic data governance assessment failed: ${errorMessage(error)}`, { tool: "sumologic_assess_data_governance" });
      }
    },
  });

  pi.registerTool({
    name: "sumologic_assess_content_sharing",
    label: "Assess Sumo Logic content sharing and alerting",
    description:
      "Assess Sumo Logic content sharing permissions, scheduled search role bindings, lookup table access, dashboard sharing restrictions, and monitor alert routing (spec controls 11, 15, 18, 19, 20).",
    parameters: Type.Object({ ...authParams, ...contentSharingParams }),
    prepareArguments: normalizeContentSharingArgs,
    async execute(_toolCallId: string, args: ContentSharingArgs) {
      try {
        const result = await assessSumologicContentSharing(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "sumologic_assess_content_sharing", ...result });
      } catch (error) {
        return errorResult(`Sumo Logic content sharing assessment failed: ${errorMessage(error)}`, { tool: "sumologic_assess_content_sharing" });
      }
    },
  });

  pi.registerTool({
    name: "sumologic_export_audit_bundle",
    label: "Export Sumo Logic audit bundle",
    description:
      "Export a Sumo Logic audit package with raw API snapshots, normalized findings for all 20 spec controls, executive summary, unified compliance matrix, per-framework reports, an error log for partial collection, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      ...identityParams,
      ...accessControlParams,
      ...dataGovernanceParams,
      ...contentSharingParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}. Each run allocates a new directory and matching zip.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveSumologicConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSumologicAuditBundle(new SumologicApiClient(config), config, outputRoot, toOptions(args));
        return textResult(
          [
            "Sumo Logic audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Collection errors: ${result.errorCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "sumologic_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            error_count: result.errorCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(`Sumo Logic audit bundle export failed: ${errorMessage(error)}`, { tool: "sumologic_export_audit_bundle" });
      }
    },
  });
}
