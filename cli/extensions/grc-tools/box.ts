/**
 * Box enterprise security inspector tools for grclanker.
 *
 * Read-only Box Content API coverage for the 25 controls in
 * specs/box-sec-inspector.spec.md: identity and access, sharing and
 * collaboration, data governance, and Shield plus monitoring posture.
 */
import { createPrivateKey, createSign, randomBytes } from "node:crypto";
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
import { parse as parseYaml, YAMLError } from "yaml";
import { createCredentialScrubber } from "./credential-scrub.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/box";
const DEFAULT_BASE_URL = "https://api.box.com/2.0";
const DEFAULT_TOKEN_URL = "https://api.box.com/oauth2/token";
const BOX_JWT_AUDIENCE = "https://api.box.com/oauth2/token";
const BOX_VERSION_HEADER = "2025.0";
const CLASSIFICATION_TEMPLATE_KEY = "securityClassification-6VMVochwUWo";
const DEFAULT_CONFIG_DIR = ".box-sec-inspector";
const DEFAULT_CONFIG_FILE = "config.yaml";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_USER_PAGE_SIZE = 1000;
const DEFAULT_EVENT_PAGE_SIZE = 500;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_GROUP_LIMIT = 200;
const DEFAULT_EVENT_LIMIT = 2000;
const DEFAULT_LIST_LIMIT = 500;
const DEFAULT_LOOKBACK_DAYS = 90;
const DEFAULT_MAX_ADMINS = 10;
const DEFAULT_MIN_PASSWORD_LENGTH = 12;
const DEFAULT_MAX_SESSION_HOURS = 24;
const DEFAULT_STALE_ALLOWLIST_DAYS = 365;
const MAX_ASSIGNMENT_POLICIES = 50;
const REDACTED = "[REDACTED]";
const CREDENTIAL_LAST_SEGMENTS = new Set([
  "token",
  "secret",
  "secrets",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "apikey",
  "authorization",
  "credential",
  "credentials",
  "community",
]);
const CREDENTIAL_KEY_QUALIFIERS = new Set(["api", "private", "secret", "signing", "access", "shared", "encryption", "session", "master", "client"]);
const JWT_ASSERTION_TTL_SECONDS = 45;
const MAX_RETRY_AFTER_MS = 60_000;

const USER_FIELDS = [
  "id",
  "type",
  "name",
  "login",
  "role",
  "status",
  "created_at",
  "modified_at",
  "is_platform_access_only",
  "is_exempt_from_login_verification",
  "is_exempt_from_device_limits",
  "is_external_collab_restricted",
  "external_app_user_id",
].join(",");

const GROUP_FIELDS = ["id", "type", "name", "provenance", "invitability_level", "member_viewability_level", "created_at"].join(",");

const ACTIVITY_EVENT_TYPES = [
  "LOGIN",
  "ADMIN_LOGIN",
  "CHANGE_ADMIN_ROLE",
  "NEW_USER",
  "UPLOAD",
  "DOWNLOAD",
  "PREVIEW",
  "EDIT",
  "COPY",
  "MOVE",
  "DELETE",
  "UNDELETE",
  "LOCK",
  "UNLOCK",
];

const ACTIVITY_EVENT_TYPE_SET = new Set(ACTIVITY_EVENT_TYPES);

const FAILED_LOGIN_EVENT_TYPE = "FAILED_LOGIN";

const IDENTITY_EVENT_TYPES = [...ACTIVITY_EVENT_TYPES, FAILED_LOGIN_EVENT_TYPE];

const SHARING_EVENT_TYPES = [
  "ENTERPRISE_APP_AUTHORIZATION_UPDATE",
  "APPLICATION_CREATED",
  "APPLICATION_PUBLIC_KEY_ADDED",
  "EXTERNAL_COLLAB_SECURITY_SETTINGS",
  "SHARE",
  "ITEM_SHARED_UPDATE",
  "COLLABORATION_INVITE",
  "TERMS_OF_SERVICE_ACCEPT",
];

const SHIELD_EVENT_TYPES = [
  "SHIELD_ALERT",
  "SHIELD_DOWNLOAD_BLOCKED",
  "SHIELD_EXTERNAL_COLLAB_ACCESS_BLOCKED",
  "SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED",
  "SHIELD_SHARED_LINK_ACCESS_BLOCKED",
  "CONTENT_WORKFLOW_ABNORMAL_DOWNLOAD_ACTIVITY",
  "CONTENT_WORKFLOW_SHARING_POLICY_VIOLATION",
  "CONTENT_WORKFLOW_UPLOAD_POLICY_VIOLATION",
  "FILE_MARKED_MALICIOUS",
  "DEVICE_TRUST_CHECK_FAILED",
  "FILE_WATERMARKED_DOWNLOAD",
  "DOWNLOAD",
  "PREVIEW",
];

const PUBLIC_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "icloud.com",
  "me.com",
  "aol.com",
  "protonmail.com",
  "proton.me",
  "mail.com",
  "gmx.com",
  "gmx.net",
  "yandex.com",
  "zoho.com",
]);

export type BoxAuthMode = "jwt" | "ccg" | "oauth";
export type BoxSeverity = "critical" | "high" | "medium" | "low" | "info";
export type BoxFindingStatus = "pass" | "warn" | "fail" | "manual";
export type BoxArea = "identity_access" | "sharing_collaboration" | "data_governance" | "shield_monitoring";
export type BoxFramework = "FedRAMP" | "CMMC" | "SOC 2" | "CIS" | "PCI-DSS" | "STIG" | "IRAP" | "ISMAP";
type JwtAlgorithm = "RS256" | "RS384" | "RS512";

export interface BoxJwtCredentials {
  privateKey: string;
  passphrase?: string;
  publicKeyId?: string;
  algorithm: JwtAlgorithm;
}

export interface BoxResolvedConfig {
  authMode: BoxAuthMode;
  clientId?: string;
  clientSecret?: string;
  enterpriseId?: string;
  subjectType: "enterprise" | "user";
  subjectId?: string;
  accessToken?: string;
  refreshToken?: string;
  jwt?: BoxJwtCredentials;
  baseUrl: string;
  tokenUrl: string;
  timeoutMs: number;
  maxRetries: number;
  sourceChain: string[];
}

export interface BoxAccessSurface {
  name: string;
  /**
   * The path the probe requested when it was readable, the failed request's label (method, path, query) when it was
   * not, and null when no request was made for it.
   */
  endpoint: string | null;
  status: "readable" | "not_readable" | "not_configured";
  /** Records the probe returned; null when the probe was not readable. */
  count: number | null;
  error?: string;
  /** The HTTP status a failed probe observed; null when the probe was readable or the failure produced no response. */
  httpStatus: number | null;
}

export interface BoxAccessCheckResult {
  status: "healthy" | "limited";
  enterpriseId?: string;
  authMode: BoxAuthMode;
  surfaces: BoxAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface BoxFinding {
  id: string;
  control: number;
  title: string;
  severity: BoxSeverity;
  status: BoxFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  manualEvidence?: string;
}

export interface BoxAssessmentResult {
  area: BoxArea;
  title: string;
  summary: JsonRecord;
  findings: BoxFinding[];
  errors: string[];
  truncated: string[];
}

export interface BoxAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface BoxListPage {
  items: JsonRecord[];
  truncated: boolean;
}

export interface CollectedDataset<T> {
  data: T;
  error?: string;
  /** The HTTP status the failed read observed; absent when the read completed or produced no response. */
  statusCode?: number;
  /** The label of the request whose failure is recorded in `error`, when the client named one. */
  request?: string;
  /** True when no request was made because a dataset it depends on could not be read. */
  notRequested?: boolean;
  truncated?: boolean;
}

/**
 * Written in place of a list or record that was denied, errored, timed out, or never requested, so a bundle consumer
 * cannot mistake a denial for an empty inventory. `status` is the HTTP status the failed request observed, "error"
 * when the failure produced no response, and "not-collected" when no request was made.
 */
export interface BoxNotCollectedMarker {
  collected: false;
  status: number | "error" | "not-collected";
  endpoint: string | null;
  error: string | null;
  reason: "not_readable" | "not_requested";
  /** For a per-parent child map none of whose reads completed: the marker of every failed child read, keyed by parent id. */
  failed_reads?: Record<string, BoxNotCollectedMarker>;
}

/** Per-policy assignment (or per-barrier segment) lists keyed by the parent id; a denied child read carries a marker. */
export type BoxAssignmentMap = Record<string, JsonRecord[] | BoxNotCollectedMarker>;

type AuthArgs = {
  auth_method?: string;
  jwt_config_path?: string;
  jwt_passphrase?: string;
  client_id?: string;
  client_secret?: string;
  enterprise_id?: string;
  subject_type?: string;
  subject_id?: string;
  access_token?: string;
  refresh_token?: string;
  config_path?: string;
  base_url?: string;
  token_url?: string;
  timeout_seconds?: number;
  max_retries?: number;
};

type IdentityArgs = AuthArgs & {
  user_limit?: number;
  event_limit?: number;
  lookback_days?: number;
  max_admins?: number;
  min_password_length?: number;
  max_session_hours?: number;
};

type SharingArgs = AuthArgs & {
  event_limit?: number;
  lookback_days?: number;
  stale_allowlist_days?: number;
  list_limit?: number;
};

type GovernanceArgs = AuthArgs & {
  list_limit?: number;
};

type ShieldArgs = AuthArgs & {
  event_limit?: number;
  lookback_days?: number;
};

type ExportArgs = IdentityArgs & SharingArgs & GovernanceArgs & {
  output_dir?: string;
};

export interface BoxIdentityOptions {
  userLimit?: number;
  eventLimit?: number;
  lookbackDays?: number;
  maxAdmins?: number;
  minPasswordLength?: number;
  maxSessionHours?: number;
}

export interface BoxSharingOptions {
  eventLimit?: number;
  lookbackDays?: number;
  staleAllowlistDays?: number;
  listLimit?: number;
}

export interface BoxGovernanceOptions {
  listLimit?: number;
}

export interface BoxShieldOptions {
  eventLimit?: number;
  lookbackDays?: number;
}

export type BoxExportOptions = BoxIdentityOptions & BoxSharingOptions & BoxGovernanceOptions;

interface ControlDefinition {
  title: string;
  severity: BoxSeverity;
  area: BoxArea;
  mappings: Record<BoxFramework, string>;
}

const BOX_CONTROLS: Record<number, ControlDefinition> = {
  1: control("SSO enforcement", "critical", "identity_access", ["IA-2", "AC.L2-3.1.1", "CC6.1", "1.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "CPS-04"]),
  2: control("2FA for admins", "critical", "identity_access", ["IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.1", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-06"]),
  3: control("2FA for all users", "high", "identity_access", ["IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.2", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-06"]),
  4: control("External collaboration restrictions", "high", "sharing_collaboration", ["AC-4", "AC.L2-3.1.3", "CC6.6", "6.1", "7.2.3", "SRG-APP-000039", "ISM-1148", "CPS-11"]),
  5: control("Collaboration allowlist audit", "medium", "sharing_collaboration", ["AC-4", "AC.L2-3.1.3", "CC6.6", "6.2", "7.2.3", "SRG-APP-000039", "ISM-1148", "CPS-11"]),
  6: control("Sharing link policies", "high", "sharing_collaboration", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.3", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  7: control("Shared link expiration", "medium", "sharing_collaboration", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.4", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  8: control("Shared link password policy", "medium", "sharing_collaboration", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.5", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  9: control("Watermarking enabled", "medium", "sharing_collaboration", ["SC-28", "SC.L2-3.13.16", "CC6.7", "3.1", "3.4", "SRG-APP-000231", "ISM-0457", "CPS-09"]),
  10: control("Device trust and pins", "medium", "data_governance", ["IA-3", "IA.L2-3.5.1", "CC6.1", "1.2", "2.4", "SRG-APP-000158", "ISM-1482", "CPS-04"]),
  11: control("Classification labels", "medium", "data_governance", ["MP-4", "MP.L2-3.8.5", "CC6.7", "3.2", "9.6.1", "SRG-APP-000231", "ISM-0272", "CPS-09"]),
  12: control("Retention policies", "medium", "data_governance", ["AU-11", "AU.L2-3.3.1", "CC7.4", "8.1", "3.1", "SRG-APP-000515", "ISM-0859", "CPS-10"]),
  13: control("Legal hold policies", "low", "data_governance", ["AU-11", "AU.L2-3.3.1", "CC7.4", "8.2", "3.1", "SRG-APP-000515", "ISM-0859", "CPS-10"]),
  14: control("Shield smart access policies", "high", "shield_monitoring", ["AC-3", "AC.L2-3.1.2", "CC6.3", "6.6", "7.2.1", "SRG-APP-000033", "ISM-0432", "CPS-07"]),
  15: control("Shield information barriers", "medium", "shield_monitoring", ["AC-4", "AC.L2-3.1.3", "CC6.6", "6.7", "7.2.3", "SRG-APP-000039", "ISM-1148", "CPS-11"]),
  16: control("Enterprise event streaming", "high", "shield_monitoring", ["AU-2", "AU.L2-3.3.1", "CC7.2", "8.3", "10.2.1", "SRG-APP-000089", "ISM-0580", "CPS-10"]),
  17: control("Admin role minimization", "high", "identity_access", ["AC-6(5)", "AC.L2-3.1.5", "CC6.3", "6.8", "7.2.2", "SRG-APP-000340", "ISM-1507", "CPS-07"]),
  18: control("Co-admin permission scoping", "medium", "identity_access", ["AC-6", "AC.L2-3.1.5", "CC6.3", "6.9", "7.2.2", "SRG-APP-000340", "ISM-0432", "CPS-07"]),
  19: control("App approval process", "medium", "sharing_collaboration", ["CM-7(5)", "CM.L2-3.4.8", "CC8.1", "10.1", "6.3.2", "SRG-APP-000386", "ISM-1490", "CPS-12"]),
  20: control("Custom terms of service", "low", "sharing_collaboration", ["PS-6", "AT.L2-3.2.1", "CC1.4", "11.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "CPS-13"]),
  21: control("Password policy strength", "high", "identity_access", ["IA-5(1)", "IA.L2-3.5.7", "CC6.1", "5.1", "8.3.6", "SRG-APP-000166", "ISM-0421", "CPS-05"]),
  22: control("Session duration limits", "medium", "identity_access", ["AC-11", "AC.L2-3.1.10", "CC6.1", "7.1", "8.2.8", "SRG-APP-000190", "ISM-0853", "CPS-08"]),
  23: control("IP allowlisting", "medium", "identity_access", ["SC-7", "SC.L2-3.13.1", "CC6.6", "9.1", "1.3.2", "SRG-APP-000383", "ISM-1148", "CPS-11"]),
  24: control("Inactive user detection", "medium", "identity_access", ["AC-2(3)", "AC.L2-3.1.1", "CC6.2", "7.2", "8.1.4", "SRG-APP-000025", "ISM-1404", "CPS-07"]),
  25: control("Content access monitoring", "high", "shield_monitoring", ["AU-6", "AU.L2-3.3.5", "CC7.2", "8.4", "10.6.1", "SRG-APP-000108", "ISM-0580", "CPS-10"]),
};

const FRAMEWORK_ORDER: BoxFramework[] = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"];

const FRAMEWORK_REPORTS: Array<{ framework: BoxFramework; path: string; title: string }> = [
  { framework: "FedRAMP", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { framework: "CMMC", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC 2.0 Compliance Report" },
  { framework: "SOC 2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { framework: "CIS", path: "compliance/cis/cis_compliance_report.md", title: "CIS Benchmark Alignment Report" },
  { framework: "PCI-DSS", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { framework: "STIG", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { framework: "IRAP", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { framework: "ISMAP", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

function control(
  title: string,
  severity: BoxSeverity,
  area: BoxArea,
  ids: [string, string, string, string, string, string, string, string],
): ControlDefinition {
  return {
    title,
    severity,
    area,
    mappings: {
      "FedRAMP": ids[0],
      "CMMC": ids[1],
      "SOC 2": ids[2],
      "CIS": ids[3],
      "PCI-DSS": ids[4],
      "STIG": ids[5],
      "IRAP": ids[6],
      "ISMAP": ids[7],
    },
  };
}

export function mappingsForControl(controlNumber: number): string[] {
  const definition = BOX_CONTROLS[controlNumber];
  if (!definition) return [];
  return FRAMEWORK_ORDER.map((framework) => `${framework} ${definition.mappings[framework]}`);
}

export function listBoxControls(): Array<{ control: number; id: string; title: string; severity: BoxSeverity; area: BoxArea }> {
  return Object.entries(BOX_CONTROLS).map(([key, definition]) => ({
    control: Number(key),
    id: findingId(Number(key)),
    title: definition.title,
    severity: definition.severity,
    area: definition.area,
  }));
}

function findingId(controlNumber: number): string {
  return `BOX-${String(controlNumber).padStart(2, "0")}`;
}

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
    if (/^(true|1|yes|enabled|on|required)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled|off|optional)$/i.test(value.trim())) return false;
  }
  if (value === 1) return true;
  if (value === 0) return false;
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

// The base URL keeps only scheme, host, and path: userinfo, query, and fragment would otherwise ride along into every
// request label and error string.
function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
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
  return normalized || "box";
}

function parseIsoDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysBetween(later: Date, earlier: Date): number {
  return Math.floor((later.getTime() - earlier.getTime()) / 86_400_000);
}

/**
 * The module's credential scrubber (see credential-scrub.ts for the boundary): carriers whatever the value's shape,
 * every configured secret registered by a client in every encoded form, and real token shapes bare.
 */
const credentialScrubber = createCredentialScrubber();

/**
 * The scrub applied to every error string before it is recorded anywhere (findings, summaries, analysis objects,
 * access surfaces, the bundle, tool results). Unanchored, idempotent, and independent of which client threw.
 */
export function scrubErrorText(text: string): string {
  return credentialScrubber.scrub(text);
}

/**
 * The single point where a thrown value becomes recorded text: every dataset error, access surface error, `_errors.log`
 * line, and tool failure passes through here, so no path can record an unscrubbed message. A `SyntaxError` is named
 * by class only because its message quotes the text that failed to parse.
 */
function errorMessage(error: unknown): string {
  if (error instanceof SyntaxError) return PARSE_ERROR_NOTE;
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

const PARSE_ERROR_NOTE = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";

function truncateList<T>(items: T[], max = 25): T[] {
  return items.slice(0, max);
}

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
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
    const currentStat = lstatSync(currentPath);
    if (currentStat.isSymbolicLink()) {
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
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6"];
  for (const suffix of suffixes) {
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
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      total += await countFilesRecursively(pathname);
    } else if (entry.isFile()) {
      total += 1;
    }
  }
  return total;
}

function parseAuthMode(value: string | undefined): BoxAuthMode | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return undefined;
  if (normalized === "jwt") return "jwt";
  if (normalized === "ccg" || normalized === "client_credentials") return "ccg";
  if (normalized === "oauth" || normalized === "oauth2" || normalized === "token") return "oauth";
  throw new Error(`Unsupported Box auth method "${value}". Use jwt, ccg, or oauth.`);
}

function parseSubjectType(value: string | undefined): "enterprise" | "user" | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return undefined;
  if (normalized === "enterprise" || normalized === "user") return normalized;
  throw new Error(`Unsupported Box subject type "${value}". Use enterprise or user.`);
}

function parseJwtAlgorithm(value: string | undefined): JwtAlgorithm {
  const normalized = value?.trim().toUpperCase();
  if (!normalized) return "RS512";
  if (normalized === "RS256" || normalized === "RS384" || normalized === "RS512") return normalized;
  throw new Error(`Unsupported Box JWT algorithm "${value}". Use RS256, RS384, or RS512.`);
}

interface ConfigOverlay {
  authMode?: BoxAuthMode;
  jwtConfigPath?: string;
  jwtPassphrase?: string;
  jwtAlgorithm?: string;
  clientId?: string;
  clientSecret?: string;
  enterpriseId?: string;
  subjectType?: "enterprise" | "user";
  subjectId?: string;
  accessToken?: string;
  refreshToken?: string;
  baseUrl?: string;
  tokenUrl?: string;
  timeoutSeconds?: number;
  maxRetries?: number;
}

function overlayFromRecord(record: JsonRecord): ConfigOverlay {
  const pick = (...keys: string[]): unknown => {
    for (const key of keys) {
      if (record[key] !== undefined && record[key] !== null && record[key] !== "") return record[key];
    }
    return undefined;
  };
  return {
    authMode: parseAuthMode(asString(pick("auth_method", "authMethod", "auth_mode"))),
    jwtConfigPath: asString(pick("jwt_config_path", "jwt_config", "jwtConfigPath")),
    jwtPassphrase: asString(pick("jwt_passphrase", "passphrase")),
    jwtAlgorithm: asString(pick("jwt_algorithm", "jwtAlgorithm")),
    clientId: asString(pick("client_id", "clientId", "clientID")),
    clientSecret: asString(pick("client_secret", "clientSecret")),
    enterpriseId: asString(pick("enterprise_id", "enterpriseId", "enterpriseID")),
    subjectType: parseSubjectType(asString(pick("subject_type", "subjectType"))),
    subjectId: asString(pick("subject_id", "subjectId", "user_id")),
    accessToken: asString(pick("access_token", "accessToken", "token", "developer_token")),
    refreshToken: asString(pick("refresh_token", "refreshToken")),
    baseUrl: asString(pick("base_url", "baseUrl", "api_base_url")),
    tokenUrl: asString(pick("token_url", "tokenUrl")),
    timeoutSeconds: asNumber(pick("timeout_seconds", "timeout")),
    maxRetries: asNumber(pick("max_retries", "maxRetries")),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): ConfigOverlay {
  return {
    authMode: parseAuthMode(asString(env.BOX_AUTH_METHOD)),
    jwtConfigPath: asString(env.BOX_JWT_CONFIG_PATH),
    jwtPassphrase: asString(env.BOX_JWT_PASSPHRASE),
    jwtAlgorithm: asString(env.BOX_JWT_ALGORITHM),
    clientId: asString(env.BOX_CLIENT_ID),
    clientSecret: asString(env.BOX_CLIENT_SECRET),
    enterpriseId: asString(env.BOX_ENTERPRISE_ID),
    subjectType: parseSubjectType(asString(env.BOX_SUBJECT_TYPE)),
    subjectId: asString(env.BOX_SUBJECT_ID),
    accessToken: asString(env.BOX_ACCESS_TOKEN) ?? asString(env.BOX_TOKEN) ?? asString(env.BOX_DEVELOPER_TOKEN),
    refreshToken: asString(env.BOX_REFRESH_TOKEN),
    baseUrl: asString(env.BOX_API_BASE_URL) ?? asString(env.BOX_BASE_URL),
    tokenUrl: asString(env.BOX_TOKEN_URL),
    timeoutSeconds: asNumber(env.BOX_TIMEOUT),
    maxRetries: asNumber(env.BOX_MAX_RETRIES),
  };
}

function overlayHasValues(overlay: ConfigOverlay): boolean {
  return Object.values(overlay).some((value) => value !== undefined);
}

function applyOverlay(base: ConfigOverlay, overlay: ConfigOverlay): ConfigOverlay {
  const merged: ConfigOverlay = { ...base };
  for (const [key, value] of Object.entries(overlay) as Array<[keyof ConfigOverlay, unknown]>) {
    if (value !== undefined) (merged as Record<string, unknown>)[key] = value;
  }
  return merged;
}

/** Thrown when a Box config file cannot be read or parsed; the message is fixed text carrying only the path, an fs code, and a parser position. */
export class BoxConfigFileError extends Error {
  readonly path: string;
  readonly code?: string;

  constructor(message: string, path: string, code?: string) {
    super(message);
    this.name = "BoxConfigFileError";
    this.path = path;
    this.code = code;
  }
}

const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
const JSON_POSITION_PATTERN = /at position (\d+)/;

function fsErrorCode(error: unknown): string | undefined {
  const code = asObject(error)?.code;
  return typeof code === "string" && FS_ERROR_CODE_PATTERN.test(code) ? code : undefined;
}

/**
 * Read step of the two-step config loader: the filesystem's own wording (which can quote the path twice or describe
 * the operation) is never interpolated; only the validated error code is. A missing file at a path the caller did not
 * name explicitly is not an error and yields undefined.
 */
function readConfigFileText(pathname: string, label: string, required: boolean): string | undefined {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const code = fsErrorCode(error);
    if (!required && code === "ENOENT") return undefined;
    throw new BoxConfigFileError(`Unable to read ${label} ${pathname}${code ? ` (${code})` : ""}`, pathname, code);
  }
}

/**
 * Parse step for YAML: every thrown value is caught (yaml.parse throws a plain ReferenceError for an unresolved alias,
 * whose message starts with the aliased value) and the line is taken only from a YAMLError's own position.
 */
function parseConfigYaml(text: string, pathname: string, label: string): unknown {
  try {
    return parseYaml(text);
  } catch (error) {
    const line = error instanceof YAMLError ? error.linePos?.[0]?.line : undefined;
    throw new BoxConfigFileError(`Unable to parse ${label}: invalid YAML in ${pathname}${line ? ` at line ${line}` : ""}`, pathname, "INVALID_YAML");
  }
}

/**
 * Parse step for JSON: JSON.parse quotes a window of the source (or the whole source when it is short) in its message,
 * so the message is never interpolated; the failure position is taken only through a strict pattern.
 */
function parseConfigJson(text: string, pathname: string, label: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    const position = error instanceof SyntaxError ? JSON_POSITION_PATTERN.exec(error.message)?.[1] : undefined;
    throw new BoxConfigFileError(`Unable to parse ${label}: invalid JSON in ${pathname}${position ? ` at position ${position}` : ""}`, pathname, "INVALID_JSON");
  }
}

function readYamlConfigFile(pathname: string, required: boolean): ConfigOverlay | undefined {
  const text = readConfigFileText(pathname, "Box config file", required);
  if (text === undefined) return undefined;
  const record = asObject(parseConfigYaml(text, pathname, "Box config file"));
  if (!record) return undefined;
  const boxSection = asObject(record.box);
  return overlayFromRecord(boxSection ? { ...record, ...boxSection } : record);
}

function readJwtConfigFile(pathname: string): {
  clientId?: string;
  clientSecret?: string;
  enterpriseId?: string;
  privateKey?: string;
  passphrase?: string;
  publicKeyId?: string;
} {
  const text = readConfigFileText(pathname, "Box JWT config file", true) ?? "";
  const parsed = asObject(parseConfigJson(text, pathname, "Box JWT config file")) ?? {};
  const appSettings = asObject(parsed.boxAppSettings) ?? {};
  const appAuth = asObject(appSettings.appAuth) ?? {};
  return {
    clientId: asString(appSettings.clientID) ?? asString(appSettings.clientId),
    clientSecret: asString(appSettings.clientSecret),
    enterpriseId: asString(parsed.enterpriseID) ?? asString(parsed.enterpriseId),
    privateKey: typeof appAuth.privateKey === "string" ? appAuth.privateKey : undefined,
    passphrase: typeof appAuth.passphrase === "string" && appAuth.passphrase.length > 0 ? appAuth.passphrase : undefined,
    publicKeyId: asString(appAuth.publicKeyID) ?? asString(appAuth.publicKeyId),
  };
}

function inferAuthMode(overlay: ConfigOverlay): BoxAuthMode {
  if (overlay.authMode) return overlay.authMode;
  if (overlay.accessToken || overlay.refreshToken) return "oauth";
  if (overlay.jwtConfigPath) return "jwt";
  if (overlay.clientId && overlay.clientSecret && (overlay.enterpriseId || overlay.subjectId)) return "ccg";
  throw new Error(
    "Box credentials are required. Set BOX_JWT_CONFIG_PATH for JWT, BOX_CLIENT_ID plus BOX_CLIENT_SECRET plus BOX_ENTERPRISE_ID for Client Credentials Grant, or BOX_ACCESS_TOKEN for OAuth 2.0.",
  );
}

export function resolveBoxConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { cwd?: string; homeDir?: string } = {},
): BoxResolvedConfig {
  const cwd = options.cwd ?? process.cwd();
  const homeDir = options.homeDir ?? homedir();
  const sourceChain: string[] = [];
  let merged: ConfigOverlay = {};

  const argOverlay = overlayFromRecord(input);
  const configPath = asString(input.config_path) ?? asString(env.BOX_CONFIG_PATH);
  const resolvedConfigPath = configPath
    ? resolve(cwd, configPath)
    : join(homeDir, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE);
  const fileOverlay = readYamlConfigFile(resolvedConfigPath, Boolean(configPath));
  if (fileOverlay && overlayHasValues(fileOverlay)) {
    merged = applyOverlay(merged, fileOverlay);
    sourceChain.push(configPath ? `config:${relative(cwd, resolvedConfigPath) || resolvedConfigPath}` : `home:${DEFAULT_CONFIG_DIR}/${DEFAULT_CONFIG_FILE}`);
  } else if (configPath) {
    throw new BoxConfigFileError(`Box config file did not contain any Box settings: ${resolvedConfigPath}`, resolvedConfigPath, "EMPTY_CONFIG");
  }

  const envOverlay = overlayFromEnv(env);
  if (overlayHasValues(envOverlay)) {
    merged = applyOverlay(merged, envOverlay);
    sourceChain.push("environment");
  }

  if (overlayHasValues(argOverlay)) {
    merged = applyOverlay(merged, argOverlay);
    sourceChain.push("arguments");
  }

  const authMode = inferAuthMode(merged);
  let jwt: BoxJwtCredentials | undefined;
  if (authMode === "jwt") {
    if (!merged.jwtConfigPath) {
      throw new Error("Box JWT auth requires BOX_JWT_CONFIG_PATH or a jwt_config_path argument.");
    }
    const jwtFile = readJwtConfigFile(resolve(cwd, merged.jwtConfigPath));
    sourceChain.push("jwt-config-file");
    merged = applyOverlay(
      {
        clientId: jwtFile.clientId,
        clientSecret: jwtFile.clientSecret,
        enterpriseId: jwtFile.enterpriseId,
      },
      merged,
    );
    if (!jwtFile.privateKey) {
      throw new Error("Box JWT config file did not include boxAppSettings.appAuth.privateKey.");
    }
    jwt = {
      privateKey: jwtFile.privateKey,
      passphrase: merged.jwtPassphrase ?? jwtFile.passphrase,
      publicKeyId: jwtFile.publicKeyId,
      algorithm: parseJwtAlgorithm(merged.jwtAlgorithm),
    };
  }

  const subjectType = merged.subjectType ?? "enterprise";
  const subjectId = merged.subjectId ?? (subjectType === "enterprise" ? merged.enterpriseId : undefined);

  switch (authMode) {
    case "jwt":
    case "ccg": {
      if (!merged.clientId || !merged.clientSecret) {
        throw new Error(`Box ${authMode.toUpperCase()} auth requires a client ID and client secret (BOX_CLIENT_ID and BOX_CLIENT_SECRET).`);
      }
      if (!subjectId) {
        throw new Error(
          subjectType === "enterprise"
            ? `Box ${authMode.toUpperCase()} auth requires BOX_ENTERPRISE_ID (or enterpriseID in the JWT config file).`
            : "Box user-subject auth requires BOX_SUBJECT_ID.",
        );
      }
      break;
    }
    case "oauth": {
      if (!merged.accessToken && !(merged.refreshToken && merged.clientId && merged.clientSecret)) {
        throw new Error("Box OAuth 2.0 auth requires BOX_ACCESS_TOKEN, or BOX_REFRESH_TOKEN with BOX_CLIENT_ID and BOX_CLIENT_SECRET.");
      }
      break;
    }
    default: {
      const exhaustive: never = authMode;
      throw new Error(`Unhandled Box auth mode: ${String(exhaustive)}`);
    }
  }

  return {
    authMode,
    clientId: merged.clientId,
    clientSecret: merged.clientSecret,
    enterpriseId: merged.enterpriseId,
    subjectType,
    subjectId,
    accessToken: merged.accessToken,
    refreshToken: merged.refreshToken,
    jwt,
    baseUrl: normalizeBaseUrl(merged.baseUrl ?? DEFAULT_BASE_URL),
    tokenUrl: normalizeBaseUrl(merged.tokenUrl ?? DEFAULT_TOKEN_URL),
    timeoutMs: parseTimeoutSeconds(merged.timeoutSeconds),
    maxRetries: clampNumber(merged.maxRetries, DEFAULT_MAX_RETRIES, 0, 10),
    sourceChain: sourceChain.length > 0 ? [...new Set(sourceChain)] : ["defaults"],
  };
}

/**
 * Registers the given secrets with the module scrubber and scrubs the message under every rule of credential-scrub.ts:
 * the secrets in every encoded form, carriers whatever the value's shape, and real token shapes bare.
 */
export function redactSecrets(message: string, secrets: Array<string | undefined>): string {
  credentialScrubber.registerSecrets(secrets);
  return scrubErrorText(message);
}

function keySegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}

export function isCredentialKey(name: string): boolean {
  const segments = keySegments(name);
  const last = segments[segments.length - 1];
  if (!last) return false;
  if (CREDENTIAL_LAST_SEGMENTS.has(last)) return true;
  if (last === "key" && segments.length > 1 && CREDENTIAL_KEY_QUALIFIERS.has(segments[segments.length - 2])) return true;
  return false;
}

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function redactUrlQuery(text: string): string {
  if (!/^https?:\/\/[^\s]+\?/i.test(text)) return text;
  const [base, query] = text.split("?", 2);
  const rewritten = query
    .split("&")
    .map((pair) => {
      const [name] = pair.split("=", 1);
      return isCredentialKey(safeDecode(name)) ? `${name}=${REDACTED}` : pair;
    })
    .join("&");
  return `${base}?${rewritten}`;
}

/**
 * Deep-copies a collected payload while replacing every value stored under a
 * credential-shaped key (token, secret, password, api_key, ...) with a marker,
 * including {name, value} and {key, value} pair shapes and token-bearing URL
 * query parameters. Applied to every snapshot before it is written.
 */
export function redactCredentialValues(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => redactCredentialValues(entry));
  if (typeof value === "string") return redactUrlQuery(value);
  const record = asObject(value);
  if (!record) return value;
  const pairName = asString(record.name) ?? asString(record.key);
  const redacted: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    if (isCredentialKey(key) || (key === "value" && pairName !== undefined && isCredentialKey(pairName))) {
      redacted[key] = entry === null || entry === undefined ? entry : REDACTED;
    } else {
      redacted[key] = redactCredentialValues(entry);
    }
  }
  return redacted;
}

function projectActor(actor: unknown): JsonRecord | null {
  const record = asObject(actor);
  if (!record) return null;
  return { id: asString(record.id) ?? null, type: asString(record.type) ?? null, name: asString(record.name) ?? null, login: asString(record.login) ?? null };
}

/** Keeps only the event fields the verdicts read, dropping the free-form additional_details bucket. */
export function projectEnterpriseEvent(event: JsonRecord): JsonRecord {
  return {
    event_id: asString(event.event_id) ?? null,
    event_type: asString(event.event_type) ?? null,
    created_at: asString(event.created_at) ?? null,
    created_by: projectActor(event.created_by),
    source: projectActor(event.source),
    session_id: asString(event.session_id) ?? null,
    ip_address: asString(event.ip_address) ?? null,
  };
}

interface UnreadableInventory {
  name: string;
  /** The request whose failure made the inventory unreadable, or null when the client did not name one. */
  endpoint: string | null;
  /** The HTTP status that request observed, or null when the failure produced no response. */
  status: number | null;
  reason: string;
  unchecked: string;
}

/**
 * The gap a finding records for an inventory it reads that could not be collected. The endpoint and status are the
 * ones the failed request observed; nothing is named from a constant.
 */
function unreadableInventory(name: string, dataset: CollectedDataset<unknown>, unchecked: string): UnreadableInventory | undefined {
  if (!dataset.error) return undefined;
  return { name, endpoint: dataset.request ?? null, status: dataset.statusCode ?? null, reason: unreadableReason(dataset), unchecked };
}

/** "collaboration_allowlist_entries (GET /collaboration_whitelist_entries?limit=500)" or just the name when no request was recorded. */
function describeInventory(name: string, dataset: CollectedDataset<unknown>): string {
  return dataset.request ? `${name} (${dataset.request})` : name;
}

/**
 * Rule 1 corollary: a finding computed from several inventories never reports
 * pass while one of them is unreadable. The unreadable inventories are named in
 * the summary and recorded in the evidence; pass drops to warn.
 */
function capForUnreadableInventories(item: BoxFinding, inventories: Array<UnreadableInventory | undefined>, manualEvidence: string): BoxFinding {
  const unreadable = inventories.filter((entry): entry is UnreadableInventory => entry !== undefined);
  if (unreadable.length === 0) return item;
  const evidence = {
    ...(item.evidence ?? {}),
    unreadable_inventories: unreadable.map(({ name, endpoint, status, reason }) => ({ name, endpoint, status, reason })),
  };
  if (item.status !== "pass" && item.status !== "warn") return { ...item, evidence };
  const described = unreadable
    .map((entry) => `${entry.name}${entry.endpoint ? ` (${entry.endpoint})` : ""} could not be read because ${entry.reason}, so ${entry.unchecked}`)
    .join("; ");
  return {
    ...item,
    status: "warn",
    summary: `${item.summary} The verdict is capped at warn because ${described}.`,
    evidence,
    manualEvidence: item.manualEvidence ?? manualEvidence,
  };
}

export function buildBoxJwtAssertion(options: {
  clientId: string;
  subjectId: string;
  subjectType: "enterprise" | "user";
  credentials: BoxJwtCredentials;
  now?: Date;
  audience?: string;
}): string {
  const issuedAt = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const header: JsonRecord = { alg: options.credentials.algorithm, typ: "JWT" };
  if (options.credentials.publicKeyId) header.kid = options.credentials.publicKeyId;
  const claims: JsonRecord = {
    iss: options.clientId,
    sub: options.subjectId,
    box_sub_type: options.subjectType,
    aud: options.audience ?? BOX_JWT_AUDIENCE,
    jti: randomBytes(32).toString("hex"),
    iat: issuedAt,
    exp: issuedAt + JWT_ASSERTION_TTL_SECONDS,
  };
  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(claims))}`;
  const key = createPrivateKey({
    key: options.credentials.privateKey,
    format: "pem",
    passphrase: options.credentials.passphrase,
  });
  const digest = signatureDigest(options.credentials.algorithm);
  const signature = createSign(digest).update(signingInput).sign(key);
  return `${signingInput}.${base64Url(signature)}`;
}

function signatureDigest(algorithm: JwtAlgorithm): string {
  switch (algorithm) {
    case "RS256":
      return "RSA-SHA256";
    case "RS384":
      return "RSA-SHA384";
    case "RS512":
      return "RSA-SHA512";
    default: {
      const exhaustive: never = algorithm;
      throw new Error(`Unhandled JWT algorithm: ${String(exhaustive)}`);
    }
  }
}

/**
 * A Box response with a non-2xx status. `request` is the label of the request that observed it (method, path, and
 * query, without the origin), so every endpoint and status a finding or summary names is one the run actually saw.
 */
export class BoxApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly request?: string;

  constructor(message: string, status: number, code?: string, requestId?: string, request?: string) {
    super(message);
    this.name = "BoxApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.request = request;
  }
}

/** A request that produced no response (timeout, connection failure); it carries the request label but no status. */
export class BoxTransportError extends Error {
  readonly request: string;

  constructor(message: string, request: string) {
    super(message);
    this.name = "BoxTransportError";
    this.request = request;
  }
}

/** The request label of a thrown value, when the client recorded one. */
function requestOf(error: unknown): string | undefined {
  return error instanceof BoxApiError || error instanceof BoxTransportError ? error.request : undefined;
}

/** "GET /users?fields=id,login&limit=100": the method plus the path and query of a request, without the origin. */
export function describeBoxRequest(method: string, url: string): string {
  try {
    const parsed = new URL(url);
    return `${method.toUpperCase()} ${parsed.pathname}${parsed.search}`;
  } catch {
    return `${method.toUpperCase()} ${url}`;
  }
}

/** "403 Forbidden", or just "403" when the response carried no status text. */
function statusLine(response: Response): string {
  return response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
}

// Box's documented error codes are short identifiers (access_denied_insufficient_permissions, rate_limit_exceeded);
// anything else in the field is not the documented shape and is not quoted.
const ERROR_CODE_PATTERN = /^[a-z0-9_-]{1,80}$/i;
const MAX_ERROR_DETAIL_LENGTH = 300;

/**
 * Only Box's documented JSON error fields (message, error_description, error, context_info.message, code, request_id)
 * are quoted, each scrubbed before it is cut to length: cutting first could leave the tail of a token that the
 * whole-value scrub no longer recognizes.
 */
function boxErrorSummary(payload: unknown, redact: (text: string) => string): { message?: string; code?: string; requestId?: string } {
  const object = asObject(payload);
  if (!object) return {};
  const contextMessage = asString(asObject(object.context_info)?.message);
  const message = [asString(object.message), asString(object.error_description), asString(object.error), contextMessage]
    .filter((item): item is string => Boolean(item))
    .map((item) => redact(item).replace(/\s+/g, " "))
    .join("; ")
    .slice(0, MAX_ERROR_DETAIL_LENGTH);
  const rawCode = asString(object.code) ?? asString(object.error);
  const rawRequestId = asString(object.request_id);
  return {
    message: message.length > 0 ? message : undefined,
    code: rawCode && ERROR_CODE_PATTERN.test(rawCode) ? rawCode : undefined,
    requestId: rawRequestId && ERROR_CODE_PATTERN.test(rawRequestId) ? rawRequestId : undefined,
  };
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

export interface BoxReadClient {
  getResolvedConfig(): BoxResolvedConfig;
  getNow(): Date;
  getCurrentUser(): Promise<JsonRecord>;
  resolveEnterpriseId(): Promise<string>;
  getEnterpriseConfiguration(categories?: string[]): Promise<JsonRecord>;
  listUsers(limit?: number): Promise<BoxListPage>;
  listGroups(limit?: number): Promise<BoxListPage>;
  listEnterpriseEvents(options?: { eventTypes?: string[]; createdAfter?: Date; limit?: number }): Promise<BoxListPage>;
  listDevicePinners(limit?: number): Promise<BoxListPage>;
  listRetentionPolicies(limit?: number): Promise<BoxListPage>;
  listRetentionPolicyAssignments(policyId: string, limit?: number): Promise<BoxListPage>;
  listLegalHoldPolicies(limit?: number): Promise<BoxListPage>;
  listLegalHoldPolicyAssignments(policyId: string, limit?: number): Promise<BoxListPage>;
  listShieldInformationBarriers(limit?: number): Promise<BoxListPage>;
  listShieldInformationBarrierSegments(barrierId: string, limit?: number): Promise<BoxListPage>;
  listShieldLists(): Promise<BoxListPage>;
  listCollaborationAllowlistEntries(limit?: number): Promise<BoxListPage>;
  listCollaborationAllowlistExemptTargets(limit?: number): Promise<BoxListPage>;
  listEnterpriseMetadataTemplates(limit?: number): Promise<BoxListPage>;
  getClassificationTemplate(): Promise<JsonRecord>;
  listTermsOfServices(): Promise<BoxListPage>;
}

function completePage(items: JsonRecord[]): BoxListPage {
  return { items, truncated: false };
}

export class BoxApiClient implements BoxReadClient {
  private readonly config: BoxResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private accessToken?: string;
  private refreshToken?: string;
  private accessTokenExpiresAt = 0;
  private accessTokenPromise?: Promise<string>;
  private enterpriseIdPromise?: Promise<string>;
  private readonly memo = new Map<string, Promise<unknown>>();

  constructor(
    config: BoxResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
      sleep?: (ms: number) => Promise<void>;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.refreshToken = config.refreshToken;
    if (config.authMode === "oauth" && config.accessToken) {
      this.accessToken = config.accessToken;
      this.accessTokenExpiresAt = Number.MAX_SAFE_INTEGER;
    }
    // The configured secrets are scrubbed from every recorded error string in every encoded form from here on; tokens
    // issued later are registered as they arrive.
    credentialScrubber.registerSecrets([
      config.clientSecret,
      config.accessToken,
      config.refreshToken,
      config.jwt?.passphrase,
      config.jwt?.privateKey,
    ]);
  }

  getResolvedConfig(): BoxResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private redact(message: string): string {
    return scrubErrorText(message);
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, Array.isArray(value) ? value.join(",") : String(value));
    }
    return url.toString();
  }

  private async fetchWithTimeout(url: string, init: RequestInit, request: string): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) {
        throw new BoxTransportError(`Box request timed out after ${this.config.timeoutMs}ms: ${request}`, request);
      }
      throw new BoxTransportError(`Box request failed: ${request}: ${errorMessage(error)}`, request);
    } finally {
      clearTimeout(timeout);
    }
  }

  private retryDelayMs(response: Response, attempt: number): number {
    const retryAfter = asNumber(response.headers.get("retry-after"));
    if (response.status === 429 && retryAfter !== undefined) {
      return Math.min(Math.max(retryAfter, 0) * 1000, MAX_RETRY_AFTER_MS);
    }
    return Math.min(500 * 2 ** attempt, 8_000);
  }

  private async requestJson(
    url: string,
    init: RequestInit = {},
    options: { skipAuth?: boolean; allowRefresh?: boolean } = {},
  ): Promise<JsonRecord> {
    let attempt = 0;
    let refreshed = false;
    const request = describeBoxRequest(init.method ?? "GET", url);
    for (;;) {
      const headers = new Headers(init.headers ?? {});
      if (!headers.has("accept")) headers.set("accept", "application/json");
      if (!options.skipAuth) {
        headers.set("authorization", `Bearer ${await this.getAccessToken()}`);
      }

      const response = await this.fetchWithTimeout(url, { ...init, headers }, request);
      const rawText = await response.text();
      let payload: JsonRecord | undefined;
      let bodyNote: string | undefined;
      if (rawText.length > 0) {
        try {
          payload = asObject(JSON.parse(rawText));
        } catch {
          // A body that is not JSON (an HTML proxy page, a WAF block) can reflect the request, including its
          // Authorization header, so it is described by content type and length and never echoed.
          bodyNote = `non-JSON ${response.headers.get("content-type") ?? "unknown content type"} response body (${rawText.length} bytes, not echoed)`;
        }
      }

      if (response.ok) return payload ?? {};

      if (response.status === 401 && !refreshed && options.allowRefresh !== false && !options.skipAuth && this.canRefresh()) {
        refreshed = true;
        this.accessToken = undefined;
        this.accessTokenExpiresAt = 0;
        continue;
      }

      if (isRetryableStatus(response.status) && attempt < this.config.maxRetries) {
        await this.sleep(this.retryDelayMs(response, attempt));
        attempt += 1;
        continue;
      }

      const summary = boxErrorSummary(payload, (text) => this.redact(text));
      if (payload !== undefined && summary.message === undefined && rawText.length > 0) {
        bodyNote = `JSON body without a documented error field (${rawText.length} bytes, not echoed)`;
      }
      const detail = summary.message ?? bodyNote;
      throw new BoxApiError(
        this.redact(`Box request failed (${statusLine(response)}) for ${request}${detail ? `: ${detail}` : ""}`),
        response.status,
        summary.code,
        summary.requestId,
        request,
      );
    }
  }

  private canRefresh(): boolean {
    switch (this.config.authMode) {
      case "jwt":
      case "ccg":
        return true;
      case "oauth":
        return Boolean(this.refreshToken && this.config.clientId && this.config.clientSecret);
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unhandled Box auth mode: ${String(exhaustive)}`);
      }
    }
  }

  private tokenRequestBody(): URLSearchParams {
    const body = new URLSearchParams();
    switch (this.config.authMode) {
      case "jwt": {
        if (!this.config.jwt || !this.config.clientId || !this.config.clientSecret || !this.config.subjectId) {
          throw new Error("Box JWT credentials are incomplete.");
        }
        body.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        body.set("assertion", buildBoxJwtAssertion({
          clientId: this.config.clientId,
          subjectId: this.config.subjectId,
          subjectType: this.config.subjectType,
          credentials: this.config.jwt,
          audience: this.config.tokenUrl,
          now: this.now(),
        }));
        body.set("client_id", this.config.clientId);
        body.set("client_secret", this.config.clientSecret);
        return body;
      }
      case "ccg": {
        if (!this.config.clientId || !this.config.clientSecret || !this.config.subjectId) {
          throw new Error("Box Client Credentials Grant credentials are incomplete.");
        }
        body.set("grant_type", "client_credentials");
        body.set("client_id", this.config.clientId);
        body.set("client_secret", this.config.clientSecret);
        body.set("box_subject_type", this.config.subjectType);
        body.set("box_subject_id", this.config.subjectId);
        return body;
      }
      case "oauth": {
        if (!this.refreshToken || !this.config.clientId || !this.config.clientSecret) {
          throw new Error("Box OAuth 2.0 access token expired and no refresh token with client credentials is available.");
        }
        body.set("grant_type", "refresh_token");
        body.set("refresh_token", this.refreshToken);
        body.set("client_id", this.config.clientId);
        body.set("client_secret", this.config.clientSecret);
        return body;
      }
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unhandled Box auth mode: ${String(exhaustive)}`);
      }
    }
  }

  private async fetchAccessToken(): Promise<string> {
    const payload = await this.requestJson(this.config.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: this.tokenRequestBody().toString(),
    }, { skipAuth: true });

    const accessToken = asString(payload.access_token);
    if (!accessToken) {
      throw new Error("Box token response did not include access_token.");
    }
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = this.now().getTime() + Math.max((expiresIn - 60) * 1000, 60_000);
    const nextRefreshToken = asString(payload.refresh_token);
    if (nextRefreshToken) this.refreshToken = nextRefreshToken;
    credentialScrubber.registerSecrets([accessToken, nextRefreshToken]);
    return accessToken;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && this.now().getTime() < this.accessTokenExpiresAt) {
      return this.accessToken;
    }
    if (!this.accessTokenPromise) {
      this.accessTokenPromise = this.fetchAccessToken();
    }
    try {
      return await this.accessTokenPromise;
    } finally {
      this.accessTokenPromise = undefined;
    }
  }

  private memoized<T>(key: string, loader: () => Promise<T>): Promise<T> {
    const existing = this.memo.get(key);
    if (existing) return existing as Promise<T>;
    const pending = loader();
    this.memo.set(key, pending);
    pending.catch(() => this.memo.delete(key));
    return pending;
  }

  async get(path: string, query: JsonRecord = {}, headers: Record<string, string> = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path, query);
    return this.memoized(`GET ${url} ${JSON.stringify(headers)}`, () => this.requestJson(url, { method: "GET", headers }));
  }

  async listMarker(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number; useMarkerFlag?: boolean; headers?: Record<string, string> } = {},
  ): Promise<BoxListPage> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 100_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 1000);
    const items: JsonRecord[] = [];
    let marker: string | undefined;
    let truncated = false;

    while (true) {
      const remaining = limit - items.length;
      const payload = await this.get(path, {
        ...query,
        limit: Math.min(pageSize, remaining),
        ...(options.useMarkerFlag ? { usemarker: "true" } : {}),
        marker,
      }, options.headers);
      const entries = asRecordArray(payload.entries);
      items.push(...entries.slice(0, remaining));
      const nextMarker = asString(payload.next_marker);
      if (entries.length === 0) {
        truncated = Boolean(nextMarker);
        break;
      }
      if (entries.length > remaining) {
        truncated = true;
        break;
      }
      if (!nextMarker) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
      marker = nextMarker;
    }

    return { items, truncated };
  }

  async listOffset(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<BoxListPage> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 10_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 1000);
    const items: JsonRecord[] = [];
    let offset = 0;
    let truncated = false;

    while (true) {
      const remaining = limit - items.length;
      const requested = Math.min(pageSize, remaining);
      const payload = await this.get(path, { ...query, limit: requested, offset });
      const entries = asRecordArray(payload.entries);
      items.push(...entries.slice(0, remaining));
      offset += entries.length;
      const totalCount = asNumber(payload.total_count);
      const moreAvailable = totalCount !== undefined ? offset < totalCount : entries.length >= requested;
      if (entries.length === 0) {
        truncated = moreAvailable && totalCount !== undefined;
        break;
      }
      if (!moreAvailable) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
    }

    return { items, truncated };
  }

  async getCurrentUser(): Promise<JsonRecord> {
    return this.get("/users/me", { fields: "id,type,name,login,role,status,enterprise,is_platform_access_only" });
  }

  async resolveEnterpriseId(): Promise<string> {
    if (this.config.enterpriseId) return this.config.enterpriseId;
    if (!this.enterpriseIdPromise) {
      this.enterpriseIdPromise = this.getCurrentUser().then((user) => {
        const enterpriseId = asString(asObject(user.enterprise)?.id);
        if (!enterpriseId) {
          throw new Error("Unable to determine the Box enterprise ID; set BOX_ENTERPRISE_ID explicitly.");
        }
        return enterpriseId;
      });
      this.enterpriseIdPromise.catch(() => {
        this.enterpriseIdPromise = undefined;
      });
    }
    return this.enterpriseIdPromise;
  }

  async getEnterpriseConfiguration(categories: string[] = ["security", "content_and_sharing", "user_settings", "shield"]): Promise<JsonRecord> {
    const enterpriseId = await this.resolveEnterpriseId();
    return this.get(
      `/enterprise_configurations/${encodeURIComponent(enterpriseId)}`,
      { categories: categories.join(",") },
      { "box-version": BOX_VERSION_HEADER },
    );
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/users", { fields: USER_FIELDS }, { limit, pageSize: DEFAULT_USER_PAGE_SIZE, useMarkerFlag: true });
  }

  async listGroups(limit = DEFAULT_GROUP_LIMIT): Promise<BoxListPage> {
    return this.listOffset("/groups", { fields: GROUP_FIELDS }, { limit, pageSize: 1000 });
  }

  async listEnterpriseEvents(options: { eventTypes?: string[]; createdAfter?: Date; limit?: number } = {}): Promise<BoxListPage> {
    const limit = clampNumber(options.limit, DEFAULT_EVENT_LIMIT, 1, 100_000);
    const key = `EVENTS ${JSON.stringify([options.eventTypes ?? [], options.createdAfter?.toISOString() ?? null, limit])}`;
    return this.memoized(key, async () => {
      const items: JsonRecord[] = [];
      let streamPosition: string | undefined;
      let truncated = false;
      while (true) {
        const remaining = limit - items.length;
        const payload = await this.requestJson(this.buildUrl("/events", {
          stream_type: "admin_logs",
          limit: Math.min(DEFAULT_EVENT_PAGE_SIZE, remaining),
          event_type: options.eventTypes && options.eventTypes.length > 0 ? options.eventTypes.join(",") : undefined,
          created_after: options.createdAfter?.toISOString(),
          stream_position: streamPosition,
        }), { method: "GET" });
        const entries = asRecordArray(payload.entries);
        items.push(...entries.slice(0, remaining));
        const nextPosition = asString(payload.next_stream_position);
        if (entries.length === 0) break;
        if (!nextPosition || nextPosition === streamPosition || entries.length > remaining || items.length >= limit) {
          truncated = true;
          break;
        }
        streamPosition = nextPosition;
      }
      return { items, truncated };
    });
  }

  async listDevicePinners(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    const enterpriseId = await this.resolveEnterpriseId();
    return this.listMarker(`/enterprises/${encodeURIComponent(enterpriseId)}/device_pinners`, {}, { limit });
  }

  async listRetentionPolicies(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/retention_policies", {
      fields: "id,type,policy_name,policy_type,retention_length,retention_type,disposition_action,status,assignment_counts,created_at,modified_at",
    }, { limit });
  }

  async listRetentionPolicyAssignments(policyId: string, limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker(`/retention_policies/${encodeURIComponent(policyId)}/assignments`, {}, { limit });
  }

  async listLegalHoldPolicies(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/legal_hold_policies", {
      fields: "id,type,policy_name,description,status,assignment_counts,created_at,modified_at",
    }, { limit });
  }

  async listLegalHoldPolicyAssignments(policyId: string, limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/legal_hold_policy_assignments", { policy_id: policyId }, { limit });
  }

  async listShieldInformationBarriers(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/shield_information_barriers", {}, { limit });
  }

  async listShieldInformationBarrierSegments(barrierId: string, limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/shield_information_barrier_segments", { shield_information_barrier_id: barrierId }, { limit });
  }

  async listShieldLists(): Promise<BoxListPage> {
    const payload = await this.get("/shield_lists", {}, { "box-version": BOX_VERSION_HEADER });
    return completePage(asRecordArray(payload.entries));
  }

  async listCollaborationAllowlistEntries(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/collaboration_whitelist_entries", {}, { limit });
  }

  async listCollaborationAllowlistExemptTargets(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/collaboration_whitelist_exempt_targets", {}, { limit });
  }

  async listEnterpriseMetadataTemplates(limit = DEFAULT_LIST_LIMIT): Promise<BoxListPage> {
    return this.listMarker("/metadata_templates/enterprise", {}, { limit });
  }

  async getClassificationTemplate(): Promise<JsonRecord> {
    return this.get(`/metadata_templates/enterprise/${CLASSIFICATION_TEMPLATE_KEY}/schema`);
  }

  async listTermsOfServices(): Promise<BoxListPage> {
    const payload = await this.get("/terms_of_services");
    return completePage(asRecordArray(payload.entries));
  }
}

async function collect<T>(loader: () => Promise<T>, fallback: T): Promise<CollectedDataset<T>> {
  try {
    return { data: await loader() };
  } catch (error) {
    return {
      data: fallback,
      error: errorMessage(error),
      statusCode: error instanceof BoxApiError ? error.status : undefined,
      request: requestOf(error),
    };
  }
}

async function collectList(loader: () => Promise<BoxListPage>): Promise<CollectedDataset<JsonRecord[]>> {
  const collected = await collect(loader, completePage([]));
  return {
    data: collected.data.items,
    error: collected.error,
    statusCode: collected.statusCode,
    request: collected.request,
    truncated: collected.error ? undefined : collected.data.truncated,
  };
}

/** True when the read completed; a dataset that was denied, errored, or timed out proves nothing about its inventory. */
function isRead(dataset: CollectedDataset<unknown>): boolean {
  return dataset.error === undefined;
}

/** True when the read completed without stopping at a cap, so counts and names derived from it are complete. */
function isComplete(dataset: CollectedDataset<unknown>): boolean {
  return isRead(dataset) && dataset.truncated !== true;
}

/** A value derived from a dataset renders only when the dataset was read at all. */
function whenRead<T>(dataset: CollectedDataset<unknown>, value: T): T | null {
  return isRead(dataset) ? value : null;
}

/** A value joined across several datasets renders only when every one of them was read. */
function whenAllRead<T>(datasets: Array<CollectedDataset<unknown>>, value: T): T | null {
  return datasets.every(isRead) ? value : null;
}

/**
 * A list of records observed to hold a property: the records found are real observations and always render, while an
 * empty list renders `[]` only when every dataset that could have revealed one was read completely, and null otherwise.
 */
function observedList<T>(sources: Array<CollectedDataset<unknown>>, items: T[]): T[] | null {
  return items.length > 0 || sources.every(isComplete) ? items : null;
}

/** The count of records observed to hold a property, with the same rule as observedList: zero is asserted only from complete reads. */
function observedCount(sources: Array<CollectedDataset<unknown>>, count: number): number | null {
  return count > 0 || sources.every(isComplete) ? count : null;
}

function isNotCollectedMarker(value: unknown): value is BoxNotCollectedMarker {
  return asObject(value)?.collected === false;
}

/**
 * The marker written for a dataset whose read did not complete, or that was never requested. A child map none of
 * whose reads completed carries every child's own marker under failed_reads, so the per-parent status and request
 * survive alongside the first failure the top-level fields name.
 */
function notReadableMarker(dataset: CollectedDataset<unknown>): BoxNotCollectedMarker {
  if (dataset.notRequested) return notRequestedMarker();
  const failedReads = Object.entries(asObject(dataset.data) ?? {}).filter((entry): entry is [string, BoxNotCollectedMarker] => isNotCollectedMarker(entry[1]));
  return {
    collected: false,
    status: dataset.statusCode ?? "error",
    endpoint: dataset.request ?? null,
    error: dataset.error ?? null,
    reason: "not_readable",
    ...(failedReads.length > 0 ? { failed_reads: Object.fromEntries(failedReads) } : {}),
  };
}

/** The marker written for a dataset that was never requested. */
function notRequestedMarker(): BoxNotCollectedMarker {
  return { collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested" };
}

/** The child list read for one parent id, or undefined when that read was denied or never made. */
function childList(map: BoxAssignmentMap, parentId: string | undefined): JsonRecord[] | undefined {
  const entry = parentId === undefined ? undefined : map[parentId];
  return Array.isArray(entry) ? entry : undefined;
}

function datasetErrors(label: string, dataset: CollectedDataset<unknown>): string[] {
  return dataset.error ? [`${label}: ${dataset.error}`] : [];
}

/** Records loaded by a read: array length, the summed length of the child lists that were read, or 1 for a record. */
function datasetRecordCount(data: unknown): number | null {
  if (Array.isArray(data)) return data.length;
  const record = asObject(data);
  if (!record) return null;
  const values = Object.values(record);
  if (values.length > 0 && values.every((value) => Array.isArray(value) || isNotCollectedMarker(value))) {
    return values.reduce<number>((total, items) => total + (Array.isArray(items) ? items.length : 0), 0);
  }
  return values.length > 0 ? 1 : 0;
}

function datasetTruncations(label: string, dataset: CollectedDataset<unknown>, limitOption?: string): string[] {
  if (!dataset.truncated) return [];
  const remedy = limitOption ? `raise ${limitOption} and rerun` : `the built-in ${DEFAULT_LIST_LIMIT}-record cap was reached, so review the remainder in the Admin Console`;
  return [`${label}: collection stopped at the ${datasetRecordCount(dataset.data) ?? 0}-record cap while the server reported more records; ${remedy} before treating absence as compliance`];
}

function finding(
  controlNumber: number,
  status: BoxFindingStatus,
  summary: string,
  evidence?: JsonRecord,
  manualEvidence?: string,
): BoxFinding {
  const definition = BOX_CONTROLS[controlNumber];
  return {
    id: findingId(controlNumber),
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: mappingsForControl(controlNumber),
    manualEvidence,
  };
}

interface ConfigSetting {
  value: unknown;
  isUsed: boolean | undefined;
}

type ConfigSettings = Record<string, ConfigSetting | undefined>;

function configCategory(configuration: JsonRecord | undefined, category: string): JsonRecord | undefined {
  return asObject(configuration?.[category]);
}

function configSetting(configuration: JsonRecord | undefined, category: string, key: string): ConfigSetting | undefined {
  const item = asObject(configCategory(configuration, category)?.[key]);
  if (!item) return undefined;
  return { value: item.value, isUsed: asBoolean(item.is_used) };
}

function configSettings(configuration: JsonRecord | undefined, category: string, keys: string[]): ConfigSettings {
  return Object.fromEntries(keys.map((key) => [key, configSetting(configuration, category, key)]));
}

function configValue(configuration: JsonRecord | undefined, category: string, key: string): unknown {
  const setting = configSetting(configuration, category, key);
  return setting?.isUsed === false ? undefined : setting?.value;
}

function isUsedStates(settings: ConfigSettings): Record<string, boolean | null> {
  return Object.fromEntries(Object.entries(settings).map(([key, setting]) => [key, setting?.isUsed ?? null]));
}

function unusedSettings(settings: ConfigSettings, keys: string[] = Object.keys(settings)): JsonRecord {
  const unused: JsonRecord = {};
  for (const key of keys) {
    const setting = settings[key];
    if (setting?.isUsed === false) unused[key] = setting.value ?? null;
  }
  return unused;
}

function hasUnusedSettings(unused: JsonRecord): boolean {
  return Object.keys(unused).length > 0;
}

/**
 * The is_used states and unused settings a finding records for a configuration category; both render null when the
 * category could not be read so a denied configuration never looks like one with every setting in use.
 */
function settingsEvidence(readable: boolean, settings: ConfigSettings, unused: JsonRecord): { is_used: Record<string, boolean | null> | null; unused_settings: JsonRecord | null } {
  return { is_used: readable ? isUsedStates(settings) : null, unused_settings: readable ? unused : null };
}

/** "N" for a dataset that was read, "unread" for one that was not, so a sentence never states a zero from a denied read. */
function countOrUnread(dataset: CollectedDataset<unknown>, count: number): string {
  return isRead(dataset) ? String(count) : "unread";
}

function unusedSettingsSummary(unused: JsonRecord, consequence: string): string {
  const described = Object.entries(unused)
    .map(([key, value]) => `${key} (reported value ${JSON.stringify(value)})`)
    .join(", ");
  return `Box reports ${described} as not in use for this enterprise (is_used false), so ${consequence}.`;
}

function configBool(configuration: JsonRecord | undefined, category: string, key: string): boolean | undefined {
  return asBoolean(configValue(configuration, category, key));
}

function configString(configuration: JsonRecord | undefined, category: string, key: string): string | undefined {
  return asString(configValue(configuration, category, key));
}

function configNumber(configuration: JsonRecord | undefined, category: string, key: string): number | undefined {
  return asNumber(configValue(configuration, category, key));
}

function categoryReadable(dataset: CollectedDataset<JsonRecord>, category: string): boolean {
  return !dataset.error && configCategory(dataset.data, category) !== undefined;
}

function categoryUnreadableReason(dataset: CollectedDataset<JsonRecord>, category: string): string {
  if (dataset.error) return unreadableReason(dataset);
  if (dataset.data[category] === null) {
    return `the ${category} category was returned as null, so Box did not expose these settings for this enterprise`;
  }
  return `the ${category} category was missing from the enterprise configuration response`;
}

function unreadableReason(dataset: CollectedDataset<unknown>): string {
  if (!dataset.error) return "the response did not include the expected data";
  if (dataset.statusCode === 403) return "the audit principal lacks the scope or admin role to read it";
  if (dataset.statusCode === 404) return "the endpoint reported the resource as not found for this enterprise";
  return dataset.error;
}

function userRole(user: JsonRecord): string {
  return (asString(user.role) ?? "user").toLowerCase();
}

function userLabel(user: JsonRecord): string {
  return asString(user.login) ?? asString(user.name) ?? asString(user.id) ?? "user";
}

function isAdminUser(user: JsonRecord): boolean {
  return userRole(user) === "admin";
}

function isCoAdminUser(user: JsonRecord): boolean {
  return userRole(user) === "coadmin";
}

function isPrivilegedUser(user: JsonRecord): boolean {
  return isAdminUser(user) || isCoAdminUser(user);
}

function isActiveHumanUser(user: JsonRecord): boolean {
  const status = (asString(user.status) ?? "active").toLowerCase();
  return status === "active" && asBoolean(user.is_platform_access_only) !== true;
}

function isExemptFromLoginVerification(user: JsonRecord): boolean {
  return asBoolean(user.is_exempt_from_login_verification) === true;
}

function userInventoryGap(users: JsonRecord[], truncated: boolean): string | undefined {
  if (users.length === 0) {
    return "the user list was readable but returned zero managed users; a Box enterprise always has at least the primary admin, so the inventory is empty and nothing was assessed";
  }
  if (truncated) {
    return `the user list stopped at the ${users.length}-record cap while Box reported more users (a next_marker remained), so the inventory is partial and the absence of a matching record proves nothing; raise user_limit and rerun`;
  }
  if (!users.some(isAdminUser)) {
    return `the ${users.length}-user inventory contains no admin account; a Box enterprise always has a primary admin, so the listing is incomplete or the audit principal cannot see admin accounts`;
  }
  return undefined;
}

function eventActorId(event: JsonRecord): string | undefined {
  return asString(asObject(event.created_by)?.id);
}

function eventType(event: JsonRecord): string {
  return asString(event.event_type) ?? "";
}

function countEventTypes(events: JsonRecord[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    const type = eventType(event) || "UNKNOWN";
    counts[type] = (counts[type] ?? 0) + 1;
  }
  return counts;
}

export function isUnitlessDuration(value: string | undefined): boolean {
  return value !== undefined && /^\d+(?:\.\d+)?$/.test(value.trim());
}

export function parseDurationHours(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const text = value.trim().toLowerCase();
  if (!text) return undefined;
  if (/^(never|none|unlimited|no_expiration|no expiration)$/.test(text)) return Number.POSITIVE_INFINITY;
  const match = text.match(/(\d+(?:\.\d+)?)\s*(minute|min|hour|hr|day|week|month|year|d|h|m|w)s?/);
  if (!match) return undefined;
  const amount = Number(match[1]);
  switch (match[2]) {
    case "minute":
    case "min":
    case "m":
      return amount / 60;
    case "hour":
    case "hr":
    case "h":
      return amount;
    case "day":
    case "d":
      return amount * 24;
    case "week":
    case "w":
      return amount * 24 * 7;
    case "month":
      return amount * 24 * 30;
    case "year":
      return amount * 24 * 365;
    default:
      return undefined;
  }
}

function describeUninterpretableDuration(value: string | undefined): string {
  return isUnitlessDuration(value)
    ? "has no explicit unit and Box does not document one for this field"
    : "could not be interpreted as a duration";
}

function accessLevelIsOpen(value: string | undefined): boolean {
  if (!value) return false;
  return /open|public|anyone/i.test(value);
}

function accessLevelIsRestricted(value: string | undefined): boolean {
  if (!value) return false;
  return /company|collaborators|enterprise|people_in|invited/i.test(value);
}

function isPublicEmailDomain(domain: string): boolean {
  return PUBLIC_EMAIL_DOMAINS.has(domain.toLowerCase());
}

function shieldListContentType(list: JsonRecord): string | undefined {
  return asString(asObject(list.content)?.type);
}

export interface BoxIdentityData {
  enterpriseId?: string;
  currentUser: CollectedDataset<JsonRecord>;
  configuration: CollectedDataset<JsonRecord>;
  users: CollectedDataset<JsonRecord[]>;
  events: CollectedDataset<JsonRecord[]>;
  shieldLists: CollectedDataset<JsonRecord[]>;
  lookbackDays: number;
  eventLimit: number;
  now: Date;
}

export interface BoxSharingData {
  enterpriseId?: string;
  configuration: CollectedDataset<JsonRecord>;
  allowlistEntries: CollectedDataset<JsonRecord[]>;
  exemptTargets: CollectedDataset<JsonRecord[]>;
  termsOfServices: CollectedDataset<JsonRecord[]>;
  shieldLists: CollectedDataset<JsonRecord[]>;
  events: CollectedDataset<JsonRecord[]>;
  lookbackDays: number;
  now: Date;
}

export interface BoxGovernanceData {
  enterpriseId?: string;
  devicePinners: CollectedDataset<JsonRecord[]>;
  classificationTemplate: CollectedDataset<JsonRecord>;
  metadataTemplates: CollectedDataset<JsonRecord[]>;
  retentionPolicies: CollectedDataset<JsonRecord[]>;
  retentionAssignments: CollectedDataset<BoxAssignmentMap>;
  legalHoldPolicies: CollectedDataset<JsonRecord[]>;
  legalHoldAssignments: CollectedDataset<BoxAssignmentMap>;
  configuration: CollectedDataset<JsonRecord>;
}

export interface BoxShieldData {
  enterpriseId?: string;
  configuration: CollectedDataset<JsonRecord>;
  barriers: CollectedDataset<JsonRecord[]>;
  barrierSegments: CollectedDataset<BoxAssignmentMap>;
  shieldLists: CollectedDataset<JsonRecord[]>;
  events: CollectedDataset<JsonRecord[]>;
  lookbackDays: number;
  eventLimit: number;
  now: Date;
}

function lookbackStart(now: Date, lookbackDays: number): Date {
  return new Date(now.getTime() - lookbackDays * 86_400_000);
}

async function safeEnterpriseId(client: Pick<BoxReadClient, "resolveEnterpriseId">): Promise<string | undefined> {
  try {
    return await client.resolveEnterpriseId();
  } catch {
    return undefined;
  }
}

export async function collectBoxIdentityData(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getCurrentUser" | "getEnterpriseConfiguration" | "listUsers" | "listEnterpriseEvents" | "listShieldLists">,
  options: BoxIdentityOptions = {},
): Promise<BoxIdentityData> {
  const now = client.getNow();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const eventLimit = clampNumber(options.eventLimit, DEFAULT_EVENT_LIMIT, 1, 100_000);
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 100_000);
  const [enterpriseId, currentUser, configuration, users, events, shieldLists] = await Promise.all([
    safeEnterpriseId(client),
    collect(() => client.getCurrentUser(), {}),
    collect(() => client.getEnterpriseConfiguration(["security", "user_settings"]), {}),
    collectList(() => client.listUsers(userLimit)),
    collectList(() => client.listEnterpriseEvents({
      eventTypes: IDENTITY_EVENT_TYPES,
      createdAfter: lookbackStart(now, lookbackDays),
      limit: eventLimit,
    })),
    collectList(() => client.listShieldLists()),
  ]);
  return { enterpriseId, currentUser, configuration, users, events, shieldLists, lookbackDays, eventLimit, now };
}

export function assessBoxIdentityAccessData(data: BoxIdentityData, options: BoxIdentityOptions = {}): BoxAssessmentResult {
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10_000);
  const minPasswordLength = clampNumber(options.minPasswordLength, DEFAULT_MIN_PASSWORD_LENGTH, 4, 128);
  const maxSessionHours = clampNumber(options.maxSessionHours, DEFAULT_MAX_SESSION_HOURS, 1, 24 * 365);
  const configuration = data.configuration.error ? undefined : data.configuration.data;
  const userSettingsReadable = categoryReadable(data.configuration, "user_settings");
  const securityReadable = categoryReadable(data.configuration, "security");
  const usersReadable = !data.users.error;
  const users = data.users.data;
  const events = data.events.data;

  const ssoRequired = configBool(configuration, "user_settings", "is_enterprise_sso_required");
  const ssoTesting = configBool(configuration, "user_settings", "is_enterprise_sso_in_testing");
  const mfaRequired = configBool(configuration, "security", "is_multi_factor_auth_required");
  const mfaType = configString(configuration, "security", "multi_factor_auth_type");
  const admins = users.filter(isAdminUser);
  const coAdmins = users.filter(isCoAdminUser);
  const privileged = users.filter(isPrivilegedUser);
  const exemptPrivileged = privileged.filter(isExemptFromLoginVerification);
  const exemptUsers = users.filter((user) => !isPrivilegedUser(user) && isExemptFromLoginVerification(user));
  const activeUsers = users.filter(isActiveHumanUser);
  const usersTruncated = data.users.truncated === true;
  const inventoryGap = usersReadable ? userInventoryGap(users, usersTruncated) : undefined;
  // Every count and name below is gated on the dataset that proves it: a denied user listing renders null, never 0 or
  // [], and a user is named as holding a property only from a record that was actually read.
  const inventoryEvidence = {
    sampled_users: whenRead(data.users, users.length),
    admin_users: whenRead(data.users, admins.length),
    users_truncated: whenRead(data.users, usersTruncated),
    inventory_gap: inventoryGap ?? null,
  };
  const inventoryManualEvidence = "Admin Console > Users & Groups: export the full managed user list (including the primary admin) and confirm the count matches the API inventory before relying on user-level findings.";

  const findings: BoxFinding[] = [];

  const ssoSettings = configSettings(configuration, "user_settings", ["is_enterprise_sso_required", "is_enterprise_sso_in_testing"]);
  const ssoUnused = unusedSettings(ssoSettings, ["is_enterprise_sso_required"]);
  const ssoEvidence = {
    is_enterprise_sso_required: ssoRequired ?? null,
    is_enterprise_sso_in_testing: ssoTesting ?? null,
    ...settingsEvidence(userSettingsReadable, ssoSettings, ssoUnused),
  };
  const ssoManualEvidence = "Admin Console > Enterprise Settings > User Settings > Configure Single Sign On (SSO): confirm SSO is set to Required, not Enabled (optional) or Test mode, and record the identity provider.";
  findings.push(
    !userSettingsReadable
      ? finding(1, "manual", `Enterprise SSO configuration could not be read because ${categoryUnreadableReason(data.configuration, "user_settings")}.`, { ...ssoEvidence, config_error: data.configuration.error ?? null }, ssoManualEvidence)
      : hasUnusedSettings(ssoUnused)
        ? finding(1, "warn", unusedSettingsSummary(ssoUnused, "SSO cannot be treated as enforced"), ssoEvidence, ssoManualEvidence)
        : ssoRequired === true && ssoTesting !== true
        ? finding(1, "pass", "Enterprise settings expose SSO as required for all users and not in testing mode.", ssoEvidence)
        : ssoRequired === true
          ? finding(1, "warn", "SSO is marked required but the enterprise is still in SSO testing mode, so users can bypass the identity provider.", ssoEvidence)
          : ssoRequired === false
            ? finding(1, "fail", "Enterprise settings report SSO as not required, so Box passwords remain a valid sign-in path.", ssoEvidence)
            : finding(1, "warn", "Enterprise user settings were readable but did not expose is_enterprise_sso_required, so SSO enforcement cannot be confirmed from the API.", ssoEvidence, ssoManualEvidence),
  );

  const mfaSettings = configSettings(configuration, "security", ["is_multi_factor_auth_required", "multi_factor_auth_type"]);
  const mfaUnused = unusedSettings(mfaSettings, ["is_multi_factor_auth_required"]);
  const mfaState = hasUnusedSettings(mfaUnused)
    ? "reported but not in use (is_used false)"
    : mfaRequired === true
      ? `required${mfaType ? ` (${mfaType})` : ""}`
      : mfaRequired === false ? "not required" : "not exposed";
  const adminMfaEvidence = {
    is_multi_factor_auth_required: mfaRequired ?? null,
    multi_factor_auth_type: mfaType ?? null,
    is_enterprise_sso_required: ssoRequired ?? null,
    ...settingsEvidence(securityReadable, mfaSettings, mfaUnused),
    privileged_users: whenRead(data.users, privileged.length),
    exempt_privileged_users: observedList([data.users], truncateList(exemptPrivileged.map(userLabel))),
    ...inventoryEvidence,
  };
  const adminMfaManualEvidence = "Admin Console > Enterprise Settings > Security > 2-Step Verification: confirm 2-step verification is required for all managed users, and open each admin and co-admin user record to confirm the 'Exempt from 2-step verification' option is not set.";
  findings.push(
    !securityReadable && !usersReadable
      ? adminMfaUnreadableFinding(data)
      : !usersReadable
        ? finding(2, "manual", `Enterprise users could not be listed because ${unreadableReason(data.users)}, so admin and co-admin exemptions from login verification cannot be verified; enterprise MFA is ${mfaState}.`, { ...adminMfaEvidence, users_error: data.users.error ?? null }, adminMfaManualEvidence)
        : !securityReadable
          ? finding(2, "manual", `Enterprise MFA settings could not be read because ${categoryUnreadableReason(data.configuration, "security")}; ${exemptPrivileged.length}/${privileged.length} admin or co-admin accounts are flagged exempt from login verification.`, adminMfaEvidence, adminMfaManualEvidence)
          : hasUnusedSettings(mfaUnused)
            ? finding(2, "warn", unusedSettingsSummary(mfaUnused, `enterprise MFA cannot be treated as enforced for the ${privileged.length} admin or co-admin accounts (${exemptPrivileged.length} flagged exempt from login verification)`), adminMfaEvidence, adminMfaManualEvidence)
            : mfaRequired === true
            ? exemptPrivileged.length > 0
              ? finding(2, "fail", `${exemptPrivileged.length}/${privileged.length} admin or co-admin accounts are exempt from login verification even though enterprise MFA is required.`, adminMfaEvidence)
              : inventoryGap
                ? finding(2, "warn", `Multi-factor authentication is required for managed users${mfaType ? ` (${mfaType})` : ""}, but admin exemptions could not be assessed because ${inventoryGap}.`, adminMfaEvidence, inventoryManualEvidence)
                : finding(2, "pass", `Multi-factor authentication is required for managed users${mfaType ? ` (${mfaType})` : ""} and none of the ${privileged.length} admin or co-admin accounts are exempt from login verification.`, adminMfaEvidence)
            : mfaRequired === undefined
              ? finding(2, "warn", `Enterprise security settings were readable but did not expose is_multi_factor_auth_required, so admin MFA enforcement cannot be confirmed from the API; ${exemptPrivileged.length}/${privileged.length} admin or co-admin accounts are flagged exempt from login verification.`, adminMfaEvidence, adminMfaManualEvidence)
              : ssoRequired === true
                ? finding(2, "warn", "Box-native MFA is not required; admin MFA depends entirely on the identity provider enforced through required SSO.", adminMfaEvidence, "Confirm the SSO identity provider enforces phishing-resistant MFA for every Box admin and co-admin.")
                : finding(2, "fail", `Multi-factor authentication is not required for managed users, leaving ${privileged.length} admin or co-admin accounts without an enforced second factor.`, adminMfaEvidence),
  );

  const userMfaEvidence = {
    is_multi_factor_auth_required: mfaRequired ?? null,
    multi_factor_auth_type: mfaType ?? null,
    is_enterprise_sso_required: ssoRequired ?? null,
    ...settingsEvidence(securityReadable, mfaSettings, mfaUnused),
    exempt_users: observedList([data.users], truncateList(exemptUsers.map(userLabel))),
    ...inventoryEvidence,
  };
  const userMfaManualEvidence = "Admin Console > Enterprise Settings > Security > 2-Step Verification: confirm 2-step verification is required for all users, including external collaborators.";
  findings.push(
    !securityReadable && !usersReadable
      ? finding(3, "manual", `Neither enterprise MFA settings (${categoryUnreadableReason(data.configuration, "security")}) nor enterprise users (${unreadableReason(data.users)}) could be read.`, { ...userMfaEvidence, users_error: data.users.error ?? null }, userMfaManualEvidence)
      : !usersReadable
        ? finding(3, "manual", `Enterprise users could not be listed because ${unreadableReason(data.users)}, so per-user exemptions from login verification cannot be verified; enterprise MFA is ${mfaState}.`, { ...userMfaEvidence, users_error: data.users.error ?? null }, userMfaManualEvidence)
        : !securityReadable
          ? finding(3, "manual", `Enterprise MFA settings could not be read because ${categoryUnreadableReason(data.configuration, "security")}.`, userMfaEvidence, userMfaManualEvidence)
          : hasUnusedSettings(mfaUnused)
            ? finding(3, "warn", unusedSettingsSummary(mfaUnused, `enterprise MFA cannot be treated as enforced for the sampled ${users.length} users (${exemptUsers.length} flagged exempt from login verification)`), userMfaEvidence, userMfaManualEvidence)
            : mfaRequired === true
            ? exemptUsers.length > 0
              ? finding(3, "warn", `Multi-factor authentication is required enterprise-wide, but ${exemptUsers.length}/${users.length} sampled users are exempt from login verification.`, userMfaEvidence)
              : inventoryGap
                ? finding(3, "warn", `Multi-factor authentication is required for all managed users${mfaType ? ` (${mfaType})` : ""}, but per-user exemptions could not be assessed because ${inventoryGap}.`, userMfaEvidence, inventoryManualEvidence)
                : finding(3, "pass", `Multi-factor authentication is required for all managed users${mfaType ? ` (${mfaType})` : ""} with no exempt accounts in the sampled ${users.length} users.`, userMfaEvidence)
            : mfaRequired === undefined
              ? finding(3, "warn", "Enterprise security settings were readable but did not expose is_multi_factor_auth_required, so MFA enforcement cannot be confirmed from the API.", userMfaEvidence, userMfaManualEvidence)
              : ssoRequired === true
                ? finding(3, "warn", "Box-native MFA is not required for all users; MFA coverage depends on the identity provider enforced through required SSO.", userMfaEvidence, "Confirm the SSO identity provider enforces MFA for every Box user population, including service and app users that sign in with passwords.")
                : finding(3, "fail", `Multi-factor authentication is not required enterprise-wide and ${ssoRequired === false ? "SSO is not required, so password-only sign-in is possible" : "SSO enforcement could not be read, so password-only sign-in may be possible"}.`, userMfaEvidence),
  );

  const adminRoleChanges = events.filter((event) => eventType(event) === "CHANGE_ADMIN_ROLE");
  const adminCountEvidence = {
    admins: observedList([data.users], truncateList(admins.map(userLabel))),
    coadmins: observedList([data.users], truncateList(coAdmins.map(userLabel))),
    max_admins: maxAdmins,
    admin_role_change_events: observedCount([data.events], adminRoleChanges.length),
    ...inventoryEvidence,
  };
  findings.push(
    !usersReadable
      ? finding(17, "manual", `Enterprise users could not be listed because ${unreadableReason(data.users)}.`, { users_error: data.users.error ?? null }, "Admin Console > Users & Groups: filter by Admin and Co-Admin roles, export the list, and confirm each assignment is justified.")
      : privileged.length > maxAdmins
        ? finding(17, "warn", `${privileged.length} admin or co-admin accounts exceed the configured threshold of ${maxAdmins}.`, adminCountEvidence)
        : inventoryGap
          ? finding(17, "warn", `Admin and co-admin counts could not be assessed because ${inventoryGap}.`, adminCountEvidence, inventoryManualEvidence)
          : finding(17, "pass", `${admins.length} admin and ${coAdmins.length} co-admin accounts fall within the configured threshold of ${maxAdmins}.`, adminCountEvidence),
  );

  findings.push(
    !usersReadable
      ? finding(18, "manual", `Enterprise users could not be listed because ${unreadableReason(data.users)}.`, undefined, "Admin Console > Users & Groups: open each co-admin and review the co-admin permission set under Edit User Access Permissions.")
      : coAdmins.length > 0
        ? finding(18, "manual", `${coAdmins.length} co-admin accounts exist; the Box API does not expose individual co-admin permission sets, so scoping must be confirmed in the Admin Console.`, { coadmins: truncateList(coAdmins.map(userLabel)), ...inventoryEvidence }, "Admin Console > Users & Groups > (each co-admin) > Edit User Access Permissions: confirm each co-admin has only the permission categories they need (for example Users and Groups, Reports, Content) and no co-admin holds the full set equivalent to a primary admin.")
        : inventoryGap
          ? finding(18, "warn", `Co-admin permission scoping could not be assessed because ${inventoryGap}.`, { coadmins: observedCount([data.users], 0), ...inventoryEvidence }, inventoryManualEvidence)
          : finding(18, "pass", "No co-admin accounts exist, so there are no delegated permission sets to scope.", { coadmins: 0, ...inventoryEvidence }),
  );

  const passwordMinLength = configNumber(configuration, "security", "password_min_length");
  const passwordUppercase = configNumber(configuration, "security", "password_min_uppercase_characters");
  const passwordNumeric = configNumber(configuration, "security", "password_min_numeric_characters");
  const passwordSpecial = configNumber(configuration, "security", "password_min_special_characters");
  const weakPasswordPrevention = configBool(configuration, "security", "is_weak_password_prevention_enabled");
  const passwordLeakDetection = configBool(configuration, "security", "is_password_leak_detection_enabled");
  const passwordResetFrequency = configString(configuration, "security", "password_reset_frequency");
  const passwordReuseLimit = configString(configuration, "security", "previous_password_reuse_limit");
  const passwordSettings = configSettings(configuration, "security", [
    "password_min_length",
    "password_min_uppercase_characters",
    "password_min_numeric_characters",
    "password_min_special_characters",
    "is_weak_password_prevention_enabled",
    "is_password_leak_detection_enabled",
    "password_reset_frequency",
    "previous_password_reuse_limit",
  ]);
  const passwordUnused = unusedSettings(passwordSettings, ["password_min_length"]);
  const passwordEvidence = {
    password_min_length: passwordMinLength ?? null,
    password_min_uppercase_characters: passwordUppercase ?? null,
    password_min_numeric_characters: passwordNumeric ?? null,
    password_min_special_characters: passwordSpecial ?? null,
    is_weak_password_prevention_enabled: weakPasswordPrevention ?? null,
    is_password_leak_detection_enabled: passwordLeakDetection ?? null,
    password_reset_frequency: passwordResetFrequency ?? null,
    previous_password_reuse_limit: passwordReuseLimit ?? null,
    ...settingsEvidence(securityReadable, passwordSettings, unusedSettings(passwordSettings)),
    required_min_length: minPasswordLength,
  };
  const passwordManualEvidence = "Admin Console > Enterprise Settings > Security > Password Requirements: record minimum length, character class rules, weak password prevention, reset frequency, and reuse limits.";
  const complexityCount = [passwordUppercase, passwordNumeric, passwordSpecial].filter((value) => (value ?? 0) > 0).length;
  findings.push(
    !securityReadable
      ? finding(21, "manual", `Enterprise password settings could not be read because ${categoryUnreadableReason(data.configuration, "security")}.`, undefined, passwordManualEvidence)
      : hasUnusedSettings(passwordUnused)
        ? finding(21, "warn", unusedSettingsSummary(passwordUnused, "the enterprise password policy cannot be treated as enforced"), passwordEvidence, passwordManualEvidence)
        : passwordMinLength === undefined
          ? finding(21, "warn", "Enterprise password settings were readable but did not expose a minimum password length.", passwordEvidence, passwordManualEvidence)
        : passwordMinLength >= minPasswordLength && weakPasswordPrevention === true && complexityCount >= 2
          ? finding(21, "pass", `Passwords require at least ${passwordMinLength} characters with ${complexityCount} character-class rules and weak password prevention enabled.`, passwordEvidence)
          : passwordMinLength >= 8
            ? finding(21, "warn", `Passwords require ${passwordMinLength} characters, below the ${minPasswordLength}-character target or missing complexity or weak password prevention controls.`, passwordEvidence)
            : finding(21, "fail", `Passwords require only ${passwordMinLength} characters, below the 8-character minimum baseline.`, passwordEvidence),
  );

  const sessionDuration = configString(configuration, "security", "session_duration");
  const sessionHours = parseDurationHours(sessionDuration);
  const customSessionEnabled = configBool(configuration, "security", "is_custom_session_duration_enabled");
  const customSessionValue = configString(configuration, "security", "custom_session_duration_value");
  const customSessionHours = parseDurationHours(customSessionValue);
  const sessionSettings = configSettings(configuration, "security", ["session_duration", "is_custom_session_duration_enabled", "custom_session_duration_value"]);
  const sessionUnused = unusedSettings(sessionSettings, ["session_duration"]);
  const sessionEvidence = {
    session_duration: sessionDuration ?? null,
    session_hours: sessionHours === undefined || !Number.isFinite(sessionHours) ? null : sessionHours,
    is_custom_session_duration_enabled: customSessionEnabled ?? null,
    custom_session_duration_value: customSessionValue ?? null,
    ...settingsEvidence(securityReadable, sessionSettings, unusedSettings(sessionSettings)),
    max_session_hours: maxSessionHours,
  };
  const sessionManualEvidence = "Admin Console > Enterprise Settings > Security > Session Duration: record the inactivity timeout and any custom group durations.";
  findings.push(
    !securityReadable
      ? finding(22, "manual", `Enterprise session settings could not be read because ${categoryUnreadableReason(data.configuration, "security")}.`, undefined, sessionManualEvidence)
      : hasUnusedSettings(sessionUnused)
        ? finding(22, "warn", unusedSettingsSummary(sessionUnused, "the session duration cannot be treated as enforced"), sessionEvidence, sessionManualEvidence)
        : sessionDuration === undefined
          ? finding(22, "warn", "Enterprise session settings were readable but did not expose a session duration value.", sessionEvidence, sessionManualEvidence)
          : sessionHours === undefined
            ? finding(22, "warn", `Session duration "${sessionDuration}" ${describeUninterpretableDuration(sessionDuration)}, so it cannot be compared against the ${maxSessionHours}-hour threshold.`, sessionEvidence, `${sessionManualEvidence} Confirm the unit behind the raw value "${sessionDuration}" and whether it is at or below ${maxSessionHours} hours.`)
            : sessionHours > maxSessionHours
              ? finding(22, "fail", `Session duration ${sessionDuration} exceeds the ${maxSessionHours}-hour threshold.`, sessionEvidence)
              : customSessionEnabled !== true
                ? finding(22, "pass", `Session duration is ${sessionDuration}, within the ${maxSessionHours}-hour threshold.`, sessionEvidence)
                : customSessionHours === undefined
                  ? finding(22, "warn", `Session duration is ${sessionDuration}, but the custom group duration "${customSessionValue ?? "unset"}" ${describeUninterpretableDuration(customSessionValue)}, so it cannot be compared against the ${maxSessionHours}-hour threshold.`, sessionEvidence, sessionManualEvidence)
                  : customSessionHours <= maxSessionHours
                    ? finding(22, "pass", `Session duration is ${sessionDuration} and the custom group duration is ${customSessionValue}, both within the ${maxSessionHours}-hour threshold.`, sessionEvidence)
                    : finding(22, "fail", `Session duration ${sessionDuration} is within the threshold, but the custom group duration ${customSessionValue} exceeds ${maxSessionHours} hours.`, sessionEvidence),
  );

  const ipLists = data.shieldLists.data.filter((list) => shieldListContentType(list) === "ip");
  findings.push(
    finding(
      23,
      "manual",
      ipLists.length > 0
        ? `${ipLists.length} Shield IP lists exist, but the Box API does not expose whether IP restrictions are enforced for enterprise sign-in or access policies.`
        : data.shieldLists.error
          ? `Shield lists could not be read (${unreadableReason(data.shieldLists)}) and the Box API does not expose enterprise IP allowlisting settings.`
          : "No Shield IP lists exist and the Box API does not expose enterprise IP allowlisting settings.",
      { shield_ip_lists: whenRead(data.shieldLists, truncateList(ipLists.map((list) => asString(list.name) ?? asString(list.id) ?? "list"))), shield_lists_error: data.shieldLists.error ?? null },
      "Admin Console > Enterprise Settings > Security > Allowed IP addresses (or Box Shield > Access Policies > Session and location rules): record the enforced IP ranges and which user populations they apply to.",
    ),
  );

  const eventsReadable = !data.events.error;
  const activityEvents = events.filter((event) => ACTIVITY_EVENT_TYPE_SET.has(eventType(event)));
  const failedLogins = events.filter((event) => eventType(event) === FAILED_LOGIN_EVENT_TYPE);
  const activeActorIds = new Set(activityEvents.map(eventActorId).filter((id): id is string => Boolean(id)));
  const cutoff = lookbackStart(data.now, data.lookbackDays);
  const inactiveCandidates = activeUsers.filter((user) => {
    const createdAt = parseIsoDate(user.created_at);
    if (createdAt && createdAt > cutoff) return false;
    const id = asString(user.id);
    return Boolean(id) && !activeActorIds.has(id as string);
  });
  const failedLoginActorIds = new Set(failedLogins.map(eventActorId).filter((id): id is string => Boolean(id)));
  const inactiveWithFailedLogins = inactiveCandidates.filter((user) => failedLoginActorIds.has(asString(user.id) ?? ""));
  const eventsTruncated = data.events.truncated === true;
  const inactiveRatio = activeUsers.length > 0 ? inactiveCandidates.length / activeUsers.length : 0;
  // Inactivity is the absence of an event, so a user is named inactive only when the event stream was read completely
  // and the user's own record was read; a capped stream renders the candidates as unknown.
  const inactivityProven = usersReadable && isComplete(data.events);
  const inactivityEvidence = {
    lookback_days: data.lookbackDays,
    active_users: whenRead(data.users, activeUsers.length),
    inactive_candidates: inactivityProven ? truncateList(inactiveCandidates.map(userLabel)) : null,
    inactive_candidates_with_failed_logins: inactivityProven ? truncateList(inactiveWithFailedLogins.map(userLabel)) : null,
    sampled_events: whenRead(data.events, events.length),
    activity_events: whenRead(data.events, activityEvents.length),
    failed_login_events: whenRead(data.events, failedLogins.length),
    event_limit: data.eventLimit,
    events_truncated: whenRead(data.events, eventsTruncated),
    ...inventoryEvidence,
  };
  const inactivityManualEvidence = `Admin Console > Reports > User Activity (or the Users report with last login): identify users with no login in the last ${data.lookbackDays} days and confirm deactivation decisions.`;
  findings.push(
    !usersReadable || !eventsReadable
      ? finding(24, "manual", `Inactive users could not be derived because ${!usersReadable ? `users were unreadable (${unreadableReason(data.users)})` : `enterprise events were unreadable (${unreadableReason(data.events)})`}.`, { lookback_days: data.lookbackDays }, inactivityManualEvidence)
      : inventoryGap
        ? finding(24, "warn", `Inactive users could not be assessed because ${inventoryGap}.`, inactivityEvidence, inventoryManualEvidence)
        : activeUsers.length === 0
          ? finding(24, "warn", `None of the ${users.length} sampled users are active managed users (only deactivated or platform-only app users were returned), so there was no activity to assess.`, inactivityEvidence, inactivityManualEvidence)
          : eventsTruncated
            ? finding(24, "warn", `The event collection stopped at the ${events.length}-event cap while Box reported more events (a next_stream_position remained), so ${inactiveCandidates.length}/${activeUsers.length} active users without observed activity is an upper bound; raise event_limit or confirm in the Admin Console.`, inactivityEvidence, inactivityManualEvidence)
            : inactiveCandidates.length === 0
              ? finding(24, "pass", `All ${activeUsers.length} active users showed successful login or content activity events within the last ${data.lookbackDays} days.`, inactivityEvidence)
              : inactiveRatio > 0.25
                ? finding(24, "fail", `${inactiveCandidates.length}/${activeUsers.length} active users had no successful login or content activity in the last ${data.lookbackDays} days${inactiveWithFailedLogins.length > 0 ? ` (${inactiveWithFailedLogins.length} of them only recorded failed logins)` : ""}.`, inactivityEvidence)
                : finding(24, "warn", `${inactiveCandidates.length}/${activeUsers.length} active users had no successful login or content activity in the last ${data.lookbackDays} days${inactiveWithFailedLogins.length > 0 ? ` (${inactiveWithFailedLogins.length} of them only recorded failed logins)` : ""}.`, inactivityEvidence),
  );

  return {
    area: "identity_access",
    title: "Box identity and access posture",
    summary: {
      enterprise_id: data.enterpriseId ?? null,
      sampled_users: whenRead(data.users, users.length),
      admins: whenRead(data.users, admins.length),
      coadmins: whenRead(data.users, coAdmins.length),
      exempt_privileged_users: observedCount([data.users], exemptPrivileged.length),
      sso_required: ssoRequired ?? null,
      mfa_required: mfaRequired ?? null,
      password_min_length: passwordMinLength ?? null,
      session_duration: sessionDuration ?? null,
      inactive_candidates: inactivityProven ? inactiveCandidates.length : null,
      sampled_events: whenRead(data.events, events.length),
      lookback_days: data.lookbackDays,
    },
    findings: sortFindings(findings),
    errors: [
      ...datasetErrors("current_user", data.currentUser),
      ...datasetErrors("enterprise_configuration", data.configuration),
      ...datasetErrors("users", data.users),
      ...datasetErrors("enterprise_events", data.events),
      ...datasetErrors("shield_lists", data.shieldLists),
    ],
    truncated: [
      ...datasetTruncations("users", data.users, "user_limit"),
      ...datasetTruncations("enterprise_events", data.events, "event_limit"),
    ],
  };
}

function adminMfaUnreadableFinding(data: BoxIdentityData): BoxFinding {
  return finding(
    2,
    "manual",
    `Neither enterprise MFA settings (${categoryUnreadableReason(data.configuration, "security")}) nor enterprise users (${unreadableReason(data.users)}) could be read.`,
    { config_error: data.configuration.error ?? null, users_error: data.users.error ?? null },
    "Admin Console > Enterprise Settings > Security > 2-Step Verification: confirm 2-step verification is required, then review each admin and co-admin for the 'Exempt from 2-step verification' option.",
  );
}

function sortFindings(findings: BoxFinding[]): BoxFinding[] {
  return [...findings].sort((left, right) => left.control - right.control);
}

export async function assessBoxIdentityAccess(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getCurrentUser" | "getEnterpriseConfiguration" | "listUsers" | "listEnterpriseEvents" | "listShieldLists">,
  options: BoxIdentityOptions = {},
): Promise<BoxAssessmentResult> {
  return assessBoxIdentityAccessData(await collectBoxIdentityData(client, options), options);
}

export async function collectBoxSharingData(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listCollaborationAllowlistEntries" | "listCollaborationAllowlistExemptTargets" | "listTermsOfServices" | "listShieldLists" | "listEnterpriseEvents">,
  options: BoxSharingOptions = {},
): Promise<BoxSharingData> {
  const now = client.getNow();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const eventLimit = clampNumber(options.eventLimit, DEFAULT_EVENT_LIMIT, 1, 100_000);
  const listLimit = clampNumber(options.listLimit, DEFAULT_LIST_LIMIT, 1, 100_000);
  const [enterpriseId, configuration, allowlistEntries, exemptTargets, termsOfServices, shieldLists, events] = await Promise.all([
    safeEnterpriseId(client),
    collect(() => client.getEnterpriseConfiguration(["security", "content_and_sharing", "user_settings"]), {}),
    collectList(() => client.listCollaborationAllowlistEntries(listLimit)),
    collectList(() => client.listCollaborationAllowlistExemptTargets(listLimit)),
    collectList(() => client.listTermsOfServices()),
    collectList(() => client.listShieldLists()),
    collectList(() => client.listEnterpriseEvents({
      eventTypes: SHARING_EVENT_TYPES,
      createdAfter: lookbackStart(now, lookbackDays),
      limit: eventLimit,
    })),
  ]);
  return { enterpriseId, configuration, allowlistEntries, exemptTargets, termsOfServices, shieldLists, events, lookbackDays, now };
}

export function assessBoxSharingCollaborationData(data: BoxSharingData, options: BoxSharingOptions = {}): BoxAssessmentResult {
  const staleDays = clampNumber(options.staleAllowlistDays, DEFAULT_STALE_ALLOWLIST_DAYS, 1, 3650);
  const configuration = data.configuration.error ? undefined : data.configuration.data;
  const configReadable = categoryReadable(data.configuration, "content_and_sharing");
  const configUnreadableReason = categoryUnreadableReason(data.configuration, "content_and_sharing");
  const allowlistReadable = !data.allowlistEntries.error;
  const allowlistTruncated = data.allowlistEntries.truncated === true || data.exemptTargets.truncated === true;
  const entries = data.allowlistEntries.data;
  const exemptTargets = data.exemptTargets.data;
  const events = data.events.data;

  const externalStatus = configString(configuration, "content_and_sharing", "external_collaboration_status");
  const collaborationRestrictions = asArray(configValue(configuration, "content_and_sharing", "collaboration_restrictions")).map((item) => asString(item)).filter((item): item is string => Boolean(item));
  const allowlistUsers = asRecordArray(configValue(configuration, "content_and_sharing", "external_collaboration_allowlist_users"));
  const findings: BoxFinding[] = [];

  const externalSettings = configSettings(configuration, "content_and_sharing", ["external_collaboration_status", "collaboration_restrictions", "external_collaboration_allowlist_users"]);
  const externalUnused = unusedSettings(externalSettings, ["external_collaboration_status"]);
  const externalEvidence = {
    external_collaboration_status: externalStatus ?? null,
    collaboration_restrictions: configReadable ? collaborationRestrictions : null,
    allowlist_entries: whenRead(data.allowlistEntries, entries.length),
    allowlist_exempt_users: configReadable && isRead(data.exemptTargets) ? exemptTargets.length + allowlistUsers.length : null,
    ...settingsEvidence(configReadable, externalSettings, externalUnused),
  };
  const externalManualEvidence = "Admin Console > Enterprise Settings > Content & Sharing > Collaboration: record whether external collaboration is enabled for everyone, restricted to allowlisted domains, or disabled.";
  const allowlistUnreadable = unreadableInventory("collaboration_allowlist_entries", data.allowlistEntries, "the permitted external domains were not checked");
  const exemptTargetsUnreadable = unreadableInventory("collaboration_allowlist_exempt_targets", data.exemptTargets, "users exempt from the domain restriction were not checked");
  const collaborationConfigUnreadable = unreadableInventory("enterprise_configuration (content_and_sharing)", data.configuration, "the external collaboration mode that decides whether an empty allowlist is compliant was not checked");
  findings.push(capForUnreadableInventories(
    !configReadable
      ? allowlistReadable && entries.length > 0
        ? finding(4, "warn", `${entries.length} collaboration allowlist domains exist, but the enterprise external collaboration mode could not be read (${configUnreadableReason}).`, externalEvidence, "Admin Console > Enterprise Settings > Content & Sharing > Collaboration: confirm external collaboration is limited to allowlisted domains or disabled.")
        : finding(4, "manual", `External collaboration settings could not be read because ${configUnreadableReason}.`, externalEvidence, externalManualEvidence)
      : hasUnusedSettings(externalUnused)
        ? finding(4, "warn", unusedSettingsSummary(externalUnused, `the external collaboration mode cannot be treated as enforced (${countOrUnread(data.allowlistEntries, entries.length)} allowlist entries visible)`), externalEvidence, externalManualEvidence)
        : externalStatus === "limit_collaboration_to_users_within_enterprise"
        ? finding(4, "pass", "External collaboration is limited to users within the enterprise.", externalEvidence)
        : externalStatus === "limit_collaboration_to_allowlisted_domains"
          ? !allowlistReadable
            ? finding(4, "warn", `External collaboration is limited to allowlisted domains, but the ${describeInventory("collaboration allowlist", data.allowlistEntries)} could not be read because ${unreadableReason(data.allowlistEntries)}, so the permitted domains were not checked.`, externalEvidence, "Admin Console > Enterprise Settings > Content & Sharing > Collaboration > Allowlisted domains: export the domain list and confirm each entry is a business partner.")
            : entries.length > 0
              ? finding(4, "pass", `External collaboration is limited to allowlisted domains (${entries.length} domain entries visible).`, externalEvidence)
              : finding(4, "warn", "External collaboration is limited to allowlisted domains, but the allowlist is empty, which may block all external work or indicate an incomplete rollout.", externalEvidence)
          : externalStatus === "enable_external_collaboration"
            ? finding(4, "fail", "External collaboration is enabled for any domain without an allowlist restriction.", externalEvidence)
            : finding(4, "warn", `External collaboration status "${externalStatus ?? "unknown"}" was not recognized; confirm the setting manually.`, externalEvidence),
    [allowlistUnreadable],
    externalManualEvidence,
  ));

  const publicDomainEntries = entries.filter((entry) => isPublicEmailDomain(asString(entry.domain) ?? ""));
  const undatedEntries = entries.filter((entry) => parseIsoDate(entry.created_at) === undefined);
  const staleEntries = entries.filter((entry) => {
    const createdAt = parseIsoDate(entry.created_at);
    return createdAt !== undefined && daysBetween(data.now, createdAt) > staleDays;
  });
  const bothDirectionEntries = entries.filter((entry) => asString(entry.direction) === "both");
  const allowlistEvidence = {
    allowlist_entries: observedList([data.allowlistEntries], truncateList(entries.map((entry) => `${asString(entry.domain) ?? "domain"} (${asString(entry.direction) ?? "direction"})`))),
    public_email_domains: observedList([data.allowlistEntries], publicDomainEntries.map((entry) => asString(entry.domain))),
    stale_entries: observedList([data.allowlistEntries], truncateList(staleEntries.map((entry) => asString(entry.domain)))),
    undated_entries: observedList([data.allowlistEntries], truncateList(undatedEntries.map((entry) => `${asString(entry.domain) ?? asString(entry.id) ?? "entry"} (created_at: ${entry.created_at === undefined ? "missing" : JSON.stringify(entry.created_at)})`))),
    both_direction_entries: observedCount([data.allowlistEntries], bothDirectionEntries.length),
    exempt_targets: observedCount([data.exemptTargets], exemptTargets.length),
    stale_days: staleDays,
    allowlist_truncated: whenAllRead([data.allowlistEntries, data.exemptTargets], allowlistTruncated),
  };
  const allowlistManualEvidence = "Admin Console > Enterprise Settings > Content & Sharing > Collaboration > Allowlisted domains: export the domain list and review each entry for business justification, direction, and age.";
  const allowlistReviewReasons = [
    ...(staleEntries.length > 0 ? [`${staleEntries.length} allowlist entries are older than ${staleDays} days`] : []),
    ...(undatedEntries.length > 0 ? [`${undatedEntries.length} allowlist entries have a missing or unparseable created_at (a documented CollaborationAllowlistEntry field), so their age cannot be assessed`] : []),
    ...(exemptTargets.length > 0 ? [`${exemptTargets.length} users are exempt from domain restrictions`] : []),
  ];
  findings.push(capForUnreadableInventories(
    !allowlistReadable
      ? finding(5, "manual", `The collaboration allowlist could not be read because ${unreadableReason(data.allowlistEntries)}.`, allowlistEvidence, allowlistManualEvidence)
      : publicDomainEntries.length > 0
        ? finding(5, "fail", `${publicDomainEntries.length} allowlisted domains are public consumer email providers, which effectively allow anyone to collaborate.`, allowlistEvidence)
        : allowlistTruncated
          ? finding(5, "warn", `The collaboration allowlist collection stopped at the cap (${entries.length} entries and ${countOrUnread(data.exemptTargets, exemptTargets.length)} exempt users retrieved) while Box reported more records, so unreviewed public, stale, or exempt entries may remain; raise list_limit and rerun.`, allowlistEvidence, allowlistManualEvidence)
        : entries.length === 0
          ? finding(5, externalStatus === "limit_collaboration_to_allowlisted_domains" ? "warn" : "pass", entries.length === 0 && externalStatus === "limit_collaboration_to_allowlisted_domains" ? "The allowlist is empty while collaboration is limited to allowlisted domains." : "No collaboration allowlist entries exist to audit.", allowlistEvidence)
          : allowlistReviewReasons.length > 0
            ? finding(5, "warn", `${allowlistReviewReasons.join("; ")}; review them for continued need.`, allowlistEvidence, "Confirm with content owners that each stale, undated, or exempt entry still has an active business relationship, and record the creation date of any undated entry from the Admin Console export.")
            // The absence of exemptions is stated only from an exempt-target listing that was read; otherwise it is unread.
            : finding(5, "pass", `${entries.length} allowlist entries are dated, recent, non-public domains${isRead(data.exemptTargets) ? " with no user exemptions" : "; the user exemption list is unread"}.`, allowlistEvidence),
    [exemptTargetsUnreadable, collaborationConfigUnreadable],
    allowlistManualEvidence,
  ));

  const sharedLinkDefault = configString(configuration, "content_and_sharing", "shared_link_default_access");
  const sharedLinkAllowed = configString(configuration, "content_and_sharing", "shared_link_access");
  const linkSettings = configSettings(configuration, "content_and_sharing", ["shared_link_default_access", "shared_link_access", "shared_link_company_definition"]);
  const linkUnused = unusedSettings(linkSettings, ["shared_link_default_access", "shared_link_access"]);
  const linkEvidence = {
    shared_link_default_access: sharedLinkDefault ?? null,
    shared_link_access: sharedLinkAllowed ?? null,
    shared_link_company_definition: configString(configuration, "content_and_sharing", "shared_link_company_definition") ?? null,
    ...settingsEvidence(configReadable, linkSettings, linkUnused),
  };
  const linkManualEvidence = "Admin Console > Enterprise Settings > Content & Sharing > Shared Links: record the default link access level and whether open (public) links are permitted.";
  findings.push(
    !configReadable
      ? finding(6, "manual", `Shared link settings could not be read because ${configUnreadableReason}.`, undefined, linkManualEvidence)
      : hasUnusedSettings(linkUnused)
        ? finding(6, "warn", unusedSettingsSummary(linkUnused, "the shared link access policy cannot be treated as enforced"), linkEvidence, linkManualEvidence)
        : accessLevelIsOpen(sharedLinkDefault)
        ? finding(6, "fail", `The default shared link access level "${sharedLinkDefault}" creates public links.`, linkEvidence)
        : accessLevelIsRestricted(sharedLinkDefault)
          ? accessLevelIsOpen(sharedLinkAllowed)
            ? finding(6, "warn", `Shared links default to "${sharedLinkDefault}", but open links remain available to users through "${sharedLinkAllowed}".`, linkEvidence)
            : finding(6, "pass", `Shared links default to "${sharedLinkDefault}" and open links are not offered by the enterprise setting "${sharedLinkAllowed ?? "unset"}".`, linkEvidence)
          : finding(6, "warn", `Shared link default access "${sharedLinkDefault ?? "unset"}" was not recognized; confirm it is People in this company or more restrictive.`, linkEvidence),
  );

  const expirationEnabled = configBool(configuration, "content_and_sharing", "is_shared_links_expiration_enabled");
  const expirationDays = configNumber(configuration, "content_and_sharing", "shared_links_expiration_days");
  const publicExpirationEnabled = configBool(configuration, "content_and_sharing", "is_public_shared_links_expiration_enabled");
  const publicExpirationDays = configNumber(configuration, "content_and_sharing", "public_shared_links_expiration_days");
  const expirationSettings = configSettings(configuration, "content_and_sharing", [
    "is_shared_links_expiration_enabled",
    "shared_links_expiration_days",
    "is_public_shared_links_expiration_enabled",
    "public_shared_links_expiration_days",
    "shared_expiration_target",
  ]);
  const expirationUnused = unusedSettings(expirationSettings, ["is_shared_links_expiration_enabled"]);
  const expirationEvidence = {
    is_shared_links_expiration_enabled: expirationEnabled ?? null,
    shared_links_expiration_days: expirationDays ?? null,
    is_public_shared_links_expiration_enabled: publicExpirationEnabled ?? null,
    public_shared_links_expiration_days: publicExpirationDays ?? null,
    shared_expiration_target: configString(configuration, "content_and_sharing", "shared_expiration_target") ?? null,
    ...settingsEvidence(configReadable, expirationSettings, unusedSettings(expirationSettings)),
  };
  const expirationManualEvidence = "Admin Console > Enterprise Settings > Content & Sharing > Shared Links: confirm automatic expiration is enabled and record the day count.";
  findings.push(
    !configReadable
      ? finding(7, "manual", `Shared link expiration settings could not be read because ${configUnreadableReason}.`, undefined, expirationManualEvidence)
      : hasUnusedSettings(expirationUnused)
        ? finding(7, "warn", unusedSettingsSummary(expirationUnused, "shared link expiration cannot be treated as enforced"), expirationEvidence, expirationManualEvidence)
        : expirationEnabled === true
        ? finding(7, "pass", `Shared links expire automatically after ${expirationDays ?? "a configured number of"} days.`, expirationEvidence)
        : publicExpirationEnabled === true
          ? finding(7, "warn", `Only public shared links expire automatically (${publicExpirationDays ?? "configured"} days); company and collaborator links have no mandatory expiration.`, expirationEvidence)
          : expirationEnabled === false
            ? finding(7, "fail", "Shared links do not have a mandatory expiration configured.", expirationEvidence)
            : finding(7, "warn", "Enterprise settings did not expose is_shared_links_expiration_enabled, so shared link expiration cannot be confirmed from the API.", expirationEvidence, expirationManualEvidence),
  );

  findings.push(
    finding(
      8,
      "manual",
      configReadable
        ? "The enterprise configuration API does not expose whether passwords are required for open shared links."
        : `Shared link settings could not be read (${configUnreadableReason}) and the API does not expose shared link password requirements.`,
      { is_strong_password_for_ext_collab_enabled: configBool(configuration, "security", "is_strong_password_for_ext_collab_enabled") ?? null, shared_link_default_access: sharedLinkDefault ?? null },
      "Admin Console > Enterprise Settings > Content & Sharing > Shared Links: confirm 'Require password for open shared links' (or equivalent) is enabled and record the password strength setting.",
    ),
  );

  const watermarkingEnabled = configBool(configuration, "content_and_sharing", "is_watermarking_enterprise_feature_enabled");
  const watermarkFeatures = asRecordArray(configValue(configuration, "content_and_sharing", "enterprise_feature_settings"))
    .concat(asRecordArray(configCategory(configuration, "content_and_sharing")?.enterprise_feature_settings))
    .map((item) => asObject(item.value) ?? item)
    .filter((setting) => /watermark/i.test(asString(asObject(setting.feature)?.id) ?? ""));
  const watermarkSettings = configSettings(configuration, "content_and_sharing", ["is_watermarking_enterprise_feature_enabled"]);
  const watermarkUnused = unusedSettings(watermarkSettings);
  const watermarkEvidence = {
    is_watermarking_enterprise_feature_enabled: watermarkingEnabled ?? null,
    watermark_feature_states: watermarkFeatures.map((setting) => asString(setting.state) ?? "unknown"),
    ...settingsEvidence(configReadable, watermarkSettings, watermarkUnused),
  };
  const watermarkManualEvidence = "Admin Console > Enterprise Settings > Content & Sharing > Watermarking: confirm watermarking is enabled and which folders or classifications apply it.";
  findings.push(
    !configReadable
      ? finding(9, "manual", `Watermarking settings could not be read because ${configUnreadableReason}.`, undefined, watermarkManualEvidence)
      : hasUnusedSettings(watermarkUnused)
        ? finding(9, "warn", unusedSettingsSummary(watermarkUnused, "watermarking cannot be treated as an enforced enterprise feature"), watermarkEvidence, watermarkManualEvidence)
        : watermarkingEnabled === true
        ? finding(9, "pass", "Watermarking is enabled as an enterprise feature; confirm sensitive folders and classifications apply it.", watermarkEvidence, "Spot check sensitive folders for the watermark setting and confirm classification policies apply watermarks where required.")
        : watermarkingEnabled === false
          ? finding(9, "fail", "Watermarking is not enabled as an enterprise feature.", watermarkEvidence)
          : finding(9, "warn", "Enterprise settings did not expose the watermarking feature flag.", watermarkEvidence),
  );

  const appEvents = events.filter((event) => /^(ENTERPRISE_APP_AUTHORIZATION_UPDATE|APPLICATION_CREATED|APPLICATION_PUBLIC_KEY_ADDED)$/.test(eventType(event)));
  const integrationLists = data.shieldLists.data.filter((list) => shieldListContentType(list) === "integration");
  findings.push(
    finding(
      19,
      "manual",
      `${countOrUnread(data.events, appEvents.length)} app authorization or creation events occurred in the last ${data.lookbackDays} days and ${countOrUnread(data.shieldLists, integrationLists.length)} Shield integration lists exist; the Box API does not expose the app approval policy itself.`,
      {
        app_events: whenRead(data.events, countEventTypes(appEvents)),
        integration_shield_lists: whenRead(data.shieldLists, integrationLists.map((list) => asString(list.name) ?? asString(list.id) ?? "list")),
        events_error: data.events.error ?? null,
        shield_lists_error: data.shieldLists.error ?? null,
      },
      "Admin Console > Apps > Custom Apps Manager and Individual Application Controls: confirm unpublished and third-party apps are disabled by default and require admin approval, and reconcile the authorized app list against the events above.",
    ),
  );

  const managedTerms = data.termsOfServices.data.filter((terms) => asString(terms.tos_type) === "managed");
  const externalTerms = data.termsOfServices.data.filter((terms) => asString(terms.tos_type) === "external");
  const enabledManaged = managedTerms.filter((terms) => asString(terms.status) === "enabled");
  const tosEvidence = {
    managed_terms: whenRead(data.termsOfServices, managedTerms.map((terms) => ({ id: asString(terms.id), status: asString(terms.status), modified_at: asString(terms.modified_at) }))),
    external_terms: whenRead(data.termsOfServices, externalTerms.map((terms) => ({ id: asString(terms.id), status: asString(terms.status) }))),
    terms_accept_events: observedCount([data.events], events.filter((event) => eventType(event) === "TERMS_OF_SERVICE_ACCEPT").length),
  };
  findings.push(
    data.termsOfServices.error
      ? finding(20, "manual", `Terms of service could not be read because ${unreadableReason(data.termsOfServices)}.`, tosEvidence, "Admin Console > Enterprise Settings > Custom Setup > Custom Terms of Service: confirm terms are enabled for managed users and record the last modification date.")
      : enabledManaged.length > 0
        ? finding(20, "pass", `Custom terms of service are enabled for managed users${externalTerms.some((terms) => asString(terms.status) === "enabled") ? " and external users" : ""}.`, tosEvidence)
        : managedTerms.length > 0
          ? finding(20, "fail", "Custom terms of service exist for managed users but are disabled.", tosEvidence)
          : finding(20, "fail", "No custom terms of service are configured for managed users.", tosEvidence),
  );

  return {
    area: "sharing_collaboration",
    title: "Box sharing and collaboration governance",
    summary: {
      enterprise_id: data.enterpriseId ?? null,
      external_collaboration_status: externalStatus ?? null,
      allowlist_entries: whenRead(data.allowlistEntries, entries.length),
      public_email_domains: observedCount([data.allowlistEntries], publicDomainEntries.length),
      stale_allowlist_entries: observedCount([data.allowlistEntries], staleEntries.length),
      undated_allowlist_entries: observedCount([data.allowlistEntries], undatedEntries.length),
      exempt_targets: whenRead(data.exemptTargets, exemptTargets.length),
      shared_link_default_access: sharedLinkDefault ?? null,
      shared_links_expiration_enabled: expirationEnabled ?? null,
      watermarking_enabled: watermarkingEnabled ?? null,
      managed_terms_enabled: whenRead(data.termsOfServices, enabledManaged.length),
      app_events: whenRead(data.events, appEvents.length),
      lookback_days: data.lookbackDays,
    },
    findings: sortFindings(findings),
    errors: [
      ...datasetErrors("enterprise_configuration", data.configuration),
      ...datasetErrors("collaboration_allowlist_entries", data.allowlistEntries),
      ...datasetErrors("collaboration_allowlist_exempt_targets", data.exemptTargets),
      ...datasetErrors("terms_of_services", data.termsOfServices),
      ...datasetErrors("shield_lists", data.shieldLists),
      ...datasetErrors("enterprise_events", data.events),
    ],
    truncated: [
      ...datasetTruncations("collaboration_allowlist_entries", data.allowlistEntries, "list_limit"),
      ...datasetTruncations("collaboration_allowlist_exempt_targets", data.exemptTargets, "list_limit"),
      ...datasetTruncations("enterprise_events", data.events, "event_limit"),
    ],
  };
}

export async function assessBoxSharingCollaboration(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listCollaborationAllowlistEntries" | "listCollaborationAllowlistExemptTargets" | "listTermsOfServices" | "listShieldLists" | "listEnterpriseEvents">,
  options: BoxSharingOptions = {},
): Promise<BoxAssessmentResult> {
  return assessBoxSharingCollaborationData(await collectBoxSharingData(client, options), options);
}

/**
 * Reads one child list per parent record. A denied child read is recorded as a marker under the parent's id (never
 * an empty list), the first failure's status and request are carried on the dataset, and the parents beyond the
 * per-run cap are reported as truncation. A parent listing that was not itself read yields no child reads at all.
 */
async function collectAssignments(
  parents: CollectedDataset<JsonRecord[]>,
  loader: (parentId: string) => Promise<BoxListPage>,
): Promise<CollectedDataset<BoxAssignmentMap>> {
  if (!isRead(parents)) {
    return { data: {}, error: "not requested because the parent listing could not be read", notRequested: true };
  }
  const result: BoxAssignmentMap = {};
  const errors: string[] = [];
  let firstFailure: CollectedDataset<unknown> | undefined;
  let truncated = parents.data.length > MAX_ASSIGNMENT_POLICIES;
  for (const parent of parents.data.slice(0, MAX_ASSIGNMENT_POLICIES)) {
    const parentId = asString(parent.id);
    if (!parentId) continue;
    try {
      const page = await loader(parentId);
      result[parentId] = page.items;
      truncated = truncated || page.truncated;
    } catch (error) {
      const failed: CollectedDataset<unknown> = {
        data: undefined,
        error: errorMessage(error),
        statusCode: error instanceof BoxApiError ? error.status : undefined,
        request: requestOf(error),
      };
      firstFailure = firstFailure ?? failed;
      result[parentId] = notReadableMarker(failed);
      errors.push(`${parentId}: ${failed.error}`);
    }
  }
  return {
    data: result,
    error: errors.length > 0 ? errors.join("; ") : undefined,
    statusCode: firstFailure?.statusCode,
    request: firstFailure?.request,
    truncated: errors.length > 0 ? undefined : truncated,
  };
}

export async function collectBoxGovernanceData(
  client: Pick<BoxReadClient, "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listDevicePinners" | "getClassificationTemplate" | "listEnterpriseMetadataTemplates" | "listRetentionPolicies" | "listRetentionPolicyAssignments" | "listLegalHoldPolicies" | "listLegalHoldPolicyAssignments">,
  options: BoxGovernanceOptions = {},
): Promise<BoxGovernanceData> {
  const listLimit = clampNumber(options.listLimit, DEFAULT_LIST_LIMIT, 1, 100_000);
  const [enterpriseId, configuration, devicePinners, classificationTemplate, metadataTemplates, retentionPolicies, legalHoldPolicies] = await Promise.all([
    safeEnterpriseId(client),
    collect(() => client.getEnterpriseConfiguration(["user_settings", "content_and_sharing"]), {}),
    collectList(() => client.listDevicePinners(listLimit)),
    collect(() => client.getClassificationTemplate(), {}),
    collectList(() => client.listEnterpriseMetadataTemplates(listLimit)),
    collectList(() => client.listRetentionPolicies(listLimit)),
    collectList(() => client.listLegalHoldPolicies(listLimit)),
  ]);
  const [retentionAssignments, legalHoldAssignments] = await Promise.all([
    collectAssignments(retentionPolicies, (policyId) => client.listRetentionPolicyAssignments(policyId, listLimit)),
    collectAssignments(legalHoldPolicies, (policyId) => client.listLegalHoldPolicyAssignments(policyId, listLimit)),
  ]);
  return {
    enterpriseId,
    devicePinners,
    classificationTemplate,
    metadataTemplates,
    retentionPolicies,
    retentionAssignments,
    legalHoldPolicies,
    legalHoldAssignments,
    configuration,
  };
}

/** The total of a policy's own assignment_counts, or null when the record carries none. */
function assignmentCountTotal(policy: JsonRecord): number | null {
  const counts = asObject(policy.assignment_counts);
  if (!counts) return null;
  return Object.values(counts).reduce<number>((total, value) => total + (asNumber(value) ?? 0), 0);
}

/**
 * Assignments a policy is known to have: the child listing when it was read, otherwise the policy's own
 * assignment_counts total, otherwise null. Zero is stated only from a source that was read.
 */
function knownAssignments(policy: JsonRecord, assignments: BoxAssignmentMap): number | null {
  const listed = childList(assignments, asString(policy.id));
  if (listed !== undefined) return listed.length > 0 ? listed.length : (assignmentCountTotal(policy) ?? 0);
  return assignmentCountTotal(policy);
}

function hasKnownAssignments(policy: JsonRecord, assignments: BoxAssignmentMap): boolean {
  return (knownAssignments(policy, assignments) ?? 0) > 0;
}

function classificationOptions(template: JsonRecord): string[] {
  const fields = asRecordArray(template.fields);
  const classificationField = fields.find((field) => asString(field.key) === "Box__Security__Classification__Key") ?? fields[0];
  return asRecordArray(classificationField?.options).map((option) => asString(option.key) ?? asString(option.id) ?? "option");
}

export function assessBoxDataGovernanceData(data: BoxGovernanceData): BoxAssessmentResult {
  const configuration = data.configuration.error ? undefined : data.configuration.data;
  const findings: BoxFinding[] = [];

  const pins = data.devicePinners.data;
  const pinProducts = countEventTypesBy(pins, (pin) => asString(pin.product_name) ?? "unknown");
  const deviceEvidence = {
    device_pins: whenRead(data.devicePinners, pins.length),
    device_pin_products: whenRead(data.devicePinners, pinProducts),
    is_device_limit_exemption_enabled_for_new_users: configBool(configuration, "user_settings", "is_device_limit_exemption_enabled_for_new_users") ?? null,
    is_box_sync_restricted_for_new_users: configBool(configuration, "user_settings", "is_box_sync_restricted_for_new_users") ?? null,
  };
  findings.push(
    data.devicePinners.error
      ? finding(10, "manual", `Device pins could not be read because ${unreadableReason(data.devicePinners)}.`, deviceEvidence, "Admin Console > Enterprise Settings > Device Trust: record whether device pinning is enforced for Box Drive, Box Sync, and mobile apps, and export the pinned device list.")
      : pins.length === 0
        ? finding(10, "warn", "No device pins exist, which indicates device pinning is not enforced for desktop or mobile clients.", deviceEvidence, "Admin Console > Enterprise Settings > Device Trust: confirm whether device pinning and device trust checks are intentionally disabled.")
        : finding(10, "manual", `${pins.length} device pins are registered; the Box API does not expose the device trust policy that decides whether unpinned devices are blocked.`, deviceEvidence, "Admin Console > Enterprise Settings > Device Trust: confirm device pinning is required, record per-user device limits, and review the pinned device inventory for stale entries."),
  );

  const templates = data.metadataTemplates.data;
  // A 404 is Box saying no classification template exists, which is a readable answer of zero labels.
  const classificationReadable = isRead(data.classificationTemplate) || data.classificationTemplate.statusCode === 404;
  const classifications = isRead(data.classificationTemplate) ? classificationOptions(data.classificationTemplate.data) : [];
  const classificationEvidence = {
    classifications: classificationReadable ? classifications : null,
    enterprise_metadata_templates: whenRead(data.metadataTemplates, templates.length),
    classification_error: data.classificationTemplate.error ?? null,
  };
  findings.push(
    data.classificationTemplate.error && data.classificationTemplate.statusCode !== 404
      ? finding(11, "manual", `The classification template could not be read because ${unreadableReason(data.classificationTemplate)}.`, classificationEvidence, "Admin Console > Enterprise Settings > Classification: record the defined labels and confirm sensitive folders carry a classification.")
      : classifications.length > 0
        ? finding(11, "pass", `${classifications.length} classification labels are defined (${classifications.join(", ")}); label application to sensitive content still needs a sampled folder review.`, classificationEvidence, "Sample sensitive folders and confirm they carry the expected classification label and downstream Shield or sharing policies.")
        : finding(11, "fail", "No classification labels are defined for the enterprise.", classificationEvidence),
  );

  const retentionPolicies = data.retentionPolicies.data;
  const activeRetention = retentionPolicies.filter((policy) => (asString(policy.status) ?? "active") === "active");
  const assignedRetention = activeRetention.filter((policy) => hasKnownAssignments(policy, data.retentionAssignments.data));
  const retentionEvidence = {
    retention_policies: whenRead(data.retentionPolicies, truncateList(retentionPolicies.map((policy) => ({
      name: asString(policy.policy_name),
      status: asString(policy.status),
      type: asString(policy.policy_type),
      retention_length: asString(policy.retention_length),
      disposition_action: asString(policy.disposition_action),
      assignments: knownAssignments(policy, data.retentionAssignments.data),
    })))),
    active_policies: whenRead(data.retentionPolicies, activeRetention.length),
    assigned_policies: observedCount([data.retentionPolicies, data.retentionAssignments], assignedRetention.length),
  };
  const retentionManualEvidence = "Admin Console > Governance > Retention: record each policy, its retention length, disposition action, and the folders or metadata it is assigned to.";
  findings.push(capForUnreadableInventories(
    data.retentionPolicies.error
      ? finding(12, "manual", `Retention policies could not be read because ${unreadableReason(data.retentionPolicies)}; this endpoint requires Box Governance and the manage_data_retention scope.`, retentionEvidence, retentionManualEvidence)
      : assignedRetention.length > 0
        ? finding(12, "pass", `${assignedRetention.length}/${activeRetention.length} active retention policies have assignments.`, retentionEvidence)
        : activeRetention.length > 0
          ? finding(12, "warn", `${activeRetention.length} active retention policies exist but none have visible assignments.`, retentionEvidence)
          : finding(12, "fail", "No active retention policies exist.", retentionEvidence),
    [unreadableInventory("retention_policy_assignments", data.retentionAssignments, "the folders and metadata each policy is assigned to were not checked (only the policy's own assignment_counts were read)")],
    retentionManualEvidence,
  ));

  const legalHolds = data.legalHoldPolicies.data;
  const activeHolds = legalHolds.filter((policy) => ["active", "applying"].includes(asString(policy.status) ?? ""));
  const assignedHolds = activeHolds.filter((policy) => hasKnownAssignments(policy, data.legalHoldAssignments.data));
  const holdEvidence = {
    legal_hold_policies: whenRead(data.legalHoldPolicies, truncateList(legalHolds.map((policy) => ({
      name: asString(policy.policy_name),
      status: asString(policy.status),
      assignments: knownAssignments(policy, data.legalHoldAssignments.data),
    })))),
    active_policies: whenRead(data.legalHoldPolicies, activeHolds.length),
    assigned_policies: observedCount([data.legalHoldPolicies, data.legalHoldAssignments], assignedHolds.length),
  };
  const holdManualEvidence = "Admin Console > Governance > Legal Holds: record each policy, its custodians or folders, and confirm the legal team's hold process is documented.";
  findings.push(capForUnreadableInventories(
    data.legalHoldPolicies.error
      ? finding(13, "manual", `Legal hold policies could not be read because ${unreadableReason(data.legalHoldPolicies)}; this endpoint requires Box Governance and the manage_legal_holds scope.`, holdEvidence, holdManualEvidence)
      : assignedHolds.length > 0
        ? finding(13, "pass", `${assignedHolds.length}/${activeHolds.length} active legal hold policies have custodian or content assignments.`, holdEvidence)
        : activeHolds.length > 0
          ? finding(13, "warn", `${activeHolds.length} active legal hold policies exist without visible assignments.`, holdEvidence)
          : finding(13, "warn", "No legal hold policies exist; confirm a documented process exists to create holds when litigation is anticipated.", holdEvidence, "Obtain the legal team's hold procedure and confirm Box Governance is licensed so holds can be applied when required."),
    [unreadableInventory("legal_hold_policy_assignments", data.legalHoldAssignments, "the custodians and content each hold covers were not checked (only the policy's own assignment_counts were read)")],
    holdManualEvidence,
  ));

  return {
    area: "data_governance",
    title: "Box data governance posture",
    summary: {
      enterprise_id: data.enterpriseId ?? null,
      device_pins: whenRead(data.devicePinners, pins.length),
      classifications: classificationReadable ? classifications.length : null,
      metadata_templates: whenRead(data.metadataTemplates, templates.length),
      retention_policies: whenRead(data.retentionPolicies, retentionPolicies.length),
      assigned_retention_policies: observedCount([data.retentionPolicies, data.retentionAssignments], assignedRetention.length),
      legal_hold_policies: whenRead(data.legalHoldPolicies, legalHolds.length),
      assigned_legal_hold_policies: observedCount([data.legalHoldPolicies, data.legalHoldAssignments], assignedHolds.length),
    },
    findings: sortFindings(findings),
    errors: [
      ...datasetErrors("enterprise_configuration", data.configuration),
      ...datasetErrors("device_pinners", data.devicePinners),
      ...datasetErrors("classification_template", data.classificationTemplate),
      ...datasetErrors("metadata_templates", data.metadataTemplates),
      ...datasetErrors("retention_policies", data.retentionPolicies),
      ...datasetErrors("retention_policy_assignments", data.retentionAssignments),
      ...datasetErrors("legal_hold_policies", data.legalHoldPolicies),
      ...datasetErrors("legal_hold_policy_assignments", data.legalHoldAssignments),
    ],
    truncated: [
      ...datasetTruncations("device_pinners", data.devicePinners, "list_limit"),
      ...datasetTruncations("metadata_templates", data.metadataTemplates, "list_limit"),
      ...datasetTruncations("retention_policies", data.retentionPolicies, "list_limit"),
      ...datasetTruncations("retention_policy_assignments", data.retentionAssignments, "list_limit"),
      ...datasetTruncations("legal_hold_policies", data.legalHoldPolicies, "list_limit"),
      ...datasetTruncations("legal_hold_policy_assignments", data.legalHoldAssignments, "list_limit"),
    ],
  };
}

function countEventTypesBy(items: JsonRecord[], keyOf: (item: JsonRecord) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const key = keyOf(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

export async function assessBoxDataGovernance(
  client: Pick<BoxReadClient, "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listDevicePinners" | "getClassificationTemplate" | "listEnterpriseMetadataTemplates" | "listRetentionPolicies" | "listRetentionPolicyAssignments" | "listLegalHoldPolicies" | "listLegalHoldPolicyAssignments">,
  options: BoxGovernanceOptions = {},
): Promise<BoxAssessmentResult> {
  return assessBoxDataGovernanceData(await collectBoxGovernanceData(client, options));
}

export async function collectBoxShieldData(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listShieldInformationBarriers" | "listShieldInformationBarrierSegments" | "listShieldLists" | "listEnterpriseEvents">,
  options: BoxShieldOptions = {},
): Promise<BoxShieldData> {
  const now = client.getNow();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const eventLimit = clampNumber(options.eventLimit, DEFAULT_EVENT_LIMIT, 1, 100_000);
  const [enterpriseId, configuration, barriers, shieldLists, events] = await Promise.all([
    safeEnterpriseId(client),
    collect(() => client.getEnterpriseConfiguration(["shield"]), {}),
    collectList(() => client.listShieldInformationBarriers()),
    collectList(() => client.listShieldLists()),
    collectList(() => client.listEnterpriseEvents({
      eventTypes: SHIELD_EVENT_TYPES,
      createdAfter: lookbackStart(now, lookbackDays),
      limit: eventLimit,
    })),
  ]);
  const barrierSegments = await collectAssignments(barriers, (barrierId) => client.listShieldInformationBarrierSegments(barrierId));
  return { enterpriseId, configuration, barriers, barrierSegments, shieldLists, events, lookbackDays, eventLimit, now };
}

export function assessBoxShieldMonitoringData(data: BoxShieldData): BoxAssessmentResult {
  const configuration = data.configuration.error ? undefined : data.configuration.data;
  const shieldReadable = categoryReadable(data.configuration, "shield");
  const shieldUnreadableReason = categoryUnreadableReason(data.configuration, "shield");
  const shieldRules = asRecordArray(configCategory(configuration, "shield")?.shield_rules);
  const events = data.events.data;
  const eventsReadable = !data.events.error;
  const eventCounts = countEventTypes(events);
  const findings: BoxFinding[] = [];

  const ruleCategories = countEventTypesBy(shieldRules, (rule) => asString(rule.rule_category) ?? "unknown");
  const ruleEvidence = {
    shield_rules: shieldReadable ? truncateList(shieldRules.map((rule) => ({ name: asString(rule.name), category: asString(rule.rule_category), priority: asString(rule.priority) }))) : null,
    rule_categories: shieldReadable ? ruleCategories : null,
    shield_lists: whenRead(data.shieldLists, data.shieldLists.data.length),
    shield_events: whenRead(data.events, Object.fromEntries(Object.entries(eventCounts).filter(([type]) => type.startsWith("SHIELD_")))),
  };
  findings.push(
    !shieldReadable
      ? finding(14, "manual", `Shield rule configuration could not be read because ${shieldUnreadableReason}; Box Shield licensing and the manage_enterprise_properties scope are required.`, ruleEvidence, "Admin Console > Shield > Access Policies and Threat Detection Rules: record each policy, its scope (classification, user, group), and the enabled anomaly detectors.")
      : shieldRules.length > 0
        ? finding(14, "pass", `${shieldRules.length} Shield rules are configured across ${Object.keys(ruleCategories).length} categories.`, ruleEvidence)
        : finding(14, "fail", "No Shield smart access or threat detection rules are configured.", ruleEvidence),
  );

  const barriers = data.barriers.data;
  const enabledBarriers = barriers.filter((barrier) => asString(barrier.status) === "enabled");
  const barrierEvidence = {
    barriers: whenRead(data.barriers, truncateList(barriers.map((barrier) => ({
      id: asString(barrier.id),
      status: asString(barrier.status),
      segments: childList(data.barrierSegments.data, asString(barrier.id))?.length ?? null,
    })))),
    enabled_barriers: whenRead(data.barriers, enabledBarriers.length),
  };
  const enabledWithSegments = enabledBarriers.filter((barrier) => (childList(data.barrierSegments.data, asString(barrier.id))?.length ?? 0) > 0);
  const barrierManualEvidence = "Admin Console > Shield > Information Barriers: record each barrier, its segments, and the restrictions between segments, or confirm barriers are not required for this enterprise.";
  findings.push(capForUnreadableInventories(
    data.barriers.error
      ? finding(15, "manual", `Shield information barriers could not be read because ${unreadableReason(data.barriers)}.`, barrierEvidence, barrierManualEvidence)
      : enabledWithSegments.length > 0
        ? finding(15, "pass", `${enabledWithSegments.length} enabled information barriers have segments defined.`, barrierEvidence)
        : enabledBarriers.length > 0
          // "No segments" is asserted only from segment reads that completed; a denied segment read leaves them unread.
          ? finding(15, "warn", `${enabledBarriers.length} information barriers are enabled but ${isRead(data.barrierSegments) ? "have no visible segments" : "their segments could not be read"}.`, barrierEvidence)
          : barriers.length > 0
            ? finding(15, "warn", `${barriers.length} information barriers exist but none are enabled.`, barrierEvidence)
            : finding(15, "warn", "No information barriers are configured; confirm segregation between groups is not required.", barrierEvidence, "Document whether regulatory or conflict-of-interest requirements call for information barriers between business units."),
    [unreadableInventory("shield_information_barrier_segments", data.barrierSegments, "the segments behind the enabled barriers were not checked")],
    barrierManualEvidence,
  ));

  const streamEvidence = {
    sampled_events: whenRead(data.events, events.length),
    event_types: whenRead(data.events, eventCounts),
    lookback_days: data.lookbackDays,
    events_error: data.events.error ?? null,
    verified_scope: "admin_logs stream readability only",
    siem_consumption_verified: false,
  };
  const streamManualEvidence = "Admin Console > Reports and Box Shield > SIEM integrations, or the Events API consumer configuration: record which SIEM or log pipeline polls the enterprise event stream (service account and stream_position checkpoint), confirm it is receiving events, and record how alerting is configured.";
  findings.push(
    !eventsReadable
      ? finding(16, "manual", `The enterprise event stream could not be read because ${unreadableReason(data.events)}; the admin_logs stream requires an admin or co-admin with report permissions or the manage_enterprise_properties scope.`, streamEvidence, streamManualEvidence)
      : events.length > 0
        ? finding(16, "pass", `Verified only that the enterprise admin_logs event stream is active and readable (${events.length} monitoring events in the last ${data.lookbackDays} days); the Box API does not expose whether a SIEM consumes the stream, so SIEM consumption still requires the manual evidence listed.`, streamEvidence, streamManualEvidence)
        : finding(16, "warn", `The enterprise event stream is readable but returned no monitoring events in the last ${data.lookbackDays} days, and the Box API does not expose whether a SIEM consumes the stream.`, streamEvidence, streamManualEvidence),
  );

  const anomalyEvents = events.filter((event) => /^(SHIELD_ALERT|CONTENT_WORKFLOW_ABNORMAL_DOWNLOAD_ACTIVITY|SHIELD_DOWNLOAD_BLOCKED|SHIELD_SHARED_LINK_ACCESS_BLOCKED|FILE_MARKED_MALICIOUS)$/.test(eventType(event)));
  const accessEvents = events.filter((event) => /^(DOWNLOAD|PREVIEW|FILE_WATERMARKED_DOWNLOAD)$/.test(eventType(event)));
  const anomalyRules = shieldRules.filter((rule) => /anomal|threat|download|session|location|malicious/i.test(`${asString(rule.rule_category) ?? ""} ${asString(rule.name) ?? ""}`));
  const monitoringEvidence = {
    anomaly_events: whenRead(data.events, anomalyEvents.length),
    content_access_events: whenRead(data.events, accessEvents.length),
    anomaly_detection_rules: shieldReadable ? anomalyRules.length : null,
    shield_rules_error: shieldReadable ? null : shieldUnreadableReason,
    events_error: data.events.error ?? null,
    lookback_days: data.lookbackDays,
  };
  const monitoringManualEvidence = "Admin Console > Shield > Threat Detection: confirm anomalous download, session, and location detection rules are enabled and alerts route to the security team.";
  const shieldConfigUnreadable = unreadableInventory("enterprise_configuration (shield)", data.configuration, "the configured Shield anomaly detection rules were not checked");
  const monitoringEventsUnreadable = unreadableInventory("enterprise_events", data.events, "Shield alert and block events were not checked");
  findings.push(capForUnreadableInventories(
    !eventsReadable && !shieldReadable
      ? finding(25, "manual", "Neither enterprise events nor Shield rules could be read, so content access monitoring cannot be confirmed from the API.", monitoringEvidence, monitoringManualEvidence)
      : anomalyRules.length > 0 || anomalyEvents.length > 0
        ? finding(25, "pass", `${shieldReadable ? String(anomalyRules.length) : "unread"} Shield anomaly detection rules and ${countOrUnread(data.events, anomalyEvents.length)} Shield alert or block events show content access monitoring is active.`, monitoringEvidence)
        : !shieldReadable
          ? finding(25, "warn", `Shield rule configuration could not be read because ${shieldUnreadableReason}, and no Shield alert or block events were observed among ${accessEvents.length} download and preview events; detection may depend on external analytics.`, monitoringEvidence, monitoringManualEvidence)
          : !eventsReadable
            ? finding(25, "warn", `No Shield anomaly detection rules exist and the enterprise event stream could not be read (${unreadableReason(data.events)}), so content access monitoring cannot be confirmed from the API.`, monitoringEvidence, monitoringManualEvidence)
            : accessEvents.length > 0
              ? finding(25, "warn", `${accessEvents.length} download and preview events are recorded, but no Shield anomaly rules or alerts were observed, so detection depends on external analytics.`, monitoringEvidence, "Confirm the SIEM applies anomaly detection to Box download and preview events, or enable Shield threat detection rules.")
              : data.events.truncated
                ? finding(25, "warn", `No Shield anomaly detection rules exist and no Shield alerts appeared in the ${events.length} sampled events, but the event collection stopped at the cap while Box reported more events, so alerts may exist beyond the sample; raise event_limit and rerun.`, monitoringEvidence, monitoringManualEvidence)
                : finding(25, "fail", "No Shield anomaly detection rules exist and no content access events were observed in the sampled window.", monitoringEvidence),
    [shieldConfigUnreadable, monitoringEventsUnreadable],
    monitoringManualEvidence,
  ));

  return {
    area: "shield_monitoring",
    title: "Box Shield and monitoring posture",
    summary: {
      enterprise_id: data.enterpriseId ?? null,
      shield_rules: shieldReadable ? shieldRules.length : null,
      information_barriers: whenRead(data.barriers, barriers.length),
      enabled_information_barriers: whenRead(data.barriers, enabledBarriers.length),
      shield_lists: whenRead(data.shieldLists, data.shieldLists.data.length),
      sampled_events: whenRead(data.events, events.length),
      anomaly_events: whenRead(data.events, anomalyEvents.length),
      lookback_days: data.lookbackDays,
    },
    findings: sortFindings(findings),
    errors: [
      ...datasetErrors("enterprise_configuration", data.configuration),
      ...datasetErrors("shield_information_barriers", data.barriers),
      ...datasetErrors("shield_information_barrier_segments", data.barrierSegments),
      ...datasetErrors("shield_lists", data.shieldLists),
      ...datasetErrors("enterprise_events", data.events),
    ],
    truncated: [
      ...datasetTruncations("shield_information_barriers", data.barriers),
      ...datasetTruncations("shield_information_barrier_segments", data.barrierSegments),
      ...datasetTruncations("enterprise_events", data.events, "event_limit"),
    ],
  };
}

export async function assessBoxShieldMonitoring(
  client: Pick<BoxReadClient, "getNow" | "resolveEnterpriseId" | "getEnterpriseConfiguration" | "listShieldInformationBarriers" | "listShieldInformationBarrierSegments" | "listShieldLists" | "listEnterpriseEvents">,
  options: BoxShieldOptions = {},
): Promise<BoxAssessmentResult> {
  return assessBoxShieldMonitoringData(await collectBoxShieldData(client, options));
}

async function readableSurface(
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<BoxAccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, status: "readable", count: countResolver?.(value) ?? null, httpStatus: null };
  } catch (error) {
    // Only a request the run actually issued may be named, so the label travels on the error; a failure raised before
    // any request (for example an unresolved enterprise ID) leaves the endpoint and status null.
    return {
      name,
      endpoint: requestOf(error) ?? null,
      status: "not_readable",
      count: null,
      error: errorMessage(error),
      httpStatus: error instanceof BoxApiError ? error.status : null,
    };
  }
}

function pageLength(value: unknown): number | undefined {
  const items = asObject(value)?.items;
  return Array.isArray(items) ? items.length : undefined;
}

export async function checkBoxAccess(
  client: Pick<
    BoxReadClient,
    | "getResolvedConfig"
    | "getCurrentUser"
    | "resolveEnterpriseId"
    | "getEnterpriseConfiguration"
    | "listUsers"
    | "listGroups"
    | "listEnterpriseEvents"
    | "listDevicePinners"
    | "listRetentionPolicies"
    | "listLegalHoldPolicies"
    | "listShieldInformationBarriers"
    | "listShieldLists"
    | "listCollaborationAllowlistEntries"
    | "listCollaborationAllowlistExemptTargets"
    | "listEnterpriseMetadataTemplates"
    | "getClassificationTemplate"
    | "listTermsOfServices"
  >,
): Promise<BoxAccessCheckResult> {
  const config = client.getResolvedConfig();
  const currentUserSurface = await readableSurface("current_user", "/users/me", () => client.getCurrentUser(), () => 1);
  const currentUser = currentUserSurface.status === "readable" ? await client.getCurrentUser().catch(() => ({})) : {};
  const enterpriseId = await client.resolveEnterpriseId().catch(() => undefined);

  const surfaces: BoxAccessSurface[] = [currentUserSurface];
  if (enterpriseId) {
    surfaces.push(
      await readableSurface("enterprise_configuration", `/enterprise_configurations/${enterpriseId}`, () => client.getEnterpriseConfiguration(), (value) => Object.keys(asObject(value) ?? {}).length),
    );
  } else {
    surfaces.push({
      name: "enterprise_configuration",
      endpoint: null,
      status: "not_configured",
      count: null,
      error: "Enterprise ID could not be resolved; set BOX_ENTERPRISE_ID.",
      httpStatus: null,
    });
  }
  surfaces.push(
    await readableSurface("users", "/users", () => client.listUsers(100), pageLength),
    await readableSurface("groups", "/groups", () => client.listGroups(100), pageLength),
    await readableSurface("enterprise_events", "/events?stream_type=admin_logs", () => client.listEnterpriseEvents({ limit: 50 }), pageLength),
    await readableSurface("device_pinners", `/enterprises/${enterpriseId ?? "{enterprise_id}"}/device_pinners`, () => client.listDevicePinners(100), pageLength),
    await readableSurface("retention_policies", "/retention_policies", () => client.listRetentionPolicies(100), pageLength),
    await readableSurface("legal_hold_policies", "/legal_hold_policies", () => client.listLegalHoldPolicies(100), pageLength),
    await readableSurface("shield_information_barriers", "/shield_information_barriers", () => client.listShieldInformationBarriers(100), pageLength),
    await readableSurface("shield_lists", "/shield_lists", () => client.listShieldLists(), pageLength),
    await readableSurface("collaboration_allowlist_entries", "/collaboration_whitelist_entries", () => client.listCollaborationAllowlistEntries(100), pageLength),
    await readableSurface("collaboration_allowlist_exempt_targets", "/collaboration_whitelist_exempt_targets", () => client.listCollaborationAllowlistExemptTargets(100), pageLength),
    await readableSurface("metadata_templates", "/metadata_templates/enterprise", () => client.listEnterpriseMetadataTemplates(100), pageLength),
    await readableSurface("classification_template", `/metadata_templates/enterprise/${CLASSIFICATION_TEMPLATE_KEY}/schema`, () => client.getClassificationTemplate(), () => 1),
    await readableSurface("terms_of_services", "/terms_of_services", () => client.listTermsOfServices(), pageLength),
  );

  const readable = new Set(surfaces.filter((surface) => surface.status === "readable").map((surface) => surface.name));
  const coreReadable = ["current_user", "enterprise_configuration", "users", "enterprise_events"].every((name) => readable.has(name));
  const status = coreReadable && readable.size >= 9 ? "healthy" : "limited";
  const identity = asString(asObject(currentUser)?.login) ?? asString(asObject(currentUser)?.name) ?? asString(asObject(currentUser)?.id) ?? "current Box principal";

  return {
    status,
    enterpriseId,
    authMode: config.authMode,
    surfaces,
    notes: [
      `Authenticated with ${config.authMode.toUpperCase()} as ${identity}${asString(asObject(currentUser)?.role) ? ` (role ${asString(asObject(currentUser)?.role)})` : ""}.`,
      enterpriseId ? `Using Box enterprise ${enterpriseId}.` : "Box enterprise ID could not be resolved.",
      `${readable.size}/${surfaces.length} Box audit surfaces are readable.`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run box_assess_identity_access, box_assess_sharing_collaboration, box_assess_data_governance, box_assess_shield_monitoring, or box_export_audit_bundle."
        : "Grant the Box app Manage users, Manage groups, Manage enterprise properties, and (with Governance or Shield licensing) Manage retention policies, Manage legal holds, and Shield read access, then re-authorize it in the Admin Console.",
  };
}

function statusLabel(status: BoxFindingStatus): string {
  switch (status) {
    case "pass":
      return "PASS";
    case "warn":
      return "WARN";
    case "fail":
      return "FAIL";
    case "manual":
      return "MANUAL";
    default: {
      const exhaustive: never = status;
      throw new Error(`Unhandled finding status: ${String(exhaustive)}`);
    }
  }
}

export function summarizeFindingStatuses(findings: BoxFinding[]): Record<BoxFindingStatus, number> {
  const summary: Record<BoxFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) summary[item.status] += 1;
  return summary;
}

function formatAccessCheckText(result: BoxAccessCheckResult): string {
  // A count, request, or status the probe did not observe renders as "-", never as a number or a constant path. The
  // note drops the request label (the Request column carries it whole) before it is shortened, so a cut never leaves a
  // partial endpoint in the output.
  const rows = result.surfaces.map((surface) => {
    const note = (surface.error ?? "").replace(surface.endpoint ? ` for ${surface.endpoint}` : "", "").replace(/\s+/g, " ");
    return [
      surface.name,
      surface.status,
      surface.count === undefined || surface.count === null ? "-" : String(surface.count),
      surface.httpStatus === null ? "-" : String(surface.httpStatus),
      surface.endpoint ?? "-",
      note.length > 120 ? `${note.slice(0, 120)}...` : note,
    ];
  });

  return [
    `Box access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "HTTP", "Request", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: BoxAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    statusLabel(item.status),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  const manualNotes = result.findings
    .filter((item) => item.manualEvidence)
    .map((item) => `- ${item.id}: ${item.manualEvidence}`);
  const counts = summarizeFindingStatuses(result.findings);

  return [
    result.title,
    "",
    `Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(manualNotes.length > 0 ? ["", "Manual evidence to collect:", ...manualNotes] : []),
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
    ...(result.truncated.length > 0 ? ["", "Truncated datasets:", ...result.truncated.map((note) => `- ${note}`)] : []),
  ].join("\n");
}

function markdownEscapePipes(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function buildExecutiveSummary(config: BoxResolvedConfig, enterpriseId: string | undefined, assessments: BoxAssessmentResult[], errors: string[], truncated: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeFindingStatuses(findings);
  const priority = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
    .slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");

  return [
    "# Box Security Inspector Executive Summary",
    "",
    `- Enterprise: ${enterpriseId ?? "unknown"}`,
    `- Auth mode: ${config.authMode}`,
    `- Config source chain: ${config.sourceChain.join(" -> ")}`,
    `- Generated: ${new Date().toISOString()}`,
    `- Controls assessed: ${findings.length} of ${Object.keys(BOX_CONTROLS).length}`,
    `- Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(priority.length > 0
      ? priority.map((item) => `- ${item.id} ${item.title} (${item.severity.toUpperCase()} / ${statusLabel(item.status)}): ${item.summary}`)
      : ["- No failing or warning findings were generated."]),
    "",
    "## Manual Evidence Required",
    "",
    ...(manual.length > 0
      ? manual.map((item) => `- ${item.id} ${item.title}: ${item.manualEvidence ?? item.summary}`)
      : ["- No controls require manual evidence."]),
    ...(errors.length > 0 ? ["", "## Partial Collection Warnings", "", ...errors.map((error) => `- ${error}`)] : []),
    ...(truncated.length > 0 ? ["", "## Truncated Datasets", "", ...truncated.map((note) => `- ${note}`)] : []),
    "",
  ].join("\n");
}

function severityRank(severity: BoxSeverity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default: {
      const exhaustive: never = severity;
      throw new Error(`Unhandled severity: ${String(exhaustive)}`);
    }
  }
}

function mappingFor(item: BoxFinding, framework: BoxFramework): string {
  return BOX_CONTROLS[item.control]?.mappings[framework] ?? "-";
}

function buildUnifiedMatrix(findings: BoxFinding[]): string {
  const lines = [
    "# Unified Compliance Matrix",
    "",
    `| Control | Title | ${FRAMEWORK_ORDER.join(" | ")} | Status |`,
    `| --- | --- | ${FRAMEWORK_ORDER.map(() => "---").join(" | ")} | --- |`,
  ];
  for (const item of findings) {
    lines.push(`| ${item.id} | ${markdownEscapePipes(item.title)} | ${FRAMEWORK_ORDER.map((framework) => mappingFor(item, framework)).join(" | ")} | ${statusLabel(item.status)} |`);
  }
  return `${lines.join("\n")}\n`;
}

function buildFrameworkReport(title: string, framework: BoxFramework, findings: BoxFinding[]): string {
  const lines = [
    `# ${title}`,
    "",
    "| Control | Check | Mapping | Severity | Status | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
  ];
  for (const item of findings) {
    lines.push(
      `| ${item.id} | ${markdownEscapePipes(item.title)} | ${mappingFor(item, framework)} | ${item.severity} | ${statusLabel(item.status)} | ${markdownEscapePipes(item.summary)} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

function projectEventDataset(dataset: CollectedDataset<JsonRecord[]>): CollectedDataset<JsonRecord[]> {
  return { ...dataset, data: dataset.data.map(projectEnterpriseEvent) };
}

/**
 * The value a core_data snapshot file carries: the records when the read completed (a readable-but-empty list stays
 * []), and the not-collected marker when the read was denied, errored, or never requested, so a bundle consumer cannot
 * mistake a denial for an empty inventory.
 */
function snapshotValue(dataset: CollectedDataset<unknown>): unknown {
  return isRead(dataset) || isPartialChildMap(dataset) ? dataset.data : notReadableMarker(dataset);
}

/**
 * True for a per-parent child map whose parent listing was read and some, but not all, child reads completed: the map
 * itself is the truthful snapshot, since every denied child already carries its own marker. A map none of whose reads
 * completed is not partial; it is written as a single marker so no flag or count defaults from it.
 */
function isPartialChildMap(dataset: CollectedDataset<unknown>): boolean {
  if (isRead(dataset) || dataset.notRequested) return false;
  const values = Object.values(asObject(dataset.data) ?? {});
  return values.some((value) => Array.isArray(value)) && values.every((value) => Array.isArray(value) || isNotCollectedMarker(value));
}

type CollectionStatusLabel = "collected" | "truncated" | "partial" | "denied" | "error" | "not-requested";

function collectionStatusLabel(dataset: CollectedDataset<unknown>): CollectionStatusLabel {
  if (dataset.notRequested) return "not-requested";
  if (isPartialChildMap(dataset)) return "partial";
  if (!isRead(dataset)) return dataset.statusCode === 401 || dataset.statusCode === 403 ? "denied" : "error";
  return dataset.truncated === true ? "truncated" : "collected";
}

/**
 * One collection_status.json row. Count, complete, and truncated describe a read that happened; a read that was denied,
 * errored, or never requested renders them null behind an explicit collected: false so no flag defaults, and a child
 * map with some denied children reports the records it did observe as partial.
 */
function collectionStatusEntry(pathname: string, dataset: CollectedDataset<unknown>): JsonRecord {
  const read = isRead(dataset);
  const partial = isPartialChildMap(dataset);
  return {
    file: pathname,
    collected: read || partial,
    status: collectionStatusLabel(dataset),
    count: read || partial ? datasetRecordCount(dataset.data) : null,
    complete: read ? dataset.truncated !== true : partial ? false : null,
    truncated: read ? dataset.truncated === true : null,
    error: dataset.error ?? null,
    status_code: dataset.statusCode ?? null,
    endpoint: dataset.request ?? null,
  };
}

function buildQuickReference(): string {
  return [
    "# Box Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains the Box API responses used during this assessment; enterprise events are projected to the actor, source, and timing fields the verdicts read, and any credential-shaped field (token, secret, password, api key) is replaced with [REDACTED] before it is written.",
    "- `core_data/collection_status.json` records, per snapshot file, whether the read happened, the record count, any read error, and whether the list was truncated at its cap; truncated lists never support a PASS that depends on the absence of a record.",
    "- A snapshot whose read was denied, failed, or was never requested is written as a marker object (`collected: false` with the observed status, request, and error) rather than an empty list, so a denial is never mistaken for an empty inventory; a readable-but-empty inventory stays `[]`.",
    "- `analysis/` contains normalized findings and per-area assessment summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Findings with status MANUAL list the Admin Console evidence a human must collect.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/findings.json` for the supporting evidence behind each finding",
    "",
    "Credentials are never written into the bundle.",
    "",
  ].join("\n");
}

export async function exportBoxAuditBundle(
  client: Pick<
    BoxReadClient,
    | "getResolvedConfig"
    | "getNow"
    | "getCurrentUser"
    | "resolveEnterpriseId"
    | "getEnterpriseConfiguration"
    | "listUsers"
    | "listGroups"
    | "listEnterpriseEvents"
    | "listDevicePinners"
    | "listRetentionPolicies"
    | "listRetentionPolicyAssignments"
    | "listLegalHoldPolicies"
    | "listLegalHoldPolicyAssignments"
    | "listShieldInformationBarriers"
    | "listShieldInformationBarrierSegments"
    | "listShieldLists"
    | "listCollaborationAllowlistEntries"
    | "listCollaborationAllowlistExemptTargets"
    | "listEnterpriseMetadataTemplates"
    | "getClassificationTemplate"
    | "listTermsOfServices"
  >,
  config: BoxResolvedConfig,
  outputRoot: string,
  options: BoxExportOptions = {},
): Promise<BoxAuditBundleResult> {
  const access = await checkBoxAccess(client);
  const identityData = await collectBoxIdentityData(client, options);
  const sharingData = await collectBoxSharingData(client, options);
  const governanceData = await collectBoxGovernanceData(client, options);
  const shieldData = await collectBoxShieldData(client, options);
  const groups = await collectList(() => client.listGroups());
  const assessments = [
    assessBoxIdentityAccessData(identityData, options),
    assessBoxSharingCollaborationData(sharingData, options),
    assessBoxDataGovernanceData(governanceData),
    assessBoxShieldMonitoringData(shieldData),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set([...assessments.flatMap((assessment) => assessment.errors), ...datasetErrors("groups", groups)])];
  const truncated = [...new Set([...assessments.flatMap((assessment) => assessment.truncated), ...datasetTruncations("groups", groups)])];
  const enterpriseId = access.enterpriseId ?? identityData.enterpriseId;

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(enterpriseId ?? "box-enterprise")}-audit-bundle`);

  const coreDatasets: Array<[string, CollectedDataset<unknown>]> = [
    ["core_data/current_user.json", identityData.currentUser],
    ["core_data/users.json", identityData.users],
    ["core_data/groups.json", groups],
    ["core_data/enterprise_events_activity.json", projectEventDataset(identityData.events)],
    ["core_data/enterprise_events_sharing.json", projectEventDataset(sharingData.events)],
    ["core_data/enterprise_events_shield.json", projectEventDataset(shieldData.events)],
    ["core_data/device_pinners.json", governanceData.devicePinners],
    ["core_data/classification_template.json", governanceData.classificationTemplate],
    ["core_data/metadata_templates.json", governanceData.metadataTemplates],
    ["core_data/retention_policies.json", governanceData.retentionPolicies],
    ["core_data/retention_policy_assignments.json", governanceData.retentionAssignments],
    ["core_data/legal_hold_policies.json", governanceData.legalHoldPolicies],
    ["core_data/legal_hold_policy_assignments.json", governanceData.legalHoldAssignments],
    ["core_data/shield_information_barriers.json", shieldData.barriers],
    ["core_data/shield_information_barrier_segments.json", shieldData.barrierSegments],
    ["core_data/shield_lists.json", shieldData.shieldLists],
    ["core_data/collaboration_allowlist_entries.json", sharingData.allowlistEntries],
    ["core_data/collaboration_allowlist_exempt_targets.json", sharingData.exemptTargets],
    ["core_data/terms_of_services.json", sharingData.termsOfServices],
  ];
  const configurationDatasets = [identityData.configuration, sharingData.configuration, governanceData.configuration, shieldData.configuration];
  const readConfigurations = configurationDatasets.filter(isRead);
  const mergedConfiguration: JsonRecord = Object.assign({}, ...readConfigurations.map((dataset) => dataset.data));
  const configurationErrors = [...new Set(configurationDatasets.map((dataset) => dataset.error).filter((error): error is string => Boolean(error)))];
  const failedConfiguration = configurationDatasets.find((dataset) => !isRead(dataset));
  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    // A configuration none of the four category reads could fetch is written as a marker, never as {}.
    ["core_data/enterprise_configuration.json", readConfigurations.length > 0 || !failedConfiguration ? mergedConfiguration : notReadableMarker(failedConfiguration)],
    ...coreDatasets.map(([pathname, dataset]): [string, unknown] => [pathname, snapshotValue(dataset)]),
    ["core_data/collection_status.json", {
      generated_at: new Date().toISOString(),
      datasets: [
        {
          file: "core_data/enterprise_configuration.json",
          collected: readConfigurations.length > 0,
          status: readConfigurations.length === 0 && failedConfiguration
            ? collectionStatusLabel(failedConfiguration)
            : configurationErrors.length > 0 ? "partial" : "collected",
          count: readConfigurations.length > 0 ? Object.keys(mergedConfiguration).length : null,
          complete: readConfigurations.length > 0 ? configurationErrors.length === 0 : null,
          truncated: readConfigurations.length > 0 ? false : null,
          error: configurationErrors.length > 0 ? configurationErrors.join("; ") : null,
          status_code: failedConfiguration?.statusCode ?? null,
          endpoint: failedConfiguration?.request ?? null,
        },
        ...coreDatasets.map(([pathname, dataset]) => collectionStatusEntry(pathname, dataset)),
      ],
      truncated_datasets: truncated,
    }],
  ];
  for (const [pathname, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathname, serializeJson(redactCredentialValues(value)));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    generated_at: new Date().toISOString(),
    enterprise_id: enterpriseId ?? null,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    status_counts: summarizeFindingStatuses(findings),
    errors,
    truncated_datasets: truncated,
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, enterpriseId, assessments, errors, truncated));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, report.path, buildFrameworkReport(report.title, report.framework, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    enterprise_id: enterpriseId ?? null,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    base_url: config.baseUrl,
  }));
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
    auth_method: asString(value.auth_method),
    jwt_config_path: asString(value.jwt_config_path),
    jwt_passphrase: asString(value.jwt_passphrase),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    enterprise_id: asString(value.enterprise_id),
    subject_type: asString(value.subject_type),
    subject_id: asString(value.subject_id),
    access_token: asString(value.access_token),
    refresh_token: asString(value.refresh_token),
    config_path: asString(value.config_path),
    base_url: asString(value.base_url),
    token_url: asString(value.token_url),
    timeout_seconds: asNumber(value.timeout_seconds),
    max_retries: asNumber(value.max_retries),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    user_limit: asNumber(value.user_limit),
    event_limit: asNumber(value.event_limit),
    lookback_days: asNumber(value.lookback_days),
    max_admins: asNumber(value.max_admins),
    min_password_length: asNumber(value.min_password_length),
    max_session_hours: asNumber(value.max_session_hours),
  };
}

function normalizeSharingArgs(args: unknown): SharingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    event_limit: asNumber(value.event_limit),
    lookback_days: asNumber(value.lookback_days),
    stale_allowlist_days: asNumber(value.stale_allowlist_days),
    list_limit: asNumber(value.list_limit),
  };
}

function normalizeGovernanceArgs(args: unknown): GovernanceArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    list_limit: asNumber(value.list_limit),
  };
}

function normalizeShieldArgs(args: unknown): ShieldArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    event_limit: asNumber(value.event_limit),
    lookback_days: asNumber(value.lookback_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeSharingArgs(args),
    ...normalizeGovernanceArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function identityOptions(args: IdentityArgs): BoxIdentityOptions {
  return {
    userLimit: args.user_limit,
    eventLimit: args.event_limit,
    lookbackDays: args.lookback_days,
    maxAdmins: args.max_admins,
    minPasswordLength: args.min_password_length,
    maxSessionHours: args.max_session_hours,
  };
}

function sharingOptions(args: SharingArgs): BoxSharingOptions {
  return {
    eventLimit: args.event_limit,
    lookbackDays: args.lookback_days,
    staleAllowlistDays: args.stale_allowlist_days,
    listLimit: args.list_limit,
  };
}

function createClient(args: AuthArgs): BoxApiClient {
  return new BoxApiClient(resolveBoxConfiguration(args as JsonRecord));
}

const authParams = {
  auth_method: Type.Optional(Type.String({ description: "Box auth method: jwt, ccg, or oauth. Defaults to BOX_AUTH_METHOD or is inferred from the credentials provided." })),
  jwt_config_path: Type.Optional(Type.String({ description: "Path to the Box JWT app config JSON downloaded from the Developer Console. Defaults to BOX_JWT_CONFIG_PATH." })),
  jwt_passphrase: Type.Optional(Type.String({ description: "Passphrase for the encrypted JWT private key when it is not stored in the config file. Defaults to BOX_JWT_PASSPHRASE." })),
  client_id: Type.Optional(Type.String({ description: "Box app client ID. Defaults to BOX_CLIENT_ID or the JWT config file." })),
  client_secret: Type.Optional(Type.String({ description: "Box app client secret. Defaults to BOX_CLIENT_SECRET or the JWT config file." })),
  enterprise_id: Type.Optional(Type.String({ description: "Box enterprise ID. Defaults to BOX_ENTERPRISE_ID, the JWT config file, or the authenticated user's enterprise." })),
  subject_type: Type.Optional(Type.String({ description: "Token subject type for JWT and CCG: enterprise (service account, default) or user. Defaults to BOX_SUBJECT_TYPE." })),
  subject_id: Type.Optional(Type.String({ description: "Token subject ID for JWT and CCG when subject_type is user. Defaults to BOX_SUBJECT_ID." })),
  access_token: Type.Optional(Type.String({ description: "Pre-issued OAuth 2.0 access token. Defaults to BOX_ACCESS_TOKEN (also BOX_TOKEN or BOX_DEVELOPER_TOKEN)." })),
  refresh_token: Type.Optional(Type.String({ description: "OAuth 2.0 refresh token used with client_id and client_secret to renew the access token. Defaults to BOX_REFRESH_TOKEN." })),
  config_path: Type.Optional(Type.String({ description: "Path to a YAML config file. Defaults to BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml." })),
  base_url: Type.Optional(Type.String({ description: `Box Content API base URL. Defaults to ${DEFAULT_BASE_URL}.` })),
  token_url: Type.Optional(Type.String({ description: `Box OAuth 2.0 token endpoint. Defaults to ${DEFAULT_TOKEN_URL}.` })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  max_retries: Type.Optional(Type.Number({ description: "Retries for 429 and 5xx responses with backoff. Defaults to 3.", default: 3 })),
};

const eventParams = {
  event_limit: Type.Optional(Type.Number({ description: "Maximum enterprise events to sample from the admin_logs stream. Defaults to 2000.", default: 2000 })),
  lookback_days: Type.Optional(Type.Number({ description: "Event lookback window in days. Defaults to 90.", default: 90 })),
};

const identityParams = {
  ...eventParams,
  user_limit: Type.Optional(Type.Number({ description: "Maximum enterprise users to inspect. Defaults to 1000.", default: 1000 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin plus co-admin accounts before warning. Defaults to 10.", default: 10 })),
  min_password_length: Type.Optional(Type.Number({ description: "Minimum password length expected for a passing result. Defaults to 12.", default: 12 })),
  max_session_hours: Type.Optional(Type.Number({ description: "Maximum acceptable session duration in hours. Defaults to 24.", default: 24 })),
};

const listLimitParam = Type.Optional(Type.Number({ description: "Maximum records to inspect per paginated list (collaboration allowlist entries and exempt users, device pins, policies, and assignments). A list that hits the cap while Box reports more records is marked truncated and downgrades dependent findings to warn. Defaults to 500.", default: 500 }));

const sharingParams = {
  ...eventParams,
  stale_allowlist_days: Type.Optional(Type.Number({ description: "Age in days after which a collaboration allowlist entry is flagged for review. Defaults to 365.", default: 365 })),
  list_limit: listLimitParam,
};

const governanceParams = {
  list_limit: listLimitParam,
};

function runTool<TArgs extends AuthArgs>(
  toolName: string,
  failureLabel: string,
  args: TArgs,
  run: (client: BoxApiClient, args: TArgs) => Promise<BoxAssessmentResult>,
) {
  return (async () => {
    try {
      const result = await run(createClient(args), args);
      return textResult(formatAssessmentText(result), { tool: toolName, ...result });
    } catch (error) {
      return errorResult(`${failureLabel} failed: ${errorMessage(error)}`, { tool: toolName });
    }
  })();
}

export function registerBoxTools(pi: any): void {
  pi.registerTool({
    name: "box_check_access",
    label: "Check Box audit access",
    description:
      "Validate read-only Box Content API access across the current principal, enterprise configuration, users, groups, enterprise events, device pins, retention and legal hold policies, Shield barriers and lists, collaboration allowlist, metadata and classification templates, and terms of service. Supports JWT, Client Credentials Grant, and OAuth 2.0 tokens.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkBoxAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "box_check_access", ...result });
      } catch (error) {
        return errorResult(`Box access check failed: ${errorMessage(error)}`, { tool: "box_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "box_assess_identity_access",
    label: "Assess Box identity and access",
    description:
      "Assess Box identity and access controls: SSO enforcement, 2FA for admins and all users, admin role minimization, co-admin scoping, password policy strength, session duration, IP allowlisting, and inactive user detection (spec controls 1, 2, 3, 17, 18, 21, 22, 23, 24).",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      return runTool("box_assess_identity_access", "Box identity and access assessment", args, (client) =>
        assessBoxIdentityAccess(client, identityOptions(args)));
    },
  });

  pi.registerTool({
    name: "box_assess_sharing_collaboration",
    label: "Assess Box sharing and collaboration",
    description:
      "Assess Box sharing and collaboration controls: external collaboration restrictions, allowlist audit, shared link defaults, expiration, password requirements, watermarking, app approval, and custom terms of service (spec controls 4, 5, 6, 7, 8, 9, 19, 20).",
    parameters: Type.Object({ ...authParams, ...sharingParams }),
    prepareArguments: normalizeSharingArgs,
    async execute(_toolCallId: string, args: SharingArgs) {
      return runTool("box_assess_sharing_collaboration", "Box sharing and collaboration assessment", args, (client) =>
        assessBoxSharingCollaboration(client, sharingOptions(args)));
    },
  });

  pi.registerTool({
    name: "box_assess_data_governance",
    label: "Assess Box data governance",
    description:
      "Assess Box data governance controls: device trust and pins, classification labels, retention policies, and legal hold policies (spec controls 10, 11, 12, 13).",
    parameters: Type.Object({ ...authParams, ...governanceParams }),
    prepareArguments: normalizeGovernanceArgs,
    async execute(_toolCallId: string, args: GovernanceArgs) {
      return runTool("box_assess_data_governance", "Box data governance assessment", args, (client) =>
        assessBoxDataGovernance(client, { listLimit: args.list_limit }));
    },
  });

  pi.registerTool({
    name: "box_assess_shield_monitoring",
    label: "Assess Box Shield and monitoring",
    description:
      "Assess Box Shield and monitoring controls: Shield smart access and threat detection rules, information barriers, enterprise event streaming, and content access monitoring (spec controls 14, 15, 16, 25).",
    parameters: Type.Object({ ...authParams, ...eventParams }),
    prepareArguments: normalizeShieldArgs,
    async execute(_toolCallId: string, args: ShieldArgs) {
      return runTool("box_assess_shield_monitoring", "Box Shield and monitoring assessment", args, (client) =>
        assessBoxShieldMonitoring(client, { eventLimit: args.event_limit, lookbackDays: args.lookback_days }));
    },
  });

  pi.registerTool({
    name: "box_export_audit_bundle",
    label: "Export Box audit bundle",
    description:
      "Export a Box audit package covering all 25 spec controls with raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP (compliance/), a quick reference, an error log for partial collection, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      ...identityParams,
      ...sharingParams,
      ...governanceParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveBoxConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportBoxAuditBundle(new BoxApiClient(config), config, outputRoot, {
          ...identityOptions(args),
          ...sharingOptions(args),
          listLimit: args.list_limit,
        });
        return textResult(
          [
            "Box audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "box_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Box audit bundle export failed: ${errorMessage(error)}`, { tool: "box_export_audit_bundle" });
      }
    },
  });
}
