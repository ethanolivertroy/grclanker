/**
 * Zoom organization audit tools for grclanker.
 *
 * Read-only Zoom account inspection across identity posture, collaboration
 * governance, and meeting security. Every endpoint, query parameter, and
 * response field read here is traceable to the public Zoom API reference
 * (developers.zoom.us); the ZOOM_DOCS constant records the page per endpoint.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { ConfigFileError, readJsonConfig } from "./hardening/index.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/zoom";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_GROUP_LIMIT = 50;
const DEFAULT_OPERATION_LOG_LIMIT = 300;
const DEFAULT_OPERATION_LOG_WINDOW_DAYS = 30;
const DEFAULT_MAX_ADMINS = 10;
const DEFAULT_MAX_RECORDING_RETENTION_DAYS = 120;
const DEFAULT_MAX_SESSION_INACTIVITY_MINUTES = 120;
const DEFAULT_ROLE_MEMBER_LIMIT = 3000;
const MAX_RATE_LIMIT_RETRIES = 3;
const MAX_RETRY_AFTER_MS = 30_000;
const MAX_LIST_PAGES = 500;
const REDACTED = "[REDACTED]";
const DEFAULT_CONFIG_FILE_NAMES = [".zoom.json", ".grclanker-zoom.json"];

/**
 * Public Zoom API reference pages consulted for each endpoint. Page size
 * maxima, option query values, and field names below come from these pages.
 */
export const ZOOM_DOCS = {
  oauthServerToServer: "https://developers.zoom.us/docs/internal-apps/s2s-oauth/",
  pagination: "https://developers.zoom.us/docs/api/pagination/",
  rateLimits: "https://developers.zoom.us/docs/api/rate-limits/",
  scopes: "https://developers.zoom.us/docs/integrations/oauth-scopes-overview/",
  accountSettings: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/settings",
  accountLockSettings: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/lock_settings",
  managedDomains: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/managed_domains",
  trustedDomains: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/trusted_domains",
  roles: "https://developers.zoom.us/docs/api/accounts/#tag/roles/GET/roles",
  roleMembers: "https://developers.zoom.us/docs/api/accounts/#tag/roles/GET/roles/{roleId}/members",
  users: "https://developers.zoom.us/docs/api/users/#tag/users/GET/users",
  user: "https://developers.zoom.us/docs/api/users/#tag/users/GET/users/{userId}",
  userSettings: "https://developers.zoom.us/docs/api/users/#tag/users/GET/users/{userId}/settings",
  groups: "https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups",
  groupSettings: "https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups/{groupId}/settings",
  groupLockSettings: "https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups/{groupId}/lock_settings",
  operationLogs: "https://developers.zoom.us/docs/api/meetings/#tag/reports/GET/report/operationlogs",
  // The Team Chat reference has no stable per-operation anchor; its OpenAPI
  // document carries GET /im/groups (List IM directory groups) and the
  // imgroup:read:admin scope.
  imGroups: "https://developers.zoom.us/docs/api/chat/",
  phoneAccountSettings: "https://developers.zoom.us/docs/api/phone/#tag/accounts/GET/phone/account_settings",
} as const;

/**
 * The GET /accounts/{accountId}/settings `option` views this tool reads. The
 * reference documents four values (meeting_authentication,
 * recording_authentication, security, meeting_security); the
 * recording_authentication view is not requested because no verdict reads it.
 */
const ACCOUNT_SETTINGS_OPTIONS = ["meeting_authentication", "security", "meeting_security"] as const;
/** The GET /accounts/{accountId}/lock_settings `option` view this tool reads (the only documented value). */
const LOCK_SETTINGS_OPTIONS = ["meeting_security"] as const;
/** Documented `setting_types` values read from GET /phone/account_settings. */
const PHONE_SETTING_TYPES = "auto_call_recording,ad_hoc_call_recording";
type LoginTypeCategory = "sso" | "social" | "password" | "other";

/**
 * `login_types` codes. GET /users (ZOOM_DOCS.users) documents the enum
 * [0, 1, 23, 24, 27, 97, 98, 100, 101] and describes 0, 1, 24, 27, 97, 99,
 * 100, and 101; GET /users/{userId} (ZOOM_DOCS.user) additionally describes
 * 98 (RingCentral OAuth), 99 (API user), and the China-only codes 11, 21,
 * and 23. Code 99 is described on both pages but absent from the GET /users
 * enum. social: third-party OAuth providers; password: Zoom-held credentials;
 * other: documented but neither SSO nor a personal provider, so never pass.
 */
const LOGIN_TYPE_CATALOG: Record<number, { label: string; category: LoginTypeCategory }> = {
  0: { label: "Facebook OAuth", category: "social" },
  1: { label: "Google OAuth", category: "social" },
  11: { label: "Phone number (China only, GET /users/{userId})", category: "password" },
  21: { label: "WeChat (China only, GET /users/{userId})", category: "social" },
  23: { label: "Alipay (China only, described on GET /users/{userId})", category: "social" },
  24: { label: "Apple OAuth", category: "social" },
  27: { label: "Microsoft OAuth", category: "social" },
  97: { label: "Mobile device", category: "other" },
  98: { label: "RingCentral OAuth (described on GET /users/{userId})", category: "social" },
  99: { label: "API user (described on both pages, absent from the GET /users enum)", category: "other" },
  100: { label: "Zoom Work email", category: "password" },
  101: { label: "Single Sign-On (SSO)", category: "sso" },
};
const SSO_LOGIN_TYPE = 101;

function loginTypeCategory(code: number): LoginTypeCategory | "undocumented" {
  return LOGIN_TYPE_CATALOG[code]?.category ?? "undocumented";
}

function loginCodesByCategory(category: LoginTypeCategory): number[] {
  return Object.entries(LOGIN_TYPE_CATALOG)
    .filter(([, entry]) => entry.category === category)
    .map(([code]) => Number(code))
    .sort((a, b) => a - b);
}

export type ZoomFramework = "FedRAMP" | "CMMC" | "SOC 2" | "CIS" | "PCI-DSS" | "STIG" | "IRAP" | "ISMAP";

export const ZOOM_FRAMEWORKS: ZoomFramework[] = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"];

export interface ZoomSpecControl {
  number: number;
  name: string;
  mappings: Record<ZoomFramework, string>;
}

function control(number: number, name: string, ...ids: string[]): ZoomSpecControl {
  const mappings = Object.fromEntries(ZOOM_FRAMEWORKS.map((framework, index) => [framework, ids[index]])) as Record<ZoomFramework, string>;
  return { number, name, mappings };
}

/** Section 4 and 5 of specs/zoom-sec-inspector.spec.md. */
export const ZOOM_SPEC_CONTROLS: ZoomSpecControl[] = [
  control(1, "Meeting password enforcement enabled", "AC-3", "AC.L2-3.1.1", "CC6.1", "5.2", "8.3.1", "SRG-APP-000033", "ISM-0974", "8.1.1"),
  control(2, "Waiting room enabled by default", "AC-3", "AC.L2-3.1.2", "CC6.1", "5.2", "7.1.1", "SRG-APP-000033", "ISM-0974", "8.1.1"),
  control(3, "Screen sharing restricted to host only", "AC-3", "AC.L2-3.1.5", "CC6.1", "5.3", "7.1.2", "SRG-APP-000038", "ISM-1146", "8.1.2"),
  control(4, "Recording consent notification enabled", "AU-14", "AU.L2-3.3.1", "CC7.2", "8.1", "10.1", "SRG-APP-000092", "ISM-0580", "12.1.1"),
  control(5, "SSO enforcement for all users", "IA-2", "IA.L2-3.5.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "8.2.1"),
  control(6, "Two-factor authentication for admins", "IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.5", "8.3.2", "SRG-APP-000149", "ISM-1401", "8.2.2"),
  control(7, "End-to-end encryption available and default", "SC-8(1)", "SC.L2-3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0487", "10.1.1"),
  control(8, "Chat encryption enabled", "SC-8", "SC.L2-3.13.1", "CC6.7", "14.4", "4.1", "SRG-APP-000439", "ISM-0487", "10.1.1"),
  control(9, "File transfer in meetings restricted", "SC-7", "SC.L2-3.13.6", "CC6.6", "13.1", "1.3.1", "SRG-APP-000383", "ISM-1284", "10.2.1"),
  control(10, "Cloud recording auto-delete policy configured", "SI-12", "MP.L2-3.8.3", "CC6.5", "3.1", "3.1", "SRG-APP-000504", "ISM-0261", "7.1.1"),
  control(11, "Cloud recording auto-delete days within retention policy", "SI-12", "MP.L2-3.8.3", "CC6.5", "3.1", "3.1", "SRG-APP-000504", "ISM-0261", "7.1.1"),
  control(12, "External contacts restricted", "AC-4", "AC.L2-3.1.3", "CC6.6", "13.4", "1.3.4", "SRG-APP-000039", "ISM-1284", "8.1.3"),
  control(13, "Vanity URL configured and secured", "IA-8", "IA.L2-3.5.2", "CC6.1", "4.1", "8.1.1", "SRG-APP-000153", "ISM-1557", "8.2.1"),
  control(14, "Managed domains verified", "IA-8", "IA.L2-3.5.2", "CC6.1", "4.1", "8.1.1", "SRG-APP-000153", "ISM-1557", "8.2.1"),
  control(15, "IM group restrictions enforced", "AC-4", "AC.L2-3.1.3", "CC6.6", "13.4", "7.1.2", "SRG-APP-000039", "ISM-1284", "8.1.3"),
  control(16, "Sign-in methods restricted (no personal email)", "IA-5", "IA.L2-3.5.7", "CC6.1", "4.1", "8.2.1", "SRG-APP-000170", "ISM-1557", "8.2.3"),
  control(17, "Session timeout configured within organizational policy", "AC-12", "AC.L2-3.1.10", "CC6.1", "5.6", "8.1.8", "SRG-APP-000295", "ISM-1164", "8.3.1"),
  control(18, "Data routing control enabled (data residency)", "SC-7", "SC.L2-3.13.1", "CC6.6", "13.1", "1.3.1", "SRG-APP-000383", "ISM-1037", "10.2.1"),
  control(19, "Zoom Phone recording policies enforced", "AU-14", "AU.L2-3.3.1", "CC7.2", "8.1", "10.1", "SRG-APP-000092", "ISM-0580", "12.1.1"),
  control(20, "Local recording disabled or restricted", "AC-3", "MP.L2-3.8.1", "CC6.1", "3.1", "3.4.1", "SRG-APP-000033", "ISM-0261", "7.1.2"),
  control(21, "Meeting password locked at account level", "AC-3", "AC.L2-3.1.1", "CC6.1", "5.2", "8.3.1", "SRG-APP-000033", "ISM-0974", "8.1.1"),
  control(22, "Embed password in join link disabled", "IA-5", "IA.L2-3.5.10", "CC6.1", "5.2", "8.2.1", "SRG-APP-000170", "ISM-0974", "8.2.3"),
  control(23, "Only authenticated users can join meetings", "IA-2", "IA.L2-3.5.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "8.2.1"),
  control(24, "Admin operation log retention verified", "AU-11", "AU.L2-3.3.1", "CC7.2", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "12.1.2"),
  control(25, "Personal Meeting ID (PMI) usage restricted", "AC-3", "AC.L2-3.1.5", "CC6.1", "5.3", "8.1.1", "SRG-APP-000038", "ISM-0974", "8.1.2"),
];

export interface ZoomResolvedConfig {
  accountId: string;
  token?: string;
  clientId?: string;
  clientSecret?: string;
  baseUrl: string;
  oauthBaseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
  configFile?: string;
}

export type ZoomSurfaceStatus = "ok" | "denied" | "error" | "skipped";

export interface ZoomSurface<T = unknown> {
  name: string;
  endpoint: string;
  docUrl: string;
  status: ZoomSurfaceStatus;
  data?: T;
  error?: string;
  httpStatus?: number;
}

export interface ZoomListResult<T = JsonRecord> {
  items: T[];
  totalRecords?: number;
  truncated: boolean;
  pages: number;
}

export interface ZoomAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface ZoomAccessCheckResult {
  status: "healthy" | "limited";
  accountId: string;
  surfaces: ZoomAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type ZoomFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface ZoomFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: ZoomFindingStatus;
  summary: string;
  controls: number[];
  evidence?: JsonRecord;
  mappings: string[];
}

export interface ZoomAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: ZoomFinding[];
  errors: string[];
}

export interface ZoomAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface ZoomSettingsBundle {
  settings: JsonRecord;
  locks: JsonRecord;
  settingsSurfaces: ZoomSurface<JsonRecord>[];
  lockSurfaces: ZoomSurface<JsonRecord>[];
  /** Setting paths a verdict read; the export bundle projects settings to these paths only. */
  readPaths: Set<string>;
  /** Lock paths a verdict read; the export bundle projects lock settings to these paths only. */
  lockPaths: Set<string>;
}

export interface ZoomGroupPolicy {
  id: string;
  name: string;
  /** Base GET /groups/{id}/settings merged with the option=meeting_security view; status mirrors the base read. */
  settings: ZoomSurface<JsonRecord>;
  /** Base GET /groups/{id}/lock_settings merged with the option=meeting_security view; status mirrors the base read. */
  locks: ZoomSurface<JsonRecord>;
  /** Every settings view read for the group (base, option=meeting_security), kept so a denied view demotes and is disclosed. */
  settingsSurfaces: ZoomSurface<JsonRecord>[];
  /** Every lock view read for the group (base, option=meeting_security), kept for disclosure. */
  lockSurfaces: ZoomSurface<JsonRecord>[];
}

export interface ZoomSnapshot {
  accountId: string;
  collectedAt: string;
  currentUser: ZoomSurface<JsonRecord>;
  settings: ZoomSettingsBundle;
  users: ZoomSurface<ZoomListResult>;
  roles: ZoomSurface<ZoomListResult>;
  roleMembers: Record<string, ZoomSurface<ZoomListResult>>;
  groups: ZoomSurface<ZoomListResult>;
  groupPolicies: ZoomGroupPolicy[];
  imGroups: ZoomSurface<ZoomListResult>;
  managedDomains: ZoomSurface<ZoomListResult>;
  trustedDomains: ZoomSurface<ZoomListResult<unknown>>;
  operationLogs: ZoomSurface<ZoomListResult> & { from: string; to: string };
  phoneSettings: ZoomSurface<JsonRecord>;
}

export interface ZoomCollectionOptions {
  userLimit?: number;
  groupLimit?: number;
  operationLogLimit?: number;
  operationLogWindowDays?: number;
  now?: Date;
  include?: {
    identity?: boolean;
    collaboration?: boolean;
    meeting?: boolean;
  };
}

export interface ZoomIdentityOptions extends ZoomCollectionOptions {
  maxAdmins?: number;
  maxSessionInactivityMinutes?: number;
}

export interface ZoomCollaborationOptions extends ZoomCollectionOptions {
  maxRecordingRetentionDays?: number;
}

export interface ZoomMeetingSecurityOptions extends ZoomCollectionOptions {}

export type ZoomExportOptions = ZoomIdentityOptions & ZoomCollaborationOptions;

type CheckAccessArgs = {
  account_id?: string;
  token?: string;
  client_id?: string;
  client_secret?: string;
  base_url?: string;
  oauth_base_url?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  max_admins?: number;
  max_session_inactivity_minutes?: number;
};

type CollaborationArgs = CheckAccessArgs & {
  group_limit?: number;
  operation_log_limit?: number;
  max_recording_retention_days?: number;
};

type MeetingSecurityArgs = CheckAccessArgs & {
  group_limit?: number;
};

type ExportAuditBundleArgs = IdentityArgs & CollaborationArgs & {
  output_dir?: string;
};

export type ZoomClientLike = Pick<
  ZoomApiClient,
  | "getResolvedConfig"
  | "getCurrentUser"
  | "getAccountSettings"
  | "getAccountLockSettings"
  | "listUsers"
  | "listRoles"
  | "listRoleMembers"
  | "listGroups"
  | "getGroupSettings"
  | "getGroupLockSettings"
  | "listOperationLogs"
  | "listImGroups"
  | "getManagedDomains"
  | "listTrustedDomains"
  | "getPhoneAccountSettings"
>;

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
  return typeof value === "boolean" ? value : undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
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

/**
 * Bundle secret hygiene. Keys that carry credential material are redacted
 * (the key stays, the value becomes the marker); policy flags whose names
 * merely mention passwords (require_password_*, embed_password_*,
 * *_requirement) are not credentials and stay readable.
 */
const SENSITIVE_KEY_PATTERN = /(^|_)(token|secret|password|passcode|pwd|host_key|hostkey|private_key|certificate|cert|api_key|apikey|zak|credential|signature|sig)s?($|_)/i;
const POLICY_KEY_PATTERN = /^(require_|allow_|enable_|embed_|force_|only_|use_|show_|hide_|auto_)|(_requirement|_requirements|_policy|_protection|_protected|_enabled|_required|_length|_strength|_options|_type)$/i;
const SECRET_QUERY_PARAM_PATTERN = /([?&](?:pwd|passcode|password|token|access_token|refresh_token|tk|zak|sig|signature|api_key|apikey|secret|client_secret)=)[^&#\s"'<>]*/gi;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;

/**
 * Error-text hygiene (rule 9, error-body class). Every error string passes
 * through scrubErrorText: the ZoomApiError constructor, errorMessage (the
 * helper every collector uses), and the bundle write sink. A non-JSON
 * response body is never echoed at all (fetchJson substitutes status,
 * endpoint, content type, and byte length), so these rules guard the
 * documented JSON error fields that are echoed and any text assembled from
 * them. The patterns are unanchored so an embedded URL, header, or
 * name-value pair anywhere in free text is caught.
 */
const EMBEDDED_URL_QUERY_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()?#]+)\?[^\s"'<>()#]*/gi;
// Doc anchors such as #tag/accounts/GET/accounts/{accountId}/settings stay; a fragment carrying name=value pairs (implicit-flow tokens) is dropped.
const EMBEDDED_URL_FRAGMENT_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()#]+#)[^\s"'<>()]*=[^\s"'<>()]*/gi;
const BASIC_AUTH_PATTERN = /\bBasic\s+(?=[A-Za-z0-9+/=]*[0-9+/=])[A-Za-z0-9+/=]{16,}/g;
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookie)(["']?\s*[:=]\s*)(?!\s*\[REDACTED\])[^\s<>"'][^\r\n<>"']*/gi;
// client_id and clientId are listed because credentialValues() treats the resolved client id as a secret; the two lists must agree.
const CREDENTIAL_ASSIGNMENT_PATTERN = /\b((?:[a-z0-9_-]*(?:token|secret|password|passwd|passcode|session[_-]?id|sessionid|private[_-]?key|signature))|x-api-key|x-auth-token|api[_-]?key|apikey|client[_-]?id|clientid|authorization|jsessionid|session|pwd|sig|zak|tk)(["']?\s*[:=]\s*)(["']?)(?!Bearer\b|Basic\b)[^\s"'<>;,&]{6,}/gi;
// "/" is not a run character so URL and endpoint paths split into short segments; base64url, hex, and JWT material never contains it and Basic values have their own rule.
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+=_-]{16,}/g;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$/;

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key) && !POLICY_KEY_PATTERN.test(key);
}

function credentialValues(config: ZoomResolvedConfig): string[] {
  return [config.token, config.clientSecret, config.clientId]
    .filter((value): value is string => typeof value === "string" && value.trim().length >= 4);
}

/**
 * A run of 16 or more token characters is treated as a credential when it
 * carries a digit or mixed case. Plain lowercase words (meeting_authentication,
 * ad_hoc_call_recording) and uppercase error codes (INVALID_ACCESS_TOKEN) are
 * left alone. Arbitrary words in a response body are therefore not something
 * this heuristic can recognise, which is why fetchJson never echoes a non-JSON
 * body in the first place.
 */
function looksLikeToken(run: string): boolean {
  if (UPPERCASE_CODE_PATTERN.test(run)) return false;
  const hasDigit = /\d/.test(run);
  const mixedCase = /[a-z]/.test(run) && /[A-Z]/.test(run);
  return hasDigit || mixedCase;
}

export interface ScrubErrorTextOptions {
  /**
   * Apply the long-token heuristic. On by default because error text is the
   * only place a bare token can arrive; the bundle sink and data values turn
   * it off because Zoom identifiers (22-character user, group, and account
   * ids) are indistinguishable from tokens and are evidence, not secrets.
   */
  longTokens?: boolean;
}

export function scrubErrorText(text: string, secrets: string[] = [], options: ScrubErrorTextOptions = {}): string {
  let scrubbed = text;
  for (const secret of secrets) {
    scrubbed = scrubbed.split(secret).join(REDACTED);
  }
  scrubbed = scrubbed
    .replace(EMBEDDED_URL_QUERY_PATTERN, `$1?${REDACTED}`)
    .replace(EMBEDDED_URL_FRAGMENT_PATTERN, `$1${REDACTED}`)
    .replace(SECRET_QUERY_PARAM_PATTERN, `$1${REDACTED}`)
    .replace(BEARER_PATTERN, `Bearer ${REDACTED}`)
    .replace(BASIC_AUTH_PATTERN, `Basic ${REDACTED}`)
    .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`)
    .replace(CREDENTIAL_ASSIGNMENT_PATTERN, `$1$2$3${REDACTED}`);
  if (options.longTokens === false) return scrubbed;
  return scrubbed.replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTED : run));
}

/** Data values and bundle content: every rule except the long-token heuristic (see ScrubErrorTextOptions). */
function scrubDataText(text: string, secrets: string[]): string {
  return scrubErrorText(text, secrets, { longTokens: false });
}

function sanitizeValue(value: unknown, secrets: string[], redactLeaves = false): unknown {
  if (typeof value === "string") {
    return redactLeaves ? REDACTED : scrubDataText(value, secrets);
  }
  if (typeof value === "number") {
    return redactLeaves ? REDACTED : value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item, secrets, redactLeaves));
  }
  const record = asObject(value);
  if (!record) return value;
  const sanitized: JsonRecord = {};
  for (const [key, child] of Object.entries(record)) {
    const sensitive = redactLeaves || isSensitiveKey(key);
    if (sensitive && (typeof child === "string" || typeof child === "number")) {
      sanitized[key] = REDACTED;
    } else {
      sanitized[key] = sanitizeValue(child, secrets, sensitive);
    }
  }
  return sanitized;
}

function sanitizeSurface<T>(surface: ZoomSurface<T>, secrets: string[]): ZoomSurface<T> {
  return {
    ...surface,
    ...(surface.data === undefined ? {} : { data: sanitizeValue(surface.data, secrets) as T }),
    ...(surface.error === undefined ? {} : { error: scrubErrorText(surface.error, secrets) }),
  };
}

function projectPaths(source: JsonRecord, paths: Iterable<string>): JsonRecord {
  const projected: JsonRecord = {};
  for (const path of [...paths].sort()) {
    const segments = path.split(".");
    const value = getNestedValue(source, segments);
    if (value === undefined) continue;
    let cursor = projected;
    for (const segment of segments.slice(0, -1)) {
      const existing = asObject(cursor[segment]);
      if (!existing) cursor[segment] = {};
      cursor = asObject(cursor[segment]) as JsonRecord;
    }
    cursor[segments[segments.length - 1]] = value;
  }
  return projected;
}

function projectRecord(record: unknown, fields: readonly string[]): unknown {
  const source = asObject(record);
  if (!source) return typeof record === "string" ? record : null;
  return Object.fromEntries(fields.filter((field) => field in source).map((field) => [field, source[field]]));
}

/** Fields the verdicts read per list surface; everything else is dropped from the bundle. */
const BUNDLE_RECORD_FIELDS = {
  current_user: ["id", "email", "first_name"],
  users: ["id", "email", "type", "status", "login_types", "role_id"],
  roles: ["id", "name", "total_members"],
  role_members: ["id", "email"],
  groups: ["id", "name", "total_members"],
  im_groups: ["id", "name", "type", "total_members", "search_by_account", "search_by_domain", "search_by_ma_account"],
  managed_domains: ["domain", "status"],
  operation_logs: ["time", "action", "category_type", "operator"],
} as const;
const BUNDLE_PHONE_PATHS = [
  "auto_call_recording.enable",
  "auto_call_recording.locked",
  "auto_call_recording.locked_by",
  "auto_call_recording.recording_calls",
  "ad_hoc_call_recording.enable",
  "ad_hoc_call_recording.locked",
  "ad_hoc_call_recording.locked_by",
] as const;

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "zoom";
}

function formatDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function parseTimestamp(value: unknown): number | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
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
  for (let attempt = 1; attempt <= 50; attempt += 1) {
    const suffix = attempt === 1 ? "" : `-${attempt}`;
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

function encodeBasicAuth(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
}

function deriveDefaultOauthBaseUrl(baseUrl: string): string {
  return /zoomgov/i.test(baseUrl) ? "https://zoomgov.com" : "https://zoom.us";
}

interface ParsedJsonBody {
  payload: JsonRecord;
  /** False when the body was present but not JSON; such a body is described, never echoed. */
  parsed: boolean;
}

function parseJsonBody(rawText: string): ParsedJsonBody {
  if (rawText.length === 0) return { payload: {}, parsed: true };
  try {
    return { payload: asObject(JSON.parse(rawText)) ?? {}, parsed: true };
  } catch {
    return { payload: {}, parsed: false };
  }
}

function zoomErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  return [
    asString(object.message),
    asString(object.error),
    asString(object.reason),
    ...asArray(object.errors).map((item) =>
      asString(asObject(item)?.message) ?? asString(asObject(item)?.detail) ?? asString(item),
    ),
  ].filter((item): item is string => Boolean(item)).join("; ") || undefined;
}

export class ZoomApiError extends Error {
  readonly status: number;
  readonly retryAfterMs?: number;

  constructor(message: string, status: number, retryAfterMs?: number) {
    super(scrubErrorText(message));
    this.name = "ZoomApiError";
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

function isDeniedError(error: unknown): boolean {
  if (!(error instanceof ZoomApiError)) return false;
  if (error.status === 401 || error.status === 403) return true;
  return error.status === 400 && /scope|permission|not authorized|unauthorized/i.test(error.message);
}

function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

const CONFIG_FILE_OPTIONS = { label: "Zoom" } as const;

/**
 * Two guarded steps through the shared loader. The filesystem message carries
 * the path and its own wording, and JSON.parse quotes a 10-character source
 * window (or the whole file when it is 21 characters or shorter), which for an
 * unquoted credential value is the start of the credential. Neither message is
 * echoed: the loader renders fixed text plus the path, the errno or fixed
 * code, and the offset-derived position only. Like every other error string
 * this module creates, the result passes through scrubErrorText, path included.
 * The path has already been checked with existsSync, so the missing-file
 * result is a race with a deletion and is reported as the read failure it is.
 */
function readConfigFile(pathname: string): JsonRecord {
  let parsed: unknown;
  try {
    const read = readJsonConfig(pathname, CONFIG_FILE_OPTIONS);
    if (!read.ok) throw new ConfigFileError({ kind: "read", path: pathname, code: "ENOENT", label: CONFIG_FILE_OPTIONS.label });
    parsed = read.value;
  } catch (error) {
    if (!(error instanceof ConfigFileError)) throw error;
    throw new Error(scrubErrorText(error.message));
  }
  const object = asObject(parsed);
  if (!object) {
    throw new Error(`Zoom config file ${pathname} must contain a JSON object.`);
  }
  return object;
}

function discoverConfigFile(input: JsonRecord, env: NodeJS.ProcessEnv): string | undefined {
  const explicit = asString(input.config_file) ?? asString(env.ZOOM_CONFIG_FILE);
  if (explicit) {
    if (!existsSync(explicit)) {
      throw new Error(`Zoom config file not found: ${explicit}`);
    }
    return explicit;
  }
  const candidates = [
    ...DEFAULT_CONFIG_FILE_NAMES.map((name) => resolve(process.cwd(), name)),
    ...DEFAULT_CONFIG_FILE_NAMES.map((name) => join(homedir(), name)),
    join(homedir(), ".config", "grclanker", "zoom.json"),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

function configFileValue(file: JsonRecord, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = asString(file[key]);
    if (value) return value;
  }
  return undefined;
}

/**
 * Resolution order: explicit arguments, then environment variables, then a JSON
 * config file (config_file argument, ZOOM_CONFIG_FILE, ./.zoom.json, ~/.zoom.json,
 * ~/.config/grclanker/zoom.json). Server-to-Server OAuth credentials per
 * ZOOM_DOCS.oauthServerToServer; JWT apps are deprecated and not supported.
 */
export function resolveZoomConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): ZoomResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = discoverConfigFile(input, env);
  const fileValues = configFile ? readConfigFile(configFile) : {};

  const pick = (
    argKey: string,
    envKeys: string[],
    fileKeys: string[],
  ): { value?: string; source?: string } => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) return { value: fromArgs, source: `arguments-${argKey.replace(/_/g, "-")}` };
    for (const envKey of envKeys) {
      const fromEnv = asString(env[envKey]);
      if (fromEnv) return { value: fromEnv, source: `environment-${argKey.replace(/_/g, "-")}` };
    }
    const fromFile = configFileValue(fileValues, fileKeys);
    if (fromFile) return { value: fromFile, source: `config-file-${argKey.replace(/_/g, "-")}` };
    return {};
  };

  const account = pick("account_id", ["ZOOM_ACCOUNT_ID"], ["account_id", "accountId"]);
  if (!account.value) {
    throw new Error("ZOOM_ACCOUNT_ID, an account_id argument, or an account_id entry in the Zoom config file is required.");
  }
  sourceChain.push(account.source ?? "unknown");

  const token = pick("token", ["ZOOM_TOKEN", "ZOOM_ACCESS_TOKEN"], ["token", "access_token"]);
  const clientId = pick("client_id", ["ZOOM_CLIENT_ID"], ["client_id", "clientId"]);
  const clientSecret = pick("client_secret", ["ZOOM_CLIENT_SECRET"], ["client_secret", "clientSecret"]);
  if (!token.value && (!clientId.value || !clientSecret.value)) {
    throw new Error("Provide ZOOM_TOKEN or Zoom Server-to-Server OAuth credentials (ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET).");
  }
  if (token.value) {
    sourceChain.push(token.source ?? "unknown");
  } else {
    sourceChain.push(clientId.source ?? "unknown", clientSecret.source ?? "unknown");
  }

  const baseUrl = normalizeBaseUrl(
    pick("base_url", ["ZOOM_BASE_URL", "ZOOM_API_BASE_URL"], ["base_url", "baseUrl"]).value ?? "https://api.zoom.us/v2",
  );
  const oauthBaseUrl = normalizeBaseUrl(
    pick("oauth_base_url", ["ZOOM_OAUTH_BASE_URL"], ["oauth_base_url", "oauthBaseUrl"]).value ?? deriveDefaultOauthBaseUrl(baseUrl),
  );

  return {
    accountId: account.value,
    token: token.value,
    clientId: clientId.value,
    clientSecret: clientSecret.value,
    baseUrl,
    oauthBaseUrl,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.ZOOM_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
    configFile,
  };
}

function extractCollection(payload: unknown, key: string): unknown[] {
  const value = asObject(payload)?.[key];
  return Array.isArray(value) ? value : [];
}

function toRecords(items: unknown[]): JsonRecord[] {
  return items.map(asObject).filter((item): item is JsonRecord => Boolean(item));
}

export class ZoomApiClient {
  private readonly config: ZoomResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private accessTokenPromise?: Promise<string>;

  constructor(
    config: ZoomResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: (ms: number) => Promise<void>;
      /** Epoch milliseconds source for Retry-After dates and token expiry; defaults to Date.now. */
      now?: () => number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.now = options.now ?? (() => Date.now());
    if (config.token) {
      this.accessToken = config.token;
      this.accessTokenExpiresAt = Number.MAX_SAFE_INTEGER;
    }
  }

  getResolvedConfig(): ZoomResolvedConfig {
    return this.config;
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
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

  /**
   * Defensive fallback: ZOOM_DOCS.rateLimits documents HTTP 429 and asks
   * clients to wait before retrying but does not name a Retry-After header.
   * The header is honored when present (delta-seconds or HTTP-date, capped at
   * MAX_RETRY_AFTER_MS); otherwise the wait defaults to one second.
   */
  private parseRetryAfter(response: Response): number {
    const header = response.headers.get("retry-after");
    const seconds = asNumber(header);
    if (seconds !== undefined) return Math.min(Math.max(seconds, 1) * 1000, MAX_RETRY_AFTER_MS);
    const at = header ? Date.parse(header) : Number.NaN;
    if (Number.isFinite(at)) return Math.min(Math.max(at - this.now(), 1000), MAX_RETRY_AFTER_MS);
    return 1000;
  }

  private async fetchJson(
    url: string,
    init: RequestInit = {},
    options: { skipAuth?: boolean } = {},
  ): Promise<JsonRecord> {
    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const headers = new Headers(init.headers ?? {});
        if (!headers.has("accept")) headers.set("accept", "application/json");
        if (!options.skipAuth) {
          headers.set("authorization", `Bearer ${await this.getAccessToken()}`);
        }

        const response = await this.fetchImpl(url, { ...init, headers, signal: controller.signal });
        const rawText = await response.text();
        const body = parseJsonBody(rawText);
        if (response.status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
          await this.sleep(this.parseRetryAfter(response));
          continue;
        }
        if (!response.ok) {
          throw new ZoomApiError(
            this.describeFailure(url, init.method ?? "GET", response, rawText, body),
            response.status,
            response.status === 429 ? this.parseRetryAfter(response) : undefined,
          );
        }
        return body.payload;
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  /**
   * Builds the thrown message from what the response is, never from what a
   * non-JSON body says: HTTP status, method and endpoint, content type, and
   * byte length. Only the documented JSON error fields (message, error,
   * reason, errors[]) are echoed, and they pass through scrubErrorText with
   * the configured credentials, so a proxy error page, an HTML sign-in page,
   * or a debug dump can never reach a finding, a summary, or the bundle.
   */
  private describeFailure(
    url: string,
    method: string,
    response: Response,
    rawText: string,
    body: ParsedJsonBody,
  ): string {
    const target = new URL(url);
    const statusText = response.statusText ? ` ${response.statusText}` : "";
    const mediaType = (response.headers.get("content-type") ?? "").split(";")[0].trim() || "untyped";
    const bodyDescriptor = `${mediaType} body of ${Buffer.byteLength(rawText, "utf8")} bytes`;
    const secrets = credentialValues(this.config);
    const summary = body.parsed ? zoomErrorSummary(body.payload) : undefined;
    const detail = rawText.length === 0
      ? "empty body"
      : !body.parsed
        ? `non-JSON ${bodyDescriptor} omitted`
        : summary
          ? `${scrubErrorText(summary, secrets)} (${bodyDescriptor})`
          : `${bodyDescriptor} carried no documented message field`;
    // The status parenthetical sits after the endpoint so a path ending in
    // "token" followed by ": detail" cannot read as a token assignment.
    return scrubErrorText(
      `Zoom request failed for ${method.toUpperCase()} ${target.pathname}${target.search} (${response.status}${statusText}): ${detail}`,
      secrets,
    );
  }

  private async fetchAccessToken(): Promise<string> {
    if (!this.config.clientId || !this.config.clientSecret) {
      throw new Error("Zoom Server-to-Server OAuth credentials are missing.");
    }

    // ZOOM_DOCS.oauthServerToServer: POST /oauth/token with Basic client
    // credentials and a form-encoded body carrying grant_type and account_id.
    const body = new URLSearchParams({ grant_type: "account_credentials", account_id: this.config.accountId });
    const payload = await this.fetchJson(`${this.config.oauthBaseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${encodeBasicAuth(this.config.clientId, this.config.clientSecret)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    }, { skipAuth: true });

    const accessToken = asString(payload.access_token);
    if (!accessToken) {
      throw new Error("Zoom OAuth token response did not include access_token.");
    }

    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = this.now() + Math.max((expiresIn - 60) * 1000, 60_000);
    return accessToken;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && this.now() < this.accessTokenExpiresAt) {
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

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    return this.fetchJson(this.buildUrl(path, query));
  }

  /**
   * next_page_token pagination per ZOOM_DOCS.pagination. Runs to completion
   * unless a cap stops it; every cap exit (item limit, page cap, a
   * next_page_token that repeats or stops yielding items, or a total_records
   * above the collected count) reports truncated so verdicts demote.
   */
  async list<T = JsonRecord>(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize: number; mapItem?: (item: unknown) => T | undefined },
  ): Promise<ZoomListResult<T>> {
    const limit = clampNumber(options.limit, 10000, 1, 100000);
    const mapItem = options.mapItem ?? ((item: unknown) => item as T);
    const items: T[] = [];
    const seenTokens = new Set<string>();
    let nextPageToken: string | undefined;
    let totalRecords: number | undefined;
    let pages = 0;
    let truncated = false;

    while (true) {
      const payload = await this.get(path, {
        ...query,
        page_size: options.pageSize,
        next_page_token: nextPageToken,
      });
      pages += 1;
      totalRecords = asNumber(payload.total_records) ?? totalRecords;
      const pageItems = extractCollection(payload, collectionKey)
        .map(mapItem)
        .filter((item): item is T => item !== undefined);
      for (const item of pageItems) {
        if (items.length >= limit) {
          truncated = true;
          break;
        }
        items.push(item);
      }
      nextPageToken = asString(payload.next_page_token);
      if (truncated) break;
      if (!nextPageToken) break;
      if (pageItems.length === 0 || seenTokens.has(nextPageToken) || pages >= MAX_LIST_PAGES) {
        truncated = true;
        break;
      }
      seenTokens.add(nextPageToken);
    }

    if (!truncated && totalRecords !== undefined && totalRecords > items.length) {
      truncated = true;
    }
    return { items, totalRecords, truncated, pages };
  }

  /**
   * Single-response lists whose reference documents total_records: the list
   * is complete only when total_records is present and matches the returned
   * count; a missing total leaves completeness unknown, so truncated is true.
   */
  private singleResponseList(payload: JsonRecord, collectionKey: string): ZoomListResult {
    const items = toRecords(extractCollection(payload, collectionKey));
    const totalRecords = asNumber(payload.total_records);
    return { items, totalRecords, truncated: totalRecords === undefined || totalRecords > items.length, pages: 1 };
  }

  /** ZOOM_DOCS.user with the documented `me` alias. */
  async getCurrentUser(): Promise<JsonRecord> {
    return this.get("/users/me");
  }

  /** ZOOM_DOCS.accountSettings; option values: meeting_authentication, recording_authentication, security, meeting_security. */
  async getAccountSettings(option?: string): Promise<JsonRecord> {
    return this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/settings`, { option });
  }

  /** ZOOM_DOCS.accountLockSettings; option value: meeting_security. */
  async getAccountLockSettings(option?: string): Promise<JsonRecord> {
    return this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/lock_settings`, { option });
  }

  /** ZOOM_DOCS.users; page_size maximum 2000, default status filter is active. */
  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<ZoomListResult> {
    return this.list("/users", "users", { status: "active" }, { limit, pageSize: 300, mapItem: asObject });
  }

  /** ZOOM_DOCS.userSettings. */
  async getUserSettings(userIdValue: string, option?: string): Promise<JsonRecord> {
    return this.get(`/users/${encodeURIComponent(userIdValue)}/settings`, { option });
  }

  /** ZOOM_DOCS.roles; the reference documents no pagination parameters, only total_records and roles[]. */
  async listRoles(): Promise<ZoomListResult> {
    return this.singleResponseList(await this.get("/roles", { type: "common" }), "roles");
  }

  /** ZOOM_DOCS.roleMembers; page_size maximum 300. */
  async listRoleMembers(roleId: string, limit = DEFAULT_ROLE_MEMBER_LIMIT): Promise<ZoomListResult> {
    return this.list(`/roles/${encodeURIComponent(roleId)}/members`, "members", {}, { limit, pageSize: 300, mapItem: asObject });
  }

  /** ZOOM_DOCS.groups; page_size maximum 300. */
  async listGroups(limit = DEFAULT_GROUP_LIMIT): Promise<ZoomListResult> {
    return this.list("/groups", "groups", {}, { limit, pageSize: 300, mapItem: asObject });
  }

  /** ZOOM_DOCS.groupSettings; option values: meeting_authentication, recording_authentication, meeting_security. */
  async getGroupSettings(groupId: string, option?: string): Promise<JsonRecord> {
    return this.get(`/groups/${encodeURIComponent(groupId)}/settings`, { option });
  }

  /** ZOOM_DOCS.groupLockSettings; option value: meeting_security. */
  async getGroupLockSettings(groupId: string, option?: string): Promise<JsonRecord> {
    return this.get(`/groups/${encodeURIComponent(groupId)}/lock_settings`, { option });
  }

  /** ZOOM_DOCS.operationLogs; from and to (yyyy-mm-dd) are required, page_size maximum 300. */
  async listOperationLogs(from: string, to: string, limit = DEFAULT_OPERATION_LOG_LIMIT): Promise<ZoomListResult> {
    return this.list("/report/operationlogs", "operation_logs", { from, to }, { limit, pageSize: 300, mapItem: asObject });
  }

  /** ZOOM_DOCS.imGroups; the reference documents no pagination parameters, only total_records and groups[]. */
  async listImGroups(): Promise<ZoomListResult> {
    return this.singleResponseList(await this.get("/im/groups"), "groups");
  }

  /** ZOOM_DOCS.managedDomains; response keys total_records and domains[] with domain and status. */
  async getManagedDomains(): Promise<ZoomListResult> {
    return this.singleResponseList(await this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/managed_domains`), "domains");
  }

  /**
   * ZOOM_DOCS.trustedDomains; the documented response is the single array
   * trusted_domains[] (strings) with no total_records or pagination, so the
   * response is complete by contract and cannot report a partial view.
   */
  async listTrustedDomains(): Promise<ZoomListResult<unknown>> {
    const payload = await this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/trusted_domains`);
    const items = extractCollection(payload, "trusted_domains");
    return { items, truncated: false, pages: 1 };
  }

  /** ZOOM_DOCS.phoneAccountSettings with setting_types auto_call_recording,ad_hoc_call_recording. */
  async getPhoneAccountSettings(settingTypes = PHONE_SETTING_TYPES): Promise<JsonRecord> {
    return this.get("/phone/account_settings", { setting_types: settingTypes });
  }
}

async function captureSurface<T>(
  name: string,
  endpoint: string,
  docUrl: string,
  load: () => Promise<T>,
): Promise<ZoomSurface<T>> {
  try {
    const data = await load();
    return { name, endpoint, docUrl, status: "ok", data };
  } catch (error) {
    return {
      name,
      endpoint,
      docUrl,
      status: isDeniedError(error) ? "denied" : "error",
      error: errorMessage(error),
      httpStatus: error instanceof ZoomApiError ? error.status : undefined,
    };
  }
}

function skippedSurface<T>(name: string, endpoint: string, docUrl: string): ZoomSurface<T> {
  return { name, endpoint, docUrl, status: "skipped" };
}

function emptyList<T = JsonRecord>(): ZoomListResult<T> {
  return { items: [], truncated: false, pages: 0 };
}

const FAILURE_MESSAGE_PATTERN = /^Zoom request failed(?: for [A-Z]+ (\S+))? \([^)]*\): (.*)$/s;

/**
 * The scrubbed detail behind a failed surface without this module's own
 * status and endpoint prefix. A failure raised by another request (the token
 * exchange) keeps its full message so the real endpoint stays named.
 */
function surfaceDetail(surface: ZoomSurface): string | undefined {
  const error = surface.error?.trim();
  if (!error) return undefined;
  const match = FAILURE_MESSAGE_PATTERN.exec(error);
  if (!match) return error;
  const [, requestPath, detail] = match;
  const sameEndpoint = requestPath === undefined
    || requestPath.replace(/^\/v2/, "").split("?")[0] === surface.endpoint.split("?")[0];
  return sameEndpoint ? detail.trim() || undefined : error;
}

function surfaceCause(surface: ZoomSurface): string {
  switch (surface.status) {
    case "ok":
      return "readable";
    case "denied": {
      const detail = surfaceDetail(surface);
      return `${surface.endpoint} was denied (${surface.httpStatus ?? "401/403"}; check the app scopes and admin role)${detail ? `: ${detail}` : ""}`;
    }
    case "error":
      return `${surface.endpoint} failed: ${surface.error ?? "unknown error"}`;
    case "skipped":
      return `${surface.endpoint} was not collected`;
    default: {
      const exhaustive: never = surface.status;
      return exhaustive;
    }
  }
}

function surfaceErrors(surfaces: ZoomSurface[]): string[] {
  return surfaces
    .filter((surface) => surface.status === "denied" || surface.status === "error")
    .map((surface) => `${surface.name}: ${surfaceCause(surface)}`);
}

async function collectSettingsBundle(
  client: Pick<ZoomApiClient, "getResolvedConfig" | "getAccountSettings" | "getAccountLockSettings">,
): Promise<ZoomSettingsBundle> {
  const accountId = client.getResolvedConfig().accountId;
  const settingsPath = `/accounts/${accountId}/settings`;
  const locksPath = `/accounts/${accountId}/lock_settings`;

  const settingsSurfaces = await Promise.all([
    captureSurface("account_settings", settingsPath, ZOOM_DOCS.accountSettings, () => client.getAccountSettings()),
    ...ACCOUNT_SETTINGS_OPTIONS.map((option) =>
      captureSurface(`account_settings:${option}`, `${settingsPath}?option=${option}`, ZOOM_DOCS.accountSettings, () => client.getAccountSettings(option)),
    ),
  ]);
  const lockSurfaces = await Promise.all([
    captureSurface("account_lock_settings", locksPath, ZOOM_DOCS.accountLockSettings, () => client.getAccountLockSettings()),
    ...LOCK_SETTINGS_OPTIONS.map((option) =>
      captureSurface(`account_lock_settings:${option}`, `${locksPath}?option=${option}`, ZOOM_DOCS.accountLockSettings, () => client.getAccountLockSettings(option)),
    ),
  ]);

  return {
    settings: mergeSurfaces(settingsSurfaces),
    locks: mergeSurfaces(lockSurfaces),
    settingsSurfaces,
    lockSurfaces,
    readPaths: new Set<string>(),
    lockPaths: new Set<string>(),
  };
}

/**
 * Applied once per collection so every downstream consumer (tool text,
 * findings evidence, and the export bundle) sees credential-bearing keys
 * redacted and known credential values scrubbed from strings and errors.
 */
function sanitizeSnapshot(snapshot: ZoomSnapshot, secrets: string[]): ZoomSnapshot {
  const settings = snapshot.settings.settingsSurfaces.map((surface) => sanitizeSurface(surface, secrets));
  const locks = snapshot.settings.lockSurfaces.map((surface) => sanitizeSurface(surface, secrets));
  return {
    ...snapshot,
    currentUser: sanitizeSurface(snapshot.currentUser, secrets),
    settings: {
      ...snapshot.settings,
      settings: mergeSurfaces(settings),
      locks: mergeSurfaces(locks),
      settingsSurfaces: settings,
      lockSurfaces: locks,
    },
    users: sanitizeSurface(snapshot.users, secrets),
    roles: sanitizeSurface(snapshot.roles, secrets),
    roleMembers: Object.fromEntries(Object.entries(snapshot.roleMembers).map(([roleId, surface]) => [roleId, sanitizeSurface(surface, secrets)])),
    groups: sanitizeSurface(snapshot.groups, secrets),
    groupPolicies: snapshot.groupPolicies.map((policy) => ({
      ...policy,
      name: scrubDataText(policy.name, secrets),
      settings: sanitizeSurface(policy.settings, secrets),
      locks: sanitizeSurface(policy.locks, secrets),
      settingsSurfaces: policy.settingsSurfaces.map((surface) => sanitizeSurface(surface, secrets)),
      lockSurfaces: policy.lockSurfaces.map((surface) => sanitizeSurface(surface, secrets)),
    })),
    imGroups: sanitizeSurface(snapshot.imGroups, secrets),
    managedDomains: sanitizeSurface(snapshot.managedDomains, secrets),
    trustedDomains: sanitizeSurface(snapshot.trustedDomains, secrets),
    operationLogs: { ...sanitizeSurface(snapshot.operationLogs, secrets), from: snapshot.operationLogs.from, to: snapshot.operationLogs.to },
    phoneSettings: sanitizeSurface(snapshot.phoneSettings, secrets),
  };
}

function mergeSurfaces(surfaces: ZoomSurface<JsonRecord>[]): JsonRecord {
  const merged: JsonRecord = {};
  for (const surface of surfaces) {
    if (surface.status !== "ok") continue;
    for (const [key, value] of Object.entries(asObject(surface.data) ?? {})) {
      const existing = asObject(merged[key]);
      const incoming = asObject(value);
      merged[key] = existing && incoming ? { ...existing, ...incoming } : value;
    }
  }
  return merged;
}

async function collectGroupPolicies(
  client: Pick<ZoomApiClient, "getGroupSettings" | "getGroupLockSettings">,
  groups: JsonRecord[],
): Promise<ZoomGroupPolicy[]> {
  return Promise.all(groups.map(async (group) => {
    const id = asString(group.id) ?? "";
    const name = asString(group.name) ?? id;
    const [settings, meetingSecurity, locks, lockMeetingSecurity] = await Promise.all([
      captureSurface(`group_settings:${id}`, `/groups/${id}/settings`, ZOOM_DOCS.groupSettings, () => client.getGroupSettings(id)),
      captureSurface(`group_settings:${id}:meeting_security`, `/groups/${id}/settings?option=meeting_security`, ZOOM_DOCS.groupSettings, () => client.getGroupSettings(id, "meeting_security")),
      captureSurface(`group_lock_settings:${id}`, `/groups/${id}/lock_settings`, ZOOM_DOCS.groupLockSettings, () => client.getGroupLockSettings(id)),
      captureSurface(`group_lock_settings:${id}:meeting_security`, `/groups/${id}/lock_settings?option=meeting_security`, ZOOM_DOCS.groupLockSettings, () => client.getGroupLockSettings(id, "meeting_security")),
    ]);
    const settingsSurface: ZoomSurface<JsonRecord> = settings.status === "ok"
      ? { ...settings, data: mergeSurfaces([settings, meetingSecurity]) }
      : settings;
    const lockSurface: ZoomSurface<JsonRecord> = locks.status === "ok"
      ? { ...locks, data: mergeSurfaces([locks, lockMeetingSecurity]) }
      : locks;
    return {
      id,
      name,
      settings: settingsSurface,
      locks: lockSurface,
      settingsSurfaces: [settings, meetingSecurity],
      lockSurfaces: [locks, lockMeetingSecurity],
    };
  }));
}

function groupPolicySurfaces(snapshot: ZoomSnapshot): ZoomSurface<JsonRecord>[] {
  return snapshot.groupPolicies.flatMap((policy) => [...policy.settingsSurfaces, ...policy.lockSurfaces]);
}

function isAdminRole(role: JsonRecord): boolean {
  return /admin|owner/i.test(asString(role.name) ?? "");
}

export async function collectZoomSnapshot(
  client: ZoomClientLike,
  options: ZoomCollectionOptions = {},
): Promise<ZoomSnapshot> {
  const config = client.getResolvedConfig();
  const include = {
    identity: options.include?.identity ?? true,
    collaboration: options.include?.collaboration ?? true,
    meeting: options.include?.meeting ?? true,
  };
  const now = options.now ?? new Date();
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 100000);
  const groupLimit = clampNumber(options.groupLimit, DEFAULT_GROUP_LIMIT, 1, 500);
  const operationLogLimit = clampNumber(options.operationLogLimit, DEFAULT_OPERATION_LOG_LIMIT, 1, 10000);
  const windowDays = clampNumber(options.operationLogWindowDays, DEFAULT_OPERATION_LOG_WINDOW_DAYS, 1, 30);
  const from = formatDate(new Date(now.getTime() - windowDays * 86_400_000));
  const to = formatDate(now);

  const currentUser = await captureSurface("current_user", "/users/me", ZOOM_DOCS.user, () => client.getCurrentUser());
  const settings = await collectSettingsBundle(client);

  const users = include.identity
    ? await captureSurface("users", "/users", ZOOM_DOCS.users, () => client.listUsers(userLimit))
    : skippedSurface<ZoomListResult>("users", "/users", ZOOM_DOCS.users);
  const roles = include.identity
    ? await captureSurface("roles", "/roles", ZOOM_DOCS.roles, () => client.listRoles())
    : skippedSurface<ZoomListResult>("roles", "/roles", ZOOM_DOCS.roles);
  const roleMembers: Record<string, ZoomSurface<ZoomListResult>> = {};
  if (roles.status === "ok") {
    const adminRoles = (roles.data?.items ?? []).filter(isAdminRole);
    await Promise.all(adminRoles.map(async (role) => {
      const roleId = asString(role.id);
      if (!roleId) return;
      roleMembers[roleId] = await captureSurface(`role_members:${roleId}`, `/roles/${roleId}/members`, ZOOM_DOCS.roleMembers, () => client.listRoleMembers(roleId));
    }));
  }
  const managedDomains = include.identity
    ? await captureSurface("managed_domains", `/accounts/${config.accountId}/managed_domains`, ZOOM_DOCS.managedDomains, () => client.getManagedDomains())
    : skippedSurface<ZoomListResult>("managed_domains", `/accounts/${config.accountId}/managed_domains`, ZOOM_DOCS.managedDomains);

  const groups = include.meeting
    ? await captureSurface("groups", "/groups", ZOOM_DOCS.groups, () => client.listGroups(groupLimit))
    : skippedSurface<ZoomListResult>("groups", "/groups", ZOOM_DOCS.groups);
  const groupPolicies = groups.status === "ok"
    ? await collectGroupPolicies(client, (groups.data?.items ?? []).filter((group) => asString(group.id)))
    : [];

  const imGroups = include.collaboration
    ? await captureSurface("im_groups", "/im/groups", ZOOM_DOCS.imGroups, () => client.listImGroups())
    : skippedSurface<ZoomListResult>("im_groups", "/im/groups", ZOOM_DOCS.imGroups);
  const trustedDomains = include.collaboration
    ? await captureSurface("trusted_domains", `/accounts/${config.accountId}/trusted_domains`, ZOOM_DOCS.trustedDomains, () => client.listTrustedDomains())
    : skippedSurface<ZoomListResult<unknown>>("trusted_domains", `/accounts/${config.accountId}/trusted_domains`, ZOOM_DOCS.trustedDomains);
  const operationLogs = include.collaboration
    ? await captureSurface("operation_logs", `/report/operationlogs?from=${from}&to=${to}`, ZOOM_DOCS.operationLogs, () => client.listOperationLogs(from, to, operationLogLimit))
    : skippedSurface<ZoomListResult>("operation_logs", "/report/operationlogs", ZOOM_DOCS.operationLogs);
  const phoneSettings = include.collaboration
    ? await captureSurface("phone_account_settings", `/phone/account_settings?setting_types=${PHONE_SETTING_TYPES}`, ZOOM_DOCS.phoneAccountSettings, () => client.getPhoneAccountSettings())
    : skippedSurface<JsonRecord>("phone_account_settings", "/phone/account_settings", ZOOM_DOCS.phoneAccountSettings);

  return sanitizeSnapshot({
    accountId: config.accountId,
    collectedAt: now.toISOString(),
    currentUser,
    settings,
    users,
    roles,
    roleMembers,
    groups,
    groupPolicies,
    imGroups,
    managedDomains,
    trustedDomains,
    operationLogs: { ...operationLogs, from, to },
    phoneSettings,
  }, credentialValues(config));
}

function snapshotSurfaces(snapshot: ZoomSnapshot): ZoomSurface[] {
  return [
    snapshot.currentUser,
    ...snapshot.settings.settingsSurfaces,
    ...snapshot.settings.lockSurfaces,
    snapshot.users,
    snapshot.roles,
    ...Object.values(snapshot.roleMembers),
    snapshot.groups,
    ...groupPolicySurfaces(snapshot),
    snapshot.imGroups,
    snapshot.managedDomains,
    snapshot.trustedDomains,
    snapshot.operationLogs,
    snapshot.phoneSettings,
  ];
}

function controlMappings(controls: number[]): string[] {
  const mappings: string[] = [];
  for (const number of controls) {
    const spec = ZOOM_SPEC_CONTROLS.find((item) => item.number === number);
    if (!spec) continue;
    for (const framework of ZOOM_FRAMEWORKS) {
      const entry = `${framework} ${spec.mappings[framework]}`;
      if (!mappings.includes(entry)) mappings.push(entry);
    }
  }
  return mappings;
}

function finding(
  id: string,
  title: string,
  severity: ZoomFinding["severity"],
  controls: number[],
  status: ZoomFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): ZoomFinding {
  return { id, title, severity, status, summary, controls, evidence, mappings: controlMappings(controls) };
}

interface SettingRead {
  path: string;
  value: unknown;
  present: boolean;
}

function readSetting(bundle: ZoomSettingsBundle, path: string): SettingRead {
  bundle.readPaths.add(path);
  const value = getNestedValue(bundle.settings, path.split("."));
  return { path, value, present: value !== undefined };
}

function readLock(bundle: ZoomSettingsBundle, path: string): boolean | undefined {
  bundle.lockPaths.add(path);
  return asBoolean(getNestedValue(bundle.locks, path.split(".")));
}

function settingsUnreadable(bundle: ZoomSettingsBundle, surfaceName = "account_settings"): ZoomSurface | undefined {
  return bundle.settingsSurfaces.find((surface) => surface.name === surfaceName && surface.status !== "ok");
}

function manualForSurface(surface: ZoomSurface, evidenceToCollect: string): string {
  return `Manual: ${surfaceCause(surface)}. Collect ${evidenceToCollect} from the Zoom admin portal.`;
}

function manualForAbsentKey(path: string, docUrl: string, evidenceToCollect: string): string {
  return `Manual: ${path} was not present in the account settings response (documented at ${docUrl}); an absent key is unknown, not compliant. Confirm ${evidenceToCollect} in the Zoom admin portal.`;
}

function lockNote(locked: boolean | undefined, path: string, bundle: ZoomSettingsBundle): string {
  if (locked === true) return `${path} is locked at account level.`;
  if (locked === false) return `${path} is enabled but not locked, so groups and users may change it.`;
  return `${path} lock state was not visible: ${lockVisibilityCause(bundle)}.`;
}

function lockVisibilityCause(bundle: ZoomSettingsBundle): string {
  const unreadable = bundle.lockSurfaces.filter((surface) => surface.status !== "ok");
  return unreadable.length > 0
    ? unreadable.map(surfaceCause).join("; ")
    : "lock_settings was readable but carried no value for this key";
}

function pairedLockNote(locks: Array<boolean | undefined>, label: string, bundle: ZoomSettingsBundle): string {
  if (locks.every((lock) => lock === true)) return `${label} are locked at account level.`;
  if (locks.some((lock) => lock === undefined)) return `${label} lock state was not fully visible: ${lockVisibilityCause(bundle)}.`;
  return `${label} are not both locked in lock_settings, so groups may relax them.`;
}

function loginTypeCodes(user: JsonRecord): number[] | undefined {
  const raw = user.login_types;
  if (!Array.isArray(raw)) return undefined;
  const codes = raw.map(asNumber).filter((code): code is number => code !== undefined);
  return codes.length > 0 ? codes : undefined;
}

function userLabel(user: JsonRecord): string {
  return asString(user.email) ?? asString(user.id) ?? "user";
}

function listSurfaceState(surface: ZoomSurface<ZoomListResult<unknown>>): { items: unknown[]; truncated: boolean; total?: number } {
  const data = surface.data ?? emptyList<unknown>();
  return { items: data.items, truncated: data.truncated, total: data.totalRecords };
}

function partialNote(seen: number, total: number | undefined, truncated: boolean): string {
  return `Partial inventory: ${seen} seen of ${total ?? "an unknown total"}${truncated ? " (pagination stopped at the configured limit)" : ""}.`;
}

export function assessZoomIdentityFromSnapshot(
  snapshot: ZoomSnapshot,
  options: ZoomIdentityOptions = {},
): ZoomAssessmentResult {
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 5000);
  const maxInactivity = clampNumber(options.maxSessionInactivityMinutes, DEFAULT_MAX_SESSION_INACTIVITY_MINUTES, 1, 100000);
  const findings: ZoomFinding[] = [];

  const users = listSurfaceState(snapshot.users);
  const userRecords = toRecords(users.items);
  const ssoUsers = userRecords.filter((user) => loginTypeCodes(user)?.every((code) => code === SSO_LOGIN_TYPE));
  const nonSsoUsers = userRecords.filter((user) => loginTypeCodes(user)?.some((code) => code !== SSO_LOGIN_TYPE));
  const unknownLoginUsers = userRecords.filter((user) => loginTypeCodes(user) === undefined);
  const usersWithCategory = (category: LoginTypeCategory | "undocumented") =>
    userRecords.filter((user) => loginTypeCodes(user)?.some((code) => loginTypeCategory(code) === category));
  const socialUsers = usersWithCategory("social");
  const passwordUsers = usersWithCategory("password");
  const otherDocumentedUsers = usersWithCategory("other");
  const undocumentedUsers = usersWithCategory("undocumented");
  const undocumentedCodes = [...new Set(userRecords.flatMap((user) => loginTypeCodes(user) ?? []).filter((code) => loginTypeCategory(code) === "undocumented"))].sort((a, b) => a - b);
  const usersPartial = users.truncated || (users.total !== undefined && users.total > userRecords.length);
  const userEvidence = {
    seen_users: userRecords.length,
    total_records: users.total ?? null,
    truncated: users.truncated,
    sso_users: ssoUsers.length,
    non_sso_users: nonSsoUsers.slice(0, 25).map(userLabel),
    unknown_login_users: unknownLoginUsers.length,
    undocumented_login_codes: undocumentedCodes,
    login_type_codes: Object.fromEntries(Object.entries(LOGIN_TYPE_CATALOG).map(([code, entry]) => [code, `${entry.label} [${entry.category}]`])),
  };

  if (snapshot.users.status !== "ok") {
    findings.push(finding("ZOOM-ID-01", "SSO enforcement for all users", "critical", [5], "manual", manualForSurface(snapshot.users, "the user list with sign-in methods"), userEvidence));
    findings.push(finding("ZOOM-ID-05", "Personal and social sign-in methods blocked", "high", [16], "manual", manualForSurface(snapshot.users, "the user list with sign-in methods"), userEvidence));
  } else if (userRecords.length === 0) {
    const summary = "Manual: GET /users returned no active users, so sign-in methods cannot be judged; an empty inventory is treated as manual because a paid account always has at least the owner. Confirm the app scope (user:read:list_users:admin) and the account scope.";
    findings.push(finding("ZOOM-ID-01", "SSO enforcement for all users", "critical", [5], "manual", summary, userEvidence));
    findings.push(finding("ZOOM-ID-05", "Personal and social sign-in methods blocked", "high", [16], "manual", summary, userEvidence));
  } else {
    const ssoStatus: ZoomFindingStatus = nonSsoUsers.length > 0
      ? "fail"
      : usersPartial || unknownLoginUsers.length > 0
        ? "warn"
        : "pass";
    findings.push(finding(
      "ZOOM-ID-01",
      "SSO enforcement for all users",
      "critical",
      [5],
      ssoStatus,
      nonSsoUsers.length > 0
        ? `${nonSsoUsers.length}/${userRecords.length} active users expose a login_types code other than 101 (SSO).`
        : usersPartial
          ? `${partialNote(userRecords.length, users.total, users.truncated)} All seen users are SSO-only, but the unseen users were not judged.`
          : unknownLoginUsers.length > 0
            ? `${unknownLoginUsers.length}/${userRecords.length} users did not expose login_types; they are reported separately and cannot count as SSO-only.`
            : `All ${userRecords.length} active users (complete active-user inventory) expose login_types [101] (SSO) only.`,
      userEvidence,
    ));
    const unjudgedSignIns = otherDocumentedUsers.length > 0 || undocumentedUsers.length > 0;
    const signInStatus: ZoomFindingStatus = socialUsers.length > 0 || passwordUsers.length > 0
      ? "fail"
      : usersPartial || unknownLoginUsers.length > 0 || unjudgedSignIns
        ? "warn"
        : "pass";
    const unjudgedNote = [
      otherDocumentedUsers.length > 0
        ? `${otherDocumentedUsers.length} users expose codes that are documented but neither SSO nor a personal or social provider (${loginCodesByCategory("other").map((code) => `${code} ${LOGIN_TYPE_CATALOG[code].label}`).join(", ")}).`
        : "",
      undocumentedUsers.length > 0
        ? `${undocumentedUsers.length} users expose login_types codes not documented on GET /users or GET /users/{userId} [${undocumentedCodes.join(", ")}].`
        : "",
      unjudgedSignIns ? "They are reported separately and cannot count as blocked." : "",
    ].filter(Boolean).join(" ");
    findings.push(finding(
      "ZOOM-ID-05",
      "Personal and social sign-in methods blocked",
      "high",
      [16],
      signInStatus,
      socialUsers.length > 0 || passwordUsers.length > 0
        ? `${socialUsers.length} users use third-party OAuth sign-in (codes ${loginCodesByCategory("social").join(", ")}) and ${passwordUsers.length} use Zoom-held passwords (codes ${loginCodesByCategory("password").join(", ")}).`
        : usersPartial
          ? `${partialNote(userRecords.length, users.total, users.truncated)} No social or password sign-ins among seen users. ${unjudgedNote}`.trim()
          : unjudgedSignIns
            ? unjudgedNote
            : unknownLoginUsers.length > 0
              ? `${unknownLoginUsers.length}/${userRecords.length} users did not expose login_types and are reported separately.`
              : `No active user (complete active-user inventory of ${userRecords.length}) uses a third-party OAuth provider or a Zoom-held password; every login_types code is documented and classified.`,
      {
        ...userEvidence,
        social_login_users: socialUsers.slice(0, 25).map(userLabel),
        password_login_users: passwordUsers.slice(0, 25).map(userLabel),
        other_documented_login_users: otherDocumentedUsers.slice(0, 25).map(userLabel),
        undocumented_login_users: undocumentedUsers.slice(0, 25).map(userLabel),
      },
    ));
  }

  const securitySurface = settingsUnreadable(snapshot.settings, "account_settings:security");
  const twoFactor = readSetting(snapshot.settings, "security.sign_in_with_two_factor_auth");
  const twoFactorRoles = asArray(readSetting(snapshot.settings, "security.sign_in_with_two_factor_auth_roles").value).map(asString).filter((item): item is string => Boolean(item));
  const roles = listSurfaceState(snapshot.roles);
  const roleRecords = toRecords(roles.items);
  const adminRoles = roleRecords.filter(isAdminRole);
  const rolesUnreadable = snapshot.roles.status !== "ok";
  // The admin role inventory is evidence for every 2FA mode, so an unreadable
  // GET /roles is named here instead of rendering as an empty admin_roles list.
  const twoFactorEvidence = {
    sign_in_with_two_factor_auth: twoFactor.value ?? null,
    sign_in_with_two_factor_auth_roles: twoFactorRoles,
    ...(rolesUnreadable
      ? { roles_status: snapshot.roles.status, roles_cause: `GET ${surfaceCause(snapshot.roles)}` }
      : {
        admin_roles: adminRoles.map((role) => ({ id: asString(role.id) ?? null, name: asString(role.name) ?? null })),
        roles_truncated: roles.truncated,
        roles_total_records: roles.total ?? null,
      }),
  };
  if (securitySurface) {
    findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "manual", manualForSurface(securitySurface, "the Security > Sign in with Two-Factor Authentication setting"), twoFactorEvidence));
  } else if (!twoFactor.present) {
    findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "manual", manualForAbsentKey(twoFactor.path, ZOOM_DOCS.accountSettings, "the two-factor authentication setting"), twoFactorEvidence));
  } else {
    const mode = asString(twoFactor.value);
    switch (mode) {
      case "all": {
        const allSummary = "security.sign_in_with_two_factor_auth is `all`: two-factor authentication is required for every user, including admins.";
        findings.push(finding(
          "ZOOM-ID-02",
          "Two-factor authentication for admins",
          "critical",
          [6],
          rolesUnreadable || roles.truncated ? "warn" : "pass",
          rolesUnreadable
            ? `${allSummary} The admin role inventory (GET /roles) that evidences which roles this covers was unreadable: GET ${surfaceCause(snapshot.roles)}. Confirm the admin roles manually.`
            : roles.truncated
              ? `${allSummary} ${partialNote(roleRecords.length, roles.total, false)} The admin role inventory in evidence is incomplete.`
              : `${allSummary} ${adminRoles.length} admin or owner roles were inventoried from GET /roles (total_records matches).`,
          twoFactorEvidence,
        ));
        break;
      }
      case "role": {
        if (snapshot.roles.status !== "ok") {
          findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "manual", `security.sign_in_with_two_factor_auth is \`role\`, but ${surfaceCause(snapshot.roles)}, so admin role coverage cannot be confirmed. Compare the 2FA role list with the admin roles manually.`, twoFactorEvidence));
        } else if (adminRoles.length === 0) {
          findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "manual", "security.sign_in_with_two_factor_auth is `role`, but GET /roles returned no admin or owner roles to compare against; confirm the role list manually.", twoFactorEvidence));
        } else {
          const uncovered = adminRoles.filter((role) => !twoFactorRoles.includes(asString(role.id) ?? ""));
          findings.push(finding(
            "ZOOM-ID-02",
            "Two-factor authentication for admins",
            "critical",
            [6],
            uncovered.length > 0 ? "fail" : roles.truncated ? "warn" : "pass",
            uncovered.length > 0
              ? `security.sign_in_with_two_factor_auth is \`role\` but ${uncovered.length}/${adminRoles.length} admin or owner roles are missing from sign_in_with_two_factor_auth_roles.`
              : roles.truncated
                ? `${partialNote(roleRecords.length, roles.total, false)} The ${adminRoles.length} admin or owner roles seen appear in sign_in_with_two_factor_auth_roles, but unseen roles were not judged.`
                : `security.sign_in_with_two_factor_auth is \`role\` and all ${adminRoles.length} admin or owner roles appear in sign_in_with_two_factor_auth_roles (total_records matches).`,
            { ...twoFactorEvidence, uncovered_admin_roles: uncovered.map((role) => asString(role.name) ?? asString(role.id) ?? "role") },
          ));
        }
        break;
      }
      case "group":
        findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "warn", "security.sign_in_with_two_factor_auth is `group`: 2FA applies to selected groups only, and group membership of admins is not exposed by this API, so admin coverage is unproven.", twoFactorEvidence));
        break;
      case "none":
        findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "fail", "security.sign_in_with_two_factor_auth is `none`: two-factor authentication is not required for any user.", twoFactorEvidence));
        break;
      default:
        findings.push(finding("ZOOM-ID-02", "Two-factor authentication for admins", "critical", [6], "manual", `security.sign_in_with_two_factor_auth returned an undocumented value (${String(twoFactor.value)}); documented values are all, group, role, none.`, twoFactorEvidence));
    }
  }

  const domains = listSurfaceState(snapshot.managedDomains);
  const domainRecords = toRecords(domains.items);
  const verifiedDomains = domainRecords.filter((domain) => (asString(domain.status) ?? "").toLowerCase() === "verified");
  const otherDomains = domainRecords.filter((domain) => !verifiedDomains.includes(domain));
  const domainEvidence = {
    managed_domains: domainRecords.map((domain) => ({ domain: asString(domain.domain) ?? null, status: asString(domain.status) ?? null })),
    total_records: domains.total ?? null,
  };
  findings.push(finding(
    "ZOOM-ID-03",
    "Managed domains verified",
    "high",
    [14],
    snapshot.managedDomains.status !== "ok"
      ? "manual"
      : domainRecords.length === 0
        ? "manual"
        : otherDomains.length > 0
          ? "fail"
          : domains.truncated
            ? "warn"
            : "pass",
    snapshot.managedDomains.status !== "ok"
      ? manualForSurface(snapshot.managedDomains, "the Associated Domains list (requires the master account option)")
      : domainRecords.length === 0
        ? "Manual: GET /accounts/{accountId}/managed_domains returned no domains. Emptiness is treated as manual, not pass: confirm whether associated domains are claimed for this account."
        : otherDomains.length > 0
          ? `${otherDomains.length}/${domainRecords.length} managed domains report a status other than \`verified\`: ${otherDomains.map((domain) => `${asString(domain.domain) ?? "domain"}=${asString(domain.status) ?? "missing"}`).join(", ")}.`
          : domains.truncated
            ? `${partialNote(domainRecords.length, domains.total, false)} All seen managed domains are verified, but the unseen domains were not judged.`
            : `All ${domainRecords.length} managed domains report status \`verified\` (total_records matches).`,
    { ...domainEvidence, truncated: domains.truncated },
  ));

  const adminIds = new Set<string>();
  const adminMemberSurfaces = adminRoles.map((role) => snapshot.roleMembers[asString(role.id) ?? ""]).filter((surface): surface is ZoomSurface<ZoomListResult> => Boolean(surface));
  let memberTruncated = false;
  let memberDenied = false;
  for (const surface of adminMemberSurfaces) {
    if (surface.status !== "ok") {
      memberDenied = true;
      continue;
    }
    const state = listSurfaceState(surface);
    if (state.truncated) memberTruncated = true;
    for (const member of toRecords(state.items)) {
      const id = asString(member.id) ?? asString(member.email);
      if (id) adminIds.add(id);
    }
  }
  const declaredTotals = adminRoles.map((role) => asNumber(role.total_members) ?? 0).reduce((sum, value) => sum + value, 0);
  const adminEvidence = {
    admin_roles: adminRoles.map((role) => ({ id: asString(role.id) ?? null, name: asString(role.name) ?? null, total_members: asNumber(role.total_members) ?? null })),
    distinct_admin_members: adminIds.size,
    declared_total_members: declaredTotals,
    max_admins: maxAdmins,
    member_lists_truncated: memberTruncated,
    member_lists_denied: memberDenied,
  };
  findings.push(finding(
    "ZOOM-ID-04",
    "Administrative privilege concentration",
    "medium",
    [6],
    snapshot.roles.status !== "ok"
      ? "manual"
      : adminRoles.length === 0
        ? "manual"
        : memberDenied
          ? "manual"
          : memberTruncated || roles.truncated
            ? "warn"
            : adminIds.size <= maxAdmins
              ? "pass"
              : "warn",
    snapshot.roles.status !== "ok"
      ? manualForSurface(snapshot.roles, "the role list and admin role membership")
      : adminRoles.length === 0
        ? "Manual: GET /roles returned no role whose name contains admin or owner; every Zoom account has an Owner role, so the view is incomplete."
        : memberDenied
          ? `Manual: admin role member lists (GET /roles/{roleId}/members) were unreadable, so the admin count cannot be confirmed: ${surfaceErrors(adminMemberSurfaces).join("; ")}. Collect the admin role membership from the Zoom admin portal.`
          : memberTruncated
            ? `Partial inventory: admin role member pagination stopped at the configured limit; ${adminIds.size} distinct admins were seen of ${declaredTotals > 0 ? `${declaredTotals} declared` : "an unknown total"}.`
            : roles.truncated
              ? `${partialNote(roleRecords.length, roles.total, false)} ${adminIds.size} distinct admins were seen in the ${adminRoles.length} admin or owner roles returned, but unseen roles were not judged.`
              : adminIds.size <= maxAdmins
                ? `${adminIds.size} distinct users hold admin or owner roles (complete membership), within the threshold of ${maxAdmins}.`
                : `${adminIds.size} distinct users hold admin or owner roles, above the threshold of ${maxAdmins}.`,
    { ...adminEvidence, roles_truncated: roles.truncated, roles_total_records: roles.total ?? null },
  ));

  const clientTimeout = readSetting(snapshot.settings, "security.sign_again_period_for_inactivity_on_client");
  const webTimeout = readSetting(snapshot.settings, "security.sign_again_period_for_inactivity_on_web");
  const clientMinutes = asNumber(clientTimeout.value);
  const webMinutes = asNumber(webTimeout.value);
  const timeoutEvidence = {
    sign_again_period_for_inactivity_on_client_minutes: clientMinutes ?? null,
    sign_again_period_for_inactivity_on_web_minutes: webMinutes ?? null,
    automatic_sign_out: readSetting(snapshot.settings, "security.automatic_sign_out").value ?? null,
    max_session_inactivity_minutes: maxInactivity,
  };
  const timeoutDisabled = (minutes: number | undefined) => minutes === undefined || minutes <= 0;
  findings.push(finding(
    "ZOOM-ID-06",
    "Session inactivity timeout enforced",
    "medium",
    [17],
    securitySurface
      ? "manual"
      : !clientTimeout.present && !webTimeout.present
        ? "manual"
        : timeoutDisabled(clientMinutes) || timeoutDisabled(webMinutes)
          ? "fail"
          : (clientMinutes ?? 0) > maxInactivity || (webMinutes ?? 0) > maxInactivity
            ? "warn"
            : "pass",
    securitySurface
      ? manualForSurface(securitySurface, "the Security > Sign in again after a period of inactivity settings")
      : !clientTimeout.present && !webTimeout.present
        ? manualForAbsentKey("security.sign_again_period_for_inactivity_on_client and security.sign_again_period_for_inactivity_on_web", ZOOM_DOCS.accountSettings, "the inactivity sign-out periods")
        : timeoutDisabled(clientMinutes) || timeoutDisabled(webMinutes)
          ? `Inactivity sign-out is disabled (value 0 or absent) for ${[timeoutDisabled(clientMinutes) ? "the Zoom client" : undefined, timeoutDisabled(webMinutes) ? "the web portal" : undefined].filter(Boolean).join(" and ")}.`
          : (clientMinutes ?? 0) > maxInactivity || (webMinutes ?? 0) > maxInactivity
            ? `Inactivity sign-out is enabled (client ${clientMinutes} min, web ${webMinutes} min) but exceeds the ${maxInactivity}-minute policy threshold.`
            : `Inactivity sign-out is enabled for the Zoom client (${clientMinutes} min) and web portal (${webMinutes} min), within the ${maxInactivity}-minute threshold.`,
    timeoutEvidence,
  ));

  findings.push(finding(
    "ZOOM-ID-07",
    "Vanity URL configured and secured",
    "low",
    [13],
    "manual",
    `Manual: the account settings reference (${ZOOM_DOCS.accountSettings}) exposes no account vanity URL field; only per-user personal meeting room URLs are documented (vanity_url on ${ZOOM_DOCS.user}). Review the account profile vanity URL in the admin portal.`,
    { documented_alternative: "GET /users/{userId} vanity_url (personal meeting room URL, not the account vanity URL)" },
  ));

  return {
    title: "Zoom identity posture",
    summary: {
      account_id: snapshot.accountId,
      seen_users: userRecords.length,
      total_users: users.total ?? null,
      users_partial: usersPartial,
      non_sso_users: nonSsoUsers.length,
      unknown_login_users: unknownLoginUsers.length,
      two_factor_mode: asString(twoFactor.value) ?? null,
      admin_roles: adminRoles.length,
      distinct_admin_members: adminIds.size,
      managed_domains: domainRecords.length,
      unverified_domains: otherDomains.length,
      client_inactivity_minutes: clientMinutes ?? null,
      web_inactivity_minutes: webMinutes ?? null,
    },
    findings,
    errors: surfaceErrors([snapshot.users, snapshot.roles, ...adminMemberSurfaces, snapshot.managedDomains, ...snapshot.settings.settingsSurfaces]),
  };
}

/**
 * ZOOM_DOCS.accountSettings describes disclaimer_to_participants as a string
 * with the example values "All participants" and "Guest only" but documents
 * no enum, so the match is case-insensitive on those example values and any
 * other string is reported as unrecognized rather than compliant.
 */
function disclaimerVerdict(bundle: ZoomSettingsBundle): { status: ZoomFindingStatus; summary: string; evidence: JsonRecord } {
  const disclaimer = readSetting(bundle, "recording.recording_notification_for_zoom_client.disclaimer_to_participants");
  const askHost = readSetting(bundle, "recording.recording_notification_for_zoom_client.ask_host_to_confirm");
  const legacy = readSetting(bundle, "recording.recording_disclaimer");
  const phoneConsent = readSetting(bundle, "recording.recording_notifications_phone_users.require_press_one_consent_to_record");
  const evidence = {
    disclaimer_to_participants: disclaimer.value ?? null,
    ask_host_to_confirm: askHost.value ?? null,
    recording_disclaimer_deprecated: legacy.value ?? null,
    require_press_one_consent_to_record: phoneConsent.value ?? null,
  };
  const option = asString(disclaimer.value);
  if (option) {
    if (/all participants/i.test(option)) {
      return { status: "pass", summary: `recording_notification_for_zoom_client.disclaimer_to_participants is \`${option}\` (documented example value), so every participant sees the recording disclaimer.${askHost.value === true ? " Hosts must confirm before recording starts." : ""}`, evidence };
    }
    if (/guest only/i.test(option)) {
      return { status: "warn", summary: `recording_notification_for_zoom_client.disclaimer_to_participants is \`${option}\`: only guests see the disclaimer, internal participants do not.`, evidence };
    }
    return { status: "warn", summary: `recording_notification_for_zoom_client.disclaimer_to_participants is \`${option}\`, which is not one of the documented example option names (All participants, Guest only); confirm it is not the off option.`, evidence };
  }
  if (legacy.present) {
    return legacy.value === true
      ? { status: "pass", summary: "recording.recording_disclaimer (deprecated but documented) is true and the replacement field was not returned; participants see a disclaimer before recording starts.", evidence }
      : { status: "fail", summary: "recording.recording_disclaimer is false and the replacement recording_notification_for_zoom_client.disclaimer_to_participants was not returned.", evidence };
  }
  return { status: "manual", summary: manualForAbsentKey("recording.recording_notification_for_zoom_client.disclaimer_to_participants", ZOOM_DOCS.accountSettings, "the Recording notifications setting"), evidence };
}

export function assessZoomCollaborationGovernanceFromSnapshot(
  snapshot: ZoomSnapshot,
  options: ZoomCollaborationOptions = {},
): ZoomAssessmentResult {
  const maxRetention = clampNumber(options.maxRecordingRetentionDays, DEFAULT_MAX_RECORDING_RETENTION_DAYS, 1, 3650);
  const bundle = snapshot.settings;
  const settingsSurface = settingsUnreadable(bundle);
  const findings: ZoomFinding[] = [];

  const trusted = listSurfaceState(snapshot.trustedDomains);
  const trustedNames = trusted.items.map((item) => asString(item) ?? asString(asObject(item)?.domain)).filter((item): item is string => Boolean(item));
  const wildcardDomains = trustedNames.filter((name) => name.includes("*") || name === "");
  findings.push(finding(
    "ZOOM-COLLAB-01",
    "Trusted domain restrictions",
    "high",
    [12],
    snapshot.trustedDomains.status !== "ok"
      ? "manual"
      : trustedNames.length === 0
        ? "manual"
        : wildcardDomains.length === 0
          ? "pass"
          : "fail",
    snapshot.trustedDomains.status !== "ok"
      ? manualForSurface(snapshot.trustedDomains, "the trusted domains list")
      : trustedNames.length === 0
        ? "Manual: GET /accounts/{accountId}/trusted_domains returned no domains. Emptiness is treated as manual: confirm whether trusted domains are intentionally unused."
        : wildcardDomains.length === 0
          ? `${trustedNames.length} trusted domains are explicitly named with no wildcard entries.`
          : `${wildcardDomains.length}/${trustedNames.length} trusted domain entries are wildcards.`,
    { trusted_domains: trustedNames.slice(0, 50), wildcard_entries: wildcardDomains },
  ));

  const fileTransfer = readSetting(bundle, "in_meeting.file_transfer");
  const fileTransferLocked = readLock(bundle, "in_meeting.file_transfer");
  const fileTransferGroups = groupOverrideState(snapshot, groupsRelaxing(snapshot, "in_meeting.file_transfer", false));
  findings.push(finding(
    "ZOOM-COLLAB-02",
    "In-meeting file transfer restricted",
    "high",
    [9],
    settingsSurface
      ? "manual"
      : !fileTransfer.present
        ? "manual"
        : fileTransfer.value === true
          ? "fail"
          : fileTransferLocked === true && !fileTransferGroups.demote
            ? "pass"
            : "warn",
    settingsSurface
      ? manualForSurface(settingsSurface, "the In Meeting (Basic) > Send files via meeting chat setting")
      : !fileTransfer.present
        ? manualForAbsentKey(fileTransfer.path, ZOOM_DOCS.accountSettings, "the in-meeting file transfer setting")
        : fileTransfer.value === true
          ? "in_meeting.file_transfer is true: participants can send files through meeting chat."
          : `in_meeting.file_transfer is false. ${lockNote(fileTransferLocked, "in_meeting.file_transfer", bundle)} ${fileTransferGroups.note}`.trim(),
    { file_transfer: fileTransfer.value ?? null, file_transfer_locked: fileTransferLocked ?? null, chat_share_files: readSetting(bundle, "chat.share_files").value ?? null, ...fileTransferGroups.evidence },
  ));

  const cloudRecording = readSetting(bundle, "recording.cloud_recording");
  const autoDelete = readSetting(bundle, "recording.auto_delete_cmr");
  const autoDeleteDays = readSetting(bundle, "recording.auto_delete_cmr_days");
  const retentionDays = asNumber(autoDeleteDays.value);
  const autoDeleteLocked = readLock(bundle, "recording.auto_delete_cmr");
  const retentionGroups = groupOverrideState(snapshot, groupsRelaxing(snapshot, "recording.auto_delete_cmr", true));
  const retentionEvidence = {
    cloud_recording: cloudRecording.value ?? null,
    auto_delete_cmr: autoDelete.value ?? null,
    auto_delete_cmr_days: retentionDays ?? null,
    auto_delete_cmr_locked: autoDeleteLocked ?? null,
    max_recording_retention_days: maxRetention,
    ...retentionGroups.evidence,
  };
  findings.push(finding(
    "ZOOM-COLLAB-03",
    "Cloud recording auto-delete retention",
    "high",
    [10, 11],
    settingsSurface
      ? "manual"
      : !cloudRecording.present && !autoDelete.present
        ? "manual"
        : cloudRecording.value === false
          ? "manual"
          : autoDelete.value !== true
            ? "fail"
            : retentionDays === undefined
              ? "warn"
              : retentionDays > maxRetention
                ? "warn"
                : autoDeleteLocked === true && !retentionGroups.demote
                  ? "pass"
                  : "warn",
    settingsSurface
      ? manualForSurface(settingsSurface, "the Recording > Auto delete cloud recordings setting")
      : !cloudRecording.present && !autoDelete.present
        ? manualForAbsentKey("recording.cloud_recording and recording.auto_delete_cmr", ZOOM_DOCS.accountSettings, "the cloud recording retention policy")
        : cloudRecording.value === false
          ? "Manual: recording.cloud_recording is false, so cloud recording is disabled by configuration and the auto-delete control does not apply; confirm no cloud recordings exist."
          : autoDelete.value !== true
            ? "recording.auto_delete_cmr is not true: cloud recordings are retained indefinitely."
            : retentionDays === undefined
              ? "recording.auto_delete_cmr is true but recording.auto_delete_cmr_days was not returned, so the retention period is unknown."
              : retentionDays > maxRetention
                ? `Cloud recordings auto-delete after ${retentionDays} days, above the ${maxRetention}-day policy threshold.`
                : `Cloud recordings auto-delete after ${retentionDays} days (documented values 30, 60, 90, 120), within the ${maxRetention}-day threshold. ${lockNote(autoDeleteLocked, "recording.auto_delete_cmr", bundle)} ${retentionGroups.note}`.trim(),
    retentionEvidence,
  ));

  const phone = snapshot.phoneSettings;
  const autoCall = asObject(getNestedValue(phone.data, ["auto_call_recording"]));
  const adHoc = asObject(getNestedValue(phone.data, ["ad_hoc_call_recording"]));
  const phoneEvidence = {
    auto_call_recording: autoCall ? { enable: asBoolean(autoCall.enable) ?? null, locked: asBoolean(autoCall.locked) ?? null, recording_calls: asString(autoCall.recording_calls) ?? null } : null,
    ad_hoc_call_recording: adHoc ? { enable: asBoolean(adHoc.enable) ?? null, locked: asBoolean(adHoc.locked) ?? null } : null,
  };
  const phonePolicies = [autoCall, adHoc];
  const phoneUnlocked = phonePolicies.filter((policy) => policy && asBoolean(policy.locked) !== true);
  const phoneMissingEnable = phonePolicies.filter((policy) => policy && asBoolean(policy.enable) === undefined);
  findings.push(finding(
    "ZOOM-COLLAB-04",
    "Zoom Phone recording policies enforced",
    "medium",
    [19],
    phone.status !== "ok"
      ? "manual"
      : !autoCall || !adHoc
        ? "manual"
        : phoneMissingEnable.length > 0
          ? "manual"
          : phoneUnlocked.length > 0
            ? "warn"
            : "pass",
    phone.status !== "ok"
      ? `Manual: ${surfaceCause(phone)}. Zoom Phone requires a Business or Enterprise account with a Zoom Phone license; confirm whether Phone is licensed and review its recording policies in the admin portal.`
      : !autoCall || !adHoc
        ? manualForAbsentKey("auto_call_recording and ad_hoc_call_recording", ZOOM_DOCS.phoneAccountSettings, "the Zoom Phone recording policies")
        : phoneMissingEnable.length > 0
          ? "Manual: a Zoom Phone recording policy object was returned without its enable flag; the policy state is unknown."
          : phoneUnlocked.length > 0
            ? `Zoom Phone recording policies are present (auto=${String(asBoolean(autoCall.enable))}, ad hoc=${String(asBoolean(adHoc.enable))}) but ${phoneUnlocked.length} of 2 are not locked, so users can change them.`
            : `Zoom Phone recording policies are locked at account level (auto call recording enable=${String(asBoolean(autoCall.enable))}, ad hoc recording enable=${String(asBoolean(adHoc.enable))}).`,
    phoneEvidence,
  ));

  const logs = listSurfaceState(snapshot.operationLogs);
  const logRecords = toRecords(logs.items);
  const datedLogs = logRecords.filter((log) => parseTimestamp(log.time) !== undefined);
  const undatedLogs = logRecords.filter((log) => parseTimestamp(log.time) === undefined);
  const newestLog = datedLogs.map((log) => parseTimestamp(log.time) ?? 0).reduce((max, value) => Math.max(max, value), 0);
  const logEvidence = {
    window_from: snapshot.operationLogs.from,
    window_to: snapshot.operationLogs.to,
    seen_entries: logRecords.length,
    dated_entries: datedLogs.length,
    undated_entries: undatedLogs.length,
    truncated: logs.truncated,
    total_records: logs.total ?? null,
    newest_entry: newestLog > 0 ? new Date(newestLog).toISOString() : null,
    category_types: [...new Set(logRecords.map((log) => asString(log.category_type)).filter(Boolean))].slice(0, 20),
  };
  findings.push(finding(
    "ZOOM-COLLAB-05",
    "Admin operation logs readable and recent",
    "medium",
    [24],
    snapshot.operationLogs.status !== "ok"
      ? "manual"
      : logRecords.length === 0
        ? "warn"
        : logs.truncated
          ? "warn"
          : undatedLogs.length > 0
            ? "warn"
            : "pass",
    snapshot.operationLogs.status !== "ok"
      ? manualForSurface(snapshot.operationLogs, "the Admin Activity Logs report (requires report:read:operation_logs:admin)")
      : logRecords.length === 0
        ? `GET /report/operationlogs returned no entries between ${snapshot.operationLogs.from} and ${snapshot.operationLogs.to}; emptiness cannot prove retention, so this is reported as warn.`
        : logs.truncated
          ? `${partialNote(logRecords.length, logs.total, true)} The full operation log population for ${snapshot.operationLogs.from} to ${snapshot.operationLogs.to} was not enumerated.`
          : undatedLogs.length > 0
            ? `${undatedLogs.length}/${logRecords.length} operation log entries lack a parseable time and are reported separately; they cannot count as recent.`
            : `${logRecords.length} admin operation log entries were readable for ${snapshot.operationLogs.from} to ${snapshot.operationLogs.to} (complete pagination, newest ${new Date(newestLog).toISOString()}). Retention length beyond the API window must be confirmed against Zoom's published retention.`,
    logEvidence,
  ));

  const imGroups = listSurfaceState(snapshot.imGroups);
  const imRecords = toRecords(imGroups.items);
  const sharedGroups = imRecords.filter((group) => asString(group.type) === "shared");
  const unknownTypeGroups = imRecords.filter((group) => !["normal", "shared", "restricted"].includes(asString(group.type) ?? ""));
  const crossAccountSearch = imRecords.filter((group) => asBoolean(group.search_by_ma_account) === true);
  findings.push(finding(
    "ZOOM-COLLAB-06",
    "IM group restrictions enforced",
    "medium",
    [15],
    snapshot.imGroups.status !== "ok"
      ? "manual"
      : imRecords.length === 0
        ? "manual"
        : imGroups.truncated
          ? "warn"
          : sharedGroups.length > 0 || unknownTypeGroups.length > 0 || crossAccountSearch.length > 0
            ? "warn"
            : "pass",
    snapshot.imGroups.status !== "ok"
      ? manualForSurface(snapshot.imGroups, "the IM directory groups (requires contact_group:read:list_groups:admin)")
      : imRecords.length === 0
        ? "Manual: GET /im/groups returned no IM directory groups. Emptiness is manual: confirm whether Team Chat directory groups are intentionally unused."
        : imGroups.truncated
          ? `Partial inventory: ${imRecords.length} IM groups seen of ${imGroups.total ?? "an unknown total"}.`
          : sharedGroups.length > 0 || unknownTypeGroups.length > 0 || crossAccountSearch.length > 0
            ? `${sharedGroups.length} IM groups are \`shared\`, ${crossAccountSearch.length} allow search across the master account, and ${unknownTypeGroups.length} have an undocumented type.`
            : `All ${imRecords.length} IM directory groups are \`normal\` or \`restricted\` with no master-account-wide search.`,
    {
      im_groups: imRecords.slice(0, 50).map((group) => ({ name: asString(group.name) ?? null, type: asString(group.type) ?? null, search_by_ma_account: asBoolean(group.search_by_ma_account) ?? null })),
      total_records: imGroups.total ?? null,
    },
  ));

  const addContacts = asObject(readSetting(bundle, "chat.allow_users_to_add_contacts").value);
  const chatWithOthers = asObject(readSetting(bundle, "chat.allow_users_to_chat_with_others").value);
  const externalControl = asObject(readSetting(bundle, "chat.external_user_control").value);
  const contactEvidence = {
    allow_users_to_add_contacts: addContacts ?? null,
    allow_users_to_chat_with_others: chatWithOthers ?? null,
    external_user_control: externalControl ?? null,
    selected_option_codes: { 1: "Anyone (internal and external)", 2: "In the same organization", 3: "Same organization and specified domains", 4: "Same organization and specified accounts" },
  };
  const restricted = (policy: JsonRecord | undefined): boolean | undefined => {
    if (!policy) return undefined;
    const enabled = asBoolean(policy.enable);
    if (enabled === false) return true;
    if (enabled !== true) return undefined;
    const option = asNumber(policy.selected_option);
    if (option === undefined) return undefined;
    return option !== 1;
  };
  const addRestricted = restricted(addContacts);
  const chatRestricted = restricted(chatWithOthers);
  const addLocked = readLock(bundle, "chat.allow_users_to_add_contacts");
  const chatLocked = readLock(bundle, "chat.allow_users_to_chat_with_others");
  const contactsLocked = addLocked === true && chatLocked === true;
  const contactsGroups = groupOverrideState(snapshot, snapshot.groupPolicies
    .filter((policy) => policy.settings.status === "ok")
    .filter((policy) =>
      restricted(asObject(getNestedValue(policy.settings.data, ["chat", "allow_users_to_add_contacts"]))) === false
      || restricted(asObject(getNestedValue(policy.settings.data, ["chat", "allow_users_to_chat_with_others"]))) === false)
    .map((policy) => policy.name));
  findings.push(finding(
    "ZOOM-COLLAB-07",
    "External contacts restricted",
    "medium",
    [12],
    settingsSurface
      ? "manual"
      : !addContacts || !chatWithOthers
        ? "manual"
        : addRestricted === undefined || chatRestricted === undefined
          ? "manual"
          : addRestricted && chatRestricted
            ? (contactsLocked && !contactsGroups.demote ? "pass" : "warn")
            : "fail",
    settingsSurface
      ? manualForSurface(settingsSurface, "the Team Chat > Allow users to add contacts and chat with others settings")
      : !addContacts || !chatWithOthers
        ? manualForAbsentKey("chat.allow_users_to_add_contacts and chat.allow_users_to_chat_with_others", ZOOM_DOCS.accountSettings, "the external contact restrictions (Team Chat may be disabled)")
        : addRestricted === undefined || chatRestricted === undefined
          ? "Manual: the chat contact policies were returned without their enable flag or selected_option, so the restriction cannot be judged."
          : addRestricted && chatRestricted
            ? `Users cannot add or chat with anyone outside the organization: allow_users_to_add_contacts and allow_users_to_chat_with_others are disabled or scoped to the organization (selected_option 2, 3, or 4). ${pairedLockNote([addLocked, chatLocked], "Both contact settings", bundle)} ${contactsGroups.note}`.trim()
            : "allow_users_to_add_contacts or allow_users_to_chat_with_others is enabled with selected_option 1 (anyone, internal and external).",
    { ...contactEvidence, allow_users_to_add_contacts_locked: addLocked ?? null, allow_users_to_chat_with_others_locked: chatLocked ?? null, ...contactsGroups.evidence },
  ));

  findings.push(finding(
    "ZOOM-COLLAB-08",
    "Chat encryption enabled",
    "medium",
    [8],
    "manual",
    `Manual: the account settings reference (${ZOOM_DOCS.accountSettings}) documents no account-level Team Chat encryption setting under the chat object; encryption indicators exist only as per-message metadata in the Team Chat API. Confirm Advanced Chat Encryption in the admin portal.`,
    { chat_settings_present: readSetting(bundle, "chat").present },
  ));

  return {
    title: "Zoom collaboration governance",
    summary: {
      account_id: snapshot.accountId,
      trusted_domains: trustedNames.length,
      wildcard_trusted_domains: wildcardDomains.length,
      file_transfer: fileTransfer.value ?? null,
      cloud_recording: cloudRecording.value ?? null,
      auto_delete_cmr: autoDelete.value ?? null,
      auto_delete_cmr_days: retentionDays ?? null,
      phone_settings_status: phone.status,
      operation_logs_seen: logRecords.length,
      im_groups: imRecords.length,
      shared_im_groups: sharedGroups.length,
    },
    findings,
    errors: surfaceErrors([...bundle.settingsSurfaces, ...bundle.lockSurfaces, snapshot.groups, ...groupPolicySurfaces(snapshot), snapshot.trustedDomains, snapshot.imGroups, snapshot.operationLogs, snapshot.phoneSettings]),
  };
}

function groupsRelaxing(snapshot: ZoomSnapshot, path: string, compliantValue: unknown): string[] {
  snapshot.settings.readPaths.add(path);
  return snapshot.groupPolicies
    .filter((policy) => policy.settings.status === "ok")
    .filter((policy) => {
      const value = getNestedValue(policy.settings.data, path.split("."));
      return value !== undefined && value !== compliantValue;
    })
    .map((policy) => policy.name);
}

/**
 * Groups whose settings could not be fully read: the base
 * GET /groups/{id}/settings or the option=meeting_security view, which is the
 * documented per-group source for the meeting_security keys. A denied view
 * leaves its keys undefined in the merged data, so it must demote here rather
 * than look compliant. policy.lockSurfaces are retained and disclosed in the
 * errors arrays but intentionally not inspected here because no verdict reads
 * group lock state yet.
 */
function groupsUnreadable(snapshot: ZoomSnapshot): { group: string; surface: ZoomSurface<JsonRecord> }[] {
  return snapshot.groupPolicies.flatMap((policy) =>
    policy.settingsSurfaces
      .filter((surface) => surface.status !== "ok")
      .map((surface) => ({ group: policy.name, surface })),
  );
}

function unreadableGroupLabel(entry: { group: string; surface: ZoomSurface<JsonRecord> }): string {
  return `${entry.group}: ${surfaceCause(entry.surface)}`;
}

function booleanControl(
  snapshot: ZoomSnapshot,
  id: string,
  title: string,
  severity: ZoomFinding["severity"],
  controls: number[],
  path: string,
  compliantValue: boolean,
  labels: { evidenceToCollect: string; compliant: string; nonCompliant: string; surfaceName?: string; lockPath?: string },
  extraEvidence: JsonRecord = {},
): ZoomFinding {
  const bundle = snapshot.settings;
  const surface = settingsUnreadable(bundle, labels.surfaceName);
  const setting = readSetting(bundle, path);
  const locked = readLock(bundle, labels.lockPath ?? path);
  const groups = groupOverrideState(snapshot, groupsRelaxing(snapshot, path, compliantValue));
  const evidence = {
    [path]: setting.value ?? null,
    locked: locked ?? null,
    groups_sampled: snapshot.groupPolicies.length,
    ...groups.evidence,
    ...extraEvidence,
  };
  if (surface) {
    return finding(id, title, severity, controls, "manual", manualForSurface(surface, labels.evidenceToCollect), evidence);
  }
  if (!setting.present) {
    return finding(id, title, severity, controls, "manual", manualForAbsentKey(path, ZOOM_DOCS.accountSettings, labels.evidenceToCollect), evidence);
  }
  if (setting.value !== compliantValue) {
    return finding(id, title, severity, controls, "fail", `${path} is ${String(setting.value)}: ${labels.nonCompliant}`, evidence);
  }
  const status: ZoomFindingStatus = locked === true && !groups.demote ? "pass" : "warn";
  const summary = [`${path} is ${String(compliantValue)}: ${labels.compliant}`, lockNote(locked, path, bundle), groups.note].filter(Boolean).join(" ");
  return finding(id, title, severity, controls, status, summary, evidence);
}

function groupInventoryTruncated(snapshot: ZoomSnapshot): boolean {
  return snapshot.groups.status === "ok" && listSurfaceState(snapshot.groups).truncated;
}

/**
 * Every group-dependent verdict goes through this helper: group overrides,
 * unreadable group settings surfaces, a denied or failed GET /groups, or a
 * truncated group inventory all block pass. A skipped group list (the
 * collaboration tool run alone) leaves the verdict to the account lock.
 */
function groupOverrideState(snapshot: ZoomSnapshot, relaxed: string[]): { demote: boolean; note: string; evidence: JsonRecord } {
  const unreadable = groupsUnreadable(snapshot);
  const truncated = groupInventoryTruncated(snapshot);
  const listUnreadable = snapshot.groups.status === "denied" || snapshot.groups.status === "error";
  const notes = [
    relaxed.length > 0 ? `${relaxed.length} sampled groups override it: ${relaxed.slice(0, 5).join(", ")}.` : "",
    listUnreadable ? `Group overrides could not be checked: ${surfaceCause(snapshot.groups)}.` : "",
    unreadable.length > 0
      ? `${unreadable.length} group settings surfaces were unreadable, so group overrides are unproven: ${unreadable.slice(0, 5).map(unreadableGroupLabel).join("; ")}.`
      : "",
    truncated ? groupTruncationNote(snapshot) : "",
  ].filter(Boolean);
  return {
    demote: notes.length > 0,
    note: notes.join(" "),
    evidence: {
      groups_list_status: snapshot.groups.status,
      groups_relaxing: relaxed.slice(0, 25),
      groups_unreadable: unreadable.slice(0, 25).map(unreadableGroupLabel),
      groups_truncated: truncated,
    },
  };
}

function groupTruncationNote(snapshot: ZoomSnapshot): string {
  const groups = listSurfaceState(snapshot.groups);
  return `Group inventory was truncated at the configured limit (${groups.items.length} groups seen of ${groups.total ?? "an unknown total"}), so unseen groups may override it.`;
}

export function assessZoomMeetingSecurityFromSnapshot(
  snapshot: ZoomSnapshot,
  _options: ZoomMeetingSecurityOptions = {},
): ZoomAssessmentResult {
  const bundle = snapshot.settings;
  const findings: ZoomFinding[] = [];

  const passwordFinding = booleanControl(
    snapshot,
    "ZOOM-MTG-01",
    "Meeting password enforcement and account lock",
    "critical",
    [1, 21],
    "schedule_meeting.require_password_for_scheduling_new_meetings",
    true,
    {
      evidenceToCollect: "the Schedule Meeting > Require a passcode when scheduling new meetings setting and its lock",
      compliant: "new meetings require a passcode.",
      nonCompliant: "new meetings do not require a passcode.",
    },
    { meeting_security_meeting_password: readSetting(bundle, "meeting_security.meeting_password").value ?? null },
  );
  findings.push(passwordFinding);

  findings.push(booleanControl(
    snapshot,
    "ZOOM-MTG-02",
    "Waiting room enabled by default",
    "critical",
    [2],
    "meeting_security.waiting_room",
    true,
    {
      evidenceToCollect: "the Security > Waiting Room setting (option=meeting_security)",
      compliant: "participants are placed in the waiting room.",
      nonCompliant: "participants join without a waiting room.",
      surfaceName: "account_settings:meeting_security",
    },
    { waiting_room_options: readSetting(bundle, "meeting_security.waiting_room_options").value ?? null },
  ));

  const screenSharing = readSetting(bundle, "in_meeting.screen_sharing");
  const whoCanShare = readSetting(bundle, "in_meeting.who_can_share_screen");
  const screenSurface = settingsUnreadable(bundle);
  const sharingLocked = readLock(bundle, "in_meeting.screen_sharing");
  const shareGroups = groupOverrideState(snapshot, screenSharing.value === false
    ? groupsRelaxing(snapshot, "in_meeting.screen_sharing", false)
    : groupsRelaxing(snapshot, "in_meeting.who_can_share_screen", "host"));
  const sharePass = sharingLocked === true && !shareGroups.demote ? "pass" : "warn";
  const shareEvidence = {
    screen_sharing: screenSharing.value ?? null,
    who_can_share_screen: whoCanShare.value ?? null,
    screen_sharing_locked: sharingLocked ?? null,
    who_can_share_screen_when_someone_is_sharing: readSetting(bundle, "in_meeting.who_can_share_screen_when_someone_is_sharing").value ?? null,
    ...shareGroups.evidence,
  };
  findings.push(finding(
    "ZOOM-MTG-03",
    "Screen sharing restricted to host only",
    "high",
    [3],
    screenSurface
      ? "manual"
      : !screenSharing.present
        ? "manual"
        : screenSharing.value === false
          ? sharePass
          : !whoCanShare.present
            ? "manual"
            : asString(whoCanShare.value) === "host"
              ? sharePass
              : asString(whoCanShare.value) === "all"
                ? "fail"
                : "manual",
    screenSurface
      ? manualForSurface(screenSurface, "the In Meeting (Basic) > Screen sharing setting")
      : !screenSharing.present
        ? manualForAbsentKey(screenSharing.path, ZOOM_DOCS.accountSettings, "the screen sharing setting")
        : screenSharing.value === false
          ? `in_meeting.screen_sharing is false: screen sharing is disabled entirely. ${lockNote(sharingLocked, "in_meeting.screen_sharing", bundle)} ${shareGroups.note}`.trim()
          : !whoCanShare.present
            ? manualForAbsentKey(whoCanShare.path, ZOOM_DOCS.accountSettings, "who can share screen")
            : asString(whoCanShare.value) === "host"
              ? `in_meeting.who_can_share_screen is \`host\`: only hosts can share. ${lockNote(sharingLocked, "in_meeting.screen_sharing", bundle)} ${shareGroups.note}`.trim()
              : asString(whoCanShare.value) === "all"
                ? "in_meeting.who_can_share_screen is `all`: hosts and attendees can share their screen."
                : `in_meeting.who_can_share_screen returned an undocumented value (${String(whoCanShare.value)}); documented values are host and all.`,
    shareEvidence,
  ));

  findings.push(booleanControl(
    snapshot,
    "ZOOM-MTG-04",
    "Local recording disabled",
    "high",
    [20],
    "recording.local_recording",
    false,
    {
      evidenceToCollect: "the Recording > Local recording setting",
      compliant: "hosts and participants cannot record to a local file.",
      nonCompliant: "hosts and participants can record meetings locally.",
    },
    { local_recording_options: readSetting(bundle, "recording.local_recording_options").value ?? null },
  ));

  const e2ee = readSetting(bundle, "meeting_security.end_to_end_encrypted_meetings");
  const encryptionType = readSetting(bundle, "meeting_security.encryption_type");
  const e2eeSurface = settingsUnreadable(bundle, "account_settings:meeting_security");
  const e2eeLocked = readLock(bundle, "meeting_security.end_to_end_encrypted_meetings");
  const e2eeGroups = groupOverrideState(snapshot, [...new Set([
    ...groupsRelaxing(snapshot, "meeting_security.end_to_end_encrypted_meetings", true),
    ...groupsRelaxing(snapshot, "meeting_security.encryption_type", "e2ee"),
  ])]);
  findings.push(finding(
    "ZOOM-MTG-05",
    "End-to-end encryption available and default",
    "high",
    [7],
    e2eeSurface
      ? "manual"
      : !e2ee.present
        ? "manual"
        : e2ee.value !== true
          ? "fail"
          : asString(encryptionType.value) === "e2ee"
            ? (e2eeLocked === true && !e2eeGroups.demote ? "pass" : "warn")
            : "warn",
    e2eeSurface
      ? manualForSurface(e2eeSurface, "the Security > Allow use of end-to-end encryption setting (option=meeting_security)")
      : !e2ee.present
        ? manualForAbsentKey(e2ee.path, ZOOM_DOCS.accountSettings, "end-to-end encryption eligibility for this account")
        : e2ee.value !== true
          ? "meeting_security.end_to_end_encrypted_meetings is false: end-to-end encryption is not available to hosts."
          : asString(encryptionType.value) === "e2ee"
            ? `End-to-end encryption is enabled and meeting_security.encryption_type is \`e2ee\` (the default for new meetings). ${lockNote(e2eeLocked, e2ee.path, bundle)} ${e2eeGroups.note}`.trim()
            : `End-to-end encryption is enabled but meeting_security.encryption_type is ${encryptionType.present ? `\`${String(encryptionType.value)}\`` : "not returned"}, so E2EE is available but not the default.`,
    { end_to_end_encrypted_meetings: e2ee.value ?? null, encryption_type: encryptionType.value ?? null, locked: e2eeLocked ?? null, ...e2eeGroups.evidence },
  ));

  findings.push(booleanControl(
    snapshot,
    "ZOOM-MTG-06",
    "Embed password in join link disabled",
    "medium",
    [22],
    "meeting_security.embed_password_in_join_link",
    false,
    {
      evidenceToCollect: "the Security > Embed passcode in invite link for one-click join setting",
      compliant: "join links do not carry the encrypted passcode.",
      nonCompliant: "join links carry the encrypted passcode for one-click join.",
      surfaceName: "account_settings:meeting_security",
      lockPath: "meeting_security.embed_password_in_join_link",
    },
  ));

  const pmiScheduled = readSetting(bundle, "schedule_meeting.use_pmi_for_scheduled_meetings");
  const pmiInstant = readSetting(bundle, "schedule_meeting.use_pmi_for_instant_meetings");
  const personalMeeting = readSetting(bundle, "schedule_meeting.personal_meeting");
  const pmiSurface = settingsUnreadable(bundle);
  const pmiScheduledLocked = readLock(bundle, "schedule_meeting.use_pmi_for_scheduled_meetings");
  const pmiInstantLocked = readLock(bundle, "schedule_meeting.use_pmi_for_instant_meetings");
  const pmiLocked = pmiScheduledLocked === true && pmiInstantLocked === true;
  const pmiGroups = groupOverrideState(snapshot, [...new Set([
    ...groupsRelaxing(snapshot, "schedule_meeting.use_pmi_for_scheduled_meetings", false),
    ...groupsRelaxing(snapshot, "schedule_meeting.use_pmi_for_instant_meetings", false),
  ])]);
  const pmiEvidence = {
    use_pmi_for_scheduled_meetings: pmiScheduled.value ?? null,
    use_pmi_for_instant_meetings: pmiInstant.value ?? null,
    personal_meeting: personalMeeting.value ?? null,
    require_password_for_pmi_meetings: readSetting(bundle, "schedule_meeting.require_password_for_pmi_meetings").value ?? null,
    use_pmi_for_scheduled_meetings_locked: pmiScheduledLocked ?? null,
    use_pmi_for_instant_meetings_locked: pmiInstantLocked ?? null,
    ...pmiGroups.evidence,
  };
  const pmiCompliant = personalMeeting.value === false || (pmiScheduled.value === false && pmiInstant.value === false);
  findings.push(finding(
    "ZOOM-MTG-07",
    "Personal Meeting ID usage restricted",
    "medium",
    [25],
    pmiSurface
      ? "manual"
      : personalMeeting.value !== false && (!pmiScheduled.present || !pmiInstant.present)
        ? "manual"
        : !pmiCompliant
          ? "fail"
          : pmiLocked && !pmiGroups.demote
            ? "pass"
            : "warn",
    pmiSurface
      ? manualForSurface(pmiSurface, "the Schedule Meeting > Personal Meeting ID settings")
      : personalMeeting.value !== false && (!pmiScheduled.present || !pmiInstant.present)
        ? manualForAbsentKey("schedule_meeting.use_pmi_for_scheduled_meetings and schedule_meeting.use_pmi_for_instant_meetings", ZOOM_DOCS.accountSettings, "the PMI usage settings")
        : !pmiCompliant
          ? `PMI is used for ${[pmiScheduled.value === true ? "scheduled" : undefined, pmiInstant.value === true ? "instant" : undefined].filter(Boolean).join(" and ")} meetings.`
          : [
            personalMeeting.value === false
              ? "schedule_meeting.personal_meeting is false: Personal Meeting IDs are disabled for the account."
              : "PMI is not used for scheduled or instant meetings (use_pmi_for_scheduled_meetings and use_pmi_for_instant_meetings are false).",
            pairedLockNote([pmiScheduledLocked, pmiInstantLocked], "Both PMI settings", bundle),
            pmiGroups.note,
          ].filter(Boolean).join(" "),
    pmiEvidence,
  ));

  findings.push(booleanControl(
    snapshot,
    "ZOOM-MTG-08",
    "Only authenticated users can join meetings",
    "high",
    [23],
    "meeting_authentication",
    true,
    {
      evidenceToCollect: "the Security > Only authenticated users can join meetings setting (option=meeting_authentication)",
      compliant: "only authenticated users can join meetings.",
      nonCompliant: "unauthenticated participants can join meetings.",
      surfaceName: "account_settings:meeting_authentication",
      lockPath: "schedule_meeting.meeting_authentication",
    },
    { authentication_options: readSetting(bundle, "authentication_options").value ?? null },
  ));

  const customRegions = readSetting(bundle, "in_meeting.custom_data_center_regions");
  const regions = readSetting(bundle, "in_meeting.data_center_regions");
  const regionList = asArray(regions.value).map(asString).filter((item): item is string => Boolean(item));
  const regionSurface = settingsUnreadable(bundle);
  const regionsLocked = readLock(bundle, "in_meeting.custom_data_center_regions");
  const regionGroups = groupOverrideState(snapshot, groupsRelaxing(snapshot, "in_meeting.custom_data_center_regions", true));
  findings.push(finding(
    "ZOOM-MTG-09",
    "Data routing control enabled",
    "critical",
    [18],
    regionSurface
      ? "manual"
      : !customRegions.present
        ? "manual"
        : customRegions.value !== true
          ? "fail"
          : regionList.length === 0
            ? "warn"
            : regionsLocked === true && !regionGroups.demote
              ? "pass"
              : "warn",
    regionSurface
      ? manualForSurface(regionSurface, "the In Meeting (Advanced) > Select data center regions setting")
      : !customRegions.present
        ? manualForAbsentKey(customRegions.path, ZOOM_DOCS.accountSettings, "the data center region selection")
        : customRegions.value !== true
          ? "in_meeting.custom_data_center_regions is false: meeting traffic may route through any Zoom data center region."
          : regionList.length === 0
            ? "in_meeting.custom_data_center_regions is true but in_meeting.data_center_regions is empty or absent, so the allowed regions are unknown."
            : [`Custom data center regions are enabled and limited to: ${regionList.join(", ")}.`, lockNote(regionsLocked, "in_meeting.custom_data_center_regions", bundle), regionGroups.note].filter(Boolean).join(" "),
    { custom_data_center_regions: customRegions.value ?? null, data_center_regions: regionList, locked: regionsLocked ?? null, ...regionGroups.evidence },
  ));

  const disclaimerSurface = settingsUnreadable(bundle);
  const disclaimer = disclaimerSurface
    ? { status: "manual" as ZoomFindingStatus, summary: manualForSurface(disclaimerSurface, "the Recording > Recording notifications setting"), evidence: {} }
    : disclaimerVerdict(bundle);
  const disclaimerGroupsRelaxing = snapshot.groupPolicies
    .filter((policy) => policy.settings.status === "ok")
    .filter((policy) => {
      const value = asString(getNestedValue(policy.settings.data, ["recording", "recording_notification_for_zoom_client", "disclaimer_to_participants"]));
      return value !== undefined && !/all participants/i.test(value);
    })
    .map((policy) => policy.name);
  const disclaimerGroups = groupOverrideState(snapshot, disclaimerGroupsRelaxing);
  const disclaimerStatus: ZoomFindingStatus = disclaimer.status === "pass" && disclaimerGroups.demote ? "warn" : disclaimer.status;
  findings.push(finding(
    "ZOOM-MTG-10",
    "Recording consent disclaimer shown to participants",
    "high",
    [4],
    disclaimerStatus,
    [disclaimer.summary, disclaimerGroups.note].filter(Boolean).join(" "),
    { ...disclaimer.evidence, ...disclaimerGroups.evidence },
  ));

  return {
    title: "Zoom meeting security",
    summary: {
      account_id: snapshot.accountId,
      password_required: readSetting(bundle, "schedule_meeting.require_password_for_scheduling_new_meetings").value ?? null,
      password_locked: readLock(bundle, "schedule_meeting.require_password_for_scheduling_new_meetings") ?? null,
      waiting_room: readSetting(bundle, "meeting_security.waiting_room").value ?? null,
      meeting_authentication: readSetting(bundle, "meeting_authentication").value ?? null,
      who_can_share_screen: whoCanShare.value ?? null,
      local_recording: readSetting(bundle, "recording.local_recording").value ?? null,
      embed_password_in_join_link: readSetting(bundle, "meeting_security.embed_password_in_join_link").value ?? null,
      end_to_end_encrypted_meetings: e2ee.value ?? null,
      custom_data_center_regions: customRegions.value ?? null,
      groups_sampled: snapshot.groupPolicies.length,
      groups_unreadable: groupsUnreadable(snapshot).length,
    },
    findings,
    errors: surfaceErrors([...bundle.settingsSurfaces, ...bundle.lockSurfaces, snapshot.groups, ...groupPolicySurfaces(snapshot)]),
  };
}

export type ZoomAccessCheckOptions = Pick<ZoomCollectionOptions, "now">;

export async function checkZoomAccess(client: ZoomClientLike, options: ZoomAccessCheckOptions = {}): Promise<ZoomAccessCheckResult> {
  const snapshot = await collectZoomSnapshot(client, { groupLimit: 1, now: options.now });
  const config = client.getResolvedConfig();
  const currentUser = asObject(snapshot.currentUser.data) ?? {};

  const toAccessSurface = (surface: ZoomSurface, count?: number): ZoomAccessSurface => ({
    name: surface.name,
    endpoint: surface.endpoint,
    status: surface.status === "ok" ? "readable" : surface.status === "skipped" ? "not_configured" : "not_readable",
    count: surface.status === "ok" ? count : undefined,
    error: surface.status === "ok" ? undefined : surfaceCause(surface),
  });
  const listCount = (surface: ZoomSurface<ZoomListResult<unknown>>) => surface.data?.items.length;

  const surfaces: ZoomAccessSurface[] = [
    toAccessSurface(snapshot.currentUser, 1),
    ...snapshot.settings.settingsSurfaces.map((surface) => toAccessSurface(surface, Object.keys(asObject(surface.data) ?? {}).length)),
    ...snapshot.settings.lockSurfaces.map((surface) => toAccessSurface(surface, Object.keys(asObject(surface.data) ?? {}).length)),
    toAccessSurface(snapshot.users, listCount(snapshot.users)),
    toAccessSurface(snapshot.roles, listCount(snapshot.roles)),
    toAccessSurface(snapshot.groups, listCount(snapshot.groups)),
    toAccessSurface(snapshot.operationLogs, listCount(snapshot.operationLogs)),
    toAccessSurface(snapshot.imGroups, listCount(snapshot.imGroups)),
    toAccessSurface(snapshot.managedDomains, listCount(snapshot.managedDomains)),
    toAccessSurface(snapshot.trustedDomains, listCount(snapshot.trustedDomains)),
    toAccessSurface(snapshot.phoneSettings, Object.keys(asObject(snapshot.phoneSettings.data) ?? {}).length),
  ];

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const coreSurfaces = ["account_settings", "account_settings:security", "account_settings:meeting_security", "users", "roles", "groups"];
  const coreReadable = surfaces.filter((surface) => coreSurfaces.includes(surface.name) && surface.status === "readable").length;
  const status = coreReadable === coreSurfaces.length ? "healthy" : "limited";

  return {
    status,
    accountId: config.accountId,
    surfaces,
    notes: [
      `Using Zoom account ${config.accountId}.`,
      `Authenticated as ${asString(currentUser.email) ?? asString(currentUser.first_name) ?? asString(currentUser.id) ?? "current Zoom admin context"}.`,
      `${readableCount}/${surfaces.length} Zoom audit surfaces are readable.`,
      ...(config.configFile ? [`Configuration file: ${config.configFile}`] : []),
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run zoom_assess_identity, zoom_assess_collaboration_governance, zoom_assess_meeting_security, or zoom_export_audit_bundle."
        : "Grant the Server-to-Server OAuth app account:read:admin, user:read:admin, role:read:admin, group:read:admin, report:read:admin, imgroup:read:admin, and phone:read:admin (or their granular equivalents) and rerun.",
  };
}

export async function assessZoomIdentity(
  client: ZoomClientLike,
  options: ZoomIdentityOptions = {},
): Promise<ZoomAssessmentResult> {
  const snapshot = await collectZoomSnapshot(client, { ...options, include: { identity: true, collaboration: false, meeting: false } });
  return assessZoomIdentityFromSnapshot(snapshot, options);
}

export async function assessZoomCollaborationGovernance(
  client: ZoomClientLike,
  options: ZoomCollaborationOptions = {},
): Promise<ZoomAssessmentResult> {
  const snapshot = await collectZoomSnapshot(client, { ...options, include: { identity: false, collaboration: true, meeting: false } });
  return assessZoomCollaborationGovernanceFromSnapshot(snapshot, options);
}

export async function assessZoomMeetingSecurity(
  client: ZoomClientLike,
  options: ZoomMeetingSecurityOptions = {},
): Promise<ZoomAssessmentResult> {
  const snapshot = await collectZoomSnapshot(client, { ...options, include: { identity: false, collaboration: false, meeting: true } });
  return assessZoomMeetingSecurityFromSnapshot(snapshot, options);
}

function formatAccessCheckText(result: ZoomAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `Zoom access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ZoomAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function statusCounts(findings: ZoomFinding[]): Record<ZoomFindingStatus, number> {
  const counts: Record<ZoomFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(snapshot: ZoomSnapshot, assessments: ZoomAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = statusCounts(findings);
  const coveredControls = new Set(findings.flatMap((item) => item.controls));

  return [
    "# Zoom Executive Summary",
    "",
    `Account: ${snapshot.accountId}`,
    `Collected: ${snapshot.collectedAt}`,
    "",
    "## Result Counts",
    "",
    `- Failed findings: ${counts.fail}`,
    `- Warning findings: ${counts.warn}`,
    `- Manual findings: ${counts.manual}`,
    `- Passing findings: ${counts.pass}`,
    `- Spec controls covered: ${coveredControls.size} of ${ZOOM_SPEC_CONTROLS.length}`,
    `- Collection errors: ${errors.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .slice(0, 12)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Follow-up",
    "",
    ...findings
      .filter((item) => item.status === "manual")
      .map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedMatrix(findings: ZoomFinding[]): string {
  const rows = ZOOM_SPEC_CONTROLS.map((spec) => {
    const related = findings.filter((item) => item.controls.includes(spec.number));
    return [
      String(spec.number),
      spec.name,
      related.map((item) => item.id).join(", ") || "-",
      related.map((item) => item.status.toUpperCase()).join(", ") || "NOT COVERED",
      ...ZOOM_FRAMEWORKS.map((framework) => spec.mappings[framework]),
    ];
  });
  return [
    "# Zoom Unified Compliance Matrix",
    "",
    formatTable(["#", "Control", "Findings", "Status", ...ZOOM_FRAMEWORKS], rows),
  ].join("\n");
}

function frameworkFileName(framework: ZoomFramework): string {
  return `${framework.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.md`;
}

function buildFrameworkReport(framework: ZoomFramework, findings: ZoomFinding[]): string {
  const rows = ZOOM_SPEC_CONTROLS.map((spec) => {
    const related = findings.filter((item) => item.controls.includes(spec.number));
    return [
      spec.mappings[framework],
      `${spec.number}. ${spec.name}`,
      related.map((item) => item.id).join(", ") || "-",
      related.map((item) => item.status.toUpperCase()).join(", ") || "NOT COVERED",
    ];
  });
  const counts = statusCounts(findings);
  return [
    `# ${framework} Report: Zoom`,
    "",
    `Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    formatTable([`${framework} reference`, "Spec control", "Findings", "Status"], rows),
    "",
    "## Finding Details",
    "",
    ...findings.map((item) => `- ${item.id} (${item.status.toUpperCase()}): ${item.title}. ${item.summary}`),
  ].join("\n");
}

function buildQuickReference(result: { outputDir: string; zipPath: string }, findings: ZoomFinding[], errors: string[]): string {
  const counts = statusCounts(findings);
  return [
    "# Zoom Audit Bundle Quick Reference",
    "",
    `- Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    `- Bundle directory: ${basename(result.outputDir)}`,
    `- Archive: ${basename(result.zipPath)}`,
    `- Collection errors: ${errors.length}${errors.length > 0 ? " (see _errors.log)" : ""}`,
    "",
    "## Layout",
    "",
    "- `core_data/`: API snapshots projected to the fields the verdicts read; credential-bearing keys are redacted and no tokens are written",
    "- `analysis/findings.json`: every finding with status, evidence, spec controls, and framework mappings",
    "- `analysis/*.json`: per-assessment summaries (identity, collaboration governance, meeting security)",
    "- `compliance/executive_summary.md`: prioritized summary and manual follow-up list",
    "- `compliance/unified_compliance_matrix.md`: 25 spec controls against every framework",
    `- \`compliance/<framework>.md\`: one report per framework (${ZOOM_FRAMEWORKS.join(", ")})`,
    "- `summary.md`: combined human-readable tool output",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "## Status Semantics",
    "",
    "- pass: documented setting read and compliant, locked where enforcement matters, complete inventory",
    "- warn: compliant but unlocked, partial inventory, undated items, or group overrides",
    "- fail: documented setting read and non-compliant",
    "- manual: endpoint denied or errored, absent key, empty inventory by intent, or not exposed by the API",
  ].join("\n");
}

function describeSurface(surface: ZoomSurface): JsonRecord {
  return {
    name: surface.name,
    endpoint: surface.endpoint,
    doc_url: surface.docUrl,
    status: surface.status,
    http_status: surface.httpStatus ?? null,
    error: surface.error ?? null,
  };
}

/** Bundle snapshot of a settings-style surface: only the paths a verdict read. */
function projectedSettingsSurface(surface: ZoomSurface<JsonRecord>, paths: Iterable<string>): JsonRecord {
  return {
    ...describeSurface(surface),
    data: surface.data === undefined ? null : projectPaths(asObject(surface.data) ?? {}, paths),
  };
}

/** Bundle snapshot of a list surface: only the record fields a verdict read. */
function projectedListSurface(surface: ZoomSurface<ZoomListResult<unknown>>, fields: readonly string[]): JsonRecord {
  const data = surface.data;
  return {
    ...describeSurface(surface),
    data: data === undefined
      ? null
      : {
        items: data.items.map((item) => projectRecord(item, fields)),
        total_records: data.totalRecords ?? null,
        truncated: data.truncated,
        pages: data.pages,
      },
  };
}

export async function exportZoomAuditBundle(
  client: ZoomClientLike,
  config: ZoomResolvedConfig,
  outputRoot: string,
  options: ZoomExportOptions = {},
): Promise<ZoomAuditBundleResult> {
  const snapshot = await collectZoomSnapshot(client, options);
  const access = await checkZoomAccessFromSnapshot(snapshot, config);
  const identity = assessZoomIdentityFromSnapshot(snapshot, options);
  const collaboration = assessZoomCollaborationGovernanceFromSnapshot(snapshot, options);
  const meetingSecurity = assessZoomMeetingSecurityFromSnapshot(snapshot, options);
  const assessments = [identity, collaboration, meetingSecurity];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = surfaceErrors(snapshotSurfaces(snapshot));

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(config.accountId)}-audit-bundle`);
  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  const secrets = credentialValues(config);
  // Second layer for every bundle file: the same scrub the error constructors apply, minus the long-token heuristic (opaque Zoom ids are evidence).
  const write = (relativePathname: string, content: string) =>
    writeSecureTextFile(outputDir, relativePathname, scrubDataText(content, secrets));
  const readPaths = [...snapshot.settings.readPaths].sort();
  const lockPaths = [...snapshot.settings.lockPaths].sort();

  await write("README.md", `${buildQuickReference({ outputDir, zipPath }, findings, errors)}\n`);
  await write("QUICK_REFERENCE.md", `${buildQuickReference({ outputDir, zipPath }, findings, errors)}\n`);
  await write("metadata.json", serializeJson({
    generated_at: (options.now ?? new Date()).toISOString(),
    collected_at: snapshot.collectedAt,
    account_id: config.accountId,
    base_url: config.baseUrl,
    source_chain: config.sourceChain,
    config_file: config.configFile ?? null,
    finding_count: findings.length,
    error_count: errors.length,
    settings_paths_read: readPaths,
    lock_paths_read: lockPaths,
  }));
  await write("summary.md", [
    formatAccessCheckText(access),
    "",
    formatAssessmentText(identity),
    "",
    formatAssessmentText(collaboration),
    "",
    formatAssessmentText(meetingSecurity),
  ].join("\n"));

  await write("core_data/access.json", serializeJson(access));
  await write("core_data/current_user.json", serializeJson({
    ...describeSurface(snapshot.currentUser),
    data: snapshot.currentUser.data === undefined ? null : projectRecord(snapshot.currentUser.data, BUNDLE_RECORD_FIELDS.current_user),
  }));
  await write("core_data/account_settings.json", serializeJson({
    fields_read: readPaths,
    merged: projectPaths(snapshot.settings.settings, readPaths),
    surfaces: snapshot.settings.settingsSurfaces.map((surface) => projectedSettingsSurface(surface, readPaths)),
  }));
  await write("core_data/account_lock_settings.json", serializeJson({
    fields_read: lockPaths,
    merged: projectPaths(snapshot.settings.locks, lockPaths),
    surfaces: snapshot.settings.lockSurfaces.map((surface) => projectedSettingsSurface(surface, lockPaths)),
  }));
  await write("core_data/users.json", serializeJson(projectedListSurface(snapshot.users, BUNDLE_RECORD_FIELDS.users)));
  await write("core_data/roles.json", serializeJson({
    roles: projectedListSurface(snapshot.roles, BUNDLE_RECORD_FIELDS.roles),
    members: Object.values(snapshot.roleMembers).map((surface) => projectedListSurface(surface, BUNDLE_RECORD_FIELDS.role_members)),
  }));
  await write("core_data/groups.json", serializeJson({
    groups: projectedListSurface(snapshot.groups, BUNDLE_RECORD_FIELDS.groups),
    policies: snapshot.groupPolicies.map((policy) => ({
      id: policy.id,
      name: policy.name,
      settings: projectedSettingsSurface(policy.settings, readPaths),
      lock_settings: projectedSettingsSurface(policy.locks, lockPaths),
      settings_views: policy.settingsSurfaces.map(describeSurface),
      lock_views: policy.lockSurfaces.map(describeSurface),
    })),
  }));
  await write("core_data/im_groups.json", serializeJson(projectedListSurface(snapshot.imGroups, BUNDLE_RECORD_FIELDS.im_groups)));
  await write("core_data/managed_domains.json", serializeJson(projectedListSurface(snapshot.managedDomains, BUNDLE_RECORD_FIELDS.managed_domains)));
  await write("core_data/trusted_domains.json", serializeJson(projectedListSurface(snapshot.trustedDomains, [])));
  await write("core_data/operation_logs.json", serializeJson({
    ...projectedListSurface(snapshot.operationLogs, BUNDLE_RECORD_FIELDS.operation_logs),
    from: snapshot.operationLogs.from,
    to: snapshot.operationLogs.to,
  }));
  await write("core_data/phone_account_settings.json", serializeJson(projectedSettingsSurface(snapshot.phoneSettings, BUNDLE_PHONE_PATHS)));

  await write("analysis/findings.json", serializeJson(findings));
  await write("analysis/identity.json", serializeJson(identity));
  await write("analysis/collaboration-governance.json", serializeJson(collaboration));
  await write("analysis/meeting-security.json", serializeJson(meetingSecurity));
  await write("analysis/summary.json", serializeJson({
    counts: statusCounts(findings),
    controls_covered: [...new Set(findings.flatMap((item) => item.controls))].sort((a, b) => a - b),
    controls_total: ZOOM_SPEC_CONTROLS.length,
  }));

  await write("compliance/executive_summary.md", `${buildExecutiveSummary(snapshot, assessments, errors)}\n`);
  await write("compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of ZOOM_FRAMEWORKS) {
    await write(`compliance/${frameworkFileName(framework)}`, `${buildFrameworkReport(framework, findings)}\n`);
  }

  if (errors.length > 0) {
    await write("_errors.log", `${errors.join("\n")}\n`);
  }

  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
  };
}

async function checkZoomAccessFromSnapshot(snapshot: ZoomSnapshot, config: ZoomResolvedConfig): Promise<ZoomAccessCheckResult> {
  const stub: ZoomClientLike = {
    getResolvedConfig: () => config,
    getCurrentUser: async () => unwrap(snapshot.currentUser),
    getAccountSettings: async (option?: string) => unwrap(snapshot.settings.settingsSurfaces.find((surface) => surface.name === (option ? `account_settings:${option}` : "account_settings")) ?? snapshot.settings.settingsSurfaces[0]),
    getAccountLockSettings: async (option?: string) => unwrap(snapshot.settings.lockSurfaces.find((surface) => surface.name === (option ? `account_lock_settings:${option}` : "account_lock_settings")) ?? snapshot.settings.lockSurfaces[0]),
    listUsers: async () => unwrap(snapshot.users),
    listRoles: async () => unwrap(snapshot.roles),
    listRoleMembers: async (roleId: string) => unwrap(snapshot.roleMembers[roleId] ?? skippedSurface("role_members", `/roles/${roleId}/members`, ZOOM_DOCS.roleMembers)),
    listGroups: async () => unwrap(snapshot.groups),
    getGroupSettings: async (groupId: string, option?: string) => unwrap(
      snapshot.groupPolicies.find((policy) => policy.id === groupId)?.settingsSurfaces.find((surface) => surface.name === `group_settings:${groupId}${option ? `:${option}` : ""}`)
        ?? skippedSurface("group_settings", `/groups/${groupId}/settings`, ZOOM_DOCS.groupSettings),
    ),
    getGroupLockSettings: async (groupId: string, option?: string) => unwrap(
      snapshot.groupPolicies.find((policy) => policy.id === groupId)?.lockSurfaces.find((surface) => surface.name === `group_lock_settings:${groupId}${option ? `:${option}` : ""}`)
        ?? skippedSurface("group_lock_settings", `/groups/${groupId}/lock_settings`, ZOOM_DOCS.groupLockSettings),
    ),
    listOperationLogs: async () => unwrap(snapshot.operationLogs),
    listImGroups: async () => unwrap(snapshot.imGroups),
    getManagedDomains: async () => unwrap(snapshot.managedDomains),
    listTrustedDomains: async () => unwrap(snapshot.trustedDomains),
    getPhoneAccountSettings: async () => unwrap(snapshot.phoneSettings),
  };
  return checkZoomAccess(stub, { now: new Date(snapshot.collectedAt) });
}

function unwrap<T>(surface: ZoomSurface<T>): T {
  if (surface.status === "ok" && surface.data !== undefined) return surface.data;
  throw new ZoomApiError(surface.error ?? surfaceCause(surface), surface.httpStatus ?? (surface.status === "denied" ? 403 : 500));
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    account_id: asString(value.account_id),
    token: asString(value.token),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    base_url: asString(value.base_url),
    oauth_base_url: asString(value.oauth_base_url),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    max_admins: asNumber(value.max_admins),
    max_session_inactivity_minutes: asNumber(value.max_session_inactivity_minutes),
  };
}

function normalizeCollaborationArgs(args: unknown): CollaborationArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    group_limit: asNumber(value.group_limit),
    operation_log_limit: asNumber(value.operation_log_limit),
    max_recording_retention_days: asNumber(value.max_recording_retention_days),
  };
}

function normalizeMeetingSecurityArgs(args: unknown): MeetingSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    group_limit: asNumber(value.group_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeCollaborationArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): ZoomApiClient {
  return new ZoomApiClient(resolveZoomConfiguration(args));
}

function toExportOptions(args: ExportAuditBundleArgs): ZoomExportOptions {
  return {
    userLimit: args.user_limit,
    maxAdmins: args.max_admins,
    maxSessionInactivityMinutes: args.max_session_inactivity_minutes,
    groupLimit: args.group_limit,
    operationLogLimit: args.operation_log_limit,
    maxRecordingRetentionDays: args.max_recording_retention_days,
  };
}

const authParams = {
  account_id: Type.Optional(Type.String({ description: "Zoom account ID. Defaults to ZOOM_ACCOUNT_ID or the config file." })),
  token: Type.Optional(Type.String({ description: "Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN." })),
  client_id: Type.Optional(Type.String({ description: "Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID or the config file." })),
  client_secret: Type.Optional(Type.String({ description: "Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET or the config file." })),
  base_url: Type.Optional(Type.String({ description: "Zoom REST API base URL. Defaults to https://api.zoom.us/v2." })),
  oauth_base_url: Type.Optional(Type.String({ description: "Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url." })),
  config_file: Type.Optional(Type.String({ description: "JSON config file with account_id, client_id, client_secret, base_url. Defaults to ZOOM_CONFIG_FILE, ./.zoom.json, or ~/.zoom.json." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const identityParams = {
  user_limit: Type.Optional(Type.Number({ description: "Maximum users to enumerate before flagging a partial inventory. Defaults to 1000.", default: 1000 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable distinct admin users before warning. Defaults to 10.", default: 10 })),
  max_session_inactivity_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable inactivity sign-out period in minutes. Defaults to 120.", default: 120 })),
};

const collaborationParams = {
  group_limit: Type.Optional(Type.Number({ description: "Maximum groups to inspect. Defaults to 50.", default: 50 })),
  operation_log_limit: Type.Optional(Type.Number({ description: "Maximum admin operation log entries to enumerate (30-day window). Defaults to 300.", default: 300 })),
  max_recording_retention_days: Type.Optional(Type.Number({ description: "Maximum acceptable cloud recording retention in days before warning. Defaults to 120.", default: 120 })),
};

export function registerZoomTools(pi: any): void {
  pi.registerTool({
    name: "zoom_check_access",
    label: "Check Zoom audit access",
    description:
      "Validate Zoom read-only access across account settings and lock settings (the default view plus the meeting_authentication, security, and meeting_security option views this tool reads; recording_authentication is not requested because no verdict reads it), users, roles, groups, operation logs, IM groups, managed and trusted domains, and Zoom Phone account settings.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkZoomAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "zoom_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Zoom access check failed: ${errorMessage(error)}`,
          { tool: "zoom_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_identity",
    label: "Assess Zoom identity posture",
    description:
      "Assess Zoom identity posture: SSO enforcement, blocked personal sign-in methods, admin two-factor authentication, managed domain verification, admin privilege concentration, session inactivity timeout, and the manual vanity URL control.",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessZoomIdentity(createClient(args), toExportOptions(args));
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Zoom identity assessment failed: ${errorMessage(error)}`,
          { tool: "zoom_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_collaboration_governance",
    label: "Assess Zoom collaboration governance",
    description:
      "Assess Zoom collaboration governance: trusted domains, in-meeting file transfer, cloud recording auto-delete retention, Zoom Phone recording policies, admin operation logs, IM group restrictions, external contact restrictions, and the manual chat encryption control.",
    parameters: Type.Object({ ...authParams, ...collaborationParams }),
    prepareArguments: normalizeCollaborationArgs,
    async execute(_toolCallId: string, args: CollaborationArgs) {
      try {
        const result = await assessZoomCollaborationGovernance(createClient(args), toExportOptions(args));
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_collaboration_governance", ...result });
      } catch (error) {
        return errorResult(
          `Zoom collaboration governance assessment failed: ${errorMessage(error)}`,
          { tool: "zoom_assess_collaboration_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_meeting_security",
    label: "Assess Zoom meeting security",
    description:
      "Assess Zoom meeting security: passcode enforcement and lock, waiting room, host-only screen sharing, local recording, end-to-end encryption, join-link passcode embedding, PMI restrictions, authenticated join, data center regions, and recording consent disclaimers, with group override detection.",
    parameters: Type.Object({
      ...authParams,
      group_limit: Type.Optional(Type.Number({ description: "Maximum groups to inspect for override drift. Defaults to 50.", default: 50 })),
    }),
    prepareArguments: normalizeMeetingSecurityArgs,
    async execute(_toolCallId: string, args: MeetingSecurityArgs) {
      try {
        const result = await assessZoomMeetingSecurity(createClient(args), { groupLimit: args.group_limit });
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_meeting_security", ...result });
      } catch (error) {
        return errorResult(
          `Zoom meeting security assessment failed: ${errorMessage(error)}`,
          { tool: "zoom_assess_meeting_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_export_audit_bundle",
    label: "Export Zoom audit bundle",
    description:
      "Export a Zoom audit bundle: core_data raw snapshots, analysis findings, compliance reports per framework, QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive named after the allocated directory.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...identityParams,
      ...collaborationParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveZoomConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportZoomAuditBundle(new ZoomApiClient(config), config, outputRoot, toExportOptions(args));
        return textResult(
          [
            "Zoom audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "zoom_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Zoom audit bundle export failed: ${errorMessage(error)}`,
          { tool: "zoom_export_audit_bundle" },
        );
      }
    },
  });
}
