/**
 * Slack Enterprise Grid audit tools for grclanker.
 *
 * Read-only Slack Web API, Admin API, SCIM, and Audit Logs checks
 * grounded in specs/slack-sec-inspector.spec.md. Every method, argument, and
 * response field used here is listed in SLACK_METHODS with the public
 * documentation page it was verified against.
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
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { ConfigFileError, readConfigText } from "./hardening/index.js";
import { errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_WORKSPACE_LIMIT = 50;
const DEFAULT_APP_LIMIT = 500;
const DEFAULT_AUDIT_LIMIT = 200;
const DEFAULT_CHANNEL_LIMIT = 40;
const DEFAULT_SESSION_SAMPLE = 100;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_MIN_RETENTION_DAYS = 365;
const DEFAULT_OUTPUT_DIR = "./export/slack";
const DEFAULT_CONFIG_FILE = join(homedir(), ".config", "grclanker", "slack.json");
const MAX_RATE_LIMIT_RETRIES = 2;
const MAX_PAGES_PER_LIST = 50;
const MAX_RETRY_AFTER_SECONDS = 60;

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;
type HttpVerb = "GET" | "POST";
type TokenKind = "user" | "bot";

interface SlackMethodSpec {
  verb: HttpVerb;
  docs: string;
  tokens: TokenKind[];
  limitMax?: number;
  cursorField: "response_metadata" | "top_level";
}

/**
 * Web API methods used by this tool family. Verb, token types, limit maxima,
 * cursor location, and the response fields read elsewhere in this file were
 * verified against the linked public reference pages.
 */
export const SLACK_METHODS: Record<string, SlackMethodSpec> = {
  "auth.test": { verb: "POST", docs: "https://api.slack.com/methods/auth.test", tokens: ["user", "bot"], cursorField: "response_metadata" },
  "users.list": { verb: "GET", docs: "https://api.slack.com/methods/users.list", tokens: ["user", "bot"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.teams.list": { verb: "POST", docs: "https://api.slack.com/methods/admin.teams.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.teams.settings.info": { verb: "POST", docs: "https://api.slack.com/methods/admin.teams.settings.info", tokens: ["user"], cursorField: "response_metadata" },
  "admin.teams.admins.list": { verb: "GET", docs: "https://api.slack.com/methods/admin.teams.admins.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.users.list": { verb: "POST", docs: "https://api.slack.com/methods/admin.users.list", tokens: ["user"], limitMax: 100, cursorField: "response_metadata" },
  "admin.users.session.getSettings": { verb: "POST", docs: "https://api.slack.com/methods/admin.users.session.getSettings", tokens: ["user"], cursorField: "response_metadata" },
  "admin.apps.approved.list": { verb: "GET", docs: "https://api.slack.com/methods/admin.apps.approved.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.apps.restricted.list": { verb: "GET", docs: "https://api.slack.com/methods/admin.apps.restricted.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.barriers.list": { verb: "GET", docs: "https://api.slack.com/methods/admin.barriers.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.conversations.search": { verb: "POST", docs: "https://api.slack.com/methods/admin.conversations.search", tokens: ["user"], limitMax: 20, cursorField: "top_level" },
  "admin.conversations.getConversationPrefs": { verb: "POST", docs: "https://api.slack.com/methods/admin.conversations.getConversationPrefs", tokens: ["user"], cursorField: "response_metadata" },
  "admin.conversations.getCustomRetention": { verb: "POST", docs: "https://api.slack.com/methods/admin.conversations.getCustomRetention", tokens: ["user"], cursorField: "response_metadata" },
  "admin.emoji.list": { verb: "GET", docs: "https://api.slack.com/methods/admin.emoji.list", tokens: ["user"], limitMax: 1000, cursorField: "response_metadata" },
  "admin.analytics.getFile": { verb: "GET", docs: "https://api.slack.com/methods/admin.analytics.getFile", tokens: ["user"], cursorField: "response_metadata" },
  "team.preferences.list": { verb: "POST", docs: "https://docs.slack.dev/reference/methods/team.preferences.list", tokens: ["user", "bot"], cursorField: "response_metadata" },
};

export const SLACK_DOC_PAGES = {
  auditLogs: "https://docs.slack.dev/admins/audit-logs-api/",
  scim: "https://docs.slack.dev/admins/scim-api/",
  tokenRotation: "https://docs.slack.dev/authentication/using-token-rotation/",
  sessionSetSettings: "https://api.slack.com/methods/admin.users.session.setSettings",
  teamSettingsInfo: "https://api.slack.com/methods/admin.teams.settings.info",
  conversationsSearch: "https://api.slack.com/methods/admin.conversations.search",
  emojiList: "https://api.slack.com/methods/admin.emoji.list",
  analyticsGetFile: "https://api.slack.com/methods/admin.analytics.getFile",
  methodsIndex: "https://docs.slack.dev/reference/methods",
  teamPreferencesList: "https://docs.slack.dev/reference/methods/team.preferences.list",
};

/**
 * Audit Logs API action names matched by the monitoring assessment, verified
 * against https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference
 */
export const SLACK_SECURITY_AUDIT_ACTIONS = [
  "user_login",
  "user_logout",
  "app_installed",
  "app_approved",
  "app_restricted",
  "role_change_to_admin",
  "pref.sso_setting_changed",
  "pref.two_factor_auth_changed",
  "user_deactivated",
] as const;

export const SLACK_EXTERNAL_SHARING_AUDIT_ACTIONS = [
  "external_shared_channel_connected",
  "external_shared_channel_reconnected",
  "external_shared_channel_disconnected",
  "external_shared_channel_disconnect_and_archived",
  "external_shared_channel_invite_created",
  "external_shared_channel_invite_accepted",
  "external_shared_channel_invite_approved",
  "external_shared_channel_invite_declined",
  "external_shared_channel_invite_expired",
  "external_shared_channel_invite_revoked",
  "external_shared_channel_invite_auto_revoked",
  "external_shared_channel_access_upgraded",
] as const;

/**
 * Documented disable_file_uploads values from team.preferences.list, mapped to
 * the control 6 verdict: disallow_all and type:owner,type:admin restrict
 * uploads (pass), type:regular only excludes guests (warn), allow_all fails.
 */
export const SLACK_FILE_UPLOAD_VERDICTS: Record<string, "pass" | "warn" | "fail"> = {
  disallow_all: "pass",
  "type:owner,type:admin": "pass",
  "type:regular": "warn",
  allow_all: "fail",
};

type FrameworkName = "FedRAMP" | "CMMC" | "SOC 2" | "CIS" | "PCI-DSS" | "STIG" | "IRAP" | "ISMAP";

export const SLACK_FRAMEWORKS: FrameworkName[] = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"];

interface SpecControl {
  number: number;
  name: string;
  refs: Array<string | null>;
}

/** Spec section 4 control names and section 5 framework mappings, in table order. */
export const SLACK_SPEC_CONTROLS: SpecControl[] = [
  { number: 1, name: "SSO enforcement", refs: ["IA-2(1)", "3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000149", "ISM-1546", "CPS.AT-1"] },
  { number: 2, name: "Two-factor authentication", refs: ["IA-2(6)", "3.5.3", "CC6.1", "16.3", "8.4.2", "SRG-APP-000150", "ISM-1504", "CPS.AT-2"] },
  { number: 3, name: "Session duration limits", refs: ["AC-12", "3.1.10", "CC6.1", "16.4", "8.2.8", "SRG-APP-000295", "ISM-1164", "CPS.AC-7"] },
  { number: 4, name: "Session idle timeout", refs: ["AC-11", "3.1.11", "CC6.1", "16.5", "8.2.8", "SRG-APP-000190", "ISM-1164", "CPS.AC-7"] },
  { number: 5, name: "Mobile session controls", refs: ["AC-19", "3.1.18", "CC6.7", null, "8.2.8", "SRG-APP-000394", "ISM-1082", "CPS.MP-1"] },
  { number: 6, name: "File upload restrictions", refs: ["SC-7", "3.13.6", "CC6.6", null, "1.3.2", "SRG-APP-000001", "ISM-0331", "CPS.SC-7"] },
  { number: 7, name: "External sharing controls", refs: ["AC-21", "3.1.20", "CC6.6", null, "7.1.2", "SRG-APP-000378", "ISM-0661", "CPS.AC-4"] },
  { number: 8, name: "Information barriers", refs: ["AC-4", "3.1.3", "CC6.6", null, "7.1.1", "SRG-APP-000039", "ISM-1528", "CPS.AC-4"] },
  { number: 9, name: "App management policy", refs: ["CM-7", "3.4.8", "CC6.8", "2.7", "6.3.2", "SRG-APP-000141", "ISM-1624", "CPS.CM-7"] },
  { number: 10, name: "Custom app restrictions", refs: ["CM-7(4)", "3.4.8", "CC6.8", "2.7", "6.3.2", "SRG-APP-000386", "ISM-1624", "CPS.CM-7"] },
  { number: 11, name: "DLP policy configuration", refs: ["SC-7(8)", "3.13.6", "CC6.7", null, null, "SRG-APP-000400", "ISM-0261", "CPS.SC-7"] },
  { number: 12, name: "Channel retention policies", refs: ["AU-11", "3.3.1", "CC7.2", null, "10.7.1", "SRG-APP-000515", "ISM-0859", "CPS.AU-11"] },
  { number: 13, name: "Audit log streaming", refs: ["AU-6(3)", "3.3.5", "CC7.2", "8.2", "10.5.1", "SRG-APP-000516", "ISM-0580", "CPS.AU-6"] },
  { number: 14, name: "Admin role inventory", refs: ["AC-6(5)", "3.1.5", "CC6.3", "16.8", "7.1.1", "SRG-APP-000340", "ISM-1507", "CPS.AC-6"] },
  { number: 15, name: "Guest account controls", refs: ["AC-2(2)", "3.1.1", "CC6.2", "16.7", "7.1.2", "SRG-APP-000024", "ISM-0415", "CPS.AC-2"] },
  { number: 16, name: "Email domain restrictions", refs: ["IA-5", "3.5.7", "CC6.1", null, "8.3.1", "SRG-APP-000173", "ISM-1557", "CPS.IA-5"] },
  { number: 17, name: "Workspace discoverability", refs: ["AC-3", "3.1.1", "CC6.1", null, "7.1.1", "SRG-APP-000033", "ISM-0432", "CPS.AC-3"] },
  { number: 18, name: "Channel posting restrictions", refs: ["AC-3(7)", "3.1.2", "CC6.1", null, "7.1.1", "SRG-APP-000033", "ISM-0405", "CPS.AC-3"] },
  { number: 19, name: "Custom emoji restrictions", refs: ["CM-5", "3.4.5", "CC8.1", null, null, "SRG-APP-000380", "ISM-1624", "CPS.CM-5"] },
  { number: 20, name: "External email ingestion", refs: ["SC-7(4)", "3.13.6", "CC6.6", null, "1.3.2", "SRG-APP-000001", "ISM-0264", "CPS.SC-7"] },
  { number: 21, name: "Link previews and URL unfurling", refs: ["SC-7", "3.13.1", "CC6.6", null, null, "SRG-APP-000001", "ISM-0260", "CPS.SC-7"] },
  { number: 22, name: "SCIM provisioning status", refs: ["AC-2(1)", "3.1.1", "CC6.2", null, "7.1.1", "SRG-APP-000023", "ISM-1594", "CPS.AC-2"] },
  { number: 23, name: "Deactivated user audit", refs: ["AC-2(3)", "3.1.12", "CC6.2", "16.9", "8.1.4", "SRG-APP-000025", "ISM-1591", "CPS.AC-2"] },
  { number: 24, name: "Workspace analytics access", refs: ["AC-6(9)", "3.1.7", "CC6.3", null, "7.1.2", "SRG-APP-000343", "ISM-0988", "CPS.AC-6"] },
  { number: 25, name: "Token rotation and revocation", refs: ["IA-5(1)", "3.5.10", "CC6.1", null, "8.6.3", "SRG-APP-000175", "ISM-1557", "CPS.IA-5"] },
];

export interface SlackConfiguration {
  token?: string;
  botToken?: string;
  scimToken?: string;
  orgId?: string;
  webApiBaseUrl: string;
  scimBaseUrl: string;
  auditBaseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
}

interface SlackApiClientOptions {
  fetchImpl?: FetchImpl;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
}

export interface SlackAccessSurface {
  name: string;
  api: "web" | "scim" | "audit";
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface SlackAccessCheckResult {
  status: "healthy" | "limited";
  auth?: JsonRecord;
  tokenKinds: TokenKind[];
  surfaces: SlackAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type SlackFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface SlackFinding {
  id: string;
  title: string;
  control: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: SlackFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface SlackAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: SlackFinding[];
  errors: string[];
}

export interface SlackAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type CheckAccessArgs = {
  token?: string;
  bot_token?: string;
  scim_token?: string;
  org_id?: string;
  web_api_base_url?: string;
  scim_base_url?: string;
  audit_base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  skip_scim?: boolean;
};

type AdminAccessArgs = CheckAccessArgs & {
  workspace_limit?: number;
  user_limit?: number;
  max_workspace_admins?: number;
  max_session_hours?: number;
  session_sample?: number;
};

type IntegrationsArgs = CheckAccessArgs & {
  app_limit?: number;
  workspace_limit?: number;
};

type MonitoringArgs = CheckAccessArgs & {
  days?: number;
  audit_limit?: number;
};

type ChannelGovernanceArgs = CheckAccessArgs & {
  channel_limit?: number;
  min_retention_days?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  user_limit?: number;
  workspace_limit?: number;
  app_limit?: number;
  audit_limit?: number;
  channel_limit?: number;
  days?: number;
  max_workspace_admins?: number;
  max_session_hours?: number;
  min_retention_days?: number;
  skip_scim?: boolean;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
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

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(asString).filter((item): item is string => Boolean(item));
  const single = asString(value);
  return single ? single.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function asObjectArray(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((item): item is JsonRecord => Boolean(asObject(item))) : [];
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

const CONFIG_FILE_OPTIONS = { label: "Slack" } as const;

/**
 * The shared read guard renders `Unable to read Slack config file <path> (<CODE>)` from the path and the errno code
 * only, never the filesystem wording. The path has been checked with existsSync, so the missing-file result is a race
 * with a deletion and is reported as the read failure it is. Every error string this module creates passes through
 * redactErrorText at the point of creation, this one included.
 */
function readConfigFileText(candidate: string): string {
  try {
    const read = readConfigText(candidate, CONFIG_FILE_OPTIONS);
    if (read.ok) return read.value;
    throw new ConfigFileError({ kind: "read", path: candidate, code: "ENOENT", label: CONFIG_FILE_OPTIONS.label });
  } catch (error) {
    if (!(error instanceof ConfigFileError)) throw error;
    throw new Error(redactErrorText(error.message));
  }
}

function readConfigFile(env: NodeJS.ProcessEnv): { values: JsonRecord; path?: string } {
  const configured = asString(env.SLACK_CONFIG_FILE);
  const candidate = configured ?? DEFAULT_CONFIG_FILE;
  if (!existsSync(candidate)) {
    if (configured) throw new Error(`SLACK_CONFIG_FILE does not exist: ${configured}`);
    return { values: {} };
  }
  const text = readConfigFileText(candidate);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`Unable to parse Slack config file ${candidate}: the file is not valid JSON (parser detail withheld because it can quote the file)`);
  }
  return { values: asObject(parsed) ?? {}, path: candidate };
}

function pickSource(
  label: string,
  argValue: string | undefined,
  envValue: string | undefined,
  fileValue: string | undefined,
  sourceChain: string[],
): string | undefined {
  if (argValue) {
    sourceChain.push(`arguments-${label}`);
    return argValue;
  }
  if (envValue) {
    sourceChain.push(`environment-${label}`);
    return envValue;
  }
  if (fileValue) {
    sourceChain.push(`config-file-${label}`);
    return fileValue;
  }
  return undefined;
}

export function resolveSlackConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): SlackConfiguration {
  const sourceChain: string[] = [];
  const file = readConfigFile(env);
  const token = pickSource(
    "token",
    asString(input.token) ?? asString(input.user_token),
    asString(env.SLACK_USER_TOKEN) ?? asString(env.SLACK_TOKEN),
    asString(file.values.user_token) ?? asString(file.values.token),
    sourceChain,
  );
  const botToken = pickSource(
    "bot-token",
    asString(input.bot_token),
    asString(env.SLACK_BOT_TOKEN),
    asString(file.values.bot_token),
    sourceChain,
  );
  if (!token && !botToken) {
    throw new Error("SLACK_USER_TOKEN (or SLACK_BOT_TOKEN for bot-capable methods), a token argument, or a config file entry is required.");
  }
  const scimToken = pickSource(
    "scim",
    asString(input.scim_token) ?? asString(input.scimToken),
    asString(env.SLACK_SCIM_TOKEN),
    asString(file.values.scim_token),
    sourceChain,
  );
  const orgId = pickSource(
    "org",
    asString(input.org_id) ?? asString(input.enterprise_id),
    asString(env.SLACK_ORG_ID) ?? asString(env.SLACK_ENTERPRISE_ID),
    asString(file.values.org_id),
    sourceChain,
  );
  if (file.path) sourceChain.push("config-file");

  return {
    token,
    botToken,
    scimToken,
    orgId,
    webApiBaseUrl: normalizeBaseUrl(
      asString(input.web_api_base_url) ?? asString(env.SLACK_WEB_API_BASE_URL) ?? "https://slack.com/api",
    ),
    scimBaseUrl: normalizeBaseUrl(
      asString(input.scim_base_url) ?? asString(env.SLACK_SCIM_BASE_URL) ?? "https://api.slack.com/scim/v2",
    ),
    auditBaseUrl: normalizeBaseUrl(
      asString(input.audit_base_url) ?? asString(env.SLACK_AUDIT_BASE_URL) ?? "https://api.slack.com/audit/v1",
    ),
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.SLACK_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
  };
}

function encodeParams(query: JsonRecord): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, Array.isArray(value) ? value.map(String).join(",") : String(value));
  }
  return params;
}

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0 && !Number.isNaN(Date.parse(value))) return value;
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    const timestamp = value > 10_000_000_000 ? value : value * 1000;
    return new Date(timestamp).toISOString();
  }
  return undefined;
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function mappingsFor(control: number): string[] {
  const spec = SLACK_SPEC_CONTROLS.find((item) => item.number === control);
  if (!spec) return [];
  return spec.refs
    .map((ref, index) => (ref ? `${SLACK_FRAMEWORKS[index]} ${ref}` : undefined))
    .filter((item): item is string => Boolean(item));
}

function finding(
  id: string,
  title: string,
  control: number,
  severity: SlackFinding["severity"],
  status: SlackFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): SlackFinding {
  return { id, title, control, severity, status, summary, mappings: mappingsFor(control), evidence };
}

function manualFinding(
  id: string,
  title: string,
  control: number,
  severity: SlackFinding["severity"],
  reason: string,
  evidenceToCollect: string,
  evidence: JsonRecord = {},
): SlackFinding {
  return finding(id, title, control, severity, "manual", `${reason} Manual evidence: ${evidenceToCollect}`, evidence);
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export const SLACK_REDACTION_MARKER = "[REDACTED]";

/** Field names whose values are credentials; the name is kept and the value replaced. */
const SECRET_KEY_PATTERN = /token|secret|password|passwd|webhook|signing|private_key|api_key|apikey|authorization|cookie|credential/i;
/**
 * Names matching the pattern that describe a credential without carrying one. Any future evidence key that
 * matches SECRET_KEY_PATTERN but holds a count or description (for example webhook_count or token_count) must be
 * listed here, or its value is blanked in every bundle.
 */
const SECRET_KEY_ALLOWLIST = new Set(["token_type", "token_kinds", "tokenKinds", "token_format", "token_rotation", "is_token_rotating", "rotating_format", "scim_configured"]);
/** Slack bot, user, refresh, app-level, and rotating tokens, incoming webhook URLs, and bearer headers. */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /xox[abeprs]-[A-Za-z0-9-]{6,}/g,
  /xapp-[A-Za-z0-9-]{6,}/g,
  /https:\/\/hooks\.slack\.com\/[^\s"'<>)]+/g,
  /Bearer\s+[A-Za-z0-9._-]{8,}/g,
  /([?&](?:token|access_token|refresh_token|secret|client_secret|signature|sig|api_key|apikey|key)=)[^&\s"'<>)]+/gi,
];

function isSecretKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(key) && !SECRET_KEY_ALLOWLIST.has(key);
}

/**
 * The documented xox-family token prefixes, the text before the first `-`: bot `xoxb` and user `xoxp`
 * (docs.slack.dev/authentication/tokens), the rotating access forms `xoxe.xoxb` and `xoxe.xoxp`, and the refresh form
 * `xoxe` (docs.slack.dev/authentication/using-token-rotation). token_format evidence is derived only from an exact
 * member of this set, so a configured value with any other prefix (an undocumented letter such as xoxz or xoxa, `xoxe.`
 * followed by anything but xoxb or xoxp, an xapp or xwfp token, a misconfigured value, a proxy or gateway token, a
 * pasted OAuth code) renders the fixed prefix "unknown" and never any substring of itself.
 */
export const SLACK_TOKEN_PREFIXES: ReadonlySet<string> = new Set(["xoxb", "xoxp", "xoxe", "xoxe.xoxb", "xoxe.xoxp"]);
const ROTATING_TOKEN_PREFIX = "xoxe.";
const UNKNOWN_TOKEN_PREFIX = "unknown";

function describeTokenFormat(token: string): JsonRecord {
  const separator = token.indexOf("-");
  const prefix = separator > 0 ? token.slice(0, separator) : "";
  if (!SLACK_TOKEN_PREFIXES.has(prefix)) return { prefix: UNKNOWN_TOKEN_PREFIX, rotating_format: false };
  return { prefix, rotating_format: prefix.startsWith(ROTATING_TOKEN_PREFIX) };
}

/** Shorter configured values are not scrubbed by exact match, so a degenerate token cannot blank unrelated text. */
export const MIN_KNOWN_SECRET_LENGTH = 8;

export function redactSecretText(text: string, knownSecrets: readonly string[] = []): string {
  let output = text;
  for (const secret of knownSecrets) {
    if (secret.length >= MIN_KNOWN_SECRET_LENGTH) output = output.split(secret).join(SLACK_REDACTION_MARKER);
  }
  for (const pattern of SECRET_VALUE_PATTERNS) {
    output = output.replace(pattern, (match, prefix: unknown) => (typeof prefix === "string" ? `${prefix}${SLACK_REDACTION_MARKER}` : SLACK_REDACTION_MARKER));
  }
  return output;
}

/**
 * Header- and assignment-style credentials as they appear in proxy error pages, gateway responses, and logs (a
 * cookie or authorization header, an API key header, a session id, a quoted JSON credential): the name is kept and
 * the value replaced. Bare "token" is deliberately absent so ordinary prose such as "token: user" is preserved.
 */
const CREDENTIAL_ASSIGNMENT_PATTERNS: RegExp[] = [
  /((?:set-)?cookie\s*[:=]\s*)[^\r\n<>"']+/gi,
  /(authorization\s*[:=]\s*)[^\r\n<>"',;]+/gi,
  /(\b(?:x-)?(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:id|token|key)|sessionid|jsessionid|phpsessid|client[_-]?secret|secret[_-]?key|password|passwd)["']?\s*[:=]\s*["']?)[^\s"'<>;&,]+/gi,
];

/**
 * The single scrub every error string passes through at the point it is created (SlackApiError, surfaceError,
 * describeError) and again at the bundle sink: configured tokens, Slack token shapes, webhook and credential URLs,
 * bearer headers, and header- or assignment-style credentials. Non-JSON response bodies never reach an error string
 * in the first place (SlackApiClient.httpError describes them instead); this guards everything that does.
 */
export function redactErrorText(text: string, knownSecrets: readonly string[] = []): string {
  let output = redactSecretText(text, knownSecrets);
  for (const pattern of CREDENTIAL_ASSIGNMENT_PATTERNS) {
    output = output.replace(pattern, (match, prefix: unknown) => (typeof prefix === "string" ? `${prefix}${SLACK_REDACTION_MARKER}` : SLACK_REDACTION_MARKER));
  }
  return output;
}

export function redactSecrets<T>(value: T, knownSecrets: readonly string[] = []): T {
  if (typeof value === "string") return redactSecretText(value, knownSecrets) as T;
  if (Array.isArray(value)) return value.map((item) => redactSecrets(item, knownSecrets)) as T;
  if (value && typeof value === "object") {
    const output: JsonRecord = {};
    for (const [key, item] of Object.entries(value as JsonRecord)) {
      output[key] = isSecretKey(key) && item !== null && item !== undefined ? SLACK_REDACTION_MARKER : redactSecrets(item, knownSecrets);
    }
    return output as T;
  }
  return value;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "slack";
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
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
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
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    count += entry.isDirectory() ? await countFilesRecursively(fullPath) : 1;
  }
  return count;
}

/** Every message and error code is scrubbed here, so no consumer can receive an unscrubbed string. */
export class SlackApiError extends Error {
  readonly method: string;
  readonly code?: string;
  readonly httpStatus?: number;

  constructor(message: string, method: string, code?: string, httpStatus?: number) {
    super(redactErrorText(message));
    this.name = "SlackApiError";
    this.method = method;
    this.code = code === undefined ? undefined : redactErrorText(code);
    this.httpStatus = httpStatus;
  }
}

/** The shape of a Slack error or warning code (snake_case); a second gate behind the documented vocabulary below. */
const SLACK_ERROR_CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
/**
 * The shape of a documented OAuth scope, as listed in the needed and provided fields: lowercase words joined by
 * `.`, `_`, or `-` (admin.app_activities, incoming-webhook), at most two `:` groups (users:read.email,
 * files:write:user), segments of at most 24 letters, and no digits anywhere. A hex, base32, or base64 credential
 * carries digits or uppercase and fails the shape; the configured secrets are removed from the list before it is
 * checked.
 */
const SLACK_SCOPE_PATTERN = /^[a-z][a-z_-]{0,23}(?:\.[a-z][a-z_-]{0,23}){0,3}(?::[a-z][a-z_]{0,23}(?:\.[a-z][a-z_]{0,23}){0,3}){0,2}$/;
export const UNKNOWN_ERROR_CODE = "UnknownError";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
/** RFC 7644 section 3.12, Table 9: the scimType keywords. A scimType outside this vocabulary is dropped, whatever its shape. */
const SCIM_TYPES = new Set(["invalidFilter", "tooMany", "uniqueness", "mutability", "invalidSyntax", "invalidPath", "noTarget", "invalidValue", "invalidVers", "sensitive"]);

/**
 * Slack's documented error codes: the common errors table every Web API method page carries, the method-specific
 * codes of the sixteen methods this module calls (docs.slack.dev/reference/methods/<method>, "Errors"), the
 * JSON-body errors of the Web API overview (docs.slack.dev/apis/web-api), the conversations-family code the review
 * named, and the Audit Logs API errors table (docs.slack.dev/reference/audit-logs-api/methods-actions-reference).
 * A body value outside this vocabulary is not rendered: the method pages say other errors can be returned when the
 * service is down, and such a value renders as the fixed placeholder rather than verbatim, so a credential that an
 * endpoint or a proxy returns in the `error` field can never pass as a code.
 */
export const SLACK_DOCUMENTED_ERROR_CODES: ReadonlySet<string> = new Set([
  // Common Web API errors, present on every method page.
  "access_denied", "accesslimited", "account_inactive", "deprecated_endpoint", "ekm_access_denied",
  "enterprise_is_restricted", "fatal_error", "internal_error", "invalid_arg_name", "invalid_arguments",
  "invalid_array_arg", "invalid_auth", "invalid_charset", "invalid_form_data", "invalid_post_type",
  "method_deprecated", "missing_post_type", "missing_scope", "no_permission", "not_allowed_token_type",
  "not_authed", "org_login_required", "ratelimited", "request_timeout", "service_unavailable",
  "team_access_not_granted", "team_added_to_org", "token_expired", "token_revoked", "two_factor_setup_required",
  // Method-specific errors of the methods this module calls.
  "admin_unauthorized", "app_management_app_not_installed_on_org", "bots_not_allowed", "channel_not_found",
  "channel_type_not_supported", "connected_team_passed_in_is_not_top_level_team", "could_not_get_conversation_prefs",
  "could_not_get_retention", "data_not_available", "default_org_wide_channel", "external_team_not_connected_to_this_org",
  "failed_to_fetch_info", "feature_not_available", "feature_not_enabled", "file_not_found", "file_not_yet_available",
  "include_deactivated_user_workspaces_invalid", "invalid_actor", "invalid_cursor", "invalid_date", "invalid_limit",
  "invalid_search_channel_type", "invalid_sort", "invalid_sort_dir", "invalid_team", "invalid_type", "limit_required",
  "member_analytics_disabled", "metadata_not_available", "metadata_only_does_not_support_date", "missing_argument",
  "not_allowed", "not_an_admin", "not_an_enterprise", "org_level_email_display_disabled", "restricted_action",
  "retention_override_not_allowed", "team_not_found", "too_many_teams_provided", "unknown_method",
  "user_cannot_manage_public_channels", "user_not_found",
  // Conversations-family code named in the review.
  "method_not_supported_for_channel_type",
  // JSON-body errors from the Web API overview.
  "invalid_json", "json_not_object",
  // Audit Logs API errors table.
  "bad_endpoint", "invalid_action", "invalid_authentication", "invalid_range", "invalid_workspace",
  "method_not_allowed", "missing_authentication", "rate_limited", "team_not_authorized", "user_not_authorized",
]);

/** The documented warning codes (charset notes on the Web API pages) beside the error vocabulary, for the `warning` list. */
const SLACK_DOCUMENTED_WARNING_CODES: ReadonlySet<string> = new Set(["missing_charset", "superfluous_charset", ...SLACK_DOCUMENTED_ERROR_CODES]);

/**
 * One code copied from a response body, rendered only when the token scrub with the configured secrets leaves it
 * unchanged, it has the documented shape, and it is in the documented vocabulary; otherwise the fixed placeholder.
 * The scrub runs first so a configured credential can never survive as a code whatever its shape, and the
 * vocabulary is what keeps an undocumented value (a credential from an endpoint or a proxy) out of every string.
 */
function documentedCode(value: string, pattern: RegExp, vocabulary: ReadonlySet<string> | undefined, secrets: readonly string[]): string {
  if (redactErrorText(value, secrets) !== value) return UNKNOWN_ERROR_CODE;
  if (!pattern.test(value)) return UNKNOWN_ERROR_CODE;
  if (vocabulary !== undefined && !vocabulary.has(value)) return UNKNOWN_ERROR_CODE;
  return value;
}

/** A vendor error code copied from a response body: scrubbed with the configured secrets, then validated against the documented vocabulary. */
export function vendorErrorCode(value: unknown, secrets: readonly string[] = []): string {
  return typeof value === "string" ? documentedCode(value, SLACK_ERROR_CODE_PATTERN, SLACK_DOCUMENTED_ERROR_CODES, secrets) : UNKNOWN_ERROR_CODE;
}

/** Which documented list a comma-separated body field is checked against. */
type SlackCodeList = "scopes" | "warnings";

function vendorCodeList(value: unknown, list: SlackCodeList, secrets: readonly string[]): string {
  const items = typeof value === "string" ? value.split(",").map((item) => item.trim()).filter((item) => item.length > 0) : [];
  if (items.length === 0) return UNKNOWN_ERROR_CODE;
  switch (list) {
    case "scopes":
      return items.map((item) => documentedCode(item, SLACK_SCOPE_PATTERN, undefined, secrets)).join(",");
    case "warnings":
      return items.map((item) => documentedCode(item, SLACK_ERROR_CODE_PATTERN, SLACK_DOCUMENTED_WARNING_CODES, secrets)).join(",");
    default: {
      const exhaustive: never = list;
      throw new Error(`Unhandled Slack code list ${String(exhaustive)}`);
    }
  }
}

function validHttpStatus(value: unknown): number | undefined {
  const status = typeof value === "number" ? value : typeof value === "string" && /^\d{3}$/.test(value) ? Number(value) : undefined;
  return status !== undefined && Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined;
}

function validScimType(value: unknown): string | undefined {
  return typeof value === "string" && SCIM_TYPES.has(value) ? value : undefined;
}

/**
 * Which Slack API answered a request. The error renderer reads only the fields that API documents, so a Web API
 * or Audit Logs body cannot be read as a SCIM error because a gateway added a `detail` field, and a SCIM body
 * cannot be read as a Web API error.
 */
export type SlackApiFamily = "web" | "audit" | "scim";

const WITHHELD_ERROR_FIELDS = "JSON body without documented error fields withheld";

/** True when the body carries the SCIM 2.0 error discriminator (RFC 7644 section 3.12): the `schemas` array names the Error message schema. */
function isScimErrorBody(json: JsonRecord): boolean {
  return Array.isArray(json.schemas) && json.schemas.includes(SCIM_ERROR_SCHEMA);
}

/**
 * Renders only the documented fields of a JSON error body, chosen by the API that was called rather than by the
 * fields the body happens to carry. Web API and Audit Logs bodies (`ok: false` with an `error` code, optional
 * `needed`, `provided`, `warning`): `error` (a code in the documented vocabulary), `needed` and `provided`
 * (scope-shaped lists), `warning` (documented code list), each scrubbed with the configured secrets first; a
 * `detail`, `status`, or `scimType` field in such a body is gateway text and is dropped. SCIM bodies: only a body
 * carrying the SCIM 2.0 error schema renders `status` (validated integer), `scimType` (RFC 7644 keyword, else
 * dropped), and `detail` (scrubbed with the configured secrets and cut); a SCIM body without the discriminator is
 * withheld. Every other field, including response_metadata.messages, is dropped rather than echoed.
 */
export function describeErrorFields(json: JsonRecord, family: SlackApiFamily, secrets: readonly string[] = []): string {
  const parts: string[] = [];
  switch (family) {
    case "web":
    case "audit":
      if (json.error !== undefined) parts.push(`error=${vendorErrorCode(json.error, secrets)}`);
      if (json.needed !== undefined) parts.push(`needed=${vendorCodeList(json.needed, "scopes", secrets)}`);
      if (json.provided !== undefined) parts.push(`provided=${vendorCodeList(json.provided, "scopes", secrets)}`);
      if (json.warning !== undefined) parts.push(`warning=${vendorCodeList(json.warning, "warnings", secrets)}`);
      break;
    case "scim": {
      if (!isScimErrorBody(json)) return WITHHELD_ERROR_FIELDS;
      const status = validHttpStatus(json.status);
      if (status !== undefined) parts.push(`status=${status}`);
      const scimType = validScimType(json.scimType);
      if (scimType !== undefined) parts.push(`scimType=${scimType}`);
      if (typeof json.detail === "string") parts.push(`detail=${redactErrorText(json.detail, secrets).slice(0, 200)}`);
      break;
    }
    default: {
      const exhaustive: never = family;
      throw new Error(`Unhandled Slack API family ${String(exhaustive)}`);
    }
  }
  return parts.length > 0 ? parts.join(" ") : WITHHELD_ERROR_FIELDS;
}

/** Describes a response body that is not a JSON object without quoting any of it. */
function withheldBody(response: Response, text: string): string {
  const contentType = (response.headers.get("content-type") ?? "").split(";")[0].trim() || "unknown content type";
  return `non-JSON ${contentType} body (${text.length} characters) withheld`;
}

/** Why a paginated collection stopped before the cursor was exhausted. */
export type SlackTruncation = "item_cap" | "page_cap" | "stalled_cursor" | "unknown_total";

export interface SlackPage {
  items: JsonRecord[];
  complete: boolean;
  pages: number;
  total?: number;
  truncation?: SlackTruncation;
}

export class SlackApiClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    private readonly config: SlackConfiguration,
    options: SlackApiClientOptions = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? ((ms: number) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }

  private async fetchWithRateLimit(url: URL, init: RequestInit): Promise<Response> {
    for (let attempt = 0; ; attempt += 1) {
      const response = await this.fetchWithTimeout(url.toString(), init);
      if (response.status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
        const retryAfter = clampNumber(asNumber(response.headers.get("retry-after")), 1, 1, MAX_RETRY_AFTER_SECONDS);
        await this.sleep(retryAfter * 1000);
        continue;
      }
      return response;
    }
  }

  knownSecrets(): string[] {
    return [this.config.token, this.config.botToken, this.config.scimToken].filter((item): item is string => Boolean(item));
  }

  redactText(text: string): string {
    return redactSecretText(text, this.knownSecrets());
  }

  /**
   * A JSON error body is never echoed: only the fields documented for the API that was called are rendered, codes
   * pattern-validated and SCIM detail scrubbed and cut (describeErrorFields); any other body (an HTML error page
   * from a proxy or gateway, plain text) is only described by content type and length. The SlackApiError
   * constructor scrubs the result again.
   */
  private describeBody(family: SlackApiFamily, response: Response, text: string): string {
    const json = parseJsonRecord(text);
    return json ? describeErrorFields(json, family, this.knownSecrets()) : withheldBody(response, text);
  }

  private httpError(label: string, family: SlackApiFamily, response: Response, text: string): SlackApiError {
    return new SlackApiError(
      `${label} failed (HTTP ${response.status}) ${this.describeBody(family, response, text)}`,
      label,
      response.status === 401 || response.status === 403 ? "http_forbidden" : `http_${response.status}`,
      response.status,
    );
  }

  private parseOkJson(label: string, response: Response, text: string): JsonRecord {
    if (text.trim().length === 0) return {};
    const json = parseJsonRecord(text);
    if (!json) {
      throw new SlackApiError(`${label} failed (HTTP ${response.status}) ${withheldBody(response, text)}`, label, "non_json_body", response.status);
    }
    if (json.ok === false) {
      const code = json.error === undefined ? "ok_false" : vendorErrorCode(json.error, this.knownSecrets());
      throw new SlackApiError(`${label} failed: ${code}`, label, code, response.status);
    }
    return redactSecrets(json, this.knownSecrets());
  }

  private async fetchJson(url: URL, init: RequestInit, label: string, family: SlackApiFamily): Promise<JsonRecord> {
    const response = await this.fetchWithRateLimit(url, init);
    const text = await response.text();
    if (!response.ok) throw this.httpError(label, family, response, text);
    return this.parseOkJson(label, response, text);
  }

  /**
   * Capability probe for admin.analytics.getFile: success is a gzipped
   * newline-delimited JSON file with Content-type application/gzip, failure is
   * a JSON body with ok:false. The file body is never downloaded.
   */
  async probeAnalyticsExport(): Promise<{ content_type: string }> {
    const method = "admin.analytics.getFile";
    const label = `Slack Web API ${method}`;
    const url = new URL(`${this.config.webApiBaseUrl}/${method}`);
    url.search = encodeParams({ type: "public_channel", metadata_only: true }).toString();
    const response = await this.fetchWithRateLimit(url, {
      method: "GET",
      headers: { accept: "application/gzip, application/json", authorization: `Bearer ${this.tokenFor(method)}` },
    });
    const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
    if (!response.ok) {
      const text = await response.text();
      throw this.httpError(label, "web", response, text);
    }
    if (contentType.includes("gzip")) {
      await response.body?.cancel().catch(() => undefined);
      return { content_type: contentType };
    }
    const text = await response.text();
    const json = parseJsonRecord(text);
    if (json) this.parseOkJson(label, response, text);
    return { content_type: contentType || (json ? "application/json" : "unknown") };
  }

  private tokenFor(method: string): string {
    const spec = SLACK_METHODS[method];
    const allowsBot = spec?.tokens.includes("bot") ?? false;
    if (this.config.token) return this.config.token;
    if (allowsBot && this.config.botToken) return this.config.botToken;
    throw new SlackApiError(
      `Slack Web API ${method} requires a user token (not_allowed_token_type); only a bot token is configured.`,
      method,
      "not_allowed_token_type",
    );
  }

  async web(method: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const spec = SLACK_METHODS[method];
    const token = this.tokenFor(method);
    const label = `Slack Web API ${method}`;
    const params = encodeParams(query);
    if (spec?.verb === "POST") {
      return this.fetchJson(new URL(`${this.config.webApiBaseUrl}/${method}`), {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Bearer ${token}`,
        },
        body: params.toString(),
      }, label, "web");
    }
    const url = new URL(`${this.config.webApiBaseUrl}/${method}`);
    url.search = params.toString();
    return this.fetchJson(url, {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${token}` },
    }, label, "web");
  }

  async scim(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    if (!this.config.scimToken) {
      throw new SlackApiError("SLACK_SCIM_TOKEN is required for Slack SCIM checks.", `SCIM ${path}`, "not_configured");
    }
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(`${this.config.scimBaseUrl}${normalizedPath}`);
    url.search = encodeParams(query).toString();
    return this.fetchJson(url, {
      method: "GET",
      headers: {
        accept: "application/scim+json,application/json",
        authorization: `Bearer ${this.config.scimToken}`,
      },
    }, `Slack SCIM ${normalizedPath}`, "scim");
  }

  async audit(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    if (!this.config.token) {
      throw new SlackApiError("The Audit Logs API requires an org-level user token.", `Audit Logs ${path}`, "not_allowed_token_type");
    }
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(`${this.config.auditBaseUrl}${normalizedPath}`);
    url.search = encodeParams(query).toString();
    return this.fetchJson(url, {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${this.config.token}` },
    }, `Slack Audit Logs ${normalizedPath}`, "audit");
  }

  async paginateWeb(
    method: string,
    itemKeys: string[],
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<JsonRecord[]> {
    return (await this.collectWeb(method, itemKeys, query, options)).items;
  }

  async collectWeb(
    method: string,
    itemKeys: string[],
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<SlackPage> {
    const spec = SLACK_METHODS[method];
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const pageLimit = clampNumber(options.pageLimit, Math.min(spec?.limitMax ?? 200, 200), 1, spec?.limitMax ?? 1000);
    let cursor: string | undefined;
    let pages = 0;
    let total: number | undefined;
    const items: JsonRecord[] = [];

    let truncation: SlackTruncation | undefined;
    do {
      const page = await this.web(method, { ...query, limit: pageLimit, cursor });
      pages += 1;
      const pageItems = itemKeys.flatMap((key) => (Array.isArray(page[key]) ? page[key] : []))
        .map((item) => asObject(item) ?? (asString(item) ? { id: asString(item) } : undefined))
        .filter((item): item is JsonRecord => Boolean(item));
      const accepted = pageItems.slice(0, Math.max(0, limit - items.length));
      items.push(...accepted);
      total = asNumber(page.total_count) ?? total;
      cursor = spec?.cursorField === "top_level"
        ? asString(page.next_cursor)
        : asString(asObject(page.response_metadata)?.next_cursor);
      if (accepted.length < pageItems.length) truncation = "item_cap";
      else if (cursor && pageItems.length === 0) truncation = "stalled_cursor";
      else if (cursor && items.length >= limit) truncation = "item_cap";
      else if (cursor && pages >= MAX_PAGES_PER_LIST) truncation = "page_cap";
    } while (cursor && !truncation);

    return { items, complete: truncation === undefined && !cursor, pages, total, truncation };
  }

  async paginateScim(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<JsonRecord[]> {
    return (await this.collectScim(path, query, options)).items;
  }

  async collectScim(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<SlackPage> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const pageLimit = clampNumber(options.pageLimit, 100, 1, 1000);
    let startIndex = asNumber(query.startIndex) ?? 1;
    let pages = 0;
    let total: number | undefined;
    const items: JsonRecord[] = [];

    let truncation: SlackTruncation | undefined;
    for (;;) {
      const page = await this.scim(path, { ...query, startIndex, count: pageLimit });
      pages += 1;
      const resources = asObjectArray(page.Resources);
      const accepted = resources.slice(0, Math.max(0, limit - items.length));
      items.push(...accepted);
      total = asNumber(page.totalResults) ?? total;
      if (total === undefined) {
        truncation = "unknown_total";
        break;
      }
      if (accepted.length < resources.length || (items.length >= limit && items.length < total)) {
        truncation = "item_cap";
        break;
      }
      if (items.length >= total) break;
      if (resources.length === 0) {
        truncation = "stalled_cursor";
        break;
      }
      if (pages >= MAX_PAGES_PER_LIST) {
        truncation = "page_cap";
        break;
      }
      startIndex += resources.length;
    }

    return { items, complete: truncation === undefined, pages, total, truncation };
  }

  getNow(): Date {
    return this.now();
  }

  getOrgQuery(): JsonRecord {
    return this.config.orgId ? { enterprise_id: this.config.orgId } : {};
  }

  getTokenKinds(): TokenKind[] {
    const kinds: TokenKind[] = [];
    if (this.config.token) kinds.push("user");
    if (this.config.botToken) kinds.push("bot");
    return kinds;
  }

  describeToken(): JsonRecord {
    return describeTokenFormat(this.config.token ?? this.config.botToken ?? "");
  }
}

type ReadResult<T> =
  | { ok: true; value: T; complete: boolean; total?: number; truncation?: SlackTruncation; error?: undefined; code?: undefined }
  | { ok: false; error: string; code?: string; value?: undefined; complete?: undefined; total?: undefined; truncation?: undefined };

function surfaceError(error: unknown): string {
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

function parseJsonRecord(text: string): JsonRecord | undefined {
  if (!text.trimStart().startsWith("{")) return undefined;
  try {
    return asObject(JSON.parse(text));
  } catch {
    return undefined;
  }
}

function errorCode(error: unknown): string | undefined {
  return error instanceof SlackApiError ? error.code : undefined;
}

async function readWeb(client: SlackApiClient, method: string, query: JsonRecord = {}): Promise<ReadResult<JsonRecord>> {
  try {
    return { ok: true, value: await client.web(method, query), complete: true };
  } catch (error) {
    return { ok: false, error: surfaceError(error), code: errorCode(error) };
  }
}

async function readAnalyticsProbe(client: SlackApiClient): Promise<ReadResult<{ content_type: string }>> {
  try {
    return { ok: true, value: await client.probeAnalyticsExport(), complete: true };
  } catch (error) {
    return { ok: false, error: surfaceError(error), code: errorCode(error) };
  }
}

interface SlackEmojiEntry {
  name: string;
  uploaded_by?: string;
  date_created?: string;
}

/**
 * admin.emoji.list returns a name-keyed map rather than an array, so it cannot go through collectWeb.
 * The loop records the same exit reasons: an empty page with a cursor outstanding is a stalled cursor
 * and stops on the spot; MAX_PAGES_PER_LIST requests with a cursor outstanding is the page cap.
 */
async function collectEmoji(client: SlackApiClient): Promise<ReadResult<SlackEmojiEntry[]>> {
  const entries: SlackEmojiEntry[] = [];
  let truncation: SlackTruncation | undefined;
  let cursor: string | undefined;
  let pages = 0;
  try {
    do {
      const page = await client.web("admin.emoji.list", { limit: 1000, cursor });
      pages += 1;
      const emoji = Object.entries(asObject(page.emoji) ?? {});
      for (const [name, value] of emoji) {
        const record = asObject(value);
        entries.push({ name, uploaded_by: asString(record?.uploaded_by), date_created: extractTimestamp(record?.date_created) });
      }
      cursor = asString(asObject(page.response_metadata)?.next_cursor);
      if (cursor && emoji.length === 0) truncation = "stalled_cursor";
      else if (cursor && pages >= MAX_PAGES_PER_LIST) truncation = "page_cap";
    } while (cursor && !truncation);
  } catch (error) {
    return { ok: false, error: surfaceError(error), code: errorCode(error) };
  }
  return { ok: true, value: entries, complete: truncation === undefined && !cursor, truncation };
}

async function readWebList(
  client: SlackApiClient,
  method: string,
  itemKeys: string[],
  query: JsonRecord = {},
  options: { limit?: number; pageLimit?: number } = {},
): Promise<ReadResult<JsonRecord[]>> {
  try {
    const page = await client.collectWeb(method, itemKeys, query, options);
    return { ok: true, value: page.items, complete: page.complete, total: page.total, truncation: page.truncation };
  } catch (error) {
    return { ok: false, error: surfaceError(error), code: errorCode(error) };
  }
}

function unreadableReason(result: { error: string; code?: string }): string {
  const code = result.code;
  if (code === "not_allowed_token_type") return `${result.error} (requires an org-level user token)`;
  if (code === "missing_scope") return `${result.error} (grant the documented scope)`;
  if (code === "not_an_enterprise" || code === "feature_not_enabled" || code === "enterprise_is_restricted") {
    return `${result.error} (requires an Enterprise Grid plan with the Admin API feature)`;
  }
  return result.error;
}

function truncationNote(truncation: SlackTruncation | undefined): string {
  switch (truncation) {
    case "item_cap":
      return "item limit reached";
    case "page_cap":
      return `page cap of ${MAX_PAGES_PER_LIST} reached`;
    case "stalled_cursor":
      return "cursor returned an empty page";
    case "unknown_total":
      return "total count missing from the response";
    case undefined:
      return "pagination capped";
    default: {
      const exhaustive: never = truncation;
      return String(exhaustive);
    }
  }
}

function partialNote(seen: number, complete: boolean, total?: number, truncation?: SlackTruncation): string {
  if (complete) return `${seen} seen (complete)`;
  return `${seen} seen of ${total ?? "unknown total"} (partial view, ${truncationNote(truncation)})`;
}

function inventoryCount<T>(result: ReadResult<T>, count: number): number | null {
  return result.ok ? count : null;
}

function inventoryStatus<T>(result: ReadResult<T>, endpoint: string): string {
  if (!result.ok) return `unreadable: ${endpoint} ${result.error}`;
  return result.complete ? `complete: ${endpoint}` : `partial: ${endpoint} ${truncationNote(result.truncation)}`;
}

function notCollected(upstream: string, error: string, consequence: string): string {
  return `not collected: ${upstream} was unreadable (${error}), so ${consequence}`;
}

async function webSurface(
  client: SlackApiClient,
  name: string,
  method: string,
  itemKeys: string[] = [],
  query: JsonRecord = {},
): Promise<SlackAccessSurface> {
  try {
    const spec = SLACK_METHODS[method];
    const result = await client.web(method, spec?.limitMax ? { ...query, limit: 1 } : query);
    return {
      name,
      api: "web",
      endpoint: method,
      status: "readable",
      count: itemKeys.length > 0 ? itemKeys.reduce((sum, key) => sum + asObjectArray(result[key]).length, 0) : 1,
    };
  } catch (error) {
    return { name, api: "web", endpoint: method, status: "not_readable", error: surfaceError(error) };
  }
}

async function scimSurface(client: SlackApiClient, name: string, path: string): Promise<SlackAccessSurface> {
  try {
    const result = await client.scim(path, path === "/ServiceProviderConfig" ? {} : { count: 1 });
    return {
      name,
      api: "scim",
      endpoint: path,
      status: "readable",
      count: path === "/ServiceProviderConfig" ? 1 : asNumber(result.totalResults) ?? asObjectArray(result.Resources).length,
    };
  } catch (error) {
    const status = errorCode(error) === "not_configured" ? "not_configured" : "not_readable";
    return { name, api: "scim", endpoint: path, status, error: surfaceError(error) };
  }
}

async function auditSurface(client: SlackApiClient, name: string, path: string): Promise<SlackAccessSurface> {
  try {
    const result = await client.audit(path, path === "/logs" ? { limit: 1 } : {});
    return {
      name,
      api: "audit",
      endpoint: path,
      status: "readable",
      count: asObjectArray(result.entries).length + asObjectArray(result.schemas).length,
    };
  } catch (error) {
    return { name, api: "audit", endpoint: path, status: "not_readable", error: surfaceError(error) };
  }
}

export async function checkSlackAccess(client: SlackApiClient): Promise<SlackAccessCheckResult> {
  const auth = await client.web("auth.test");
  const orgQuery = client.getOrgQuery();
  const surfaces = await Promise.all([
    webSurface(client, "auth", "auth.test"),
    webSurface(client, "workspaces", "admin.teams.list", ["teams"]),
    webSurface(client, "users", "users.list", ["members"], asString(auth.team_id) ? { team_id: auth.team_id } : {}),
    webSurface(client, "admin_users", "admin.users.list", ["users"]),
    webSurface(client, "approved_apps", "admin.apps.approved.list", ["approved_apps"], orgQuery),
    webSurface(client, "restricted_apps", "admin.apps.restricted.list", ["restricted_apps"], orgQuery),
    webSurface(client, "information_barriers", "admin.barriers.list", ["barriers"]),
    webSurface(client, "channels", "admin.conversations.search", ["conversations"], { total_count_only: true }),
    webSurface(client, "emoji", "admin.emoji.list"),
    webSurface(client, "team_preferences", "team.preferences.list"),
    auditSurface(client, "audit_logs", "/logs"),
    auditSurface(client, "audit_schemas", "/schemas"),
    scimSurface(client, "scim_users", "/Users"),
    scimSurface(client, "scim_groups", "/Groups"),
    scimSurface(client, "scim_config", "/ServiceProviderConfig"),
  ]);

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const auditReadable = surfaces.some((surface) => surface.name === "audit_logs" && surface.status === "readable");
  const status = readableCount >= 9 && auditReadable ? "healthy" : "limited";
  const team = asString(auth.team) ?? asString(auth.team_id) ?? "Slack tenant";
  const notes = [
    `Authenticated to ${team}${asString(auth.user) ? ` as ${auth.user}` : ""}${auth.is_enterprise_install === true ? " (enterprise install)" : ""}.`,
    `${readableCount}/${surfaces.length} Slack audit surfaces are readable.`,
    surfaces.some((surface) => surface.api === "scim" && surface.status === "readable")
      ? "SCIM checks are available."
      : "SCIM checks are not available; set SLACK_SCIM_TOKEN to enable provisioning coverage.",
    client.getTokenKinds().includes("user")
      ? "A user token is configured; Admin API methods can be attempted."
      : "Only a bot token is configured; admin.* and Audit Logs methods require an org-level user token.",
  ];

  return {
    status,
    auth: {
      url: auth.url,
      team: auth.team,
      team_id: auth.team_id,
      user: auth.user,
      user_id: auth.user_id,
      enterprise_id: auth.enterprise_id,
      is_enterprise_install: auth.is_enterprise_install,
    },
    tokenKinds: client.getTokenKinds(),
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run slack_assess_identity, slack_assess_admin_access, slack_assess_integrations, slack_assess_channel_governance, and slack_assess_monitoring."
        : "Grant a read-only org-level Enterprise Grid user token with admin.teams:read, admin.users:read, admin.apps:read, admin.barriers:read, admin.conversations:read, auditlogs:read, users:read, and optional SCIM read access.",
  };
}

function isHumanUser(user: JsonRecord): boolean {
  return user.is_bot !== true && user.is_app_user !== true;
}

function isDeletedUser(user: JsonRecord): boolean {
  return user.deleted === true;
}

function isGuestUser(user: JsonRecord): boolean {
  return user.is_restricted === true || user.is_ultra_restricted === true;
}

function userEmail(user: JsonRecord): string | undefined {
  return asString(asObject(user.profile)?.email)?.toLowerCase();
}

function scimUserEmail(user: JsonRecord): string | undefined {
  const primary = asObjectArray(user.emails).find((email) => email.primary === true);
  return (asString(user.userName) ?? asString(primary?.value))?.toLowerCase();
}

function userLabel(user: JsonRecord): string {
  return asString(user.name) ?? asString(user.username) ?? asString(user.id) ?? "unknown";
}

async function resolveTeamId(client: SlackApiClient): Promise<string | undefined> {
  const auth = await readWeb(client, "auth.test");
  return auth.ok ? asString(auth.value.team_id) : undefined;
}

export async function assessSlackIdentity(
  client: SlackApiClient,
  options: { userLimit?: number; skipScim?: boolean } = {},
): Promise<SlackAssessmentResult> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 20_000);
  const errors: string[] = [];
  const teamId = await resolveTeamId(client);
  const usersResult = await readWebList(client, "users.list", ["members"], teamId ? { team_id: teamId } : {}, { limit: userLimit });
  if (!usersResult.ok) errors.push(`users.list: ${usersResult.error}`);
  const users = usersResult.ok ? usersResult.value : [];
  const usersComplete = usersResult.ok && usersResult.complete;
  const humans = users.filter(isHumanUser);
  const activeHumans = humans.filter((user) => !isDeletedUser(user));
  const knownMfa = activeHumans.filter((user) => typeof user.has_2fa === "boolean");
  const unknownMfa = activeHumans.length - knownMfa.length;
  const withoutMfa = activeHumans.filter((user) => user.has_2fa === false);
  const guests = activeHumans.filter(isGuestUser);
  const deactivated = humans.filter(isDeletedUser);

  const scimConfig: ReadResult<JsonRecord> = options.skipScim
    ? { ok: false, error: "SCIM checks were skipped by request.", code: "skipped" }
    : await client.scim("/ServiceProviderConfig")
      .then((value): ReadResult<JsonRecord> => ({ ok: true, value, complete: true }))
      .catch((error): ReadResult<JsonRecord> => ({ ok: false, error: surfaceError(error), code: errorCode(error) }));
  const scimUsers: ReadResult<JsonRecord[]> = options.skipScim || !scimConfig.ok
    ? { ok: false, error: scimConfig.error ?? "SCIM unavailable", code: scimConfig.code }
    : await client.collectScim("/Users", {}, { limit: userLimit })
      .then((page): ReadResult<JsonRecord[]> => ({ ok: true, value: page.items, complete: page.complete, total: page.total, truncation: page.truncation }))
      .catch((error): ReadResult<JsonRecord[]> => ({ ok: false, error: surfaceError(error), code: errorCode(error) }));
  if (!options.skipScim && !scimConfig.ok) errors.push(`SCIM /ServiceProviderConfig: ${scimConfig.error}`);
  if (!options.skipScim && scimConfig.ok && !scimUsers.ok) errors.push(`SCIM /Users: ${scimUsers.error}`);
  const scimUsersStatus = options.skipScim
    ? "not collected: SCIM checks were skipped by request, so SCIM /Users was not called"
    : !scimConfig.ok
      ? notCollected("SCIM /ServiceProviderConfig", scimConfig.error, "SCIM /Users was not called")
      : inventoryStatus(scimUsers, "SCIM /Users");

  const deletedSlackEmails = new Set(deactivated.map(userEmail).filter((email): email is string => Boolean(email)));
  const scimActiveDeletedInSlack = (scimUsers.ok ? scimUsers.value : []).filter((user) => {
    if (user.active === false) return false;
    const email = scimUserEmail(user);
    return Boolean(email && deletedSlackEmails.has(email));
  });
  const usersView = usersResult.ok ? partialNote(users.length, usersResult.complete, usersResult.total, usersResult.truncation) : "unreadable";

  const findings: SlackFinding[] = [];
  if (!usersResult.ok) {
    const reason = `users.list is not readable: ${unreadableReason(usersResult)}.`;
    findings.push(
      manualFinding("SLACK-ID-01", "MFA enrollment", 2, "critical", reason, "export the member list with 2FA status from the admin dashboard."),
      manualFinding("SLACK-ID-02", "Guest account inventory", 15, "medium", reason, "export guest accounts and expiration dates from the admin dashboard."),
    );
  } else {
    findings.push(
      finding(
        "SLACK-ID-01",
        "MFA enrollment",
        2,
        "critical",
        activeHumans.length === 0
          ? "warn"
          : withoutMfa.length > 0
            ? "fail"
            : unknownMfa > 0 || !usersComplete
              ? "warn"
              : "pass",
        activeHumans.length === 0
          ? `users.list returned no active human users (${usersView}); an empty inventory is not treated as compliant.`
          : withoutMfa.length > 0
            ? `${withoutMfa.length}/${activeHumans.length} active human users have has_2fa=false (${usersView}).`
            : unknownMfa > 0
              ? `${unknownMfa}/${activeHumans.length} active human users did not expose has_2fa; they are reported separately and do not count as enrolled (${usersView}).`
              : !usersComplete
                ? `Every seen active human user has has_2fa=true but the inventory is partial (${usersView}).`
                : `All ${activeHumans.length} active human users have has_2fa=true (${usersView}).`,
        {
          active_human_users: activeHumans.length,
          known_mfa_users: knownMfa.length,
          unknown_mfa_users: unknownMfa,
          users_without_mfa: withoutMfa.slice(0, 20).map(userLabel),
          inventory_complete: usersComplete,
        },
      ),
      finding(
        "SLACK-ID-02",
        "Guest account inventory",
        15,
        "medium",
        guests.length > 0 ? "warn" : usersComplete && activeHumans.length > 0 ? "pass" : "warn",
        guests.length > 0
          ? `${guests.length}/${activeHumans.length} active human users are guests (is_restricted or is_ultra_restricted). Verify expiration and channel scope (${usersView}).`
          : usersComplete && activeHumans.length > 0
            ? `No active guest users in the complete inventory of ${activeHumans.length} active human users; emptiness is compliant by intent for this control.`
            : `No guests seen but the inventory is ${activeHumans.length === 0 ? "empty" : "partial"} (${usersView}); not treated as compliant.`,
        { guest_count: guests.length, sample: guests.slice(0, 20).map(userLabel), inventory_complete: usersComplete },
      ),
    );
  }

  if (options.skipScim) {
    findings.push(
      manualFinding("SLACK-ID-03", "SCIM provisioning coverage", 22, "high", "SCIM checks were skipped by request.", "confirm SCIM provisioning is active in the identity provider and Slack admin dashboard."),
      manualFinding("SLACK-ID-04", "User lifecycle alignment", 23, "high", "SCIM checks were skipped by request.", "reconcile IdP deprovisioning records against Slack deactivations."),
    );
  } else if (!scimConfig.ok) {
    const reason = scimConfig.code === "not_configured"
      ? "SLACK_SCIM_TOKEN is not configured, so SCIM /ServiceProviderConfig was not called."
      : `SCIM /ServiceProviderConfig is not readable: ${unreadableReason(scimConfig)} (Business+ or Enterprise plan required).`;
    findings.push(
      manualFinding("SLACK-ID-03", "SCIM provisioning coverage", 22, "high", reason, "confirm SCIM provisioning is active in the identity provider and Slack admin dashboard."),
      manualFinding("SLACK-ID-04", "User lifecycle alignment", 23, "high", reason, "reconcile IdP deprovisioning records against Slack deactivations."),
    );
  } else if (!scimUsers.ok) {
    const reason = `SCIM /Users is not readable: ${unreadableReason(scimUsers)}.`;
    findings.push(
      manualFinding("SLACK-ID-03", "SCIM provisioning coverage", 22, "high", reason, "export the SCIM user list from the identity provider."),
      manualFinding("SLACK-ID-04", "User lifecycle alignment", 23, "high", reason, "reconcile IdP deprovisioning records against Slack deactivations."),
    );
  } else {
    const scimCount = scimUsers.value.length;
    const scimView = partialNote(scimCount, scimUsers.complete, scimUsers.total, scimUsers.truncation);
    findings.push(
      finding(
        "SLACK-ID-03",
        "SCIM provisioning coverage",
        22,
        "high",
        scimCount === 0 ? "fail" : scimUsers.complete ? "pass" : "warn",
        scimCount === 0
          ? "SCIM is readable but /Users returned zero provisioned users; provisioning does not appear active."
          : `SCIM /ServiceProviderConfig is readable and /Users returned provisioned users (${scimView}).`,
        { scim_users: scimCount, scim_total: scimUsers.total, inventory_complete: scimUsers.complete },
      ),
      finding(
        "SLACK-ID-04",
        "User lifecycle alignment",
        23,
        "high",
        !usersResult.ok
          ? "manual"
          : scimActiveDeletedInSlack.length > 0
            ? "fail"
            : usersComplete && scimUsers.complete && scimCount > 0
              ? "pass"
              : "warn",
        !usersResult.ok
          ? `users.list is not readable (${unreadableReason(usersResult)}), so SCIM-active users could not be compared with Slack deactivations. Manual evidence: reconcile IdP records against the Slack member export.`
          : scimActiveDeletedInSlack.length > 0
            ? `${scimActiveDeletedInSlack.length} SCIM-active users are deactivated in Slack; reconcile IdP and Slack lifecycle state.`
            : usersComplete && scimUsers.complete && scimCount > 0
              ? `No SCIM-active user matched a deactivated Slack user across ${scimCount} SCIM users and ${deactivated.length} deactivated Slack users.`
              : `No mismatch seen, but the comparison used a partial or empty inventory (Slack: ${usersView}; SCIM: ${scimView}).`,
        {
          mismatched_users: usersResult.ok ? scimActiveDeletedInSlack.slice(0, 20).map((user) => asString(user.userName) ?? asString(user.id)) : null,
          mismatched_users_status: !usersResult.ok
            ? notCollected("users.list", usersResult.error, "SCIM-active users were not compared with Slack deactivations")
            : usersComplete && scimUsers.complete
              ? "complete: users.list compared with SCIM /Users"
              : `partial: the comparison used a partial inventory (Slack: ${usersView}; SCIM: ${scimView})`,
        },
      ),
    );
  }

  findings.push(
    !usersResult.ok
      ? manualFinding("SLACK-ID-05", "Deactivated user visibility", 23, "info", `users.list is not readable: ${unreadableReason(usersResult)}.`, "export deactivated members from the admin dashboard.")
      : finding(
        "SLACK-ID-05",
        "Deactivated user visibility",
        23,
        "info",
        usersComplete && humans.length > 0 ? "pass" : "warn",
        usersComplete && humans.length > 0
          ? `${deactivated.length} deactivated human users are visible for lifecycle review (complete inventory of ${humans.length} human users).`
          : humans.length === 0
            ? `users.list returned no human users (${usersView}); an empty inventory is not treated as compliant.`
            : `${deactivated.length} deactivated human users seen, but the inventory is partial (${usersView}).`,
        { deactivated_users: deactivated.length, inventory_complete: usersComplete },
      ),
  );

  return {
    title: "Slack identity posture",
    summary: {
      users_seen: inventoryCount(usersResult, users.length),
      users_status: inventoryStatus(usersResult, "users.list"),
      users_inventory_complete: usersComplete,
      active_human_users: inventoryCount(usersResult, activeHumans.length),
      guests: inventoryCount(usersResult, guests.length),
      users_without_mfa: inventoryCount(usersResult, withoutMfa.length),
      scim_users: inventoryCount(scimUsers, scimUsers.ok ? scimUsers.value.length : 0),
      scim_users_status: scimUsersStatus,
    },
    findings,
    errors,
  };
}

interface WorkspaceRecord {
  id: string;
  name: string;
  discoverability?: string;
}

function toWorkspaceRecord(team: JsonRecord): WorkspaceRecord | undefined {
  const id = asString(team.id);
  if (!id) return undefined;
  return { id, name: asString(team.name) ?? id, discoverability: asString(team.discoverability)?.toLowerCase() };
}

function isAdminOrOwner(user: JsonRecord): boolean {
  return user.is_admin === true || user.is_owner === true || user.is_primary_owner === true;
}

export async function assessSlackAdminAccess(
  client: SlackApiClient,
  options: {
    workspaceLimit?: number;
    userLimit?: number;
    maxWorkspaceAdmins?: number;
    maxSessionHours?: number;
    sessionSample?: number;
  } = {},
): Promise<SlackAssessmentResult> {
  const workspaceLimit = clampNumber(options.workspaceLimit, DEFAULT_WORKSPACE_LIMIT, 1, 500);
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 20_000);
  const maxWorkspaceAdmins = clampNumber(options.maxWorkspaceAdmins, 5, 1, 100);
  const maxSessionHours = clampNumber(options.maxSessionHours, 24, 1, 720);
  const sessionSample = clampNumber(options.sessionSample, DEFAULT_SESSION_SAMPLE, 1, 500);
  const errors: string[] = [];

  const teamsResult = await readWebList(client, "admin.teams.list", ["teams"], {}, { limit: workspaceLimit });
  if (!teamsResult.ok) errors.push(`admin.teams.list: ${teamsResult.error}`);
  const workspaces = (teamsResult.ok ? teamsResult.value : []).map(toWorkspaceRecord).filter((item): item is WorkspaceRecord => Boolean(item));
  const workspacesComplete = teamsResult.ok && teamsResult.complete;
  const workspaceView = teamsResult.ok ? partialNote(workspaces.length, teamsResult.complete, teamsResult.total, teamsResult.truncation) : "unreadable";

  const adminInventory: Array<{ id: string; name: string; admin_ids: string[]; complete: boolean }> = [];
  const unreadableAdminLists: Array<{ id: string; name: string; error: string }> = [];
  const emailDomains: Array<{ id: string; name: string; email_domain: string }> = [];
  const settingsErrors: string[] = [];
  for (const workspace of workspaces) {
    const admins = await readWebList(client, "admin.teams.admins.list", ["admin_ids"], { team_id: workspace.id }, { limit: 5000 });
    if (admins.ok) {
      const ids = admins.value.map((item) => asString(item.id)).filter((id): id is string => Boolean(id));
      adminInventory.push({ id: workspace.id, name: workspace.name, admin_ids: ids, complete: admins.complete });
    } else {
      unreadableAdminLists.push({ id: workspace.id, name: workspace.name, error: unreadableReason(admins) });
    }
    const settings = await readWeb(client, "admin.teams.settings.info", { team_id: workspace.id });
    if (settings.ok) {
      const team = asObject(settings.value.team);
      const emailDomain = typeof team?.email_domain === "string" ? team.email_domain.trim() : undefined;
      if (emailDomain !== undefined) emailDomains.push({ id: workspace.id, name: workspace.name, email_domain: emailDomain });
      else settingsErrors.push(`${workspace.id}: team.email_domain absent from admin.teams.settings.info response`);
    } else {
      settingsErrors.push(`${workspace.id}: ${unreadableReason(settings)}`);
    }
  }
  const adminErrors = unreadableAdminLists.map((item) => `${item.id}: ${item.error}`);
  const adminListGap = unreadableAdminLists.length > 0
    ? `admin.teams.admins.list unreadable for ${unreadableAdminLists.map((item) => `${item.id} (${item.name}): ${item.error}`).join("; ")}`
    : undefined;
  const settingsGap = settingsErrors.length > 0 ? `admin.teams.settings.info unreadable or lacking team.email_domain for ${settingsErrors.join("; ")}` : undefined;
  errors.push(...adminErrors.map((item) => `admin.teams.admins.list ${item}`), ...settingsErrors.map((item) => `admin.teams.settings.info ${item}`));

  const orgUsers = await readWebList(client, "admin.users.list", ["users"], {}, { limit: userLimit });
  if (!orgUsers.ok) errors.push(`admin.users.list: ${orgUsers.error}`);
  const activeOrgUsers = (orgUsers.ok ? orgUsers.value : []).filter((user) => user.is_active !== false && user.is_bot !== true);
  const orgUsersComplete = orgUsers.ok && orgUsers.complete;
  const orgUsersView = orgUsers.ok ? partialNote(activeOrgUsers.length, orgUsers.complete, orgUsers.total, orgUsers.truncation) : "unreadable";
  const ssoKnown = activeOrgUsers.filter((user) => typeof user.has_sso === "boolean");
  const withoutSso = activeOrgUsers.filter((user) => user.has_sso === false);
  const ssoUnknown = activeOrgUsers.length - ssoKnown.length;
  const adminUserIds = new Set([
    ...activeOrgUsers.filter(isAdminOrOwner).map((user) => asString(user.id)).filter((id): id is string => Boolean(id)),
    ...adminInventory.flatMap((item) => item.admin_ids),
  ]);

  const sessionUserIds = activeOrgUsers.map((user) => asString(user.id)).filter((id): id is string => Boolean(id)).slice(0, sessionSample);
  const sessionSettings: JsonRecord[] = [];
  const noSettingsApplied: string[] = [];
  let sessionError: { error: string; code?: string } | undefined;
  for (let index = 0; index < sessionUserIds.length; index += 100) {
    const batch = sessionUserIds.slice(index, index + 100);
    const result = await readWeb(client, "admin.users.session.getSettings", { user_ids: batch });
    if (!result.ok) {
      sessionError = { error: result.error, code: result.code };
      errors.push(`admin.users.session.getSettings: ${result.error}`);
      break;
    }
    sessionSettings.push(...asObjectArray(result.value.session_settings));
    noSettingsApplied.push(...asStringArray(result.value.no_settings_applied));
  }
  const durations = sessionSettings
    .map((item) => ({ user_id: asString(item.user_id), duration_hours: (asNumber(item.duration) ?? Number.NaN) / 3600, desktop_app_browser_quit: item.desktop_app_browser_quit }))
    .filter((item) => Number.isFinite(item.duration_hours));
  const overlongSessions = durations.filter((item) => item.duration_hours > maxSessionHours);
  const browserQuitKnown = sessionSettings.filter((item) => typeof item.desktop_app_browser_quit === "boolean");

  const emojiResult = await collectEmoji(client);
  if (!emojiResult.ok) errors.push(`admin.emoji.list: ${emojiResult.error}`);
  const emojiEntries = emojiResult.ok ? emojiResult.value : [];
  const emojiComplete = emojiResult.ok && emojiResult.complete;
  const emojiView = emojiResult.ok ? partialNote(emojiEntries.length, emojiResult.complete, undefined, emojiResult.truncation) : "unreadable";

  const analyticsProbe = await readAnalyticsProbe(client);
  if (!analyticsProbe.ok) errors.push(`admin.analytics.getFile: ${analyticsProbe.error}`);

  const excessiveAdmins = adminInventory.filter((item) => item.admin_ids.length > maxWorkspaceAdmins);
  const truncatedAdminLists = adminInventory.filter((item) => !item.complete).map((item) => `${item.name} (${item.id})`);
  const adminsComplete = workspacesComplete && adminErrors.length === 0 && adminInventory.every((item) => item.complete);
  const rosterGaps: string[] = [];
  if (!orgUsers.ok) rosterGaps.push(`admin.users.list unreadable (${orgUsers.error})`);
  else if (!orgUsers.complete) rosterGaps.push(`admin.users.list partial (${orgUsersView})`);
  if (!teamsResult.ok) rosterGaps.push(`admin.teams.list unreadable (${teamsResult.error})`);
  else if (!teamsResult.complete) rosterGaps.push(`admin.teams.list partial (${workspaceView})`);
  if (adminListGap) rosterGaps.push(adminListGap);
  if (truncatedAdminLists.length > 0) rosterGaps.push(`admin.teams.admins.list truncated for ${truncatedAdminLists.join(", ")}`);
  const adminRosterComplete = rosterGaps.length === 0;
  const adminListsCollected = teamsResult.ok && workspaces.length > 0;
  const workspaceAdminsStatus = !teamsResult.ok
    ? notCollected("admin.teams.list", teamsResult.error, "admin.teams.admins.list was not called")
    : workspaces.length === 0
      ? "not collected: admin.teams.list returned no workspaces, so admin.teams.admins.list was not called"
      : adminInventory.length === 0
        ? `unreadable: ${adminListGap}`
        : adminListGap || truncatedAdminLists.length > 0
          ? `partial: admin.teams.admins.list readable for ${adminInventory.length} of ${workspaces.length} workspaces${adminListGap ? ` (${adminListGap})` : ""}${truncatedAdminLists.length > 0 ? ` (truncated for ${truncatedAdminLists.join(", ")})` : ""}`
          : `complete: admin.teams.admins.list readable for ${adminInventory.length} of ${workspaces.length} workspaces`;
  const workspaceAdminsSeen = adminInventory.length > 0 ? new Set(adminInventory.flatMap((item) => item.admin_ids)).size : null;
  const sessionsCollected = sessionUserIds.length > 0 && sessionError === undefined;
  const sessionsStatus = sessionError
    ? `unreadable: admin.users.session.getSettings ${sessionError.error}`
    : !orgUsers.ok
      ? notCollected("admin.users.list", orgUsers.error, "admin.users.session.getSettings was not called")
      : sessionUserIds.length === 0
        ? "not collected: admin.users.list returned no active users, so admin.users.session.getSettings was not called"
        : `${sessionUserIds.length < activeOrgUsers.length || !orgUsers.complete ? "partial" : "complete"}: admin.users.session.getSettings sampled ${sessionUserIds.length} of ${activeOrgUsers.length} seen active users${orgUsers.complete ? "" : ` (admin.users.list ${orgUsersView})`}`;
  const uploadsOutsideRoster = emojiEntries.filter((item) => !item.uploaded_by || !adminUserIds.has(item.uploaded_by));
  const nonAdminUploads = adminRosterComplete ? uploadsOutsideRoster : undefined;
  const everyAdminListUnreadable = teamsResult.ok && workspaces.length > 0 && adminInventory.length === 0 && unreadableAdminLists.length > 0;
  const openWorkspaces = workspaces.filter((item) => item.discoverability === "open");
  const unknownDiscoverability = workspaces.filter((item) => !item.discoverability);
  const unrestrictedDomains = emailDomains.filter((item) => item.email_domain.length === 0);

  const findings: SlackFinding[] = [];

  findings.push(
    !teamsResult.ok
      ? manualFinding("SLACK-ADMIN-01", "Workspace admin inventory", 14, "high", `admin.teams.list is not readable: ${unreadableReason(teamsResult)}.`, "export the admin and owner roster for every workspace from the org dashboard.")
      : adminInventory.length === 0
        ? manualFinding("SLACK-ADMIN-01", "Workspace admin inventory", 14, "high", workspaces.length === 0 ? `admin.teams.list returned no workspaces (${workspaceView}).` : `admin.teams.admins.list is not readable for any workspace (${adminErrors.join("; ")}).`, "export the admin and owner roster for every workspace from the org dashboard.", { admin_counts: unreadableAdminLists.map((item) => ({ id: item.id, name: item.name, count: null, status: `unreadable: admin.teams.admins.list ${item.error}` })), unreadable_workspaces: adminErrors, workspace_admin_lists_status: workspaceAdminsStatus })
        : finding(
          "SLACK-ADMIN-01",
          "Workspace admin inventory",
          14,
          "high",
          excessiveAdmins.length > 0 ? "fail" : adminsComplete ? "pass" : "warn",
          excessiveAdmins.length > 0
            ? `${excessiveAdmins.length}/${adminInventory.length} workspaces exceed ${maxWorkspaceAdmins} admins (admin_ids; workspaces: ${workspaceView}${truncatedAdminLists.length > 0 ? `; admin lists truncated for ${truncatedAdminLists.join(", ")}` : ""}).`
            : adminsComplete
              ? `No workspace exceeds ${maxWorkspaceAdmins} admins across ${adminInventory.length} workspaces (${workspaceView}).`
              : `No seen workspace exceeds ${maxWorkspaceAdmins} admins, but the view is partial (workspaces: ${workspaceView}; admin lists truncated: ${truncatedAdminLists.length}${truncatedAdminLists.length > 0 ? ` (${truncatedAdminLists.join(", ")})` : ""}; ${adminListGap ?? "no unreadable admin lists"}).`,
          {
            admin_counts: [
              ...adminInventory.map((item) => ({ id: item.id, name: item.name, count: item.admin_ids.length, complete: item.complete, status: item.complete ? "complete" : "truncated" })),
              ...unreadableAdminLists.map((item) => ({ id: item.id, name: item.name, count: null, complete: false, status: `unreadable: admin.teams.admins.list ${item.error}` })),
            ],
            max_workspace_admins: maxWorkspaceAdmins,
            unreadable_workspaces: adminErrors,
            inventory_complete: adminsComplete,
          },
        ),
  );

  findings.push(
    !orgUsers.ok
      ? manualFinding("SLACK-ADMIN-02", "SSO enforcement", 1, "critical", `admin.users.list is not readable: ${unreadableReason(orgUsers)}.`, "confirm the org authentication policy requires SAML SSO and export member SSO status.")
      : finding(
        "SLACK-ADMIN-02",
        "SSO enforcement",
        1,
        "critical",
        activeOrgUsers.length === 0
          ? "warn"
          : withoutSso.length > 0
            ? "fail"
            : ssoUnknown > 0 || !orgUsersComplete
              ? "warn"
              : "pass",
        activeOrgUsers.length === 0
          ? `admin.users.list returned no active users (${orgUsersView}); an empty inventory is not treated as compliant.`
          : withoutSso.length > 0
            ? `${withoutSso.length}/${activeOrgUsers.length} active users have has_sso=false; SAML SSO is not enforced for them (${orgUsersView}).`
            : ssoUnknown > 0
              ? `${ssoUnknown}/${activeOrgUsers.length} active users did not expose has_sso and are reported separately (${orgUsersView}).`
              : !orgUsersComplete
                ? `Every seen active user has has_sso=true but the inventory is partial (${orgUsersView}).`
                : `All ${activeOrgUsers.length} active users have has_sso=true (${orgUsersView}). The org-level SSO requirement toggle is not exposed by admin.teams.settings.info; confirm it in the admin dashboard when a policy artifact is required.`,
        { active_users: activeOrgUsers.length, users_without_sso: withoutSso.slice(0, 20).map(userLabel), unknown_sso_users: ssoUnknown, inventory_complete: orgUsersComplete },
      ),
  );

  findings.push(
    sessionError
      ? manualFinding("SLACK-ADMIN-03", "Session duration limits", 3, "high", `admin.users.session.getSettings is not readable: ${unreadableReason(sessionError)}.`, "capture the org session duration setting from the admin dashboard.")
      : !orgUsers.ok || sessionUserIds.length === 0
        ? manualFinding("SLACK-ADMIN-03", "Session duration limits", 3, "high", `No active users were available to sample session settings (admin.users.list: ${orgUsers.ok ? orgUsersView : unreadableReason(orgUsers)}).`, "capture the org session duration setting from the admin dashboard.")
        : durations.length === 0
          ? manualFinding("SLACK-ADMIN-03", "Session duration limits", 3, "high", `All ${sessionUserIds.length} sampled users are in no_settings_applied; the org default session duration is not exposed by the API.`, "capture the org session duration setting from the admin dashboard.", { sampled_users: sessionUserIds.length, no_settings_applied: noSettingsApplied.length })
          : finding(
            "SLACK-ADMIN-03",
            "Session duration limits",
            3,
            "high",
            overlongSessions.length > 0 ? "fail" : noSettingsApplied.length > 0 || sessionUserIds.length < activeOrgUsers.length || !orgUsersComplete ? "warn" : "pass",
            overlongSessions.length > 0
              ? `${overlongSessions.length}/${durations.length} sampled users have a session duration above ${maxSessionHours} hours (${orgUsersView}).`
              : noSettingsApplied.length > 0
                ? `All ${durations.length} users with settings are at or below ${maxSessionHours} hours, but ${noSettingsApplied.length} sampled users inherit an org default that the API does not expose (${orgUsersView}).`
                : sessionUserIds.length < activeOrgUsers.length
                  ? `All ${durations.length} sampled users are at or below ${maxSessionHours} hours, but only ${sessionUserIds.length}/${activeOrgUsers.length} seen active users were sampled (${orgUsersView}).`
                  : !orgUsersComplete
                    ? `All ${durations.length} seen active users are at or below ${maxSessionHours} hours but the user inventory is partial (${orgUsersView}); unseen users were not sampled.`
                    : `All ${durations.length} active users have a session duration at or below ${maxSessionHours} hours (${orgUsersView}).`,
            { sampled_users: sessionUserIds.length, active_users_seen: activeOrgUsers.length, inventory_complete: orgUsersComplete, sessions_with_settings: durations.length, no_settings_applied: noSettingsApplied.length, overlong: overlongSessions.slice(0, 20), max_session_hours: maxSessionHours },
          ),
  );

  findings.push(
    manualFinding(
      "SLACK-ADMIN-04",
      "Session idle timeout",
      4,
      "medium",
      `Slack exposes no idle-timeout setting: admin.users.session.getSettings and setSettings document only duration and desktop_app_browser_quit (${SLACK_DOC_PAGES.sessionSetSettings}).`,
      "record the idle-timeout compensating control (IdP session policy or device lock) in the control narrative.",
      { citation: SLACK_DOC_PAGES.sessionSetSettings },
    ),
  );

  findings.push(
    !teamsResult.ok
      ? manualFinding("SLACK-ADMIN-05", "Workspace discoverability", 17, "medium", `admin.teams.list is not readable: ${unreadableReason(teamsResult)}.`, "capture each workspace's discoverability setting from the org dashboard.")
      : workspaces.length === 0
        ? manualFinding("SLACK-ADMIN-05", "Workspace discoverability", 17, "medium", `admin.teams.list returned no workspaces (${workspaceView}).`, "capture each workspace's discoverability setting from the org dashboard.")
        : finding(
          "SLACK-ADMIN-05",
          "Workspace discoverability",
          17,
          "medium",
          openWorkspaces.length > 0 ? "fail" : unknownDiscoverability.length > 0 || !workspacesComplete ? "warn" : "pass",
          openWorkspaces.length > 0
            ? `${openWorkspaces.length}/${workspaces.length} workspaces have discoverability=open (${workspaceView}).`
            : unknownDiscoverability.length > 0
              ? `${unknownDiscoverability.length}/${workspaces.length} workspaces did not expose discoverability and are reported separately (${workspaceView}).`
              : !workspacesComplete
                ? `No seen workspace is open, but the inventory is partial (${workspaceView}).`
                : `No workspace has discoverability=open across ${workspaces.length} workspaces (${workspaceView}).`,
          { workspaces: workspaces.map((item) => ({ id: item.id, name: item.name, discoverability: item.discoverability ?? null })) },
        ),
  );

  findings.push(
    manualFinding(
      "SLACK-ADMIN-06",
      "Mobile session controls",
      5,
      "medium",
      `Mobile-specific session and jailbreak controls are not exposed by the API; admin.users.session.getSettings documents only duration and desktop_app_browser_quit (${SLACK_DOC_PAGES.sessionSetSettings}).`,
      "capture the mobile session duration and Slack for EMM settings from the admin dashboard.",
      { citation: SLACK_DOC_PAGES.sessionSetSettings, sampled_sessions: sessionSettings.length, desktop_app_browser_quit_enabled: browserQuitKnown.filter((item) => item.desktop_app_browser_quit === true).length },
    ),
  );

  findings.push(
    !teamsResult.ok
      ? manualFinding("SLACK-ADMIN-07", "Email domain restrictions", 16, "high", `admin.teams.list is not readable: ${unreadableReason(teamsResult)}.`, "capture the allowed signup email domains for each workspace.")
      : emailDomains.length === 0
        ? manualFinding("SLACK-ADMIN-07", "Email domain restrictions", 16, "high", workspaces.length === 0 ? `admin.teams.list returned no workspaces (${workspaceView}).` : `admin.teams.settings.info did not return team.email_domain for any workspace (${settingsErrors.join("; ")}).`, "capture the allowed signup email domains for each workspace.", { email_domains: null, email_domains_status: `unreadable: ${settingsGap ?? "admin.teams.settings.info"}`, unreadable_workspaces: settingsErrors })
        : finding(
          "SLACK-ADMIN-07",
          "Email domain restrictions",
          16,
          "high",
          unrestrictedDomains.length > 0 ? "fail" : settingsErrors.length > 0 || !workspacesComplete ? "warn" : "pass",
          unrestrictedDomains.length > 0
            ? `${unrestrictedDomains.length}/${emailDomains.length} workspaces have an empty team.email_domain, so signup is not restricted to approved domains (${workspaceView}).`
            : settingsErrors.length > 0 || !workspacesComplete
              ? `Every readable workspace restricts signup by email domain, but ${settingsGap ?? "no workspace was unreadable"}${workspacesComplete ? ` (workspaces: ${workspaceView})` : `; the workspace view is partial (${workspaceView})`}.`
              : `All ${emailDomains.length} workspaces restrict signup to approved email domains (team.email_domain populated; ${workspaceView}).`,
          { email_domains: emailDomains, unreadable_workspaces: settingsErrors, inventory_complete: workspacesComplete },
        ),
  );

  findings.push(
    !emojiResult.ok
      ? manualFinding("SLACK-ADMIN-08", "Custom emoji governance", 19, "low", `admin.emoji.list is not readable: ${unreadableReason(emojiResult)}.`, "capture the custom emoji upload permission from the workspace settings.")
      : emojiEntries.length === 0
        ? manualFinding(
          "SLACK-ADMIN-08",
          "Custom emoji governance",
          19,
          "low",
          emojiComplete
            ? `admin.emoji.list returned no custom emoji (${emojiView}); the upload permission setting is not exposed by the API (${SLACK_DOC_PAGES.emojiList}).`
            : `admin.emoji.list was truncated before any custom emoji were seen (${emojiView}); the upload permission setting is not exposed by the API (${SLACK_DOC_PAGES.emojiList}).`,
          "capture the custom emoji upload permission from the workspace settings.",
          { citation: SLACK_DOC_PAGES.emojiList, emoji_count: 0, inventory_complete: emojiComplete, emoji_truncation: emojiResult.truncation ?? null },
        )
        : adminUserIds.size === 0
          ? manualFinding("SLACK-ADMIN-08", "Custom emoji governance", 19, "low", `No admin or owner identities were readable${rosterGaps.length > 0 ? ` (${rosterGaps.join("; ")})` : ""}, so emoji uploaders could not be compared with the admin roster (emoji: ${emojiView}).`, "compare the emoji uploader list with the admin roster.", { emoji_count: emojiEntries.length, non_admin_uploads: null, non_admin_uploads_status: `unknown: ${rosterGaps.join("; ") || "no admin identities readable"}`, unreadable_workspaces: adminListsCollected ? adminErrors : null, workspace_admin_lists_status: workspaceAdminsStatus, roster_complete: adminRosterComplete, inventory_complete: emojiComplete })
          : everyAdminListUnreadable
            ? manualFinding(
              "SLACK-ADMIN-08",
              "Custom emoji governance",
              19,
              "low",
              `${adminListGap}, so the ${emojiEntries.length} custom emoji uploaders could not be compared with a workspace admin roster (emoji: ${emojiView}; users: ${orgUsersView}).`,
              "compare the emoji uploader list with the admin roster.",
              { emoji_count: emojiEntries.length, non_admin_uploads: null, non_admin_uploads_status: `unknown: ${adminListGap}`, uploads_outside_readable_roster: uploadsOutsideRoster.length, unreadable_workspaces: adminErrors, workspace_admin_lists_status: workspaceAdminsStatus, roster_complete: false, inventory_complete: emojiComplete },
            )
            : finding(
              "SLACK-ADMIN-08",
              "Custom emoji governance",
              19,
              "low",
              nonAdminUploads && nonAdminUploads.length > 0 ? "fail" : adminRosterComplete && emojiComplete ? "pass" : "warn",
              nonAdminUploads && nonAdminUploads.length > 0
                ? `${nonAdminUploads.length}/${emojiEntries.length} custom emoji were uploaded by non-admin users; uploads are not restricted to admins (emoji: ${emojiView}; roster complete).`
                : adminRosterComplete && emojiComplete
                  ? `All ${emojiEntries.length} custom emoji were uploaded by admins or owners (emoji: ${emojiView}; users: ${orgUsersView}).`
                  : !adminRosterComplete
                    ? `All ${emojiEntries.length} seen custom emoji were checked against an incomplete admin roster (${rosterGaps.join("; ")}); ${uploadsOutsideRoster.length} uploads are by users outside the readable roster and were not classified as non-admin (emoji: ${emojiView}).`
                    : `All ${emojiEntries.length} seen custom emoji were uploaded by admins or owners, but the emoji inventory is partial (emoji: ${emojiView}; users: ${orgUsersView}).`,
              {
                emoji_count: emojiEntries.length,
                non_admin_uploads: nonAdminUploads ? nonAdminUploads.slice(0, 20).map((item) => item.name) : null,
                non_admin_uploads_status: adminRosterComplete ? "classified against the complete admin roster" : `unknown: admin roster incomplete (${rosterGaps.join("; ")})`,
                uploads_outside_readable_roster: uploadsOutsideRoster.length,
                unreadable_workspaces: adminListsCollected ? adminErrors : null,
                workspace_admin_lists_status: workspaceAdminsStatus,
                roster_complete: adminRosterComplete,
                inventory_complete: emojiComplete,
                emoji_truncation: emojiResult.truncation ?? null,
                users_inventory_complete: orgUsersComplete,
              },
            ),
  );

  findings.push(
    manualFinding(
      "SLACK-ADMIN-09",
      "Workspace analytics access",
      24,
      "low",
      analyticsProbe.ok
        ? `This token can export analytics (admin.analytics.getFile metadata probe returned ${analyticsProbe.value.content_type}); the API does not list which admins hold analytics access (${SLACK_DOC_PAGES.analyticsGetFile}).`
        : `admin.analytics.getFile metadata probe failed: ${unreadableReason(analyticsProbe)}; the API does not list which admins hold analytics access (${SLACK_DOC_PAGES.analyticsGetFile}).`,
      "review the analytics dashboard access roles in the admin dashboard.",
      { citation: SLACK_DOC_PAGES.analyticsGetFile, analytics_export_readable: analyticsProbe.ok, analytics_content_type: analyticsProbe.ok ? analyticsProbe.value.content_type : null },
    ),
  );

  return {
    title: "Slack admin access posture",
    summary: {
      workspaces_seen: inventoryCount(teamsResult, workspaces.length),
      workspaces_status: inventoryStatus(teamsResult, "admin.teams.list"),
      workspaces_complete: workspacesComplete,
      workspace_admins_seen: workspaceAdminsSeen,
      workspace_admins_status: workspaceAdminsStatus,
      active_org_users: inventoryCount(orgUsers, activeOrgUsers.length),
      org_users_status: inventoryStatus(orgUsers, "admin.users.list"),
      users_without_sso: inventoryCount(orgUsers, withoutSso.length),
      sessions_sampled: sessionsCollected ? sessionSettings.length : null,
      sessions_status: sessionsStatus,
      custom_emoji: inventoryCount(emojiResult, emojiEntries.length),
      custom_emoji_status: inventoryStatus(emojiResult, "admin.emoji.list"),
      analytics_export_readable: analyticsProbe.ok,
    },
    findings,
    errors,
  };
}

interface AppRecord {
  id?: string;
  name: string;
  is_internal?: boolean;
  is_app_directory_approved?: boolean;
  developer_type?: string;
  sensitive_scopes: string[];
}

function toAppRecord(entry: JsonRecord): AppRecord {
  const app = asObject(entry.app) ?? {};
  const scopes = asObjectArray(entry.scopes);
  return {
    id: asString(app.id),
    name: asString(app.name) ?? asString(app.id) ?? "unknown",
    is_internal: asBoolean(app.is_internal),
    is_app_directory_approved: asBoolean(app.is_app_directory_approved),
    developer_type: asString(app.developer_type),
    sensitive_scopes: scopes.filter((scope) => scope.is_sensitive === true).map((scope) => asString(scope.name) ?? "unknown"),
  };
}

export async function assessSlackIntegrations(
  client: SlackApiClient,
  options: { appLimit?: number; workspaceLimit?: number } = {},
): Promise<SlackAssessmentResult> {
  const appLimit = clampNumber(options.appLimit, DEFAULT_APP_LIMIT, 1, 5000);
  const workspaceLimit = clampNumber(options.workspaceLimit, DEFAULT_WORKSPACE_LIMIT, 1, 500);
  const orgQuery = client.getOrgQuery();
  const errors: string[] = [];
  const teamsResult = await readWebList(client, "admin.teams.list", ["teams"], {}, { limit: workspaceLimit });
  const approvedResult = await readWebList(client, "admin.apps.approved.list", ["approved_apps"], orgQuery, { limit: appLimit });
  const restrictedResult = await readWebList(client, "admin.apps.restricted.list", ["restricted_apps"], orgQuery, { limit: appLimit });
  const barriersResult = await readWebList(client, "admin.barriers.list", ["barriers"], {}, { limit: 1000 });
  const preferencesResult = await readWeb(client, "team.preferences.list");
  const authResult = await readWeb(client, "auth.test");
  for (const [label, result] of [["admin.teams.list", teamsResult], ["admin.apps.approved.list", approvedResult], ["admin.apps.restricted.list", restrictedResult], ["admin.barriers.list", barriersResult], ["team.preferences.list", preferencesResult], ["auth.test", authResult]] as const) {
    if (!result.ok) errors.push(`${label}: ${result.error}`);
  }

  const approvedApps = (approvedResult.ok ? approvedResult.value : []).map(toAppRecord);
  const restrictedApps = (restrictedResult.ok ? restrictedResult.value : []).map(toAppRecord);
  const approvedView = approvedResult.ok ? partialNote(approvedApps.length, approvedResult.complete, approvedResult.total, approvedResult.truncation) : "unreadable";
  const customApps = approvedApps.filter((app) => app.is_internal === true || app.developer_type === "internal");
  const unreviewedApps = approvedApps.filter((app) => app.is_app_directory_approved === false);
  const sensitiveApps = approvedApps.filter((app) => app.sensitive_scopes.length > 0);
  const flaggedApps = new Set([...customApps, ...unreviewedApps, ...sensitiveApps].map((app) => app.name));
  const fileUploadSetting = preferencesResult.ok ? asString(preferencesResult.value.disable_file_uploads) : undefined;
  const fileUploadVerdict = fileUploadSetting ? SLACK_FILE_UPLOAD_VERDICTS[fileUploadSetting] : undefined;
  const tokenWorkspace = authResult.ok ? asString(authResult.value.team_id) : undefined;
  const identityGap = !authResult.ok
    ? `auth.test was not readable (${authResult.error}), so the workspace the preference applies to could not be identified`
    : !tokenWorkspace
      ? "auth.test did not return team_id, so the workspace the preference applies to could not be identified"
      : undefined;
  const workspaceLabel = tokenWorkspace ? `workspace ${tokenWorkspace}` : "the token's workspace (id unknown)";
  const workspaceScope = !teamsResult.ok
    ? `admin.teams.list is not readable (${teamsResult.error}), so org-wide coverage is unknown`
    : !teamsResult.complete
      ? `the workspace inventory is partial (${teamsResult.value.length} seen), so other workspaces are unverified`
      : teamsResult.value.length > 1
        ? `the org has ${teamsResult.value.length} workspaces and only the token's workspace was read`
        : undefined;

  const findings: SlackFinding[] = [];
  findings.push(
    !approvedResult.ok
      ? manualFinding("SLACK-APP-01", "Approved app inventory", 9, "high", `admin.apps.approved.list is not readable: ${unreadableReason(approvedResult)}.`, "export the approved app list from the org app management dashboard.")
      : finding(
        "SLACK-APP-01",
        "Approved app inventory",
        9,
        "high",
        approvedApps.length === 0 ? "warn" : approvedResult.complete ? "pass" : "warn",
        approvedApps.length === 0
          ? "admin.apps.approved.list returned no approved apps; an empty inventory is not treated as compliant because it can also mean app approval is not enabled."
          : approvedResult.complete
            ? `${approvedApps.length} approved apps are visible for review (${approvedView}).`
            : `Approved apps are readable but the inventory is partial (${approvedView}).`,
        { approved_app_count: approvedApps.length, inventory_complete: approvedResult.complete },
      ),
    !restrictedResult.ok
      ? manualFinding("SLACK-APP-02", "Restricted app policy", 9, "medium", `admin.apps.restricted.list is not readable: ${unreadableReason(restrictedResult)}.`, "confirm app approval is required and export the restricted app list.")
      : finding(
        "SLACK-APP-02",
        "Restricted app policy",
        9,
        "medium",
        restrictedApps.length === 0 ? "warn" : restrictedResult.complete ? "pass" : "warn",
        restrictedApps.length === 0
          ? "No restricted apps are visible; confirm the admin approval policy is active (emptiness is not treated as compliant)."
          : `${restrictedApps.length} restricted apps are visible (${partialNote(restrictedApps.length, restrictedResult.complete, restrictedResult.total, restrictedResult.truncation)}).`,
        { restricted_app_count: restrictedApps.length, inventory_complete: restrictedResult.complete },
      ),
    !approvedResult.ok
      ? manualFinding("SLACK-APP-03", "Custom and sensitive-scope apps", 10, "high", `admin.apps.approved.list is not readable: ${unreadableReason(approvedResult)}.`, "review internal apps and sensitive scopes in the app management dashboard.")
      : approvedApps.length === 0
        ? finding("SLACK-APP-03", "Custom and sensitive-scope apps", 10, "medium", "warn", "No approved apps were returned, so no custom or sensitive-scope apps could be evaluated (empty inventory is not compliant by default).", { approved_app_count: 0 })
        : finding(
          "SLACK-APP-03",
          "Custom and sensitive-scope apps",
          10,
          flaggedApps.size > 0 ? "high" : "medium",
          flaggedApps.size > 0 ? "warn" : approvedResult.complete ? "pass" : "warn",
          flaggedApps.size > 0
            ? `${customApps.length} internal apps, ${unreviewedApps.length} apps not approved in the Slack Marketplace, and ${sensitiveApps.length} apps with is_sensitive scopes need review (${approvedView}).`
            : approvedResult.complete
              ? `No approved app is internal, unreviewed, or granted is_sensitive scopes across ${approvedApps.length} apps.`
              : `No flagged app seen, but the inventory is partial (${approvedView}).`,
          {
            custom_apps: customApps.slice(0, 20).map((app) => app.name),
            unreviewed_apps: unreviewedApps.slice(0, 20).map((app) => app.name),
            sensitive_scope_apps: sensitiveApps.slice(0, 20).map((app) => ({ name: app.name, scopes: app.sensitive_scopes })),
          },
        ),
    !barriersResult.ok
      ? manualFinding("SLACK-APP-04", "Information barriers", 8, "high", `admin.barriers.list is not readable: ${unreadableReason(barriersResult)}.`, "export the information barrier configuration from the org dashboard.")
      : finding(
        "SLACK-APP-04",
        "Information barriers",
        8,
        "high",
        barriersResult.value.length === 0 ? "warn" : barriersResult.complete ? "pass" : "warn",
        barriersResult.value.length === 0
          ? "No information barriers are configured; confirm whether restricted groups require barriers (emptiness is not treated as compliant)."
          : `${barriersResult.value.length} information barriers are configured (${partialNote(barriersResult.value.length, barriersResult.complete, barriersResult.total, barriersResult.truncation)}).`,
        {
          barrier_count: barriersResult.value.length,
          barriers: barriersResult.value.slice(0, 20).map((barrier) => ({
            id: barrier.id,
            primary_usergroup: asObject(barrier.primary_usergroup)?.name,
            restricted_subjects: asStringArray(barrier.restricted_subjects),
          })),
        },
      ),
    manualFinding(
      "SLACK-APP-05",
      "DLP and Discovery visibility",
      11,
      "medium",
      `The Discovery API has no public reference page and no discovery.* method appears in the Web API methods index (${SLACK_DOC_PAGES.methodsIndex}), so Discovery entitlement and DLP scanning status cannot be read by this tool.`,
      "collect the DLP partner policy export and the Discovery API entitlement confirmation from Slack.",
      { citation: SLACK_DOC_PAGES.methodsIndex },
    ),
    !preferencesResult.ok
      ? manualFinding("SLACK-APP-06", "File upload restrictions", 6, "medium", `team.preferences.list is not readable: ${unreadableReason(preferencesResult)} (requires team.preferences:read).`, "capture the file upload permission from the workspace settings.", { citation: SLACK_DOC_PAGES.teamPreferencesList })
      : !fileUploadSetting
        ? manualFinding("SLACK-APP-06", "File upload restrictions", 6, "medium", "team.preferences.list did not return disable_file_uploads.", "capture the file upload permission from the workspace settings.", { citation: SLACK_DOC_PAGES.teamPreferencesList })
        : finding(
          "SLACK-APP-06",
          "File upload restrictions",
          6,
          "medium",
          fileUploadVerdict === "pass" && (workspaceScope || identityGap) ? "warn" : fileUploadVerdict ?? "warn",
          `${fileUploadVerdict === "pass"
            ? `disable_file_uploads=${fileUploadSetting}: uploads are ${fileUploadSetting === "disallow_all" ? "disabled for everyone" : "restricted to owners and admins"} in ${workspaceLabel}`
            : fileUploadVerdict === "warn"
              ? `disable_file_uploads=${fileUploadSetting}: every regular member of ${workspaceLabel} can upload files and only guests are excluded; confirm this matches the org's intent`
              : fileUploadVerdict === "fail"
                ? `disable_file_uploads=${fileUploadSetting}: file uploads are allowed for everyone in ${workspaceLabel}, including guests`
                : `disable_file_uploads=${fileUploadSetting} is not one of the documented values (disallow_all, allow_all, type:owner,type:admin, type:regular); review manually`}${identityGap ? `; ${identityGap}` : ""}${workspaceScope ? `; ${workspaceScope}` : ""}. Verdict map: disallow_all and type:owner,type:admin pass, type:regular warns, allow_all fails.`,
          {
            citation: SLACK_DOC_PAGES.teamPreferencesList,
            disable_file_uploads: fileUploadSetting,
            workspace_id: tokenWorkspace ?? null,
            workspace_id_status: !authResult.ok ? `unreadable: auth.test ${authResult.error}` : tokenWorkspace ? "read from auth.test team_id" : "absent: auth.test returned no team_id",
            workspaces_seen: teamsResult.ok ? teamsResult.value.length : null,
            workspaces_status: inventoryStatus(teamsResult, "admin.teams.list"),
            workspace_inventory_complete: teamsResult.ok ? teamsResult.complete : false,
            verdict_map: SLACK_FILE_UPLOAD_VERDICTS,
          },
        ),
    manualFinding(
      "SLACK-APP-07",
      "Token rotation and revocation",
      25,
      "high",
      `Token rotation is an app-level opt-in with no read method listing token age or legacy tokens (${SLACK_DOC_PAGES.tokenRotation}). ${authResult.ok ? `auth.test identity: user ${asString(authResult.value.user_id) ?? "unknown"} on team ${asString(authResult.value.team_id) ?? "unknown"}.` : `auth.test failed: ${authResult.error}.`} Configured token uses the ${client.describeToken().rotating_format ? "rotating (xoxe.) format" : "non-rotating format"}.`,
      "review installed app tokens and legacy token revocation in the app management dashboard.",
      { citation: SLACK_DOC_PAGES.tokenRotation, token_format: client.describeToken(), auth: authResult.ok ? { user_id: authResult.value.user_id, team_id: authResult.value.team_id, is_enterprise_install: authResult.value.is_enterprise_install } : null },
    ),
  );

  return {
    title: "Slack integrations posture",
    summary: {
      approved_apps: inventoryCount(approvedResult, approvedApps.length),
      approved_apps_status: inventoryStatus(approvedResult, "admin.apps.approved.list"),
      approved_inventory_complete: approvedResult.ok ? approvedResult.complete : false,
      restricted_apps: inventoryCount(restrictedResult, restrictedApps.length),
      restricted_apps_status: inventoryStatus(restrictedResult, "admin.apps.restricted.list"),
      custom_apps: inventoryCount(approvedResult, customApps.length),
      sensitive_scope_apps: inventoryCount(approvedResult, sensitiveApps.length),
      information_barriers: inventoryCount(barriersResult, barriersResult.ok ? barriersResult.value.length : 0),
      information_barriers_status: inventoryStatus(barriersResult, "admin.barriers.list"),
      disable_file_uploads: fileUploadSetting ?? null,
      disable_file_uploads_status: preferencesResult.ok ? (fileUploadSetting ? "read from team.preferences.list" : "absent: team.preferences.list returned no disable_file_uploads") : `unreadable: team.preferences.list ${preferencesResult.error}`,
    },
    findings,
    errors,
  };
}

interface ChannelRecord {
  id: string;
  name: string;
  is_private?: boolean;
  is_general?: boolean;
  is_org_default?: boolean;
  is_org_mandatory?: boolean;
  is_ext_shared?: boolean;
  connected_team_ids: string[];
  pending_connected_team_ids: string[];
}

function toChannelRecord(conversation: JsonRecord): ChannelRecord | undefined {
  const id = asString(conversation.id);
  if (!id) return undefined;
  return {
    id,
    name: asString(conversation.name) ?? id,
    is_private: asBoolean(conversation.is_private),
    is_general: asBoolean(conversation.is_general),
    is_org_default: asBoolean(conversation.is_org_default),
    is_org_mandatory: asBoolean(conversation.is_org_mandatory),
    is_ext_shared: asBoolean(conversation.is_ext_shared),
    connected_team_ids: asStringArray(conversation.connected_team_ids),
    pending_connected_team_ids: asStringArray(conversation.pending_connected_team_ids),
  };
}

function isAnnouncementChannel(channel: ChannelRecord): boolean {
  return channel.is_general === true || channel.is_org_default === true || channel.is_org_mandatory === true;
}

/** who_can_post.type spellings documented on admin.conversations.getConversationPrefs (singular examples plus the plural "admins" form). */
const RESTRICTED_POSTER_TYPES = new Set(["admin", "admins", "owner", "owners"]);

export function isSlackPostingRestricted(prefs: JsonRecord): boolean | undefined {
  const whoCanPost = asObject(prefs.who_can_post);
  if (!whoCanPost) return undefined;
  const types = asStringArray(whoCanPost.type).map((item) => item.toLowerCase());
  const users = asStringArray(whoCanPost.user);
  if (types.length === 0 && users.length === 0) return undefined;
  return types.every((type) => RESTRICTED_POSTER_TYPES.has(type)) && (types.length > 0 || users.length > 0);
}

export async function assessSlackChannelGovernance(
  client: SlackApiClient,
  options: { channelLimit?: number; minRetentionDays?: number } = {},
): Promise<SlackAssessmentResult> {
  const channelLimit = clampNumber(options.channelLimit, DEFAULT_CHANNEL_LIMIT, 1, 400);
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 1, 36_500);
  const errors: string[] = [];

  const externalResult = await readWebList(client, "admin.conversations.search", ["conversations"], { search_channel_types: ["external_shared"] }, { limit: channelLimit });
  const channelsResult = await readWebList(client, "admin.conversations.search", ["conversations"], { search_channel_types: ["exclude_archived"], sort: "member_count", sort_dir: "desc" }, { limit: channelLimit });
  if (!externalResult.ok) errors.push(`admin.conversations.search external_shared: ${externalResult.error}`);
  if (!channelsResult.ok) errors.push(`admin.conversations.search: ${channelsResult.error}`);

  const externalChannels = (externalResult.ok ? externalResult.value : []).map(toChannelRecord).filter((item): item is ChannelRecord => Boolean(item));
  const channels = (channelsResult.ok ? channelsResult.value : []).map(toChannelRecord).filter((item): item is ChannelRecord => Boolean(item));
  const channelsView = channelsResult.ok ? partialNote(channels.length, channelsResult.complete, channelsResult.total, channelsResult.truncation) : "unreadable";

  const prefsByChannel: Array<{ channel: ChannelRecord; restricted?: boolean }> = [];
  const prefsErrors: string[] = [];
  const unreadablePrefs: Array<{ channel: ChannelRecord; error: string }> = [];
  const retentionByChannel: Array<{ channel: ChannelRecord; is_policy_enabled?: boolean; duration_days?: number }> = [];
  const retentionErrors: string[] = [];
  const unreadableRetention: Array<{ channel: ChannelRecord; error: string }> = [];
  for (const channel of channels) {
    const prefs = await readWeb(client, "admin.conversations.getConversationPrefs", { channel_id: channel.id });
    if (prefs.ok) {
      prefsByChannel.push({ channel, restricted: isSlackPostingRestricted(asObject(prefs.value.prefs) ?? {}) });
    } else {
      prefsErrors.push(`${channel.id}: ${unreadableReason(prefs)}`);
      unreadablePrefs.push({ channel, error: unreadableReason(prefs) });
    }
    const retention = await readWeb(client, "admin.conversations.getCustomRetention", { channel_id: channel.id });
    if (retention.ok) {
      retentionByChannel.push({ channel, is_policy_enabled: asBoolean(retention.value.is_policy_enabled), duration_days: asNumber(retention.value.duration_days) });
    } else {
      retentionErrors.push(`${channel.id}: ${unreadableReason(retention)}`);
      unreadableRetention.push({ channel, error: unreadableReason(retention) });
    }
  }
  errors.push(...prefsErrors.map((item) => `admin.conversations.getConversationPrefs ${item}`), ...retentionErrors.map((item) => `admin.conversations.getCustomRetention ${item}`));

  const announcementChannels = channels.filter(isAnnouncementChannel);
  const announcementPrefs = prefsByChannel.filter((item) => isAnnouncementChannel(item.channel));
  const unreadableAnnouncements = unreadablePrefs.filter((item) => isAnnouncementChannel(item.channel));
  const unrestrictedAnnouncements = announcementPrefs.filter((item) => item.restricted === false);
  const unknownAnnouncements = announcementPrefs.filter((item) => item.restricted === undefined);
  const channelLabel = (channel: ChannelRecord): string => `${channel.id} (#${channel.name})`;
  const prefsGap = unreadablePrefs.length > 0
    ? `admin.conversations.getConversationPrefs unreadable for ${unreadablePrefs.map((item) => `${channelLabel(item.channel)}: ${item.error}`).join("; ")}`
    : undefined;
  const retentionGap = unreadableRetention.length > 0
    ? `admin.conversations.getCustomRetention unreadable for ${unreadableRetention.map((item) => `${channelLabel(item.channel)}: ${item.error}`).join("; ")}`
    : undefined;
  const perChannelStatus = (endpoint: string, readable: number, gap: string | undefined): string => !channelsResult.ok
    ? notCollected("admin.conversations.search", channelsResult.error, `${endpoint} was not called`)
    : channels.length === 0
      ? `not collected: admin.conversations.search returned no active channels, so ${endpoint} was not called`
      : readable === 0 && gap
        ? `unreadable: ${gap}`
        : gap
          ? `partial: ${endpoint} readable for ${readable} of ${channels.length} channels (${gap})`
          : `complete: ${endpoint} readable for ${readable} of ${channels.length} channels`;
  const postingPrefsStatus = perChannelStatus("admin.conversations.getConversationPrefs", prefsByChannel.length, prefsGap);
  const retentionStatus = perChannelStatus("admin.conversations.getCustomRetention", retentionByChannel.length, retentionGap);
  const restrictedChannels = prefsByChannel.filter((item) => item.restricted === true);
  const shortRetention = retentionByChannel.filter((item) => item.is_policy_enabled === true && item.duration_days !== undefined && item.duration_days < minRetentionDays);
  const inheritingDefault = retentionByChannel.filter((item) => item.is_policy_enabled !== true);
  const channelsComplete = channelsResult.ok && channelsResult.complete;

  const findings: SlackFinding[] = [];
  findings.push(
    !externalResult.ok
      ? manualFinding("SLACK-CHAN-01", "Slack Connect exposure", 7, "high", `admin.conversations.search (external_shared) is not readable: ${unreadableReason(externalResult)}.`, "export the Slack Connect channel list and the org Slack Connect permission settings.")
      : finding(
        "SLACK-CHAN-01",
        "Slack Connect exposure",
        7,
        "high",
        externalChannels.length > 0 ? "warn" : externalResult.complete ? "pass" : "warn",
        externalChannels.length > 0
          ? `${externalChannels.length} externally shared channels (is_ext_shared) connect to ${new Set(externalChannels.flatMap((item) => item.connected_team_ids)).size} external teams, with ${externalChannels.filter((item) => item.pending_connected_team_ids.length > 0).length} pending invitations (${partialNote(externalChannels.length, externalResult.complete, externalResult.total, externalResult.truncation)}). Review against the Slack Connect policy; the org-level Connect permission toggle is not exposed by the API.`
          : externalResult.complete
            ? "No externally shared channels exist in the complete search (search_channel_types=external_shared); emptiness is compliant by intent for this control."
            : `No externally shared channel seen, but the search is partial (${partialNote(externalChannels.length, externalResult.complete, externalResult.total, externalResult.truncation)}).`,
        { external_channels: externalChannels.slice(0, 20).map((item) => ({ id: item.id, name: item.name, connected_team_ids: item.connected_team_ids, pending_connected_team_ids: item.pending_connected_team_ids })), inventory_complete: externalResult.complete },
      ),
    !channelsResult.ok
      ? manualFinding("SLACK-CHAN-02", "Channel posting restrictions", 18, "medium", `admin.conversations.search is not readable: ${unreadableReason(channelsResult)}.`, "capture posting permissions for #general and org default channels.")
      : channels.length === 0
        ? manualFinding("SLACK-CHAN-02", "Channel posting restrictions", 18, "medium", `admin.conversations.search returned no active channels (${channelsView}).`, "capture posting permissions for #general and org default channels.")
        : announcementChannels.length === 0
          ? manualFinding("SLACK-CHAN-02", "Channel posting restrictions", 18, "medium", `No general, org default, or org mandatory channel was in the ${channels.length} sampled channels (${channelsView})${prefsGap ? `; ${prefsGap}` : ""}.`, "capture posting permissions for #general and org default channels.", { announcement_channels: [], restricted_channels_seen: prefsByChannel.length > 0 ? restrictedChannels.length : null, posting_prefs_status: postingPrefsStatus, unreadable_channels: prefsErrors.length, unreadable_channel_details: prefsErrors })
          : announcementPrefs.length === 0
            ? manualFinding("SLACK-CHAN-02", "Channel posting restrictions", 18, "medium", `admin.conversations.getConversationPrefs is not readable for ${unreadableAnnouncements.length === 1 ? "the announcement channel" : `any of the ${unreadableAnnouncements.length} announcement channels`} ${unreadableAnnouncements.map((item) => `${channelLabel(item.channel)}: ${item.error}`).join("; ")} (${channelsView}).`, "capture posting permissions for #general and org default channels.", { announcement_channels: unreadableAnnouncements.map((item) => ({ id: item.channel.id, name: item.channel.name, restricted: null, status: `unreadable: admin.conversations.getConversationPrefs ${item.error}` })), restricted_channels_seen: prefsByChannel.length > 0 ? restrictedChannels.length : null, posting_prefs_status: postingPrefsStatus, unreadable_channels: prefsErrors.length, unreadable_channel_details: prefsErrors })
            : finding(
              "SLACK-CHAN-02",
              "Channel posting restrictions",
              18,
              "medium",
              unrestrictedAnnouncements.length > 0 ? "fail" : unknownAnnouncements.length > 0 || prefsErrors.length > 0 || !channelsComplete ? "warn" : "pass",
              unrestrictedAnnouncements.length > 0
                ? `${unrestrictedAnnouncements.length}/${announcementChannels.length} general or org default channels allow anyone to post (prefs.who_can_post)${prefsGap ? `; ${prefsGap}` : ""}.`
                : unknownAnnouncements.length > 0 || prefsErrors.length > 0
                  ? `Restricted posting is set on every readable general or org default channel (${announcementPrefs.length}/${announcementChannels.length} readable), but ${unknownAnnouncements.length} lacked a who_can_post value and ${prefsGap ?? "no channel was unreadable"} (${channelsView}).`
                  : !channelsComplete
                    ? `All ${announcementPrefs.length} seen general or org default channels restrict posting to admins or owners, but the channel search is partial (${channelsView}); unseen org default channels were not checked.`
                    : `All ${announcementPrefs.length} general or org default channels restrict posting to admins or owners; ${restrictedChannels.length}/${prefsByChannel.length} sampled channels restrict posting overall (${channelsView}).`,
              {
                announcement_channels: [
                  ...announcementPrefs.map((item) => ({ id: item.channel.id, name: item.channel.name, restricted: item.restricted ?? null, status: item.restricted === undefined ? "read: no who_can_post value" : "read" })),
                  ...unreadableAnnouncements.map((item) => ({ id: item.channel.id, name: item.channel.name, restricted: null, status: `unreadable: admin.conversations.getConversationPrefs ${item.error}` })),
                ],
                restricted_channels: restrictedChannels.slice(0, 20).map((item) => item.channel.name),
                posting_prefs_status: postingPrefsStatus,
                unreadable_channels: prefsErrors.length,
                unreadable_channel_details: prefsErrors,
                channels_complete: channelsComplete,
              },
            ),
    !channelsResult.ok
      ? manualFinding("SLACK-CHAN-03", "Channel retention overrides", 12, "medium", `admin.conversations.search is not readable: ${unreadableReason(channelsResult)}.`, "capture the workspace retention defaults and channel overrides from the admin dashboard.")
      : retentionByChannel.length === 0
        ? manualFinding("SLACK-CHAN-03", "Channel retention overrides", 12, "medium", channels.length === 0 ? `admin.conversations.search returned no active channels (${channelsView}).` : `${retentionGap ?? "admin.conversations.getCustomRetention is not readable"} (${channelsView}).`, "capture the workspace retention defaults and channel overrides from the admin dashboard.", { short_retention_channels: null, short_retention_status: `unknown: ${retentionGap ?? "admin.conversations.getCustomRetention unreadable"}`, retention_status: retentionStatus, unreadable_channels: retentionErrors.length, unreadable_channel_details: retentionErrors })
        : finding(
          "SLACK-CHAN-03",
          "Channel retention overrides",
          12,
          "medium",
          shortRetention.length > 0 ? "fail" : retentionErrors.length > 0 || !channelsComplete ? "warn" : "pass",
          shortRetention.length > 0
            ? `${shortRetention.length}/${retentionByChannel.length} sampled channels override retention below ${minRetentionDays} days (is_policy_enabled with duration_days)${retentionGap ? `; ${retentionGap}` : ""}.`
            : retentionErrors.length > 0 || !channelsComplete
              ? `No readable channel overrides retention below ${minRetentionDays} days, but ${retentionGap ?? "no channel was unreadable"}${channelsComplete ? ` (channels: ${channelsView})` : `; the channel view is partial (${channelsView})`}.`
              : `No channel overrides retention below ${minRetentionDays} days across ${retentionByChannel.length} channels; ${inheritingDefault.length} inherit the workspace default, which the API does not expose and must be confirmed in the admin dashboard.`,
          {
            min_retention_days: minRetentionDays,
            short_retention_channels: shortRetention.slice(0, 20).map((item) => ({ id: item.channel.id, name: item.channel.name, duration_days: item.duration_days })),
            inheriting_default: inheritingDefault.length,
            retention_status: retentionStatus,
            unreadable_channels: retentionErrors.length,
            unreadable_channel_details: retentionErrors,
          },
        ),
    manualFinding(
      "SLACK-CHAN-04",
      "External email ingestion",
      20,
      "medium",
      `The admin.conversations.search response documents no channel email address field and no admin method exposes the email-to-channel setting (${SLACK_DOC_PAGES.conversationsSearch}).`,
      "capture the 'Send emails to channels' permission from the workspace settings.",
      { citation: SLACK_DOC_PAGES.conversationsSearch },
    ),
    manualFinding(
      "SLACK-CHAN-05",
      "Link previews and URL unfurling",
      21,
      "medium",
      `admin.teams.settings.info documents no link preview or unfurl setting (${SLACK_DOC_PAGES.teamSettingsInfo}).`,
      "capture the link preview settings from the workspace messages and media settings.",
      { citation: SLACK_DOC_PAGES.teamSettingsInfo },
    ),
  );

  return {
    title: "Slack channel governance posture",
    summary: {
      channels_seen: inventoryCount(channelsResult, channels.length),
      channels_status: inventoryStatus(channelsResult, "admin.conversations.search"),
      channels_total: channelsResult.ok ? channelsResult.total ?? null : null,
      channels_complete: channelsComplete,
      external_channels: inventoryCount(externalResult, externalChannels.length),
      external_channels_status: inventoryStatus(externalResult, "admin.conversations.search (external_shared)"),
      restricted_posting_channels: prefsByChannel.length > 0 ? restrictedChannels.length : null,
      posting_prefs_status: postingPrefsStatus,
      short_retention_channels: retentionByChannel.length > 0 ? shortRetention.length : null,
      retention_status: retentionStatus,
    },
    findings,
    errors,
  };
}

export async function assessSlackMonitoring(
  client: SlackApiClient,
  options: { days?: number; auditLimit?: number } = {},
): Promise<SlackAssessmentResult> {
  const now = client.getNow();
  const days = clampNumber(options.days, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const auditLimit = clampNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT, 1, 9999);
  const oldest = Math.floor((now.getTime() - days * 24 * 60 * 60 * 1000) / 1000);
  const errors: string[] = [];
  const logsResult = await client.audit("/logs", { limit: auditLimit, oldest })
    .then((value): ReadResult<JsonRecord[]> => ({
      ok: true,
      value: asObjectArray(value.entries),
      complete: !asString(asObject(value.response_metadata)?.next_cursor),
    }))
    .catch((error): ReadResult<JsonRecord[]> => ({ ok: false, error: surfaceError(error), code: errorCode(error) }));
  const schemasResult = await client.audit("/schemas")
    .then((value): ReadResult<JsonRecord[]> => ({ ok: true, value: asObjectArray(value.schemas), complete: true }))
    .catch((error): ReadResult<JsonRecord[]> => ({ ok: false, error: surfaceError(error), code: errorCode(error) }));
  if (!logsResult.ok) errors.push(`Audit Logs /logs: ${logsResult.error}`);
  if (!schemasResult.ok) errors.push(`Audit Logs /schemas: ${schemasResult.error}`);

  const entries = logsResult.ok ? logsResult.value : [];
  const entryAges = entries.map((entry) => daysBetween(now, extractTimestamp(entry.date_create)));
  const undatedEntries = entryAges.filter((age) => age === undefined).length;
  const latestAge = entryAges.filter((age): age is number => age !== undefined).sort((left, right) => left - right)[0];
  const securityActions = new Set<string>(SLACK_SECURITY_AUDIT_ACTIONS);
  const externalActions = new Set<string>(SLACK_EXTERNAL_SHARING_AUDIT_ACTIONS);
  const visibleSecurityEvents = entries.filter((entry) => securityActions.has(asString(entry.action) ?? ""));
  const visibleExternalEvents = entries.filter((entry) => externalActions.has(asString(entry.action) ?? ""));
  const logsView = logsResult.ok ? `${entries.length} entries in the last ${days} days${logsResult.complete ? "" : " (window truncated at the sample limit)"}` : "unreadable";

  const findings: SlackFinding[] = [];
  if (!logsResult.ok) {
    const reason = `Audit Logs API /logs is not readable: ${unreadableReason(logsResult)} (requires an Enterprise Grid org-level token with auditlogs:read).`;
    findings.push(
      manualFinding("SLACK-MON-01", "Audit Logs API access", 13, "critical", reason, "export audit log evidence from the org dashboard or SIEM."),
      manualFinding("SLACK-MON-02", "Audit log recency", 13, "high", reason, "confirm audit log ingestion recency in the SIEM."),
      manualFinding("SLACK-MON-03", "Security event visibility", 13, "medium", reason, "confirm security administration events are collected in the SIEM."),
      manualFinding("SLACK-MON-05", "External sharing monitoring", 7, "medium", reason, "confirm Slack Connect and external sharing events are monitored."),
    );
  } else {
    findings.push(
      finding(
        "SLACK-MON-01",
        "Audit Logs API access",
        13,
        "critical",
        entries.length === 0 ? "fail" : logsResult.complete ? "pass" : "warn",
        entries.length === 0
          ? `Audit Logs API is readable but returned no entries in the last ${days} days; an active org should produce events, so emptiness is treated as a failure.`
          : logsResult.complete
            ? `Audit Logs API is readable (${logsView}).`
            : `Audit Logs API is readable but the window was truncated at audit_limit=${auditLimit} (${logsView}); raise audit_limit to read the full window.`,
        { entries: entries.length, days, window_complete: logsResult.complete },
      ),
      finding(
        "SLACK-MON-02",
        "Audit log recency",
        13,
        "high",
        latestAge === undefined ? "warn" : latestAge > 1 ? "fail" : logsResult.complete ? "pass" : "warn",
        latestAge === undefined
          ? `No entry carried a parseable date_create (${undatedEntries} undated entries are reported separately).`
          : `Latest parseable audit event is ${latestAge.toFixed(2)} days old; ${undatedEntries} undated entries were excluded from the recency calculation${logsResult.complete ? "" : "; the window was truncated so ordering is not guaranteed"}.`,
        { latest_event_age_days: latestAge ?? null, undated_entries: undatedEntries },
      ),
      finding(
        "SLACK-MON-03",
        "Security event visibility",
        13,
        "medium",
        visibleSecurityEvents.length === 0 || !logsResult.complete ? "warn" : "pass",
        visibleSecurityEvents.length === 0
          ? `No common security administration action appeared in the sampled entries (${logsView}); emptiness is not treated as compliant.`
          : `${visibleSecurityEvents.length} security administration events were visible (${logsView}).`,
        { security_event_count: visibleSecurityEvents.length, matched_actions: [...new Set(visibleSecurityEvents.map((entry) => asString(entry.action) ?? ""))] },
      ),
      finding(
        "SLACK-MON-05",
        "External sharing monitoring",
        7,
        "medium",
        visibleExternalEvents.length === 0 || !logsResult.complete ? "warn" : "pass",
        visibleExternalEvents.length === 0
          ? `No Slack Connect or external sharing action appeared in the sampled entries (${logsView}); confirm monitoring coverage rather than treating emptiness as compliant.`
          : `${visibleExternalEvents.length} external sharing events were visible (${logsView}).`,
        { external_event_count: visibleExternalEvents.length, matched_actions: [...new Set(visibleExternalEvents.map((entry) => asString(entry.action) ?? ""))] },
      ),
    );
  }
  findings.push(
    !schemasResult.ok
      ? manualFinding("SLACK-MON-04", "Audit schema visibility", 13, "low", `Audit Logs API /schemas is not readable: ${unreadableReason(schemasResult)}.`, "reference the published audit event schema documentation.")
      : finding(
        "SLACK-MON-04",
        "Audit schema visibility",
        13,
        "low",
        schemasResult.value.length === 0 ? "warn" : "pass",
        schemasResult.value.length === 0
          ? "Audit Logs API /schemas returned no schemas."
          : `${schemasResult.value.length} audit event schemas are readable.`,
        { schemas: schemasResult.value.length },
      ),
    manualFinding(
      "SLACK-MON-06",
      "Audit log SIEM streaming",
      13,
      "high",
      `The Audit Logs API is pull-based and documents no method that reports SIEM streaming or export destinations (${SLACK_DOC_PAGES.auditLogs}).`,
      "collect the SIEM ingestion configuration and a recent ingestion timestamp for Slack audit events.",
      { citation: SLACK_DOC_PAGES.auditLogs, audit_api_readable: logsResult.ok },
    ),
  );
  findings.sort((left, right) => left.id.localeCompare(right.id));

  return {
    title: "Slack monitoring posture",
    summary: {
      days,
      audit_entries: inventoryCount(logsResult, entries.length),
      audit_status: inventoryStatus(logsResult, "Audit Logs /logs"),
      audit_window_complete: logsResult.ok ? logsResult.complete : false,
      latest_event_age_days: latestAge ?? null,
      security_events: inventoryCount(logsResult, visibleSecurityEvents.length),
      external_sharing_events: inventoryCount(logsResult, visibleExternalEvents.length),
      schemas_readable: schemasResult.ok,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: SlackAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.api,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Slack access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "API", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SlackAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    String(item.control),
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
    formatTable(["Finding", "Spec", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", `Collection errors (${result.errors.length}):`, ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function statusCounts(findings: SlackFinding[]): Record<SlackFindingStatus, number> {
  const counts: Record<SlackFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(config: SlackConfiguration, findings: SlackFinding[], generatedAt: string): string {
  const counts = statusCounts(findings);
  const coveredControls = new Set(findings.map((item) => item.control));
  return [
    "# Slack Security Inspector Executive Summary",
    "",
    `Target: ${config.orgId ?? "Slack workspace token scope"}`,
    `Generated: ${generatedAt}`,
    "",
    "## Result Counts",
    "",
    `- Failed findings: ${counts.fail}`,
    `- Warning findings: ${counts.warn}`,
    `- Passing findings: ${counts.pass}`,
    `- Manual findings: ${counts.manual}`,
    `- Spec controls covered: ${coveredControls.size} of ${SLACK_SPEC_CONTROLS.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Findings",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedComplianceMatrix(findings: SlackFinding[]): string {
  const rows = findings.map((item) => {
    const spec = SLACK_SPEC_CONTROLS.find((control) => control.number === item.control);
    return [
      item.id,
      `${item.control}. ${spec?.name ?? "unknown"}`,
      item.status.toUpperCase(),
      ...(spec?.refs.map((ref) => ref ?? "-") ?? SLACK_FRAMEWORKS.map(() => "-")),
    ];
  });
  return [
    "# Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Spec control", "Status", ...SLACK_FRAMEWORKS], rows),
  ].join("\n");
}

function frameworkSlug(framework: FrameworkName): string {
  return framework.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function buildFrameworkReport(framework: FrameworkName, findings: SlackFinding[]): string {
  const index = SLACK_FRAMEWORKS.indexOf(framework);
  const rows = findings
    .map((item) => ({ item, ref: SLACK_SPEC_CONTROLS.find((control) => control.number === item.control)?.refs[index] ?? null }))
    .filter((entry) => entry.ref !== null)
    .map((entry) => [entry.ref ?? "-", entry.item.id, entry.item.status.toUpperCase(), entry.item.title, entry.item.summary]);
  return [
    `# ${framework} Report`,
    "",
    rows.length === 0 ? `No spec control maps to ${framework}.` : formatTable([`${framework} reference`, "Finding", "Status", "Title", "Summary"], rows),
  ].join("\n");
}

function buildQuickReference(result: { outputDir: string; zipPath: string }, findings: SlackFinding[], errors: string[]): string {
  const counts = statusCounts(findings);
  return [
    "# Quick Reference",
    "",
    `- Bundle directory: ${result.outputDir}`,
    `- Archive: ${result.zipPath}`,
    `- Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    `- Collection errors: ${errors.length}${errors.length > 0 ? " (see _errors.log)" : ""}`,
    "",
    "## Layout",
    "",
    "- `core_data/`: raw access check and per-area collection snapshots (credential fields keep their name with a [REDACTED] value)",
    "- `analysis/findings.json`: every finding with status, evidence, and framework mappings",
    "- `analysis/<area>.json`: per-area summaries",
    "- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, one report per framework",
    "- `reports/<area>.md`: human-readable per-area tables",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "## Status Semantics",
    "",
    "- pass: documented evidence read completely and compliant",
    "- warn: compliant on the seen data but partial, empty, or needing review",
    "- fail: documented evidence shows a gap",
    "- manual: the API cannot prove the control; the summary names the cause and the evidence to collect",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Slack Evidence Bundle",
    "",
    "Generated by grclanker's native Slack Enterprise Grid tools. See QUICK_REFERENCE.md for the layout and status semantics.",
    "",
    "Slack tokens, app secrets, webhook URLs, and other credential values are redacted at collection time and again when each file is written; the field names remain with a [REDACTED] marker.",
  ].join("\n");
}

export async function exportSlackAuditBundle(
  client: SlackApiClient,
  config: SlackConfiguration,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<SlackAuditBundleResult> {
  const access = await checkSlackAccess(client);
  const areas: Array<{ slug: string; result: SlackAssessmentResult }> = [
    { slug: "identity", result: await assessSlackIdentity(client, { userLimit: options.user_limit, skipScim: options.skip_scim }) },
    {
      slug: "admin-access",
      result: await assessSlackAdminAccess(client, {
        workspaceLimit: options.workspace_limit,
        userLimit: options.user_limit,
        maxWorkspaceAdmins: options.max_workspace_admins,
        maxSessionHours: options.max_session_hours,
      }),
    },
    { slug: "integrations", result: await assessSlackIntegrations(client, { appLimit: options.app_limit, workspaceLimit: options.workspace_limit }) },
    { slug: "channel-governance", result: await assessSlackChannelGovernance(client, { channelLimit: options.channel_limit, minRetentionDays: options.min_retention_days }) },
    { slug: "monitoring", result: await assessSlackMonitoring(client, { days: options.days, auditLimit: options.audit_limit }) },
  ];

  const findings = areas.flatMap((area) => area.result.findings);
  const errors = areas.flatMap((area) => area.result.errors.map((item) => `[${area.slug}] ${item}`));
  const generatedAt = client.getNow().toISOString();
  const targetName = safeDirName(`${config.orgId ?? "slack"}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);
  const zipPath = `${outputDir}.zip`;

  const secrets = client.knownSecrets();
  const writeBundleFile = (rootDir: string, relativePathname: string, content: string): Promise<void> =>
    writeSecureTextFile(rootDir, relativePathname, redactErrorText(content, secrets));
  await writeBundleFile(outputDir, "README.md", buildBundleReadme());
  await writeBundleFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference({ outputDir, zipPath }, findings, errors));
  await writeBundleFile(outputDir, "metadata.json", serializeJson(redactSecrets({
    target: config.orgId ?? null,
    auth_mode: "bearer-token",
    token_kinds: client.getTokenKinds(),
    scim_configured: Boolean(config.scimToken),
    source_chain: config.sourceChain,
    generated_at: generatedAt,
    options: {
      user_limit: options.user_limit ?? DEFAULT_USER_LIMIT,
      workspace_limit: options.workspace_limit ?? DEFAULT_WORKSPACE_LIMIT,
      app_limit: options.app_limit ?? DEFAULT_APP_LIMIT,
      audit_limit: options.audit_limit ?? DEFAULT_AUDIT_LIMIT,
      channel_limit: options.channel_limit ?? DEFAULT_CHANNEL_LIMIT,
      days: options.days ?? DEFAULT_LOOKBACK_DAYS,
      max_workspace_admins: options.max_workspace_admins ?? 5,
      max_session_hours: options.max_session_hours ?? 24,
      min_retention_days: options.min_retention_days ?? DEFAULT_MIN_RETENTION_DAYS,
    },
  }, secrets)));
  await writeBundleFile(outputDir, "core_data/access.json", serializeJson(redactSecrets(access, secrets)));
  for (const area of areas) {
    await writeBundleFile(outputDir, `core_data/${area.slug}.json`, serializeJson(redactSecrets({ summary: area.result.summary, evidence: area.result.findings.map((item) => ({ id: item.id, evidence: item.evidence ?? null })), errors: area.result.errors }, secrets)));
    await writeBundleFile(outputDir, `analysis/${area.slug}.json`, serializeJson(redactSecrets({ title: area.result.title, summary: area.result.summary, status_counts: statusCounts(area.result.findings) }, secrets)));
    await writeBundleFile(outputDir, `reports/${area.slug}.md`, formatAssessmentText(area.result));
  }
  await writeBundleFile(outputDir, "analysis/findings.json", serializeJson(redactSecrets(findings, secrets)));
  await writeBundleFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, findings, generatedAt));
  await writeBundleFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedComplianceMatrix(findings));
  for (const framework of SLACK_FRAMEWORKS) {
    await writeBundleFile(outputDir, `compliance/${frameworkSlug(framework)}.md`, buildFrameworkReport(framework, findings));
  }
  if (errors.length > 0) {
    await writeBundleFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return { outputDir, zipPath, fileCount, findingCount: findings.length, errorCount: errors.length };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    token: asString(value.token) ?? asString(value.user_token),
    bot_token: asString(value.bot_token),
    scim_token: asString(value.scim_token) ?? asString(value.scimToken),
    org_id: asString(value.org_id) ?? asString(value.enterprise_id),
    web_api_base_url: asString(value.web_api_base_url),
    scim_base_url: asString(value.scim_base_url),
    audit_base_url: asString(value.audit_base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCheckAccessArgs(args), user_limit: asNumber(value.user_limit), skip_scim: asBoolean(value.skip_scim) };
}

function normalizeAdminAccessArgs(args: unknown): AdminAccessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    workspace_limit: asNumber(value.workspace_limit),
    user_limit: asNumber(value.user_limit),
    max_workspace_admins: asNumber(value.max_workspace_admins),
    max_session_hours: asNumber(value.max_session_hours),
    session_sample: asNumber(value.session_sample),
  };
}

function normalizeIntegrationsArgs(args: unknown): IntegrationsArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCheckAccessArgs(args), app_limit: asNumber(value.app_limit), workspace_limit: asNumber(value.workspace_limit) };
}

function normalizeMonitoringArgs(args: unknown): MonitoringArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCheckAccessArgs(args), days: asNumber(value.days), audit_limit: asNumber(value.audit_limit) };
}

function normalizeChannelGovernanceArgs(args: unknown): ChannelGovernanceArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeCheckAccessArgs(args), channel_limit: asNumber(value.channel_limit), min_retention_days: asNumber(value.min_retention_days) };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    user_limit: asNumber(value.user_limit),
    workspace_limit: asNumber(value.workspace_limit),
    app_limit: asNumber(value.app_limit),
    audit_limit: asNumber(value.audit_limit),
    channel_limit: asNumber(value.channel_limit),
    days: asNumber(value.days),
    max_workspace_admins: asNumber(value.max_workspace_admins),
    max_session_hours: asNumber(value.max_session_hours),
    min_retention_days: asNumber(value.min_retention_days),
    skip_scim: asBoolean(value.skip_scim),
  };
}

function createClient(args: CheckAccessArgs): SlackApiClient {
  return new SlackApiClient(resolveSlackConfiguration(args as JsonRecord));
}

function describeError(error: unknown): string {
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

const authParams = {
  token: Type.Optional(Type.String({ description: "Slack org-level user token. Defaults to SLACK_USER_TOKEN, then the config file." })),
  bot_token: Type.Optional(Type.String({ description: "Slack bot token for bot-capable methods (auth.test, users.list). Defaults to SLACK_BOT_TOKEN." })),
  scim_token: Type.Optional(Type.String({ description: "Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN." })),
  org_id: Type.Optional(Type.String({ description: "Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "Request timeout in seconds. Defaults to 30.", default: 30 })),
};

type ToolName =
  | "slack_check_access"
  | "slack_assess_identity"
  | "slack_assess_admin_access"
  | "slack_assess_integrations"
  | "slack_assess_channel_governance"
  | "slack_assess_monitoring";

async function runAssessment(tool: ToolName, args: unknown): Promise<unknown> {
  switch (tool) {
    case "slack_check_access": {
      const result = await checkSlackAccess(createClient(args as CheckAccessArgs));
      return textResult(formatAccessCheckText(result), { tool, ...result });
    }
    case "slack_assess_identity": {
      const typed = args as IdentityArgs;
      const result = await assessSlackIdentity(createClient(typed), { userLimit: typed.user_limit, skipScim: typed.skip_scim });
      return textResult(formatAssessmentText(result), { tool, ...result });
    }
    case "slack_assess_admin_access": {
      const typed = args as AdminAccessArgs;
      const result = await assessSlackAdminAccess(createClient(typed), {
        workspaceLimit: typed.workspace_limit,
        userLimit: typed.user_limit,
        maxWorkspaceAdmins: typed.max_workspace_admins,
        maxSessionHours: typed.max_session_hours,
        sessionSample: typed.session_sample,
      });
      return textResult(formatAssessmentText(result), { tool, ...result });
    }
    case "slack_assess_integrations": {
      const typed = args as IntegrationsArgs;
      const result = await assessSlackIntegrations(createClient(typed), { appLimit: typed.app_limit, workspaceLimit: typed.workspace_limit });
      return textResult(formatAssessmentText(result), { tool, ...result });
    }
    case "slack_assess_channel_governance": {
      const typed = args as ChannelGovernanceArgs;
      const result = await assessSlackChannelGovernance(createClient(typed), { channelLimit: typed.channel_limit, minRetentionDays: typed.min_retention_days });
      return textResult(formatAssessmentText(result), { tool, ...result });
    }
    case "slack_assess_monitoring": {
      const typed = args as MonitoringArgs;
      const result = await assessSlackMonitoring(createClient(typed), { days: typed.days, auditLimit: typed.audit_limit });
      return textResult(formatAssessmentText(result), { tool, ...result });
    }
    default: {
      const exhaustive: never = tool;
      throw new Error(`Unhandled Slack tool ${String(exhaustive)}`);
    }
  }
}

function registerAssessment(
  pi: any,
  tool: ToolName,
  label: string,
  description: string,
  parameters: unknown,
  prepareArguments: (args: unknown) => unknown,
): void {
  pi.registerTool({
    name: tool,
    label,
    description,
    parameters,
    prepareArguments,
    async execute(_toolCallId: string, args: unknown) {
      try {
        return await runAssessment(tool, args);
      } catch (error) {
        return errorResult(`${label} failed: ${describeError(error)}`, { tool });
      }
    },
  });
}

export function registerSlackTools(pi: any): void {
  registerAssessment(
    pi,
    "slack_check_access",
    "Check Slack audit access",
    "Validate read-only Slack Enterprise Grid API access and show which Web API, Admin API, SCIM, and Audit Logs surfaces are readable with the configured user, bot, and SCIM tokens.",
    Type.Object(authParams),
    normalizeCheckAccessArgs,
  );

  registerAssessment(
    pi,
    "slack_assess_identity",
    "Assess Slack identity posture",
    "Assess Slack MFA enrollment (has_2fa), guest inventory, SCIM provisioning coverage, user lifecycle alignment, and deactivated user visibility.",
    Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to read. Defaults to 1000.", default: 1000 })),
      skip_scim: Type.Optional(Type.Boolean({ description: "Skip SCIM provisioning checks. Defaults to false.", default: false })),
    }),
    normalizeIdentityArgs,
  );

  registerAssessment(
    pi,
    "slack_assess_admin_access",
    "Assess Slack admin access",
    "Assess Slack workspace admin inventory, SSO coverage (has_sso), session duration, idle timeout, discoverability, mobile session controls, email domain restrictions, custom emoji governance, and analytics access.",
    Type.Object({
      ...authParams,
      workspace_limit: Type.Optional(Type.Number({ description: "Maximum workspaces to read. Defaults to 50.", default: 50 })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum org users to read from admin.users.list. Defaults to 1000.", default: 1000 })),
      max_workspace_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per workspace. Defaults to 5.", default: 5 })),
      max_session_hours: Type.Optional(Type.Number({ description: "Maximum acceptable session duration in hours. Defaults to 24.", default: 24 })),
      session_sample: Type.Optional(Type.Number({ description: "Maximum users whose session settings are sampled. Defaults to 100.", default: 100 })),
    }),
    normalizeAdminAccessArgs,
  );

  registerAssessment(
    pi,
    "slack_assess_integrations",
    "Assess Slack integrations",
    "Assess Slack approved and restricted app inventories, internal and sensitive-scope apps, information barriers, DLP and Discovery evidence, file upload restrictions (team.preferences.list), and token rotation.",
    Type.Object({
      ...authParams,
      app_limit: Type.Optional(Type.Number({ description: "Maximum approved/restricted apps to read. Defaults to 500.", default: 500 })),
      workspace_limit: Type.Optional(Type.Number({ description: "Maximum workspaces to read when scoping team.preferences.list. Defaults to 50.", default: 50 })),
    }),
    normalizeIntegrationsArgs,
  );

  registerAssessment(
    pi,
    "slack_assess_channel_governance",
    "Assess Slack channel governance",
    "Assess Slack Connect exposure, posting restrictions on general and org default channels, channel retention overrides, external email ingestion, and link preview settings.",
    Type.Object({
      ...authParams,
      channel_limit: Type.Optional(Type.Number({ description: "Maximum active channels to sample for prefs and retention. Defaults to 40.", default: 40 })),
      min_retention_days: Type.Optional(Type.Number({ description: "Minimum acceptable custom retention in days. Defaults to 365.", default: 365 })),
    }),
    normalizeChannelGovernanceArgs,
  );

  registerAssessment(
    pi,
    "slack_assess_monitoring",
    "Assess Slack monitoring",
    "Assess Slack Audit Logs API access, event recency, security administration events, schema visibility, external sharing monitoring, and SIEM streaming evidence.",
    Type.Object({
      ...authParams,
      days: Type.Optional(Type.Number({ description: "Audit log lookback window in days. Defaults to 30.", default: 30 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit events to read (1-9999). Defaults to 200.", default: 200 })),
    }),
    normalizeMonitoringArgs,
  );

  pi.registerTool({
    name: "slack_export_audit_bundle",
    label: "Export Slack audit bundle",
    description:
      "Export a Slack audit bundle with core_data snapshots, analysis JSON, per-framework compliance reports, QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive named after the allocated directory.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to read. Defaults to 1000.", default: 1000 })),
      workspace_limit: Type.Optional(Type.Number({ description: "Maximum workspaces to read. Defaults to 50.", default: 50 })),
      app_limit: Type.Optional(Type.Number({ description: "Maximum approved/restricted apps to read. Defaults to 500.", default: 500 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit events to read. Defaults to 200.", default: 200 })),
      channel_limit: Type.Optional(Type.Number({ description: "Maximum channels to sample. Defaults to 40.", default: 40 })),
      days: Type.Optional(Type.Number({ description: "Audit log lookback window in days. Defaults to 30.", default: 30 })),
      max_workspace_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per workspace. Defaults to 5.", default: 5 })),
      max_session_hours: Type.Optional(Type.Number({ description: "Maximum acceptable session duration in hours. Defaults to 24.", default: 24 })),
      min_retention_days: Type.Optional(Type.Number({ description: "Minimum acceptable custom retention in days. Defaults to 365.", default: 365 })),
      skip_scim: Type.Optional(Type.Boolean({ description: "Skip SCIM provisioning checks. Defaults to false.", default: false })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveSlackConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSlackAuditBundle(new SlackApiClient(config), config, outputRoot, args);
        return textResult(
          [
            "Slack audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "slack_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Slack audit bundle export failed: ${describeError(error)}`, { tool: "slack_export_audit_bundle" });
      }
    },
  });
}
