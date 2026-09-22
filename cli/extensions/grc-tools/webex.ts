/**
 * Cisco Webex organization audit tools for grclanker.
 *
 * Read-only Webex REST API inspector covering identity posture, collaboration
 * governance, and meeting plus hybrid security controls. Every request path,
 * query parameter, and response field read here is traceable to a public
 * developer.webex.com page named in WEBEX_DOCS.
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
import { parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

/**
 * Public documentation pages backing each request. The canonical reference URL
 * https://developer.webex.com/docs/api/v1/<category>/<page> answers 302 to a
 * category-prefixed page (/admin/docs, /meeting/docs, /calling/docs,
 * /messaging/docs) whose server-rendered HTML embeds the OpenAPI 3.0.3 spec
 * for every endpoint in that category; `curl -L` fetches it without a browser.
 * The URLs below are those redirect targets, and every field read in this
 * module was checked against the embedded schema.
 */
export const WEBEX_DOCS = {
  basics: "https://developer.webex.com/docs/api/basics",
  integrations: "https://developer.webex.com/docs/integrations",
  serviceApps: "https://developer.webex.com/docs/service-apps",
  bots: "https://developer.webex.com/docs/bots",
  complianceGuide: "https://developer.webex.com/docs/api/guides/compliance",
  peopleMe: "https://developer.webex.com/admin/docs/api/v1/people/get-my-own-details",
  peopleList: "https://developer.webex.com/admin/docs/api/v1/people/list-people",
  organizationsList: "https://developer.webex.com/admin/docs/api/v1/organizations/list-organizations",
  organizationGet: "https://developer.webex.com/admin/docs/api/v1/organizations/get-organization-details",
  authenticationConfig: "https://developer.webex.com/admin/docs/api/v1/identity-organization/update-organization-authentication-configuration-settings",
  rolesList: "https://developer.webex.com/admin/docs/api/v1/roles/list-roles",
  licensesList: "https://developer.webex.com/admin/docs/api/v1/licenses/list-licenses",
  eventsList: "https://developer.webex.com/admin/docs/api/v1/events/list-events",
  adminAuditEvents: "https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events",
  adminRecordings: "https://developer.webex.com/admin/docs/api/v1/recordings/list-recordings-for-an-admin-or-compliance-officer",
  guestCount: "https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count",
  hybridClusters: "https://developer.webex.com/admin/docs/api/v1/hybrid-clusters/list-hybrid-clusters",
  hybridConnectors: "https://developer.webex.com/admin/docs/api/v1/hybrid-connectors/list-hybrid-connectors",
  meetingsList: "https://developer.webex.com/meeting/docs/api/v1/meetings/list-meetings",
  meetingPreferences: "https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-meeting-preference-details",
  meetingSites: "https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-site-list",
  meetingCommonSettings: "https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration",
  sessionTypes: "https://developer.webex.com/meeting/docs/api/v1/session-types",
  webhooksList: "https://developer.webex.com/meeting/docs/api/v1/webhooks/list-webhooks",
  devicesList: "https://developer.webex.com/calling/docs/api/v1/devices/list-devices",
  workspacesList: "https://developer.webex.com/calling/docs/api/v1/workspaces/list-workspaces",
  roomsList: "https://developer.webex.com/messaging/docs/api/v1/rooms/list-rooms",
} as const;

const DEFAULT_OUTPUT_DIR = "./export/webex";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_CONFIG_DIR = join(".config", "webex-sec-inspector");
const CONFIG_FILE_NAMES = ["config.json", "config.yaml", "config.yml"];
const MAX_RETRY_AFTER_MS = 30_000;
const MAX_429_RETRIES = 2;
/** Ceiling on rel="next" hops per listing; reaching it reports truncated: true. */
const MAX_LIST_PAGES = 1000;

/**
 * Per-page `max` for the endpoints whose reference documents a `max` query
 * parameter, kept within each documented ceiling (adminAudit 200, admin
 * recordings 1 to 100, meetings up to 100, events and rooms 1 to 1000).
 * /organizations, /roles, /licenses, /meetingPreferences/sites,
 * /hybrid/clusters, and /hybrid/connectors document no `max`, so none is sent.
 */
const PAGE_MAX = {
  people: 100,
  events: 100,
  adminAudit: 200,
  adminRecordings: 100,
  meetings: 100,
  devices: 100,
  workspaces: 100,
  rooms: 100,
  webhooks: 100,
} as const;
const MIN_MEETING_PASSWORD_LENGTH = 8;

const DEFAULT_PEOPLE_LIMIT = 1000;
const DEFAULT_EVENT_LIMIT = 500;
const DEFAULT_LICENSE_LIMIT = 200;
const DEFAULT_RECORDING_LIMIT = 200;
const DEFAULT_MEETING_LIMIT = 200;
const DEFAULT_WEBHOOK_LIMIT = 200;
const DEFAULT_DEVICE_LIMIT = 500;
const DEFAULT_ROOM_LIMIT = 500;
const DEFAULT_GENERIC_LIMIT = 200;
const DEFAULT_MAX_ADMINS = 10;
const ADMIN_AUDIT_WINDOW_DAYS = 30;

export type WebexFrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig" | "irap" | "ismap";
export type WebexFrameworkMap = Record<WebexFrameworkKey, string[]>;
export type WebexFindingStatus = "pass" | "warn" | "fail" | "manual";
export type WebexTokenType = "person" | "bot" | "appuser" | "unknown";

export const WEBEX_FRAMEWORK_LABELS: Record<WebexFrameworkKey, string> = {
  fedramp: "FedRAMP / NIST 800-53",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis: "CIS Controls",
  pci_dss: "PCI-DSS",
  disa_stig: "DISA STIG",
  irap: "IRAP / ISM",
  ismap: "ISMAP",
};

function frameworks(
  fedramp: string, cmmc: string, soc2: string, cis: string, pci: string, stig: string, irap: string, ismap: string,
): WebexFrameworkMap {
  const list = (value: string): string[] => value ? [value] : [];
  return { fedramp: list(fedramp), cmmc: list(cmmc), soc2: list(soc2), cis: list(cis), pci_dss: list(pci), disa_stig: list(stig), irap: list(irap), ismap: list(ismap) };
}

/** Spec section 5 mapping table, keyed by spec control number. */
export const WEBEX_CONTROL_FRAMEWORKS: Record<number, WebexFrameworkMap> = {
  1: frameworks("IA-2(1)", "L2 3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000148", "ISM-1546", "CPS-7.1"),
  2: frameworks("IA-2(2)", "L2 3.5.3", "CC6.1", "16.3", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-7.2"),
  3: frameworks("AU-1", "L2 3.3.2", "CC7.2", "8.1", "12.5.2", "SRG-APP-000516", "ISM-0042", "CPS-12.1"),
  4: frameworks("AC-4", "L2 3.1.3", "CC6.6", "13.4", "1.3.7", "SRG-APP-000100", "ISM-1528", "CPS-11.1"),
  5: frameworks("AC-4(1)", "L2 3.1.3", "CC6.7", "13.4", "1.3.7", "SRG-APP-000100", "ISM-0947", "CPS-11.2"),
  6: frameworks("SC-28", "L2 3.13.16", "CC6.7", "14.8", "3.4.1", "SRG-APP-000428", "ISM-0457", "CPS-11.3"),
  7: frameworks("SI-12", "L2 3.8.9", "CC6.5", "14.8", "3.1", "SRG-APP-000504", "ISM-0859", "CPS-12.2"),
  8: frameworks("SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.4"),
  9: frameworks("AC-3", "L2 3.1.1", "CC6.1", "16.7", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.1"),
  10: frameworks("IA-5", "L2 3.5.7", "CC6.1", "16.5", "8.2.3", "SRG-APP-000170", "ISM-1557", "CPS-7.3"),
  11: frameworks("AU-11", "L2 3.3.1", "CC7.3", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "CPS-12.3"),
  12: frameworks("SI-12", "L2 3.8.9", "CC6.5", "14.8", "3.1", "SRG-APP-000504", "ISM-0859", "CPS-12.4"),
  13: frameworks("AC-14", "L2 3.1.1", "CC6.1", "16.7", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.2"),
  14: frameworks("AC-16", "L2 3.13.12", "CC6.7", "14.1", "9.6.1", "SRG-APP-000311", "ISM-0271", "CPS-11.5"),
  15: frameworks("CM-8", "L2 3.4.1", "CC6.8", "1.1", "2.4", "SRG-APP-000383", "ISM-1409", "CPS-10.1"),
  16: frameworks("SI-4", "L2 3.14.6", "CC7.1", "1.1", "10.6", "SRG-APP-000516", "ISM-0576", "CPS-12.5"),
  17: frameworks("SI-2", "L2 3.14.1", "CC7.1", "7.4", "6.2", "SRG-APP-000456", "ISM-1143", "CPS-13.1"),
  18: frameworks("CM-8(3)", "L2 3.4.1", "CC6.8", "1.4", "9.7.1", "SRG-APP-000383", "ISM-1482", "CPS-10.2"),
  19: frameworks("CM-7", "L2 3.4.6", "CC6.8", "4.8", "2.2.2", "SRG-APP-000141", "ISM-1407", "CPS-10.3"),
  20: frameworks("SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.6"),
  21: frameworks("SC-7(8)", "L2 3.13.1", "CC6.7", "13.4", "1.3.7", "SRG-APP-000516", "ISM-0947", "CPS-11.7"),
  22: frameworks("SC-8", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000439", "ISM-0484", "CPS-11.8"),
  23: frameworks("AC-3", "L2 3.1.1", "CC6.1", "", "", "SRG-APP-000033", "", ""),
  24: frameworks("CM-8", "L2 3.4.1", "CC6.8", "1.1", "2.4", "SRG-APP-000383", "ISM-1409", "CPS-10.4"),
  25: frameworks("AU-12", "L2 3.3.1", "CC7.2", "8.5", "10.2.2", "SRG-APP-000507", "ISM-0580", "CPS-12.6"),
};

export interface WebexRefreshCredentials {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

export interface WebexResolvedConfig {
  token?: string;
  refresh?: WebexRefreshCredentials;
  orgId?: string;
  baseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
  configFile?: string;
}

export interface WebexAccessSurface {
  name: string;
  endpoint: string;
  doc: string;
  status: "readable" | "not_readable" | "not_configured" | "manual";
  count?: number;
  truncated?: boolean;
  error?: string;
}

export interface WebexAccessCheckResult {
  status: "healthy" | "limited";
  orgId?: string;
  tokenType: WebexTokenType;
  adminCapable: boolean;
  surfaces: WebexAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface WebexFinding {
  id: string;
  control: number[];
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: WebexFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  frameworks: WebexFrameworkMap;
}

export interface WebexAssessmentResult {
  title: string;
  category: string;
  summary: JsonRecord;
  findings: WebexFinding[];
  errors: string[];
  rawData: Record<string, unknown>;
}

export interface WebexAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface WebexPage {
  items: JsonRecord[];
  truncated: boolean;
  pageCount: number;
}

export class WebexApiError extends Error {
  readonly status: number;
  readonly endpoint: string;

  constructor(message: string, status: number, endpoint: string) {
    super(scrubErrorText(message));
    this.name = "WebexApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

type SurfaceResult<T> =
  | { ok: true; data: T; truncated: boolean }
  | { ok: false; error: string; status?: number };

type CheckAccessArgs = {
  token?: string;
  org_id?: string;
  base_url?: string;
  timeout_seconds?: number;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  config_file?: string;
};

type IdentityArgs = CheckAccessArgs & {
  people_limit?: number;
  max_admins?: number;
};

type CollaborationArgs = CheckAccessArgs & {
  event_limit?: number;
  recording_limit?: number;
  webhook_limit?: number;
  license_limit?: number;
  room_limit?: number;
};

type MeetingHybridArgs = CheckAccessArgs & {
  meeting_limit?: number;
  device_limit?: number;
};

type ExportAuditBundleArgs = IdentityArgs & CollaborationArgs & MeetingHybridArgs & {
  output_dir?: string;
};

type AssessmentOptions = {
  peopleLimit?: number;
  maxAdmins?: number;
  eventLimit?: number;
  recordingLimit?: number;
  webhookLimit?: number;
  licenseLimit?: number;
  roomLimit?: number;
  meetingLimit?: number;
  deviceLimit?: number;
};

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
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function asDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
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

/** RFC 5988 Link header; only rel="next" is guaranteed by Webex (basics guide). */
export function parseLinkHeaderNext(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="?next"?/i);
    if (match?.[1]) return match[1];
  }
  return null;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const SECRET_KEY_PATTERN = /token|secret|password|passcode|hostpin|hostkey|authorization|accesscode|activationcode|credential/i;
/** Policy flags from commonSettings.securityOptions that name passwords without holding one. */
const POLICY_KEY_PATTERN = /^(passwordCriteria|requireStrongPassword|excludePassword)$/;
/**
 * Any scheme-prefixed URL embedded anywhere in a string (not only a whole-value URL):
 * everything from its first ? or # carries no evidence value (RCID, MTID, token parameters).
 */
const EMBEDDED_URL_PATTERN = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
/** Credential parameters embedded in SIP and tel URIs, for example ;pwd=1234. */
const URI_CREDENTIAL_PARAM_PATTERN = /;(pwd|password|pin|passcode|token|secret)=[^;?#\s]*/gi;
/** Key names whose assigned value in free text is treated as a credential. */
const CREDENTIAL_KEY_WORDS = "token|secret|passw(?:or)?d|pwd|pin|passcode|session|sid|api[_-]?key|apikey|key|bearer|basic|authorization|auth|cookie|credential|access[_-]?key|signature";
/** `key=value`, `key: value`, or `"key":"value"` where the key names a credential; the value may itself start with Bearer or Basic. */
const CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
  `\\b"?([A-Za-z0-9_.-]*(?:${CREDENTIAL_KEY_WORDS})[A-Za-z0-9_.-]*)"?\\s*[=:]\\s*"?(?:(?:bearer|basic)\\s+)?[^\\s"'&;,<>]+`,
  "gi",
);
/** A standalone `Bearer <value>` or `Basic <value>` authorization value. */
const CREDENTIAL_SCHEME_PATTERN = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;

/**
 * Strips credential-bearing parts from a string while keeping host and path:
 * the query string and fragment of every scheme-prefixed URL found anywhere in
 * the text (recording download and playback RCID, meeting join MTID, webhook
 * tokens, sign-in links quoted inside error messages) and ;pwd= style
 * parameters inside SIP URIs.
 */
export function scrubValue(value: string): string {
  return value
    .replace(EMBEDDED_URL_PATTERN, (url) => {
      // Sentence punctuation directly after a URL belongs to the surrounding prose, not the query.
      const trailing = url.match(/[.,;:!]+$/)?.[0] ?? "";
      const body = url.slice(0, url.length - trailing.length);
      const cut = body.search(/[?#]/);
      return `${cut >= 0 ? body.slice(0, cut) : body}${trailing}`;
    })
    .replace(URI_CREDENTIAL_PARAM_PATTERN, "");
}

/**
 * The one scrub applied where error strings are created: the WebexApiError
 * constructor (every API failure) and errorMessage (every other thrown value
 * turned into a surface error). Besides scrubValue it redacts credential-shaped
 * fragments such as `Bearer <value>`, `session=<value>`, `X-Api-Key: <value>`,
 * or `"access_token":"<value>"`, so no downstream consumer (errors array,
 * _errors.log, access.json, inventory status, finding summaries, reports)
 * ever receives an unscrubbed error string. Idempotent.
 */
export function scrubErrorText(message: string): string {
  return scrubValue(message)
    .replace(CREDENTIAL_ASSIGNMENT_PATTERN, (_match, key: string) => `${key}=[REDACTED]`)
    .replace(CREDENTIAL_SCHEME_PATTERN, (_match, scheme: string) => `${scheme} [REDACTED]`);
}

/**
 * Key-name redaction plus value scrubbing. This is the second layer; the
 * first is the per-surface allowlist in WEBEX_SURFACE_FIELDS, which decides
 * what reaches the bundle at all.
 */
export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (typeof value === "string") return scrubValue(value);
  const object = asObject(value);
  if (!object) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    const sensitive = SECRET_KEY_PATTERN.test(key) && !POLICY_KEY_PATTERN.test(key);
    output[key] = sensitive && entry !== null && entry !== undefined ? "[REDACTED]" : redactSecrets(entry);
  }
  return output;
}

type FieldSpec = true | { readonly [field: string]: FieldSpec };
type SurfaceSpec = { readonly [field: string]: FieldSpec };

const PERSON_FIELDS: SurfaceSpec = { id: true, displayName: true, emails: true, type: true, roles: true, orgId: true, created: true };
const ORGANIZATION_FIELDS: SurfaceSpec = { id: true, displayName: true, created: true };
const SITE_FIELDS: SurfaceSpec = { siteUrl: true, default: true };
const SECURITY_OPTIONS_FIELDS: SurfaceSpec = {
  joinBeforeHost: true,
  audioBeforeHost: true,
  firstAttendeeAsPresenter: true,
  unlistAllMeetings: true,
  requireLoginBeforeAccess: true,
  allowMobileScreenCapture: true,
  requireStrongPassword: true,
  passwordCriteria: {
    mixedCase: true,
    minLength: true,
    minNumeric: true,
    minAlpha: true,
    minSpecial: true,
    disallowDynamicWebText: true,
    disallowList: true,
    disallowValues: true,
  },
};

/**
 * Fields written to core_data per collected surface: exactly what the
 * verdicts and evidence read plus the documented identifiers that make a row
 * citable. Every other property the API returns is dropped before anything is
 * written, so an undocumented or newly added field can never reach the bundle
 * or the zip. `password` and `secret` stay listed so their presence is
 * recorded as [REDACTED] by redactSecrets; URL-valued fields keep host and
 * path only. A surface without an entry here cannot be stored (compile error).
 */
export const WEBEX_SURFACE_FIELDS = {
  me: PERSON_FIELDS,
  organizations: ORGANIZATION_FIELDS,
  organization: ORGANIZATION_FIELDS,
  people: PERSON_FIELDS,
  roles: { id: true, name: true },
  guest_count: { count: true },
  licenses: { id: true, name: true, totalUnits: true, consumedUnits: true, subscriptionId: true, siteUrl: true, siteType: true },
  events: { id: true, resource: true, type: true, actorId: true, actorOrgId: true, orgId: true, created: true },
  admin_audit_events: {
    id: true,
    actorId: true,
    actorOrgId: true,
    targetOrgId: true,
    created: true,
    data: { eventCategory: true, eventDescription: true, actionText: true, actorEmail: true, actorName: true, adminRoles: true, targetType: true, targetName: true },
  },
  admin_recordings: {
    id: true,
    meetingId: true,
    topic: true,
    createTime: true,
    timeRecorded: true,
    hostEmail: true,
    siteUrl: true,
    downloadUrl: true,
    playbackUrl: true,
    format: true,
    serviceType: true,
    durationSeconds: true,
    sizeBytes: true,
    status: true,
  },
  rooms: { id: true, title: true, type: true, isLocked: true, isPublic: true, classificationId: true, teamId: true, ownerId: true, created: true, lastActivity: true },
  webhooks: { id: true, name: true, targetUrl: true, resource: true, event: true, secret: true, status: true, ownedBy: true, created: true },
  meeting_preferences: {
    personalMeetingRoom: { enabledAutoLock: true, autoLockMinutes: true, notifyHost: true, supportCoHost: true, supportAnyoneAsCoHost: true, allowFirstUserToBeCoHost: true, allowAuthenticatedDevices: true },
    audio: { defaultAudioType: true, enabledGlobalCallIn: true, enabledTollFree: true, enabledAutoConnection: true },
    schedulingOptions: { enabledJoinBeforeHost: true, joinBeforeHostMinutes: true, enabledAutoShareRecording: true, enabledWebexAssistantByDefault: true },
    sites: SITE_FIELDS,
  },
  meeting_sites: SITE_FIELDS,
  meeting_common_settings: { siteUrl: true, securityOptions: SECURITY_OPTIONS_FIELDS },
  meetings: {
    id: true,
    title: true,
    meetingType: true,
    state: true,
    start: true,
    end: true,
    hostEmail: true,
    siteUrl: true,
    webLink: true,
    password: true,
    unlockedMeetingJoinSecurity: true,
    enabledJoinBeforeHost: true,
    joinBeforeHostMinutes: true,
    enableAutomaticLock: true,
    automaticLockMinutes: true,
    publicMeeting: true,
  },
  hybrid_clusters: { id: true, name: true, orgId: true, resourceGroupId: true },
  hybrid_connectors: { id: true, orgId: true, hybridClusterId: true, hostname: true, type: true, version: true, status: true, created: true },
  devices: { id: true, displayName: true, workspaceId: true, personId: true, orgId: true, product: true, type: true, software: true, upgradeChannel: true, connectionStatus: true, managedBy: true, created: true },
  workspaces: { id: true, displayName: true, type: true, orgId: true, created: true },
} as const satisfies Record<string, SurfaceSpec>;

export type WebexSurfaceName = keyof typeof WEBEX_SURFACE_FIELDS;

function projectValue(value: unknown, spec: FieldSpec): unknown {
  if (spec === true) {
    if (Array.isArray(value)) return value.filter((entry) => entry === null || typeof entry !== "object");
    return value !== null && typeof value === "object" ? undefined : value;
  }
  if (Array.isArray(value)) return value.map((entry) => projectValue(entry, spec)).filter((entry) => entry !== undefined);
  const object = asObject(value);
  if (!object) return undefined;
  const output: JsonRecord = {};
  for (const [field, fieldSpec] of Object.entries(spec)) {
    if (!(field in object)) continue;
    const projected = projectValue(object[field], fieldSpec);
    if (projected !== undefined) output[field] = projected;
  }
  return output;
}

/** Projects a collected surface to its allowlisted fields, then redacts and scrubs the values. */
export function projectSurface(name: WebexSurfaceName, data: unknown): unknown {
  return redactSecrets(projectValue(data, WEBEX_SURFACE_FIELDS[name]));
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "webex";
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

/** Webex list payloads wrap results in `items`; the meeting sites list uses `sites`. */
function extractItems(payload: unknown): JsonRecord[] {
  const object = asObject(payload);
  if (!object) return [];
  const list = Array.isArray(object.items) ? object.items : Array.isArray(object.sites) ? object.sites : [];
  return list.map(asObject).filter((item): item is JsonRecord => Boolean(item));
}

function webexErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const messages = [
    ...asArray(object.errors).map((item) => asString(asObject(item)?.description) ?? asString(asObject(item)?.message)),
    asString(object.message),
    asString(object.error_description),
    asString(object.error),
  ].filter((item): item is string => Boolean(item));
  return messages.length > 0 ? messages.join("; ") : undefined;
}

/** A response body parsed as a JSON object; {} for an empty or non-object JSON body, undefined when the body is not JSON at all. */
function parseJsonObject(rawText: string): JsonRecord | undefined {
  if (rawText.length === 0) return {};
  try {
    return asObject(JSON.parse(rawText)) ?? {};
  } catch {
    return undefined;
  }
}

/**
 * What an error response contributes to its error string: the documented
 * message fields of a JSON body (scrubbed with the rest of the string by the
 * WebexApiError constructor), never a raw body. A non-JSON body, such as an
 * HTML gateway page, is described only by content type and length so that
 * nothing it carries can reach the bundle.
 */
function describeErrorBody(payload: JsonRecord | undefined, rawText: string, contentType: string | null): string | undefined {
  if (rawText.length === 0) return undefined;
  const bytes = Buffer.byteLength(rawText, "utf8");
  if (payload === undefined) return `non-JSON error body (${contentType ?? "unknown content type"}; ${bytes} bytes)`;
  return webexErrorSummary(payload) ?? `JSON error body without a message field (${bytes} bytes)`;
}

function loadConfigFile(pathname: string): JsonRecord {
  const raw = readFileSync(pathname, "utf8");
  const parsed = pathname.endsWith(".json") ? JSON.parse(raw) : parseYaml(raw);
  const object = asObject(parsed);
  if (!object) throw new Error(`Webex config file ${pathname} must contain an object.`);
  return object;
}

function discoverConfigFile(env: NodeJS.ProcessEnv, homeDir: string, explicitPath?: string): string | undefined {
  const candidates = explicitPath
    ? [explicitPath]
    : asString(env.WEBEX_CONFIG_FILE)
      ? [asString(env.WEBEX_CONFIG_FILE) as string]
      : CONFIG_FILE_NAMES.map((name) => join(homeDir, DEFAULT_CONFIG_DIR, name));
  return candidates.find((candidate) => existsSync(candidate));
}

/**
 * Precedence: explicit arguments, then environment variables, then the config
 * file at ~/.config/webex-sec-inspector/config.{json,yaml,yml}. The spec names
 * config.toml; JSON or YAML is accepted instead to avoid a TOML dependency.
 */
export function resolveWebexConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDir?: string } = {},
): WebexResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = discoverConfigFile(env, options.homeDir ?? homedir(), asString(input.config_file));
  const fileValues = configFile ? loadConfigFile(configFile) : {};
  if (configFile) sourceChain.push(`config-file:${basename(configFile)}`);

  const pick = (argKey: string, envKey: string, fileKey: string, label: string): string | undefined => {
    const argValue = asString(input[argKey]);
    if (argValue) {
      sourceChain.push(`arguments-${label}`);
      return argValue;
    }
    const envValue = asString(env[envKey]);
    if (envValue) {
      sourceChain.push(`environment-${label}`);
      return envValue;
    }
    const fileValue = asString(fileValues[fileKey]);
    if (fileValue) sourceChain.push(`file-${label}`);
    return fileValue;
  };

  const token = pick("token", "WEBEX_TOKEN", "token", "token");
  const clientId = pick("client_id", "WEBEX_CLIENT_ID", "client_id", "client-id");
  const clientSecret = pick("client_secret", "WEBEX_CLIENT_SECRET", "client_secret", "client-secret");
  const refreshToken = pick("refresh_token", "WEBEX_REFRESH_TOKEN", "refresh_token", "refresh-token");
  const orgId = pick("org_id", "WEBEX_ORG_ID", "org_id", "org");
  const baseUrl = pick("base_url", "WEBEX_API_BASE_URL", "base_url", "base-url") ?? "https://webexapis.com/v1";
  const timeoutSeconds = asNumber(input.timeout_seconds) ?? asNumber(env.WEBEX_TIMEOUT) ?? asNumber(fileValues.timeout_seconds);

  const refresh = clientId && clientSecret && refreshToken ? { clientId, clientSecret, refreshToken } : undefined;
  if (!token && !refresh) {
    throw new Error(
      "WEBEX_TOKEN (or a token argument) or the WEBEX_CLIENT_ID, WEBEX_CLIENT_SECRET, and WEBEX_REFRESH_TOKEN trio is required.",
    );
  }

  return {
    token,
    refresh,
    orgId,
    baseUrl: normalizeBaseUrl(baseUrl),
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    sourceChain: [...new Set(sourceChain)],
    configFile,
  };
}

export class WebexApiClient {
  private readonly config: WebexResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxPages: number;
  private accessToken?: string;

  constructor(
    config: WebexResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
      sleep?: (ms: number) => Promise<void>;
      maxPages?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
    this.maxPages = clampNumber(options.maxPages, MAX_LIST_PAGES, 1, 100_000);
    this.accessToken = config.token;
  }

  getResolvedConfig(): WebexResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  getOrgQuery(): JsonRecord {
    return this.config.orgId ? { orgId: this.config.orgId } : {};
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
   * Integration and Service App refresh grant: POST /access_token with
   * grant_type=refresh_token (integrations guide, service-apps guide).
   */
  async refreshAccessToken(): Promise<string> {
    const refresh = this.config.refresh;
    if (!refresh) throw new Error("No Webex refresh credentials configured.");
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: refresh.clientId,
      client_secret: refresh.clientSecret,
      refresh_token: refresh.refreshToken,
    });
    const response = await this.fetchImpl(this.buildUrl("/access_token"), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
    });
    const rawText = await response.text();
    const payload = parseJsonObject(rawText);
    if (!response.ok) {
      const detail = describeErrorBody(payload, rawText, response.headers.get("content-type"));
      throw new WebexApiError(`Webex token refresh failed (${response.status})${detail ? `: ${detail}` : ""}`, response.status, "/access_token");
    }
    if (payload === undefined) {
      throw new WebexApiError(
        `Webex token refresh returned ${describeErrorBody(undefined, rawText, response.headers.get("content-type"))} with status ${response.status}`,
        response.status,
        "/access_token",
      );
    }
    const accessToken = asString(payload.access_token);
    if (!accessToken) throw new Error("Webex token refresh response did not include access_token.");
    this.accessToken = accessToken;
    return accessToken;
  }

  private async currentToken(): Promise<string> {
    if (this.accessToken) return this.accessToken;
    return this.refreshAccessToken();
  }

  private async fetchJson(url: string, attempt = 0): Promise<{ payload: JsonRecord; rawText: string; nextUrl: string | null }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    const endpoint = new URL(url).pathname;

    try {
      const response = await this.fetchImpl(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${await this.currentToken()}`,
        },
        signal: controller.signal,
      });

      if (response.status === 429 && attempt < MAX_429_RETRIES) {
        const retryAfterSeconds = asNumber(response.headers.get("retry-after")) ?? 1;
        await this.sleep(Math.min(Math.max(retryAfterSeconds, 1) * 1000, MAX_RETRY_AFTER_MS));
        return this.fetchJson(url, attempt + 1);
      }

      const rawText = await response.text();
      const payload = parseJsonObject(rawText);

      if (!response.ok) {
        const detail = describeErrorBody(payload, rawText, response.headers.get("content-type"));
        throw new WebexApiError(
          `Webex request failed (${response.status} ${response.statusText}) for ${endpoint}${detail ? `: ${detail}` : ""}`,
          response.status,
          endpoint,
        );
      }

      return {
        payload: payload ?? {},
        rawText,
        nextUrl: parseLinkHeaderNext(response.headers.get("link")),
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const { payload } = await this.fetchJson(this.buildUrl(path, query));
    return payload;
  }

  /**
   * Follows rel="next" until absent, the item limit is reached, or the page
   * ceiling is hit (a server that keeps emitting rel="next" on empty pages
   * would otherwise never stop); every early exit reports truncated: true.
   * `max` is sent only when the caller passes pageMax, which happens only for
   * endpoints whose reference documents that parameter.
   */
  async list(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageMax?: number } = {},
  ): Promise<WebexPage> {
    const limit = clampNumber(options.limit, DEFAULT_GENERIC_LIMIT, 1, 50_000);
    const pageQuery: JsonRecord = options.pageMax === undefined ? {} : { max: clampNumber(options.pageMax, 100, 1, 1000) };
    const items: JsonRecord[] = [];
    let pageCount = 0;
    let nextUrl: string | null = this.buildUrl(path, { ...pageQuery, ...query });

    while (nextUrl) {
      const response = await this.fetchJson(nextUrl);
      pageCount += 1;
      const pageItems = extractItems(response.payload);
      const remaining = limit - items.length;
      items.push(...pageItems.slice(0, remaining));
      nextUrl = response.nextUrl;
      if (items.length >= limit && (nextUrl || pageItems.length > remaining)) {
        return { items, truncated: true, pageCount };
      }
      if (nextUrl && pageCount >= this.maxPages) {
        return { items, truncated: true, pageCount };
      }
    }

    return { items, truncated: false, pageCount };
  }

  async getMe(): Promise<JsonRecord> {
    return this.get("/people/me");
  }

  async listOrganizations(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/organizations", {}, { limit });
  }

  async getOrganization(orgId: string): Promise<JsonRecord> {
    return this.get(`/organizations/${encodeURIComponent(orgId)}`);
  }

  async listPeople(limit = DEFAULT_PEOPLE_LIMIT): Promise<WebexPage> {
    return this.list("/people", this.getOrgQuery(), { limit, pageMax: PAGE_MAX.people });
  }

  async listRoles(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/roles", {}, { limit });
  }

  async listLicenses(limit = DEFAULT_LICENSE_LIMIT): Promise<WebexPage> {
    return this.list("/licenses", this.getOrgQuery(), { limit });
  }

  /**
   * GET /guests/count (guest-management reference, scope guest-issuer:read)
   * answers with a bare number in a text/plain body.
   */
  async getGuestCount(): Promise<JsonRecord> {
    const { payload, rawText } = await this.fetchJson(this.buildUrl("/guests/count"));
    const fromObject = Object.values(payload).map(asNumber).find((value) => value !== undefined);
    const count = fromObject ?? asNumber(rawText.trim());
    return { count: count ?? null };
  }

  async listEvents(limit = DEFAULT_EVENT_LIMIT): Promise<WebexPage> {
    return this.list("/events", {}, { limit, pageMax: PAGE_MAX.events });
  }

  /** Admin audit events require orgId, from, and to (admin-audit-events reference). */
  async listAdminAuditEvents(orgId: string, limit = DEFAULT_EVENT_LIMIT, windowDays = ADMIN_AUDIT_WINDOW_DAYS): Promise<WebexPage> {
    const to = this.now();
    const from = new Date(to.getTime() - windowDays * 24 * 60 * 60 * 1000);
    return this.list(
      "/adminAudit/events",
      { orgId, from: from.toISOString(), to: to.toISOString() },
      { limit, pageMax: PAGE_MAX.adminAudit },
    );
  }

  async listAdminRecordings(limit = DEFAULT_RECORDING_LIMIT): Promise<WebexPage> {
    return this.list("/admin/recordings", {}, { limit, pageMax: PAGE_MAX.adminRecordings });
  }

  async listMeetings(limit = DEFAULT_MEETING_LIMIT): Promise<WebexPage> {
    return this.list("/meetings", {}, { limit, pageMax: PAGE_MAX.meetings });
  }

  async getMeetingPreferences(): Promise<JsonRecord> {
    return this.get("/meetingPreferences");
  }

  async listMeetingSites(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/meetingPreferences/sites", {}, { limit });
  }

  /**
   * Site administrator common settings (site reference, scope
   * meeting:admin_config_read). siteUrl selects the site; without it the API
   * answers for the administrator's preferred site.
   */
  async getMeetingCommonSettings(siteUrl?: string): Promise<JsonRecord> {
    return this.get("/admin/meeting/config/commonSettings", siteUrl ? { siteUrl } : {});
  }

  async listHybridClusters(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/hybrid/clusters", this.getOrgQuery(), { limit });
  }

  async listHybridConnectors(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/hybrid/connectors", this.getOrgQuery(), { limit });
  }

  async listDevices(limit = DEFAULT_DEVICE_LIMIT): Promise<WebexPage> {
    return this.list("/devices", this.getOrgQuery(), { limit, pageMax: PAGE_MAX.devices });
  }

  async listWorkspaces(limit = DEFAULT_GENERIC_LIMIT): Promise<WebexPage> {
    return this.list("/workspaces", this.getOrgQuery(), { limit, pageMax: PAGE_MAX.workspaces });
  }

  async listRooms(limit = DEFAULT_ROOM_LIMIT): Promise<WebexPage> {
    return this.list("/rooms", {}, { limit, pageMax: PAGE_MAX.rooms });
  }

  async listWebhooks(limit = DEFAULT_WEBHOOK_LIMIT): Promise<WebexPage> {
    return this.list("/webhooks", {}, { limit, pageMax: PAGE_MAX.webhooks });
  }
}

type WebexClientLike = Pick<
  WebexApiClient,
  | "getResolvedConfig"
  | "getMe"
  | "listOrganizations"
  | "getOrganization"
  | "listPeople"
  | "listRoles"
  | "listLicenses"
  | "getGuestCount"
  | "listEvents"
  | "listAdminAuditEvents"
  | "listAdminRecordings"
  | "listMeetings"
  | "getMeetingPreferences"
  | "listMeetingSites"
  | "getMeetingCommonSettings"
  | "listHybridClusters"
  | "listHybridConnectors"
  | "listDevices"
  | "listWorkspaces"
  | "listRooms"
  | "listWebhooks"
>;

function errorStatus(error: unknown): number | undefined {
  if (error instanceof WebexApiError) return error.status;
  const status = asNumber(asObject(error)?.status);
  return status;
}

/** Every thrown value becomes a surface error string here, so this is the second and last point where scrubErrorText must run. */
function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

async function collectPage(load: () => Promise<WebexPage>): Promise<SurfaceResult<JsonRecord[]>> {
  try {
    const page = await load();
    return { ok: true, data: page.items, truncated: page.truncated };
  } catch (error) {
    return { ok: false, error: errorMessage(error), status: errorStatus(error) };
  }
}

async function collectObject(load: () => Promise<JsonRecord>): Promise<SurfaceResult<JsonRecord>> {
  try {
    return { ok: true, data: await load(), truncated: false };
  } catch (error) {
    return { ok: false, error: errorMessage(error), status: errorStatus(error) };
  }
}

function surfaceItems(result: SurfaceResult<JsonRecord[]>): JsonRecord[] {
  return result.ok ? result.data : [];
}

/** Collected surfaces keyed by name; only names with a WEBEX_SURFACE_FIELDS allowlist are storable. */
type SurfaceSet = Partial<Record<WebexSurfaceName, SurfaceResult<unknown>>>;

function surfaceEntries(entries: SurfaceSet): Array<[WebexSurfaceName, SurfaceResult<unknown>]> {
  return (Object.entries(entries) as Array<[WebexSurfaceName, SurfaceResult<unknown> | undefined]>)
    .flatMap(([name, result]) => (result ? [[name, result] as [WebexSurfaceName, SurfaceResult<unknown>]] : []));
}

function surfaceErrors(entries: SurfaceSet): string[] {
  return surfaceEntries(entries)
    .flatMap(([name, result]) => (result.ok ? [] : [`${name}: ${result.error}`]));
}

/** core_data content: each surface projected to its allowlist, never the raw response. */
function surfaceRaw(entries: SurfaceSet): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [name, result] of surfaceEntries(entries)) {
    output[name] = result.ok ? projectSurface(name, result.data) : { error: scrubValue(result.error), status: result.status ?? null };
  }
  return output;
}

function deriveOrgContext(
  config: WebexResolvedConfig,
  orgs: SurfaceResult<JsonRecord[]>,
): { orgId?: string; note: string } {
  if (config.orgId) {
    return { orgId: config.orgId, note: `Using configured Webex org ${config.orgId}.` };
  }
  if (!orgs.ok) {
    return { orgId: undefined, note: `GET /organizations was not readable (${orgs.error}); set WEBEX_ORG_ID to run org-scoped checks.` };
  }
  const soleId = asString(orgs.data[0]?.id);
  if (orgs.data.length === 1 && soleId) {
    return { orgId: soleId, note: `Using the only visible Webex org ${soleId}.` };
  }
  if (orgs.data.length === 0) {
    return { orgId: undefined, note: "No Webex organizations were visible; org-scoped checks stay manual until WEBEX_ORG_ID is set." };
  }
  return {
    orgId: undefined,
    note: "Multiple Webex organizations were visible with no org_id selected; org-scoped checks stay manual until WEBEX_ORG_ID is set.",
  };
}

function finding(
  id: string,
  control: number[],
  title: string,
  severity: WebexFinding["severity"],
  status: WebexFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): WebexFinding {
  const merged: WebexFrameworkMap = frameworks("", "", "", "", "", "", "", "");
  for (const number of control) {
    const map = WEBEX_CONTROL_FRAMEWORKS[number];
    if (!map) continue;
    for (const key of Object.keys(merged) as WebexFrameworkKey[]) {
      merged[key] = [...new Set([...merged[key], ...map[key]])];
    }
  }
  const mappings = (Object.keys(merged) as WebexFrameworkKey[])
    .flatMap((key) => merged[key].map((value) => `${WEBEX_FRAMEWORK_LABELS[key]} ${value}`));
  return { id, control, title, severity, status, summary, evidence, mappings, frameworks: merged };
}

function deniedSummary(surface: string, endpoint: string, result: { error: string; status?: number }, requirement: string): string {
  const cause = /bot token/i.test(result.error)
    ? `${endpoint} was not queried because a bot token cannot read admin surfaces (${surface})`
    : result.status === 401 || result.status === 403
      ? `${endpoint} returned ${result.status}; the token lacks the scope or admin role for ${surface}`
      : `${endpoint} could not be read (${result.error})`;
  return `Manual: ${cause}. Collect ${requirement}.`;
}

function partialNote(result: SurfaceResult<JsonRecord[]>, label: string): string {
  return result.ok && result.truncated
    ? ` The ${label} listing was truncated at ${result.data.length} items (more pages remained), so the population is partial.`
    : "";
}

/** Readability of a collected inventory, rendered beside every count or list derived from it. */
function inventoryStatus(result: SurfaceResult<unknown>): JsonRecord {
  return result.ok
    ? { readable: true, truncated: result.truncated }
    : { readable: false, status: result.status ?? null, error: scrubValue(result.error) };
}

/** A count derived from one or more inventories is null, never a fabricated 0, when any of them was unreadable. */
function countIfReadable(value: number, ...inventories: SurfaceResult<unknown>[]): number | null {
  return inventories.every((result) => result.ok) ? value : null;
}

/**
 * An inventory a finding depends on besides the one its verdict is computed from. Rule 1
 * corollary: when it is unreadable the finding cannot pass, the summary names the endpoint,
 * and anything derived from it is rendered as null plus status.
 */
interface SecondaryInventory {
  endpoint: string;
  scope: string;
  result: SurfaceResult<unknown>;
  consequence: string;
}

function unreadableDetail(item: SecondaryInventory): string {
  if (item.result.ok) return "";
  return item.result.status ? `${item.result.status}; scope ${item.scope}` : item.result.error;
}

function unreadableNote(secondaries: SecondaryInventory[]): string {
  return secondaries
    .filter((item) => !item.result.ok)
    .map((item) => ` ${item.endpoint} was not readable (${unreadableDetail(item)}), so ${item.consequence}.`)
    .join("");
}

function capForUnreadable(status: WebexFindingStatus, secondaries: SecondaryInventory[]): { status: WebexFindingStatus; note: string } {
  const note = unreadableNote(secondaries);
  return { status: status === "pass" && note.length > 0 ? "warn" : status, note };
}

/**
 * The token-type probe as a secondary inventory: when GET /people/me was unreadable or carried
 * no type, a bot token's partial view cannot be excluded, so findings that gate their bot-token
 * warn path on the token type cannot pass.
 */
function tokenProbeInventory(me: SurfaceResult<JsonRecord>, tokenType: WebexTokenType): SecondaryInventory {
  const result: SurfaceResult<unknown> = tokenType === "unknown" && me.ok ? { ok: false, error: "the response carried no Person.type" } : me;
  return {
    endpoint: "GET /people/me",
    scope: "spark:people_read",
    result,
    consequence: "the token type could not be verified and a bot token's partial view cannot be excluded",
  };
}

type SiteJudgement = { status: WebexFindingStatus; detail: string; values: JsonRecord };

interface SiteSettingsCoverage {
  readable: Array<{ siteUrl: string; settings: JsonRecord }>;
  denied: Array<{ site_url: string; error: string; status: number | null }>;
  /** True only when the site list was read completely and every listed site answered. */
  complete: boolean;
  coverageNote: string;
  /** Readability of GET /meetingPreferences/sites, the reason coverage can stay incomplete when every site answered. */
  siteListStatus: JsonRecord;
}

function worstStatus(statuses: WebexFindingStatus[]): WebexFindingStatus {
  return statuses.reduce<WebexFindingStatus>((worst, status) => (statusRank(status) < statusRank(worst) ? status : worst), "pass");
}

/**
 * Reads GET /admin/meeting/config/commonSettings once per Webex site. The site
 * list comes from GET /meetingPreferences/sites, falling back to the sites array
 * of GET /meetingPreferences; when neither names a site, the API is asked once
 * for the administrator's preferred site and coverage is marked incomplete.
 */
async function collectSiteSettings(
  client: WebexClientLike,
  tokenType: WebexTokenType,
  meetingSites: SurfaceResult<JsonRecord[]>,
  meetingPreferences: SurfaceResult<JsonRecord>,
): Promise<SiteSettingsCoverage & { raw: SurfaceResult<JsonRecord[]> }> {
  const listedSites = meetingSites.ok ? meetingSites.data : asArray(meetingPreferences.ok ? meetingPreferences.data.sites : []).map(asObject);
  const siteUrls = [...new Set(listedSites.map((site) => asString(site?.siteUrl)).filter((site): site is string => Boolean(site)))];

  const siteListStatus = inventoryStatus(meetingSites);

  if (tokenType === "bot") {
    const error = "bot token cannot read admin surfaces";
    return { readable: [], denied: [{ site_url: "*", error, status: 403 }], complete: false, coverageNote: "", siteListStatus, raw: { ok: false, error, status: 403 } };
  }

  const targets = siteUrls.length > 0 ? siteUrls : [undefined];
  const results = await Promise.all(targets.map(async (siteUrl) => ({ siteUrl, result: await collectObject(() => client.getMeetingCommonSettings(siteUrl)) })));
  const readable = results.flatMap(({ siteUrl, result }) => (result.ok ? [{ siteUrl: siteUrl ?? "(preferred site)", settings: result.data }] : []));
  const denied = results.flatMap(({ siteUrl, result }) => (result.ok ? [] : [{ site_url: siteUrl ?? "(preferred site)", error: result.error, status: result.status ?? null }]));

  const notes: string[] = [];
  if (!meetingSites.ok) {
    notes.push(siteUrls.length > 0
      ? ` The site list (GET /meetingPreferences/sites) was not readable (${meetingSites.error}), so the ${siteUrls.length} sites came from the sites array of GET /meetingPreferences and site coverage cannot be confirmed complete.`
      : ` The site list (GET /meetingPreferences/sites) was not readable (${meetingSites.error}), so only the administrator's preferred site was evaluated.`);
  } else if (siteUrls.length === 0) {
    notes.push(" The site list (GET /meetingPreferences/sites) was empty, so only the administrator's preferred site was evaluated.");
  } else if (meetingSites.truncated) {
    notes.push(` The site list was truncated at ${siteUrls.length} sites (more pages remained), so the population is partial.`);
  }
  if (denied.length > 0 && readable.length > 0) {
    notes.push(` ${denied.length} of ${results.length} sites could not be read (${denied.map((item) => `${item.site_url}: ${item.error}`).join("; ")}), so the org-wide view is partial.`);
  }
  const complete = siteUrls.length > 0 && meetingSites.ok && !meetingSites.truncated && denied.length === 0;
  const raw: SurfaceResult<JsonRecord[]> = readable.length > 0
    ? { ok: true, data: readable.map((site) => ({ siteUrl: site.siteUrl, ...site.settings })), truncated: !complete }
    : { ok: false, error: denied[0]?.error ?? "no Webex site answered", status: denied[0]?.status ?? undefined };
  return { readable, denied, complete, coverageNote: notes.join(""), siteListStatus, raw };
}

/** Per-site commonSettings failures for the assessment errors array, which surfaceErrors misses whenever any site answered. */
function siteSettingsErrors(coverage: SiteSettingsCoverage): string[] {
  return coverage.denied.map((site) => `meeting_common_settings[${site.site_url}]: ${site.error}`);
}

function judgeSites(
  coverage: SiteSettingsCoverage,
  judge: (securityOptions: JsonRecord | undefined) => SiteJudgement,
): { status: WebexFindingStatus; text: string; evidence: JsonRecord } {
  const judgements = coverage.readable.map((site) => ({ site_url: site.siteUrl, ...judge(asObject(site.settings.securityOptions)) }));
  const worst = worstStatus(judgements.map((item) => item.status));
  const status: WebexFindingStatus = worst === "pass" && !coverage.complete ? "warn" : worst;
  const text = `${judgements.map((item) => `${item.site_url}: ${item.detail}`).join("; ")} (GET /admin/meeting/config/commonSettings, ${judgements.length} of ${judgements.length + coverage.denied.length} sites).${coverage.coverageNote}`;
  return {
    status,
    text,
    evidence: {
      sites: judgements.map((item) => ({ site_url: item.site_url, status: item.status, detail: item.detail, ...item.values })),
      denied_sites: coverage.denied,
      site_coverage_complete: coverage.complete,
      site_list_status: coverage.siteListStatus,
      citation: WEBEX_DOCS.meetingCommonSettings,
    },
  };
}

/** Control 9: attendees held until the host joins and meetings unlisted (securityOptions, site reference). */
function judgeLobbyDefaults(securityOptions: JsonRecord | undefined): SiteJudgement {
  const joinBeforeHost = asBoolean(securityOptions?.joinBeforeHost);
  const audioBeforeHost = asBoolean(securityOptions?.audioBeforeHost);
  const unlistAllMeetings = asBoolean(securityOptions?.unlistAllMeetings);
  const values = { join_before_host: joinBeforeHost ?? null, audio_before_host: audioBeforeHost ?? null, unlist_all_meetings: unlistAllMeetings ?? null };
  if (joinBeforeHost === undefined) {
    return { status: "manual", detail: "securityOptions.joinBeforeHost was absent from the response", values };
  }
  if (joinBeforeHost || audioBeforeHost) {
    return { status: "fail", detail: `attendees may join before the host (joinBeforeHost = ${joinBeforeHost}, audioBeforeHost = ${audioBeforeHost ?? "unreported"})`, values };
  }
  if (audioBeforeHost === undefined || unlistAllMeetings !== true) {
    return { status: "warn", detail: `joinBeforeHost = false but audioBeforeHost = ${audioBeforeHost ?? "unreported"} and unlistAllMeetings = ${unlistAllMeetings ?? "unreported"}`, values };
  }
  return { status: "pass", detail: "joinBeforeHost = false, audioBeforeHost = false, unlistAllMeetings = true", values };
}

/** Control 10: strict meeting passwords with a documented minimum length (securityOptions.passwordCriteria). */
function judgePasswordPolicy(securityOptions: JsonRecord | undefined): SiteJudgement {
  const requireStrongPassword = asBoolean(securityOptions?.requireStrongPassword);
  const criteria = asObject(securityOptions?.passwordCriteria);
  const minLength = asNumber(criteria?.minLength);
  const values = {
    require_strong_password: requireStrongPassword ?? null,
    min_length: minLength ?? null,
    mixed_case: asBoolean(criteria?.mixedCase) ?? null,
    min_numeric: asNumber(criteria?.minNumeric) ?? null,
    min_alpha: asNumber(criteria?.minAlpha) ?? null,
    min_special: asNumber(criteria?.minSpecial) ?? null,
    disallow_dynamic_web_text: asBoolean(criteria?.disallowDynamicWebText) ?? null,
    disallow_list: asBoolean(criteria?.disallowList) ?? null,
  };
  if (requireStrongPassword === undefined) {
    return { status: "manual", detail: "securityOptions.requireStrongPassword was absent from the response", values };
  }
  if (!requireStrongPassword) {
    return { status: "fail", detail: "requireStrongPassword = false", values };
  }
  if (minLength === undefined || minLength < MIN_MEETING_PASSWORD_LENGTH) {
    return { status: "warn", detail: `requireStrongPassword = true but passwordCriteria.minLength = ${minLength ?? "unreported"} (threshold ${MIN_MEETING_PASSWORD_LENGTH})`, values };
  }
  return { status: "pass", detail: `requireStrongPassword = true with passwordCriteria.minLength = ${minLength}`, values };
}

/** Control 13: site access requires login (securityOptions.requireLoginBeforeAccess). */
function judgeGuestAccess(securityOptions: JsonRecord | undefined): SiteJudgement {
  const requireLoginBeforeAccess = asBoolean(securityOptions?.requireLoginBeforeAccess);
  const values = { require_login_before_access: requireLoginBeforeAccess ?? null };
  if (requireLoginBeforeAccess === undefined) {
    return { status: "manual", detail: "securityOptions.requireLoginBeforeAccess was absent from the response", values };
  }
  if (!requireLoginBeforeAccess) {
    return { status: "fail", detail: "requireLoginBeforeAccess = false (unauthenticated guests can reach the site)", values };
  }
  return { status: "pass", detail: "requireLoginBeforeAccess = true", values };
}

function siteFinding(
  id: string,
  control: number[],
  title: string,
  severity: WebexFinding["severity"],
  coverage: SiteSettingsCoverage,
  judge: (securityOptions: JsonRecord | undefined) => SiteJudgement,
  tokenType: WebexTokenType,
  manualEvidence: string,
  secondaries: SecondaryInventory[],
  extraEvidence: JsonRecord = {},
): WebexFinding {
  if (coverage.readable.length === 0) {
    const denied = coverage.denied[0] ?? { site_url: "*", error: "no Webex site answered", status: null };
    return finding(id, control, title, severity, "manual",
      `${deniedSummary("meeting common settings", "/admin/meeting/config/commonSettings", { error: denied.error, status: denied.status ?? undefined }, manualEvidence)}${coverage.coverageNote}${unreadableNote(secondaries)}`,
      { denied_sites: coverage.denied, site_list_status: coverage.siteListStatus, citation: WEBEX_DOCS.meetingCommonSettings, token_type: tokenType, ...extraEvidence });
  }
  const judged = judgeSites(coverage, judge);
  const capped = capForUnreadable(judged.status, secondaries);
  const summary = judged.status === "manual"
    ? `Manual: ${judged.text} Collect ${manualEvidence}.${capped.note}`
    : `${judged.text}${capped.note}`;
  return finding(id, control, title, severity, capped.status, summary, { ...judged.evidence, token_type: tokenType, ...extraEvidence });
}

/** Person.type is documented as person, bot, or appuser (people reference, bots guide). */
export function detectTokenType(me: JsonRecord | undefined): WebexTokenType {
  const type = asString(me?.type);
  switch (type) {
    case "person":
      return "person";
    case "bot":
      return "bot";
    case "appuser":
      return "appuser";
    case undefined:
      return "unknown";
    default:
      return "unknown";
  }
}

function personRoleIds(person: JsonRecord): string[] {
  return asArray(person.roles).map((item) => asString(item)).filter((item): item is string => Boolean(item));
}

function roleMapFromRoles(roles: JsonRecord[]): Map<string, string> {
  return new Map(
    roles
      .map((role) => {
        const id = asString(role.id);
        const name = asString(role.name);
        return id && name ? [id, name] as const : undefined;
      })
      .filter((item): item is readonly [string, string] => Boolean(item)),
  );
}

function personRoleNames(person: JsonRecord, roleMap: Map<string, string>): string[] {
  return personRoleIds(person).map((id) => roleMap.get(id) ?? id);
}

function personLabel(person: JsonRecord): string {
  return asString(person.displayName) ?? asString(asArray(person.emails)[0]) ?? asString(person.id) ?? "person";
}

function statusRank(status: WebexFindingStatus): number {
  switch (status) {
    case "fail":
      return 0;
    case "warn":
      return 1;
    case "manual":
      return 2;
    case "pass":
      return 3;
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

function countStatuses(findings: WebexFinding[]): Record<WebexFindingStatus, number> {
  const counts: Record<WebexFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

export async function checkWebexAccess(client: WebexClientLike): Promise<WebexAccessCheckResult> {
  const config = client.getResolvedConfig();
  const me = await collectObject(() => client.getMe());
  const orgs = await collectPage(() => client.listOrganizations());
  const { orgId, note } = deriveOrgContext(config, orgs);
  const tokenType = detectTokenType(me.ok ? me.data : undefined);

  const pageSurface = async (name: string, endpoint: string, doc: string, load: () => Promise<WebexPage>): Promise<WebexAccessSurface> => {
    const result = await collectPage(load);
    return result.ok
      ? { name, endpoint, doc, status: "readable", count: result.data.length, truncated: result.truncated }
      : { name, endpoint, doc, status: "not_readable", error: result.error };
  };
  const objectSurface = async (name: string, endpoint: string, doc: string, load: () => Promise<JsonRecord>): Promise<WebexAccessSurface> => {
    const result = await collectObject(load);
    return result.ok
      ? { name, endpoint, doc, status: "readable", count: 1 }
      : { name, endpoint, doc, status: "not_readable", error: result.error };
  };

  const surfaces: WebexAccessSurface[] = [
    me.ok
      ? { name: "me", endpoint: "/people/me", doc: WEBEX_DOCS.peopleMe, status: "readable", count: 1 }
      : { name: "me", endpoint: "/people/me", doc: WEBEX_DOCS.peopleMe, status: "not_readable", error: me.error },
    orgs.ok
      ? { name: "organizations", endpoint: "/organizations", doc: WEBEX_DOCS.organizationsList, status: "readable", count: orgs.data.length, truncated: orgs.truncated }
      : { name: "organizations", endpoint: "/organizations", doc: WEBEX_DOCS.organizationsList, status: "not_readable", error: orgs.error },
  ];

  const adminSurfaces: Array<[string, string, string, () => Promise<WebexPage>]> = [
    ["people", "/people", WEBEX_DOCS.peopleList, () => client.listPeople()],
    ["roles", "/roles", WEBEX_DOCS.rolesList, () => client.listRoles()],
    ["licenses", "/licenses", WEBEX_DOCS.licensesList, () => client.listLicenses()],
    ["admin_recordings", "/admin/recordings", WEBEX_DOCS.adminRecordings, () => client.listAdminRecordings()],
    ["events", "/events", WEBEX_DOCS.eventsList, () => client.listEvents()],
    ["hybrid_clusters", "/hybrid/clusters", WEBEX_DOCS.hybridClusters, () => client.listHybridClusters()],
    ["hybrid_connectors", "/hybrid/connectors", WEBEX_DOCS.hybridConnectors, () => client.listHybridConnectors()],
    ["devices", "/devices", WEBEX_DOCS.devicesList, () => client.listDevices()],
    ["workspaces", "/workspaces", WEBEX_DOCS.workspacesList, () => client.listWorkspaces()],
  ];
  const userSurfaces: Array<[string, string, string, () => Promise<WebexPage>]> = [
    ["rooms", "/rooms", WEBEX_DOCS.roomsList, () => client.listRooms()],
    ["webhooks", "/webhooks", WEBEX_DOCS.webhooksList, () => client.listWebhooks()],
    ["meetings", "/meetings", WEBEX_DOCS.meetingsList, () => client.listMeetings()],
  ];

  for (const [name, endpoint, doc, load] of adminSurfaces) {
    if (tokenType === "bot") {
      surfaces.push({ name, endpoint, doc, status: "manual", error: "Bot tokens cannot read admin surfaces; use an admin, integration, or Service App token." });
    } else {
      surfaces.push(await pageSurface(name, endpoint, doc, load));
    }
  }
  if (orgId) {
    surfaces.push(await objectSurface("organization", `/organizations/${orgId}`, WEBEX_DOCS.organizationGet, () => client.getOrganization(orgId)));
    if (tokenType === "bot") {
      surfaces.push({ name: "admin_audit_events", endpoint: "/adminAudit/events", doc: WEBEX_DOCS.adminAuditEvents, status: "manual", error: "Bot tokens cannot read admin audit events." });
    } else {
      surfaces.push(await pageSurface("admin_audit_events", "/adminAudit/events", WEBEX_DOCS.adminAuditEvents, () => client.listAdminAuditEvents(orgId)));
    }
  } else {
    surfaces.push(
      { name: "organization", endpoint: "/organizations/{orgId}", doc: WEBEX_DOCS.organizationGet, status: "not_configured", error: note },
      { name: "admin_audit_events", endpoint: "/adminAudit/events", doc: WEBEX_DOCS.adminAuditEvents, status: "not_configured", error: note },
    );
  }
  for (const [name, endpoint, doc, load] of userSurfaces) {
    surfaces.push(await pageSurface(name, endpoint, doc, load));
  }
  surfaces.push(await objectSurface("meeting_preferences", "/meetingPreferences", WEBEX_DOCS.meetingPreferences, () => client.getMeetingPreferences()));
  const sites = await collectPage(() => client.listMeetingSites());
  surfaces.push(sites.ok
    ? { name: "meeting_sites", endpoint: "/meetingPreferences/sites", doc: WEBEX_DOCS.meetingSites, status: "readable", count: sites.data.length, truncated: sites.truncated }
    : { name: "meeting_sites", endpoint: "/meetingPreferences/sites", doc: WEBEX_DOCS.meetingSites, status: "not_readable", error: sites.error });
  const firstSite = sites.ok ? asString(sites.data[0]?.siteUrl) : undefined;
  const adminObjectSurfaces: Array<[string, string, string, () => Promise<JsonRecord>]> = [
    ["meeting_common_settings", "/admin/meeting/config/commonSettings", WEBEX_DOCS.meetingCommonSettings, () => client.getMeetingCommonSettings(firstSite)],
    ["guest_count", "/guests/count", WEBEX_DOCS.guestCount, () => client.getGuestCount()],
  ];
  for (const [name, endpoint, doc, load] of adminObjectSurfaces) {
    if (tokenType === "bot") {
      surfaces.push({ name, endpoint, doc, status: "manual", error: "Bot tokens cannot read admin surfaces; use an admin, integration, or Service App token." });
    } else {
      surfaces.push(await objectSurface(name, endpoint, doc, load));
    }
  }

  const readable = surfaces.filter((item) => item.status === "readable");
  const adminCapable = tokenType !== "bot"
    && ["people", "roles"].every((name) => readable.some((item) => item.name === name));
  const status = adminCapable && readable.length >= 8 ? "healthy" : "limited";

  return {
    status,
    orgId,
    tokenType,
    adminCapable,
    surfaces,
    notes: [
      me.ok
        ? `Authenticated as ${personLabel(me.data)} (token type: ${tokenType}).`
        : `GET /people/me failed (${me.error}); token type unknown.`,
      note,
      `${readable.length}/${surfaces.length} Webex audit surfaces are readable.`,
      ...(tokenType === "bot" ? ["Bot tokens cannot read admin surfaces; admin-only controls will render as manual."] : []),
      ...(config.refresh ? ["Access token obtained through the refresh_token grant; tokens are redacted from all output."] : []),
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run webex_assess_identity, webex_assess_collaboration_governance, webex_assess_meeting_hybrid_security, or webex_export_audit_bundle."
        : "Provide an admin, integration, or Service App token with spark-admin:people_read, spark-admin:roles_read, spark-admin:licenses_read, spark-admin:organizations_read, spark-admin:devices_read, spark-admin:hybrid_clusters_read, spark-compliance:events_read, spark-compliance:recordings_read, audit:events_read, meeting:admin_config_read, and guest-issuer:read.",
  };
}

export async function assessWebexIdentity(
  client: WebexClientLike,
  options: AssessmentOptions = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const peopleLimit = clampNumber(options.peopleLimit, DEFAULT_PEOPLE_LIMIT, 1, 50_000);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 5000);

  const me = await collectObject(() => client.getMe());
  const tokenType = detectTokenType(me.ok ? me.data : undefined);
  const orgs = await collectPage(() => client.listOrganizations());
  const { orgId, note } = deriveOrgContext(config, orgs);
  const botDenied: SurfaceResult<JsonRecord[]> = { ok: false, error: "bot token cannot read admin surfaces", status: 403 };
  const botDeniedObject: SurfaceResult<JsonRecord> = { ok: false, error: "bot token cannot read admin surfaces", status: 403 };
  const [people, roles, organization, guestCount] = await Promise.all([
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listPeople(peopleLimit)),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listRoles()),
    orgId ? collectObject(() => client.getOrganization(orgId)) : Promise.resolve<SurfaceResult<JsonRecord>>({ ok: false, error: note }),
    tokenType === "bot" ? Promise.resolve(botDeniedObject) : collectObject(() => client.getGuestCount()),
  ]);
  const surfaces: SurfaceSet = { me, organizations: orgs, people, roles, organization, guest_count: guestCount };

  const roleMap = roleMapFromRoles(surfaceItems(roles));
  const humans = surfaceItems(people).filter((person) => !["bot", "appuser"].includes(asString(person.type) ?? ""));
  const bots = surfaceItems(people).filter((person) => asString(person.type) === "bot");
  const guests = surfaceItems(people).filter((person) => asString(person.type) === "appuser");
  const adminUsers = humans.filter((person) => personRoleNames(person, roleMap).some((role) => /administrator/i.test(role)));
  const complianceOfficers = humans.filter((person) => personRoleNames(person, roleMap).some((role) => /compliance officer/i.test(role)));
  const peoplePartial = partialNote(people, "people");
  const orgLabel = organization.ok ? asString(organization.data.displayName) ?? orgId ?? "org" : orgId ?? "org";

  const ssoFinding = finding(
    "WEBEX-ID-01",
    [1],
    "Organization SSO enforcement",
    "critical",
    "manual",
    `Manual: the Organizations API (${WEBEX_DOCS.organizationGet}) documents only id, displayName, and created, so SSO enforcement for ${orgLabel} is not readable. Export the Control Hub Organization Settings > Authentication page showing SSO enabled.`,
    { org_id: orgId ?? null, organization: organization.ok ? projectSurface("organization", organization.data) : { error: organization.error }, citation: WEBEX_DOCS.organizationGet },
  );

  const mfaReadOnlyNote = `mfaEnabled is documented on /identity/organizations/{orgId}/authenticationConfig only in the PATCH request schema (${WEBEX_DOCS.authenticationConfig}); no GET is published, and this read-only inspector never issues a PATCH, so the org MFA setting cannot be read.`;
  // The administrator list is derived from /people and /roles together, so either denial takes the denied path (as ID-03 and ID-04 do).
  let adminMfaFinding: WebexFinding;
  if (!people.ok || !roles.ok) {
    const deniedSurface = !people.ok ? "people" : "roles";
    const deniedEndpoint = !people.ok ? "/people" : "/roles";
    adminMfaFinding = finding("WEBEX-ID-02", [2], "Admin MFA enforcement", "critical", "manual",
      `${deniedSummary(deniedSurface, deniedEndpoint, (!people.ok ? people : roles) as { error: string; status?: number }, "the Control Hub admin list with MFA status for each administrator")} No administrator count is asserted because the list is derived from GET /people and GET /roles together. ${mfaReadOnlyNote}`,
      {
        admin_users: null,
        admin_count: null,
        denied_endpoint: `GET ${deniedEndpoint}`,
        inventory_status: { people: inventoryStatus(people), roles: inventoryStatus(roles) },
        citation: WEBEX_DOCS.authenticationConfig,
        people_citation: WEBEX_DOCS.peopleList,
        roles_citation: WEBEX_DOCS.rolesList,
        token_type: tokenType,
      });
  } else {
    adminMfaFinding = finding("WEBEX-ID-02", [2], "Admin MFA enforcement", "critical", "manual",
      `Manual: ${mfaReadOnlyNote} The People API (${WEBEX_DOCS.peopleList}) exposes roles but no MFA attribute, so the ${adminUsers.length} administrators found are listed as evidence only. Confirm MFA enforcement in Control Hub Organization Settings > Authentication for each listed admin.${peoplePartial}`,
      { admin_users: adminUsers.slice(0, 50).map(personLabel), admin_count: adminUsers.length, people_seen: surfaceItems(people).length, people_truncated: people.truncated, citation: WEBEX_DOCS.authenticationConfig, people_citation: WEBEX_DOCS.peopleList });
  }

  let complianceFinding: WebexFinding;
  if (!people.ok || !roles.ok) {
    const denied = !people.ok ? people : roles;
    complianceFinding = finding("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", "manual",
      deniedSummary(!people.ok ? "people" : "roles", !people.ok ? "/people" : "/roles", denied as { error: string; status?: number }, "the Control Hub Users list filtered to the Compliance Officer role"),
      { citation: WEBEX_DOCS.rolesList, token_type: tokenType });
  } else if (surfaceItems(people).length === 0) {
    complianceFinding = finding("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", "manual",
      "Manual: GET /people returned zero people, which is not a valid population for an active org; confirm the token has spark-admin:people_read and the org is correct.",
      { people_seen: 0, citation: WEBEX_DOCS.peopleList });
  } else if (complianceOfficers.length > 0) {
    complianceFinding = finding("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", people.truncated ? "warn" : "pass",
      `${complianceOfficers.length} of ${humans.length} people carry the Compliance Officer role.${peoplePartial}`,
      { compliance_officers: complianceOfficers.slice(0, 50).map(personLabel), compliance_officer_count: complianceOfficers.length, people_seen: humans.length, people_truncated: people.truncated });
  } else {
    complianceFinding = finding("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", "fail",
      `No person among ${humans.length} listed carries the Compliance Officer role.${peoplePartial}`,
      { people_seen: humans.length, people_truncated: people.truncated, roles_seen: [...roleMap.values()] });
  }

  let concentrationFinding: WebexFinding;
  if (!people.ok || !roles.ok) {
    concentrationFinding = finding("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium", "manual",
      deniedSummary("people and roles", "/people and /roles", (!people.ok ? people : roles) as { error: string; status?: number }, "the Control Hub administrator list"),
      { token_type: tokenType });
  } else if (surfaceItems(people).length === 0) {
    concentrationFinding = finding("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium", "manual",
      "Manual: GET /people returned zero people; an empty population cannot demonstrate bounded admin counts.",
      { people_seen: 0 });
  } else if (adminUsers.length === 0) {
    concentrationFinding = finding("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium", "warn",
      `No administrators were visible among ${humans.length} people; every org has at least one Full Administrator, so the role data is incomplete.${peoplePartial}`,
      { admin_users: 0, people_seen: humans.length, people_truncated: people.truncated });
  } else {
    const within = adminUsers.length <= maxAdmins;
    concentrationFinding = finding("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium",
      within ? (people.truncated ? "warn" : "pass") : "warn",
      `${adminUsers.length} of ${humans.length} people hold administrator roles (threshold ${maxAdmins}).${peoplePartial}`,
      { admin_users: adminUsers.slice(0, 50).map(personLabel), admin_count: adminUsers.length, max_admins: maxAdmins, people_seen: humans.length, people_truncated: people.truncated });
  }

  let botInventoryFinding: WebexFinding;
  if (!people.ok) {
    botInventoryFinding = finding("WEBEX-ID-05", [19], "Bot account inventory", "medium", "manual",
      deniedSummary("people", "/people", people, "the Control Hub Apps > Bots list"),
      { citation: WEBEX_DOCS.bots, token_type: tokenType });
  } else if (surfaceItems(people).length === 0) {
    botInventoryFinding = finding("WEBEX-ID-05", [19], "Bot account inventory", "medium", "manual",
      "Manual: GET /people returned zero people, so no bot inventory could be built.",
      { people_seen: 0 });
  } else {
    botInventoryFinding = finding("WEBEX-ID-05", [19], "Bot account inventory", "medium", people.truncated ? "warn" : "pass",
      `${bots.length} bot accounts (Person.type = bot) were inventoried among ${surfaceItems(people).length} people; review the list against the approved bot register.${peoplePartial}`,
      {
        bots: bots.slice(0, 100).map((bot) => ({ id: asString(bot.id), display_name: asString(bot.displayName), emails: asArray(bot.emails).map(asString), created: asString(bot.created) })),
        bot_count: bots.length,
        people_seen: surfaceItems(people).length,
        people_truncated: people.truncated,
        citation: WEBEX_DOCS.bots,
      });
  }

  const botInventoryPhrase = people.ok
    ? `the ${bots.length} inventoried bots`
    : "the bot inventory in WEBEX-ID-05, which could not be built because GET /people was not readable, so no bot count is asserted here";
  const botApprovalFinding = finding("WEBEX-ID-06", [19], "Bot approval state", "medium", "manual",
    `Manual: bot approval is managed in Control Hub (Management > Apps) and the bots guide (${WEBEX_DOCS.bots}) documents no API field for approval state. Export the Control Hub bot management page and reconcile it with ${botInventoryPhrase}.`,
    { bot_count: countIfReadable(bots.length, people), people_status: inventoryStatus(people), citation: WEBEX_DOCS.bots });

  const guestCountValue = guestCount.ok ? asNumber(guestCount.data.count) : undefined;
  const guestCountInventory: SecondaryInventory = {
    endpoint: "GET /guests/count",
    scope: "guest-issuer:read",
    result: guestCount,
    consequence: "the guest-issuer count could not be reconciled with the people-based inventory",
  };
  const guestCountNote = guestCount.ok
    ? guestCountValue === undefined
      ? " GET /guests/count answered without a numeric body."
      : ` GET /guests/count reports ${guestCountValue} guest-issuer guests.`
    : unreadableNote([guestCountInventory]);
  const guestEvidence = {
    guests: people.ok ? guests.slice(0, 100).map((guest) => ({ id: asString(guest.id), display_name: asString(guest.displayName), created: asString(guest.created) })) : null,
    guest_count_people: countIfReadable(guests.length, people),
    guest_count_api: guestCountValue ?? null,
    guest_count_api_error: guestCount.ok ? null : guestCount.error,
    guest_count_api_status: inventoryStatus(guestCount),
    people_seen: countIfReadable(surfaceItems(people).length, people),
    people_truncated: people.ok ? people.truncated : null,
    citation: WEBEX_DOCS.peopleList,
    guest_count_citation: WEBEX_DOCS.guestCount,
  };
  let guestInventoryFinding: WebexFinding;
  if (!people.ok) {
    guestInventoryFinding = finding("WEBEX-ID-07", [13], "Guest account inventory", "medium", "manual",
      `${deniedSummary("people", "/people", people, "the Control Hub guest user list")}${guestCountNote}`,
      { ...guestEvidence, token_type: tokenType });
  } else if (surfaceItems(people).length === 0) {
    guestInventoryFinding = finding("WEBEX-ID-07", [13], "Guest account inventory", "medium", "manual",
      `Manual: GET /people returned zero people, so no guest inventory could be built.${guestCountNote}`,
      guestEvidence);
  } else {
    const guestCapped = capForUnreadable(people.truncated ? "warn" : "pass", [guestCountInventory]);
    guestInventoryFinding = finding("WEBEX-ID-07", [13], "Guest account inventory", "medium", guestCapped.status,
      `${guests.length} guest accounts (Person.type = appuser, documented as a guest user) were inventoried among ${surfaceItems(people).length} people.${guestCountNote} Reconcile the list with the guest access policy assessed in WEBEX-MTG-03.${peoplePartial}`,
      guestEvidence);
  }

  const findings = [ssoFinding, adminMfaFinding, complianceFinding, concentrationFinding, botInventoryFinding, botApprovalFinding, guestInventoryFinding];
  return {
    title: "Webex identity posture",
    category: "identity",
    summary: {
      org_id: orgId ?? null,
      token_type: tokenType,
      people_seen: countIfReadable(surfaceItems(people).length, people),
      people_truncated: people.ok ? people.truncated : null,
      admin_users: countIfReadable(adminUsers.length, people, roles),
      compliance_officers: countIfReadable(complianceOfficers.length, people, roles),
      bots: countIfReadable(bots.length, people),
      guests: countIfReadable(guests.length, people),
      inventory_status: {
        people: inventoryStatus(people),
        roles: inventoryStatus(roles),
        guest_count: inventoryStatus(guestCount),
      },
      ...countStatuses(findings),
    },
    findings,
    errors: surfaceErrors(surfaces),
    rawData: surfaceRaw(surfaces),
  };
}

export async function assessWebexCollaborationGovernance(
  client: WebexClientLike,
  options: AssessmentOptions = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const eventLimit = clampNumber(options.eventLimit, DEFAULT_EVENT_LIMIT, 1, 50_000);
  const recordingLimit = clampNumber(options.recordingLimit, DEFAULT_RECORDING_LIMIT, 1, 50_000);
  const webhookLimit = clampNumber(options.webhookLimit, DEFAULT_WEBHOOK_LIMIT, 1, 50_000);
  const licenseLimit = clampNumber(options.licenseLimit, DEFAULT_LICENSE_LIMIT, 1, 50_000);
  const roomLimit = clampNumber(options.roomLimit, DEFAULT_ROOM_LIMIT, 1, 50_000);

  const me = await collectObject(() => client.getMe());
  const tokenType = detectTokenType(me.ok ? me.data : undefined);
  const orgs = await collectPage(() => client.listOrganizations());
  const { orgId, note } = deriveOrgContext(config, orgs);
  const botDenied: SurfaceResult<JsonRecord[]> = { ok: false, error: "bot token cannot read admin surfaces", status: 403 };
  const notConfigured: SurfaceResult<JsonRecord[]> = { ok: false, error: note };
  const [events, adminAudit, recordings, rooms, webhooks, licenses] = await Promise.all([
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listEvents(eventLimit)),
    tokenType === "bot" ? Promise.resolve(botDenied) : orgId ? collectPage(() => client.listAdminAuditEvents(orgId, eventLimit)) : Promise.resolve(notConfigured),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listAdminRecordings(recordingLimit)),
    collectPage(() => client.listRooms(roomLimit)),
    collectPage(() => client.listWebhooks(webhookLimit)),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listLicenses(licenseLimit)),
  ]);
  const surfaces: SurfaceSet = { me, organizations: orgs, events, admin_audit_events: adminAudit, admin_recordings: recordings, rooms, webhooks, licenses };
  const tokenProbe = tokenProbeInventory(me, tokenType);

  const externalFinding = finding("WEBEX-COLLAB-01", [4], "External communications policy", "high", "manual",
    `Manual: no documented Webex API endpoint exposes the external communication policy; the Organizations reference (${WEBEX_DOCS.organizationGet}) documents only id, displayName, and created. Guest access (control 13) is judged from the site common settings in WEBEX-MTG-03 and inventoried in WEBEX-ID-07. Export Control Hub Messaging settings (external communication allow list).`,
    { org_id: orgId ?? null, citation: WEBEX_DOCS.organizationGet });

  const fileDlpFinding = finding("WEBEX-COLLAB-02", [5, 21], "File sharing restrictions and messaging DLP", "high", "manual",
    `Manual: file sharing restrictions are Control Hub settings and DLP is delivered through Events API integrations (${WEBEX_DOCS.complianceGuide}); no API field reports the policy state. Export Control Hub file sharing controls and the DLP/CASB integration evidence.${events.ok ? ` ${surfaceItems(events).length} compliance events were readable as integration evidence.` : ` GET /events was not readable (${events.error}).`}`,
    { events_readable: events.ok, events_seen: countIfReadable(surfaceItems(events).length, events), events_status: inventoryStatus(events), citation: WEBEX_DOCS.complianceGuide });

  const recordingItems = surfaceItems(recordings);
  const deletedRecordings = recordingItems.filter((item) => asString(item.status) === "deleted");
  const recordingFinding = !recordings.ok
    ? finding("WEBEX-COLLAB-03", [6, 7, 12], "Recording storage and retention governance", "medium", "manual",
      deniedSummary("admin recordings", "/admin/recordings", recordings, "Control Hub recording retention and storage settings"),
      { citation: WEBEX_DOCS.adminRecordings, token_type: tokenType })
    : finding("WEBEX-COLLAB-03", [6, 7, 12], "Recording storage and retention governance", "medium", "manual",
      `Manual: the admin recordings reference (${WEBEX_DOCS.adminRecordings}) documents no storage location or retention field; ${recordingItems.length} recordings were inventoried (${deletedRecordings.length} in deleted status). Export Control Hub retention settings for recordings and messaging.${partialNote(recordings, "recordings")}`,
      { recordings_seen: recordingItems.length, deleted_recordings: deletedRecordings.length, recordings_truncated: recordings.truncated, citation: WEBEX_DOCS.adminRecordings });

  const roomItems = surfaceItems(rooms);
  const roomsWithoutClassification = roomItems.filter((room) => !asString(room.classificationId));
  let classificationFinding: WebexFinding;
  if (!rooms.ok) {
    classificationFinding = finding("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", "manual",
      deniedSummary("rooms", "/rooms", rooms, "the Control Hub space classification settings"), { citation: WEBEX_DOCS.roomsList });
  } else if (roomItems.length === 0) {
    classificationFinding = finding("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", "manual",
      "Manual: GET /rooms lists only spaces the token is a member of and returned none; confirm classification enforcement in Control Hub.",
      { rooms_seen: 0, citation: WEBEX_DOCS.roomsList });
  } else if (roomsWithoutClassification.length === 0) {
    const capped = capForUnreadable(rooms.truncated || tokenType === "bot" ? "warn" : "pass", [tokenProbe]);
    classificationFinding = finding("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", capped.status,
      `All ${roomItems.length} spaces visible to this token carry a classificationId. GET /rooms only lists spaces the token is a member of, so this is the credential's view, not the whole org.${tokenType === "bot" ? " A bot token sees only its own spaces, so the view is partial." : ""}${partialNote(rooms, "rooms")}${capped.note}`,
      { rooms_seen: roomItems.length, rooms_truncated: rooms.truncated, token_type: tokenType, token_probe_status: inventoryStatus(tokenProbe.result) });
  } else {
    classificationFinding = finding("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", "fail",
      `${roomsWithoutClassification.length} of ${roomItems.length} visible spaces have no classificationId.${partialNote(rooms, "rooms")}`,
      {
        rooms_seen: roomItems.length,
        rooms_without_classification: roomsWithoutClassification.slice(0, 25).map((room) => asString(room.title) ?? asString(room.id)),
        rooms_without_classification_count: roomsWithoutClassification.length,
        rooms_truncated: rooms.truncated,
      });
  }

  const webhookItems = surfaceItems(webhooks);
  const insecureWebhooks = webhookItems.filter((webhook) => {
    const targetUrl = asString(webhook.targetUrl) ?? "";
    return !targetUrl.startsWith("https://") || !asString(webhook.secret);
  });
  const inactiveWebhooks = webhookItems.filter((webhook) => asString(webhook.status) === "inactive");
  let webhookFinding: WebexFinding;
  if (!webhooks.ok) {
    webhookFinding = finding("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", "manual",
      deniedSummary("webhooks", "/webhooks", webhooks, "the webhook list from each integration owner"), { citation: WEBEX_DOCS.webhooksList });
  } else if (webhookItems.length === 0) {
    webhookFinding = finding("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", "manual",
      "Manual: no webhooks are visible to this token (GET /webhooks lists only the caller's webhooks); collect webhook inventories from integration owners.",
      { webhooks_seen: 0, citation: WEBEX_DOCS.webhooksList });
  } else if (insecureWebhooks.length === 0) {
    const capped = capForUnreadable(webhooks.truncated || tokenType === "bot" ? "warn" : "pass", [tokenProbe]);
    webhookFinding = finding("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", capped.status,
      `All ${webhookItems.length} webhooks visible to this token use https targetUrl values and have a secret (${inactiveWebhooks.length} inactive).${tokenType === "bot" ? " A bot token sees only its own webhooks, so the view is partial." : ""}${partialNote(webhooks, "webhooks")}${capped.note}`,
      { webhooks_seen: webhookItems.length, inactive_webhooks: inactiveWebhooks.length, webhooks_truncated: webhooks.truncated, token_type: tokenType, token_probe_status: inventoryStatus(tokenProbe.result) });
  } else {
    webhookFinding = finding("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", "fail",
      `${insecureWebhooks.length} of ${webhookItems.length} visible webhooks lack an https targetUrl or a secret.${partialNote(webhooks, "webhooks")}`,
      {
        insecure_webhooks: insecureWebhooks.slice(0, 25).map((item) => ({ id: asString(item.id), name: asString(item.name), target_url: scrubValue(asString(item.targetUrl) ?? "") })),
        insecure_webhooks_count: insecureWebhooks.length,
        webhooks_seen: webhookItems.length,
      });
  }

  const licenseItems = surfaceItems(licenses);
  const totalUnits = licenseItems.reduce((count, license) => count + (asNumber(license.totalUnits) ?? 0), 0);
  const consumedUnits = licenseItems.reduce((count, license) => count + (asNumber(license.consumedUnits) ?? 0), 0);
  const unassigned = Math.max(totalUnits - consumedUnits, 0);
  const unassignedRatio = totalUnits > 0 ? unassigned / totalUnits : 0;
  let licenseFinding: WebexFinding;
  if (!licenses.ok) {
    licenseFinding = finding("WEBEX-COLLAB-06", [24], "License utilization review", "low", "manual",
      deniedSummary("licenses", "/licenses", licenses, "the Control Hub subscriptions and license usage report"), { citation: WEBEX_DOCS.licensesList, token_type: tokenType });
  } else if (licenseItems.length === 0 || totalUnits === 0) {
    licenseFinding = finding("WEBEX-COLLAB-06", [24], "License utilization review", "low", "manual",
      "Manual: GET /licenses returned no licenses with totalUnits; a paid org always has licenses, so confirm scope and org selection.",
      { licenses_seen: licenseItems.length, citation: WEBEX_DOCS.licensesList });
  } else {
    licenseFinding = finding("WEBEX-COLLAB-06", [24], "License utilization review", "low",
      unassignedRatio <= 0.2 ? (licenses.truncated ? "warn" : "pass") : "warn",
      `${unassigned} of ${totalUnits} license units are unassigned (${Math.round(unassignedRatio * 100)}%, threshold 20%) across ${licenseItems.length} licenses.${partialNote(licenses, "licenses")}`,
      { total_units: totalUnits, consumed_units: consumedUnits, unassigned_units: unassigned, licenses_seen: licenseItems.length, licenses_truncated: licenses.truncated });
  }

  const auditItems = surfaceItems(adminAudit);
  const datedAudit = auditItems.filter((item) => asDate(item.created));
  let auditFinding: WebexFinding;
  if (!adminAudit.ok) {
    auditFinding = finding("WEBEX-COLLAB-07", [25], "Admin activity audit visibility", "high", "manual",
      orgId
        ? deniedSummary("admin audit events", "/adminAudit/events", adminAudit, "a Control Hub admin audit log export (audit:events_read scope required)")
        : `Manual: ${note}`,
      { citation: WEBEX_DOCS.adminAuditEvents, token_type: tokenType });
  } else if (auditItems.length === 0) {
    auditFinding = finding("WEBEX-COLLAB-07", [25], "Admin activity audit visibility", "high", "warn",
      `GET /adminAudit/events returned no events in the last ${ADMIN_AUDIT_WINDOW_DAYS} days; confirm the log is populated and reviewed (an active org normally records admin activity).`,
      { events_seen: 0, window_days: ADMIN_AUDIT_WINDOW_DAYS });
  } else {
    auditFinding = finding("WEBEX-COLLAB-07", [25], "Admin activity audit visibility", "high", adminAudit.truncated ? "warn" : "pass",
      `${auditItems.length} admin audit events (${datedAudit.length} with a created timestamp) were readable for the last ${ADMIN_AUDIT_WINDOW_DAYS} days; attach the review record.${partialNote(adminAudit, "admin audit events")}`,
      { events_seen: auditItems.length, events_with_dates: datedAudit.length, undated_events: auditItems.length - datedAudit.length, window_days: ADMIN_AUDIT_WINDOW_DAYS, events_truncated: adminAudit.truncated });
  }

  const ediscoveryFinding = finding("WEBEX-COLLAB-08", [11], "eDiscovery and legal hold capability", "high", "manual",
    `Manual: the compliance guide (${WEBEX_DOCS.complianceGuide}) states the eDiscovery report is available through Control Hub and documents no API for eDiscovery or legal hold configuration. Events older than 90 days require Pro Pack. Export the Control Hub eDiscovery and legal hold configuration${events.ok ? `; ${surfaceItems(events).length} compliance events were readable as capability evidence` : `; GET /events was not readable (${events.error})`}.`,
    { events_readable: events.ok, events_seen: countIfReadable(surfaceItems(events).length, events), events_truncated: events.ok ? events.truncated : null, events_status: inventoryStatus(events), citation: WEBEX_DOCS.complianceGuide });

  const findings = [externalFinding, fileDlpFinding, recordingFinding, classificationFinding, webhookFinding, licenseFinding, auditFinding, ediscoveryFinding];
  return {
    title: "Webex collaboration governance",
    category: "collaboration-governance",
    summary: {
      org_id: orgId ?? null,
      token_type: tokenType,
      rooms_seen: countIfReadable(roomItems.length, rooms),
      rooms_without_classification: countIfReadable(roomsWithoutClassification.length, rooms),
      webhooks_seen: countIfReadable(webhookItems.length, webhooks),
      insecure_webhooks: countIfReadable(insecureWebhooks.length, webhooks),
      recordings_seen: countIfReadable(recordingItems.length, recordings),
      admin_audit_events: countIfReadable(auditItems.length, adminAudit),
      compliance_events: countIfReadable(surfaceItems(events).length, events),
      unassigned_license_units: countIfReadable(unassigned, licenses),
      total_license_units: countIfReadable(totalUnits, licenses),
      inventory_status: {
        rooms: inventoryStatus(rooms),
        webhooks: inventoryStatus(webhooks),
        admin_recordings: inventoryStatus(recordings),
        admin_audit_events: inventoryStatus(adminAudit),
        events: inventoryStatus(events),
        licenses: inventoryStatus(licenses),
      },
      ...countStatuses(findings),
    },
    findings,
    errors: surfaceErrors(surfaces),
    rawData: surfaceRaw(surfaces),
  };
}

export async function assessWebexMeetingHybridSecurity(
  client: WebexClientLike,
  options: AssessmentOptions = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const meetingLimit = clampNumber(options.meetingLimit, DEFAULT_MEETING_LIMIT, 1, 50_000);
  const deviceLimit = clampNumber(options.deviceLimit, DEFAULT_DEVICE_LIMIT, 1, 50_000);

  const me = await collectObject(() => client.getMe());
  const tokenType = detectTokenType(me.ok ? me.data : undefined);
  const orgs = await collectPage(() => client.listOrganizations());
  const { orgId } = deriveOrgContext(config, orgs);
  const botDenied: SurfaceResult<JsonRecord[]> = { ok: false, error: "bot token cannot read admin surfaces", status: 403 };
  const [meetingPreferences, meetingSites, meetings, hybridClusters, hybridConnectors, devices, workspaces] = await Promise.all([
    collectObject(() => client.getMeetingPreferences()),
    collectPage(() => client.listMeetingSites()),
    collectPage(() => client.listMeetings(meetingLimit)),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listHybridClusters()),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listHybridConnectors()),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listDevices(deviceLimit)),
    tokenType === "bot" ? Promise.resolve(botDenied) : collectPage(() => client.listWorkspaces()),
  ]);
  const siteSettings = await collectSiteSettings(client, tokenType, meetingSites, meetingPreferences);
  const surfaces: SurfaceSet = {
    me,
    organizations: orgs,
    meeting_preferences: meetingPreferences,
    meeting_sites: meetingSites,
    meeting_common_settings: siteSettings.raw,
    meetings,
    hybrid_clusters: hybridClusters,
    hybrid_connectors: hybridConnectors,
    devices,
    workspaces,
  };

  const tokenProbe = tokenProbeInventory(me, tokenType);

  const encryptionFinding = finding("WEBEX-MTG-01", [8, 22], "Meeting E2EE and calling SRTP defaults", "high", "manual",
    `Manual: no encryption field exists in the meeting preferences reference (${WEBEX_DOCS.meetingPreferences}), the site common settings (${WEBEX_DOCS.meetingCommonSettings}), or the session types reference (${WEBEX_DOCS.sessionTypes}, which returns id, shortName, siteUrl, name, and type), and no public API exposes a Webex Calling SRTP setting, so calling SRTP (control 22) stays folded into this finding. Export the Control Hub meeting session type (E2EE) and calling security configuration.`,
    {
      meeting_preferences_readable: meetingPreferences.ok,
      sites_seen: meetingSites.ok ? surfaceItems(meetingSites).map((site) => asString(site.siteUrl)) : null,
      meeting_sites_status: inventoryStatus(meetingSites),
      citation: WEBEX_DOCS.meetingCommonSettings,
    });

  const meetingItems = surfaceItems(meetings);
  const sampledWithoutLobby = meetingItems.filter((meeting) => asString(meeting.unlockedMeetingJoinSecurity) === "allowJoin");
  const sampledWithoutPassword = meetingItems.filter((meeting) => !asString(meeting.password));
  const pmr = asObject(meetingPreferences.ok ? meetingPreferences.data.personalMeetingRoom : undefined);
  const sampledMeetingEvidence = {
    meetings_seen: countIfReadable(meetingItems.length, meetings),
    meetings_truncated: meetings.ok ? meetings.truncated : null,
    meetings_status: inventoryStatus(meetings),
    sampled_allow_join_without_lobby: countIfReadable(sampledWithoutLobby.length, meetings),
    sampled_without_password: countIfReadable(sampledWithoutPassword.length, meetings),
    personal_meeting_room_auto_lock: pmr ? asBoolean(pmr.enabledAutoLock) ?? null : null,
    meeting_preferences_status: inventoryStatus(meetingPreferences),
    token_probe_status: inventoryStatus(tokenProbe.result),
    meetings_citation: WEBEX_DOCS.meetingsList,
  };
  const meetingSecondaries: SecondaryInventory[] = [
    { endpoint: "GET /meetings", scope: "meeting:schedules_read or meeting:admin_schedule_read", result: meetings, consequence: "the sampled per-meeting lobby and password evidence is unavailable" },
    { endpoint: "GET /meetingPreferences", scope: "meeting:preferences_read or meeting:admin_preferences_read", result: meetingPreferences, consequence: "the Personal Room auto-lock preference is unavailable" },
    tokenProbe,
  ];
  const lobbyFinding = siteFinding("WEBEX-MTG-02", [9], "Meeting lobby and join-before-host defaults", "high", siteSettings, judgeLobbyDefaults, tokenType,
    "the Control Hub site Common Settings > Security page (join before host, unlisted meetings)", meetingSecondaries, sampledMeetingEvidence);
  const passwordFinding = siteFinding("WEBEX-MTG-06", [10], "Meeting password policy", "high", siteSettings, judgePasswordPolicy, tokenType,
    "the Control Hub site Common Settings > Security page (strong password criteria)", meetingSecondaries, sampledMeetingEvidence);
  const guestFinding = siteFinding("WEBEX-MTG-03", [13], "Guest meeting access policy", "medium", siteSettings, judgeGuestAccess, tokenType,
    "the Control Hub site Common Settings > Security page (require login before site access)", [tokenProbe], { token_probe_status: inventoryStatus(tokenProbe.result) });

  const virtualBackgroundFinding = finding("WEBEX-MTG-07", [23], "Virtual background policy", "low", "manual",
    `Manual: virtual background enforcement is a Control Hub meeting setting with no field in the site common settings (${WEBEX_DOCS.meetingCommonSettings}), the meeting preferences reference (${WEBEX_DOCS.meetingPreferences}), or the session types reference (${WEBEX_DOCS.sessionTypes}). Export the Control Hub meeting settings page for virtual backgrounds.`,
    { citation: WEBEX_DOCS.meetingCommonSettings });

  const clusterItems = surfaceItems(hybridClusters);
  const connectorItems = surfaceItems(hybridConnectors);
  const nonOperational = connectorItems.filter((connector) => asString(connector.status) !== "operational");
  const undatedConnectors = connectorItems.filter((connector) => !asDate(connector.created));
  let hybridFinding: WebexFinding;
  if (!hybridClusters.ok || !hybridConnectors.ok) {
    const denied = (!hybridClusters.ok ? hybridClusters : hybridConnectors) as { error: string; status?: number };
    hybridFinding = finding("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", "manual",
      deniedSummary("hybrid services", !hybridClusters.ok ? "/hybrid/clusters" : "/hybrid/connectors", denied, "the Control Hub Hybrid Services status page"),
      { citation: WEBEX_DOCS.hybridConnectors, token_type: tokenType });
  } else if (clusterItems.length === 0 && connectorItems.length === 0) {
    hybridFinding = finding("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", "manual",
      "Manual: no hybrid clusters or connectors are registered; confirm in Control Hub that hybrid services are not deployed, in which case controls 15 and 16 are not applicable.",
      { clusters_seen: 0, connectors_seen: 0 });
  } else if (nonOperational.length === 0 && connectorItems.length > 0) {
    hybridFinding = finding("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high",
      hybridClusters.truncated || hybridConnectors.truncated ? "warn" : "pass",
      `All ${connectorItems.length} hybrid connectors across ${clusterItems.length} clusters report status = operational.${partialNote(hybridConnectors, "connectors")}`,
      { clusters_seen: clusterItems.length, connectors_seen: connectorItems.length, connector_versions: [...new Set(connectorItems.map((item) => asString(item.version)).filter(Boolean))], undated_connectors: undatedConnectors.length });
  } else if (connectorItems.length === 0) {
    hybridFinding = finding("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", "fail",
      `${clusterItems.length} hybrid clusters are registered but no connectors report status, so nothing demonstrates the clusters are healthy.`,
      { clusters_seen: clusterItems.length, connectors_seen: 0 });
  } else {
    hybridFinding = finding("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", "fail",
      `${nonOperational.length} of ${connectorItems.length} hybrid connectors are not operational.${partialNote(hybridConnectors, "connectors")}`,
      {
        non_operational: nonOperational.slice(0, 25).map((item) => ({ id: asString(item.id), type: asString(item.type), status: asString(item.status) ?? null })),
        non_operational_count: nonOperational.length,
        connectors_seen: connectorItems.length,
        clusters_seen: clusterItems.length,
      });
  }

  const deviceItems = surfaceItems(devices);
  const personalModeDevices = deviceItems.filter((device) => asString(device.personId));
  const softwareVersions = [...new Set(deviceItems.map((item) => asString(item.software)).filter(Boolean))];
  const upgradeChannels = [...new Set(deviceItems.map((item) => asString(item.upgradeChannel)).filter(Boolean))];
  const devicesWithoutUpgradeChannel = deviceItems.filter((item) => !asString(item.upgradeChannel)).length;
  const deviceFinding = !devices.ok
    ? finding("WEBEX-MTG-05", [17, 18], "Device firmware and management posture", "high", "manual",
      deniedSummary("devices", "/devices", devices, "the Control Hub device inventory with software versions"), { citation: WEBEX_DOCS.devicesList, token_type: tokenType })
    : finding("WEBEX-MTG-05", [17, 18], "Device firmware and management posture", "high", "manual",
      `Manual: the devices reference (${WEBEX_DOCS.devicesList}) documents software, upgradeChannel, connectionStatus, managedBy, personId, and workspaceId but no end-of-life flag or device-blocking policy; ${deviceItems.length} devices were inventoried (${personalModeDevices.length} assigned to a person, ${softwareVersions.length} distinct software versions, upgrade channels ${upgradeChannels.length > 0 ? upgradeChannels.join(", ") : "unreported"}, ${workspaces.ok ? `${surfaceItems(workspaces).length} workspaces` : `workspaces not readable: GET /workspaces ${workspaces.error}`}). Compare the versions against Cisco RoomOS release notes and export the Control Hub device activation policy.${partialNote(devices, "devices")}`,
      {
        devices_seen: deviceItems.length,
        devices_truncated: devices.truncated,
        personal_mode_devices: personalModeDevices.length,
        software_versions: softwareVersions.slice(0, 50),
        software_version_count: softwareVersions.length,
        upgrade_channels: upgradeChannels.slice(0, 50),
        upgrade_channel_count: upgradeChannels.length,
        devices_without_upgrade_channel: devicesWithoutUpgradeChannel,
        managed_by: [...new Set(deviceItems.map((item) => asString(item.managedBy)).filter(Boolean))],
        workspaces_seen: countIfReadable(surfaceItems(workspaces).length, workspaces),
        workspaces_status: inventoryStatus(workspaces),
        citation: WEBEX_DOCS.devicesList,
      });

  const findings = [encryptionFinding, lobbyFinding, guestFinding, hybridFinding, deviceFinding, passwordFinding, virtualBackgroundFinding];
  return {
    title: "Webex meeting and hybrid security",
    category: "meeting-hybrid-security",
    summary: {
      org_id: orgId ?? null,
      token_type: tokenType,
      sites_evaluated: siteSettings.readable.length,
      sites_denied: siteSettings.denied.length,
      meetings_seen: countIfReadable(meetingItems.length, meetings),
      hybrid_clusters: countIfReadable(clusterItems.length, hybridClusters),
      hybrid_connectors: countIfReadable(connectorItems.length, hybridConnectors),
      non_operational_connectors: countIfReadable(nonOperational.length, hybridConnectors),
      devices_seen: countIfReadable(deviceItems.length, devices),
      workspaces_seen: countIfReadable(surfaceItems(workspaces).length, workspaces),
      inventory_status: {
        meeting_preferences: inventoryStatus(meetingPreferences),
        meeting_sites: inventoryStatus(meetingSites),
        meeting_common_settings: inventoryStatus(siteSettings.raw),
        meetings: inventoryStatus(meetings),
        hybrid_clusters: inventoryStatus(hybridClusters),
        hybrid_connectors: inventoryStatus(hybridConnectors),
        devices: inventoryStatus(devices),
        workspaces: inventoryStatus(workspaces),
      },
      ...countStatuses(findings),
    },
    findings,
    errors: [...surfaceErrors(surfaces).filter((item) => !item.startsWith("meeting_common_settings:")), ...siteSettingsErrors(siteSettings)],
    rawData: surfaceRaw(surfaces),
  };
}

function formatAccessCheckText(result: WebexAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : `${surfaceItem.count}${surfaceItem.truncated ? "+" : ""}`,
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);

  return [
    `Webex access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: WebexAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: WebexResolvedConfig, assessments: WebexAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countStatuses(findings);
  const prioritized = [...findings]
    .filter((item) => item.status !== "pass")
    .sort((left, right) => statusRank(left.status) - statusRank(right.status))
    .slice(0, 12);

  return [
    "# Webex Executive Summary",
    "",
    `Org: ${config.orgId ?? "auto / unspecified"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Fail: ${counts.fail}`,
    `- Warn: ${counts.warn}`,
    `- Manual: ${counts.manual}`,
    `- Pass: ${counts.pass}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`)
      : ["- No failing, warning, or manual findings were generated."]),
    ...(errors.length > 0 ? ["", "## Partial Collection Warnings", "", ...errors.map((item) => `- ${item}`)] : []),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: WebexFinding[]): string {
  const keys = Object.keys(WEBEX_FRAMEWORK_LABELS) as WebexFrameworkKey[];
  const rows = findings.map((item) => [
    item.id,
    item.control.join(", "),
    item.status.toUpperCase(),
    ...keys.map((key) => item.frameworks[key].join(", ") || "-"),
  ]);
  return `${["# Webex Unified Compliance Matrix", "", formatTable(["Finding", "Spec control", "Status", ...keys.map((key) => WEBEX_FRAMEWORK_LABELS[key])], rows)].join("\n")}\n`;
}

function buildFrameworkReport(key: WebexFrameworkKey, findings: WebexFinding[]): string {
  const mapped = findings.filter((item) => item.frameworks[key].length > 0);
  const rows = mapped.map((item) => [item.frameworks[key].join(", "), item.id, item.status.toUpperCase(), item.title, item.summary]);
  return [
    `# ${WEBEX_FRAMEWORK_LABELS[key]} Compliance Report (Webex)`,
    "",
    `${mapped.length} findings map to ${WEBEX_FRAMEWORK_LABELS[key]}. Manual findings require exported Control Hub evidence before asserting compliance.`,
    "",
    formatTable(["Requirement", "Finding", "Status", "Title", "Summary"], rows),
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# Webex Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains each Webex API surface projected to the documented fields the findings read; tokens, secrets, passwords, and PINs are redacted, and URL query strings (recording RCID, meeting MTID, webhook tokens) are stripped.",
    "- `analysis/` contains normalized findings and per-category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Manual findings name the Control Hub evidence a reviewer must export; they never count as pass.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
  ].join("\n");
}

const FRAMEWORK_REPORT_PATHS: Record<WebexFrameworkKey, string> = {
  fedramp: "compliance/fedramp/fedramp_compliance_report.md",
  cmmc: "compliance/cmmc/cmmc_compliance_report.md",
  soc2: "compliance/soc2/soc2_compliance_report.md",
  cis: "compliance/cis/cis_controls_report.md",
  pci_dss: "compliance/pci_dss/pci_dss_compliance_report.md",
  disa_stig: "compliance/disa_stig/stig_compliance_checklist.md",
  irap: "compliance/irap/irap_compliance_report.md",
  ismap: "compliance/ismap/ismap_compliance_report.md",
};

export async function exportWebexAuditBundle(
  client: WebexClientLike,
  config: WebexResolvedConfig,
  outputRoot: string,
  options: AssessmentOptions = {},
): Promise<WebexAuditBundleResult> {
  const access = await checkWebexAccess(client);
  const identity = await assessWebexIdentity(client, options);
  const collaboration = await assessWebexCollaborationGovernance(client, options);
  const meetingHybrid = await assessWebexMeetingHybridSecurity(client, options);
  const assessments = [identity, collaboration, meetingHybrid];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors.map((item) => `${assessment.category}: ${item}`)))];

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(config.orgId ?? access.orgId ?? "webex-org")}-audit-bundle`,
  );

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    org_id: config.orgId ?? access.orgId ?? null,
    token_type: access.tokenType,
    source_chain: config.sourceChain,
    config_file: config.configFile ? basename(config.configFile) : null,
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, value] of Object.entries(assessment.rawData)) {
      await writeSecureTextFile(outputDir, `core_data/${assessment.category}/${name}.json`, serializeJson(value));
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson({
      title: assessment.title,
      category: assessment.category,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    }));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const key of Object.keys(FRAMEWORK_REPORT_PATHS) as WebexFrameworkKey[]) {
    await writeSecureTextFile(outputDir, FRAMEWORK_REPORT_PATHS[key], buildFrameworkReport(key, findings));
  }
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
    token: asString(value.token),
    org_id: asString(value.org_id),
    base_url: asString(value.base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    refresh_token: asString(value.refresh_token),
    config_file: asString(value.config_file),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    people_limit: asNumber(value.people_limit),
    max_admins: asNumber(value.max_admins),
  };
}

function normalizeCollaborationArgs(args: unknown): CollaborationArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    event_limit: asNumber(value.event_limit),
    recording_limit: asNumber(value.recording_limit),
    webhook_limit: asNumber(value.webhook_limit),
    license_limit: asNumber(value.license_limit),
    room_limit: asNumber(value.room_limit),
  };
}

function normalizeMeetingHybridArgs(args: unknown): MeetingHybridArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    meeting_limit: asNumber(value.meeting_limit),
    device_limit: asNumber(value.device_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeCollaborationArgs(args),
    ...normalizeMeetingHybridArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function assessmentOptions(args: ExportAuditBundleArgs): AssessmentOptions {
  return {
    peopleLimit: args.people_limit,
    maxAdmins: args.max_admins,
    eventLimit: args.event_limit,
    recordingLimit: args.recording_limit,
    webhookLimit: args.webhook_limit,
    licenseLimit: args.license_limit,
    roomLimit: args.room_limit,
    meetingLimit: args.meeting_limit,
    deviceLimit: args.device_limit,
  };
}

function createClient(args: CheckAccessArgs): WebexApiClient {
  return new WebexApiClient(resolveWebexConfiguration(args as JsonRecord));
}

const authParams = {
  token: Type.Optional(Type.String({ description: "Webex access token. Defaults to WEBEX_TOKEN, then the config file." })),
  client_id: Type.Optional(Type.String({ description: "Integration or Service App client ID for the refresh_token grant. Defaults to WEBEX_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "Integration or Service App client secret. Defaults to WEBEX_CLIENT_SECRET." })),
  refresh_token: Type.Optional(Type.String({ description: "Integration or Service App refresh token. Defaults to WEBEX_REFRESH_TOKEN." })),
  config_file: Type.Optional(Type.String({ description: "Config file path. Defaults to WEBEX_CONFIG_FILE, then ~/.config/webex-sec-inspector/config.{json,yaml,yml}." })),
  org_id: Type.Optional(Type.String({ description: "Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible." })),
  base_url: Type.Optional(Type.String({ description: "Webex API base URL. Defaults to https://webexapis.com/v1." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerWebexTools(pi: any): void {
  pi.registerTool({
    name: "webex_check_access",
    label: "Check Webex audit access",
    description:
      "Validate read-only Webex access across people, organizations, roles, licenses, recordings, events, admin audit, hybrid, devices, workspaces, rooms, webhooks, meetings, site common settings, and guest count, and report the token type.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkWebexAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "webex_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Webex access check failed: ${errorMessage(error)}`,
          { tool: "webex_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_identity",
    label: "Assess Webex identity posture",
    description:
      "Assess Webex identity posture across SSO enforcement, admin MFA, Compliance Officer assignment, administrative privilege concentration, bot inventory, bot approval state, and guest account inventory.",
    parameters: Type.Object({
      ...authParams,
      people_limit: Type.Optional(Type.Number({ description: "Maximum people to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessWebexIdentity(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "webex_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Webex identity assessment failed: ${errorMessage(error)}`,
          { tool: "webex_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_collaboration_governance",
    label: "Assess Webex collaboration governance",
    description:
      "Assess Webex collaboration governance across external communications, file sharing and DLP, recording governance, space classification, webhook security, license utilization, admin audit visibility, and eDiscovery capability.",
    parameters: Type.Object({
      ...authParams,
      event_limit: Type.Optional(Type.Number({ description: "Maximum events to inspect. Defaults to 500.", default: 500 })),
      recording_limit: Type.Optional(Type.Number({ description: "Maximum recordings to inspect. Defaults to 200.", default: 200 })),
      webhook_limit: Type.Optional(Type.Number({ description: "Maximum webhooks to inspect. Defaults to 200.", default: 200 })),
      license_limit: Type.Optional(Type.Number({ description: "Maximum licenses to inspect. Defaults to 200.", default: 200 })),
      room_limit: Type.Optional(Type.Number({ description: "Maximum rooms to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeCollaborationArgs,
    async execute(_toolCallId: string, args: CollaborationArgs) {
      try {
        const result = await assessWebexCollaborationGovernance(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "webex_assess_collaboration_governance", ...result });
      } catch (error) {
        return errorResult(
          `Webex collaboration governance assessment failed: ${errorMessage(error)}`,
          { tool: "webex_assess_collaboration_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_meeting_hybrid_security",
    label: "Assess Webex meeting and hybrid security",
    description:
      "Assess Webex meeting and hybrid security across encryption defaults, per-site lobby, password, and guest access settings from the site common settings API, virtual background policy, hybrid connector health, and device inventory posture.",
    parameters: Type.Object({
      ...authParams,
      meeting_limit: Type.Optional(Type.Number({ description: "Maximum meetings to inspect. Defaults to 200.", default: 200 })),
      device_limit: Type.Optional(Type.Number({ description: "Maximum devices to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeMeetingHybridArgs,
    async execute(_toolCallId: string, args: MeetingHybridArgs) {
      try {
        const result = await assessWebexMeetingHybridSecurity(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "webex_assess_meeting_hybrid_security", ...result });
      } catch (error) {
        return errorResult(
          `Webex meeting and hybrid assessment failed: ${errorMessage(error)}`,
          { tool: "webex_assess_meeting_hybrid_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_export_audit_bundle",
    label: "Export Webex audit bundle",
    description:
      "Export a Webex audit bundle with field-allowlisted, redacted core_data snapshots (URL query strings such as recording RCID and meeting MTID stripped), analysis JSON, compliance reports per framework, a quick reference, and a zip archive named after the allocated output directory.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      people_limit: Type.Optional(Type.Number({ description: "Maximum people to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
      event_limit: Type.Optional(Type.Number({ description: "Maximum events to inspect. Defaults to 500.", default: 500 })),
      recording_limit: Type.Optional(Type.Number({ description: "Maximum recordings to inspect. Defaults to 200.", default: 200 })),
      webhook_limit: Type.Optional(Type.Number({ description: "Maximum webhooks to inspect. Defaults to 200.", default: 200 })),
      license_limit: Type.Optional(Type.Number({ description: "Maximum licenses to inspect. Defaults to 200.", default: 200 })),
      room_limit: Type.Optional(Type.Number({ description: "Maximum rooms to inspect. Defaults to 500.", default: 500 })),
      meeting_limit: Type.Optional(Type.Number({ description: "Maximum meetings to inspect. Defaults to 200.", default: 200 })),
      device_limit: Type.Optional(Type.Number({ description: "Maximum devices to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveWebexConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportWebexAuditBundle(new WebexApiClient(config), config, outputRoot, assessmentOptions(args));
        return textResult(
          [
            "Webex audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "webex_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Webex audit bundle export failed: ${errorMessage(error)}`,
          { tool: "webex_export_audit_bundle" },
        );
      }
    },
  });
}
