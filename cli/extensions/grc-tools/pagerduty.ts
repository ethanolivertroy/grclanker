/**
 * PagerDuty security inspector tools for grclanker.
 *
 * Read-only PagerDuty REST API v2 access across account access control,
 * incident response configuration, on-call coverage, audit logging, and
 * integration security, mapped to the 25 controls in
 * specs/pagerduty-sec-inspector.spec.md.
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
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const US_BASE_URL = "https://api.pagerduty.com";
const EU_BASE_URL = "https://api.eu.pagerduty.com";
const IDENTITY_TOKEN_URL = "https://identity.pagerduty.com/oauth/token";
const ACCEPT_HEADER = "application/vnd.pagerduty+json;version=2";
const DEFAULT_OUTPUT_DIR = "./export/pagerduty";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 100;
const CLASSIC_PAGINATION_CAP = 10_000;
const DEFAULT_LIST_LIMIT = 1000;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_TEAM_LIMIT = 50;
const DEFAULT_SCHEDULE_LIMIT = 50;
export const DEFAULT_AUDIT_LIMIT = 2000;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_COVERAGE_DAYS = 30;
const DEFAULT_AUDIT_WINDOW_DAYS = 30;
const DEFAULT_MIN_RETENTION_DAYS = 365;
const DEFAULT_API_KEY_MAX_AGE_DAYS = 90;
const DEFAULT_MAX_RETRIES = 3;
const MAX_RETRY_DELAY_MS = 30_000;
const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CONFIG_FILE = join(".config", "grclanker", "pagerduty.json");
const PRIVILEGED_ROLES = new Set(["owner", "admin"]);
const RESPONDER_ROLES = new Set(["owner", "admin", "user", "limited_user"]);
const REDACTED = "[REDACTED]";
const SECRET_KEY_PATTERN = /secret|password|passwd|token|privatekey|authorization|apikey|accesskey|credential|integrationkey|routingkey|signingkey/;
const SECRET_KEY_EXCEPTIONS = new Set(["truncatedtoken"]);
const MAX_REDACTION_DEPTH = 32;
// PagerDuty REST API keys, OAuth client secrets, and bearer tokens are long; a shorter minimum would
// remember common words and redact them out of ordinary error text.
const MIN_REMEMBERED_SECRET_LENGTH = 8;
/** Every credential literal a client in this process was configured with or obtained from the identity service. */
const KNOWN_SECRETS = new Set<string>();
/** The forms a remembered secret takes in an echoed body (raw, base64, base64url, URL-encoded, JSON-escaped), computed once per secret. */
const SECRET_FORMS = new Map<string, string[]>();
// Scrub boundary. A value inside a carrier (an Authorization, Cookie, Set-Cookie, or API key header, a
// cookie or session assignment, URL userinfo or a query pair, a Bearer/Basic/Digest/Token/ApiKey scheme,
// a credential-named key-value pair, a SOAP credential element) is removed whatever its shape, quoted or bare; a
// remembered secret is removed whatever its shape and in its encoded forms; a bare value is removed only
// when it has a real token shape (JWT, PEM block, hex digest, vendor prefix, or a 16+ character run with
// base64 symbols, scattered digits, or token casing). A bare name-shaped value (words joined by hyphens
// or underscores, such as prod-us-east-2026) is indistinguishable from a resource name and stays.
// A literal JSON escape (`\n`, `\r`, `\t`, `\b`, `\f`, `\/`, `\"`, `\uXXXX`) stands right before a header, a scheme,
// a URL, or a token in a doubly-encoded body (a gateway error whose field holds serialized JSON). Its last character is
// a word character for most of them, so `\b` and a "not preceded by a word character" lookbehind see no boundary there;
// every carrier and token opener of the pass therefore also starts right after one, and no token shape starts inside one.
const JSON_ESCAPE = String.raw`\\(?:u[0-9a-fA-F]{4}|[nrtbf/"])`;
const AFTER_JSON_ESCAPE = `(?<=${JSON_ESCAPE})`;
const OPENER_BOUNDARY = String.raw`(?:\b|${AFTER_JSON_ESCAPE})`;
const NOT_INSIDE_JSON_ESCAPE = String.raw`(?!(?<=\\)(?:u[0-9a-fA-F]{4}|[nrtbf/]))`;
const URL_IN_TEXT_PATTERN = new RegExp(String.raw`${OPENER_BOUNDARY}(https?:\/\/)(?:([^\s/?#@"'<>]+)@)?([^\s/?#"'<>]+)([^\s?#"'<>]*)(\?[^\s#"'<>]*)?(#[^\s"'<>]*)?`, "gi");
// A query pair standing without its URL (`?token=...`, `&sid=...`).
const BARE_QUERY_PAIR_PATTERN = /([?&][\w.~%-]+=)([^\s"'&#<>\\]+)/g;
// Header name to value: `: `, `="`, or the JSON-escaped `\":\"`.
const HEADER_SEPARATOR = String.raw`\\?["']?\s*[:=]\s*\\?["']?`;
// The next header on the same line (`; X-Api-Key: x`, `, Content-Type: x`, ` Accept: x`, a quoted or JSON-object
// name too): a cookie or header value ends before it, so that header keeps its name and gets its own carrier treatment.
const NEXT_HEADER_NAME = String.raw`\s*\{?\s*\\?["']?[A-Za-z][\w-]*\\?["']?\s*:`;
// The schemes that stand as carriers in prose (the ruling's list, including PagerDuty's REST API key
// scheme `Token token=<key>`) and the wider set recognized inside an Authorization header.
const PROSE_AUTH_SCHEMES = "bearer|basic|digest|token|apikey|api-key";
const HEADER_AUTH_SCHEMES = `${PROSE_AUTH_SCHEMES}|negotiate|ntlm|hmac|oauth|hoba|mutual|vapid|aws4-hmac-sha256|scram-sha-1|scram-sha-256`;
// A quote closes a value only when a delimiter or the end of the text follows it; a quote followed by a value
// character opens the next header's value instead, so the value it seemed to close was never terminated.
const CLOSING_QUOTE_BOUNDARY = String.raw`(?![\w/+=-])`;
// A quoted value, in double quotes (possibly JSON-escaped) or single quotes, on one line, ending at its closing
// quote even with `; Name:` inside. Quotes around a credential belong to its carrier: `Bearer "x"`, `sid='x'`,
// `--token "x"` carry x whatever its shape.
const QUOTED_VALUE = String.raw`(?:\\?"[^"\\\r\n]+\\?"|'[^'\r\n]+')${CLOSING_QUOTE_BOUNDARY}`;
// A value whose opening quote never closes: it runs to the next `;`, `,`, or space (where the header patterns
// apply the `Name:` cut) or to the end of the line, stray quotes included.
const UNTERMINATED_QUOTED_VALUE = String.raw`\\?["'][^\s<>,;\\]+`;
// One credential token (bare or quoted), or a parameter list such as Digest's `username="u", response="r"`
// (quotes possibly JSON-escaped or single) or PagerDuty's `token=k`.
const CREDENTIAL_TOKEN = String.raw`(?:${QUOTED_VALUE}|${UNTERMINATED_QUOTED_VALUE}|[^\s"'<>,;\\]+)`;
const CREDENTIAL_PARAMETER_VALUE = String.raw`(?:(?:\\?"[^"\\\r\n]*\\?"|'[^'\r\n]*')${CLOSING_QUOTE_BOUNDARY}|\\?["']?[^\s"',;<>\\]+)`;
const CREDENTIAL_PARAMETERS = String.raw`[\w-]+=${CREDENTIAL_PARAMETER_VALUE}(?:\s*[,;]\s*[\w-]+=${CREDENTIAL_PARAMETER_VALUE})*`;
// The whole value of an Authorization header: a scheme and its credential, or up to two tokens for an unknown scheme.
const AUTHORIZATION_HEADER_PATTERN = new RegExp(
  String.raw`${OPENER_BOUNDARY}((?:proxy-)?authorization)(${HEADER_SEPARATOR})(?:(?:${HEADER_AUTH_SCHEMES})\s+(?:${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN})|${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN}(?:\s+(?!${NEXT_HEADER_NAME})${CREDENTIAL_TOKEN})?)`,
  "gi",
);
// Cookie and Set-Cookie headers: every pair of the header value is a session credential. A pair's value may be
// quoted (`sid="x"`, `sid = 'x'`, JSON-escaped `sid=\"x\"`) and ends at its closing quote even with `; Name:`
// inside; a quote anywhere else closes the value, so the next header of a JSON headers object is not taken; an
// unquoted value, or one whose opening quote never closes, runs to the `;`, `,`, or space that begins the next
// header on the line, or to the end of the line.
const COOKIE_PAIR_VALUE = String.raw`(?<==\s*)(?:(?:\\?"[^"\\\r\n,;\s][^"\\\r\n]*\\?"|'[^'\r\n,;\s][^'\r\n]*')${CLOSING_QUOTE_BOUNDARY}|${UNTERMINATED_QUOTED_VALUE})`;
const COOKIE_HEADER_VALUE = String.raw`(?:[^\s"'<>\\;,]|[ \t;,](?!${NEXT_HEADER_NAME})|${COOKIE_PAIR_VALUE})+`;
const COOKIE_HEADER_PATTERN = new RegExp(String.raw`${OPENER_BOUNDARY}(set-cookie|cookie)(${HEADER_SEPARATOR})(${COOKIE_HEADER_VALUE})`, "gi");
// A scheme standing in prose (`Bearer x`, `Bearer "x"`, `Token token=x`, `ApiKey x`); a scheme word that is itself a
// header or field name (`X-Api-Key : x`) is left to the field rule.
const AUTH_SCHEME_PATTERN = new RegExp(String.raw`${OPENER_BOUNDARY}(${PROSE_AUTH_SCHEMES})(?!\s*[:=])\s+(${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN})`, "gi");
// What follows a scheme word in prose rather than as its credential: after a lowercase scheme, a word without
// digits (lowercase, Capitalized, camelCase with up to three humps, a short acronym, or an acronym-led word such
// as OAuth) or an environment variable name ("bearer of", "OAuth bearer token.", "access token (OAuth bearer
// token)", "JWT bearer (SF_CONSUMER_KEY,"); after a capitalized scheme, only the capitalized next word of a title
// ("Refresh Token Policy"). Wrapping punctuation belongs to the prose, so it is allowed around the word.
const PROSE_AFTER_LOWERCASE_SCHEME_PATTERN = /^\(?(?:[A-Z]?[a-z]+(?:[A-Z][a-z]+){0,3}|[A-Z]{2,5}(?:[a-z]+)?|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)[).:!?]*$/;
const PROSE_AFTER_CAPITALIZED_SCHEME_PATTERN = /^\(?[A-Z][a-z]+[).:!?]*$/;
const CREDENTIAL_PARAMETER_PATTERN = new RegExp(String.raw`([\w-]+=)${CREDENTIAL_PARAMETER_VALUE}`, "g");
// Credential-named assignments (`client_secret=x`, `client_secret = "x"`, `JSESSIONID=x`, `connect.sid='x'`, `--token=x`).
const SECRET_ASSIGNMENT_PATTERN = new RegExp(
  String.raw`(?:(?<![\w.-])|${AFTER_JSON_ESCAPE})([\w.-]*(?:sess|sid|token|secret|passw|passphrase|pwd|passcode|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|assertion|signature|auth|cookie|otp)[\w.-]*\s*=\s*)(${QUOTED_VALUE}|${UNTERMINATED_QUOTED_VALUE}|[^\s"'&;,<>\\]+)`,
  "gi",
);
// Credential-named fields and single-value credential headers (`x-api-key: x`, `"password": "x"`, `\"access_token\":\"x\"`).
const SECRET_FIELD_PATTERN = new RegExp(
  String.raw`(?:(?<![\w/.-])|${AFTER_JSON_ESCAPE})((?:[\w-]*(?:api[_-]?key|apikey|token|secret|passw|passphrase|credential|assertion|signature|private[_-]?key|access[_-]?key|authorization)[\w-]*|pwd|passcode|otp|sid|jsessionid|session|sessionid|session[_-]?id|cookie|set-cookie|x-auth|x-token|x-secret|auth)\\?["']?\s*:\s*\\?["']?)([^\s"'&;,<>\\]+(?:["'](?=[\w/+=-])[^\s"'&;,<>\\]*)*)`,
  "gi",
);
// SOAP and XML credential elements (`<sessionId>x</sessionId>`, `<urn:password>x</urn:password>`).
const CREDENTIAL_ELEMENT_PATTERN = /<((?:[\w.-]+:)?(?:session_?id|session|passw(?:or)?d|pwd|passcode|otp|token|access_?token|refresh_?token|id_?token|secret|client_?secret|api_?key|apikey|assertion|signature|credentials?|authorization|private_?key)[\w-]*)(\s[^>]*)?>([^<]*)<\/\1\s*>/gi;
// Command-line credential flags (`--token x`, `-password x`); the flag starts a word, so `access-token against` is prose.
const CLI_SECRET_FLAG_PATTERN = new RegExp(
  String.raw`(?:(?<![\w-])|${AFTER_JSON_ESCAPE})(--?(?:token|password|passwd|pwd|passcode|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|auth|bearer|session|cookie|sid|otp)\s+)(${QUOTED_VALUE}|${UNTERMINATED_QUOTED_VALUE}|[^\s"'&;,<>-][^\s"'&;,<>]*)`,
  "gi",
);
// Real token shapes, removed bare.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g;
const JWT_PATTERN = new RegExp(String.raw`${OPENER_BOUNDARY}eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`, "g");
const HEX_DIGEST_PATTERN = new RegExp(String.raw`(?:(?<![A-Za-z0-9])|${AFTER_JSON_ESCAPE})${NOT_INSIDE_JSON_ESCAPE}[0-9a-f]{32,}(?![A-Za-z0-9])`, "gi");
const VENDOR_TOKEN_PATTERN = new RegExp(String.raw`${OPENER_BOUNDARY}${NOT_INSIDE_JSON_ESCAPE}(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abopsre]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{20,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{30,}|dop_v1_[a-f0-9]{40,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|hvs\.[A-Za-z0-9_-]{20,}|shpat_[a-fA-F0-9]{32}|dckr_pat_[A-Za-z0-9_-]{20,}|lin_api_[A-Za-z0-9]{20,}|figd_[A-Za-z0-9_-]{20,}|u\+[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])`, "g");
// A run long enough to be a token; redactTokenRun decides by segment shape whether it is one. It may start right
// after `=` (`theme=<run>`, `x==<run>`): the pair rule has already replaced every credential-named pair by the time
// this rule runs, so a run still standing after `=` is under a non-credential name and is judged by its shape alone;
// the padding of a base64 run is taken on its right side.
const BARE_TOKEN_RUN_PATTERN = new RegExp(String.raw`(?:(?<![A-Za-z0-9+/_-])|${AFTER_JSON_ESCAPE})${NOT_INSIDE_JSON_ESCAPE}[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])`, "g");
// A segment that reads as a word: lowercase, UPPERCASE, Capitalized, or camelCase with up to six humps, each
// hump optionally led by a short acronym (enableCSRFOnPost, connectedAppOAuth) or closed by one
// (sessionTimeoutSAML), optionally followed by digits (oauth2, sha256, dev12345) or a version suffix
// (EngineProtectionV2, getDeviceControlPoliciesV2).
const WORD_SEGMENT_PATTERN = /^(?:[A-Z]+|[A-Z]?[a-z]+(?:[A-Z]{1,5}[a-z]+){0,6}(?:[A-Z]{2,5})?|[A-Z]{2,}[a-z]+(?:[A-Z]{1,5}[a-z]+){0,6}(?:[A-Z]{2,5})?)(?:V\d+|\d*)$/;
// A canonical UUID (8-4-4-4-12 hex) is a vendor identifier (a Falcon user uuid, an Anypoint organization or
// environment id), not a credential, so it stays bare; inside a carrier or when remembered it still goes.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Node fs error codes (ENOENT, EACCES, EISDIR); anything else on error.code is not echoed.
const FS_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
// The only part of a JSON.parse message that is taken; the rest quotes the source.
const JSON_POSITION_PATTERN = /at position (\d+)/;
const SERVICE_SNAPSHOT_FIELDS = [
  "id",
  "type",
  "summary",
  "name",
  "description",
  "status",
  "created_at",
  "updated_at",
  "html_url",
  "escalation_policy",
  "teams",
  "incident_urgency_rule",
  "support_hours",
  "acknowledgement_timeout",
  "auto_resolve_timeout",
  "alert_creation",
  "response_play",
  "last_incident_timestamp",
];
const INTEGRATION_SNAPSHOT_FIELDS = [
  "id",
  "type",
  "summary",
  "name",
  "html_url",
  "created_at",
  "vendor",
  "service",
  "email_incident_creation",
  "email_filter_mode",
  "email_parsing_fallback",
];
const INTEGRATION_SECRET_FIELDS = ["integration_key", "integration_email"];
const USER_SNAPSHOT_FIELDS = ["id", "type", "summary", "name", "email", "role", "created_via_sso", "invitation_sent", "billed", "time_zone", "job_title", "html_url"];
const CONTACT_METHOD_SNAPSHOT_FIELDS = ["id", "type", "label", "enabled", "blacklisted", "device_type"];
const NOTIFICATION_RULE_SNAPSHOT_FIELDS = ["id", "type", "urgency", "start_delay_in_minutes"];
const REFERENCE_FIELDS = ["id", "type", "summary"];
const WORKFLOW_SNAPSHOT_FIELDS = ["id", "type", "summary", "name", "description", "is_enabled", "created_at", "team"];
const CHANGE_EVENT_SNAPSHOT_FIELDS = ["id", "type", "summary", "source", "timestamp"];
const AUDIT_RECORD_SNAPSHOT_FIELDS = ["id", "execution_time", "action"];
const AUDIT_METHOD_SNAPSHOT_FIELDS = ["type", "truncated_token"];
const OAUTH_SCOPES = [
  "abilities.read",
  "users.read",
  "teams.read",
  "services.read",
  "escalation_policies.read",
  "schedules.read",
  "oncalls.read",
  "audit_records.read",
  "extensions.read",
  "webhook_subscriptions.read",
  "priorities.read",
  "incident_workflows.read",
  "change_events.read",
];

export type PagerdutyRegion = "us" | "eu";
export type PagerdutyAuthMode = "api_token" | "oauth_bearer" | "oauth_client_credentials";

export interface PagerdutyResolvedConfig {
  authMode: PagerdutyAuthMode;
  apiToken?: string;
  accessToken?: string;
  clientId?: string;
  clientSecret?: string;
  subdomain?: string;
  region: PagerdutyRegion;
  baseUrl: string;
  identityTokenUrl: string;
  fromEmail?: string;
  timeoutMs: number;
  sourceChain: string[];
}

export interface PagerdutyAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  /** Items returned by the probe; absent (never 0) when the surface was not readable. */
  count?: number;
  error?: string;
  /** HTTP status observed on the failed probe, when the failure was an HTTP response. */
  http_status?: number;
}

export interface PagerdutyAccessCheckResult {
  status: "healthy" | "limited";
  region: PagerdutyRegion;
  authMode: PagerdutyAuthMode;
  surfaces: PagerdutyAccessSurface[];
  missingPermissions: string[];
  notes: string[];
  recommendedNextStep: string;
}

export type PagerdutySeverity = "critical" | "high" | "medium" | "low" | "info";
export type PagerdutyFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface PagerdutyFinding {
  id: string;
  control: number;
  title: string;
  severity: PagerdutySeverity;
  status: PagerdutyFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface PagerdutyAssessmentResult {
  category: string;
  title: string;
  summary: JsonRecord;
  findings: PagerdutyFinding[];
  errors: string[];
}

export interface PagerdutyAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface Snapshot<T> {
  data: T;
  error?: string;
  /** HTTP status observed on the failed request, when the failure was an HTTP response. */
  status?: number;
  /** Path of the request that failed, taken from the request that was actually issued. */
  endpoint?: string;
  /**
   * Set when the reads behind this snapshot were never issued because the parent list they key on
   * was not read; names the parent. The snapshot also carries `error` so every consumer treats it
   * as unread rather than as a readable-but-empty dataset.
   */
  skipped?: string;
}

/**
 * Written to core_data (and carried inside analysis snapshots) in place of a list dataset that was
 * denied, errored, or never collected, so a bundle consumer cannot mistake a denial for an empty
 * inventory. A readable-but-empty dataset keeps its normal shape with an empty item list. A
 * dataset whose reads were never requested carries `status: null` and `endpoint: null` rather than
 * borrowing the parent's, and its error starts with "not requested:" and names the parent read.
 */
export interface NotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string | null;
  error: string;
}

export function notCollected(snapshot: Snapshot<unknown>): NotCollectedMarker | undefined {
  if (!snapshot.error) return undefined;
  if (snapshot.skipped) return { collected: false, status: null, endpoint: null, error: snapshot.error };
  return {
    collected: false,
    status: snapshot.status ?? requestStatus(snapshot.error) ?? null,
    endpoint: snapshot.endpoint ?? requestEndpoint(snapshot.error) ?? null,
    error: snapshot.error,
  };
}

/**
 * The snapshot of per-item reads (team members, schedule details, business service dependencies)
 * that were never issued because the parent list was not read. Its error names the parent so the
 * finding gates on the parent's failure and `notCollected` writes a marker instead of `{}` or `[]`.
 */
function skippedSnapshot<T>(fallback: T, dependent: string, parentEndpoint: string, parent: Snapshot<unknown>): Snapshot<T> {
  const reason = `the ${parentEndpoint} list was not read (${parent.error ?? "unknown error"}), so no ${dependent} were requested`;
  return { data: fallback, error: `not requested: ${reason}`, skipped: reason };
}

function coreDataValue<T>(snapshot: Snapshot<T>): T | NotCollectedMarker {
  return notCollected(snapshot) ?? snapshot.data;
}

export interface PagerdutyCollection {
  items: JsonRecord[];
  complete: boolean;
  total?: number;
  truncation?: string;
}

/**
 * How a classic (limit/offset) listing decides that the collection is exhausted.
 * "more_flag" trusts the documented `more` boolean. "short_page" is for endpoints such as
 * GET /change_events whose 200 schema declares no `more` or `total`, so a page shorter than
 * the requested limit is the only end signal and a full page means another page must be read.
 * A response that omits the `more` boolean falls back to the short-page rule in either mode, so a
 * full final page at the requested limit is recorded as incomplete instead of complete.
 */
export type PagerdutyListCompletion = "more_flag" | "short_page";

function pageHasMore(payload: JsonRecord, pageLength: number, requestLimit: number): boolean {
  if (typeof payload.more === "boolean") return payload.more;
  return pageLength >= requestLimit;
}

export interface PagerdutyCredentialScope {
  kind: "account" | "user" | "unknown";
  userId?: string;
  email?: string;
  role?: string;
  fullVisibility: boolean;
  note?: string;
}

export function emptyCollection(): PagerdutyCollection {
  return { items: [], complete: true };
}

export function collectionOf(items: JsonRecord[], overrides: Partial<PagerdutyCollection> = {}): PagerdutyCollection {
  return { items, complete: true, total: items.length, ...overrides };
}

type FrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig" | "irap" | "ismap";

interface ControlDefinition {
  control: number;
  title: string;
  severity: PagerdutySeverity;
  mappings: Record<FrameworkKey, string>;
}

const FRAMEWORK_LABELS: Record<FrameworkKey, string> = {
  fedramp: "FedRAMP",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis: "CIS",
  pci_dss: "PCI-DSS",
  disa_stig: "STIG",
  irap: "IRAP",
  ismap: "ISMAP",
};

const FRAMEWORK_KEYS: FrameworkKey[] = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "disa_stig", "irap", "ismap"];

function control(
  controlNumber: number,
  title: string,
  severity: PagerdutySeverity,
  mappings: [string, string, string, string, string, string, string, string],
): ControlDefinition {
  return {
    control: controlNumber,
    title,
    severity,
    mappings: {
      fedramp: mappings[0],
      cmmc: mappings[1],
      soc2: mappings[2],
      cis: mappings[3],
      pci_dss: mappings[4],
      disa_stig: mappings[5],
      irap: mappings[6],
      ismap: mappings[7],
    },
  };
}

export const PAGERDUTY_CONTROLS: ControlDefinition[] = [
  control(1, "SSO enforcement enabled for account", "critical", ["IA-2", "IA.L2-3.5.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "8.2.1"]),
  control(2, "User roles follow least privilege", "critical", ["AC-6(1)", "AC.L2-3.1.5", "CC6.3", "6.1", "7.1.1", "SRG-APP-000340", "ISM-1508", "8.1.2"]),
  control(3, "Owner role restricted to the account owner", "high", ["AC-6(5)", "AC.L2-3.1.5", "CC6.3", "6.2", "7.1.2", "SRG-APP-000340", "ISM-1508", "8.1.3"]),
  control(4, "Team-based access configured", "high", ["AC-3", "AC.L2-3.1.2", "CC6.1", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1"]),
  control(5, "All services have escalation policies assigned", "critical", ["IR-4", "IR.L2-3.6.1", "CC7.3", "17.1", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(6, "Escalation policies have multiple escalation levels", "high", ["IR-4(1)", "IR.L2-3.6.2", "CC7.3", "17.2", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.2"]),
  control(7, "Escalation policies do not terminate without notification", "high", ["IR-4", "IR.L2-3.6.1", "CC7.3", "17.1", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(8, "On-call schedules provide 24/7 coverage", "high", ["IR-7", "IR.L2-3.6.1", "CC7.3", "17.3", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.3"]),
  control(9, "On-call schedules have multiple participants", "medium", ["IR-7(1)", "IR.L2-3.6.2", "CC7.3", "17.3", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.3"]),
  control(10, "Incident response automation configured for services", "medium", ["IR-4(1)", "IR.L2-3.6.2", "CC7.4", "17.4", "12.10.6", "SRG-APP-000516", "ISM-0043", "16.1.4"]),
  control(11, "Audit logging is active and accessible", "high", ["AU-2", "AU.L2-3.3.1", "CC7.2", "8.1", "10.1", "SRG-APP-000089", "ISM-0580", "12.1.1"]),
  control(12, "Audit log retention meets compliance requirements", "medium", ["AU-11", "AU.L2-3.3.1", "CC7.2", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "12.1.2"]),
  control(13, "API keys are rotated", "high", ["IA-5(1)", "IA.L2-3.5.10", "CC6.1", "4.4", "8.2.4", "SRG-APP-000174", "ISM-1557", "8.2.4"]),
  control(14, "Webhook endpoints use HTTPS", "high", ["SC-8(1)", "SC.L2-3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0487", "10.1.1"]),
  control(15, "Webhook signatures verified", "medium", ["SC-8(1)", "SC.L2-3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0487", "10.1.1"]),
  control(16, "Integration permissions are scoped appropriately", "medium", ["AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1"]),
  control(17, "Notification rules configured for all users", "medium", ["IR-6", "IR.L2-3.6.1", "CC7.3", "17.5", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.5"]),
  control(18, "Contact methods verified for on-call users", "high", ["IR-7", "IR.L2-3.6.1", "CC7.3", "17.5", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.5"]),
  control(19, "Service urgency rules configured", "low", ["IR-4", "IR.L2-3.6.1", "CC7.3", "17.6", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(20, "Custom incident priorities defined", "low", ["IR-4", "IR.L2-3.6.1", "CC7.4", "17.6", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(21, "Service dependencies mapped for impact analysis", "medium", ["CM-8", "CM.L2-3.4.1", "CC3.1", "2.1", "2.4", "SRG-APP-000141", "ISM-1284", "6.1.1"]),
  control(22, "Acknowledgement timeouts configured on services", "medium", ["IR-4", "IR.L2-3.6.1", "CC7.3", "17.1", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(23, "Auto-resolve timeouts configured on services", "low", ["IR-4", "IR.L2-3.6.1", "CC7.3", "17.1", "12.10.1", "SRG-APP-000516", "ISM-0043", "16.1.1"]),
  control(24, "Analytics access restricted to appropriate roles", "medium", ["AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1"]),
  control(25, "Change events tracking enabled for services", "low", ["CM-3", "CM.L2-3.4.3", "CC8.1", "2.3", "6.4.5", "SRG-APP-000128", "ISM-1211", "6.2.1"]),
];

function controlDefinition(controlNumber: number): ControlDefinition {
  const definition = PAGERDUTY_CONTROLS.find((item) => item.control === controlNumber);
  if (!definition) throw new Error(`Unknown PagerDuty control ${controlNumber}`);
  return definition;
}

export function findingId(controlNumber: number): string {
  return `PD-${String(controlNumber).padStart(2, "0")}`;
}

function mappingsFor(definition: ControlDefinition): string[] {
  return FRAMEWORK_KEYS.map((key) => `${FRAMEWORK_LABELS[key]} ${definition.mappings[key]}`);
}

function finding(
  controlNumber: number,
  status: PagerdutyFindingStatus,
  summary: string,
  evidence?: JsonRecord,
  partialView: string[] = [],
): PagerdutyFinding {
  const definition = controlDefinition(controlNumber);
  const downgraded = status === "pass" && partialView.length > 0;
  return {
    id: findingId(controlNumber),
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status: downgraded ? "warn" : status,
    summary: downgraded
      ? `${summary} Downgraded from pass to warn because the inventory is partial: ${partialView.join("; ")}.`
      : summary,
    evidence: partialView.length > 0 ? { ...(evidence ?? {}), partial_view: partialView } : evidence,
    mappings: mappingsFor(definition),
  };
}

interface InventoryView {
  label: string;
  items: JsonRecord[];
  error?: string;
  readable: boolean;
  empty: boolean;
  complete: boolean;
  seen: number;
  total?: number;
  partial?: string;
}

function inventory(label: string, snapshot: Snapshot<PagerdutyCollection>): InventoryView {
  const collection = snapshot.data;
  const readable = !snapshot.error;
  const truncation = collection.truncation ?? "collection incomplete";
  const partial = readable && !collection.complete
    ? collection.total !== undefined
      ? `${label}: ${collection.items.length} of ${collection.total} seen (${truncation})`
      : `${label}: ${collection.items.length} seen of an unknown total (${truncation})`
    : undefined;
  return {
    label,
    items: collection.items,
    error: snapshot.error,
    readable,
    empty: readable && collection.items.length === 0,
    complete: readable && collection.complete,
    seen: collection.items.length,
    total: collection.total,
    partial,
  };
}

function partialNotes(scope: Snapshot<PagerdutyCredentialScope>, ...views: InventoryView[]): string[] {
  const notes = views.map((view) => view.partial).filter((note): note is string => Boolean(note));
  if (scope.error) {
    notes.push(`credential scope could not be determined (${scope.error})`);
  } else if (!scope.data.fullVisibility && scope.data.note) {
    notes.push(scope.data.note);
  }
  return notes;
}

function unreadable(view: InventoryView, evidenceToCollect: string): string {
  return `${view.label} could not be read (${view.error ?? "no response"}). ${evidenceToCollect}`;
}

type InventoryState = "complete" | "partial" | "unread";

function inventoryState(view: InventoryView): InventoryState {
  if (!view.readable) return "unread";
  if (!view.complete) return "partial";
  return "complete";
}

function describeInventory(view: InventoryView): string {
  const state = inventoryState(view);
  switch (state) {
    case "unread":
      return `${view.label}: unread (${view.error ?? "no response"})`;
    case "partial":
      return view.partial ?? `${view.label}: partial`;
    case "complete":
      return `${view.label}: complete (${view.seen} seen)`;
    default: {
      const exhaustive: never = state;
      throw new Error(`Unhandled inventory state ${String(exhaustive)}`);
    }
  }
}

function isAbsenceValue(value: unknown): boolean {
  if (value === 0) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value as object).length === 0;
  return false;
}

/**
 * A count, list, flag, or map derived from one or more inventories. It renders null when any source
 * inventory was not read, and null when a source is partial and the value would assert absence
 * (0, [], {}), because a partly read inventory cannot prove that nothing exists.
 */
function derived<T>(value: T, ...views: InventoryView[]): T | null {
  if (views.some((view) => !view.readable)) return null;
  if (views.some((view) => !view.complete) && isAbsenceValue(value)) return null;
  return value;
}

/** The number of items read is meaningful whenever the inventory was read at all; it is null when it was not. */
function seenCount(view: InventoryView): number | null {
  return view.readable ? view.seen : null;
}

function totalCount(view: InventoryView): number | null {
  return view.readable ? view.total ?? null : null;
}

function inventoriesComplete(views: InventoryView[]): boolean {
  return views.every((view) => view.readable && view.complete);
}

function inventoryKey(view: InventoryView): string {
  return view.label.replace(/[^a-z0-9]+/gi, "_").toLowerCase();
}

function inventoryStatus(...views: InventoryView[]): Record<string, string> {
  return Object.fromEntries(views.map((view) => [inventoryKey(view), describeInventory(view)]));
}

/**
 * Lists that name principals (users, tokens, accounts) as holding or lacking a property are emitted only
 * from inventories read to completion. When any proving inventory is denied or partial, every list
 * renders null and `principals_withheld` names the inventory that was not fully read, so no principal
 * is asserted as compliant or non-compliant from a set that may exclude the evidence about them.
 */
function principalEvidence(lists: Record<string, unknown[]>, ...views: InventoryView[]): JsonRecord {
  const complete = inventoriesComplete(views);
  const evidence: JsonRecord = {};
  for (const [key, labels] of Object.entries(lists)) evidence[key] = complete ? labels : null;
  evidence.principals_withheld = complete
    ? null
    : views.filter((view) => !(view.readable && view.complete)).map(describeInventory).join("; ");
  return evidence;
}

/** A count of principals holding or lacking a property, unknown unless every proving inventory was fully read. */
function principalCount(value: number, ...views: InventoryView[]): number | null {
  return inventoriesComplete(views) ? value : null;
}

function requestEndpoint(error: string | undefined): string | undefined {
  const match = error?.match(/ for (\/[^\s:]+)/) ?? error?.match(/: (\/[^\s:]+)$/);
  return match ? match[1] : undefined;
}

/** Collection state of a snapshot that is not a paged collection (a single object, a map, or a plain list). */
function describeSnapshot(label: string, snapshot: Snapshot<unknown>, seen: number, truncated: string[] = []): string {
  if (snapshot.skipped) return `${label}: not requested (${snapshot.skipped})`;
  if (snapshot.error) return `${label}: unread (${snapshot.error})`;
  if (truncated.length > 0) return `${label}: partial (${truncated.join("; ")})`;
  return `${label}: complete (${seen} seen)`;
}

function countSeen(view: InventoryView): string {
  return view.total !== undefined && view.total !== view.seen
    ? `${view.seen} ${view.label} (of ${view.total} total)`
    : `${view.seen} ${view.label}`;
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

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function isSecretKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[-_\s]/g, "");
  if (SECRET_KEY_EXCEPTIONS.has(normalized)) return false;
  return SECRET_KEY_PATTERN.test(normalized);
}

function redactUrlQuery(text: string): string {
  if (!/^https?:\/\/[^?]+\?/i.test(text)) return text;
  return text.replace(/([?&])([^=&#]+)=([^&#]*)/g, (match, separator: string, key: string) => (
    isSecretKey(key) ? `${separator}${key}=${REDACTED}` : match
  ));
}

function isSecretNamedPair(object: JsonRecord): boolean {
  if (!("value" in object)) return false;
  const name = asString(object.name) ?? asString(object.key);
  return name !== undefined && isSecretKey(name);
}

function redactedValue(entry: unknown): unknown {
  return entry === null || entry === undefined || typeof entry === "boolean" ? entry : REDACTED;
}

/**
 * Deny-list pass applied to every captured snapshot: any key that names a secret, any
 * {name, value} pair whose name does, and any secret-named query parameter inside a URL string
 * is replaced with the redaction marker. The allowlist projections below remove the fields the
 * vendor documents as credential carriers; this pass covers free-form objects such as change
 * event custom_details and workflow action inputs. A value nested deeper than MAX_REDACTION_DEPTH
 * (container or leaf) is replaced by the marker rather than passed through.
 */
export function redactSnapshot(value: unknown, depth = 0): unknown {
  if (depth > MAX_REDACTION_DEPTH) return REDACTED;
  if (typeof value === "string") return scrubDataText(redactUrlQuery(value));
  if (Array.isArray(value)) return value.map((item) => redactSnapshot(item, depth + 1));
  const object = asObject(value);
  if (!object) return value;
  const secretPair = isSecretNamedPair(object);
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    output[key] = isSecretKey(key) || (secretPair && key === "value") ? redactedValue(entry) : redactSnapshot(entry, depth + 1);
  }
  return output;
}

/**
 * Webhook destinations carry their secret in the path (Slack and Teams incoming webhooks) or the
 * query string, so a stored URL keeps only the scheme and host; anything beyond the host is
 * replaced with the marker so the reduction is visible. The scheme is all PD-14 needs.
 */
export function reduceUrl(value: unknown): unknown {
  const text = asString(value);
  if (text === undefined) return value;
  try {
    const url = new URL(text);
    const detailed = url.pathname !== "/" || url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "";
    return `${url.protocol}//${url.host}${detailed ? `/${REDACTED}` : ""}`;
  } catch {
    return REDACTED;
  }
}

function pickFields(record: JsonRecord, fields: string[]): JsonRecord {
  const output: JsonRecord = {};
  for (const field of fields) {
    if (field in record) output[field] = record[field];
  }
  return output;
}

function projectArray(value: unknown, project: (item: JsonRecord) => JsonRecord): unknown {
  return Array.isArray(value) ? asRecords(value).map(project) : value;
}

function projectReference(value: unknown): unknown {
  const record = asObject(value);
  return record ? pickFields(record, REFERENCE_FIELDS) : value;
}

function projectIntegration(integration: JsonRecord): JsonRecord {
  const output = pickFields(integration, INTEGRATION_SNAPSHOT_FIELDS);
  for (const field of INTEGRATION_SECRET_FIELDS) {
    if (field in integration) output[field] = REDACTED;
  }
  return output;
}

export function projectService(service: JsonRecord): JsonRecord {
  const output = pickFields(service, SERVICE_SNAPSHOT_FIELDS);
  if ("integrations" in service) output.integrations = projectArray(service.integrations, projectIntegration);
  return output;
}

export function projectUser(user: JsonRecord): JsonRecord {
  const output = pickFields(user, USER_SNAPSHOT_FIELDS);
  if ("teams" in user) output.teams = projectArray(user.teams, (team) => pickFields(team, REFERENCE_FIELDS));
  if ("contact_methods" in user) {
    output.contact_methods = projectArray(user.contact_methods, (method) => pickFields(method, CONTACT_METHOD_SNAPSHOT_FIELDS));
  }
  if ("notification_rules" in user) {
    output.notification_rules = projectArray(user.notification_rules, (rule) => {
      const projected = pickFields(rule, NOTIFICATION_RULE_SNAPSHOT_FIELDS);
      if ("contact_method" in rule) projected.contact_method = projectReference(rule.contact_method);
      return projected;
    });
  }
  return output;
}

export function projectExtension(extension: JsonRecord): JsonRecord {
  const output: JsonRecord = { ...extension };
  if ("config" in extension) output.config = REDACTED;
  if ("endpoint_url" in extension) output.endpoint_url = reduceUrl(extension.endpoint_url);
  return output;
}

export function projectWebhookSubscription(subscription: JsonRecord): JsonRecord {
  const delivery = asObject(subscription.delivery_method);
  if (!delivery) return subscription;
  const output: JsonRecord = { ...delivery };
  if ("url" in delivery) output.url = reduceUrl(delivery.url);
  if ("custom_headers" in delivery) {
    output.custom_headers = projectArray(delivery.custom_headers, (header) => ({ name: asString(header.name) ?? "unnamed", value: REDACTED }));
  }
  return { ...subscription, delivery_method: output };
}

export function projectIncidentWorkflow(workflow: JsonRecord): JsonRecord {
  const output = pickFields(workflow, WORKFLOW_SNAPSHOT_FIELDS);
  if ("team" in workflow) output.team = projectReference(workflow.team);
  return output;
}

export function projectChangeEvent(event: JsonRecord): JsonRecord {
  const output = pickFields(event, CHANGE_EVENT_SNAPSHOT_FIELDS);
  if ("services" in event) output.services = projectArray(event.services, (service) => pickFields(service, REFERENCE_FIELDS));
  return output;
}

export function projectAuditRecord(record: JsonRecord): JsonRecord {
  const output = pickFields(record, AUDIT_RECORD_SNAPSHOT_FIELDS);
  const method = asObject(record.method);
  if (method) output.method = pickFields(method, AUDIT_METHOD_SNAPSHOT_FIELDS);
  if ("actors" in record) output.actors = projectArray(record.actors, (actor) => pickFields(actor, REFERENCE_FIELDS));
  if ("root_resource" in record) output.root_resource = projectReference(record.root_resource);
  return output;
}

function projectCollection(collection: PagerdutyCollection, project: (item: JsonRecord) => JsonRecord): PagerdutyCollection {
  return { ...collection, items: collection.items.map(project) };
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

function isoDate(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function daysAgo(now: Date, days: number): Date {
  return new Date(now.getTime() - days * DAY_MS);
}

function daysAhead(now: Date, days: number): Date {
  return new Date(now.getTime() + days * DAY_MS);
}

function parseDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "pagerduty";
}

/**
 * The single point where a thrown error becomes a recorded string (snapshot errors, access-check
 * surfaces, errors arrays, _errors.log, tool error results). It re-applies the redaction pass so a
 * message built outside PagerdutyRequestError (a transport error, a timeout, a JSON parse failure)
 * cannot bypass it.
 */
function errorMessage(error: unknown): string {
  return scrubSecretText(error instanceof Error ? error.message : String(error));
}

/**
 * The unanchored redaction pass applied to every error string (once in PagerdutyRequestError, again
 * at errorMessage): every secret any client in this process has seen, in every form it can take in
 * an echoed body, then the carriers (URL userinfo, query strings, and fragments anywhere in the text,
 * Authorization and cookie headers, auth schemes in prose including PagerDuty's `Token token=`,
 * credential-named assignments, fields, and elements, command-line flags), then the bare token shapes
 * (PEM blocks, JWTs, hex digests, vendor prefixes, and long runs with base64 symbols, scattered
 * digits, or token casing).
 */
function scrubSecretText(text: string, secrets: Iterable<string | undefined> = []): string {
  let scrubbed = text;
  for (const secret of [...secrets, ...KNOWN_SECRETS]) {
    if (!secret || secret.length < MIN_REMEMBERED_SECRET_LENGTH) continue;
    for (const form of secretForms(secret)) scrubbed = scrubbed.split(form).join(REDACTED);
  }
  return scrubBareTokens(scrubCarriers(scrubbed));
}

/**
 * The carrier stage of the pass: URL userinfo, query strings, and fragments anywhere in the text,
 * Authorization and cookie headers, credential elements, JWTs and PEM blocks, auth schemes in prose,
 * credential-named assignments, fields, and command-line flags. It removes a value by the company it
 * keeps, never by its shape alone.
 */
function scrubCarriers(text: string): string {
  return text
    .replace(PEM_BLOCK_PATTERN, REDACTED)
    .replace(URL_IN_TEXT_PATTERN, (_match, scheme: string, userinfo: string | undefined, host: string, path: string, query?: string, fragment?: string) =>
      `${scheme}${userinfo ? `${REDACTED}@` : ""}${host}${path}${query ? `?${REDACTED}` : ""}${fragment ? `#${REDACTED}` : ""}`)
    .replace(BARE_QUERY_PAIR_PATTERN, (_match, pair: string) => `${pair}${REDACTED}`)
    .replace(AUTHORIZATION_HEADER_PATTERN, (_match, header: string, separator: string) => `${header}${separator}${REDACTED}`)
    .replace(COOKIE_HEADER_PATTERN, (_match, header: string, separator: string) => `${header}${separator}${REDACTED}`)
    .replace(CREDENTIAL_ELEMENT_PATTERN, (_match, element: string, attributes: string | undefined) => `<${element}${attributes ?? ""}>${REDACTED}</${element}>`)
    .replace(JWT_PATTERN, REDACTED)
    .replace(AUTH_SCHEME_PATTERN, (match: string, scheme: string, credential: string) =>
      (isProseAfterScheme(scheme, credential) ? match : `${scheme} ${redactCredentialParameters(credential)}`))
    .replace(SECRET_ASSIGNMENT_PATTERN, (_match, assignment: string) => `${assignment}${REDACTED}`)
    .replace(SECRET_FIELD_PATTERN, (_match, field: string) => `${field}${REDACTED}`)
    .replace(CLI_SECRET_FLAG_PATTERN, (_match, flag: string) => `${flag}${REDACTED}`);
}

/** The bare-token stage: real token shapes removed whatever their company (vendor prefixes, hex digests, long runs with base64 symbols, scattered digits, or token casing). */
function scrubBareTokens(text: string): string {
  return text
    .replace(VENDOR_TOKEN_PATTERN, REDACTED)
    .replace(HEX_DIGEST_PATTERN, REDACTED)
    .replace(BARE_TOKEN_RUN_PATTERN, redactTokenRun);
}

/** Every secret any client in this process has seen, in every form it can take in a text. */
function scrubRememberedSecrets(text: string): string {
  let scrubbed = text;
  for (const secret of KNOWN_SECRETS) {
    for (const form of secretForms(secret)) scrubbed = scrubbed.split(form).join(REDACTED);
  }
  return scrubbed;
}

/**
 * The data-side pass (rule 9, data-side carrier class) for every string a snapshot, evidence list,
 * summary, core_data file, or tool payload keeps from an API response: the remembered secrets in every
 * form, then the carrier stage (which takes JWTs and PEM blocks), then the vendor-prefixed token shapes
 * (`sk_live_`, `xoxb-`, `ghp_`, `AKIA`, and the rest of VENDOR_TOKEN_PATTERN), unambiguous credential
 * shapes with no identifier collision. It has no generic bare-run stage, so prose identifiers (a UUID, a
 * sys_id, a name such as prod-us-east-2026) stay while a header line, URL credential, assignment,
 * configured secret, or vendor token embedded in a description, name, or note goes.
 */
function scrubDataText(text: string): string {
  return scrubCarriers(scrubRememberedSecrets(text)).replace(VENDOR_TOKEN_PATTERN, REDACTED);
}

/** A scheme word standing in prose ("bearer of", "OAuth bearer token.", "Refresh Token Policy") rather than carrying a credential. */
function isProseAfterScheme(scheme: string, credential: string): boolean {
  return /^[a-z]+$/.test(scheme)
    ? PROSE_AFTER_LOWERCASE_SCHEME_PATTERN.test(credential)
    : PROSE_AFTER_CAPITALIZED_SCHEME_PATTERN.test(credential);
}

/** A parameter list (`token=k`, `username="u", response="r"`) keeps its parameter names; a single credential is replaced whole. */
function redactCredentialParameters(credential: string): string {
  return /^[\w-]+=/.test(credential) ? credential.replace(CREDENTIAL_PARAMETER_PATTERN, (_match, name: string) => `${name}${REDACTED}`) : REDACTED;
}

/** The raw, base64, base64url, URL-encoded, and JSON-escaped forms of a secret, so an encoded echo is caught too. */
function secretForms(secret: string): string[] {
  let forms = SECRET_FORMS.get(secret);
  if (!forms) {
    const bytes = Buffer.from(secret, "utf8");
    const base64 = bytes.toString("base64");
    const urlEncoded = encodeURIComponent(secret);
    forms = [...new Set([
      secret,
      base64,
      base64.replace(/=+$/, ""),
      bytes.toString("base64url"),
      urlEncoded,
      urlEncoded.replace(/%20/g, "+"),
      urlEncoded.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase()),
      JSON.stringify(secret).slice(1, -1),
    ])].filter((form) => form.length >= MIN_REMEMBERED_SECRET_LENGTH);
    SECRET_FORMS.set(secret, forms);
  }
  return forms;
}

/**
 * A run reads as a token when any hyphen- or underscore-separated segment is neither a word, a number, nor
 * a short abbreviation; a canonical UUID is an identifier and never reads as one.
 */
function looksLikeToken(value: string): boolean {
  if (UUID_PATTERN.test(value)) return false;
  return value.split(/[-_]+/).some((segment) =>
    segment.length > 0 && !/^\d+$/.test(segment) && !WORD_SEGMENT_PATTERN.test(segment) && !(segment.length < 8 && /^[A-Za-z0-9]+$/.test(segment)));
}

/** Base64 symbols mark a token; otherwise a run without slashes is judged whole and a path piece by piece, keeping its word-like skeleton. */
function redactTokenRun(run: string): string {
  if (run.includes("+") || run.endsWith("=")) return REDACTED;
  if (!run.includes("/")) return looksLikeToken(run) ? REDACTED : run;
  return run.split("/").map((piece) => (looksLikeToken(piece) ? REDACTED : piece)).join("/");
}

function rememberSecrets(...values: Array<string | undefined>): void {
  for (const value of values) {
    if (value && value.length >= MIN_REMEMBERED_SECRET_LENGTH) KNOWN_SECRETS.add(value);
  }
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

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<{ outputDir: string; zipPath: string }> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-10"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    const zipCandidate = resolveSecureOutputPath(root, `${preferredName}${suffix}.zip`);
    if (!existsSync(candidate) && !existsSync(zipCandidate)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return { outputDir: candidate, zipPath: zipCandidate };
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

/**
 * Thrown by the config loader. The message is fixed text carrying only the path, the fs error code,
 * and the line: neither Node's fs message (which quotes its own wording and path) nor V8's
 * JSON.parse message (which quotes a window of the source, or the whole source when it is short)
 * is ever interpolated.
 */
export class PagerdutyConfigFileError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "PagerdutyConfigFileError";
    this.code = code;
  }
}

/** Read step of the config loader: any failure becomes fixed text with the validated fs code. */
function readConfigFileText(pathname: string): string {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const rawCode = (error as { code?: unknown } | null)?.code;
    const code = typeof rawCode === "string" && FS_ERROR_CODE_PATTERN.test(rawCode) ? rawCode : undefined;
    throw new PagerdutyConfigFileError(`Unable to read PagerDuty config file ${pathname}${code ? ` (${code})` : ""}`, code ?? "EUNKNOWN");
  }
}

/**
 * Parse step of the config loader: every thrown value is caught and only a position taken through
 * the strict `at position N` pattern is kept, converted to the line it falls on.
 */
function parseConfigFileJson(pathname: string, text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const position = error instanceof Error ? JSON_POSITION_PATTERN.exec(error.message) : null;
    const line = position ? text.slice(0, Number(position[1])).split("\n").length : undefined;
    throw new PagerdutyConfigFileError(`Unable to parse PagerDuty config file: invalid JSON in ${pathname}${line ? ` at line ${line}` : ""}`, "INVALID_JSON");
  }
}

/**
 * Loads the config file. The default location is skipped when absent; an explicit path that cannot
 * be read fails with the fixed-text read error (ENOENT included).
 */
function readConfigFile(pathname: string, explicit: boolean): JsonRecord {
  if (!explicit && !existsSync(pathname)) return {};
  return asObject(parseConfigFileJson(pathname, readConfigFileText(pathname))) ?? {};
}

function normalizeRegion(value: string | undefined): PagerdutyRegion | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === "us" || normalized === "eu") return normalized;
  throw new Error(`Unsupported PagerDuty service region "${value}". Use "us" or "eu".`);
}

function regionFromBaseUrl(baseUrl: string): PagerdutyRegion {
  return /\.eu\.pagerduty\.com$/i.test(new URL(baseUrl).hostname) ? "eu" : "us";
}

function baseUrlForRegion(region: PagerdutyRegion): string {
  switch (region) {
    case "us":
      return US_BASE_URL;
    case "eu":
      return EU_BASE_URL;
    default: {
      const exhaustive: never = region;
      throw new Error(`Unhandled PagerDuty region ${String(exhaustive)}`);
    }
  }
}

export function resolvePagerdutyConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): PagerdutyResolvedConfig {
  const explicitConfigPath = asString(input.config_file) ?? asString(env.PAGERDUTY_CONFIG_FILE);
  const configPath = explicitConfigPath ?? join(homedir(), DEFAULT_CONFIG_FILE);
  const file = readConfigFile(configPath, explicitConfigPath !== undefined);
  const sourceChain: string[] = [];

  const pick = (argKeys: string[], envKeys: string[], fileKeys: string[], label: string): string | undefined => {
    for (const key of argKeys) {
      const value = asString(input[key]);
      if (value) {
        sourceChain.push(`arguments-${label}`);
        return value;
      }
    }
    for (const key of envKeys) {
      const value = asString(env[key]);
      if (value) {
        sourceChain.push(`environment-${label}`);
        return value;
      }
    }
    for (const key of fileKeys) {
      const value = asString(file[key]);
      if (value) {
        sourceChain.push(`config-file-${label}`);
        return value;
      }
    }
    return undefined;
  };

  const apiToken = pick(
    ["api_token", "api_key", "token"],
    ["PAGERDUTY_API_TOKEN", "PAGERDUTY_API_KEY", "PAGERDUTY_TOKEN", "PD_API_KEY"],
    ["api_token", "api_key", "token"],
    "api-token",
  );
  const accessToken = pick(
    ["access_token"],
    ["PAGERDUTY_ACCESS_TOKEN", "PAGERDUTY_OAUTH_TOKEN"],
    ["access_token"],
    "access-token",
  );
  const clientId = pick(["client_id"], ["PAGERDUTY_CLIENT_ID"], ["client_id"], "client-id");
  const clientSecret = pick(["client_secret"], ["PAGERDUTY_CLIENT_SECRET"], ["client_secret"], "client-secret");
  const subdomain = pick(["subdomain"], ["PAGERDUTY_SUBDOMAIN", "PAGERDUTY_ACCOUNT_SUBDOMAIN"], ["subdomain"], "subdomain");
  const fromEmail = pick(["from_email", "email"], ["PAGERDUTY_USER_EMAIL", "PAGERDUTY_FROM_EMAIL"], ["from_email", "email"], "from-email");
  const explicitRegion = normalizeRegion(pick(["region"], ["PAGERDUTY_REGION", "PAGERDUTY_SERVICE_REGION"], ["region"], "region"));
  const explicitBaseUrl = pick(["base_url"], ["PAGERDUTY_BASE_URL", "PAGERDUTY_API_BASE_URL"], ["base_url"], "base-url");

  let authMode: PagerdutyAuthMode;
  if (apiToken) {
    authMode = "api_token";
  } else if (accessToken) {
    authMode = "oauth_bearer";
  } else if (clientId && clientSecret && subdomain) {
    authMode = "oauth_client_credentials";
  } else {
    throw new Error(
      "PagerDuty credentials are required: set PAGERDUTY_API_TOKEN (account or user REST API key), PAGERDUTY_ACCESS_TOKEN (OAuth bearer token), or PAGERDUTY_CLIENT_ID, PAGERDUTY_CLIENT_SECRET, and PAGERDUTY_SUBDOMAIN (Scoped OAuth app credentials).",
    );
  }

  const baseUrl = normalizeBaseUrl(explicitBaseUrl ?? baseUrlForRegion(explicitRegion ?? "us"));
  const region = explicitRegion ?? regionFromBaseUrl(baseUrl);
  const timeoutMs = parseTimeoutSeconds(
    asNumber(input.timeout_seconds) ?? asNumber(env.PAGERDUTY_TIMEOUT) ?? asNumber(file.timeout_seconds),
  );

  return {
    authMode,
    apiToken,
    accessToken,
    clientId,
    clientSecret,
    subdomain,
    region,
    baseUrl,
    identityTokenUrl: normalizeBaseUrl(asString(input.identity_token_url) ?? asString(env.PAGERDUTY_IDENTITY_TOKEN_URL) ?? IDENTITY_TOKEN_URL),
    fromEmail,
    timeoutMs,
    sourceChain: [...new Set(sourceChain)],
  };
}

/** PagerDuty's documented error object (`error.message`, `error.code`, `error.errors[]`); nothing else in a body is echoed. */
function pagerdutyErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  const error = asObject(object?.error);
  if (!error) return undefined;
  const parts = [
    asString(error.message),
    asString(error.code) ? `code ${asString(error.code)}` : undefined,
    ...asArray(error.errors).map((item) => asString(item)),
  ].filter((item): item is string => Boolean(item));
  return parts.length > 0 ? parts.join("; ") : undefined;
}

/**
 * An error body that is not JSON (a proxy or WAF page, whatever its content type claims), or JSON
 * without PagerDuty's documented error fields, is described by status and length only; its text is
 * never copied into an error string because those strings land in findings and the bundle's error log.
 */
function describeOpaqueBody(response: Response, rawText: string, parsedJson: boolean): string | undefined {
  if (rawText.length === 0) return undefined;
  const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() || "unknown content type";
  const bytes = Buffer.byteLength(rawText, "utf8");
  return parsedJson
    ? `JSON body without documented error fields (${contentType}, ${bytes} bytes)`
    : `non-JSON body (${contentType}, ${bytes} bytes)`;
}

/** Parses a response body as a JSON object; undefined when it is not JSON, so the body is never echoed. */
function parseJsonBody(rawText: string): JsonRecord | undefined {
  if (rawText.length === 0) return undefined;
  try {
    return asObject(JSON.parse(rawText));
  } catch {
    return undefined;
  }
}

function requestPath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return "the requested path";
  }
}

/**
 * The one error class the client throws for HTTP failures. The message is built from the status,
 * the request path, and either PagerDuty's documented error fields or a status-and-length note for
 * any other body; the constructor runs the redaction pass over it regardless of how it was built.
 */
export class PagerdutyRequestError extends Error {
  readonly status: number;
  /** The request path that produced the response, without the query string. */
  readonly path?: string;

  constructor(status: number, message: string, path?: string) {
    super(scrubSecretText(message));
    this.name = "PagerdutyRequestError";
    this.status = status;
    this.path = path;
  }
}

export class PagerdutyApiClient {
  private readonly config: PagerdutyResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxRetries: number;
  private bearerToken?: string;
  private bearerExpiresAt = 0;

  constructor(
    config: PagerdutyResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
      sleep?: (ms: number) => Promise<void>;
      maxRetries?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.maxRetries = clampNumber(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
    if (config.accessToken) {
      this.bearerToken = config.accessToken;
      this.bearerExpiresAt = Number.MAX_SAFE_INTEGER;
    }
    rememberSecrets(config.apiToken, config.accessToken, config.clientSecret);
  }

  getResolvedConfig(): PagerdutyResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  /** The redaction pass with this client's own credentials (including short ones) removed first. */
  redact(text: string): string {
    let redacted = text;
    for (const secret of [this.config.apiToken, this.config.accessToken, this.config.clientSecret, this.bearerToken]) {
      if (secret && secret.length > 0) redacted = redacted.split(secret).join(REDACTED);
    }
    return scrubSecretText(redacted);
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) url.searchParams.append(key, String(item));
        continue;
      }
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async fetchOAuthToken(): Promise<string> {
    if (!this.config.clientId || !this.config.clientSecret || !this.config.subdomain) {
      throw new Error("PagerDuty Scoped OAuth client credentials are incomplete.");
    }
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: [`as_account-${this.config.region}.${this.config.subdomain}`, ...OAUTH_SCOPES].join(" "),
    });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await this.fetchImpl(this.config.identityTokenUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: body.toString(),
        signal: controller.signal,
      });
      const rawText = await response.text();
      const parsed = parseJsonBody(rawText);
      const payload = parsed ?? {};
      if (!response.ok) {
        // RFC 6749 error and error_description are the documented fields; anything else is described by shape.
        const detail = asString(payload.error_description) ?? asString(payload.error) ?? describeOpaqueBody(response, rawText, parsed !== undefined) ?? "empty response body";
        throw new PagerdutyRequestError(
          response.status,
          this.redact(`PagerDuty OAuth token request failed (${response.status}) for ${requestPath(this.config.identityTokenUrl)}: ${detail}`),
          requestPath(this.config.identityTokenUrl),
        );
      }
      const token = asString(payload.access_token);
      if (!token) throw new Error(`PagerDuty OAuth token response did not include access_token (${describeOpaqueBody(response, rawText, parsed !== undefined) ?? "empty response body"}).`);
      const expiresIn = asNumber(payload.expires_in) ?? 3600;
      this.bearerToken = token;
      this.bearerExpiresAt = this.now().getTime() + Math.max((expiresIn - 60) * 1000, 60_000);
      rememberSecrets(token);
      return token;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async authorizationHeader(): Promise<string> {
    switch (this.config.authMode) {
      case "api_token":
        return `Token token=${this.config.apiToken}`;
      case "oauth_bearer":
        return `Bearer ${this.config.accessToken}`;
      case "oauth_client_credentials": {
        if (this.bearerToken && this.now().getTime() < this.bearerExpiresAt) {
          return `Bearer ${this.bearerToken}`;
        }
        return `Bearer ${await this.fetchOAuthToken()}`;
      }
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unhandled PagerDuty auth mode ${String(exhaustive)}`);
      }
    }
  }

  private retryDelayMs(response: Response, attempt: number): number {
    const resetSeconds = asNumber(response.headers.get("ratelimit-reset"))
      ?? asNumber(response.headers.get("retry-after"));
    const backoff = Math.min(1000 * 2 ** attempt, MAX_RETRY_DELAY_MS);
    if (resetSeconds !== undefined && resetSeconds >= 0) {
      return Math.min(Math.max(resetSeconds * 1000, 250), MAX_RETRY_DELAY_MS);
    }
    return backoff;
  }

  private async fetchOnce(url: string): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const headers: Record<string, string> = {
        accept: ACCEPT_HEADER,
        authorization: await this.authorizationHeader(),
      };
      if (this.config.fromEmail) headers.from = this.config.fromEmail;
      return await this.fetchImpl(url, { method: "GET", headers, signal: controller.signal });
    } catch (error) {
      // A token exchange failure is already a PagerdutyRequestError carrying its status and path.
      if (error instanceof PagerdutyRequestError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`PagerDuty request timed out after ${this.config.timeoutMs}ms: ${requestPath(url)}`);
      }
      throw new Error(this.redact(errorMessage(error)));
    } finally {
      clearTimeout(timeout);
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path, query);
    for (let attempt = 0; ; attempt += 1) {
      const response = await this.fetchOnce(url);
      const retryable = response.status === 429 || response.status >= 500;
      if (retryable && attempt < this.maxRetries) {
        await this.sleep(this.retryDelayMs(response, attempt));
        continue;
      }
      const rawText = await response.text();
      const parsed = parseJsonBody(rawText);
      const payload: JsonRecord = parsed ?? {};
      if (!response.ok) {
        const detail = pagerdutyErrorSummary(payload) ?? describeOpaqueBody(response, rawText, parsed !== undefined);
        throw new PagerdutyRequestError(
          response.status,
          this.redact(`PagerDuty request failed (${response.status} ${response.statusText}) for ${path}${detail ? `: ${detail}` : ""}`),
          path,
        );
      }
      return payload;
    }
  }

  async list(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number; completion?: PagerdutyListCompletion } = {},
  ): Promise<PagerdutyCollection> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, CLASSIC_PAGINATION_CAP);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const completion = options.completion ?? "more_flag";
    const items: JsonRecord[] = [];
    let offset = 0;
    let total: number | undefined;
    let more = false;
    let flagDeclared = true;
    let stall: string | undefined;

    while (items.length < limit && offset < CLASSIC_PAGINATION_CAP) {
      const requestLimit = Math.min(pageSize, limit - items.length, CLASSIC_PAGINATION_CAP - offset);
      const payload = await this.get(path, { ...query, limit: requestLimit, offset, total: true });
      const pageItems = asRecords(payload[collectionKey]);
      const room = limit - items.length;
      items.push(...pageItems.slice(0, room));
      offset += pageItems.length;
      total = asNumber(payload.total) ?? total;
      flagDeclared = typeof payload.more === "boolean";
      more = pageHasMore(payload, pageItems.length, requestLimit) || pageItems.length > room;
      if (pageItems.length === 0) {
        if (more) stall = "the API returned an empty page while reporting more results available, so the listing stalled before its end";
        break;
      }
      if (!more) break;
    }

    if (stall) return { items, complete: false, total, truncation: stall };
    if (!more) {
      if (total !== undefined && total > items.length) {
        return {
          items,
          complete: false,
          total,
          truncation: `the API reported no more results after ${items.length} records while declaring a total of ${total}`,
        };
      }
      return { items, complete: true, total: total ?? items.length };
    }
    const truncation = offset >= CLASSIC_PAGINATION_CAP
      ? `stopped at the ${CLASSIC_PAGINATION_CAP} record pagination ceiling with more results available`
      : completion === "short_page" || !flagDeclared
        ? `stopped at the requested limit of ${limit} after a full page; the response declares no more flag, so further results may exist`
        : `stopped at the requested limit of ${limit} with more results available`;
    return { items, complete: false, total, truncation };
  }

  async listCursor(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<PagerdutyCollection> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 100_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const items: JsonRecord[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    let stall: string | undefined;

    while (items.length < limit) {
      const payload = await this.get(path, { ...query, limit: Math.min(pageSize, limit - items.length), cursor });
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      const nextCursor = asString(payload.next_cursor);
      if (!nextCursor) {
        cursor = undefined;
        break;
      }
      if (pageItems.length === 0) {
        stall = "the API returned an empty page with a next_cursor still present, so the listing stalled before its end";
        break;
      }
      if (seenCursors.has(nextCursor)) {
        stall = "the API returned a next_cursor it had already served, so the listing cannot advance past this page";
        break;
      }
      seenCursors.add(nextCursor);
      cursor = nextCursor;
    }

    if (stall) return { items, complete: false, truncation: stall };
    if (!cursor) return { items, complete: true, total: items.length };
    return {
      items,
      complete: false,
      truncation: `stopped at the requested limit of ${limit} with a next_cursor still available`,
    };
  }

  async getAbilities(): Promise<string[]> {
    const payload = await this.get("/abilities");
    return asArray(payload.abilities).map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }

  async getCredentialScope(): Promise<PagerdutyCredentialScope> {
    if (this.config.authMode === "oauth_client_credentials") {
      return { kind: "account", fullVisibility: true, note: "Scoped OAuth app token acting as the account" };
    }
    try {
      const payload = await this.get("/users/me");
      const user = asObject(payload.user) ?? payload;
      const role = asString(user.role) ?? "unknown";
      const email = asString(user.email);
      const fullVisibility = PRIVILEGED_ROLES.has(role);
      return {
        kind: "user",
        userId: asString(user.id),
        email,
        role,
        fullVisibility,
        note: fullVisibility
          ? `user-level credential for ${email ?? "unknown user"} with role ${role}`
          : `user-level credential for ${email ?? "unknown user"} with role ${role} only returns the objects that user can see`,
      };
    } catch (error) {
      if (error instanceof PagerdutyRequestError && error.status === 400) {
        return { kind: "account", fullVisibility: true, note: "account-level REST API key" };
      }
      throw error;
    }
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/users", "users", { "include[]": ["contact_methods", "notification_rules", "teams"] }, { limit });
  }

  async listTeams(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/teams", "teams", {}, { limit });
  }

  async listTeamMembers(teamId: string, limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list(`/teams/${encodeURIComponent(teamId)}/members`, "members", {}, { limit });
  }

  async listServices(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/services", "services", { "include[]": ["integrations", "escalation_policies", "teams"] }, { limit });
  }

  async listEscalationPolicies(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/escalation_policies", "escalation_policies", { "include[]": ["services", "teams"] }, { limit });
  }

  async listSchedules(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/schedules", "schedules", {}, { limit });
  }

  async getSchedule(scheduleId: string, since: Date, until: Date): Promise<JsonRecord> {
    const payload = await this.get(`/schedules/${encodeURIComponent(scheduleId)}`, {
      since: isoDate(since),
      until: isoDate(until),
      time_zone: "UTC",
    });
    return asObject(payload.schedule) ?? payload;
  }

  async listOncalls(since: Date, until: Date, limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/oncalls", "oncalls", { since: isoDate(since), until: isoDate(until), time_zone: "UTC" }, { limit });
  }

  async listAuditRecords(since: Date, until: Date, limit = DEFAULT_AUDIT_LIMIT): Promise<PagerdutyCollection> {
    return this.listCursor("/audit/records", "records", { since: isoDate(since), until: isoDate(until) }, { limit });
  }

  async listExtensions(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/extensions", "extensions", { "include[]": ["extension_schemas"] }, { limit });
  }

  async listWebhookSubscriptions(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/webhook_subscriptions", "webhook_subscriptions", {}, { limit });
  }

  async listBusinessServices(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/business_services", "business_services", {}, { limit });
  }

  async getBusinessServiceDependencies(businessServiceId: string): Promise<JsonRecord[]> {
    const payload = await this.get(`/service_dependencies/business_services/${encodeURIComponent(businessServiceId)}`);
    return asRecords(payload.relationships);
  }

  async listPriorities(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/priorities", "priorities", {}, { limit });
  }

  async listIncidentWorkflows(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list("/incident_workflows", "incident_workflows", {}, { limit });
  }

  async listIncidentWorkflowTriggers(limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.listCursor("/incident_workflows/triggers", "triggers", {}, { limit });
  }

  async listChangeEvents(since: Date, until: Date, limit = DEFAULT_LIST_LIMIT): Promise<PagerdutyCollection> {
    return this.list(
      "/change_events",
      "change_events",
      { since: isoDate(since), until: isoDate(until) },
      { limit, completion: "short_page" },
    );
  }
}

export type PagerdutyClientSurface = Pick<
  PagerdutyApiClient,
  | "getResolvedConfig"
  | "getNow"
  | "getAbilities"
  | "getCredentialScope"
  | "listUsers"
  | "listTeams"
  | "listTeamMembers"
  | "listServices"
  | "listEscalationPolicies"
  | "listSchedules"
  | "getSchedule"
  | "listOncalls"
  | "listAuditRecords"
  | "listExtensions"
  | "listWebhookSubscriptions"
  | "listBusinessServices"
  | "getBusinessServiceDependencies"
  | "listPriorities"
  | "listIncidentWorkflows"
  | "listIncidentWorkflowTriggers"
  | "listChangeEvents"
>;

/**
 * Every snapshot that reaches an assessment, a tool payload, or a core_data file passes through
 * here, so the deny-list redaction cannot be bypassed by a new caller.
 */
async function capture<T>(fallback: T, load: () => Promise<T>): Promise<Snapshot<T>> {
  try {
    return { data: redactSnapshot(await load()) as T };
  } catch (error) {
    const message = errorMessage(error);
    const status = error instanceof PagerdutyRequestError ? error.status : requestStatus(message);
    const endpoint = (error instanceof PagerdutyRequestError ? error.path : undefined) ?? requestEndpoint(message);
    return {
      data: fallback,
      error: message,
      ...(status !== undefined ? { status } : {}),
      ...(endpoint !== undefined ? { endpoint } : {}),
    };
  }
}

function snapshotErrors(label: string, snapshots: Record<string, Snapshot<unknown>>): string[] {
  return Object.entries(snapshots)
    .filter(([, snapshot]) => snapshot.error)
    .map(([name, snapshot]) => `${label}.${name}: ${snapshot.error}`);
}

function requestStatus(error: string | undefined): number | undefined {
  const match = error?.match(/\((\d{3}) /);
  return match ? Number(match[1]) : undefined;
}

function referenceId(value: unknown): string | undefined {
  return asString(asObject(value)?.id);
}

function nameOf(record: JsonRecord): string {
  return asString(record.summary) ?? asString(record.name) ?? asString(record.id) ?? "unnamed";
}

function userLabel(user: JsonRecord): string {
  return asString(user.email) ?? asString(user.name) ?? asString(user.id) ?? "unknown-user";
}

function roleOf(user: JsonRecord): string {
  return asString(user.role) ?? "unknown";
}

function statusRank(status: PagerdutyFindingStatus): number {
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
      throw new Error(`Unhandled finding status ${String(exhaustive)}`);
    }
  }
}

function severityRank(severity: PagerdutySeverity): number {
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

function countByStatus(findings: PagerdutyFinding[]): Record<PagerdutyFindingStatus, number> {
  const counts: Record<PagerdutyFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

export async function checkPagerdutyAccess(client: PagerdutyClientSurface): Promise<PagerdutyAccessCheckResult> {
  const config = client.getResolvedConfig();
  const now = client.getNow();
  const probes: Array<[name: string, endpoint: string, load: () => Promise<unknown>, permission: string]> = [
    ["abilities", "/abilities", () => client.getAbilities(), "abilities.read"],
    ["users", "/users", () => client.listUsers(25), "users.read"],
    ["teams", "/teams", () => client.listTeams(25), "teams.read"],
    ["services", "/services", () => client.listServices(25), "services.read"],
    ["escalation_policies", "/escalation_policies", () => client.listEscalationPolicies(25), "escalation_policies.read"],
    ["schedules", "/schedules", () => client.listSchedules(25), "schedules.read"],
    ["oncalls", "/oncalls", () => client.listOncalls(now, daysAhead(now, 1), 25), "oncalls.read"],
    ["audit_records", "/audit/records", () => client.listAuditRecords(daysAgo(now, 1), now, 25), "audit_records.read (admin or global API key, Audit Trail plan feature)"],
    ["extensions", "/extensions", () => client.listExtensions(25), "extensions.read"],
    ["webhook_subscriptions", "/webhook_subscriptions", () => client.listWebhookSubscriptions(25), "webhook_subscriptions.read"],
    ["business_services", "/business_services", () => client.listBusinessServices(25), "services.read"],
    ["priorities", "/priorities", () => client.listPriorities(25), "priorities.read"],
    ["incident_workflows", "/incident_workflows", () => client.listIncidentWorkflows(25), "incident_workflows.read"],
    ["change_events", "/change_events", () => client.listChangeEvents(daysAgo(now, 7), now, 25), "change_events.read"],
  ];

  const surfaces: PagerdutyAccessSurface[] = [];
  const missingPermissions: string[] = [];
  for (const [name, endpoint, load, permission] of probes) {
    try {
      const value = await load();
      const count = Array.isArray(value)
        ? value.length
        : asObject(value) && Array.isArray(asObject(value)?.items)
          ? asNumber(asObject(value)?.total) ?? asRecords(asObject(value)?.items).length
          : undefined;
      surfaces.push({ name, endpoint, status: "readable", count });
    } catch (error) {
      const message = errorMessage(error);
      const httpStatus = error instanceof PagerdutyRequestError ? error.status : requestStatus(message);
      surfaces.push({
        name,
        endpoint,
        status: "not_readable",
        error: message,
        ...(httpStatus !== undefined ? { http_status: httpStatus } : {}),
      });
      missingPermissions.push(`${endpoint}: ${permission}`);
    }
  }

  const scope = await capture<PagerdutyCredentialScope>(
    { kind: "unknown", fullVisibility: false },
    () => client.getCredentialScope(),
  );
  const scopeNote = scope.error
    ? `Credential scope could not be determined (${scope.error}); universal-claim findings will not pass until it is.`
    : `Credential scope: ${scope.data.note ?? scope.data.kind}${scope.data.fullVisibility ? "" : " (partial visibility, passing findings are downgraded to warn)"}.`;

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const coreSurfaces = ["abilities", "users", "teams", "services", "escalation_policies", "schedules"];
  const coreReadable = surfaces.filter((surface) => coreSurfaces.includes(surface.name) && surface.status === "readable").length;
  const status = coreReadable === coreSurfaces.length && readableCount >= surfaces.length - 2 && !scope.error && scope.data.fullVisibility
    ? "healthy"
    : "limited";

  return {
    status,
    region: config.region,
    authMode: config.authMode,
    surfaces,
    missingPermissions,
    notes: [
      `Using PagerDuty ${config.region.toUpperCase()} service region at ${config.baseUrl} with ${config.authMode} authentication.`,
      scopeNote,
      `${readableCount}/${surfaces.length} PagerDuty audit surfaces are readable.`,
      ...(missingPermissions.length > 0 ? [`Missing read access: ${missingPermissions.join("; ")}.`] : []),
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run pagerduty_assess_access_control, pagerduty_assess_incident_response, pagerduty_assess_oncall_coverage, pagerduty_assess_audit_logging, pagerduty_assess_integration_security, or pagerduty_export_audit_bundle."
        : "Use a read-only account-level REST API key created by an account admin (Integrations > API Access Keys), or a Scoped OAuth app token that includes the listed *.read scopes.",
  };
}

export interface PagerdutyAccessControlData {
  scope: Snapshot<PagerdutyCredentialScope>;
  abilities: Snapshot<string[]>;
  users: Snapshot<PagerdutyCollection>;
  teams: Snapshot<PagerdutyCollection>;
  teamMembers: Snapshot<Record<string, JsonRecord[]>>;
  teamMembersTruncated?: string[];
}

function captureScope(client: PagerdutyClientSurface): Promise<Snapshot<PagerdutyCredentialScope>> {
  return capture<PagerdutyCredentialScope>({ kind: "unknown", fullVisibility: false }, () => client.getCredentialScope());
}

export async function collectPagerdutyAccessControlData(
  client: PagerdutyClientSurface,
  options: { userLimit?: number; teamLimit?: number } = {},
): Promise<PagerdutyAccessControlData> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const teamLimit = clampNumber(options.teamLimit, DEFAULT_TEAM_LIMIT, 1, 500);
  const [scope, abilities, users, teams] = await Promise.all([
    captureScope(client),
    capture<string[]>([], () => client.getAbilities()),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listUsers(userLimit), projectUser)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listTeams(teamLimit)),
  ]);
  const teamMembersTruncated: string[] = [];
  // Member lists are keyed on the teams that were read; without a team list no member request is issued.
  const teamMembers = teams.error
    ? skippedSnapshot<Record<string, JsonRecord[]>>({}, "team member lists", "/teams", teams)
    : await capture<Record<string, JsonRecord[]>>({}, async () => {
      const entries: Record<string, JsonRecord[]> = {};
      for (const team of teams.data.items.slice(0, teamLimit)) {
        const id = asString(team.id);
        if (!id) continue;
        const members = await client.listTeamMembers(id);
        entries[id] = members.items;
        if (!members.complete) {
          teamMembersTruncated.push(`${nameOf(team)}: ${members.items.length} members seen of ${members.total ?? "an unknown total"}`);
        }
      }
      return entries;
    });
  return { scope, abilities, users, teams, teamMembers, teamMembersTruncated };
}

const USERS_EMPTY_EVIDENCE = "Zero users were returned even though every PagerDuty account has at least an account owner, so the credential is not seeing the user directory. Export the Users page (with roles) from the web app as evidence.";

export function assessPagerdutyAccessControl(
  data: PagerdutyAccessControlData,
  options: { maxAdmins?: number } = {},
): PagerdutyAssessmentResult {
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 1, 1000);
  const abilities = data.abilities.data;
  const abilitiesReadable = !data.abilities.error;
  const abilitiesEmpty = abilitiesReadable && abilities.length === 0;
  const users = inventory("users", data.users);
  const teams = inventory("teams", data.teams);
  const ssoAbility = abilities.includes("sso");
  const teamsAbility = abilities.includes("teams");
  const ssoUsers = users.items.filter((user) => user.created_via_sso === true);
  const nonSsoUsers = users.items.filter((user) => user.created_via_sso !== true);
  const usersWithoutRole = users.items.filter((user) => asString(user.role) === undefined);
  const privilegedUsers = users.items.filter((user) => PRIVILEGED_ROLES.has(roleOf(user)));
  const owners = users.items.filter((user) => roleOf(user) === "owner");
  const usersWithoutTeams = users.items.filter((user) => asArray(user.teams).length === 0);
  const teamManagers = Object.values(data.teamMembers.data)
    .flat()
    .filter((member) => /manager/i.test(asString(member.role) ?? "")).length;
  const roleCounts: Record<string, number> = {};
  for (const user of users.items) roleCounts[roleOf(user)] = (roleCounts[roleOf(user)] ?? 0) + 1;
  const analyticsAbilities = abilities.filter((ability) => /analytic|insight|report/i.test(ability));
  const userNotes = partialNotes(data.scope, users);
  const roleNote = usersWithoutRole.length > 0
    ? ` ${usersWithoutRole.length} users have no role field, so their privilege level is unknown and the verdict cannot exceed warn.`
    : "";
  const abilitiesUnavailable = !abilitiesReadable
    ? `the abilities list could not be read (${data.abilities.error})`
    : abilitiesEmpty
      ? "GET /abilities returned an empty ability list"
      : undefined;
  const teamsAbilityKnownAbsent = abilitiesUnavailable === undefined && !teamsAbility;
  const teamsAbilityNote = abilitiesUnavailable
    ? ` The "teams" ability could not be confirmed because ${abilitiesUnavailable}, so the verdict cannot exceed warn.`
    : "";
  const truncatedTeamMembers = data.teamMembersTruncated ?? [];
  const teamMembersReadable = !data.teamMembers.error;
  const teamMembershipSample = [
    ...(teamMembersReadable
      ? [`${teamManagers} team manager assignments sampled`]
      : [`team membership listing failed (${data.teamMembers.error}), so manager assignments could not be sampled`]),
    ...(truncatedTeamMembers.length > 0 ? [`member lists were truncated for ${truncatedTeamMembers.length} teams`] : []),
  ].join("; ");
  const teamManagerAssignments = !teamMembersReadable
    ? null
    : truncatedTeamMembers.length > 0 && teamManagers === 0
      ? null
      : derived(teamManagers, teams);
  const ssoUserNote = users.readable
    ? `${ssoUsers.length}/${users.seen} returned users were created via SSO`
    : `the user directory could not be read (${users.error}), so SSO-created users could not be counted`;

  const userDirectoryStatus = (): PagerdutyFindingStatus | undefined => {
    if (!users.readable || users.empty) return "manual";
    return undefined;
  };
  const userDirectorySummary = (evidence: string): string =>
    !users.readable ? unreadable(users, evidence) : USERS_EMPTY_EVIDENCE;

  const findings: PagerdutyFinding[] = [
    finding(
      1,
      !abilitiesReadable || abilitiesEmpty ? "manual" : ssoAbility ? "manual" : "fail",
      !abilitiesReadable
        ? `Abilities could not be read (${data.abilities.error}). Collect a screenshot of Account Settings > Single Sign-On showing SSO configured and the option that requires SSO login enabled.`
        : abilitiesEmpty
          ? "GET /abilities returned an empty ability list, which does not happen on a live account, so SSO availability cannot be determined from the API. Collect a screenshot of Account Settings > Single Sign-On showing SSO configured and required."
          : ssoAbility
            ? `The account exposes the "sso" ability and ${ssoUserNote}. The REST API does not expose whether SSO login is required, so collect a screenshot of Account Settings > Single Sign-On showing SSO enabled and password login disallowed.`
            : `The account exposes ${abilities.length} abilities and "sso" is not one of them, so SSO is not available or not configured for this account.`,
      {
        sso_ability: abilitiesReadable ? ssoAbility : null,
        abilities: abilitiesReadable ? abilities.slice(0, 50) : null,
        users_created_via_sso: principalCount(ssoUsers.length, users),
        ...principalEvidence({ users_not_created_via_sso: nonSsoUsers.slice(0, 25).map(userLabel) }, users),
      },
    ),
    finding(
      2,
      userDirectoryStatus()
        ?? (privilegedUsers.length > maxAdmins ? "fail" : usersWithoutRole.length > 0 ? "warn" : "pass"),
      userDirectoryStatus()
        ? userDirectorySummary("Export the Users page with roles from the web app and confirm the number of Account Owner and Global Admin users.")
        : privilegedUsers.length > maxAdmins
          ? `${privilegedUsers.length} of ${countSeen(users)} hold owner or admin roles, exceeding the threshold of ${maxAdmins}.${roleNote}`
          : `${privilegedUsers.length} of ${countSeen(users)} hold owner or admin roles, within the threshold of ${maxAdmins}.${roleNote}`,
      {
        ...principalEvidence({
          privileged_users: privilegedUsers.slice(0, 25).map((user) => `${userLabel(user)} (${roleOf(user)})`),
          users_without_role: usersWithoutRole.slice(0, 25).map(userLabel),
        }, users),
        role_counts: derived(roleCounts, users),
        max_admins: maxAdmins,
        users_seen: seenCount(users),
        users_total: totalCount(users),
      },
      userNotes,
    ),
    finding(
      3,
      userDirectoryStatus()
        ?? (owners.length > 1 ? "fail" : owners.length === 0 || usersWithoutRole.length > 0 ? "warn" : "pass"),
      userDirectoryStatus()
        ? userDirectorySummary("Confirm on the Users page that exactly one user holds the Account Owner role.")
        : owners.length > 1
          ? `${owners.length} of ${countSeen(users)} hold the owner role; PagerDuty accounts should have a single account owner.`
          : owners.length === 0
            ? `No owner role was found among ${countSeen(users)}; confirm the account owner is within the returned user set.${roleNote}`
            : `Exactly one owner among ${countSeen(users)}.${roleNote}`,
      principalEvidence({
        owners: owners.slice(0, 10).map(userLabel),
        users_without_role: usersWithoutRole.slice(0, 25).map(userLabel),
      }, users),
      userNotes,
    ),
    finding(
      4,
      userDirectoryStatus()
        ?? (!teams.readable
          ? "manual"
          : teams.empty || teamsAbilityKnownAbsent
            ? "fail"
            : usersWithoutTeams.length === 0
              ? abilitiesUnavailable
                ? "warn"
                : "pass"
              : usersWithoutTeams.length / users.seen > 0.5
                ? "fail"
                : "warn"),
      userDirectoryStatus()
        ? userDirectorySummary("Review Teams in the web app and confirm every responder belongs to at least one team.")
        : !teams.readable
          ? unreadable(teams, "Review Teams in the web app and confirm every responder belongs to at least one team.")
          : teams.empty || teamsAbilityKnownAbsent
            ? `GET /teams returned ${teams.seen} teams${teamsAbilityKnownAbsent ? " and the \"teams\" ability is absent" : ""}, so access is not scoped by team; an empty team list fails this control.`
            : usersWithoutTeams.length === 0
              ? `${countSeen(teams)} are configured and every one of ${countSeen(users)} belongs to at least one team (${teamMembershipSample}).${teamsAbilityNote}`
              : `${usersWithoutTeams.length} of ${countSeen(users)} do not belong to any team.${teamsAbilityNote}`,
      {
        teams_ability: abilitiesUnavailable ? null : teamsAbility,
        abilities_status: abilitiesUnavailable ?? "readable",
        teams_seen: seenCount(teams),
        teams_total: totalCount(teams),
        team_manager_assignments: teamManagerAssignments,
        team_member_lists_truncated: teamMembersReadable ? truncatedTeamMembers : null,
        ...principalEvidence({ users_without_teams: usersWithoutTeams.slice(0, 25).map(userLabel) }, users),
      },
      partialNotes(data.scope, users, teams),
    ),
    finding(
      24,
      "manual",
      `${abilitiesReadable ? `The REST API exposes ${analyticsAbilities.length} analytics-related abilities` : `Abilities could not be read (${data.abilities.error})`} and never exposes per-role analytics permissions, so this control is outside the API's scope. Record which roles can open Analytics and Insights in the web app (compare the Users page role list against your approved analytics viewer list) and attach that review as evidence.`,
      {
        analytics_abilities: abilitiesReadable ? analyticsAbilities : null,
        role_counts: derived(roleCounts, users),
      },
    ),
  ];

  return {
    category: "access_control",
    title: "PagerDuty access control",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      abilities: abilitiesReadable ? abilities.length : null,
      sso_ability: abilitiesReadable ? ssoAbility : null,
      users_seen: seenCount(users),
      users_total: totalCount(users),
      privileged_users: principalCount(privilegedUsers.length, users),
      owners: principalCount(owners.length, users),
      teams_seen: seenCount(teams),
      users_without_teams: principalCount(usersWithoutTeams.length, users),
      inventories: {
        abilities: describeSnapshot("abilities", data.abilities, abilities.length),
        ...inventoryStatus(users, teams),
        team_members: describeSnapshot("team members", data.teamMembers, Object.keys(data.teamMembers.data).length, truncatedTeamMembers),
      },
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("access_control", {
      credential_scope: data.scope,
      abilities: data.abilities,
      users: data.users,
      teams: data.teams,
      team_members: data.teamMembers,
    }),
  };
}

export interface PagerdutyIncidentResponseData {
  scope: Snapshot<PagerdutyCredentialScope>;
  services: Snapshot<PagerdutyCollection>;
  escalationPolicies: Snapshot<PagerdutyCollection>;
  priorities: Snapshot<PagerdutyCollection>;
  incidentWorkflows: Snapshot<PagerdutyCollection>;
  workflowTriggers: Snapshot<PagerdutyCollection>;
}

export async function collectPagerdutyIncidentResponseData(
  client: PagerdutyClientSurface,
  options: { serviceLimit?: number } = {},
): Promise<PagerdutyIncidentResponseData> {
  const serviceLimit = clampNumber(options.serviceLimit, DEFAULT_LIST_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const [scope, services, escalationPolicies, priorities, incidentWorkflows, workflowTriggers] = await Promise.all([
    captureScope(client),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listServices(serviceLimit), projectService)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listEscalationPolicies()),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listPriorities()),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listIncidentWorkflows(), projectIncidentWorkflow)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listIncidentWorkflowTriggers()),
  ]);
  return { scope, services, escalationPolicies, priorities, incidentWorkflows, workflowTriggers };
}

const SERVICES_EMPTY_EVIDENCE = "GET /services returned zero services, so there is nothing to evaluate and the credential may not see the service directory. Export the Service Directory from the web app as evidence.";

function isPlanError(error: string | undefined): boolean {
  return requestStatus(error) === 402 || /payment required|not (?:included|available) (?:in|on) (?:your|this) plan|upgrade your plan/i.test(error ?? "");
}

function activeServices(services: JsonRecord[]): JsonRecord[] {
  return services.filter((service) => asString(service.status) !== "disabled");
}

function urgencySummary(service: JsonRecord): string {
  const rule = asObject(service.incident_urgency_rule);
  if (!rule) return "missing";
  const type = asString(rule.type) ?? "unknown";
  if (type === "use_support_hours") return "use_support_hours";
  return `${type}:${asString(rule.urgency) ?? "unknown"}`;
}

type WorkflowTriggerState = "enabled" | "disabled" | "unresolved";
type WorkflowTriggerSource = "is_disabled" | "workflow.is_enabled";

interface WorkflowTriggerClass {
  trigger: JsonRecord;
  state: WorkflowTriggerState;
  source?: WorkflowTriggerSource;
}

/**
 * The trigger `is_disabled` boolean is optional and deprecated in the OpenAPI reference, documented as
 * inherited from the owning workflow's `is_enabled`. An explicit `is_disabled: true` is always rejected
 * while the field is served. Otherwise the parent workflow referenced by `trigger.workflow.id` is the
 * source of truth when it was returned with an `is_enabled` value; an explicit `is_disabled: false` is
 * accepted only when no parent is available to contradict it. A trigger with neither is unresolved.
 */
function classifyWorkflowTrigger(trigger: JsonRecord, workflowsById: Map<string, JsonRecord>): WorkflowTriggerClass {
  if (trigger.is_disabled === true) return { trigger, state: "disabled", source: "is_disabled" };
  const parent = workflowsById.get(referenceId(trigger.workflow) ?? "");
  if (parent && typeof parent.is_enabled === "boolean") {
    return { trigger, state: parent.is_enabled ? "enabled" : "disabled", source: "workflow.is_enabled" };
  }
  if (trigger.is_disabled === false) return { trigger, state: "enabled", source: "is_disabled" };
  return { trigger, state: "unresolved" };
}

export function assessPagerdutyIncidentResponse(data: PagerdutyIncidentResponseData): PagerdutyAssessmentResult {
  const services = inventory("services", data.services);
  const policies = inventory("escalation policies", data.escalationPolicies);
  const priorities = inventory("priorities", data.priorities);
  const workflows = inventory("incident workflows", data.incidentWorkflows);
  const triggers = inventory("incident workflow triggers", data.workflowTriggers);
  const active = activeServices(services.items);
  const noActiveServices = services.readable && !services.empty && active.length === 0;
  const serviceNotes = partialNotes(data.scope, services);
  const policyNotes = partialNotes(data.scope, policies);

  const servicesWithoutPolicy = active.filter((service) => !referenceId(service.escalation_policy));
  const attachedPolicies = policies.items.filter((policy) => asArray(policy.services).length > 0);
  const singleLevelPolicies = attachedPolicies.filter((policy) => asArray(policy.escalation_rules).length < 2);
  const emptyTargetPolicies = policies.items.filter((policy) =>
    asRecords(policy.escalation_rules).length === 0
    || asRecords(policy.escalation_rules).some((rule) => asArray(rule.targets).length === 0));
  const missingLoops = attachedPolicies.filter((policy) => asNumber(policy.num_loops) === undefined);
  const nonRepeatingPolicies = attachedPolicies.filter((policy) => (asNumber(policy.num_loops) ?? 0) === 0);
  const enabledWorkflows = workflows.items.filter((workflow) => workflow.is_enabled === true);
  const workflowsById = new Map<string, JsonRecord>();
  for (const workflow of workflows.items) {
    const id = asString(workflow.id);
    if (id) workflowsById.set(id, workflow);
  }
  const triggerClasses = triggers.items.map((trigger) => classifyWorkflowTrigger(trigger, workflowsById));
  const enabledTriggers = triggerClasses.filter((item) => item.state === "enabled");
  const disabledTriggers = triggerClasses.filter((item) => item.state === "disabled");
  const unresolvedTriggers = triggerClasses.filter((item) => item.state === "unresolved");
  const triggersVerifiedByParent = enabledTriggers.filter((item) => item.source === "workflow.is_enabled").length;
  const triggersMissingDisabledFlag = triggers.items.filter((trigger) => typeof trigger.is_disabled !== "boolean").length;
  const automationVerified = enabledWorkflows.length > 0 && enabledTriggers.length > 0 && unresolvedTriggers.length === 0;
  const triggerCounts = `${countSeen(triggers)} (${enabledTriggers.length} enabled, ${disabledTriggers.length} disabled, ${unresolvedTriggers.length} unresolved)`;
  const legacyResponsePlays = services.items.filter((service) => asArray(service.response_play).length > 0 || asObject(service.response_play));
  const responsePlayCount = services.readable
    ? `${legacyResponsePlays.length} services still reference one`
    : `services could not be read (${services.error}), so services still referencing one could not be counted`;
  const responsePlayReferences = services.readable
    ? `${legacyResponsePlays.length} services reference deprecated response plays`
    : `response play references could not be checked because services could not be read (${services.error})`;
  const urgencyModes = active.map(urgencySummary);
  const constantHighOnly = urgencyModes.length > 0 && urgencyModes.every((mode) => mode === "constant:high");
  const missingUrgency = active.filter((service) => !asObject(service.incident_urgency_rule));
  const noAckTimeout = active.filter((service) => asNumber(service.acknowledgement_timeout) === undefined);
  const noAutoResolve = active.filter((service) => asNumber(service.auto_resolve_timeout) === undefined);

  const serviceGate = (): PagerdutyFindingStatus | undefined =>
    !services.readable || services.empty || noActiveServices ? "manual" : undefined;
  const serviceGateSummary = (subject: string): string =>
    !services.readable
      ? unreadable(services, `Review each service's Settings page in the web app and record ${subject}.`)
      : services.empty
        ? SERVICES_EMPTY_EVIDENCE
        : `All ${services.seen} returned services are disabled, so ${subject} cannot be evaluated on a live service; confirm in the Service Directory that no active services exist.`;
  const policyGate = (): PagerdutyFindingStatus | undefined =>
    !policies.readable || policies.empty || attachedPolicies.length === 0 ? "manual" : undefined;
  const policyGateSummary = (subject: string): string =>
    !policies.readable
      ? unreadable(policies, `Review each escalation policy in the web app and record ${subject}.`)
      : policies.empty
        ? "GET /escalation_policies returned zero policies even though PagerDuty creates a default policy, so the credential is not seeing escalation policies. Export the Escalation Policies page from the web app as evidence."
        : `${countSeen(policies)} were returned but none is attached to a service (the include[]=services expansion returned no services), so ${subject} cannot be tied to a live service. Record the service assignments from the web app.`;

  const findings: PagerdutyFinding[] = [
    finding(
      5,
      serviceGate() ?? (servicesWithoutPolicy.length === 0 ? "pass" : "fail"),
      serviceGate()
        ? serviceGateSummary("the assigned escalation policy")
        : servicesWithoutPolicy.length === 0
          ? `All ${active.length} active services (of ${countSeen(services)}) reference an escalation policy.`
          : `${servicesWithoutPolicy.length} of ${active.length} active services have no escalation policy.`,
      {
        services_seen: seenCount(services),
        services_total: totalCount(services),
        active_services: derived(active.length, services),
        services_without_policy: derived(servicesWithoutPolicy.slice(0, 25).map(nameOf), services),
        disabled_services: derived(services.seen - active.length, services),
      },
      serviceNotes,
    ),
    finding(
      6,
      policyGate() ?? (singleLevelPolicies.length === 0 ? "pass" : "warn"),
      policyGate()
        ? policyGateSummary("the number of escalation levels")
        : singleLevelPolicies.length === 0
          ? `All ${attachedPolicies.length} escalation policies attached to services (of ${countSeen(policies)}) define two or more escalation levels.`
          : `${singleLevelPolicies.length} of ${attachedPolicies.length} escalation policies attached to services define a single escalation level.`,
      {
        policies_seen: seenCount(policies),
        policies_total: totalCount(policies),
        attached_policies: derived(attachedPolicies.length, policies),
        single_level_policies: derived(singleLevelPolicies.slice(0, 25).map(nameOf), policies),
      },
      policyNotes,
    ),
    finding(
      7,
      policyGate() ?? (emptyTargetPolicies.length > 0 ? "fail" : nonRepeatingPolicies.length > 0 || missingLoops.length > 0 ? "warn" : "pass"),
      policyGate()
        ? policyGateSummary("whether every escalation rule has a target and the policy repeats")
        : emptyTargetPolicies.length > 0
          ? `${emptyTargetPolicies.length} escalation policies contain no rules or rules with no notification targets.`
          : nonRepeatingPolicies.length > 0 || missingLoops.length > 0
            ? `${nonRepeatingPolicies.length} of ${attachedPolicies.length} attached escalation policies never repeat (num_loops is 0${missingLoops.length > 0 ? ` or absent on ${missingLoops.length}` : ""}), so an unacknowledged incident stops notifying after the final level.`
            : `Every one of ${attachedPolicies.length} attached escalation policies has targets on each rule and a num_loops value above 0.`,
      {
        empty_target_policies: derived(emptyTargetPolicies.slice(0, 25).map(nameOf), policies),
        non_repeating_policies: derived(nonRepeatingPolicies.slice(0, 25).map(nameOf), policies),
        policies_missing_num_loops: derived(missingLoops.slice(0, 25).map(nameOf), policies),
      },
      policyNotes,
    ),
    finding(
      10,
      !workflows.readable
        ? "manual"
        : !triggers.readable
          ? "manual"
          : automationVerified
            ? services.readable
              ? "pass"
              : "warn"
            : workflows.items.length > 0 || triggers.items.length > 0 || legacyResponsePlays.length > 0
              ? "warn"
              : "fail",
      !workflows.readable
        ? isPlanError(workflows.error)
          ? `The Incident Workflows API is not available on this account's plan (${workflows.error}), so automated incident response cannot be evaluated through the API and this control is not applicable until the feature is licensed. Record any response automation configured in the web app.`
          : unreadable(workflows, "Record the configured Incident Workflows and their service triggers from Automation > Incident Workflows in the web app.")
        : !triggers.readable
          ? unreadable(triggers, "Record which services each Incident Workflow is triggered from in the web app.")
          : automationVerified
            ? `${enabledWorkflows.length} incident workflows with is_enabled true (of ${countSeen(workflows)}) and ${enabledTriggers.length} enabled triggers (of ${countSeen(triggers)}; ${enabledTriggers.length - triggersVerifiedByParent} verified by is_disabled false, ${triggersVerifiedByParent} by the parent workflow's is_enabled) are configured (response plays are deprecated in the REST API; ${responsePlayCount}).${services.readable ? "" : " The verdict cannot exceed warn until the service directory is readable."}`
            : workflows.items.length > 0 || triggers.items.length > 0 || legacyResponsePlays.length > 0
              ? `${countSeen(workflows)} (${enabledWorkflows.length} with is_enabled true) and ${triggerCounts} were read, so automated incident response is not verified${unresolvedTriggers.length > 0 ? " because a trigger without the is_disabled flag could not be matched to a returned workflow with an is_enabled value" : ""}; ${responsePlayReferences}. Confirm workflow and trigger state in Automation > Incident Workflows.`
              : services.readable
                ? `The Incident Workflows API is readable and returned zero workflows and zero triggers, and no service references a response play, so no automated incident response is configured; emptiness fails this control.`
                : `The Incident Workflows API is readable and returned zero workflows and zero triggers, so no workflow automation is configured; ${responsePlayReferences}. Emptiness fails this control.`,
      {
        incident_workflows_seen: seenCount(workflows),
        enabled_workflows: derived(enabledWorkflows.length, workflows),
        triggers_seen: seenCount(triggers),
        enabled_triggers: derived(enabledTriggers.length, triggers, workflows),
        disabled_triggers: derived(disabledTriggers.length, triggers, workflows),
        unresolved_triggers: derived(unresolvedTriggers.slice(0, 25).map((item) => nameOf(item.trigger)), triggers, workflows),
        triggers_missing_is_disabled_flag: derived(triggersMissingDisabledFlag, triggers),
        triggers_verified_by_parent_workflow: derived(triggersVerifiedByParent, triggers, workflows),
        services_inventory: describeInventory(services),
        services_with_legacy_response_plays: derived(legacyResponsePlays.slice(0, 25).map(nameOf), services),
      },
      partialNotes(data.scope, workflows, triggers),
    ),
    finding(
      19,
      serviceGate() ?? (missingUrgency.length > 0 ? "fail" : constantHighOnly ? "warn" : "pass"),
      serviceGate()
        ? serviceGateSummary("the incident urgency rule")
        : missingUrgency.length > 0
          ? `${missingUrgency.length} of ${active.length} active services do not expose an incident urgency rule.`
          : constantHighOnly
            ? `All ${active.length} active services use a constant high urgency; consider support-hours or severity-based urgency for lower-impact services.`
            : `All ${active.length} active services expose an incident urgency rule, using a mix of modes: ${[...new Set(urgencyModes)].join(", ")}.`,
      {
        active_services: derived(active.length, services),
        services_without_urgency_rule: derived(missingUrgency.slice(0, 25).map(nameOf), services),
        urgency_modes: derived(urgencyModes.reduce<Record<string, number>>((acc, mode) => ({ ...acc, [mode]: (acc[mode] ?? 0) + 1 }), {}), services),
      },
      serviceNotes,
    ),
    finding(
      20,
      !priorities.readable ? "manual" : priorities.empty ? "fail" : "pass",
      !priorities.readable
        ? isPlanError(priorities.error)
          ? `The Priorities API is not available on this account's plan (${priorities.error}); record the incident priority scheme from Account Settings > Incident Priority once licensed.`
          : unreadable(priorities, "Record the incident priority levels from Account Settings > Incident Priority.")
        : priorities.empty
          ? "GET /priorities is readable and returned zero priorities, so no custom incident priorities are defined; emptiness fails this control."
          : `${countSeen(priorities)} are defined (${priorities.items.slice(0, 10).map(nameOf).join(", ")}); confirm they are applied to incidents during postmortem review.`,
      { priorities: derived(priorities.items.slice(0, 10).map(nameOf), priorities), priorities_seen: seenCount(priorities) },
      partialNotes(data.scope, priorities),
    ),
    finding(
      22,
      serviceGate() ?? (noAckTimeout.length === 0 ? "pass" : "warn"),
      serviceGate()
        ? serviceGateSummary("the acknowledgement timeout")
        : noAckTimeout.length === 0
          ? `All ${active.length} active services (of ${countSeen(services)}) configure an acknowledgement timeout.`
          : `${noAckTimeout.length} of ${active.length} active services have acknowledgement timeout disabled or absent.`,
      {
        active_services: derived(active.length, services),
        services_without_ack_timeout: derived(noAckTimeout.slice(0, 25).map(nameOf), services),
      },
      serviceNotes,
    ),
    finding(
      23,
      serviceGate() ?? (noAutoResolve.length === 0 ? "pass" : "warn"),
      serviceGate()
        ? serviceGateSummary("the auto-resolve timeout")
        : noAutoResolve.length === 0
          ? `All ${active.length} active services (of ${countSeen(services)}) configure an auto-resolve timeout.`
          : `${noAutoResolve.length} of ${active.length} active services have auto-resolve disabled or absent.`,
      {
        active_services: derived(active.length, services),
        services_without_auto_resolve: derived(noAutoResolve.slice(0, 25).map(nameOf), services),
      },
      serviceNotes,
    ),
  ];

  return {
    category: "incident_response",
    title: "PagerDuty incident response configuration",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      services_seen: seenCount(services),
      services_total: totalCount(services),
      active_services: derived(active.length, services),
      escalation_policies_seen: seenCount(policies),
      incident_workflows_seen: seenCount(workflows),
      workflow_triggers_seen: seenCount(triggers),
      enabled_workflow_triggers: derived(enabledTriggers.length, triggers, workflows),
      priorities_seen: seenCount(priorities),
      inventories: inventoryStatus(services, policies, priorities, workflows, triggers),
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("incident_response", {
      credential_scope: data.scope,
      services: data.services,
      escalation_policies: data.escalationPolicies,
      priorities: data.priorities,
      incident_workflows: data.incidentWorkflows,
      workflow_triggers: data.workflowTriggers,
    }),
  };
}

export interface PagerdutyOncallCoverageData {
  scope: Snapshot<PagerdutyCredentialScope>;
  schedules: Snapshot<PagerdutyCollection>;
  scheduleDetails: Snapshot<JsonRecord[]>;
  oncalls: Snapshot<PagerdutyCollection>;
  users: Snapshot<PagerdutyCollection>;
  coverageWindow: { since: string; until: string; days: number };
}

export async function collectPagerdutyOncallCoverageData(
  client: PagerdutyClientSurface,
  options: { scheduleLimit?: number; coverageDays?: number; userLimit?: number } = {},
): Promise<PagerdutyOncallCoverageData> {
  const scheduleLimit = clampNumber(options.scheduleLimit, DEFAULT_SCHEDULE_LIMIT, 1, 500);
  const coverageDays = clampNumber(options.coverageDays, DEFAULT_COVERAGE_DAYS, 1, 90);
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const now = client.getNow();
  const until = daysAhead(now, coverageDays);
  const [scope, schedules, oncalls, users] = await Promise.all([
    captureScope(client),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listSchedules(scheduleLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listOncalls(now, daysAhead(now, 1))),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listUsers(userLimit), projectUser)),
  ]);
  // Detail reads are keyed on the schedules that were read; without a schedule list none is issued.
  const scheduleDetails = schedules.error
    ? skippedSnapshot<JsonRecord[]>([], "schedule detail reads", "/schedules", schedules)
    : await capture<JsonRecord[]>([], async () => {
      const details: JsonRecord[] = [];
      for (const schedule of schedules.data.items.slice(0, scheduleLimit)) {
        const id = asString(schedule.id);
        if (!id) continue;
        details.push(await client.getSchedule(id, now, until));
      }
      return details;
    });
  return {
    scope,
    schedules,
    scheduleDetails,
    oncalls,
    users,
    coverageWindow: { since: isoDate(now), until: isoDate(until), days: coverageDays },
  };
}

export interface ScheduleCoverage {
  gaps: Array<{ start: string; end: string }>;
  entriesMissingDates: number;
  entries: number;
}

export function scheduleCoverageGaps(schedule: JsonRecord, since: Date, until: Date): ScheduleCoverage {
  const rawEntries = asRecords(asObject(schedule.final_schedule)?.rendered_schedule_entries);
  const dated = rawEntries
    .map((entry) => ({ start: parseDate(entry.start), end: parseDate(entry.end) }))
    .filter((entry): entry is { start: Date; end: Date } => Boolean(entry.start) && Boolean(entry.end))
    .sort((left, right) => left.start.getTime() - right.start.getTime());
  const gaps: Array<{ start: string; end: string }> = [];
  let cursor = since.getTime();
  for (const entry of dated) {
    const start = entry.start.getTime();
    const end = entry.end.getTime();
    if (start > cursor) gaps.push({ start: isoDate(new Date(cursor)), end: isoDate(new Date(start)) });
    cursor = Math.max(cursor, end);
    if (cursor >= until.getTime()) break;
  }
  if (cursor < until.getTime()) gaps.push({ start: isoDate(new Date(cursor)), end: isoDate(until) });
  return { gaps, entriesMissingDates: rawEntries.length - dated.length, entries: rawEntries.length };
}

function scheduleIsAttached(schedule: JsonRecord): boolean {
  return asArray(schedule.escalation_policies).length > 0;
}

function distinctScheduleUsers(schedule: JsonRecord): Set<string> {
  const ids = new Set<string>();
  for (const user of asRecords(schedule.users)) {
    const id = asString(user.id);
    if (id) ids.add(id);
  }
  for (const layer of asRecords(schedule.schedule_layers)) {
    for (const layerUser of asRecords(layer.users)) {
      const id = referenceId(layerUser.user);
      if (id) ids.add(id);
    }
  }
  return ids;
}

type ContactMethodClass = "usable_pager" | "usable_email" | "blocked_or_disabled" | "unverifiable";

function classifyContactMethod(method: JsonRecord): ContactMethodClass {
  const type = asString(method.type) ?? "unknown";
  if (method.blacklisted === true || method.enabled === false) return "blocked_or_disabled";
  switch (type) {
    case "phone_contact_method":
    case "sms_contact_method":
      return method.enabled === true && method.blacklisted === false ? "usable_pager" : "unverifiable";
    case "push_notification_contact_method":
      return method.blacklisted === false ? "usable_pager" : "unverifiable";
    case "email_contact_method":
      return method.enabled === true ? "usable_email" : "unverifiable";
    default:
      return "unverifiable";
  }
}

function contactMethodClasses(user: JsonRecord): ContactMethodClass[] {
  return asRecords(user.contact_methods).map(classifyContactMethod);
}

export function assessPagerdutyOncallCoverage(data: PagerdutyOncallCoverageData): PagerdutyAssessmentResult {
  const since = new Date(data.coverageWindow.since);
  const until = new Date(data.coverageWindow.until);
  const schedules = inventory("schedules", data.schedules);
  const users = inventory("users", data.users);
  const oncalls = inventory("on-call entries", data.oncalls);
  const details = data.scheduleDetails.data;
  const detailsReadable = !data.scheduleDetails.error;
  const attached = details.filter(scheduleIsAttached);
  const coverage = attached.map((schedule) => ({ schedule, coverage: scheduleCoverageGaps(schedule, since, until) }));
  const schedulesWithGaps = coverage.filter((item) => item.coverage.gaps.length > 0);
  const schedulesWithUndatedEntries = coverage.filter((item) => item.coverage.entriesMissingDates > 0);
  const singleParticipant = attached.filter((schedule) => distinctScheduleUsers(schedule).size < 2);
  const usersWithoutRole = users.items.filter((user) => asString(user.role) === undefined);
  const responders = users.items.filter((user) => RESPONDER_ROLES.has(roleOf(user)));
  const respondersWithoutRules = responders.filter((user) => asArray(user.notification_rules).length === 0);
  const respondersWithoutHighUrgencyRule = responders.filter((user) =>
    asArray(user.notification_rules).length > 0
    && !asRecords(user.notification_rules).some((rule) => asString(rule.urgency) === "high"));
  const oncallUserIds = new Set(
    oncalls.items.map((oncall) => referenceId(oncall.user)).filter((id): id is string => Boolean(id)),
  );
  const oncallUsers = users.items.filter((user) => oncallUserIds.has(asString(user.id) ?? ""));
  const oncallWithoutContact = oncallUsers.filter((user) =>
    contactMethodClasses(user).every((item) => item === "blocked_or_disabled"));
  const oncallUnverifiable = oncallUsers.filter((user) => {
    const classes = contactMethodClasses(user);
    return !classes.includes("usable_pager") && classes.includes("unverifiable");
  });
  const oncallEmailOnly = oncallUsers.filter((user) => {
    const classes = contactMethodClasses(user);
    return classes.includes("usable_email") && !classes.includes("usable_pager") && !classes.includes("unverifiable");
  });
  const unresolvedOncallUsers = [...oncallUserIds].filter((id) => !users.items.some((user) => asString(user.id) === id));
  const scheduleNotes = partialNotes(data.scope, schedules);
  const userNotes = partialNotes(data.scope, users);
  // Values computed from rendered schedule details depend on the schedule list and on every detail read.
  const detailed = <T>(value: T): T | null => (detailsReadable ? derived(value, schedules) : null);

  const scheduleGate = (): PagerdutyFindingStatus | undefined =>
    !schedules.readable || !detailsReadable || schedules.empty || attached.length === 0 ? "manual" : undefined;
  const scheduleGateSummary = (evidence: string): string =>
    !schedules.readable
      ? unreadable(schedules, evidence)
      : !detailsReadable
        ? `Schedule details could not be rendered (${data.scheduleDetails.error}). ${evidence}`
        : schedules.empty
          ? `GET /schedules returned zero schedules, so on-call coverage cannot be shown from rotations; either the account pages individuals directly from escalation policies or the credential cannot see schedules. ${evidence}`
          : `${countSeen(schedules)} exist but none is attached to an escalation policy, so no rotation feeds an escalation path. ${evidence}`;
  const userGate = (): PagerdutyFindingStatus | undefined =>
    !users.readable || users.empty ? "manual" : undefined;

  const findings: PagerdutyFinding[] = [
    finding(
      8,
      scheduleGate() ?? (schedulesWithGaps.length > 0 ? "fail" : schedulesWithUndatedEntries.length > 0 ? "warn" : "pass"),
      scheduleGate()
        ? scheduleGateSummary(`Open each on-call schedule in the web app, switch to the final schedule view for the next ${data.coverageWindow.days} days, and record any uncovered time.`)
        : schedulesWithGaps.length > 0
          ? `${schedulesWithGaps.length} of ${attached.length} attached schedules have coverage gaps in the next ${data.coverageWindow.days} days.`
          : schedulesWithUndatedEntries.length > 0
            ? `No gaps were found in the dated entries, but ${schedulesWithUndatedEntries.length} of ${attached.length} attached schedules contain rendered entries missing a start or end time; those entries were not counted as coverage, so the verdict cannot exceed warn.`
            : `All ${attached.length} schedules attached to escalation policies (of ${countSeen(schedules)}) render continuous final-schedule coverage from ${data.coverageWindow.since} to ${data.coverageWindow.until}.`,
      {
        coverage_window: data.coverageWindow,
        schedules_seen: seenCount(schedules),
        attached_schedules: detailed(attached.length),
        schedules_with_gaps: detailed(schedulesWithGaps.slice(0, 25).map((item) => ({
          schedule: nameOf(item.schedule),
          gaps: item.coverage.gaps.slice(0, 5),
          rendered_coverage_percentage: asNumber(asObject(item.schedule.final_schedule)?.rendered_coverage_percentage) ?? null,
        }))),
        schedules_with_undated_entries: detailed(schedulesWithUndatedEntries.slice(0, 25).map((item) => ({
          schedule: nameOf(item.schedule),
          entries_missing_dates: item.coverage.entriesMissingDates,
        }))),
        unattached_schedules: detailed(details.length - attached.length),
      },
      scheduleNotes,
    ),
    finding(
      9,
      scheduleGate() ?? (singleParticipant.length === 0 ? "pass" : "fail"),
      scheduleGate()
        ? scheduleGateSummary("Record the number of distinct participants on each on-call schedule from the web app.")
        : singleParticipant.length === 0
          ? `All ${attached.length} attached schedules (of ${countSeen(schedules)}) include at least two distinct participants.`
          : `${singleParticipant.length} of ${attached.length} attached schedules rely on a single participant.`,
      {
        attached_schedules: detailed(attached.length),
        single_participant_schedules: detailed(singleParticipant.slice(0, 25).map(nameOf)),
      },
      scheduleNotes,
    ),
    finding(
      17,
      userGate()
        ?? (responders.length === 0
          ? "manual"
          : respondersWithoutRules.length / responders.length > 0.25
            ? "fail"
            : respondersWithoutRules.length > 0 || respondersWithoutHighUrgencyRule.length > 0 || usersWithoutRole.length > 0
              ? "warn"
              : "pass"),
      userGate()
        ? !users.readable
          ? unreadable(users, "Review each responder's notification rules in the web app and record users with no high-urgency rule.")
          : USERS_EMPTY_EVIDENCE
        : responders.length === 0
          ? `${countSeen(users)} were returned but none has a responder role (owner, admin, user, limited_user), so there are no notification rules to evaluate; confirm from the Users page which users respond to incidents.`
          : respondersWithoutRules.length / responders.length > 0.25
            ? `${respondersWithoutRules.length} of ${responders.length} responders have no notification rules.`
            : respondersWithoutRules.length > 0 || respondersWithoutHighUrgencyRule.length > 0 || usersWithoutRole.length > 0
              ? `${respondersWithoutRules.length} of ${responders.length} responders have no notification rules, ${respondersWithoutHighUrgencyRule.length} have no high-urgency rule, and ${usersWithoutRole.length} users have no role field.`
              : `All ${responders.length} responders (of ${countSeen(users)}) define notification rules including a high-urgency rule.`,
      {
        responders: derived(responders.length, users),
        ...principalEvidence({
          users_without_role: usersWithoutRole.slice(0, 25).map(userLabel),
          responders_without_rules: respondersWithoutRules.slice(0, 25).map(userLabel),
          responders_without_high_urgency_rule: respondersWithoutHighUrgencyRule.slice(0, 25).map(userLabel),
        }, users),
      },
      userNotes,
    ),
    finding(
      18,
      userGate()
        ?? (!oncalls.readable || oncalls.empty || oncallUsers.length === 0
          ? "manual"
          : oncallWithoutContact.length > 0
            ? "fail"
            : oncallEmailOnly.length > 0 || oncallUnverifiable.length > 0 || unresolvedOncallUsers.length > 0
              ? "warn"
              : "pass"),
      userGate()
        ? !users.readable
          ? unreadable(users, "Review the contact methods of every current on-call responder in the web app and record any unverified phone or SMS methods.")
          : USERS_EMPTY_EVIDENCE
        : !oncalls.readable
          ? unreadable(oncalls, "Review the contact methods of every current on-call responder in the web app and record any unverified phone or SMS methods.")
          : oncalls.empty
            ? "GET /oncalls returned no one on call right now, so there are no on-call contact methods to evaluate; record who is on call from the web app and review their contact methods."
            : oncallUsers.length === 0
              ? `${oncalls.seen} on-call entries reference ${unresolvedOncallUsers.length} users that are not in the ${countSeen(users)} returned, so their contact methods could not be read; review them in the web app.`
              : oncallWithoutContact.length > 0
                ? `${oncallWithoutContact.length} of ${oncallUsers.length} current on-call users have no usable contact method: every method they have is blacklisted or disabled, or they have none.`
                : oncallEmailOnly.length > 0 || oncallUnverifiable.length > 0 || unresolvedOncallUsers.length > 0
                  ? `${oncallEmailOnly.length} of ${oncallUsers.length} current on-call users rely on email only, ${oncallUnverifiable.length} have phone, SMS, or push methods whose enabled or blacklisted flags are absent, and ${unresolvedOncallUsers.length} on-call users were outside the returned user set; the REST API does not expose phone verification, so confirm in the web app.`
                  : `All ${oncallUsers.length} current on-call users have a phone or SMS method with enabled true and blacklisted false, or a push method with blacklisted false (the push contact method schema has no enabled flag).`,
      {
        current_oncall_users: derived(oncallUsers.length, users, oncalls),
        oncall_entries_seen: seenCount(oncalls),
        oncall_users_not_in_returned_set: derived(unresolvedOncallUsers.length, users, oncalls),
        ...principalEvidence({
          oncall_without_contact_methods: oncallWithoutContact.slice(0, 25).map(userLabel),
          oncall_email_only: oncallEmailOnly.slice(0, 25).map(userLabel),
          oncall_unverifiable_methods: oncallUnverifiable.slice(0, 25).map(userLabel),
        }, users, oncalls),
      },
      partialNotes(data.scope, users, oncalls),
    ),
  ];

  return {
    category: "oncall_coverage",
    title: "PagerDuty on-call coverage",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      schedules_seen: seenCount(schedules),
      attached_schedules: detailed(attached.length),
      schedules_with_gaps: detailed(schedulesWithGaps.length),
      single_participant_schedules: detailed(singleParticipant.length),
      responders: derived(responders.length, users),
      current_oncall_users: derived(oncallUsers.length, users, oncalls),
      inventories: {
        ...inventoryStatus(schedules, oncalls, users),
        schedule_details: describeSnapshot("schedule details", data.scheduleDetails, details.length),
      },
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("oncall_coverage", {
      credential_scope: data.scope,
      schedules: data.schedules,
      schedule_details: data.scheduleDetails,
      oncalls: data.oncalls,
      users: data.users,
    }),
  };
}

export interface PagerdutyAuditLoggingData {
  scope: Snapshot<PagerdutyCredentialScope>;
  recentRecords: Snapshot<PagerdutyCollection>;
  retentionProbe: Snapshot<PagerdutyCollection>;
  windows: { recent: { since: string; until: string }; retention: { since: string; until: string } };
}

export async function collectPagerdutyAuditLoggingData(
  client: PagerdutyClientSurface,
  options: { auditWindowDays?: number; auditLimit?: number } = {},
): Promise<PagerdutyAuditLoggingData> {
  const auditWindowDays = clampNumber(options.auditWindowDays, DEFAULT_AUDIT_WINDOW_DAYS, 1, 31);
  const auditLimit = clampNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT, 1, 10_000);
  const now = client.getNow();
  const recentSince = daysAgo(now, auditWindowDays);
  const retentionSince = daysAgo(now, 365);
  const retentionUntil = daysAgo(now, 335);
  const [scope, recentRecords, retentionProbe] = await Promise.all([
    captureScope(client),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listAuditRecords(recentSince, now, auditLimit), projectAuditRecord)),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listAuditRecords(retentionSince, retentionUntil, 25), projectAuditRecord)),
  ]);
  return {
    scope,
    recentRecords,
    retentionProbe,
    windows: {
      recent: { since: isoDate(recentSince), until: isoDate(now) },
      retention: { since: isoDate(retentionSince), until: isoDate(retentionUntil) },
    },
  };
}

function datedWithin(records: JsonRecord[], window: { since: string; until: string }): { dated: JsonRecord[]; undated: number; outside: number } {
  const since = new Date(window.since).getTime();
  const until = new Date(window.until).getTime();
  const dated: JsonRecord[] = [];
  let undated = 0;
  let outside = 0;
  for (const record of records) {
    const executed = parseDate(record.execution_time);
    if (!executed) {
      undated += 1;
    } else if (executed.getTime() < since || executed.getTime() > until) {
      outside += 1;
    } else {
      dated.push(record);
    }
  }
  return { dated, undated, outside };
}

export function assessPagerdutyAuditLogging(
  data: PagerdutyAuditLoggingData,
  options: { minRetentionDays?: number; apiKeyMaxAgeDays?: number } = {},
): PagerdutyAssessmentResult {
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 1, 3650);
  const apiKeyMaxAgeDays = clampNumber(options.apiKeyMaxAgeDays, DEFAULT_API_KEY_MAX_AGE_DAYS, 1, 3650);
  const recent = inventory("audit records", data.recentRecords);
  const probe = inventory("retention probe records", data.retentionProbe);
  const records = recent.items;
  const recentError = recent.error;
  const recentDated = datedWithin(records, data.windows.recent);
  const probeDated = datedWithin(probe.items, data.windows.retention);
  const auditNotes = partialNotes(data.scope, recent);
  const methodCounts: Record<string, number> = {};
  const tokenUsage = new Map<string, { uses: number; lastUsed: string; actors: Set<string> }>();
  for (const record of records) {
    const method = asObject(record.method);
    const type = asString(method?.type) ?? "unknown";
    methodCounts[type] = (methodCounts[type] ?? 0) + 1;
    const truncated = asString(method?.truncated_token);
    if (type === "api_token" && truncated) {
      const entry = tokenUsage.get(truncated) ?? { uses: 0, lastUsed: "", actors: new Set<string>() };
      entry.uses += 1;
      const executed = asString(record.execution_time) ?? "";
      if (executed > entry.lastUsed) entry.lastUsed = executed;
      for (const actor of asRecords(record.actors)) {
        const id = asString(actor.id);
        if (id) entry.actors.add(id);
      }
      tokenUsage.set(truncated, entry);
    }
  }
  const apiTokens = [...tokenUsage.entries()].map(([token, entry]) => ({
    truncated_token: `...${token}`,
    uses: entry.uses,
    last_used: entry.lastUsed,
    actors: [...entry.actors].slice(0, 5),
  }));

  const planLimited = isPlanError(recentError);
  const undatedNote = recentDated.undated > 0 || recentDated.outside > 0
    ? ` ${recentDated.undated} records have no execution_time and ${recentDated.outside} fall outside the window; they were not counted as recent.`
    : "";

  const findings: PagerdutyFinding[] = [
    finding(
      11,
      recentError
        ? "manual"
        : recentDated.dated.length > 0
          ? "pass"
          : "warn",
      recentError
        ? planLimited
          ? `The audit records API rejected the request as a plan limitation (${recentError}), so the Audit Trail feature is not included in this account's plan and audit logging cannot be evidenced through the API. Record the plan tier and any alternative logging (for example webhook or SIEM exports) from the web app.`
          : `${unreadable(recent, "Use an admin or global API key, or export the audit trail from the web app to evidence that logging is active.")}`
        : recentDated.dated.length > 0
          ? `${recentDated.dated.length} audit records with an execution_time inside ${data.windows.recent.since} to ${data.windows.recent.until} were retrieved (${recent.seen} returned in total).${undatedNote}`
          : records.length > 0
            ? `${records.length} audit records were returned but none carries an execution_time inside ${data.windows.recent.since} to ${data.windows.recent.until}, so recent logging activity cannot be confirmed.${undatedNote}`
            : `The audit records API is readable but returned zero records between ${data.windows.recent.since} and ${data.windows.recent.until}; an empty audit trail cannot demonstrate active logging, so confirm recent configuration changes appear in the web app audit trail.`,
      {
        window: data.windows.recent,
        records_returned: seenCount(recent),
        records_dated_in_window: derived(recentDated.dated.length, recent),
        records_missing_execution_time: derived(recentDated.undated, recent),
        records_outside_window: derived(recentDated.outside, recent),
        method_types: derived(methodCounts, recent),
      },
      auditNotes,
    ),
    finding(
      12,
      recentError
        ? "manual"
        : minRetentionDays > 365
          ? "manual"
          : !probe.readable
            ? "warn"
            : probeDated.dated.length > 0
              ? "pass"
              : "warn",
      recentError
        ? planLimited
          ? `The Audit Trail feature is not included in this account's plan (${recentError}), so retention cannot be evidenced through the API. Attach evidence that configuration changes are retained for at least ${minRetentionDays} days elsewhere.`
          : `Audit records could not be read (${recentError}), so retention could not be probed. Confirm audit records or a SIEM export cover at least ${minRetentionDays} days.`
        : minRetentionDays > 365
          ? `PagerDuty documents 12 months of audit record retention, which is shorter than the required ${minRetentionDays} days; attach evidence that audit records are exported to a SIEM or archive that meets the requirement.`
          : !probe.readable
            ? `The 11-to-12-month retention window could not be probed (${probe.error}); PagerDuty documents 12 months of retention.`
            : probeDated.dated.length > 0
              ? `${probeDated.dated.length} audit records dated inside ${data.windows.retention.since} to ${data.windows.retention.until} were retrievable (sample of up to 25), consistent with the documented 12-month retention and the ${minRetentionDays}-day requirement.`
              : probe.seen > 0
                ? `${probe.seen} records were returned for the retention probe but none carries an execution_time inside ${data.windows.retention.since} to ${data.windows.retention.until}, so retention cannot be confirmed from them.`
                : `No audit records were returned for ${data.windows.retention.since} to ${data.windows.retention.until}; the account may be younger than 12 months or had no configuration changes then. PagerDuty documents 12 months of retention.`,
      {
        documented_retention_days: 365,
        required_retention_days: minRetentionDays,
        probe_window: data.windows.retention,
        probe_records_returned: seenCount(probe),
        probe_records_dated_in_window: derived(probeDated.dated.length, probe),
        probe_records_missing_execution_time: derived(probeDated.undated, probe),
      },
      auditNotes,
    ),
    finding(
      13,
      "manual",
      recentError
        ? `The REST API has no endpoint that lists API keys or their creation dates, and audit records could not be read (${recentError}). Open Integrations > API Access Keys and each user's User Settings > API Access in the web app, record the Created date of every key, and rotate keys older than ${apiKeyMaxAgeDays} days.`
        : recent.complete
          ? `The REST API has no endpoint that lists API keys or their creation dates; ${apiTokens.length} distinct API tokens (by truncated suffix) performed configuration changes in the last window. Open Integrations > API Access Keys and each user's User Settings > API Access in the web app, record the Created date of every key, and rotate keys older than ${apiKeyMaxAgeDays} days.`
          : `The REST API has no endpoint that lists API keys or their creation dates, and the audit record inventory was only partly read (${recent.partial ?? "collection incomplete"}), so the set of API tokens that performed configuration changes is unknown and none is named. Open Integrations > API Access Keys and each user's User Settings > API Access in the web app, record the Created date of every key, and rotate keys older than ${apiKeyMaxAgeDays} days.`,
      {
        api_key_max_age_days: apiKeyMaxAgeDays,
        ...principalEvidence({ api_tokens_observed: apiTokens.slice(0, 25) }, recent),
      },
      auditNotes,
    ),
  ];

  return {
    category: "audit_logging",
    title: "PagerDuty audit logging",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      recent_records_returned: seenCount(recent),
      recent_records_dated_in_window: derived(recentDated.dated.length, recent),
      retention_probe_records: seenCount(probe),
      api_tokens_observed: principalCount(apiTokens.length, recent),
      inventories: inventoryStatus(recent, probe),
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("audit_logging", {
      credential_scope: data.scope,
      recent_records: data.recentRecords,
      retention_probe: data.retentionProbe,
    }),
  };
}

export interface PagerdutyIntegrationSecurityData {
  scope: Snapshot<PagerdutyCredentialScope>;
  services: Snapshot<PagerdutyCollection>;
  extensions: Snapshot<PagerdutyCollection>;
  webhookSubscriptions: Snapshot<PagerdutyCollection>;
  businessServices: Snapshot<PagerdutyCollection>;
  businessServiceDependencies: Snapshot<Record<string, JsonRecord[]>>;
  changeEvents: Snapshot<PagerdutyCollection>;
  changeWindow: { since: string; until: string };
}

export async function collectPagerdutyIntegrationSecurityData(
  client: PagerdutyClientSurface,
  options: { serviceLimit?: number; businessServiceLimit?: number; changeEventDays?: number } = {},
): Promise<PagerdutyIntegrationSecurityData> {
  const serviceLimit = clampNumber(options.serviceLimit, DEFAULT_LIST_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const businessServiceLimit = clampNumber(options.businessServiceLimit, DEFAULT_TEAM_LIMIT, 1, 500);
  const changeEventDays = clampNumber(options.changeEventDays, DEFAULT_AUDIT_WINDOW_DAYS, 1, 90);
  const now = client.getNow();
  const since = daysAgo(now, changeEventDays);
  const [scope, services, extensions, webhookSubscriptions, businessServices, changeEvents] = await Promise.all([
    captureScope(client),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listServices(serviceLimit), projectService)),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listExtensions(), projectExtension)),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listWebhookSubscriptions(), projectWebhookSubscription)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listBusinessServices(businessServiceLimit)),
    capture<PagerdutyCollection>(emptyCollection(), async () => projectCollection(await client.listChangeEvents(since, now), projectChangeEvent)),
  ]);
  // Dependency reads are keyed on the business services that were read; without that list none is issued.
  const businessServiceDependencies = businessServices.error
    ? skippedSnapshot<Record<string, JsonRecord[]>>({}, "business service dependency reads", "/business_services", businessServices)
    : await capture<Record<string, JsonRecord[]>>({}, async () => {
      const entries: Record<string, JsonRecord[]> = {};
      for (const businessService of businessServices.data.items.slice(0, businessServiceLimit)) {
        const id = asString(businessService.id);
        if (!id) continue;
        entries[id] = await client.getBusinessServiceDependencies(id);
      }
      return entries;
    });
  return {
    scope,
    services,
    extensions,
    webhookSubscriptions,
    businessServices,
    businessServiceDependencies,
    changeEvents,
    changeWindow: { since: isoDate(since), until: isoDate(now) },
  };
}

const LEGACY_INTEGRATION_TYPES = new Set([
  "generic_events_api_inbound_integration",
  "cloudkick_inbound_integration",
  "keynote_inbound_integration",
  "nagios_inbound_integration",
  "pingdom_inbound_integration",
  "sql_monitor_inbound_integration",
]);

const CHANGE_EVENTS_PAGINATION_NOTE =
  "GET /change_events declares no more or total field, so offset pages are read until a page shorter than the requested limit; a full final page at the requested limit is recorded as incomplete.";

type ExtensionClass = "generic_webhook" | "other" | "unclassified";

function classifyExtension(extension: JsonRecord): ExtensionClass {
  const schema = asObject(extension.extension_schema);
  const label = `${asString(schema?.summary) ?? ""} ${asString(schema?.key) ?? ""} ${asString(schema?.label) ?? ""}`.trim();
  if (!label) return "unclassified";
  return /webhook/i.test(label) ? "generic_webhook" : "other";
}

function isHttpsUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function eventTimestampWithin(events: JsonRecord[], window: { since: string; until: string }): { dated: JsonRecord[]; undated: number } {
  const since = new Date(window.since).getTime();
  const until = new Date(window.until).getTime();
  const dated: JsonRecord[] = [];
  let undated = 0;
  for (const event of events) {
    const timestamp = parseDate(event.timestamp);
    if (!timestamp) {
      undated += 1;
    } else if (timestamp.getTime() >= since && timestamp.getTime() <= until) {
      dated.push(event);
    }
  }
  return { dated, undated };
}

export function assessPagerdutyIntegrationSecurity(data: PagerdutyIntegrationSecurityData): PagerdutyAssessmentResult {
  const extensions = inventory("extensions", data.extensions);
  const subscriptions = inventory("webhook subscriptions", data.webhookSubscriptions);
  const services = inventory("services", data.services);
  const businessServices = inventory("business services", data.businessServices);
  const changeEvents = inventory("change events", data.changeEvents);
  const webhooksReadable = extensions.readable && subscriptions.readable;
  const noWebhooks = webhooksReadable && extensions.empty && subscriptions.empty;
  const insecureExtensions = extensions.items.filter((extension) => !isHttpsUrl(asString(extension.endpoint_url)));
  const insecureSubscriptions = subscriptions.items.filter((subscription) => !isHttpsUrl(asString(asObject(subscription.delivery_method)?.url)));
  const disabledDeliveries = [
    ...extensions.items.filter((extension) => extension.temporarily_disabled === true).map(nameOf),
    ...subscriptions.items.filter((subscription) => asObject(subscription.delivery_method)?.temporarily_disabled === true).map(nameOf),
  ];
  const extensionClasses = extensions.items.map((extension) => ({ extension, kind: classifyExtension(extension) }));
  const legacyWebhookExtensions = extensionClasses.filter((item) => item.kind === "generic_webhook").map((item) => item.extension);
  const unclassifiedExtensions = extensionClasses.filter((item) => item.kind === "unclassified").map((item) => item.extension);
  const activeSubscriptions = subscriptions.items.filter((subscription) => subscription.active === true);
  const subscriptionsMissingActive = subscriptions.items.filter((subscription) => typeof subscription.active !== "boolean");
  const webhookNotes = partialNotes(data.scope, extensions, subscriptions);
  const webhookEvidence = "Record every webhook destination from Integrations > Generic Webhooks and each service's Integrations tab.";

  const integrations = services.items.flatMap((service) =>
    asRecords(service.integrations).map((integration) => ({ service: nameOf(service), integration })));
  const servicesWithoutIntegrationField = services.items.filter((service) => !Array.isArray(service.integrations));
  const legacyIntegrations = integrations.filter((item) => LEGACY_INTEGRATION_TYPES.has(asString(item.integration.type) ?? ""));
  const unfilteredEmailIntegrations = integrations.filter((item) =>
    asString(item.integration.type) === "generic_email_inbound_integration"
    && (asString(item.integration.email_filter_mode) ?? "all-email") === "all-email");
  const eventsV2Services = services.items.filter((service) =>
    asRecords(service.integrations).some((integration) => asString(integration.type) === "events_api_v2_inbound_integration"));
  const serviceNotes = partialNotes(data.scope, services);

  const dependencyMap = data.businessServiceDependencies.data;
  const unmappedBusinessServices = businessServices.items.filter((businessService) =>
    (dependencyMap[asString(businessService.id) ?? ""] ?? []).length === 0);
  const changeEventsDated = eventTimestampWithin(changeEvents.items, data.changeWindow);
  const servicesWithChangeEvents = new Set(
    changeEventsDated.dated.flatMap((event) => asRecords(event.services).map((service) => asString(service.id)).filter(Boolean)),
  );

  const findings: PagerdutyFinding[] = [
    finding(
      14,
      !webhooksReadable || noWebhooks
        ? "manual"
        : insecureExtensions.length + insecureSubscriptions.length > 0
          ? "fail"
          : "pass",
      !webhooksReadable
        ? `${!extensions.readable ? unreadable(extensions, "") : unreadable(subscriptions, "")}${webhookEvidence} Confirm every URL uses https.`
        : noWebhooks
          ? `GET /extensions and GET /webhook_subscriptions are readable and both returned zero entries, so there are no webhook endpoints to evaluate; this control is not applicable until a webhook exists. ${webhookEvidence}`
          : insecureExtensions.length + insecureSubscriptions.length > 0
            ? `${insecureExtensions.length} of ${countSeen(extensions)} and ${insecureSubscriptions.length} of ${countSeen(subscriptions)} deliver to non-https or missing endpoint URLs.`
            : `All ${countSeen(extensions)} and ${countSeen(subscriptions)} have an endpoint URL whose scheme is https.`,
      {
        extensions_seen: seenCount(extensions),
        subscriptions_seen: seenCount(subscriptions),
        insecure_extensions: derived(insecureExtensions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(reduceUrl(item.endpoint_url)) ?? "missing"}`), extensions),
        insecure_subscriptions: derived(insecureSubscriptions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(reduceUrl(asObject(item.delivery_method)?.url)) ?? "missing"}`), subscriptions),
        temporarily_disabled_deliveries: derived(disabledDeliveries.slice(0, 25), extensions, subscriptions),
      },
      webhookNotes,
    ),
    finding(
      15,
      !webhooksReadable || noWebhooks
        ? "manual"
        : legacyWebhookExtensions.length > 0
          ? "warn"
          : unclassifiedExtensions.length > 0 || activeSubscriptions.length === 0 || subscriptionsMissingActive.length > 0
            ? "warn"
            : "pass",
      !webhooksReadable
        ? `${!extensions.readable ? unreadable(extensions, "") : unreadable(subscriptions, "")}Record which webhooks are v3 subscriptions (signed with X-PagerDuty-Signature) versus legacy generic webhook extensions.`
        : noWebhooks
          ? "GET /extensions and GET /webhook_subscriptions are readable and both returned zero entries, so there are no webhook deliveries to sign; this control is not applicable until a webhook exists. Confirm in the web app that no webhooks are configured."
          : legacyWebhookExtensions.length > 0
            ? `${legacyWebhookExtensions.length} of ${countSeen(extensions)} are legacy generic webhook extensions, which are not signed. Migrate them to v3 webhook subscriptions, which sign every delivery with an HMAC-SHA256 X-PagerDuty-Signature header, and confirm receivers verify it.`
            : unclassifiedExtensions.length > 0
              ? `${unclassifiedExtensions.length} of ${countSeen(extensions)} returned no extension_schema summary, so they could not be classified as signed or unsigned; review them in Integrations > Extensions.`
              : activeSubscriptions.length === 0
                ? `${countSeen(extensions)} were read and none is a legacy generic webhook, but ${countSeen(subscriptions)} include zero with active true, so no signed v3 delivery is in effect; confirm which webhooks are live in the web app.`
                : subscriptionsMissingActive.length > 0
                  ? `${subscriptionsMissingActive.length} of ${countSeen(subscriptions)} did not return the active flag, so their delivery state is unknown.`
                  : `${countSeen(extensions)} were read and none is a legacy generic webhook; ${activeSubscriptions.length} of ${countSeen(subscriptions)} have active true and v3 deliveries carry an HMAC-SHA256 X-PagerDuty-Signature header. Confirm receiving systems verify the signature.`,
      {
        extensions_seen: seenCount(extensions),
        legacy_webhook_extensions: derived(legacyWebhookExtensions.slice(0, 25).map(nameOf), extensions),
        unclassified_extensions: derived(unclassifiedExtensions.slice(0, 25).map(nameOf), extensions),
        subscriptions_seen: seenCount(subscriptions),
        active_v3_subscriptions: derived(activeSubscriptions.length, subscriptions),
        subscriptions_missing_active_flag: derived(subscriptionsMissingActive.length, subscriptions),
        subscriptions_with_custom_headers: derived(
          subscriptions.items.filter((item) => asArray(asObject(item.delivery_method)?.custom_headers).length > 0).length,
          subscriptions,
        ),
      },
      webhookNotes,
    ),
    finding(
      16,
      !services.readable || services.empty
        ? "manual"
        : legacyIntegrations.length + unfilteredEmailIntegrations.length > 0
          ? "warn"
          : servicesWithoutIntegrationField.length > 0
            ? "warn"
            : "pass",
      !services.readable
        ? unreadable(services, "Review each service's Integrations tab and record legacy or unfiltered inbound integrations.")
        : services.empty
          ? SERVICES_EMPTY_EVIDENCE
          : legacyIntegrations.length + unfilteredEmailIntegrations.length > 0
            ? `${legacyIntegrations.length} legacy inbound integrations and ${unfilteredEmailIntegrations.length} email integrations that accept all email were found across ${countSeen(services)}.`
            : servicesWithoutIntegrationField.length > 0
              ? `${servicesWithoutIntegrationField.length} of ${countSeen(services)} did not return the integrations expansion, so their integrations could not be reviewed.`
              : `All ${integrations.length} integrations across ${countSeen(services)} use current integration types and email integrations apply filters.`,
      {
        services_seen: seenCount(services),
        integrations: derived(integrations.length, services),
        services_without_integration_expansion: derived(servicesWithoutIntegrationField.slice(0, 25).map(nameOf), services),
        legacy_integrations: derived(legacyIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)} (${asString(item.integration.type)})`), services),
        unfiltered_email_integrations: derived(unfilteredEmailIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)}`), services),
      },
      serviceNotes,
    ),
    finding(
      21,
      !businessServices.readable
        ? "manual"
        : businessServices.empty
          ? "fail"
          : unmappedBusinessServices.length === 0 && !data.businessServiceDependencies.error
            ? "pass"
            : "warn",
      !businessServices.readable
        ? isPlanError(businessServices.error)
          ? `Business services are not available on this account's plan (${businessServices.error}), so dependency mapping cannot be evaluated through the API and this control is not applicable until the feature is licensed. Record any service dependency documentation kept outside PagerDuty.`
          : unreadable(businessServices, "Record the business services and their supporting technical services from Service Directory > Business Services.")
        : businessServices.empty
          ? "GET /business_services is readable and returned zero business services, so service dependencies are not mapped for impact analysis; emptiness fails this control."
          : unmappedBusinessServices.length === 0 && !data.businessServiceDependencies.error
            ? `All ${countSeen(businessServices)} have at least one mapped dependency.`
            : `${unmappedBusinessServices.length} of ${countSeen(businessServices)} have no mapped dependencies${data.businessServiceDependencies.error ? ` (dependency listing failed: ${data.businessServiceDependencies.error})` : ""}.`,
      {
        business_services_seen: seenCount(businessServices),
        unmapped_business_services: data.businessServiceDependencies.error
          ? null
          : derived(unmappedBusinessServices.slice(0, 25).map(nameOf), businessServices),
      },
      partialNotes(data.scope, businessServices),
    ),
    finding(
      25,
      !changeEvents.readable || !services.readable
        ? "manual"
        : services.empty
          ? "manual"
          : changeEventsDated.dated.length > 0
            ? "pass"
            : changeEvents.seen > 0 || eventsV2Services.length > 0
              ? "warn"
              : "fail",
      !changeEvents.readable || !services.readable
        ? `${!changeEvents.readable ? unreadable(changeEvents, "") : unreadable(services, "")}Record which services receive change events from each service's Activity or Change Events tab.`
        : services.empty
          ? SERVICES_EMPTY_EVIDENCE
          : changeEventsDated.dated.length > 0
            ? `${changeEventsDated.dated.length} change events with a timestamp inside ${data.changeWindow.since} to ${data.changeWindow.until} were received across ${servicesWithChangeEvents.size} services (${changeEvents.seen} returned, ${changeEventsDated.undated} without a timestamp).`
            : changeEvents.seen > 0
              ? `${changeEvents.seen} change events were returned but none carries a timestamp inside the window, so recent change tracking cannot be confirmed.`
              : eventsV2Services.length > 0
                ? `No change events were received in the window even though ${eventsV2Services.length} of ${countSeen(services)} have Events API v2 integrations capable of change events.`
                : `GET /change_events is readable and returned zero events, and none of ${countSeen(services)} exposes an Events API v2 integration, so change tracking is not enabled; emptiness fails this control.`,
      {
        change_window: data.changeWindow,
        change_events_returned: seenCount(changeEvents),
        change_events_complete: changeEvents.readable ? changeEvents.complete : null,
        change_events_pagination: CHANGE_EVENTS_PAGINATION_NOTE,
        change_events_dated_in_window: derived(changeEventsDated.dated.length, changeEvents),
        change_events_missing_timestamp: derived(changeEventsDated.undated, changeEvents),
        services_with_change_events: derived(servicesWithChangeEvents.size, changeEvents),
        events_v2_services: derived(eventsV2Services.length, services),
      },
      partialNotes(data.scope, changeEvents, services),
    ),
  ];

  return {
    category: "integration_security",
    title: "PagerDuty integration security",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      extensions_seen: seenCount(extensions),
      webhook_subscriptions_seen: seenCount(subscriptions),
      service_integrations: derived(integrations.length, services),
      business_services_seen: seenCount(businessServices),
      change_events_returned: seenCount(changeEvents),
      inventories: {
        ...inventoryStatus(extensions, subscriptions, services, businessServices, changeEvents),
        business_service_dependencies: describeSnapshot(
          "business service dependencies",
          data.businessServiceDependencies,
          Object.keys(data.businessServiceDependencies.data).length,
        ),
      },
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("integration_security", {
      credential_scope: data.scope,
      services: data.services,
      extensions: data.extensions,
      webhook_subscriptions: data.webhookSubscriptions,
      business_services: data.businessServices,
      business_service_dependencies: data.businessServiceDependencies,
      change_events: data.changeEvents,
    }),
  };
}

export interface PagerdutyAssessmentOptions {
  userLimit?: number;
  teamLimit?: number;
  maxAdmins?: number;
  serviceLimit?: number;
  scheduleLimit?: number;
  coverageDays?: number;
  auditWindowDays?: number;
  auditLimit?: number;
  minRetentionDays?: number;
  apiKeyMaxAgeDays?: number;
  businessServiceLimit?: number;
  changeEventDays?: number;
}

export async function runPagerdutyAccessControlAssessment(
  client: PagerdutyClientSurface,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAssessmentResult> {
  return assessPagerdutyAccessControl(await collectPagerdutyAccessControlData(client, options), options);
}

export async function runPagerdutyIncidentResponseAssessment(
  client: PagerdutyClientSurface,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAssessmentResult> {
  return assessPagerdutyIncidentResponse(await collectPagerdutyIncidentResponseData(client, options));
}

export async function runPagerdutyOncallCoverageAssessment(
  client: PagerdutyClientSurface,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAssessmentResult> {
  return assessPagerdutyOncallCoverage(await collectPagerdutyOncallCoverageData(client, options));
}

export async function runPagerdutyAuditLoggingAssessment(
  client: PagerdutyClientSurface,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAssessmentResult> {
  return assessPagerdutyAuditLogging(await collectPagerdutyAuditLoggingData(client, options), options);
}

export async function runPagerdutyIntegrationSecurityAssessment(
  client: PagerdutyClientSurface,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAssessmentResult> {
  return assessPagerdutyIntegrationSecurity(await collectPagerdutyIntegrationSecurityData(client, options));
}

function formatAccessCheckText(result: PagerdutyAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `PagerDuty access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: PagerdutyAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", "Partial collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(
  config: PagerdutyResolvedConfig,
  assessments: PagerdutyAssessmentResult[],
  errors: string[],
  generatedAt: Date,
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => statusRank(left.status) - statusRank(right.status) || severityRank(left.severity) - severityRank(right.severity));
  const manual = findings.filter((item) => item.status === "manual");

  const lines = [
    "# PagerDuty Security Inspection: Executive Summary",
    "",
    `- Service region: ${config.region.toUpperCase()} (${config.baseUrl})`,
    `- Authentication mode: ${config.authMode}`,
    `- Generated: ${generatedAt.toISOString()}`,
    `- Controls assessed: ${findings.length} of ${PAGERDUTY_CONTROLS.length}`,
    `- Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  if (prioritized.length === 0) {
    lines.push("- No failing or warning findings were generated.");
  } else {
    for (const item of prioritized.slice(0, 15)) {
      lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}) ${item.title}: ${item.summary}`);
    }
  }
  lines.push("", "## Manual Evidence Required", "");
  if (manual.length === 0) {
    lines.push("- None.");
  } else {
    for (const item of manual) lines.push(`- ${item.id} ${item.title}: ${item.summary}`);
  }
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "");
    for (const error of errors) lines.push(`- ${error}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: PagerdutyFinding[]): string {
  const rows = findings.map((item) => {
    const definition = controlDefinition(item.control);
    return [
      item.id,
      item.status.toUpperCase(),
      item.severity.toUpperCase(),
      item.title,
      ...FRAMEWORK_KEYS.map((key) => definition.mappings[key]),
    ];
  });
  return [
    "# PagerDuty Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Status", "Severity", "Control", ...FRAMEWORK_KEYS.map((key) => FRAMEWORK_LABELS[key])], rows),
    "",
  ].join("\n");
}

function buildFrameworkReport(title: string, findings: PagerdutyFinding[], framework: FrameworkKey): string {
  const rows = findings.map((item) => [
    controlDefinition(item.control).mappings[framework],
    item.id,
    item.status.toUpperCase(),
    item.severity.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const counts = countByStatus(findings);
  return [
    `# ${title}`,
    "",
    `Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    formatTable([FRAMEWORK_LABELS[framework], "Finding", "Status", "Severity", "Control", "Summary"], rows),
    "",
    "Manual findings require evidence collected from the PagerDuty web app before asserting compliance.",
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# PagerDuty Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains PagerDuty REST API snapshots captured during this assessment. Credentials are never written: integration keys and inbound integration emails, extension `config` objects, webhook custom header values, and any secret-named field are replaced with `[REDACTED]`; webhook and extension URLs are reduced to scheme and host; users, services, workflows, change events, and audit records are projected to the fields the findings read.",
    "- A dataset that was denied, errored, or never collected is written as `{ \"collected\": false, \"status\": <http status or null>, \"endpoint\": <path or null>, \"error\": <message> }` instead of an empty list; a readable dataset with no items keeps its normal shape with `items: []`. Per-item reads that were never issued because their parent list was not read (`team_members.json`, `schedule_details.json`, `business_service_dependencies.json`) carry the same marker with `status: null`, `endpoint: null`, and an error starting `not requested:` that names the parent list. Counts in `analysis/*.json` that depend on an unread inventory are `null`, and each summary carries an `inventories` map stating whether every source was read to completion.",
    "- Every error string in this bundle (`_errors.log`, `analysis/*.json` errors and summaries, `core_data/access_check.json`) has passed a redaction step: configured credentials, URL userinfo and query strings, JWT-shaped strings, Authorization values, and credential-named assignments are replaced with `[REDACTED]`, and a non-JSON error body is recorded only as its status, content type, and byte length.",
    "- `analysis/` contains normalized findings (`findings.json`) and one JSON summary per assessment category.",
    "- `compliance/` contains the executive summary, the unified matrix, and one report per framework.",
    "- `_errors.log` appears only when some reads failed but the bundle still completed.",
    "- Finding ids `PD-01` to `PD-25` match the control numbers in specs/pagerduty-sec-inspector.spec.md.",
    "- Status `manual` means the REST API cannot verify the control; the summary states the evidence to collect from the web app.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/*.json` for the evidence behind each finding",
    "",
  ].join("\n");
}

export async function exportPagerdutyAuditBundle(
  client: PagerdutyClientSurface,
  config: PagerdutyResolvedConfig,
  outputRoot: string,
  options: PagerdutyAssessmentOptions = {},
): Promise<PagerdutyAuditBundleResult> {
  const generatedAt = client.getNow();
  const access = await checkPagerdutyAccess(client);
  const accessControlData = await collectPagerdutyAccessControlData(client, options);
  const incidentResponseData = await collectPagerdutyIncidentResponseData(client, options);
  const oncallData = await collectPagerdutyOncallCoverageData(client, options);
  const auditData = await collectPagerdutyAuditLoggingData(client, options);
  const integrationData = await collectPagerdutyIntegrationSecurityData(client, options);

  const assessments = [
    assessPagerdutyAccessControl(accessControlData, options),
    assessPagerdutyIncidentResponse(incidentResponseData),
    assessPagerdutyOncallCoverage(oncallData),
    assessPagerdutyAuditLogging(auditData, options),
    assessPagerdutyIntegrationSecurity(integrationData),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors);

  ensurePrivateDir(outputRoot);
  const { outputDir, zipPath } = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(`pagerduty-${config.region}`)}-audit-bundle`,
  );

  // A denied, errored, or uncollected dataset is written as a not-collected marker, never as an empty list.
  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/credential_scope.json", coreDataValue(accessControlData.scope)],
    ["core_data/abilities.json", coreDataValue(accessControlData.abilities)],
    ["core_data/users.json", coreDataValue(accessControlData.users)],
    ["core_data/teams.json", coreDataValue(accessControlData.teams)],
    ["core_data/team_members.json", coreDataValue(accessControlData.teamMembers)],
    ["core_data/services.json", coreDataValue(incidentResponseData.services)],
    ["core_data/escalation_policies.json", coreDataValue(incidentResponseData.escalationPolicies)],
    ["core_data/priorities.json", coreDataValue(incidentResponseData.priorities)],
    ["core_data/incident_workflows.json", coreDataValue(incidentResponseData.incidentWorkflows)],
    ["core_data/incident_workflow_triggers.json", coreDataValue(incidentResponseData.workflowTriggers)],
    ["core_data/schedules.json", coreDataValue(oncallData.schedules)],
    ["core_data/schedule_details.json", coreDataValue(oncallData.scheduleDetails)],
    ["core_data/oncalls.json", coreDataValue(oncallData.oncalls)],
    ["core_data/audit_records_recent.json", coreDataValue(auditData.recentRecords)],
    ["core_data/audit_records_retention_probe.json", coreDataValue(auditData.retentionProbe)],
    ["core_data/extensions.json", coreDataValue(integrationData.extensions)],
    ["core_data/webhook_subscriptions.json", coreDataValue(integrationData.webhookSubscriptions)],
    ["core_data/business_services.json", coreDataValue(integrationData.businessServices)],
    ["core_data/business_service_dependencies.json", coreDataValue(integrationData.businessServiceDependencies)],
    ["core_data/change_events.json", coreDataValue(integrationData.changeEvents)],
  ];
  for (const [pathName, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathName, serializeJson(value));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/metadata.json", serializeJson({
    generated_at: generatedAt.toISOString(),
    region: config.region,
    base_url: config.baseUrl,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    controls_total: PAGERDUTY_CONTROLS.length,
  }));

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  const frameworkReports: Array<[string, string, FrameworkKey]> = [
    ["compliance/fedramp/fedramp_compliance_report.md", "FedRAMP / NIST 800-53 Compliance Report", "fedramp"],
    ["compliance/cmmc/cmmc_compliance_report.md", "CMMC Level 2 Compliance Report", "cmmc"],
    ["compliance/soc2/soc2_compliance_report.md", "SOC 2 Compliance Report", "soc2"],
    ["compliance/cis/cis_compliance_report.md", "CIS Controls Compliance Report", "cis"],
    ["compliance/pci_dss/pci_dss_compliance_report.md", "PCI-DSS Compliance Report", "pci_dss"],
    ["compliance/disa_stig/stig_compliance_checklist.md", "DISA STIG Compliance Checklist", "disa_stig"],
    ["compliance/irap/irap_compliance_report.md", "IRAP / ISM Compliance Report", "irap"],
    ["compliance/ismap/ismap_compliance_report.md", "ISMAP Compliance Report", "ismap"],
  ];
  for (const [pathName, title, framework] of frameworkReports) {
    await writeSecureTextFile(outputDir, pathName, buildFrameworkReport(title, findings, framework));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
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

type AuthArgs = {
  api_token?: string;
  access_token?: string;
  client_id?: string;
  client_secret?: string;
  subdomain?: string;
  region?: string;
  base_url?: string;
  from_email?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AssessArgs = AuthArgs & {
  user_limit?: number;
  team_limit?: number;
  max_admins?: number;
  service_limit?: number;
  schedule_limit?: number;
  coverage_days?: number;
  audit_window_days?: number;
  audit_limit?: number;
  min_retention_days?: number;
  api_key_max_age_days?: number;
  business_service_limit?: number;
  change_event_days?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    api_token: asString(value.api_token) ?? asString(value.api_key) ?? asString(value.token),
    access_token: asString(value.access_token),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    subdomain: asString(value.subdomain),
    region: asString(value.region),
    base_url: asString(value.base_url),
    from_email: asString(value.from_email),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    user_limit: asNumber(value.user_limit),
    team_limit: asNumber(value.team_limit),
    max_admins: asNumber(value.max_admins),
    service_limit: asNumber(value.service_limit),
    schedule_limit: asNumber(value.schedule_limit),
    coverage_days: asNumber(value.coverage_days),
    audit_window_days: asNumber(value.audit_window_days),
    audit_limit: asNumber(value.audit_limit),
    min_retention_days: asNumber(value.min_retention_days),
    api_key_max_age_days: asNumber(value.api_key_max_age_days),
    business_service_limit: asNumber(value.business_service_limit),
    change_event_days: asNumber(value.change_event_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function assessmentOptions(args: AssessArgs): PagerdutyAssessmentOptions {
  return {
    userLimit: args.user_limit,
    teamLimit: args.team_limit,
    maxAdmins: args.max_admins,
    serviceLimit: args.service_limit,
    scheduleLimit: args.schedule_limit,
    coverageDays: args.coverage_days,
    auditWindowDays: args.audit_window_days,
    auditLimit: args.audit_limit,
    minRetentionDays: args.min_retention_days,
    apiKeyMaxAgeDays: args.api_key_max_age_days,
    businessServiceLimit: args.business_service_limit,
    changeEventDays: args.change_event_days,
  };
}

function createClient(args: AuthArgs): PagerdutyApiClient {
  return new PagerdutyApiClient(resolvePagerdutyConfiguration(args as JsonRecord));
}

const authParams = {
  api_token: Type.Optional(Type.String({ description: "PagerDuty REST API key (account or user token). Defaults to PAGERDUTY_API_TOKEN or PAGERDUTY_API_KEY." })),
  access_token: Type.Optional(Type.String({ description: "Pre-issued PagerDuty OAuth bearer token. Defaults to PAGERDUTY_ACCESS_TOKEN." })),
  client_id: Type.Optional(Type.String({ description: "Scoped OAuth app client ID for the client_credentials flow. Defaults to PAGERDUTY_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "Scoped OAuth app client secret. Defaults to PAGERDUTY_CLIENT_SECRET." })),
  subdomain: Type.Optional(Type.String({ description: "PagerDuty account subdomain, required for the client_credentials flow. Defaults to PAGERDUTY_SUBDOMAIN." })),
  region: Type.Optional(Type.String({ description: "Service region: us (api.pagerduty.com) or eu (api.eu.pagerduty.com). Defaults to PAGERDUTY_REGION or us." })),
  base_url: Type.Optional(Type.String({ description: "Explicit REST API base URL. Overrides region. Defaults to PAGERDUTY_BASE_URL." })),
  from_email: Type.Optional(Type.String({ description: "Optional From header email recorded on requests. Defaults to PAGERDUTY_USER_EMAIL." })),
  config_file: Type.Optional(Type.String({ description: "Optional JSON config file. Defaults to PAGERDUTY_CONFIG_FILE or ~/.config/grclanker/pagerduty.json." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const limitParams = {
  user_limit: Type.Optional(Type.Number({ description: "Maximum users to inspect. Defaults to 1000.", default: 1000 })),
  team_limit: Type.Optional(Type.Number({ description: "Maximum teams whose membership is sampled. Defaults to 50.", default: 50 })),
  service_limit: Type.Optional(Type.Number({ description: "Maximum services to inspect. Defaults to 1000.", default: 1000 })),
};

function auditLimitParam() {
  return Type.Optional(Type.Number({
    description: `Maximum recent audit records to fetch. Defaults to ${DEFAULT_AUDIT_LIMIT}.`,
    default: DEFAULT_AUDIT_LIMIT,
  }));
}

function runAssessmentTool(
  pi: any,
  name: string,
  label: string,
  description: string,
  extraParams: Record<string, unknown>,
  run: (client: PagerdutyApiClient, options: PagerdutyAssessmentOptions) => Promise<PagerdutyAssessmentResult>,
): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object({ ...authParams, ...extraParams } as Record<string, any>),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await run(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(`${label} failed: ${errorMessage(error)}`, { tool: name });
      }
    },
  });
}

export function registerPagerdutyTools(pi: any): void {
  pi.registerTool({
    name: "pagerduty_check_access",
    label: "Check PagerDuty audit access",
    description:
      "Validate read-only PagerDuty REST API access across abilities, users, teams, services, escalation policies, schedules, on-calls, audit records, extensions, webhook subscriptions, business services, priorities, incident workflows, and change events, and report missing permissions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkPagerdutyAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "pagerduty_check_access", ...result });
      } catch (error) {
        return errorResult(`PagerDuty access check failed: ${errorMessage(error)}`, { tool: "pagerduty_check_access" });
      }
    },
  });

  runAssessmentTool(
    pi,
    "pagerduty_assess_access_control",
    "Assess PagerDuty access control",
    "Assess PagerDuty access control (spec controls 1-4 and 24): SSO availability, owner and admin least privilege, team-based access, and analytics role review.",
    {
      user_limit: limitParams.user_limit,
      team_limit: limitParams.team_limit,
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable owner plus admin users before failing. Defaults to 5.", default: 5 })),
    },
    runPagerdutyAccessControlAssessment,
  );

  runAssessmentTool(
    pi,
    "pagerduty_assess_incident_response",
    "Assess PagerDuty incident response configuration",
    "Assess PagerDuty incident response configuration (spec controls 5-7, 10, 19, 20, 22, 23): escalation policy assignment, levels and repeat behavior, incident workflows, urgency rules, priorities, and acknowledgement plus auto-resolve timeouts.",
    { service_limit: limitParams.service_limit },
    runPagerdutyIncidentResponseAssessment,
  );

  runAssessmentTool(
    pi,
    "pagerduty_assess_oncall_coverage",
    "Assess PagerDuty on-call coverage",
    "Assess PagerDuty on-call coverage (spec controls 8, 9, 17, 18): final-schedule coverage gaps, single-participant schedules, responder notification rules, and contact methods for current on-call users.",
    {
      schedule_limit: Type.Optional(Type.Number({ description: "Maximum schedules to render. Defaults to 50.", default: 50 })),
      coverage_days: Type.Optional(Type.Number({ description: "Days ahead to check final-schedule coverage. Defaults to 30.", default: 30 })),
      user_limit: limitParams.user_limit,
    },
    runPagerdutyOncallCoverageAssessment,
  );

  runAssessmentTool(
    pi,
    "pagerduty_assess_audit_logging",
    "Assess PagerDuty audit logging",
    "Assess PagerDuty audit logging (spec controls 11-13): audit record availability, retention against the documented 12 months, and API key rotation evidence derived from audit record token usage.",
    {
      audit_window_days: Type.Optional(Type.Number({ description: "Recent audit window in days (maximum 31 per the API). Defaults to 30.", default: 30 })),
      audit_limit: auditLimitParam(),
      min_retention_days: Type.Optional(Type.Number({ description: "Required audit retention in days. Defaults to 365.", default: 365 })),
      api_key_max_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable API key age in days for the manual rotation review. Defaults to 90.", default: 90 })),
    },
    runPagerdutyAuditLoggingAssessment,
  );

  runAssessmentTool(
    pi,
    "pagerduty_assess_integration_security",
    "Assess PagerDuty integration security",
    "Assess PagerDuty integration security (spec controls 14-16, 21, 25): HTTPS webhook delivery, v3 webhook signing versus legacy extensions, inbound integration scoping, business service dependency mapping, and change event tracking.",
    {
      service_limit: limitParams.service_limit,
      business_service_limit: Type.Optional(Type.Number({ description: "Maximum business services whose dependencies are fetched. Defaults to 50.", default: 50 })),
      change_event_days: Type.Optional(Type.Number({ description: "Days of change events to inspect. Defaults to 30.", default: 30 })),
    },
    runPagerdutyIntegrationSecurityAssessment,
  );

  pi.registerTool({
    name: "pagerduty_export_audit_bundle",
    label: "Export PagerDuty audit bundle",
    description:
      "Export a PagerDuty audit package covering all 25 spec controls with projected and redacted API snapshots plus not-collected markers for denied datasets (core_data/), normalized findings (analysis/), executive summary, unified matrix and per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log for partial failures, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...limitParams,
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable owner plus admin users before failing. Defaults to 5.", default: 5 })),
      schedule_limit: Type.Optional(Type.Number({ description: "Maximum schedules to render. Defaults to 50.", default: 50 })),
      coverage_days: Type.Optional(Type.Number({ description: "Days ahead to check final-schedule coverage. Defaults to 30.", default: 30 })),
      audit_window_days: Type.Optional(Type.Number({ description: "Recent audit window in days (maximum 31). Defaults to 30.", default: 30 })),
      audit_limit: auditLimitParam(),
      min_retention_days: Type.Optional(Type.Number({ description: "Required audit retention in days. Defaults to 365.", default: 365 })),
      api_key_max_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable API key age in days. Defaults to 90.", default: 90 })),
      business_service_limit: Type.Optional(Type.Number({ description: "Maximum business services whose dependencies are fetched. Defaults to 50.", default: 50 })),
      change_event_days: Type.Optional(Type.Number({ description: "Days of change events to inspect. Defaults to 30.", default: 30 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolvePagerdutyConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportPagerdutyAuditBundle(new PagerdutyApiClient(config), config, outputRoot, assessmentOptions(args));
        return textResult(
          [
            "PagerDuty audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "pagerduty_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`PagerDuty audit bundle export failed: ${errorMessage(error)}`, { tool: "pagerduty_export_audit_bundle" });
      }
    },
  });
}
