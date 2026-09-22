/**
 * ServiceNow instance security inspector for grclanker.
 *
 * Read-only Table API and Aggregate API access across identity, platform
 * hardening, access control, and operations governance controls. Every verdict
 * is evidence-gated: unreadable, forbidden, ACL-filtered, truncated, or empty
 * inventories never produce a pass on their own.
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
import { YAMLError, parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/servicenow";
const DEFAULT_CONFIG_DIR = ".servicenow-sec-inspector";
const DEFAULT_CONFIG_FILE = "config.yaml";
const REDACTED = "[REDACTED]";
// ServiceNow passwords, OAuth client secrets, and bearer tokens are long; a shorter minimum would
// remember common words and redact them out of ordinary error text.
const MIN_REMEMBERED_SECRET_LENGTH = 8;
/** Nesting beyond this depth is left as served; parsed API payloads never reach it. */
const MAX_REDACTION_DEPTH = 32;
/** Every credential literal a client in this process was configured with or obtained from oauth_token.do. */
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
const URL_IN_TEXT_PATTERN = /\b(https?:\/\/)(?:([^\s/?#@"'<>]+)@)?([^\s/?#"'<>]+)([^\s?#"'<>]*)(\?[^\s#"'<>]*)?(#[^\s"'<>]*)?/gi;
// A query pair standing without its URL (`?token=...`, `&sid=...`).
const BARE_QUERY_PAIR_PATTERN = /([?&][\w.~%-]+=)([^\s"'&#<>\\]+)/g;
// Header name to value: `: `, `="`, or the JSON-escaped `\":\"`.
const HEADER_SEPARATOR = String.raw`\\?["']?\s*[:=]\s*\\?["']?`;
// The next header on the same line (`; X-Api-Key: x`, `, Content-Type: x`, ` Accept: x`, a quoted or JSON-object
// name too): a cookie or header value ends before it, so that header keeps its name and gets its own carrier treatment.
const NEXT_HEADER_NAME = String.raw`\s*\{?\s*\\?["']?[A-Za-z][\w-]*\\?["']?\s*:`;
// The schemes that stand as carriers in prose (the ruling's list) and the wider set recognized inside an Authorization header.
const PROSE_AUTH_SCHEMES = "bearer|basic|digest|token|apikey|api-key";
const HEADER_AUTH_SCHEMES = `${PROSE_AUTH_SCHEMES}|negotiate|ntlm|hmac|oauth|hoba|mutual|vapid|aws4-hmac-sha256|scram-sha-1|scram-sha-256`;
// A quoted value, in double quotes (possibly JSON-escaped) or single quotes, on one line. Quotes around a
// credential belong to its carrier: `Bearer "x"`, `sid='x'`, `--token "x"` carry x whatever its shape.
const QUOTED_VALUE = String.raw`\\?"[^"\\\r\n]+\\?"|'[^'\r\n]+'`;
// One credential token (bare or quoted), or a parameter list such as Digest's `username="u", response="r"`
// (quotes possibly JSON-escaped or single) or PagerDuty's `token=k`.
const CREDENTIAL_TOKEN = String.raw`(?:${QUOTED_VALUE}|[^\s"'<>,;\\]+)`;
const CREDENTIAL_PARAMETER_VALUE = String.raw`(?:\\?"[^"\\\r\n]*\\?"|'[^'\r\n]*'|[^\s"',;<>\\]+)`;
const CREDENTIAL_PARAMETERS = String.raw`[\w-]+=${CREDENTIAL_PARAMETER_VALUE}(?:\s*[,;]\s*[\w-]+=${CREDENTIAL_PARAMETER_VALUE})*`;
// The whole value of an Authorization header: a scheme and its credential, or up to two tokens for an unknown scheme.
const AUTHORIZATION_HEADER_PATTERN = new RegExp(
  String.raw`\b((?:proxy-)?authorization)(${HEADER_SEPARATOR})(?:(?:${HEADER_AUTH_SCHEMES})\s+(?:${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN})|${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN}(?:\s+(?!${NEXT_HEADER_NAME})${CREDENTIAL_TOKEN})?)`,
  "gi",
);
// Cookie and Set-Cookie headers: every pair of the header value is a session credential. A pair's value may be
// quoted (`sid="x"`, `sid = 'x'`, JSON-escaped `sid=\"x\"`) and ends at its closing quote; a quote anywhere else
// closes the value, so the next header of a JSON headers object is not taken; an unquoted value runs to the
// `;`, `,`, or space that begins the next header on the line, or to the end of the line.
const COOKIE_PAIR_VALUE = String.raw`(?<==\s*)(?:\\?"[^"\\\r\n,;\s][^"\\\r\n]*\\?"|'[^'\r\n,;\s][^'\r\n]*')`;
const COOKIE_HEADER_VALUE = String.raw`(?:[^\s"'<>\\;,]|[ \t;,](?!${NEXT_HEADER_NAME})|${COOKIE_PAIR_VALUE})+`;
const COOKIE_HEADER_PATTERN = new RegExp(String.raw`\b(set-cookie|cookie)(${HEADER_SEPARATOR})(${COOKIE_HEADER_VALUE})`, "gi");
// A scheme standing in prose (`Bearer x`, `Bearer "x"`, `Token token=x`, `ApiKey x`); a scheme word that is itself a
// header or field name (`X-Api-Key : x`) is left to the field rule.
const AUTH_SCHEME_PATTERN = new RegExp(String.raw`\b(${PROSE_AUTH_SCHEMES})(?!\s*[:=])\s+(${CREDENTIAL_PARAMETERS}|${CREDENTIAL_TOKEN})`, "gi");
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
  String.raw`(?<![\w.-])([\w.-]*(?:sess|sid|token|secret|passw|passphrase|pwd|passcode|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|assertion|signature|auth|cookie|otp)[\w.-]*\s*=\s*)(${QUOTED_VALUE}|[^\s"'&;,<>\\]+)`,
  "gi",
);
// Credential-named fields and single-value credential headers (`x-api-key: x`, `"password": "x"`, `\"access_token\":\"x\"`).
const SECRET_FIELD_PATTERN = /(?<![\w/.-])((?:[\w-]*(?:api[_-]?key|apikey|token|secret|passw|passphrase|credential|assertion|signature|private[_-]?key|access[_-]?key|authorization)[\w-]*|pwd|passcode|otp|sid|jsessionid|session|sessionid|session[_-]?id|cookie|set-cookie|x-auth|x-token|x-secret|auth)\\?["']?\s*:\s*\\?["']?)([^\s"'&;,<>\\]+)/gi;
// SOAP and XML credential elements (`<sessionId>x</sessionId>`, `<urn:password>x</urn:password>`).
const CREDENTIAL_ELEMENT_PATTERN = /<((?:[\w.-]+:)?(?:session_?id|session|passw(?:or)?d|pwd|passcode|otp|token|access_?token|refresh_?token|id_?token|secret|client_?secret|api_?key|apikey|assertion|signature|credentials?|authorization|private_?key)[\w-]*)(\s[^>]*)?>([^<]*)<\/\1\s*>/gi;
// Command-line credential flags (`--token x`, `-password x`); the flag starts a word, so `access-token against` is prose.
const CLI_SECRET_FLAG_PATTERN = new RegExp(
  String.raw`(?<![\w-])(--?(?:token|password|passwd|pwd|passcode|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|credential|auth|bearer|session|cookie|sid|otp)\s+)(${QUOTED_VALUE}|[^\s"'&;,<>-][^\s"'&;,<>]*)`,
  "gi",
);
// Real token shapes, removed bare.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const HEX_DIGEST_PATTERN = /(?<![A-Za-z0-9])[0-9a-f]{32,}(?![A-Za-z0-9])/gi;
const VENDOR_TOKEN_PATTERN = /\b(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abopsre]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{20,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{30,}|dop_v1_[a-f0-9]{40,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|hvs\.[A-Za-z0-9_-]{20,}|shpat_[a-fA-F0-9]{32}|dckr_pat_[A-Za-z0-9_-]{20,}|lin_api_[A-Za-z0-9]{20,}|figd_[A-Za-z0-9_-]{20,}|u\+[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/g;
// A run long enough to be a token; redactTokenRun decides by segment shape whether it is one.
const BARE_TOKEN_RUN_PATTERN = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])/g;
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
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_PAGE_SIZE = 500;
const DEFAULT_RECORD_LIMIT = 10_000;
const DEFAULT_INACTIVE_DAYS = 90;
const DEFAULT_MAX_SESSION_TIMEOUT_MINUTES = 60;
const DEFAULT_MIN_PASSWORD_LENGTH = 12;
const DEFAULT_CERT_EXPIRY_WARN_DAYS = 30;
const DEFAULT_MAX_ADMINS = 10;
const MAX_RETRY_AFTER_MS = 60_000;
const AUDIT_LOOKBACK_DAYS = 7;

const PRIVILEGED_ROLE_NAMES = ["admin", "security_admin", "user_admin", "impersonator", "maint"];
const ELEVATED_ROLE_NAMES = ["admin", "security_admin"];
const AUDITED_CRITICAL_TABLES = ["sys_user", "sys_user_has_role", "sys_user_role", "sys_security_acl", "sys_properties"];
const SENSITIVE_ACL_TABLES = ["sys_user", "sys_user_has_role", "sys_user_role", "sys_properties", "sys_script", "sys_security_acl", "syslog", "sys_audit"];
const REQUIRED_SECURITY_PLUGINS = [
  { key: "high_security", pattern: /high security/i, label: "High Security Settings" },
  { key: "contextual_security_v2", pattern: /contextual security.*role management v2/i, label: "Contextual Security: Role Management V2" },
  { key: "security_jump_start", pattern: /security jump ?start/i, label: "Security Jump Start (ACL Rules)" },
];
const OPTIONAL_SECURITY_PLUGINS = [
  { key: "instance_security_center", pattern: /instance security center/i, label: "Instance Security Center" },
  { key: "security_incident_response", pattern: /security incident response/i, label: "Security Incident Response" },
  { key: "grc", pattern: /governance, risk,? and compliance|policy and compliance/i, label: "GRC" },
  { key: "vulnerability_response", pattern: /vulnerability response/i, label: "Vulnerability Response" },
];

export type ServicenowAuthMode = "basic" | "oauth" | "mtls";
export type ServicenowSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ServicenowFindingStatus = "pass" | "warn" | "fail" | "manual";
export type ServicenowArea = "identity_access" | "platform_hardening" | "access_control" | "operations_governance";
export type ServicenowFramework = "FedRAMP" | "CMMC" | "SOC 2" | "CIS" | "PCI-DSS" | "STIG" | "IRAP" | "ISMAP";

export interface ServicenowResolvedConfig {
  instanceUrl: string;
  instanceName: string;
  authMode: ServicenowAuthMode;
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  accessToken?: string;
  /** A refresh token issued earlier to the OAuth client; when present the first token exchange uses the refresh_token grant. */
  refreshToken?: string;
  timeoutMs: number;
  maxRetries: number;
  pageSize: number;
  sourceChain: string[];
}

export interface TableSnapshot {
  table: string;
  query?: string;
  rows: JsonRecord[];
  total?: number;
  pages: number;
  truncated: boolean;
  /** Why pagination stopped before the inventory was exhausted; set whenever truncated is true. */
  truncationReason?: string;
  /** True when rows came back without an X-Total-Count header, so the population size is unproven. */
  totalUnknown?: boolean;
  partial: boolean;
  error?: string;
  statusCode?: number;
  unavailable?: string;
  /** Path of the Table API request that was issued for this snapshot; absent when no request was made. */
  endpoint?: string;
  /** Set when no request was issued at all, with the reason; the flags and counts on such a snapshot are placeholders. */
  skipped?: string;
}

export interface CountResult {
  table: string;
  query?: string;
  count?: number;
  error?: string;
  statusCode?: number;
  /** Path of the Aggregate API request that was issued; absent when no request was made. */
  endpoint?: string;
}

/**
 * Written to core_data in place of a table or aggregate dataset that was denied, errored, unavailable,
 * or never requested, so a bundle consumer cannot mistake a denial for an empty inventory. A readable
 * table with no matching rows keeps its snapshot shape with `rows: []`.
 */
export interface NotCollectedMarker {
  collected: false;
  table: string;
  query: string | null;
  status: number | null;
  endpoint: string | null;
  error: string;
  pages?: number;
}

/** True when a Table API request was issued and answered with rows (possibly none); false for denied, errored, unavailable, or skipped reads. */
function tableCollected(snapshot: TableSnapshot): boolean {
  return !snapshot.error && !snapshot.unavailable && !snapshot.skipped;
}

export function tableCoreData(snapshot: TableSnapshot): TableSnapshot | NotCollectedMarker {
  if (tableCollected(snapshot)) return snapshot;
  const reason = snapshot.error
    ?? (snapshot.skipped ? `not requested: ${snapshot.skipped}` : `table unavailable: ${snapshot.unavailable}`);
  return {
    collected: false,
    table: snapshot.table,
    query: snapshot.query ?? null,
    status: snapshot.statusCode ?? null,
    endpoint: snapshot.endpoint ?? null,
    error: reason,
    ...(snapshot.pages > 0 ? { pages: snapshot.pages } : {}),
  };
}

export function countCoreData(count: CountResult): CountResult | NotCollectedMarker {
  if (!count.error) return count;
  return {
    collected: false,
    table: count.table,
    query: count.query ?? null,
    status: count.statusCode ?? null,
    endpoint: count.endpoint ?? null,
    error: count.error,
  };
}

export interface ServicenowAccessSurface {
  name: string;
  table: string;
  status: "readable" | "forbidden" | "acl_filtered" | "not_readable";
  /** Rows the probe returned; absent when the Table API read was not answered with rows. */
  visible?: number;
  /** Aggregate count, or the X-Total-Count header when the aggregate failed; absent when neither request answered. */
  total?: number;
  /** HTTP status the failed Table API probe observed; absent for readable surfaces and non-HTTP failures. */
  http_status?: number;
  error?: string;
}

export interface ServicenowAccessCheckResult {
  status: "healthy" | "limited";
  instanceUrl: string;
  authMode: ServicenowAuthMode;
  identity?: string;
  surfaces: ServicenowAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface ServicenowFinding {
  id: string;
  control: number;
  title: string;
  severity: ServicenowSeverity;
  status: ServicenowFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  manualEvidence?: string;
}

export interface ServicenowAssessmentResult {
  area: ServicenowArea;
  title: string;
  summary: JsonRecord;
  findings: ServicenowFinding[];
  errors: string[];
}

export interface ServicenowAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface ServicenowIdentityOptions {
  inactiveDays?: number;
  minPasswordLength?: number;
  certExpiryWarnDays?: number;
  maxAdmins?: number;
  recordLimit?: number;
}

export interface ServicenowHardeningOptions {
  maxSessionTimeoutMinutes?: number;
  recordLimit?: number;
}

export interface ServicenowAccessControlOptions {
  recordLimit?: number;
}

export interface ServicenowOperationsOptions {
  recordLimit?: number;
}

export type ServicenowExportOptions = ServicenowIdentityOptions & ServicenowHardeningOptions & ServicenowAccessControlOptions & ServicenowOperationsOptions;

type AuthArgs = {
  instance?: string;
  instance_url?: string;
  auth_method?: string;
  username?: string;
  password?: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  config_file?: string;
  timeout_seconds?: number;
  max_retries?: number;
  page_size?: number;
};

type IdentityArgs = AuthArgs & {
  inactive_days?: number;
  min_password_length?: number;
  cert_expiry_warn_days?: number;
  max_admins?: number;
  record_limit?: number;
};

type HardeningArgs = AuthArgs & {
  max_session_timeout_minutes?: number;
  record_limit?: number;
};

type LimitArgs = AuthArgs & {
  record_limit?: number;
};

type ExportArgs = IdentityArgs & HardeningArgs & {
  output_dir?: string;
};

interface ControlDefinition {
  title: string;
  severity: ServicenowSeverity;
  area: ServicenowArea;
  mappings: Record<ServicenowFramework, string>;
}

const FRAMEWORK_ORDER: ServicenowFramework[] = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"];

const FRAMEWORK_REPORTS: Array<{ framework: ServicenowFramework; path: string; title: string }> = [
  { framework: "FedRAMP", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { framework: "CMMC", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC 2.0 Compliance Report" },
  { framework: "SOC 2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { framework: "CIS", path: "compliance/cis/cis_compliance_report.md", title: "CIS Controls Alignment Report" },
  { framework: "PCI-DSS", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { framework: "STIG", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { framework: "IRAP", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { framework: "ISMAP", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

function control(
  title: string,
  severity: ServicenowSeverity,
  area: ServicenowArea,
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

const SERVICENOW_CONTROLS: Record<number, ControlDefinition> = {
  1: control("Instance security properties", "high", "platform_hardening", ["CM-6", "3.4.2", "CC6.1", "5.1", "2.2.1", "SRG-APP-000384", "ISM-1624", "CPS.CM-6"]),
  2: control("ACL rule completeness", "high", "access_control", ["AC-3", "3.1.2", "CC6.1", "n/a", "7.1.1", "SRG-APP-000033", "ISM-0405", "CPS.AC-3"]),
  3: control("Role hierarchy audit", "high", "identity_access", ["AC-6(1)", "3.1.5", "CC6.3", "n/a", "7.1.1", "SRG-APP-000340", "ISM-1507", "CPS.AC-6"]),
  4: control("User access review", "high", "identity_access", ["AC-2(3)", "3.1.12", "CC6.2", "5.3", "8.1.4", "SRG-APP-000025", "ISM-1591", "CPS.AC-2"]),
  5: control("Session timeout configuration", "medium", "platform_hardening", ["AC-12", "3.1.10", "CC6.1", "16.4", "8.2.8", "SRG-APP-000295", "ISM-1164", "CPS.AC-7"]),
  6: control("Password policy enforcement", "high", "identity_access", ["IA-5(1)", "3.5.7", "CC6.1", "5.2", "8.3.6", "SRG-APP-000164", "ISM-0421", "CPS.IA-5"]),
  7: control("MFA enforcement", "critical", "identity_access", ["IA-2(1)", "3.5.3", "CC6.1", "6.3", "8.4.2", "SRG-APP-000149", "ISM-1504", "CPS.AT-2"]),
  8: control("LDAP/SSO integration", "high", "identity_access", ["IA-2(12)", "3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000395", "ISM-1546", "CPS.IA-2"]),
  9: control("Encryption at rest", "medium", "operations_governance", ["SC-28", "3.13.16", "CC6.1", "n/a", "3.4.1", "SRG-APP-000429", "ISM-0457", "CPS.SC-28"]),
  10: control("Audit logging configuration", "high", "operations_governance", ["AU-3", "3.3.1", "CC7.2", "8.5", "10.2.1", "SRG-APP-000095", "ISM-0580", "CPS.AU-3"]),
  11: control("Table-level access controls", "high", "access_control", ["AC-3(7)", "3.1.2", "CC6.1", "n/a", "7.1.2", "SRG-APP-000033", "ISM-0405", "CPS.AC-3"]),
  12: control("Script execution restrictions", "high", "platform_hardening", ["CM-7(2)", "3.4.8", "CC6.8", "n/a", "6.2.4", "SRG-APP-000141", "ISM-1624", "CPS.CM-7"]),
  13: control("Instance hardening", "high", "platform_hardening", ["CM-6(1)", "3.4.2", "CC6.1", "n/a", "2.2.1", "SRG-APP-000384", "ISM-1624", "CPS.CM-6"]),
  14: control("Integration user permissions", "high", "identity_access", ["AC-6(10)", "3.1.7", "CC6.3", "n/a", "7.1.2", "SRG-APP-000343", "ISM-0988", "CPS.AC-6"]),
  15: control("Update set management", "medium", "operations_governance", ["CM-3", "3.4.3", "CC8.1", "n/a", "6.5.1", "SRG-APP-000380", "ISM-1624", "CPS.CM-3"]),
  16: control("Debug mode verification", "medium", "platform_hardening", ["CM-7", "3.4.7", "CC6.1", "n/a", "2.2.1", "SRG-APP-000141", "ISM-1624", "CPS.CM-7"]),
  17: control("IP access restrictions", "medium", "platform_hardening", ["AC-17(1)", "3.1.12", "CC6.6", "n/a", "1.3.1", "SRG-APP-000142", "ISM-1528", "CPS.AC-17"]),
  18: control("Email security", "medium", "platform_hardening", ["SC-8", "3.13.8", "CC6.7", "n/a", "4.1.1", "SRG-APP-000411", "ISM-0572", "CPS.SC-8"]),
  19: control("MID Server security", "medium", "operations_governance", ["SC-7(7)", "3.13.6", "CC6.6", "n/a", "1.3.2", "SRG-APP-000001", "ISM-1528", "CPS.SC-7"]),
  20: control("Plugin inventory and licensing", "low", "operations_governance", ["CM-7(4)", "3.4.8", "CC6.8", "n/a", "2.2.1", "SRG-APP-000386", "ISM-1624", "CPS.CM-7"]),
};

export function mappingsForControl(controlNumber: number): string[] {
  const definition = SERVICENOW_CONTROLS[controlNumber];
  if (!definition) return [];
  return FRAMEWORK_ORDER.map((framework) => `${framework} ${definition.mappings[framework]}`);
}

export function listServicenowControls(): Array<{ control: number; id: string; title: string; severity: ServicenowSeverity; area: ServicenowArea }> {
  return Object.entries(SERVICENOW_CONTROLS).map(([key, definition]) => ({
    control: Number(key),
    id: findingId(Number(key)),
    title: definition.title,
    severity: definition.severity,
    area: definition.area,
  }));
}

function findingId(controlNumber: number): string {
  return `SNOW-${String(controlNumber).padStart(2, "0")}`;
}

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asRecordArray(value: unknown): JsonRecord[] {
  if (!Array.isArray(value)) return [];
  return value.map(asObject).filter((item): item is JsonRecord => Boolean(item));
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return String(value);
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
    if (/^(true|1|yes|active|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|inactive|off)$/i.test(value.trim())) return false;
  }
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function normalizeBaseUrl(rawUrl: string): string {
  const withScheme = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(withScheme);
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
  return normalized || "servicenow";
}

function parseServicenowDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text) ? `${text.replace(" ", "T")}Z` : text;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysBetween(later: Date, earlier: Date): number {
  return Math.floor((later.getTime() - earlier.getTime()) / 86_400_000);
}

/** "403 Forbidden", or just "403" when the server (or an HTTP/2 hop) sent no reason phrase. */
function describeStatus(response: Response): string {
  return response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
}

/**
 * The single point where a thrown error becomes a recorded string (table and count snapshot errors,
 * access-check surfaces, errors arrays, _errors.log, tool error results). It re-applies the redaction
 * pass so a message built outside ServicenowApiError (a transport error, a timeout, a token response
 * without access_token) cannot bypass it.
 */
function errorMessage(error: unknown): string {
  return scrubSecretText(error instanceof Error ? error.message : String(error));
}

/**
 * The unanchored redaction pass applied to every error string (once in ServicenowApiError, again at
 * errorMessage): every secret any client in this process has seen, in every form it can take in an
 * echoed body, then the carriers (URL userinfo, query strings, and fragments anywhere in the text,
 * Authorization and cookie headers, auth schemes in prose, credential-named assignments, fields, and
 * elements, command-line flags), then the bare token shapes (PEM blocks, JWTs, hex digests, vendor
 * prefixes, and long runs with base64 symbols, scattered digits, or token casing).
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
 * form, then the carrier stage. It has no bare-token stage, so prose identifiers (a UUID, a sys_id, a
 * name such as prod-us-east-2026) stay while a header line, URL credential, assignment, or configured
 * secret embedded in a description, name, or note goes.
 */
function scrubDataText(text: string): string {
  return scrubCarriers(scrubRememberedSecrets(text));
}

/** A collected value with every string leaf through the data-side pass; arrays and plain objects are rebuilt, other values are kept. */
function scrubDataStrings<T>(value: T, depth = 0): T {
  if (typeof value === "string") return scrubDataText(value) as T;
  if (depth > MAX_REDACTION_DEPTH || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => scrubDataStrings(item, depth + 1)) as T;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return value;
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) output[key] = scrubDataStrings(entry, depth + 1);
  return output as T;
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

/**
 * Thrown by the config loader. The message is fixed text carrying only the path, the fs error code,
 * and the line: neither Node's fs message (which quotes its own wording and path) nor the yaml
 * parser's message (which quotes the offending source line, or for an unresolved alias starts with
 * the alias value) is ever interpolated.
 */
export class ServicenowConfigFileError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "ServicenowConfigFileError";
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
    throw new ServicenowConfigFileError(`Unable to read ServiceNow config file ${pathname}${code ? ` (${code})` : ""}`, code ?? "EUNKNOWN");
  }
}

/**
 * Parse step of the config loader: every thrown value is caught (the yaml package throws a plain
 * ReferenceError, not a YAMLError, for an unresolved alias) and only a YAMLError's line is kept.
 */
function parseConfigFileYaml(pathname: string, text: string): unknown {
  try {
    return parseYaml(text);
  } catch (error) {
    const line = error instanceof YAMLError ? error.linePos?.[0]?.line : undefined;
    throw new ServicenowConfigFileError(`Unable to parse ServiceNow config file: invalid YAML in ${pathname}${line ? ` at line ${line}` : ""}`, "INVALID_YAML");
  }
}

function truncateList<T>(items: T[], max = 25): T[] {
  return items.slice(0, max);
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

function parseAuthMode(value: string | undefined): ServicenowAuthMode | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "basic" || normalized === "oauth" || normalized === "mtls") return normalized;
  if (normalized === "oauth2" || normalized === "oauth_client_credentials" || normalized === "client_credentials" || normalized === "password") return "oauth";
  return undefined;
}

interface ConfigOverlay {
  instanceUrl?: string;
  instanceName?: string;
  authMode?: ServicenowAuthMode;
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  accessToken?: string;
  timeoutSeconds?: number;
  maxRetries?: number;
  pageSize?: number;
}

function overlayFromRecord(record: JsonRecord): ConfigOverlay {
  const pick = (...keys: string[]): unknown => {
    for (const key of keys) {
      if (record[key] !== undefined && record[key] !== null && record[key] !== "") return record[key];
    }
    return undefined;
  };
  return {
    instanceUrl: asString(pick("instance_url", "url", "instanceUrl", "base_url")),
    instanceName: asString(pick("instance", "instance_name", "instanceName")),
    authMode: parseAuthMode(asString(pick("auth_method", "authMethod", "auth_mode"))),
    username: asString(pick("username", "user")),
    password: asString(pick("password")),
    clientId: asString(pick("client_id", "clientId")),
    clientSecret: asString(pick("client_secret", "clientSecret")),
    accessToken: asString(pick("access_token", "accessToken", "token")),
    timeoutSeconds: asNumber(pick("timeout_seconds", "timeout")),
    maxRetries: asNumber(pick("max_retries", "maxRetries")),
    pageSize: asNumber(pick("page_size", "pageSize")),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): ConfigOverlay {
  return {
    instanceUrl: asString(env.SERVICENOW_URL) ?? asString(env.SERVICENOW_INSTANCE_URL),
    instanceName: asString(env.SERVICENOW_INSTANCE),
    authMode: parseAuthMode(asString(env.SERVICENOW_AUTH_METHOD)),
    username: asString(env.SERVICENOW_USERNAME),
    password: asString(env.SERVICENOW_PASSWORD),
    clientId: asString(env.SERVICENOW_CLIENT_ID),
    clientSecret: asString(env.SERVICENOW_CLIENT_SECRET),
    accessToken: asString(env.SERVICENOW_ACCESS_TOKEN) ?? asString(env.SERVICENOW_TOKEN),
    timeoutSeconds: asNumber(env.SERVICENOW_TIMEOUT),
    maxRetries: asNumber(env.SERVICENOW_MAX_RETRIES),
    pageSize: asNumber(env.SERVICENOW_PAGE_SIZE),
  };
}

function applyOverlay(base: ConfigOverlay, overlay: ConfigOverlay, source: string, sourceChain: string[]): ConfigOverlay {
  const merged: ConfigOverlay = { ...base };
  let applied = false;
  for (const [key, value] of Object.entries(overlay) as Array<[keyof ConfigOverlay, unknown]>) {
    if (value === undefined) continue;
    (merged as Record<string, unknown>)[key] = value;
    applied = true;
  }
  if (applied) sourceChain.push(source);
  return merged;
}

/**
 * Loads one candidate config file. A default candidate that does not exist is skipped; an explicit
 * path that cannot be read fails with the fixed-text read error (ENOENT included).
 */
function readYamlConfigFile(pathname: string, explicit = false): ConfigOverlay | undefined {
  if (!explicit && !existsSync(pathname)) return undefined;
  const parsed = parseConfigFileYaml(pathname, readConfigFileText(pathname));
  const record = asObject(parsed);
  if (!record) return undefined;
  const section = asObject(record.servicenow);
  return overlayFromRecord(section ? { ...record, ...section } : record);
}

function inferAuthMode(overlay: ConfigOverlay): ServicenowAuthMode {
  if (overlay.authMode) return overlay.authMode;
  if (overlay.accessToken) return "oauth";
  if (overlay.clientId && overlay.clientSecret) return "oauth";
  if (overlay.username && overlay.password) return "basic";
  throw new Error(
    "ServiceNow credentials are required. Set SERVICENOW_USERNAME plus SERVICENOW_PASSWORD for basic auth, SERVICENOW_CLIENT_ID plus SERVICENOW_CLIENT_SECRET (optionally with username and password for the password grant) for OAuth, or SERVICENOW_ACCESS_TOKEN for a pre-issued bearer token.",
  );
}

export function resolveServicenowConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { cwd?: string; homeDir?: string } = {},
): ServicenowResolvedConfig {
  const cwd = options.cwd ?? process.cwd();
  const homeDir = options.homeDir ?? homedir();
  const sourceChain: string[] = [];

  const explicitConfigPath = asString(input.config_file) ?? asString(env.SERVICENOW_CONFIG_FILE);
  const configCandidates = explicitConfigPath
    ? [resolve(cwd, explicitConfigPath)]
    : [resolve(cwd, ".servicenow.yaml"), join(homeDir, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE)];

  let overlay: ConfigOverlay = {};
  for (const candidate of configCandidates) {
    const fileOverlay = readYamlConfigFile(candidate, Boolean(explicitConfigPath));
    if (fileOverlay) {
      overlay = applyOverlay(overlay, fileOverlay, `config-file:${candidate}`, sourceChain);
      break;
    }
    if (explicitConfigPath) {
      throw new ServicenowConfigFileError(`Unable to parse ServiceNow config file: ${candidate} must contain a YAML mapping`, "INVALID_YAML");
    }
  }
  overlay = applyOverlay(overlay, overlayFromEnv(env), "environment", sourceChain);
  overlay = applyOverlay(overlay, overlayFromRecord({
    instance_url: input.instance_url ?? input.url,
    instance: input.instance,
    auth_method: input.auth_method,
    username: input.username,
    password: input.password,
    client_id: input.client_id,
    client_secret: input.client_secret,
    access_token: input.access_token,
    timeout_seconds: input.timeout_seconds,
    max_retries: input.max_retries,
    page_size: input.page_size,
  }), "arguments", sourceChain);

  const rawUrl = overlay.instanceUrl ?? (overlay.instanceName ? `https://${overlay.instanceName}.service-now.com` : undefined);
  if (!rawUrl) {
    throw new Error("SERVICENOW_URL or SERVICENOW_INSTANCE (or an instance_url / instance argument) is required.");
  }
  const instanceUrl = normalizeBaseUrl(rawUrl);
  const instanceName = overlay.instanceName ?? new URL(instanceUrl).hostname.split(".")[0];
  const authMode = inferAuthMode(overlay);

  switch (authMode) {
    case "basic":
      if (!overlay.username || !overlay.password) {
        throw new Error("ServiceNow basic auth requires SERVICENOW_USERNAME and SERVICENOW_PASSWORD.");
      }
      break;
    case "oauth":
      if (!overlay.accessToken && (!overlay.clientId || !overlay.clientSecret)) {
        throw new Error("ServiceNow OAuth requires SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET (or SERVICENOW_ACCESS_TOKEN).");
      }
      break;
    case "mtls":
      throw new Error(
        "ServiceNow mutual TLS is recognized but not supported by this runtime's fetch client; set SERVICENOW_AUTH_METHOD to basic or oauth.",
      );
    default: {
      const exhaustive: never = authMode;
      throw new Error(`Unhandled ServiceNow auth mode: ${String(exhaustive)}`);
    }
  }

  return {
    instanceUrl,
    instanceName,
    authMode,
    username: overlay.username,
    password: overlay.password,
    clientId: overlay.clientId,
    clientSecret: overlay.clientSecret,
    accessToken: overlay.accessToken,
    timeoutMs: parseTimeoutSeconds(overlay.timeoutSeconds),
    maxRetries: clampNumber(overlay.maxRetries, DEFAULT_MAX_RETRIES, 0, 10),
    pageSize: clampNumber(overlay.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000),
    sourceChain: [...new Set(sourceChain)],
  };
}

/** The client's own credentials (including short ones) removed first, then the shared redaction pass with their encoded forms. */
export function redactSecrets(message: string, secrets: Array<string | undefined>): string {
  let redacted = message;
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    redacted = redacted.split(secret).join(REDACTED);
  }
  return scrubSecretText(redacted, secrets);
}

/**
 * The one error class the client throws for HTTP failures. The message is built from the status,
 * the request path, and either ServiceNow's documented error fields or a status-and-length note for
 * any other body; the constructor runs the redaction pass over the message and the detail
 * regardless of how they were built.
 */
export class ServicenowApiError extends Error {
  readonly status: number;
  readonly detail?: string;

  constructor(message: string, status: number, detail?: string) {
    super(scrubSecretText(message));
    this.name = "ServicenowApiError";
    this.status = status;
    this.detail = detail === undefined ? undefined : scrubSecretText(detail);
  }
}

/**
 * ServiceNow's documented error fields (`error.message`, `error.detail`, `status` on Table and
 * Aggregate API errors; `error` and `error_description` on oauth_token.do); nothing else in a body
 * is echoed.
 */
function servicenowErrorDetail(payload: JsonRecord): string | undefined {
  const error = asObject(payload.error);
  return [asString(error?.message), asString(error?.detail), asString(payload.error_description), asString(payload.status)]
    .filter((item): item is string => Boolean(item))
    .join("; ") || undefined;
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

export function parseLinkNext(header: string | null | undefined): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(",")) {
    const match = part.trim().match(/^<([^>]+)>\s*;\s*rel="?next"?/i);
    if (match) return match[1];
  }
  return undefined;
}

/**
 * Error strings land in access_check.json, analysis errors, and _errors.log, so an error body that
 * is not JSON (a proxy or gateway page that may echo request headers, whatever its content type
 * claims), or JSON without ServiceNow's documented error fields, is described by status, content
 * type, and byte length only and never quoted.
 */
function describeOpaqueBody(response: Response, rawText: string, parsedJson: boolean): string {
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

function requestPathname(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return "(unparseable url)";
  }
}

/**
 * Client-side counterpart of sysparm_fields: keep only the requested columns
 * so a server that ignores the parameter (or a widened schema) cannot land
 * password, key, or payload columns in the snapshot.
 */
export function projectRows(rows: JsonRecord[], fields: string[] | undefined): JsonRecord[] {
  if (!fields || fields.length === 0) return rows;
  const keep = new Set(fields);
  return rows.map((row) => Object.fromEntries(Object.entries(row).filter(([key]) => keep.has(key))));
}

export interface ServicenowTableQuery {
  query?: string;
  fields?: string[];
  limit?: number;
  pageSize?: number;
  displayValue?: boolean | "all";
}

/**
 * Every table read the collectors and the access check make goes through here, so each kept row passes
 * the data-side pass (remembered secrets and carriers, no bare-token stage) before it reaches a snapshot,
 * evidence, a summary, core_data, or a tool payload.
 */
async function readTable(client: Pick<ServicenowReadClient, "queryTable">, table: string, options: ServicenowTableQuery = {}): Promise<TableSnapshot> {
  const snapshot = await client.queryTable(table, options);
  return { ...snapshot, rows: scrubDataStrings(snapshot.rows) };
}

export interface ServicenowReadClient {
  getResolvedConfig(): ServicenowResolvedConfig;
  getNow(): Date;
  queryTable(table: string, options?: ServicenowTableQuery): Promise<TableSnapshot>;
  countRecords(table: string, query?: string): Promise<CountResult>;
}

export class ServicenowApiClient implements ServicenowReadClient {
  private readonly config: ServicenowResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: (ms: number) => Promise<void>;
  private readonly now: () => Date;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private refreshToken?: string;
  private tokenPromise?: Promise<string>;

  constructor(
    config: ServicenowResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: (ms: number) => Promise<void>;
      now?: () => Date;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.now = options.now ?? (() => new Date());
    if (config.accessToken) {
      this.accessToken = config.accessToken;
      this.accessTokenExpiresAt = Number.MAX_SAFE_INTEGER;
    }
    this.refreshToken = config.refreshToken;
    rememberSecrets(config.password, config.clientSecret, config.accessToken, config.refreshToken);
  }

  getResolvedConfig(): ServicenowResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private redact(message: string): string {
    return redactSecrets(message, [this.config.password, this.config.clientSecret, this.config.accessToken, this.accessToken, this.refreshToken]);
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.instanceUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, Array.isArray(value) ? value.join(",") : String(value));
    }
    return url.toString();
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) {
        throw new Error(`ServiceNow request timed out after ${this.config.timeoutMs}ms: ${requestPathname(url)}`);
      }
      throw new Error(`ServiceNow request failed: ${this.redact(errorMessage(error))}`);
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

  private async authorizationHeader(): Promise<string> {
    switch (this.config.authMode) {
      case "basic":
        return `Basic ${Buffer.from(`${this.config.username ?? ""}:${this.config.password ?? ""}`).toString("base64")}`;
      case "oauth":
        return `Bearer ${await this.getAccessToken()}`;
      case "mtls":
        throw new Error("ServiceNow mutual TLS is not supported by this runtime.");
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unhandled ServiceNow auth mode: ${String(exhaustive)}`);
      }
    }
  }

  private canRefreshToken(): boolean {
    return this.config.authMode === "oauth" && Boolean(this.config.clientId && this.config.clientSecret);
  }

  private tokenRequestBody(): URLSearchParams {
    const body = new URLSearchParams();
    if (!this.config.clientId || !this.config.clientSecret) {
      throw new Error("ServiceNow OAuth client credentials are missing.");
    }
    body.set("client_id", this.config.clientId);
    body.set("client_secret", this.config.clientSecret);
    if (this.refreshToken) {
      body.set("grant_type", "refresh_token");
      body.set("refresh_token", this.refreshToken);
    } else if (this.config.username && this.config.password) {
      body.set("grant_type", "password");
      body.set("username", this.config.username);
      body.set("password", this.config.password);
    } else {
      body.set("grant_type", "client_credentials");
    }
    return body;
  }

  private async fetchAccessToken(): Promise<string> {
    const body = this.tokenRequestBody();
    const response = await this.fetchWithTimeout(`${this.config.instanceUrl}/oauth_token.do`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
    });
    const rawText = await response.text();
    const parsed = parseJsonBody(rawText);
    const payload: JsonRecord = parsed ?? {};
    if (!response.ok) {
      const detail = servicenowErrorDetail(payload) ?? asString(payload.error) ?? (rawText.length > 0 ? describeOpaqueBody(response, rawText, parsed !== undefined) : undefined);
      throw new ServicenowApiError(
        this.redact(`ServiceNow OAuth token request failed (${describeStatus(response)}) for /oauth_token.do${detail ? `: ${detail}` : ""}`),
        response.status,
        detail,
      );
    }
    const accessToken = asString(payload.access_token);
    if (!accessToken) {
      throw new Error(`ServiceNow OAuth token response did not include access_token (${rawText.length > 0 ? describeOpaqueBody(response, rawText, parsed !== undefined) : "empty response body"}).`);
    }
    const expiresIn = asNumber(payload.expires_in) ?? 1800;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = Date.now() + Math.max((expiresIn - 60) * 1000, 60_000);
    this.refreshToken = asString(payload.refresh_token) ?? this.refreshToken;
    rememberSecrets(accessToken, this.refreshToken);
    return accessToken;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.accessTokenExpiresAt) {
      return this.accessToken;
    }
    if (!this.canRefreshToken()) {
      throw new Error("ServiceNow access token is missing or expired and no OAuth client credentials are configured to refresh it.");
    }
    if (!this.tokenPromise) {
      this.tokenPromise = this.fetchAccessToken();
    }
    try {
      return await this.tokenPromise;
    } finally {
      this.tokenPromise = undefined;
    }
  }

  async requestJson(url: string, init: RequestInit = {}): Promise<{ payload: JsonRecord; headers: Headers; status: number }> {
    let attempt = 0;
    let reauthenticated = false;
    for (;;) {
      const headers = new Headers(init.headers ?? {});
      if (!headers.has("accept")) headers.set("accept", "application/json");
      headers.set("authorization", await this.authorizationHeader());

      const response = await this.fetchWithTimeout(url, { ...init, headers });
      const rawText = await response.text();
      const parsed = parseJsonBody(rawText);
      const payload: JsonRecord = parsed ?? {};

      if (response.ok) return { payload, headers: response.headers, status: response.status };

      if (response.status === 401 && !reauthenticated && this.canRefreshToken() && !this.config.accessToken) {
        reauthenticated = true;
        this.accessToken = undefined;
        this.accessTokenExpiresAt = 0;
        continue;
      }

      if (isRetryableStatus(response.status) && attempt < this.config.maxRetries) {
        await this.sleepImpl(this.retryDelayMs(response, attempt));
        attempt += 1;
        continue;
      }

      const detail = servicenowErrorDetail(payload) ?? (rawText.length > 0 ? describeOpaqueBody(response, rawText, parsed !== undefined) : undefined);
      throw new ServicenowApiError(
        this.redact(`ServiceNow request failed (${describeStatus(response)}) for ${new URL(url).pathname}${detail ? `: ${detail}` : ""}`),
        response.status,
        detail,
      );
    }
  }

  async queryTable(table: string, options: ServicenowTableQuery = {}): Promise<TableSnapshot> {
    const limit = clampNumber(options.limit, DEFAULT_RECORD_LIMIT, 1, 500_000);
    const pageSize = Math.min(clampNumber(options.pageSize, this.config.pageSize, 1, 10_000), limit);
    const rows: JsonRecord[] = [];
    let total: number | undefined;
    let pages = 0;
    let truncationReason: string | undefined;
    let currentOffset = 0;
    const visitedUrls = new Set<string>();
    const endpoint = `/api/now/table/${encodeURIComponent(table)}`;
    let url: string | undefined = this.buildUrl(endpoint, {
      sysparm_query: options.query,
      sysparm_fields: options.fields?.join(","),
      sysparm_limit: pageSize,
      sysparm_offset: 0,
      sysparm_display_value: options.displayValue === undefined ? undefined : String(options.displayValue),
      sysparm_exclude_reference_link: "true",
    });

    try {
      while (url) {
        visitedUrls.add(url);
        const { payload, headers } = await this.requestJson(url);
        pages += 1;
        const pageRows = projectRows(asRecordArray(payload.result), options.fields);
        rows.push(...pageRows);
        const count = asNumber(headers.get("x-total-count"));
        if (count !== undefined) total = count;
        const next = parseLinkNext(headers.get("link"));
        if (!next) break;
        // More rows are promised by Link rel=next but this page carried none: a
        // stuck cursor, so the read is reported truncated instead of complete.
        if (pageRows.length === 0) {
          truncationReason = "empty page returned with a Link rel=next";
          break;
        }
        if (rows.length >= limit) {
          truncationReason = "record limit reached";
          break;
        }
        const nextUrl = new URL(next, this.config.instanceUrl);
        const nextOffset = asNumber(nextUrl.searchParams.get("sysparm_offset"));
        if (total !== undefined && nextOffset !== undefined && nextOffset >= total) break;
        const nextUrlText = nextUrl.toString();
        if (visitedUrls.has(nextUrlText) || nextOffset === undefined || nextOffset <= currentOffset) {
          truncationReason = "Link rel=next offset did not advance";
          break;
        }
        currentOffset = nextOffset;
        url = nextUrlText;
      }
    } catch (error) {
      // The in-memory flags on a failed read are placeholders; every rendered surface (core_data,
      // evidence, summaries) reads them through tableCoreData or snapshotEvidence, which render null.
      return {
        table,
        query: options.query,
        rows: [],
        total,
        pages,
        truncated: false,
        partial: false,
        error: this.redact(errorMessage(error)),
        statusCode: error instanceof ServicenowApiError ? error.status : undefined,
        endpoint,
      };
    }

    const truncated = truncationReason !== undefined;
    const totalUnknown = total === undefined && rows.length > 0;
    return {
      table,
      query: options.query,
      rows,
      total,
      pages,
      truncated,
      ...(truncationReason ? { truncationReason } : {}),
      ...(totalUnknown ? { totalUnknown } : {}),
      partial: truncated || totalUnknown || (total !== undefined && total > rows.length),
      endpoint,
    };
  }

  async countRecords(table: string, query?: string): Promise<CountResult> {
    const endpoint = `/api/now/stats/${encodeURIComponent(table)}`;
    try {
      const { payload } = await this.requestJson(this.buildUrl(endpoint, {
        sysparm_count: "true",
        sysparm_query: query,
      }));
      const result = asObject(payload.result);
      const stats = asObject(result?.stats);
      return { table, query, count: asNumber(stats?.count), endpoint };
    } catch (error) {
      return {
        table,
        query,
        error: this.redact(errorMessage(error)),
        statusCode: error instanceof ServicenowApiError ? error.status : undefined,
        endpoint,
      };
    }
  }
}

function snapshotIssue(snapshot: TableSnapshot): string | undefined {
  if (snapshot.error) {
    if (snapshot.skipped) {
      return `${snapshot.table} was not requested (${snapshot.skipped})`;
    }
    if (snapshot.statusCode === 401 || snapshot.statusCode === 403) {
      return `${snapshot.table} read was forbidden (${snapshot.statusCode})`;
    }
    return `${snapshot.table} read failed (${snapshot.error})`;
  }
  return undefined;
}

/**
 * Tables that belong to an inactive plugin do not exist on the instance and the
 * Table API answers 400 Invalid table. That is a documented state, not a read
 * failure, so the snapshot is marked unavailable and left readable for gating.
 */
function normalizeMissingTable(snapshot: TableSnapshot, reason: string): TableSnapshot {
  if (snapshot.statusCode === 400 && /invalid table/i.test(snapshot.error ?? "")) {
    // The observed status code and message are kept so the core_data marker names what the API answered.
    return { ...snapshot, rows: [], error: undefined, truncated: false, partial: false, unavailable: `${reason} (${snapshot.error})` };
  }
  return snapshot;
}

function snapshotPartialNote(snapshot: TableSnapshot): string | undefined {
  if (snapshot.error) return undefined;
  if (snapshot.truncated) {
    return `${snapshot.table} was truncated at ${snapshot.rows.length} of ${snapshot.total ?? "unknown"} rows (${snapshot.truncationReason ?? "record limit reached"})`;
  }
  if (snapshot.total !== undefined && snapshot.total > snapshot.rows.length) {
    return `${snapshot.table} returned ${snapshot.rows.length} of ${snapshot.total} rows (ACL-filtered or hidden rows)`;
  }
  if (visibilityUnproven(snapshot)) {
    return `${snapshot.table} returned 0 rows without an X-Total-Count header (visibility unproven)`;
  }
  if (snapshot.totalUnknown) {
    return `${snapshot.table} returned ${snapshot.rows.length} rows without an X-Total-Count header (total unknown)`;
  }
  return undefined;
}

/**
 * A response with no rows and no X-Total-Count header cannot be told apart
 * from an ACL-filtered read, so it never supports a pass on its own.
 */
function visibilityUnproven(snapshot: TableSnapshot): boolean {
  return !snapshot.error && !snapshot.unavailable && snapshot.pages > 0 && snapshot.rows.length === 0 && snapshot.total === undefined;
}

function snapshotErrors(label: string, snapshot: TableSnapshot): string[] {
  const issue = snapshotIssue(snapshot);
  const partial = snapshotPartialNote(snapshot);
  return [
    ...(issue ? [`${label}: ${issue}`] : []),
    ...(partial ? [`${label}: ${partial}`] : []),
  ];
}

function countErrors(label: string, count: CountResult): string[] {
  return count.error ? [`${label}: aggregate count failed (${count.error})`] : [];
}

type TableState = "complete" | "partial" | "unread" | "unavailable" | "not_requested";

function tableState(snapshot: TableSnapshot): TableState {
  if (snapshot.skipped) return "not_requested";
  if (snapshot.error) return "unread";
  if (snapshot.unavailable) return "unavailable";
  if (snapshot.partial || visibilityUnproven(snapshot)) return "partial";
  return "complete";
}

/**
 * Renders one inventory state as `<table> read: <state> (<detail>)`. The word `read` keeps a
 * credential-named table (password_policy) from forming a `name: value` pair that the redaction
 * pass would take as a credential, so the fixed text survives the pass unchanged.
 */
function describeTable(snapshot: TableSnapshot): string {
  const state = tableState(snapshot);
  switch (state) {
    case "unread":
      return `${snapshot.table} read: unread (${snapshot.error})`;
    case "not_requested":
      return `${snapshot.table} read: not requested (${snapshot.skipped})`;
    case "unavailable":
      return `${snapshot.table} read: unavailable (${snapshot.unavailable})`;
    case "partial":
      return `${snapshot.table} read: partial (${snapshotPartialNote(snapshot) ?? "visible rows are not the full population"})`;
    case "complete":
      return `${snapshot.table} read: complete (${snapshot.rows.length} row${snapshot.rows.length === 1 ? "" : "s"}${snapshot.total !== undefined ? ` of ${snapshot.total}` : ""})`;
    default: {
      const exhaustive: never = state;
      throw new Error(`Unhandled table state ${String(exhaustive)}`);
    }
  }
}

function describeCount(count: CountResult): string {
  if (count.error) return `${count.table} aggregate: unread (${count.error})`;
  if (count.count === undefined) return `${count.table} aggregate: unread (no count returned)`;
  return `${count.table} aggregate: complete (${count.count})`;
}

/** True when every listed snapshot was read without error and its visible rows are the whole population. */
function tablesComplete(snapshots: TableSnapshot[]): boolean {
  return snapshots.every((snapshot) => tableState(snapshot) === "complete");
}

function tablesReadable(snapshots: TableSnapshot[]): boolean {
  return snapshots.every((snapshot) => !snapshot.error);
}

function isAbsenceValue(value: unknown): boolean {
  if (value === 0) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value as object).length === 0;
  return false;
}

/**
 * A count, list, or map derived from one or more table reads. It renders null when any source was not
 * read, and null when a source is partial or unavailable and the value would assert absence (0, [], {}),
 * because a partly read inventory cannot prove that nothing exists.
 */
function derived<T>(value: T, ...snapshots: TableSnapshot[]): T | null {
  if (!tablesReadable(snapshots)) return null;
  if (!tablesComplete(snapshots) && isAbsenceValue(value)) return null;
  return value;
}

/** A boolean observation: true is a positive sighting from any read; false is an absence claim that needs a complete read. */
function derivedFlag(value: boolean, ...snapshots: TableSnapshot[]): boolean | null {
  if (!tablesReadable(snapshots)) return null;
  if (!value && !tablesComplete(snapshots)) return null;
  return value;
}

/** The number of rows read is meaningful whenever the table was read at all; it is null when it was not. */
function visibleRows(snapshot: TableSnapshot): number | null {
  return tableCollected(snapshot) ? snapshot.rows.length : null;
}

/** An X-Total-Count or aggregate total is reported only when the request that carries it was answered. */
function totalRows(snapshot: TableSnapshot): number | null {
  return tableCollected(snapshot) ? snapshot.total ?? null : null;
}

function countValue(count: CountResult): number | null {
  return count.error ? null : count.count ?? null;
}

/** A count of principals holding or lacking a property, unknown unless every proving table was fully read. */
function principalCount(value: number, ...snapshots: TableSnapshot[]): number | null {
  return tablesComplete(snapshots) ? value : null;
}

/**
 * Collection metadata for one input table. Counts and flags are real only when the read was answered
 * with rows; a denied, errored, unavailable, or skipped read renders every one of them null so a
 * consumer cannot mistake a placeholder `truncated: false` or `visible_rows: 0` for an observation.
 */
function snapshotEvidence(snapshot: TableSnapshot): JsonRecord {
  const listed = tableCollected(snapshot);
  return {
    table: snapshot.table,
    query: snapshot.query ?? null,
    state: tableState(snapshot),
    visible_rows: listed ? snapshot.rows.length : null,
    total_rows: listed ? snapshot.total ?? null : null,
    // Pages read before a failure are an observation; zero pages on a read that was not answered is not.
    pages: listed || snapshot.pages > 0 ? snapshot.pages : null,
    truncated: listed ? snapshot.truncated : null,
    truncation_reason: snapshot.truncationReason ?? null,
    total_unknown: listed ? snapshot.totalUnknown ?? false : null,
    partial: listed ? snapshot.partial : null,
    error: snapshot.error ?? null,
    status_code: snapshot.statusCode ?? null,
    endpoint: snapshot.endpoint ?? null,
    unavailable: snapshot.unavailable ?? null,
    skipped: snapshot.skipped ?? null,
  };
}

interface Evaluation {
  status: ServicenowFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  manualEvidence?: string;
  /**
   * Lists that name principals (users, accounts, integrations) as holding or lacking a property, and
   * counts of such principals. They are emitted only when every input was read to completion; a partial
   * input renders each of them null and `principals_withheld` names the inventory that was not fully read.
   */
  principals?: Record<string, unknown[] | number>;
  /** Thresholds and options echoed into evidence verbatim; they describe the run, not the tenant, so they are never gated. */
  parameters?: JsonRecord;
}

/** Under a partial read, evidence values that assert absence (0, [], {}) render null because the missing rows could hold the item. */
function withoutAbsenceClaims(evidence: JsonRecord | undefined, complete: boolean): JsonRecord {
  if (!evidence) return {};
  if (complete) return evidence;
  return Object.fromEntries(Object.entries(evidence).map(([key, value]) => [key, isAbsenceValue(value) ? null : value]));
}

function gatedPrincipals(principals: Record<string, unknown[] | number> | undefined, complete: boolean, partialNotes: string[]): JsonRecord {
  if (!principals) return {};
  const gated: JsonRecord = {};
  for (const [key, value] of Object.entries(principals)) gated[key] = complete ? value : null;
  gated.principals_withheld = complete ? null : partialNotes.join("; ");
  return gated;
}

function finding(controlNumber: number, evaluation: Evaluation): ServicenowFinding {
  const definition = SERVICENOW_CONTROLS[controlNumber];
  return {
    id: findingId(controlNumber),
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status: evaluation.status,
    summary: evaluation.summary,
    evidence: evaluation.evidence,
    mappings: mappingsForControl(controlNumber),
    manualEvidence: evaluation.manualEvidence,
  };
}

/**
 * Gate an evaluation on the readability and completeness of its inputs.
 * Any unreadable input turns the verdict into manual; any partial or truncated
 * input prevents pass and is reported with seen and total counts.
 */
function gatedFinding(
  controlNumber: number,
  inputs: TableSnapshot[],
  manualEvidence: string,
  evaluate: () => Evaluation,
): ServicenowFinding {
  const issues = inputs.map(snapshotIssue).filter((item): item is string => Boolean(item));
  const inputEvidence: JsonRecord = { inputs: inputs.map(snapshotEvidence) };
  if (issues.length > 0) {
    return finding(controlNumber, {
      status: "manual",
      summary: `Verdict unknown: ${issues.join("; ")}. Collect the evidence manually.`,
      evidence: inputEvidence,
      manualEvidence,
    });
  }

  const evaluation = evaluate();
  const partialNotes = inputs.map(snapshotPartialNote).filter((item): item is string => Boolean(item));
  const complete = partialNotes.length === 0;
  const evidence = {
    ...inputEvidence,
    ...(evaluation.parameters ?? {}),
    ...withoutAbsenceClaims(evaluation.evidence, complete),
    ...gatedPrincipals(evaluation.principals, complete, partialNotes),
  };
  if (complete) {
    return finding(controlNumber, { ...evaluation, evidence, manualEvidence: evaluation.manualEvidence ?? (evaluation.status === "manual" ? manualEvidence : undefined) });
  }

  const partialSummary = `Partial view: ${partialNotes.join("; ")}.`;
  switch (evaluation.status) {
    case "pass":
      return finding(controlNumber, {
        status: "warn",
        summary: `${evaluation.summary} ${partialSummary} The verdict is downgraded because the visible rows are not the full population.`,
        evidence,
        manualEvidence,
      });
    case "warn":
    case "fail":
      return finding(controlNumber, { ...evaluation, summary: `${evaluation.summary} ${partialSummary}`, evidence });
    case "manual":
      return finding(controlNumber, { ...evaluation, summary: `${evaluation.summary} ${partialSummary}`, evidence, manualEvidence: evaluation.manualEvidence ?? manualEvidence });
    default: {
      const exhaustive: never = evaluation.status;
      throw new Error(`Unhandled finding status: ${String(exhaustive)}`);
    }
  }
}

interface PropertyReading {
  name: string;
  exists: boolean;
  value?: string;
}

function readProperty(snapshot: TableSnapshot, name: string): PropertyReading {
  const row = snapshot.rows.find((item) => asString(item.name) === name);
  if (!row) return { name, exists: false };
  return { name, exists: true, value: asString(row.value) ?? "" };
}

interface PropertyExpectation {
  name: string;
  expected: "true" | "false" | ((value: string) => boolean);
  describe: string;
}

interface PropertyCheck extends PropertyReading {
  expected: string;
  compliant?: boolean;
}

function checkProperties(snapshot: TableSnapshot, expectations: PropertyExpectation[]): PropertyCheck[] {
  return expectations.map((expectation) => {
    const reading = readProperty(snapshot, expectation.name);
    const expected = typeof expectation.expected === "string" ? expectation.expected : expectation.describe;
    if (!reading.exists) return { ...reading, expected, compliant: undefined };
    const value = reading.value ?? "";
    const compliant = typeof expectation.expected === "string"
      ? value.trim().toLowerCase() === expectation.expected
      : expectation.expected(value);
    return { ...reading, expected, compliant };
  });
}

function propertyVerdict(checks: PropertyCheck[], subject: string): Evaluation {
  const nonCompliant = checks.filter((item) => item.compliant === false);
  const absent = checks.filter((item) => !item.exists);
  const compliant = checks.filter((item) => item.compliant === true);
  const evidence: JsonRecord = {
    properties: checks.map((item) => ({ name: item.name, exists: item.exists, value: item.value ?? null, expected: item.expected, compliant: item.compliant ?? null })),
  };
  if (nonCompliant.length > 0) {
    return {
      status: "fail",
      summary: `${nonCompliant.length}/${checks.length} ${subject} properties are set to non-compliant values: ${nonCompliant.map((item) => `${item.name} is ${item.value === undefined || item.value === "" ? "empty" : item.value}`).join(", ")}.`,
      evidence,
    };
  }
  if (absent.length > 0) {
    return {
      status: "warn",
      summary: `${compliant.length}/${checks.length} ${subject} properties are present and compliant; ${absent.length} have no sys_properties row (${absent.map((item) => item.name).join(", ")}). Absent rows are not assumed to hold their defaults.`,
      evidence,
    };
  }
  return {
    status: "pass",
    summary: `All ${checks.length} ${subject} properties are present with compliant values.`,
    evidence,
  };
}

function propertyNames(expectations: PropertyExpectation[]): string[] {
  return expectations.map((item) => item.name);
}

function rowString(row: JsonRecord, key: string): string | undefined {
  return asString(row[key]);
}

function rowBoolean(row: JsonRecord, key: string): boolean | undefined {
  return asBoolean(row[key]);
}

function userLabel(row: JsonRecord): string {
  return rowString(row, "user_name") ?? rowString(row, "user.user_name") ?? rowString(row, "name") ?? rowString(row, "sys_id") ?? "unknown";
}

/**
 * The Multi-factor Roles list on a criteria record is returned as a
 * comma-separated display value; the column name is not documented, so any
 * role-named column other than the record name is read.
 */
function criteriaRoleNames(row: JsonRecord): string[] {
  const names = new Set<string>();
  for (const [key, value] of Object.entries(row)) {
    if (key === "name" || !/role/i.test(key)) continue;
    const text = asString(value);
    if (!text) continue;
    for (const part of text.split(",")) {
      const trimmed = part.trim();
      if (trimmed) names.add(trimmed);
    }
  }
  return [...names].sort();
}

const INSTANCE_SECURITY_PROPERTIES: PropertyExpectation[] = [
  { name: "glide.security.use_csrf_token", expected: "true", describe: "true" },
  { name: "glide.security.csrf.strict.validation.mode", expected: "true", describe: "true" },
  { name: "glide.security.file.mime_type.validation", expected: "true", describe: "true" },
  { name: "glide.security.diag_txns_acl", expected: "true", describe: "true" },
  { name: "glide.security.strict.user_image_upload", expected: "true", describe: "true" },
];

const SCRIPT_RESTRICTION_PROPERTIES: PropertyExpectation[] = [
  { name: "glide.script.use.sandbox", expected: "true", describe: "true" },
  { name: "glide.script.allow.ajaxevaluate", expected: "false", describe: "false" },
  { name: "glide.script.secure.ajaxgliderecord", expected: "true", describe: "true" },
  { name: "glide.script.ccsi.ispublic", expected: "false", describe: "false" },
];

const HARDENING_PROPERTIES: PropertyExpectation[] = [
  { name: "glide.security.strict.updates", expected: "true", describe: "true" },
  { name: "glide.security.strict.actions", expected: "true", describe: "true" },
  { name: "glide.ui.escape_html_list_field", expected: "true", describe: "true" },
  { name: "glide.ui.escape_all_script", expected: "true", describe: "true" },
  { name: "glide.html.escape_script", expected: "true", describe: "true" },
  { name: "glide.html.sanitize_all_fields", expected: "true", describe: "true" },
  { name: "glide.ui.security.allow_codetag", expected: "false", describe: "false" },
  { name: "glide.ui.security.codetag.allow_script", expected: "false", describe: "false" },
  { name: "glide.set_x_frame_options", expected: "true", describe: "true" },
  { name: "glide.ui.secure_cookies", expected: "true", describe: "true" },
  { name: "glide.cookies.http_only", expected: "true", describe: "true" },
];

const SESSION_PROPERTY_NAMES = ["glide.ui.session_timeout", "glide.ui.rotate_sessions", "glide.ui.user_cookie.max_life_span_in_days"];
const IP_PROPERTY_NAMES = ["glide.ip.authenticate.strict"];
const EMAIL_PROPERTY_NAMES = ["glide.smtp.auth", "glide.email.email_with_no_target_visible_to_all"];
const PASSWORD_PROPERTY_NAMES = ["glide.enable.password_policy", "glide.apply.password_policy.on_login", "glide.login.no_blank_password"];
const MFA_PROPERTY_NAMES = ["glide.authenticate.multifactor", "glide.authenticate.multifactor.email.otp.enabled"];
const SSO_PROPERTY_NAMES = ["glide.authenticate.multisso.enabled", "glide.authenticate.sso.redirect.idp", "glide.sso.acr.enabled"];
const MID_PROPERTY_NAMES = ["mid.version.override"];

const HARDENING_PROPERTY_QUERY_NAMES = [
  ...propertyNames(INSTANCE_SECURITY_PROPERTIES),
  ...propertyNames(SCRIPT_RESTRICTION_PROPERTIES),
  ...propertyNames(HARDENING_PROPERTIES),
  ...SESSION_PROPERTY_NAMES,
  ...IP_PROPERTY_NAMES,
  ...EMAIL_PROPERTY_NAMES,
];

const IDENTITY_PROPERTY_QUERY_NAMES = [...PASSWORD_PROPERTY_NAMES, ...MFA_PROPERTY_NAMES, ...SSO_PROPERTY_NAMES];

const PROPERTY_FIELDS = ["name", "value", "type", "sys_updated_on"];
const USER_FIELDS = ["sys_id", "user_name", "name", "email", "active", "locked_out", "last_login_time", "web_service_access_only", "internal_integration_user", "enable_multifactor_authn", "sys_created_on", "source", "sso_source"];
const USER_ROLE_FIELDS = ["sys_id", "user", "user.user_name", "user.active", "user.web_service_access_only", "user.internal_integration_user", "user.last_login_time", "role", "role.name", "inherited", "state"];
const ROLE_CONTAINS_FIELDS = ["sys_id", "role", "role.name", "contains", "contains.name"];
const CERTIFICATE_FIELDS = ["sys_id", "name", "type", "expires", "active", "sys_updated_on"];
const ACL_FIELDS = ["sys_id", "name", "operation", "type", "active", "admin_overrides", "condition", "script", "advanced", "description"];
const ACL_ROLE_FIELDS = ["sys_id", "sys_security_acl", "sys_security_acl.name", "sys_user_role", "sys_user_role.name"];
const PLUGIN_FIELDS = ["sys_id", "name", "source", "active", "version"];
/**
 * SNOW-06 reads the policy name, the minimum and maximum length, the
 * character-class requirements, and the strength preset. Both the
 * "require_*" flag and the "minimum_*_characters" count spellings are
 * requested because the Table API ignores unknown names in sysparm_fields;
 * anything else on the record (description, lockout, history, expiration) is
 * dropped before the snapshot is stored.
 */
const PASSWORD_POLICY_FIELDS = [
  "sys_id",
  "name",
  "active",
  "sys_updated_on",
  "minimum_password_length",
  "maximum_password_length",
  "password_strength_preset",
  "require_uppercase",
  "require_lowercase",
  "require_digit",
  "require_special",
  "minimum_uppercase_characters",
  "minimum_lowercase_characters",
  "minimum_numeric_characters",
  "minimum_special_characters",
];
/** SNOW-07 reads the criteria name, active flag, and the Multi-factor Roles list (display value). */
const MFA_CRITERIA_FIELDS = ["sys_id", "name", "active", "order", "roles", "multi_factor_roles", "sys_updated_on"];
const MFA_CRITERIA_TABLE = "multi_factor_criteria";
const CRYPTO_MODULE_TABLE = "sys_kmf_crypto_module";
const LEGACY_ENCRYPTION_CONTEXT_TABLE = "sys_encryption_context";
const IP_ACCESS_TABLE = "ip_access";
const IP_AUTHENTICATOR_PLUGIN = "com.snc.ipauthenticator";
const IP_ACCESS_FIELDS = ["sys_id", "type", "direction", "active", "range_start", "range_end", "description", "sys_updated_on"];
const EMAIL_ACCOUNT_FIELDS = ["sys_id", "name", "type", "active", "connection_security", "enable_ssl", "enable_tls", "authentication", "server", "port", "sys_updated_on"];

export interface ServicenowIdentityData {
  users: TableSnapshot;
  privilegedAssignments: TableSnapshot;
  roleInheritance: TableSnapshot;
  roleInheritanceTotal: CountResult;
  properties: TableSnapshot;
  passwordPolicies: TableSnapshot;
  ssoProviders: TableSnapshot;
  ldapServers: TableSnapshot;
  certificates: TableSnapshot;
  oauthEntities: TableSnapshot;
  mfaCriteria: TableSnapshot;
  now: Date;
  inactiveDays: number;
  minPasswordLength: number;
  certExpiryWarnDays: number;
  maxAdmins: number;
}

export async function collectServicenowIdentityData(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords" | "getNow">,
  options: ServicenowIdentityOptions = {},
): Promise<ServicenowIdentityData> {
  const recordLimit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 500_000);
  const roleList = PRIVILEGED_ROLE_NAMES.join(",");
  const [users, privilegedAssignments, roleInheritance, roleInheritanceTotal, properties, passwordPolicies, ssoProviders, ldapServers, certificates, oauthEntities, mfaCriteria] = await Promise.all([
    readTable(client, "sys_user", { query: "active=true", fields: USER_FIELDS, limit: recordLimit }),
    readTable(client, "sys_user_has_role", { query: `role.nameIN${roleList}`, fields: USER_ROLE_FIELDS, limit: recordLimit }),
    readTable(client, "sys_user_role_contains", { query: `contains.nameIN${ELEVATED_ROLE_NAMES.join(",")}`, fields: ROLE_CONTAINS_FIELDS, limit: recordLimit }),
    client.countRecords("sys_user_role_contains"),
    readTable(client, "sys_properties", { query: `nameIN${IDENTITY_PROPERTY_QUERY_NAMES.join(",")}`, fields: PROPERTY_FIELDS, limit: recordLimit }),
    readTable(client, "password_policy", { fields: PASSWORD_POLICY_FIELDS, limit: recordLimit }),
    readTable(client, "sso_properties", { fields: ["sys_id", "name", "active", "default", "auto_redirect_idp", "sys_updated_on"], limit: recordLimit }),
    readTable(client, "ldap_server_config", { fields: ["sys_id", "name", "active", "sys_updated_on"], limit: recordLimit }),
    readTable(client, "sys_certificate", { fields: CERTIFICATE_FIELDS, limit: recordLimit }),
    readTable(client, "oauth_entity", { fields: ["sys_id", "name", "type", "active", "client_id", "sys_updated_on"], limit: recordLimit }),
    readTable(client, MFA_CRITERIA_TABLE, { fields: MFA_CRITERIA_FIELDS, displayValue: true, limit: recordLimit }),
  ]);
  return {
    users,
    privilegedAssignments,
    roleInheritance,
    roleInheritanceTotal,
    properties,
    passwordPolicies,
    ssoProviders,
    ldapServers,
    certificates,
    oauthEntities,
    mfaCriteria,
    now: client.getNow(),
    inactiveDays: clampNumber(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650),
    minPasswordLength: clampNumber(options.minPasswordLength, DEFAULT_MIN_PASSWORD_LENGTH, 1, 128),
    certExpiryWarnDays: clampNumber(options.certExpiryWarnDays, DEFAULT_CERT_EXPIRY_WARN_DAYS, 1, 3650),
    maxAdmins: clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 100_000),
  };
}

function isIntegrationUser(row: JsonRecord): boolean {
  return rowBoolean(row, "web_service_access_only") === true || rowBoolean(row, "internal_integration_user") === true;
}

function assignmentIsIntegration(row: JsonRecord): boolean {
  return rowBoolean(row, "user.web_service_access_only") === true || rowBoolean(row, "user.internal_integration_user") === true;
}

function findPolicyNumber(policy: JsonRecord, pattern: RegExp): number | undefined {
  for (const [key, value] of Object.entries(policy)) {
    if (pattern.test(key)) {
      const parsed = asNumber(value);
      if (parsed !== undefined) return parsed;
    }
  }
  return undefined;
}

function findPolicyFlag(policy: JsonRecord, pattern: RegExp): boolean | undefined {
  for (const [key, value] of Object.entries(policy)) {
    if (pattern.test(key)) {
      const parsed = asBoolean(value);
      if (parsed !== undefined) return parsed;
      const numeric = asNumber(value);
      if (numeric !== undefined) return numeric > 0;
    }
  }
  return undefined;
}

export function assessServicenowIdentityAccessData(data: ServicenowIdentityData): ServicenowAssessmentResult {
  const errors = [
    ...snapshotErrors("users", data.users),
    ...snapshotErrors("privileged role assignments", data.privilegedAssignments),
    ...snapshotErrors("role inheritance", data.roleInheritance),
    ...countErrors("role inheritance", data.roleInheritanceTotal),
    ...snapshotErrors("identity properties", data.properties),
    ...snapshotErrors("password policies", data.passwordPolicies),
    ...snapshotErrors("sso providers", data.ssoProviders),
    ...snapshotErrors("ldap servers", data.ldapServers),
    ...snapshotErrors("certificates", data.certificates),
    ...snapshotErrors("oauth entities", data.oauthEntities),
    ...snapshotErrors("multi-factor criteria", data.mfaCriteria),
  ];

  const users = data.users.rows;
  const assignments = data.privilegedAssignments.rows;
  const elevatedAssignments = assignments.filter((row) => ELEVATED_ROLE_NAMES.includes(rowString(row, "role.name") ?? ""));
  const elevatedUserIds = new Set(elevatedAssignments.map((row) => rowString(row, "user")).filter((item): item is string => Boolean(item)));
  const elevatedUserNames = [...new Set(elevatedAssignments.map(userLabel))];
  const privilegedByUser = new Map<string, Set<string>>();
  for (const row of assignments) {
    const user = rowString(row, "user");
    const role = rowString(row, "role.name");
    if (!user || !role) continue;
    const roles = privilegedByUser.get(user) ?? new Set<string>();
    roles.add(role);
    privilegedByUser.set(user, roles);
  }
  const multiPrivilegedUsers = [...privilegedByUser.entries()].filter(([, roles]) => roles.size > 1);

  const roleHierarchy = gatedFinding(3, [data.roleInheritance], "Navigate to User Administration > Roles, open admin and security_admin, and review the Contained By related list; justify every role that inherits admin or security_admin.", () => {
    const inheriting = data.roleInheritance.rows.map((row) => ({
      role: rowString(row, "role.name") ?? rowString(row, "role") ?? "unknown",
      contains: rowString(row, "contains.name") ?? rowString(row, "contains") ?? "unknown",
    }));
    const visibilityProof = data.roleInheritanceTotal.count;
    if (data.roleInheritanceTotal.error || visibilityProof === undefined || visibilityProof === 0) {
      return {
        status: "manual",
        summary: `The sys_user_role_contains inventory could not be proven visible (aggregate count ${visibilityProof ?? "unavailable"}${data.roleInheritanceTotal.error ? `, ${data.roleInheritanceTotal.error}` : ""}), so an empty admin-inheritance result cannot be trusted.`,
        evidence: { inheriting_roles: truncateList(inheriting), role_contains_total: visibilityProof ?? null },
      };
    }
    if (visibilityUnproven(data.roleInheritance)) {
      return {
        status: "manual",
        summary: `The admin-inheritance query returned no rows and no X-Total-Count header, so the empty result cannot be distinguished from ACL-filtered rows even though sys_user_role_contains holds ${visibilityProof} rows in aggregate.`,
        evidence: { inheriting_roles: [], role_contains_total: visibilityProof, x_total_count_present: false },
      };
    }
    if (inheriting.length === 0) {
      return {
        status: "pass",
        summary: `No role inherits admin or security_admin across ${visibilityProof} role containment rows.`,
        evidence: { inheriting_roles: [], role_contains_total: visibilityProof },
      };
    }
    return {
      status: "warn",
      summary: `${inheriting.length} role containment rows grant admin or security_admin through inheritance (${truncateList(inheriting.map((item) => item.role), 10).join(", ")}); confirm each follows least privilege.`,
      evidence: { inheriting_roles: truncateList(inheriting), role_contains_total: visibilityProof },
    };
  });

  const userAccessReview = gatedFinding(4, [data.users, data.privilegedAssignments], `Export User Administration > Users filtered on Active = true with Last login time, and User Administration > Roles > admin > Users; review accounts with no login in ${data.inactiveDays} days and every admin assignment.`, () => {
    if (users.length === 0) {
      return {
        status: "manual",
        summary: "No active users were visible although the authenticated account itself is active, so sys_user is being filtered; the access review cannot be performed from this credential.",
        evidence: { active_users: 0 },
      };
    }
    if (elevatedAssignments.length === 0) {
      return {
        status: "manual",
        summary: `No admin or security_admin role assignments were visible for ${users.length} active users; every instance has at least one admin, so sys_user_has_role is being filtered.`,
        evidence: { active_users: users.length, admin_assignments: 0 },
      };
    }
    const stale: string[] = [];
    const neverLoggedIn: string[] = [];
    const staleAdmins: string[] = [];
    for (const user of users) {
      const lastLogin = parseServicenowDate(user.last_login_time);
      const id = rowString(user, "sys_id") ?? "";
      if (!lastLogin) {
        neverLoggedIn.push(userLabel(user));
        continue;
      }
      if (daysBetween(data.now, lastLogin) > data.inactiveDays) {
        stale.push(userLabel(user));
        if (elevatedUserIds.has(id)) staleAdmins.push(userLabel(user));
      }
    }
    const adminsWithoutLoginDate = users.filter((user) => elevatedUserIds.has(rowString(user, "sys_id") ?? "") && !parseServicenowDate(user.last_login_time)).map(userLabel);
    const lockedOut = users.filter((user) => rowBoolean(user, "locked_out") === true);
    const lockedOutAdmins = lockedOut.filter((user) => elevatedUserIds.has(rowString(user, "sys_id") ?? "")).map(userLabel);
    const evidence: JsonRecord = { active_users: users.length };
    const parameters: JsonRecord = { max_admins: data.maxAdmins, inactive_days: data.inactiveDays };
    const principals: Evaluation["principals"] = {
      admin_users: elevatedUserIds.size,
      admin_user_names: truncateList(elevatedUserNames),
      inactive_users: truncateList(stale),
      inactive_user_count: stale.length,
      users_without_last_login: truncateList(neverLoggedIn),
      users_without_last_login_count: neverLoggedIn.length,
      admins_without_last_login: adminsWithoutLoginDate,
      inactive_admins: staleAdmins,
      locked_out_users: truncateList(lockedOut.map(userLabel)),
      locked_out_user_count: lockedOut.length,
      locked_out_admins: lockedOutAdmins,
      multi_privileged_users: truncateList(multiPrivilegedUsers.map(([user, roles]) => ({ user, roles: [...roles] }))),
    };
    // Counts of principals are stated only when both inventories were read to completion; a partial
    // read reports what was observed without a number or a name, since the missing rows could change both.
    const complete = tablesComplete([data.users, data.privilegedAssignments]);
    const withheld = "exact counts and names are withheld because the user inventory was not fully read";
    if (staleAdmins.length > 0 || elevatedUserIds.size > data.maxAdmins) {
      return {
        status: "fail",
        summary: complete
          ? `${elevatedUserIds.size} active users hold admin or security_admin (threshold ${data.maxAdmins}); ${staleAdmins.length} admins have not logged in for ${data.inactiveDays}+ days; ${stale.length} active users are inactive; ${neverLoggedIn.length} have no last login date and are not counted as active; ${lockedOut.length} active accounts are locked out (${lockedOutAdmins.length} admins).`
          : `Among the visible rows, ${staleAdmins.length > 0 ? `an admin or security_admin holder has not logged in for ${data.inactiveDays}+ days` : `more than ${data.maxAdmins} active users hold admin or security_admin`}; ${withheld}.`,
        evidence,
        parameters,
        principals,
      };
    }
    if (stale.length > 0 || neverLoggedIn.length > 0 || adminsWithoutLoginDate.length > 0 || multiPrivilegedUsers.length > 0 || lockedOut.length > 0) {
      return {
        status: "warn",
        summary: complete
          ? `${elevatedUserIds.size} admin users are within the threshold of ${data.maxAdmins}, but ${stale.length} active users are inactive for ${data.inactiveDays}+ days, ${neverLoggedIn.length} have no last login date (reported separately, never counted as active), ${lockedOut.length} active accounts are locked out (${lockedOutAdmins.length} admins; review or deactivate them), and ${multiPrivilegedUsers.length} users hold multiple privileged roles.`
          : `Among the visible rows, accounts that are inactive for ${data.inactiveDays}+ days, have no last login date, are locked out, or hold multiple privileged roles were observed; ${withheld}.`,
        evidence,
        parameters,
        principals,
      };
    }
    return {
      status: "pass",
      summary: complete
        ? `${users.length} active users reviewed: ${elevatedUserIds.size} admins within the threshold of ${data.maxAdmins}, no user inactive for ${data.inactiveDays}+ days, every active user has a last login date, no active account is locked out, and no user stacks multiple privileged roles.`
        : `No inactive, never-logged-in, locked-out, or multi-privileged account was observed among the visible rows and the visible admin holders are within the threshold of ${data.maxAdmins}, but the user inventory was not fully read, so the population is unknown.`,
      evidence,
      parameters,
      principals,
    };
  });

  const passwordPolicy = gatedFinding(6, [data.properties, data.passwordPolicies], `Open Password Policy > Password Policies > Default and Password Policy > Properties; record minimum length (expected ${data.minPasswordLength}+), character class requirements, and glide.enable.password_policy.`, () => {
    const enablement = readProperty(data.properties, "glide.enable.password_policy");
    const applyOnLogin = readProperty(data.properties, "glide.apply.password_policy.on_login");
    const noBlank = readProperty(data.properties, "glide.login.no_blank_password");
    const policies = data.passwordPolicies.rows;
    const evidence: JsonRecord = {
      glide_enable_password_policy: enablement.exists ? enablement.value : null,
      glide_apply_password_policy_on_login: applyOnLogin.exists ? applyOnLogin.value : null,
      glide_login_no_blank_password: noBlank.exists ? noBlank.value : null,
      policy_count: policies.length,
      min_password_length_threshold: data.minPasswordLength,
    };
    if (enablement.exists && asBoolean(enablement.value) === false) {
      return { status: "fail", summary: "glide.enable.password_policy is set to false, so the password_policy table is not enforced.", evidence };
    }
    if (policies.length === 0) {
      return {
        status: "fail",
        summary: "No password_policy rows are visible; the baseline Default policy should exist, so either the policy was removed or the credential cannot read it.",
        evidence,
      };
    }
    const evaluated = policies.map((policy) => ({
      name: rowString(policy, "name") ?? rowString(policy, "sys_id") ?? "policy",
      min_length: findPolicyNumber(policy, /min.*(length|len)/i),
      max_length: findPolicyNumber(policy, /max.*(length|len)/i),
      upper: findPolicyFlag(policy, /upper/i),
      lower: findPolicyFlag(policy, /lower/i),
      digit: findPolicyFlag(policy, /digit|numer/i),
      special: findPolicyFlag(policy, /special/i),
      preset: rowString(policy, "password_strength_preset") ?? rowString(policy, "preset"),
    }));
    evidence.policies = truncateList(evaluated);
    const unreadable = evaluated.filter((item) => item.min_length === undefined);
    if (unreadable.length === evaluated.length) {
      return {
        status: "manual",
        summary: `${policies.length} password_policy rows are visible but none exposed a recognizable minimum length column; review the policy form manually.`,
        evidence,
      };
    }
    const weak = evaluated.filter((item) => item.min_length !== undefined && (item.min_length < data.minPasswordLength || item.upper === false || item.lower === false || item.digit === false));
    if (weak.length > 0) {
      return {
        status: "fail",
        summary: `${weak.length}/${evaluated.length} password policies fall below the threshold (minimum length ${data.minPasswordLength}, upper, lower, digit required): ${weak.map((item) => `${item.name} (min ${item.min_length ?? "?"})`).join(", ")}.`,
        evidence,
      };
    }
    if (!enablement.exists) {
      return {
        status: "warn",
        summary: `All ${evaluated.length} visible password policies meet the threshold, but glide.enable.password_policy has no sys_properties row; ServiceNow documents it as automatically true, yet the row was not observed so enforcement is not assumed.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `glide.enable.password_policy is true and all ${evaluated.length} password policies meet the threshold (minimum length ${data.minPasswordLength}, upper, lower, and digit required).`,
      evidence,
    };
  });

  const mfa = gatedFinding(7, [data.properties, data.users, data.privilegedAssignments, data.mfaCriteria], `Open Multi-factor Authentication > Multi-factor Criteria (${MFA_CRITERIA_TABLE}) and confirm the Role-based multi-factor authentication record is Active with admin and security_admin in its Multi-factor Roles list; open System Properties for glide.authenticate.multifactor and glide.authenticate.multifactor.email.otp.enabled; confirm every admin user carries enable_multifactor_authn or is covered by an MFA authentication policy.`, () => {
    const enabled = readProperty(data.properties, "glide.authenticate.multifactor");
    const emailOtp = readProperty(data.properties, "glide.authenticate.multifactor.email.otp.enabled");
    const admins = users.filter((user) => elevatedUserIds.has(rowString(user, "sys_id") ?? ""));
    const adminsWithoutFlag = admins.filter((user) => rowBoolean(user, "enable_multifactor_authn") !== true).map(userLabel);
    const criteria = data.mfaCriteria.rows.map((row) => ({
      name: rowString(row, "name") ?? rowString(row, "sys_id") ?? "criteria",
      active: rowBoolean(row, "active") ?? null,
      roles: criteriaRoleNames(row),
    }));
    const roleBased = criteria.filter((item) => /role/i.test(item.name));
    const activeRoleBased = roleBased.filter((item) => item.active === true);
    const enforcedRoles = [...new Set(activeRoleBased.flatMap((item) => item.roles))].sort();
    const elevatedCovered = ELEVATED_ROLE_NAMES.filter((role) => enforcedRoles.includes(role));
    const elevatedMissing = ELEVATED_ROLE_NAMES.filter((role) => !enforcedRoles.includes(role));
    const roleEnforced = activeRoleBased.length > 0 && elevatedMissing.length === 0;
    const userEnforced = admins.length > 0 && adminsWithoutFlag.length === 0;
    const evidence: JsonRecord = {
      glide_authenticate_multifactor: enabled.exists ? enabled.value : null,
      email_otp_enabled: emailOtp.exists ? emailOtp.value : null,
      multi_factor_criteria: truncateList(criteria),
      role_based_criteria_active: activeRoleBased.length > 0,
      role_based_criteria_roles: enforcedRoles,
      elevated_roles_covered_by_criteria: elevatedCovered,
    };
    const principals: Evaluation["principals"] = {
      admin_users: admins.length,
      admins_without_user_mfa_flag: truncateList(adminsWithoutFlag),
    };
    // Admin ratios are stated only from a complete read; a partial user or role read reports the observation without numbers.
    const complete = tablesComplete([data.users, data.privilegedAssignments]);
    const unflaggedAdmins = complete
      ? `${adminsWithoutFlag.length}/${admins.length} admin users do not carry enable_multifactor_authn`
      : "visible admin users without enable_multifactor_authn were observed (counts withheld because the user inventory was not fully read)";
    const allAdminsFlagged = complete
      ? `all ${admins.length} admin users carry enable_multifactor_authn`
      : "every visible admin user carries enable_multifactor_authn (counts withheld because the user inventory was not fully read)";
    // A property row that is absent from a partial sys_properties read may sit among the unread rows.
    if (!enabled.exists && !tablesComplete([data.properties])) {
      return {
        status: "manual",
        summary: "glide.authenticate.multifactor was not among the visible sys_properties rows and that read was partial, so the unread rows could hold it; platform MFA enablement is unknown.",
        evidence,
        principals,
      };
    }
    if (!enabled.exists || asBoolean(enabled.value) !== true) {
      return {
        status: "fail",
        summary: enabled.exists
          ? `glide.authenticate.multifactor is ${enabled.value}; platform MFA is disabled.`
          : "glide.authenticate.multifactor has no sys_properties row; the documented default is false, so platform MFA is not enabled.",
        evidence,
        principals,
      };
    }
    if (criteria.length === 0) {
      return {
        status: "manual",
        summary: `glide.authenticate.multifactor is true, but no ${MFA_CRITERIA_TABLE} rows were visible; the baseline Role-based multi-factor authentication record always exists, so the credential cannot read the enforcement criteria and enforcement is unknown.`,
        evidence,
        principals,
      };
    }
    if (admins.length === 0) {
      return {
        status: "manual",
        summary: `glide.authenticate.multifactor is true and the Role-based multi-factor authentication criteria record is ${activeRoleBased.length > 0 ? "active" : "inactive"}, but no admin users were visible to verify enforcement.`,
        evidence,
        principals,
      };
    }
    if (activeRoleBased.length === 0 && !userEnforced) {
      return {
        status: "fail",
        summary: `glide.authenticate.multifactor is true, but the Role-based multi-factor authentication criteria record is ${roleBased.length > 0 ? "inactive" : "not present among the visible criteria"} and ${unflaggedAdmins}, so MFA is not enforced for administrators.`,
        evidence,
        principals,
      };
    }
    if (activeRoleBased.length === 0) {
      return {
        status: "warn",
        summary: `glide.authenticate.multifactor is true and ${allAdminsFlagged}, but the Role-based multi-factor authentication criteria record is inactive, so newly granted administrators are not enforced automatically.`,
        evidence,
        principals,
      };
    }
    if (!roleEnforced && !userEnforced) {
      const rolesDescription = enforcedRoles.length > 0
        ? `its Multi-factor Roles list (${enforcedRoles.join(", ")}) does not include ${elevatedMissing.join(" and ")}`
        : "its Multi-factor Roles list was not returned by the Table API";
      return {
        status: "warn",
        summary: `glide.authenticate.multifactor is true and the Role-based multi-factor authentication criteria record is active, but ${rolesDescription} and ${unflaggedAdmins}; confirm admin and security_admin are enforced.`,
        evidence,
        principals,
      };
    }
    const enforcement = roleEnforced
      ? `the Role-based multi-factor authentication criteria record is active and covers ${elevatedCovered.join(" and ")}`
      : "the Role-based multi-factor authentication criteria record is active";
    const perUser = userEnforced
      ? complete
        ? `; all ${admins.length} admin users also carry enable_multifactor_authn`
        : "; every visible admin user also carries enable_multifactor_authn (counts withheld because the user inventory was not fully read)"
      : "";
    if (emailOtp.exists && asBoolean(emailOtp.value) === true) {
      return {
        status: "warn",
        summary: `MFA is enforced for administrators (${enforcement}${perUser}), but email OTP is enabled as a factor; ServiceNow hardening guidance treats email as a weak factor.`,
        evidence,
        principals,
      };
    }
    return {
      status: "pass",
      summary: `glide.authenticate.multifactor is true and MFA is enforced for administrators: ${enforcement}${perUser}.`,
      evidence,
      principals,
    };
  });

  const sso = gatedFinding(8, [data.ssoProviders, data.ldapServers, data.properties, data.certificates], "Open Multi-Provider SSO > Identity Providers and System LDAP > LDAP Servers; record active providers, certificate expiration dates, glide.authenticate.multisso.enabled, and the default redirect IdP.", () => {
    const activeSso = data.ssoProviders.rows.filter((row) => rowBoolean(row, "active") === true);
    const activeLdap = data.ldapServers.rows.filter((row) => rowBoolean(row, "active") === true);
    const multisso = readProperty(data.properties, "glide.authenticate.multisso.enabled");
    const redirect = readProperty(data.properties, "glide.authenticate.sso.redirect.idp");
    const activeCertificates = data.certificates.rows.filter((row) => rowBoolean(row, "active") !== false);
    const expiring: string[] = [];
    const expired: string[] = [];
    const undated: string[] = [];
    for (const certificate of activeCertificates) {
      const expires = parseServicenowDate(certificate.expires);
      const label = rowString(certificate, "name") ?? rowString(certificate, "sys_id") ?? "certificate";
      if (!expires) {
        undated.push(label);
        continue;
      }
      const remaining = daysBetween(expires, data.now);
      if (remaining < 0) expired.push(label);
      else if (remaining <= data.certExpiryWarnDays) expiring.push(label);
    }
    const evidence: JsonRecord = {
      active_sso_providers: truncateList(activeSso.map((row) => rowString(row, "name") ?? rowString(row, "sys_id") ?? "provider")),
      active_ldap_servers: truncateList(activeLdap.map((row) => rowString(row, "name") ?? rowString(row, "sys_id") ?? "ldap")),
      multisso_enabled: multisso.exists ? multisso.value : null,
      default_redirect_idp: redirect.exists ? Boolean(redirect.value) : null,
      certificates: activeCertificates.length,
      certificates_expired: expired,
      certificates_expiring: expiring,
      certificates_without_expiration: truncateList(undated),
    };
    if (activeSso.length === 0 && activeLdap.length === 0) {
      // Absence is only provable on complete reads: an active provider may sit in the unread remainder.
      if (!tablesComplete([data.ssoProviders, data.ldapServers])) {
        return {
          status: "manual",
          summary: "No active SSO identity provider (sso_properties) or LDAP server (ldap_server_config) was among the visible rows, and at least one of those reads was partial, so the absence of an external identity provider cannot be asserted.",
          evidence,
        };
      }
      return {
        status: "fail",
        summary: "No active SSO identity provider (sso_properties) or LDAP server (ldap_server_config) is configured; users authenticate with local passwords only.",
        evidence,
      };
    }
    if (expired.length > 0) {
      return { status: "fail", summary: `${expired.length} active certificates have already expired: ${expired.join(", ")}.`, evidence };
    }
    const concerns: string[] = [];
    if (activeSso.length > 0 && asBoolean(multisso.value) !== true) concerns.push(`glide.authenticate.multisso.enabled is ${multisso.exists ? multisso.value : "absent"}`);
    if (activeSso.length > 0 && (!redirect.exists || !redirect.value)) concerns.push("no default redirect IdP (glide.authenticate.sso.redirect.idp), so the local login form remains the default entry point");
    if (expiring.length > 0) concerns.push(`${expiring.length} certificates expire within ${data.certExpiryWarnDays} days (${expiring.join(", ")})`);
    if (undated.length > 0) concerns.push(`${undated.length} certificates have no expiration date and are not treated as valid`);
    if (concerns.length > 0) {
      return {
        status: "warn",
        summary: `${activeSso.length} active SSO providers and ${activeLdap.length} active LDAP servers are configured, but: ${concerns.join("; ")}.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `${activeSso.length} active SSO providers and ${activeLdap.length} active LDAP servers are configured, Multi-Provider SSO is enabled with a default redirect IdP, and no active certificate expires within ${data.certExpiryWarnDays} days.`,
      evidence,
    };
  });

  const integrationUsers = gatedFinding(14, [data.users, data.privilegedAssignments, data.oauthEntities], "List User Administration > Users with Web service access only = true or Internal Integration User = true, and System OAuth > Application Registry; confirm each integration account holds only the roles its integration needs and none hold admin.", () => {
    const integration = users.filter(isIntegrationUser);
    const integrationWithAdmin = assignments.filter((row) => assignmentIsIntegration(row) && ELEVATED_ROLE_NAMES.includes(rowString(row, "role.name") ?? "")).map(userLabel);
    const integrationWithPrivilege = assignments.filter(assignmentIsIntegration).map((row) => `${userLabel(row)}:${rowString(row, "role.name") ?? "role"}`);
    const evidence: JsonRecord = {
      oauth_entities: data.oauthEntities.rows.length,
    };
    const principals: Evaluation["principals"] = {
      integration_users: integration.length,
      integration_user_names: truncateList(integration.map(userLabel)),
      integration_users_with_admin: [...new Set(integrationWithAdmin)],
      integration_privileged_assignments: truncateList([...new Set(integrationWithPrivilege)]),
    };
    const complete = tablesComplete([data.users, data.privilegedAssignments, data.oauthEntities]);
    const withheld = "counts and names are withheld because the user or role inventory was not fully read";
    if (integrationWithAdmin.length > 0) {
      const names = [...new Set(integrationWithAdmin)];
      return {
        status: "fail",
        summary: complete
          ? `${names.length} integration accounts hold admin or security_admin: ${names.join(", ")}.`
          : `Among the visible rows, integration accounts hold admin or security_admin; ${withheld}.`,
        evidence,
        principals,
      };
    }
    if (integration.length === 0) {
      return {
        status: "manual",
        summary: `No active user is flagged web_service_access_only or internal_integration_user although ${data.oauthEntities.rows.length} OAuth application registry entries exist; integrations may be running under interactive accounts, which cannot be told apart through the API.`,
        evidence,
        principals,
      };
    }
    if (integrationWithPrivilege.length > 0) {
      return {
        status: "warn",
        summary: complete
          ? `${integration.length} integration accounts exist and none hold admin, but ${new Set(integrationWithPrivilege).size} privileged assignments (${PRIVILEGED_ROLE_NAMES.join(", ")}) belong to integration accounts.`
          : `Among the visible rows, no integration account holds admin, but privileged assignments (${PRIVILEGED_ROLE_NAMES.join(", ")}) belong to integration accounts; ${withheld}.`,
        evidence,
        principals,
      };
    }
    return {
      status: "pass",
      summary: complete
        ? `${integration.length} integration accounts are flagged web service or internal integration users and none hold a privileged role.`
        : `No visible integration account holds a privileged role, but the user or role inventory was not fully read, so the population is unknown.`,
      evidence,
      principals,
    };
  });

  const findings = sortFindings([roleHierarchy, userAccessReview, passwordPolicy, mfa, sso, integrationUsers]);
  return {
    area: "identity_access",
    title: "ServiceNow identity and access",
    summary: {
      active_users_visible: visibleRows(data.users),
      active_users_total: totalRows(data.users),
      admin_users: principalCount(elevatedUserIds.size, data.users, data.privilegedAssignments),
      privileged_assignments_visible: visibleRows(data.privilegedAssignments),
      roles_inheriting_admin: derived(data.roleInheritance.rows.length, data.roleInheritance),
      active_sso_providers: derived(data.ssoProviders.rows.filter((row) => rowBoolean(row, "active") === true).length, data.ssoProviders),
      active_ldap_servers: derived(data.ldapServers.rows.filter((row) => rowBoolean(row, "active") === true).length, data.ldapServers),
      inventories: {
        users: describeTable(data.users),
        privileged_assignments: describeTable(data.privilegedAssignments),
        role_inheritance: describeTable(data.roleInheritance),
        role_inheritance_total: describeCount(data.roleInheritanceTotal),
        properties: describeTable(data.properties),
        password_policies: describeTable(data.passwordPolicies),
        sso_providers: describeTable(data.ssoProviders),
        ldap_servers: describeTable(data.ldapServers),
        certificates: describeTable(data.certificates),
        oauth_entities: describeTable(data.oauthEntities),
        mfa_criteria: describeTable(data.mfaCriteria),
      },
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors,
  };
}

export async function assessServicenowIdentityAccess(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords" | "getNow">,
  options: ServicenowIdentityOptions = {},
): Promise<ServicenowAssessmentResult> {
  return assessServicenowIdentityAccessData(await collectServicenowIdentityData(client, options));
}

export interface ServicenowHardeningData {
  properties: TableSnapshot;
  debugProperties: TableSnapshot;
  evalScripts: TableSnapshot;
  ipAccessRules: TableSnapshot;
  ipAuthenticatorPlugin: TableSnapshot;
  emailAccounts: TableSnapshot;
  maxSessionTimeoutMinutes: number;
}

export async function collectServicenowHardeningData(
  client: Pick<ServicenowReadClient, "queryTable">,
  options: ServicenowHardeningOptions = {},
): Promise<ServicenowHardeningData> {
  const recordLimit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 500_000);
  const [properties, debugProperties, evalScripts, ipAccessRules, ipAuthenticatorPlugin, emailAccounts] = await Promise.all([
    readTable(client, "sys_properties", { query: `nameIN${HARDENING_PROPERTY_QUERY_NAMES.join(",")}`, fields: PROPERTY_FIELDS, limit: recordLimit }),
    readTable(client, "sys_properties", { query: "nameLIKEdebug^value=true", fields: PROPERTY_FIELDS, limit: recordLimit }),
    readTable(client, "sys_script", { query: "active=true^scriptLIKEeval(", fields: ["sys_id", "name", "collection", "sys_updated_on"], limit: recordLimit }),
    readTable(client, IP_ACCESS_TABLE, { fields: IP_ACCESS_FIELDS, limit: recordLimit }),
    readTable(client, "sys_plugins", { query: `source=${IP_AUTHENTICATOR_PLUGIN}`, fields: PLUGIN_FIELDS, limit: recordLimit }),
    readTable(client, "sys_email_account", { fields: EMAIL_ACCOUNT_FIELDS, displayValue: true, limit: recordLimit }),
  ]);
  return {
    properties,
    debugProperties,
    evalScripts,
    ipAccessRules: normalizeMissingTable(ipAccessRules, `${IP_ACCESS_TABLE} does not exist on this instance; the ${IP_AUTHENTICATOR_PLUGIN} plugin creates it when activated`),
    ipAuthenticatorPlugin,
    emailAccounts,
    maxSessionTimeoutMinutes: clampNumber(options.maxSessionTimeoutMinutes, DEFAULT_MAX_SESSION_TIMEOUT_MINUTES, 1, 1440),
  };
}

type EmailConnectionSecurity = "ssl_tls" | "starttls" | "none" | "unknown";

interface EmailAccountSecurity {
  name: string;
  connection_security: string | null;
  level: EmailConnectionSecurity;
  source: "connection_security" | "legacy_flags" | "not_returned";
}

/**
 * The documented Email Account field is the Connection Security choice
 * (None, STARTTLS, SSL/TLS). Older schemas exposed enable_ssl and enable_tls
 * booleans instead; anything else leaves the transport unverified.
 */
function classifyEmailConnectionSecurity(row: JsonRecord): EmailAccountSecurity {
  const name = rowString(row, "name") ?? rowString(row, "sys_id") ?? "account";
  const declared = rowString(row, "connection_security");
  if (declared) {
    const normalized = declared.toLowerCase();
    const level: EmailConnectionSecurity = /starttls/.test(normalized)
      ? "starttls"
      : /ssl|tls/.test(normalized)
        ? "ssl_tls"
        : /none/.test(normalized)
          ? "none"
          : "unknown";
    return { name, connection_security: declared, level, source: "connection_security" };
  }
  const ssl = rowBoolean(row, "enable_ssl");
  const tls = rowBoolean(row, "enable_tls");
  if (ssl === true) return { name, connection_security: "enable_ssl=true", level: "ssl_tls", source: "legacy_flags" };
  if (tls === true) return { name, connection_security: "enable_tls=true", level: "starttls", source: "legacy_flags" };
  if (ssl === false || tls === false) {
    return { name, connection_security: `enable_ssl=${ssl ?? "absent"}, enable_tls=${tls ?? "absent"}`, level: "none", source: "legacy_flags" };
  }
  return { name, connection_security: null, level: "unknown", source: "not_returned" };
}

export function assessServicenowPlatformHardeningData(data: ServicenowHardeningData): ServicenowAssessmentResult {
  const errors = [
    ...snapshotErrors("hardening properties", data.properties),
    ...snapshotErrors("debug properties", data.debugProperties),
    ...snapshotErrors("business rules using eval", data.evalScripts),
    ...snapshotErrors("ip access rules", data.ipAccessRules),
    ...snapshotErrors("ip authenticator plugin", data.ipAuthenticatorPlugin),
    ...snapshotErrors("email accounts", data.emailAccounts),
  ];

  const instanceSecurity = gatedFinding(1, [data.properties], "Open System Properties > Security (or the Instance Security Center hardening view) and record glide.security.use_csrf_token, glide.security.csrf.strict.validation.mode, glide.security.file.mime_type.validation, glide.security.diag_txns_acl, and glide.security.strict.user_image_upload.", () =>
    propertyVerdict(checkProperties(data.properties, INSTANCE_SECURITY_PROPERTIES), "instance security"));

  const session = gatedFinding(5, [data.properties], `Open System Properties > UI Properties and record glide.ui.session_timeout (expected ${data.maxSessionTimeoutMinutes} minutes or less), glide.ui.rotate_sessions, and glide.ui.user_cookie.max_life_span_in_days.`, () => {
    const timeout = readProperty(data.properties, "glide.ui.session_timeout");
    const rotate = readProperty(data.properties, "glide.ui.rotate_sessions");
    const cookieLife = readProperty(data.properties, "glide.ui.user_cookie.max_life_span_in_days");
    const timeoutMinutes = asNumber(timeout.value);
    const evidence: JsonRecord = {
      session_timeout_minutes: timeoutMinutes ?? null,
      session_timeout_present: timeout.exists,
      max_session_timeout_minutes: data.maxSessionTimeoutMinutes,
      rotate_sessions: rotate.exists ? rotate.value : null,
      user_cookie_max_life_span_days: cookieLife.exists ? cookieLife.value : null,
    };
    if (timeout.exists && (timeoutMinutes === undefined || timeoutMinutes <= 0 || timeoutMinutes > data.maxSessionTimeoutMinutes)) {
      return {
        status: "fail",
        summary: `glide.ui.session_timeout is ${timeout.value}, which exceeds the ${data.maxSessionTimeoutMinutes} minute threshold or is not a positive number.`,
        evidence,
      };
    }
    if (!timeout.exists) {
      return {
        status: "warn",
        summary: `glide.ui.session_timeout has no sys_properties row; ServiceNow documents a fallback of 30 minutes, but the value is not observed and is not assumed. Set it explicitly to ${data.maxSessionTimeoutMinutes} minutes or less.`,
        evidence,
      };
    }
    if (rotate.exists && asBoolean(rotate.value) === false) {
      return {
        status: "warn",
        summary: `glide.ui.session_timeout is ${timeoutMinutes} minutes, within the threshold, but glide.ui.rotate_sessions is false.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `glide.ui.session_timeout is ${timeoutMinutes} minutes, within the ${data.maxSessionTimeoutMinutes} minute threshold${rotate.exists ? `, and glide.ui.rotate_sessions is ${rotate.value}` : ""}.`,
      evidence,
    };
  });

  const scripts = gatedFinding(12, [data.properties, data.evalScripts], "Open System Properties > Security and record glide.script.use.sandbox, glide.script.allow.ajaxevaluate, glide.script.secure.ajaxgliderecord, and glide.script.ccsi.ispublic; search System Definition > Business Rules for eval( usage.", () => {
    const verdict = propertyVerdict(checkProperties(data.properties, SCRIPT_RESTRICTION_PROPERTIES), "script restriction");
    const evalRules = data.evalScripts.rows.map((row) => `${rowString(row, "name") ?? rowString(row, "sys_id") ?? "rule"} (${rowString(row, "collection") ?? "table"})`);
    const evidence = { ...(verdict.evidence ?? {}), business_rules_using_eval: truncateList(evalRules), business_rules_using_eval_count: evalRules.length };
    if (evalRules.length > 0) {
      return {
        status: "fail",
        summary: `${verdict.summary} ${evalRules.length} active business rules call eval(): ${truncateList(evalRules, 10).join(", ")}.`,
        evidence,
      };
    }
    return { ...verdict, summary: `${verdict.summary} No active business rule calls eval().`, evidence };
  });

  const hardening = gatedFinding(13, [data.properties], "Open System Properties > Security and the Instance Security Center hardening view; record the strict update, strict action, HTML escaping, sanitizer, code tag, X-Frame-Options, and cookie properties.", () =>
    propertyVerdict(checkProperties(data.properties, HARDENING_PROPERTIES), "hardening"));

  const debug = gatedFinding(16, [data.properties, data.debugProperties], "Filter System Properties on name contains debug and confirm every debug property is false, then confirm no session debug is enabled for shared accounts.", () => {
    const enabledDebug = data.debugProperties.rows.map((row) => rowString(row, "name") ?? "property");
    const evidence: JsonRecord = { enabled_debug_properties: truncateList(enabledDebug), hardening_properties_visible: data.properties.rows.length };
    if (enabledDebug.length > 0) {
      return { status: "fail", summary: `${enabledDebug.length} debug properties are enabled: ${truncateList(enabledDebug, 10).join(", ")}.`, evidence };
    }
    if (data.properties.rows.length === 0) {
      return {
        status: "manual",
        summary: "No debug property is enabled, but the companion hardening property read returned zero rows, so sys_properties visibility is not proven and the empty result cannot be trusted.",
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `No sys_properties row whose name contains debug is set to true (sys_properties visibility proven by ${data.properties.rows.length} readable hardening rows).`,
      evidence,
    };
  });

  const ipAccess = gatedFinding(17, [data.properties, data.ipAccessRules, data.ipAuthenticatorPlugin], `Open System Definition > Plugins and confirm IP Range Based Authentication (${IP_AUTHENTICATOR_PLUGIN}) is active, then open System Security > IP Address Access Control and record the active allow and deny rules (type, direction, range) plus glide.ip.authenticate.strict.`, () => {
    const strict = readProperty(data.properties, "glide.ip.authenticate.strict");
    const pluginRow = data.ipAuthenticatorPlugin.rows.find((row) => rowString(row, "source") === IP_AUTHENTICATOR_PLUGIN) ?? data.ipAuthenticatorPlugin.rows[0];
    const pluginState = pluginRow ? pluginActive(pluginRow) : undefined;
    const tableUnavailable = data.ipAccessRules.unavailable;
    const rules = data.ipAccessRules.rows;
    const activeRules = rules.filter((row) => rowBoolean(row, "active") !== false);
    const evidence: JsonRecord = {
      ip_authenticator_plugin: IP_AUTHENTICATOR_PLUGIN,
      ip_authenticator_plugin_present: Boolean(pluginRow),
      ip_authenticator_plugin_active: pluginState ?? null,
      ip_access_table_available: !tableUnavailable,
      ip_access_rules: rules.length,
      active_ip_access_rules: activeRules.length,
      active_rules: truncateList(activeRules.map((row) => `${rowString(row, "type") ?? "type"} ${rowString(row, "direction") ?? "direction"} ${rowString(row, "range_start") ?? "?"}-${rowString(row, "range_end") ?? "?"}`)),
      glide_ip_authenticate_strict: strict.exists ? strict.value : null,
    };
    if (pluginState !== true) {
      if (!pluginRow && activeRules.length > 0) {
        return {
          status: "warn",
          summary: `${activeRules.length} active ${IP_ACCESS_TABLE} rules exist, but ${IP_AUTHENTICATOR_PLUGIN} was not visible in sys_plugins, so plugin activation could not be confirmed from this credential.`,
          evidence,
        };
      }
      if (!pluginRow && !tablesComplete([data.ipAuthenticatorPlugin])) {
        return {
          status: "manual",
          summary: `${IP_AUTHENTICATOR_PLUGIN} was not among the visible sys_plugins rows and that read was partial, so plugin activation cannot be asserted either way.`,
          evidence,
        };
      }
      const pluginDescription = pluginRow ? `is ${rowString(pluginRow, "active") ?? "not active"} in sys_plugins` : "has no row in sys_plugins";
      return {
        status: "fail",
        summary: `IP Range Based Authentication (${IP_AUTHENTICATOR_PLUGIN}) ${pluginDescription}${tableUnavailable ? ` and the ${IP_ACCESS_TABLE} table does not exist` : ` and ${activeRules.length} active ${IP_ACCESS_TABLE} rules are visible`}; administrative access is not restricted by source network.`,
        evidence,
      };
    }
    if (tableUnavailable) {
      return {
        status: "manual",
        summary: `${IP_AUTHENTICATOR_PLUGIN} is active but the ${IP_ACCESS_TABLE} table was reported as invalid (${tableUnavailable}); review IP Address Access Control manually.`,
        evidence,
      };
    }
    if (activeRules.length === 0) {
      if (!tablesComplete([data.ipAccessRules])) {
        return {
          status: "manual",
          summary: `${IP_AUTHENTICATOR_PLUGIN} is active and none of the visible ${IP_ACCESS_TABLE} rows is active, but that read was partial, so the absence of an active rule cannot be asserted.`,
          evidence,
        };
      }
      return {
        status: "fail",
        summary: `${IP_AUTHENTICATOR_PLUGIN} is active but no active IP Address Access Control rule exists (${IP_ACCESS_TABLE} has ${rules.length} rows, none active), so administrative access is not restricted by source network.`,
        evidence,
      };
    }
    if (!strict.exists || asBoolean(strict.value) !== true) {
      return {
        status: "warn",
        summary: `${IP_AUTHENTICATOR_PLUGIN} is active with ${activeRules.length} active ${IP_ACCESS_TABLE} rules, but glide.ip.authenticate.strict is ${strict.exists ? strict.value : "absent"}; strict enforcement is not confirmed.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `${IP_AUTHENTICATOR_PLUGIN} is active, ${activeRules.length} active ${IP_ACCESS_TABLE} rules restrict access by source network, and glide.ip.authenticate.strict is true.`,
      evidence,
    };
  });

  const email = gatedFinding(18, [data.properties, data.emailAccounts], "Open System Mailboxes > Administration > Email Accounts and record the Connection Security choice (SSL/TLS expected) on each active SMTP account; open Email Properties for glide.smtp.auth; record DKIM signing configuration and notification security headers.", () => {
    const smtpAuth = readProperty(data.properties, "glide.smtp.auth");
    const smtpAuthDisabled = smtpAuth.exists && asBoolean(smtpAuth.value) === false;
    const smtpAccounts = data.emailAccounts.rows.filter((row) => /smtp/i.test(rowString(row, "type") ?? "") && rowBoolean(row, "active") !== false);
    const classified = smtpAccounts.map(classifyEmailConnectionSecurity);
    const byLevel = (level: EmailConnectionSecurity) => classified.filter((item) => item.level === level);
    const insecure = byLevel("none");
    const opportunistic = byLevel("starttls");
    const unverified = byLevel("unknown");
    const secure = byLevel("ssl_tls");
    const names = (items: EmailAccountSecurity[]) => items.map((item) => item.name);
    const evidence: JsonRecord = {
      active_smtp_accounts: smtpAccounts.length,
      smtp_connection_security: truncateList(classified),
      smtp_accounts_ssl_tls: names(secure),
      smtp_accounts_starttls: names(opportunistic),
      smtp_accounts_none: names(insecure),
      smtp_accounts_unverified: names(unverified),
      glide_smtp_auth: smtpAuth.exists ? smtpAuth.value : null,
      dkim_verified_via_api: false,
    };
    if (insecure.length > 0 || smtpAuthDisabled) {
      return {
        status: "fail",
        summary: `${insecure.length}/${smtpAccounts.length} active SMTP accounts use Connection Security = None${insecure.length > 0 ? ` (${names(insecure).join(", ")})` : ""}${smtpAuthDisabled ? " and glide.smtp.auth is false" : ""}; ServiceNow warns that None may expose data and recommends SSL/TLS.`,
        evidence,
      };
    }
    if (smtpAccounts.length === 0) {
      return {
        status: "manual",
        summary: "No active SMTP email account is visible; either outbound email is disabled or the credential cannot read sys_email_account. Confirm outbound email configuration and DKIM manually.",
        evidence,
      };
    }
    if (unverified.length > 0) {
      return {
        status: "manual",
        summary: `Connection Security could not be read for ${unverified.length}/${smtpAccounts.length} active SMTP accounts (${names(unverified).join(", ")}): the connection_security column and the legacy enable_ssl and enable_tls flags were not returned, so the transport is neither assumed secure nor insecure. Confirm each account's Connection Security and DKIM manually.`,
        evidence,
      };
    }
    if (opportunistic.length > 0) {
      return {
        status: "warn",
        summary: `${opportunistic.length}/${smtpAccounts.length} active SMTP accounts use STARTTLS (${names(opportunistic).join(", ")}); ServiceNow warns that STARTTLS may expose data and recommends SSL/TLS. DKIM signing and notification security headers still require manual confirmation.`,
        evidence,
      };
    }
    return {
      status: "manual",
      summary: `All ${smtpAccounts.length} active SMTP accounts use Connection Security = SSL/TLS${smtpAuth.exists ? ` and glide.smtp.auth is ${smtpAuth.value}` : ", but glide.smtp.auth has no row"}; DKIM signing and notification security headers are not exposed through the Table API and must be confirmed manually.`,
      evidence,
    };
  });

  const findings = sortFindings([instanceSecurity, session, scripts, hardening, debug, ipAccess, email]);
  return {
    area: "platform_hardening",
    title: "ServiceNow platform hardening",
    summary: {
      hardening_properties_visible: visibleRows(data.properties),
      hardening_properties_expected: HARDENING_PROPERTY_QUERY_NAMES.length,
      enabled_debug_properties: derived(data.debugProperties.rows.length, data.debugProperties),
      business_rules_using_eval: derived(data.evalScripts.rows.length, data.evalScripts),
      active_ip_access_rules: derived(data.ipAccessRules.rows.filter((row) => rowBoolean(row, "active") !== false).length, data.ipAccessRules),
      ip_authenticator_plugin_active: derivedFlag(data.ipAuthenticatorPlugin.rows.some((row) => pluginActive(row) === true), data.ipAuthenticatorPlugin),
      inventories: {
        properties: describeTable(data.properties),
        debug_properties: describeTable(data.debugProperties),
        eval_scripts: describeTable(data.evalScripts),
        ip_access_rules: describeTable(data.ipAccessRules),
        ip_authenticator_plugin: describeTable(data.ipAuthenticatorPlugin),
        email_accounts: describeTable(data.emailAccounts),
      },
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors,
  };
}

export async function assessServicenowPlatformHardening(
  client: Pick<ServicenowReadClient, "queryTable">,
  options: ServicenowHardeningOptions = {},
): Promise<ServicenowAssessmentResult> {
  return assessServicenowPlatformHardeningData(await collectServicenowHardeningData(client, options));
}

export interface ServicenowAccessControlData {
  acls: TableSnapshot;
  aclRoles: TableSnapshot;
  aclTotal: CountResult;
  publicPages: TableSnapshot;
}

/**
 * ServiceNow encoded queries bind ^OR to the adjacent condition only, so the
 * name alternatives are expressed as ^NQ groups that each repeat the active
 * and type conditions. The result is (active AND record AND name-in-list) OR
 * (active AND record AND name starts with "table.") for every sensitive table.
 */
export function buildSensitiveAclQuery(): string {
  const base = "active=true^type=record";
  const names = ["*", ...SENSITIVE_ACL_TABLES];
  return [
    `${base}^nameIN${names.join(",")}`,
    ...names.map((name) => `${base}^nameSTARTSWITH${name}.`),
  ].join("^NQ");
}

/**
 * SNOW-02 and SNOW-11 only ask whether an ACL carries a condition or a
 * script, so the tenant code bodies are reduced to booleans before the
 * snapshot is stored or exported.
 */
export function projectAclRow(row: JsonRecord): JsonRecord {
  const { condition, script, ...rest } = row;
  return { ...rest, has_condition: Boolean(asString(condition)), has_script: Boolean(asString(script)) };
}

export async function collectServicenowAccessControlData(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords">,
  options: ServicenowAccessControlOptions = {},
): Promise<ServicenowAccessControlData> {
  const recordLimit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 500_000);
  const rawAcls = await readTable(client, "sys_security_acl", { query: buildSensitiveAclQuery(), fields: ACL_FIELDS, limit: recordLimit });
  const acls: TableSnapshot = { ...rawAcls, rows: rawAcls.rows.map(projectAclRow) };
  const aclIds = acls.rows.map((row) => rowString(row, "sys_id")).filter((item): item is string => Boolean(item));
  // The role lookup is keyed on the ACL ids that were read. Without ids no request is issued, and the
  // placeholder snapshot says so instead of borrowing the status code of the sys_security_acl read.
  const skippedRoles = (reason: string, failed: boolean): TableSnapshot => ({
    table: "sys_security_acl_role",
    query: "sys_security_aclIN",
    rows: [],
    pages: 0,
    truncated: false,
    partial: false,
    skipped: reason,
    ...(failed ? { error: `not requested: ${reason}` } : {}),
  });
  const [aclRoles, aclTotal, publicPages] = await Promise.all([
    aclIds.length > 0
      ? readTable(client, "sys_security_acl_role", { query: `sys_security_aclIN${aclIds.join(",")}`, fields: ACL_ROLE_FIELDS, limit: recordLimit })
      : Promise.resolve(acls.error
        ? skippedRoles(`the ${acls.table} read failed, so there were no ACL ids to look up`, true)
        : skippedRoles(`the ${acls.table} read returned no rows, so there were no ACL ids to look up`, false)),
    client.countRecords("sys_security_acl", "active=true^type=record"),
    readTable(client, "sys_public", { query: "active=true", fields: ["sys_id", "page", "active", "sys_updated_on"], limit: recordLimit }),
  ]);
  return { acls, aclRoles, aclTotal, publicPages };
}

function aclLabel(row: JsonRecord): string {
  return `${rowString(row, "name") ?? "acl"}:${rowString(row, "operation") ?? "op"}`;
}

export function assessServicenowAccessControlData(data: ServicenowAccessControlData): ServicenowAssessmentResult {
  const errors = [
    ...snapshotErrors("acls", data.acls),
    ...snapshotErrors("acl roles", data.aclRoles),
    ...countErrors("acls", data.aclTotal),
    ...snapshotErrors("public pages", data.publicPages),
  ];

  const rolesByAcl = new Map<string, string[]>();
  for (const row of data.aclRoles.rows) {
    const acl = rowString(row, "sys_security_acl");
    const role = rowString(row, "sys_user_role.name") ?? rowString(row, "sys_user_role");
    if (!acl || !role) continue;
    rolesByAcl.set(acl, [...(rolesByAcl.get(acl) ?? []), role]);
  }
  const describeAcl = (row: JsonRecord) => {
    const id = rowString(row, "sys_id") ?? "";
    const roles = rolesByAcl.get(id) ?? [];
    const hasCondition = rowBoolean(row, "has_condition") ?? Boolean(rowString(row, "condition"));
    const hasScript = rowBoolean(row, "has_script") ?? Boolean(rowString(row, "script"));
    return { label: aclLabel(row), name: rowString(row, "name") ?? "", operation: rowString(row, "operation") ?? "", roles, unrestricted: roles.length === 0 && !hasCondition && !hasScript, admin_overrides: rowBoolean(row, "admin_overrides") };
  };
  const described = data.acls.rows.map(describeAcl);
  const wildcard = described.filter((item) => item.name === "*" || item.name.startsWith("*."));
  const unrestricted = described.filter((item) => item.unrestricted);

  const completeness = gatedFinding(2, [data.acls, data.aclRoles, data.publicPages], "Open System Security > Access Control (ACL), filter Active = true and Type = record; review wildcard (*) rules and rules with no role, condition, or script. Open System Definition > Public Pages and justify each active page.", () => {
    const publicPages = data.publicPages.rows.map((row) => rowString(row, "page") ?? rowString(row, "sys_id") ?? "page");
    const proven = data.aclTotal.count;
    const evidence: JsonRecord = {
      record_acl_total: proven ?? null,
      sensitive_acls_visible: described.length,
      wildcard_acls: truncateList(wildcard.map((item) => item.label)),
      unrestricted_acls: truncateList(unrestricted.map((item) => item.label)),
      unrestricted_acl_count: unrestricted.length,
      public_pages: truncateList(publicPages),
      public_page_count: publicPages.length,
    };
    if (data.aclTotal.error || proven === undefined || proven === 0) {
      return {
        status: "manual",
        summary: `The sys_security_acl inventory could not be proven visible (aggregate count ${proven ?? "unavailable"}${data.aclTotal.error ? `, ${data.aclTotal.error}` : ""}); every instance ships thousands of ACLs, so the visible rows cannot be trusted.`,
        evidence,
      };
    }
    if (unrestricted.length > 0) {
      return {
        status: "fail",
        summary: `${unrestricted.length} active record ACLs on sensitive or wildcard tables have no role, condition, or script and therefore grant unrestricted access: ${truncateList(unrestricted.map((item) => item.label), 10).join(", ")}.`,
        evidence,
      };
    }
    if (wildcard.length > 0 || publicPages.length > 0) {
      return {
        status: "warn",
        summary: `${proven} active record ACLs exist; ${wildcard.length} wildcard ACLs and ${publicPages.length} active public pages (${truncateList(publicPages, 8).join(", ")}) need justification.`,
        evidence,
      };
    }
    if (described.length === 0) {
      return {
        status: "manual",
        summary: `${proven} active record ACLs exist but none of the sensitive-table or wildcard ACLs were visible to this credential, so completeness cannot be judged.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `${proven} active record ACLs exist; ${described.length} ACLs on sensitive tables were reviewed, none is unrestricted, no wildcard ACL is active, and no public page is active.`,
      evidence,
    };
  });

  const tableLevel = gatedFinding(11, [data.acls, data.aclRoles], `Open System Security > Access Control (ACL) and confirm read, write, and delete record ACLs with roles exist for ${SENSITIVE_ACL_TABLES.join(", ")}.`, () => {
    const proven = data.aclTotal.count;
    // Per-table "no ACL" and "missing operation" claims are absence claims; on a partial ACL read they render null.
    const complete = tablesComplete([data.acls, data.aclRoles]);
    const coverage = SENSITIVE_ACL_TABLES.map((table) => {
      const rows = described.filter((item) => item.name === table || item.name.startsWith(`${table}.`));
      const operations = new Set(rows.map((item) => item.operation));
      const roleProtected = rows.filter((item) => item.roles.length > 0 || item.name.startsWith(`${table}.`)).length;
      return {
        table,
        acls: rows.length,
        operations: [...operations].sort(),
        missing_operations: ["read", "write", "delete"].filter((operation) => !operations.has(operation)),
        role_protected_acls: roleProtected,
      };
    });
    const coverageEvidence = coverage.map((item) => ({
      table: item.table,
      acls: complete || item.acls > 0 ? item.acls : null,
      operations: complete || item.operations.length > 0 ? item.operations : null,
      missing_operations: complete ? item.missing_operations : null,
      role_protected_acls: complete || item.role_protected_acls > 0 ? item.role_protected_acls : null,
    }));
    const evidence: JsonRecord = { record_acl_total: proven ?? null, sensitive_table_coverage: coverageEvidence };
    if (data.aclTotal.error || proven === undefined || proven === 0) {
      return {
        status: "manual",
        summary: `The sys_security_acl inventory could not be proven visible (aggregate count ${proven ?? "unavailable"}), so table-level coverage cannot be judged.`,
        evidence,
      };
    }
    const uncovered = coverage.filter((item) => item.acls === 0);
    const gaps = coverage.filter((item) => item.acls > 0 && item.missing_operations.length > 0);
    // A table with no ACL among the visible rows is an absence claim; on a partial read the unread rows could hold it.
    if ((uncovered.length > 0 || gaps.length > 0) && !complete) {
      return {
        status: "manual",
        summary: "Some sensitive tables showed no active record ACL, or no explicit read, write, or delete rule, among the visible sys_security_acl rows, but that read was partial, so the unread rows could hold them; table names and counts are withheld and coverage cannot be judged.",
        evidence,
      };
    }
    if (uncovered.length > 0) {
      return {
        status: "fail",
        summary: `${uncovered.length} sensitive tables have no visible active record ACL: ${uncovered.map((item) => item.table).join(", ")}.`,
        evidence,
      };
    }
    if (gaps.length > 0) {
      return {
        status: "warn",
        summary: `All ${coverage.length} sensitive tables have record ACLs, but ${gaps.length} lack an explicit read, write, or delete rule: ${gaps.map((item) => `${item.table} (missing ${item.missing_operations.join("/")})`).join(", ")}.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `All ${coverage.length} sensitive tables have active read, write, and delete record ACLs.`,
      evidence,
    };
  });

  const findings = sortFindings([completeness, tableLevel]);
  return {
    area: "access_control",
    title: "ServiceNow access control",
    summary: {
      record_acl_total: countValue(data.aclTotal),
      sensitive_acls_visible: visibleRows(data.acls),
      wildcard_acls: derived(wildcard.length, data.acls),
      unrestricted_acls: derived(unrestricted.length, data.acls, data.aclRoles),
      public_pages: derived(data.publicPages.rows.length, data.publicPages),
      inventories: {
        acls: describeTable(data.acls),
        acl_roles: describeTable(data.aclRoles),
        acl_total: describeCount(data.aclTotal),
        public_pages: describeTable(data.publicPages),
      },
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors,
  };
}

export async function assessServicenowAccessControl(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords">,
  options: ServicenowAccessControlOptions = {},
): Promise<ServicenowAssessmentResult> {
  return assessServicenowAccessControlData(await collectServicenowAccessControlData(client, options));
}

export interface ServicenowOperationsData {
  encryptionContexts: TableSnapshot;
  cryptoModules: TableSnapshot;
  encryptedFields: TableSnapshot;
  auditDictionary: TableSnapshot;
  recentAuditCount: CountResult;
  recentTransactionCount: CountResult;
  updateSetsInProgress: TableSnapshot;
  updateSetTotal: CountResult;
  sensitiveUpdateXml: TableSnapshot;
  midServers: TableSnapshot;
  properties: TableSnapshot;
  plugins: TableSnapshot;
}

export async function collectServicenowOperationsData(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords">,
  options: ServicenowOperationsOptions = {},
): Promise<ServicenowOperationsData> {
  const recordLimit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 500_000);
  const sensitiveXmlQuery = [
    "update_set.state=in progress",
    ["sys_security_acl_", "sys_user_role_", "sys_user_role_contains_", "sys_script_", "sys_script_include_", "sys_properties_"].map((prefix) => `nameSTARTSWITH${prefix}`).join("^OR"),
  ].join("^");
  const [encryptionContexts, cryptoModules, encryptedFields, auditDictionary, recentAuditCount, recentTransactionCount, updateSetsInProgress, updateSetTotal, sensitiveUpdateXml, midServers, properties, plugins] = await Promise.all([
    readTable(client, LEGACY_ENCRYPTION_CONTEXT_TABLE, { fields: ["sys_id", "name", "type", "sys_updated_on"], limit: recordLimit }),
    readTable(client, CRYPTO_MODULE_TABLE, { fields: ["sys_id", "name", "module_name", "state", "sys_scope", "sys_updated_on"], limit: recordLimit }),
    readTable(client, "sys_dictionary", { query: "internal_type=glide_encrypted^ORinternal_type=password2", fields: ["sys_id", "name", "element", "internal_type"], limit: recordLimit }),
    readTable(client, "sys_dictionary", { query: `internal_type=collection^nameIN${AUDITED_CRITICAL_TABLES.join(",")}`, fields: ["sys_id", "name", "audit", "attributes"], limit: recordLimit }),
    client.countRecords("sys_audit", `sys_created_on>=javascript:gs.daysAgoStart(${AUDIT_LOOKBACK_DAYS})`),
    client.countRecords("syslog_transaction", "sys_created_on>=javascript:gs.daysAgoStart(1)"),
    readTable(client, "sys_update_set", { query: "state=in progress", fields: ["sys_id", "name", "state", "application", "sys_created_by", "sys_updated_on"], limit: recordLimit }),
    client.countRecords("sys_update_set"),
    readTable(client, "sys_update_xml", { query: sensitiveXmlQuery, fields: ["sys_id", "name", "type", "target_name", "action", "update_set", "update_set.name", "sys_updated_on"], limit: recordLimit }),
    readTable(client, "ecc_agent", { fields: ["sys_id", "name", "status", "validated", "version", "host_name", "sys_updated_on"], limit: recordLimit }),
    readTable(client, "sys_properties", { query: `nameIN${MID_PROPERTY_NAMES.join(",")}`, fields: PROPERTY_FIELDS, limit: recordLimit }),
    readTable(client, "sys_plugins", { fields: PLUGIN_FIELDS, limit: recordLimit }),
  ]);
  return {
    encryptionContexts: normalizeMissingTable(encryptionContexts, `${LEGACY_ENCRYPTION_CONTEXT_TABLE} (legacy Column Level Encryption contexts) does not exist on this instance`),
    cryptoModules,
    encryptedFields,
    auditDictionary,
    recentAuditCount,
    recentTransactionCount,
    updateSetsInProgress,
    updateSetTotal,
    sensitiveUpdateXml,
    midServers,
    properties,
    plugins,
  };
}

function pluginActive(row: JsonRecord): boolean | undefined {
  const active = row.active;
  const parsed = asBoolean(active);
  if (parsed !== undefined) return parsed;
  const text = asString(active)?.toLowerCase();
  if (text === "active") return true;
  if (text === "inactive") return false;
  return undefined;
}

export function assessServicenowOperationsGovernanceData(data: ServicenowOperationsData): ServicenowAssessmentResult {
  const errors = [
    ...snapshotErrors("encryption contexts", data.encryptionContexts),
    ...snapshotErrors("cryptographic modules", data.cryptoModules),
    ...snapshotErrors("encrypted fields", data.encryptedFields),
    ...snapshotErrors("audit dictionary", data.auditDictionary),
    ...countErrors("recent audit rows", data.recentAuditCount),
    ...countErrors("recent transaction log rows", data.recentTransactionCount),
    ...snapshotErrors("update sets in progress", data.updateSetsInProgress),
    ...countErrors("update sets", data.updateSetTotal),
    ...snapshotErrors("sensitive update xml", data.sensitiveUpdateXml),
    ...snapshotErrors("mid servers", data.midServers),
    ...snapshotErrors("mid properties", data.properties),
    ...snapshotErrors("plugins", data.plugins),
  ];

  const encryption = gatedFinding(9, [data.encryptionContexts, data.cryptoModules, data.encryptedFields], `Open Key Management Framework > Cryptographic Modules (${CRYPTO_MODULE_TABLE}), System Security > Field Encryption > Encryption Contexts (legacy), and System Definition > Dictionary filtered on Type = Encrypted Text; confirm every field holding regulated data is encrypted, and record whether Column Level Encryption Enterprise, Cloud Encryption, or Edge Encryption is licensed.`, () => {
    const contexts = data.encryptionContexts.rows.map((row) => rowString(row, "name") ?? rowString(row, "sys_id") ?? "context");
    const modules = data.cryptoModules.rows.map((row) => rowString(row, "name") ?? rowString(row, "module_name") ?? rowString(row, "sys_id") ?? "module");
    const fields = data.encryptedFields.rows.map((row) => `${rowString(row, "name") ?? "table"}.${rowString(row, "element") ?? "field"}`);
    const evidence: JsonRecord = {
      crypto_modules: truncateList(modules),
      crypto_module_count: modules.length,
      legacy_encryption_contexts: truncateList(contexts),
      legacy_encryption_context_count: contexts.length,
      legacy_context_table_available: !data.encryptionContexts.unavailable,
      encrypted_fields: truncateList(fields),
      encrypted_field_count: fields.length,
    };
    if (contexts.length === 0 && modules.length === 0 && fields.length === 0) {
      return {
        status: "manual",
        summary: `No KMF cryptographic modules, legacy encryption contexts${data.encryptionContexts.unavailable ? ` (${LEGACY_ENCRYPTION_CONTEXT_TABLE} is not present)` : ""}, or encrypted dictionary fields exist; column-level encryption is not in use. Confirm whether sensitive fields require encryption and whether an encryption module (CLE Enterprise, Cloud Encryption, Edge Encryption) is licensed and scoped for this instance.`,
        evidence,
      };
    }
    return {
      status: "manual",
      summary: `${modules.length} KMF cryptographic modules, ${contexts.length} legacy encryption contexts, and ${fields.length} encrypted dictionary fields are configured; the API cannot determine whether every sensitive field is covered, so coverage must be confirmed against the data classification inventory.`,
      evidence,
    };
  });

  const audit = gatedFinding(10, [data.auditDictionary], `Open System Definition > Dictionary, filter Type = Collection, and confirm Audit is checked for ${AUDITED_CRITICAL_TABLES.join(", ")}; open System Archiving or Table Rotation to record the sys_audit retention period.`, () => {
    const rowsByTable = new Map(data.auditDictionary.rows.map((row) => [rowString(row, "name") ?? "", row]));
    const missing = AUDITED_CRITICAL_TABLES.filter((table) => !rowsByTable.has(table));
    const unaudited = AUDITED_CRITICAL_TABLES.filter((table) => rowsByTable.has(table) && rowBoolean(rowsByTable.get(table) ?? {}, "audit") !== true);
    const audited = AUDITED_CRITICAL_TABLES.filter((table) => rowBoolean(rowsByTable.get(table) ?? {}, "audit") === true);
    const evidence: JsonRecord = {
      audited_tables: audited,
      unaudited_tables: unaudited,
      dictionary_rows_missing: missing,
      audit_rows_last_7_days: data.recentAuditCount.count ?? null,
      audit_count_error: data.recentAuditCount.error ?? null,
      transaction_log_rows_last_day: data.recentTransactionCount.count ?? null,
      retention_verified_via_api: false,
    };
    if (unaudited.length > 0) {
      return {
        status: "fail",
        summary: `${unaudited.length} critical tables are not audited in sys_dictionary: ${unaudited.join(", ")}.`,
        evidence,
      };
    }
    if (missing.length > 0) {
      return {
        status: "manual",
        summary: `Collection dictionary rows for ${missing.join(", ")} were not visible, so their audit flags cannot be verified.`,
        evidence,
      };
    }
    if (data.recentAuditCount.count === 0) {
      return {
        status: "fail",
        summary: `All ${audited.length} critical tables are flagged for auditing, but sys_audit received zero rows in the last ${AUDIT_LOOKBACK_DAYS} days, so auditing does not appear to be producing records.`,
        evidence,
      };
    }
    return {
      status: "manual",
      summary: `All ${audited.length} critical tables are flagged for auditing${data.recentAuditCount.count !== undefined ? ` and sys_audit recorded ${data.recentAuditCount.count} rows in the last ${AUDIT_LOOKBACK_DAYS} days` : ", but the recent sys_audit count was unavailable"}; the audit retention period is not exposed through the Table API and must be confirmed in Table Rotation or System Archiving.`,
      evidence,
    };
  });

  const updateSets = gatedFinding(15, [data.updateSetsInProgress, data.sensitiveUpdateXml], "Open System Update Sets > Local Update Sets filtered on State = In progress and review Customer Updates for ACL, role, script, and property changes; confirm each has a change record.", () => {
    const inProgress = data.updateSetsInProgress.rows.map((row) => rowString(row, "name") ?? rowString(row, "sys_id") ?? "update set");
    const sensitive = data.sensitiveUpdateXml.rows.map((row) => `${rowString(row, "update_set.name") ?? rowString(row, "update_set") ?? "set"}: ${rowString(row, "type") ?? "type"} ${rowString(row, "target_name") ?? rowString(row, "name") ?? ""}`.trim());
    const proven = data.updateSetTotal.count;
    const evidence: JsonRecord = {
      update_set_total: proven ?? null,
      in_progress_update_sets: truncateList(inProgress),
      in_progress_count: inProgress.length,
      sensitive_pending_changes: truncateList(sensitive),
      sensitive_pending_change_count: sensitive.length,
    };
    if (data.updateSetTotal.error || proven === undefined || proven === 0) {
      return {
        status: "manual",
        summary: `The sys_update_set inventory could not be proven visible (aggregate count ${proven ?? "unavailable"}); the Default update set always exists, so an empty in-progress list cannot be trusted.`,
        evidence,
      };
    }
    if (visibilityUnproven(data.updateSetsInProgress)) {
      return {
        status: "manual",
        summary: `The in-progress update set query returned no rows and no X-Total-Count header, so the empty result cannot be distinguished from ACL-filtered rows even though sys_update_set holds ${proven} rows in aggregate.`,
        evidence: { ...evidence, x_total_count_present: false },
      };
    }
    if (sensitive.length > 0) {
      return {
        status: "warn",
        summary: `${inProgress.length} update sets are in progress and ${sensitive.length} pending customer updates touch ACLs, roles, scripts, or properties: ${truncateList(sensitive, 8).join("; ")}.`,
        evidence,
      };
    }
    if (inProgress.length > 0) {
      return {
        status: "warn",
        summary: `${inProgress.length} update sets are in progress (${truncateList(inProgress, 8).join(", ")}) with no pending ACL, role, script, or property changes visible; confirm each is tracked by change management.`,
        evidence,
      };
    }
    return {
      status: "pass",
      summary: `${proven} update sets exist and none is in progress, so no uncommitted security-sensitive changes are pending.`,
      evidence,
    };
  });

  const midServer = gatedFinding(19, [data.midServers, data.properties], "Open MID Server > Servers and record Validated, Status, Version, mutual authentication (client certificate) configuration, and the allowed host list in config.xml; record mid.version.override in System Properties.", () => {
    const servers = data.midServers.rows;
    const override = readProperty(data.properties, "mid.version.override");
    const notValidated = servers.filter((row) => rowBoolean(row, "validated") !== true).map((row) => rowString(row, "name") ?? "mid");
    const notUp = servers.filter((row) => !/^up$/i.test(rowString(row, "status") ?? "")).map((row) => rowString(row, "name") ?? "mid");
    const evidence: JsonRecord = {
      mid_servers: servers.length,
      not_validated: truncateList(notValidated),
      not_up: truncateList(notUp),
      versions: truncateList([...new Set(servers.map((row) => rowString(row, "version") ?? "unknown"))]),
      mid_version_override: override.exists ? override.value : null,
      mutual_auth_verified_via_api: false,
    };
    if (servers.length === 0) {
      return {
        status: "manual",
        summary: "Not applicable as observed: no MID Servers are registered in ecc_agent. Confirm that no MID Server is expected for this instance.",
        evidence,
      };
    }
    if (notValidated.length > 0) {
      return {
        status: "fail",
        summary: `${notValidated.length}/${servers.length} MID Servers are not validated: ${notValidated.join(", ")}.`,
        evidence,
      };
    }
    if (override.exists && override.value) {
      return {
        status: "warn",
        summary: `All ${servers.length} MID Servers are validated, but mid.version.override is ${override.value}, which pins the version and disables automatic upgrade; ${notUp.length} are not Up.`,
        evidence,
      };
    }
    return {
      status: "manual",
      summary: `All ${servers.length} MID Servers are validated${notUp.length > 0 ? ` (${notUp.length} not Up)` : ""} and automatic upgrade is not pinned; mutual authentication and the allowed host list are not exposed through the Table API and must be confirmed on each MID Server.`,
      evidence,
    };
  });

  const plugins = gatedFinding(20, [data.plugins], "Open System Definition > Plugins; confirm High Security Settings, Contextual Security: Role Management V2, and Security Jump Start are active, record Instance Security Center, Security Incident Response, GRC, and Vulnerability Response status, and review every other active plugin for necessity.", () => {
    const rows = data.plugins.rows;
    // A plugin absent from a partial sys_plugins read may sit among the unread rows, so its presence is unknown rather than false.
    const complete = tablesComplete([data.plugins]);
    const evaluate = (definition: { key: string; pattern: RegExp; label: string }) => {
      const match = rows.find((row) => definition.pattern.test(rowString(row, "name") ?? ""));
      return { key: definition.key, label: definition.label, present: match ? true : complete ? false : null, active: match ? pluginActive(match) ?? null : null };
    };
    const required = REQUIRED_SECURITY_PLUGINS.map(evaluate);
    const optional = OPTIONAL_SECURITY_PLUGINS.map(evaluate);
    const evidence: JsonRecord = {
      plugins_visible: rows.length,
      required_security_plugins: required,
      optional_security_plugins: optional,
      unnecessary_plugin_review_via_api: false,
    };
    if (rows.length === 0) {
      return {
        status: "manual",
        summary: "No plugin rows are visible in sys_plugins; every instance has hundreds of plugins, so the credential cannot read the inventory.",
        evidence,
      };
    }
    const inactiveRequired = required.filter((item) => item.active !== true);
    const observedInactive = inactiveRequired.filter((item) => item.present === true);
    if (observedInactive.length > 0) {
      return {
        status: "fail",
        summary: `${observedInactive.length} baseline security plugins are present but not active: ${observedInactive.map((item) => item.label).join(", ")}.`,
        evidence,
      };
    }
    if (inactiveRequired.length > 0 && !complete) {
      return {
        status: "manual",
        summary: `${inactiveRequired.length} baseline security plugins were not among the visible sys_plugins rows and that read was partial, so the unread rows could hold them; their status is unknown.`,
        evidence,
      };
    }
    if (inactiveRequired.length > 0) {
      return {
        status: "fail",
        summary: `${inactiveRequired.length} baseline security plugins are not active: ${inactiveRequired.map((item) => item.label).join(", ")}.`,
        evidence,
      };
    }
    return {
      status: "manual",
      summary: `${rows.length} plugins inventoried and all ${required.length} baseline security plugins are active; ${optional.filter((item) => item.active === true).length}/${optional.length} optional security products are active. Necessity of the remaining active plugins must be reviewed manually.`,
      evidence,
    };
  });

  const findings = sortFindings([encryption, audit, updateSets, midServer, plugins]);
  return {
    area: "operations_governance",
    title: "ServiceNow operations governance",
    summary: {
      encryption_contexts: derived(data.encryptionContexts.rows.length, data.encryptionContexts),
      crypto_modules: derived(data.cryptoModules.rows.length, data.cryptoModules),
      encrypted_fields: derived(data.encryptedFields.rows.length, data.encryptedFields),
      audit_rows_last_7_days: countValue(data.recentAuditCount),
      update_sets_in_progress: derived(data.updateSetsInProgress.rows.length, data.updateSetsInProgress),
      mid_servers: derived(data.midServers.rows.length, data.midServers),
      plugins_visible: visibleRows(data.plugins),
      inventories: {
        encryption_contexts: describeTable(data.encryptionContexts),
        crypto_modules: describeTable(data.cryptoModules),
        encrypted_fields: describeTable(data.encryptedFields),
        audit_dictionary: describeTable(data.auditDictionary),
        recent_audit_count: describeCount(data.recentAuditCount),
        recent_transaction_count: describeCount(data.recentTransactionCount),
        update_sets_in_progress: describeTable(data.updateSetsInProgress),
        update_set_total: describeCount(data.updateSetTotal),
        sensitive_update_xml: describeTable(data.sensitiveUpdateXml),
        mid_servers: describeTable(data.midServers),
        mid_properties: describeTable(data.properties),
        plugins: describeTable(data.plugins),
      },
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors,
  };
}

export async function assessServicenowOperationsGovernance(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords">,
  options: ServicenowOperationsOptions = {},
): Promise<ServicenowAssessmentResult> {
  return assessServicenowOperationsGovernanceData(await collectServicenowOperationsData(client, options));
}

const ACCESS_SURFACES: Array<{ name: string; table: string }> = [
  { name: "users", table: "sys_user" },
  { name: "user_roles", table: "sys_user_has_role" },
  { name: "roles", table: "sys_user_role" },
  { name: "role_inheritance", table: "sys_user_role_contains" },
  { name: "system_properties", table: "sys_properties" },
  { name: "acls", table: "sys_security_acl" },
  { name: "acl_roles", table: "sys_security_acl_role" },
  { name: "public_pages", table: "sys_public" },
  { name: "password_policies", table: "password_policy" },
  { name: "sso_providers", table: "sso_properties" },
  { name: "ldap_servers", table: "ldap_server_config" },
  { name: "certificates", table: "sys_certificate" },
  { name: "oauth_entities", table: "oauth_entity" },
  { name: "mfa_criteria", table: MFA_CRITERIA_TABLE },
  { name: "audit", table: "sys_audit" },
  { name: "transaction_logs", table: "syslog_transaction" },
  { name: "update_sets", table: "sys_update_set" },
  { name: "update_xml", table: "sys_update_xml" },
  { name: "user_sessions", table: "sys_user_session" },
  { name: "dictionary", table: "sys_dictionary" },
  { name: "encryption_contexts", table: LEGACY_ENCRYPTION_CONTEXT_TABLE },
  { name: "crypto_modules", table: CRYPTO_MODULE_TABLE },
  { name: "business_rules", table: "sys_script" },
  { name: "ip_access_rules", table: IP_ACCESS_TABLE },
  { name: "email_accounts", table: "sys_email_account" },
  { name: "mid_servers", table: "ecc_agent" },
  { name: "plugins", table: "sys_plugins" },
];

const CORE_ACCESS_SURFACES = new Set(["users", "user_roles", "roles", "system_properties", "acls", "acl_roles", "audit", "update_sets", "dictionary"]);

async function probeSurface(
  client: Pick<ServicenowReadClient, "queryTable" | "countRecords">,
  surface: { name: string; table: string },
): Promise<ServicenowAccessSurface> {
  const [snapshot, count] = await Promise.all([
    readTable(client, surface.table, { fields: ["sys_id"], limit: 1, pageSize: 1 }),
    client.countRecords(surface.table),
  ]);
  const total = count.count ?? snapshot.total;
  if (snapshot.error) {
    return {
      name: surface.name,
      table: surface.table,
      status: snapshot.statusCode === 401 || snapshot.statusCode === 403 ? "forbidden" : "not_readable",
      ...(total !== undefined ? { total } : {}),
      ...(snapshot.statusCode !== undefined ? { http_status: snapshot.statusCode } : {}),
      error: count.error ? `${snapshot.error}; aggregate count also failed (${count.error})` : snapshot.error,
    };
  }
  if (snapshot.rows.length === 0 && total !== undefined && total > 0) {
    return {
      name: surface.name,
      table: surface.table,
      status: "acl_filtered",
      visible: 0,
      total,
      error: `aggregate count ${total} but no rows returned; ACLs hide the rows`,
    };
  }
  return { name: surface.name, table: surface.table, status: "readable", visible: snapshot.rows.length, total };
}

export async function checkServicenowAccess(
  client: Pick<ServicenowReadClient, "getResolvedConfig" | "queryTable" | "countRecords">,
): Promise<ServicenowAccessCheckResult> {
  const config = client.getResolvedConfig();
  const whoami = await readTable(client, "sys_user", { query: "sys_id=javascript:gs.getUserID()", fields: ["user_name", "name"], limit: 1, pageSize: 1 });
  const identity = whoami.rows[0] ? rowString(whoami.rows[0], "user_name") ?? rowString(whoami.rows[0], "name") : undefined;
  const surfaces = await Promise.all(ACCESS_SURFACES.map((surface) => probeSurface(client, surface)));
  const readable = surfaces.filter((surface) => surface.status === "readable");
  const coreReadable = readable.filter((surface) => CORE_ACCESS_SURFACES.has(surface.name)).length;
  const status = coreReadable === CORE_ACCESS_SURFACES.size ? "healthy" : "limited";
  const degraded = surfaces.filter((surface) => surface.status !== "readable");

  return {
    status,
    instanceUrl: config.instanceUrl,
    authMode: config.authMode,
    identity,
    surfaces,
    notes: [
      `Instance ${config.instanceUrl} via ${config.authMode} auth${identity ? ` as ${identity}` : whoami.error ? ` (identity lookup failed: ${whoami.error})` : ""}.`,
      `${readable.length}/${surfaces.length} audit tables are readable; ${coreReadable}/${CORE_ACCESS_SURFACES.size} core tables are readable.`,
      ...(degraded.length > 0 ? [`Degraded: ${degraded.map((surface) => `${surface.table} (${surface.status})`).join(", ")}.`] : []),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run servicenow_assess_identity_access, servicenow_assess_platform_hardening, servicenow_assess_access_control, servicenow_assess_operations_governance, or servicenow_export_audit_bundle."
      : "Grant the audit account admin (read) or a scoped read role over the listed tables; forbidden or ACL-filtered tables render as manual findings.",
  };
}

function severityRank(severity: ServicenowSeverity): number {
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
      throw new Error(`Unhandled severity: ${String(exhaustive)}`);
    }
  }
}

function statusRank(status: ServicenowFindingStatus): number {
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
      throw new Error(`Unhandled status: ${String(exhaustive)}`);
    }
  }
}

function sortFindings(findings: ServicenowFinding[]): ServicenowFinding[] {
  return [...findings].sort((left, right) =>
    statusRank(left.status) - statusRank(right.status)
    || severityRank(left.severity) - severityRank(right.severity)
    || left.control - right.control);
}

export function summarizeFindingStatuses(findings: ServicenowFinding[]): Record<ServicenowFindingStatus, number> {
  const counts: Record<ServicenowFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function statusLabel(status: ServicenowFindingStatus): string {
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
      throw new Error(`Unhandled status: ${String(exhaustive)}`);
    }
  }
}

function formatAccessCheckText(result: ServicenowAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.table,
    surface.status,
    surface.visible === undefined ? "-" : String(surface.visible),
    surface.total === undefined ? "-" : String(surface.total),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `ServiceNow access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Table", "Status", "Visible", "Total", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ServicenowAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    statusLabel(item.status),
    item.title,
    item.summary.length > 160 ? `${item.summary.slice(0, 157)}...` : item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "object" && value !== null ? JSON.stringify(value) : String(value)}`)
    .join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection issues:", ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function markdownEscapePipes(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function buildExecutiveSummary(config: ServicenowResolvedConfig, identity: string | undefined, assessments: ServicenowAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeFindingStatuses(findings);
  const prioritized = sortFindings(findings).filter((item) => item.status !== "pass");
  return [
    "# ServiceNow Security Inspection: Executive Summary",
    "",
    `Instance: ${config.instanceUrl}`,
    `Authentication: ${config.authMode}${identity ? ` as ${identity}` : ""}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual controls (evidence required): ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    `- Collection issues: ${errors.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...prioritized.slice(0, 12).map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${statusLabel(item.status)}): ${item.summary}`),
    "",
    "## Manual Evidence To Collect",
    "",
    ...findings.filter((item) => item.status === "manual" && item.manualEvidence).map((item) => `- ${item.id}: ${item.manualEvidence}`),
    "",
  ].join("\n");
}

function mappingFor(item: ServicenowFinding, framework: ServicenowFramework): string {
  return SERVICENOW_CONTROLS[item.control]?.mappings[framework] ?? "n/a";
}

function buildUnifiedMatrix(findings: ServicenowFinding[]): string {
  const header = `| Control | Status | Severity | Title | ${FRAMEWORK_ORDER.join(" | ")} |`;
  const divider = `|${"---|".repeat(4 + FRAMEWORK_ORDER.length)}`;
  const rows = [...findings].sort((left, right) => left.control - right.control).map((item) =>
    `| ${item.id} | ${statusLabel(item.status)} | ${item.severity} | ${markdownEscapePipes(item.title)} | ${FRAMEWORK_ORDER.map((framework) => mappingFor(item, framework)).join(" | ")} |`);
  return ["# Unified Compliance Matrix", "", header, divider, ...rows, ""].join("\n");
}

function buildFrameworkReport(title: string, framework: ServicenowFramework, findings: ServicenowFinding[]): string {
  const rows = [...findings].sort((left, right) => left.control - right.control).map((item) =>
    `| ${mappingFor(item, framework)} | ${item.id} | ${statusLabel(item.status)} | ${markdownEscapePipes(item.title)} | ${markdownEscapePipes(item.summary)} |`);
  return [
    `# ${title}`,
    "",
    `Framework: ${framework}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    `| ${framework} Reference | Control | Status | Title | Summary |`,
    "|---|---|---|---|---|",
    ...rows,
    "",
    "Status semantics: PASS requires complete, readable evidence; WARN flags partial views or hygiene gaps; FAIL is a verified non-compliant setting; MANUAL means the evidence must be collected by a human.",
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# ServiceNow Evidence Bundle: Quick Reference",
    "",
    "Generated by grclanker's native ServiceNow tools. Credentials are never written into the bundle.",
    "",
    "## Layout",
    "",
    "- `core_data/`: projected Table API and Aggregate API snapshots (rows, X-Total-Count, pagination); a dataset that was denied, errored, unavailable, or never requested is written as `{ collected: false, status, endpoint, error }` instead of an empty row list, so `rows: []` always means a readable table with no matching rows",
    "- `analysis/findings.json`: normalized findings with framework mappings",
    "- `analysis/<area>.json`: per-area assessment results, an `inventories` map stating each table read as complete, partial, unread, unavailable, or not requested, and collection issues; counts derived from an unread or partial table render null",
    "- `analysis/summary.json`: status counts and run metadata",
    "- `compliance/executive_summary.md`: prioritized findings and manual evidence list",
    "- `compliance/unified_compliance_matrix.md`: all controls against all frameworks",
    "- `compliance/<framework>/`: one report per framework",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "## Status Semantics",
    "",
    "- PASS: complete, readable evidence shows the compliant configuration",
    "- WARN: compliant on the visible rows, but the view is partial, truncated, or hygiene issues remain",
    "- FAIL: a verified non-compliant configuration",
    "- MANUAL: forbidden, filtered, empty, or out-of-scope evidence; a human must collect it",
    "",
  ].join("\n");
}

export async function exportServicenowAuditBundle(
  client: Pick<ServicenowReadClient, "getResolvedConfig" | "getNow" | "queryTable" | "countRecords">,
  config: ServicenowResolvedConfig,
  outputRoot: string,
  options: ServicenowExportOptions = {},
): Promise<ServicenowAuditBundleResult> {
  const access = await checkServicenowAccess(client);
  const identityData = await collectServicenowIdentityData(client, options);
  const hardeningData = await collectServicenowHardeningData(client, options);
  const accessControlData = await collectServicenowAccessControlData(client, options);
  const operationsData = await collectServicenowOperationsData(client, options);
  const assessments = [
    assessServicenowIdentityAccessData(identityData),
    assessServicenowPlatformHardeningData(hardeningData),
    assessServicenowAccessControlData(accessControlData),
    assessServicenowOperationsGovernanceData(operationsData),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(config.instanceName)}-audit-bundle`);

  // Every table or aggregate dataset passes through tableCoreData or countCoreData, so a denied, errored,
  // unavailable, or skipped read is written as a not-collected marker rather than as an empty snapshot.
  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/sys_user.json", tableCoreData(identityData.users)],
    ["core_data/sys_user_has_role_privileged.json", tableCoreData(identityData.privilegedAssignments)],
    ["core_data/sys_user_role_contains.json", tableCoreData(identityData.roleInheritance)],
    ["core_data/sys_user_role_contains_count.json", countCoreData(identityData.roleInheritanceTotal)],
    ["core_data/sys_properties_identity.json", tableCoreData(identityData.properties)],
    ["core_data/password_policy.json", tableCoreData(identityData.passwordPolicies)],
    ["core_data/sso_properties.json", tableCoreData(identityData.ssoProviders)],
    ["core_data/ldap_server_config.json", tableCoreData(identityData.ldapServers)],
    ["core_data/sys_certificate.json", tableCoreData(identityData.certificates)],
    ["core_data/oauth_entity.json", tableCoreData(identityData.oauthEntities)],
    ["core_data/multi_factor_criteria.json", tableCoreData(identityData.mfaCriteria)],
    ["core_data/sys_properties_hardening.json", tableCoreData(hardeningData.properties)],
    ["core_data/sys_properties_debug.json", tableCoreData(hardeningData.debugProperties)],
    ["core_data/sys_script_eval.json", tableCoreData(hardeningData.evalScripts)],
    ["core_data/ip_access.json", tableCoreData(hardeningData.ipAccessRules)],
    ["core_data/sys_plugins_ip_authenticator.json", tableCoreData(hardeningData.ipAuthenticatorPlugin)],
    ["core_data/sys_email_account.json", tableCoreData(hardeningData.emailAccounts)],
    ["core_data/sys_security_acl.json", tableCoreData(accessControlData.acls)],
    ["core_data/sys_security_acl_role.json", tableCoreData(accessControlData.aclRoles)],
    ["core_data/sys_security_acl_count.json", countCoreData(accessControlData.aclTotal)],
    ["core_data/sys_public.json", tableCoreData(accessControlData.publicPages)],
    ["core_data/sys_encryption_context.json", tableCoreData(operationsData.encryptionContexts)],
    ["core_data/sys_kmf_crypto_module.json", tableCoreData(operationsData.cryptoModules)],
    ["core_data/sys_dictionary_encrypted.json", tableCoreData(operationsData.encryptedFields)],
    ["core_data/sys_dictionary_audit.json", tableCoreData(operationsData.auditDictionary)],
    ["core_data/sys_audit_count.json", countCoreData(operationsData.recentAuditCount)],
    ["core_data/syslog_transaction_count.json", countCoreData(operationsData.recentTransactionCount)],
    ["core_data/sys_update_set_in_progress.json", tableCoreData(operationsData.updateSetsInProgress)],
    ["core_data/sys_update_set_count.json", countCoreData(operationsData.updateSetTotal)],
    ["core_data/sys_update_xml_sensitive.json", tableCoreData(operationsData.sensitiveUpdateXml)],
    ["core_data/ecc_agent.json", tableCoreData(operationsData.midServers)],
    ["core_data/sys_properties_mid.json", tableCoreData(operationsData.properties)],
    ["core_data/sys_plugins.json", tableCoreData(operationsData.plugins)],
  ];
  for (const [pathname, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathname, serializeJson(value));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    generated_at: new Date().toISOString(),
    instance_url: config.instanceUrl,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    status_counts: summarizeFindingStatuses(findings),
    errors,
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, access.identity, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, report.path, buildFrameworkReport(report.title, report.framework, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    instance_url: config.instanceUrl,
    instance_name: config.instanceName,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
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
    instance: asString(value.instance),
    instance_url: asString(value.instance_url) ?? asString(value.url),
    auth_method: asString(value.auth_method),
    username: asString(value.username),
    password: asString(value.password),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    access_token: asString(value.access_token),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
    max_retries: asNumber(value.max_retries),
    page_size: asNumber(value.page_size),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    inactive_days: asNumber(value.inactive_days),
    min_password_length: asNumber(value.min_password_length),
    cert_expiry_warn_days: asNumber(value.cert_expiry_warn_days),
    max_admins: asNumber(value.max_admins),
    record_limit: asNumber(value.record_limit),
  };
}

function normalizeHardeningArgs(args: unknown): HardeningArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    max_session_timeout_minutes: asNumber(value.max_session_timeout_minutes),
    record_limit: asNumber(value.record_limit),
  };
}

function normalizeLimitArgs(args: unknown): LimitArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    record_limit: asNumber(value.record_limit),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeHardeningArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function identityOptions(args: IdentityArgs): ServicenowIdentityOptions {
  return {
    inactiveDays: args.inactive_days,
    minPasswordLength: args.min_password_length,
    certExpiryWarnDays: args.cert_expiry_warn_days,
    maxAdmins: args.max_admins,
    recordLimit: args.record_limit,
  };
}

function hardeningOptions(args: HardeningArgs): ServicenowHardeningOptions {
  return {
    maxSessionTimeoutMinutes: args.max_session_timeout_minutes,
    recordLimit: args.record_limit,
  };
}

function createClient(args: AuthArgs): ServicenowApiClient {
  return new ServicenowApiClient(resolveServicenowConfiguration(args as JsonRecord));
}

const authParams = {
  instance: Type.Optional(Type.String({ description: "ServiceNow instance name (for https://<instance>.service-now.com). Defaults to SERVICENOW_INSTANCE." })),
  instance_url: Type.Optional(Type.String({ description: "Full instance URL. Defaults to SERVICENOW_URL, or is derived from the instance name." })),
  auth_method: Type.Optional(Type.String({ description: "basic, oauth, or mtls. Defaults to SERVICENOW_AUTH_METHOD or is inferred from the credentials provided." })),
  username: Type.Optional(Type.String({ description: "Audit account user name for basic auth or the OAuth password grant. Defaults to SERVICENOW_USERNAME." })),
  password: Type.Optional(Type.String({ description: "Audit account password. Defaults to SERVICENOW_PASSWORD." })),
  client_id: Type.Optional(Type.String({ description: "OAuth application registry client ID. Defaults to SERVICENOW_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "OAuth application registry client secret. Defaults to SERVICENOW_CLIENT_SECRET." })),
  access_token: Type.Optional(Type.String({ description: "Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN." })),
  config_file: Type.Optional(Type.String({ description: "YAML config file. Defaults to SERVICENOW_CONFIG_FILE, ./.servicenow.yaml, or ~/.servicenow-sec-inspector/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  max_retries: Type.Optional(Type.Number({ description: "Retries for 429 and 5xx responses. Defaults to 3.", default: 3 })),
  page_size: Type.Optional(Type.Number({ description: "Table API page size (sysparm_limit). Defaults to 500.", default: 500 })),
};

const recordLimitParam = {
  record_limit: Type.Optional(Type.Number({ description: "Maximum rows to page through per table before recording truncation. Defaults to 10000.", default: 10000 })),
};

const identityParams = {
  ...authParams,
  ...recordLimitParam,
  inactive_days: Type.Optional(Type.Number({ description: "Days without login before a user counts as inactive. Defaults to 90.", default: 90 })),
  min_password_length: Type.Optional(Type.Number({ description: "Minimum acceptable password length. Defaults to 12.", default: 12 })),
  cert_expiry_warn_days: Type.Optional(Type.Number({ description: "Warn when a certificate expires within this many days. Defaults to 30.", default: 30 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin or security_admin users before failing. Defaults to 10.", default: 10 })),
};

const hardeningParams = {
  ...authParams,
  ...recordLimitParam,
  max_session_timeout_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable glide.ui.session_timeout in minutes. Defaults to 60 (ServiceNow hardening guidance); the spec suggests 30.", default: 60 })),
};

function runTool<TArgs extends AuthArgs>(
  toolName: string,
  failurePrefix: string,
  handler: (args: TArgs) => Promise<{ text: string; details: JsonRecord }>,
) {
  return async (_toolCallId: string, args: TArgs) => {
    try {
      const result = await handler(args);
      return textResult(result.text, { tool: toolName, ...result.details });
    } catch (error) {
      return errorResult(`${failurePrefix}: ${errorMessage(error)}`, { tool: toolName });
    }
  };
}

export function registerServicenowTools(pi: any): void {
  pi.registerTool({
    name: "servicenow_check_access",
    label: "Check ServiceNow audit access",
    description:
      "Validate read-only ServiceNow Table API and Aggregate API access across the users, roles, ACL, property, SSO, audit, update set, session, OAuth, dictionary, encryption, MID Server, and plugin tables, reporting forbidden and ACL-filtered tables.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    execute: runTool<AuthArgs>("servicenow_check_access", "ServiceNow access check failed", async (args) => {
      const result = await checkServicenowAccess(createClient(args));
      return { text: formatAccessCheckText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "servicenow_assess_identity_access",
    label: "Assess ServiceNow identity and access",
    description:
      "Assess ServiceNow role hierarchy (control 3), user access review (4), password policy (6), MFA enforcement (7), LDAP and SSO integration (8), and integration user permissions (14) with evidence-gated verdicts.",
    parameters: Type.Object(identityParams),
    prepareArguments: normalizeIdentityArgs,
    execute: runTool<IdentityArgs>("servicenow_assess_identity_access", "ServiceNow identity assessment failed", async (args) => {
      const result = await assessServicenowIdentityAccess(createClient(args), identityOptions(args));
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "servicenow_assess_platform_hardening",
    label: "Assess ServiceNow platform hardening",
    description:
      "Assess ServiceNow instance security properties (control 1), session timeout (5), script execution restrictions (12), instance hardening (13), debug mode (16), IP access restrictions (17), and email security (18) from sys_properties and related tables.",
    parameters: Type.Object(hardeningParams),
    prepareArguments: normalizeHardeningArgs,
    execute: runTool<HardeningArgs>("servicenow_assess_platform_hardening", "ServiceNow platform hardening assessment failed", async (args) => {
      const result = await assessServicenowPlatformHardening(createClient(args), hardeningOptions(args));
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "servicenow_assess_access_control",
    label: "Assess ServiceNow access control rules",
    description:
      "Assess ServiceNow ACL rule completeness including wildcard, unrestricted, and public page exposure (control 2) and table-level ACL coverage for sensitive tables (11).",
    parameters: Type.Object({ ...authParams, ...recordLimitParam }),
    prepareArguments: normalizeLimitArgs,
    execute: runTool<LimitArgs>("servicenow_assess_access_control", "ServiceNow access control assessment failed", async (args) => {
      const result = await assessServicenowAccessControl(createClient(args), { recordLimit: args.record_limit });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "servicenow_assess_operations_governance",
    label: "Assess ServiceNow operations governance",
    description:
      "Assess ServiceNow encryption at rest (control 9), audit logging configuration (10), update set management (15), MID Server security (19), and plugin inventory (20); controls whose evidence is not exposed through the API render as manual with the evidence a human must collect.",
    parameters: Type.Object({ ...authParams, ...recordLimitParam }),
    prepareArguments: normalizeLimitArgs,
    execute: runTool<LimitArgs>("servicenow_assess_operations_governance", "ServiceNow operations governance assessment failed", async (args) => {
      const result = await assessServicenowOperationsGovernance(createClient(args), { recordLimit: args.record_limit });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "servicenow_export_audit_bundle",
    label: "Export ServiceNow audit bundle",
    description:
      "Export a ServiceNow evidence bundle with raw table snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a paired zip archive.",
    parameters: Type.Object({
      ...identityParams,
      max_session_timeout_minutes: hardeningParams.max_session_timeout_minutes,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    execute: runTool<ExportArgs>("servicenow_export_audit_bundle", "ServiceNow audit bundle export failed", async (args) => {
      const config = resolveServicenowConfiguration(args as JsonRecord);
      const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
      const result = await exportServicenowAuditBundle(new ServicenowApiClient(config), config, outputRoot, {
        ...identityOptions(args),
        ...hardeningOptions(args),
      });
      return {
        text: [
          "ServiceNow audit bundle exported.",
          `Output dir: ${result.outputDir}`,
          `Zip archive: ${result.zipPath}`,
          `Findings: ${result.findingCount}`,
          `Files: ${result.fileCount}`,
          `Collection issues: ${result.errorCount}`,
        ].join("\n"),
        details: {
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          finding_count: result.findingCount,
          file_count: result.fileCount,
          error_count: result.errorCount,
        },
      };
    }),
  });
}
