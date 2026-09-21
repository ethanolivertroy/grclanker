/**
 * Google Workspace GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the official Admin SDK
 * Directory API, Reports API, Alert Center API, and Cloud Identity Policy API
 * discovery documents. Every request stays read-only and every verdict follows
 * the verdict-safety rules documented in the integration guide: unreadable or
 * empty inventories never pass, partial views are flagged, pagination runs to
 * completion or records truncation, and re-running an export never overwrites
 * an earlier bundle.
 *
 * Endpoint references (all public, unauthenticated):
 * - users.list: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list
 * - roles.list: https://developers.google.com/workspace/admin/directory/reference/rest/v1/roles/list
 * - roleAssignments.list: https://developers.google.com/workspace/admin/directory/reference/rest/v1/roleAssignments/list
 * - tokens.list: https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list
 * - activities.list: https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
 * - alerts.list: https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list
 * - policies.list: https://cloud.google.com/identity/docs/reference/rest/v1/policies/list
 * - Policy API settings catalog: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
import { createPrivateKey, sign as signData } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type GwsAuthMode = "service_account" | "access_token";
type GwsFindingStatus = "Pass" | "Partial" | "Fail" | "Manual" | "Info";
type GwsSeverity = "critical" | "high" | "medium" | "low" | "info";
type FrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap"
  | "general";
type ReportFrameworkKey = Exclude<FrameworkKey, "general">;

const DEFAULT_OUTPUT_DIR = "./export/gws";
const DEFAULT_LOOKBACK_DAYS = 30;
/** users.list maxResults maximum is 500 (Directory API reference). */
const USERS_PAGE_SIZE = 500;
/** roles.list maxResults maximum is 100 (Directory API reference). */
const ROLES_PAGE_SIZE = 100;
/** roleAssignments.list maxResults maximum is 200 (Directory API reference). */
const ROLE_ASSIGNMENTS_PAGE_SIZE = 200;
/** activities.list maxResults maximum is 1000 (Reports API reference). */
const ACTIVITY_PAGE_SIZE = 1000;
/** alerts.list pageSize has no documented maximum; the server may return fewer. */
const ALERTS_PAGE_SIZE = 100;
/** policies.list pageSize maximum is 100 (Cloud Identity reference). */
const POLICIES_PAGE_SIZE = 100;
const MAX_USERS = 5000;
const MAX_ROLES = 1000;
const MAX_ROLE_ASSIGNMENTS = 10000;
const MAX_ACTIVITY_RECORDS = 5000;
const MAX_ALERTS = 1000;
const MAX_POLICIES = 1000;
/** A cursor that keeps advancing past this many pages is recorded as truncation rather than followed forever. */
const MAX_PAGES = 1000;
const MAX_TOKEN_USERS = 50;
const MAX_RETRIES = 4;
const TOKEN_SKEW_MS = 60 * 1000;
const DORMANT_DAYS = 90;
/** Every field below is documented on the Directory API User resource. */
const USERS_FIELDS = [
  "users(id,primaryEmail,isAdmin,isDelegatedAdmin,suspended,archived,lastLoginTime,isEnrolledIn2Sv,isEnforcedIn2Sv,orgUnitPath)",
  "nextPageToken",
].join(",");
const GWS_READ_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
  "https://www.googleapis.com/auth/admin.directory.user.security",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
  "https://www.googleapis.com/auth/apps.alerts",
];
/**
 * The Policy API scope is requested with its own token so tenants that have not
 * delegated it keep every other surface working; only GWS-ID-005 turns manual.
 */
const GWS_POLICY_SCOPES = ["https://www.googleapis.com/auth/cloud-identity.policies.readonly"];
/**
 * Setting types from the Policy API settings catalog
 * (https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings).
 */
const TWO_STEP_ENFORCEMENT_SETTING = "settings/security.two_step_verification_enforcement";
const TWO_STEP_ENROLLMENT_SETTING = "settings/security.two_step_verification_enrollment";
const TWO_STEP_FACTOR_SETTING = "settings/security.two_step_verification_enforcement_factor";
/**
 * policies.list filter syntax is documented on the method reference page; the
 * dot is escaped as \\. inside the CEL string literal exactly as the reference
 * example `setting.type.matches('^settings/gmail\\..*$')` does.
 */
const TWO_STEP_POLICY_FILTER_PATTERN = "^settings/security\\\\.two_step_verification.*$";
/**
 * Login audit event names from
 * https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login
 */
const SUSPICIOUS_LOGIN_NAMES = new Set([
  "suspicious_login",
  "suspicious_login_less_secure_app",
  "suspicious_programmatic_login",
  "gov_attack_warning",
  "risky_sensitive_action_blocked",
  "user_signed_out_due_to_suspicious_session_cookie",
  "account_disabled_hijacked",
  "account_disabled_password_leak",
]);
/** Alert metadata.status values documented on the Alert Center Alert resource. */
const CLOSED_ALERT_STATUS = "closed";
const HIGH_RISK_SCOPE_PATTERN = /(admin|gmail|drive|cloud-platform|apps\.groups|directory|classroom|vault|spreadsheets|docs)/i;
/**
 * Matched against key names normalized to lowercase alphanumerics, so privateKey,
 * private_key, and PRIVATE-KEY all match. Bare "token" is excluded on purpose:
 * nextPageToken and the token inventory wrapper are not secrets.
 */
const SECRET_KEY_PATTERN = /(password|passwd|secret|privatekey|accesstoken|refreshtoken|idtoken|oauthtoken|bearertoken|authtoken|sessiontoken|apikey|hashfunction|credential)/;
/** Reports API event parameters carry their value under one of these documented keys next to `name`. */
const PAIR_VALUE_KEYS = ["value", "multiValue", "intValue", "multiIntValue", "boolValue", "messageValue", "multiMessageValue"] as const;
/** Every URL inside a string, whether the string is the URL or the URL sits mid-prose; stops at whitespace, quotes, and brackets. */
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
/**
 * Well-known credential shapes redacted wherever they appear in free text: RFC 6750 bearer credentials, Google
 * OAuth access (ya29.) and refresh (1//) tokens, Google API keys (AIza), OAuth client secrets (GOCSPX-), JWTs,
 * and PEM private key blocks. This is defense in depth behind projection and key-based redaction.
 */
const CREDENTIAL_SHAPE_PATTERNS: ReadonlyArray<{ pattern: RegExp; replacement: string }> = [
  { pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, replacement: "Bearer [REDACTED]" },
  { pattern: /\bya29\.[A-Za-z0-9._-]{8,}/g, replacement: "[REDACTED]" },
  { pattern: /\b1\/\/[A-Za-z0-9._-]{8,}/g, replacement: "[REDACTED]" },
  { pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, replacement: "[REDACTED]" },
  { pattern: /\bGOCSPX-[A-Za-z0-9_-]{8,}/g, replacement: "[REDACTED]" },
  { pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, replacement: "[REDACTED]" },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[^"]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: "[REDACTED]" },
];
/** `key=value`, `key: value`, and `"key": "value"` pairs inside free text such as error messages, display names, and rendered JSON. */
const TEXT_PAIR_PATTERN = /([A-Za-z_][A-Za-z0-9_.-]*)"?\s*[=:]\s*"?([A-Za-z0-9._~+/=-]{8,})/g;
/** A free-text pair whose normalized key ends in one of these names carries a credential; page tokens are cursors, not secrets. */
const TEXT_SECRET_KEY_PATTERN = /(token|secret|password|passwd|credential|credentials|apikey|authorization|assertion)$/;
/** Google API error identifiers (google.rpc.Code names, errors[].reason, ErrorInfo.reason, RFC 6749 error codes) are short identifiers. */
const ERROR_IDENTIFIER_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
/** Directory API User fields requested through USERS_FIELDS; nothing else is written to core_data. */
const USER_SNAPSHOT_FIELDS = ["id", "primaryEmail", "isAdmin", "isDelegatedAdmin", "suspended", "archived", "lastLoginTime", "isEnrolledIn2Sv", "isEnforcedIn2Sv", "orgUnitPath"] as const;
/** Directory API Role resource (https://developers.google.com/workspace/admin/directory/reference/rest/v1/roles). */
const ROLE_SNAPSHOT_FIELDS = ["roleId", "roleName", "isSystemRole", "isSuperAdminRole"] as const;
const ROLE_PRIVILEGE_SNAPSHOT_FIELDS = ["privilegeName", "serviceId"] as const;
/** Directory API RoleAssignment resource (https://developers.google.com/workspace/admin/directory/reference/rest/v1/roleAssignments). */
const ROLE_ASSIGNMENT_SNAPSHOT_FIELDS = ["roleAssignmentId", "roleId", "assignedTo", "assigneeType", "scopeType", "orgUnitId"] as const;
/** Directory API Token resource (https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens); scopes is handled separately. */
const TOKEN_SNAPSHOT_FIELDS = ["clientId", "displayText", "anonymous", "nativeApp", "userKey"] as const;
/**
 * Reports API Activity resource (https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list).
 * events[].parameters[] is not stored: no finding reads it and its {name, value} pairs carry arbitrary values.
 */
const ACTIVITY_ID_SNAPSHOT_FIELDS = ["time", "uniqueQualifier", "applicationName", "customerId"] as const;
const ACTIVITY_ACTOR_SNAPSHOT_FIELDS = ["email", "profileId", "callerType"] as const;
const ACTIVITY_EVENT_SNAPSHOT_FIELDS = ["type", "name"] as const;
/**
 * Alert Center Alert resource (https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts).
 * The `data` payload is an arbitrary per-source blob and is never stored; verdicts read metadata.status only.
 */
const ALERT_SNAPSHOT_FIELDS = ["alertId", "customerId", "createTime", "startTime", "endTime", "updateTime", "type", "source", "deleted"] as const;
const ALERT_METADATA_SNAPSHOT_FIELDS = ["alertId", "customerId", "status", "assignee", "updateTime", "severity"] as const;
/** Cloud Identity Policy resource (https://cloud.google.com/identity/docs/reference/rest/v1/policies). */
const POLICY_SNAPSHOT_FIELDS = ["name", "customer", "type"] as const;
const POLICY_QUERY_SNAPSHOT_FIELDS = ["query", "orgUnit", "group", "sortOrder"] as const;
const POLICY_SETTING_VALUE_SNAPSHOT_FIELDS = ["enforcedFrom", "allowEnrollment", "allowedSignInFactorSet"] as const;
const FRAMEWORK_REPORTS: Record<ReportFrameworkKey, { title: string; file: string }> = {
  fedramp: { title: "FedRAMP / NIST 800-53 Compliance Report", file: "compliance/fedramp/fedramp_compliance_report.md" },
  cmmc: { title: "CMMC 2.0 / NIST 800-171 Compliance Report", file: "compliance/cmmc/cmmc_compliance_report.md" },
  soc2: { title: "SOC 2 Compliance Report", file: "compliance/soc2/soc2_compliance_report.md" },
  disa_stig: { title: "DISA STIG Compliance Checklist", file: "compliance/disa_stig/stig_compliance_checklist.md" },
  irap: { title: "IRAP / ISM Compliance Report", file: "compliance/irap/irap_compliance_report.md" },
  ismap: { title: "ISMAP / ISO 27001 Compliance Report", file: "compliance/ismap/ismap_compliance_report.md" },
  pci_dss: { title: "PCI-DSS 4.0.1 Compliance Report", file: "compliance/pci_dss/pci_dss_compliance_report.md" },
  cis: { title: "CIS Google Workspace Benchmark Report", file: "compliance/cis/cis_compliance_report.md" },
};
const REPORT_FRAMEWORK_KEYS = Object.keys(FRAMEWORK_REPORTS) as ReportFrameworkKey[];

type RawConfigArgs = {
  auth_mode?: string;
  credentials_file?: string;
  credentials_json?: string;
  access_token?: string;
  admin_email?: string;
  domain?: string;
  customer_id?: string;
  lookback_days?: number;
};

type GwsConfigOverlay = {
  authMode?: GwsAuthMode;
  credentialsFile?: string;
  credentialsJson?: string;
  accessToken?: string;
  adminEmail?: string;
  domain?: string;
  customerId?: string;
  lookbackDays?: number;
};

interface ServiceAccountCredentials {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

export interface GwsResolvedConfig {
  authMode: GwsAuthMode;
  credentialsFile?: string;
  accessToken?: string;
  adminEmail?: string;
  domain?: string;
  customerId: string;
  lookbackDays: number;
  serviceAccountEmail?: string;
  serviceAccountPrivateKey?: string;
  tokenUri: string;
  sourceChain: string[];
}

type GwsEndpointStatus = "ok" | "forbidden" | "unauthorized" | "error";

export interface GwsAccessProbe {
  key: string;
  path: string;
  status: GwsEndpointStatus;
  detail: string;
}

export interface GwsAccessCheckResult {
  organization: string;
  authMode: GwsAuthMode;
  status: "healthy" | "limited";
  sourceChain: string[];
  probes: GwsAccessProbe[];
  notes: string[];
  recommendedNextStep: string;
}

interface FrameworkMap {
  fedramp: string[];
  cmmc: string[];
  soc2: string[];
  cis: string[];
  pci_dss: string[];
  disa_stig: string[];
  irap: string[];
  ismap: string[];
  general: string[];
}

interface CheckDefinition {
  id: string;
  title: string;
  category: "identity" | "admin_access" | "integrations" | "monitoring";
  severity: GwsSeverity;
  frameworks: FrameworkMap;
}

export interface GwsFinding {
  id: string;
  title: string;
  category: CheckDefinition["category"];
  status: GwsFindingStatus;
  severity: GwsSeverity;
  summary: string;
  evidence: string[];
  recommendation: string;
  manualNote?: string;
  frameworks: FrameworkMap;
}

export interface GwsAssessmentResult {
  category: CheckDefinition["category"];
  findings: GwsFinding[];
  summary: Record<GwsFindingStatus, number>;
  snapshotSummary: Record<string, number | string>;
  text: string;
}

/** A fully paginated listing, or the seen portion when the cap was reached. */
export interface GwsCollection<T = JsonRecord> {
  items: T[];
  truncated: boolean;
  pages: number;
}

export interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
  errorKind?: GwsEndpointStatus;
  truncated?: boolean;
  pages?: number;
  seen?: number;
  total?: number;
  failed?: number;
}

interface TokenInventoryRecord {
  userId: string;
  primaryEmail: string;
  token: JsonRecord;
}

export interface GwsIdentityData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  loginActivities: CollectedDataset<JsonRecord[]>;
  twoStepPolicies?: CollectedDataset<JsonRecord[]>;
}

export interface GwsAdminAccessData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  adminActivities: CollectedDataset<JsonRecord[]>;
}

export interface GwsIntegrationData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  tokenInventory: CollectedDataset<TokenInventoryRecord[]>;
  tokenActivities: CollectedDataset<JsonRecord[]>;
}

export interface GwsMonitoringData {
  loginActivities: CollectedDataset<JsonRecord[]>;
  adminActivities: CollectedDataset<JsonRecord[]>;
  tokenActivities: CollectedDataset<JsonRecord[]>;
  alerts: CollectedDataset<JsonRecord[]>;
}

export interface GwsAuditData {
  identity: GwsIdentityData;
  adminAccess: GwsAdminAccessData;
  integrations: GwsIntegrationData;
  monitoring: GwsMonitoringData;
}

export interface GwsAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
  frameworks: ReportFrameworkKey[];
}

export interface GwsAuditCollector {
  collectUsers(): Promise<GwsCollection>;
  collectRoles(): Promise<GwsCollection>;
  collectRoleAssignments(): Promise<GwsCollection>;
  collectActivities(applicationName: "login" | "admin" | "token"): Promise<GwsCollection>;
  collectAlerts(): Promise<GwsCollection>;
  collectTwoStepPolicies(): Promise<GwsCollection>;
  listUserTokens(userKey: string): Promise<JsonRecord[]>;
}

type FetchImpl = typeof fetch;

type GwsTokenCacheEntry = {
  token?: string;
  expiresAt?: number;
  pending?: Promise<string>;
};

const tokenCache = new Map<string, GwsTokenCacheEntry>();

export class GwsApiError extends Error {
  status: number;
  url: string;

  constructor(status: number, message: string, url: string) {
    super(message);
    this.name = "GwsApiError";
    this.status = status;
    this.url = url;
  }
}

const GWS_ACCESS_PROBES = [
  {
    key: "users",
    scopes: GWS_READ_SCOPES,
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl("/admin/directory/v1/users", {
        customer: config.customerId,
        maxResults: 1,
        fields: USERS_FIELDS,
      }),
  },
  {
    key: "roles",
    scopes: GWS_READ_SCOPES,
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(config.customerId)}/roles`, {
        maxResults: 1,
      }),
  },
  {
    key: "role_assignments",
    scopes: GWS_READ_SCOPES,
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(config.customerId)}/roleassignments`, {
        maxResults: 1,
      }),
  },
  {
    key: "reports_login",
    scopes: GWS_READ_SCOPES,
    url: () =>
      buildAdminUrl("/admin/reports/v1/activity/users/all/applications/login", {
        maxResults: 1,
        startTime: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      }),
  },
  {
    key: "alert_center",
    scopes: GWS_READ_SCOPES,
    url: () => buildAlertsUrl("/v1beta1/alerts", { pageSize: 1 }),
  },
  {
    key: "policies",
    scopes: GWS_POLICY_SCOPES,
    url: (config: GwsResolvedConfig) =>
      buildCloudIdentityUrl("/v1/policies", {
        pageSize: 1,
        filter: buildTwoStepPolicyFilter(config.customerId),
      }),
  },
] as const;

const GWS_CHECKS: Record<string, CheckDefinition> = {
  "GWS-ID-001": {
    id: "GWS-ID-001",
    title: "Privileged users enforce 2-step verification",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-2(1)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["1.2"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["administrator MFA enforcement"],
    },
  },
  "GWS-ID-002": {
    id: "GWS-ID-002",
    title: "Broad 2-step verification coverage for active users",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["1.1"],
      pci_dss: ["8.4.1"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["user MFA coverage"],
    },
  },
  "GWS-ID-003": {
    id: "GWS-ID-003",
    title: "Dormant active accounts stay limited",
    category: "identity",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2", "AC-2(3)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["1.8"],
      pci_dss: ["7.2.4"],
      disa_stig: ["SRG-APP-000163"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["stale user review"],
    },
  },
  "GWS-ID-004": {
    id: "GWS-ID-004",
    title: "Super admins stay strongly protected",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6", "IA-2"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["1.3"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["super admin hardening"],
    },
  },
  "GWS-ID-005": {
    id: "GWS-ID-005",
    title: "2-step verification is enforced by organization policy",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-2(1)", "CM-6"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["1.1"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["tenant-wide MFA policy"],
    },
  },
  "GWS-ADMIN-001": {
    id: "GWS-ADMIN-001",
    title: "Super admin population stays constrained",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-5", "AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["2.1"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["least privilege for top-tier admins"],
    },
  },
  "GWS-ADMIN-002": {
    id: "GWS-ADMIN-002",
    title: "Suspended or archived privileged accounts are removed",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-2", "AC-2(3)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["2.4"],
      pci_dss: ["7.2.4"],
      disa_stig: ["SRG-APP-000163"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["privileged account lifecycle"],
    },
  },
  "GWS-ADMIN-003": {
    id: "GWS-ADMIN-003",
    title: "Delegated roles reduce Super Admin dependence",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-5", "AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.3"],
      cis: ["2.2"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["delegated administration"],
    },
  },
  "GWS-ADMIN-004": {
    id: "GWS-ADMIN-004",
    title: "Privileged activity stays observable",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-6"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.1"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-2"],
      general: ["admin audit visibility"],
    },
  },
  "GWS-ADMIN-005": {
    id: "GWS-ADMIN-005",
    title: "Group-based admin grants get explicit review",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2", "AC-6"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["2.3"],
      pci_dss: ["7.2.1"],
      disa_stig: ["SRG-APP-000038"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["group-based privileged access review"],
    },
  },
  "GWS-INTEG-001": {
    id: "GWS-INTEG-001",
    title: "Third-party token inventory is readable",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["CA-7", "CM-8"],
      cmmc: ["3.4.1"],
      soc2: ["CC7.1"],
      cis: ["4.1"],
      pci_dss: ["2.4"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1840"],
      ismap: ["CPS.CM-8"],
      general: ["OAuth application visibility"],
    },
  },
  "GWS-INTEG-002": {
    id: "GWS-INTEG-002",
    title: "Privileged users avoid excessive third-party token exposure",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6", "SA-9"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["4.2"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["privileged OAuth hygiene"],
    },
  },
  "GWS-INTEG-003": {
    id: "GWS-INTEG-003",
    title: "High-scope third-party apps stay limited",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-8", "SA-9"],
      cmmc: ["3.4.1"],
      soc2: ["CC7.1"],
      cis: ["4.3"],
      pci_dss: ["2.4"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1840"],
      ismap: ["CPS.CM-8"],
      general: ["high-scope OAuth sprawl"],
    },
  },
  "GWS-INTEG-004": {
    id: "GWS-INTEG-004",
    title: "Token activity telemetry stays available",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["4.4"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-6"],
      general: ["OAuth audit telemetry"],
    },
  },
  "GWS-MON-001": {
    id: "GWS-MON-001",
    title: "Alert Center is available for the tenant",
    category: "monitoring",
    severity: "high",
    frameworks: {
      fedramp: ["SI-4", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.1"],
      pci_dss: ["10.6.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.SI-4"],
      general: ["central alerting visibility"],
    },
  },
  "GWS-MON-002": {
    id: "GWS-MON-002",
    title: "Suspicious login backlog stays low",
    category: "monitoring",
    severity: "high",
    frameworks: {
      fedramp: ["SI-4", "IR-5"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.2"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.SI-4"],
      general: ["suspicious login response"],
    },
  },
  "GWS-MON-003": {
    id: "GWS-MON-003",
    title: "Admin audit telemetry stays available",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-6"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.3"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-2"],
      general: ["admin audit logging"],
    },
  },
  "GWS-MON-004": {
    id: "GWS-MON-004",
    title: "Token audit telemetry stays available",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.4"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-6"],
      general: ["token audit visibility"],
    },
  },
  "GWS-MON-005": {
    id: "GWS-MON-005",
    title: "Open alert backlog is manageable",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["IR-5", "SI-4"],
      cmmc: ["3.6.2"],
      soc2: ["CC7.4"],
      cis: ["5.5"],
      pci_dss: ["12.10.5"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.IR-5"],
      general: ["alert triage hygiene"],
    },
  },
};

export const GWS_CHECK_IDS = Object.keys(GWS_CHECKS);

function buildUrl(origin: string, pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = new URL(`${origin}${pathname}`);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value === undefined || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function buildAdminUrl(pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  return buildUrl("https://admin.googleapis.com", pathname, params);
}

function buildAlertsUrl(pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  return buildUrl("https://alertcenter.googleapis.com", pathname, params);
}

function buildCloudIdentityUrl(pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  return buildUrl("https://cloudidentity.googleapis.com", pathname, params);
}

/**
 * Filter clauses follow the policies.list reference: a customer clause plus a
 * setting.type.matches() regular expression, combined with &&.
 */
export function buildTwoStepPolicyFilter(customerId: string): string {
  return `customer == "customers/${customerId}" && setting.type.matches('${TWO_STEP_POLICY_FILTER_PATTERN}')`;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" ? value as JsonRecord : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeLower(value: unknown): string {
  return asString(value)?.toLowerCase() ?? "";
}

function normalizeString(value: unknown): string | undefined {
  return asString(value)?.trim();
}

function summarizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function base64Url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

function buildJwtAssertion(config: GwsResolvedConfig, scopes: string[]): string {
  if (!config.serviceAccountEmail || !config.serviceAccountPrivateKey || !config.adminEmail) {
    throw new Error("Service-account auth requires service account credentials plus admin_email.");
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: config.serviceAccountEmail,
    sub: config.adminEmail,
    scope: scopes.join(" "),
    aud: config.tokenUri,
    iat: now,
    exp: now + 3600,
  };

  const encodedHeader = base64Url(JSON.stringify(header));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const privateKey = createPrivateKey(config.serviceAccountPrivateKey);
  const signature = signData("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function tokenCacheKey(config: GwsResolvedConfig, scopes: string[]): string {
  return [
    config.authMode,
    config.serviceAccountEmail ?? "direct",
    config.adminEmail ?? "none",
    scopes.join(" "),
  ].join("::");
}

function errorIdentifier(value: unknown): string | undefined {
  const text = asString(value);
  return text !== undefined && ERROR_IDENTIFIER_PATTERN.test(text) ? text : undefined;
}

/**
 * Closed-vocabulary identifiers from an error body: `error.status` (a google.rpc.Code name), `error.errors[].reason`,
 * `error.details[].reason` (google.rpc.ErrorInfo), or the RFC 6749 `error` code of a token response
 * (https://cloud.google.com/apis/design/errors, https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
 * `error.message` and `error_description` are server-controlled free text and are never returned.
 */
export function describeErrorReasons(payload: JsonRecord): string[] {
  const reasons: string[] = [];
  const tokenErrorCode = errorIdentifier(payload.error);
  if (tokenErrorCode) reasons.push(`error ${tokenErrorCode}`);
  const error = asRecord(payload.error);
  const status = errorIdentifier(error.status);
  if (status) reasons.push(`status ${status}`);
  const reasonCodes = [...asArray(error.errors), ...asArray(error.details)]
    .map((entry) => errorIdentifier(asRecord(entry).reason))
    .filter((value): value is string => value !== undefined);
  for (const reason of Array.from(new Set(reasonCodes))) {
    reasons.push(`reason ${reason}`);
  }
  return reasons;
}

function classifyError(error: unknown): GwsEndpointStatus {
  if (error instanceof GwsApiError) {
    if (error.status === 403) return "forbidden";
    if (error.status === 401) return "unauthorized";
  }
  return "error";
}

async function collectDataset(collector: () => Promise<GwsCollection>): Promise<CollectedDataset<JsonRecord[]>> {
  try {
    const collection = await collector();
    return {
      data: collection.items,
      truncated: collection.truncated,
      pages: collection.pages,
      seen: collection.items.length,
    };
  } catch (error) {
    return { data: [], error: summarizeError(error), errorKind: classifyError(error), seen: 0 };
  }
}

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  worker: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(values.length);
  let index = 0;

  async function runWorker(): Promise<void> {
    while (true) {
      const current = index;
      index += 1;
      if (current >= values.length) return;
      results[current] = await worker(values[current], current);
    }
  }

  const workers = Array.from({ length: Math.max(1, Math.min(limit, values.length)) }, () => runWorker());
  await Promise.all(workers);
  return results;
}

function isSuperAdminRole(role: JsonRecord | undefined): boolean {
  if (!role) return false;
  if (asBoolean(role.isSuperAdminRole) === true) return true;
  return asArray(role.rolePrivileges).some((privilege) => safeLower(asRecord(privilege).privilegeName) === "super_admin");
}

/** RoleAssignment.assigneeType is documented as `USER` or `GROUP` (compared case-insensitively). */
function isGroupAssignment(assignment: JsonRecord): boolean {
  return safeLower(assignment.assigneeType) === "group";
}

function isUserAssignment(assignment: JsonRecord): boolean {
  return safeLower(assignment.assigneeType) === "user";
}

function getRoleMap(roles: JsonRecord[]): Map<string, JsonRecord> {
  return new Map(
    roles
      .map((role) => [asString(role.roleId), role] as const)
      .filter(([roleId]) => Boolean(roleId)) as Array<[string, JsonRecord]>,
  );
}

function getUserMap(users: JsonRecord[]): Map<string, JsonRecord> {
  return new Map(
    users
      .map((user) => [asString(user.id), user] as const)
      .filter(([userId]) => Boolean(userId)) as Array<[string, JsonRecord]>,
  );
}

function getDisplayOrganization(config: GwsResolvedConfig): string {
  return config.domain ?? config.customerId;
}

function countByStatus(findings: GwsFinding[]): Record<GwsFindingStatus, number> {
  return findings.reduce(
    (acc, finding) => {
      acc[finding.status] += 1;
      return acc;
    },
    { Pass: 0, Partial: 0, Fail: 0, Manual: 0, Info: 0 } as Record<GwsFindingStatus, number>,
  );
}

function buildFinding(
  definitionId: string,
  status: GwsFindingStatus,
  summary: string,
  evidence: string[],
  recommendation: string,
  manualNote?: string,
): GwsFinding {
  const definition = GWS_CHECKS[definitionId];
  if (!definition) throw new Error(`Unknown GWS check definition: ${definitionId}`);
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    status,
    severity: definition.severity,
    summary,
    evidence,
    recommendation,
    manualNote,
    frameworks: definition.frameworks,
  };
}

function isActiveUser(user: JsonRecord): boolean {
  return asBoolean(user.suspended) !== true && asBoolean(user.archived) !== true;
}

function describeCause(dataset: CollectedDataset<unknown>, scopeHint: string): string {
  switch (dataset.errorKind) {
    case "forbidden":
      return `HTTP 403 (missing scope ${scopeHint} in the domain-wide delegation, or the delegated account lacks the admin role for this surface)`;
    case "unauthorized":
      return "HTTP 401 (the bearer token was rejected)";
    case "error":
    case "ok":
    case undefined:
      return "request error";
    default: {
      const exhaustive: never = dataset.errorKind;
      return exhaustive;
    }
  }
}

function unreadableFinding(
  definitionId: string,
  endpoint: string,
  dataset: CollectedDataset<unknown>,
  scopeHint: string,
  evidenceToCollect: string,
): GwsFinding {
  return buildFinding(
    definitionId,
    "Manual",
    `${endpoint} was not readable, so this control could not be assessed: ${describeCause(dataset, scopeHint)}.`,
    [`${endpoint} error: ${dataset.error ?? "unknown"}`],
    `Grant ${scopeHint} to the audit principal and confirm the delegated admin role, then re-run the assessment.`,
    `Collect manually: ${evidenceToCollect}`,
  );
}

function partialViewEvidence(label: string, dataset: CollectedDataset<unknown[]>): string[] {
  if (!dataset.truncated) return [];
  return [
    `${label}: partial view, seen ${dataset.data.length} across ${dataset.pages ?? 0} page(s), more pages exist (total unknown; the listing stopped at the collection cap)`,
  ];
}

/** Privileged-user identification joins users, roles, and role assignments, so a truncated listing of any of them caps the verdict. */
function privilegedViewEvidence(data: Pick<GwsIdentityData, "users" | "roles" | "roleAssignments">): string[] {
  return [
    ...partialViewEvidence("Users", data.users),
    ...partialViewEvidence("Roles", data.roles),
    ...partialViewEvidence("Role assignments", data.roleAssignments),
  ];
}

function withPartialCap(finding: GwsFinding, notes: string[]): GwsFinding {
  if (notes.length === 0) return finding;
  const status: GwsFindingStatus = finding.status === "Pass" ? "Partial" : finding.status;
  return {
    ...finding,
    status,
    summary: finding.status === "Pass"
      ? `${finding.summary} The verdict is capped at Partial because the credential only saw a partial inventory.`
      : finding.summary,
    evidence: [...finding.evidence, ...notes],
  };
}

function findingTable(findings: GwsFinding[]): string {
  return formatTable(
    ["Check", "Status", "Severity", "Title"],
    findings.map((finding) => [finding.id, finding.status, finding.severity, finding.title]),
  );
}

function buildAssessmentText(
  categoryLabel: string,
  organization: string,
  findings: GwsFinding[],
  snapshotSummary: Record<string, number | string>,
): string {
  const summary = countByStatus(findings);
  return [
    `${categoryLabel} for ${organization}`,
    `Summary: Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}`,
    "",
    "Snapshot:",
    ...Object.entries(snapshotSummary).map(([key, value]) => `- ${key}: ${value}`),
    "",
    findingTable(findings),
    "",
    ...findings.map((finding) => [
      `${finding.id}: ${finding.summary}`,
      ...finding.evidence.map((line) => `  - ${line}`),
      `  Recommendation: ${finding.recommendation}`,
      finding.manualNote ? `  Manual note: ${finding.manualNote}` : "",
    ].filter(Boolean).join("\n")),
  ].join("\n");
}

function renderAssessmentToolResult(result: GwsAssessmentResult) {
  return textResult(result.text, {
    category: result.category,
    findings: result.findings,
    summary: result.summary,
    snapshot_summary: result.snapshotSummary,
  });
}

function probeTable(probes: GwsAccessProbe[]): string {
  return formatTable(
    ["Probe", "Status", "Detail"],
    probes.map((probe) => [probe.key, probe.status, probe.detail]),
  );
}

function renderAccessCheck(result: GwsAccessCheckResult) {
  return textResult(
    [
      `Google Workspace access check for ${result.organization}`,
      `Status: ${result.status}`,
      `Auth mode: ${result.authMode}`,
      "",
      probeTable(result.probes),
      "",
      "Notes:",
      ...result.notes.map((note) => `- ${note}`),
      "",
      `Next step: ${result.recommendedNextStep}`,
    ].join("\n"),
    {
      organization: result.organization,
      auth_mode: result.authMode,
      source_chain: result.sourceChain,
      probes: result.probes,
      status: result.status,
    },
  );
}

function buildExportText(config: GwsResolvedConfig, result: GwsAuditBundleResult): string {
  return [
    `Exported Google Workspace audit bundle for ${getDisplayOrganization(config)}.`,
    `Output directory: ${result.outputDir}`,
    `Zip archive: ${result.zipPath}`,
    `Files written: ${result.fileCount}`,
    `Findings recorded: ${result.findingCount}`,
    `Framework reports: ${result.frameworks.join(", ")}`,
    `Collection warnings: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
  ].join("\n");
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function normalizeKeyName(key: string): string {
  return key.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

function isSecretKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(normalizeKeyName(key));
}

/** Signed URLs and tokens hide in query strings, so every URL in the string, bare or embedded in prose, keeps only scheme, host, and path. */
function stripUrlQuery(value: string): string {
  return value.replace(EMBEDDED_URL_PATTERN, (url) => url.replace(/[?#].*$/, ""));
}

function isTextSecretKey(key: string): boolean {
  const normalized = normalizeKeyName(key);
  return TEXT_SECRET_KEY_PATTERN.test(normalized) && !normalized.endsWith("pagetoken");
}

/**
 * Scrubs free text before it reaches a bundle: URL query strings are removed, well-known credential shapes are
 * replaced, and `key=value` or `key: value` pairs whose key names a credential lose their value.
 */
export function scrubText(value: string): string {
  let output = stripUrlQuery(value);
  for (const { pattern, replacement } of CREDENTIAL_SHAPE_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output.replace(TEXT_PAIR_PATTERN, (match: string, key: string, secret: string) => (
    isTextSecretKey(key) ? `${match.slice(0, match.length - secret.length)}[REDACTED]` : match
  ));
}

function isSecretPair(record: JsonRecord): boolean {
  const pairName = asString(record.name) ?? asString(record.key);
  if (pairName === undefined || !isSecretKey(pairName)) return false;
  return PAIR_VALUE_KEYS.some((valueKey) => record[valueKey] !== undefined);
}

export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    const record = value as JsonRecord;
    const secretPair = isSecretPair(record);
    const output: JsonRecord = {};
    for (const [key, entry] of Object.entries(record)) {
      const redactPairValue = secretPair && (PAIR_VALUE_KEYS as readonly string[]).includes(key);
      output[key] = isSecretKey(key) || redactPairValue ? "[REDACTED]" : redactSecrets(entry);
    }
    return output;
  }
  if (typeof value === "string") return scrubText(value);
  return value;
}

/** Replaces every occurrence of a known secret value (for example a token from the environment) wherever it appears. */
export function redactKnownValues(value: unknown, secrets: string[]): unknown {
  const known = secrets.filter((secret) => secret.length >= 8);
  if (known.length === 0) return value;
  const scrub = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(scrub);
    if (input && typeof input === "object") {
      const output: JsonRecord = {};
      for (const [key, entry] of Object.entries(input as JsonRecord)) output[key] = scrub(entry);
      return output;
    }
    if (typeof input === "string") {
      return known.reduce((current, secret) => current.split(secret).join("[REDACTED]"), input);
    }
    return input;
  };
  return scrub(value);
}

function pickFields(record: JsonRecord, fields: readonly string[]): JsonRecord {
  const output: JsonRecord = {};
  for (const field of fields) {
    if (record[field] !== undefined) output[field] = record[field];
  }
  return output;
}

function projectUserSnapshot(user: JsonRecord): JsonRecord {
  return pickFields(user, USER_SNAPSHOT_FIELDS);
}

function projectRoleSnapshot(role: JsonRecord): JsonRecord {
  const output = pickFields(role, ROLE_SNAPSHOT_FIELDS);
  if (Array.isArray(role.rolePrivileges)) {
    output.rolePrivileges = role.rolePrivileges.map((privilege) => pickFields(asRecord(privilege), ROLE_PRIVILEGE_SNAPSHOT_FIELDS));
  }
  return output;
}

function projectRoleAssignmentSnapshot(assignment: JsonRecord): JsonRecord {
  return pickFields(assignment, ROLE_ASSIGNMENT_SNAPSHOT_FIELDS);
}

function projectTokenSnapshot(token: JsonRecord): JsonRecord {
  const output = pickFields(token, TOKEN_SNAPSHOT_FIELDS);
  if (Array.isArray(token.scopes)) {
    output.scopes = token.scopes.filter((scope) => typeof scope === "string");
  }
  return output;
}

function projectTokenInventorySnapshot(record: TokenInventoryRecord): JsonRecord {
  return {
    userId: record.userId,
    primaryEmail: record.primaryEmail,
    token: projectTokenSnapshot(record.token),
  };
}

export function projectActivitySnapshot(activity: JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  if (activity.id !== undefined) output.id = pickFields(asRecord(activity.id), ACTIVITY_ID_SNAPSHOT_FIELDS);
  if (activity.actor !== undefined) {
    const actor = asRecord(activity.actor);
    const actorOutput = pickFields(actor, ACTIVITY_ACTOR_SNAPSHOT_FIELDS);
    const applicationName = asString(asRecord(actor.applicationInfo).applicationName);
    if (applicationName) actorOutput.applicationInfo = { applicationName };
    output.actor = actorOutput;
  }
  if (activity.ipAddress !== undefined) output.ipAddress = activity.ipAddress;
  if (Array.isArray(activity.events)) {
    output.events = activity.events.map((event) => pickFields(asRecord(event), ACTIVITY_EVENT_SNAPSHOT_FIELDS));
  }
  return output;
}

export function projectAlertSnapshot(alert: JsonRecord): JsonRecord {
  const output = pickFields(alert, ALERT_SNAPSHOT_FIELDS);
  if (alert.metadata !== undefined) output.metadata = pickFields(asRecord(alert.metadata), ALERT_METADATA_SNAPSHOT_FIELDS);
  return output;
}

function projectPolicySnapshot(policy: JsonRecord): JsonRecord {
  const output = pickFields(policy, POLICY_SNAPSHOT_FIELDS);
  if (policy.policyQuery !== undefined) output.policyQuery = pickFields(asRecord(policy.policyQuery), POLICY_QUERY_SNAPSHOT_FIELDS);
  if (policy.setting !== undefined) {
    const setting = asRecord(policy.setting);
    const settingOutput: JsonRecord = {};
    if (setting.type !== undefined) settingOutput.type = setting.type;
    if (setting.value !== undefined) settingOutput.value = pickFields(asRecord(setting.value), POLICY_SETTING_VALUE_SNAPSHOT_FIELDS);
    output.setting = settingOutput;
  }
  return output;
}

function projectDataset<T>(dataset: CollectedDataset<T[]>, projector: (item: T) => JsonRecord): CollectedDataset<JsonRecord[]> {
  return { ...dataset, data: dataset.data.map(projector) };
}

function safeDirName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "gws-audit";
}

function frameworkMatrixRow(finding: GwsFinding): string {
  const mappings = Object.entries(finding.frameworks)
    .filter(([, values]) => values.length > 0)
    .map(([key, values]) => `${key}: ${values.join(", ")}`)
    .join(" | ");
  return `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${mappings} |`;
}

function buildFrameworkReport(title: string, findings: GwsFinding[], key: ReportFrameworkKey): string {
  const mapped = findings.filter((finding) => finding.frameworks[key].length > 0);
  const summary = countByStatus(mapped);
  return [
    `# ${title}`,
    "",
    `Findings mapped: ${mapped.length}. Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}.`,
    "",
    "| Check | Title | Status | Severity | Mapping | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
    ...mapped.map((finding) =>
      `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${finding.frameworks[key].join(", ")} | ${finding.summary.replace(/\|/g, "/")} |`),
    "",
    "Manual findings require human evidence before the mapped requirement can be asserted.",
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: GwsFinding[]): string {
  return [
    "# Unified Google Workspace Compliance Matrix",
    "",
    "| Check | Title | Status | Severity | Mappings |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map(frameworkMatrixRow),
    "",
  ].join("\n");
}

function buildQuickReference(frameworks: ReportFrameworkKey[]): string {
  return [
    "# Google Workspace Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains the raw Google Workspace API payloads collected for this assessment (secret-looking keys redacted).",
    "- `analysis/` contains `findings.json` plus one JSON summary per assessment category.",
    "- `compliance/` contains the executive summary, the unified matrix, and one report per framework.",
    "- `_errors.log` appears only when some reads failed but the bundle still completed.",
    "- Review Manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    `3. the framework report matching your engagement (${frameworks.join(", ")})`,
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
    "This bundle is read-only evidence collection. It does not write back to the tenant.",
    "",
  ].join("\n");
}

function collectErrors(...datasets: Array<[label: string, dataset: CollectedDataset<unknown>]>): string[] {
  return datasets
    .filter(([, dataset]) => Boolean(dataset.error))
    .map(([label, dataset]) => `${label}: ${dataset.error}`);
}

function parseDate(value: unknown): number | undefined {
  const stringValue = asString(value);
  if (!stringValue) return undefined;
  const timestamp = Date.parse(stringValue);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

interface DormancyBuckets {
  dormant: number;
  unknownLastLogin: number;
}

/**
 * Users without a parseable lastLoginTime are never counted as fresh; they go
 * into a separate bucket that caps the verdict at Partial.
 */
function bucketDormancy(users: JsonRecord[], cutoffMs: number): DormancyBuckets {
  let dormant = 0;
  let unknownLastLogin = 0;
  for (const user of users) {
    const lastLogin = parseDate(user.lastLoginTime);
    if (lastLogin === undefined) {
      unknownLastLogin += 1;
    } else if (lastLogin < cutoffMs) {
      dormant += 1;
    }
  }
  return { dormant, unknownLastLogin };
}

function extractActivityEventNames(activities: JsonRecord[]): string[] {
  const names: string[] = [];
  for (const activity of activities) {
    for (const event of asArray(activity.events)) {
      const name = asString(asRecord(event).name);
      if (name) names.push(name);
    }
  }
  return names;
}

function countMatchingEvents(activities: JsonRecord[], wanted: Set<string>): number {
  return extractActivityEventNames(activities).filter((name) => wanted.has(name)).length;
}

interface PrivilegedContext {
  privilegedUsers: JsonRecord[];
  superAdmins: JsonRecord[];
  delegatedAdmins: JsonRecord[];
  groupAssignmentCount: number;
  unresolvedAssignments: number;
}

function getPrivilegedUsers(
  users: JsonRecord[],
  roles: JsonRecord[],
  roleAssignments: JsonRecord[],
): PrivilegedContext {
  const userMap = getUserMap(users);
  const roleMap = getRoleMap(roles);
  const privilegedUserIds = new Set<string>();
  const superAdminUserIds = new Set<string>();
  let unresolvedAssignments = 0;

  for (const user of users) {
    const userId = asString(user.id);
    if (!userId) continue;
    if (asBoolean(user.isAdmin) === true || asBoolean(user.isDelegatedAdmin) === true) {
      privilegedUserIds.add(userId);
    }
    if (asBoolean(user.isAdmin) === true) {
      superAdminUserIds.add(userId);
    }
  }

  for (const assignment of roleAssignments) {
    if (!isUserAssignment(assignment)) continue;
    const userId = asString(assignment.assignedTo);
    if (!userId) continue;
    if (!userMap.has(userId)) unresolvedAssignments += 1;
    privilegedUserIds.add(userId);
    const role = roleMap.get(asString(assignment.roleId) ?? "");
    if (isSuperAdminRole(role)) {
      superAdminUserIds.add(userId);
    }
  }

  const privilegedUsers = Array.from(privilegedUserIds)
    .map((userId) => userMap.get(userId))
    .filter((user): user is JsonRecord => Boolean(user));
  const superAdmins = Array.from(superAdminUserIds)
    .map((userId) => userMap.get(userId))
    .filter((user): user is JsonRecord => Boolean(user));
  const delegatedAdmins = privilegedUsers.filter((user) => asBoolean(user.isAdmin) !== true);
  const groupAssignmentCount = roleAssignments.filter((assignment) => isGroupAssignment(assignment)).length;

  return {
    privilegedUsers,
    superAdmins,
    delegatedAdmins,
    groupAssignmentCount,
    unresolvedAssignments,
  };
}

function selectUsersForTokenInventory(
  users: JsonRecord[],
  privilegedUsers: JsonRecord[],
): JsonRecord[] {
  const activeUsers = users.filter(isActiveUser);
  const selected = new Map<string, JsonRecord>();
  for (const user of privilegedUsers) {
    const userId = asString(user.id);
    if (!userId) continue;
    selected.set(userId, user);
  }
  for (const user of activeUsers) {
    if (selected.size >= MAX_TOKEN_USERS) break;
    const userId = asString(user.id);
    if (!userId || selected.has(userId)) continue;
    selected.set(userId, user);
  }
  return Array.from(selected.values()).slice(0, MAX_TOKEN_USERS);
}

function countHighRiskTokens(records: TokenInventoryRecord[]): number {
  return records.filter((record) => {
    const scopes = asArray(record.token.scopes).map((scope) => asString(scope) ?? "");
    return scopes.some((scope) => HIGH_RISK_SCOPE_PATTERN.test(scope)) || scopes.length >= 6;
  }).length;
}

/** displayText is third-party-controlled free text, so it is scrubbed and paired with the documented clientId. */
function uniqueClientLabels(records: TokenInventoryRecord[]): string[] {
  return Array.from(
    new Set(
      records.map((record) => {
        const clientId = asString(record.token.clientId);
        const displayText = asString(record.token.displayText);
        if (displayText && clientId) return `${scrubText(displayText)} (${clientId})`;
        return scrubText(displayText ?? clientId ?? "unknown-client");
      }),
    ),
  );
}

interface AlertBuckets {
  open: number;
  closed: number;
  unknownStatus: number;
}

/** Alert status lives in metadata.status (NOT_STARTED, IN_PROGRESS, CLOSED). */
function bucketAlerts(alerts: JsonRecord[]): AlertBuckets {
  const buckets: AlertBuckets = { open: 0, closed: 0, unknownStatus: 0 };
  for (const alert of alerts) {
    const status = safeLower(asRecord(alert.metadata).status);
    if (!status) {
      buckets.unknownStatus += 1;
    } else if (status === CLOSED_ALERT_STATUS) {
      buckets.closed += 1;
    } else {
      buckets.open += 1;
    }
  }
  return buckets;
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
  const stat = lstatSync(realParent);
  if (stat.isSymbolicLink()) {
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

/** The credential values this run holds (direct bearer, service-account key, minted tokens), so any echo of them is scrubbed. */
function knownGwsSecretValues(config: GwsResolvedConfig): string[] {
  const values: Array<string | undefined> = [config.accessToken, config.serviceAccountPrivateKey];
  for (const entry of tokenCache.values()) {
    values.push(entry.token);
  }
  return values.filter((value): value is string => typeof value === "string" && value.length > 0);
}

/** Every bundle file passes through here, so no rendered text reaches disk without free-text scrubbing and known-value replacement. */
function scrubBundleText(content: string, knownSecrets: string[]): string {
  return redactKnownValues(scrubText(content), knownSecrets) as string;
}

async function writeBundleFile(rootDir: string, relativePathname: string, content: string, knownSecrets: string[]): Promise<void> {
  await writeSecureTextFile(rootDir, relativePathname, scrubBundleText(content, knownSecrets));
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
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    if (entry.isDirectory()) {
      count += await countFilesRecursively(fullPath);
    } else {
      count += 1;
    }
  }
  return count;
}

async function readServiceAccountFromFile(pathname: string): Promise<ServiceAccountCredentials> {
  const contents = readFileSync(pathname, "utf8");
  return parseServiceAccount(contents, pathname);
}

function parseServiceAccount(contents: string, label: string): ServiceAccountCredentials {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch (error) {
    throw new Error(`Failed to parse service account JSON from ${label}: ${summarizeError(error)}`);
  }
  const record = asRecord(parsed);
  const clientEmail = asString(record.client_email);
  const privateKey = asString(record.private_key);
  if (!clientEmail || !privateKey) {
    throw new Error(`Service account JSON from ${label} is missing client_email or private_key.`);
  }
  return {
    client_email: clientEmail,
    private_key: privateKey,
    token_uri: asString(record.token_uri),
  };
}

function normalizeAssessmentArgs(args: RawConfigArgs): RawConfigArgs {
  return {
    ...args,
    auth_mode: normalizeString(args.auth_mode),
    credentials_file: normalizeString(args.credentials_file),
    credentials_json: normalizeString(args.credentials_json),
    access_token: normalizeString(args.access_token),
    admin_email: normalizeString(args.admin_email),
    domain: normalizeString(args.domain),
    customer_id: normalizeString(args.customer_id),
  };
}

const normalizeExportArgs = normalizeAssessmentArgs;

export function normalizeFrameworkSelection(value: unknown): ReportFrameworkKey[] {
  const raw = Array.isArray(value)
    ? value.map((entry) => String(entry))
    : typeof value === "string"
      ? value.split(",")
      : [];
  const requested = raw.map((entry) => entry.trim().toLowerCase()).filter(Boolean);
  if (requested.length === 0) return [...REPORT_FRAMEWORK_KEYS];
  const selected: ReportFrameworkKey[] = [];
  for (const entry of requested) {
    if (!REPORT_FRAMEWORK_KEYS.includes(entry as ReportFrameworkKey)) {
      throw new Error(`Unknown framework "${entry}". Supported values: ${REPORT_FRAMEWORK_KEYS.join(", ")}.`);
    }
    if (!selected.includes(entry as ReportFrameworkKey)) selected.push(entry as ReportFrameworkKey);
  }
  return selected;
}

export async function resolveGwsConfiguration(
  args: RawConfigArgs = {},
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsResolvedConfig> {
  const sourceChain: string[] = [];
  const overlays: GwsConfigOverlay[] = [];

  const envOverlay: GwsConfigOverlay = {
    authMode: normalizeString(env.GWS_AUTH_MODE) as GwsAuthMode | undefined,
    credentialsFile: normalizeString(env.GWS_CREDENTIALS_FILE)
      ?? normalizeString(env.GWS_SERVICE_ACCOUNT_FILE)
      ?? normalizeString(env.GOOGLE_APPLICATION_CREDENTIALS),
    credentialsJson: normalizeString(env.GWS_CREDENTIALS_JSON)
      ?? normalizeString(env.GWS_SERVICE_ACCOUNT_JSON),
    accessToken: normalizeString(env.GWS_ACCESS_TOKEN),
    adminEmail: normalizeString(env.GWS_ADMIN_EMAIL),
    domain: normalizeString(env.GWS_DOMAIN),
    customerId: normalizeString(env.GWS_CUSTOMER_ID),
    lookbackDays: env.GWS_LOOKBACK_DAYS ? Number(env.GWS_LOOKBACK_DAYS) : undefined,
  };
  if (Object.values(envOverlay).some((value) => value !== undefined)) {
    overlays.push(envOverlay);
    sourceChain.push("environment");
  }

  const normalizedArgs = normalizeAssessmentArgs(args);
  const argsOverlay: GwsConfigOverlay = {
    authMode: normalizeString(normalizedArgs.auth_mode) as GwsAuthMode | undefined,
    credentialsFile: normalizedArgs.credentials_file,
    credentialsJson: normalizedArgs.credentials_json,
    accessToken: normalizedArgs.access_token,
    adminEmail: normalizedArgs.admin_email,
    domain: normalizedArgs.domain,
    customerId: normalizedArgs.customer_id,
    lookbackDays: normalizedArgs.lookback_days,
  };
  if (Object.values(argsOverlay).some((value) => value !== undefined)) {
    overlays.push(argsOverlay);
    sourceChain.push("arguments");
  }

  const merged = overlays.reduce<GwsConfigOverlay>((acc, overlay) => ({ ...acc, ...overlay }), {});
  const authMode = (merged.authMode
    ?? (merged.accessToken ? "access_token" : "service_account")) as GwsAuthMode;
  if (authMode !== "service_account" && authMode !== "access_token") {
    throw new Error(
      `Unsupported Google Workspace auth_mode "${String(merged.authMode)}". Supported values: service_account, access_token. Interactive installed-app OAuth is not shipped yet; obtain a token externally and use access_token.`,
    );
  }
  const customerId = merged.customerId ?? "my_customer";
  const lookbackDays = Number.isFinite(merged.lookbackDays)
    ? Math.max(1, Math.min(180, Number(merged.lookbackDays)))
    : DEFAULT_LOOKBACK_DAYS;

  let serviceAccount: ServiceAccountCredentials | undefined;
  if (authMode === "service_account") {
    if (merged.credentialsJson) {
      serviceAccount = parseServiceAccount(merged.credentialsJson, "credentials_json");
    } else if (merged.credentialsFile) {
      serviceAccount = await readServiceAccountFromFile(merged.credentialsFile);
    } else {
      throw new Error(
        "Google Workspace service-account auth requires credentials_json or credentials_file (or the matching environment variable).",
      );
    }
    if (!merged.adminEmail) {
      throw new Error("Google Workspace service-account auth requires admin_email for delegated access.");
    }
  }

  if (authMode === "access_token" && !merged.accessToken) {
    throw new Error("Google Workspace access_token auth requires access_token or GWS_ACCESS_TOKEN.");
  }

  return {
    authMode,
    credentialsFile: merged.credentialsFile,
    accessToken: merged.accessToken,
    adminEmail: merged.adminEmail,
    domain: merged.domain,
    customerId,
    lookbackDays,
    serviceAccountEmail: serviceAccount?.client_email,
    serviceAccountPrivateKey: serviceAccount?.private_key,
    tokenUri: serviceAccount?.token_uri ?? "https://oauth2.googleapis.com/token",
    sourceChain,
  };
}

export class GoogleWorkspaceAuditorClient implements GwsAuditCollector {
  constructor(
    private readonly config: GwsResolvedConfig,
    private readonly fetchImpl: FetchImpl = fetch,
  ) {}

  async fetchJson(url: string, scopes: string[] = GWS_READ_SCOPES): Promise<JsonRecord> {
    const response = await this.request(url, scopes);
    return asRecord(await response.json());
  }

  async probe(url: string, scopes: string[] = GWS_READ_SCOPES): Promise<GwsAccessProbe> {
    const pathname = new URL(url).pathname;
    try {
      const response = await this.request(url, scopes, { allowFailure: true });
      if (!response.ok) {
        return {
          key: basename(pathname) || pathname,
          path: pathname,
          status: response.status === 401 ? "unauthorized" : response.status === 403 ? "forbidden" : "error",
          detail: `${response.status} ${response.statusText}`,
        };
      }
      return {
        key: basename(pathname) || pathname,
        path: pathname,
        status: "ok",
        detail: `${response.status} ${response.statusText}`,
      };
    } catch (error) {
      return {
        key: basename(pathname) || pathname,
        path: pathname,
        status: "error",
        detail: summarizeError(error),
      };
    }
  }

  private async paginate(
    buildPageUrl: (pageToken: string | undefined, remaining: number) => string,
    itemsKey: string,
    maxItems: number,
    scopes: string[] = GWS_READ_SCOPES,
  ): Promise<GwsCollection> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    let pages = 0;
    while (true) {
      const payload = await this.fetchJson(buildPageUrl(pageToken, maxItems - items.length), scopes);
      pages += 1;
      items.push(...asArray(payload[itemsKey]).map(asRecord));
      const nextPageToken = asString(payload.nextPageToken);
      if (!nextPageToken) return { items, truncated: false, pages };
      const cursorStalled = nextPageToken === pageToken;
      if (items.length >= maxItems || cursorStalled || pages >= MAX_PAGES) {
        return { items: items.slice(0, maxItems), truncated: true, pages };
      }
      pageToken = nextPageToken;
    }
  }

  async collectUsers(): Promise<GwsCollection> {
    return this.paginate(
      (pageToken) => buildAdminUrl("/admin/directory/v1/users", {
        customer: this.config.customerId,
        maxResults: USERS_PAGE_SIZE,
        orderBy: "email",
        sortOrder: "ASCENDING",
        projection: "basic",
        showDeleted: "false",
        fields: USERS_FIELDS,
        pageToken,
      }),
      "users",
      MAX_USERS,
    );
  }

  async listUsers(): Promise<JsonRecord[]> {
    return (await this.collectUsers()).items;
  }

  async collectRoles(): Promise<GwsCollection> {
    return this.paginate(
      (pageToken) => buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(this.config.customerId)}/roles`, {
        maxResults: ROLES_PAGE_SIZE,
        pageToken,
      }),
      "items",
      MAX_ROLES,
    );
  }

  async listRoles(): Promise<JsonRecord[]> {
    return (await this.collectRoles()).items;
  }

  async collectRoleAssignments(): Promise<GwsCollection> {
    return this.paginate(
      (pageToken) => buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(this.config.customerId)}/roleassignments`, {
        maxResults: ROLE_ASSIGNMENTS_PAGE_SIZE,
        pageToken,
      }),
      "items",
      MAX_ROLE_ASSIGNMENTS,
    );
  }

  async listRoleAssignments(): Promise<JsonRecord[]> {
    return (await this.collectRoleAssignments()).items;
  }

  async collectActivities(applicationName: "login" | "admin" | "token"): Promise<GwsCollection> {
    const startTime = new Date(Date.now() - this.config.lookbackDays * 24 * 60 * 60 * 1000).toISOString();
    return this.paginate(
      (pageToken, remaining) => buildAdminUrl(`/admin/reports/v1/activity/users/all/applications/${applicationName}`, {
        startTime,
        maxResults: Math.max(1, Math.min(ACTIVITY_PAGE_SIZE, remaining)),
        pageToken,
      }),
      "items",
      MAX_ACTIVITY_RECORDS,
    );
  }

  async listActivities(applicationName: "login" | "admin" | "token"): Promise<JsonRecord[]> {
    return (await this.collectActivities(applicationName)).items;
  }

  async collectAlerts(): Promise<GwsCollection> {
    return this.paginate(
      (pageToken, remaining) => buildAlertsUrl("/v1beta1/alerts", {
        pageSize: Math.max(1, Math.min(ALERTS_PAGE_SIZE, remaining)),
        pageToken,
      }),
      "alerts",
      MAX_ALERTS,
    );
  }

  async listAlerts(): Promise<JsonRecord[]> {
    return (await this.collectAlerts()).items;
  }

  async collectTwoStepPolicies(): Promise<GwsCollection> {
    return this.paginate(
      (pageToken) => buildCloudIdentityUrl("/v1/policies", {
        pageSize: POLICIES_PAGE_SIZE,
        filter: buildTwoStepPolicyFilter(this.config.customerId),
        pageToken,
      }),
      "policies",
      MAX_POLICIES,
      GWS_POLICY_SCOPES,
    );
  }

  async listUserTokens(userKey: string): Promise<JsonRecord[]> {
    const payload = await this.fetchJson(
      buildAdminUrl(`/admin/directory/v1/users/${encodeURIComponent(userKey)}/tokens`),
    );
    return asArray(payload.items).map(asRecord);
  }

  private async request(
    url: string,
    scopes: string[],
    options: { allowFailure?: boolean; attempt?: number } = {},
  ): Promise<Response> {
    const attempt = options.attempt ?? 0;
    const token = await this.getAccessToken(scopes);
    const response = await this.fetchImpl(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
      },
    });

    if (response.ok || options.allowFailure) {
      return response;
    }

    if (response.status === 401 && attempt < MAX_RETRIES) {
      this.clearToken(scopes);
      return this.request(url, scopes, { ...options, attempt: attempt + 1 });
    }

    if ((response.status === 429 || response.status >= 500) && attempt < MAX_RETRIES) {
      await sleep(250 * 2 ** attempt);
      return this.request(url, scopes, { ...options, attempt: attempt + 1 });
    }

    throw new GwsApiError(response.status, await this.readError(response), url);
  }

  /** Renders the HTTP status plus documented identifiers only; the body's free-text message is never kept (see describeErrorReasons). */
  private async readError(response: Response): Promise<string> {
    const base = `${response.status} ${response.statusText}`.trim();
    let payload: JsonRecord;
    try {
      payload = asRecord(await response.json());
    } catch {
      return base;
    }
    const reasons = describeErrorReasons(payload);
    return reasons.length > 0 ? `${base} (${reasons.join(", ")})` : base;
  }

  private clearToken(scopes: string[]): void {
    tokenCache.delete(tokenCacheKey(this.config, scopes));
  }

  private async getAccessToken(scopes: string[]): Promise<string> {
    if (this.config.authMode === "access_token" && this.config.accessToken) {
      return this.config.accessToken;
    }

    const cacheKey = tokenCacheKey(this.config, scopes);
    const entry = tokenCache.get(cacheKey);
    const now = Date.now();
    if (entry?.token && entry.expiresAt && entry.expiresAt - TOKEN_SKEW_MS > now) {
      return entry.token;
    }
    if (entry?.pending) {
      return entry.pending;
    }

    const pending = this.fetchServiceAccountAccessToken(scopes).then((tokenEntry) => {
      tokenCache.set(cacheKey, tokenEntry);
      return tokenEntry.token;
    }).finally(() => {
      const current = tokenCache.get(cacheKey);
      if (current?.pending) {
        delete current.pending;
      }
    });

    tokenCache.set(cacheKey, { ...entry, pending });
    return pending;
  }

  private async fetchServiceAccountAccessToken(scopes: string[]): Promise<{ token: string; expiresAt: number }> {
    const assertion = buildJwtAssertion(this.config, scopes);
    const response = await this.fetchImpl(this.config.tokenUri, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to obtain Google access token: ${await this.readError(response)}`);
    }

    const payload = asRecord(await response.json());
    const accessToken = asString(payload.access_token);
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    if (!accessToken) {
      throw new Error("Google token exchange response did not include access_token.");
    }

    return {
      token: accessToken,
      expiresAt: Date.now() + expiresIn * 1000,
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export function clearGwsTokenCacheForTests(): void {
  tokenCache.clear();
}

export async function runGwsAccessCheck(
  client: GoogleWorkspaceAuditorClient,
  config: GwsResolvedConfig,
): Promise<GwsAccessCheckResult> {
  const probes = await Promise.all(
    GWS_ACCESS_PROBES.map(async (probe) => {
      const result = await client.probe(probe.url(config), [...probe.scopes]);
      return {
        ...result,
        key: probe.key,
      };
    }),
  );

  const okKeys = new Set(probes.filter((probe) => probe.status === "ok").map((probe) => probe.key));
  const status = okKeys.has("users") && okKeys.has("roles") && okKeys.has("role_assignments") && okKeys.has("reports_login")
    ? "healthy"
    : "limited";

  const notes = [
    config.authMode === "service_account"
      ? "Service-account auth assumes domain-wide delegation is configured for the supplied admin email."
      : "Access-token mode skips service-account token exchange and uses the provided bearer directly.",
    "Surfaces: Directory users and roles, Reports audit activity, Alert Center, per-user token inventory, and Cloud Identity 2-step verification policies.",
    okKeys.has("policies")
      ? "The Cloud Identity Policy API is readable, so GWS-ID-005 can be evaluated automatically."
      : "The Cloud Identity Policy API is not readable (scope cloud-identity.policies.readonly); GWS-ID-005 will render Manual until it is delegated.",
  ];

  return {
    organization: getDisplayOrganization(config),
    authMode: config.authMode,
    status,
    sourceChain: config.sourceChain,
    probes,
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run the focused GWS assessment that matches the question, or export the audit bundle for a full evidence package."
      : "Fix the missing Google scopes or delegated-admin setup, then re-run gws_check_access before trusting posture findings.",
  };
}

async function collectTokenInventory(
  client: Pick<GwsAuditCollector, "listUserTokens">,
  users: JsonRecord[],
  population: number,
): Promise<CollectedDataset<TokenInventoryRecord[]>> {
  const records: TokenInventoryRecord[] = [];
  const errors: string[] = [];
  let forbidden = 0;
  const collected = await mapWithConcurrency(users, 4, async (user) => {
    const userKey = asString(user.primaryEmail) ?? asString(user.id);
    if (!userKey) return { records: [] as TokenInventoryRecord[], error: undefined, kind: undefined as GwsEndpointStatus | undefined };
    try {
      const tokens = await client.listUserTokens(userKey);
      return {
        records: tokens.map((token) => ({
          userId: asString(user.id) ?? userKey,
          primaryEmail: asString(user.primaryEmail) ?? userKey,
          token,
        })),
        error: undefined,
        kind: undefined as GwsEndpointStatus | undefined,
      };
    } catch (error) {
      return {
        records: [] as TokenInventoryRecord[],
        error: `${userKey}: ${summarizeError(error)}`,
        kind: classifyError(error),
      };
    }
  });

  for (const result of collected) {
    records.push(...result.records);
    if (result.error) errors.push(result.error);
    if (result.kind === "forbidden" || result.kind === "unauthorized") forbidden += 1;
  }

  return {
    data: records,
    error: errors.length > 0 ? errors.join("; ") : undefined,
    errorKind: errors.length > 0 ? (forbidden > 0 ? "forbidden" : "error") : undefined,
    seen: users.length,
    total: population,
    failed: errors.length,
    truncated: users.length < population,
  };
}

export async function collectGwsAuditData(client: GwsAuditCollector): Promise<GwsAuditData> {
  const [users, roles, roleAssignments, loginActivities, adminActivities, tokenActivities, alerts, twoStepPolicies] =
    await Promise.all([
      collectDataset(() => client.collectUsers()),
      collectDataset(() => client.collectRoles()),
      collectDataset(() => client.collectRoleAssignments()),
      collectDataset(() => client.collectActivities("login")),
      collectDataset(() => client.collectActivities("admin")),
      collectDataset(() => client.collectActivities("token")),
      collectDataset(() => client.collectAlerts()),
      collectDataset(() => client.collectTwoStepPolicies()),
    ]);

  const privilegedContext = getPrivilegedUsers(users.data, roles.data, roleAssignments.data);
  const tokenUsers = selectUsersForTokenInventory(users.data, privilegedContext.privilegedUsers);
  const activePopulation = users.data.filter(isActiveUser).length;
  const tokenInventory = await collectTokenInventory(client, tokenUsers, Math.max(activePopulation, tokenUsers.length));

  return {
    identity: { users, roles, roleAssignments, loginActivities, twoStepPolicies },
    adminAccess: { users, roles, roleAssignments, adminActivities },
    integrations: { users, roles, roleAssignments, tokenInventory, tokenActivities },
    monitoring: { loginActivities, adminActivities, tokenActivities, alerts },
  };
}

export async function collectGwsIdentityData(client: GwsAuditCollector): Promise<GwsIdentityData> {
  const [users, roles, roleAssignments, loginActivities, twoStepPolicies] = await Promise.all([
    collectDataset(() => client.collectUsers()),
    collectDataset(() => client.collectRoles()),
    collectDataset(() => client.collectRoleAssignments()),
    collectDataset(() => client.collectActivities("login")),
    collectDataset(() => client.collectTwoStepPolicies()),
  ]);

  return { users, roles, roleAssignments, loginActivities, twoStepPolicies };
}

export async function collectGwsAdminAccessData(client: GwsAuditCollector): Promise<GwsAdminAccessData> {
  const [users, roles, roleAssignments, adminActivities] = await Promise.all([
    collectDataset(() => client.collectUsers()),
    collectDataset(() => client.collectRoles()),
    collectDataset(() => client.collectRoleAssignments()),
    collectDataset(() => client.collectActivities("admin")),
  ]);

  return { users, roles, roleAssignments, adminActivities };
}

export async function collectGwsIntegrationData(client: GwsAuditCollector): Promise<GwsIntegrationData> {
  const [users, roles, roleAssignments, tokenActivities] = await Promise.all([
    collectDataset(() => client.collectUsers()),
    collectDataset(() => client.collectRoles()),
    collectDataset(() => client.collectRoleAssignments()),
    collectDataset(() => client.collectActivities("token")),
  ]);

  const privilegedContext = getPrivilegedUsers(users.data, roles.data, roleAssignments.data);
  const tokenUsers = selectUsersForTokenInventory(users.data, privilegedContext.privilegedUsers);
  const activePopulation = users.data.filter(isActiveUser).length;
  const tokenInventory = await collectTokenInventory(client, tokenUsers, Math.max(activePopulation, tokenUsers.length));

  return { users, roles, roleAssignments, tokenInventory, tokenActivities };
}

export async function collectGwsMonitoringData(client: GwsAuditCollector): Promise<GwsMonitoringData> {
  const [loginActivities, adminActivities, tokenActivities, alerts] = await Promise.all([
    collectDataset(() => client.collectActivities("login")),
    collectDataset(() => client.collectActivities("admin")),
    collectDataset(() => client.collectActivities("token")),
    collectDataset(() => client.collectAlerts()),
  ]);

  return { loginActivities, adminActivities, tokenActivities, alerts };
}

const DIRECTORY_SCOPE_HINT = "admin.directory.user.readonly and admin.directory.rolemanagement.readonly";
const REPORTS_SCOPE_HINT = "admin.reports.audit.readonly";
const ALERTS_SCOPE_HINT = "apps.alerts";
const TOKEN_SCOPE_HINT = "admin.directory.user.security";
const POLICY_SCOPE_HINT = "cloud-identity.policies.readonly";

function directoryUnreadable(
  users: CollectedDataset<JsonRecord[]>,
  roles: CollectedDataset<JsonRecord[]>,
  roleAssignments: CollectedDataset<JsonRecord[]>,
): { endpoint: string; dataset: CollectedDataset<JsonRecord[]> } | undefined {
  if (users.error) return { endpoint: "Directory users.list", dataset: users };
  if (roles.error) return { endpoint: "Directory roles.list", dataset: roles };
  if (roleAssignments.error) return { endpoint: "Directory roleAssignments.list", dataset: roleAssignments };
  return undefined;
}

function assessTwoStepPolicy(dataset: CollectedDataset<JsonRecord[]> | undefined): GwsFinding {
  if (!dataset) {
    return buildFinding(
      "GWS-ID-005",
      "Manual",
      "Cloud Identity Policy API data was not collected in this run, so the organization-level 2-step verification policy could not be evaluated.",
      ["policies.list was not queried"],
      "Re-run the identity assessment with the cloud-identity.policies.readonly scope delegated.",
      "Collect manually: Admin console > Security > Authentication > 2-Step Verification enforcement setting per organizational unit.",
    );
  }
  if (dataset.error) {
    return unreadableFinding(
      "GWS-ID-005",
      "Cloud Identity policies.list",
      dataset,
      POLICY_SCOPE_HINT,
      "Admin console > Security > Authentication > 2-Step Verification enforcement setting per organizational unit.",
    );
  }

  const enforcement = dataset.data.filter((policy) => asString(asRecord(policy.setting).type) === TWO_STEP_ENFORCEMENT_SETTING);
  const enrollment = dataset.data.filter((policy) => asString(asRecord(policy.setting).type) === TWO_STEP_ENROLLMENT_SETTING);
  const factors = dataset.data.filter((policy) => asString(asRecord(policy.setting).type) === TWO_STEP_FACTOR_SETTING);
  if (enforcement.length === 0) {
    return buildFinding(
      "GWS-ID-005",
      "Manual",
      `The Policy API returned ${dataset.data.length} 2-step verification policies but none of type ${TWO_STEP_ENFORCEMENT_SETTING}; emptiness is treated as an unconfirmed policy, not as compliance.`,
      [`Policies returned: ${dataset.data.length}`],
      "Confirm the Policy API is enabled for the customer and that the enforcement setting is returned, then re-run.",
      "Collect manually: Admin console > Security > Authentication > 2-Step Verification > Enforcement for the root organizational unit.",
    );
  }

  const now = Date.now();
  const describeScope = (policy: JsonRecord): string => {
    const query = asRecord(policy.policyQuery);
    return asString(query.group) ? `group ${query.group as string}` : `orgUnit ${asString(query.orgUnit) ?? "unknown"}`;
  };
  const enforced = enforcement.filter((policy) => {
    const value = asRecord(asRecord(policy.setting).value);
    const enforcedFrom = parseDate(value.enforcedFrom);
    return enforcedFrom !== undefined && enforcedFrom <= now;
  });
  const enrollmentDisabled = enrollment.filter((policy) => {
    const value = asRecord(asRecord(policy.setting).value);
    return asBoolean(value.allowEnrollment) === false;
  });
  const factorSets = Array.from(new Set(factors.map((policy) => {
    const value = asRecord(asRecord(policy.setting).value);
    return asString(value.allowedSignInFactorSet) ?? "unspecified";
  })));
  const evidence = [
    `Enforcement policies returned: ${enforcement.length} (${enforcement.map((policy) => `${describeScope(policy)} [${asString(policy.type) ?? "type unknown"}]`).join("; ")})`,
    `Enforcement policies with enforcedFrom at or before now: ${enforced.length}`,
    `Enrollment policies with allowEnrollment=false: ${enrollmentDisabled.length}`,
    `Allowed sign-in factor sets observed: ${factorSets.join(", ") || "none returned"}`,
    ...partialViewEvidence("Policies", dataset),
  ];

  if (enforced.length === enforcement.length && enrollmentDisabled.length === 0) {
    return withPartialCap(
      buildFinding(
        "GWS-ID-005",
        "Pass",
        "Every returned 2-step verification enforcement policy has an enforcedFrom timestamp in the past and enrollment is allowed everywhere.",
        evidence,
        "Keep enforcement on the root organizational unit and prefer passkey or NO_TELEPHONY factor sets for privileged units.",
      ),
      partialViewEvidence("Policies", dataset),
    );
  }
  if (enforced.length > 0) {
    return buildFinding(
      "GWS-ID-005",
      "Partial",
      "2-step verification is enforced for some scopes, but at least one returned policy leaves enforcement unset, in the future, or blocks enrollment.",
      evidence,
      "Extend enforcement to every organizational unit and group, and make sure allowEnrollment is not disabled where enforcement applies.",
    );
  }
  return buildFinding(
    "GWS-ID-005",
    "Fail",
    "No returned 2-step verification enforcement policy has an active enforcedFrom timestamp; 2SV is not enforced by policy.",
    evidence,
    "Enable 2-Step Verification enforcement for the root organizational unit and set an enforcement date in the past.",
  );
}

export function assessGwsIdentity(
  data: GwsIdentityData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const users = data.users.data;
  const roles = data.roles.data;
  const roleAssignments = data.roleAssignments.data;
  const privileged = getPrivilegedUsers(users, roles, roleAssignments);
  const activeUsers = users.filter(isActiveUser);
  const enforcedUsers = activeUsers.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const enrolledUsers = activeUsers.filter((user) => asBoolean(user.isEnrolledIn2Sv) === true);
  const privilegedEnforced = privileged.privilegedUsers.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const superAdminEnforced = privileged.superAdmins.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const dormantCutoff = Date.now() - DORMANT_DAYS * 24 * 60 * 60 * 1000;
  const dormancy = bucketDormancy(activeUsers, dormantCutoff);
  const directoryProblem = directoryUnreadable(data.users, data.roles, data.roleAssignments);
  const userPartial = partialViewEvidence("Users", data.users);
  const privilegedViewNotes = privilegedViewEvidence(data);
  const privilegedPartial = privileged.unresolvedAssignments > 0
    ? [`Role assignments pointing at users outside the collected listing: ${privileged.unresolvedAssignments}`]
    : [];

  const findings: GwsFinding[] = [];

  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-ID-001",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Directory > Users filtered to admins, with each admin's 2-Step Verification enforcement status.",
    ));
  } else if (privileged.privilegedUsers.length === 0) {
    findings.push(buildFinding(
      "GWS-ID-001",
      "Manual",
      "No privileged users were identified, which cannot be a compliant state because every tenant has at least one super admin; treat this as a scoped or incomplete read.",
      [
        `Users collected: ${users.length}`,
        `Role assignments collected: ${roleAssignments.length}`,
        ...privilegedViewNotes,
      ],
      "Confirm the delegated admin can read every user and role assignment, then re-run the assessment.",
      "Collect manually: Admin console > Account > Admin roles, listing every assigned administrator.",
    ));
  } else {
    const coverage = privilegedEnforced.length / privileged.privilegedUsers.length;
    const evidence = [
      `Privileged users: ${privileged.privilegedUsers.length}`,
      `Privileged users with isEnforcedIn2Sv=true: ${privilegedEnforced.length}`,
    ];
    findings.push(withPartialCap(
      coverage >= 1
        ? buildFinding(
          "GWS-ID-001",
          "Pass",
          "Every privileged user in the collected dataset has isEnforcedIn2Sv=true.",
          evidence,
          "Keep delegated-admin reviews in place so newly privileged users stay covered by enforced 2SV.",
        )
        : coverage >= 0.8
          ? buildFinding(
            "GWS-ID-001",
            "Partial",
            "Most privileged users enforce 2-step verification, but there are still uncovered admin identities.",
            evidence,
            "Require enforced 2-step verification for the remaining privileged users before treating the tenant as strongly hardened.",
          )
          : buildFinding(
            "GWS-ID-001",
            "Fail",
            "Too many privileged users lack enforced 2-step verification.",
            evidence,
            "Make enforced 2-step verification mandatory for privileged users immediately.",
          ),
      [...privilegedViewNotes, ...privilegedPartial],
    ));
  }

  if (data.users.error) {
    findings.push(unreadableFinding(
      "GWS-ID-002",
      "Directory users.list",
      data.users,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Reporting > User reports > Security, exported with the 2-Step Verification enforcement column.",
    ));
  } else if (activeUsers.length === 0) {
    findings.push(buildFinding(
      "GWS-ID-002",
      "Manual",
      "No active users were returned; an empty directory cannot be compliant because the auditing admin is itself a user, so the read is treated as scoped or incomplete.",
      [`Users collected: ${users.length}`],
      "Verify the delegated admin can read the whole user directory and re-run the assessment.",
      "Collect manually: the Admin console user list with 2-Step Verification enrollment and enforcement columns.",
    ));
  } else {
    const coverage = enforcedUsers.length / activeUsers.length;
    const evidence = [
      `Active users: ${activeUsers.length}`,
      `Users with isEnforcedIn2Sv=true: ${enforcedUsers.length}`,
      `Users with isEnrolledIn2Sv=true: ${enrolledUsers.length}`,
    ];
    findings.push(withPartialCap(
      coverage >= 0.98
        ? buildFinding(
          "GWS-ID-002",
          "Pass",
          "2-step verification enforcement is near-universal across active users.",
          evidence,
          "Maintain enrollment and enforcement checks so coverage stays high as users churn.",
        )
        : coverage >= 0.85
          ? buildFinding(
            "GWS-ID-002",
            "Partial",
            "2-step verification coverage is substantial but still leaves a meaningful population without enforced protection.",
            evidence,
            "Close the remaining MFA enforcement gap, starting with the highest-risk org units and externally reachable users.",
          )
          : buildFinding(
            "GWS-ID-002",
            "Fail",
            "Broad 2-step verification coverage is too low for a strong compliance posture.",
            evidence,
            "Roll out enforced 2-step verification for the tenant in stages, prioritizing admins and high-risk populations first.",
          ),
      userPartial,
    ));
  }

  if (data.users.error) {
    findings.push(unreadableFinding(
      "GWS-ID-003",
      "Directory users.list",
      data.users,
      DIRECTORY_SCOPE_HINT,
      "Admin console user list sorted by last sign-in, identifying active accounts idle for more than 90 days.",
    ));
  } else if (activeUsers.length === 0) {
    findings.push(buildFinding(
      "GWS-ID-003",
      "Manual",
      "No active users were returned, so dormancy could not be evaluated; emptiness is treated as an incomplete read rather than as zero dormant accounts.",
      [`Users collected: ${users.length}`],
      "Verify directory read access and re-run the assessment.",
      "Collect manually: the Admin console user list with the last sign-in column.",
    ));
  } else {
    const evidence = [
      `Active users reviewed: ${activeUsers.length}`,
      `Dormant active users (lastLoginTime older than ${DORMANT_DAYS} days): ${dormancy.dormant}`,
      `Active users with no parseable lastLoginTime (reported separately, never counted as fresh): ${dormancy.unknownLastLogin}`,
    ];
    const unknownNotes = dormancy.unknownLastLogin > 0
      ? [`${dormancy.unknownLastLogin} active user(s) have no lastLoginTime and need a manual freshness check`]
      : [];
    findings.push(withPartialCap(
      dormancy.dormant === 0
        ? buildFinding(
          "GWS-ID-003",
          "Pass",
          "No dormant active accounts were detected among the users with a known last login.",
          evidence,
          "Keep periodic stale-account reviews in place so unused access does not accumulate.",
        )
        : dormancy.dormant <= Math.max(2, Math.ceil(activeUsers.length * 0.05))
          ? buildFinding(
            "GWS-ID-003",
            "Partial",
            "A small set of dormant active accounts needs review.",
            evidence,
            "Review dormant accounts and suspend or archive those that are no longer justified.",
          )
          : buildFinding(
            "GWS-ID-003",
            "Fail",
            "There are too many dormant active accounts in the tenant.",
            evidence,
            "Perform a tenant-wide stale-account cleanup and tighten the joiner/mover/leaver review cadence.",
          ),
      [...userPartial, ...unknownNotes],
    ));
  }

  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-ID-004",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Account > Admin roles > Super Admin, with each member's 2-Step Verification status.",
    ));
  } else if (privileged.superAdmins.length === 0) {
    findings.push(buildFinding(
      "GWS-ID-004",
      "Manual",
      "No super-admin accounts were identified; every Google Workspace tenant has at least one, so the collected view is incomplete rather than compliant.",
      [
        `Role assignments collected: ${roleAssignments.length}`,
        `Users with isAdmin=true: ${users.filter((user) => asBoolean(user.isAdmin) === true).length}`,
        ...privilegedViewNotes,
      ],
      "Confirm the audit principal can read super admins (users.list isAdmin and the _SEED_ADMIN_ROLE assignments) and re-run.",
      "Collect manually: Admin console > Account > Admin roles > Super Admin membership.",
    ));
  } else {
    const evidence = [
      `Super admins: ${privileged.superAdmins.length}`,
      `Super admins with isEnforcedIn2Sv=true: ${superAdminEnforced.length}`,
    ];
    findings.push(withPartialCap(
      superAdminEnforced.length === privileged.superAdmins.length
        ? buildFinding(
          "GWS-ID-004",
          "Pass",
          "All identified super admins have isEnforcedIn2Sv=true.",
          evidence,
          "Keep the super-admin roster short and review it regularly.",
        )
        : buildFinding(
          "GWS-ID-004",
          "Fail",
          "One or more identified super admins do not enforce 2-step verification.",
          evidence,
          "Require enforced 2-step verification for every super-admin account immediately.",
        ),
      [...privilegedViewNotes, ...privilegedPartial],
    ));
  }

  findings.push(assessTwoStepPolicy(data.twoStepPolicies));

  const snapshotSummary = {
    active_users: activeUsers.length,
    users_seen_partial_view: data.users.truncated ? "yes" : "no",
    privileged_users: privileged.privilegedUsers.length,
    super_admins: privileged.superAdmins.length,
    users_enforced_in_2sv: enforcedUsers.length,
    dormant_active_users: dormancy.dormant,
    users_without_last_login: dormancy.unknownLastLogin,
    two_step_policies: data.twoStepPolicies?.data.length ?? "not collected",
  };

  return {
    category: "identity",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace identity assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsAdminAccess(
  data: GwsAdminAccessData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const users = data.users.data;
  const roles = data.roles.data;
  const roleAssignments = data.roleAssignments.data;
  const privileged = getPrivilegedUsers(users, roles, roleAssignments);
  const staleCutoff = Date.now() - DORMANT_DAYS * 24 * 60 * 60 * 1000;
  const suspendedPrivileged = privileged.privilegedUsers.filter((user) => !isActiveUser(user));
  const stalePrivileged = bucketDormancy(privileged.privilegedUsers.filter(isActiveUser), staleCutoff);
  const directoryProblem = directoryUnreadable(data.users, data.roles, data.roleAssignments);
  const partialNotes = [
    ...privilegedViewEvidence(data),
    ...(privileged.unresolvedAssignments > 0
      ? [`Role assignments pointing at users outside the collected listing: ${privileged.unresolvedAssignments}`]
      : []),
  ];

  const findings: GwsFinding[] = [];

  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-ADMIN-001",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Account > Admin roles > Super Admin membership count.",
    ));
  } else if (privileged.superAdmins.length === 0) {
    findings.push(buildFinding(
      "GWS-ADMIN-001",
      "Manual",
      "No super admins were identified; every tenant has at least one, so the collected view is incomplete and the population cannot be judged constrained.",
      [`Users collected: ${users.length}`, `Role assignments collected: ${roleAssignments.length}`, ...partialNotes],
      "Confirm directory and role-assignment read access, then re-run.",
      "Collect manually: Admin console > Account > Admin roles > Super Admin membership.",
    ));
  } else {
    const evidence = [`Super admins identified: ${privileged.superAdmins.length}`];
    findings.push(withPartialCap(
      privileged.superAdmins.length <= 4
        ? buildFinding(
          "GWS-ADMIN-001",
          "Pass",
          "The tenant keeps the super-admin population constrained.",
          evidence,
          "Maintain at least one break-glass administrator, but keep routine admin work delegated whenever possible.",
        )
        : privileged.superAdmins.length <= 6
          ? buildFinding(
            "GWS-ADMIN-001",
            "Partial",
            "The tenant has a moderately broad super-admin population.",
            evidence,
            "Reduce routine Super Admin usage by migrating operators to delegated roles where possible.",
          )
          : buildFinding(
            "GWS-ADMIN-001",
            "Fail",
            "The super-admin population is broader than a least-privilege posture would usually tolerate.",
            evidence,
            "Shrink the super-admin set and move everyday administration into narrower delegated roles.",
          ),
      partialNotes,
    ));
  }

  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-ADMIN-002",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Admin role membership cross-checked against suspended and archived users.",
    ));
  } else if (privileged.privilegedUsers.length === 0) {
    findings.push(buildFinding(
      "GWS-ADMIN-002",
      "Manual",
      "No privileged users were identified, so the privileged lifecycle could not be checked; emptiness is treated as an incomplete read.",
      [`Users collected: ${users.length}`, ...partialNotes],
      "Confirm directory and role-assignment read access, then re-run.",
      "Collect manually: Admin role membership cross-checked against suspended and archived users.",
    ));
  } else {
    findings.push(withPartialCap(
      suspendedPrivileged.length === 0
        ? buildFinding(
          "GWS-ADMIN-002",
          "Pass",
          "No suspended or archived privileged accounts were identified among the privileged population.",
          [`Privileged users reviewed: ${privileged.privilegedUsers.length}`],
          "Keep deprovisioning reviews tied to privileged-role assignments.",
        )
        : buildFinding(
          "GWS-ADMIN-002",
          "Fail",
          "Suspended or archived users still appear in the privileged population.",
          [
            `Privileged users reviewed: ${privileged.privilegedUsers.length}`,
            `Suspended or archived privileged users: ${suspendedPrivileged.length}`,
          ],
          "Remove or verify every privileged assignment attached to suspended or archived identities.",
        ),
      partialNotes,
    ));
  }

  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-ADMIN-003",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Account > Admin roles, listing delegated and custom role assignments.",
    ));
  } else {
    findings.push(withPartialCap(
      privileged.delegatedAdmins.length > 0
        ? buildFinding(
          "GWS-ADMIN-003",
          "Pass",
          "The tenant uses delegated or custom admin roles in addition to super-admin access.",
          [
            `Delegated admin users identified: ${privileged.delegatedAdmins.length}`,
            `Total privileged users: ${privileged.privilegedUsers.length}`,
          ],
          "Continue using delegated roles to keep Super Admin access exceptional.",
        )
        : buildFinding(
          "GWS-ADMIN-003",
          "Manual",
          "The collected data did not show delegated-admin usage beyond Super Admin; an empty delegated set is not treated as compliant.",
          [
            `Delegated admin users identified: ${privileged.delegatedAdmins.length}`,
            `Total privileged users: ${privileged.privilegedUsers.length}`,
          ],
          "Review whether the tenant intentionally uses only Super Admin or whether delegated roles should be expanded.",
          "Collect manually: the documented administrative model and the role assignment list.",
        ),
      partialNotes,
    ));
  }

  if (data.adminActivities.error) {
    findings.push(unreadableFinding(
      "GWS-ADMIN-004",
      "Reports activities.list (applicationName=admin)",
      data.adminActivities,
      REPORTS_SCOPE_HINT,
      "Admin console > Reporting > Audit and investigation > Admin log events for the review window.",
    ));
  } else if (data.adminActivities.data.length === 0) {
    findings.push(buildFinding(
      "GWS-ADMIN-004",
      "Manual",
      `The admin audit log returned zero events for the ${config.lookbackDays}-day window; an empty window is treated as unconfirmed observability rather than as a pass.`,
      ["Admin activities collected: 0"],
      "Confirm admin audit logging is retained and that the window contains expected administrative changes.",
      "Collect manually: Admin console > Reporting > Audit and investigation > Admin log events.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-ADMIN-004",
        "Pass",
        "Admin activity telemetry is readable for the configured lookback window.",
        [`Admin activities collected: ${data.adminActivities.data.length} across ${data.adminActivities.pages ?? 1} page(s)`],
        "Use the admin activity stream during periodic privileged-access reviews and incident response.",
      ),
      partialViewEvidence("Admin activities", data.adminActivities),
    ));
  }

  if (data.roleAssignments.error) {
    findings.push(unreadableFinding(
      "GWS-ADMIN-005",
      "Directory roleAssignments.list",
      data.roleAssignments,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Account > Admin roles, listing group-based assignments.",
    ));
  } else if (roleAssignments.length === 0) {
    findings.push(buildFinding(
      "GWS-ADMIN-005",
      "Manual",
      "No role assignments were returned; every tenant has at least the super-admin assignment, so the empty list is treated as an incomplete read.",
      ["Role assignments collected: 0"],
      "Confirm the rolemanagement.readonly scope and re-run.",
      "Collect manually: Admin console > Account > Admin roles, listing group-based assignments.",
    ));
  } else if (privileged.groupAssignmentCount === 0) {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-ADMIN-005",
        "Pass",
        "No group-based role assignments exist among the returned assignments (assigneeType=GROUP count is zero within a non-empty assignment inventory), which is compliant by intent.",
        [`Role assignments reviewed: ${roleAssignments.length}`, `Group role assignments: ${privileged.groupAssignmentCount}`],
        "Keep group-based privileged grants documented if they are introduced later.",
      ),
      privilegedViewEvidence(data),
    ));
  } else {
    findings.push(buildFinding(
      "GWS-ADMIN-005",
      "Manual",
      "Group-based role assignments exist and need explicit membership review.",
      [`Group role assignments: ${privileged.groupAssignmentCount}`],
      "Review security-group membership and make sure external or stale principals cannot inherit admin access indirectly.",
      "This slice does not expand group membership, so the inherited privileged population needs a manual spot check.",
    ));
  }

  const snapshotSummary = {
    privileged_users: privileged.privilegedUsers.length,
    super_admins: privileged.superAdmins.length,
    delegated_admins: privileged.delegatedAdmins.length,
    stale_privileged_users: stalePrivileged.dormant,
    privileged_users_without_last_login: stalePrivileged.unknownLastLogin,
    group_role_assignments: privileged.groupAssignmentCount,
    users_seen_partial_view: data.users.truncated ? "yes" : "no",
  };

  return {
    category: "admin_access",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace admin-access assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsIntegrations(
  data: GwsIntegrationData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const privileged = getPrivilegedUsers(data.users.data, data.roles.data, data.roleAssignments.data);
  const privilegedIds = new Set(privileged.privilegedUsers.map((user) => asString(user.id)).filter((value): value is string => Boolean(value)));
  const allTokens = data.tokenInventory.data;
  const privilegedTokens = allTokens.filter((record) => privilegedIds.has(record.userId));
  const uniqueClients = uniqueClientLabels(allTokens);
  const highRiskTokens = countHighRiskTokens(allTokens);
  const tokenEvents = extractActivityEventNames(data.tokenActivities.data);
  const sampled = data.tokenInventory.seen ?? 0;
  const population = data.tokenInventory.total ?? sampled;
  const failed = data.tokenInventory.failed ?? 0;
  const directoryProblem = directoryUnreadable(data.users, data.roles, data.roleAssignments);
  const sampleNotes = [
    ...(sampled < population ? [`Token inventory sample: seen ${sampled} of ${population} active users (privileged users first)`] : []),
    ...(failed > 0 ? [`Per-user token reads that failed: ${failed}`] : []),
    ...partialViewEvidence("Users", data.users),
  ];
  const inventoryEvidence = [
    `Users sampled for token inventory: ${sampled}`,
    `Token records collected: ${allTokens.length}`,
  ];

  const findings: GwsFinding[] = [];

  if (data.users.error) {
    findings.push(unreadableFinding(
      "GWS-INTEG-001",
      "Directory users.list",
      data.users,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Security > API controls > App access control, listing authorized third-party apps.",
    ));
  } else if (sampled === 0) {
    findings.push(buildFinding(
      "GWS-INTEG-001",
      "Manual",
      "No users were available to sample for token inventory, so readability could not be demonstrated.",
      inventoryEvidence,
      "Confirm directory read access, then re-run the integrations assessment.",
      "Collect manually: Admin console > Security > API controls > App access control.",
    ));
  } else if (failed === sampled) {
    findings.push(unreadableFinding(
      "GWS-INTEG-001",
      "Directory tokens.list",
      data.tokenInventory,
      TOKEN_SCOPE_HINT,
      "Admin console > Security > API controls > App access control, plus per-user connected apps.",
    ));
  } else if (failed > 0) {
    findings.push(buildFinding(
      "GWS-INTEG-001",
      "Partial",
      "Third-party token inventory was only partially readable.",
      [...inventoryEvidence, `Token inventory errors: ${data.tokenInventory.error}`, ...sampleNotes],
      "Grant the admin.directory.user.security scope and verify the delegated admin can enumerate third-party tokens for every user.",
    ));
  } else if (allTokens.length === 0) {
    findings.push(buildFinding(
      "GWS-INTEG-001",
      "Manual",
      `tokens.list responded for all ${sampled} sampled users but returned no tokens; an empty inventory is reported for confirmation rather than treated as a pass.`,
      [...inventoryEvidence, ...sampleNotes],
      "Confirm in the Admin console that no third-party apps are authorized, or widen the sample.",
      "Collect manually: Admin console > Security > API controls > App access control > Configured apps.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-INTEG-001",
        "Pass",
        "Third-party token inventory is readable for the sampled users.",
        inventoryEvidence,
        "Use the token inventory during third-party app reviews and user-access attestations.",
      ),
      sampleNotes,
    ));
  }

  const privilegedSampled = privileged.privilegedUsers.length <= MAX_TOKEN_USERS;
  if (directoryProblem) {
    findings.push(unreadableFinding(
      "GWS-INTEG-002",
      directoryProblem.endpoint,
      directoryProblem.dataset,
      DIRECTORY_SCOPE_HINT,
      "Connected third-party apps for each administrator account.",
    ));
  } else if (privileged.privilegedUsers.length === 0 || allTokens.length === 0 || failed > 0 && privilegedTokens.length === 0) {
    findings.push(buildFinding(
      "GWS-INTEG-002",
      "Manual",
      "Privileged OAuth exposure could not be confirmed: the privileged set or the token inventory is empty or partially unreadable, so zero privileged tokens is not treated as a pass.",
      [
        `Privileged users identified: ${privileged.privilegedUsers.length}`,
        `Token records collected: ${allTokens.length}`,
        `Privileged third-party tokens: ${privilegedTokens.length}`,
        ...sampleNotes,
      ],
      "Restore full directory and token readability, then re-run.",
      "Collect manually: connected third-party apps for each administrator account.",
    ));
  } else {
    const evidence = [
      `Privileged users sampled: ${Math.min(privileged.privilegedUsers.length, MAX_TOKEN_USERS)} of ${privileged.privilegedUsers.length}`,
      `Privileged third-party tokens: ${privilegedTokens.length}`,
      `Privileged token clients: ${uniqueClientLabels(privilegedTokens).join(", ") || "none"}`,
    ];
    const capNotes = [
      ...(privilegedSampled ? [] : [`Privileged users beyond the ${MAX_TOKEN_USERS}-user token sample were not inspected`]),
      ...privilegedViewEvidence(data),
    ];
    findings.push(withPartialCap(
      privilegedTokens.length === 0
        ? buildFinding(
          "GWS-INTEG-002",
          "Pass",
          "No third-party tokens were observed for privileged users within a non-empty token inventory.",
          evidence,
          "Keep privileged accounts clean of unnecessary third-party OAuth grants.",
        )
        : privilegedTokens.length <= 3
          ? buildFinding(
            "GWS-INTEG-002",
            "Partial",
            "A small number of privileged users still hold third-party OAuth tokens.",
            evidence,
            "Review each privileged OAuth grant and remove anything not strictly required for administration or incident response.",
          )
          : buildFinding(
            "GWS-INTEG-002",
            "Fail",
            "Privileged-user third-party token exposure is broader than expected.",
            evidence,
            "Perform a privileged OAuth cleanup and require explicit approval for any remaining third-party grants.",
          ),
      capNotes,
    ));
  }

  if (data.users.error) {
    findings.push(unreadableFinding(
      "GWS-INTEG-003",
      "Directory users.list",
      data.users,
      DIRECTORY_SCOPE_HINT,
      "Admin console > Security > API controls > App access control with requested scopes per app.",
    ));
  } else if (allTokens.length === 0) {
    findings.push(buildFinding(
      "GWS-INTEG-003",
      "Manual",
      "The token inventory is empty or unreadable, so high-scope app sprawl could not be measured; emptiness is not treated as a pass.",
      [`Token records collected: ${allTokens.length}`, ...sampleNotes],
      "Restore token readability or confirm the tenant has no authorized third-party apps.",
      "Collect manually: Admin console > Security > API controls > App access control with scopes per app.",
    ));
  } else {
    const evidence = [
      `Third-party clients observed: ${uniqueClients.length}`,
      `High-scope token records: ${highRiskTokens}`,
    ];
    findings.push(withPartialCap(
      highRiskTokens === 0
        ? buildFinding(
          "GWS-INTEG-003",
          "Pass",
          "No high-scope third-party tokens were found in the sampled inventory.",
          evidence,
          "Keep reviewing third-party client scopes before approving new apps.",
        )
        : highRiskTokens <= 5
          ? buildFinding(
            "GWS-INTEG-003",
            "Partial",
            "A limited set of third-party tokens carries broad scopes.",
            evidence,
            "Review high-scope apps and trim or revoke unnecessary grants, especially those touching admin, Drive, Gmail, or cloud-platform scopes.",
          )
          : buildFinding(
            "GWS-INTEG-003",
            "Fail",
            "High-scope third-party OAuth sprawl is too broad in the sampled inventory.",
            evidence,
            "Run a focused OAuth app review and clean up broad-scope third-party access before treating the environment as well-controlled.",
          ),
      sampleNotes,
    ));
  }

  if (data.tokenActivities.error) {
    findings.push(unreadableFinding(
      "GWS-INTEG-004",
      "Reports activities.list (applicationName=token)",
      data.tokenActivities,
      REPORTS_SCOPE_HINT,
      "Admin console > Reporting > Audit and investigation > OAuth log events.",
    ));
  } else if (data.tokenActivities.data.length === 0) {
    findings.push(buildFinding(
      "GWS-INTEG-004",
      "Manual",
      `The token audit log returned zero events for the ${config.lookbackDays}-day window; an empty window is treated as unconfirmed telemetry rather than as a pass.`,
      ["Token activity records collected: 0"],
      "Confirm OAuth log events are retained and that the window should contain authorizations.",
      "Collect manually: Admin console > Reporting > Audit and investigation > OAuth log events.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-INTEG-004",
        "Pass",
        "Token activity telemetry is readable for the configured lookback window.",
        [
          `Token activity records collected: ${data.tokenActivities.data.length}`,
          `Observed token event names: ${Array.from(new Set(tokenEvents)).slice(0, 6).join(", ") || "none"}`,
        ],
        "Use token-activity reporting to support OAuth app reviews and incident triage.",
      ),
      partialViewEvidence("Token activities", data.tokenActivities),
    ));
  }

  const snapshotSummary = {
    sampled_users: sampled,
    active_user_population: population,
    privileged_users: privileged.privilegedUsers.length,
    token_records: allTokens.length,
    privileged_token_records: privilegedTokens.length,
    high_scope_token_records: highRiskTokens,
    token_read_failures: failed,
    token_activity_records: data.tokenActivities.data.length,
  };

  return {
    category: "integrations",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace integrations assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsMonitoring(
  data: GwsMonitoringData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const suspiciousLogins = countMatchingEvents(data.loginActivities.data, SUSPICIOUS_LOGIN_NAMES);
  const alerts = bucketAlerts(data.alerts.data);

  const findings: GwsFinding[] = [];

  if (data.alerts.error) {
    findings.push(unreadableFinding(
      "GWS-MON-001",
      "Alert Center alerts.list",
      data.alerts,
      ALERTS_SCOPE_HINT,
      "Admin console > Security > Alert center, confirming the alert list loads for the tenant.",
    ));
  } else if (data.alerts.data.length === 0) {
    findings.push(buildFinding(
      "GWS-MON-001",
      "Manual",
      "Alert Center responded but returned zero alerts; an empty list is reported for confirmation rather than treated as proof of a healthy alerting pipeline.",
      ["Alerts collected: 0"],
      "Confirm Alert Center is enabled and that system-defined rules are turned on for the tenant.",
      "Collect manually: Admin console > Security > Alert center and Rules.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-MON-001",
        "Pass",
        "Alert Center is readable for the tenant.",
        [`Alerts collected: ${data.alerts.data.length} across ${data.alerts.pages ?? 1} page(s)`],
        "Use Alert Center as one of the tenant's primary security-monitoring inputs.",
      ),
      partialViewEvidence("Alerts", data.alerts),
    ));
  }

  if (data.loginActivities.error) {
    findings.push(unreadableFinding(
      "GWS-MON-002",
      "Reports activities.list (applicationName=login)",
      data.loginActivities,
      REPORTS_SCOPE_HINT,
      "Admin console > Reporting > Audit and investigation > User log events filtered to suspicious login events.",
    ));
  } else if (data.loginActivities.data.length === 0) {
    findings.push(buildFinding(
      "GWS-MON-002",
      "Manual",
      `The login audit log returned zero events for the ${config.lookbackDays}-day window, so the suspicious-login backlog could not be measured; emptiness is not treated as a pass.`,
      ["Login activity records collected: 0"],
      "Confirm login audit logging is retained and that users signed in during the window.",
      "Collect manually: Admin console > Reporting > Audit and investigation > User log events.",
    ));
  } else {
    const evidence = [
      `Login activity records collected: ${data.loginActivities.data.length}`,
      `Suspicious login signals: ${suspiciousLogins}`,
    ];
    findings.push(withPartialCap(
      suspiciousLogins === 0
        ? buildFinding(
          "GWS-MON-002",
          "Pass",
          "No suspicious-login events were observed in the current lookback window.",
          evidence,
          "Keep reviewing login telemetry for spikes or new event types as part of routine monitoring.",
        )
        : suspiciousLogins <= 5
          ? buildFinding(
            "GWS-MON-002",
            "Partial",
            "A small suspicious-login backlog needs review.",
            evidence,
            "Review the suspicious-login events and make sure they were triaged, blocked, or otherwise resolved.",
          )
          : buildFinding(
            "GWS-MON-002",
            "Fail",
            "Suspicious-login volume in the lookback window is too high to ignore.",
            evidence,
            "Escalate suspicious-login review immediately and confirm the tenant's response workflow is keeping up.",
          ),
      partialViewEvidence("Login activities", data.loginActivities),
    ));
  }

  if (data.adminActivities.error) {
    findings.push(unreadableFinding(
      "GWS-MON-003",
      "Reports activities.list (applicationName=admin)",
      data.adminActivities,
      REPORTS_SCOPE_HINT,
      "Admin console > Reporting > Audit and investigation > Admin log events.",
    ));
  } else if (data.adminActivities.data.length === 0) {
    findings.push(buildFinding(
      "GWS-MON-003",
      "Manual",
      `The admin audit log returned zero events for the ${config.lookbackDays}-day window; emptiness is not treated as proof of telemetry.`,
      ["Admin activity records collected: 0"],
      "Confirm admin audit logging is retained for the tenant.",
      "Collect manually: Admin console > Reporting > Audit and investigation > Admin log events.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-MON-003",
        "Pass",
        "Admin audit telemetry is readable for the configured lookback window.",
        [`Admin activity records collected: ${data.adminActivities.data.length}`],
        "Use admin activity as a standing control for privileged-change review and investigations.",
      ),
      partialViewEvidence("Admin activities", data.adminActivities),
    ));
  }

  if (data.tokenActivities.error) {
    findings.push(unreadableFinding(
      "GWS-MON-004",
      "Reports activities.list (applicationName=token)",
      data.tokenActivities,
      REPORTS_SCOPE_HINT,
      "Admin console > Reporting > Audit and investigation > OAuth log events.",
    ));
  } else if (data.tokenActivities.data.length === 0) {
    findings.push(buildFinding(
      "GWS-MON-004",
      "Manual",
      `The token audit log returned zero events for the ${config.lookbackDays}-day window; emptiness is not treated as proof of telemetry.`,
      ["Token activity records collected: 0"],
      "Confirm OAuth log events are retained for the tenant.",
      "Collect manually: Admin console > Reporting > Audit and investigation > OAuth log events.",
    ));
  } else {
    findings.push(withPartialCap(
      buildFinding(
        "GWS-MON-004",
        "Pass",
        "Token audit telemetry is readable for the configured lookback window.",
        [`Token activity records collected: ${data.tokenActivities.data.length}`],
        "Use token activity in third-party app governance and incident response.",
      ),
      partialViewEvidence("Token activities", data.tokenActivities),
    ));
  }

  if (data.alerts.error) {
    findings.push(unreadableFinding(
      "GWS-MON-005",
      "Alert Center alerts.list",
      data.alerts,
      ALERTS_SCOPE_HINT,
      "Admin console > Security > Alert center, counting alerts whose status is not CLOSED.",
    ));
  } else if (data.alerts.data.length === 0) {
    findings.push(buildFinding(
      "GWS-MON-005",
      "Manual",
      "Alert Center returned zero alerts, so the backlog could not be measured; see GWS-MON-001 for the availability check.",
      ["Alerts collected: 0"],
      "Confirm Alert Center is populated before relying on the backlog signal.",
      "Collect manually: Admin console > Security > Alert center.",
    ));
  } else {
    const evidence = [
      `Alerts collected: ${data.alerts.data.length}`,
      `Open alerts (metadata.status NOT_STARTED or IN_PROGRESS): ${alerts.open}`,
      `Closed alerts (metadata.status CLOSED): ${alerts.closed}`,
      `Alerts without metadata.status (reported separately, never counted as closed): ${alerts.unknownStatus}`,
    ];
    const unknownNotes = alerts.unknownStatus > 0
      ? [`${alerts.unknownStatus} alert(s) carry no metadata.status and need a manual triage check`]
      : [];
    findings.push(withPartialCap(
      alerts.open <= 3
        ? buildFinding(
          "GWS-MON-005",
          "Pass",
          "The open alert backlog is manageable in the current snapshot.",
          evidence,
          "Keep alert ownership and closure practices explicit so the backlog stays manageable.",
        )
        : alerts.open <= 10
          ? buildFinding(
            "GWS-MON-005",
            "Partial",
            "The open alert backlog is noticeable and should be reviewed.",
            evidence,
            "Review the alert queue, verify ownership, and close or annotate stale alerts.",
          )
          : buildFinding(
            "GWS-MON-005",
            "Fail",
            "The open alert backlog is larger than a healthy review cadence would usually tolerate.",
            evidence,
            "Run a focused alert-triage sprint and make sure the queue has clear owners and escalation paths.",
          ),
      [...partialViewEvidence("Alerts", data.alerts), ...unknownNotes],
    ));
  }

  const snapshotSummary = {
    login_activity_records: data.loginActivities.data.length,
    suspicious_login_signals: suspiciousLogins,
    admin_activity_records: data.adminActivities.data.length,
    token_activity_records: data.tokenActivities.data.length,
    alerts_collected: data.alerts.data.length,
    open_alerts: alerts.open,
    alerts_without_status: alerts.unknownStatus,
  };

  return {
    category: "monitoring",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace monitoring assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

function buildExecutiveSummary(
  config: GwsResolvedConfig,
  assessments: GwsAssessmentResult[],
  errors: string[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const summary = countByStatus(findings);
  const failing = findings.filter((finding) => finding.status === "Fail");
  return [
    "# Google Workspace Audit Executive Summary",
    "",
    `- Organization: ${getDisplayOrganization(config)}`,
    `- Auth mode: ${config.authMode}`,
    `- Customer ID: ${config.customerId}`,
    `- Admin email: ${config.adminEmail ?? "not supplied"}`,
    `- Lookback days: ${config.lookbackDays}`,
    `- Source chain: ${config.sourceChain.join(" -> ") || "direct"}`,
    `- Controls evaluated: ${findings.length} of ${GWS_CHECK_IDS.length}`,
    "",
    "## Findings",
    "",
    `- Pass: ${summary.Pass}`,
    `- Partial: ${summary.Partial}`,
    `- Fail: ${summary.Fail}`,
    `- Manual: ${summary.Manual}`,
    `- Info: ${summary.Info}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(failing.length === 0
      ? ["- No failing findings were generated in this assessment set."]
      : failing.map((finding) => `- ${finding.id} ${finding.title}: ${finding.summary}`)),
    "",
    errors.length > 0
      ? [
        "## Partial Collection Warnings",
        "",
        ...errors.map((error) => `- ${error}`),
        "",
      ].join("\n")
      : "",
  ].filter(Boolean).join("\n");
}

export async function exportGwsAuditBundle(
  client: GwsAuditCollector,
  config: GwsResolvedConfig,
  outputRoot: string,
  frameworks: ReportFrameworkKey[] = [...REPORT_FRAMEWORK_KEYS],
): Promise<GwsAuditBundleResult> {
  const data = await collectGwsAuditData(client);
  const { identity, adminAccess, integrations, monitoring } = data;

  // Findings and errors are redacted as objects before any rendering, then every file passes through writeBundleFile.
  const assessments = redactSecrets([
    assessGwsIdentity(identity, config),
    assessGwsAdminAccess(adminAccess, config),
    assessGwsIntegrations(integrations, config),
    assessGwsMonitoring(monitoring, config),
  ]) as GwsAssessmentResult[];

  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  const errors = redactSecrets(collectErrors(
    ["users.list", identity.users],
    ["roles.list", identity.roles],
    ["roleAssignments.list", identity.roleAssignments],
    ["activities.list (login)", identity.loginActivities],
    ["policies.list", identity.twoStepPolicies ?? { data: [] }],
    ["activities.list (admin)", adminAccess.adminActivities],
    ["tokens.list", integrations.tokenInventory],
    ["activities.list (token)", integrations.tokenActivities],
    ["alerts.list", monitoring.alerts],
  )) as string[];
  const knownSecrets = knownGwsSecretValues(config);

  const safeName = safeDirName(`${getDisplayOrganization(config)}-gws-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, safeName);

  const coreDataFiles: Array<[string, CollectedDataset<JsonRecord[]>]> = [
    ["core_data/users.json", projectDataset(identity.users, projectUserSnapshot)],
    ["core_data/roles.json", projectDataset(identity.roles, projectRoleSnapshot)],
    ["core_data/role_assignments.json", projectDataset(identity.roleAssignments, projectRoleAssignmentSnapshot)],
    ["core_data/login_activities.json", projectDataset(identity.loginActivities, projectActivitySnapshot)],
    ["core_data/admin_activities.json", projectDataset(adminAccess.adminActivities, projectActivitySnapshot)],
    ["core_data/token_activities.json", projectDataset(integrations.tokenActivities, projectActivitySnapshot)],
    ["core_data/token_inventory.json", projectDataset(integrations.tokenInventory, projectTokenInventorySnapshot)],
    ["core_data/alerts.json", projectDataset(monitoring.alerts, projectAlertSnapshot)],
    ["core_data/two_step_verification_policies.json", projectDataset(identity.twoStepPolicies ?? { data: [], error: "not collected" }, projectPolicySnapshot)],
  ];
  for (const [pathName, dataset] of coreDataFiles) {
    await writeBundleFile(outputDir, pathName, serializeJson(redactSecrets(dataset)), knownSecrets);
  }

  await writeBundleFile(outputDir, "analysis/findings.json", serializeJson(allFindings), knownSecrets);
  for (const assessment of assessments) {
    await writeBundleFile(outputDir, `analysis/${assessment.category}.json`, serializeJson({
      category: assessment.category,
      summary: assessment.summary,
      snapshot_summary: assessment.snapshotSummary,
      findings: assessment.findings,
    }), knownSecrets);
    await writeBundleFile(outputDir, `analysis/${assessment.category}.md`, assessment.text, knownSecrets);
  }

  await writeBundleFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors), knownSecrets);
  await writeBundleFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(allFindings), knownSecrets);
  for (const framework of frameworks) {
    const report = FRAMEWORK_REPORTS[framework];
    await writeBundleFile(outputDir, report.file, buildFrameworkReport(report.title, allFindings, framework), knownSecrets);
  }
  await writeBundleFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference(frameworks), knownSecrets);
  if (errors.length > 0) {
    await writeBundleFile(outputDir, "_errors.log", `${errors.join("\n")}\n`, knownSecrets);
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return {
    outputDir,
    zipPath,
    fileCount,
    findingCount: allFindings.length,
    errorCount: errors.length,
    frameworks,
  };
}

export function registerGwsTools(pi: any): void {
  const authParams = {
    auth_mode: Type.Optional(
      Type.String({
        description: "Optional auth mode override. Supported values: service_account or access_token.",
      }),
    ),
    credentials_file: Type.Optional(
      Type.String({
        description: "Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS.",
      }),
    ),
    credentials_json: Type.Optional(
      Type.String({
        description: "Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory.",
      }),
    ),
    access_token: Type.Optional(
      Type.String({
        description: "Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN.",
      }),
    ),
    admin_email: Type.Optional(
      Type.String({
        description: "Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL.",
      }),
    ),
    domain: Type.Optional(
      Type.String({
        description: "Optional primary domain label used for display. Falls back to GWS_DOMAIN.",
      }),
    ),
    customer_id: Type.Optional(
      Type.String({
        description: "Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID.",
      }),
    ),
    lookback_days: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: 180,
        description: "Optional audit lookback window in days. Defaults to 30.",
      }),
    ),
  } as const;

  pi.registerTool({
    name: "gws_check_access",
    label: "Check Google Workspace audit access",
    description:
      "Validate Google Workspace read access for delegated service-account or direct access-token auth and show which security-relevant Admin SDK, Alert Center, and Cloud Identity Policy surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const result = await runGwsAccessCheck(client, config);
        return renderAccessCheck(result);
      } catch (error) {
        return errorResult(
          `Google Workspace access check failed: ${summarizeError(error)}`,
          { tool: "gws_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_identity",
    label: "Assess Google Workspace identity posture",
    description:
      "Review Google Workspace identity posture: 2-step verification coverage, privileged-user MFA enforcement, super-admin protection, dormant accounts, and the organization-level 2SV enforcement policy from the Cloud Identity Policy API.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsIdentityData(client);
        return renderAssessmentToolResult(assessGwsIdentity(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace identity assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_admin_access",
    label: "Assess Google Workspace admin access",
    description:
      "Review Google Workspace privileged-role population, super-admin sprawl, suspended privileged accounts, delegated-admin use, admin audit visibility, and group-based grants.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsAdminAccessData(client);
        return renderAssessmentToolResult(assessGwsAdminAccess(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace admin-access assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_admin_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_integrations",
    label: "Assess Google Workspace integrations",
    description:
      "Review third-party OAuth token inventory, privileged-user app exposure, high-scope client sprawl, and token-audit visibility in Google Workspace.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsIntegrationData(client);
        return renderAssessmentToolResult(assessGwsIntegrations(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace integrations assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_monitoring",
    label: "Assess Google Workspace monitoring",
    description:
      "Review Google Workspace Alert Center visibility, suspicious-login signals, admin audit coverage, token audit coverage, and the current alert backlog.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsMonitoringData(client);
        return renderAssessmentToolResult(assessGwsMonitoring(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace monitoring assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_export_audit_bundle",
    label: "Export Google Workspace audit bundle",
    description:
      "Collect the Google Workspace identity, admin-access, integrations, and monitoring evidence set once, then write core_data/, analysis/, compliance/ (executive summary, unified matrix, per-framework reports), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip archive that never overwrites an earlier bundle.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root for the Google Workspace audit bundle. Defaults to ${DEFAULT_OUTPUT_DIR}.`,
        }),
      ),
      frameworks: Type.Optional(
        Type.Array(Type.String(), {
          description: `Optional framework report filter. Supported values: ${REPORT_FRAMEWORK_KEYS.join(", ")}. Defaults to every framework.`,
        }),
      ),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: RawConfigArgs & { output_dir?: string; frameworks?: string[] }) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const frameworks = normalizeFrameworkSelection(args.frameworks);
        const result = await exportGwsAuditBundle(
          client,
          config,
          args.output_dir?.trim() || DEFAULT_OUTPUT_DIR,
          frameworks,
        );
        return textResult(buildExportText(config, result), {
          organization: getDisplayOrganization(config),
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          file_count: result.fileCount,
          finding_count: result.findingCount,
          error_count: result.errorCount,
          frameworks: result.frameworks,
        });
      } catch (error) {
        return errorResult(
          `Google Workspace audit export failed: ${summarizeError(error)}`,
          { tool: "gws_export_audit_bundle" },
        );
      }
    },
  });
}
