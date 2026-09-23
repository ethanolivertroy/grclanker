/**
 * Datadog security inspector tools for grclanker.
 *
 * Read-only assessment of a Datadog organization's tenant configuration
 * (SAML, users, roles, keys, audit trail, Cloud SIEM, CSM, logs, monitors)
 * against the 20 controls in specs/datadog-sec-inspector.spec.md.
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
import { createCredentialScrubber, isBearerIdKey } from "./credential-scrub.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type SleepImpl = (ms: number) => Promise<void>;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/datadog";
const DEFAULT_SITE = "datadoghq.com";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const MAX_RATE_LIMIT_WAIT_MS = 60_000;
const V2_PAGE_SIZE = 100;
const CURSOR_PAGE_SIZE = 100;
const MONITOR_PAGE_SIZE = 200;
const FINDING_PAGE_SIZE = 1000;
const ORG_CONNECTION_PAGE_SIZE = 1000;
const DASHBOARD_PAGE_SIZE = 100;
const DEFAULT_DASHBOARD_LIMIT = 2000;
const DEFAULT_USER_LIMIT = 2000;
const DEFAULT_ROLE_LIMIT = 100;
const DEFAULT_KEY_LIMIT = 500;
const DEFAULT_RULE_LIMIT = 1000;
const DEFAULT_SIGNAL_LIMIT = 200;
const DEFAULT_MONITOR_LIMIT = 1000;
const DEFAULT_FINDING_LIMIT = 10000;
const DEFAULT_ORG_CONNECTION_LIMIT = 10000;
const DEFAULT_KEY_ROTATION_DAYS = 90;
const DEFAULT_KEY_UNUSED_DAYS = 30;
const DEFAULT_INACTIVE_USER_DAYS = 90;
const DEFAULT_PENDING_INVITE_DAYS = 30;
const DEFAULT_AUDIT_RETENTION_DAYS = 90;
const DEFAULT_SIGNAL_SLA_HOURS = 72;
const DEFAULT_SIGNAL_LOOKBACK_DAYS = 30;
const DEFAULT_MIN_LOG_RETENTION_DAYS = 30;
const DEFAULT_MIN_POSTURE_PASS_RATE = 0.8;
const DEFAULT_MAX_ADMINS = 10;
const DEFAULT_REQUIRED_FRAMEWORKS = ["cis", "pci", "soc2", "hipaa"];
const MAX_EVIDENCE_SAMPLES = 25;
// Cursor endpoints may legitimately return an empty page while more results exist; give up (and report truncation)
// after this many consecutive empty pages so a server that always returns a cursor cannot spin the collector.
const MAX_EMPTY_CURSOR_PAGES = 5;
const MAX_ERROR_DETAIL_CHARS = 240;
const MAX_REDACTION_DEPTH = 64;

const REDACTED = "[REDACTED]";
const CREDENTIAL_LAST_SEGMENTS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwd", "pwd", "passphrase", "apikey", "appkey", "authorization",
  "credential", "credentials", "bearer",
]);
const CREDENTIAL_KEY_QUALIFIERS = new Set(["api", "app", "application", "private", "secret", "signing", "access", "shared", "session", "master", "client", "auth"]);
const URL_KEY_SEGMENTS = new Set(["url", "urls", "uri", "endpoint", "link", "href"]);
const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
const CREDENTIAL_QUERY_PATTERN = /[?&#][^=&#]*(token|secret|password|passwd|key|signature|sig|credential|auth)[^=&#]*=/i;
// Fields on cloud integration records that carry or identify the integration credential; the list endpoints return
// them only in part, but the projection drops them whether or not they are present.
const CLOUD_CREDENTIAL_FIELDS = new Set(["access_key_id", "secret_access_key", "private_key", "private_key_id", "client_secret", "client_id_secret"]);

const KNOWN_SITES = [
  "datadoghq.com",
  "datadoghq.eu",
  "us3.datadoghq.com",
  "us5.datadoghq.com",
  "ap1.datadoghq.com",
  "ap2.datadoghq.com",
  "uk1.datadoghq.com",
  "ddog-gov.com",
  "us2.ddog-gov.com",
];

const SITE_ALIASES: Record<string, string> = {
  us: "datadoghq.com",
  us1: "datadoghq.com",
  eu: "datadoghq.eu",
  eu1: "datadoghq.eu",
  us3: "us3.datadoghq.com",
  us5: "us5.datadoghq.com",
  ap1: "ap1.datadoghq.com",
  ap2: "ap2.datadoghq.com",
  uk1: "uk1.datadoghq.com",
  gov: "ddog-gov.com",
  "us1-fed": "ddog-gov.com",
  "us2-fed": "us2.ddog-gov.com",
  us2gov: "us2.ddog-gov.com",
};

const DEFAULT_ROLE_NAMES = new Set([
  "datadog admin role",
  "datadog standard role",
  "datadog read only role",
]);

const COMPLIANCE_RULE_TYPES = new Set(["cloud_configuration", "infrastructure_configuration"]);

const ADMIN_EQUIVALENT_PERMISSIONS = [
  "org_management",
  "user_access_manage",
  "api_keys_write",
  "org_app_keys_write",
  "service_account_write",
];

const CRITICAL_RULE_CATEGORIES: Array<{ name: string; pattern: RegExp }> = [
  { name: "authentication", pattern: /credential[-_ ]access|TA0006|authentication|brute[-_ ]force|password[-_ ]spray|login|sign[-_ ]?in|mfa/i },
  { name: "privilege_escalation", pattern: /privilege[-_ ]escalation|TA0004|escalat|admin(istrator)? (role|added|granted)|iam policy|assume[-_ ]?role/i },
  { name: "data_exfiltration", pattern: /exfiltration|TA0010|exfil|data transfer|public (bucket|snapshot|ami)|snapshot shared/i },
];

const SECURITY_SOURCE_PATTERN =
  /cloudtrail|guardduty|securityhub|okta|auth0|azure\.activedirectory|azure\.security|gcp\.audit|gcp\.iam|kubernetes\.audit|auditd|sshd|windows\.security|\baudit\b|\bsecurity\b|\biam\b|\bwaf\b|zeek|suricata|crowdstrike|sentinelone/i;

const SECURITY_MONITOR_PATTERN =
  /security|audit|compliance|siem|guardduty|unauthori[sz]ed|\biam\b|brute|intrusion|malware|exfil|privilege|root (login|account)|mfa|waf/i;

const INTEGRATION_HANDLE_PATTERN =
  /^@(pagerduty|opsgenie|slack|webhook|teams|msteams|servicenow|jira|victorops|sns|hipchat|flowdock|oncall)[-_:]/i;

const PII_PATTERN_HINT =
  /credit|card|pan\b|pci|ssn|social security|passport|iban|routing|account number|email|phone|address|pii|personal|health|hipaa|api[-_ ]?key|secret|token|password|aws|gcp|azure/i;

export type DatadogFrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap";

interface FrameworkDescriptor {
  key: DatadogFrameworkKey;
  label: string;
  file: string;
}

export const DATADOG_FRAMEWORKS: ReadonlyArray<FrameworkDescriptor> = [
  { key: "fedramp", label: "FedRAMP", file: "fedramp" },
  { key: "cmmc", label: "CMMC", file: "cmmc" },
  { key: "soc2", label: "SOC 2", file: "soc2" },
  { key: "cis", label: "CIS", file: "cis" },
  { key: "pci_dss", label: "PCI-DSS", file: "pci-dss" },
  { key: "disa_stig", label: "DISA STIG", file: "disa-stig" },
  { key: "irap", label: "IRAP", file: "irap" },
  { key: "ismap", label: "ISMAP", file: "ismap" },
];

interface ControlDescriptor {
  title: string;
  frameworks: Record<DatadogFrameworkKey, string[]>;
}

function control(
  title: string,
  fedramp: string[],
  cmmc: string[],
  soc2: string[],
  cis: string[],
  pciDss: string[],
  disaStig: string[],
  irap: string[],
  ismap: string[],
): ControlDescriptor {
  return {
    title,
    frameworks: { fedramp, cmmc, soc2, cis, pci_dss: pciDss, disa_stig: disaStig, irap, ismap },
  };
}

export const DATADOG_CONTROL_CATALOG: Record<number, ControlDescriptor> = {
  1: control("SAML SSO Enforcement", ["AC-2", "IA-2", "IA-8"], ["AC.L2-3.1.1"], ["CC6.1", "CC6.2"], ["5.1"], ["8.3.1", "8.3.2"], ["SRG-APP-000023"], ["ISM-1546"], ["CPS-9.1"]),
  2: control("MFA Status", ["IA-2(1)", "IA-2(2)"], ["IA.L2-3.5.3"], ["CC6.1", "CC6.6"], ["5.2"], ["8.4.1", "8.4.2"], ["SRG-APP-000149"], ["ISM-1401"], ["CPS-9.2"]),
  3: control("RBAC Configuration (Custom Roles)", ["AC-2", "AC-3", "AC-6"], ["AC.L2-3.1.5", "AC.L2-3.1.6"], ["CC6.1", "CC6.3"], ["5.4"], ["7.1.1", "7.2.1"], ["SRG-APP-000033"], ["ISM-1508"], ["CPS-7.1"]),
  4: control("User Access Review", ["AC-2(3)", "PS-4"], ["AC.L2-3.1.1"], ["CC6.2", "CC6.3"], ["5.3"], ["7.2.4", "7.2.5"], ["SRG-APP-000024"], ["ISM-1503"], ["CPS-7.2"]),
  5: control("API Key Rotation", ["IA-5(1)"], ["IA.L2-3.5.7", "IA.L2-3.5.8"], ["CC6.1"], ["5.5"], ["8.3.9", "8.6.3"], ["SRG-APP-000175"], ["ISM-1590"], ["CPS-9.3"]),
  6: control("Application Key Audit", ["IA-5", "AC-6(10)"], ["IA.L2-3.5.1"], ["CC6.1", "CC6.3"], ["5.6"], ["8.6.1", "8.6.2"], ["SRG-APP-000176"], ["ISM-1551"], ["CPS-9.4"]),
  7: control("Audit Log Enabled and Retained", ["AU-2", "AU-3", "AU-6", "AU-11"], ["AU.L2-3.3.1", "AU.L2-3.3.2"], ["CC7.2", "CC7.3"], ["6.1"], ["10.1", "10.2", "10.7"], ["SRG-APP-000092"], ["ISM-0580"], ["CPS-11.1"]),
  8: control("Security Detection Rules Enabled", ["SI-4", "IR-4"], ["SI.L2-3.14.6", "SI.L2-3.14.7"], ["CC7.2", "CC7.3"], ["6.2"], ["10.4.1", "10.6.1"], ["SRG-APP-000095"], ["ISM-0576"], ["CPS-11.2"]),
  9: control("Security Signals Review", ["IR-4", "IR-5", "IR-6"], ["IR.L2-3.6.1", "IR.L2-3.6.2"], ["CC7.3", "CC7.4"], ["6.3"], ["10.6.1", "12.10.5"], ["SRG-APP-000516"], ["ISM-0123"], ["CPS-12.1"]),
  10: control("Log Pipeline Security", ["AU-2", "AU-3", "SI-4"], ["AU.L2-3.3.1"], ["CC7.2"], ["6.4"], ["10.2.1", "10.3.1"], ["SRG-APP-000093"], ["ISM-0585"], ["CPS-11.3"]),
  11: control("Sensitive Data Scanner", ["SC-28", "SI-4", "MP-6"], ["SC.L2-3.13.16"], ["CC6.1", "CC6.7"], ["3.1"], ["3.4.1", "3.5.1"], ["SRG-APP-000231"], ["ISM-1187"], ["CPS-8.1"]),
  12: control("Cloud Security Posture Management (CSPM)", ["CA-7", "CM-6", "RA-5"], ["CA.L2-3.12.3"], ["CC7.1"], ["2.1"], ["6.3.1", "11.3.1"], ["SRG-APP-000456"], ["ISM-1163"], ["CPS-6.1"]),
  13: control("Compliance Rule Coverage", ["CA-2", "CA-7"], ["CA.L2-3.12.1"], ["CC4.1"], ["2.2"], ["12.1.1"], ["SRG-APP-000454"], ["ISM-1526"], ["CPS-6.2"]),
  14: control("Public Dashboard Restrictions", ["AC-3", "AC-22"], ["AC.L2-3.1.22"], ["CC6.1", "CC6.6"], ["4.1"], ["7.2.1", "9.4.1"], ["SRG-APP-000033"], ["ISM-1532"], ["CPS-7.3"]),
  15: control("IP Allowlisting", ["AC-3", "SC-7"], ["SC.L2-3.13.1", "SC.L2-3.13.6"], ["CC6.1", "CC6.6"], ["4.2"], ["1.3.1", "1.4.1"], ["SRG-APP-000142"], ["ISM-1170"], ["CPS-10.1"]),
  16: control("Session Timeout", ["AC-11", "AC-12"], ["AC.L2-3.1.10", "AC.L2-3.1.11"], ["CC6.1"], ["5.7"], ["8.2.8"], ["SRG-APP-000190"], ["ISM-1164"], ["CPS-9.5"]),
  17: control("Monitor Notification Channels", ["IR-6", "SI-4"], ["IR.L2-3.6.2"], ["CC7.3", "CC7.4"], ["6.5"], ["10.6.1", "12.10.1"], ["SRG-APP-000516"], ["ISM-0125"], ["CPS-12.2"]),
  18: control("Integration Permissions", ["AC-6", "SA-9"], ["AC.L2-3.1.5"], ["CC6.3", "CC9.2"], ["4.3"], ["12.8.1", "12.8.5"], ["SRG-APP-000342"], ["ISM-1567"], ["CPS-7.4"]),
  19: control("Service Account Audit", ["AC-2(1)", "IA-4"], ["AC.L2-3.1.1", "IA.L2-3.5.1"], ["CC6.1", "CC6.2"], ["5.8"], ["8.6.1", "8.6.3"], ["SRG-APP-000163"], ["ISM-1548"], ["CPS-9.6"]),
  20: control("Organization Settings (Data Retention & Sharing)", ["CM-6", "SC-8", "MP-6"], ["CM.L2-3.4.2"], ["CC6.1", "CC7.1"], ["3.2"], ["3.1.1", "9.4.1"], ["SRG-APP-000231"], ["ISM-0289"], ["CPS-8.2"]),
};

export interface DatadogResolvedConfig {
  apiKey: string;
  appKey: string;
  site: string;
  baseUrl: string;
  timeoutMs: number;
  maxRetries: number;
  sourceChain: string[];
}

export interface DatadogAccessSurface {
  name: string;
  /** The request the probe made (path plus the query it sent). */
  endpoint: string;
  permission: string;
  status: "readable" | "forbidden" | "not_readable";
  /** True only when the probe was answered with a readable payload. */
  collected: boolean;
  /** HTTP status observed on a failing probe; null when the probe was read or failed before a response arrived. */
  http_status: number | null;
  /** Records the bounded probe returned (list probes ask for one record); null when the surface was not collected. */
  count: number | null;
  error?: string;
}

export interface DatadogAccessCheckResult {
  status: "healthy" | "limited" | "failed";
  site: string;
  apiKeyValid: boolean;
  keyPairValid: boolean;
  surfaces: DatadogAccessSurface[];
  /** Permissions whose probe was denied (401 or 403). */
  missingPermissions: string[];
  /** Surfaces whose probe failed for a reason other than a permission denial, so their permission state is unknown. */
  permissionStateUnknown: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface DatadogFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface DatadogAssessmentResult {
  category: string;
  title: string;
  summary: JsonRecord;
  findings: DatadogFinding[];
  errors: string[];
}

export interface DatadogAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

/**
 * Result of a paginated read. `truncated` is true whenever the loop stopped before the server ran out of records:
 * the item cap was reached while a next page was still available, the server repeated a page cursor, or empty
 * pages kept arriving with a cursor. `total` is the server-reported count when the endpoint exposes one.
 */
export interface DatadogListing {
  items: JsonRecord[];
  truncated: boolean;
  total?: number;
  truncationReason?: string;
}

interface SurfaceResult<T> {
  value?: T;
  error?: string;
  forbidden?: boolean;
  /** HTTP status the failing request observed; absent for transport errors, timeouts, and readable surfaces. */
  httpStatus?: number;
  truncated?: boolean;
  limit?: number;
  seen?: number;
  total?: number;
  truncationReason?: string;
}

export interface DatadogInventoryGap {
  inventory: string;
  /** The request the run made and saw fail. */
  endpoint: string;
  permission: string;
  http_status: number | null;
  error: string;
  not_checked: string;
  collect_manually: string;
}

/**
 * Written in place of a list (or object) dataset whenever it was denied, errored, or never requested, so a bundle
 * consumer cannot mistake a denial for an empty inventory; a readable-but-empty dataset stays `[]`.
 */
export interface DatadogNotCollectedMarker {
  collected: false;
  /** The HTTP status the failing request observed, "error" for a failure without a response, or "not-collected" when no request was made. */
  status: number | "error" | "not-collected";
  /** The request that failed; null when the dataset was never requested, so no unobserved endpoint is named. */
  endpoint: string | null;
  permission: string;
  error: string;
  reason: "not_readable" | "not_attempted";
}

interface InventoryDescriptor {
  label: string;
  endpoint: string;
  permission: string;
  limitArgument?: string;
  collectManually: string;
}

const INVENTORIES: Record<string, InventoryDescriptor> = {
  organization: { label: "organization settings", endpoint: "GET /api/v1/org", permission: "org_management", collectManually: "Organization Settings > Login Methods and Public Sharing (SAML, strict mode, private_widget_share)" },
  users: { label: "users", endpoint: "GET /api/v2/users", permission: "user_access_read", limitArgument: "user_limit", collectManually: "the user export from Organization Settings > Users" },
  roles: { label: "roles", endpoint: "GET /api/v2/roles", permission: "user_access_read", limitArgument: "role_limit", collectManually: "Organization Settings > Roles with each role's member count" },
  role_permissions: { label: "role_permissions", endpoint: "GET /api/v2/roles/{id}/permissions", permission: "user_access_read", collectManually: "the permission list of each custom role from Organization Settings > Roles" },
  application_keys: { label: "application_keys", endpoint: "GET /api/v2/application_keys", permission: "org_app_keys_read", limitArgument: "key_limit", collectManually: "Organization Settings > Application Keys with owner, scopes, created, and last used dates" },
  org_configs: { label: "org_configs", endpoint: "GET /api/v2/org_configs", permission: "none", collectManually: "Organization Settings > Preferences" },
  api_keys: { label: "api_keys", endpoint: "GET /api/v2/api_keys", permission: "api_keys_read", limitArgument: "key_limit", collectManually: "Organization Settings > API Keys with created and last used dates" },
  shared_dashboards: { label: "shared_dashboards", endpoint: "GET /api/v1/dashboard?filter[shared]=true", permission: "dashboards_read", limitArgument: "the dashboard limit", collectManually: "Dashboards > Shared Dashboards with each share type" },
  ip_allowlist: { label: "ip_allowlist", endpoint: "GET /api/v2/ip_allowlist", permission: "org_management", collectManually: "Organization Settings > Security > IP Allowlist" },
  aws_integrations: { label: "aws_integrations", endpoint: "GET /api/v1/integration/aws", permission: "aws_configuration_read", collectManually: "Integrations > AWS showing each account, its authentication method, and resource collection" },
  gcp_integrations: { label: "gcp_integrations", endpoint: "GET /api/v1/integration/gcp", permission: "gcp_configuration_read", collectManually: "Integrations > Google Cloud Platform showing each project and resource collection" },
  azure_integrations: { label: "azure_integrations", endpoint: "GET /api/v1/integration/azure", permission: "azure_configuration_read", collectManually: "Integrations > Azure showing each tenant and resource collection" },
  security_rules: { label: "security_rules", endpoint: "GET /api/v2/security_monitoring/rules", permission: "security_monitoring_rules_read", limitArgument: "rule_limit", collectManually: "Security > Cloud SIEM > Detection Rules and Security > Cloud Security > Compliance rule lists" },
  security_signals: { label: "security_signals", endpoint: "GET /api/v2/security_monitoring/signals", permission: "security_monitoring_signals_read", limitArgument: "signal_limit", collectManually: "Security > Signals filtered to open high and critical signals" },
  posture_findings_fail: { label: "posture_findings_fail", endpoint: "GET /api/v2/posture_management/findings?filter[evaluation]=fail", permission: "security_monitoring_findings_read", limitArgument: "finding_limit", collectManually: "Security > Cloud Security > Compliance showing the failing finding count" },
  posture_findings_pass: { label: "posture_findings_pass", endpoint: "GET /api/v2/posture_management/findings?filter[evaluation]=pass", permission: "security_monitoring_findings_read", limitArgument: "finding_limit", collectManually: "Security > Cloud Security > Compliance showing the passing finding count" },
  monitors: { label: "monitors", endpoint: "GET /api/v1/monitor", permission: "monitors_read", limitArgument: "monitor_limit", collectManually: "Monitors > Manage Monitors filtered to security monitors with their notification handles" },
  audit_events_oldest: { label: "audit_events_oldest", endpoint: "GET /api/v2/audit/events (oldest event in the retention window)", permission: "audit_logs_read", collectManually: "Organization Settings > Audit Trail showing the retention setting" },
  audit_events_recent: { label: "audit_events_recent", endpoint: "GET /api/v2/audit/events (last 7 days)", permission: "audit_logs_read", collectManually: "Organization Settings > Audit Trail showing recent events" },
  log_pipelines: { label: "log_pipelines", endpoint: "GET /api/v1/logs/config/pipelines", permission: "logs_read_config", collectManually: "Logs > Configuration > Pipelines" },
  log_indexes: { label: "log_indexes", endpoint: "GET /api/v1/logs/config/indexes", permission: "logs_read_config", collectManually: "Logs > Configuration > Indexes with retention and exclusion filters" },
  log_archives: { label: "log_archives", endpoint: "GET /api/v2/logs/config/archives", permission: "logs_read_archives", collectManually: "Logs > Configuration > Archives with each destination and state" },
  sensitive_data_scanner: { label: "sensitive_data_scanner", endpoint: "GET /api/v2/sensitive-data-scanner/config", permission: "data_scanner_read", collectManually: "Organization Settings > Sensitive Data Scanner" },
  org_connections: { label: "org_connections", endpoint: "GET /api/v2/org_connections", permission: "org_connections_read", limitArgument: "the org connection limit", collectManually: "Organization Settings > Org Connections" },
};

function inventoryDescriptor(inventory: string): InventoryDescriptor {
  return INVENTORIES[inventory] ?? { label: inventory, endpoint: inventory, permission: "unknown", collectManually: `the ${inventory} inventory from the Datadog console` };
}

export interface DatadogRolePermissionFailure {
  role: string;
  error: string;
  /** The per-role request that failed; null when no request was made (the role record had no id). */
  endpoint: string | null;
  http_status: number | null;
}

export interface DatadogIdentitySnapshot {
  organization: SurfaceResult<JsonRecord>;
  users: SurfaceResult<JsonRecord[]>;
  roles: SurfaceResult<JsonRecord[]>;
  rolePermissions: Record<string, string[]>;
  rolePermissionErrors: Record<string, DatadogRolePermissionFailure>;
  applicationKeys: SurfaceResult<JsonRecord>;
  orgConfigs: SurfaceResult<JsonRecord[]>;
  errors: string[];
}

export interface DatadogAccessControlSnapshot {
  organization: SurfaceResult<JsonRecord>;
  apiKeys: SurfaceResult<JsonRecord[]>;
  applicationKeys: SurfaceResult<JsonRecord>;
  sharedDashboards: SurfaceResult<JsonRecord[]>;
  ipAllowlist: SurfaceResult<JsonRecord>;
  awsIntegrations: SurfaceResult<JsonRecord[]>;
  gcpIntegrations: SurfaceResult<JsonRecord[]>;
  azureIntegrations: SurfaceResult<JsonRecord[]>;
  errors: string[];
}

export interface DatadogSecurityMonitoringSnapshot {
  rules: SurfaceResult<JsonRecord[]>;
  signals: SurfaceResult<JsonRecord[]>;
  postureFailing: SurfaceResult<JsonRecord>;
  posturePassing: SurfaceResult<JsonRecord>;
  monitors: SurfaceResult<JsonRecord[]>;
  awsIntegrations: SurfaceResult<JsonRecord[]>;
  gcpIntegrations: SurfaceResult<JsonRecord[]>;
  azureIntegrations: SurfaceResult<JsonRecord[]>;
  errors: string[];
}

export interface DatadogDataProtectionSnapshot {
  organization: SurfaceResult<JsonRecord>;
  oldestAuditEvents: SurfaceResult<JsonRecord[]>;
  recentAuditEvents: SurfaceResult<JsonRecord[]>;
  pipelines: SurfaceResult<JsonRecord[]>;
  indexes: SurfaceResult<JsonRecord[]>;
  archives: SurfaceResult<JsonRecord[]>;
  sensitiveDataScanner: SurfaceResult<JsonRecord>;
  orgConnections: SurfaceResult<JsonRecord[]>;
  errors: string[];
}

export interface DatadogIdentityOptions {
  now?: Date;
  userLimit?: number;
  roleLimit?: number;
  /** Cap on the application keys read for service account key rotation (DD-19); shared with the access control assessment's key_limit. */
  keyLimit?: number;
  maxAdmins?: number;
  inactiveDays?: number;
  pendingInviteDays?: number;
  keyRotationDays?: number;
  serviceAccountPattern?: string;
}

export interface DatadogAccessControlOptions {
  now?: Date;
  keyLimit?: number;
  keyRotationDays?: number;
  keyUnusedDays?: number;
}

export interface DatadogSecurityMonitoringOptions {
  now?: Date;
  ruleLimit?: number;
  signalLimit?: number;
  signalSlaHours?: number;
  signalLookbackDays?: number;
  monitorLimit?: number;
  findingLimit?: number;
  minPosturePassRate?: number;
  requiredFrameworks?: string[];
}

export interface DatadogDataProtectionOptions {
  now?: Date;
  minAuditRetentionDays?: number;
  minLogRetentionDays?: number;
}

export type DatadogAssessmentOptions =
  DatadogIdentityOptions
  & DatadogAccessControlOptions
  & DatadogSecurityMonitoringOptions
  & DatadogDataProtectionOptions;

type CheckAccessArgs = {
  api_key?: string;
  app_key?: string;
  site?: string;
  base_url?: string;
  config_file?: string;
  timeout_seconds?: number;
  max_retries?: number;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  role_limit?: number;
  key_limit?: number;
  max_admins?: number;
  inactive_days?: number;
  pending_invite_days?: number;
  key_rotation_days?: number;
  service_account_pattern?: string;
};

type AccessControlArgs = CheckAccessArgs & {
  key_limit?: number;
  key_rotation_days?: number;
  key_unused_days?: number;
};

type SecurityMonitoringArgs = CheckAccessArgs & {
  rule_limit?: number;
  signal_limit?: number;
  signal_sla_hours?: number;
  signal_lookback_days?: number;
  monitor_limit?: number;
  finding_limit?: number;
  min_posture_pass_rate?: number;
  required_frameworks?: string;
};

type DataProtectionArgs = CheckAccessArgs & {
  min_audit_retention_days?: number;
  min_log_retention_days?: number;
};

type ExportAuditBundleArgs = IdentityArgs & AccessControlArgs & SecurityMonitoringArgs & DataProtectionArgs & {
  output_dir?: string;
};

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
    if (/^(true|1|yes|enabled|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asStringArray(value: unknown): string[] {
  return asArray(value).map(asString).filter((item): item is string => Boolean(item));
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function clampFraction(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(Math.max(value, 0), 1);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
}

function attributesOf(record: JsonRecord): JsonRecord {
  return asObject(record.attributes) ?? {};
}

function pageTotal(payload: JsonRecord): number | undefined {
  return asNumber(getNestedValue(payload, ["meta", "page", "total_filtered_count"]))
    ?? asNumber(getNestedValue(payload, ["meta", "page", "total_count"]));
}

function toListing(listing: DatadogListing): DatadogListing {
  return {
    items: listing.items,
    truncated: listing.truncated,
    ...(listing.total === undefined ? {} : { total: listing.total }),
    ...(listing.truncationReason === undefined ? {} : { truncationReason: listing.truncationReason }),
  };
}

/** Accepts either a bare record array or a DatadogListing so collectors can consume both shapes. */
function normalizeListing(value: JsonRecord[] | DatadogListing): DatadogListing {
  if (Array.isArray(value)) return { items: value, truncated: false };
  return {
    items: asRecordArray(value.items),
    truncated: value.truncated === true,
    ...(typeof value.total === "number" ? { total: value.total } : {}),
    ...(typeof value.truncationReason === "string" ? { truncationReason: value.truncationReason } : {}),
  };
}

function keySegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}

/**
 * True for token/secret/password style keys, for `key`/`keys` qualified by api, private, client, and so on, for
 * the `<qualifier>_key_id` identifiers (access_key_id, private_key_id) that name a credential even when they are not
 * the secret half of it, and for a bearer id (`secret_id`, `session_id`, `sid`) whose value authenticates by itself;
 * every other `_id` (`org_id`, `account_id`, `key_id` unqualified) names a thing and keeps its value.
 */
export function isCredentialKey(name: string): boolean {
  if (isBearerIdKey(name)) return true;
  const segments = keySegments(name);
  const last = segments[segments.length - 1];
  if (!last) return false;
  if (CREDENTIAL_LAST_SEGMENTS.has(last)) return true;
  const qualified = (prefix: string[]) => prefix.some((segment) => CREDENTIAL_KEY_QUALIFIERS.has(segment));
  if (last === "key" || last === "keys") return qualified(segments.slice(0, -1));
  if (last === "id" && segments[segments.length - 2] === "key") return qualified(segments.slice(0, -2));
  return false;
}

function isUrlKey(name: string): boolean {
  return keySegments(name).some((segment) => URL_KEY_SEGMENTS.has(segment));
}

/** Reduces an absolute URL to scheme plus host; a relative path survives unless its query string names a credential. */
export function reduceUrl(value: string): string {
  if (ABSOLUTE_URL_PATTERN.test(value)) {
    try {
      const url = new URL(value);
      return `${url.protocol}//${url.host}`;
    } catch {
      return REDACTED;
    }
  }
  return CREDENTIAL_QUERY_PATTERN.test(value) ? REDACTED : value;
}

/**
 * Data-side pass over every collected surface (applied at the collection boundary and again on every file written):
 * the value under any credential-shaped key becomes [REDACTED] whether it is a string, a list, or a nested object
 * (the key survives so an auditor can see the field existed), URL-shaped keys keep only scheme and host, {name, value}
 * pairs whose name is credential-shaped lose their value, and every other string gets the shared scrubber's pattern
 * pass, so a `?token=` query in an allowlist note, a `Bearer` template in a pipeline processor, a `password=` pair in
 * an index filter, a webhook path in a monitor message, or a bare token in a role description or user title goes the
 * way it would in an error message. Booleans, numbers, and nulls pass through; nesting recurses up to a depth cap.
 */
export function redactCredentialValues(value: unknown): unknown {
  return credentialScrubber.scrubData(value, {
    isCredentialKey,
    maxDepth: MAX_REDACTION_DEPTH,
    transformString: (text, key) => (key !== undefined && isUrlKey(key) ? reduceUrl(text) : text),
  });
}

/**
 * The module's credential scrubber (see credential-scrub.ts for the boundary): carriers whatever the value's shape,
 * every configured key registered by a client in every encoded form, real token shapes bare (Datadog API and
 * application keys are hex digests), and Datadog's own key headers.
 */
const credentialScrubber = createCredentialScrubber({ headers: ["dd-api-key", "dd-application-key"] });

/**
 * The scrub applied to every error string before it is recorded anywhere (findings, summaries, analysis objects,
 * access surfaces, the bundle, tool results). Unanchored, idempotent, and independent of which client threw.
 */
export function scrubErrorText(text: string): string {
  return credentialScrubber.scrub(text);
}

const PARSE_ERROR_NOTE = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";

/** JSON.parse quotes a window of the text it rejected, so a SyntaxError is recorded by name only, never by its message. */
function isParseError(error: unknown): boolean {
  return error instanceof SyntaxError || (error instanceof Error && error.name === "SyntaxError");
}

/** The message of any thrown value with the structural parse-error guard applied, before scrubbing. */
function describeThrown(error: unknown): string {
  if (isParseError(error)) return PARSE_ERROR_NOTE;
  return error instanceof Error ? error.message : String(error);
}

function pick(record: JsonRecord, keys: string[]): JsonRecord {
  const projected: JsonRecord = {};
  for (const key of keys) {
    if (record[key] !== undefined) projected[key] = record[key];
  }
  return projected;
}

/** Keeps an API or application key record without its `key` attribute; the list endpoints return `last4`, and the full value is never needed. */
export function projectKeyRecord(key: JsonRecord): JsonRecord {
  const safeAttributes = Object.fromEntries(Object.entries(attributesOf(key)).filter(([name]) => name !== "key"));
  return { ...key, attributes: safeAttributes };
}

/**
 * Cloud integration records are reduced to the identity and collection flags the assessments read. Credential
 * fields (`access_key_id`, `private_key`, `client_secret`, ...) are dropped and listed by name so an auditor can
 * see which were present; the AWS authentication method is derived before the access key id is discarded.
 */
export function projectCloudIntegration(provider: "aws" | "gcp" | "azure", record: JsonRecord): JsonRecord {
  const credentialFields = Object.keys(record).filter((key) => CLOUD_CREDENTIAL_FIELDS.has(key) || isCredentialKey(key)).sort();
  const base = provider === "aws"
    ? {
      ...pick(record, [
        "account_id", "role_name", "cspm_resource_collection_enabled", "resource_collection_enabled",
        "extended_resource_collection_enabled", "metrics_collection_enabled", "host_tags", "filter_tags", "excluded_regions",
      ]),
      authentication: asString(record.role_name) ? "role_delegation" : asString(record.access_key_id) ? "access_key" : "unknown",
    }
    : provider === "gcp"
      ? pick(record, [
        "project_id", "client_email", "is_cspm_enabled", "resource_collection_enabled", "is_security_command_center_enabled",
        "is_resource_change_collection_enabled", "automute", "host_filters",
      ])
      : pick(record, [
        "tenant_name", "client_id", "cspm_enabled", "resource_collection_enabled", "metrics_enabled", "metrics_enabled_default",
        "usage_metrics_enabled", "custom_metrics_enabled", "automute", "host_filters", "app_service_plan_filters", "container_app_filters",
      ]);
  return { ...base, credential_fields_dropped: credentialFields };
}

/** Security signals keep only the timestamp, severity, triage state, rule identity, message, and tags the review reads; the triggering log content is dropped. */
export function projectSecuritySignal(signal: JsonRecord): JsonRecord {
  const attributes = attributesOf(signal);
  const inner = asObject(attributes.attributes) ?? asObject(attributes.custom) ?? {};
  const workflow = asObject(inner.workflow) ?? {};
  const rule = asObject(workflow.rule) ?? {};
  return {
    ...pick(signal, ["id", "type"]),
    attributes: {
      ...pick(attributes, ["timestamp", "message", "status"]),
      tags: asStringArray(attributes.tags),
      attributes: {
        ...pick(inner, ["status"]),
        workflow: {
          triage: pick(asObject(workflow.triage) ?? {}, ["state"]),
          rule: pick(rule, ["id", "name"]),
        },
      },
    },
  };
}

/** Audit events keep the timestamp, service, action, and asset type; the request and actor payload is dropped. */
export function projectAuditEvent(event: JsonRecord): JsonRecord {
  const attributes = attributesOf(event);
  const inner = asObject(attributes.attributes) ?? {};
  const asset = asObject(inner.asset) ?? {};
  return {
    ...pick(event, ["id", "type"]),
    attributes: {
      ...pick(attributes, ["timestamp", "service"]),
      action: asString(inner.action) ?? asString(getNestedValue(inner, ["evt", "name"])) ?? null,
      asset_type: asString(asset.type) ?? null,
    },
  };
}

/** Monitors keep identity, tags, priority, state, and the notification message; the query, options, and creator are dropped. */
export function projectMonitor(monitor: JsonRecord): JsonRecord {
  return pick(monitor, ["id", "name", "type", "tags", "priority", "message", "overall_state", "created", "modified"]);
}

/** Shared dashboards keep identity and timestamps; the author handle and the URL are dropped. */
export function projectDashboard(dashboard: JsonRecord): JsonRecord {
  return pick(dashboard, ["id", "title", "layout_type", "is_read_only", "created_at", "modified_at"]);
}

/** Posture findings keep the evaluation, status, rule, and resource identity; the captured resource configuration is dropped. */
export function projectPostureFinding(item: JsonRecord): JsonRecord {
  const attributes = attributesOf(item);
  return {
    ...pick(item, ["id", "type"]),
    attributes: {
      ...pick(attributes, ["evaluation", "status", "resource_type", "resource", "evaluation_changed_at"]),
      rule: pick(asObject(attributes.rule) ?? {}, ["id", "name"]),
    },
  };
}

function projectPostureFindings(result: JsonRecord): JsonRecord {
  return { ...result, data: asRecordArray(result.data).map(projectPostureFinding) };
}

function parseDate(value: unknown): Date | undefined {
  if (value instanceof Date) return value;
  if (typeof value === "number" && Number.isFinite(value)) {
    return new Date(value < 1e12 ? value * 1000 : value);
  }
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysBetween(from: Date | undefined, to: Date): number | undefined {
  if (!from) return undefined;
  return Math.floor((to.getTime() - from.getTime()) / 86_400_000);
}

function hoursBetween(from: Date | undefined, to: Date): number | undefined {
  if (!from) return undefined;
  return Math.floor((to.getTime() - from.getTime()) / 3_600_000);
}

function sample<T>(items: T[]): T[] {
  return items.slice(0, MAX_EVIDENCE_SAMPLES);
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "datadog";
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

export function normalizeDatadogSite(rawSite: string | undefined): string {
  const trimmed = (rawSite ?? "").trim().toLowerCase();
  if (!trimmed) return DEFAULT_SITE;
  const alias = SITE_ALIASES[trimmed];
  if (alias) return alias;

  let host = trimmed;
  if (/^https?:\/\//.test(host)) {
    host = new URL(host).hostname;
  }
  host = host.replace(/\/+$/, "");
  host = host.replace(/^(api|app|http-intake\.logs)\./, "");
  if (KNOWN_SITES.includes(host)) return host;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) {
    throw new Error(`Unrecognized Datadog site: ${rawSite}. Use a value such as datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, ap1.datadoghq.com, or ddog-gov.com.`);
  }
  return host;
}

export function datadogBaseUrlForSite(site: string): string {
  return `https://api.${normalizeDatadogSite(site)}`;
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

interface DogrcOverlay {
  apiKey?: string;
  appKey?: string;
  apiHost?: string;
}

function parseDogrc(content: string): DogrcOverlay {
  let section = "";
  const overlay: DogrcOverlay = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sectionMatch = /^\[(.+)\]$/.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1].trim().toLowerCase();
      continue;
    }
    if (section !== "connection") continue;
    const separator = line.indexOf("=");
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key === "apikey") overlay.apiKey = value || undefined;
    if (key === "appkey") overlay.appKey = value || undefined;
    if (key === "api_host") overlay.apiHost = value || undefined;
  }
  return overlay;
}

const ERRNO_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;

/**
 * Raised when the .dogrc file cannot be read or parsed. The file carries the API and application keys, so the
 * message is fixed text built only from the path and an errno code validated against ERRNO_CODE_PATTERN: neither
 * the filesystem's message nor anything the parser might throw is ever interpolated. parseDogrc itself never
 * throws (a line it cannot read is skipped, never quoted), so the parse arm is a guard against every thrown value.
 */
export class DatadogConfigFileError extends Error {
  readonly path: string;
  /** The errno code of a read failure, or INVALID_INI for a parse failure. */
  readonly code: string;
  /** Always undefined: the dogshell INI parser has no structured position to report. */
  readonly line: number | undefined;

  constructor(step: "read" | "parse", path: string, code: string | undefined) {
    super(step === "read"
      ? `Unable to read Datadog config file ${path}${code ? ` (${code})` : ""}`
      : `Unable to parse Datadog config file: invalid INI in ${path}`);
    this.name = "DatadogConfigFileError";
    this.path = path;
    this.code = code ?? "UNKNOWN";
    this.line = undefined;
  }
}

/** The errno code of a filesystem error, only when it has the strict E[A-Z0-9_] shape; anything else is dropped. */
function errnoCode(error: unknown): string | undefined {
  const code = asString(asObject(error)?.code);
  return code && ERRNO_CODE_PATTERN.test(code) ? code : undefined;
}

/** Read step of the config loader: any filesystem failure surfaces as fixed text with the validated errno code only. */
function readDogrcSource(location: string): string {
  try {
    return readFileSync(location, "utf8");
  } catch (error) {
    throw new DatadogConfigFileError("read", location, errnoCode(error));
  }
}

/** Parse step of the config loader: every thrown value becomes fixed text naming only the path. */
function parseDogrcSource(location: string, source: string): DogrcOverlay {
  try {
    return parseDogrc(source);
  } catch {
    throw new DatadogConfigFileError("parse", location, "INVALID_INI");
  }
}

/**
 * Loads the .dogrc overlay. A missing default file is simply absent; a path named explicitly (argument or
 * environment) that cannot be read is an error, so a typo in the path is not silently ignored.
 */
function readDogrc(location: string, explicit: boolean): DogrcOverlay | undefined {
  if (!explicit && !existsSync(location)) return undefined;
  return parseDogrcSource(location, readDogrcSource(location));
}

export function resolveDatadogConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
): DatadogResolvedConfig {
  const sourceChain: string[] = [];
  const explicitConfigPath = asString(input.config_file)
    ?? asString(env.DD_CONFIG_FILE)
    ?? asString(env.DATADOG_CONFIG_FILE);
  const configPath = explicitConfigPath ?? join(homeDir, ".dogrc");
  const fileOverlay = readDogrc(configPath, explicitConfigPath !== undefined) ?? {};

  const argApiKey = asString(input.api_key);
  const envApiKey = asString(env.DD_API_KEY) ?? asString(env.DATADOG_API_KEY);
  const apiKey = argApiKey ?? envApiKey ?? fileOverlay.apiKey;
  if (!apiKey) {
    throw new Error("DD_API_KEY (or an api_key argument, or apikey in ~/.dogrc) is required.");
  }
  sourceChain.push(argApiKey ? "arguments-api-key" : envApiKey ? "environment-api-key" : "config-file-api-key");

  const argAppKey = asString(input.app_key);
  const envAppKey = asString(env.DD_APP_KEY) ?? asString(env.DD_APPLICATION_KEY) ?? asString(env.DATADOG_APP_KEY);
  const appKey = argAppKey ?? envAppKey ?? fileOverlay.appKey;
  if (!appKey) {
    throw new Error("DD_APP_KEY (or an app_key argument, or appkey in ~/.dogrc) is required because every read endpoint needs an application key.");
  }
  sourceChain.push(argAppKey ? "arguments-app-key" : envAppKey ? "environment-app-key" : "config-file-app-key");

  const argSite = asString(input.site);
  const envSite = asString(env.DD_SITE) ?? asString(env.DATADOG_SITE);
  const site = normalizeDatadogSite(argSite ?? envSite ?? DEFAULT_SITE);
  sourceChain.push(argSite ? "arguments-site" : envSite ? "environment-site" : "default-site");

  const argBaseUrl = asString(input.base_url);
  const envBaseUrl = asString(env.DD_HOST) ?? asString(env.DATADOG_HOST);
  const explicitBaseUrl = argBaseUrl ?? envBaseUrl ?? fileOverlay.apiHost;
  const baseUrl = explicitBaseUrl ? normalizeBaseUrl(explicitBaseUrl) : datadogBaseUrlForSite(site);
  if (explicitBaseUrl) {
    sourceChain.push(argBaseUrl ? "arguments-base-url" : envBaseUrl ? "environment-base-url" : "config-file-base-url");
  }

  return {
    apiKey,
    appKey,
    site,
    baseUrl,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.DD_TIMEOUT)),
    maxRetries: clampNumber(asNumber(input.max_retries) ?? asNumber(env.DD_MAX_RETRIES), DEFAULT_MAX_RETRIES, 0, 10),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class DatadogApiError extends Error {
  readonly status: number;
  readonly path: string;

  constructor(message: string, status: number, path: string) {
    // The constructor is the last stop before the message can escape, so the unanchored scrub runs here as well as at the sink.
    super(scrubErrorText(message));
    this.name = "DatadogApiError";
    this.status = status;
    this.path = path;
  }
}

function datadogErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const errors = asArray(object.errors).map((item) =>
    asString(item) ?? asString(asObject(item)?.detail) ?? asString(asObject(item)?.title),
  );
  // Scrub first, cut second: a cut through a configured key would leave a fragment the whole-value rule no longer
  // matches, so the documented detail loses its credentials at full length and is truncated afterwards.
  const summary = scrubErrorText([asString(object.message), asString(object.error), ...errors]
    .filter((item): item is string => Boolean(item))
    .join("; "));
  if (!summary) return undefined;
  return summary.length > MAX_ERROR_DETAIL_CHARS ? `${summary.slice(0, MAX_ERROR_DETAIL_CHARS)}... (truncated)` : summary;
}

/**
 * Describes a body that is not Datadog's documented JSON error shape by status, content type, and length instead of
 * echoing it, so HTML or proxy pages (which can carry bearer, session, and key values) never reach an error string.
 */
/** "403 Forbidden" or just "403" when the response carried no status text. */
function statusLine(response: Response): string {
  return response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
}

/**
 * The documented shape of a successful body per endpoint: the v2 API answers with a `data` container, the v1 API with
 * bare arrays or named containers (`orgs`, `dashboards`, `indexes`, `accounts`, `pipeline_ids`), and the key checks
 * with `valid`. A 2xx whose body is empty or of another shape (a status page, a different service behind the same
 * host) is a failed read of that request, recorded with the 200 the server sent, never an empty inventory.
 */
type DatadogResponseShape = { kind: "array" } | { kind: "object"; documentedKeys: readonly string[] } | { kind: "any-object" };

const ARRAY_SHAPE: DatadogResponseShape = { kind: "array" };
const DATA_SHAPE: DatadogResponseShape = { kind: "object", documentedKeys: ["data"] };
// The key-pair check is judged by its status alone and its body is not documented beyond being a JSON object.
const ANY_OBJECT_SHAPE: DatadogResponseShape = { kind: "any-object" };
function objectShape(...documentedKeys: string[]): DatadogResponseShape {
  return { kind: "object", documentedKeys };
}

function matchesResponseShape(payload: unknown, shape: DatadogResponseShape): boolean {
  switch (shape.kind) {
    case "array":
      return Array.isArray(payload);
    case "object": {
      const record = asObject(payload);
      return record !== undefined && shape.documentedKeys.some((key) => key in record);
    }
    case "any-object":
      return asObject(payload) !== undefined;
    default: {
      const exhaustive: never = shape;
      return exhaustive;
    }
  }
}

function describeResponseShape(shape: DatadogResponseShape): string {
  switch (shape.kind) {
    case "array":
      return "JSON array";
    case "object":
      return `JSON object (one of ${shape.documentedKeys.join(", ")})`;
    case "any-object":
      return "JSON object";
    default: {
      const exhaustive: never = shape;
      return exhaustive;
    }
  }
}

function describeOpaqueBody(response: Response, rawText: string, parsedJson: boolean): string {
  const contentType = (response.headers.get("content-type") ?? "").split(";")[0].trim() || "untyped";
  const size = `${contentType}, ${Buffer.byteLength(rawText, "utf8")} bytes, not echoed`;
  return parsedJson
    ? `${statusLine(response)}: JSON body without a documented error field (${size})`
    : `${statusLine(response)}: non-JSON body (${size})`;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export class DatadogApiClient {
  private readonly config: DatadogResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: SleepImpl;

  constructor(
    config: DatadogResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleepImpl?: SleepImpl;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? defaultSleep;
    // The configured keys are scrubbed from every recorded error string in every encoded form from here on.
    credentialScrubber.registerSecrets([config.apiKey, config.appKey]);
  }

  getResolvedConfig(): DatadogResolvedConfig {
    return this.config;
  }

  /** Configured secrets first, then the configuration-independent scrub, so no client error string can bypass either. */
  private redact(message: string): string {
    let output = message;
    for (const secret of [this.config.apiKey, this.config.appKey]) {
      if (secret.length >= 8) output = output.split(secret).join(REDACTED);
    }
    return scrubErrorText(output);
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private buildHeaders(hasBody: boolean): Headers {
    const headers = new Headers();
    headers.set("accept", "application/json");
    headers.set("DD-API-KEY", this.config.apiKey);
    headers.set("DD-APPLICATION-KEY", this.config.appKey);
    if (hasBody) headers.set("content-type", "application/json");
    return headers;
  }

  private retryDelayMs(response: Response, attempt: number): number {
    if (response.status === 429) {
      const resetSeconds = asNumber(response.headers.get("x-ratelimit-reset") ?? undefined);
      if (resetSeconds !== undefined && resetSeconds >= 0) {
        return Math.min(Math.max(resetSeconds, 1) * 1000, MAX_RATE_LIMIT_WAIT_MS);
      }
      return Math.min(1000 * 2 ** attempt, MAX_RATE_LIMIT_WAIT_MS);
    }
    return Math.min(500 * 2 ** attempt, 10_000);
  }

  private async performRequest(method: string, url: string, body: unknown): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, {
        method,
        headers: this.buildHeaders(body !== undefined),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted) {
        throw new Error(this.redact(`Datadog request timed out after ${this.config.timeoutMs}ms: ${method} ${new URL(url).pathname}`));
      }
      throw new Error(this.redact(`Datadog request failed: ${method} ${new URL(url).pathname}: ${describeThrown(error)}`));
    } finally {
      clearTimeout(timeout);
    }
  }

  async request(method: string, path: string, query: JsonRecord = {}, body: unknown, shape: DatadogResponseShape): Promise<unknown> {
    const url = this.buildUrl(path, query);
    for (let attempt = 0; ; attempt += 1) {
      const response = await this.performRequest(method, url, body);
      const retryable = response.status === 429 || response.status >= 500;
      if (retryable && attempt < this.config.maxRetries) {
        await response.text().catch(() => "");
        await this.sleepImpl(this.retryDelayMs(response, attempt));
        continue;
      }

      const rawText = await response.text();
      let payload: unknown = {};
      let parsedJson = false;
      if (rawText.length > 0) {
        try {
          payload = JSON.parse(rawText) as unknown;
          parsedJson = true;
        } catch {
          payload = {};
        }
      }

      if (!response.ok) {
        // Only Datadog's documented JSON error fields (message, error, errors[]) are echoed; anything else is
        // described by status and length.
        const detail = rawText.length === 0
          ? ""
          : (parsedJson ? datadogErrorSummary(payload) : undefined) ?? describeOpaqueBody(response, rawText, parsedJson);
        throw new DatadogApiError(
          this.redact(`Datadog request failed (${statusLine(response)}) ${method} ${path}${detail ? `: ${detail}` : ""}`),
          response.status,
          path,
        );
      }
      // A success status is not a success by itself: an empty body, a login or proxy page, or JSON of another shape is
      // not an empty inventory. Each is a failed read of this request carrying the status the server sent.
      if (rawText.length === 0) {
        throw new DatadogApiError(
          this.redact(`Datadog request ${method} ${path} returned ${statusLine(response)} with an empty body (0 bytes); the endpoint is not serving the JSON API`),
          response.status,
          path,
        );
      }
      if (!parsedJson) {
        throw new DatadogApiError(
          this.redact(`Datadog request ${method} ${path} returned a ${describeOpaqueBody(response, rawText, false)}; the endpoint is not serving the JSON API`),
          response.status,
          path,
        );
      }
      if (!matchesResponseShape(payload, shape)) {
        throw new DatadogApiError(
          this.redact(`Datadog request ${method} ${path} returned ${statusLine(response)} with a JSON body that is not the documented ${describeResponseShape(shape)} (${Buffer.byteLength(rawText, "utf8")} bytes, not echoed); the endpoint is not serving the JSON API`),
          response.status,
          path,
        );
      }
      return payload;
    }
  }

  async get(path: string, query: JsonRecord, shape: DatadogResponseShape): Promise<unknown> {
    return this.request("GET", path, query, undefined, shape);
  }

  /**
   * Shared exit logic for page-number and offset paging: the listing is complete when a short page arrives or the
   * server-reported total is reached, and truncated when the item cap stops it while the last page was still full.
   */
  private async listPaged(
    limit: number,
    pageSize: number,
    fetchPage: (pageIndex: number, size: number) => Promise<{ data: JsonRecord[]; total?: number; extra?: JsonRecord[] }>,
  ): Promise<DatadogListing & { extra: JsonRecord[] }> {
    const items: JsonRecord[] = [];
    const extra: JsonRecord[] = [];
    const size = Math.min(pageSize, limit);
    let total: number | undefined;
    const truncated = (truncationReason: string) => ({ items, truncated: true, total, truncationReason, extra });
    for (let page = 0; ; page += 1) {
      const result = await fetchPage(page, size);
      total ??= result.total;
      const taken = result.data.slice(0, limit - items.length);
      items.push(...taken);
      extra.push(...(result.extra ?? []));
      // Records left on the page after the cap was filled prove the inventory continues, even on a short last page.
      if (result.data.length > taken.length) return truncated(`the item cap of ${limit} was reached with more records on the same page`);
      if (result.data.length < size) {
        // A short page ends the listing only when the server's own total agrees; a short page under a larger total
        // means records exist that no page delivered, and that is a truncated read, not a complete one.
        if (total !== undefined && items.length < total) {
          return truncated(`the server returned a short page of ${result.data.length} while reporting ${total} total, so ${total - items.length} record(s) could not be read`);
        }
        return { items, truncated: false, total: total ?? items.length, extra };
      }
      if (total !== undefined && items.length >= total) return { items, truncated: false, total, extra };
      if (items.length >= limit) return truncated(`the item cap of ${limit} was reached while the last page was still full`);
    }
  }

  private async listNumbered(
    path: string,
    query: JsonRecord,
    limit: number,
    pageSize: number = V2_PAGE_SIZE,
  ): Promise<DatadogListing> {
    return toListing(await this.listPaged(limit, pageSize, async (page, size) => {
      const payload = asObject(await this.get(path, { ...query, "page[size]": size, "page[number]": page }, DATA_SHAPE)) ?? {};
      return { data: asRecordArray(payload.data), total: pageTotal(payload) };
    }));
  }

  /**
   * Cursor paging never trusts an empty page or a repeated cursor as "done": an empty page with a fresh cursor is
   * followed (up to MAX_EMPTY_CURSOR_PAGES times), a repeated cursor stops the loop as truncated, and reaching the
   * item cap while a next cursor exists is truncated as well.
   */
  private async listCursor(
    path: string,
    query: JsonRecord,
    limit: number,
    cursorPath: string[],
    pageSize: number = CURSOR_PAGE_SIZE,
  ): Promise<DatadogListing> {
    const items: JsonRecord[] = [];
    const size = Math.min(pageSize, limit);
    let cursor: string | undefined;
    let emptyPages = 0;
    for (;;) {
      const payload = asObject(await this.get(path, { ...query, "page[limit]": size, "page[cursor]": cursor }, DATA_SHAPE)) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      const nextCursor = asString(getNestedValue(payload, cursorPath));
      if (!nextCursor) return { items, truncated: false, total: items.length };
      if (nextCursor === cursor) {
        return { items, truncated: true, truncationReason: "the server repeated the same page cursor, so the remaining pages could not be read" };
      }
      if (items.length >= limit) {
        return { items, truncated: true, truncationReason: `the item cap of ${limit} was reached while a next-page cursor was still present` };
      }
      if (data.length === 0) {
        emptyPages += 1;
        if (emptyPages >= MAX_EMPTY_CURSOR_PAGES) {
          return { items, truncated: true, truncationReason: `${MAX_EMPTY_CURSOR_PAGES} consecutive empty pages arrived with a next-page cursor, so the remaining pages could not be read` };
        }
      } else {
        emptyPages = 0;
      }
      cursor = nextCursor;
    }
  }

  async validateApiKey(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v1/validate", {}, objectShape("valid"))) ?? {};
  }

  async validateKeyPair(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/validate_keys", {}, ANY_OBJECT_SHAPE)) ?? {};
  }

  async getOrganization(): Promise<JsonRecord> {
    const payload = asObject(await this.get("/api/v1/org", {}, objectShape("orgs"))) ?? {};
    const orgs = asRecordArray(payload.orgs);
    return orgs[0] ?? payload;
  }

  async listOrgConfigs(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/org_configs", {}, DATA_SHAPE)) ?? {};
    return asRecordArray(payload.data);
  }

  async listOrgConnections(limit = DEFAULT_ORG_CONNECTION_LIMIT): Promise<DatadogListing> {
    return toListing(await this.listPaged(limit, ORG_CONNECTION_PAGE_SIZE, async (page, size) => {
      const payload = asObject(await this.get("/api/v2/org_connections", { limit: size, offset: page * size }, DATA_SHAPE)) ?? {};
      return { data: asRecordArray(payload.data), total: pageTotal(payload) };
    }));
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<DatadogListing> {
    return this.listNumbered("/api/v2/users", {}, limit);
  }

  async listRoles(limit = DEFAULT_ROLE_LIMIT): Promise<DatadogListing> {
    return this.listNumbered("/api/v2/roles", {}, limit);
  }

  async listRolePermissions(roleId: string): Promise<JsonRecord[]> {
    const payload = asObject(await this.get(`/api/v2/roles/${encodeURIComponent(roleId)}/permissions`, {}, DATA_SHAPE)) ?? {};
    return asRecordArray(payload.data);
  }

  async listPermissions(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/permissions", {}, DATA_SHAPE)) ?? {};
    return asRecordArray(payload.data);
  }

  async listApiKeys(limit = DEFAULT_KEY_LIMIT): Promise<DatadogListing> {
    return this.listNumbered("/api/v2/api_keys", { include: "created_by" }, limit);
  }

  /**
   * Returns `{ data, included, truncated, total, truncation_reason }`: the key records, the owner records the
   * `include=owned_by` parameter adds, and the same truncation flags every other listing carries.
   */
  async listApplicationKeys(limit = DEFAULT_KEY_LIMIT): Promise<JsonRecord> {
    const paged = await this.listPaged(limit, V2_PAGE_SIZE, async (page, size) => {
      const payload = asObject(await this.get("/api/v2/application_keys", {
        include: "owned_by",
        "page[size]": size,
        "page[number]": page,
      }, DATA_SHAPE)) ?? {};
      return { data: asRecordArray(payload.data), total: pageTotal(payload), extra: asRecordArray(payload.included) };
    });
    return {
      data: paged.items,
      included: paged.extra,
      truncated: paged.truncated,
      total: paged.total ?? null,
      truncation_reason: paged.truncationReason ?? null,
    };
  }

  async listCurrentUserApplicationKeys(limit = DEFAULT_KEY_LIMIT): Promise<DatadogListing> {
    return this.listNumbered("/api/v2/current_user/application_keys", {}, limit);
  }

  async listAuditEvents(options: {
    from?: string;
    to?: string;
    query?: string;
    sort?: "timestamp" | "-timestamp";
    limit?: number;
  } = {}): Promise<DatadogListing> {
    const limit = clampNumber(options.limit, 100, 1, 5000);
    return this.listCursor("/api/v2/audit/events", {
      "filter[query]": options.query,
      "filter[from]": options.from,
      "filter[to]": options.to,
      sort: options.sort ?? "-timestamp",
    }, limit, ["meta", "page", "after"]);
  }

  async listSecurityRules(limit = DEFAULT_RULE_LIMIT): Promise<DatadogListing> {
    return this.listNumbered("/api/v2/security_monitoring/rules", {}, limit);
  }

  async listSecuritySignals(options: {
    query?: string;
    from?: string;
    to?: string;
    sort?: "timestamp" | "-timestamp";
    limit?: number;
  } = {}): Promise<DatadogListing> {
    const limit = clampNumber(options.limit, DEFAULT_SIGNAL_LIMIT, 1, 5000);
    return this.listCursor("/api/v2/security_monitoring/signals", {
      "filter[query]": options.query,
      "filter[from]": options.from,
      "filter[to]": options.to,
      sort: options.sort ?? "-timestamp",
    }, limit, ["meta", "page", "after"]);
  }

  async listPostureFindings(options: {
    evaluation?: "pass" | "fail";
    status?: string;
    limit?: number;
  } = {}): Promise<JsonRecord> {
    const limit = clampNumber(options.limit, DEFAULT_FINDING_LIMIT, 1, 100000);
    const pageSize = Math.min(FINDING_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    let totalFilteredCount: number | null = null;
    let cursor: string | undefined;
    let truncated = false;
    let truncationReason: string | null = null;
    let capReached = false;
    let emptyPages = 0;
    for (;;) {
      const payload = asObject(await this.get("/api/v2/posture_management/findings", {
        "filter[evaluation]": options.evaluation,
        "filter[status]": options.status,
        "page[limit]": pageSize,
        "page[cursor]": cursor,
      }, DATA_SHAPE)) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      totalFilteredCount ??= asNumber(getNestedValue(payload, ["meta", "page", "total_filtered_count"])) ?? null;
      const nextCursor = asString(getNestedValue(payload, ["meta", "page", "cursor"]));
      // A server-side total makes the count authoritative; the paged data is then only a sample.
      if (totalFilteredCount !== null) break;
      if (!nextCursor) break;
      if (nextCursor === cursor) {
        truncated = true;
        truncationReason = "the server repeated the same page cursor, so the remaining findings could not be counted";
        break;
      }
      if (items.length >= limit) {
        truncated = true;
        capReached = true;
        truncationReason = `finding_limit (${limit}) was reached while a next-page cursor was still present`;
        break;
      }
      if (data.length === 0) {
        emptyPages += 1;
        if (emptyPages >= MAX_EMPTY_CURSOR_PAGES) {
          truncated = true;
          truncationReason = `${MAX_EMPTY_CURSOR_PAGES} consecutive empty pages arrived with a next-page cursor, so the remaining findings could not be counted`;
          break;
        }
      } else {
        emptyPages = 0;
      }
      cursor = nextCursor;
    }
    return {
      data: items,
      total_filtered_count: totalFilteredCount,
      truncated,
      truncation_reason: truncationReason,
      // Only a cap-driven stop yields to a larger finding_limit; a repeated cursor or a run of empty pages does not.
      cap_reached: capReached,
      seen: items.length,
    };
  }

  async getIpAllowlist(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/ip_allowlist", {}, DATA_SHAPE)) ?? {};
  }

  async getSensitiveDataScannerConfig(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/sensitive-data-scanner/config", {}, DATA_SHAPE)) ?? {};
  }

  async listLogPipelines(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/logs/config/pipelines", {}, ARRAY_SHAPE));
  }

  async getLogPipelineOrder(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v1/logs/config/pipeline-order", {}, objectShape("pipeline_ids"))) ?? {};
  }

  async listLogIndexes(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v1/logs/config/indexes", {}, objectShape("indexes"))) ?? {};
    return asRecordArray(payload.indexes);
  }

  async listLogArchives(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/logs/config/archives", {}, DATA_SHAPE)) ?? {};
    return asRecordArray(payload.data);
  }

  async listDashboards(options: { shared?: boolean; limit?: number } = {}): Promise<DatadogListing> {
    const limit = clampNumber(options.limit, DEFAULT_DASHBOARD_LIMIT, 1, 100000);
    return toListing(await this.listPaged(limit, DASHBOARD_PAGE_SIZE, async (page, size) => {
      const payload = asObject(await this.get("/api/v1/dashboard", {
        "filter[shared]": options.shared === undefined ? undefined : String(options.shared),
        count: size,
        start: page * size,
      }, objectShape("dashboards"))) ?? {};
      return { data: asRecordArray(payload.dashboards) };
    }));
  }

  async listMonitors(limit = DEFAULT_MONITOR_LIMIT): Promise<DatadogListing> {
    return toListing(await this.listPaged(limit, MONITOR_PAGE_SIZE, async (page, size) => ({
      data: asRecordArray(await this.get("/api/v1/monitor", { page, page_size: size }, ARRAY_SHAPE)),
    })));
  }

  async listAwsIntegrations(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v1/integration/aws", {}, objectShape("accounts"))) ?? {};
    return asRecordArray(payload.accounts);
  }

  async listGcpIntegrations(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/integration/gcp", {}, ARRAY_SHAPE));
  }

  async listAzureIntegrations(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/integration/azure", {}, ARRAY_SHAPE));
  }
}

type IdentityReader = Pick<
  DatadogApiClient,
  "getResolvedConfig" | "getOrganization" | "listUsers" | "listRoles" | "listRolePermissions" | "listApplicationKeys" | "listOrgConfigs"
>;

type AccessControlReader = Pick<
  DatadogApiClient,
  | "getResolvedConfig"
  | "getOrganization"
  | "listApiKeys"
  | "listApplicationKeys"
  | "listDashboards"
  | "getIpAllowlist"
  | "listAwsIntegrations"
  | "listGcpIntegrations"
  | "listAzureIntegrations"
>;

type SecurityMonitoringReader = Pick<
  DatadogApiClient,
  | "getResolvedConfig"
  | "listSecurityRules"
  | "listSecuritySignals"
  | "listPostureFindings"
  | "listMonitors"
  | "listAwsIntegrations"
  | "listGcpIntegrations"
  | "listAzureIntegrations"
>;

type DataProtectionReader = Pick<
  DatadogApiClient,
  | "getResolvedConfig"
  | "getOrganization"
  | "listAuditEvents"
  | "listLogPipelines"
  | "listLogIndexes"
  | "listLogArchives"
  | "getSensitiveDataScannerConfig"
  | "listOrgConnections"
>;

type AccessCheckReader = Pick<
  DatadogApiClient,
  | "getResolvedConfig"
  | "validateApiKey"
  | "validateKeyPair"
  | "getOrganization"
  | "listOrgConnections"
  | "listUsers"
  | "listRoles"
  | "listApiKeys"
  | "listApplicationKeys"
  | "listAuditEvents"
  | "listSecurityRules"
  | "listSecuritySignals"
  | "listPostureFindings"
  | "getIpAllowlist"
  | "getSensitiveDataScannerConfig"
  | "listLogPipelines"
  | "listLogIndexes"
  | "listLogArchives"
  | "listDashboards"
  | "listMonitors"
  | "listAwsIntegrations"
  | "listGcpIntegrations"
  | "listAzureIntegrations"
>;

type BundleReader = IdentityReader & AccessControlReader & SecurityMonitoringReader & DataProtectionReader & AccessCheckReader;

/** The single point where an error becomes a recorded string: every caller gets the configuration-independent scrub. */
function errorMessage(error: unknown): string {
  return scrubErrorText(describeThrown(error));
}

function isForbidden(error: unknown): boolean {
  return error instanceof DatadogApiError && (error.status === 401 || error.status === 403);
}

function observedStatus(error: unknown): number | undefined {
  return error instanceof DatadogApiError ? error.status : undefined;
}

/**
 * Every surface is scrubbed at the collection boundary, so the records a finding reads, the counts and names a summary
 * renders, and the files a bundle writes all come from the same credential-free copy (see `redactCredentialValues`).
 */
async function loadSurface<T>(label: string, load: () => Promise<T>, errors: string[]): Promise<SurfaceResult<T>> {
  try {
    return { value: redactCredentialValues(await load()) as T };
  } catch (error) {
    const message = errorMessage(error);
    errors.push(`${label}: ${message}`);
    const httpStatus = observedStatus(error);
    return { error: message, forbidden: isForbidden(error), ...(httpStatus === undefined ? {} : { httpStatus }) };
  }
}

/** Carries the failure fields of a surface result forward without its value. */
function failedSurface<T>(result: SurfaceResult<unknown>): SurfaceResult<T> {
  return {
    error: result.error,
    forbidden: result.forbidden,
    ...(result.httpStatus === undefined ? {} : { httpStatus: result.httpStatus }),
  };
}

function describeTruncation(seen: number, total: number | undefined): string {
  return `${seen} of ${total === undefined ? "an unknown total" : total} loaded`;
}

/**
 * Loads a capped inventory. The client is asked for one item beyond the cap so a full inventory can be told from a
 * capped one, and the listing's own truncation flag (cursor stuck, empty pages, cap hit) is honored as well. Every
 * truncation is recorded in `errors` with the seen and total counts and the argument to raise.
 */
async function loadInventory(
  inventory: string,
  limit: number,
  load: (probeLimit: number) => Promise<JsonRecord[] | DatadogListing>,
  errors: string[],
  project: (item: JsonRecord) => JsonRecord = (item) => item,
): Promise<SurfaceResult<JsonRecord[]>> {
  const result = await loadSurface(inventory, () => load(limit + 1), errors);
  if (result.value === undefined) return failedSurface(result);
  const listing = normalizeListing(result.value);
  const items = listing.items.slice(0, limit).map(project);
  const truncated = listing.items.length > limit || listing.truncated;
  const total = listing.total ?? (truncated ? undefined : items.length);
  if (truncated) {
    const reason = listing.items.length > limit ? `more than ${limit} items exist` : listing.truncationReason ?? "the listing stopped early";
    errors.push(`${inventory}: inventory truncated at ${limit} items (${describeTruncation(items.length, total)}; ${reason}); raise ${inventoryDescriptor(inventory).limitArgument ?? "the matching limit argument"} to inspect the full list`);
    return { value: items, truncated: true, limit, seen: items.length, total, truncationReason: reason };
  }
  return { value: items, truncated: false, limit, seen: items.length, total };
}

/** Loads a deliberately bounded sample (no probe, no error entry) but still records whether more records existed. */
async function loadSample(
  inventory: string,
  load: () => Promise<JsonRecord[] | DatadogListing>,
  errors: string[],
  project: (item: JsonRecord) => JsonRecord = (item) => item,
): Promise<SurfaceResult<JsonRecord[]>> {
  const result = await loadSurface(inventory, load, errors);
  if (result.value === undefined) return failedSurface(result);
  const listing = normalizeListing(result.value);
  const items = listing.items.map(project);
  return {
    value: items,
    truncated: listing.truncated,
    seen: items.length,
    total: listing.total ?? (listing.truncated ? undefined : items.length),
    truncationReason: listing.truncationReason,
  };
}

/** The recorded error string, which carries the status the failing request actually observed; no status is invented. */
function describeSurfaceError(surface: SurfaceResult<unknown>): string {
  if (surface.error) return surface.error;
  return surface.httpStatus === undefined ? "the request failed without an error message" : `the request failed with HTTP ${surface.httpStatus}`;
}

/**
 * Records an unreadable inventory. `endpoint` defaults to the descriptor's request line, which is the request the
 * collector issued for that inventory; callers whose request path differs (per-role reads) pass the paths they made.
 */
function inventoryGap(inventory: string, surface: SurfaceResult<unknown>, notChecked: string, endpoint?: string): DatadogInventoryGap {
  const descriptor = inventoryDescriptor(inventory);
  return {
    inventory: descriptor.label,
    endpoint: endpoint ?? descriptor.endpoint,
    permission: descriptor.permission,
    http_status: surface.httpStatus ?? null,
    error: describeSurfaceError(surface),
    not_checked: notChecked,
    collect_manually: descriptor.collectManually,
  };
}

function inventoryGapCaveat(gap: DatadogInventoryGap): string {
  return `Unreadable inventory: ${gap.inventory} (${gap.endpoint}, ${gap.permission}: ${gap.error}), so ${gap.not_checked}. Collect manually: ${gap.collect_manually}.`;
}

/** Returns one gap per unreadable surface, in the order given. */
function unreadableSurfaces(entries: Array<[string, SurfaceResult<unknown>, string]>): DatadogInventoryGap[] {
  return entries
    .filter(([, surface]) => surface.value === undefined)
    .map(([inventory, surface, notChecked]) => inventoryGap(inventory, surface, notChecked));
}

/** Summary text for a control that cannot be verified because one or more of its inventories was unreadable. */
function unreadableSurfacesReason(gaps: DatadogInventoryGap[]): string {
  return `${gaps.map(inventoryGapCaveat).join(" ")} This control could not be verified through the API.`;
}

/** Loads one cloud provider's integration list and drops credential fields from every record before it is kept. */
async function loadCloudIntegrations(
  provider: "aws" | "gcp" | "azure",
  load: () => Promise<JsonRecord[]>,
  errors: string[],
): Promise<SurfaceResult<JsonRecord[]>> {
  return loadSurface(`${provider}_integrations`, async () => (await load()).map((record) => projectCloudIntegration(provider, record)), errors);
}

function withUnreadableEvidence(evidence: JsonRecord, gaps: DatadogInventoryGap[]): JsonRecord {
  return gaps.length > 0 ? { ...evidence, unreadable_inventories: gaps } : evidence;
}

/**
 * Rule 1 corollary gate for a finding that read a secondary inventory it could not load: a `pass` becomes `manual`
 * when the inventory is essential to the control and `warn` otherwise, the summary names the inventory and the
 * console evidence that stands in for it, and the evidence records the gap. Non-passing verdicts keep their status.
 */
function withInventoryGaps(
  item: DatadogFinding,
  gaps: DatadogInventoryGap[],
  options: { essential: boolean; manualEvidence?: string[] },
): DatadogFinding {
  if (gaps.length === 0) return item;
  const existing = asRecordArray(item.evidence?.unreadable_inventories) as unknown as DatadogInventoryGap[];
  const added = gaps.filter((gap) => !existing.some((known) => known.inventory === gap.inventory));
  const evidence = withUnreadableEvidence(item.evidence ?? {}, [...existing, ...added]);
  const caveat = gaps.map(inventoryGapCaveat).join(" ");
  if (item.status !== "pass") return { ...item, summary: `${item.summary} ${caveat}`, evidence };
  if (options.essential) {
    const manualEvidence = options.manualEvidence ?? gaps.map((gap) => `Collect ${gap.collect_manually}.`);
    return {
      ...item,
      status: "manual",
      summary: `${item.summary} ${caveat} Manual evidence required: ${manualEvidence.join(" ")}`,
      evidence: { ...evidence, manual_evidence: manualEvidence },
    };
  }
  return { ...item, status: "warn", summary: `${item.summary} ${caveat}`, evidence };
}

function truncationCaveat(inventory: string, surface: SurfaceResult<unknown>, limitArgument: string): string | undefined {
  if (!surface.truncated) return undefined;
  const seen = surface.seen ?? (Array.isArray(surface.value) ? surface.value.length : 0);
  return `${inventory} inventory is truncated at ${surface.limit ?? "the configured limit of"} items (${describeTruncation(seen, surface.total)}; raise ${limitArgument}), so the verdict covers a partial view and violators from it are neither counted nor named.`;
}

/**
 * Caveats always reach the summary (the reader must see which inventory was partial or undated whatever the verdict);
 * a pass additionally downgrades to warn because a partial view cannot prove compliance.
 */
function withVerdictCaveats(finding: DatadogFinding, caveats: Array<string | undefined>): DatadogFinding {
  const active = caveats.filter((caveat): caveat is string => Boolean(caveat));
  if (active.length === 0) return finding;
  const evidence = { ...finding.evidence, verdict_caveats: active };
  if (finding.status !== "pass") return { ...finding, summary: `${finding.summary} ${active.join(" ")}`, evidence };
  return {
    ...finding,
    status: "warn",
    summary: `${finding.summary} Downgraded to warn: ${active.join(" ")}`,
    evidence,
  };
}

function controlId(controlNumber: number): string {
  return `DD-${String(controlNumber).padStart(2, "0")}`;
}

function buildMappings(controlNumber: number): string[] {
  const descriptor = DATADOG_CONTROL_CATALOG[controlNumber];
  const mappings: string[] = [];
  for (const framework of DATADOG_FRAMEWORKS) {
    for (const reference of descriptor.frameworks[framework.key]) {
      mappings.push(`${framework.label} ${reference}`);
    }
  }
  return mappings;
}

function finding(
  controlNumber: number,
  severity: DatadogFinding["severity"],
  status: DatadogFinding["status"],
  summary: string,
  evidence?: JsonRecord,
): DatadogFinding {
  return {
    id: controlId(controlNumber),
    title: DATADOG_CONTROL_CATALOG[controlNumber].title,
    severity,
    status,
    summary,
    evidence,
    mappings: buildMappings(controlNumber),
  };
}

function manualFinding(
  controlNumber: number,
  severity: DatadogFinding["severity"],
  reason: string,
  evidenceToCollect: string[],
  evidence: JsonRecord = {},
): DatadogFinding {
  return finding(controlNumber, severity, "manual", `${reason} Manual evidence required: ${evidenceToCollect.join(" ")}`, {
    ...evidence,
    manual_evidence: evidenceToCollect,
  });
}

/** Names the observed failure; the status code comes only from the recorded error, never from the branch taken. */
function unreadableReason(label: string, surface: SurfaceResult<unknown>): string {
  return surface.forbidden
    ? `The ${label} surface was denied (${describeSurfaceError(surface)}), so this control could not be verified through the API.`
    : `The ${label} surface was not readable (${describeSurfaceError(surface)}), so this control could not be verified through the API.`;
}

/** True when the surface was read and the listing did not stop early, so counts and names derived from it are complete. */
function isComplete(surface: SurfaceResult<unknown>): boolean {
  return surface.value !== undefined && surface.truncated !== true;
}

/** A count or principal list derived from an inventory renders only when that inventory was read completely. */
function whenComplete<T>(surface: SurfaceResult<unknown>, value: T): T | null {
  return isComplete(surface) ? value : null;
}

/** A value derived from a surface renders only when the surface was read at all. */
function whenRead<T>(surface: SurfaceResult<unknown>, value: T): T | null {
  return surface.value !== undefined ? value : null;
}

/** An aggregate over several surfaces renders only when every one of them was read; a missing input makes the total unknown. */
function whenAllRead<T>(surfaces: SurfaceResult<unknown>[], value: T): T | null {
  return surfaces.every((surface) => surface.value !== undefined) ? value : null;
}

/** A count or list joined across several inventories renders only when every one of them was read completely. */
function whenAllComplete<T>(surfaces: SurfaceResult<unknown>[], value: T): T | null {
  return surfaces.every(isComplete) ? value : null;
}

/** The truncation flag of an inventory; null when the inventory was never read, so a flag cannot default on a scan that did not run. */
function truncatedFlag(surface: SurfaceResult<unknown>): boolean | null {
  return surface.value === undefined ? null : surface.truncated === true;
}

/**
 * Whether a violation was observed: true when at least one violator was found among the records read (a real
 * observation), false only when every set that proves the property was read completely, and null when any of them
 * was partial or unreadable, so "no violation" is never asserted from data that was not fully read.
 */
function violationFlag(sources: Array<SurfaceResult<unknown> | boolean>, observed: number): boolean | null {
  if (observed > 0) return true;
  return sources.every(completeness) ? false : null;
}

/** Records an inventory's read state next to the counts derived from it. */
function inventoryState(inventory: string, surface: SurfaceResult<unknown>): JsonRecord {
  const descriptor = inventoryDescriptor(inventory);
  const read = surface.value !== undefined;
  return {
    inventory: descriptor.label,
    endpoint: descriptor.endpoint,
    read,
    complete: read ? surface.truncated !== true : null,
    seen: read ? surface.seen ?? arrayCount(surface.value) ?? null : null,
    total: read ? surface.total ?? null : null,
    limit: surface.limit ?? null,
    http_status: surface.httpStatus ?? null,
  };
}

function inventoryStates(entries: Array<[string, SurfaceResult<unknown>]>): JsonRecord[] {
  return entries.map(([inventory, surface]) => inventoryState(inventory, surface));
}

function completeness(source: SurfaceResult<unknown> | boolean): boolean {
  return typeof source === "boolean" ? source : isComplete(source);
}

/** "3" when the inventory is complete; otherwise the count stays unknown and only its presence or absence among the read records is stated. */
function countText(source: SurfaceResult<unknown> | boolean, count: number): string {
  if (completeness(source)) return String(count);
  return count > 0 ? "an uncounted number of" : "none of the read";
}

/** "3/7" when the inventory is complete; otherwise the count stays unknown and the seen total is named instead. */
function ratioText(source: SurfaceResult<unknown> | boolean, part: number, whole: number): string {
  if (completeness(source)) return `${part}/${whole}`;
  return part > 0 ? `an uncounted share of the ${whole}` : `none of the ${whole}`;
}

/** " read" when the inventory is partial, so a summary about it speaks of the records read rather than the population. */
function readSuffix(source: SurfaceResult<unknown> | boolean): string {
  return completeness(source) ? "" : " read";
}

function settingEnabled(settings: JsonRecord, key: string): boolean | undefined {
  const value = settings[key];
  const direct = asBoolean(value);
  if (direct !== undefined) return direct;
  return asBoolean(asObject(value)?.enabled);
}

function userAttributes(user: JsonRecord): {
  id: string;
  handle: string;
  status: string;
  disabled: boolean;
  mfaEnabled: boolean | undefined;
  serviceAccount: boolean;
  lastLogin: Date | undefined;
  createdAt: Date | undefined;
  name: string | undefined;
} {
  const attributes = attributesOf(user);
  return {
    id: asString(user.id) ?? asString(attributes.uuid) ?? "unknown",
    handle: asString(attributes.handle) ?? asString(attributes.email) ?? asString(user.id) ?? "unknown",
    status: (asString(attributes.status) ?? "unknown").toLowerCase(),
    disabled: asBoolean(attributes.disabled) === true,
    mfaEnabled: asBoolean(attributes.mfa_enabled),
    serviceAccount: asBoolean(attributes.service_account) === true,
    lastLogin: parseDate(attributes.last_login_time),
    createdAt: parseDate(attributes.created_at),
    name: asString(attributes.name),
  };
}

function roleName(role: JsonRecord): string {
  return asString(attributesOf(role).name) ?? asString(role.id) ?? "role";
}

function isDefaultRole(role: JsonRecord): boolean {
  return DEFAULT_ROLE_NAMES.has(roleName(role).toLowerCase());
}

function permissionName(permission: JsonRecord): string | undefined {
  return asString(attributesOf(permission).name) ?? asString(permission.id);
}

function keyOwnerId(key: JsonRecord): string | undefined {
  return asString(getNestedValue(key, ["relationships", "owned_by", "data", "id"]))
    ?? asString(getNestedValue(key, ["relationships", "created_by", "data", "id"]));
}

function keyLabel(key: JsonRecord): string {
  const attributes = attributesOf(key);
  const name = asString(attributes.name) ?? "unnamed";
  const last4 = asString(attributes.last4);
  return last4 ? `${name} (...${last4})` : name;
}

function isPlaceholderKeyName(name: string | undefined): boolean {
  if (!name || name.length < 3) return true;
  return /^(test|temp|tmp|my|new|default|key|api ?key|app ?key|untitled)\b/i.test(name);
}

function buildServiceAccountPattern(pattern: string | undefined): RegExp {
  if (pattern) {
    try {
      return new RegExp(pattern, "i");
    } catch {
      return /(^|[-_.@])(svc|sa|service|bot|automation|robot|ci|pipeline|terraform|integration)([-_.@]|$)/i;
    }
  }
  return /(^|[-_.@])(svc|sa|service|bot|automation|robot|ci|pipeline|terraform|integration)([-_.@]|$)/i;
}

export async function collectDatadogIdentityData(
  client: IdentityReader,
  options: DatadogIdentityOptions = {},
): Promise<DatadogIdentitySnapshot> {
  const errors: string[] = [];
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 20000);
  const roleLimit = clampNumber(options.roleLimit, DEFAULT_ROLE_LIMIT, 1, 1000);
  const keyLimit = clampNumber(options.keyLimit, DEFAULT_KEY_LIMIT, 1, 10000);

  const [organization, users, roles, applicationKeys, orgConfigs] = await Promise.all([
    loadSurface("organization", () => client.getOrganization(), errors),
    loadInventory("users", userLimit, (probeLimit) => client.listUsers(probeLimit), errors),
    loadInventory("roles", roleLimit, (probeLimit) => client.listRoles(probeLimit), errors),
    loadApplicationKeyInventory(client, keyLimit, errors),
    loadSurface("org_configs", () => client.listOrgConfigs(), errors),
  ]);

  const rolePermissions: Record<string, string[]> = {};
  const rolePermissionErrors: Record<string, DatadogRolePermissionFailure> = {};
  const customRoles = (roles.value ?? []).filter((role) => !isDefaultRole(role));
  await Promise.all(customRoles.map(async (role) => {
    const roleId = asString(role.id);
    if (!roleId) {
      rolePermissionErrors[roleName(role)] = { role: roleName(role), error: "role record has no id, so no permission request was made", endpoint: null, http_status: null };
      return;
    }
    // The path the client requests for this role, recorded so the gap names the request that was actually made.
    const endpoint = `GET /api/v2/roles/${encodeURIComponent(roleId)}/permissions`;
    try {
      const permissions = await client.listRolePermissions(roleId);
      rolePermissions[roleId] = permissions.map(permissionName).filter((name): name is string => Boolean(name));
    } catch (error) {
      const message = errorMessage(error);
      rolePermissionErrors[roleId] = { role: roleName(role), error: message, endpoint, http_status: observedStatus(error) ?? null };
      errors.push(`role_permissions(${roleName(role)}): ${message}`);
    }
  }));

  return { organization, users, roles, rolePermissions, rolePermissionErrors, applicationKeys, orgConfigs, errors };
}

async function loadApplicationKeyInventory(
  client: Pick<DatadogApiClient, "listApplicationKeys">,
  limit: number,
  errors: string[],
): Promise<SurfaceResult<JsonRecord>> {
  const result = await loadSurface("application_keys", () => client.listApplicationKeys(limit + 1), errors);
  if (!result.value) return result;
  const data = asRecordArray(result.value.data);
  const keys = data.slice(0, limit).map(projectKeyRecord);
  const included = asRecordArray(result.value.included);
  const listingTruncated = asBoolean(result.value.truncated) === true;
  const truncated = data.length > limit || listingTruncated;
  const total = asNumber(result.value.total) ?? (truncated ? undefined : keys.length);
  const value = { data: keys, included };
  if (truncated) {
    const reason = data.length > limit ? `more than ${limit} keys exist` : asString(result.value.truncation_reason) ?? "the listing stopped early";
    errors.push(`application_keys: inventory truncated at ${limit} items (${describeTruncation(keys.length, total)}; ${reason}); raise key_limit to inspect the full list`);
    return { value, truncated: true, limit, seen: keys.length, total, truncationReason: reason };
  }
  return { value, truncated: false, limit, seen: keys.length, total };
}

function evaluateSamlControl(snapshot: DatadogIdentitySnapshot): { finding: DatadogFinding; strictSaml: boolean } {
  if (!snapshot.organization.value) {
    return {
      strictSaml: false,
      finding: manualFinding(1, "critical", unreadableReason("organization settings (org_management)", snapshot.organization), [
        "Capture Organization Settings > Login Methods showing SAML enabled, strict mode (password login disabled), and the IdP-initiated login setting.",
      ]),
    };
  }
  const settings = asObject(snapshot.organization.value.settings) ?? {};
  const samlSetting = settingEnabled(settings, "saml");
  const strictSetting = settingEnabled(settings, "saml_strict_mode");
  const samlEnabled = samlSetting === true;
  const strictMode = strictSetting === true;
  const idpInitiatedSetting = settingEnabled(settings, "saml_idp_initiated_login");
  const idpInitiated = idpInitiatedSetting === true;
  const metadataUploaded = asBoolean(settings.saml_idp_metadata_uploaded);
  const evidence = {
    saml_enabled: samlSetting ?? null,
    saml_strict_mode: strictSetting ?? null,
    saml_idp_initiated_login: idpInitiatedSetting ?? null,
    saml_idp_metadata_uploaded: metadataUploaded ?? null,
    saml_can_be_enabled: asBoolean(settings.saml_can_be_enabled) ?? null,
    saml_autocreate_users_domains: getNestedValue(settings, ["saml_autocreate_users_domains", "domains"]) ?? null,
  };
  if (samlSetting === undefined) {
    return {
      strictSaml: false,
      finding: manualFinding(1, "critical", "The organization response did not include the saml setting, so SSO enforcement could not be read.", [
        "Capture Organization Settings > Login Methods showing SAML enabled, strict mode, and the IdP metadata status.",
      ], evidence),
    };
  }
  if (!samlEnabled) {
    return {
      strictSaml: false,
      finding: finding(1, "critical", "fail", "SAML SSO is not enabled for the organization; users authenticate with Datadog passwords.", evidence),
    };
  }
  if (strictSetting === undefined) {
    return {
      strictSaml: false,
      finding: manualFinding(1, "critical", "SAML SSO is enabled but the organization response did not include the saml_strict_mode setting, so password login enforcement could not be read; the partial settings object does not support pass.", [
        "Capture Organization Settings > Login Methods showing that password login is disabled (SAML strict mode on).",
      ], evidence),
    };
  }
  if (!strictMode) {
    return {
      strictSaml: false,
      finding: finding(1, "critical", "warn", "SAML SSO is enabled but strict mode is off, so password login remains available alongside SSO.", evidence),
    };
  }
  return {
    strictSaml: true,
    finding: finding(1, "critical", "pass", `SAML SSO is enabled with strict mode enforced${idpInitiated ? " and IdP-initiated login configured" : ""}.`, evidence),
  };
}

function evaluateMfaControl(snapshot: DatadogIdentitySnapshot, strictSaml: boolean): DatadogFinding {
  if (!snapshot.users.value) {
    return manualFinding(2, "critical", unreadableReason("users (user_access_read)", snapshot.users), [
      "Export the user list from Organization Settings > Users and confirm every active human user shows MFA enabled or authenticates only through the SAML IdP with MFA enforced there.",
    ]);
  }
  const organizationReadable = snapshot.organization.value !== undefined;
  const organizationGaps = unreadableSurfaces([
    ["organization", snapshot.organization, "whether SAML strict mode disables password login for the users below was not checked"],
  ]);
  const users = snapshot.users.value.map(userAttributes);
  const activeHumans = users.filter((user) => user.status === "active" && !user.disabled && !user.serviceAccount);
  const withoutMfa = activeHumans.filter((user) => user.mfaEnabled !== true);
  // A truncated user list proves a violation when one is seen, but the population counts and the names of users
  // lacking MFA are derived from a partial set and stay unknown.
  const evidence = withUnreadableEvidence({
    users_returned: users.length,
    active_human_users: whenComplete(snapshot.users, activeHumans.length),
    users_without_native_mfa: whenComplete(snapshot.users, withoutMfa.length),
    users_without_native_mfa_sample: whenComplete(snapshot.users, sample(withoutMfa.map((user) => user.handle))),
    violation_observed: violationFlag([snapshot.users], withoutMfa.length),
    saml_strict_mode: organizationReadable ? strictSaml : null,
    organization_settings_readable: organizationReadable,
    users_inventory_truncated: truncatedFlag(snapshot.users),
    inventory: inventoryState("users", snapshot.users),
  }, organizationGaps);
  if (users.length === 0) {
    return manualFinding(2, "critical", "The users endpoint returned no users, which cannot be a complete inventory because the application key in use belongs to a user; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Users and confirm every active human user has MFA enabled or authenticates only through a SAML IdP that enforces MFA.",
    ], evidence);
  }
  const caveats = [truncationCaveat("users", snapshot.users, "user_limit")];
  if (activeHumans.length === 0) {
    return withInventoryGaps(
      withVerdictCaveats(
        finding(2, "critical", "warn", `${users.length} users were returned but none is an active human user, so MFA coverage could not be measured; review the disabled and service account population manually.`, evidence),
        caveats,
      ),
      organizationGaps,
      { essential: false },
    );
  }
  if (withoutMfa.length === 0) {
    // Native MFA covers every active human, so the control is judged from the user list alone; an unreadable
    // organization only means the SAML strict-mode context is missing, which the summary must say.
    return withInventoryGaps(
      withVerdictCaveats(
        finding(2, "critical", "pass", `All ${activeHumans.length} active human users${readSuffix(snapshot.users)} have Datadog MFA enabled (mfa_enabled was read as true for each of them).`, evidence),
        caveats,
      ),
      organizationGaps,
      { essential: false },
    );
  }
  const lacking = `${ratioText(snapshot.users, withoutMfa.length, activeHumans.length)} active human users${readSuffix(snapshot.users)}`;
  if (!organizationReadable) {
    // Users without native MFA may still be blocked from password login by SAML strict mode; without the
    // organization settings the verdict cannot be fail or pass.
    return withInventoryGaps(
      withVerdictCaveats(
        manualFinding(
          2,
          "critical",
          `${lacking} lack Datadog-native MFA, and whether SAML strict mode blocks their password login is unknown.`,
          [
            "Capture Organization Settings > Login Methods showing whether SAML strict mode (password login disabled) is on.",
            "If strict mode is on, capture the identity provider sign-on policy for the Datadog application showing MFA is required for every assigned user; otherwise enable Datadog MFA for the users lacking it.",
          ],
          evidence,
        ),
        caveats,
      ),
      organizationGaps,
      { essential: true },
    );
  }
  if (strictSaml) {
    return withVerdictCaveats(
      manualFinding(
        2,
        "critical",
        `${lacking} lack Datadog-native MFA. SAML strict mode disables password login, but the Datadog API does not expose whether the identity provider enforces a second factor, so IdP MFA cannot be confirmed here.`,
        [
          "Capture the identity provider sign-on policy for the Datadog application showing MFA is required for every assigned user (for example an Okta authentication policy or Entra ID conditional access policy) and export the IdP MFA enrollment report for the users lacking native MFA.",
        ],
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(
      2,
      "critical",
      "fail",
      `${lacking} can sign in with a password and do not have MFA enabled.`,
      evidence,
    ),
    caveats,
  );
}

function evaluateRbacControl(snapshot: DatadogIdentitySnapshot, maxAdmins: number, totalUsers: number | undefined): DatadogFinding {
  if (!snapshot.roles.value) {
    return manualFinding(3, "high", unreadableReason("roles (user_access_read)", snapshot.roles), [
      "Export Organization Settings > Roles with each custom role's permission list and the Datadog Admin Role membership count.",
    ]);
  }
  const roles = snapshot.roles.value;
  const customRoles = roles.filter((role) => !isDefaultRole(role));
  const overPrivileged = customRoles
    .map((role) => {
      const roleId = asString(role.id) ?? "";
      const granted = (snapshot.rolePermissions[roleId] ?? []).filter((permission) => ADMIN_EQUIVALENT_PERMISSIONS.includes(permission));
      return { name: roleName(role), granted };
    })
    .filter((role) => role.granted.length > 0);
  const adminRole = roles.find((role) => roleName(role).toLowerCase() === "datadog admin role");
  const adminCount = asNumber(attributesOf(adminRole ?? {}).user_count);
  const adminOverAssigned = adminCount !== undefined && adminCount > maxAdmins;
  const unresolved = customRoles.filter((role) => !((asString(role.id) ?? "") in snapshot.rolePermissions));
  const unresolvedDetail: DatadogRolePermissionFailure[] = unresolved.map((role) =>
    snapshot.rolePermissionErrors[asString(role.id) ?? roleName(role)]
    ?? { role: roleName(role), error: "permissions were not collected", endpoint: null, http_status: null },
  );
  // The per-role permission reads are a secondary inventory of this control; when any of them failed the gap is
  // recorded like every other unreadable surface, naming the per-role requests that were actually made.
  const failedRequests = unresolvedDetail.map((item) => item.endpoint).filter((endpoint): endpoint is string => Boolean(endpoint));
  const observedStatuses = [...new Set(unresolvedDetail.map((item) => item.http_status).filter((status): status is number => status !== null))];
  const permissionGaps = unresolved.length > 0
    ? [inventoryGap(
      "role_permissions",
      {
        error: unresolvedDetail.slice(0, 3).map((item) => `${item.role}: ${item.error}`).join("; "),
        forbidden: unresolvedDetail.every((item) => item.http_status === 401 || item.http_status === 403),
        ...(observedStatuses.length === 1 ? { httpStatus: observedStatuses[0] } : {}),
      },
      `admin-equivalent grants in ${unresolved.length} custom roles could not be ruled out`,
      failedRequests.length > 0 ? failedRequests.slice(0, 3).join(", ") : "no permission request was made",
    )]
    : [];
  // Custom roles in a truncated role list are a partial set: the roles named as over-privileged are real, but
  // the role population counts are unknown. An empty violator list is asserted only when every custom role's
  // permissions were read; otherwise "none" would be derived from the roles whose reads failed.
  const permissionsComplete = unresolved.length === 0;
  const evidence = {
    total_roles: whenComplete(snapshot.roles, roles.length),
    roles_returned: roles.length,
    custom_roles: whenComplete(snapshot.roles, customRoles.length),
    custom_roles_with_admin_equivalent_permissions: whenComplete(
      snapshot.roles,
      overPrivileged.length > 0 || permissionsComplete ? overPrivileged.map((role) => ({ role: role.name, permissions: role.granted })) : null,
    ),
    violation_observed: violationFlag([snapshot.roles, permissionsComplete], overPrivileged.length),
    admin_role_user_count: adminCount ?? null,
    total_users: totalUsers ?? null,
    max_admins: maxAdmins,
    custom_roles_without_permission_detail: unresolved.length,
    custom_roles_without_permission_detail_sample: sample(unresolvedDetail),
    roles_inventory_truncated: truncatedFlag(snapshot.roles),
    inventory: inventoryState("roles", snapshot.roles),
    ...(permissionGaps.length > 0 ? { unreadable_inventories: permissionGaps } : {}),
  };
  if (roles.length === 0) {
    return manualFinding(3, "high", "The roles endpoint returned no roles, which cannot be a complete inventory because every organization has the three managed Datadog roles; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Roles with each custom role's permission list and the Datadog Admin Role membership count.",
    ], evidence);
  }
  const caveats = [truncationCaveat("roles", snapshot.roles, "role_limit")];
  if (overPrivileged.length > 0) {
    return withVerdictCaveats(
      finding(
        3,
        "high",
        "fail",
        `${ratioText(snapshot.roles, overPrivileged.length, customRoles.length)} custom roles${readSuffix(snapshot.roles)} grant admin-equivalent permissions (${ADMIN_EQUIVALENT_PERMISSIONS.join(", ")}).`,
        evidence,
      ),
      [
        unresolved.length > 0 ? `${unresolved.length} custom roles could not have their permissions read.` : undefined,
        ...caveats,
      ],
    );
  }
  if (unresolved.length > 0) {
    return withVerdictCaveats(
      manualFinding(
        3,
        "high",
        `${ratioText(snapshot.roles, unresolved.length, customRoles.length)} custom roles${readSuffix(snapshot.roles)} could not have their permissions read, so admin-equivalent grants could not be ruled out. ${permissionGaps.map(inventoryGapCaveat).join(" ")}`,
        [
          `Export the permission list for ${unresolved.map((role) => roleName(role)).slice(0, MAX_EVIDENCE_SAMPLES).join(", ")} from Organization Settings > Roles and confirm none grants ${ADMIN_EQUIVALENT_PERMISSIONS.join(", ")}.`,
        ],
        evidence,
      ),
      caveats,
    );
  }
  if (adminOverAssigned) {
    return withVerdictCaveats(finding(3, "high", "warn", `Datadog Admin Role is assigned to ${adminCount} users, above the threshold of ${maxAdmins}.`, evidence), caveats);
  }
  return withVerdictCaveats(
    finding(
      3,
      "high",
      "pass",
      `${customRoles.length} custom roles${readSuffix(snapshot.roles)} were checked and none of them grants admin-equivalent permissions; the Datadog Admin Role has ${adminCount ?? "an unknown number of"} members.`,
      evidence,
    ),
    [
      adminCount === undefined ? "The Datadog Admin Role membership count (user_count) was not returned, so admin over-assignment could not be checked." : undefined,
      ...caveats,
    ],
  );
}

function evaluateUserAccessControl(snapshot: DatadogIdentitySnapshot, now: Date, inactiveDays: number, pendingInviteDays: number): DatadogFinding {
  if (!snapshot.users.value) {
    return manualFinding(4, "high", unreadableReason("users (user_access_read)", snapshot.users), [
      `Export the user list and confirm no active user has been inactive for more than ${inactiveDays} days and no invitation has been pending for more than ${pendingInviteDays} days.`,
    ]);
  }
  const users = snapshot.users.value.map(userAttributes);
  const activeHumans = users.filter((user) => user.status === "active" && !user.disabled && !user.serviceAccount);
  const inactive = activeHumans.filter((user) => {
    const reference = user.lastLogin ?? user.createdAt;
    const age = daysBetween(reference, now);
    return age !== undefined && age > inactiveDays;
  });
  const stalePending = users.filter((user) => {
    if (user.status !== "pending") return false;
    const age = daysBetween(user.createdAt, now);
    return age !== undefined && age > pendingInviteDays;
  });
  const disabledUsers = users.filter((user) => user.disabled || user.status === "disabled");
  const undated = activeHumans.filter((user) => user.lastLogin === undefined && user.createdAt === undefined);
  const undatedPending = users.filter((user) => user.status === "pending" && user.createdAt === undefined);
  const evidence = {
    users_returned: users.length,
    total_users: whenComplete(snapshot.users, users.length),
    active_human_users: whenComplete(snapshot.users, activeHumans.length),
    disabled_users: whenComplete(snapshot.users, disabledUsers.length),
    service_accounts: whenComplete(snapshot.users, users.filter((user) => user.serviceAccount).length),
    inactive_days_threshold: inactiveDays,
    inactive_users: whenComplete(snapshot.users, sample(inactive.map((user) => ({ handle: user.handle, last_login: user.lastLogin?.toISOString() ?? null })))),
    inactive_user_count: whenComplete(snapshot.users, inactive.length),
    stale_pending_invitations: whenComplete(snapshot.users, sample(stalePending.map((user) => user.handle))),
    violation_observed: violationFlag([snapshot.users], inactive.length),
    active_users_without_login_or_creation_date: whenComplete(snapshot.users, sample(undated.map((user) => user.handle))),
    pending_invitations_without_creation_date: whenComplete(snapshot.users, sample(undatedPending.map((user) => user.handle))),
    users_inventory_truncated: truncatedFlag(snapshot.users),
    inventory: inventoryState("users", snapshot.users),
  };
  if (users.length === 0) {
    return manualFinding(4, "high", "The users endpoint returned no users, which cannot be a complete inventory because the application key in use belongs to a user; the empty list is treated as unverifiable rather than compliant.", [
      `Export the user list and confirm no active user has been inactive for more than ${inactiveDays} days and no invitation has been pending for more than ${pendingInviteDays} days.`,
    ], evidence);
  }
  const caveats = [
    truncationCaveat("users", snapshot.users, "user_limit"),
    undated.length > 0 ? `${undated.length} active users have neither last_login_time nor created_at and were not counted as recently active.` : undefined,
    undatedPending.length > 0 ? `${undatedPending.length} pending invitations have no created_at and could not be aged.` : undefined,
  ];
  const read = readSuffix(snapshot.users);
  if (inactive.length > 0) {
    return withVerdictCaveats(
      finding(4, "high", "fail", `${ratioText(snapshot.users, inactive.length, activeHumans.length)} active users${read} have not signed in for more than ${inactiveDays} days.`, evidence),
      caveats,
    );
  }
  if (stalePending.length > 0) {
    return withVerdictCaveats(
      finding(4, "high", "warn", `${countText(snapshot.users, stalePending.length)} invitations${read} have been pending for more than ${pendingInviteDays} days.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(4, "high", "pass", `All ${activeHumans.length} active users${read} signed in within ${inactiveDays} days and no invitations${read} are stale.`, evidence),
    caveats,
  );
}

function evaluateSessionTimeoutControl(snapshot: DatadogIdentitySnapshot): DatadogFinding {
  const configNames = (snapshot.orgConfigs.value ?? []).map((item) => asString(attributesOf(item).name)).filter((name): name is string => Boolean(name));
  // The preference list is context only (it proves the session setting is not among the API-exposed configs), so an
  // unreadable list leaves the verdict manual as before but is still named rather than rendered as an empty list.
  const configGaps = unreadableSurfaces([
    ["org_configs", snapshot.orgConfigs, "the organization preference names could not be listed to confirm the session timeout is absent from the API-exposed settings"],
  ]);
  return withInventoryGaps(
    manualFinding(
      16,
      "medium",
      "Datadog does not expose the organization session timeout through the public API.",
      [
        "Capture Organization Settings > Security (or Login Methods) showing the configured session duration and confirm it does not exceed the policy maximum (for example 15 minutes for FedRAMP High or 30 minutes for Moderate).",
      ],
      {
        org_config_names: whenRead(snapshot.orgConfigs, configNames),
        org_configs_readable: Boolean(snapshot.orgConfigs.value),
        inventory: inventoryState("org_configs", snapshot.orgConfigs),
      },
    ),
    configGaps,
    { essential: false },
  );
}

function evaluateServiceAccountControl(snapshot: DatadogIdentitySnapshot, now: Date, keyRotationDays: number, pattern: RegExp): DatadogFinding {
  if (!snapshot.users.value) {
    return manualFinding(19, "medium", unreadableReason("users (user_access_read)", snapshot.users), [
      "List service accounts from Organization Settings > Service Accounts, confirm naming convention, confirm none have interactive logins, and confirm their application keys were rotated within policy.",
    ]);
  }
  const serviceAccounts = snapshot.users.value.map(userAttributes).filter((user) => user.serviceAccount);
  const serviceAccountIds = new Set(serviceAccounts.map((user) => user.id));
  const nonConforming = serviceAccounts.filter((user) => !pattern.test(user.handle) && !pattern.test(user.name ?? ""));
  const interactive = serviceAccounts.filter((user) => user.lastLogin !== undefined);
  // Naming and interactive logins are judged from the user list alone; key rotation needs the application key
  // inventory, so an unreadable key list caps the verdict at warn and the summary says rotation was not checked.
  const keyGaps = unreadableSurfaces([
    ["application_keys", snapshot.applicationKeys, `whether the application keys owned by these service accounts were rotated within ${keyRotationDays} days was not checked`],
  ]);
  const keysRead = snapshot.applicationKeys.value !== undefined;
  const appKeys = asRecordArray(snapshot.applicationKeys.value?.data);
  const serviceKeys = appKeys.filter((key) => {
    const owner = keyOwnerId(key);
    return Boolean(owner && serviceAccountIds.has(owner));
  });
  const staleKeys = serviceKeys.filter((key) => {
    const age = daysBetween(parseDate(attributesOf(key).created_at), now);
    return age !== undefined && age > keyRotationDays;
  });
  const undatedKeys = serviceKeys.filter((key) => parseDate(attributesOf(key).created_at) === undefined);
  // Service account counts and names come from the user list; the key counts join the user list with the key list,
  // so they are known only when both inventories were read completely.
  const usersComplete = isComplete(snapshot.users);
  const keysComplete = usersComplete && isComplete(snapshot.applicationKeys);
  const evidence = {
    users_returned: snapshot.users.value.length,
    service_accounts: whenComplete(snapshot.users, serviceAccounts.length),
    service_account_handles: whenComplete(snapshot.users, sample(serviceAccounts.map((user) => user.handle))),
    non_conforming_names: whenComplete(snapshot.users, sample(nonConforming.map((user) => user.handle))),
    service_accounts_with_login_history: whenComplete(snapshot.users, sample(interactive.map((user) => user.handle))),
    violation_observed: violationFlag([snapshot.users, keysComplete], interactive.length + staleKeys.length),
    service_account_application_keys: keysComplete ? serviceKeys.length : null,
    application_keys_readable: keysRead,
    stale_service_account_keys: keysComplete ? sample(staleKeys.map(keyLabel)) : null,
    service_account_keys_without_created_at: keysComplete ? sample(undatedKeys.map(keyLabel)) : null,
    key_rotation_days: keyRotationDays,
    users_inventory_truncated: truncatedFlag(snapshot.users),
    application_keys_inventory_truncated: truncatedFlag(snapshot.applicationKeys),
    inventories: inventoryStates([["users", snapshot.users], ["application_keys", snapshot.applicationKeys]]),
  };
  if (snapshot.users.value.length === 0) {
    return manualFinding(19, "medium", "The users endpoint returned no users, so the service account population could not be inventoried; the empty list is treated as unverifiable rather than compliant.", [
      "List service accounts from Organization Settings > Service Accounts, confirm naming convention, confirm none have interactive logins, and confirm their application keys were rotated within policy.",
    ], evidence);
  }
  if (serviceAccounts.length === 0) {
    return manualFinding(19, "medium", `None of the ${snapshot.users.value.length} returned users is flagged service_account, so there is nothing to audit through the API; the empty service account inventory is treated as not applicable rather than compliant.`, [
      "Confirm in Organization Settings > Service Accounts that no service accounts exist and document how automation authenticates (personal application keys used by automation should be reviewed under DD-06).",
    ], evidence);
  }
  const caveats = [
    truncationCaveat("users", snapshot.users, "user_limit"),
    truncationCaveat("application_keys", snapshot.applicationKeys, "key_limit"),
    undatedKeys.length > 0 ? `${undatedKeys.length} service account application keys have no created_at and were not counted as rotated.` : undefined,
  ];
  const read = readSuffix(usersComplete);
  if (interactive.length > 0 || staleKeys.length > 0) {
    // A zero is stated only for an inventory that was read completely; a partial or unread key list says nothing
    // about rotation beyond the stale keys that were actually seen.
    const clauses = [
      interactive.length > 0 || usersComplete
        ? `${countText(usersComplete, interactive.length)} service accounts${read} show interactive login history`
        : undefined,
      keysRead && (staleKeys.length > 0 || keysComplete)
        ? `${countText(keysComplete, staleKeys.length)} service account application keys${readSuffix(keysComplete)} are older than ${keyRotationDays} days`
        : undefined,
    ].filter((clause): clause is string => Boolean(clause));
    return withInventoryGaps(
      withVerdictCaveats(finding(19, "medium", "fail", `${clauses.join(" and ")}.`, evidence), caveats),
      keyGaps,
      { essential: false },
    );
  }
  if (nonConforming.length > 0) {
    return withInventoryGaps(
      withVerdictCaveats(
        finding(19, "medium", "warn", `${ratioText(usersComplete, nonConforming.length, serviceAccounts.length)} service accounts${read} do not follow the naming convention.`, evidence),
        caveats,
      ),
      keyGaps,
      { essential: false },
    );
  }
  return withInventoryGaps(
    withVerdictCaveats(
      finding(
        19,
        "medium",
        "pass",
        keyGaps.length > 0
          ? `${serviceAccounts.length} service accounts${read} follow the naming convention and have no interactive logins.`
          : `${serviceAccounts.length} service accounts${read} follow the naming convention, have no interactive logins, and their ${serviceKeys.length} application keys${readSuffix(keysComplete)} are within the rotation window.`,
        evidence,
      ),
      caveats,
    ),
    keyGaps,
    { essential: false },
  );
}

export function evaluateDatadogIdentity(
  snapshot: DatadogIdentitySnapshot,
  options: DatadogIdentityOptions = {},
): DatadogAssessmentResult {
  const now = options.now ?? new Date();
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10000);
  const inactiveDays = clampNumber(options.inactiveDays, DEFAULT_INACTIVE_USER_DAYS, 1, 3650);
  const pendingInviteDays = clampNumber(options.pendingInviteDays, DEFAULT_PENDING_INVITE_DAYS, 1, 3650);
  const keyRotationDays = clampNumber(options.keyRotationDays, DEFAULT_KEY_ROTATION_DAYS, 1, 3650);
  const serviceAccountPattern = buildServiceAccountPattern(options.serviceAccountPattern);

  const saml = evaluateSamlControl(snapshot);
  const totalUsers = snapshot.users.value?.length;
  const findings = [
    saml.finding,
    evaluateMfaControl(snapshot, saml.strictSaml),
    evaluateRbacControl(snapshot, maxAdmins, totalUsers),
    evaluateUserAccessControl(snapshot, now, inactiveDays, pendingInviteDays),
    evaluateSessionTimeoutControl(snapshot),
    evaluateServiceAccountControl(snapshot, now, keyRotationDays, serviceAccountPattern),
  ];

  // Summary counts are evidence too: a count from an unread or truncated inventory renders null, never 0.
  const organizationSettings = asObject(snapshot.organization.value?.settings);
  return {
    category: "identity",
    title: "Datadog identity and access posture",
    summary: {
      users: whenComplete(snapshot.users, totalUsers ?? 0),
      users_seen: whenRead(snapshot.users, totalUsers ?? 0),
      users_complete: whenRead(snapshot.users, isComplete(snapshot.users)),
      roles: whenComplete(snapshot.roles, snapshot.roles.value?.length ?? 0),
      custom_roles: whenComplete(snapshot.roles, snapshot.roles.value?.filter((role) => !isDefaultRole(role)).length ?? 0),
      saml_strict_mode: organizationSettings ? settingEnabled(organizationSettings, "saml_strict_mode") ?? null : null,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshot.errors,
  };
}

export async function assessDatadogIdentity(
  client: IdentityReader,
  options: DatadogIdentityOptions = {},
): Promise<DatadogAssessmentResult> {
  return evaluateDatadogIdentity(await collectDatadogIdentityData(client, options), options);
}

export async function collectDatadogAccessControlData(
  client: AccessControlReader,
  options: DatadogAccessControlOptions = {},
): Promise<DatadogAccessControlSnapshot> {
  const errors: string[] = [];
  const keyLimit = clampNumber(options.keyLimit, DEFAULT_KEY_LIMIT, 1, 10000);
  const [organization, apiKeys, applicationKeys, sharedDashboards, ipAllowlist, awsIntegrations, gcpIntegrations, azureIntegrations] = await Promise.all([
    loadSurface("organization", () => client.getOrganization(), errors),
    loadInventory("api_keys", keyLimit, (probeLimit) => client.listApiKeys(probeLimit), errors, projectKeyRecord),
    loadApplicationKeyInventory(client, keyLimit, errors),
    loadInventory("shared_dashboards", DEFAULT_DASHBOARD_LIMIT, (probeLimit) => client.listDashboards({ shared: true, limit: probeLimit }), errors, projectDashboard),
    loadSurface("ip_allowlist", () => client.getIpAllowlist(), errors),
    loadCloudIntegrations("aws", () => client.listAwsIntegrations(), errors),
    loadCloudIntegrations("gcp", () => client.listGcpIntegrations(), errors),
    loadCloudIntegrations("azure", () => client.listAzureIntegrations(), errors),
  ]);
  return { organization, apiKeys, applicationKeys, sharedDashboards, ipAllowlist, awsIntegrations, gcpIntegrations, azureIntegrations, errors };
}

function evaluateApiKeyControl(snapshot: DatadogAccessControlSnapshot, now: Date, rotationDays: number, unusedDays: number): DatadogFinding {
  if (!snapshot.apiKeys.value) {
    return manualFinding(5, "high", unreadableReason("API keys (api_keys_read)", snapshot.apiKeys), [
      `Export Organization Settings > API Keys and confirm every key was created or rotated within ${rotationDays} days and unused keys were revoked.`,
    ]);
  }
  const keys = snapshot.apiKeys.value;
  const aged = keys.filter((key) => {
    const age = daysBetween(parseDate(attributesOf(key).created_at), now);
    return age !== undefined && age > rotationDays;
  });
  const stale = keys.filter((key) => {
    const attributes = attributesOf(key);
    const lastUsed = parseDate(attributes.date_last_used);
    if (!lastUsed) {
      const created = daysBetween(parseDate(attributes.created_at), now);
      return created !== undefined && created > unusedDays;
    }
    const idle = daysBetween(lastUsed, now);
    return idle !== undefined && idle > unusedDays;
  });
  const placeholders = keys.filter((key) => isPlaceholderKeyName(asString(attributesOf(key).name)));
  const undated = keys.filter((key) => parseDate(attributesOf(key).created_at) === undefined);
  // A truncated key list proves the violations that were seen, but population counts and the names of the keys
  // that violate are derived from a partial set and stay unknown.
  const evidence = {
    keys_returned: keys.length,
    api_keys: whenComplete(snapshot.apiKeys, keys.length),
    rotation_days: rotationDays,
    keys_older_than_rotation_window: whenComplete(snapshot.apiKeys, sample(aged.map(keyLabel))),
    keys_older_than_rotation_window_count: whenComplete(snapshot.apiKeys, aged.length),
    unused_days: unusedDays,
    keys_unused_beyond_threshold: whenComplete(snapshot.apiKeys, sample(stale.map(keyLabel))),
    keys_with_placeholder_names: whenComplete(snapshot.apiKeys, sample(placeholders.map(keyLabel))),
    keys_without_created_at: whenComplete(snapshot.apiKeys, sample(undated.map(keyLabel))),
    keys_without_created_at_count: whenComplete(snapshot.apiKeys, undated.length),
    violation_observed: violationFlag([snapshot.apiKeys], aged.length),
    api_keys_inventory_truncated: truncatedFlag(snapshot.apiKeys),
    inventory: inventoryState("api_keys", snapshot.apiKeys),
  };
  if (keys.length === 0) {
    return manualFinding(5, "high", "The API keys endpoint returned no keys, which cannot be a complete inventory because the API key used for this request must exist; the empty list is treated as unverifiable rather than compliant.", [
      `Export Organization Settings > API Keys and confirm every key was created or rotated within ${rotationDays} days and unused keys were revoked.`,
    ], evidence);
  }
  const caveats = [
    truncationCaveat("api_keys", snapshot.apiKeys, "key_limit"),
    undated.length > 0 ? `${undated.length} API keys have no created_at and were not counted as rotated within the window.` : undefined,
  ];
  const read = readSuffix(snapshot.apiKeys);
  if (aged.length > 0) {
    return withVerdictCaveats(
      finding(5, "high", "fail", `${ratioText(snapshot.apiKeys, aged.length, keys.length)} API keys${read} are older than the ${rotationDays}-day rotation window.`, evidence),
      caveats,
    );
  }
  if (stale.length > 0 || placeholders.length > 0) {
    return withVerdictCaveats(
      finding(
        5,
        "high",
        "warn",
        `${countText(snapshot.apiKeys, stale.length)} API keys${read} have been unused for more than ${unusedDays} days and ${countText(snapshot.apiKeys, placeholders.length)} use placeholder names.`,
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(5, "high", "pass", `All ${keys.length} API keys${read} are within the ${rotationDays}-day rotation window, recently used, and descriptively named.`, evidence),
    caveats,
  );
}

function evaluateApplicationKeyControl(snapshot: DatadogAccessControlSnapshot, now: Date, unusedDays: number): DatadogFinding {
  if (!snapshot.applicationKeys.value) {
    return manualFinding(6, "high", unreadableReason("application keys (org_app_keys_read)", snapshot.applicationKeys), [
      "Export Organization Settings > Application Keys, confirm each key is scoped, owned by an active user or service account, and used recently.",
    ]);
  }
  const keys = asRecordArray(snapshot.applicationKeys.value.data);
  const included = asRecordArray(snapshot.applicationKeys.value.included);
  const ownersById = new Map<string, ReturnType<typeof userAttributes>>();
  for (const item of included) {
    if (asString(item.type) === "users") {
      const owner = userAttributes(item);
      ownersById.set(owner.id, owner);
    }
  }
  const unscoped = keys.filter((key) => asStringArray(attributesOf(key).scopes).length === 0);
  const orphaned = keys.filter((key) => {
    const owner = ownersById.get(keyOwnerId(key) ?? "");
    return Boolean(owner && (owner.disabled || owner.status === "disabled"));
  });
  const idle = keys.filter((key) => {
    const attributes = attributesOf(key);
    const lastUsed = parseDate(attributes.last_used_at);
    const reference = lastUsed ?? parseDate(attributes.created_at);
    const age = daysBetween(reference, now);
    return age !== undefined && age > unusedDays;
  });
  const undated = keys.filter((key) => {
    const attributes = attributesOf(key);
    return parseDate(attributes.last_used_at) === undefined && parseDate(attributes.created_at) === undefined;
  });
  const ownerUnresolved = keys.filter((key) => {
    const owner = keyOwnerId(key);
    return !owner || !ownersById.has(owner);
  });
  const surface = snapshot.applicationKeys;
  const evidence = {
    keys_returned: keys.length,
    application_keys: whenComplete(surface, keys.length),
    unscoped_keys: whenComplete(surface, unscoped.length),
    unscoped_keys_sample: whenComplete(surface, sample(unscoped.map(keyLabel))),
    orphaned_keys: whenComplete(surface, sample(orphaned.map(keyLabel))),
    idle_keys: whenComplete(surface, sample(idle.map(keyLabel))),
    idle_days_threshold: unusedDays,
    owners_resolved: whenComplete(surface, ownersById.size),
    keys_without_resolved_owner: whenComplete(surface, ownerUnresolved.length),
    keys_without_resolved_owner_sample: whenComplete(surface, sample(ownerUnresolved.map(keyLabel))),
    keys_without_any_date: whenComplete(surface, sample(undated.map(keyLabel))),
    violation_observed: violationFlag([surface], orphaned.length),
    application_keys_inventory_truncated: truncatedFlag(surface),
    inventory: inventoryState("application_keys", surface),
  };
  if (keys.length === 0) {
    return manualFinding(6, "high", "The application keys endpoint returned no keys, which cannot be a complete inventory because the application key used for this request must exist; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Application Keys, confirm each key is scoped, owned by an active user or service account, and used recently.",
    ], evidence);
  }
  const caveats = [
    truncationCaveat("application_keys", surface, "key_limit"),
    ownerUnresolved.length > 0
      ? `${ownerUnresolved.length} application keys have no owner record in the response (include=owned_by), so ownership by an active user could not be confirmed for them.`
      : undefined,
    undated.length > 0 ? `${undated.length} application keys have neither last_used_at nor created_at and were not counted as recently used.` : undefined,
  ];
  const read = readSuffix(surface);
  if (orphaned.length > 0) {
    return withVerdictCaveats(
      finding(6, "high", "fail", `${countText(surface, orphaned.length)} application keys${read} belong to disabled users and remain active.`, evidence),
      caveats,
    );
  }
  if (unscoped.length > 0 || idle.length > 0) {
    return withVerdictCaveats(
      finding(
        6,
        "high",
        "warn",
        `${ratioText(surface, unscoped.length, keys.length)} application keys${read} inherit the owner's full permissions (unscoped) and ${countText(surface, idle.length)} have not been used for more than ${unusedDays} days.`,
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(6, "high", "pass", `All ${keys.length} application keys${read} are scoped, owned by active users (${ownersById.size} owner records resolved), and recently used.`, evidence),
    caveats,
  );
}

function evaluateDashboardSharingControl(snapshot: DatadogAccessControlSnapshot): DatadogFinding {
  const organizationReadable = Boolean(snapshot.organization.value);
  const settings = asObject(snapshot.organization.value?.settings) ?? {};
  const widgetShare = organizationReadable ? asBoolean(settings.private_widget_share) : undefined;
  const shared = snapshot.sharedDashboards.value ?? [];
  // Both inventories are essential: the org setting governs widget sharing and the dashboard list governs link
  // sharing, so losing either one leaves the control unverifiable rather than partially passing.
  const gaps = unreadableSurfaces([
    ["organization", snapshot.organization, "whether widget sharing outside the organization (private_widget_share) is disabled was not checked"],
    ["shared_dashboards", snapshot.sharedDashboards, "whether any dashboard is shared through a public link was not checked"],
  ]);
  // Dashboard titles are named only from a complete list: a truncated list proves that sharing exists but cannot
  // enumerate which dashboards are shared.
  const evidence = withUnreadableEvidence({
    shared_dashboards: whenComplete(snapshot.sharedDashboards, shared.length),
    shared_dashboards_seen: whenRead(snapshot.sharedDashboards, shared.length),
    shared_dashboard_titles: whenComplete(snapshot.sharedDashboards, sample(shared.map((dashboard) => asString(dashboard.title) ?? asString(dashboard.id) ?? "dashboard"))),
    private_widget_share: widgetShare ?? null,
    organization_settings_readable: organizationReadable,
    shared_dashboards_readable: Boolean(snapshot.sharedDashboards.value),
    shared_dashboards_inventory_truncated: truncatedFlag(snapshot.sharedDashboards),
    inventories: inventoryStates([["organization", snapshot.organization], ["shared_dashboards", snapshot.sharedDashboards]]),
  }, gaps);
  const publicSharingEvidence = "Capture Organization Settings > Public Sharing showing that sharing widgets outside the organization (private_widget_share) is disabled.";
  const sharedDashboardEvidence = "Open Dashboards > Shared Dashboards and confirm every shared dashboard is invite-only with an email domain allowlist.";
  if (widgetShare === true) {
    return withInventoryGaps(
      finding(14, "high", "fail", "Organization settings allow users to share widgets outside Datadog (private_widget_share enabled).", evidence),
      gaps,
      { essential: true },
    );
  }
  if (gaps.length > 0) {
    return manualFinding(14, "high", unreadableSurfacesReason(gaps), [
      ...(snapshot.sharedDashboards.value ? [] : [sharedDashboardEvidence]),
      publicSharingEvidence,
    ], evidence);
  }
  if (widgetShare === undefined) {
    return manualFinding(14, "high", "The organization response did not include the private_widget_share setting, so widget sharing outside the org could not be confirmed.", [
      publicSharingEvidence,
    ], evidence);
  }
  const caveats = [truncationCaveat("shared_dashboards", snapshot.sharedDashboards, "the dashboard limit")];
  if (shared.length > 0) {
    return withVerdictCaveats(
      finding(
        14,
        "high",
        "warn",
        `${countText(snapshot.sharedDashboards, shared.length)} dashboards${readSuffix(snapshot.sharedDashboards)} are shared through public links; confirm each uses invite-only sharing with an email domain allowlist because the list endpoint does not expose the share type.`,
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(14, "high", "pass", `No dashboards${readSuffix(snapshot.sharedDashboards)} are shared through public links and widget sharing outside the org is disabled (private_widget_share read as false).`, evidence),
    caveats,
  );
}

function cidrPrefixLength(cidr: string): number | undefined {
  const slash = cidr.indexOf("/");
  const isIpv6 = cidr.includes(":");
  if (slash < 0) return isIpv6 ? 128 : 32;
  const prefix = Number(cidr.slice(slash + 1));
  return Number.isFinite(prefix) ? prefix : undefined;
}

function evaluateIpAllowlistControl(snapshot: DatadogAccessControlSnapshot): DatadogFinding {
  if (!snapshot.ipAllowlist.value) {
    return manualFinding(15, "high", unreadableReason("IP allowlist (org_management)", snapshot.ipAllowlist), [
      "Capture Organization Settings > Security > IP Allowlist showing it is enabled and listing every CIDR entry with its justification.",
    ], { enabled: null, entries: null, inventory: inventoryState("ip_allowlist", snapshot.ipAllowlist) });
  }
  const attributes = asObject(getNestedValue(snapshot.ipAllowlist.value, ["data", "attributes"])) ?? {};
  const enabledSetting = asBoolean(attributes.enabled);
  const enabled = enabledSetting === true;
  const entries = asRecordArray(attributes.entries).map((entry) => {
    const entryAttributes = asObject(getNestedValue(entry, ["data", "attributes"])) ?? attributesOf(entry);
    return {
      cidr_block: asString(entryAttributes.cidr_block) ?? "",
      note: asString(entryAttributes.note) ?? null,
    };
  }).filter((entry) => entry.cidr_block.length > 0);
  const broad = entries.filter((entry) => {
    const prefix = cidrPrefixLength(entry.cidr_block);
    const isIpv6 = entry.cidr_block.includes(":");
    return prefix !== undefined && prefix <= (isIpv6 ? 32 : 8);
  });
  const wide = entries.filter((entry) => {
    const prefix = cidrPrefixLength(entry.cidr_block);
    const isIpv6 = entry.cidr_block.includes(":");
    return prefix !== undefined && prefix > (isIpv6 ? 32 : 8) && prefix < (isIpv6 ? 48 : 16);
  });
  const evidence = {
    enabled: enabledSetting ?? null,
    entries: entries.length,
    entry_sample: sample(entries),
    overly_broad_entries: broad.map((entry) => entry.cidr_block),
    wide_entries: wide.map((entry) => entry.cidr_block),
    inventory: inventoryState("ip_allowlist", snapshot.ipAllowlist),
  };
  if (enabledSetting === undefined) {
    return manualFinding(15, "high", "The IP allowlist response did not include the enabled flag, so enforcement could not be confirmed.", [
      "Capture Organization Settings > Security > IP Allowlist showing it is enabled and listing every CIDR entry with its justification.",
    ], evidence);
  }
  if (!enabled) {
    return finding(15, "high", "fail", "The organization IP allowlist is disabled.", evidence);
  }
  if (broad.length > 0) {
    return finding(15, "high", "fail", `The IP allowlist is enabled but ${broad.length} entries are overly broad (/8 or wider): ${broad.map((entry) => entry.cidr_block).join(", ")}.`, evidence);
  }
  if (wide.length > 0) {
    return finding(15, "high", "warn", `The IP allowlist is enabled but ${wide.length} entries are wider than /16 and should be reviewed.`, evidence);
  }
  if (entries.length === 0) {
    return finding(15, "high", "warn", "The IP allowlist reports enabled but returned no CIDR entries, so the enforced range could not be reviewed; confirm the entry list in Organization Settings > Security > IP Allowlist.", evidence);
  }
  return finding(15, "high", "pass", `The IP allowlist is enabled (enabled read as true) with ${entries.length} scoped entries.`, evidence);
}

function awsUsesStaticKey(account: JsonRecord): boolean {
  const authentication = asString(account.authentication);
  if (authentication) return authentication === "access_key";
  return Boolean(asString(account.access_key_id)) && !asString(account.role_name);
}

function evaluateIntegrationPermissionsControl(snapshot: DatadogAccessControlSnapshot): DatadogFinding {
  const aws = snapshot.awsIntegrations.value ?? [];
  const gcp = snapshot.gcpIntegrations.value ?? [];
  const azure = snapshot.azureIntegrations.value ?? [];
  const awsStaticKeys = aws.filter(awsUsesStaticKey);
  const gaps = unreadableSurfaces([
    ["aws_integrations", snapshot.awsIntegrations, "AWS accounts and their authentication method were not inventoried"],
    ["gcp_integrations", snapshot.gcpIntegrations, "GCP projects were not inventoried"],
    ["azure_integrations", snapshot.azureIntegrations, "Azure tenants were not inventoried"],
  ]);
  const cloudSurfaces = [snapshot.awsIntegrations, snapshot.gcpIntegrations, snapshot.azureIntegrations];
  const evidence = {
    aws_accounts: whenRead(snapshot.awsIntegrations, aws.length),
    aws_accounts_with_static_key_authentication: whenRead(snapshot.awsIntegrations, sample(awsStaticKeys.map((account) => asString(account.account_id) ?? "aws-account"))),
    aws_accounts_with_static_key_authentication_count: whenRead(snapshot.awsIntegrations, awsStaticKeys.length),
    aws_accounts_using_role_delegation: whenRead(snapshot.awsIntegrations, aws.filter((account) => Boolean(asString(account.role_name))).length),
    gcp_projects: whenRead(snapshot.gcpIntegrations, gcp.length),
    azure_tenants: whenRead(snapshot.azureIntegrations, azure.length),
    cloud_integrations: whenAllRead(cloudSurfaces, aws.length + gcp.length + azure.length),
    surfaces_readable: {
      aws: Boolean(snapshot.awsIntegrations.value),
      gcp: Boolean(snapshot.gcpIntegrations.value),
      azure: Boolean(snapshot.azureIntegrations.value),
    },
    inventories: inventoryStates([
      ["aws_integrations", snapshot.awsIntegrations],
      ["gcp_integrations", snapshot.gcpIntegrations],
      ["azure_integrations", snapshot.azureIntegrations],
    ]),
  };
  const inventoried = [
    snapshot.awsIntegrations.value ? `${aws.length} AWS` : undefined,
    snapshot.gcpIntegrations.value ? `${gcp.length} GCP` : undefined,
    snapshot.azureIntegrations.value ? `${azure.length} Azure` : undefined,
  ].filter((item): item is string => Boolean(item));
  const reason = awsStaticKeys.length > 0
    ? `${awsStaticKeys.length} AWS integrations authenticate with static access keys instead of IAM role delegation, and the cloud-side IAM policies and webhook targets are not visible through the Datadog API.`
    : `${inventoried.length > 0 ? `${inventoried.join(", ")} integrations were inventoried` : "No cloud integration surface was readable"}, and the cloud-side IAM policies and webhook targets are not visible through the Datadog API.`;
  return withInventoryGaps(
    manualFinding(18, "medium", reason, [
      "Export the IAM role or service account policy attached to each cloud integration and confirm it is read-only (for example the Datadog-recommended policy without write actions).",
      "Open Integrations > Webhooks and confirm every webhook URL uses https:// (the API only returns a webhook by exact name).",
      "Review Integrations > Installed for any integration configured with owner or admin credentials.",
    ], evidence),
    gaps,
    { essential: true },
  );
}

function evaluateOrgSettingsControl(snapshot: DatadogDataProtectionSnapshot, minLogRetentionDays: number): DatadogFinding {
  const consoleEvidence = [
    "Capture Organization Settings > Public Sharing showing widget sharing outside the org (private_widget_share) disabled.",
    `Capture Logs > Configuration > Indexes showing retention per index of at least ${minLogRetentionDays} days.`,
    "Capture Organization Settings > Org Connections (or the Cross-Org Visibility settings) showing no connections that share data with other organizations.",
  ];
  const settings = asObject(snapshot.organization.value?.settings) ?? {};
  const widgetShareSetting = snapshot.organization.value ? asBoolean(settings.private_widget_share) : undefined;
  const autocreateEnabled = settingEnabled(settings, "saml_autocreate_users_domains") === true;
  const autocreateDomains = asStringArray(getNestedValue(settings, ["saml_autocreate_users_domains", "domains"]));
  const indexes = snapshot.indexes.value ?? [];
  const retentionByIndex = indexes.map((index) => ({ name: asString(index.name) ?? "index", retention_days: asNumber(index.num_retention_days) ?? null }));
  const shortRetention = retentionByIndex.filter((index) => index.retention_days !== null && index.retention_days < minLogRetentionDays);
  const unknownRetention = retentionByIndex.filter((index) => index.retention_days === null);
  const connections = snapshot.orgConnections.value ?? [];
  const unreadable = unreadableSurfaces([
    ["organization", snapshot.organization, "whether widget sharing outside the organization (private_widget_share) is disabled and whether SAML user auto-creation is domain-restricted were not checked"],
    ["log_indexes", snapshot.indexes, `whether every log index retains data for at least ${minLogRetentionDays} days was not checked`],
    ["org_connections", snapshot.orgConnections, "whether any cross-org connection shares data with another organization was not checked"],
  ]);
  // Every count and list below is derived from one inventory and renders null when that inventory was not read (or,
  // for the paged org connections, not read completely); sink org ids are named only from a complete list.
  const evidence = withUnreadableEvidence({
    private_widget_share: widgetShareSetting ?? null,
    organization_settings_readable: Boolean(snapshot.organization.value),
    saml_autocreate_users_enabled: whenRead(snapshot.organization, autocreateEnabled),
    saml_autocreate_domains: whenRead(snapshot.organization, autocreateDomains),
    log_indexes: whenRead(snapshot.indexes, indexes.length),
    log_indexes_readable: Boolean(snapshot.indexes.value),
    min_log_retention_days: minLogRetentionDays,
    indexes_below_retention_minimum: whenRead(snapshot.indexes, shortRetention),
    indexes_without_retention_value: whenRead(snapshot.indexes, sample(unknownRetention.map((index) => index.name))),
    org_connections: whenComplete(snapshot.orgConnections, connections.length),
    org_connections_seen: whenRead(snapshot.orgConnections, connections.length),
    org_connections_readable: Boolean(snapshot.orgConnections.value),
    org_connections_inventory_truncated: truncatedFlag(snapshot.orgConnections),
    org_connection_sample: whenComplete(snapshot.orgConnections, sample(connections.map((connection) => ({
      types: asStringArray(attributesOf(connection).connection_types),
      sink_org: asString(getNestedValue(connection, ["relationships", "sink_org", "data", "id"])) ?? null,
    })))),
    inventories: inventoryStates([
      ["organization", snapshot.organization],
      ["log_indexes", snapshot.indexes],
      ["org_connections", snapshot.orgConnections],
    ]),
  }, unreadable);
  if (widgetShareSetting === true) {
    return withInventoryGaps(
      finding(20, "medium", "fail", "Widget sharing outside the organization is enabled (private_widget_share).", evidence),
      unreadable,
      { essential: true },
    );
  }
  if (unreadable.length > 0) {
    return manualFinding(20, "medium", unreadableSurfacesReason(unreadable), consoleEvidence, evidence);
  }
  if (widgetShareSetting === undefined) {
    return manualFinding(20, "medium", "The organization response did not include the private_widget_share setting, so widget sharing outside the org could not be confirmed.", [consoleEvidence[0]], evidence);
  }
  if (indexes.length === 0) {
    return manualFinding(20, "medium", "The log indexes endpoint returned no indexes, so log retention could not be evaluated; the empty inventory is treated as unverifiable rather than compliant.", [consoleEvidence[1]], evidence);
  }
  const connectionCaveats = [truncationCaveat("org_connections", snapshot.orgConnections, "the org connection limit")];
  if (shortRetention.length > 0 || unknownRetention.length > 0 || connections.length > 0 || (autocreateEnabled && autocreateDomains.length === 0)) {
    return withVerdictCaveats(
      finding(
        20,
        "medium",
        "warn",
        `${shortRetention.length} log indexes retain data for less than ${minLogRetentionDays} days, ${unknownRetention.length} indexes did not report num_retention_days, ${countText(snapshot.orgConnections, connections.length)} cross-org connections${readSuffix(snapshot.orgConnections)} share data with other orgs, and SAML user auto-creation ${autocreateEnabled ? `is enabled for ${autocreateDomains.length} domains` : "is disabled"}.`,
        evidence,
      ),
      connectionCaveats,
    );
  }
  return withVerdictCaveats(
    finding(20, "medium", "pass", `Widget sharing outside the org is disabled (private_widget_share read as false), all ${indexes.length} log indexes meet the ${minLogRetentionDays}-day retention minimum, and the org connections list was read${readSuffix(snapshot.orgConnections)} and is empty.`, evidence),
    connectionCaveats,
  );
}

export function evaluateDatadogAccessControls(
  snapshot: DatadogAccessControlSnapshot,
  options: DatadogAccessControlOptions = {},
): DatadogAssessmentResult {
  const now = options.now ?? new Date();
  const rotationDays = clampNumber(options.keyRotationDays, DEFAULT_KEY_ROTATION_DAYS, 1, 3650);
  const unusedDays = clampNumber(options.keyUnusedDays, DEFAULT_KEY_UNUSED_DAYS, 1, 3650);
  const findings = [
    evaluateApiKeyControl(snapshot, now, rotationDays, unusedDays),
    evaluateApplicationKeyControl(snapshot, now, Math.max(unusedDays, rotationDays)),
    evaluateDashboardSharingControl(snapshot),
    evaluateIpAllowlistControl(snapshot),
    evaluateIntegrationPermissionsControl(snapshot),
  ];
  return {
    category: "access-controls",
    title: "Datadog key, sharing, network, and integration controls",
    // Summary counts are evidence: a count over an unread or truncated inventory renders null, and the cloud
    // integration total is unknown as soon as one provider's list was not read.
    summary: {
      api_keys: whenComplete(snapshot.apiKeys, snapshot.apiKeys.value?.length ?? 0),
      api_keys_seen: whenRead(snapshot.apiKeys, snapshot.apiKeys.value?.length ?? 0),
      application_keys: whenComplete(snapshot.applicationKeys, asRecordArray(snapshot.applicationKeys.value?.data).length),
      application_keys_seen: whenRead(snapshot.applicationKeys, asRecordArray(snapshot.applicationKeys.value?.data).length),
      shared_dashboards: whenComplete(snapshot.sharedDashboards, snapshot.sharedDashboards.value?.length ?? 0),
      shared_dashboards_seen: whenRead(snapshot.sharedDashboards, snapshot.sharedDashboards.value?.length ?? 0),
      ip_allowlist_enabled: snapshot.ipAllowlist.value ? asBoolean(getNestedValue(snapshot.ipAllowlist.value, ["data", "attributes", "enabled"])) ?? null : null,
      cloud_integrations: whenAllRead(
        [snapshot.awsIntegrations, snapshot.gcpIntegrations, snapshot.azureIntegrations],
        (snapshot.awsIntegrations.value?.length ?? 0) + (snapshot.gcpIntegrations.value?.length ?? 0) + (snapshot.azureIntegrations.value?.length ?? 0),
      ),
      ...countByStatus(findings),
    },
    findings,
    errors: snapshot.errors,
  };
}

export async function assessDatadogAccessControls(
  client: AccessControlReader,
  options: DatadogAccessControlOptions = {},
): Promise<DatadogAssessmentResult> {
  return evaluateDatadogAccessControls(await collectDatadogAccessControlData(client, options), options);
}

function signalQuery(): string {
  return "status:(critical OR high) -@workflow.triage.state:archived";
}

export async function collectDatadogSecurityMonitoringData(
  client: SecurityMonitoringReader,
  options: DatadogSecurityMonitoringOptions = {},
): Promise<DatadogSecurityMonitoringSnapshot> {
  const errors: string[] = [];
  const ruleLimit = clampNumber(options.ruleLimit, DEFAULT_RULE_LIMIT, 1, 10000);
  const signalLimit = clampNumber(options.signalLimit, DEFAULT_SIGNAL_LIMIT, 1, 5000);
  const lookbackDays = clampNumber(options.signalLookbackDays, DEFAULT_SIGNAL_LOOKBACK_DAYS, 1, 365);
  const monitorLimit = clampNumber(options.monitorLimit, DEFAULT_MONITOR_LIMIT, 1, 20000);
  const findingLimit = clampNumber(options.findingLimit, DEFAULT_FINDING_LIMIT, 1, 100000);

  const [rules, signals, postureFailing, posturePassing, monitors, awsIntegrations, gcpIntegrations, azureIntegrations] = await Promise.all([
    loadInventory("security_rules", ruleLimit, (probeLimit) => client.listSecurityRules(probeLimit), errors),
    loadInventory("security_signals", signalLimit, (probeLimit) => client.listSecuritySignals({
      query: signalQuery(),
      from: `now-${lookbackDays}d`,
      to: "now",
      sort: "timestamp",
      limit: probeLimit,
    }), errors, projectSecuritySignal),
    loadSurface("posture_findings_fail", async () => projectPostureFindings(await client.listPostureFindings({ evaluation: "fail", limit: findingLimit })), errors),
    loadSurface("posture_findings_pass", async () => projectPostureFindings(await client.listPostureFindings({ evaluation: "pass", limit: findingLimit })), errors),
    loadInventory("monitors", monitorLimit, (probeLimit) => client.listMonitors(probeLimit), errors, projectMonitor),
    loadCloudIntegrations("aws", () => client.listAwsIntegrations(), errors),
    loadCloudIntegrations("gcp", () => client.listGcpIntegrations(), errors),
    loadCloudIntegrations("azure", () => client.listAzureIntegrations(), errors),
  ]);
  return { rules, signals, postureFailing, posturePassing, monitors, awsIntegrations, gcpIntegrations, azureIntegrations, errors };
}

function ruleType(rule: JsonRecord): string {
  return (asString(rule.type) ?? "").toLowerCase();
}

function ruleEnabled(rule: JsonRecord): boolean {
  return asBoolean(rule.isEnabled) === true && asBoolean(rule.isDeleted) !== true;
}

function ruleText(rule: JsonRecord): string {
  return [asString(rule.name) ?? "", ...asStringArray(rule.tags), ...asStringArray(rule.defaultTags)].join(" ");
}

function isDetectionRule(rule: JsonRecord): boolean {
  return !COMPLIANCE_RULE_TYPES.has(ruleType(rule));
}

function evaluateDetectionRulesControl(snapshot: DatadogSecurityMonitoringSnapshot): DatadogFinding {
  if (!snapshot.rules.value) {
    return manualFinding(8, "high", unreadableReason("security monitoring rules (security_monitoring_rules_read)", snapshot.rules), [
      "Export Security > Cloud SIEM > Detection Rules showing enabled rules for authentication, privilege escalation, and data exfiltration, plus any disabled default rules.",
    ]);
  }
  const rules = snapshot.rules.value;
  const detectionRules = rules.filter(isDetectionRule);
  const enabledDetection = detectionRules.filter(ruleEnabled);
  const disabledDefaults = detectionRules.filter((rule) => asBoolean(rule.isDefault) === true && !ruleEnabled(rule));
  const categoryCoverage = CRITICAL_RULE_CATEGORIES.map((category) => ({
    category: category.name,
    enabled_rules: enabledDetection.filter((rule) => category.pattern.test(ruleText(rule))).length,
  }));
  const uncovered = categoryCoverage.filter((item) => item.enabled_rules === 0).map((item) => item.category);
  const surface = snapshot.rules;
  const complete = isComplete(surface);
  const read = readSuffix(surface);
  // Population counts, rule names, and per-category coverage are derived from the whole rule list, so they render
  // only when the list was read completely; the `_read` counts describe the records that were read.
  const evidence = {
    rules_returned: rules.length,
    total_rules: whenComplete(surface, rules.length),
    detection_rules: whenComplete(surface, detectionRules.length),
    enabled_detection_rules: whenComplete(surface, enabledDetection.length),
    enabled_detection_rules_read: enabledDetection.length,
    disabled_default_rules: whenComplete(surface, disabledDefaults.length),
    disabled_default_rule_sample: whenComplete(surface, sample(disabledDefaults.map((rule) => asString(rule.name) ?? asString(rule.id) ?? "rule"))),
    critical_category_coverage: whenComplete(surface, categoryCoverage),
    critical_categories_without_enabled_rule_among_read: uncovered,
    rules_inventory_truncated: truncatedFlag(surface),
    inventory: inventoryState("security_rules", surface),
  };
  if (rules.length === 0) {
    return finding(8, "high", "fail", "The security monitoring rules endpoint returned no rules at all. An empty rule inventory is treated as fail because no detection is active; if Cloud SIEM is not licensed for this organization, record the control as not applicable with the plan evidence.", evidence);
  }
  const caveats = [truncationCaveat("security_rules", surface, "rule_limit")];
  // An absence (no enabled rule, no rule for a category) is proven only by a complete list; from a truncated list it
  // is reported as warn because rules beyond the cap may hold what was not seen.
  if (enabledDetection.length === 0) {
    return withVerdictCaveats(
      finding(8, "high", complete ? "fail" : "warn", complete
        ? `${rules.length} rules were returned but no Cloud SIEM detection rules are enabled.`
        : `${rules.length} rules were read and none of them is an enabled Cloud SIEM detection rule; rules beyond the truncation point were not read.`, evidence),
      caveats,
    );
  }
  if (uncovered.length > 0) {
    return withVerdictCaveats(
      finding(8, "high", complete ? "fail" : "warn", complete
        ? `${enabledDetection.length} detection rules are enabled but no enabled rule covers: ${uncovered.join(", ")}.`
        : `${enabledDetection.length} detection rules${read} are enabled but none of them covers: ${uncovered.join(", ")}; coverage by rules beyond the truncation point is unknown.`, evidence),
      caveats,
    );
  }
  if (disabledDefaults.length > 0) {
    return withVerdictCaveats(
      finding(8, "high", "warn", `${enabledDetection.length} detection rules${read} are enabled across all critical categories, but ${countText(surface, disabledDefaults.length)} default rules${read} have been disabled.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(8, "high", "pass", `${enabledDetection.length} detection rules${read} are enabled, all critical categories are covered, and no default rules${read} are disabled.`, evidence),
    caveats,
  );
}

function signalDetails(signal: JsonRecord, now: Date): { id: string; severity: string; triage: string; ageHours: number | undefined; title: string } {
  const attributes = attributesOf(signal);
  const inner = asObject(attributes.attributes) ?? asObject(attributes.custom) ?? {};
  const severity = (asString(inner.status) ?? asString(attributes.status) ?? "unknown").toLowerCase();
  const triage = (asString(getNestedValue(inner, ["workflow", "triage", "state"])) ?? "open").toLowerCase();
  return {
    id: asString(signal.id) ?? "signal",
    severity,
    triage,
    ageHours: hoursBetween(parseDate(attributes.timestamp), now),
    title: asString(attributes.message) ?? asString(getNestedValue(inner, ["workflow", "rule", "name"])) ?? "signal",
  };
}

function evaluateSignalsControl(snapshot: DatadogSecurityMonitoringSnapshot, now: Date, slaHours: number, lookbackDays: number): DatadogFinding {
  if (!snapshot.signals.value) {
    return manualFinding(9, "high", unreadableReason("security signals (security_monitoring_signals_read)", snapshot.signals), [
      `Open Security > Signals filtered to status:(critical OR high) and open or under review states, and confirm none are older than ${slaHours} hours.`,
    ]);
  }
  const signals = snapshot.signals.value.map((signal) => signalDetails(signal, now)).filter((signal) => signal.triage !== "archived");
  const overdue = signals.filter((signal) => signal.ageHours !== undefined && signal.ageHours > slaHours);
  const undated = signals.filter((signal) => signal.ageHours === undefined);
  const enabledDetectionRules = snapshot.rules.value?.filter((rule) => isDetectionRule(rule) && ruleEnabled(rule)).length;
  // The rule inventory is what makes an empty signal list meaningful: without it the silence cannot be told from a
  // disabled Cloud SIEM, so it is essential to the pass path and only a caveat on the warn and fail paths.
  const ruleGaps = unreadableSurfaces([
    ["security_rules", snapshot.rules, "whether any detection rule is enabled to generate signals was not checked"],
  ]);
  const surface = snapshot.signals;
  const read = readSuffix(surface);
  // Signal counts and signal ids are derived from the whole signal list, so they render only when the list was read
  // completely; the enabled rule count is population-wide only when the rule list was complete.
  const evidence = withUnreadableEvidence({
    lookback_days: lookbackDays,
    unresolved_high_or_critical_signals: whenComplete(surface, signals.length),
    unresolved_high_or_critical_signals_read: signals.length,
    sla_hours: slaHours,
    overdue_signals: whenComplete(surface, overdue.length),
    overdue_signal_sample: whenComplete(surface, sample(overdue.map((signal) => ({ id: signal.id, severity: signal.severity, triage: signal.triage, age_hours: signal.ageHours, title: signal.title })))),
    signals_without_timestamp: whenComplete(surface, undated.length),
    signals_without_timestamp_sample: whenComplete(surface, sample(undated.map((signal) => signal.id))),
    enabled_detection_rules: whenComplete(snapshot.rules, enabledDetectionRules ?? 0),
    enabled_detection_rules_read: enabledDetectionRules ?? null,
    signals_inventory_truncated: truncatedFlag(surface),
    query: signalQuery(),
    inventories: inventoryStates([["security_signals", surface], ["security_rules", snapshot.rules]]),
  }, ruleGaps);
  if (overdue.length > 0) {
    return withInventoryGaps(
      finding(9, "high", "fail", `${ratioText(surface, overdue.length, signals.length)} unresolved high or critical signals${read} are older than the ${slaHours}-hour SLA.`, evidence),
      ruleGaps,
      { essential: true },
    );
  }
  if (signals.length > 0) {
    const truncated = surface.truncated ? ` The signal list is truncated at ${surface.limit} items (raise signal_limit), so older overdue signals may exist.` : "";
    const undatedNote = undated.length > 0 ? ` ${undated.length} signals have no timestamp and could not be aged.` : "";
    return withInventoryGaps(
      finding(9, "high", "warn", `${countText(surface, signals.length)} unresolved high or critical signals${read} are open within the ${slaHours}-hour SLA.${undatedNote}${truncated}`, evidence),
      ruleGaps,
      { essential: true },
    );
  }
  const signalEvidence = `Open Security > Signals filtered to status:(critical OR high) over the last ${lookbackDays} days and confirm Cloud SIEM is enabled and generating signals.`;
  if (enabledDetectionRules === undefined) {
    return manualFinding(9, "high", `No unresolved high or critical signals were returned, but the detection rule inventory was not readable, so it is unknown whether Cloud SIEM is generating signals at all; the empty list is treated as unverifiable rather than compliant. ${unreadableSurfacesReason(ruleGaps)}`, [signalEvidence], evidence);
  }
  if (enabledDetectionRules === 0) {
    return manualFinding(9, "high", "No unresolved high or critical signals were returned, but no detection rules are enabled, so the empty signal list reflects the absence of detection rather than timely triage; the empty list is treated as unverifiable rather than compliant.", [signalEvidence], evidence);
  }
  return withVerdictCaveats(
    finding(9, "high", "pass", `No unresolved high or critical security signals in the last ${lookbackDays} days. The empty result is treated as compliant because ${enabledDetectionRules} enabled detection rules${readSuffix(snapshot.rules)} are active, so signals would appear here if they were open.`, evidence),
    [
      surface.truncated
        ? `The signal query returned a truncated list of ${surface.limit} items that were all archived, so unresolved signals beyond the truncation point (raise signal_limit) cannot be ruled out.`
        : undefined,
    ],
  );
}

function integrationCspmEnabled(snapshot: { awsIntegrations: SurfaceResult<JsonRecord[]>; gcpIntegrations: SurfaceResult<JsonRecord[]>; azureIntegrations: SurfaceResult<JsonRecord[]> }): { enabled: number; total: number } {
  const aws = snapshot.awsIntegrations.value ?? [];
  const gcp = snapshot.gcpIntegrations.value ?? [];
  const azure = snapshot.azureIntegrations.value ?? [];
  const enabled = aws.filter((account) => asBoolean(account.cspm_resource_collection_enabled) === true).length
    + gcp.filter((project) => asBoolean(project.is_cspm_enabled) === true).length
    + azure.filter((tenant) => asBoolean(tenant.cspm_enabled) === true).length;
  return { enabled, total: aws.length + gcp.length + azure.length };
}

interface PostureCount {
  count: number;
  source: "total_filtered_count" | "paged_data";
  truncated: boolean;
  /** The same truncation_reason the collection_status row reports for this posture surface. */
  truncationReason?: string;
  capReached: boolean;
}

function postureCount(surface: SurfaceResult<JsonRecord>): PostureCount | undefined {
  if (!surface.value) return undefined;
  const total = asNumber(surface.value.total_filtered_count);
  if (total !== undefined) return { count: total, source: "total_filtered_count", truncated: false, capReached: false };
  const truncated = asBoolean(surface.value.truncated) === true;
  return {
    count: asRecordArray(surface.value.data).length,
    source: "paged_data",
    truncated,
    truncationReason: truncated ? asString(surface.value.truncation_reason) : undefined,
    capReached: truncated && asBoolean(surface.value.cap_reached) === true,
  };
}

/**
 * Why the paged posture counts stopped, in the words the collection_status row carries for the same surfaces. Each
 * truncated evaluation is named, and raising finding_limit is advised only when a cap stopped the paging: a repeated
 * cursor or a run of empty pages does not yield to a larger limit, so those leave the console as the only remedy.
 */
function postureTruncation(failing: PostureCount | undefined, passing: PostureCount | undefined): { clause: string; remedy: string } {
  const stopped: Array<{ label: string; count: PostureCount }> = [];
  if (failing?.truncated) stopped.push({ label: "failing", count: failing });
  if (passing?.truncated) stopped.push({ label: "passing", count: passing });
  const describe = (labels: string[], reason: string | undefined): string =>
    `the paged ${labels.join(" and ")} count${labels.length === 1 ? "" : "s"} stopped early${reason === undefined ? "" : ` because ${reason}`}`;
  const reasons = new Set(stopped.map((entry) => entry.count.truncationReason));
  const clause = reasons.size <= 1
    ? describe(stopped.map((entry) => entry.label), stopped[0]?.count.truncationReason)
    : stopped.map((entry) => describe([entry.label], entry.count.truncationReason)).join(" and ");
  const remedy = stopped.some((entry) => entry.count.capReached)
    ? "Raise finding_limit or capture the passing percentage from the console."
    : "Capture the passing percentage from the console.";
  return { clause, remedy };
}

function evaluateCspmControl(snapshot: DatadogSecurityMonitoringSnapshot, minPassRate: number): DatadogFinding {
  const cloudRules = (snapshot.rules.value ?? []).filter((rule) => ruleType(rule) === "cloud_configuration");
  const enabledCloudRules = cloudRules.filter(ruleEnabled);
  const cspm = integrationCspmEnabled(snapshot);
  const failing = postureCount(snapshot.postureFailing);
  const passing = postureCount(snapshot.posturePassing);
  const countsTruncated = Boolean(failing?.truncated || passing?.truncated);
  const passRate = failing && passing && failing.count + passing.count > 0 ? passing.count / (failing.count + passing.count) : undefined;
  const unreadableInputs = unreadableSurfaces([
    ["security_rules", snapshot.rules, "whether any cloud_configuration compliance rule is enabled was not checked"],
    ["aws_integrations", snapshot.awsIntegrations, "whether AWS accounts have CSPM resource collection enabled was not checked"],
    ["gcp_integrations", snapshot.gcpIntegrations, "whether GCP projects have CSPM resource collection enabled was not checked"],
    ["azure_integrations", snapshot.azureIntegrations, "whether Azure tenants have CSPM resource collection enabled was not checked"],
  ]);
  const unreadablePosture = unreadableSurfaces([
    ["posture_findings_fail", snapshot.postureFailing, "the failing posture finding count behind the passing rate was not read"],
    ["posture_findings_pass", snapshot.posturePassing, "the passing posture finding count behind the passing rate was not read"],
  ]);
  const cloudSurfaces = [snapshot.awsIntegrations, snapshot.gcpIntegrations, snapshot.azureIntegrations];
  const rulesRead = readSuffix(snapshot.rules);
  // Rule counts render only from a complete rule list, integration totals only when every provider list was read,
  // and posture counts and their truncation flag only when both posture queries were answered.
  const evidence = withUnreadableEvidence({
    cloud_configuration_rules: whenComplete(snapshot.rules, cloudRules.length),
    enabled_cloud_configuration_rules: whenComplete(snapshot.rules, enabledCloudRules.length),
    enabled_cloud_configuration_rules_read: whenRead(snapshot.rules, enabledCloudRules.length),
    rules_readable: Boolean(snapshot.rules.value),
    rules_inventory_truncated: truncatedFlag(snapshot.rules),
    integrations_with_cspm_resource_collection: whenAllRead(cloudSurfaces, cspm.enabled),
    cloud_integrations: whenAllRead(cloudSurfaces, cspm.total),
    cloud_integration_surfaces_readable: {
      aws: Boolean(snapshot.awsIntegrations.value),
      gcp: Boolean(snapshot.gcpIntegrations.value),
      azure: Boolean(snapshot.azureIntegrations.value),
    },
    posture_findings_failing: failing?.count ?? null,
    posture_findings_passing: passing?.count ?? null,
    posture_count_source: failing?.source ?? passing?.source ?? null,
    posture_counts_truncated: unreadablePosture.length === 0 ? countsTruncated : null,
    posture_counts_truncation_reasons: unreadablePosture.length === 0
      ? { failing: failing?.truncationReason ?? null, passing: passing?.truncationReason ?? null }
      : null,
    posture_pass_rate: passRate === undefined ? null : Number(passRate.toFixed(3)),
    min_posture_pass_rate: minPassRate,
    posture_findings_readable: unreadablePosture.length === 0,
    posture_findings_seen: {
      failing: whenRead(snapshot.postureFailing, asNumber(snapshot.postureFailing.value?.seen) ?? asRecordArray(snapshot.postureFailing.value?.data).length),
      passing: whenRead(snapshot.posturePassing, asNumber(snapshot.posturePassing.value?.seen) ?? asRecordArray(snapshot.posturePassing.value?.data).length),
    },
    inventories: inventoryStates([
      ["security_rules", snapshot.rules],
      ["aws_integrations", snapshot.awsIntegrations],
      ["gcp_integrations", snapshot.gcpIntegrations],
      ["azure_integrations", snapshot.azureIntegrations],
      ["posture_findings_fail", snapshot.postureFailing],
      ["posture_findings_pass", snapshot.posturePassing],
    ]),
  }, [...unreadableInputs, ...unreadablePosture]);
  const consoleEvidence = "Open Security > Cloud Security > Compliance and capture the enabled frameworks, the cloud accounts with resource collection enabled, and the current passing percentage.";
  if (unreadableInputs.length > 0) {
    return manualFinding(12, "high", unreadableSurfacesReason([...unreadableInputs, ...unreadablePosture]), [consoleEvidence], evidence);
  }
  if (cspm.total === 0 && enabledCloudRules.length === 0) {
    return manualFinding(12, "high", `No AWS, GCP, or Azure integrations are configured and no cloud_configuration rules${rulesRead} are enabled, so there is no cloud footprint for CSPM to evaluate through the API; the empty inventory is treated as not applicable rather than compliant.`, [
      "Confirm whether cloud accounts are in scope for this organization; if none are, record CSPM as not applicable, otherwise connect the accounts and enable resource collection.",
    ], evidence);
  }
  if (enabledCloudRules.length === 0 && cspm.enabled === 0) {
    return withInventoryGaps(
      withVerdictCaveats(
        finding(12, "high", "fail", `Cloud Security Posture Management is not active: ${cspm.total} cloud integrations are configured but none has CSPM resource collection enabled and none of the ${cloudRules.length} cloud_configuration rules${rulesRead} is enabled.`, evidence),
        [truncationCaveat("security_rules", snapshot.rules, "rule_limit")],
      ),
      unreadablePosture,
      { essential: true },
    );
  }
  if (unreadablePosture.length > 0) {
    return manualFinding(12, "high", `CSPM appears active (${enabledCloudRules.length} enabled cloud_configuration rules${rulesRead}, ${cspm.enabled} integrations with resource collection), but the posture passing rate could not be measured. ${unreadableSurfacesReason(unreadablePosture)}`, [consoleEvidence], evidence);
  }
  const ruleCaveats = [truncationCaveat("security_rules", snapshot.rules, "rule_limit")];
  if (countsTruncated) {
    const { clause, remedy } = postureTruncation(failing, passing);
    return withVerdictCaveats(finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules${rulesRead}, but the passing rate could not be measured reliably: the posture findings response carried no total_filtered_count and ${clause}. ${remedy}`, evidence), ruleCaveats);
  }
  if (passRate === undefined) {
    return withVerdictCaveats(finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules${rulesRead}, but no posture findings were returned yet so the passing rate could not be measured.`, evidence), ruleCaveats);
  }
  if (passRate < minPassRate) {
    return withVerdictCaveats(finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules${rulesRead}, but the posture passing rate ${(passRate * 100).toFixed(1)}% is below the ${(minPassRate * 100).toFixed(0)}% threshold.`, evidence), ruleCaveats);
  }
  return withVerdictCaveats(
    finding(12, "high", "pass", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules${rulesRead} and a ${(passRate * 100).toFixed(1)}% posture passing rate (${failing?.source === "paged_data" ? "counted from paged findings" : "from total_filtered_count"}).`, evidence),
    ruleCaveats,
  );
}

function frameworkTokens(rule: JsonRecord): string[] {
  return asStringArray(rule.tags)
    .filter((tag) => /^(framework|compliance_framework|requirement_framework):/i.test(tag))
    .map((tag) => tag.slice(tag.indexOf(":") + 1).toLowerCase());
}

function frameworkMatches(token: string, required: string): boolean {
  const normalizedToken = token.replace(/[^a-z0-9]/g, "");
  const normalizedRequired = required.toLowerCase().replace(/[^a-z0-9]/g, "");
  return normalizedToken.includes(normalizedRequired);
}

function evaluateComplianceCoverageControl(snapshot: DatadogSecurityMonitoringSnapshot, requiredFrameworks: string[]): DatadogFinding {
  if (!snapshot.rules.value) {
    return manualFinding(13, "medium", unreadableReason("security monitoring rules (security_monitoring_rules_read)", snapshot.rules), [
      `Open Security > Cloud Security > Compliance and confirm rule sets are enabled for: ${requiredFrameworks.join(", ")}.`,
    ]);
  }
  const complianceRules = snapshot.rules.value.filter((rule) => COMPLIANCE_RULE_TYPES.has(ruleType(rule)) && ruleEnabled(rule));
  const tokens = new Set(complianceRules.flatMap(frameworkTokens));
  const coverage = requiredFrameworks.map((framework) => ({
    framework,
    enabled_rules: complianceRules.filter((rule) => frameworkTokens(rule).some((token) => frameworkMatches(token, framework))).length,
  }));
  const gaps = coverage.filter((item) => item.enabled_rules === 0).map((item) => item.framework);
  const surface = snapshot.rules;
  const rules = snapshot.rules.value;
  const complete = isComplete(surface);
  // Population counts and per-framework coverage come from the whole rule list and render only when it was complete;
  // an absence (no rule for a framework) is proven only by a complete list and is a warn from a truncated one.
  const evidence = {
    rules_returned: rules.length,
    total_rules: whenComplete(surface, rules.length),
    enabled_compliance_rules: whenComplete(surface, complianceRules.length),
    enabled_compliance_rules_read: complianceRules.length,
    frameworks_observed: [...tokens].sort(),
    required_frameworks: requiredFrameworks,
    coverage: whenComplete(surface, coverage),
    frameworks_without_enabled_rule_among_read: gaps,
    rules_inventory_truncated: truncatedFlag(surface),
    inventory: inventoryState("security_rules", surface),
  };
  const caveats = [truncationCaveat("security_rules", surface, "rule_limit")];
  if (complianceRules.length === 0) {
    return withVerdictCaveats(
      finding(13, "medium", complete ? "fail" : "warn", complete
        ? `${rules.length} rules were returned but none is an enabled cloud_configuration or infrastructure_configuration compliance rule. The empty compliance rule set is treated as fail; if Cloud Security is not licensed for this organization, record the control as not applicable with the plan evidence.`
        : `${rules.length} rules were read and none of them is an enabled cloud_configuration or infrastructure_configuration compliance rule; rules beyond the truncation point were not read.`, evidence),
      caveats,
    );
  }
  if (gaps.length > 0) {
    return withVerdictCaveats(
      finding(13, "medium", complete ? "fail" : "warn", complete
        ? `Enabled compliance rules cover ${tokens.size} framework tags but none reference: ${gaps.join(", ")}.`
        : `Enabled compliance rules read cover ${tokens.size} framework tags but none of them references: ${gaps.join(", ")}; coverage by rules beyond the truncation point is unknown.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(13, "medium", "pass", `Enabled compliance rules${readSuffix(surface)} reference every required framework (${requiredFrameworks.join(", ")}).`, evidence),
    caveats,
  );
}

function notificationHandles(message: string): string[] {
  const handles = message.match(/@[A-Za-z0-9][A-Za-z0-9._+:#-]*(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?/g) ?? [];
  return [...new Set(handles)];
}

function classifyHandle(handle: string): "integration" | "email" | "other" {
  if (INTEGRATION_HANDLE_PATTERN.test(handle)) return "integration";
  if (/^@[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(handle)) return "email";
  return "other";
}

function isSecurityMonitor(monitor: JsonRecord): boolean {
  const tags = asStringArray(monitor.tags);
  if (tags.some((tag) => SECURITY_MONITOR_PATTERN.test(tag))) return true;
  if (asNumber(monitor.priority) === 1) return true;
  return SECURITY_MONITOR_PATTERN.test(asString(monitor.name) ?? "");
}

function evaluateMonitorNotificationControl(snapshot: DatadogSecurityMonitoringSnapshot): DatadogFinding {
  if (!snapshot.monitors.value) {
    return manualFinding(17, "medium", unreadableReason("monitors (monitors_read)", snapshot.monitors), [
      "Export security-related monitors and confirm each notifies an approved channel (PagerDuty, security Slack channel, or distribution list) rather than a personal mailbox.",
    ]);
  }
  const monitors = snapshot.monitors.value;
  const securityMonitors = monitors.filter(isSecurityMonitor);
  const classified = securityMonitors.map((monitor) => {
    const handles = notificationHandles(asString(monitor.message) ?? "");
    const kinds = handles.map(classifyHandle);
    return {
      id: asString(monitor.id) ?? "monitor",
      name: asString(monitor.name) ?? "monitor",
      handles,
      hasIntegration: kinds.includes("integration"),
      emailOnly: handles.length > 0 && kinds.every((kind) => kind === "email"),
    };
  });
  const silent = classified.filter((monitor) => monitor.handles.length === 0);
  const emailOnly = classified.filter((monitor) => monitor.emailOnly);
  const surface = snapshot.monitors;
  const read = readSuffix(surface);
  // Monitor counts and the names of monitors that violate are derived from the whole monitor list, so they render
  // only when the list was read completely.
  const evidence = {
    monitors_returned: monitors.length,
    monitors: whenComplete(surface, monitors.length),
    security_monitors: whenComplete(surface, securityMonitors.length),
    security_monitors_read: securityMonitors.length,
    security_monitors_without_notifications: whenComplete(surface, sample(silent.map((monitor) => monitor.name))),
    security_monitors_without_notifications_count: whenComplete(surface, silent.length),
    security_monitors_email_only: whenComplete(surface, sample(emailOnly.map((monitor) => ({ name: monitor.name, handles: monitor.handles })))),
    security_monitors_email_only_count: whenComplete(surface, emailOnly.length),
    security_monitors_with_integration_channels: whenComplete(surface, classified.filter((monitor) => monitor.hasIntegration).length),
    violation_observed: violationFlag([surface], silent.length),
    monitors_inventory_truncated: truncatedFlag(surface),
    inventory: inventoryState("monitors", surface),
  };
  if (monitors.length === 0) {
    return manualFinding(17, "medium", "The monitors endpoint returned no monitors, so there are no security alerts whose routing can be verified; the empty inventory is treated as unverifiable rather than compliant.", [
      "Confirm in Monitors > Manage Monitors whether security-related monitors exist; if alerting is handled entirely by Cloud SIEM notification rules, capture Security > Cloud SIEM > Notification Rules instead.",
    ], evidence);
  }
  const caveats = [truncationCaveat("monitors", surface, "monitor_limit")];
  if (securityMonitors.length === 0) {
    return withVerdictCaveats(
      finding(17, "medium", "warn", `${monitors.length} monitors${read} were inventoried but none of them is tagged or named as a security monitor; tag security-critical monitors so notification routing can be verified.`, evidence),
      caveats,
    );
  }
  if (silent.length > 0) {
    return withVerdictCaveats(
      finding(17, "medium", "fail", `${ratioText(surface, silent.length, securityMonitors.length)} security monitors${read} have no notification handles in their message.`, evidence),
      caveats,
    );
  }
  if (emailOnly.length > 0) {
    return withVerdictCaveats(
      finding(17, "medium", "warn", `${ratioText(surface, emailOnly.length, securityMonitors.length)} security monitors${read} notify individual email addresses only; confirm they are distribution lists or route them to PagerDuty or a security channel.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(17, "medium", "pass", `All ${securityMonitors.length} security monitors${read} notify at least one integration channel.`, evidence),
    caveats,
  );
}

export function evaluateDatadogSecurityMonitoring(
  snapshot: DatadogSecurityMonitoringSnapshot,
  options: DatadogSecurityMonitoringOptions = {},
): DatadogAssessmentResult {
  const now = options.now ?? new Date();
  const slaHours = clampNumber(options.signalSlaHours, DEFAULT_SIGNAL_SLA_HOURS, 1, 8760);
  const lookbackDays = clampNumber(options.signalLookbackDays, DEFAULT_SIGNAL_LOOKBACK_DAYS, 1, 365);
  const minPassRate = clampFraction(options.minPosturePassRate, DEFAULT_MIN_POSTURE_PASS_RATE);
  const requiredFrameworks = (options.requiredFrameworks ?? DEFAULT_REQUIRED_FRAMEWORKS).map((item) => item.trim().toLowerCase()).filter(Boolean);
  const findings = [
    evaluateDetectionRulesControl(snapshot),
    evaluateSignalsControl(snapshot, now, slaHours, lookbackDays),
    evaluateCspmControl(snapshot, minPassRate),
    evaluateComplianceCoverageControl(snapshot, requiredFrameworks.length > 0 ? requiredFrameworks : DEFAULT_REQUIRED_FRAMEWORKS),
    evaluateMonitorNotificationControl(snapshot),
  ];
  return {
    category: "security-monitoring",
    title: "Datadog Cloud SIEM, CSM, and alerting posture",
    // Summary counts are evidence: a count over an unread or truncated inventory renders null; `_seen` counts the
    // records that were read.
    summary: {
      rules: whenComplete(snapshot.rules, snapshot.rules.value?.length ?? 0),
      rules_seen: whenRead(snapshot.rules, snapshot.rules.value?.length ?? 0),
      enabled_detection_rules: whenComplete(snapshot.rules, snapshot.rules.value?.filter((rule) => isDetectionRule(rule) && ruleEnabled(rule)).length ?? 0),
      enabled_cloud_configuration_rules: whenComplete(snapshot.rules, snapshot.rules.value?.filter((rule) => ruleType(rule) === "cloud_configuration" && ruleEnabled(rule)).length ?? 0),
      unresolved_high_or_critical_signals: whenComplete(snapshot.signals, snapshot.signals.value?.length ?? 0),
      unresolved_high_or_critical_signals_seen: whenRead(snapshot.signals, snapshot.signals.value?.length ?? 0),
      monitors: whenComplete(snapshot.monitors, snapshot.monitors.value?.length ?? 0),
      monitors_seen: whenRead(snapshot.monitors, snapshot.monitors.value?.length ?? 0),
      ...countByStatus(findings),
    },
    findings,
    errors: snapshot.errors,
  };
}

export async function assessDatadogSecurityMonitoring(
  client: SecurityMonitoringReader,
  options: DatadogSecurityMonitoringOptions = {},
): Promise<DatadogAssessmentResult> {
  return evaluateDatadogSecurityMonitoring(await collectDatadogSecurityMonitoringData(client, options), options);
}

export async function collectDatadogDataProtectionData(
  client: DataProtectionReader,
  options: DatadogDataProtectionOptions = {},
): Promise<DatadogDataProtectionSnapshot> {
  const errors: string[] = [];
  const retentionDays = clampNumber(options.minAuditRetentionDays, DEFAULT_AUDIT_RETENTION_DAYS, 1, 3650);
  const [organization, oldestAuditEvents, recentAuditEvents, pipelines, indexes, archives, sensitiveDataScanner, orgConnections] = await Promise.all([
    loadSurface("organization", () => client.getOrganization(), errors),
    loadSample("audit_events_oldest", () => client.listAuditEvents({ from: `now-${retentionDays}d`, to: "now", sort: "timestamp", limit: 1 }), errors, projectAuditEvent),
    loadSample("audit_events_recent", () => client.listAuditEvents({ from: "now-7d", to: "now", sort: "-timestamp", limit: 25 }), errors, projectAuditEvent),
    loadSurface("log_pipelines", () => client.listLogPipelines(), errors),
    loadSurface("log_indexes", () => client.listLogIndexes(), errors),
    loadSurface("log_archives", () => client.listLogArchives(), errors),
    loadSurface("sensitive_data_scanner", () => client.getSensitiveDataScannerConfig(), errors),
    loadInventory("org_connections", DEFAULT_ORG_CONNECTION_LIMIT, (probeLimit) => client.listOrgConnections(probeLimit), errors),
  ]);
  return { organization, oldestAuditEvents, recentAuditEvents, pipelines, indexes, archives, sensitiveDataScanner, orgConnections, errors };
}

function evaluateAuditTrailControl(snapshot: DatadogDataProtectionSnapshot, now: Date, retentionDays: number): DatadogFinding {
  const unreadable = unreadableSurfaces([
    ["audit_events_oldest", snapshot.oldestAuditEvents, `whether events at least ${retentionDays - 7} days old are still retained was not checked`],
    ["audit_events_recent", snapshot.recentAuditEvents, "whether Audit Trail recorded any event in the last 7 days was not checked"],
  ]);
  const consoleEvidence = `Open Organization Settings > Audit Trail, confirm it is enabled, and capture the retention setting showing at least ${retentionDays} days.`;
  const inventories = inventoryStates([["audit_events_oldest", snapshot.oldestAuditEvents], ["audit_events_recent", snapshot.recentAuditEvents]]);
  if (unreadable.length > 0) {
    return manualFinding(7, "high", unreadableSurfacesReason(unreadable), [consoleEvidence], withUnreadableEvidence({
      recent_events_last_7_days: whenRead(snapshot.recentAuditEvents, snapshot.recentAuditEvents.value?.length ?? 0),
      oldest_event_timestamp: null,
      oldest_events_readable: Boolean(snapshot.oldestAuditEvents.value),
      recent_events_readable: Boolean(snapshot.recentAuditEvents.value),
      min_retention_days: retentionDays,
      inventories,
    }, unreadable));
  }
  const oldest = snapshot.oldestAuditEvents.value ?? [];
  const recent = snapshot.recentAuditEvents.value ?? [];
  const oldestTimestamp = parseDate(attributesOf(oldest[0] ?? {}).timestamp);
  const oldestAgeDays = daysBetween(oldestTimestamp, now);
  // The recent sample is bounded, so its length is a population count only when the listing did not stop early.
  const evidence = {
    recent_events_last_7_days: whenComplete(snapshot.recentAuditEvents, recent.length),
    recent_events_sampled: recent.length,
    recent_events_sample_truncated: truncatedFlag(snapshot.recentAuditEvents),
    oldest_event_timestamp: oldestTimestamp?.toISOString() ?? null,
    oldest_event_age_days: oldestAgeDays ?? null,
    oldest_event_has_timestamp: oldest.length > 0 ? oldestTimestamp !== undefined : null,
    min_retention_days: retentionDays,
    retention_inferred_from_oldest_event: true,
    inventories,
  };
  const recentCount = snapshot.recentAuditEvents.truncated ? `at least ${recent.length}` : String(recent.length);
  if (oldest.length === 0 && recent.length === 0) {
    return finding(7, "high", "fail", `Audit Trail returned no events in the last ${retentionDays} days even though this assessment's own API calls are auditable activity. The empty inventory is treated as fail because Audit Trail appears disabled or is not recording; if Audit Trail is not available on the plan, record the control as not applicable.`, evidence);
  }
  if (oldest.length > 0 && oldestTimestamp === undefined) {
    return finding(7, "high", "warn", `Audit Trail is recording events (${recentCount} in the last 7 days) but the oldest returned event has no timestamp, so ${retentionDays}-day retention could not be inferred from the API.`, evidence);
  }
  if (recent.length === 0) {
    return finding(7, "high", "warn", `Audit Trail has historical events (oldest is ${oldestAgeDays ?? "an unknown number of"} days old) but returned none in the last 7 days, so current recording could not be confirmed.`, evidence);
  }
  if (oldestAgeDays !== undefined && oldestAgeDays >= retentionDays - 7) {
    return finding(7, "high", "pass", `Audit Trail is recording events (${recentCount} in the last 7 days) and the oldest available event is ${oldestAgeDays} days old, supporting ${retentionDays}-day retention.`, evidence);
  }
  return finding(
    7,
    "high",
    "warn",
    `Audit Trail is recording events (${recentCount} in the last 7 days) but the oldest available event is only ${oldestAgeDays ?? "an unknown number of"} days old, so ${retentionDays}-day retention could not be confirmed from the API.`,
    evidence,
  );
}

function exclusionFilters(index: JsonRecord): Array<{ index: string; name: string; query: string; sample_rate: number | null; enabled: boolean }> {
  return asRecordArray(index.exclusion_filters).map((filter) => ({
    index: asString(index.name) ?? "index",
    name: asString(filter.name) ?? "exclusion",
    query: asString(getNestedValue(filter, ["filter", "query"])) ?? "",
    sample_rate: asNumber(getNestedValue(filter, ["filter", "sample_rate"])) ?? null,
    enabled: asBoolean(filter.is_enabled) !== false,
  }));
}

function evaluateLogPipelineControl(snapshot: DatadogDataProtectionSnapshot): DatadogFinding {
  const consoleEvidence = "Capture Logs > Configuration > Indexes (exclusion filters), Pipelines, and Archives showing that security sources are retained and an archive destination exists.";
  const pipelines = snapshot.pipelines.value ?? [];
  const indexes = snapshot.indexes.value ?? [];
  const archives = snapshot.archives.value ?? [];
  const filters = indexes.flatMap(exclusionFilters);
  const securityDrops = filters.filter((filter) => filter.enabled && SECURITY_SOURCE_PATTERN.test(filter.query));
  const failingArchives = archives.filter((archive) => /failing/i.test(asString(attributesOf(archive).state) ?? ""));
  const unreadable = unreadableSurfaces([
    ["log_pipelines", snapshot.pipelines, "whether processing pipelines are configured for security sources was not checked"],
    ["log_indexes", snapshot.indexes, "whether any index exclusion filter drops security-relevant log sources was not checked"],
    ["log_archives", snapshot.archives, "whether a healthy archive destination exists for long-term retention was not checked"],
  ]);
  // Each count and list renders null when the inventory it is derived from was not read.
  const evidence = withUnreadableEvidence({
    pipelines: whenRead(snapshot.pipelines, pipelines.length),
    enabled_pipelines: whenRead(snapshot.pipelines, pipelines.filter((pipeline) => asBoolean(pipeline.is_enabled) !== false).length),
    indexes: whenRead(snapshot.indexes, indexes.length),
    exclusion_filters: whenRead(snapshot.indexes, filters.length),
    exclusion_filters_dropping_security_sources: whenRead(snapshot.indexes, sample(securityDrops)),
    exclusion_filters_dropping_security_sources_count: whenRead(snapshot.indexes, securityDrops.length),
    archives: whenRead(snapshot.archives, archives.length),
    surfaces_readable: {
      pipelines: Boolean(snapshot.pipelines.value),
      indexes: Boolean(snapshot.indexes.value),
      archives: Boolean(snapshot.archives.value),
    },
    archive_destinations: whenRead(snapshot.archives, sample(archives.map((archive) => ({
      name: asString(attributesOf(archive).name) ?? "archive",
      destination: asString(getNestedValue(archive, ["attributes", "destination", "type"])) ?? null,
      state: asString(attributesOf(archive).state) ?? null,
    })))),
    failing_archives: whenRead(snapshot.archives, failingArchives.length),
    redaction_note: "Field-level redaction is assessed by the Sensitive Data Scanner control (DD-11).",
    inventories: inventoryStates([
      ["log_pipelines", snapshot.pipelines],
      ["log_indexes", snapshot.indexes],
      ["log_archives", snapshot.archives],
    ]),
  }, unreadable);
  if (securityDrops.length > 0) {
    return withInventoryGaps(
      finding(10, "medium", "fail", `${securityDrops.length} enabled index exclusion filters drop security-relevant log sources.`, evidence),
      unreadable,
      { essential: true },
    );
  }
  if (unreadable.length > 0) {
    return manualFinding(10, "medium", unreadableSurfacesReason(unreadable), [consoleEvidence], evidence);
  }
  if (indexes.length === 0) {
    return manualFinding(10, "medium", "The log indexes endpoint returned no indexes, so there is no retained log data whose exclusion filters or retention can be evaluated; the empty inventory is treated as unverifiable rather than compliant.", [
      "Confirm in Logs > Configuration > Indexes whether Log Management is in use; if it is not, record the control as not applicable, otherwise capture the index list and exclusion filters.",
    ], evidence);
  }
  if (archives.length === 0 || failingArchives.length > 0) {
    return finding(
      10,
      "medium",
      "warn",
      archives.length === 0
        ? `${indexes.length} indexes keep security sources, but no log archive destination is configured for long-term retention.`
        : `${failingArchives.length} log archives are in a failing state.`,
      evidence,
    );
  }
  return finding(10, "medium", "pass", `${indexes.length} indexes retain security sources, ${pipelines.length} pipelines are configured, and ${archives.length} archive destinations are healthy.`, evidence);
}

function evaluateSensitiveDataScannerControl(snapshot: DatadogDataProtectionSnapshot): DatadogFinding {
  if (!snapshot.sensitiveDataScanner.value) {
    return manualFinding(11, "medium", unreadableReason("sensitive data scanner configuration (data_scanner_read)", snapshot.sensitiveDataScanner), [
      "Open Organization Settings > Sensitive Data Scanner and capture the enabled scanning groups, their products (logs, APM, RUM, events), and the active PII and PCI rules.",
    ], { scanning_groups: null, enabled_scanning_groups: null, rules: null, enabled_rules: null, inventory: inventoryState("sensitive_data_scanner", snapshot.sensitiveDataScanner) });
  }
  const configuration = snapshot.sensitiveDataScanner.value;
  const included = asRecordArray(configuration.included);
  const groups = included.filter((item) => asString(item.type) === "sensitive_data_scanner_group");
  const rules = included.filter((item) => asString(item.type) === "sensitive_data_scanner_rule");
  const referencedGroupIds = asRecordArray(getNestedValue(configuration, ["data", "relationships", "groups", "data"]))
    .map((reference) => asString(reference.id))
    .filter((id): id is string => Boolean(id));
  const includedGroupIds = new Set(groups.map((group) => asString(group.id)).filter((id): id is string => Boolean(id)));
  const missingGroupIds = referencedGroupIds.filter((id) => !includedGroupIds.has(id));
  const enabledGroups = groups.filter((group) => asBoolean(attributesOf(group).is_enabled) === true);
  const unknownStateGroups = groups.filter((group) => asBoolean(attributesOf(group).is_enabled) === undefined);
  const products = new Set(enabledGroups.flatMap((group) => asStringArray(attributesOf(group).product_list).map((product) => product.toLowerCase())));
  const missingProducts = ["logs", "apm", "rum", "events"].filter((product) => !products.has(product));
  const enabledRules = rules.filter((rule) => asBoolean(attributesOf(rule).is_enabled) === true);
  const piiRules = enabledRules.filter((rule) => {
    const attributes = attributesOf(rule);
    const text = [asString(attributes.name) ?? "", asString(attributes.description) ?? "", ...asStringArray(attributes.tags)].join(" ");
    return PII_PATTERN_HINT.test(text) || Boolean(getNestedValue(rule, ["relationships", "standard_pattern", "data", "id"]));
  });
  const evidence = {
    scanning_groups: groups.length,
    scanning_groups_referenced_by_configuration: referencedGroupIds.length,
    scanning_groups_missing_from_included: sample(missingGroupIds),
    scanning_groups_without_is_enabled: sample(unknownStateGroups.map((group) => asString(attributesOf(group).name) ?? asString(group.id) ?? "group")),
    enabled_scanning_groups: enabledGroups.length,
    products_covered: [...products].sort(),
    products_missing: missingProducts,
    rules: rules.length,
    enabled_rules: enabledRules.length,
    enabled_pii_or_pci_rules: piiRules.length,
    rule_sample: sample(enabledRules.map((rule) => asString(attributesOf(rule).name) ?? "rule")),
    inventory: inventoryState("sensitive_data_scanner", snapshot.sensitiveDataScanner),
  };
  const consoleEvidence = "Open Organization Settings > Sensitive Data Scanner and capture every scanning group with its enabled state, products (logs, APM, RUM, events), and active PII and PCI rules.";
  const partialCaveats = [
    missingGroupIds.length > 0
      ? `${missingGroupIds.length}/${referencedGroupIds.length} scanning groups referenced by the configuration were not returned in the included payload, so the group inventory is partial.`
      : undefined,
    unknownStateGroups.length > 0
      ? `${unknownStateGroups.length} scanning groups did not report is_enabled and were not counted as active.`
      : undefined,
  ];
  if (enabledGroups.length === 0) {
    if (missingGroupIds.length > 0 || unknownStateGroups.length > 0) {
      return manualFinding(11, "medium", `No scanning group could be confirmed as enabled: ${partialCaveats.filter(Boolean).join(" ")} The partial configuration is treated as unverifiable rather than compliant.`, [consoleEvidence], evidence);
    }
    return finding(11, "medium", "fail", `Sensitive Data Scanner has no enabled scanning groups (${groups.length} groups returned). The empty configuration is treated as fail because no redaction is active; if Sensitive Data Scanner is not licensed for this organization, record the control as not applicable with the plan evidence.`, evidence);
  }
  if (enabledRules.length === 0 || piiRules.length === 0) {
    return withVerdictCaveats(finding(11, "medium", "fail", `${enabledGroups.length} scanning groups are enabled but no active PII or PCI detection rules were found.`, evidence), partialCaveats);
  }
  if (missingProducts.length > 0) {
    return withVerdictCaveats(finding(11, "medium", "warn", `Sensitive Data Scanner is active with ${piiRules.length} PII/PCI rules but enabled groups do not cover: ${missingProducts.join(", ")}.`, evidence), partialCaveats);
  }
  return withVerdictCaveats(
    finding(11, "medium", "pass", `Sensitive Data Scanner is active across logs, APM, RUM, and events with ${piiRules.length} PII/PCI rules enabled.`, evidence),
    partialCaveats,
  );
}

export function evaluateDatadogDataProtection(
  snapshot: DatadogDataProtectionSnapshot,
  options: DatadogDataProtectionOptions = {},
): DatadogAssessmentResult {
  const now = options.now ?? new Date();
  const retentionDays = clampNumber(options.minAuditRetentionDays, DEFAULT_AUDIT_RETENTION_DAYS, 1, 3650);
  const minLogRetentionDays = clampNumber(options.minLogRetentionDays, DEFAULT_MIN_LOG_RETENTION_DAYS, 1, 3650);
  const findings = [
    evaluateAuditTrailControl(snapshot, now, retentionDays),
    evaluateLogPipelineControl(snapshot),
    evaluateSensitiveDataScannerControl(snapshot),
    evaluateOrgSettingsControl(snapshot, minLogRetentionDays),
  ];
  return {
    category: "data-protection",
    title: "Datadog audit trail, log, and data handling posture",
    // Summary counts are evidence: the bounded audit sample is a population count only when it did not stop early,
    // and every other count renders null when its inventory was not read.
    summary: {
      recent_audit_events: whenComplete(snapshot.recentAuditEvents, snapshot.recentAuditEvents.value?.length ?? 0),
      recent_audit_events_seen: whenRead(snapshot.recentAuditEvents, snapshot.recentAuditEvents.value?.length ?? 0),
      pipelines: whenRead(snapshot.pipelines, snapshot.pipelines.value?.length ?? 0),
      indexes: whenRead(snapshot.indexes, snapshot.indexes.value?.length ?? 0),
      archives: whenRead(snapshot.archives, snapshot.archives.value?.length ?? 0),
      org_connections: whenComplete(snapshot.orgConnections, snapshot.orgConnections.value?.length ?? 0),
      sensitive_data_scanner_readable: Boolean(snapshot.sensitiveDataScanner.value),
      ...countByStatus(findings),
    },
    findings,
    errors: snapshot.errors,
  };
}

export async function assessDatadogDataProtection(
  client: DataProtectionReader,
  options: DatadogDataProtectionOptions = {},
): Promise<DatadogAssessmentResult> {
  return evaluateDatadogDataProtection(await collectDatadogDataProtectionData(client, options), options);
}

function countByStatus(findings: DatadogFinding[]): { pass: number; warn: number; fail: number; manual: number } {
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
        throw new Error(`Unhandled finding status: ${String(exhaustive)}`);
      }
    }
  }
  return counts;
}

function severityRank(severity: DatadogFinding["severity"]): number {
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

/**
 * Probes one surface. A failed probe carries the HTTP status it observed (null for a transport failure) and renders
 * its count as null, so nothing about the surface defaults on a request that was not answered with data.
 */
async function probeSurface(
  name: string,
  endpoint: string,
  permission: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<DatadogAccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, permission, status: "readable", collected: true, http_status: null, count: countResolver?.(value) ?? null };
  } catch (error) {
    return {
      name,
      endpoint,
      permission,
      status: isForbidden(error) ? "forbidden" : "not_readable",
      collected: false,
      http_status: observedStatus(error) ?? null,
      count: null,
      error: errorMessage(error),
    };
  }
}

/** Counts a bare record array, a DatadogListing (`items`), or a `{ data }` envelope. */
function arrayCount(value: unknown): number | undefined {
  if (Array.isArray(value)) return value.length;
  const record = asObject(value);
  if (!record) return undefined;
  if (Array.isArray(record.items)) return record.items.length;
  if (Array.isArray(record.data)) return record.data.length;
  return undefined;
}

function dataCount(value: unknown): number | undefined {
  return asRecordArray(asObject(value)?.data).length;
}

export async function checkDatadogAccess(client: AccessCheckReader): Promise<DatadogAccessCheckResult> {
  const config = client.getResolvedConfig();
  const validate = await probeSurface("validate", "/api/v1/validate", "API key", () => client.validateApiKey(), () => 1);
  const apiKeyValid = validate.status === "readable";
  const validateKeys = await probeSurface("validate_keys", "/api/v2/validate_keys", "API key + application key", () => client.validateKeyPair(), () => 1);
  const keyPairValid = validateKeys.status === "readable";

  const surfaces: DatadogAccessSurface[] = [
    validate,
    validateKeys,
    await probeSurface("organization", "/api/v1/org", "org_management", () => client.getOrganization(), () => 1),
    await probeSurface("org_connections", "/api/v2/org_connections", "org_connections_read", () => client.listOrgConnections(1), arrayCount),
    await probeSurface("users", "/api/v2/users", "user_access_read", () => client.listUsers(1), arrayCount),
    await probeSurface("roles", "/api/v2/roles", "user_access_read", () => client.listRoles(1), arrayCount),
    await probeSurface("api_keys", "/api/v2/api_keys", "api_keys_read", () => client.listApiKeys(1), arrayCount),
    await probeSurface("application_keys", "/api/v2/application_keys", "org_app_keys_read", () => client.listApplicationKeys(1), dataCount),
    await probeSurface("audit_events", "/api/v2/audit/events", "audit_logs_read", () => client.listAuditEvents({ from: "now-1d", to: "now", limit: 1 }), arrayCount),
    await probeSurface("security_rules", "/api/v2/security_monitoring/rules", "security_monitoring_rules_read", () => client.listSecurityRules(1), arrayCount),
    await probeSurface("security_signals", "/api/v2/security_monitoring/signals", "security_monitoring_signals_read", () => client.listSecuritySignals({ from: "now-1d", to: "now", limit: 1 }), arrayCount),
    await probeSurface("posture_findings", "/api/v2/posture_management/findings", "security_monitoring_findings_read", () => client.listPostureFindings({ limit: 1 }), dataCount),
    await probeSurface("ip_allowlist", "/api/v2/ip_allowlist", "org_management", () => client.getIpAllowlist(), () => 1),
    await probeSurface("sensitive_data_scanner", "/api/v2/sensitive-data-scanner/config", "data_scanner_read", () => client.getSensitiveDataScannerConfig(), () => 1),
    await probeSurface("log_pipelines", "/api/v1/logs/config/pipelines", "logs_read_config", () => client.listLogPipelines(), arrayCount),
    await probeSurface("log_indexes", "/api/v1/logs/config/indexes", "logs_read_config", () => client.listLogIndexes(), arrayCount),
    await probeSurface("log_archives", "/api/v2/logs/config/archives", "logs_read_archives", () => client.listLogArchives(), arrayCount),
    await probeSurface("dashboards", "/api/v1/dashboard?filter[shared]=true", "dashboards_read", () => client.listDashboards({ shared: true, limit: 1 }), arrayCount),
    await probeSurface("monitors", "/api/v1/monitor", "monitors_read", () => client.listMonitors(1), arrayCount),
    await probeSurface("aws_integrations", "/api/v1/integration/aws", "aws_configuration_read", () => client.listAwsIntegrations(), arrayCount),
    await probeSurface("gcp_integrations", "/api/v1/integration/gcp", "gcp_configuration_read", () => client.listGcpIntegrations(), arrayCount),
    await probeSurface("azure_integrations", "/api/v1/integration/azure", "azure_configuration_read", () => client.listAzureIntegrations(), arrayCount),
  ];

  const validationSurfaces = new Set(["validate", "validate_keys"]);
  const dataSurfaces = surfaces.filter((surface) => !validationSurfaces.has(surface.name));
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const dataSurfacesReadable = dataSurfaces.filter((surface) => surface.status === "readable").length;
  const missingPermissions = [...new Set(
    dataSurfaces
      .filter((surface) => surface.status === "forbidden")
      .map((surface) => surface.permission),
  )];
  // A probe that failed for a reason other than a denial (5xx, transport error, timeout) says nothing about the
  // permission, so it is reported as unknown rather than counted as granted or missing.
  const permissionStateUnknown = dataSurfaces.filter((surface) => surface.status === "not_readable").map((surface) => surface.name);

  const status: DatadogAccessCheckResult["status"] = !apiKeyValid || dataSurfacesReadable === 0
    ? "failed"
    : keyPairValid && dataSurfacesReadable === dataSurfaces.length
      ? "healthy"
      : "limited";

  return {
    status,
    site: config.site,
    apiKeyValid,
    keyPairValid,
    surfaces,
    missingPermissions,
    permissionStateUnknown,
    notes: [
      `Using Datadog site ${config.site} (${config.baseUrl}).`,
      apiKeyValid ? `The API key validated successfully (GET ${validate.endpoint}).` : `The API key did not validate (GET ${validate.endpoint}): ${validate.error ?? "unknown error"}.`,
      keyPairValid
        ? `The API key and application key pair validated successfully (GET ${validateKeys.endpoint}).`
        : `The API key and application key pair did not validate (GET ${validateKeys.endpoint}): ${validateKeys.error ?? "unknown error"}.`,
      `${readableCount}/${surfaces.length} Datadog audit surfaces are readable.`,
      missingPermissions.length > 0
        ? `Missing application key permissions: ${missingPermissions.join(", ")}.`
        : permissionStateUnknown.length > 0
          ? "No permission denials were observed among the probes that were answered."
          : "No permission denials were observed.",
      ...(permissionStateUnknown.length > 0
        ? [`Permission state unknown for ${permissionStateUnknown.join(", ")}: the probe failed without a permission denial, so the permission was neither confirmed nor found missing.`]
        : []),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run datadog_assess_identity, datadog_assess_access_controls, datadog_assess_security_monitoring, datadog_assess_data_protection, or datadog_export_audit_bundle."
      : status === "limited"
        ? "Grant the missing read permissions to the application key owner (or use an unscoped key owned by a Datadog Admin Role user) and rerun datadog_check_access."
        : "Verify DD_API_KEY and DD_APP_KEY belong to the same organization and that DD_SITE matches the org region.",
  };
}

function formatAccessCheckText(result: DatadogAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.permission,
    surface.count === null ? "unknown" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);

  return [
    `Datadog access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Permission", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: DatadogAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function markdownEscape(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function mappingsForFramework(item: DatadogFinding, framework: FrameworkDescriptor): string[] {
  const prefix = `${framework.label} `;
  return item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length));
}

function buildExecutiveSummary(config: DatadogResolvedConfig, assessments: DatadogAssessmentResult[], errors: string[], generatedAt: Date): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => (left.status === right.status ? severityRank(left.severity) - severityRank(right.severity) : left.status === "fail" ? -1 : 1))
    .slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");

  return [
    "# Datadog Security Inspector Executive Summary",
    "",
    `- Site: ${config.site}`,
    `- API base: ${config.baseUrl}`,
    `- Generated: ${generatedAt.toISOString()}`,
    `- Source chain: ${config.sourceChain.join(" -> ")}`,
    `- Controls assessed: ${findings.length} of 20`,
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
    ...(manual.length > 0
      ? manual.map((item) => `- ${item.id} ${item.title}: ${item.summary}`)
      : ["- Every control was verified through the API."]),
    ...(errors.length > 0 ? ["", "## Collection Warnings", "", ...errors.map((error) => `- ${error}`)] : []),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: DatadogFinding[]): string {
  const header = ["Control", "Title", "Status", "Severity", ...DATADOG_FRAMEWORKS.map((framework) => framework.label)];
  return [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...findings.map((item) => `| ${[
      item.id,
      item.title,
      item.status,
      item.severity,
      ...DATADOG_FRAMEWORKS.map((framework) => mappingsForFramework(item, framework).join(", ") || "N/A"),
    ].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildFrameworkReport(framework: FrameworkDescriptor, findings: DatadogFinding[]): string {
  const scoped = findings.filter((item) => mappingsForFramework(item, framework).length > 0);
  if (scoped.length === 0) {
    return `# ${framework.label} Report\n\nNo mapped findings were generated for this framework.\n`;
  }
  const counts = countByStatus(scoped);
  return [
    `# ${framework.label} Report`,
    "",
    `- Mapped controls: ${scoped.length}`,
    `- Pass: ${counts.pass}, Warn: ${counts.warn}, Fail: ${counts.fail}, Manual: ${counts.manual}`,
    "",
    "| Control | Title | Status | Severity | Mapping | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
    ...scoped.map((item) => `| ${[
      item.id,
      item.title,
      item.status,
      item.severity,
      mappingsForFramework(item, framework).join(", "),
      item.summary,
    ].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildQuickReference(result: { assessments: DatadogAssessmentResult[]; access: DatadogAccessCheckResult; errors: string[] }): string {
  const findings = result.assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  return [
    "# Datadog Audit Bundle Quick Reference",
    "",
    `Access check: ${result.access.status} (${result.access.surfaces.filter((surface) => surface.status === "readable").length}/${result.access.surfaces.length} surfaces readable)`,
    `Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    "## Where to look",
    "",
    "- `compliance/executive_summary.md`: prioritized findings and manual evidence list",
    "- `compliance/unified_compliance_matrix.md`: every control mapped across FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, and ISMAP",
    "- `compliance/frameworks/*.md`: one report per framework",
    "- `analysis/findings.json`: normalized findings (id, title, severity, status, summary, evidence, mappings)",
    "- `analysis/<category>.json`: per-assessment summaries and collection warnings",
    "- `core_data/*.json`: API snapshots projected to the fields the assessments read (keys are shown as last4 only, cloud integration credentials are dropped, signal and audit event payloads are reduced to identity and timing)",
    "- `core_data/access.json`: readable surfaces, missing permissions, and surfaces whose permission state is unknown",
    "- `core_data/collection_status.json`: per-inventory status, observed HTTP status, complete, seen, total, and truncation reason (null for an inventory that was not read), plus totals that count only what was observed",
    "- A `core_data` file (or field) whose `collected` is false is a not-collected marker carrying the observed status, endpoint, and redacted error; it is never an empty list. `[]` and `0` always mean the inventory was read and is empty",
    ...(result.errors.length > 0 ? ["- `_errors.log`: surfaces that failed during collection or stopped early"] : []),
    "",
    "## Controls by status",
    "",
    ...findings.map((item) => `- ${item.id} ${item.title}: ${item.status.toUpperCase()}`),
    "",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Datadog Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Datadog security inspector tools.",
    "",
    "## Contents",
    "",
    "- `QUICK_REFERENCE.md`: orientation and control status list",
    "- `compliance/executive_summary.md`: prioritized audit summary",
    "- `compliance/unified_compliance_matrix.md`: cross-framework mapping matrix",
    "- `compliance/frameworks/*.md`: per-framework reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/*.json`: API snapshots used as evidence, projected to the fields the assessments read",
    "- `core_data/collection_status.json`: whether each inventory was readable and complete, with seen and total counts; flags and counts are null for an inventory that was not read",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: present only when some surfaces failed to collect or stopped before the end of the inventory",
    "",
    "## Reading Unread Data",
    "",
    "- A `core_data` file or field whose `collected` is false is a not-collected marker (`status` carries the HTTP status the failing request observed, `endpoint` the request, `error` the redacted message); it is never an empty list",
    "- Counts, lists, and flags derived from an inventory that was denied, errored, or truncated render `null` in findings and summaries; `[]` and `0` always mean the inventory was read and is empty",
    "- Named principals (users, keys, roles, dashboards, monitors) are listed only from inventories that were read completely",
    "",
    "Credentials are never written into the bundle: API and application keys appear only as their last four characters, cloud integration credential fields are dropped at collection time, and every JSON document passes through a credential-key redactor before it is written.",
    "",
  ].join("\n");
}

/**
 * One collection-status row. `complete`, `truncated`, `seen`, and `total` describe a read that happened; on an
 * inventory that was denied or errored they render null rather than defaulting to false or zero.
 */
function surfaceStatus(inventory: string, surface: SurfaceResult<unknown>): JsonRecord {
  const descriptor = inventoryDescriptor(inventory);
  const readable = surface.value !== undefined;
  return {
    inventory,
    endpoint: descriptor.endpoint,
    permission: descriptor.permission,
    status: readable ? "readable" : surface.forbidden ? "forbidden" : "not_readable",
    collected: readable,
    readable,
    http_status: surface.httpStatus ?? null,
    complete: readable ? surface.truncated !== true : null,
    truncated: readable ? surface.truncated === true : null,
    seen: readable ? surface.seen ?? arrayCount(surface.value) ?? null : null,
    total: readable ? surface.total ?? null : null,
    limit: surface.limit ?? null,
    truncation_reason: readable ? surface.truncationReason ?? null : null,
    error: surface.error ?? null,
  };
}

/** Marker written in place of a dataset that was denied or errored; the status and endpoint are the ones the failing request observed. */
function notCollectedMarker(inventory: string, surface: SurfaceResult<unknown>): DatadogNotCollectedMarker {
  const descriptor = inventoryDescriptor(inventory);
  return {
    collected: false,
    status: surface.httpStatus ?? "error",
    endpoint: descriptor.endpoint,
    permission: descriptor.permission,
    error: describeSurfaceError(surface),
    reason: "not_readable",
  };
}

/** Marker for a dataset that was never requested (because the inventory it depends on was not read); no endpoint or status is named. */
function notAttemptedMarker(inventory: string, error: string): DatadogNotCollectedMarker {
  return {
    collected: false,
    status: "not-collected",
    endpoint: null,
    permission: inventoryDescriptor(inventory).permission,
    error,
    reason: "not_attempted",
  };
}

/** The core_data payload for a surface: its value when it was read (an empty inventory stays `[]`), the marker otherwise. */
function coreDataValue<T>(inventory: string, surface: SurfaceResult<T>): T | DatadogNotCollectedMarker {
  return surface.value === undefined ? notCollectedMarker(inventory, surface) : surface.value;
}

/** Per-role permission lists, with a marker for every custom role whose permissions were not read. */
function rolePermissionsCoreData(snapshot: DatadogIdentitySnapshot): Record<string, string[] | DatadogNotCollectedMarker> | DatadogNotCollectedMarker {
  if (snapshot.roles.value === undefined) {
    return notAttemptedMarker("role_permissions", "the role list was not read, so no per-role permission request was made");
  }
  const byRole: Record<string, string[] | DatadogNotCollectedMarker> = { ...snapshot.rolePermissions };
  for (const [key, failure] of Object.entries(snapshot.rolePermissionErrors)) {
    byRole[key] = failure.endpoint === null
      ? notAttemptedMarker("role_permissions", failure.error)
      : {
        collected: false,
        status: failure.http_status ?? "error",
        endpoint: failure.endpoint,
        permission: inventoryDescriptor("role_permissions").permission,
        error: failure.error,
        reason: "not_readable",
      };
  }
  return byRole;
}

/** Posture findings carry their own count fields because the endpoint reports a server-side total when it has one. */
function postureSurfaceStatus(inventory: string, surface: SurfaceResult<JsonRecord>): JsonRecord {
  const value = surface.value;
  if (!value) return surfaceStatus(inventory, surface);
  const truncated = asBoolean(value.truncated) === true;
  return surfaceStatus(inventory, {
    value,
    truncated,
    seen: asNumber(value.seen) ?? asRecordArray(value.data).length,
    total: asNumber(value.total_filtered_count) ?? (truncated ? undefined : asRecordArray(value.data).length),
    truncationReason: asString(value.truncation_reason),
  });
}

/**
 * One row per collected inventory: readable, complete (readable and not truncated), the seen and total counts, the
 * configured cap, and the truncation reason or error. Rule 10 wants every capped loop to be visible here, and the
 * totals count only what was observed: an inventory that was not read is neither complete nor truncated.
 */
function buildCollectionStatus(
  identity: DatadogIdentitySnapshot,
  access: DatadogAccessControlSnapshot,
  monitoring: DatadogSecurityMonitoringSnapshot,
  data: DatadogDataProtectionSnapshot,
): { inventories: JsonRecord[]; totals: JsonRecord } {
  const inventories = collectionStatusRows(identity, access, monitoring, data);
  const collected = inventories.filter((row) => row.collected === true);
  return {
    inventories,
    totals: {
      inventories: inventories.length,
      readable: collected.length,
      forbidden: inventories.filter((row) => row.status === "forbidden").length,
      not_readable: inventories.filter((row) => row.status === "not_readable").length,
      complete: collected.filter((row) => row.complete === true).length,
      truncated: collected.filter((row) => row.truncated === true).length,
      truncation_unknown: inventories.length - collected.length,
    },
  };
}

function collectionStatusRows(
  identity: DatadogIdentitySnapshot,
  access: DatadogAccessControlSnapshot,
  monitoring: DatadogSecurityMonitoringSnapshot,
  data: DatadogDataProtectionSnapshot,
): JsonRecord[] {
  return [
    surfaceStatus("organization", identity.organization),
    surfaceStatus("users", identity.users),
    surfaceStatus("roles", identity.roles),
    surfaceStatus("application_keys", access.applicationKeys),
    surfaceStatus("org_configs", identity.orgConfigs),
    surfaceStatus("api_keys", access.apiKeys),
    surfaceStatus("shared_dashboards", access.sharedDashboards),
    surfaceStatus("ip_allowlist", access.ipAllowlist),
    surfaceStatus("aws_integrations", access.awsIntegrations),
    surfaceStatus("gcp_integrations", access.gcpIntegrations),
    surfaceStatus("azure_integrations", access.azureIntegrations),
    surfaceStatus("security_rules", monitoring.rules),
    surfaceStatus("security_signals", monitoring.signals),
    postureSurfaceStatus("posture_findings_fail", monitoring.postureFailing),
    postureSurfaceStatus("posture_findings_pass", monitoring.posturePassing),
    surfaceStatus("monitors", monitoring.monitors),
    surfaceStatus("audit_events_oldest", data.oldestAuditEvents),
    surfaceStatus("audit_events_recent", data.recentAuditEvents),
    surfaceStatus("log_pipelines", data.pipelines),
    surfaceStatus("log_indexes", data.indexes),
    surfaceStatus("log_archives", data.archives),
    surfaceStatus("sensitive_data_scanner", data.sensitiveDataScanner),
    surfaceStatus("org_connections", data.orgConnections),
  ];
}

/** Every JSON document in the bundle passes through the credential redactor before it is written. */
async function writeBundleJson(outputDir: string, pathname: string, value: unknown): Promise<void> {
  await writeSecureTextFile(outputDir, pathname, serializeJson(redactCredentialValues(value)));
}

export async function exportDatadogAuditBundle(
  client: BundleReader,
  config: DatadogResolvedConfig,
  outputRoot: string,
  options: DatadogAssessmentOptions = {},
): Promise<DatadogAuditBundleResult> {
  const now = options.now ?? new Date();
  const access = await checkDatadogAccess(client);
  const identitySnapshot = await collectDatadogIdentityData(client, options);
  const accessSnapshot = await collectDatadogAccessControlData(client, options);
  const monitoringSnapshot = await collectDatadogSecurityMonitoringData(client, options);
  const dataSnapshot = await collectDatadogDataProtectionData(client, options);

  const assessments = [
    evaluateDatadogIdentity(identitySnapshot, { ...options, now }),
    evaluateDatadogAccessControls(accessSnapshot, { ...options, now }),
    evaluateDatadogSecurityMonitoring(monitoringSnapshot, { ...options, now }),
    evaluateDatadogDataProtection(dataSnapshot, { ...options, now }),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set([
    ...identitySnapshot.errors,
    ...accessSnapshot.errors,
    ...monitoringSnapshot.errors,
    ...dataSnapshot.errors,
  ])];

  ensurePrivateDir(outputRoot);
  const bundleName = `${safeDirName(config.site)}-audit-bundle`;
  const outputDir = await nextAvailableAuditDir(outputRoot, bundleName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference({ assessments, access, errors }));
  await writeBundleJson(outputDir, "metadata.json", {
    generated_at: now.toISOString(),
    site: config.site,
    api_base_url: config.baseUrl,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    ...countByStatus(findings),
  });

  // A dataset that was denied or errored is written as a not-collected marker (never `[]`), so a bundle consumer
  // cannot mistake a denial for an empty inventory; a dataset that was read and is empty stays `[]`.
  const coreData: Array<[string, unknown]> = [
    ["core_data/access.json", access],
    ["core_data/collection_status.json", buildCollectionStatus(identitySnapshot, accessSnapshot, monitoringSnapshot, dataSnapshot)],
    ["core_data/organization.json", coreDataValue("organization", identitySnapshot.organization)],
    ["core_data/users.json", coreDataValue("users", identitySnapshot.users)],
    ["core_data/roles.json", { roles: coreDataValue("roles", identitySnapshot.roles), permissions_by_role: rolePermissionsCoreData(identitySnapshot) }],
    ["core_data/org_configs.json", coreDataValue("org_configs", identitySnapshot.orgConfigs)],
    ["core_data/api_keys.json", coreDataValue("api_keys", accessSnapshot.apiKeys)],
    ["core_data/application_keys.json", coreDataValue("application_keys", accessSnapshot.applicationKeys)],
    ["core_data/shared_dashboards.json", coreDataValue("shared_dashboards", accessSnapshot.sharedDashboards)],
    ["core_data/ip_allowlist.json", coreDataValue("ip_allowlist", accessSnapshot.ipAllowlist)],
    ["core_data/cloud_integrations.json", {
      aws: coreDataValue("aws_integrations", accessSnapshot.awsIntegrations),
      gcp: coreDataValue("gcp_integrations", accessSnapshot.gcpIntegrations),
      azure: coreDataValue("azure_integrations", accessSnapshot.azureIntegrations),
    }],
    ["core_data/security_rules.json", coreDataValue("security_rules", monitoringSnapshot.rules)],
    ["core_data/security_signals.json", coreDataValue("security_signals", monitoringSnapshot.signals)],
    ["core_data/posture_findings.json", {
      failing: coreDataValue("posture_findings_fail", monitoringSnapshot.postureFailing),
      passing: coreDataValue("posture_findings_pass", monitoringSnapshot.posturePassing),
    }],
    ["core_data/monitors.json", coreDataValue("monitors", monitoringSnapshot.monitors)],
    ["core_data/audit_events.json", {
      oldest: coreDataValue("audit_events_oldest", dataSnapshot.oldestAuditEvents),
      recent: coreDataValue("audit_events_recent", dataSnapshot.recentAuditEvents),
    }],
    ["core_data/log_pipelines.json", coreDataValue("log_pipelines", dataSnapshot.pipelines)],
    ["core_data/log_indexes.json", coreDataValue("log_indexes", dataSnapshot.indexes)],
    ["core_data/log_archives.json", coreDataValue("log_archives", dataSnapshot.archives)],
    ["core_data/sensitive_data_scanner.json", coreDataValue("sensitive_data_scanner", dataSnapshot.sensitiveDataScanner)],
    ["core_data/org_connections.json", coreDataValue("org_connections", dataSnapshot.orgConnections)],
  ];
  for (const [pathname, value] of coreData) {
    await writeBundleJson(outputDir, pathname, value);
  }

  await writeBundleJson(outputDir, "analysis/findings.json", findings);
  for (const assessment of assessments) {
    await writeBundleJson(outputDir, `analysis/${assessment.category}.json`, assessment);
  }
  await writeBundleJson(outputDir, "analysis/summary.json", {
    controls_assessed: findings.length,
    ...countByStatus(findings),
    categories: assessments.map((assessment) => ({ category: assessment.category, ...countByStatus(assessment.findings) })),
  });

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, now));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of DATADOG_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.file}.md`, buildFrameworkReport(framework, findings));
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

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    api_key: asString(value.api_key),
    app_key: asString(value.app_key),
    site: asString(value.site),
    base_url: asString(value.base_url),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
    max_retries: asNumber(value.max_retries),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    role_limit: asNumber(value.role_limit),
    key_limit: asNumber(value.key_limit),
    max_admins: asNumber(value.max_admins),
    inactive_days: asNumber(value.inactive_days),
    pending_invite_days: asNumber(value.pending_invite_days),
    key_rotation_days: asNumber(value.key_rotation_days),
    service_account_pattern: asString(value.service_account_pattern),
  };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    key_limit: asNumber(value.key_limit),
    key_rotation_days: asNumber(value.key_rotation_days),
    key_unused_days: asNumber(value.key_unused_days),
  };
}

function normalizeSecurityMonitoringArgs(args: unknown): SecurityMonitoringArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    rule_limit: asNumber(value.rule_limit),
    signal_limit: asNumber(value.signal_limit),
    signal_sla_hours: asNumber(value.signal_sla_hours),
    signal_lookback_days: asNumber(value.signal_lookback_days),
    monitor_limit: asNumber(value.monitor_limit),
    finding_limit: asNumber(value.finding_limit),
    min_posture_pass_rate: asNumber(value.min_posture_pass_rate),
    required_frameworks: asString(value.required_frameworks),
  };
}

function normalizeDataProtectionArgs(args: unknown): DataProtectionArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    min_audit_retention_days: asNumber(value.min_audit_retention_days),
    min_log_retention_days: asNumber(value.min_log_retention_days),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeAccessControlArgs(args),
    ...normalizeSecurityMonitoringArgs(args),
    ...normalizeDataProtectionArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function parseFrameworkList(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  const items = value.split(/[,\s]+/).map((item) => item.trim().toLowerCase()).filter(Boolean);
  return items.length > 0 ? items : undefined;
}

function identityOptions(args: IdentityArgs): DatadogIdentityOptions {
  return {
    userLimit: args.user_limit,
    roleLimit: args.role_limit,
    keyLimit: args.key_limit,
    maxAdmins: args.max_admins,
    inactiveDays: args.inactive_days,
    pendingInviteDays: args.pending_invite_days,
    keyRotationDays: args.key_rotation_days,
    serviceAccountPattern: args.service_account_pattern,
  };
}

function accessControlOptions(args: AccessControlArgs): DatadogAccessControlOptions {
  return {
    keyLimit: args.key_limit,
    keyRotationDays: args.key_rotation_days,
    keyUnusedDays: args.key_unused_days,
  };
}

function securityMonitoringOptions(args: SecurityMonitoringArgs): DatadogSecurityMonitoringOptions {
  return {
    ruleLimit: args.rule_limit,
    signalLimit: args.signal_limit,
    signalSlaHours: args.signal_sla_hours,
    signalLookbackDays: args.signal_lookback_days,
    monitorLimit: args.monitor_limit,
    findingLimit: args.finding_limit,
    minPosturePassRate: args.min_posture_pass_rate,
    requiredFrameworks: parseFrameworkList(args.required_frameworks),
  };
}

function dataProtectionOptions(args: DataProtectionArgs): DatadogDataProtectionOptions {
  return {
    minAuditRetentionDays: args.min_audit_retention_days,
    minLogRetentionDays: args.min_log_retention_days,
  };
}

function createClient(args: CheckAccessArgs): DatadogApiClient {
  return new DatadogApiClient(resolveDatadogConfiguration(args));
}

const authParams = {
  api_key: Type.Optional(Type.String({ description: "Datadog API key. Defaults to DD_API_KEY, then apikey in ~/.dogrc." })),
  app_key: Type.Optional(Type.String({ description: "Datadog application key. Defaults to DD_APP_KEY (or DD_APPLICATION_KEY), then appkey in ~/.dogrc." })),
  site: Type.Optional(Type.String({ description: "Datadog site such as datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, ap1.datadoghq.com, or ddog-gov.com. Defaults to DD_SITE, then datadoghq.com." })),
  base_url: Type.Optional(Type.String({ description: "Explicit API base URL override (for example https://api.ddog-gov.com). Defaults to DD_HOST or https://api.<site>." })),
  config_file: Type.Optional(Type.String({ description: "Path to a dogshell-style INI config with a [Connection] section (apikey, appkey, api_host). Defaults to DD_CONFIG_FILE, then ~/.dogrc." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  max_retries: Type.Optional(Type.Number({ description: "Retries for 429 and 5xx responses (429 honors X-RateLimit-Reset). Defaults to 3.", default: 3 })),
};

const identityParams = {
  user_limit: Type.Optional(Type.Number({ description: "Maximum users to inspect; a larger inventory is reported as truncated and caps the verdict at warn. Defaults to 2000.", default: DEFAULT_USER_LIMIT })),
  role_limit: Type.Optional(Type.Number({ description: "Maximum roles to inspect (every listed custom role has its permissions expanded); a larger inventory is reported as truncated. Defaults to 100.", default: DEFAULT_ROLE_LIMIT })),
  key_limit: Type.Optional(Type.Number({ description: "Maximum application keys to inspect for service account key rotation; a larger inventory is reported as truncated. Defaults to 500.", default: DEFAULT_KEY_LIMIT })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Datadog Admin Role members before warning. Defaults to 10.", default: DEFAULT_MAX_ADMINS })),
  inactive_days: Type.Optional(Type.Number({ description: "Days without login before an active user is flagged. Defaults to 90.", default: DEFAULT_INACTIVE_USER_DAYS })),
  pending_invite_days: Type.Optional(Type.Number({ description: "Days before a pending invitation is flagged. Defaults to 30.", default: DEFAULT_PENDING_INVITE_DAYS })),
  key_rotation_days: Type.Optional(Type.Number({ description: "Rotation window in days for service account application keys. Defaults to 90.", default: DEFAULT_KEY_ROTATION_DAYS })),
  service_account_pattern: Type.Optional(Type.String({ description: "Regular expression that service account handles or names must match. Defaults to common svc/sa/bot/automation prefixes." })),
};

const accessControlParams = {
  key_limit: Type.Optional(Type.Number({ description: "Maximum API and application keys to inspect. Defaults to 500.", default: DEFAULT_KEY_LIMIT })),
  key_rotation_days: Type.Optional(Type.Number({ description: "Rotation window in days for API keys. Defaults to 90.", default: DEFAULT_KEY_ROTATION_DAYS })),
  key_unused_days: Type.Optional(Type.Number({ description: "Days without use before an API key is flagged as stale. Defaults to 30.", default: DEFAULT_KEY_UNUSED_DAYS })),
};

const securityMonitoringParams = {
  rule_limit: Type.Optional(Type.Number({ description: "Maximum security monitoring rules to inspect. Defaults to 1000.", default: DEFAULT_RULE_LIMIT })),
  signal_limit: Type.Optional(Type.Number({ description: "Maximum unresolved high or critical signals to inspect. Defaults to 200.", default: DEFAULT_SIGNAL_LIMIT })),
  signal_sla_hours: Type.Optional(Type.Number({ description: "Hours before an unresolved high or critical signal breaches SLA. Defaults to 72.", default: DEFAULT_SIGNAL_SLA_HOURS })),
  signal_lookback_days: Type.Optional(Type.Number({ description: "Days of signal history to search. Defaults to 30.", default: DEFAULT_SIGNAL_LOOKBACK_DAYS })),
  monitor_limit: Type.Optional(Type.Number({ description: "Maximum monitors to inspect. Defaults to 1000.", default: DEFAULT_MONITOR_LIMIT })),
  finding_limit: Type.Optional(Type.Number({ description: "Maximum CSPM posture findings to page through per evaluation when the API omits total_filtered_count. Defaults to 10000.", default: DEFAULT_FINDING_LIMIT })),
  min_posture_pass_rate: Type.Optional(Type.Number({ description: "Minimum CSPM posture passing rate (0 to 1). Defaults to 0.8.", default: DEFAULT_MIN_POSTURE_PASS_RATE })),
  required_frameworks: Type.Optional(Type.String({ description: "Comma-separated compliance frameworks that must have enabled rules. Defaults to cis,pci,soc2,hipaa.", default: DEFAULT_REQUIRED_FRAMEWORKS.join(",") })),
};

const dataProtectionParams = {
  min_audit_retention_days: Type.Optional(Type.Number({ description: "Minimum Audit Trail retention in days to confirm from the oldest available event. Defaults to 90.", default: DEFAULT_AUDIT_RETENTION_DAYS })),
  min_log_retention_days: Type.Optional(Type.Number({ description: "Minimum log index retention in days before warning. Defaults to 30.", default: DEFAULT_MIN_LOG_RETENTION_DAYS })),
};

export function registerDatadogTools(pi: any): void {
  pi.registerTool({
    name: "datadog_check_access",
    label: "Check Datadog audit access",
    description:
      "Validate the Datadog API key and probe every read surface the inspector needs (org settings, users, roles, API and application keys, audit events, security rules and signals, posture findings, IP allowlist, Sensitive Data Scanner, log pipelines, indexes, archives, dashboards, monitors, cloud integrations), reporting missing application key permissions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkDatadogAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "datadog_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Datadog access check failed: ${errorMessage(error)}`,
          { tool: "datadog_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "datadog_assess_identity",
    label: "Assess Datadog identity posture",
    description:
      "Assess Datadog identity controls: SAML SSO enforcement (control 1), MFA status (2), custom role least privilege (3), user access review (4), session timeout (16, manual), and service account audit (19).",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessDatadogIdentity(createClient(args), identityOptions(args));
        return textResult(formatAssessmentText(result), { tool: "datadog_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Datadog identity assessment failed: ${errorMessage(error)}`,
          { tool: "datadog_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "datadog_assess_access_controls",
    label: "Assess Datadog key, sharing, and network controls",
    description:
      "Assess Datadog access controls: API key rotation (control 5), application key scoping and ownership (6), public dashboard restrictions (14), IP allowlisting (15), and integration permissions (18, manual with API-visible evidence).",
    parameters: Type.Object({ ...authParams, ...accessControlParams }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await assessDatadogAccessControls(createClient(args), accessControlOptions(args));
        return textResult(formatAssessmentText(result), { tool: "datadog_assess_access_controls", ...result });
      } catch (error) {
        return errorResult(
          `Datadog access control assessment failed: ${errorMessage(error)}`,
          { tool: "datadog_assess_access_controls" },
        );
      }
    },
  });

  pi.registerTool({
    name: "datadog_assess_security_monitoring",
    label: "Assess Datadog Cloud SIEM and CSM posture",
    description:
      "Assess Datadog security monitoring: detection rules enabled (control 8), unresolved high and critical signals against SLA (9), CSPM enablement and posture passing rate (12), compliance framework rule coverage (13), and security monitor notification channels (17).",
    parameters: Type.Object({ ...authParams, ...securityMonitoringParams }),
    prepareArguments: normalizeSecurityMonitoringArgs,
    async execute(_toolCallId: string, args: SecurityMonitoringArgs) {
      try {
        const result = await assessDatadogSecurityMonitoring(createClient(args), securityMonitoringOptions(args));
        return textResult(formatAssessmentText(result), { tool: "datadog_assess_security_monitoring", ...result });
      } catch (error) {
        return errorResult(
          `Datadog security monitoring assessment failed: ${errorMessage(error)}`,
          { tool: "datadog_assess_security_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "datadog_assess_data_protection",
    label: "Assess Datadog audit trail and log protection",
    description:
      "Assess Datadog data protection: Audit Trail activity and inferred retention (control 7), log pipeline, index exclusion, and archive security (10), Sensitive Data Scanner coverage (11), and organization retention and sharing settings (20).",
    parameters: Type.Object({ ...authParams, ...dataProtectionParams }),
    prepareArguments: normalizeDataProtectionArgs,
    async execute(_toolCallId: string, args: DataProtectionArgs) {
      try {
        const result = await assessDatadogDataProtection(createClient(args), dataProtectionOptions(args));
        return textResult(formatAssessmentText(result), { tool: "datadog_assess_data_protection", ...result });
      } catch (error) {
        return errorResult(
          `Datadog data protection assessment failed: ${errorMessage(error)}`,
          { tool: "datadog_assess_data_protection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "datadog_export_audit_bundle",
    label: "Export Datadog audit bundle",
    description:
      "Export a Datadog audit package covering all 20 spec controls: raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...identityParams,
      ...accessControlParams,
      ...securityMonitoringParams,
      ...dataProtectionParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveDatadogConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportDatadogAuditBundle(new DatadogApiClient(config), config, outputRoot, {
          ...identityOptions(args),
          ...accessControlOptions(args),
          ...securityMonitoringOptions(args),
          ...dataProtectionOptions(args),
        });
        return textResult(
          [
            "Datadog audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "datadog_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Datadog audit bundle export failed: ${errorMessage(error)}`,
          { tool: "datadog_export_audit_bundle" },
        );
      }
    },
  });
}
