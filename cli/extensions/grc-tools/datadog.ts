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
  endpoint: string;
  permission: string;
  status: "readable" | "forbidden" | "not_readable";
  count?: number;
  error?: string;
}

export interface DatadogAccessCheckResult {
  status: "healthy" | "limited" | "failed";
  site: string;
  apiKeyValid: boolean;
  keyPairValid: boolean;
  surfaces: DatadogAccessSurface[];
  missingPermissions: string[];
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

interface SurfaceResult<T> {
  value?: T;
  error?: string;
  forbidden?: boolean;
  truncated?: boolean;
  limit?: number;
}

export interface DatadogIdentitySnapshot {
  organization: SurfaceResult<JsonRecord>;
  users: SurfaceResult<JsonRecord[]>;
  roles: SurfaceResult<JsonRecord[]>;
  rolePermissions: Record<string, string[]>;
  rolePermissionErrors: Record<string, string>;
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

function readDogrc(location: string): DogrcOverlay | undefined {
  if (!existsSync(location)) return undefined;
  return parseDogrc(readFileSync(location, "utf8"));
}

export function resolveDatadogConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
): DatadogResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file)
    ?? asString(env.DD_CONFIG_FILE)
    ?? asString(env.DATADOG_CONFIG_FILE)
    ?? join(homeDir, ".dogrc");
  const fileOverlay = readDogrc(configPath) ?? {};

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
    super(message);
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
  return [asString(object.message), asString(object.error), ...errors]
    .filter((item): item is string => Boolean(item))
    .join("; ") || undefined;
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
  }

  getResolvedConfig(): DatadogResolvedConfig {
    return this.config;
  }

  private redact(message: string): string {
    let output = message;
    for (const secret of [this.config.apiKey, this.config.appKey]) {
      if (secret.length >= 8) output = output.split(secret).join("[REDACTED]");
    }
    return output;
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
        throw new Error(`Datadog request timed out after ${this.config.timeoutMs}ms: ${method} ${new URL(url).pathname}`);
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(this.redact(`Datadog request failed: ${method} ${new URL(url).pathname}: ${message}`));
    } finally {
      clearTimeout(timeout);
    }
  }

  async request(method: string, path: string, query: JsonRecord = {}, body?: unknown): Promise<unknown> {
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
      if (rawText.length > 0) {
        try {
          payload = JSON.parse(rawText) as unknown;
        } catch {
          payload = { message: rawText.slice(0, 240) };
        }
      }

      if (!response.ok) {
        const detail = datadogErrorSummary(payload) ?? rawText.slice(0, 240);
        throw new DatadogApiError(
          this.redact(`Datadog request failed (${response.status} ${response.statusText}) ${method} ${path}${detail ? `: ${detail}` : ""}`),
          response.status,
          path,
        );
      }
      return payload;
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("GET", path, query);
  }

  async post(path: string, body: unknown, query: JsonRecord = {}): Promise<unknown> {
    return this.request("POST", path, query, body);
  }

  private async listNumbered(
    path: string,
    query: JsonRecord,
    limit: number,
    pageSize: number = V2_PAGE_SIZE,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    const size = Math.min(pageSize, limit);
    for (let page = 0; items.length < limit; page += 1) {
      const payload = asObject(await this.get(path, { ...query, "page[size]": size, "page[number]": page })) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      const total = asNumber(getNestedValue(payload, ["meta", "page", "total_filtered_count"]))
        ?? asNumber(getNestedValue(payload, ["meta", "page", "total_count"]));
      if (data.length < size || (total !== undefined && items.length >= total)) break;
    }
    return items;
  }

  private async listCursor(
    path: string,
    query: JsonRecord,
    limit: number,
    cursorPath: string[],
    pageSize: number = CURSOR_PAGE_SIZE,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    const size = Math.min(pageSize, limit);
    let cursor: string | undefined;
    while (items.length < limit) {
      const payload = asObject(await this.get(path, { ...query, "page[limit]": size, "page[cursor]": cursor })) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      const nextCursor = asString(getNestedValue(payload, cursorPath));
      if (!nextCursor || data.length === 0 || nextCursor === cursor) break;
      cursor = nextCursor;
    }
    return items;
  }

  async validateApiKey(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v1/validate")) ?? {};
  }

  async validateKeyPair(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/validate_keys")) ?? {};
  }

  async getOrganization(): Promise<JsonRecord> {
    const payload = asObject(await this.get("/api/v1/org")) ?? {};
    const orgs = asRecordArray(payload.orgs);
    return orgs[0] ?? payload;
  }

  async listOrgConfigs(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/org_configs")) ?? {};
    return asRecordArray(payload.data);
  }

  async listOrgConnections(limit = DEFAULT_ORG_CONNECTION_LIMIT): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    const pageSize = Math.min(ORG_CONNECTION_PAGE_SIZE, limit);
    for (let offset = 0; items.length < limit; offset += pageSize) {
      const payload = asObject(await this.get("/api/v2/org_connections", { limit: pageSize, offset })) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      const total = asNumber(getNestedValue(payload, ["meta", "page", "total_filtered_count"]))
        ?? asNumber(getNestedValue(payload, ["meta", "page", "total_count"]));
      if (data.length < pageSize || (total !== undefined && items.length >= total)) break;
    }
    return items;
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.listNumbered("/api/v2/users", {}, limit);
  }

  async listRoles(limit = DEFAULT_ROLE_LIMIT): Promise<JsonRecord[]> {
    return this.listNumbered("/api/v2/roles", {}, limit);
  }

  async listRolePermissions(roleId: string): Promise<JsonRecord[]> {
    const payload = asObject(await this.get(`/api/v2/roles/${encodeURIComponent(roleId)}/permissions`)) ?? {};
    return asRecordArray(payload.data);
  }

  async listPermissions(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/permissions")) ?? {};
    return asRecordArray(payload.data);
  }

  async listApiKeys(limit = DEFAULT_KEY_LIMIT): Promise<JsonRecord[]> {
    return this.listNumbered("/api/v2/api_keys", { include: "created_by" }, limit);
  }

  async listApplicationKeys(limit = DEFAULT_KEY_LIMIT): Promise<JsonRecord> {
    const items: JsonRecord[] = [];
    const included: JsonRecord[] = [];
    const size = Math.min(V2_PAGE_SIZE, limit);
    for (let page = 0; items.length < limit; page += 1) {
      const payload = asObject(await this.get("/api/v2/application_keys", {
        include: "owned_by",
        "page[size]": size,
        "page[number]": page,
      })) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      included.push(...asRecordArray(payload.included));
      if (data.length < size) break;
    }
    return { data: items, included };
  }

  async listCurrentUserApplicationKeys(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/current_user/application_keys", { "page[size]": V2_PAGE_SIZE })) ?? {};
    return asRecordArray(payload.data);
  }

  async listAuditEvents(options: {
    from?: string;
    to?: string;
    query?: string;
    sort?: "timestamp" | "-timestamp";
    limit?: number;
  } = {}): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, 100, 1, 5000);
    return this.listCursor("/api/v2/audit/events", {
      "filter[query]": options.query,
      "filter[from]": options.from,
      "filter[to]": options.to,
      sort: options.sort ?? "-timestamp",
    }, limit, ["meta", "page", "after"]);
  }

  async listSecurityRules(limit = DEFAULT_RULE_LIMIT): Promise<JsonRecord[]> {
    return this.listNumbered("/api/v2/security_monitoring/rules", {}, limit);
  }

  async listSecuritySignals(options: {
    query?: string;
    from?: string;
    to?: string;
    sort?: "timestamp" | "-timestamp";
    limit?: number;
  } = {}): Promise<JsonRecord[]> {
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
    for (;;) {
      const payload = asObject(await this.get("/api/v2/posture_management/findings", {
        "filter[evaluation]": options.evaluation,
        "filter[status]": options.status,
        "page[limit]": pageSize,
        "page[cursor]": cursor,
      })) ?? {};
      const data = asRecordArray(payload.data);
      items.push(...data.slice(0, limit - items.length));
      totalFilteredCount ??= asNumber(getNestedValue(payload, ["meta", "page", "total_filtered_count"])) ?? null;
      const nextCursor = asString(getNestedValue(payload, ["meta", "page", "cursor"]));
      if (totalFilteredCount !== null) break;
      if (!nextCursor || data.length === 0 || nextCursor === cursor) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
      cursor = nextCursor;
    }
    return { data: items, total_filtered_count: totalFilteredCount, truncated };
  }

  async getIpAllowlist(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/ip_allowlist")) ?? {};
  }

  async getSensitiveDataScannerConfig(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v2/sensitive-data-scanner/config")) ?? {};
  }

  async listLogPipelines(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/logs/config/pipelines"));
  }

  async getLogPipelineOrder(): Promise<JsonRecord> {
    return asObject(await this.get("/api/v1/logs/config/pipeline-order")) ?? {};
  }

  async listLogIndexes(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v1/logs/config/indexes")) ?? {};
    return asRecordArray(payload.indexes);
  }

  async listLogArchives(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v2/logs/config/archives")) ?? {};
    return asRecordArray(payload.data);
  }

  async listDashboards(options: { shared?: boolean; limit?: number } = {}): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_DASHBOARD_LIMIT, 1, 100000);
    const pageSize = Math.min(DASHBOARD_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    for (let start = 0; items.length < limit; start += pageSize) {
      const payload = asObject(await this.get("/api/v1/dashboard", {
        "filter[shared]": options.shared === undefined ? undefined : String(options.shared),
        count: pageSize,
        start,
      })) ?? {};
      const data = asRecordArray(payload.dashboards);
      items.push(...data.slice(0, limit - items.length));
      if (data.length < pageSize) break;
    }
    return items;
  }

  async listMonitors(limit = DEFAULT_MONITOR_LIMIT): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    const pageSize = Math.min(MONITOR_PAGE_SIZE, limit);
    for (let page = 0; items.length < limit; page += 1) {
      const data = asRecordArray(await this.get("/api/v1/monitor", { page, page_size: pageSize }));
      items.push(...data.slice(0, limit - items.length));
      if (data.length < pageSize) break;
    }
    return items;
  }

  async listAwsIntegrations(): Promise<JsonRecord[]> {
    const payload = asObject(await this.get("/api/v1/integration/aws")) ?? {};
    return asRecordArray(payload.accounts);
  }

  async listGcpIntegrations(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/integration/gcp"));
  }

  async listAzureIntegrations(): Promise<JsonRecord[]> {
    return asRecordArray(await this.get("/api/v1/integration/azure"));
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isForbidden(error: unknown): boolean {
  return error instanceof DatadogApiError && (error.status === 401 || error.status === 403);
}

async function loadSurface<T>(label: string, load: () => Promise<T>, errors: string[]): Promise<SurfaceResult<T>> {
  try {
    return { value: await load() };
  } catch (error) {
    const message = errorMessage(error);
    errors.push(`${label}: ${message}`);
    return { error: message, forbidden: isForbidden(error) };
  }
}

async function loadInventory(
  label: string,
  limit: number,
  load: (probeLimit: number) => Promise<JsonRecord[]>,
  errors: string[],
): Promise<SurfaceResult<JsonRecord[]>> {
  const result = await loadSurface(label, () => load(limit + 1), errors);
  if (!result.value) return result;
  if (result.value.length > limit) {
    errors.push(`${label}: inventory truncated at ${limit} items; raise the matching limit argument to inspect the full list`);
    return { value: result.value.slice(0, limit), truncated: true, limit };
  }
  return { value: result.value, truncated: false, limit };
}

function unreadableSurfaces(entries: Array<[string, SurfaceResult<unknown>]>): string[] {
  return entries
    .filter(([, surface]) => surface.value === undefined)
    .map(([label, surface]) => `${label} (${surface.forbidden ? "403 forbidden" : surface.error ?? "unknown error"})`);
}

function unreadableSurfacesReason(unreadable: string[]): string {
  return `The following surfaces were not readable, so this control could not be verified through the API: ${unreadable.join("; ")}.`;
}

function truncationCaveat(label: string, surface: SurfaceResult<unknown>, limitArgument: string): string | undefined {
  if (!surface.truncated) return undefined;
  return `${label} inventory is truncated at ${surface.limit ?? "the configured limit of"} items (raise ${limitArgument}), so the verdict covers a partial view.`;
}

function withVerdictCaveats(finding: DatadogFinding, caveats: Array<string | undefined>): DatadogFinding {
  const active = caveats.filter((caveat): caveat is string => Boolean(caveat));
  if (active.length === 0) return finding;
  const evidence = { ...finding.evidence, verdict_caveats: active };
  if (finding.status !== "pass") return { ...finding, evidence };
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

function unreadableReason(label: string, surface: SurfaceResult<unknown>): string {
  return surface.forbidden
    ? `The ${label} surface returned 403, so this control could not be verified through the API.`
    : `The ${label} surface was not readable (${surface.error ?? "unknown error"}), so this control could not be verified through the API.`;
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

  const [organization, users, roles, applicationKeys, orgConfigs] = await Promise.all([
    loadSurface("organization", () => client.getOrganization(), errors),
    loadInventory("users", userLimit, (probeLimit) => client.listUsers(probeLimit), errors),
    loadInventory("roles", roleLimit, (probeLimit) => client.listRoles(probeLimit), errors),
    loadApplicationKeyInventory(client, DEFAULT_KEY_LIMIT, errors),
    loadSurface("org_configs", () => client.listOrgConfigs(), errors),
  ]);

  const rolePermissions: Record<string, string[]> = {};
  const rolePermissionErrors: Record<string, string> = {};
  const customRoles = (roles.value ?? []).filter((role) => !isDefaultRole(role));
  await Promise.all(customRoles.map(async (role) => {
    const roleId = asString(role.id);
    if (!roleId) {
      rolePermissionErrors[roleName(role)] = "role record has no id";
      return;
    }
    try {
      const permissions = await client.listRolePermissions(roleId);
      rolePermissions[roleId] = permissions.map(permissionName).filter((name): name is string => Boolean(name));
    } catch (error) {
      const message = errorMessage(error);
      rolePermissionErrors[roleId] = message;
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
  if (data.length > limit) {
    errors.push(`application_keys: inventory truncated at ${limit} items; raise key_limit to inspect the full list`);
    return { value: { ...result.value, data: data.slice(0, limit) }, truncated: true, limit };
  }
  return { value: result.value, truncated: false, limit };
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
  const idpInitiated = settingEnabled(settings, "saml_idp_initiated_login") === true;
  const metadataUploaded = asBoolean(settings.saml_idp_metadata_uploaded);
  const evidence = {
    saml_enabled: samlSetting ?? null,
    saml_strict_mode: strictSetting ?? null,
    saml_idp_initiated_login: idpInitiated,
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
  const users = snapshot.users.value.map(userAttributes);
  const activeHumans = users.filter((user) => user.status === "active" && !user.disabled && !user.serviceAccount);
  const withoutMfa = activeHumans.filter((user) => user.mfaEnabled !== true);
  const evidence = {
    users_returned: users.length,
    active_human_users: activeHumans.length,
    users_without_native_mfa: withoutMfa.length,
    users_without_native_mfa_sample: sample(withoutMfa.map((user) => user.handle)),
    saml_strict_mode: strictSaml,
    users_inventory_truncated: snapshot.users.truncated ?? false,
  };
  if (users.length === 0) {
    return manualFinding(2, "critical", "The users endpoint returned no users, which cannot be a complete inventory because the application key in use belongs to a user; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Users and confirm every active human user has MFA enabled or authenticates only through a SAML IdP that enforces MFA.",
    ], evidence);
  }
  const caveats = [truncationCaveat("users", snapshot.users, "user_limit")];
  if (activeHumans.length === 0) {
    return finding(2, "critical", "warn", `${users.length} users were returned but none is an active human user, so MFA coverage could not be measured; review the disabled and service account population manually.`, evidence);
  }
  if (withoutMfa.length === 0) {
    return withVerdictCaveats(
      finding(2, "critical", "pass", `All ${activeHumans.length} active human users have Datadog MFA enabled (mfa_enabled was read as true for each of them).`, evidence),
      caveats,
    );
  }
  if (strictSaml) {
    return manualFinding(
      2,
      "critical",
      `${withoutMfa.length}/${activeHumans.length} active users lack Datadog-native MFA. SAML strict mode disables password login, but the Datadog API does not expose whether the identity provider enforces a second factor, so IdP MFA cannot be confirmed here.`,
      [
        "Capture the identity provider sign-on policy for the Datadog application showing MFA is required for every assigned user (for example an Okta authentication policy or Entra ID conditional access policy) and export the IdP MFA enrollment report for the listed users.",
      ],
      evidence,
    );
  }
  return finding(
    2,
    "critical",
    "fail",
    `${withoutMfa.length}/${activeHumans.length} active human users can sign in with a password and do not have MFA enabled.`,
    evidence,
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
  const unresolvedDetail = unresolved.map((role) => ({
    role: roleName(role),
    error: snapshot.rolePermissionErrors[asString(role.id) ?? roleName(role)] ?? "permissions were not collected",
  }));
  const evidence = {
    total_roles: roles.length,
    custom_roles: customRoles.length,
    custom_roles_with_admin_equivalent_permissions: overPrivileged.map((role) => ({ role: role.name, permissions: role.granted })),
    admin_role_user_count: adminCount ?? null,
    total_users: totalUsers ?? null,
    max_admins: maxAdmins,
    custom_roles_without_permission_detail: unresolved.length,
    custom_roles_without_permission_detail_sample: sample(unresolvedDetail),
    roles_inventory_truncated: snapshot.roles.truncated ?? false,
  };
  if (roles.length === 0) {
    return manualFinding(3, "high", "The roles endpoint returned no roles, which cannot be a complete inventory because every organization has the three managed Datadog roles; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Roles with each custom role's permission list and the Datadog Admin Role membership count.",
    ], evidence);
  }
  if (overPrivileged.length > 0) {
    return withVerdictCaveats(
      finding(
        3,
        "high",
        "fail",
        `${overPrivileged.length}/${customRoles.length} custom roles grant admin-equivalent permissions (${ADMIN_EQUIVALENT_PERMISSIONS.join(", ")}).`,
        evidence,
      ),
      [
        unresolved.length > 0 ? `${unresolved.length} custom roles could not have their permissions read.` : undefined,
        truncationCaveat("roles", snapshot.roles, "role_limit"),
      ],
    );
  }
  if (unresolved.length > 0) {
    return manualFinding(
      3,
      "high",
      `${unresolved.length}/${customRoles.length} custom roles could not have their permissions read (GET /api/v2/roles/{id}/permissions failed), so admin-equivalent grants could not be ruled out.`,
      [
        `Export the permission list for ${unresolved.map((role) => roleName(role)).slice(0, MAX_EVIDENCE_SAMPLES).join(", ")} from Organization Settings > Roles and confirm none grants ${ADMIN_EQUIVALENT_PERMISSIONS.join(", ")}.`,
      ],
      evidence,
    );
  }
  if (adminOverAssigned) {
    return finding(3, "high", "warn", `Datadog Admin Role is assigned to ${adminCount} users, above the threshold of ${maxAdmins}.`, evidence);
  }
  return withVerdictCaveats(
    finding(
      3,
      "high",
      "pass",
      `${customRoles.length} custom roles were checked and none grants admin-equivalent permissions; the Datadog Admin Role has ${adminCount ?? "an unknown number of"} members.`,
      evidence,
    ),
    [
      adminCount === undefined ? "The Datadog Admin Role membership count (user_count) was not returned, so admin over-assignment could not be checked." : undefined,
      truncationCaveat("roles", snapshot.roles, "role_limit"),
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
    total_users: users.length,
    active_human_users: activeHumans.length,
    disabled_users: disabledUsers.length,
    service_accounts: users.filter((user) => user.serviceAccount).length,
    inactive_days_threshold: inactiveDays,
    inactive_users: sample(inactive.map((user) => ({ handle: user.handle, last_login: user.lastLogin?.toISOString() ?? null }))),
    inactive_user_count: inactive.length,
    stale_pending_invitations: sample(stalePending.map((user) => user.handle)),
    active_users_without_login_or_creation_date: sample(undated.map((user) => user.handle)),
    pending_invitations_without_creation_date: sample(undatedPending.map((user) => user.handle)),
    users_inventory_truncated: snapshot.users.truncated ?? false,
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
  if (inactive.length > 0) {
    return withVerdictCaveats(
      finding(4, "high", "fail", `${inactive.length}/${activeHumans.length} active users have not signed in for more than ${inactiveDays} days.`, evidence),
      caveats,
    );
  }
  if (stalePending.length > 0) {
    return withVerdictCaveats(
      finding(4, "high", "warn", `${stalePending.length} invitations have been pending for more than ${pendingInviteDays} days.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(4, "high", "pass", `All ${activeHumans.length} active users signed in within ${inactiveDays} days and no invitations are stale.`, evidence),
    caveats,
  );
}

function evaluateSessionTimeoutControl(snapshot: DatadogIdentitySnapshot): DatadogFinding {
  const configNames = (snapshot.orgConfigs.value ?? []).map((item) => asString(attributesOf(item).name)).filter((name): name is string => Boolean(name));
  return manualFinding(
    16,
    "medium",
    "Datadog does not expose the organization session timeout through the public API.",
    [
      "Capture Organization Settings > Security (or Login Methods) showing the configured session duration and confirm it does not exceed the policy maximum (for example 15 minutes for FedRAMP High or 30 minutes for Moderate).",
    ],
    {
      org_config_names: configNames,
      org_configs_readable: Boolean(snapshot.orgConfigs.value),
    },
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
  const evidence = {
    users_returned: snapshot.users.value.length,
    service_accounts: serviceAccounts.length,
    service_account_handles: sample(serviceAccounts.map((user) => user.handle)),
    non_conforming_names: sample(nonConforming.map((user) => user.handle)),
    service_accounts_with_login_history: sample(interactive.map((user) => user.handle)),
    service_account_application_keys: serviceKeys.length,
    application_keys_readable: Boolean(snapshot.applicationKeys.value),
    stale_service_account_keys: sample(staleKeys.map(keyLabel)),
    service_account_keys_without_created_at: sample(undatedKeys.map(keyLabel)),
    key_rotation_days: keyRotationDays,
    users_inventory_truncated: snapshot.users.truncated ?? false,
    application_keys_inventory_truncated: snapshot.applicationKeys.truncated ?? false,
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
  if (interactive.length > 0 || staleKeys.length > 0) {
    return withVerdictCaveats(
      finding(
        19,
        "medium",
        "fail",
        `${interactive.length} service accounts show interactive login history and ${staleKeys.length} service account application keys are older than ${keyRotationDays} days.`,
        evidence,
      ),
      caveats,
    );
  }
  if (nonConforming.length > 0 || !snapshot.applicationKeys.value) {
    return withVerdictCaveats(
      finding(
        19,
        "medium",
        "warn",
        nonConforming.length > 0
          ? `${nonConforming.length}/${serviceAccounts.length} service accounts do not follow the naming convention.`
          : "Service accounts look healthy but their application keys could not be read to confirm rotation.",
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(19, "medium", "pass", `${serviceAccounts.length} service accounts follow the naming convention, have no interactive logins, and their ${serviceKeys.length} application keys are within the rotation window.`, evidence),
    caveats,
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

  return {
    category: "identity",
    title: "Datadog identity and access posture",
    summary: {
      users: totalUsers ?? null,
      roles: snapshot.roles.value?.length ?? null,
      custom_roles: snapshot.roles.value?.filter((role) => !isDefaultRole(role)).length ?? null,
      saml_strict_mode: saml.strictSaml,
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
    loadInventory("api_keys", keyLimit, (probeLimit) => client.listApiKeys(probeLimit), errors),
    loadApplicationKeyInventory(client, keyLimit, errors),
    loadInventory("shared_dashboards", DEFAULT_DASHBOARD_LIMIT, (probeLimit) => client.listDashboards({ shared: true, limit: probeLimit }), errors),
    loadSurface("ip_allowlist", () => client.getIpAllowlist(), errors),
    loadSurface("aws_integrations", () => client.listAwsIntegrations(), errors),
    loadSurface("gcp_integrations", () => client.listGcpIntegrations(), errors),
    loadSurface("azure_integrations", () => client.listAzureIntegrations(), errors),
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
  const evidence = {
    api_keys: keys.length,
    rotation_days: rotationDays,
    keys_older_than_rotation_window: sample(aged.map(keyLabel)),
    keys_older_than_rotation_window_count: aged.length,
    unused_days: unusedDays,
    keys_unused_beyond_threshold: sample(stale.map(keyLabel)),
    keys_with_placeholder_names: sample(placeholders.map(keyLabel)),
    keys_without_created_at: sample(undated.map(keyLabel)),
    keys_without_created_at_count: undated.length,
    api_keys_inventory_truncated: snapshot.apiKeys.truncated ?? false,
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
  if (aged.length > 0) {
    return withVerdictCaveats(
      finding(5, "high", "fail", `${aged.length}/${keys.length} API keys are older than the ${rotationDays}-day rotation window.`, evidence),
      caveats,
    );
  }
  if (stale.length > 0 || placeholders.length > 0) {
    return withVerdictCaveats(
      finding(
        5,
        "high",
        "warn",
        `${stale.length} API keys have been unused for more than ${unusedDays} days and ${placeholders.length} use placeholder names.`,
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(5, "high", "pass", `All ${keys.length} API keys are within the ${rotationDays}-day rotation window, recently used, and descriptively named.`, evidence),
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
  const evidence = {
    application_keys: keys.length,
    unscoped_keys: unscoped.length,
    unscoped_keys_sample: sample(unscoped.map(keyLabel)),
    orphaned_keys: sample(orphaned.map(keyLabel)),
    idle_keys: sample(idle.map(keyLabel)),
    idle_days_threshold: unusedDays,
    owners_resolved: ownersById.size,
    keys_without_resolved_owner: ownerUnresolved.length,
    keys_without_resolved_owner_sample: sample(ownerUnresolved.map(keyLabel)),
    keys_without_any_date: sample(undated.map(keyLabel)),
    application_keys_inventory_truncated: snapshot.applicationKeys.truncated ?? false,
  };
  if (keys.length === 0) {
    return manualFinding(6, "high", "The application keys endpoint returned no keys, which cannot be a complete inventory because the application key used for this request must exist; the empty list is treated as unverifiable rather than compliant.", [
      "Export Organization Settings > Application Keys, confirm each key is scoped, owned by an active user or service account, and used recently.",
    ], evidence);
  }
  const caveats = [
    truncationCaveat("application_keys", snapshot.applicationKeys, "key_limit"),
    ownerUnresolved.length > 0
      ? `${ownerUnresolved.length} application keys have no owner record in the response (include=owned_by), so ownership by an active user could not be confirmed for them.`
      : undefined,
    undated.length > 0 ? `${undated.length} application keys have neither last_used_at nor created_at and were not counted as recently used.` : undefined,
  ];
  if (orphaned.length > 0) {
    return withVerdictCaveats(
      finding(6, "high", "fail", `${orphaned.length} application keys belong to disabled users and remain active.`, evidence),
      caveats,
    );
  }
  if (unscoped.length > 0 || idle.length > 0) {
    return withVerdictCaveats(
      finding(
        6,
        "high",
        "warn",
        `${unscoped.length}/${keys.length} application keys inherit the owner's full permissions (unscoped) and ${idle.length} have not been used for more than ${unusedDays} days.`,
        evidence,
      ),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(6, "high", "pass", `All ${keys.length} application keys are scoped, owned by active users (${ownersById.size} owner records resolved), and recently used.`, evidence),
    caveats,
  );
}

function evaluateDashboardSharingControl(snapshot: DatadogAccessControlSnapshot): DatadogFinding {
  const organizationReadable = Boolean(snapshot.organization.value);
  const settings = asObject(snapshot.organization.value?.settings) ?? {};
  const widgetShare = organizationReadable ? asBoolean(settings.private_widget_share) : undefined;
  const shared = snapshot.sharedDashboards.value ?? [];
  const evidence = {
    shared_dashboards: snapshot.sharedDashboards.value ? shared.length : null,
    shared_dashboard_titles: sample(shared.map((dashboard) => asString(dashboard.title) ?? asString(dashboard.id) ?? "dashboard")),
    private_widget_share: widgetShare ?? null,
    organization_settings_readable: organizationReadable,
    shared_dashboards_readable: Boolean(snapshot.sharedDashboards.value),
    shared_dashboards_inventory_truncated: snapshot.sharedDashboards.truncated ?? false,
  };
  if (widgetShare === true) {
    return finding(14, "high", "fail", "Organization settings allow users to share widgets outside Datadog (private_widget_share enabled).", evidence);
  }
  const publicSharingEvidence = "Capture Organization Settings > Public Sharing showing that sharing widgets outside the organization (private_widget_share) is disabled.";
  if (!snapshot.sharedDashboards.value) {
    return manualFinding(14, "high", unreadableReason("dashboards (dashboards_read)", snapshot.sharedDashboards), [
      "Open Dashboards > Shared Dashboards and confirm every shared dashboard is invite-only with an email domain allowlist.",
      publicSharingEvidence,
    ], evidence);
  }
  if (!organizationReadable) {
    return manualFinding(14, "high", `${unreadableReason("organization settings (org_management)", snapshot.organization)} The private_widget_share setting was therefore never read.`, [
      publicSharingEvidence,
    ], evidence);
  }
  if (widgetShare === undefined) {
    return manualFinding(14, "high", "The organization response did not include the private_widget_share setting, so widget sharing outside the org could not be confirmed.", [
      publicSharingEvidence,
    ], evidence);
  }
  if (shared.length > 0) {
    return withVerdictCaveats(
      finding(
        14,
        "high",
        "warn",
        `${shared.length} dashboards are shared through public links; confirm each uses invite-only sharing with an email domain allowlist because the list endpoint does not expose the share type.`,
        evidence,
      ),
      [truncationCaveat("shared_dashboards", snapshot.sharedDashboards, "the dashboard limit")],
    );
  }
  return finding(14, "high", "pass", "No dashboards are shared through public links and widget sharing outside the org is disabled (private_widget_share read as false).", evidence);
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
    ]);
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

function evaluateIntegrationPermissionsControl(snapshot: DatadogAccessControlSnapshot): DatadogFinding {
  const aws = snapshot.awsIntegrations.value ?? [];
  const gcp = snapshot.gcpIntegrations.value ?? [];
  const azure = snapshot.azureIntegrations.value ?? [];
  const awsStaticKeys = aws.filter((account) => Boolean(asString(account.access_key_id)) && !asString(account.role_name));
  const evidence = {
    aws_accounts: aws.length,
    aws_accounts_using_static_access_keys: sample(awsStaticKeys.map((account) => asString(account.account_id) ?? asString(account.access_key_id) ?? "aws-account")),
    aws_accounts_using_role_delegation: aws.filter((account) => Boolean(asString(account.role_name))).length,
    gcp_projects: gcp.length,
    azure_tenants: azure.length,
    surfaces_readable: {
      aws: Boolean(snapshot.awsIntegrations.value),
      gcp: Boolean(snapshot.gcpIntegrations.value),
      azure: Boolean(snapshot.azureIntegrations.value),
    },
  };
  const reason = awsStaticKeys.length > 0
    ? `${awsStaticKeys.length} AWS integrations authenticate with static access keys instead of IAM role delegation, and the cloud-side IAM policies and webhook targets are not visible through the Datadog API.`
    : `${aws.length} AWS, ${gcp.length} GCP, and ${azure.length} Azure integrations were inventoried, but their cloud-side IAM policies and webhook targets are not visible through the Datadog API.`;
  return manualFinding(18, "medium", reason, [
    "Export the IAM role or service account policy attached to each cloud integration and confirm it is read-only (for example the Datadog-recommended policy without write actions).",
    "Open Integrations > Webhooks and confirm every webhook URL uses https:// (the API only returns a webhook by exact name).",
    "Review Integrations > Installed for any integration configured with owner or admin credentials.",
  ], evidence);
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
    ["organization settings (org_management)", snapshot.organization],
    ["log_indexes (logs_read_config)", snapshot.indexes],
    ["org_connections (org_connections_read)", snapshot.orgConnections],
  ]);
  const evidence = {
    private_widget_share: widgetShareSetting ?? null,
    organization_settings_readable: Boolean(snapshot.organization.value),
    saml_autocreate_users_enabled: autocreateEnabled,
    saml_autocreate_domains: autocreateDomains,
    log_indexes: snapshot.indexes.value ? indexes.length : null,
    log_indexes_readable: Boolean(snapshot.indexes.value),
    min_log_retention_days: minLogRetentionDays,
    indexes_below_retention_minimum: shortRetention,
    indexes_without_retention_value: sample(unknownRetention.map((index) => index.name)),
    org_connections: snapshot.orgConnections.value ? connections.length : null,
    org_connections_readable: Boolean(snapshot.orgConnections.value),
    org_connection_sample: sample(connections.map((connection) => ({
      types: asStringArray(attributesOf(connection).connection_types),
      sink_org: asString(getNestedValue(connection, ["relationships", "sink_org", "data", "id"])) ?? null,
    }))),
  };
  if (widgetShareSetting === true) {
    return finding(20, "medium", "fail", "Widget sharing outside the organization is enabled (private_widget_share).", evidence);
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
  if (shortRetention.length > 0 || unknownRetention.length > 0 || connections.length > 0 || (autocreateEnabled && autocreateDomains.length === 0)) {
    return finding(
      20,
      "medium",
      "warn",
      `${shortRetention.length} log indexes retain data for less than ${minLogRetentionDays} days, ${unknownRetention.length} indexes did not report num_retention_days, ${connections.length} cross-org connections share data with other orgs, and SAML user auto-creation ${autocreateEnabled ? `is enabled for ${autocreateDomains.length} domains` : "is disabled"}.`,
      evidence,
    );
  }
  return finding(20, "medium", "pass", `Widget sharing outside the org is disabled (private_widget_share read as false), all ${indexes.length} log indexes meet the ${minLogRetentionDays}-day retention minimum, and the org connections list was read and is empty.`, evidence);
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
    summary: {
      api_keys: snapshot.apiKeys.value?.length ?? null,
      application_keys: snapshot.applicationKeys.value ? asRecordArray(snapshot.applicationKeys.value.data).length : null,
      shared_dashboards: snapshot.sharedDashboards.value?.length ?? null,
      ip_allowlist_enabled: snapshot.ipAllowlist.value ? asBoolean(getNestedValue(snapshot.ipAllowlist.value, ["data", "attributes", "enabled"])) ?? false : null,
      cloud_integrations: (snapshot.awsIntegrations.value?.length ?? 0) + (snapshot.gcpIntegrations.value?.length ?? 0) + (snapshot.azureIntegrations.value?.length ?? 0),
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
    }), errors),
    loadSurface("posture_findings_fail", () => client.listPostureFindings({ evaluation: "fail", limit: findingLimit }), errors),
    loadSurface("posture_findings_pass", () => client.listPostureFindings({ evaluation: "pass", limit: findingLimit }), errors),
    loadInventory("monitors", monitorLimit, (probeLimit) => client.listMonitors(probeLimit), errors),
    loadSurface("aws_integrations", () => client.listAwsIntegrations(), errors),
    loadSurface("gcp_integrations", () => client.listGcpIntegrations(), errors),
    loadSurface("azure_integrations", () => client.listAzureIntegrations(), errors),
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
  const evidence = {
    total_rules: rules.length,
    detection_rules: detectionRules.length,
    enabled_detection_rules: enabledDetection.length,
    disabled_default_rules: disabledDefaults.length,
    disabled_default_rule_sample: sample(disabledDefaults.map((rule) => asString(rule.name) ?? asString(rule.id) ?? "rule")),
    critical_category_coverage: categoryCoverage,
    rules_inventory_truncated: snapshot.rules.truncated ?? false,
  };
  if (rules.length === 0) {
    return finding(8, "high", "fail", "The security monitoring rules endpoint returned no rules at all. An empty rule inventory is treated as fail because no detection is active; if Cloud SIEM is not licensed for this organization, record the control as not applicable with the plan evidence.", evidence);
  }
  const caveats = [truncationCaveat("security_rules", snapshot.rules, "rule_limit")];
  if (enabledDetection.length === 0) {
    return withVerdictCaveats(finding(8, "high", "fail", `${rules.length} rules were returned but no Cloud SIEM detection rules are enabled.`, evidence), caveats);
  }
  if (uncovered.length > 0) {
    return withVerdictCaveats(
      finding(8, "high", "fail", `${enabledDetection.length} detection rules are enabled but no enabled rule covers: ${uncovered.join(", ")}.`, evidence),
      caveats,
    );
  }
  if (disabledDefaults.length > 0) {
    return withVerdictCaveats(
      finding(8, "high", "warn", `${enabledDetection.length} detection rules are enabled across all critical categories, but ${disabledDefaults.length} default rules have been disabled.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(8, "high", "pass", `${enabledDetection.length} detection rules are enabled, all critical categories are covered, and no default rules are disabled.`, evidence),
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
  const evidence = {
    lookback_days: lookbackDays,
    unresolved_high_or_critical_signals: signals.length,
    sla_hours: slaHours,
    overdue_signals: overdue.length,
    overdue_signal_sample: sample(overdue.map((signal) => ({ id: signal.id, severity: signal.severity, triage: signal.triage, age_hours: signal.ageHours, title: signal.title }))),
    signals_without_timestamp: undated.length,
    signals_without_timestamp_sample: sample(undated.map((signal) => signal.id)),
    enabled_detection_rules: enabledDetectionRules ?? null,
    signals_inventory_truncated: snapshot.signals.truncated ?? false,
    query: signalQuery(),
  };
  if (overdue.length > 0) {
    return finding(9, "high", "fail", `${overdue.length}/${signals.length} unresolved high or critical signals are older than the ${slaHours}-hour SLA.`, evidence);
  }
  if (signals.length > 0) {
    const truncated = snapshot.signals.truncated ? ` The signal list is truncated at ${snapshot.signals.limit} items (raise signal_limit), so older overdue signals may exist.` : "";
    const undatedNote = undated.length > 0 ? ` ${undated.length} signals have no timestamp and could not be aged.` : "";
    return finding(9, "high", "warn", `${signals.length} unresolved high or critical signals are open within the ${slaHours}-hour SLA.${undatedNote}${truncated}`, evidence);
  }
  const signalEvidence = `Open Security > Signals filtered to status:(critical OR high) over the last ${lookbackDays} days and confirm Cloud SIEM is enabled and generating signals.`;
  if (enabledDetectionRules === undefined) {
    return manualFinding(9, "high", "No unresolved high or critical signals were returned, but the detection rule inventory was not readable, so it is unknown whether Cloud SIEM is generating signals at all; the empty list is treated as unverifiable rather than compliant.", [signalEvidence], evidence);
  }
  if (enabledDetectionRules === 0) {
    return manualFinding(9, "high", "No unresolved high or critical signals were returned, but no detection rules are enabled, so the empty signal list reflects the absence of detection rather than timely triage; the empty list is treated as unverifiable rather than compliant.", [signalEvidence], evidence);
  }
  return finding(9, "high", "pass", `No unresolved high or critical security signals in the last ${lookbackDays} days. The empty result is treated as compliant because ${enabledDetectionRules} enabled detection rules are active, so signals would appear here if they were open.`, evidence);
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

function postureCount(surface: SurfaceResult<JsonRecord>): { count: number; source: "total_filtered_count" | "paged_data"; truncated: boolean } | undefined {
  if (!surface.value) return undefined;
  const total = asNumber(surface.value.total_filtered_count);
  if (total !== undefined) return { count: total, source: "total_filtered_count", truncated: false };
  return { count: asRecordArray(surface.value.data).length, source: "paged_data", truncated: asBoolean(surface.value.truncated) === true };
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
    ["security_rules (security_monitoring_rules_read)", snapshot.rules],
    ["aws_integrations (aws_configuration_read)", snapshot.awsIntegrations],
    ["gcp_integrations (gcp_configuration_read)", snapshot.gcpIntegrations],
    ["azure_integrations (azure_configuration_read)", snapshot.azureIntegrations],
  ]);
  const unreadablePosture = unreadableSurfaces([
    ["posture_findings_fail (security_monitoring_findings_read)", snapshot.postureFailing],
    ["posture_findings_pass (security_monitoring_findings_read)", snapshot.posturePassing],
  ]);
  const evidence = {
    cloud_configuration_rules: cloudRules.length,
    enabled_cloud_configuration_rules: enabledCloudRules.length,
    rules_readable: Boolean(snapshot.rules.value),
    rules_inventory_truncated: snapshot.rules.truncated ?? false,
    integrations_with_cspm_resource_collection: cspm.enabled,
    cloud_integrations: cspm.total,
    cloud_integration_surfaces_readable: {
      aws: Boolean(snapshot.awsIntegrations.value),
      gcp: Boolean(snapshot.gcpIntegrations.value),
      azure: Boolean(snapshot.azureIntegrations.value),
    },
    posture_findings_failing: failing?.count ?? null,
    posture_findings_passing: passing?.count ?? null,
    posture_count_source: failing?.source ?? passing?.source ?? null,
    posture_counts_truncated: countsTruncated,
    posture_pass_rate: passRate === undefined ? null : Number(passRate.toFixed(3)),
    min_posture_pass_rate: minPassRate,
    posture_findings_readable: unreadablePosture.length === 0,
  };
  const consoleEvidence = "Open Security > Cloud Security > Compliance and capture the enabled frameworks, the cloud accounts with resource collection enabled, and the current passing percentage.";
  if (unreadableInputs.length > 0) {
    return manualFinding(12, "high", unreadableSurfacesReason(unreadableInputs), [consoleEvidence], evidence);
  }
  if (cspm.total === 0 && enabledCloudRules.length === 0) {
    return manualFinding(12, "high", "No AWS, GCP, or Azure integrations are configured and no cloud_configuration rules are enabled, so there is no cloud footprint for CSPM to evaluate through the API; the empty inventory is treated as not applicable rather than compliant.", [
      "Confirm whether cloud accounts are in scope for this organization; if none are, record CSPM as not applicable, otherwise connect the accounts and enable resource collection.",
    ], evidence);
  }
  if (enabledCloudRules.length === 0 && cspm.enabled === 0) {
    return finding(12, "high", "fail", `Cloud Security Posture Management is not active: ${cspm.total} cloud integrations are configured but none has CSPM resource collection enabled and no cloud_configuration rules are enabled.`, evidence);
  }
  if (unreadablePosture.length > 0) {
    return manualFinding(12, "high", `CSPM appears active (${enabledCloudRules.length} enabled cloud_configuration rules, ${cspm.enabled} integrations with resource collection), but ${unreadableSurfacesReason(unreadablePosture)}`, [consoleEvidence], evidence);
  }
  if (countsTruncated) {
    return finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules, but the posture findings response carried no total_filtered_count and the paged counts hit the finding_limit, so the passing rate could not be measured reliably; raise finding_limit or capture the passing percentage from the console.`, evidence);
  }
  if (passRate === undefined) {
    return finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules, but no posture findings were returned yet so the passing rate could not be measured.`, evidence);
  }
  if (passRate < minPassRate) {
    return finding(12, "high", "warn", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules, but the posture passing rate ${(passRate * 100).toFixed(1)}% is below the ${(minPassRate * 100).toFixed(0)}% threshold.`, evidence);
  }
  return withVerdictCaveats(
    finding(12, "high", "pass", `CSPM is active with ${enabledCloudRules.length} enabled compliance rules and a ${(passRate * 100).toFixed(1)}% posture passing rate (${failing?.source === "paged_data" ? "counted from paged findings" : "from total_filtered_count"}).`, evidence),
    [truncationCaveat("security_rules", snapshot.rules, "rule_limit")],
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
  const evidence = {
    total_rules: snapshot.rules.value.length,
    enabled_compliance_rules: complianceRules.length,
    frameworks_observed: [...tokens].sort(),
    required_frameworks: requiredFrameworks,
    coverage,
    rules_inventory_truncated: snapshot.rules.truncated ?? false,
  };
  const caveats = [truncationCaveat("security_rules", snapshot.rules, "rule_limit")];
  if (complianceRules.length === 0) {
    return withVerdictCaveats(
      finding(13, "medium", "fail", `${snapshot.rules.value.length} rules were returned but none is an enabled cloud_configuration or infrastructure_configuration compliance rule. The empty compliance rule set is treated as fail; if Cloud Security is not licensed for this organization, record the control as not applicable with the plan evidence.`, evidence),
      caveats,
    );
  }
  if (gaps.length > 0) {
    return withVerdictCaveats(
      finding(13, "medium", "fail", `Enabled compliance rules cover ${tokens.size} framework tags but none reference: ${gaps.join(", ")}.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(13, "medium", "pass", `Enabled compliance rules reference every required framework (${requiredFrameworks.join(", ")}).`, evidence),
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
  const evidence = {
    monitors: monitors.length,
    security_monitors: securityMonitors.length,
    security_monitors_without_notifications: sample(silent.map((monitor) => monitor.name)),
    security_monitors_email_only: sample(emailOnly.map((monitor) => ({ name: monitor.name, handles: monitor.handles }))),
    security_monitors_with_integration_channels: classified.filter((monitor) => monitor.hasIntegration).length,
    monitors_inventory_truncated: snapshot.monitors.truncated ?? false,
  };
  if (monitors.length === 0) {
    return manualFinding(17, "medium", "The monitors endpoint returned no monitors, so there are no security alerts whose routing can be verified; the empty inventory is treated as unverifiable rather than compliant.", [
      "Confirm in Monitors > Manage Monitors whether security-related monitors exist; if alerting is handled entirely by Cloud SIEM notification rules, capture Security > Cloud SIEM > Notification Rules instead.",
    ], evidence);
  }
  const caveats = [truncationCaveat("monitors", snapshot.monitors, "monitor_limit")];
  if (securityMonitors.length === 0) {
    return withVerdictCaveats(
      finding(17, "medium", "warn", `${monitors.length} monitors were inventoried but none are tagged or named as security monitors; tag security-critical monitors so notification routing can be verified.`, evidence),
      caveats,
    );
  }
  if (silent.length > 0) {
    return withVerdictCaveats(
      finding(17, "medium", "fail", `${silent.length}/${securityMonitors.length} security monitors have no notification handles in their message.`, evidence),
      caveats,
    );
  }
  if (emailOnly.length > 0) {
    return withVerdictCaveats(
      finding(17, "medium", "warn", `${emailOnly.length}/${securityMonitors.length} security monitors notify individual email addresses only; confirm they are distribution lists or route them to PagerDuty or a security channel.`, evidence),
      caveats,
    );
  }
  return withVerdictCaveats(
    finding(17, "medium", "pass", `All ${securityMonitors.length} security monitors notify at least one integration channel.`, evidence),
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
    summary: {
      rules: snapshot.rules.value?.length ?? null,
      enabled_detection_rules: snapshot.rules.value?.filter((rule) => isDetectionRule(rule) && ruleEnabled(rule)).length ?? null,
      enabled_cloud_configuration_rules: snapshot.rules.value?.filter((rule) => ruleType(rule) === "cloud_configuration" && ruleEnabled(rule)).length ?? null,
      unresolved_high_or_critical_signals: snapshot.signals.value?.length ?? null,
      monitors: snapshot.monitors.value?.length ?? null,
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
    loadSurface("audit_events_oldest", () => client.listAuditEvents({ from: `now-${retentionDays}d`, to: "now", sort: "timestamp", limit: 1 }), errors),
    loadSurface("audit_events_recent", () => client.listAuditEvents({ from: "now-7d", to: "now", sort: "-timestamp", limit: 25 }), errors),
    loadSurface("log_pipelines", () => client.listLogPipelines(), errors),
    loadSurface("log_indexes", () => client.listLogIndexes(), errors),
    loadSurface("log_archives", () => client.listLogArchives(), errors),
    loadSurface("sensitive_data_scanner", () => client.getSensitiveDataScannerConfig(), errors),
    loadSurface("org_connections", () => client.listOrgConnections(), errors),
  ]);
  return { organization, oldestAuditEvents, recentAuditEvents, pipelines, indexes, archives, sensitiveDataScanner, orgConnections, errors };
}

function evaluateAuditTrailControl(snapshot: DatadogDataProtectionSnapshot, now: Date, retentionDays: number): DatadogFinding {
  const unreadable = unreadableSurfaces([
    ["audit_events_oldest (audit_logs_read)", snapshot.oldestAuditEvents],
    ["audit_events_recent (audit_logs_read)", snapshot.recentAuditEvents],
  ]);
  const consoleEvidence = `Open Organization Settings > Audit Trail, confirm it is enabled, and capture the retention setting showing at least ${retentionDays} days.`;
  if (unreadable.length > 0) {
    return manualFinding(7, "high", unreadableSurfacesReason(unreadable), [consoleEvidence], {
      oldest_events_readable: Boolean(snapshot.oldestAuditEvents.value),
      recent_events_readable: Boolean(snapshot.recentAuditEvents.value),
    });
  }
  const oldest = snapshot.oldestAuditEvents.value ?? [];
  const recent = snapshot.recentAuditEvents.value ?? [];
  const oldestTimestamp = parseDate(attributesOf(oldest[0] ?? {}).timestamp);
  const oldestAgeDays = daysBetween(oldestTimestamp, now);
  const evidence = {
    recent_events_last_7_days: recent.length,
    oldest_event_timestamp: oldestTimestamp?.toISOString() ?? null,
    oldest_event_age_days: oldestAgeDays ?? null,
    oldest_event_has_timestamp: oldest.length > 0 ? oldestTimestamp !== undefined : null,
    min_retention_days: retentionDays,
    retention_inferred_from_oldest_event: true,
  };
  if (oldest.length === 0 && recent.length === 0) {
    return finding(7, "high", "fail", `Audit Trail returned no events in the last ${retentionDays} days even though this assessment's own API calls are auditable activity. The empty inventory is treated as fail because Audit Trail appears disabled or is not recording; if Audit Trail is not available on the plan, record the control as not applicable.`, evidence);
  }
  if (oldest.length > 0 && oldestTimestamp === undefined) {
    return finding(7, "high", "warn", `Audit Trail is recording events (${recent.length} in the last 7 days) but the oldest returned event has no timestamp, so ${retentionDays}-day retention could not be inferred from the API.`, evidence);
  }
  if (recent.length === 0) {
    return finding(7, "high", "warn", `Audit Trail has historical events (oldest is ${oldestAgeDays ?? "an unknown number of"} days old) but returned none in the last 7 days, so current recording could not be confirmed.`, evidence);
  }
  if (oldestAgeDays !== undefined && oldestAgeDays >= retentionDays - 7) {
    return finding(7, "high", "pass", `Audit Trail is recording events (${recent.length} in the last 7 days) and the oldest available event is ${oldestAgeDays} days old, supporting ${retentionDays}-day retention.`, evidence);
  }
  return finding(
    7,
    "high",
    "warn",
    `Audit Trail is recording events (${recent.length} in the last 7 days) but the oldest available event is only ${oldestAgeDays ?? "an unknown number of"} days old, so ${retentionDays}-day retention could not be confirmed from the API.`,
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
    ["log_pipelines (logs_read_config)", snapshot.pipelines],
    ["log_indexes (logs_read_config)", snapshot.indexes],
    ["log_archives (logs_read_archives)", snapshot.archives],
  ]);
  const evidence = {
    pipelines: snapshot.pipelines.value ? pipelines.length : null,
    enabled_pipelines: pipelines.filter((pipeline) => asBoolean(pipeline.is_enabled) !== false).length,
    indexes: snapshot.indexes.value ? indexes.length : null,
    exclusion_filters: filters.length,
    exclusion_filters_dropping_security_sources: sample(securityDrops),
    archives: snapshot.archives.value ? archives.length : null,
    surfaces_readable: {
      pipelines: Boolean(snapshot.pipelines.value),
      indexes: Boolean(snapshot.indexes.value),
      archives: Boolean(snapshot.archives.value),
    },
    archive_destinations: sample(archives.map((archive) => ({
      name: asString(attributesOf(archive).name) ?? "archive",
      destination: asString(getNestedValue(archive, ["attributes", "destination", "type"])) ?? null,
      state: asString(attributesOf(archive).state) ?? null,
    }))),
    failing_archives: failingArchives.length,
    redaction_note: "Field-level redaction is assessed by the Sensitive Data Scanner control (DD-11).",
  };
  if (securityDrops.length > 0) {
    return finding(10, "medium", "fail", `${securityDrops.length} enabled index exclusion filters drop security-relevant log sources.`, evidence);
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
    ]);
  }
  const included = asRecordArray(snapshot.sensitiveDataScanner.value.included);
  const groups = included.filter((item) => asString(item.type) === "sensitive_data_scanner_group");
  const rules = included.filter((item) => asString(item.type) === "sensitive_data_scanner_rule");
  const enabledGroups = groups.filter((group) => asBoolean(attributesOf(group).is_enabled) === true);
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
    enabled_scanning_groups: enabledGroups.length,
    products_covered: [...products].sort(),
    products_missing: missingProducts,
    rules: rules.length,
    enabled_rules: enabledRules.length,
    enabled_pii_or_pci_rules: piiRules.length,
    rule_sample: sample(enabledRules.map((rule) => asString(attributesOf(rule).name) ?? "rule")),
  };
  if (enabledGroups.length === 0) {
    return finding(11, "medium", "fail", `Sensitive Data Scanner has no enabled scanning groups (${groups.length} groups returned). The empty configuration is treated as fail because no redaction is active; if Sensitive Data Scanner is not licensed for this organization, record the control as not applicable with the plan evidence.`, evidence);
  }
  if (enabledRules.length === 0 || piiRules.length === 0) {
    return finding(11, "medium", "fail", `${enabledGroups.length} scanning groups are enabled but no active PII or PCI detection rules were found.`, evidence);
  }
  if (missingProducts.length > 0) {
    return finding(11, "medium", "warn", `Sensitive Data Scanner is active with ${piiRules.length} PII/PCI rules but enabled groups do not cover: ${missingProducts.join(", ")}.`, evidence);
  }
  return finding(11, "medium", "pass", `Sensitive Data Scanner is active across logs, APM, RUM, and events with ${piiRules.length} PII/PCI rules enabled.`, evidence);
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
    summary: {
      recent_audit_events: snapshot.recentAuditEvents.value?.length ?? null,
      pipelines: snapshot.pipelines.value?.length ?? null,
      indexes: snapshot.indexes.value?.length ?? null,
      archives: snapshot.archives.value?.length ?? null,
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

async function probeSurface(
  name: string,
  endpoint: string,
  permission: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<DatadogAccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, permission, status: "readable", count: countResolver?.(value) };
  } catch (error) {
    return {
      name,
      endpoint,
      permission,
      status: isForbidden(error) ? "forbidden" : "not_readable",
      error: errorMessage(error),
    };
  }
}

function arrayCount(value: unknown): number | undefined {
  return Array.isArray(value) ? value.length : undefined;
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
  const coreSurfaces = new Set(["organization", "users", "roles", "api_keys", "application_keys", "audit_events", "security_rules"]);
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const dataSurfacesReadable = surfaces.filter((surface) => !validationSurfaces.has(surface.name) && surface.status === "readable").length;
  const coreReadable = surfaces.filter((surface) => coreSurfaces.has(surface.name) && surface.status === "readable").length;
  const missingPermissions = [...new Set(
    surfaces
      .filter((surface) => surface.status === "forbidden" && !validationSurfaces.has(surface.name))
      .map((surface) => surface.permission),
  )];

  const status: DatadogAccessCheckResult["status"] = !apiKeyValid || dataSurfacesReadable === 0
    ? "failed"
    : coreReadable === coreSurfaces.size && keyPairValid
      ? "healthy"
      : "limited";

  return {
    status,
    site: config.site,
    apiKeyValid,
    keyPairValid,
    surfaces,
    missingPermissions,
    notes: [
      `Using Datadog site ${config.site} (${config.baseUrl}).`,
      apiKeyValid ? "The API key validated successfully." : `The API key did not validate: ${validate.error ?? "unknown error"}.`,
      keyPairValid
        ? "The API key and application key pair validated successfully (GET /api/v2/validate_keys)."
        : `The API key and application key pair did not validate (GET /api/v2/validate_keys): ${validateKeys.error ?? "unknown error"}.`,
      `${readableCount}/${surfaces.length} Datadog audit surfaces are readable.`,
      missingPermissions.length > 0
        ? `Missing application key permissions: ${missingPermissions.join(", ")}.`
        : "No permission denials were observed.",
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
    surface.count === undefined ? "-" : String(surface.count),
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
    "- `core_data/*.json`: raw API snapshots (keys are shown as last4 only)",
    "- `core_data/access.json`: readable surfaces and missing permissions",
    ...(result.errors.length > 0 ? ["- `_errors.log`: surfaces that failed during collection"] : []),
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
    "- `core_data/*.json`: raw API snapshots used as evidence",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: present only when some surfaces failed to collect",
    "",
    "Credentials are never written into the bundle; API and application keys appear only as their last four characters.",
    "",
  ].join("\n");
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
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: now.toISOString(),
    site: config.site,
    api_base_url: config.baseUrl,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    ...countByStatus(findings),
  }));

  const coreData: Array<[string, unknown]> = [
    ["core_data/access.json", access],
    ["core_data/organization.json", identitySnapshot.organization.value ?? { error: identitySnapshot.organization.error }],
    ["core_data/users.json", identitySnapshot.users.value ?? { error: identitySnapshot.users.error }],
    ["core_data/roles.json", { roles: identitySnapshot.roles.value ?? null, permissions_by_role: identitySnapshot.rolePermissions, error: identitySnapshot.roles.error }],
    ["core_data/org_configs.json", identitySnapshot.orgConfigs.value ?? { error: identitySnapshot.orgConfigs.error }],
    ["core_data/api_keys.json", accessSnapshot.apiKeys.value ?? { error: accessSnapshot.apiKeys.error }],
    ["core_data/application_keys.json", accessSnapshot.applicationKeys.value ?? { error: accessSnapshot.applicationKeys.error }],
    ["core_data/shared_dashboards.json", accessSnapshot.sharedDashboards.value ?? { error: accessSnapshot.sharedDashboards.error }],
    ["core_data/ip_allowlist.json", accessSnapshot.ipAllowlist.value ?? { error: accessSnapshot.ipAllowlist.error }],
    ["core_data/cloud_integrations.json", {
      aws: accessSnapshot.awsIntegrations.value ?? { error: accessSnapshot.awsIntegrations.error },
      gcp: accessSnapshot.gcpIntegrations.value ?? { error: accessSnapshot.gcpIntegrations.error },
      azure: accessSnapshot.azureIntegrations.value ?? { error: accessSnapshot.azureIntegrations.error },
    }],
    ["core_data/security_rules.json", monitoringSnapshot.rules.value ?? { error: monitoringSnapshot.rules.error }],
    ["core_data/security_signals.json", monitoringSnapshot.signals.value ?? { error: monitoringSnapshot.signals.error }],
    ["core_data/posture_findings.json", {
      failing: monitoringSnapshot.postureFailing.value ?? { error: monitoringSnapshot.postureFailing.error },
      passing: monitoringSnapshot.posturePassing.value ?? { error: monitoringSnapshot.posturePassing.error },
    }],
    ["core_data/monitors.json", monitoringSnapshot.monitors.value ?? { error: monitoringSnapshot.monitors.error }],
    ["core_data/audit_events.json", {
      oldest: dataSnapshot.oldestAuditEvents.value ?? { error: dataSnapshot.oldestAuditEvents.error },
      recent: dataSnapshot.recentAuditEvents.value ?? { error: dataSnapshot.recentAuditEvents.error },
    }],
    ["core_data/log_pipelines.json", dataSnapshot.pipelines.value ?? { error: dataSnapshot.pipelines.error }],
    ["core_data/log_indexes.json", dataSnapshot.indexes.value ?? { error: dataSnapshot.indexes.error }],
    ["core_data/log_archives.json", dataSnapshot.archives.value ?? { error: dataSnapshot.archives.error }],
    ["core_data/sensitive_data_scanner.json", dataSnapshot.sensitiveDataScanner.value ?? { error: dataSnapshot.sensitiveDataScanner.error }],
    ["core_data/org_connections.json", dataSnapshot.orgConnections.value ?? { error: dataSnapshot.orgConnections.error }],
  ];
  for (const [pathname, value] of coreData) {
    await writeSecureTextFile(outputDir, pathname, serializeJson(value));
  }

  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    controls_assessed: findings.length,
    ...countByStatus(findings),
    categories: assessments.map((assessment) => ({ category: assessment.category, ...countByStatus(assessment.findings) })),
  }));

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
