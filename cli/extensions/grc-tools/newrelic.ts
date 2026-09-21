/**
 * New Relic organization security inspector tools for grclanker.
 *
 * Read-only NerdGraph and REST API v2 coverage for identity, access control,
 * alerting, and data governance posture, mapped to compliance frameworks.
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
type SleepImpl = (ms: number) => Promise<void>;

export type NewrelicRegion = "US" | "EU";
export type NewrelicFindingStatus = "pass" | "warn" | "fail" | "manual";
export type NewrelicFindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type NewrelicAssessmentCategory = "identity" | "access_control" | "alerting" | "data_governance";

const DEFAULT_OUTPUT_DIR = "./export/newrelic";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_AUDIT_WINDOW_DAYS = 30;
const DEFAULT_INACTIVE_DAYS = 90;
const DEFAULT_MAX_KEY_AGE_DAYS = 90;
const DEFAULT_MAX_ADMINS = 10;
const DEFAULT_MAX_ACCOUNTS_PER_USER = 5;
const DEFAULT_MAX_FULL_PLATFORM_PERCENT = 60;
const DEFAULT_MIN_RETENTION_DAYS = 30;
const DEFAULT_USER_LIMIT = 2000;
const DEFAULT_PAGE_LIMIT = 500;
const DEFAULT_ENTITY_LIMIT = 1000;
const DEFAULT_SCRIPT_SAMPLE_LIMIT = 25;
const DEFAULT_MAX_RETRIES = 3;
const MAX_PAGES = 200;
const DEFAULT_ADMIN_ROLE_PATTERN = "organization manager|authentication domain manager|all product admin";
const DEFAULT_PRODUCTION_ACCOUNT_PATTERN = "prod";
const DEFAULT_NONPRODUCTION_ACCOUNT_PATTERN = "dev|test|stag|sandbox|qa|nonprod|non-prod|uat|demo";

const REGION_ENDPOINTS: Record<NewrelicRegion, { nerdgraph: string; rest: string }> = {
  US: { nerdgraph: "https://api.newrelic.com/graphql", rest: "https://api.newrelic.com" },
  EU: { nerdgraph: "https://api.eu.newrelic.com/graphql", rest: "https://api.eu.newrelic.com" },
};

const PERSONAL_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "hotmail.com",
  "outlook.com",
  "live.com",
  "msn.com",
  "icloud.com",
  "me.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "mail.com",
  "gmx.com",
  "yandex.com",
]);

const SSO_AUTHENTICATION_TYPES = new Set(["SAML_SSO", "OIDC_SSO", "HEROKU_SSO"]);
const EXTERNAL_DESTINATION_TYPES = new Set([
  "EMAIL",
  "WEBHOOK",
  "SLACK",
  "SLACK_COLLABORATION",
  "SLACK_LEGACY",
  "JIRA",
  "SERVICE_NOW",
  "SERVICE_NOW_APP",
  "MICROSOFT_TEAMS",
  "EVENT_BRIDGE",
]);
const CRITICAL_ENTITY_TYPES = new Set(["APM-APPLICATION", "INFRA-HOST", "SYNTH-MONITOR"]);
const SCRIPTED_MONITOR_TYPES = new Set(["SCRIPT_API", "SCRIPT_BROWSER"]);

const SECRET_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: "credential assignment", pattern: /(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*["'][^"']{6,}["']/i },
  { label: "New Relic user key", pattern: /NRAK-[A-Z0-9]{20,}/ },
  { label: "AWS access key id", pattern: /AKIA[0-9A-Z]{16}/ },
  { label: "bearer token", pattern: /bearer\s+[A-Za-z0-9._~+/=-]{20,}/i },
  { label: "private key block", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: "basic auth in url", pattern: /https?:\/\/[^\s/:@"']+:[^\s/:@"']+@/i },
];

const LOG_SECRET_NRQL_PATTERN =
  "(?i).*(password\\s*[:=]|passwd\\s*[:=]|secret\\s*[:=]|api[_-]?key\\s*[:=]|authorization:\\s*bearer|NRAK-[A-Z0-9]{27}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY).*";

const FRAMEWORKS = [
  { label: "FedRAMP", slug: "fedramp", file: "fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { label: "CMMC", slug: "cmmc", file: "cmmc_compliance_report.md", title: "CMMC Level 2 Compliance Report" },
  { label: "SOC 2", slug: "soc2", file: "soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { label: "CIS", slug: "cis", file: "cis_compliance_report.md", title: "CIS Benchmark Alignment Report" },
  { label: "PCI-DSS", slug: "pci_dss", file: "pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { label: "STIG", slug: "disa_stig", file: "stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { label: "IRAP", slug: "irap", file: "irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { label: "ISMAP", slug: "ismap", file: "ismap_compliance_report.md", title: "ISMAP Compliance Report" },
] as const;

interface ControlDefinition {
  number: number;
  id: string;
  title: string;
  severity: NewrelicFindingSeverity;
  category: NewrelicAssessmentCategory;
  mappings: string[];
}

function mappingsFor(values: [string, string, string, string, string, string, string, string]): string[] {
  return FRAMEWORKS.map((framework, index) => `${framework.label} ${values[index]}`);
}

const CONTROLS: Record<number, ControlDefinition> = {
  1: { number: 1, id: "NR-01-SSO-ENFORCEMENT", title: "SSO/SAML enforcement", severity: "critical", category: "identity", mappings: mappingsFor(["IA-2", "AC.L2-3.1.1", "CC6.1", "1.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "CPS-04"]) },
  2: { number: 2, id: "NR-02-USER-TYPE-LEAST-PRIVILEGE", title: "User type least privilege", severity: "medium", category: "identity", mappings: mappingsFor(["AC-6", "AC.L2-3.1.5", "CC6.3", "6.1", "7.2.1", "SRG-APP-000340", "ISM-0432", "CPS-07"]) },
  3: { number: 3, id: "NR-03-ADMIN-MINIMIZATION", title: "Admin user minimization", severity: "high", category: "identity", mappings: mappingsFor(["AC-6(5)", "AC.L2-3.1.5", "CC6.3", "6.2", "7.2.2", "SRG-APP-000340", "ISM-1507", "CPS-07"]) },
  4: { number: 4, id: "NR-04-API-KEY-INVENTORY", title: "API key inventory", severity: "high", category: "access_control", mappings: mappingsFor(["IA-5", "IA.L2-3.5.2", "CC6.1", "5.1", "8.6.1", "SRG-APP-000175", "ISM-1590", "CPS-05"]) },
  5: { number: 5, id: "NR-05-API-KEY-AGE", title: "API key age", severity: "high", category: "access_control", mappings: mappingsFor(["IA-5(1)", "IA.L2-3.5.8", "CC6.1", "5.2", "8.6.3", "SRG-APP-000175", "ISM-1590", "CPS-05"]) },
  6: { number: 6, id: "NR-06-UNUSED-API-KEYS", title: "Unused API keys", severity: "medium", category: "access_control", mappings: mappingsFor(["AC-2(3)", "AC.L2-3.1.1", "CC6.2", "5.3", "8.1.4", "SRG-APP-000025", "ISM-1404", "CPS-07"]) },
  7: { number: 7, id: "NR-07-ACCOUNT-ACCESS-CONTROLS", title: "Account access controls", severity: "high", category: "access_control", mappings: mappingsFor(["AC-3", "AC.L2-3.1.2", "CC6.3", "6.3", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]) },
  8: { number: 8, id: "NR-08-CROSS-ACCOUNT-RESTRICTIONS", title: "Cross-account access restrictions", severity: "medium", category: "access_control", mappings: mappingsFor(["AC-4", "AC.L2-3.1.3", "CC6.6", "6.4", "7.2.3", "SRG-APP-000039", "ISM-1148", "CPS-11"]) },
  9: { number: 9, id: "NR-09-ALERT-POLICY-COVERAGE", title: "Alert policy coverage", severity: "high", category: "alerting", mappings: mappingsFor(["SI-4", "SI.L2-3.14.6", "CC7.2", "8.1", "10.6.1", "SRG-APP-000089", "ISM-0580", "CPS-10"]) },
  10: { number: 10, id: "NR-10-ALERT-NOTIFICATION-CHANNELS", title: "Alert notification channels", severity: "high", category: "alerting", mappings: mappingsFor(["AU-5", "AU.L2-3.3.4", "CC7.3", "8.2", "10.6.1", "SRG-APP-000108", "ISM-0580", "CPS-10"]) },
  11: { number: 11, id: "NR-11-DATA-RETENTION", title: "Data retention settings", severity: "medium", category: "data_governance", mappings: mappingsFor(["AU-11", "AU.L2-3.3.1", "CC7.4", "8.3", "3.1", "SRG-APP-000515", "ISM-0859", "CPS-10"]) },
  12: { number: 12, id: "NR-12-LOG-OBFUSCATION", title: "Log obfuscation rules", severity: "high", category: "data_governance", mappings: mappingsFor(["SC-28", "SC.L2-3.13.16", "CC6.7", "3.1", "3.4", "SRG-APP-000231", "ISM-0457", "CPS-09"]) },
  13: { number: 13, id: "NR-13-SYNTHETIC-MONITOR-SECURITY", title: "Synthetic monitor security", severity: "high", category: "data_governance", mappings: mappingsFor(["IA-5(7)", "IA.L2-3.5.10", "CC6.1", "5.4", "8.2.1", "SRG-APP-000175", "ISM-1590", "CPS-05"]) },
  14: { number: 14, id: "NR-14-DASHBOARD-PERMISSIONS", title: "Dashboard permissions", severity: "medium", category: "data_governance", mappings: mappingsFor(["AC-3", "AC.L2-3.1.2", "CC6.3", "6.5", "7.2.2", "SRG-APP-000033", "ISM-0432", "CPS-07"]) },
  15: { number: 15, id: "NR-15-LOGS-IN-CONTEXT-SECURITY", title: "Logs in context security", severity: "high", category: "data_governance", mappings: mappingsFor(["SC-28", "SC.L2-3.13.16", "CC6.7", "3.2", "3.4", "SRG-APP-000231", "ISM-0457", "CPS-09"]) },
  16: { number: 16, id: "NR-16-INFRA-AGENT-CONFIGURATION", title: "Infrastructure agent configuration", severity: "medium", category: "data_governance", mappings: mappingsFor(["SC-8", "SC.L2-3.13.8", "CC6.7", "9.1", "4.1", "SRG-APP-000219", "ISM-0490", "CPS-11"]) },
  17: { number: 17, id: "NR-17-APPLIED-INTELLIGENCE-SENSITIVITY", title: "Applied intelligence sensitivity", severity: "medium", category: "alerting", mappings: mappingsFor(["SC-28", "SC.L2-3.13.16", "CC6.7", "3.3", "3.4.1", "SRG-APP-000231", "ISM-0457", "CPS-09"]) },
  18: { number: 18, id: "NR-18-AUTH-DOMAIN-CONFIGURATION", title: "Authentication domain configuration", severity: "high", category: "identity", mappings: mappingsFor(["IA-2", "AC.L2-3.1.1", "CC6.1", "1.2", "8.3.2", "SRG-APP-000148", "ISM-1557", "CPS-04"]) },
  19: { number: 19, id: "NR-19-INACTIVE-USER-ACCOUNTS", title: "Inactive user accounts", severity: "medium", category: "identity", mappings: mappingsFor(["AC-2(3)", "AC.L2-3.1.1", "CC6.2", "7.1", "8.1.4", "SRG-APP-000025", "ISM-1404", "CPS-07"]) },
  20: { number: 20, id: "NR-20-CUSTOM-ROLE-PERMISSIONS", title: "Custom role permissions", severity: "medium", category: "access_control", mappings: mappingsFor(["AC-6", "AC.L2-3.1.5", "CC6.3", "6.6", "7.2.2", "SRG-APP-000340", "ISM-0432", "CPS-07"]) },
};

export const NEWRELIC_CONTROL_CATALOG: ReadonlyArray<ControlDefinition> = Object.values(CONTROLS);

export interface NewrelicResolvedConfig {
  apiKey: string;
  accountIds: number[];
  region: NewrelicRegion;
  nerdgraphUrl: string;
  restBaseUrl: string;
  timeoutMs: number;
  auditWindowDays: number;
  sourceChain: string[];
}

export interface NewrelicAccessSurface {
  name: string;
  endpoint: string;
  required: boolean;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface NewrelicAccessCheckResult {
  status: "healthy" | "limited";
  region: NewrelicRegion;
  accountIds: number[];
  surfaces: NewrelicAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface NewrelicFinding {
  id: string;
  control: number;
  title: string;
  severity: NewrelicFindingSeverity;
  status: NewrelicFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface NewrelicAssessmentResult {
  category: NewrelicAssessmentCategory;
  title: string;
  summary: JsonRecord;
  findings: NewrelicFinding[];
  errors: string[];
  coreData: Record<string, unknown>;
}

export interface NewrelicAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface Collected<T> {
  data: T;
  error?: string;
}

type AuthArgs = {
  api_key?: string;
  account_id?: string;
  region?: string;
  config_file?: string;
  timeout_seconds?: number;
  audit_window_days?: number;
};

type IdentityArgs = AuthArgs & {
  user_limit?: number;
  inactive_days?: number;
  max_admins?: number;
  max_full_platform_percent?: number;
  admin_role_pattern?: string;
};

type AccessControlArgs = AuthArgs & {
  user_limit?: number;
  inactive_days?: number;
  max_key_age_days?: number;
  max_accounts_per_user?: number;
  admin_role_pattern?: string;
  production_account_pattern?: string;
  nonproduction_account_pattern?: string;
};

type AlertingArgs = AuthArgs & {
  entity_limit?: number;
  approved_email_domains?: string;
};

type DataGovernanceArgs = AuthArgs & {
  entity_limit?: number;
  min_retention_days?: number;
  script_sample_limit?: number;
};

type ExportAuditBundleArgs = IdentityArgs & AccessControlArgs & AlertingArgs & DataGovernanceArgs & {
  output_dir?: string;
};

export interface NewrelicIdentityOptions {
  userLimit?: number;
  inactiveDays?: number;
  maxAdmins?: number;
  maxFullPlatformPercent?: number;
  adminRolePattern?: string;
  now?: number;
}

export interface NewrelicAccessControlOptions {
  userLimit?: number;
  inactiveDays?: number;
  maxKeyAgeDays?: number;
  maxAccountsPerUser?: number;
  adminRolePattern?: string;
  productionAccountPattern?: string;
  nonproductionAccountPattern?: string;
  now?: number;
}

export interface NewrelicAlertingOptions {
  entityLimit?: number;
  approvedEmailDomains?: string[];
}

export interface NewrelicDataGovernanceOptions {
  entityLimit?: number;
  minRetentionDays?: number;
  scriptSampleLimit?: number;
}

export type NewrelicBundleOptions = NewrelicIdentityOptions
  & NewrelicAccessControlOptions
  & NewrelicAlertingOptions
  & NewrelicDataGovernanceOptions;

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

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/^(true|yes|enabled|on)$/i.test(value.trim())) return true;
    if (/^(false|no|disabled|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function getNestedValue(value: unknown, path: Array<string | number>): unknown {
  let current: unknown = value;
  for (const segment of path) {
    if (typeof segment === "number") {
      current = asArray(current)[segment];
    } else {
      current = asObject(current)?.[segment];
    }
    if (current === undefined) return undefined;
  }
  return current;
}

function parseTimestamp(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 1e12 ? value * 1000 : value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return parseTimestamp(numeric);
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function ageInDays(timestampMs: number, now: number): number {
  return Math.floor((now - timestampMs) / 86_400_000);
}

function emailDomain(email: string | undefined): string | undefined {
  const at = email?.lastIndexOf("@") ?? -1;
  return at >= 0 ? email?.slice(at + 1).toLowerCase() : undefined;
}

function parseListArgument(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }
  const raw = asString(value);
  if (!raw) return [];
  return raw.split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean);
}

function parseAccountIds(value: unknown): number[] {
  const ids = parseListArgument(value)
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0);
  return [...new Set(ids)];
}

function compilePattern(value: string | undefined, fallback: string): RegExp {
  const source = value?.trim() || fallback;
  try {
    return new RegExp(source, "i");
  } catch {
    return new RegExp(fallback, "i");
  }
}

function sample<T>(values: T[], limit = 25): T[] {
  return values.slice(0, limit);
}

function percent(part: number, total: number): number {
  if (total <= 0) return 0;
  return Number(((part / total) * 100).toFixed(1));
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "newrelic";
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
    if (!existsSync(candidate)) {
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

function redactSecrets(message: string, apiKey?: string): string {
  let redacted = message.replace(/NRAK-[A-Za-z0-9]{8,}/g, "NRAK-[REDACTED]");
  if (apiKey && apiKey.length >= 8) {
    redacted = redacted.split(apiKey).join("[REDACTED]");
  }
  return redacted.replace(/(api-key\s*[:=]\s*)\S+/gi, "$1[REDACTED]");
}

function parseRegion(value: string | undefined): NewrelicRegion | undefined {
  const normalized = value?.trim().toUpperCase();
  if (!normalized) return undefined;
  if (normalized === "US" || normalized === "EU") return normalized;
  throw new Error(`Unsupported New Relic region "${value}". Use US or EU.`);
}

interface ConfigFileValues {
  apiKey?: string;
  accountIds: number[];
  region?: string;
  timeoutSeconds?: number;
  auditWindowDays?: number;
}

function readConfigFile(pathname: string): ConfigFileValues | undefined {
  if (!existsSync(pathname)) return undefined;
  let parsed: unknown;
  try {
    parsed = parseYaml(readFileSync(pathname, "utf8"));
  } catch (error) {
    throw new Error(`Unable to parse New Relic config file ${pathname}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const object = asObject(parsed) ?? {};
  return {
    apiKey: asString(object.api_key) ?? asString(object.apiKey),
    accountIds: parseAccountIds(object.account_ids ?? object.accountIds ?? object.account_id ?? object.accountId),
    region: asString(object.region),
    timeoutSeconds: asNumber(object.timeout_seconds) ?? asNumber(object.timeout),
    auditWindowDays: asNumber(object.audit_window_days) ?? asNumber(object.auditWindowDays),
  };
}

export function resolveNewrelicConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
): NewrelicResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file)
    ?? asString(env.NEW_RELIC_SEC_INSPECTOR_CONFIG)
    ?? join(homeDir, ".newrelic-sec-inspector", "config.yaml");
  const fileValues = readConfigFile(configPath);

  const apiKey = asString(input.api_key) ?? asString(env.NEW_RELIC_API_KEY) ?? fileValues?.apiKey;
  if (!apiKey) {
    throw new Error("NEW_RELIC_API_KEY, an api_key argument, or api_key in ~/.newrelic-sec-inspector/config.yaml is required.");
  }
  sourceChain.push(
    asString(input.api_key) ? "arguments:api_key" : asString(env.NEW_RELIC_API_KEY) ? "environment:NEW_RELIC_API_KEY" : `config:${configPath}`,
  );

  const argumentAccountIds = parseAccountIds(input.account_ids ?? input.account_id);
  const envAccountIds = parseAccountIds(env.NEW_RELIC_ACCOUNT_ID);
  const accountIds = argumentAccountIds.length > 0
    ? argumentAccountIds
    : envAccountIds.length > 0
      ? envAccountIds
      : fileValues?.accountIds ?? [];
  if (argumentAccountIds.length > 0) {
    sourceChain.push("arguments:account_id");
  } else if (envAccountIds.length > 0) {
    sourceChain.push("environment:NEW_RELIC_ACCOUNT_ID");
  } else if (accountIds.length > 0) {
    sourceChain.push(`config:${configPath}:account_id`);
  } else {
    sourceChain.push("discovery:actor.accounts");
  }

  const regionValue = asString(input.region) ?? asString(env.NEW_RELIC_REGION) ?? fileValues?.region;
  const region = parseRegion(regionValue) ?? "US";
  sourceChain.push(
    asString(input.region)
      ? "arguments:region"
      : asString(env.NEW_RELIC_REGION)
        ? "environment:NEW_RELIC_REGION"
        : fileValues?.region
          ? `config:${configPath}:region`
          : "default:region-us",
  );

  const timeoutSeconds = asNumber(input.timeout_seconds)
    ?? asNumber(env.NEW_RELIC_TIMEOUT)
    ?? fileValues?.timeoutSeconds;
  const auditWindowDays = asNumber(input.audit_window_days)
    ?? asNumber(env.NEW_RELIC_AUDIT_WINDOW_DAYS)
    ?? fileValues?.auditWindowDays;

  return {
    apiKey,
    accountIds,
    region,
    nerdgraphUrl: REGION_ENDPOINTS[region].nerdgraph,
    restBaseUrl: REGION_ENDPOINTS[region].rest,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    auditWindowDays: clampNumber(auditWindowDays, DEFAULT_AUDIT_WINDOW_DAYS, 1, 395),
    sourceChain: [...new Set(sourceChain)],
  };
}

function retryDelayFromResponse(response: Response, attempt: number): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, 15_000);
    }
  }
  const reset = response.headers.get("x-ratelimit-reset");
  if (reset) {
    const epochSeconds = Number(reset);
    if (Number.isFinite(epochSeconds)) {
      const delta = epochSeconds * 1000 - Date.now();
      return Math.min(Math.max(delta, 250), 15_000);
    }
  }
  return Math.min(500 * 2 ** attempt, 15_000);
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function parseLinkNext(linkHeader: string | null): string | undefined {
  if (!linkHeader) return undefined;
  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="?next"?/i);
    if (match) return match[1];
  }
  return undefined;
}

function isUnknownCursorArgumentError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /cursor/i.test(message) && /unknown argument|not defined|does not accept|undefined argument/i.test(message);
}

function nerdgraphErrorSummary(errors: unknown): string {
  return asRecords(errors)
    .map((error) => {
      const message = asString(error.message) ?? "unknown NerdGraph error";
      const path = asArray(error.path).map((segment) => String(segment)).join(".");
      return path ? `${message} (at ${path})` : message;
    })
    .join("; ");
}

const QUERY_CURRENT_USER = "{ actor { user { id email name } } }";
const QUERY_ORGANIZATION = "{ actor { organization { id name } } }";
const QUERY_ACCOUNTS = "{ actor { accounts { id name } } }";
const QUERY_AUTHENTICATION_DOMAINS = `query($cursor: String) {
  actor { organization { userManagement {
    authenticationDomains(cursor: $cursor) {
      nextCursor totalCount
      authenticationDomains { id name provisioningType }
    }
  } } }
}`;
const QUERY_DOMAIN_USERS = `query($domainId: [ID!], $cursor: String) {
  actor { organization { userManagement {
    authenticationDomains(id: $domainId) { authenticationDomains {
      id name provisioningType
      users(cursor: $cursor) {
        nextCursor totalCount
        users {
          id name email lastActive emailVerificationState timeZone
          type { id displayName }
          groups { groups { id displayName } }
        }
      }
    } }
  } } }
}`;
const QUERY_DOMAIN_GROUP_GRANTS = `query($domainId: [ID!], $cursor: String) {
  actor { organization { authorizationManagement {
    authenticationDomains(id: $domainId) { authenticationDomains {
      id name
      groups(cursor: $cursor) {
        nextCursor totalCount
        groups {
          id displayName
          roles { roles { id roleId name displayName type accountId organizationId } }
        }
      }
    } }
  } } }
}`;
const QUERY_ROLES = `query($cursor: String) {
  actor { organization { authorizationManagement {
    roles(cursor: $cursor) { nextCursor totalCount roles { id name displayName scope type } }
  } } }
}`;
const API_KEY_FIELDS = `keys {
        id name notes type createdAt
        ... on ApiAccessIngestKey { accountId ingestType }
        ... on ApiAccessUserKey { accountId userId }
      }`;
const QUERY_API_KEYS = `query($query: ApiAccessKeySearchQuery!, $cursor: String) {
  actor { apiAccess {
    keySearch(query: $query, cursor: $cursor) {
      nextCursor count
      ${API_KEY_FIELDS}
    }
  } }
}`;
const QUERY_API_KEYS_SINGLE_PAGE = `query($query: ApiAccessKeySearchQuery!) {
  actor { apiAccess {
    keySearch(query: $query) {
      count
      ${API_KEY_FIELDS}
    }
  } }
}`;
const QUERY_NRQL = `query($accountId: Int!, $nrql: Nrql!) {
  actor { account(id: $accountId) { nrql(query: $nrql) { results } } }
}`;
const QUERY_ENTITY_SEARCH = `query($query: String!, $cursor: String) {
  actor { entitySearch(query: $query) {
    count
    results(cursor: $cursor) {
      nextCursor
      entities {
        guid name entityType domain type accountId reporting
        tags { key values }
        ... on AlertableEntityOutline { alertSeverity }
        ... on DashboardEntityOutline { permissions dashboardParentGuid createdAt updatedAt owner { email userId } }
        ... on SyntheticMonitorEntityOutline { monitorType monitoredUrl period monitorId }
        ... on SecureCredentialEntityOutline { secureCredentialId updatedAt description }
        ... on WorkloadEntityOutline { workloadStatus { statusValue } }
      }
    }
  } }
}`;
const QUERY_ALERT_POLICIES = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { alerts {
    policiesSearch(cursor: $cursor) { nextCursor totalCount policies { id name incidentPreference accountId } }
  } } }
}`;
const QUERY_NRQL_CONDITIONS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { alerts {
    nrqlConditionsSearch(cursor: $cursor) {
      nextCursor totalCount
      nrqlConditions { id name type enabled policyId nrql { query } }
    }
  } } }
}`;
const QUERY_DESTINATIONS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiNotifications {
    destinations(cursor: $cursor) {
      nextCursor totalCount
      entities { id name type active status isUserAuthenticated createdAt updatedAt lastSent properties { key value displayValue } }
    }
  } } }
}`;
const QUERY_CHANNELS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiNotifications {
    channels(cursor: $cursor) {
      nextCursor totalCount
      entities { id name type destinationId product active status }
    }
  } } }
}`;
const QUERY_WORKFLOWS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiWorkflows {
    workflows(filters: {}, cursor: $cursor) {
      nextCursor totalCount
      entities {
        id name workflowEnabled enrichmentsEnabled destinationsEnabled
        destinationConfigurations { channelId name type notificationTriggers }
        enrichments { id name type configurations { ... on AiWorkflowsNrqlConfiguration { query } } }
      }
    }
  } } }
}`;
const QUERY_RETENTION_RULES = `query($accountId: Int!) {
  actor { account(id: $accountId) { dataManagement {
    eventRetentionRules { id namespace retentionInDays createdAt createdById deletedAt deletedById }
  } } }
}`;
const QUERY_RETENTION_NAMESPACES = `query($accountId: Int!) {
  actor { account(id: $accountId) { dataManagement {
    customizableRetention { eventNamespaces { namespace } }
  } } }
}`;
const QUERY_OBFUSCATION_RULES = `query($accountId: Int!) {
  actor { account(id: $accountId) { logConfigurations {
    obfuscationRules {
      id name description filter enabled createdAt updatedAt
      actions { attributes method expression { id name } }
    }
  } } }
}`;
const QUERY_OBFUSCATION_EXPRESSIONS = `query($accountId: Int!) {
  actor { account(id: $accountId) { logConfigurations {
    obfuscationExpressions { id name regex description createdAt updatedAt }
  } } }
}`;
const QUERY_PIPELINE_CLOUD_RULES = `{
  actor { entityManagement {
    entitySearch(query: "type = 'PIPELINE_CLOUD_RULE'") {
      entities {
        id name type
        ... on EntityManagementPipelineCloudRuleEntity { nrql description enabled }
      }
    }
  } }
}`;
const QUERY_NRQL_DROP_RULES = `query($accountId: Int!) {
  actor { account(id: $accountId) { nrqlDropRules {
    list { rules { id nrql accountId action createdBy createdAt description } error { reason description } }
  } } }
}`;
const QUERY_SYNTHETIC_SCRIPT = `query($accountId: Int!, $monitorGuid: EntityGuid!) {
  actor { account(id: $accountId) { synthetics { script(monitorGuid: $monitorGuid) { text } } } }
}`;
const QUERY_DASHBOARD_LIVE_URLS = `{
  actor { dashboard { liveUrls { liveUrls { title type createdAt } errors { description } } } }
}`;

export class NewrelicApiClient {
  private readonly config: NewrelicResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: SleepImpl;
  private readonly maxRetries: number;
  private discoveredAccountIds?: Promise<number[]>;

  constructor(
    config: NewrelicResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: SleepImpl;
      maxRetries?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.maxRetries = clampNumber(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
  }

  getResolvedConfig(): NewrelicResolvedConfig {
    return this.config;
  }

  private redact(message: string): string {
    return redactSecrets(message, this.config.apiKey);
  }

  private async requestWithRetry(url: string, init: RequestInit): Promise<Response> {
    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      let response: Response;
      try {
        response = await this.fetchImpl(url, { ...init, signal: controller.signal });
      } catch (error) {
        const aborted = controller.signal.aborted;
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(
          aborted
            ? `New Relic request timed out after ${Math.round(this.config.timeoutMs / 1000)}s: ${url}`
            : `New Relic request failed: ${this.redact(message)}`,
        );
      } finally {
        clearTimeout(timeout);
      }

      if (isRetryableStatus(response.status) && attempt < this.maxRetries) {
        await this.sleep(retryDelayFromResponse(response, attempt));
        continue;
      }
      return response;
    }
  }

  async nerdgraph(query: string, variables: JsonRecord = {}): Promise<JsonRecord> {
    const response = await this.requestWithRetry(this.config.nerdgraphUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "api-key": this.config.apiKey,
      },
      body: JSON.stringify({ query, variables }),
    });

    const rawText = await response.text();
    let payload: JsonRecord = {};
    if (rawText.length > 0) {
      try {
        payload = asObject(JSON.parse(rawText)) ?? {};
      } catch {
        payload = {};
      }
    }
    if (!response.ok) {
      const detail = nerdgraphErrorSummary(payload.errors) || rawText.slice(0, 240);
      throw new Error(this.redact(`NerdGraph request failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`));
    }
    const errors = asArray(payload.errors);
    const data = asObject(payload.data);
    if (errors.length > 0) {
      throw new Error(this.redact(`NerdGraph returned errors: ${nerdgraphErrorSummary(errors)}`));
    }
    if (!data) {
      throw new Error("NerdGraph response did not include data.");
    }
    return data;
  }

  private async paginate(
    query: string,
    variables: JsonRecord,
    pagePath: Array<string | number>,
    itemsKey: string,
    limit: number,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_PAGES && items.length < limit; page += 1) {
      const data = await this.nerdgraph(query, cursor ? { ...variables, cursor } : variables);
      const pageObject = asObject(getNestedValue(data, pagePath));
      if (!pageObject) {
        throw new Error(`NerdGraph response did not include ${pagePath.filter((segment) => typeof segment === "string").join(".")}.`);
      }
      const pageItems = asRecords(pageObject[itemsKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      const nextCursor = asString(pageObject.nextCursor);
      if (!nextCursor || nextCursor === cursor || pageItems.length === 0) break;
      cursor = nextCursor;
    }
    return items;
  }

  private buildRestUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.restBaseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  async restGet(pathOrUrl: string, query: JsonRecord = {}): Promise<{ payload: JsonRecord; nextUrl?: string }> {
    const url = this.buildRestUrl(pathOrUrl, query);
    const response = await this.requestWithRetry(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        "api-key": this.config.apiKey,
      },
    });
    const rawText = await response.text();
    let payload: JsonRecord = {};
    if (rawText.length > 0) {
      try {
        payload = asObject(JSON.parse(rawText)) ?? {};
      } catch {
        payload = {};
      }
    }
    if (!response.ok) {
      const detail = asString(asObject(payload.error)?.title) ?? asString(payload.error) ?? rawText.slice(0, 240);
      throw new Error(this.redact(`REST API v2 request failed for ${new URL(url).pathname} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`));
    }
    return { payload, nextUrl: parseLinkNext(response.headers.get("link")) };
  }

  async restList(path: string, collectionKey: string, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let url: string | undefined = path;
    for (let page = 0; url && page < MAX_PAGES && items.length < limit; page += 1) {
      const { payload, nextUrl } = await this.restGet(url);
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      url = nextUrl;
    }
    return items;
  }

  async getCurrentUser(): Promise<JsonRecord> {
    const data = await this.nerdgraph(QUERY_CURRENT_USER);
    return asObject(getNestedValue(data, ["actor", "user"])) ?? {};
  }

  async getOrganization(): Promise<JsonRecord> {
    const data = await this.nerdgraph(QUERY_ORGANIZATION);
    return asObject(getNestedValue(data, ["actor", "organization"])) ?? {};
  }

  async listAccounts(): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_ACCOUNTS);
    return asRecords(getNestedValue(data, ["actor", "accounts"]));
  }

  async resolveAccountIds(): Promise<number[]> {
    if (this.config.accountIds.length > 0) return this.config.accountIds;
    if (!this.discoveredAccountIds) {
      this.discoveredAccountIds = this.listAccounts().then((accounts) => {
        const ids = accounts.map((account) => asNumber(account.id)).filter((id): id is number => id !== undefined);
        if (ids.length === 0) {
          throw new Error("No New Relic accounts were visible to the API key. Set NEW_RELIC_ACCOUNT_ID explicitly.");
        }
        return ids;
      });
      this.discoveredAccountIds.catch(() => {
        this.discoveredAccountIds = undefined;
      });
    }
    return this.discoveredAccountIds;
  }

  async listAuthenticationDomains(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(
      QUERY_AUTHENTICATION_DOMAINS,
      {},
      ["actor", "organization", "userManagement", "authenticationDomains"],
      "authenticationDomains",
      limit,
    );
  }

  async listOrganizationAuthenticationDomains(organizationId: string): Promise<JsonRecord[]> {
    const query = `{
  customerAdministration {
    authenticationDomains(filter: { organizationId: { eq: ${JSON.stringify(organizationId)} } }) {
      items { id name organizationId provisioningType authenticationType }
      nextCursor
    }
  }
}`;
    const data = await this.nerdgraph(query);
    return asRecords(getNestedValue(data, ["customerAdministration", "authenticationDomains", "items"]));
  }

  async listDomainUsers(domainId: string, limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(
      QUERY_DOMAIN_USERS,
      { domainId: [domainId] },
      ["actor", "organization", "userManagement", "authenticationDomains", "authenticationDomains", 0, "users"],
      "users",
      limit,
    );
  }

  async listDomainGroupGrants(domainId: string, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    const groups = await this.paginate(
      QUERY_DOMAIN_GROUP_GRANTS,
      { domainId: [domainId] },
      ["actor", "organization", "authorizationManagement", "authenticationDomains", "authenticationDomains", 0, "groups"],
      "groups",
      limit,
    );
    return groups.map((group) => ({
      id: group.id,
      displayName: group.displayName,
      roles: asRecords(asObject(group.roles)?.roles),
    }));
  }

  async listRoles(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_ROLES, {}, ["actor", "organization", "authorizationManagement", "roles"], "roles", limit);
  }

  async listApiKeys(types: Array<"USER" | "INGEST">, accountIds?: number[], limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    const scope = accountIds && accountIds.length > 0 ? { accountIds } : undefined;
    const variables = { query: scope ? { types, scope } : { types } };
    try {
      return await this.paginate(QUERY_API_KEYS, variables, ["actor", "apiAccess", "keySearch"], "keys", limit);
    } catch (error) {
      if (!isUnknownCursorArgumentError(error)) throw error;
      const data = await this.nerdgraph(QUERY_API_KEYS_SINGLE_PAGE, variables);
      return asRecords(asObject(getNestedValue(data, ["actor", "apiAccess", "keySearch"]))?.keys).slice(0, limit);
    }
  }

  async runNrql(accountId: number, nrql: string): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_NRQL, { accountId, nrql });
    return asRecords(getNestedValue(data, ["actor", "account", "nrql", "results"]));
  }

  async searchEntities(query: string, limit = DEFAULT_ENTITY_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_ENTITY_SEARCH, { query }, ["actor", "entitySearch", "results"], "entities", limit);
  }

  async countEntities(query: string): Promise<number> {
    const data = await this.nerdgraph(QUERY_ENTITY_SEARCH, { query });
    return asNumber(getNestedValue(data, ["actor", "entitySearch", "count"])) ?? 0;
  }

  async listAlertPolicies(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_ALERT_POLICIES, { accountId }, ["actor", "account", "alerts", "policiesSearch"], "policies", limit);
  }

  async listNrqlConditions(accountId: number, limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(
      QUERY_NRQL_CONDITIONS,
      { accountId },
      ["actor", "account", "alerts", "nrqlConditionsSearch"],
      "nrqlConditions",
      limit,
    );
  }

  async listNotificationDestinations(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_DESTINATIONS, { accountId }, ["actor", "account", "aiNotifications", "destinations"], "entities", limit);
  }

  async listNotificationChannels(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_CHANNELS, { accountId }, ["actor", "account", "aiNotifications", "channels"], "entities", limit);
  }

  async listWorkflows(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.paginate(QUERY_WORKFLOWS, { accountId }, ["actor", "account", "aiWorkflows", "workflows"], "entities", limit);
  }

  async listEventRetentionRules(accountId: number): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_RETENTION_RULES, { accountId });
    return asRecords(getNestedValue(data, ["actor", "account", "dataManagement", "eventRetentionRules"]));
  }

  async listRetentionNamespaces(accountId: number): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_RETENTION_NAMESPACES, { accountId });
    return asRecords(getNestedValue(data, ["actor", "account", "dataManagement", "customizableRetention", "eventNamespaces"]));
  }

  async listObfuscationRules(accountId: number): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_OBFUSCATION_RULES, { accountId });
    return asRecords(getNestedValue(data, ["actor", "account", "logConfigurations", "obfuscationRules"]));
  }

  async listObfuscationExpressions(accountId: number): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_OBFUSCATION_EXPRESSIONS, { accountId });
    return asRecords(getNestedValue(data, ["actor", "account", "logConfigurations", "obfuscationExpressions"]));
  }

  async listPipelineCloudRules(): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_PIPELINE_CLOUD_RULES);
    return asRecords(getNestedValue(data, ["actor", "entityManagement", "entitySearch", "entities"]));
  }

  async listNrqlDropRules(accountId: number): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_NRQL_DROP_RULES, { accountId });
    const list = asObject(getNestedValue(data, ["actor", "account", "nrqlDropRules", "list"]));
    const error = asObject(list?.error);
    if (error) {
      throw new Error(`NRQL drop rule listing failed: ${asString(error.reason) ?? "unknown"} ${asString(error.description) ?? ""}`.trim());
    }
    return asRecords(list?.rules);
  }

  async getSyntheticScript(accountId: number, monitorGuid: string): Promise<string> {
    const data = await this.nerdgraph(QUERY_SYNTHETIC_SCRIPT, { accountId, monitorGuid });
    return asString(getNestedValue(data, ["actor", "account", "synthetics", "script", "text"])) ?? "";
  }

  async listDashboardLiveUrls(): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_DASHBOARD_LIVE_URLS);
    const result = asObject(getNestedValue(data, ["actor", "dashboard", "liveUrls"]));
    const errors = asRecords(result?.errors);
    if (errors.length > 0) {
      throw new Error(`Dashboard live URL listing failed: ${errors.map((error) => asString(error.description) ?? "unknown error").join("; ")}`);
    }
    return asRecords(result?.liveUrls);
  }

  async listRestUsers(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.restList("/v2/users.json", "users", limit);
  }

  async listRestAlertPolicies(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.restList("/v2/alerts_policies.json", "policies", limit);
  }
}

export type NewrelicClientSurface = Pick<
  NewrelicApiClient,
  | "getResolvedConfig"
  | "getCurrentUser"
  | "getOrganization"
  | "listAccounts"
  | "resolveAccountIds"
  | "listAuthenticationDomains"
  | "listOrganizationAuthenticationDomains"
  | "listDomainUsers"
  | "listDomainGroupGrants"
  | "listRoles"
  | "listApiKeys"
  | "runNrql"
  | "searchEntities"
  | "countEntities"
  | "listAlertPolicies"
  | "listNrqlConditions"
  | "listNotificationDestinations"
  | "listNotificationChannels"
  | "listWorkflows"
  | "listEventRetentionRules"
  | "listRetentionNamespaces"
  | "listObfuscationRules"
  | "listObfuscationExpressions"
  | "listPipelineCloudRules"
  | "listNrqlDropRules"
  | "getSyntheticScript"
  | "listDashboardLiveUrls"
  | "listRestUsers"
>;

type IdentityClient = Pick<
  NewrelicClientSurface,
  | "getResolvedConfig"
  | "getOrganization"
  | "listAuthenticationDomains"
  | "listOrganizationAuthenticationDomains"
  | "listDomainUsers"
  | "listDomainGroupGrants"
  | "listRoles"
>;

type AccessControlClient = Pick<
  NewrelicClientSurface,
  | "getResolvedConfig"
  | "resolveAccountIds"
  | "listAccounts"
  | "listAuthenticationDomains"
  | "listDomainUsers"
  | "listDomainGroupGrants"
  | "listRoles"
  | "listApiKeys"
  | "runNrql"
>;

type AlertingClient = Pick<
  NewrelicClientSurface,
  | "getResolvedConfig"
  | "resolveAccountIds"
  | "getCurrentUser"
  | "listAlertPolicies"
  | "listNrqlConditions"
  | "listNotificationDestinations"
  | "listNotificationChannels"
  | "listWorkflows"
  | "searchEntities"
>;

type DataGovernanceClient = Pick<
  NewrelicClientSurface,
  | "getResolvedConfig"
  | "resolveAccountIds"
  | "listEventRetentionRules"
  | "listRetentionNamespaces"
  | "listObfuscationRules"
  | "listObfuscationExpressions"
  | "listPipelineCloudRules"
  | "listNrqlDropRules"
  | "searchEntities"
  | "countEntities"
  | "getSyntheticScript"
  | "listDashboardLiveUrls"
  | "runNrql"
>;

async function collect<T>(source: string, fallback: T, load: () => Promise<T>): Promise<Collected<T>> {
  try {
    return { data: await load() };
  } catch (error) {
    return {
      data: fallback,
      error: `${source}: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function collectedErrors(items: Array<Collected<unknown>>): string[] {
  return items.map((item) => item.error).filter((error): error is string => Boolean(error));
}

function finding(
  controlNumber: number,
  status: NewrelicFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): NewrelicFinding {
  const control = CONTROLS[controlNumber];
  return {
    id: control.id,
    control: control.number,
    title: control.title,
    severity: control.severity,
    status,
    summary,
    evidence,
    mappings: control.mappings,
  };
}

async function readableSurface(
  name: string,
  endpoint: string,
  required: boolean,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<NewrelicAccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, required, status: "readable", count: countResolver?.(value) };
  } catch (error) {
    return {
      name,
      endpoint,
      required,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function arrayCount(value: unknown): number | undefined {
  return Array.isArray(value) ? value.length : undefined;
}

export async function checkNewrelicAccess(
  client: Pick<
    NewrelicClientSurface,
    | "getResolvedConfig"
    | "getCurrentUser"
    | "getOrganization"
    | "listAccounts"
    | "resolveAccountIds"
    | "listAuthenticationDomains"
    | "listRoles"
    | "listApiKeys"
    | "runNrql"
    | "searchEntities"
    | "listAlertPolicies"
    | "listEventRetentionRules"
    | "listObfuscationRules"
    | "listRestUsers"
  >,
): Promise<NewrelicAccessCheckResult> {
  const config = client.getResolvedConfig();
  const currentUser = await client.getCurrentUser().catch(() => ({} as JsonRecord));
  const accountIds = await client.resolveAccountIds().catch(() => config.accountIds);
  const primaryAccount = accountIds[0];

  const surfaces: NewrelicAccessSurface[] = [
    await readableSurface("actor_user", "NerdGraph actor.user", true, () => client.getCurrentUser(), () => 1),
    await readableSurface("accounts", "NerdGraph actor.accounts", true, () => client.listAccounts(), arrayCount),
    await readableSurface("organization", "NerdGraph actor.organization", true, () => client.getOrganization(), () => 1),
    await readableSurface(
      "user_management",
      "NerdGraph actor.organization.userManagement.authenticationDomains",
      true,
      () => client.listAuthenticationDomains(),
      arrayCount,
    ),
    await readableSurface(
      "authorization_management",
      "NerdGraph actor.organization.authorizationManagement.roles",
      true,
      () => client.listRoles(),
      arrayCount,
    ),
    await readableSurface("api_access", "NerdGraph actor.apiAccess.keySearch", true, () => client.listApiKeys(["USER"], undefined, 50), arrayCount),
    await readableSurface(
      "nrql",
      "NerdGraph actor.account.nrql (NrAuditEvent)",
      true,
      async () => {
        if (primaryAccount === undefined) throw new Error("No account ID available for NRQL.");
        return client.runNrql(primaryAccount, "SELECT count(*) FROM NrAuditEvent SINCE 1 day ago");
      },
      arrayCount,
    ),
    await readableSurface("entity_search", "NerdGraph actor.entitySearch", false, () => client.searchEntities("type = 'DASHBOARD'", 5), arrayCount),
    await readableSurface(
      "alerts",
      "NerdGraph actor.account.alerts.policiesSearch",
      false,
      async () => {
        if (primaryAccount === undefined) throw new Error("No account ID available for alerts.");
        return client.listAlertPolicies(primaryAccount, 50);
      },
      arrayCount,
    ),
    await readableSurface(
      "data_management",
      "NerdGraph actor.account.dataManagement.eventRetentionRules",
      false,
      async () => {
        if (primaryAccount === undefined) throw new Error("No account ID available for data management.");
        return client.listEventRetentionRules(primaryAccount);
      },
      arrayCount,
    ),
    await readableSurface(
      "log_configurations",
      "NerdGraph actor.account.logConfigurations.obfuscationRules",
      false,
      async () => {
        if (primaryAccount === undefined) throw new Error("No account ID available for log configurations.");
        return client.listObfuscationRules(primaryAccount);
      },
      arrayCount,
    ),
    await readableSurface("rest_v2_users", "REST v2 GET /v2/users.json", false, () => client.listRestUsers(50), arrayCount),
  ];

  const requiredSurfaces = surfaces.filter((surface) => surface.required);
  const readableRequired = requiredSurfaces.filter((surface) => surface.status === "readable").length;
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = readableRequired === requiredSurfaces.length ? "healthy" : "limited";

  return {
    status,
    region: config.region,
    accountIds,
    surfaces,
    notes: [
      `Using New Relic ${config.region} region endpoint ${config.nerdgraphUrl}.`,
      `Authenticated as ${asString(currentUser.email) ?? asString(currentUser.name) ?? asString(currentUser.id) ?? "unknown user"}.`,
      `Accounts in scope: ${accountIds.length > 0 ? accountIds.join(", ") : "none resolved"}.`,
      `${readableRequired}/${requiredSurfaces.length} required surfaces and ${readableCount}/${surfaces.length} total surfaces are readable.`,
      "REST API v2 /v2/users.json only lists original user model users and is informational.",
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run newrelic_assess_identity, newrelic_assess_access_control, newrelic_assess_alerting, newrelic_assess_data_governance, or newrelic_export_audit_bundle."
        : "Use a User API key from a user with Organization manager and Authentication domain manager roles plus access to every account in scope.",
  };
}

export interface NewrelicIdentityData {
  organization: Collected<JsonRecord>;
  authenticationDomains: Collected<JsonRecord[]>;
  organizationAuthenticationDomains: Collected<JsonRecord[]>;
  users: Collected<JsonRecord[]>;
  groupGrants: Collected<JsonRecord[]>;
  roles: Collected<JsonRecord[]>;
}

async function collectUsers(
  client: Pick<NewrelicClientSurface, "listDomainUsers">,
  domains: JsonRecord[],
  limit: number,
): Promise<JsonRecord[]> {
  const users: JsonRecord[] = [];
  for (const domain of domains) {
    const domainId = asString(domain.id);
    if (!domainId || users.length >= limit) continue;
    const domainUsers = await client.listDomainUsers(domainId, limit - users.length);
    users.push(...domainUsers.map((user) => ({
      ...user,
      authenticationDomainId: domainId,
      authenticationDomainName: asString(domain.name),
      provisioningType: asString(domain.provisioningType),
    })));
  }
  return users;
}

async function collectGroupGrants(
  client: Pick<NewrelicClientSurface, "listDomainGroupGrants">,
  domains: JsonRecord[],
): Promise<JsonRecord[]> {
  const groups: JsonRecord[] = [];
  for (const domain of domains) {
    const domainId = asString(domain.id);
    if (!domainId) continue;
    const domainGroups = await client.listDomainGroupGrants(domainId);
    groups.push(...domainGroups.map((group) => ({ ...group, authenticationDomainId: domainId })));
  }
  return groups;
}

export async function collectNewrelicIdentityData(
  client: IdentityClient,
  options: { userLimit?: number } = {},
): Promise<NewrelicIdentityData> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 50_000);
  const organization = await collect("organization", {} as JsonRecord, () => client.getOrganization());
  const authenticationDomains = await collect("userManagement.authenticationDomains", [] as JsonRecord[], () => client.listAuthenticationDomains());
  const organizationId = asString(organization.data.id);
  const organizationAuthenticationDomains = await collect(
    "customerAdministration.authenticationDomains",
    [] as JsonRecord[],
    async () => {
      if (!organizationId) throw new Error("organization id was not readable");
      return client.listOrganizationAuthenticationDomains(organizationId);
    },
  );
  const users = await collect("userManagement.users", [] as JsonRecord[], () => collectUsers(client, authenticationDomains.data, userLimit));
  const groupGrants = await collect("authorizationManagement.groups", [] as JsonRecord[], () => collectGroupGrants(client, authenticationDomains.data));
  const roles = await collect("authorizationManagement.roles", [] as JsonRecord[], () => client.listRoles());
  return { organization, authenticationDomains, organizationAuthenticationDomains, users, groupGrants, roles };
}

function userTypeId(user: JsonRecord): string {
  return (asString(asObject(user.type)?.id) ?? asString(asObject(user.type)?.displayName) ?? "UNKNOWN").toUpperCase();
}

function isFullPlatformUser(user: JsonRecord): boolean {
  const type = userTypeId(user);
  return type.includes("FULL");
}

function userGroupIds(user: JsonRecord): string[] {
  return asRecords(asObject(user.groups)?.groups).map((group) => asString(group.id)).filter((id): id is string => Boolean(id));
}

function userLabel(user: JsonRecord): string {
  return asString(user.email) ?? asString(user.name) ?? asString(user.id) ?? "user";
}

function grantRoleName(role: JsonRecord): string {
  return asString(role.displayName) ?? asString(role.name) ?? asString(role.roleId) ?? asString(role.id) ?? "role";
}

function adminGroupIds(groupGrants: JsonRecord[], adminRolePattern: RegExp): Set<string> {
  const ids = new Set<string>();
  for (const group of groupGrants) {
    const groupId = asString(group.id);
    if (!groupId) continue;
    const roles = asRecords(group.roles);
    if (roles.some((role) => adminRolePattern.test(grantRoleName(role)))) ids.add(groupId);
  }
  return ids;
}

function usersInGroups(users: JsonRecord[], groupIds: Set<string>): JsonRecord[] {
  return users.filter((user) => userGroupIds(user).some((id) => groupIds.has(id)));
}

function lastActiveAgeDays(user: JsonRecord, now: number): number | undefined {
  const timestamp = parseTimestamp(user.lastActive);
  return timestamp === undefined ? undefined : ageInDays(timestamp, now);
}

function domainLabel(domain: JsonRecord): string {
  return asString(domain.name) ?? asString(domain.id) ?? "authentication domain";
}

export function assessNewrelicIdentityData(
  data: NewrelicIdentityData,
  config: Pick<NewrelicResolvedConfig, "region" | "accountIds">,
  options: NewrelicIdentityOptions = {},
): NewrelicAssessmentResult {
  const now = options.now ?? Date.now();
  const inactiveDays = clampNumber(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 100_000);
  const maxFullPlatformPercent = clampNumber(options.maxFullPlatformPercent, DEFAULT_MAX_FULL_PLATFORM_PERCENT, 0, 100);
  const adminRolePattern = compilePattern(options.adminRolePattern, DEFAULT_ADMIN_ROLE_PATTERN);

  const domains = data.authenticationDomains.data;
  const orgDomains = data.organizationAuthenticationDomains.data;
  const users = data.users.data;
  const groupGrants = data.groupGrants.data;
  const roles = data.roles.data;

  const domainsReadable = !data.authenticationDomains.error;
  const usersReadable = !data.users.error;
  const grantsReadable = !data.groupGrants.error;
  const authTypeVisible = !data.organizationAuthenticationDomains.error && orgDomains.length > 0;

  const domainAuthTypes = orgDomains.map((domain) => ({
    id: asString(domain.id),
    name: domainLabel(domain),
    authenticationType: asString(domain.authenticationType)?.toUpperCase() ?? "UNKNOWN",
    provisioningType: asString(domain.provisioningType)?.toUpperCase() ?? "UNKNOWN",
  }));
  const passwordDomains = domainAuthTypes.filter((domain) => domain.authenticationType === "PASSWORD");
  const ssoDomains = domainAuthTypes.filter((domain) => SSO_AUTHENTICATION_TYPES.has(domain.authenticationType));
  const domainProvisioning = domains.map((domain) => ({
    id: asString(domain.id),
    name: domainLabel(domain),
    provisioningType: asString(domain.provisioningType)?.toUpperCase() ?? "UNKNOWN",
  }));
  const manualProvisioningDomains = domainProvisioning.filter((domain) => domain.provisioningType === "MANUAL");
  const scimDomains = domainProvisioning.filter((domain) => domain.provisioningType === "SCIM");

  const fullPlatformUsers = users.filter(isFullPlatformUser);
  const inactiveFullPlatformUsers = fullPlatformUsers.filter((user) => {
    const age = lastActiveAgeDays(user, now);
    return age === undefined || age > inactiveDays;
  });
  const fullPlatformShare = percent(fullPlatformUsers.length, users.length);
  const userTypeCounts: Record<string, number> = {};
  for (const user of users) {
    const type = userTypeId(user);
    userTypeCounts[type] = (userTypeCounts[type] ?? 0) + 1;
  }

  const adminGroups = adminGroupIds(groupGrants, adminRolePattern);
  const adminUsers = usersInGroups(users, adminGroups);
  const adminGroupNames = groupGrants
    .filter((group) => adminGroups.has(asString(group.id) ?? ""))
    .map((group) => asString(group.displayName) ?? asString(group.id) ?? "group");

  const inactiveUsers = users.filter((user) => {
    const age = lastActiveAgeDays(user, now);
    return age !== undefined && age > inactiveDays;
  });
  const neverActiveUsers = users.filter((user) => lastActiveAgeDays(user, now) === undefined);
  const customRoles = roles.filter((role) => (asString(role.type) ?? "").toUpperCase() === "CUSTOM");

  const findings: NewrelicFinding[] = [];

  findings.push(finding(
    1,
    !domainsReadable
      ? "manual"
      : authTypeVisible
        ? passwordDomains.length > 0 ? "fail" : ssoDomains.length > 0 ? "pass" : "warn"
        : "manual",
    !domainsReadable
      ? "Authentication domains were not readable. Collect a screenshot of Administration > Access Management > Authentication domains showing the Authentication method for every domain."
      : authTypeVisible
        ? passwordDomains.length > 0
          ? `${passwordDomains.length}/${domainAuthTypes.length} authentication domains still authenticate users with New Relic passwords instead of SAML or OIDC SSO.`
          : ssoDomains.length > 0
            ? `All ${domainAuthTypes.length} authentication domains authenticate through SSO (${ssoDomains.map((domain) => domain.authenticationType).join(", ")}).`
            : "Authentication domains exposed no password or SSO authentication type, so SSO enforcement is unclear."
        : `${domains.length} authentication domains were listed, but NerdGraph did not expose authenticationType (customerAdministration is limited to multi-tenant organizations). Collect the Authentication method shown in Administration > Access Management > Authentication domains for each domain and confirm it is SAML SSO or OIDC SSO with password login disabled.`,
    {
      authentication_domains: domainProvisioning,
      authentication_types: domainAuthTypes,
      password_domains: passwordDomains.map((domain) => domain.name),
      authentication_type_visible: authTypeVisible,
      manual_evidence: authTypeVisible ? undefined : "Administration > Access Management > Authentication domains > Authentication: SAML SSO or OIDC SSO for each domain.",
    },
  ));

  findings.push(finding(
    2,
    !usersReadable
      ? "manual"
      : inactiveFullPlatformUsers.length > 0
        ? "fail"
        : fullPlatformShare > maxFullPlatformPercent
          ? "warn"
          : "pass",
    !usersReadable
      ? "Users were not readable. Export Administration > Access Management > Users with the User type column and review full platform assignments manually."
      : inactiveFullPlatformUsers.length > 0
        ? `${inactiveFullPlatformUsers.length}/${fullPlatformUsers.length} full platform users have not been active in the last ${inactiveDays} days, indicating over-provisioned user types.`
        : fullPlatformShare > maxFullPlatformPercent
          ? `${fullPlatformShare}% of ${users.length} users hold the full platform user type, above the ${maxFullPlatformPercent}% review threshold.`
          : `${fullPlatformUsers.length}/${users.length} users hold the full platform user type and all of them were active within ${inactiveDays} days.`,
    {
      users: users.length,
      user_type_counts: userTypeCounts,
      full_platform_percent: fullPlatformShare,
      max_full_platform_percent: maxFullPlatformPercent,
      inactive_full_platform_users: sample(inactiveFullPlatformUsers.map(userLabel)),
    },
  ));

  findings.push(finding(
    3,
    !grantsReadable || !usersReadable
      ? "manual"
      : adminGroups.size === 0
        ? "warn"
        : adminUsers.length > maxAdmins
          ? "fail"
          : "pass",
    !grantsReadable || !usersReadable
      ? "Group role grants or users were not readable. Review Administration > Access Management > Groups and record which groups hold Organization manager, Authentication domain manager, or All product admin roles and their member counts."
      : adminGroups.size === 0
        ? `No groups matched the admin role pattern /${adminRolePattern.source}/ across ${groupGrants.length} groups, so admin concentration could not be measured.`
        : adminUsers.length > maxAdmins
          ? `${adminUsers.length} users are members of admin groups, above the threshold of ${maxAdmins}.`
          : `${adminUsers.length} users are members of admin groups, within the threshold of ${maxAdmins}.`,
    {
      admin_groups: sample(adminGroupNames),
      admin_users: adminUsers.length,
      admin_user_sample: sample(adminUsers.map(userLabel)),
      max_admins: maxAdmins,
      admin_role_pattern: adminRolePattern.source,
    },
  ));

  findings.push(finding(
    18,
    !domainsReadable
      ? "manual"
      : domains.length === 0
        ? "warn"
        : manualProvisioningDomains.length > 0
          ? "warn"
          : "pass",
    !domainsReadable
      ? "Authentication domains were not readable. Record provisioning method, session timeout, and user upgrade settings from Administration > Access Management > Authentication domains."
      : domains.length === 0
        ? "No authentication domains were visible to the API key."
        : manualProvisioningDomains.length > 0
          ? `${manualProvisioningDomains.length}/${domains.length} authentication domains provision users manually instead of through SCIM. Confirm session duration and user upgrade approval settings in the UI, which NerdGraph does not expose.`
          : `All ${domains.length} authentication domains provision users through SCIM (${scimDomains.map((domain) => domain.name).join(", ")}). Confirm session duration and user upgrade approval settings in the UI, which NerdGraph does not expose.`,
    {
      authentication_domains: domainProvisioning,
      manual_provisioning_domains: manualProvisioningDomains.map((domain) => domain.name),
      custom_roles_visible: customRoles.length,
      manual_evidence: "Administration > Access Management > Authentication domains: Session settings and User upgrade settings for each domain.",
    },
  ));

  findings.push(finding(
    19,
    !usersReadable
      ? "manual"
      : inactiveUsers.length > 0
        ? "fail"
        : neverActiveUsers.length > 0
          ? "warn"
          : "pass",
    !usersReadable
      ? `Users were not readable. Export the user list with the Last active column and flag anyone inactive for more than ${inactiveDays} days.`
      : inactiveUsers.length > 0
        ? `${inactiveUsers.length}/${users.length} users have not been active for more than ${inactiveDays} days.`
        : neverActiveUsers.length > 0
          ? `No users exceeded ${inactiveDays} days of inactivity, but ${neverActiveUsers.length} users have never recorded activity and should be reviewed.`
          : `All ${users.length} users were active within the last ${inactiveDays} days.`,
    {
      inactive_days: inactiveDays,
      inactive_users: inactiveUsers.length,
      inactive_user_sample: sample(inactiveUsers.map(userLabel)),
      never_active_users: sample(neverActiveUsers.map(userLabel)),
    },
  ));

  return {
    category: "identity",
    title: "New Relic identity posture",
    summary: {
      region: config.region,
      organization: asString(data.organization.data.name) ?? asString(data.organization.data.id) ?? null,
      authentication_domains: domains.length,
      sso_domains: ssoDomains.length,
      password_domains: passwordDomains.length,
      scim_domains: scimDomains.length,
      users: users.length,
      full_platform_users: fullPlatformUsers.length,
      admin_users: adminUsers.length,
      inactive_users: inactiveUsers.length,
      custom_roles: customRoles.length,
      collection_errors: collectedErrors(Object.values(data)).length,
    },
    findings,
    errors: collectedErrors(Object.values(data)),
    coreData: {
      "core_data/organization.json": data.organization.data,
      "core_data/authentication_domains.json": domains,
      "core_data/authentication_domain_settings.json": orgDomains,
      "core_data/users.json": users,
      "core_data/group_role_grants.json": groupGrants,
      "core_data/roles.json": roles,
    },
  };
}

export async function assessNewrelicIdentity(
  client: IdentityClient,
  options: NewrelicIdentityOptions = {},
): Promise<NewrelicAssessmentResult> {
  const data = await collectNewrelicIdentityData(client, options);
  return assessNewrelicIdentityData(data, client.getResolvedConfig(), options);
}

export interface NewrelicAccessControlData {
  accounts: Collected<JsonRecord[]>;
  accountIds: number[];
  authenticationDomains: Collected<JsonRecord[]>;
  users: Collected<JsonRecord[]>;
  groupGrants: Collected<JsonRecord[]>;
  roles: Collected<JsonRecord[]>;
  apiKeys: Collected<JsonRecord[]>;
  apiKeyAuditEvents: Collected<JsonRecord[]>;
  apiKeyChangeEvents: Collected<JsonRecord[]>;
  auditWindowDays: number;
}

async function runNrqlAcrossAccounts(
  client: Pick<NewrelicClientSurface, "runNrql">,
  accountIds: number[],
  nrql: string,
): Promise<JsonRecord[]> {
  const results: JsonRecord[] = [];
  for (const accountId of accountIds) {
    const rows = await client.runNrql(accountId, nrql);
    results.push(...rows.map((row) => ({ ...row, queriedAccountId: accountId })));
  }
  return results;
}

export async function collectNewrelicAccessControlData(
  client: AccessControlClient,
  options: { userLimit?: number } = {},
): Promise<NewrelicAccessControlData> {
  const config = client.getResolvedConfig();
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 50_000);
  const accountIds = await client.resolveAccountIds().catch(() => config.accountIds);
  const accounts = await collect("accounts", [] as JsonRecord[], () => client.listAccounts());
  const authenticationDomains = await collect("userManagement.authenticationDomains", [] as JsonRecord[], () => client.listAuthenticationDomains());
  const users = await collect("userManagement.users", [] as JsonRecord[], () => collectUsers(client, authenticationDomains.data, userLimit));
  const groupGrants = await collect("authorizationManagement.groups", [] as JsonRecord[], () => collectGroupGrants(client, authenticationDomains.data));
  const roles = await collect("authorizationManagement.roles", [] as JsonRecord[], () => client.listRoles());
  const apiKeys = await collect("apiAccess.keySearch", [] as JsonRecord[], () => client.listApiKeys(["USER", "INGEST"], accountIds.length > 0 ? accountIds : undefined));
  const window = config.auditWindowDays;
  const apiKeyAuditEvents = await collect(
    "nrql.NrAuditEvent.api_key_actor",
    [] as JsonRecord[],
    () => runNrqlAcrossAccounts(
      client,
      accountIds,
      `SELECT actorAPIKey, actorId, actorEmail, actionIdentifier, targetType, targetId, timestamp FROM NrAuditEvent WHERE actorType = 'api_key' SINCE ${window} days ago LIMIT MAX`,
    ),
  );
  const apiKeyChangeEvents = await collect(
    "nrql.NrAuditEvent.api_key_changes",
    [] as JsonRecord[],
    () => runNrqlAcrossAccounts(
      client,
      accountIds,
      `SELECT actionIdentifier, actorEmail, actorType, description, targetType, targetId, timestamp FROM NrAuditEvent WHERE actionIdentifier LIKE 'api_key%' SINCE ${window} days ago LIMIT MAX`,
    ),
  );
  return {
    accounts,
    accountIds,
    authenticationDomains,
    users,
    groupGrants,
    roles,
    apiKeys,
    apiKeyAuditEvents,
    apiKeyChangeEvents,
    auditWindowDays: window,
  };
}

function keyLabel(key: JsonRecord): string {
  return asString(key.name) ?? asString(key.id) ?? "key";
}

function keyAgeDays(key: JsonRecord, now: number): number | undefined {
  const timestamp = parseTimestamp(key.createdAt);
  return timestamp === undefined ? undefined : ageInDays(timestamp, now);
}

function accountLabel(account: JsonRecord): string {
  return asString(account.name) ?? asString(account.id) ?? "account";
}

interface UserAccountAccess {
  user: JsonRecord;
  accountIds: Set<number>;
  organizationScoped: boolean;
  admin: boolean;
}

function buildUserAccountAccess(
  users: JsonRecord[],
  groupGrants: JsonRecord[],
  adminRolePattern: RegExp,
): UserAccountAccess[] {
  const groupAccounts = new Map<string, { accountIds: Set<number>; organizationScoped: boolean; admin: boolean }>();
  for (const group of groupGrants) {
    const groupId = asString(group.id);
    if (!groupId) continue;
    const entry = { accountIds: new Set<number>(), organizationScoped: false, admin: false };
    for (const role of asRecords(group.roles)) {
      const accountId = asNumber(role.accountId);
      if (accountId !== undefined) entry.accountIds.add(accountId);
      if (asString(role.organizationId)) entry.organizationScoped = true;
      if (adminRolePattern.test(grantRoleName(role))) entry.admin = true;
    }
    groupAccounts.set(groupId, entry);
  }

  return users.map((user) => {
    const access: UserAccountAccess = { user, accountIds: new Set<number>(), organizationScoped: false, admin: false };
    for (const groupId of userGroupIds(user)) {
      const entry = groupAccounts.get(groupId);
      if (!entry) continue;
      for (const accountId of entry.accountIds) access.accountIds.add(accountId);
      if (entry.organizationScoped) access.organizationScoped = true;
      if (entry.admin) access.admin = true;
    }
    return access;
  });
}

export function assessNewrelicAccessControlData(
  data: NewrelicAccessControlData,
  config: Pick<NewrelicResolvedConfig, "region" | "accountIds">,
  options: NewrelicAccessControlOptions = {},
): NewrelicAssessmentResult {
  const now = options.now ?? Date.now();
  const inactiveDays = clampNumber(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650);
  const maxKeyAgeDays = clampNumber(options.maxKeyAgeDays, DEFAULT_MAX_KEY_AGE_DAYS, 1, 3650);
  const maxAccountsPerUser = clampNumber(options.maxAccountsPerUser, DEFAULT_MAX_ACCOUNTS_PER_USER, 1, 10_000);
  const adminRolePattern = compilePattern(options.adminRolePattern, DEFAULT_ADMIN_ROLE_PATTERN);
  const productionPattern = compilePattern(options.productionAccountPattern, DEFAULT_PRODUCTION_ACCOUNT_PATTERN);
  const nonproductionPattern = compilePattern(options.nonproductionAccountPattern, DEFAULT_NONPRODUCTION_ACCOUNT_PATTERN);

  const accounts = data.accounts.data;
  const users = data.users.data;
  const groupGrants = data.groupGrants.data;
  const roles = data.roles.data;
  const keys = data.apiKeys.data;
  const keysReadable = !data.apiKeys.error;
  const usersReadable = !data.users.error;
  const grantsReadable = !data.groupGrants.error;
  const auditReadable = !data.apiKeyAuditEvents.error;

  const userKeys = keys.filter((key) => (asString(key.type) ?? "").toUpperCase() === "USER");
  const ingestKeys = keys.filter((key) => (asString(key.type) ?? "").toUpperCase() === "INGEST");
  const licenseKeys = ingestKeys.filter((key) => (asString(key.ingestType) ?? "").toUpperCase() === "LICENSE");
  const browserKeys = ingestKeys.filter((key) => (asString(key.ingestType) ?? "").toUpperCase() === "BROWSER");
  const unnamedKeys = keys.filter((key) => !asString(key.name));

  const userById = new Map<string, JsonRecord>();
  for (const user of users) {
    const id = asString(user.id);
    if (id) userById.set(id, user);
  }
  const access = buildUserAccountAccess(users, groupGrants, adminRolePattern);
  const adminUserIds = new Set(access.filter((entry) => entry.admin).map((entry) => asString(entry.user.id) ?? ""));
  const adminOwnedUserKeys = userKeys.filter((key) => adminUserIds.has(asString(key.userId) ?? ""));

  const agedUserKeys = userKeys.filter((key) => {
    const age = keyAgeDays(key, now);
    return age !== undefined && age > maxKeyAgeDays;
  });
  const agedLicenseKeys = licenseKeys.filter((key) => {
    const age = keyAgeDays(key, now);
    return age !== undefined && age > maxKeyAgeDays;
  });
  const keysWithoutCreatedAt = keys.filter((key) => keyAgeDays(key, now) === undefined);

  const orphanedUserKeys = usersReadable ? userKeys.filter((key) => {
    const ownerId = asString(key.userId);
    return Boolean(ownerId) && !userById.has(ownerId ?? "");
  }) : [];
  const inactiveOwnerKeys = usersReadable ? userKeys.filter((key) => {
    const owner = userById.get(asString(key.userId) ?? "");
    if (!owner) return false;
    const age = lastActiveAgeDays(owner, now);
    return age !== undefined && age > inactiveDays;
  }) : [];
  const distinctActorKeys = new Set(
    data.apiKeyAuditEvents.data.map((event) => asString(event.actorAPIKey)).filter((value): value is string => Boolean(value)),
  );

  const broadAccessUsers = access.filter((entry) => !entry.admin && (entry.organizationScoped || entry.accountIds.size > maxAccountsPerUser));
  const usersWithoutGrants = access.filter((entry) => entry.accountIds.size === 0 && !entry.organizationScoped);

  const productionAccounts = accounts.filter((account) => productionPattern.test(accountLabel(account)) && !nonproductionPattern.test(accountLabel(account)));
  const nonproductionAccounts = accounts.filter((account) => nonproductionPattern.test(accountLabel(account)));
  const productionIds = new Set(productionAccounts.map((account) => asNumber(account.id)).filter((id): id is number => id !== undefined));
  const nonproductionIds = new Set(nonproductionAccounts.map((account) => asNumber(account.id)).filter((id): id is number => id !== undefined));
  const classifiable = productionIds.size > 0 && nonproductionIds.size > 0;
  const crossEnvironmentUsers = classifiable
    ? access.filter((entry) => {
      if (entry.admin) return false;
      const ids = [...entry.accountIds];
      const touchesProduction = entry.organizationScoped || ids.some((id) => productionIds.has(id));
      const touchesNonproduction = entry.organizationScoped || ids.some((id) => nonproductionIds.has(id));
      return touchesProduction && touchesNonproduction;
    })
    : [];

  const customRoles = roles.filter((role) => (asString(role.type) ?? "").toUpperCase() === "CUSTOM");
  const customRoleGrants = groupGrants.filter((group) =>
    asRecords(group.roles).some((role) => (asString(role.type) ?? "").toUpperCase() === "CUSTOM"),
  );

  const findings: NewrelicFinding[] = [];

  findings.push(finding(
    4,
    !keysReadable
      ? "manual"
      : unnamedKeys.length > 0 || adminOwnedUserKeys.length > 0
        ? "warn"
        : "pass",
    !keysReadable
      ? "API keys were not readable through apiAccess.keySearch. Export the API keys UI list (all key types) for every account and record owners and purposes manually."
      : unnamedKeys.length > 0 || adminOwnedUserKeys.length > 0
        ? `${keys.length} keys inventoried (${userKeys.length} user, ${licenseKeys.length} license, ${browserKeys.length} browser); ${unnamedKeys.length} lack a name and ${adminOwnedUserKeys.length} user keys inherit admin-level permissions from their owners.`
        : `${keys.length} keys inventoried (${userKeys.length} user, ${licenseKeys.length} license, ${browserKeys.length} browser) with names and no user keys owned by admin group members.`,
    {
      keys_total: keys.length,
      user_keys: userKeys.length,
      license_keys: licenseKeys.length,
      browser_keys: browserKeys.length,
      unnamed_keys: sample(unnamedKeys.map(keyLabel)),
      admin_owned_user_keys: sample(adminOwnedUserKeys.map(keyLabel)),
      audit_events_by_api_keys: data.apiKeyAuditEvents.data.length,
    },
  ));

  findings.push(finding(
    5,
    !keysReadable
      ? "manual"
      : agedUserKeys.length > 0
        ? "fail"
        : userKeys.length > 0 && keysWithoutCreatedAt.length === keys.length
          ? "manual"
          : agedLicenseKeys.length > 0
            ? "warn"
            : "pass",
    !keysReadable
      ? `API keys were not readable. Review the Created column in the API keys UI and flag user keys older than ${maxKeyAgeDays} days.`
      : agedUserKeys.length > 0
        ? `${agedUserKeys.length}/${userKeys.length} user keys are older than ${maxKeyAgeDays} days without rotation.`
        : userKeys.length > 0 && keysWithoutCreatedAt.length === keys.length
          ? `createdAt was not exposed for any of the ${keys.length} keys. Review key creation dates in the API keys UI manually.`
          : agedLicenseKeys.length > 0
            ? `No user keys exceed ${maxKeyAgeDays} days, but ${agedLicenseKeys.length} license keys are older than that threshold and should have a rotation plan.`
            : `All ${userKeys.length} user keys were created within the last ${maxKeyAgeDays} days.`,
    {
      max_key_age_days: maxKeyAgeDays,
      aged_user_keys: sample(agedUserKeys.map((key) => `${keyLabel(key)} (${keyAgeDays(key, now)} days)`)),
      aged_license_keys: sample(agedLicenseKeys.map((key) => `${keyLabel(key)} (${keyAgeDays(key, now)} days)`)),
      keys_without_created_at: keysWithoutCreatedAt.length,
    },
  ));

  findings.push(finding(
    6,
    !keysReadable
      ? "manual"
      : keys.length === 0
        ? "pass"
        : orphanedUserKeys.length > 0 || inactiveOwnerKeys.length > 0
          ? "warn"
          : "manual",
    !keysReadable
      ? "API keys were not readable, so unused key detection is not possible. Review key usage with the API keys UI and NrAuditEvent queries manually."
      : keys.length === 0
        ? "No API keys are present, so there are no unused keys to review."
        : orphanedUserKeys.length > 0 || inactiveOwnerKeys.length > 0
          ? `${orphanedUserKeys.length} user keys belong to users no longer visible and ${inactiveOwnerKeys.length} belong to users inactive for more than ${inactiveDays} days; ${distinctActorKeys.size} distinct API keys performed configuration changes in the last ${data.auditWindowDays} days.`
          : `${distinctActorKeys.size} distinct API keys performed configuration changes in the last ${data.auditWindowDays} days. NrAuditEvent only records configuration changes, so read-only key usage cannot be confirmed through the API; review the remaining ${keys.length} keys with their owners and revoke any without a documented consumer.`,
    {
      keys_total: keys.length,
      distinct_api_keys_in_audit: distinctActorKeys.size,
      audit_window_days: data.auditWindowDays,
      audit_readable: auditReadable,
      orphaned_user_keys: sample(orphanedUserKeys.map(keyLabel)),
      inactive_owner_user_keys: sample(inactiveOwnerKeys.map(keyLabel)),
      manual_evidence: "API keys UI export plus owner confirmation for every key without a documented consumer; NrAuditEvent WHERE actorType = 'api_key' for change activity.",
    },
  ));

  findings.push(finding(
    7,
    !grantsReadable || !usersReadable
      ? "manual"
      : broadAccessUsers.length > 0
        ? "warn"
        : "pass",
    !grantsReadable || !usersReadable
      ? "Group grants or users were not readable. Review Administration > Access Management > Groups and record the accounts each group can access."
      : broadAccessUsers.length > 0
        ? `${broadAccessUsers.length}/${users.length} non-admin users hold organization-scoped grants or access to more than ${maxAccountsPerUser} accounts.`
        : `No non-admin users exceed ${maxAccountsPerUser} accounts or hold organization-scoped grants across ${accounts.length} accounts.`,
    {
      accounts_visible: accounts.length,
      max_accounts_per_user: maxAccountsPerUser,
      broad_access_users: sample(broadAccessUsers.map((entry) => `${userLabel(entry.user)} (${entry.organizationScoped ? "organization scope" : `${entry.accountIds.size} accounts`})`)),
      users_without_grants: usersWithoutGrants.length,
    },
  ));

  findings.push(finding(
    8,
    !grantsReadable || !usersReadable
      ? "manual"
      : accounts.length <= 1
        ? "pass"
        : !classifiable
          ? "manual"
          : crossEnvironmentUsers.length > 0
            ? "warn"
            : "pass",
    !grantsReadable || !usersReadable
      ? "Group grants or users were not readable. Map each group's account access in the UI and flag users who reach both production and non-production accounts."
      : accounts.length <= 1
        ? "Only one account is visible, so production and non-production separation does not apply."
        : !classifiable
          ? `Account names did not match both the production pattern /${productionPattern.source}/ and the non-production pattern /${nonproductionPattern.source}/. Classify the ${accounts.length} accounts manually or pass production_account_pattern and nonproduction_account_pattern.`
          : crossEnvironmentUsers.length > 0
            ? `${crossEnvironmentUsers.length} non-admin users can reach both production (${productionAccounts.length}) and non-production (${nonproductionAccounts.length}) accounts.`
            : `No non-admin users hold access to both production (${productionAccounts.length}) and non-production (${nonproductionAccounts.length}) accounts.`,
    {
      production_accounts: sample(productionAccounts.map(accountLabel)),
      nonproduction_accounts: sample(nonproductionAccounts.map(accountLabel)),
      cross_environment_users: sample(crossEnvironmentUsers.map((entry) => userLabel(entry.user))),
      admin_users_excluded: adminUserIds.size,
      manual_evidence: classifiable ? undefined : "Account inventory with environment classification from Administration > Access Management > Accounts.",
    },
  ));

  findings.push(finding(
    20,
    data.roles.error
      ? "manual"
      : customRoles.length === 0
        ? "pass"
        : "manual",
    data.roles.error
      ? "Roles were not readable. Review Administration > Access Management > Roles and record every custom role's capabilities."
      : customRoles.length === 0
        ? `No custom roles exist; only ${roles.length} standard roles are in use.`
        : `${customRoles.length} custom roles exist (${sample(customRoles.map((role) => asString(role.displayName) ?? asString(role.name) ?? asString(role.id) ?? "role"), 10).join(", ")}). NerdGraph does not expose role capabilities, so open each role in Administration > Access Management > Roles and confirm no unnecessary manage or delete capabilities are granted.`,
    {
      roles_total: roles.length,
      custom_roles: sample(customRoles.map((role) => ({
        id: asString(role.id),
        name: asString(role.displayName) ?? asString(role.name),
        scope: asString(role.scope),
      }))),
      groups_granted_custom_roles: sample(customRoleGrants.map((group) => asString(group.displayName) ?? asString(group.id) ?? "group")),
      manual_evidence: "Capability list for each custom role from Administration > Access Management > Roles.",
    },
  ));

  const allCollected = [
    data.accounts,
    data.authenticationDomains,
    data.users,
    data.groupGrants,
    data.roles,
    data.apiKeys,
    data.apiKeyAuditEvents,
    data.apiKeyChangeEvents,
  ];

  return {
    category: "access_control",
    title: "New Relic access control and API key hygiene",
    summary: {
      region: config.region,
      accounts_in_scope: data.accountIds,
      accounts_visible: accounts.length,
      users: users.length,
      keys_total: keys.length,
      user_keys: userKeys.length,
      aged_user_keys: agedUserKeys.length,
      admin_users: adminUserIds.size,
      broad_access_users: broadAccessUsers.length,
      cross_environment_users: crossEnvironmentUsers.length,
      custom_roles: customRoles.length,
      api_key_audit_events: data.apiKeyAuditEvents.data.length,
      collection_errors: collectedErrors(allCollected).length,
    },
    findings,
    errors: collectedErrors(allCollected),
    coreData: {
      "core_data/accounts.json": accounts,
      "core_data/api_keys.json": keys,
      "core_data/audit_api_key_actor_events.json": data.apiKeyAuditEvents.data,
      "core_data/audit_api_key_change_events.json": data.apiKeyChangeEvents.data,
      "core_data/users.json": users,
      "core_data/group_role_grants.json": groupGrants,
      "core_data/roles.json": roles,
    },
  };
}

export async function assessNewrelicAccessControl(
  client: AccessControlClient,
  options: NewrelicAccessControlOptions = {},
): Promise<NewrelicAssessmentResult> {
  const data = await collectNewrelicAccessControlData(client, options);
  return assessNewrelicAccessControlData(data, client.getResolvedConfig(), options);
}

export interface NewrelicAlertingData {
  accountIds: number[];
  currentUser: Collected<JsonRecord>;
  policies: Collected<JsonRecord[]>;
  conditions: Collected<JsonRecord[]>;
  destinations: Collected<JsonRecord[]>;
  channels: Collected<JsonRecord[]>;
  workflows: Collected<JsonRecord[]>;
  alertableEntities: Collected<JsonRecord[]>;
  workloads: Collected<JsonRecord[]>;
}

async function collectPerAccount(
  accountIds: number[],
  load: (accountId: number) => Promise<JsonRecord[]>,
): Promise<JsonRecord[]> {
  const items: JsonRecord[] = [];
  for (const accountId of accountIds) {
    const rows = await load(accountId);
    items.push(...rows.map((row) => ({ ...row, queriedAccountId: accountId })));
  }
  return items;
}

export async function collectNewrelicAlertingData(
  client: AlertingClient,
  options: { entityLimit?: number } = {},
): Promise<NewrelicAlertingData> {
  const config = client.getResolvedConfig();
  const entityLimit = clampNumber(options.entityLimit, DEFAULT_ENTITY_LIMIT, 1, 20_000);
  const accountIds = await client.resolveAccountIds().catch(() => config.accountIds);
  const currentUser = await collect("actor.user", {} as JsonRecord, () => client.getCurrentUser());
  const policies = await collect("alerts.policiesSearch", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listAlertPolicies(id)));
  const conditions = await collect("alerts.nrqlConditionsSearch", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listNrqlConditions(id)));
  const destinations = await collect("aiNotifications.destinations", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listNotificationDestinations(id)));
  const channels = await collect("aiNotifications.channels", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listNotificationChannels(id)));
  const workflows = await collect("aiWorkflows.workflows", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listWorkflows(id)));
  const alertableEntities = await collect(
    "entitySearch.alertable",
    [] as JsonRecord[],
    () => collectPerAccount(accountIds, (id) => client.searchEntities(`alertSeverity IS NOT NULL AND accountId = ${id}`, entityLimit)),
  );
  const workloads = await collect(
    "entitySearch.workloads",
    [] as JsonRecord[],
    () => collectPerAccount(accountIds, (id) => client.searchEntities(`type = 'WORKLOAD' AND accountId = ${id}`, entityLimit)),
  );
  return { accountIds, currentUser, policies, conditions, destinations, channels, workflows, alertableEntities, workloads };
}

function entityLabel(entity: JsonRecord): string {
  return `${asString(entity.name) ?? asString(entity.guid) ?? "entity"} (${asString(entity.entityType) ?? asString(entity.type) ?? "unknown"})`;
}

function entityDomainType(entity: JsonRecord): string {
  return `${asString(entity.domain) ?? "UNKNOWN"}-${asString(entity.type) ?? "UNKNOWN"}`;
}

function isReporting(entity: JsonRecord): boolean {
  return asBoolean(entity.reporting) !== false;
}

function destinationEmails(destination: JsonRecord): string[] {
  return asRecords(destination.properties)
    .filter((property) => (asString(property.key) ?? "").toLowerCase() === "email")
    .flatMap((property) => parseListArgument(property.value));
}

export function assessNewrelicAlertingData(
  data: NewrelicAlertingData,
  config: Pick<NewrelicResolvedConfig, "region" | "accountIds">,
  options: NewrelicAlertingOptions = {},
): NewrelicAssessmentResult {
  const policies = data.policies.data;
  const conditions = data.conditions.data;
  const destinations = data.destinations.data;
  const channels = data.channels.data;
  const workflows = data.workflows.data;
  const entities = data.alertableEntities.data;
  const workloads = data.workloads.data;

  const policiesReadable = !data.policies.error;
  const entitiesReadable = !data.alertableEntities.error;
  const destinationsReadable = !data.destinations.error;
  const workflowsReadable = !data.workflows.error;

  const reportingEntities = entities.filter(isReporting);
  const uncoveredEntities = reportingEntities.filter((entity) => (asString(entity.alertSeverity) ?? "").toUpperCase() === "NOT_CONFIGURED");
  const uncoveredCritical = uncoveredEntities.filter((entity) => CRITICAL_ENTITY_TYPES.has(entityDomainType(entity)));
  const enabledConditions = conditions.filter((condition) => asBoolean(condition.enabled) !== false);
  const policyIdsWithConditions = new Set(enabledConditions.map((condition) => asString(condition.policyId)).filter(Boolean));
  const emptyPolicies = policies.filter((policy) => !policyIdsWithConditions.has(asString(policy.id) ?? ""));
  const disruptedWorkloads = workloads.filter((workload) =>
    (asString(asObject(workload.workloadStatus)?.statusValue) ?? "").toUpperCase() === "DISRUPTED",
  );

  const approvedDomains = new Set(
    (options.approvedEmailDomains ?? []).map((domain) => domain.trim().toLowerCase().replace(/^@/, "")).filter(Boolean),
  );
  const derivedDomain = emailDomain(asString(data.currentUser.data.email));
  if (approvedDomains.size === 0 && derivedDomain) approvedDomains.add(derivedDomain);

  const emailDestinations = destinations.filter((destination) => (asString(destination.type) ?? "").toUpperCase() === "EMAIL");
  const personalEmailDestinations = emailDestinations.filter((destination) =>
    destinationEmails(destination).some((email) => PERSONAL_EMAIL_DOMAINS.has(emailDomain(email) ?? "")),
  );
  const unapprovedEmailDestinations = emailDestinations.filter((destination) =>
    destinationEmails(destination).some((email) => {
      const domain = emailDomain(email);
      return domain !== undefined && !PERSONAL_EMAIL_DOMAINS.has(domain) && approvedDomains.size > 0 && !approvedDomains.has(domain);
    }),
  );
  const inactiveDestinations = destinations.filter((destination) => asBoolean(destination.active) === false);
  const enabledWorkflows = workflows.filter((workflow) => asBoolean(workflow.workflowEnabled) !== false);
  const destinationTypeCounts: Record<string, number> = {};
  for (const destination of destinations) {
    const type = asString(destination.type) ?? "UNKNOWN";
    destinationTypeCounts[type] = (destinationTypeCounts[type] ?? 0) + 1;
  }

  const destinationById = new Map<string, JsonRecord>();
  for (const destination of destinations) {
    const id = asString(destination.id);
    if (id) destinationById.set(id, destination);
  }
  const channelById = new Map<string, JsonRecord>();
  for (const channel of channels) {
    const id = asString(channel.id);
    if (id) channelById.set(id, channel);
  }
  const enrichedWorkflows = enabledWorkflows.filter((workflow) => asRecords(workflow.enrichments).length > 0 && asBoolean(workflow.enrichmentsEnabled) !== false);
  const enrichedExternalWorkflows = enrichedWorkflows.filter((workflow) =>
    asRecords(workflow.destinationConfigurations).some((configuration) => {
      const channel = channelById.get(asString(configuration.channelId) ?? "");
      const destination = destinationById.get(asString(channel?.destinationId) ?? "");
      const type = (asString(configuration.type) ?? asString(channel?.type) ?? asString(destination?.type) ?? "").toUpperCase();
      return EXTERNAL_DESTINATION_TYPES.has(type);
    }),
  );
  const enrichmentQueries = enrichedWorkflows.flatMap((workflow) =>
    asRecords(workflow.enrichments).flatMap((enrichment) =>
      asRecords(enrichment.configurations).map((configuration) => asString(configuration.query)).filter((query): query is string => Boolean(query)),
    ),
  );

  const findings: NewrelicFinding[] = [];

  findings.push(finding(
    9,
    !policiesReadable && !entitiesReadable
      ? "manual"
      : policies.length === 0
        ? "fail"
        : uncoveredCritical.length > 0
          ? "fail"
          : uncoveredEntities.length > 0 || emptyPolicies.length > 0
            ? "warn"
            : "pass",
    !policiesReadable && !entitiesReadable
      ? "Alert policies and alertable entities were not readable. Review Alerts > Alert policies and the entity explorer alert status column manually."
      : policies.length === 0
        ? `No alert policies exist across ${data.accountIds.length} accounts while ${reportingEntities.length} reporting entities are monitored.`
        : uncoveredCritical.length > 0
          ? `${uncoveredCritical.length} reporting APM applications, infrastructure hosts, or synthetic monitors have no alert conditions targeting them (${uncoveredEntities.length}/${reportingEntities.length} alertable entities uncovered).`
          : uncoveredEntities.length > 0 || emptyPolicies.length > 0
            ? `${uncoveredEntities.length}/${reportingEntities.length} reporting alertable entities have no alert conditions and ${emptyPolicies.length}/${policies.length} policies have no enabled NRQL conditions.`
            : `${policies.length} policies with ${enabledConditions.length} enabled NRQL conditions cover all ${reportingEntities.length} reporting alertable entities.`,
    {
      policies: policies.length,
      enabled_conditions: enabledConditions.length,
      empty_policies: sample(emptyPolicies.map((policy) => asString(policy.name) ?? asString(policy.id) ?? "policy")),
      reporting_alertable_entities: reportingEntities.length,
      uncovered_entities: uncoveredEntities.length,
      uncovered_critical_entities: sample(uncoveredCritical.map(entityLabel)),
      workloads: workloads.length,
      disrupted_workloads: sample(disruptedWorkloads.map((workload) => asString(workload.name) ?? "workload")),
    },
  ));

  findings.push(finding(
    10,
    !destinationsReadable
      ? "manual"
      : personalEmailDestinations.length > 0
        ? "fail"
        : unapprovedEmailDestinations.length > 0 || (policies.length > 0 && enabledWorkflows.length === 0) || inactiveDestinations.length > 0
          ? "warn"
          : "pass",
    !destinationsReadable
      ? "Notification destinations were not readable. Review Alerts > Destinations and confirm every email destination uses a corporate address."
      : personalEmailDestinations.length > 0
        ? `${personalEmailDestinations.length} email destinations route alerts to personal email providers.`
        : unapprovedEmailDestinations.length > 0
          ? `${unapprovedEmailDestinations.length} email destinations use domains outside the approved set (${[...approvedDomains].join(", ")}).`
          : policies.length > 0 && enabledWorkflows.length === 0
            ? `${policies.length} alert policies exist but no enabled workflows route issues to destinations.`
            : inactiveDestinations.length > 0
              ? `${inactiveDestinations.length}/${destinations.length} destinations are inactive; the rest route to approved destinations.`
              : `${destinations.length} destinations across ${Object.keys(destinationTypeCounts).length} types route ${enabledWorkflows.length} enabled workflows without personal email addresses.`,
    {
      destinations: destinations.length,
      destination_types: destinationTypeCounts,
      channels: channels.length,
      enabled_workflows: enabledWorkflows.length,
      approved_email_domains: [...approvedDomains],
      personal_email_destinations: sample(personalEmailDestinations.map((destination) => asString(destination.name) ?? "destination")),
      unapproved_email_destinations: sample(unapprovedEmailDestinations.map((destination) => asString(destination.name) ?? "destination")),
      inactive_destinations: sample(inactiveDestinations.map((destination) => asString(destination.name) ?? "destination")),
    },
  ));

  findings.push(finding(
    17,
    !workflowsReadable
      ? "manual"
      : enrichedExternalWorkflows.length > 0
        ? "warn"
        : "manual",
    !workflowsReadable
      ? "Workflows were not readable. Review Alerts > Workflows for NRQL enrichments and Alerts > Correlation decisions for correlation settings that could expose sensitive attributes."
      : enrichedExternalWorkflows.length > 0
        ? `${enrichedExternalWorkflows.length} enabled workflows attach NRQL enrichment results to notifications sent to external destinations, so query output leaves the platform with each notification. Review the ${enrichmentQueries.length} enrichment queries and confirm they exclude sensitive attributes.`
        : `${enrichedWorkflows.length} enabled workflows use NRQL enrichments and none route to external destination types. Correlation decision settings are not exposed by NerdGraph: record Alerts > Correlation decisions and confirm custom decisions do not correlate on sensitive attributes.`,
    {
      workflows: workflows.length,
      enabled_workflows: enabledWorkflows.length,
      enriched_workflows: sample(enrichedWorkflows.map((workflow) => asString(workflow.name) ?? "workflow")),
      enriched_external_workflows: sample(enrichedExternalWorkflows.map((workflow) => asString(workflow.name) ?? "workflow")),
      enrichment_queries: sample(enrichmentQueries, 10),
      manual_evidence: "Alerts > Correlation decisions: list of enabled decisions and the attributes they correlate on.",
    },
  ));

  const allCollected = [
    data.currentUser,
    data.policies,
    data.conditions,
    data.destinations,
    data.channels,
    data.workflows,
    data.alertableEntities,
    data.workloads,
  ];

  return {
    category: "alerting",
    title: "New Relic alerting and notification posture",
    summary: {
      region: config.region,
      accounts_in_scope: data.accountIds,
      policies: policies.length,
      enabled_conditions: enabledConditions.length,
      reporting_alertable_entities: reportingEntities.length,
      uncovered_entities: uncoveredEntities.length,
      destinations: destinations.length,
      personal_email_destinations: personalEmailDestinations.length,
      enabled_workflows: enabledWorkflows.length,
      enriched_external_workflows: enrichedExternalWorkflows.length,
      workloads: workloads.length,
      collection_errors: collectedErrors(allCollected).length,
    },
    findings,
    errors: collectedErrors(allCollected),
    coreData: {
      "core_data/alert_policies.json": policies,
      "core_data/alert_nrql_conditions.json": conditions,
      "core_data/notification_destinations.json": destinations,
      "core_data/notification_channels.json": channels,
      "core_data/workflows.json": workflows,
      "core_data/alertable_entities.json": entities,
      "core_data/workloads.json": workloads,
    },
  };
}

export async function assessNewrelicAlerting(
  client: AlertingClient,
  options: NewrelicAlertingOptions & { entityLimit?: number } = {},
): Promise<NewrelicAssessmentResult> {
  const data = await collectNewrelicAlertingData(client, options);
  return assessNewrelicAlertingData(data, client.getResolvedConfig(), options);
}

export interface NewrelicDataGovernanceData {
  accountIds: number[];
  retentionRules: Collected<JsonRecord[]>;
  retentionNamespaces: Collected<JsonRecord[]>;
  obfuscationRules: Collected<JsonRecord[]>;
  obfuscationExpressions: Collected<JsonRecord[]>;
  cloudRules: Collected<JsonRecord[]>;
  dropRules: Collected<JsonRecord[]>;
  dashboards: Collected<JsonRecord[]>;
  dashboardLiveUrls: Collected<JsonRecord[]>;
  syntheticMonitors: Collected<JsonRecord[]>;
  secureCredentials: Collected<JsonRecord[]>;
  syntheticScripts: Collected<JsonRecord[]>;
  logVolume: Collected<JsonRecord[]>;
  logSecretMatches: Collected<JsonRecord[]>;
  infraHosts: Collected<JsonRecord[]>;
  infraAgentVersions: Collected<JsonRecord[]>;
}

function scanScriptForSecrets(text: string): string[] {
  return SECRET_PATTERNS.filter((entry) => entry.pattern.test(text)).map((entry) => entry.label);
}

async function collectSyntheticScripts(
  client: Pick<NewrelicClientSurface, "getSyntheticScript">,
  monitors: JsonRecord[],
  limit: number,
): Promise<JsonRecord[]> {
  const scripted = monitors.filter((monitor) => SCRIPTED_MONITOR_TYPES.has((asString(monitor.monitorType) ?? "").toUpperCase())).slice(0, limit);
  const snapshots: JsonRecord[] = [];
  for (const monitor of scripted) {
    const guid = asString(monitor.guid);
    const accountId = asNumber(monitor.accountId) ?? asNumber(monitor.queriedAccountId);
    if (!guid || accountId === undefined) continue;
    const text = await client.getSyntheticScript(accountId, guid);
    snapshots.push({
      guid,
      name: asString(monitor.name),
      accountId,
      monitorType: asString(monitor.monitorType),
      scriptLength: text.length,
      usesSecureCredentials: /\$secure\./.test(text),
      secretIndicators: scanScriptForSecrets(text),
    });
  }
  return snapshots;
}

export async function collectNewrelicDataGovernanceData(
  client: DataGovernanceClient,
  options: { entityLimit?: number; scriptSampleLimit?: number } = {},
): Promise<NewrelicDataGovernanceData> {
  const config = client.getResolvedConfig();
  const entityLimit = clampNumber(options.entityLimit, DEFAULT_ENTITY_LIMIT, 1, 20_000);
  const scriptSampleLimit = clampNumber(options.scriptSampleLimit, DEFAULT_SCRIPT_SAMPLE_LIMIT, 0, 500);
  const accountIds = await client.resolveAccountIds().catch(() => config.accountIds);

  const retentionRules = await collect("dataManagement.eventRetentionRules", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listEventRetentionRules(id)));
  const retentionNamespaces = await collect("dataManagement.customizableRetention", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listRetentionNamespaces(id)));
  const obfuscationRules = await collect("logConfigurations.obfuscationRules", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listObfuscationRules(id)));
  const obfuscationExpressions = await collect("logConfigurations.obfuscationExpressions", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listObfuscationExpressions(id)));
  const cloudRules = await collect("entityManagement.pipelineCloudRules", [] as JsonRecord[], () => client.listPipelineCloudRules());
  const dropRules = await collect("nrqlDropRules.list", [] as JsonRecord[], () => collectPerAccount(accountIds, (id) => client.listNrqlDropRules(id)));
  const dashboards = await collect(
    "entitySearch.dashboards",
    [] as JsonRecord[],
    () => collectPerAccount(accountIds, (id) => client.searchEntities(`type = 'DASHBOARD' AND accountId = ${id}`, entityLimit)),
  );
  const dashboardLiveUrls = await collect("dashboard.liveUrls", [] as JsonRecord[], () => client.listDashboardLiveUrls());
  const syntheticMonitors = await collect(
    "entitySearch.syntheticMonitors",
    [] as JsonRecord[],
    () => collectPerAccount(accountIds, (id) => client.searchEntities(`domain = 'SYNTH' AND type = 'MONITOR' AND accountId = ${id}`, entityLimit)),
  );
  const secureCredentials = await collect(
    "entitySearch.secureCredentials",
    [] as JsonRecord[],
    () => collectPerAccount(accountIds, (id) => client.searchEntities(`domain = 'SYNTH' AND type = 'SECURE_CRED' AND accountId = ${id}`, entityLimit)),
  );
  const syntheticScripts = await collect("synthetics.script", [] as JsonRecord[], () => collectSyntheticScripts(client, syntheticMonitors.data, scriptSampleLimit));
  const logVolume = await collect(
    "nrql.Log.volume",
    [] as JsonRecord[],
    () => runNrqlAcrossAccounts(client, accountIds, "SELECT count(*) AS logCount FROM Log SINCE 1 day ago"),
  );
  const logSecretMatches = await collect(
    "nrql.Log.secret_patterns",
    [] as JsonRecord[],
    () => runNrqlAcrossAccounts(client, accountIds, `SELECT count(*) AS matchCount FROM Log WHERE message RLIKE r'${LOG_SECRET_NRQL_PATTERN}' SINCE 1 day ago`),
  );
  const infraHosts = await collect(
    "entitySearch.infraHosts",
    [] as JsonRecord[],
    async () => {
      const rows: JsonRecord[] = [];
      for (const accountId of accountIds) {
        const count = await client.countEntities(`domain = 'INFRA' AND type = 'HOST' AND reporting = 'true' AND accountId = ${accountId}`);
        rows.push({ queriedAccountId: accountId, reportingHosts: count });
      }
      return rows;
    },
  );
  const infraAgentVersions = await collect(
    "nrql.SystemSample.agentVersion",
    [] as JsonRecord[],
    () => runNrqlAcrossAccounts(client, accountIds, "SELECT uniqueCount(entityGuid) AS hosts FROM SystemSample FACET agentVersion SINCE 1 day ago LIMIT 50"),
  );

  return {
    accountIds,
    retentionRules,
    retentionNamespaces,
    obfuscationRules,
    obfuscationExpressions,
    cloudRules,
    dropRules,
    dashboards,
    dashboardLiveUrls,
    syntheticMonitors,
    secureCredentials,
    syntheticScripts,
    logVolume,
    logSecretMatches,
    infraHosts,
    infraAgentVersions,
  };
}

function sumField(rows: JsonRecord[], field: string): number {
  return rows.reduce((total, row) => total + (asNumber(row[field]) ?? 0), 0);
}

export function assessNewrelicDataGovernanceData(
  data: NewrelicDataGovernanceData,
  config: Pick<NewrelicResolvedConfig, "region" | "accountIds">,
  options: NewrelicDataGovernanceOptions = {},
): NewrelicAssessmentResult {
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 1, 3650);

  const retentionRules = data.retentionRules.data.filter((rule) => !asString(rule.deletedAt));
  const obfuscationRules = data.obfuscationRules.data;
  const obfuscationExpressions = data.obfuscationExpressions.data;
  const cloudRules = data.cloudRules.data;
  const dropRules = data.dropRules.data;
  const dashboards = data.dashboards.data;
  const liveUrls = data.dashboardLiveUrls.data;
  const monitors = data.syntheticMonitors.data;
  const secureCredentials = data.secureCredentials.data;
  const scripts = data.syntheticScripts.data;

  const shortRetentionRules = retentionRules.filter((rule) => (asNumber(rule.retentionInDays) ?? Number.POSITIVE_INFINITY) < minRetentionDays);
  const enabledObfuscationRules = obfuscationRules.filter((rule) => asBoolean(rule.enabled) !== false);
  const expressionText = [
    ...obfuscationExpressions.map((expression) => `${asString(expression.name) ?? ""} ${asString(expression.regex) ?? ""} ${asString(expression.description) ?? ""}`),
    ...obfuscationRules.map((rule) => `${asString(rule.name) ?? ""} ${asString(rule.description) ?? ""}`),
  ].join("\n");
  const credentialCoverage = /password|passwd|secret|token|api[_-]?key|credential|bearer|authorization/i.test(expressionText);
  const piiCoverage = /ssn|social|credit|card|email|phone|pii|personal|name|address/i.test(expressionText);
  const attributeDropRules = [
    ...cloudRules.filter((rule) => /^\s*DELETE\s+(?!FROM\b)/i.test(asString(rule.nrql) ?? "")),
    ...dropRules.filter((rule) => (asString(rule.action) ?? "").toUpperCase() === "DROP_ATTRIBUTES"),
  ];
  const logCount = sumField(data.logVolume.data, "logCount");
  const secretMatchCount = sumField(data.logSecretMatches.data, "matchCount");

  const scriptedMonitors = monitors.filter((monitor) => SCRIPTED_MONITOR_TYPES.has((asString(monitor.monitorType) ?? "").toUpperCase()));
  const scriptsWithSecrets = scripts.filter((script) => asArray(script.secretIndicators).length > 0);
  const scriptsUsingSecureCredentials = scripts.filter((script) => asBoolean(script.usesSecureCredentials) === true);

  const publicReadWriteDashboards = dashboards.filter((dashboard) => (asString(dashboard.permissions) ?? "").toUpperCase() === "PUBLIC_READ_WRITE");
  const privateDashboards = dashboards.filter((dashboard) => (asString(dashboard.permissions) ?? "").toUpperCase() === "PRIVATE");
  const liveUrlSnapshots = liveUrls.map((liveUrl) => ({
    title: asString(liveUrl.title) ?? "",
    type: asString(liveUrl.type)?.toUpperCase() ?? "UNKNOWN",
    createdAt: liveUrl.createdAt ?? null,
  }));
  const dashboardLiveUrls = liveUrlSnapshots.filter((liveUrl) => liveUrl.type === "DASHBOARD");
  const widgetLiveUrls = liveUrlSnapshots.filter((liveUrl) => liveUrl.type === "WIDGET");

  const reportingHosts = sumField(data.infraHosts.data, "reportingHosts");
  const agentVersions = data.infraAgentVersions.data
    .map((row) => ({ version: asString(row.agentVersion) ?? asString(row.facet) ?? "unknown", hosts: asNumber(row.hosts) ?? 0 }))
    .filter((row) => row.version !== "unknown" || row.hosts > 0);

  const findings: NewrelicFinding[] = [];

  findings.push(finding(
    11,
    data.retentionRules.error
      ? "manual"
      : shortRetentionRules.length > 0
        ? "fail"
        : retentionRules.length === 0
          ? "warn"
          : "pass",
    data.retentionRules.error
      ? "Data retention rules were not readable. Record the retention per data type from Administration > Data management > Data retention for every account."
      : shortRetentionRules.length > 0
        ? `${shortRetentionRules.length}/${retentionRules.length} active retention rules keep data for less than ${minRetentionDays} days.`
        : retentionRules.length === 0
          ? `No custom retention rules exist across ${data.accountIds.length} accounts, so New Relic default retention applies to all ${data.retentionNamespaces.data.length} customizable namespaces. Confirm the defaults meet the ${minRetentionDays}-day requirement.`
          : `All ${retentionRules.length} active retention rules keep data for at least ${minRetentionDays} days.`,
    {
      min_retention_days: minRetentionDays,
      active_rules: sample(retentionRules.map((rule) => `${asString(rule.namespace) ?? "namespace"}: ${asNumber(rule.retentionInDays) ?? "?"} days`), 50),
      short_retention_rules: sample(shortRetentionRules.map((rule) => `${asString(rule.namespace) ?? "namespace"}: ${asNumber(rule.retentionInDays) ?? "?"} days`)),
      customizable_namespaces: data.retentionNamespaces.data.length,
    },
  ));

  findings.push(finding(
    12,
    data.obfuscationRules.error
      ? "manual"
      : enabledObfuscationRules.length === 0
        ? "fail"
        : !credentialCoverage || !piiCoverage
          ? "warn"
          : "pass",
    data.obfuscationRules.error
      ? "Log obfuscation rules were not readable. Record the rules and expressions shown in Logs > Obfuscation for every account."
      : enabledObfuscationRules.length === 0
        ? `No enabled log obfuscation rules exist across ${data.accountIds.length} accounts${logCount > 0 ? ` while ${logCount} log events were ingested in the last day` : ""}.`
        : !credentialCoverage || !piiCoverage
          ? `${enabledObfuscationRules.length} enabled obfuscation rules exist, but the ${obfuscationExpressions.length} expressions do not clearly cover ${!credentialCoverage ? "credentials or tokens" : "PII"}.`
          : `${enabledObfuscationRules.length} enabled obfuscation rules and ${obfuscationExpressions.length} expressions cover credential and PII patterns; ${attributeDropRules.length} pipeline rules also drop sensitive attributes.`,
    {
      obfuscation_rules: obfuscationRules.length,
      enabled_obfuscation_rules: enabledObfuscationRules.length,
      obfuscation_expressions: sample(obfuscationExpressions.map((expression) => asString(expression.name) ?? "expression")),
      credential_coverage: credentialCoverage,
      pii_coverage: piiCoverage,
      pipeline_cloud_rules: cloudRules.length,
      legacy_drop_rules: dropRules.length,
      attribute_drop_rules: attributeDropRules.length,
    },
  ));

  findings.push(finding(
    13,
    scriptsWithSecrets.length > 0
      ? "fail"
      : scriptedMonitors.length === 0
        ? "pass"
        : data.syntheticScripts.error
          ? "manual"
          : scriptsUsingSecureCredentials.length === 0 && secureCredentials.length === 0
            ? "warn"
            : "pass",
    scriptsWithSecrets.length > 0
      ? `${scriptsWithSecrets.length}/${scripts.length} sampled scripted monitors contain hardcoded credential patterns (${[...new Set(scriptsWithSecrets.flatMap((script) => asArray(script.secretIndicators).map(String)))].join(", ")}).`
      : scriptedMonitors.length === 0
        ? `No scripted synthetic monitors exist across ${monitors.length} monitors, so there are no scripts to review.`
        : data.syntheticScripts.error
          ? `${scriptedMonitors.length} scripted monitors exist but their scripts were not readable. Open each script in Synthetic monitoring and confirm credentials come from secure credentials ($secure.NAME).`
          : scriptsUsingSecureCredentials.length === 0 && secureCredentials.length === 0
            ? `${scripts.length} sampled scripts contain no obvious hardcoded secrets, but no secure credentials exist and no script references $secure.*, so credential handling should be confirmed.`
            : `${scripts.length} sampled scripts contain no hardcoded credential patterns; ${scriptsUsingSecureCredentials.length} reference secure credentials and ${secureCredentials.length} secure credentials are stored.`,
    {
      monitors: monitors.length,
      scripted_monitors: scriptedMonitors.length,
      scripts_sampled: scripts.length,
      scripts_with_secret_indicators: sample(scriptsWithSecrets.map((script) => `${asString(script.name) ?? asString(script.guid)}: ${asArray(script.secretIndicators).join(", ")}`)),
      scripts_using_secure_credentials: scriptsUsingSecureCredentials.length,
      secure_credentials: secureCredentials.length,
    },
  ));

  findings.push(finding(
    14,
    data.dashboards.error
      ? "manual"
      : liveUrls.length > 0
        ? "fail"
        : publicReadWriteDashboards.length > 0
          ? "warn"
          : "pass",
    data.dashboards.error
      ? "Dashboards were not readable. Review dashboard permissions and public sharing links in the Dashboards UI manually."
      : liveUrls.length > 0
        ? `${dashboardLiveUrls.length} dashboards and ${widgetLiveUrls.length} widgets are shared through public live URLs that anyone with the link can open; ${publicReadWriteDashboards.length}/${dashboards.length} dashboards also allow every account user to edit.`
        : publicReadWriteDashboards.length > 0
          ? `${publicReadWriteDashboards.length}/${dashboards.length} dashboards grant edit access to everyone in the account (PUBLIC_READ_WRITE) and no public live URLs are visible to this user.`
          : `${dashboards.length} dashboards use read-only or private permissions and no public live URLs are visible to this user.`,
    {
      dashboards: dashboards.length,
      public_read_write_dashboards: sample(publicReadWriteDashboards.map((dashboard) => asString(dashboard.name) ?? "dashboard")),
      private_dashboards: privateDashboards.length,
      public_live_urls: liveUrls.length,
      public_dashboard_live_urls: sample(dashboardLiveUrls.map((liveUrl) => liveUrl.title || "untitled dashboard")),
      public_widget_live_urls: widgetLiveUrls.length,
      live_url_visibility_note: "liveUrls only lists public links visible to the authenticated user; link values are intentionally not collected.",
    },
  ));

  findings.push(finding(
    15,
    data.logSecretMatches.error
      ? "manual"
      : secretMatchCount > 0
        ? "fail"
        : logCount === 0
          ? "warn"
          : "pass",
    data.logSecretMatches.error
      ? "Log data could not be queried for secret patterns. Run a NRQL search over Log for password, token, API key, and private key patterns manually."
      : secretMatchCount > 0
        ? `${secretMatchCount} log messages in the last day matched credential or token patterns across ${data.accountIds.length} accounts.`
        : logCount === 0
          ? "No log events were ingested in the last day, so plaintext secret exposure in logs could not be evaluated."
          : `${logCount} log events in the last day contained no messages matching credential or token patterns.`,
    {
      log_events_last_day: logCount,
      secret_pattern_matches: secretMatchCount,
      nrql_pattern: LOG_SECRET_NRQL_PATTERN,
    },
  ));

  findings.push(finding(
    16,
    "manual",
    reportingHosts > 0
      ? `${reportingHosts} infrastructure hosts are reporting across ${agentVersions.length} agent versions. Agent transport settings are not exposed by the API: collect newrelic-infra.yml from a representative host per version and confirm HTTPS endpoints, proxy_validate_certificates, and ca_bundle settings, and that the agent version is current.`
      : "No reporting infrastructure hosts were found. If infrastructure agents are deployed, collect newrelic-infra.yml from a representative host and confirm TLS and proxy settings.",
    {
      reporting_hosts: reportingHosts,
      agent_versions: sample(agentVersions, 50),
      manual_evidence: "newrelic-infra.yml (or fleet configuration) showing proxy, proxy_validate_certificates, ca_bundle_file, and agent version for each host group.",
    },
  ));

  const allCollected = [
    data.retentionRules,
    data.retentionNamespaces,
    data.obfuscationRules,
    data.obfuscationExpressions,
    data.cloudRules,
    data.dropRules,
    data.dashboards,
    data.dashboardLiveUrls,
    data.syntheticMonitors,
    data.secureCredentials,
    data.syntheticScripts,
    data.logVolume,
    data.logSecretMatches,
    data.infraHosts,
    data.infraAgentVersions,
  ];

  return {
    category: "data_governance",
    title: "New Relic data governance and telemetry security",
    summary: {
      region: config.region,
      accounts_in_scope: data.accountIds,
      retention_rules: retentionRules.length,
      short_retention_rules: shortRetentionRules.length,
      enabled_obfuscation_rules: enabledObfuscationRules.length,
      pipeline_cloud_rules: cloudRules.length,
      scripted_monitors: scriptedMonitors.length,
      scripts_with_secret_indicators: scriptsWithSecrets.length,
      dashboards: dashboards.length,
      public_live_urls: liveUrls.length,
      log_secret_pattern_matches: secretMatchCount,
      reporting_hosts: reportingHosts,
      collection_errors: collectedErrors(allCollected).length,
    },
    findings,
    errors: collectedErrors(allCollected),
    coreData: {
      "core_data/retention_rules.json": data.retentionRules.data,
      "core_data/retention_namespaces.json": data.retentionNamespaces.data,
      "core_data/obfuscation_rules.json": obfuscationRules,
      "core_data/obfuscation_expressions.json": obfuscationExpressions,
      "core_data/pipeline_cloud_rules.json": cloudRules,
      "core_data/nrql_drop_rules.json": dropRules,
      "core_data/dashboards.json": dashboards,
      "core_data/dashboard_live_urls.json": liveUrlSnapshots,
      "core_data/synthetic_monitors.json": monitors,
      "core_data/secure_credentials.json": secureCredentials,
      "core_data/synthetic_script_scan.json": scripts,
      "core_data/log_secret_scan.json": { volume: data.logVolume.data, matches: data.logSecretMatches.data },
      "core_data/infrastructure_hosts.json": { hosts: data.infraHosts.data, agentVersions: data.infraAgentVersions.data },
    },
  };
}

export async function assessNewrelicDataGovernance(
  client: DataGovernanceClient,
  options: NewrelicDataGovernanceOptions = {},
): Promise<NewrelicAssessmentResult> {
  const data = await collectNewrelicDataGovernanceData(client, options);
  return assessNewrelicDataGovernanceData(data, client.getResolvedConfig(), options);
}

function formatAccessCheckText(result: NewrelicAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.required ? "required" : "optional",
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `New Relic access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Scope", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatSummaryValue(value: unknown): string {
  if (typeof value === "number") return String(Number(value.toFixed(2)));
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ") || "-";
  if (value === null || value === undefined) return "-";
  return String(value);
}

function formatAssessmentText(result: NewrelicAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${formatSummaryValue(value)}`)
    .join("\n");
  const lines = [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
  ];
  if (result.errors.length > 0) {
    lines.push("", "Partial collection warnings:", ...result.errors.map((error) => `- ${error}`));
  }
  return lines.join("\n");
}

function countByStatus(findings: NewrelicFinding[]): Record<NewrelicFindingStatus, number> {
  const counts: Record<NewrelicFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
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

function buildExecutiveSummary(
  config: NewrelicResolvedConfig,
  accountIds: number[],
  assessments: NewrelicAssessmentResult[],
  errors: string[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const priority = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => (left.status === right.status ? 0 : left.status === "fail" ? -1 : 1))
    .slice(0, 10);

  const lines = [
    "# New Relic Security Inspector Executive Summary",
    "",
    `Region: ${config.region}`,
    `Accounts: ${accountIds.length > 0 ? accountIds.join(", ") : "none resolved"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Passing controls: ${counts.pass}`,
    `- Manual controls: ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  if (priority.length === 0) {
    lines.push("- No failing or warning findings were generated in this assessment set.");
  } else {
    for (const item of priority) {
      lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`);
    }
  }
  const manual = findings.filter((item) => item.status === "manual");
  if (manual.length > 0) {
    lines.push("", "## Manual Evidence Required", "");
    for (const item of manual) {
      lines.push(`- ${item.id}: ${item.summary}`);
    }
  }
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "");
    for (const error of errors) {
      lines.push(`- ${error}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: NewrelicFinding[]): string {
  const rows = findings.map((item) => [
    String(item.control),
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# New Relic Unified Compliance Matrix",
    "",
    formatTable(["#", "Finding", "Severity", "Status", "Title", "Mappings"], rows),
    "",
  ].join("\n");
}

function buildFrameworkReport(title: string, frameworkLabel: string, findings: NewrelicFinding[]): string {
  const prefix = `${frameworkLabel} `;
  const lines = [`# ${title}`, "", `Framework mappings are taken from the New Relic Security Inspector spec for ${frameworkLabel}.`, ""];
  for (const item of findings) {
    const mapped = item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length));
    if (mapped.length === 0) continue;
    lines.push(`## ${mapped.join(", ")}: ${item.title}`, "");
    lines.push(`- Finding: ${item.id}`);
    lines.push(`- Status: ${item.status.toUpperCase()}`);
    lines.push(`- Severity: ${item.severity.toUpperCase()}`);
    lines.push(`- Summary: ${item.summary}`);
    lines.push("");
  }
  return lines.join("\n");
}

function buildQuickReference(): string {
  return [
    "# New Relic Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw NerdGraph and REST API v2 responses used during this assessment (API key values are never requested).",
    "- `analysis/` contains normalized findings and per-category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Review manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
  ].join("\n");
}

export async function exportNewrelicAuditBundle(
  client: IdentityClient & AccessControlClient & AlertingClient & DataGovernanceClient,
  config: NewrelicResolvedConfig,
  outputRoot: string,
  options: NewrelicBundleOptions = {},
): Promise<NewrelicAuditBundleResult> {
  const identity = await assessNewrelicIdentity(client, options);
  const accessControl = await assessNewrelicAccessControl(client, options);
  const alerting = await assessNewrelicAlerting(client, options);
  const dataGovernance = await assessNewrelicDataGovernance(client, options);
  const assessments = [identity, accessControl, alerting, dataGovernance];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];
  const accountIds = asArray(accessControl.summary.accounts_in_scope).map((id) => asNumber(id)).filter((id): id is number => id !== undefined);

  ensurePrivateDir(outputRoot);
  const label = accountIds.length > 0 ? accountIds.join("-") : config.region.toLowerCase();
  const outputDir = await nextAvailableAuditDir(outputRoot, safeDirName(`newrelic-${label}-audit-bundle`));

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    region: config.region,
    nerdgraph_url: config.nerdgraphUrl,
    account_ids: accountIds,
    audit_window_days: config.auditWindowDays,
    source_chain: config.sourceChain,
  }));

  const writtenCoreData = new Set<string>();
  for (const assessment of assessments) {
    for (const [pathname, value] of Object.entries(assessment.coreData)) {
      if (writtenCoreData.has(pathname)) continue;
      writtenCoreData.add(pathname);
      await writeSecureTextFile(outputDir, pathname, serializeJson(value));
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson({
      category: assessment.category,
      title: assessment.title,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    }));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, accountIds, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORKS) {
    await writeSecureTextFile(
      outputDir,
      `compliance/${framework.slug}/${framework.file}`,
      buildFrameworkReport(framework.title, framework.label, findings),
    );
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
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
    api_key: asString(value.api_key) ?? asString(value.apiKey),
    account_id: parseListArgument(value.account_id ?? value.accountId ?? value.account_ids).join(",") || undefined,
    region: asString(value.region),
    config_file: asString(value.config_file) ?? asString(value.configFile),
    timeout_seconds: asNumber(value.timeout_seconds),
    audit_window_days: asNumber(value.audit_window_days),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    user_limit: asNumber(value.user_limit),
    inactive_days: asNumber(value.inactive_days),
    max_admins: asNumber(value.max_admins),
    max_full_platform_percent: asNumber(value.max_full_platform_percent),
    admin_role_pattern: asString(value.admin_role_pattern),
  };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    user_limit: asNumber(value.user_limit),
    inactive_days: asNumber(value.inactive_days),
    max_key_age_days: asNumber(value.max_key_age_days),
    max_accounts_per_user: asNumber(value.max_accounts_per_user),
    admin_role_pattern: asString(value.admin_role_pattern),
    production_account_pattern: asString(value.production_account_pattern),
    nonproduction_account_pattern: asString(value.nonproduction_account_pattern),
  };
}

function normalizeAlertingArgs(args: unknown): AlertingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    entity_limit: asNumber(value.entity_limit),
    approved_email_domains: parseListArgument(value.approved_email_domains).join(",") || undefined,
  };
}

function normalizeDataGovernanceArgs(args: unknown): DataGovernanceArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    entity_limit: asNumber(value.entity_limit),
    min_retention_days: asNumber(value.min_retention_days),
    script_sample_limit: asNumber(value.script_sample_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeAccessControlArgs(args),
    ...normalizeAlertingArgs(args),
    ...normalizeDataGovernanceArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function identityOptions(args: IdentityArgs): NewrelicIdentityOptions {
  return {
    userLimit: args.user_limit,
    inactiveDays: args.inactive_days,
    maxAdmins: args.max_admins,
    maxFullPlatformPercent: args.max_full_platform_percent,
    adminRolePattern: args.admin_role_pattern,
  };
}

function accessControlOptions(args: AccessControlArgs): NewrelicAccessControlOptions {
  return {
    userLimit: args.user_limit,
    inactiveDays: args.inactive_days,
    maxKeyAgeDays: args.max_key_age_days,
    maxAccountsPerUser: args.max_accounts_per_user,
    adminRolePattern: args.admin_role_pattern,
    productionAccountPattern: args.production_account_pattern,
    nonproductionAccountPattern: args.nonproduction_account_pattern,
  };
}

function alertingOptions(args: AlertingArgs): NewrelicAlertingOptions & { entityLimit?: number } {
  return {
    entityLimit: args.entity_limit,
    approvedEmailDomains: parseListArgument(args.approved_email_domains),
  };
}

function dataGovernanceOptions(args: DataGovernanceArgs): NewrelicDataGovernanceOptions {
  return {
    entityLimit: args.entity_limit,
    minRetentionDays: args.min_retention_days,
    scriptSampleLimit: args.script_sample_limit,
  };
}

function createClient(args: AuthArgs): NewrelicApiClient {
  return new NewrelicApiClient(resolveNewrelicConfiguration(args));
}

function errorMessage(error: unknown): string {
  return redactSecrets(error instanceof Error ? error.message : String(error));
}

const authParams = {
  api_key: Type.Optional(Type.String({ description: "New Relic User API key (NRAK-...). Defaults to NEW_RELIC_API_KEY or api_key in ~/.newrelic-sec-inspector/config.yaml." })),
  account_id: Type.Optional(Type.String({ description: "Account ID or comma-separated account IDs to inspect. Defaults to NEW_RELIC_ACCOUNT_ID, then the config file, then every account visible to the key." })),
  region: Type.Optional(Type.String({ description: "New Relic region: US (api.newrelic.com) or EU (api.eu.newrelic.com). Defaults to NEW_RELIC_REGION or US." })),
  config_file: Type.Optional(Type.String({ description: "Path to a YAML config file. Defaults to NEW_RELIC_SEC_INSPECTOR_CONFIG or ~/.newrelic-sec-inspector/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  audit_window_days: Type.Optional(Type.Number({ description: "NrAuditEvent lookback window in days. Defaults to 30.", default: 30 })),
};

const identityParams = {
  user_limit: Type.Optional(Type.Number({ description: "Maximum users to inspect across authentication domains. Defaults to 2000.", default: 2000 })),
  inactive_days: Type.Optional(Type.Number({ description: "Days without activity before a user is considered inactive. Defaults to 90.", default: 90 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin group members before failing. Defaults to 10.", default: 10 })),
  max_full_platform_percent: Type.Optional(Type.Number({ description: "Maximum acceptable share of full platform users before warning. Defaults to 60.", default: 60 })),
  admin_role_pattern: Type.Optional(Type.String({ description: "Case-insensitive regex identifying admin roles. Defaults to organization manager|authentication domain manager|all product admin." })),
};

const accessControlParams = {
  user_limit: identityParams.user_limit,
  inactive_days: identityParams.inactive_days,
  max_key_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable user API key age in days. Defaults to 90.", default: 90 })),
  max_accounts_per_user: Type.Optional(Type.Number({ description: "Maximum accounts a non-admin user may access before warning. Defaults to 5.", default: 5 })),
  admin_role_pattern: identityParams.admin_role_pattern,
  production_account_pattern: Type.Optional(Type.String({ description: "Case-insensitive regex matching production account names. Defaults to prod." })),
  nonproduction_account_pattern: Type.Optional(Type.String({ description: "Case-insensitive regex matching non-production account names. Defaults to dev|test|stag|sandbox|qa|nonprod|non-prod|uat|demo." })),
};

const alertingParams = {
  entity_limit: Type.Optional(Type.Number({ description: "Maximum entities to inspect per account. Defaults to 1000.", default: 1000 })),
  approved_email_domains: Type.Optional(Type.String({ description: "Comma-separated email domains approved for notification destinations. Defaults to the authenticated user's domain." })),
};

const dataGovernanceParams = {
  entity_limit: alertingParams.entity_limit,
  min_retention_days: Type.Optional(Type.Number({ description: "Minimum acceptable data retention in days for custom retention rules. Defaults to 30.", default: 30 })),
  script_sample_limit: Type.Optional(Type.Number({ description: "Maximum scripted synthetic monitors whose scripts are scanned. Defaults to 25.", default: 25 })),
};

export function registerNewrelicTools(pi: any): void {
  pi.registerTool({
    name: "newrelic_check_access",
    label: "Check New Relic audit access",
    description:
      "Validate read-only New Relic access across NerdGraph actor.user, accounts, organization, user management, authorization management, API key search, NRQL (NrAuditEvent), entity search, alerts, data management, log configurations, and REST API v2 users.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkNewrelicAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "newrelic_check_access", ...result });
      } catch (error) {
        return errorResult(`New Relic access check failed: ${errorMessage(error)}`, { tool: "newrelic_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "newrelic_assess_identity",
    label: "Assess New Relic identity posture",
    description:
      "Assess New Relic identity posture: SSO/SAML enforcement, user type least privilege, admin user minimization, authentication domain configuration, and inactive user accounts (spec controls 1, 2, 3, 18, 19).",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessNewrelicIdentity(createClient(args), identityOptions(args));
        return textResult(formatAssessmentText(result), { tool: "newrelic_assess_identity", ...result, coreData: undefined });
      } catch (error) {
        return errorResult(`New Relic identity assessment failed: ${errorMessage(error)}`, { tool: "newrelic_assess_identity" });
      }
    },
  });

  pi.registerTool({
    name: "newrelic_assess_access_control",
    label: "Assess New Relic access control and API keys",
    description:
      "Assess New Relic API key inventory, key age, unused keys, account access controls, cross-account access restrictions, and custom role permissions (spec controls 4, 5, 6, 7, 8, 20).",
    parameters: Type.Object({ ...authParams, ...accessControlParams }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await assessNewrelicAccessControl(createClient(args), accessControlOptions(args));
        return textResult(formatAssessmentText(result), { tool: "newrelic_assess_access_control", ...result, coreData: undefined });
      } catch (error) {
        return errorResult(`New Relic access control assessment failed: ${errorMessage(error)}`, { tool: "newrelic_assess_access_control" });
      }
    },
  });

  pi.registerTool({
    name: "newrelic_assess_alerting",
    label: "Assess New Relic alerting and notifications",
    description:
      "Assess New Relic alert policy coverage, notification destination hygiene, and applied intelligence enrichment exposure (spec controls 9, 10, 17).",
    parameters: Type.Object({ ...authParams, ...alertingParams }),
    prepareArguments: normalizeAlertingArgs,
    async execute(_toolCallId: string, args: AlertingArgs) {
      try {
        const result = await assessNewrelicAlerting(createClient(args), alertingOptions(args));
        return textResult(formatAssessmentText(result), { tool: "newrelic_assess_alerting", ...result, coreData: undefined });
      } catch (error) {
        return errorResult(`New Relic alerting assessment failed: ${errorMessage(error)}`, { tool: "newrelic_assess_alerting" });
      }
    },
  });

  pi.registerTool({
    name: "newrelic_assess_data_governance",
    label: "Assess New Relic data governance",
    description:
      "Assess New Relic data retention, log obfuscation, synthetic monitor credential handling, dashboard permissions and public live URLs, plaintext secrets in logs, and infrastructure agent configuration evidence (spec controls 11, 12, 13, 14, 15, 16).",
    parameters: Type.Object({ ...authParams, ...dataGovernanceParams }),
    prepareArguments: normalizeDataGovernanceArgs,
    async execute(_toolCallId: string, args: DataGovernanceArgs) {
      try {
        const result = await assessNewrelicDataGovernance(createClient(args), dataGovernanceOptions(args));
        return textResult(formatAssessmentText(result), { tool: "newrelic_assess_data_governance", ...result, coreData: undefined });
      } catch (error) {
        return errorResult(`New Relic data governance assessment failed: ${errorMessage(error)}`, { tool: "newrelic_assess_data_governance" });
      }
    },
  });

  pi.registerTool({
    name: "newrelic_export_audit_bundle",
    label: "Export New Relic audit bundle",
    description:
      "Export a New Relic audit package covering all 20 spec controls with raw NerdGraph snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), a quick reference, an _errors.log on partial failure, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...identityParams,
      ...accessControlParams,
      ...alertingParams,
      ...dataGovernanceParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveNewrelicConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportNewrelicAuditBundle(new NewrelicApiClient(config), config, outputRoot, {
          ...identityOptions(args),
          ...accessControlOptions(args),
          ...alertingOptions(args),
          ...dataGovernanceOptions(args),
        });
        return textResult(
          [
            "New Relic audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "newrelic_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`New Relic audit bundle export failed: ${errorMessage(error)}`, { tool: "newrelic_export_audit_bundle" });
      }
    },
  });
}
