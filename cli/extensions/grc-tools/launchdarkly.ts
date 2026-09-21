/**
 * LaunchDarkly account security inspector tools for grclanker.
 *
 * This native TypeScript surface provides read-only LaunchDarkly REST API v2
 * coverage across identity, access control, environment governance, flag
 * hygiene, and monitoring integrations. It never mutates the account.
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
type JsonRecord = Record<string, unknown>;
type SleepImpl = (ms: number) => Promise<void>;

const DEFAULT_OUTPUT_DIR = "./export/launchdarkly";
const DEFAULT_BASE_URL = "https://app.launchdarkly.com";
const DEFAULT_API_VERSION = "20240415";
const BETA_API_VERSION = "beta";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const MAX_RATE_LIMIT_WAIT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 50;
const AUDIT_LOG_PAGE_SIZE = 20;
const FLAG_PAGE_SIZE = 100;
const DEFAULT_LIST_LIMIT = 1000;
const DEFAULT_MEMBER_LIMIT = 1000;
const DEFAULT_TEAM_LIMIT = 100;
const DEFAULT_ROLE_LIMIT = 200;
const DEFAULT_TOKEN_LIMIT = 500;
const DEFAULT_PROJECT_LIMIT = 50;
const DEFAULT_ENVIRONMENT_LIMIT = 50;
const DEFAULT_FLAG_LIMIT = 500;
const DEFAULT_MAX_OWNERS = 1;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_STALE_TOKEN_DAYS = 90;
const DEFAULT_STALE_FLAG_DAYS = 30;
const DEFAULT_SDK_KEY_MAX_AGE_DAYS = 365;
const DEFAULT_RELAY_CONFIG_MAX_AGE_DAYS = 365;
const DEFAULT_AUDIT_RETENTION_DAYS = 90;
const DEFAULT_PRODUCTION_PATTERN = "prod";
const DEFAULT_TEST_PROJECT_PATTERN = "(^|[^a-z])(test|tmp|temp|demo|sandbox|poc|scratch|playground)([^a-z]|$)";
const DEFAULT_INTEGRATION_KEYS = [
  "datadog",
  "dynatrace",
  "elastic",
  "honeycomb",
  "logdna",
  "msteams",
  "new-relic-apm",
  "signalfx",
  "splunk",
];
const DAY_MS = 24 * 60 * 60 * 1000;
const EVIDENCE_SAMPLE_LIMIT = 25;
const CORE_ACCESS_SURFACES = new Set([
  "caller_identity",
  "members",
  "teams",
  "custom_roles",
  "projects",
  "environments",
  "flags",
  "access_tokens",
  "audit_log",
]);

export type LaunchdarklyFindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type LaunchdarklyFindingStatus = "pass" | "warn" | "fail" | "manual";
export type LaunchdarklyFramework = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "stig" | "irap" | "ismap";

export interface LaunchdarklyResolvedConfig {
  token: string;
  baseUrl: string;
  apiVersion: string;
  timeoutMs: number;
  allowedDomains: string[];
  projectKeys: string[];
  configPath: string;
  sourceChain: string[];
}

export interface LaunchdarklyAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface LaunchdarklyCallerIdentity {
  accountId?: string;
  memberId?: string;
  tokenId?: string;
  tokenName?: string;
  tokenKind?: string;
  authKind?: string;
  serviceToken?: boolean;
}

export interface LaunchdarklyAccessCheckResult {
  status: "healthy" | "limited";
  baseUrl: string;
  callerIdentity: LaunchdarklyCallerIdentity;
  surfaces: LaunchdarklyAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface LaunchdarklyCollection {
  items: JsonRecord[];
  truncated: boolean;
  seen: number;
  total?: number;
}

export interface LaunchdarklyTruncationNote {
  collection: string;
  option?: string;
  seen: number;
  total: number | null;
  scope?: string;
}

export interface LaunchdarklyFinding {
  id: string;
  control: number;
  title: string;
  severity: LaunchdarklyFindingSeverity;
  status: LaunchdarklyFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  frameworks: Record<LaunchdarklyFramework, string>;
}

export interface LaunchdarklyAssessmentResult {
  title: string;
  category: string;
  summary: JsonRecord;
  findings: LaunchdarklyFinding[];
  errors: string[];
  snapshots: Record<string, unknown>;
}

export interface LaunchdarklyAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

interface ControlDefinition {
  control: number;
  title: string;
  severity: LaunchdarklyFindingSeverity;
  frameworks: Record<LaunchdarklyFramework, string>;
}

interface PolicyStatement {
  effect: "allow" | "deny";
  actions: string[];
  notActions: string[];
  resources: string[];
  notResources: string[];
}

interface SensitiveActionGroup {
  resource: string;
  actions: string[];
}

interface EnvironmentContext {
  projectKey: string;
  projectName: string;
  projectTags: string[];
  environment: JsonRecord;
  key: string;
  name: string;
  production: boolean;
}

interface ResourceSegment {
  type: string;
  name: string;
  tags: string[];
  selectors: Record<string, string>;
}

interface EnvironmentRestriction {
  role: string;
  kind: "deny" | "not_resources" | "scoped_elsewhere";
  resource: string;
}

type AuthArgs = {
  token?: string;
  base_url?: string;
  api_version?: string;
  config_path?: string;
  timeout_seconds?: number;
};

type IdentityArgs = AuthArgs & {
  member_limit?: number;
  team_limit?: number;
  max_owners?: number;
  max_admins?: number;
  allowed_domains?: string[];
};

type AccessControlArgs = AuthArgs & {
  role_limit?: number;
  token_limit?: number;
  stale_token_days?: number;
};

type EnvironmentGovernanceArgs = AuthArgs & {
  project_limit?: number;
  environment_limit?: number;
  project_keys?: string[];
  production_pattern?: string;
  test_project_pattern?: string;
  sdk_key_max_age_days?: number;
};

type FlagHygieneArgs = AuthArgs & {
  project_limit?: number;
  flag_limit?: number;
  project_keys?: string[];
  production_pattern?: string;
  stale_flag_days?: number;
};

type MonitoringArgs = AuthArgs & {
  retention_days?: number;
  integration_keys?: string[];
  relay_config_max_age_days?: number;
  production_pattern?: string;
};

type ExportAuditBundleArgs = IdentityArgs & AccessControlArgs & EnvironmentGovernanceArgs & FlagHygieneArgs & MonitoringArgs & {
  output_dir?: string;
};

export interface LaunchdarklyIdentityOptions {
  memberLimit?: number;
  teamLimit?: number;
  maxOwners?: number;
  maxAdmins?: number;
  allowedDomains?: string[];
  now?: number;
}

export interface LaunchdarklyAccessControlOptions {
  roleLimit?: number;
  tokenLimit?: number;
  staleTokenDays?: number;
  now?: number;
}

export interface LaunchdarklyEnvironmentGovernanceOptions {
  projectLimit?: number;
  environmentLimit?: number;
  projectKeys?: string[];
  productionPattern?: string;
  testProjectPattern?: string;
  sdkKeyMaxAgeDays?: number;
  now?: number;
}

export interface LaunchdarklyFlagHygieneOptions {
  projectLimit?: number;
  flagLimit?: number;
  projectKeys?: string[];
  productionPattern?: string;
  staleFlagDays?: number;
  now?: number;
}

export interface LaunchdarklyMonitoringOptions {
  retentionDays?: number;
  integrationKeys?: string[];
  relayConfigMaxAgeDays?: number;
  productionPattern?: string;
  now?: number;
}

export type LaunchdarklyAuditBundleOptions =
  LaunchdarklyIdentityOptions
  & LaunchdarklyAccessControlOptions
  & LaunchdarklyEnvironmentGovernanceOptions
  & LaunchdarklyFlagHygieneOptions
  & LaunchdarklyMonitoringOptions;

const FRAMEWORK_ORDER: LaunchdarklyFramework[] = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "stig", "irap", "ismap"];

export const LAUNCHDARKLY_CONTROL_CATALOG: Record<number, ControlDefinition> = {
  1: control(1, "SSO/SAML enforcement enabled for the account", "critical", ["IA-2(1)", "L2 3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000148", "ISM-1546", "CPS-7.1"]),
  2: control(2, "MFA required for all members", "critical", ["IA-2(2)", "L2 3.5.3", "CC6.1", "16.3", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-7.2"]),
  3: control(3, "No members with Owner role beyond minimum required", "high", ["AC-6(5)", "L2 3.1.5", "CC6.3", "16.8", "7.1.1", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  4: control(4, "Custom roles follow least-privilege principle (no wildcard actions)", "high", ["AC-6", "L2 3.1.7", "CC6.3", "16.8", "7.1.2", "SRG-APP-000342", "ISM-1507", "CPS-8.2"]),
  5: control(5, "Custom role policies deny sensitive actions by default", "high", ["AC-3", "L2 3.1.1", "CC6.1", "16.8", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.3"]),
  6: control(6, "All members assigned to teams (no orphaned members)", "medium", ["AC-2", "L2 3.1.1", "CC6.2", "16.1", "8.1.4", "SRG-APP-000025", "ISM-1503", "CPS-9.1"]),
  7: control(7, "Team permissions use custom roles, not built-in admin", "medium", ["AC-3", "L2 3.1.2", "CC6.3", "16.8", "7.1.2", "SRG-APP-000033", "ISM-1507", "CPS-8.2"]),
  8: control(8, "API access tokens have expiration dates set", "critical", ["AC-2(3)", "L2 3.1.1", "CC6.1", "16.9", "8.1.5", "SRG-APP-000025", "ISM-1552", "CPS-9.2"]),
  9: control(9, "No API tokens unused beyond 90 days (stale tokens)", "high", ["AC-2(3)", "L2 3.1.12", "CC6.1", "16.9", "8.1.4", "SRG-APP-000025", "ISM-1552", "CPS-9.3"]),
  10: control(10, "Service tokens scoped to minimum required roles", "high", ["AC-6(1)", "L2 3.1.5", "CC6.3", "16.8", "7.1.2", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  11: control(11, "Personal tokens limited to individual member scope", "medium", ["AC-6(1)", "L2 3.1.5", "CC6.3", "16.8", "7.1.2", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  12: control(12, "Audit log retention meets compliance requirements (>= 90 days queryable)", "high", ["AU-11", "L2 3.3.1", "CC7.2", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "CPS-12.1"]),
  13: control(13, "Audit log events present for critical actions (role changes, member adds)", "medium", ["AU-12", "L2 3.3.1", "CC7.2", "8.5", "10.2.2", "SRG-APP-000507", "ISM-0580", "CPS-12.2"]),
  14: control(14, "Flag targeting rules do not expose individual user keys in production", "medium", ["SC-28", "L2 3.13.16", "CC6.7", "14.6", "6.5.3", "SRG-APP-000428", "ISM-0457", "CPS-11.1"]),
  15: control(15, "Stale flags identified (not evaluated in > 30 days) and flagged for cleanup", "low", ["CM-3", "L2 3.4.3", "CC8.1", "4.8", "6.3.2", "SRG-APP-000380", "ISM-1210", "CPS-10.1"]),
  16: control(16, "Environment-level access controls restrict production modifications", "high", ["AC-3", "L2 3.1.1", "CC6.1", "16.8", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.3"]),
  17: control(17, "Approval workflows enabled for production environment changes", "high", ["CM-3(2)", "L2 3.4.3", "CC8.1", "4.8", "6.4.2", "SRG-APP-000380", "ISM-1210", "CPS-10.2"]),
  18: control(18, "Relay proxy configurations use secure mode", "high", ["SC-8", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000439", "ISM-0484", "CPS-11.2"]),
  19: control(19, "SDK keys rotated within policy period (< 365 days)", "medium", ["SC-12(1)", "L2 3.13.10", "CC6.1", "16.4", "3.6.4", "SRG-APP-000176", "ISM-1557", "CPS-7.3"]),
  20: control(20, "Integrations use least-privilege scopes", "medium", ["AC-6(1)", "L2 3.1.5", "CC6.3", "16.8", "7.1.2", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  21: control(21, "Webhook endpoints use HTTPS and signing is enabled", "high", ["SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.3"]),
  22: control(22, "No test/temporary projects in production account", "low", ["CM-2", "L2 3.4.1", "CC8.1", "4.1", "2.2.1", "SRG-APP-000131", "ISM-1407", "CPS-10.3"]),
  23: control(23, "Environment critical settings (secure mode, default TTL) configured", "medium", ["CM-6", "L2 3.4.2", "CC8.1", "4.1", "2.2.2", "SRG-APP-000131", "ISM-1407", "CPS-10.4"]),
  24: control(24, "Member email domains match organization domain policy", "medium", ["IA-4", "L2 3.5.5", "CC6.1", "16.6", "8.1.1", "SRG-APP-000163", "ISM-1547", "CPS-7.4"]),
  25: control(25, "Flag prerequisites do not create circular dependencies", "low", ["CM-3", "L2 3.4.5", "CC8.1", "4.8", "6.3.2", "SRG-APP-000380", "ISM-1210", "CPS-10.5"]),
};

const SENSITIVE_ACTION_GROUPS: SensitiveActionGroup[] = [
  {
    resource: "acct",
    actions: [
      "updateRequireMfa",
      "updateSamlRequireSso",
      "updateSamlEnabled",
      "updateSamlDefaultRole",
      "createSamlConfig",
      "deleteSamlConfig",
      "createScimConfig",
      "deleteScimConfig",
      "updateSessionDuration",
      "updateSessionRefresh",
      "revokeSessions",
      "updateAccountToken",
      "updateOrganization",
    ],
  },
  { resource: "member", actions: ["createMember", "deleteMember", "updateRole", "updateCustomRole"] },
  { resource: "role", actions: ["createRole", "deleteRole", "updatePolicy", "updateBasePermissions", "updateMembers"] },
  { resource: "service-token", actions: ["createAccessToken", "resetAccessToken", "deleteAccessToken"] },
  { resource: "relay-proxy-config", actions: ["createRelayAutoConfiguration", "resetRelayAutoConfiguration", "updateRelayAutoConfigurationPolicy"] },
  { resource: "webhook", actions: ["createWebhook", "updateSecret", "updateUrl", "updateStatements"] },
  { resource: "team", actions: ["updateTeamCustomRoles", "updateTeamPermissionGrants"] },
];

const CRITICAL_AUDIT_ACTIONS = new Set([
  "createMember",
  "deleteMember",
  "updateRole",
  "updateCustomRole",
  "createRole",
  "deleteRole",
  "updatePolicy",
  "updateBasePermissions",
  "updateMembers",
  "updateTeamCustomRoles",
  "updateTeamMembers",
]);

const SSO_AUDIT_ACTIONS = new Set([
  "createSamlConfig",
  "deleteSamlConfig",
  "updateSamlEnabled",
  "updateSamlRequireSso",
  "updateSamlSsoUrl",
  "createScimConfig",
  "deleteScimConfig",
  "updateRequireMfa",
]);

function control(
  controlNumber: number,
  title: string,
  severity: LaunchdarklyFindingSeverity,
  mappings: [string, string, string, string, string, string, string, string],
): ControlDefinition {
  return {
    control: controlNumber,
    title,
    severity,
    frameworks: {
      fedramp: mappings[0],
      cmmc: mappings[1],
      soc2: mappings[2],
      cis: mappings[3],
      pci_dss: mappings[4],
      stig: mappings[5],
      irap: mappings[6],
      ismap: mappings[7],
    },
  };
}

export function frameworkLabel(framework: LaunchdarklyFramework): string {
  switch (framework) {
    case "fedramp":
      return "FedRAMP";
    case "cmmc":
      return "CMMC";
    case "soc2":
      return "SOC 2";
    case "cis":
      return "CIS";
    case "pci_dss":
      return "PCI-DSS";
    case "stig":
      return "STIG";
    case "irap":
      return "IRAP";
    case "ismap":
      return "ISMAP";
    default: {
      const exhaustive: never = framework;
      throw new Error(`Unknown framework: ${String(exhaustive)}`);
    }
  }
}

function statusRank(status: LaunchdarklyFindingStatus): number {
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
      throw new Error(`Unknown finding status: ${String(exhaustive)}`);
    }
  }
}

function severityRank(severity: LaunchdarklyFindingSeverity): number {
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
      throw new Error(`Unknown finding severity: ${String(exhaustive)}`);
    }
  }
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

function asStringArray(value: unknown): string[] {
  return asArray(value).map(asString).filter((item): item is string => Boolean(item));
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

function asTimestamp(value: unknown): number | undefined {
  const numeric = asNumber(value);
  if (numeric !== undefined) return numeric > 0 ? numeric : undefined;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function normalizeStringList(value: unknown): string[] {
  if (Array.isArray(value)) return asStringArray(value);
  const text = asString(value);
  if (!text) return [];
  return text.split(",").map((item) => item.trim()).filter(Boolean);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function sample<T>(values: T[]): T[] {
  return values.slice(0, EVIDENCE_SAMPLE_LIMIT);
}

function daysBetween(fromMs: number, toMs: number): number {
  return Math.floor((toMs - fromMs) / DAY_MS);
}

function isoDate(timestampMs: number | undefined): string | null {
  return timestampMs === undefined ? null : new Date(timestampMs).toISOString();
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Unsupported LaunchDarkly base URL protocol: ${parsed.protocol}`);
  }
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
  return normalized || "launchdarkly";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function maskSecret(value: unknown): string | undefined {
  const text = asString(value);
  if (!text) return undefined;
  return text.length > 4 ? `****${text.slice(-4)}` : "****";
}

function redactTokenText(message: string, token?: string): string {
  let redacted = message.replace(/api-[A-Za-z0-9-]{8,}/g, "api-[REDACTED]");
  if (token && token.length > 0) {
    redacted = redacted.split(token).join("[REDACTED]");
  }
  return redacted;
}

function buildRegex(pattern: string | undefined, fallback: string): RegExp {
  const source = pattern?.trim() || fallback;
  try {
    return new RegExp(source, "i");
  } catch {
    return new RegExp(fallback, "i");
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

function auditZipPath(outputDir: string): string {
  return resolveSecureOutputPath(dirname(outputDir), `${basename(outputDir)}.zip`);
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate) && !existsSync(auditZipPath(candidate))) {
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

function stripTomlComment(line: string): string {
  let quote: string | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quote) {
      if (char === "\\" && quote === "\"") {
        index += 1;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === "\"" || char === "'") {
      quote = char;
      continue;
    }
    if (char === "#") return line.slice(0, index);
  }
  return line;
}

function splitTomlArray(body: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quote: string | undefined;
  for (const char of body) {
    if (quote) {
      current += char;
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === "\"" || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (char === ",") {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim().length > 0) parts.push(current);
  return parts.map((part) => part.trim()).filter((part) => part.length > 0);
}

function parseTomlScalar(raw: string): unknown {
  const value = raw.trim();
  if (value.startsWith("\"") && value.endsWith("\"") && value.length >= 2) {
    return value.slice(1, -1).replace(/\\"/g, "\"").replace(/\\\\/g, "\\");
  }
  if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
    return value.slice(1, -1);
  }
  if (value.startsWith("[") && value.endsWith("]")) {
    return splitTomlArray(value.slice(1, -1)).map(parseTomlScalar);
  }
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

export function parseSimpleToml(text: string): JsonRecord {
  const result: JsonRecord = {};
  let section = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (line.length === 0) continue;
    const sectionMatch = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1].replace(/^["']|["']$/g, "");
      continue;
    }
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim().replace(/^["']|["']$/g, "");
    const value = parseTomlScalar(line.slice(separator + 1));
    result[section ? `${section}.${key}` : key] = value;
  }
  return result;
}

function lookupConfigValue(values: JsonRecord, keys: string[]): unknown {
  for (const key of keys) {
    if (values[key] !== undefined) return values[key];
  }
  for (const key of keys) {
    for (const [entryKey, entryValue] of Object.entries(values)) {
      if (entryKey.endsWith(`.${key}`) && entryValue !== undefined) return entryValue;
    }
  }
  return undefined;
}

function readLaunchdarklyConfigFile(configPath: string): { values: JsonRecord; present: boolean } {
  if (!existsSync(configPath)) return { values: {}, present: false };
  try {
    return { values: parseSimpleToml(readFileSync(configPath, "utf8")), present: true };
  } catch (error) {
    throw new Error(`Unable to read LaunchDarkly config file ${configPath}: ${errorMessage(error)}`);
  }
}

export function resolveLaunchdarklyConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDir?: string } = {},
): LaunchdarklyResolvedConfig {
  const sourceChain: string[] = [];
  const homeDir = options.homeDir ?? homedir();
  const configPath = asString(input.config_path)
    ?? asString(env.LAUNCHDARKLY_CONFIG)
    ?? join(homeDir, ".config", "launchdarkly-sec-inspector", "config.toml");
  const configFile = readLaunchdarklyConfigFile(configPath);
  const fileValues = configFile.values;

  const pick = (
    label: string,
    argValue: unknown,
    envValue: unknown,
    fileKeys: string[],
  ): unknown => {
    if (argValue !== undefined && argValue !== null && argValue !== "") {
      sourceChain.push(`arguments-${label}`);
      return argValue;
    }
    if (envValue !== undefined && envValue !== null && envValue !== "") {
      sourceChain.push(`environment-${label}`);
      return envValue;
    }
    const fileValue = lookupConfigValue(fileValues, fileKeys);
    if (fileValue !== undefined && fileValue !== null && fileValue !== "") {
      sourceChain.push(`config-${label}`);
      return fileValue;
    }
    return undefined;
  };

  const token = asString(pick(
    "token",
    input.token,
    asString(env.LAUNCHDARKLY_API_TOKEN) ?? asString(env.LD_ACCESS_TOKEN),
    ["token", "api_token", "access_token"],
  ));
  if (!token) {
    throw new Error(
      `LaunchDarkly API access token is required. Pass token, set LAUNCHDARKLY_API_TOKEN, or add token to ${configPath}.`,
    );
  }

  const baseUrl = normalizeBaseUrl(asString(pick(
    "base-url",
    input.base_url,
    asString(env.LAUNCHDARKLY_BASE_URL) ?? asString(env.LD_BASE_URI),
    ["base_url", "base_uri"],
  )) ?? DEFAULT_BASE_URL);

  const apiVersion = asString(pick(
    "api-version",
    input.api_version,
    env.LAUNCHDARKLY_API_VERSION,
    ["api_version"],
  )) ?? DEFAULT_API_VERSION;

  const timeoutSeconds = asNumber(pick(
    "timeout",
    input.timeout_seconds,
    env.LAUNCHDARKLY_TIMEOUT,
    ["timeout_seconds", "timeout"],
  ));

  const allowedDomains = normalizeStringList(pick(
    "allowed-domains",
    Array.isArray(input.allowed_domains) && input.allowed_domains.length === 0 ? undefined : input.allowed_domains,
    env.LAUNCHDARKLY_ALLOWED_DOMAINS,
    ["allowed_domains", "domains"],
  )).map((domain) => domain.toLowerCase().replace(/^@/, ""));

  const projectKeys = normalizeStringList(pick(
    "projects",
    Array.isArray(input.project_keys) && input.project_keys.length === 0 ? undefined : input.project_keys,
    env.LAUNCHDARKLY_PROJECTS,
    ["projects", "project_keys"],
  ));

  if (configFile.present && !sourceChain.some((item) => item.startsWith("config-"))) {
    sourceChain.push("config-file-present");
  }

  return {
    token,
    baseUrl,
    apiVersion,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    allowedDomains: uniqueStrings(allowedDomains),
    projectKeys: uniqueStrings(projectKeys),
    configPath,
    sourceChain: uniqueStrings(sourceChain),
  };
}

function extractItems(payload: JsonRecord): JsonRecord[] {
  return asRecordArray(payload.items);
}

function launchdarklyErrorDetail(payload: JsonRecord | undefined, rawText: string): string | undefined {
  if (payload) {
    const code = asString(payload.code);
    const message = asString(payload.message);
    if (code && message) return `${code}: ${message}`;
    if (message) return message;
    if (code) return code;
  }
  const trimmed = rawText.trim();
  return trimmed.length > 0 ? trimmed.slice(0, 240) : undefined;
}

function parseJsonSafely(text: string): JsonRecord | undefined {
  if (text.trim().length === 0) return {};
  try {
    return asObject(JSON.parse(text)) ?? {};
  } catch {
    return undefined;
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function redactEnvironment(environment: JsonRecord): JsonRecord {
  return {
    ...environment,
    apiKey: maskSecret(environment.apiKey),
    mobileKey: maskSecret(environment.mobileKey),
  };
}

function redactSdkKey(sdkKey: JsonRecord): JsonRecord {
  return { ...sdkKey, value: maskSecret(sdkKey.value) };
}

function redactWebhook(webhook: JsonRecord): JsonRecord {
  const secret = asString(webhook.secret);
  return { ...webhook, secret: secret ? "[REDACTED]" : undefined };
}

function redactRelayConfig(relayConfig: JsonRecord): JsonRecord {
  return { ...relayConfig, fullKey: maskSecret(relayConfig.fullKey) };
}

function redactIntegrationSubscription(subscription: JsonRecord): JsonRecord {
  const config = asObject(subscription.config);
  const redactedConfig = config
    ? Object.fromEntries(Object.entries(config).map(([key, value]) =>
      /key|secret|token|password/i.test(key) ? [key, maskSecret(value)] : [key, value]))
    : undefined;
  return {
    ...subscription,
    apiKey: maskSecret(subscription.apiKey),
    config: redactedConfig,
  };
}

export class LaunchdarklyApiClient {
  private readonly config: LaunchdarklyResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: SleepImpl;
  private readonly maxRetries: number;
  private pauseUntil = 0;

  constructor(
    config: LaunchdarklyResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: SleepImpl;
      maxRetries?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? defaultSleep;
    this.maxRetries = clampNumber(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
  }

  getResolvedConfig(): LaunchdarklyResolvedConfig {
    return this.config;
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
      ? new URL(pathOrUrl)
      : new URL(pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`, `${this.config.baseUrl}/`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private redact(message: string): string {
    return redactTokenText(message, this.config.token);
  }

  private recordRateLimitHeaders(headers: Headers): void {
    const remainingHeaders = [
      ["x-ratelimit-route-remaining", "x-ratelimit-reset"],
      ["x-ratelimit-global-remaining", "x-ratelimit-reset"],
      ["x-ratelimit-auth-token-remaining", "x-ratelimit-auth-token-reset"],
    ];
    for (const [remainingHeader, resetHeader] of remainingHeaders) {
      const remaining = asNumber(headers.get(remainingHeader));
      const reset = asNumber(headers.get(resetHeader));
      if (remaining !== undefined && remaining <= 0 && reset !== undefined) {
        this.pauseUntil = Math.max(this.pauseUntil, Math.min(reset, Date.now() + MAX_RATE_LIMIT_WAIT_MS));
      }
    }
  }

  private rateLimitWaitMs(headers: Headers, attempt: number): number {
    const reset = asNumber(headers.get("x-ratelimit-auth-token-reset")) ?? asNumber(headers.get("x-ratelimit-reset"));
    if (reset !== undefined) {
      return Math.min(Math.max(reset - Date.now(), 0), MAX_RATE_LIMIT_WAIT_MS);
    }
    const retryAfterSeconds = asNumber(headers.get("retry-after"));
    if (retryAfterSeconds !== undefined) {
      return Math.min(Math.max(retryAfterSeconds * 1000, 0), MAX_RATE_LIMIT_WAIT_MS);
    }
    return Math.min(500 * 2 ** attempt, MAX_RATE_LIMIT_WAIT_MS);
  }

  private async fetchJson(url: string, options: { apiVersion?: string } = {}): Promise<JsonRecord> {
    const pathname = new URL(url).pathname;
    for (let attempt = 0; ; attempt += 1) {
      const pause = this.pauseUntil - Date.now();
      if (pause > 0) await this.sleep(Math.min(pause, MAX_RATE_LIMIT_WAIT_MS));

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
      let response: Response;
      let rawText: string;
      try {
        response = await this.fetchImpl(url, {
          method: "GET",
          headers: {
            accept: "application/json",
            authorization: this.config.token,
            "ld-api-version": options.apiVersion ?? this.config.apiVersion,
            "user-agent": "grclanker-launchdarkly-inspector",
          },
          signal: controller.signal,
        });
        rawText = await response.text();
      } catch (error) {
        const timedOut = error instanceof Error && error.name === "AbortError";
        if (attempt < this.maxRetries) {
          await this.sleep(Math.min(500 * 2 ** attempt, MAX_RATE_LIMIT_WAIT_MS));
          continue;
        }
        const detail = timedOut ? `timed out after ${this.config.timeoutMs}ms` : errorMessage(error);
        throw new Error(this.redact(`LaunchDarkly request failed for GET ${pathname}: ${detail}`));
      } finally {
        clearTimeout(timer);
      }

      this.recordRateLimitHeaders(response.headers);

      if (response.status === 429 && attempt < this.maxRetries) {
        await this.sleep(this.rateLimitWaitMs(response.headers, attempt));
        continue;
      }
      if (response.status >= 500 && attempt < this.maxRetries) {
        await this.sleep(Math.min(500 * 2 ** attempt, MAX_RATE_LIMIT_WAIT_MS));
        continue;
      }

      const payload = parseJsonSafely(rawText);
      if (!response.ok) {
        const detail = launchdarklyErrorDetail(payload, rawText);
        throw new Error(this.redact(
          `LaunchDarkly request failed (${response.status} ${response.statusText}) for GET ${pathname}${detail ? `: ${detail}` : ""}`,
        ));
      }
      if (!payload) {
        throw new Error(this.redact(`LaunchDarkly response for GET ${pathname} was not valid JSON.`));
      }
      return payload;
    }
  }

  async get(path: string, query: JsonRecord = {}, options: { apiVersion?: string } = {}): Promise<JsonRecord> {
    return this.fetchJson(this.buildUrl(path, query), options);
  }

  async list(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number; apiVersion?: string } = {},
  ): Promise<LaunchdarklyCollection> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 50_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 100);
    const items: JsonRecord[] = [];
    let offset = 0;
    let total: number | undefined;
    let remaining = false;
    let nextUrl: string | undefined = this.buildUrl(path, { ...query, limit: Math.min(pageSize, limit), offset });

    while (nextUrl) {
      if (items.length >= limit) {
        remaining = true;
        break;
      }
      const payload = await this.fetchJson(nextUrl, options);
      const pageItems = extractItems(payload);
      const room = limit - items.length;
      items.push(...pageItems.slice(0, room));
      total = asNumber(payload.totalCount) ?? total;
      if (pageItems.length > room) {
        remaining = true;
        break;
      }
      if (pageItems.length === 0) break;
      offset += pageItems.length;

      const nextHref = asString(asObject(asObject(payload._links)?.next)?.href);
      if (nextHref) {
        nextUrl = this.buildUrl(nextHref);
      } else if (total !== undefined && offset < total && pageItems.length >= Math.min(pageSize, limit)) {
        nextUrl = this.buildUrl(path, { ...query, limit: Math.min(pageSize, limit - items.length), offset });
      } else {
        nextUrl = undefined;
      }
    }

    return {
      items,
      truncated: total !== undefined ? total > items.length : remaining,
      seen: items.length,
      total,
    };
  }

  private async getItems(path: string, query: JsonRecord = {}, options: { apiVersion?: string } = {}): Promise<JsonRecord[]> {
    return extractItems(await this.get(path, query, options));
  }

  async getCallerIdentity(): Promise<JsonRecord> {
    return this.get("/api/v2/caller-identity");
  }

  async listMembers(limit = DEFAULT_MEMBER_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list("/api/v2/members", {}, { limit });
  }

  async getMember(memberId: string): Promise<JsonRecord> {
    return this.get(`/api/v2/members/${encodeURIComponent(memberId)}`);
  }

  async listTeams(limit = DEFAULT_TEAM_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list("/api/v2/teams", { expand: "members" }, { limit });
  }

  async listTeamRoles(teamKey: string, limit = DEFAULT_ROLE_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list(`/api/v2/teams/${encodeURIComponent(teamKey)}/roles`, {}, { limit });
  }

  async listCustomRoles(limit = DEFAULT_ROLE_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list("/api/v2/roles", {}, { limit });
  }

  async listProjects(limit = DEFAULT_PROJECT_LIMIT, projectKeys: string[] = []): Promise<LaunchdarklyCollection> {
    const filter = projectKeys.length > 0 ? `keys:${projectKeys.join("|")}` : undefined;
    return this.list("/api/v2/projects", { filter }, { limit });
  }

  async listEnvironments(projectKey: string, limit = DEFAULT_ENVIRONMENT_LIMIT): Promise<LaunchdarklyCollection> {
    const environments = await this.list(`/api/v2/projects/${encodeURIComponent(projectKey)}/environments`, {}, { limit });
    return { ...environments, items: environments.items.map(redactEnvironment) };
  }

  async listSdkKeys(projectKey: string, environmentKey: string, limit = 100): Promise<LaunchdarklyCollection> {
    const sdkKeys = await this.list(
      `/api/v2/projects/${encodeURIComponent(projectKey)}/environments/${encodeURIComponent(environmentKey)}/sdk-keys`,
      {},
      { limit, apiVersion: BETA_API_VERSION },
    );
    return { ...sdkKeys, items: sdkKeys.items.map(redactSdkKey) };
  }

  async listFlags(projectKey: string, environmentKey: string, limit = DEFAULT_FLAG_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list(
      `/api/v2/flags/${encodeURIComponent(projectKey)}`,
      { env: environmentKey, summary: "0" },
      { limit, pageSize: FLAG_PAGE_SIZE },
    );
  }

  async listFlagStatuses(projectKey: string, environmentKey: string): Promise<JsonRecord[]> {
    return this.getItems(
      `/api/v2/flag-statuses/${encodeURIComponent(projectKey)}/${encodeURIComponent(environmentKey)}`,
    );
  }

  async listAuditLogEntries(
    query: { before?: number; after?: number; spec?: string; q?: string } = {},
    limit = AUDIT_LOG_PAGE_SIZE,
  ): Promise<LaunchdarklyCollection> {
    return this.list(
      "/api/v2/auditlog",
      { before: query.before, after: query.after, spec: query.spec, q: query.q },
      { limit, pageSize: Math.min(limit, AUDIT_LOG_PAGE_SIZE) },
    );
  }

  async listTokens(limit = DEFAULT_TOKEN_LIMIT): Promise<LaunchdarklyCollection> {
    return this.list("/api/v2/tokens", { showAll: "true" }, { limit });
  }

  async listWebhooks(): Promise<JsonRecord[]> {
    const webhooks = await this.getItems("/api/v2/webhooks");
    return webhooks.map(redactWebhook);
  }

  async listIntegrationSubscriptions(integrationKey: string): Promise<JsonRecord[]> {
    const subscriptions = await this.getItems(`/api/v2/integrations/${encodeURIComponent(integrationKey)}`);
    return subscriptions.map(redactIntegrationSubscription);
  }

  async listRelayProxyConfigs(): Promise<JsonRecord[]> {
    const relayConfigs = await this.getItems("/api/v2/account/relay-auto-configs");
    return relayConfigs.map(redactRelayConfig);
  }
}

type IdentityClient = Pick<
  LaunchdarklyApiClient,
  "getResolvedConfig" | "listMembers" | "listTeams" | "listTeamRoles" | "listAuditLogEntries"
>;

type AccessControlClient = Pick<
  LaunchdarklyApiClient,
  "getResolvedConfig" | "getCallerIdentity" | "listCustomRoles" | "listTokens" | "listMembers"
>;

type EnvironmentGovernanceClient = Pick<
  LaunchdarklyApiClient,
  "getResolvedConfig" | "listProjects" | "listEnvironments" | "listSdkKeys" | "listCustomRoles"
>;

type FlagHygieneClient = Pick<
  LaunchdarklyApiClient,
  "getResolvedConfig" | "listProjects" | "listEnvironments" | "listFlags" | "listFlagStatuses"
>;

type MonitoringClient = Pick<
  LaunchdarklyApiClient,
  | "getResolvedConfig"
  | "listAuditLogEntries"
  | "listRelayProxyConfigs"
  | "listIntegrationSubscriptions"
  | "listWebhooks"
  | "listProjects"
  | "listEnvironments"
>;

type AccessCheckClient = Pick<
  LaunchdarklyApiClient,
  | "getResolvedConfig"
  | "getCallerIdentity"
  | "listMembers"
  | "listTeams"
  | "listCustomRoles"
  | "listProjects"
  | "listEnvironments"
  | "listFlags"
  | "listTokens"
  | "listAuditLogEntries"
  | "listWebhooks"
  | "listRelayProxyConfigs"
  | "listIntegrationSubscriptions"
>;

export type LaunchdarklyAuditClient = IdentityClient
  & AccessControlClient
  & EnvironmentGovernanceClient
  & FlagHygieneClient
  & MonitoringClient
  & AccessCheckClient;

async function readableSurface(
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<LaunchdarklyAccessSurface> {
  try {
    const value = await load();
    return {
      name,
      endpoint,
      status: "readable",
      count: countResolver?.(value),
    };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      error: errorMessage(error),
    };
  }
}

function toCollection(value: unknown): LaunchdarklyCollection {
  if (Array.isArray(value)) {
    const items = asRecordArray(value);
    return { items, truncated: false, seen: items.length };
  }
  const record = asObject(value);
  const items = asRecordArray(record?.items);
  const total = asNumber(record?.total);
  return {
    items,
    truncated: asBoolean(record?.truncated) === true || (total !== undefined && total > items.length),
    seen: items.length,
    total,
  };
}

function listCount(value: unknown): number | undefined {
  if (Array.isArray(value)) return value.length;
  const items = asObject(value)?.items;
  return Array.isArray(items) ? items.length : undefined;
}

function parseCallerIdentity(payload: JsonRecord): LaunchdarklyCallerIdentity {
  return {
    accountId: asString(payload.accountId),
    memberId: asString(payload.memberId),
    tokenId: asString(payload.tokenId),
    tokenName: asString(payload.tokenName),
    tokenKind: asString(payload.tokenKind),
    authKind: asString(payload.authKind),
    serviceToken: asBoolean(payload.serviceToken),
  };
}

export async function checkLaunchdarklyAccess(client: AccessCheckClient): Promise<LaunchdarklyAccessCheckResult> {
  const config = client.getResolvedConfig();
  let callerIdentity: LaunchdarklyCallerIdentity = {};
  const callerSurface = await readableSurface("caller_identity", "/api/v2/caller-identity", async () => {
    const payload = await client.getCallerIdentity();
    callerIdentity = parseCallerIdentity(payload);
    return payload;
  }, () => 1);

  let firstProjectKey: string | undefined;
  const projectsSurface = await readableSurface("projects", "/api/v2/projects", async () => {
    const projects = toCollection(await client.listProjects(5, config.projectKeys));
    firstProjectKey = asString(projects.items[0]?.key);
    return projects;
  }, listCount);

  let firstEnvironmentKey: string | undefined;
  const environmentsSurface = firstProjectKey
    ? await readableSurface("environments", "/api/v2/projects/{projectKey}/environments", async () => {
      const environments = toCollection(await client.listEnvironments(firstProjectKey ?? "", 5));
      firstEnvironmentKey = asString(environments.items[0]?.key);
      return environments;
    }, listCount)
    : { name: "environments", endpoint: "/api/v2/projects/{projectKey}/environments", status: "not_configured" as const, error: "No project was readable." };

  const flagsSurface = firstProjectKey && firstEnvironmentKey
    ? await readableSurface("flags", "/api/v2/flags/{projectKey}", () => client.listFlags(firstProjectKey ?? "", firstEnvironmentKey ?? "", 5), listCount)
    : { name: "flags", endpoint: "/api/v2/flags/{projectKey}", status: "not_configured" as const, error: "No project environment was readable." };

  const surfaces: LaunchdarklyAccessSurface[] = [
    callerSurface,
    await readableSurface("members", "/api/v2/members", () => client.listMembers(5), listCount),
    await readableSurface("teams", "/api/v2/teams", () => client.listTeams(5), listCount),
    await readableSurface("custom_roles", "/api/v2/roles", () => client.listCustomRoles(5), listCount),
    projectsSurface,
    environmentsSurface,
    flagsSurface,
    await readableSurface("access_tokens", "/api/v2/tokens", () => client.listTokens(5), listCount),
    await readableSurface("audit_log", "/api/v2/auditlog", () => client.listAuditLogEntries({}, 5), listCount),
    await readableSurface("webhooks", "/api/v2/webhooks", () => client.listWebhooks(), listCount),
    await readableSurface("relay_proxy_configs", "/api/v2/account/relay-auto-configs", () => client.listRelayProxyConfigs(), listCount),
    await readableSurface("integration_subscriptions", "/api/v2/integrations/{integrationKey}", () => client.listIntegrationSubscriptions(DEFAULT_INTEGRATION_KEYS[0]), listCount),
  ];

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const coreReadable = surfaces
    .filter((surface) => CORE_ACCESS_SURFACES.has(surface.name))
    .every((surface) => surface.status === "readable");
  const status = coreReadable ? "healthy" : "limited";

  return {
    status,
    baseUrl: config.baseUrl,
    callerIdentity,
    surfaces,
    notes: [
      `Using LaunchDarkly instance ${config.baseUrl} with API version ${config.apiVersion}.`,
      `Authenticated as ${callerIdentity.tokenName ?? callerIdentity.tokenId ?? "unknown token"} (${callerIdentity.serviceToken ? "service token" : "personal token"}, member ${callerIdentity.memberId ?? "n/a"}).`,
      `Config precedence resolved from: ${config.sourceChain.join(" -> ")}.`,
      `${readableCount}/${surfaces.length} LaunchDarkly audit surfaces are readable (webhooks, Relay Proxy configs, and integration subscriptions are optional).`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run launchdarkly_assess_identity, launchdarkly_assess_access_control, launchdarkly_assess_environment_governance, launchdarkly_assess_flag_hygiene, launchdarkly_assess_monitoring_integrations, or launchdarkly_export_audit_bundle."
        : "Use an access token with the Reader base role (Admin or Owner for showAll token listing and audit log depth), or a custom role with reader base permissions plus viewProject on the audited projects, then rerun the access check.",
  };
}

function buildFinding(
  controlNumber: number,
  status: LaunchdarklyFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): LaunchdarklyFinding {
  const definition = LAUNCHDARKLY_CONTROL_CATALOG[controlNumber];
  if (!definition) {
    throw new Error(`Unknown LaunchDarkly control ${controlNumber}`);
  }
  return {
    id: `LD-${String(controlNumber).padStart(2, "0")}`,
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: FRAMEWORK_ORDER.map((framework) => `${frameworkLabel(framework)} ${definition.frameworks[framework]}`),
    frameworks: { ...definition.frameworks },
  };
}

async function collect<T>(errors: string[], label: string, load: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await load();
  } catch (error) {
    errors.push(`${label}: ${errorMessage(error)}`);
    return fallback;
  }
}

async function collectList(
  errors: string[],
  label: string,
  load: () => Promise<LaunchdarklyCollection | JsonRecord[]>,
): Promise<LaunchdarklyCollection> {
  return toCollection(await collect<LaunchdarklyCollection | JsonRecord[]>(errors, label, load, []));
}

function truncationNote(
  collection: string,
  option: string | undefined,
  result: LaunchdarklyCollection,
  scope?: string,
): LaunchdarklyTruncationNote[] {
  if (!result.truncated) return [];
  return [{
    collection,
    ...(option ? { option } : {}),
    seen: result.seen,
    total: result.total ?? null,
    ...(scope ? { scope } : {}),
  }];
}

function truncationCaveat(notes: LaunchdarklyTruncationNote[]): string {
  const parts = notes.map((note) =>
    `${note.collection}${note.scope ? ` for ${note.scope}` : ""} (${note.seen} of ${note.total ?? "an unknown total"} collected)`);
  const options = uniqueStrings(notes.map((note) => note.option).filter((option): option is string => Boolean(option)));
  const remedy = options.length > 0
    ? `raise ${options.join(" and ")} and rerun for a complete evaluation`
    : "review the uncollected items manually";
  return `Truncated listing: ${parts.join("; ")}. The verdict covers only the collected items, so ${remedy}.`;
}

type FindingBuilder = (
  controlNumber: number,
  status: LaunchdarklyFindingStatus,
  summary: string,
  evidence?: JsonRecord,
) => LaunchdarklyFinding;

function truncationAwareFinding(notes: LaunchdarklyTruncationNote[]): FindingBuilder {
  if (notes.length === 0) return buildFinding;
  return (controlNumber, status, summary, evidence) => buildFinding(
    controlNumber,
    status === "pass" ? "warn" : status,
    `${summary} ${truncationCaveat(notes)}`,
    { ...(evidence ?? {}), truncated_collections: notes },
  );
}

function collectionSnapshot(result: LaunchdarklyCollection, items: unknown[] = result.items): JsonRecord {
  return { truncated: result.truncated, seen: result.seen, total: result.total ?? null, items };
}

function memberEmail(member: JsonRecord): string {
  return asString(member.email) ?? asString(member._id) ?? "unknown-member";
}

function memberDomain(member: JsonRecord): string | undefined {
  const email = asString(member.email);
  const at = email?.lastIndexOf("@") ?? -1;
  return email && at >= 0 ? email.slice(at + 1).toLowerCase() : undefined;
}

function isPendingMember(member: JsonRecord): boolean {
  return asBoolean(member._pendingInvite) === true;
}

function memberBaseRole(member: JsonRecord): string {
  return (asString(member.role) ?? "").toLowerCase();
}

function auditActions(entry: JsonRecord): string[] {
  return asRecordArray(entry.accesses).map((access) => asString(access.action)).filter((action): action is string => Boolean(action));
}

export async function assessLaunchdarklyIdentity(
  client: IdentityClient,
  options: LaunchdarklyIdentityOptions = {},
): Promise<LaunchdarklyAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const memberLimit = clampNumber(options.memberLimit, DEFAULT_MEMBER_LIMIT, 1, 50_000);
  const teamLimit = clampNumber(options.teamLimit, DEFAULT_TEAM_LIMIT, 1, 1000);
  const maxOwners = clampNumber(options.maxOwners, DEFAULT_MAX_OWNERS, 1, 100);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10_000);
  const allowedDomains = uniqueStrings(
    (options.allowedDomains && options.allowedDomains.length > 0 ? options.allowedDomains : config.allowedDomains)
      .map((domain) => domain.toLowerCase().replace(/^@/, "")),
  );

  const [memberCollection, teamCollection, accountAuditCollection] = await Promise.all([
    collectList(errors, "members", () => client.listMembers(memberLimit)),
    collectList(errors, "teams", () => client.listTeams(teamLimit)),
    collectList(errors, "audit_log_account", () => client.listAuditLogEntries({ spec: "acct" }, AUDIT_LOG_PAGE_SIZE)),
  ]);
  const members = memberCollection.items;
  const teams = teamCollection.items;
  const accountAuditEntries = accountAuditCollection.items;

  const teamRoles = await Promise.all(teams.slice(0, teamLimit).map(async (team) => {
    const key = asString(team.key) ?? "";
    const roleCollection = key
      ? await collectList(errors, `team_roles:${key}`, () => client.listTeamRoles(key))
      : toCollection([]);
    return { key, name: asString(team.name) ?? key, roles: roleCollection.items, collection: roleCollection };
  }));

  const memberNotes = truncationNote("members", "member_limit", memberCollection);
  const teamNotes = truncationNote("teams", "team_limit", teamCollection);
  const teamRoleNotes = teamRoles.flatMap((team) => truncationNote("team_roles", "role_limit", team.collection, `team ${team.key}`));
  const memberFinding = truncationAwareFinding(memberNotes);
  const membershipFinding = truncationAwareFinding([...memberNotes, ...teamNotes]);
  const teamRoleFinding = truncationAwareFinding([...teamNotes, ...teamRoleNotes]);

  const activeMembers = members.filter((member) => !isPendingMember(member));
  const pendingMembers = members.filter(isPendingMember);
  const scimProvisioned = activeMembers.filter((member) => asObject(member._integrationMetadata) !== undefined);
  const passwordMembers = activeMembers.filter((member) => asBoolean(member.hasPassword) === true);
  const passwordDataMembers = activeMembers.filter((member) => asBoolean(member.hasPassword) !== undefined);
  const oauthMembers = activeMembers.filter((member) => asStringArray(member.oauthProviders).length > 0);
  const ssoAuditEvents = accountAuditEntries.filter((entry) => auditActions(entry).some((action) => SSO_AUDIT_ACTIONS.has(action)));

  const membersWithoutMfa = activeMembers.filter((member) => (asString(member.mfa) ?? "").toLowerCase() !== "enabled");
  const mfaEnforcedMembers = activeMembers.filter((member) => asBoolean(member.mfaEnforced) === true);

  const owners = members.filter((member) => memberBaseRole(member) === "owner");
  const admins = members.filter((member) => memberBaseRole(member) === "admin");

  const orphanedMembers = activeMembers.filter((member) => asRecordArray(member.teams).length === 0);
  const teamsWithoutCustomRoles = teamRoles.filter((team) => team.roles.length === 0);

  const domainCounts = new Map<string, number>();
  for (const member of activeMembers) {
    const domain = memberDomain(member);
    if (domain) domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + 1);
  }
  const domainDistribution = [...domainCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([domain, count]) => ({ domain, members: count }));
  const offDomainMembers = allowedDomains.length > 0
    ? activeMembers.filter((member) => {
      const domain = memberDomain(member);
      return !domain || !allowedDomains.includes(domain);
    })
    : [];

  const findings: LaunchdarklyFinding[] = [
    memberFinding(
      1,
      "manual",
      [
        "The LaunchDarkly REST API does not expose the account SSO/SAML enforcement setting.",
        "Confirm in Organization settings > Security that SAML SSO is enabled and Require SSO is on, then capture a screenshot or the SCIM/IdP configuration as evidence.",
        scimProvisioned.length > 0
          ? `${scimProvisioned.length}/${activeMembers.length} active members are SCIM/IdP provisioned, which supports an SSO deployment.`
          : "No active members exposed IdP provisioning metadata.",
        passwordDataMembers.length > 0
          ? `${passwordMembers.length}/${passwordDataMembers.length} members with password data still have a LaunchDarkly password set.`
          : "Member password state was not exposed by the API.",
        ssoAuditEvents.length > 0
          ? `${ssoAuditEvents.length} recent account audit entries touched SAML, SCIM, or MFA settings.`
          : "No recent account audit entries touched SAML, SCIM, or MFA settings.",
      ].join(" "),
      {
        active_members: activeMembers.length,
        scim_provisioned_members: scimProvisioned.length,
        members_with_password: passwordMembers.length,
        members_with_oauth_providers: oauthMembers.length,
        recent_sso_audit_events: sample(ssoAuditEvents.map((entry) => ({
          date: isoDate(asTimestamp(entry.date)),
          actions: auditActions(entry),
          title: asString(entry.title) ?? asString(entry.shortDescription),
        }))),
        manual_evidence: [
          "Organization settings > Security > SAML: Enable SSO and Require SSO are checked",
          "IdP application assignment export or SCIM provisioning configuration",
        ],
      },
    ),
    memberFinding(
      2,
      activeMembers.length === 0 ? "warn" : membersWithoutMfa.length === 0 ? "pass" : "fail",
      activeMembers.length === 0
        ? "No active members were readable, so MFA coverage could not be evaluated."
        : membersWithoutMfa.length === 0
          ? `All ${activeMembers.length} active members report MFA enabled (${mfaEnforcedMembers.length} under account enforcement). Confirm the account level Require MFA for new members setting in Organization settings > Security.`
          : `${membersWithoutMfa.length}/${activeMembers.length} active members do not have MFA enabled.`,
      {
        active_members: activeMembers.length,
        pending_invites: pendingMembers.length,
        members_without_mfa: sample(membersWithoutMfa.map(memberEmail)),
        mfa_enforced_members: mfaEnforcedMembers.length,
      },
    ),
    memberFinding(
      3,
      owners.length > maxOwners ? "fail" : admins.length > maxAdmins ? "warn" : members.length === 0 ? "warn" : "pass",
      owners.length > maxOwners
        ? `${owners.length} members hold the Owner base role, exceeding the configured maximum of ${maxOwners}.`
        : admins.length > maxAdmins
          ? `${owners.length} Owner and ${admins.length} Admin base role members were found; Admin count exceeds the configured maximum of ${maxAdmins}.`
          : members.length === 0
            ? "No members were readable, so Owner and Admin concentration could not be evaluated."
            : `${owners.length} Owner and ${admins.length} Admin base role members are within the configured thresholds (${maxOwners} owners, ${maxAdmins} admins).`,
      {
        owners: sample(owners.map(memberEmail)),
        admins: sample(admins.map(memberEmail)),
        max_owners: maxOwners,
        max_admins: maxAdmins,
        total_members: members.length,
      },
    ),
    membershipFinding(
      6,
      teams.length === 0
        ? "warn"
        : orphanedMembers.length === 0 ? "pass" : "fail",
      teams.length === 0
        ? "No teams exist, so team based access management is not in use and every member is effectively unassigned."
        : orphanedMembers.length === 0
          ? `All ${activeMembers.length} active members belong to at least one of ${teams.length} teams.`
          : `${orphanedMembers.length}/${activeMembers.length} active members are not assigned to any team.`,
      {
        teams: teams.length,
        orphaned_members: sample(orphanedMembers.map(memberEmail)),
      },
    ),
    teamRoleFinding(
      7,
      teams.length === 0
        ? "warn"
        : teamsWithoutCustomRoles.length === 0 ? "pass" : "fail",
      teams.length === 0
        ? "No teams exist, so permissions are granted through individual base roles instead of team assigned custom roles."
        : teamsWithoutCustomRoles.length === 0
          ? `All ${teamRoles.length} sampled teams have at least one custom role assigned; ${admins.length + owners.length} members still hold built-in Admin or Owner base roles.`
          : `${teamsWithoutCustomRoles.length}/${teamRoles.length} sampled teams have no custom roles assigned, so their members rely on built-in base roles.`,
      {
        teams_sampled: teamRoles.length,
        teams_without_custom_roles: sample(teamsWithoutCustomRoles.map((team) => team.key)),
        built_in_admin_or_owner_members: admins.length + owners.length,
        team_roles: sample(teamRoles.map((team) => ({ team: team.key, roles: team.roles.map((role) => asString(role.key) ?? asString(role.name)) }))),
      },
    ),
    memberFinding(
      24,
      allowedDomains.length === 0
        ? "manual"
        : offDomainMembers.length === 0 ? "pass" : "fail",
      allowedDomains.length === 0
        ? `No organization domain policy was supplied. Provide allowed_domains (or LAUNCHDARKLY_ALLOWED_DOMAINS) and compare against the observed member domains: ${domainDistribution.slice(0, 5).map((item) => `${item.domain} (${item.members})`).join(", ") || "none"}.`
        : offDomainMembers.length === 0
          ? `All ${activeMembers.length} active members use approved domains (${allowedDomains.join(", ")}).`
          : `${offDomainMembers.length}/${activeMembers.length} active members use email domains outside the approved list (${allowedDomains.join(", ")}).`,
      {
        allowed_domains: allowedDomains,
        domain_distribution: sample(domainDistribution),
        off_domain_members: sample(offDomainMembers.map(memberEmail)),
      },
    ),
  ];

  return {
    title: "LaunchDarkly identity posture",
    category: "identity",
    summary: {
      base_url: config.baseUrl,
      members: members.length,
      active_members: activeMembers.length,
      pending_invites: pendingMembers.length,
      members_without_mfa: membersWithoutMfa.length,
      owners: owners.length,
      admins: admins.length,
      teams: teams.length,
      orphaned_members: orphanedMembers.length,
      teams_without_custom_roles: teamsWithoutCustomRoles.length,
      allowed_domains: allowedDomains.length,
      off_domain_members: offDomainMembers.length,
      truncated_collections: memberNotes.length + teamNotes.length + teamRoleNotes.length,
      evaluated_at: new Date(now).toISOString(),
    },
    findings,
    errors,
    snapshots: {
      members: collectionSnapshot(memberCollection),
      teams: collectionSnapshot(teamCollection),
      team_roles: teamRoles.map((team) => ({ team: team.key, name: team.name, ...collectionSnapshot(team.collection) })),
      audit_log_account: collectionSnapshot(accountAuditCollection),
    },
  };
}

function parseStatements(value: unknown): PolicyStatement[] {
  return asRecordArray(value).map((statement) => ({
    effect: (asString(statement.effect) ?? "allow").toLowerCase() === "deny" ? "deny" : "allow",
    actions: asStringArray(statement.actions),
    notActions: asStringArray(statement.notActions),
    resources: asStringArray(statement.resources),
    notResources: asStringArray(statement.notResources),
  }));
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${escaped}$`);
}

function actionMatches(pattern: string, action: string): boolean {
  if (pattern === "*") return true;
  if (!pattern.includes("*")) return pattern === action;
  return globToRegExp(pattern).test(action);
}

function isWildcardAction(pattern: string): boolean {
  return pattern.includes("*");
}

function statementUsesWildcardActions(statement: PolicyStatement): boolean {
  return statement.effect === "allow"
    && (statement.actions.some(isWildcardAction) || (statement.actions.length === 0 && statement.notActions.length > 0));
}

function resourceCoversType(resources: string[], notResources: string[], resourceType: string): boolean {
  const matchesType = (resource: string) => {
    const base = resource.split(";")[0];
    return base === "*" || base === resourceType || base.startsWith(`${resourceType}/`);
  };
  if (resources.length > 0) return resources.some(matchesType);
  if (notResources.length > 0) return !notResources.some((resource) => matchesType(resource) && resource.split(";")[0].endsWith("/*"));
  return false;
}

function statementCoversAction(statement: PolicyStatement, action: string): boolean {
  if (statement.actions.length > 0) return statement.actions.some((pattern) => actionMatches(pattern, action));
  if (statement.notActions.length > 0) return !statement.notActions.some((pattern) => actionMatches(pattern, action));
  return false;
}

function grantedSensitiveActions(statements: PolicyStatement[]): string[] {
  const granted: string[] = [];
  for (const group of SENSITIVE_ACTION_GROUPS) {
    for (const action of group.actions) {
      const allowed = statements.some((statement) =>
        statement.effect === "allow"
        && resourceCoversType(statement.resources, statement.notResources, group.resource)
        && statementCoversAction(statement, action));
      if (!allowed) continue;
      const denied = statements.some((statement) =>
        statement.effect === "deny"
        && resourceCoversType(statement.resources, statement.notResources, group.resource)
        && statementCoversAction(statement, action));
      if (!denied) granted.push(`${group.resource}:${action}`);
    }
  }
  return granted;
}

function roleKey(role: JsonRecord): string {
  return asString(role.key) ?? asString(role._id) ?? asString(role.name) ?? "role";
}

function tokenLabel(token: JsonRecord): string {
  const name = asString(token.name) ?? asString(token._id) ?? "token";
  const ending = asString(token.token);
  return ending ? `${name} (...${ending.slice(-4)})` : name;
}

function tokenRole(token: JsonRecord): string {
  return (asString(token.role) ?? "").toLowerCase();
}

function tokenHasCustomScope(token: JsonRecord): boolean {
  return asStringArray(token.customRoleIds).length > 0 || asRecordArray(token.inlineRole).length > 0;
}

const ADMIN_BASE_ROLES = new Set(["admin", "owner"]);
const BASE_ROLE_RANK: Record<string, number> = { no_access: 0, reader: 1, writer: 2, admin: 3, owner: 4 };

function baseRoleRank(role: string): number | undefined {
  return BASE_ROLE_RANK[role];
}

function knownMemberBaseRole(member: JsonRecord | undefined): string | undefined {
  const role = member ? memberBaseRole(member) : "";
  return role === "" ? undefined : role;
}

interface TokenInventory {
  scope: "full" | "partial" | "unknown";
  reason: string;
  remedy?: string;
  callerToken?: JsonRecord;
  callerTokenRole?: string;
  callerMemberRole?: string;
  visibleMemberIds: number;
}

function resolveTokenInventory(
  tokens: JsonRecord[],
  members: JsonRecord[],
  caller: LaunchdarklyCallerIdentity,
  callerReadable: boolean,
): TokenInventory {
  const callerToken = caller.tokenId ? tokens.find((token) => asString(token._id) === caller.tokenId) : undefined;
  const callerTokenRole = callerToken ? tokenRole(callerToken) : undefined;
  const callerMemberId = caller.memberId ?? (callerToken ? asString(callerToken.memberId) : undefined);
  const callerMemberRole = knownMemberBaseRole(callerMemberId ? members.find((member) => asString(member._id) === callerMemberId) : undefined);
  const personalMemberIds = new Set(tokens
    .filter((token) => asBoolean(token.serviceToken) !== true)
    .map((token) => asString(token.memberId))
    .filter((memberId): memberId is string => Boolean(memberId)));
  const base = { callerToken, callerTokenRole, callerMemberRole, visibleMemberIds: personalMemberIds.size };

  if (callerToken && callerTokenRole !== undefined) {
    if (tokenHasCustomScope(callerToken)) {
      return { ...base, scope: "partial", reason: "The assessment token is scoped by custom roles or an inline policy, so showAll returned only the caller's own personal tokens." };
    }
    if (!ADMIN_BASE_ROLES.has(callerTokenRole)) {
      return { ...base, scope: "partial", reason: `The assessment token has the ${callerTokenRole || "unknown"} base role; showAll returns other members' personal tokens only for Admin or Owner tokens.` };
    }
    if (asBoolean(callerToken.serviceToken) !== true) {
      if (callerMemberRole === undefined) {
        return { ...base, scope: "unknown", reason: `The assessment token carries the ${callerTokenRole} base role, but its member record could not be resolved from the member listing, so the member role that caps a personal token could not be confirmed.` };
      }
      if (!ADMIN_BASE_ROLES.has(callerMemberRole)) {
        return { ...base, scope: "partial", reason: `The assessment token carries the ${callerTokenRole} base role but its member holds the ${callerMemberRole} role, which caps the token below Admin.` };
      }
    }
    return { ...base, scope: "full", reason: `The assessment token has the ${callerTokenRole} base role, so showAll returned every member's personal tokens.` };
  }

  if (tokens.length === 0) {
    return { ...base, scope: "unknown", reason: "The token listing was empty even though the assessment token itself should appear in it, so the caller most likely lacks permission to list tokens." };
  }
  const otherMembers = caller.memberId ? [...personalMemberIds].filter((memberId) => memberId !== caller.memberId) : [];
  if (otherMembers.length > 0 || personalMemberIds.size > 1) {
    return { ...base, scope: "full", reason: `Personal tokens from ${Math.max(otherMembers.length, personalMemberIds.size - 1)} other members are visible, which only Admin or Owner tokens can list.` };
  }
  if (!callerReadable) {
    return { ...base, scope: "unknown", reason: "The caller identity could not be read and every visible personal token belongs to a single member, so the listing may contain only the caller's own tokens." };
  }
  return { ...base, scope: "unknown", reason: "The assessment token was not present in the listing and every visible personal token belongs to the caller, so the listing may contain only the caller's own tokens." };
}

function withTruncatedTokens(inventory: TokenInventory, tokens: LaunchdarklyCollection): TokenInventory {
  if (!tokens.truncated || inventory.scope === "partial") return inventory;
  return {
    ...inventory,
    scope: "partial",
    reason: `The token listing was truncated at ${tokens.seen} of ${tokens.total ?? "an unknown total"} tokens, so the uncollected tokens were not evaluated.`,
    remedy: "Raise token_limit and rerun for a complete inventory.",
  };
}

function tokenInventoryCaveat(inventory: TokenInventory): string {
  const prefix = inventory.scope === "partial" ? "Partial token inventory:" : "Token inventory completeness is unknown:";
  return `${prefix} ${inventory.reason} ${inventory.remedy ?? "Rerun with an Admin or Owner token for a complete inventory."}`;
}

export async function assessLaunchdarklyAccessControl(
  client: AccessControlClient,
  options: LaunchdarklyAccessControlOptions = {},
): Promise<LaunchdarklyAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const roleLimit = clampNumber(options.roleLimit, DEFAULT_ROLE_LIMIT, 1, 5000);
  const tokenLimit = clampNumber(options.tokenLimit, DEFAULT_TOKEN_LIMIT, 1, 10_000);
  const staleTokenDays = clampNumber(options.staleTokenDays, DEFAULT_STALE_TOKEN_DAYS, 1, 3650);

  const tokenErrors: string[] = [];
  const memberErrors: string[] = [];
  const callerErrors: string[] = [];
  const [roleCollection, tokenCollection, memberCollection, callerPayload] = await Promise.all([
    collectList(errors, "custom_roles", () => client.listCustomRoles(roleLimit)),
    collectList(tokenErrors, "access_tokens", () => client.listTokens(tokenLimit)),
    collectList(memberErrors, "members", () => client.listMembers(DEFAULT_MEMBER_LIMIT)),
    collect(callerErrors, "caller_identity", () => client.getCallerIdentity(), {} as JsonRecord),
  ]);
  errors.push(...tokenErrors, ...memberErrors, ...callerErrors);
  const roles = roleCollection.items;
  const tokens = tokenCollection.items;
  const members = memberCollection.items;
  const tokensReadable = tokenErrors.length === 0;
  const membersComplete = memberErrors.length === 0 && !memberCollection.truncated;
  const roleNotes = truncationNote("custom_roles", "role_limit", roleCollection);
  const tokenNotes = truncationNote("access_tokens", "token_limit", tokenCollection);
  const memberNotes = truncationNote("members", "member_limit", memberCollection);
  const roleFinding = truncationAwareFinding(roleNotes);
  const callerIdentity = parseCallerIdentity(callerPayload);
  const inventory = withTruncatedTokens(
    resolveTokenInventory(tokens, members, callerIdentity, callerErrors.length === 0),
    tokenCollection,
  );
  const inventoryEvidence: JsonRecord = {
    scope: inventory.scope,
    reason: inventory.reason,
    caller_token_role: inventory.callerTokenRole ?? null,
    caller_member_role: inventory.callerMemberRole ?? null,
    visible_tokens: tokens.length,
    total_tokens: tokenCollection.total ?? null,
    visible_personal_token_members: inventory.visibleMemberIds,
  };
  const degradeForInventory = tokensReadable && inventory.scope !== "full";
  const tokenFinding = (
    control: number,
    status: LaunchdarklyFindingStatus,
    summary: string,
    evidence: JsonRecord,
    extraNotes: LaunchdarklyTruncationNote[] = [],
  ): LaunchdarklyFinding => {
    const notes = [...tokenNotes, ...extraNotes];
    const degraded = degradeForInventory || extraNotes.length > 0;
    return buildFinding(
      control,
      degraded && status === "pass" ? "warn" : status,
      [
        summary,
        degradeForInventory ? tokenInventoryCaveat(inventory) : undefined,
        extraNotes.length > 0 ? truncationCaveat(extraNotes) : undefined,
      ].filter((part): part is string => Boolean(part)).join(" "),
      { ...evidence, token_inventory: inventoryEvidence, ...(notes.length > 0 ? { truncated_collections: notes } : {}) },
    );
  };

  const roleAnalyses = roles.map((role) => {
    const statements = parseStatements(role.policy);
    return {
      key: roleKey(role),
      basePermissions: (asString(role.basePermissions) ?? "").toLowerCase(),
      wildcardStatements: statements.filter(statementUsesWildcardActions),
      sensitiveGrants: grantedSensitiveActions(statements),
    };
  });
  const wildcardRoles = roleAnalyses.filter((role) => role.wildcardStatements.length > 0);
  const sensitiveRoles = roleAnalyses.filter((role) => role.sensitiveGrants.length > 0);
  const readerBaseRoles = roleAnalyses.filter((role) => role.basePermissions !== "no_access");

  const tokensWithoutExpiry = tokens.filter((token) => asTimestamp(token.expiry) === undefined);
  const staleTokens = tokens.filter((token) => {
    const lastUsed = asTimestamp(token.lastUsed);
    const created = asTimestamp(token.creationDate);
    const reference = lastUsed ?? created;
    return reference !== undefined && daysBetween(reference, now) > staleTokenDays;
  });

  const serviceTokens = tokens.filter((token) => asBoolean(token.serviceToken) === true);
  const personalTokens = tokens.filter((token) => asBoolean(token.serviceToken) !== true);
  const assessmentServiceToken = inventory.callerToken && asBoolean(inventory.callerToken.serviceToken) === true
    ? inventory.callerToken
    : undefined;
  const overScopedServiceTokens = serviceTokens.filter((token) =>
    !tokenHasCustomScope(token) && ADMIN_BASE_ROLES.has(tokenRole(token)));
  const overScopedOtherServiceTokens = overScopedServiceTokens.filter((token) => token !== assessmentServiceToken);
  const assessmentTokenOverScoped = overScopedServiceTokens.length !== overScopedOtherServiceTokens.length;
  const writerServiceTokens = serviceTokens.filter((token) =>
    !tokenHasCustomScope(token) && tokenRole(token) === "writer");
  const wildcardInlineTokens = serviceTokens.filter((token) => parseStatements(token.inlineRole).some(statementUsesWildcardActions));
  const serviceTokenIssues = [
    overScopedOtherServiceTokens.length > 0 ? `${overScopedOtherServiceTokens.length} use the Owner or Admin base role` : undefined,
    wildcardInlineTokens.length > 0 ? `${wildcardInlineTokens.length} use wildcard inline policies` : undefined,
    assessmentTokenOverScoped && assessmentServiceToken
      ? `the assessment token ${tokenLabel(assessmentServiceToken)} uses the ${tokenRole(assessmentServiceToken)} base role that LaunchDarkly requires for a complete token inventory, so keep it expiring, rotated, and dedicated to auditing`
      : undefined,
    writerServiceTokens.length > 0 ? `${writerServiceTokens.length} use the broad Writer base role instead of a custom role or inline policy` : undefined,
  ].filter((issue): issue is string => Boolean(issue));

  const membersById = new Map(members
    .map((member) => [asString(member._id), member] as const)
    .filter((entry): entry is readonly [string, JsonRecord] => Boolean(entry[0])));
  const unmatchedPersonalTokens = membersById.size > 0
    ? personalTokens.filter((token) => {
      const memberId = asString(token.memberId);
      return !memberId || !membersById.has(memberId);
    })
    : [];
  const orphanedPersonalTokens = membersComplete ? unmatchedPersonalTokens : [];
  const unverifiedPersonalTokens = membersComplete ? [] : unmatchedPersonalTokens;
  const overScopedPersonalTokens = personalTokens.flatMap((token) => {
    if (tokenHasCustomScope(token)) return [];
    const memberRole = knownMemberBaseRole(membersById.get(asString(token.memberId) ?? ""));
    const tokenRank = baseRoleRank(tokenRole(token));
    const memberRank = memberRole === undefined ? undefined : baseRoleRank(memberRole);
    if (tokenRank === undefined || memberRank === undefined || tokenRank <= memberRank) return [];
    return [{ token: tokenLabel(token), token_role: tokenRole(token), member_role: memberRole }];
  });

  const findings: LaunchdarklyFinding[] = [
    roleFinding(
      4,
      roles.length === 0 ? "warn" : wildcardRoles.length === 0 ? "pass" : "fail",
      roles.length === 0
        ? "No custom roles were readable; access is governed by built-in base roles only, so least privilege scoping cannot be demonstrated."
        : wildcardRoles.length === 0
          ? `All ${roles.length} custom roles enumerate explicit actions without wildcard or notActions grants.`
          : `${wildcardRoles.length}/${roles.length} custom roles contain allow statements with wildcard actions or open ended notActions grants.`,
      {
        custom_roles: roles.length,
        wildcard_roles: sample(wildcardRoles.map((role) => ({
          role: role.key,
          statements: role.wildcardStatements.map((statement) => ({ actions: statement.actions, notActions: statement.notActions, resources: statement.resources })),
        }))),
      },
    ),
    roleFinding(
      5,
      roles.length === 0
        ? "warn"
        : sensitiveRoles.length > 0 ? "fail" : readerBaseRoles.length > 0 ? "warn" : "pass",
      roles.length === 0
        ? "No custom roles were readable, so deny-by-default policy design could not be evaluated."
        : sensitiveRoles.length > 0
          ? `${sensitiveRoles.length}/${roles.length} custom roles allow sensitive account, member, role, token, relay, webhook, or team administration actions without an explicit deny.`
          : readerBaseRoles.length > 0
            ? `No custom role grants sensitive administration actions, but ${readerBaseRoles.length}/${roles.length} roles use reader base permissions instead of no_access.`
            : `All ${roles.length} custom roles start from no_access base permissions and do not allow sensitive administration actions.`,
      {
        custom_roles: roles.length,
        sensitive_roles: sample(sensitiveRoles.map((role) => ({ role: role.key, granted: sample(role.sensitiveGrants) }))),
        reader_base_permission_roles: sample(readerBaseRoles.map((role) => role.key)),
      },
    ),
    tokenFinding(
      8,
      tokens.length === 0 ? "warn" : tokensWithoutExpiry.length === 0 ? "pass" : "fail",
      tokens.length === 0
        ? "No access tokens were readable (use an Admin token so showAll returns every member's personal tokens)."
        : tokensWithoutExpiry.length === 0
          ? `All ${tokens.length} visible access tokens have an expiry configured.`
          : `${tokensWithoutExpiry.length}/${tokens.length} visible access tokens have no expiry configured.`,
      {
        tokens: tokens.length,
        tokens_without_expiry: sample(tokensWithoutExpiry.map(tokenLabel)),
      },
    ),
    tokenFinding(
      9,
      tokens.length === 0 ? "warn" : staleTokens.length === 0 ? "pass" : "fail",
      tokens.length === 0
        ? "No access tokens were readable, so token staleness could not be evaluated."
        : staleTokens.length === 0
          ? `All ${tokens.length} visible access tokens were used (or created) within the last ${staleTokenDays} days.`
          : `${staleTokens.length}/${tokens.length} visible access tokens have not been used in more than ${staleTokenDays} days.`,
      {
        stale_token_days: staleTokenDays,
        stale_tokens: sample(staleTokens.map((token) => ({
          token: tokenLabel(token),
          last_used: isoDate(asTimestamp(token.lastUsed)),
          created: isoDate(asTimestamp(token.creationDate)),
          service_token: asBoolean(token.serviceToken) === true,
        }))),
      },
    ),
    tokenFinding(
      10,
      !tokensReadable
        ? "warn"
        : serviceTokens.length === 0
          ? "pass"
          : overScopedOtherServiceTokens.length > 0 || wildcardInlineTokens.length > 0
            ? "fail"
            : assessmentTokenOverScoped || writerServiceTokens.length > 0 ? "warn" : "pass",
      !tokensReadable
        ? "Access tokens could not be read, so service token scoping could not be evaluated."
        : serviceTokens.length === 0
          ? "No service tokens are visible."
          : serviceTokenIssues.length > 0
            ? `Of ${serviceTokens.length} visible service tokens, ${serviceTokenIssues.join("; ")}.`
            : `All ${serviceTokens.length} visible service tokens use Reader, custom role, or scoped inline policy permissions.`,
      {
        service_tokens: serviceTokens.length,
        owner_or_admin_service_tokens: sample(overScopedOtherServiceTokens.map(tokenLabel)),
        assessment_service_token: assessmentServiceToken
          ? { token: tokenLabel(assessmentServiceToken), role: tokenRole(assessmentServiceToken), over_scoped: assessmentTokenOverScoped }
          : null,
        writer_service_tokens: sample(writerServiceTokens.map(tokenLabel)),
        wildcard_inline_policy_tokens: sample(wildcardInlineTokens.map(tokenLabel)),
      },
    ),
    tokenFinding(
      11,
      !tokensReadable
        ? "warn"
        : orphanedPersonalTokens.length > 0
          ? "fail"
          : overScopedPersonalTokens.length > 0 || unverifiedPersonalTokens.length > 0 ? "warn" : "pass",
      !tokensReadable
        ? "Access tokens could not be read, so personal token scope could not be evaluated."
        : orphanedPersonalTokens.length > 0
          ? `${orphanedPersonalTokens.length} visible personal tokens are not tied to a current account member.`
          : overScopedPersonalTokens.length > 0
            ? `${overScopedPersonalTokens.length}/${personalTokens.length} visible personal tokens carry a base role above their member's own role; personal tokens must stay within the member's scope.`
            : unverifiedPersonalTokens.length > 0
              ? `${unverifiedPersonalTokens.length}/${personalTokens.length} visible personal tokens could not be matched to a member in the truncated member listing, so orphaned tokens cannot be ruled out.`
              : personalTokens.length === 0
                ? "No personal tokens are visible."
                : `All ${personalTokens.length} visible personal tokens are tied to current members and stay within each member's base role scope.`,
      {
        personal_tokens: personalTokens.length,
        orphaned_personal_tokens: sample(orphanedPersonalTokens.map(tokenLabel)),
        unverified_personal_tokens: sample(unverifiedPersonalTokens.map(tokenLabel)),
        over_scoped_personal_tokens: sample(overScopedPersonalTokens),
      },
      memberNotes,
    ),
  ];

  return {
    title: "LaunchDarkly access control",
    category: "access_control",
    summary: {
      base_url: config.baseUrl,
      custom_roles: roles.length,
      wildcard_roles: wildcardRoles.length,
      sensitive_roles: sensitiveRoles.length,
      tokens: tokens.length,
      token_inventory_scope: inventory.scope,
      service_tokens: serviceTokens.length,
      personal_tokens: personalTokens.length,
      tokens_without_expiry: tokensWithoutExpiry.length,
      stale_tokens: staleTokens.length,
      truncated_collections: roleNotes.length + tokenNotes.length + memberNotes.length,
      evaluated_at: new Date(now).toISOString(),
    },
    findings,
    errors,
    snapshots: {
      custom_roles: collectionSnapshot(roleCollection),
      access_tokens: collectionSnapshot(tokenCollection),
    },
  };
}

function environmentKeyOf(environment: JsonRecord): string {
  return asString(environment.key) ?? asString(environment._id) ?? "environment";
}

interface EnvironmentInventory {
  projects: LaunchdarklyCollection;
  environments: EnvironmentContext[];
  environmentCollections: Array<{ projectKey: string; collection: LaunchdarklyCollection }>;
  notes: LaunchdarklyTruncationNote[];
}

async function collectEnvironmentContexts(
  client: Pick<LaunchdarklyApiClient, "listProjects" | "listEnvironments">,
  errors: string[],
  options: { projectLimit: number; environmentLimit: number; projectKeys: string[]; productionPattern: RegExp },
): Promise<EnvironmentInventory> {
  const projects = await collectList(
    errors,
    "projects",
    () => client.listProjects(options.projectLimit, options.projectKeys),
  );
  const environments: EnvironmentContext[] = [];
  const environmentCollections: EnvironmentInventory["environmentCollections"] = [];
  for (const project of projects.items) {
    const projectKey = asString(project.key);
    if (!projectKey) continue;
    const projectEnvironments = await collectList(
      errors,
      `environments:${projectKey}`,
      () => client.listEnvironments(projectKey, options.environmentLimit),
    );
    environmentCollections.push({ projectKey, collection: projectEnvironments });
    for (const environment of projectEnvironments.items) {
      const key = environmentKeyOf(environment);
      const name = asString(environment.name) ?? key;
      environments.push({
        projectKey,
        projectName: asString(project.name) ?? projectKey,
        projectTags: asStringArray(project.tags),
        environment,
        key,
        name,
        production: asBoolean(environment.critical) === true
          || options.productionPattern.test(key)
          || options.productionPattern.test(name),
      });
    }
  }
  const notes = [
    ...truncationNote("projects", "project_limit", projects),
    ...environmentCollections.flatMap((entry) =>
      truncationNote("environments", "environment_limit", entry.collection, `project ${entry.projectKey}`)),
  ];
  return { projects, environments, environmentCollections, notes };
}

function environmentsSnapshot(inventory: EnvironmentInventory): JsonRecord {
  const truncatedProjects = inventory.environmentCollections
    .filter((entry) => entry.collection.truncated)
    .map((entry) => entry.projectKey);
  const totals = inventory.environmentCollections.map((entry) => entry.collection.total);
  const total = totals.length > 0 && totals.every((value) => value !== undefined)
    ? totals.reduce((sum, value) => sum + (value ?? 0), 0)
    : null;
  return {
    truncated: truncatedProjects.length > 0,
    seen: inventory.environments.length,
    total,
    truncated_projects: truncatedProjects,
    items: inventory.environments.map((context) => ({ project: context.projectKey, production: context.production, ...context.environment })),
  };
}

function environmentLabel(context: EnvironmentContext): string {
  return `${context.projectKey}/${context.key}`;
}

type ApprovalWeakness = "bypass_pending_changes" | "self_review" | "declined_changes_applicable" | "tag_scoped_approvals";

interface ApprovalAnalysis {
  required: boolean;
  weaknesses: ApprovalWeakness[];
  settings: JsonRecord;
}

function analyzeApprovalSettings(value: unknown): ApprovalAnalysis {
  const raw = asObject(value);
  const requiredApprovalTags = asStringArray(raw?.requiredApprovalTags);
  const settings: JsonRecord = {
    required: asBoolean(raw?.required) === true,
    bypass_approvals_for_pending_changes: asBoolean(raw?.bypassApprovalsForPendingChanges) === true,
    can_review_own_request: asBoolean(raw?.canReviewOwnRequest) === true,
    can_apply_declined_changes: asBoolean(raw?.canApplyDeclinedChanges) === true,
    min_num_approvals: asNumber(raw?.minNumApprovals) ?? null,
    required_approval_tags: requiredApprovalTags,
    service_kind: asString(raw?.serviceKind) ?? null,
  };
  const weaknesses: ApprovalWeakness[] = [];
  if (settings.bypass_approvals_for_pending_changes === true) weaknesses.push("bypass_pending_changes");
  if (settings.can_review_own_request === true) weaknesses.push("self_review");
  if (settings.can_apply_declined_changes === true) weaknesses.push("declined_changes_applicable");
  if (requiredApprovalTags.length > 0) weaknesses.push("tag_scoped_approvals");
  return { required: settings.required === true, weaknesses, settings };
}

function approvalWeaknessLabel(weakness: ApprovalWeakness): string {
  switch (weakness) {
    case "bypass_pending_changes":
      return "pending changes can bypass approval";
    case "self_review":
      return "requesters can approve their own changes";
    case "declined_changes_applicable":
      return "changes can be applied after a single approval even when other reviewers declined";
    case "tag_scoped_approvals":
      return "approvals are required only for flags carrying specific tags, so untagged flags skip approval";
    default: {
      const exhaustive: never = weakness;
      return exhaustive;
    }
  }
}

function splitResourceSegments(resource: string): string[] {
  const segments: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of resource) {
    if (char === "{") depth += 1;
    if (char === "}") depth = Math.max(0, depth - 1);
    if (char === ":" && depth === 0) {
      segments.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function mergeBareSelectorSegments(segments: string[]): string[] {
  const merged: string[] = [];
  for (const segment of segments) {
    const trimmed = segment.trim();
    if (merged.length > 0 && trimmed !== "*" && !trimmed.includes("/")) {
      merged[merged.length - 1] = `${merged[merged.length - 1]}:${trimmed}`;
      continue;
    }
    merged.push(trimmed);
  }
  return merged;
}

function parseResourceSegment(raw: string): ResourceSegment {
  const [head, ...filterParts] = raw.replace(/^\/+/, "").split(";");
  const slash = head.indexOf("/");
  const type = (slash === -1 ? head : head.slice(0, slash)).toLowerCase();
  const name = slash === -1 ? "*" : head.slice(slash + 1);
  const tags: string[] = [];
  const selectors: Record<string, string> = {};
  for (const item of filterParts.join(";").split(",")) {
    const filter = item.trim();
    if (!filter) continue;
    const selector = filter.replace(/^\{/, "").replace(/\}$/, "");
    const colon = selector.indexOf(":");
    if (colon > 0) {
      selectors[selector.slice(0, colon).trim().toLowerCase()] = selector.slice(colon + 1).trim().toLowerCase();
    } else {
      tags.push(filter);
    }
  }
  return { type, name, tags, selectors };
}

function parseResourceSpecifier(resource: string): ResourceSegment[] {
  return mergeBareSelectorSegments(splitResourceSegments(resource.trim()))
    .filter((segment) => segment.length > 0)
    .map(parseResourceSegment);
}

function globMatches(pattern: string, value: string): boolean {
  return actionMatches(pattern.toLowerCase(), value.toLowerCase());
}

function tagsMatch(patterns: string[], tags: string[]): boolean {
  return patterns.every((pattern) => tags.some((tag) => globMatches(pattern, tag)));
}

function environmentSegmentMatches(segment: ResourceSegment, context: EnvironmentContext): boolean | undefined {
  if (!globMatches(segment.name, context.key)) return false;
  if (!tagsMatch(segment.tags, asStringArray(context.environment.tags))) return false;
  let unknownSelector = false;
  for (const [selector, value] of Object.entries(segment.selectors)) {
    if (selector === "critical") {
      const critical = asBoolean(context.environment.critical) === true;
      if ((value === "true") !== critical) return false;
    } else {
      unknownSelector = true;
    }
  }
  return unknownSelector ? undefined : true;
}

function projectSegmentMatches(segment: ResourceSegment | undefined, context: EnvironmentContext): boolean {
  if (!segment) return true;
  return globMatches(segment.name, context.projectKey) && tagsMatch(segment.tags, context.projectTags);
}

function resourceIsEnvironmentScoped(resource: string): boolean {
  return parseResourceSpecifier(resource).some((segment) => segment.type === "env");
}

function resourceRestrictsEnvironment(resource: string, context: EnvironmentContext): boolean {
  if (resource.trim() === "*") return true;
  const segments = parseResourceSpecifier(resource);
  const environment = segments.find((segment) => segment.type === "env");
  if (!environment || !projectSegmentMatches(segments.find((segment) => segment.type === "proj"), context)) return false;
  return environmentSegmentMatches(environment, context) === true;
}

function resourceCoversEnvironment(resource: string, context: EnvironmentContext): boolean {
  if (resource.trim() === "*") return true;
  const segments = parseResourceSpecifier(resource);
  const project = segments.find((segment) => segment.type === "proj");
  if (!project || !projectSegmentMatches(project, context)) return false;
  const environment = segments.find((segment) => segment.type === "env");
  if (!environment) return true;
  return environmentSegmentMatches(environment, context) !== false;
}

function statementCoversEnvironment(statement: PolicyStatement, context: EnvironmentContext): boolean {
  if (statement.resources.length > 0) {
    return statement.resources.some((resource) => resourceCoversEnvironment(resource, context));
  }
  if (statement.notResources.length > 0) {
    return !statement.notResources.some((resource) => resourceRestrictsEnvironment(resource, context));
  }
  return false;
}

function roleEnvironmentRestrictions(
  role: string,
  statements: PolicyStatement[],
  context: EnvironmentContext,
): EnvironmentRestriction[] {
  const restrictions: EnvironmentRestriction[] = [];
  for (const statement of statements) {
    if (statement.effect === "deny") {
      const resource = statement.resources.find((candidate) => resourceRestrictsEnvironment(candidate, context));
      if (resource) restrictions.push({ role, kind: "deny", resource });
      continue;
    }
    const excluded = statement.notResources.find((candidate) => resourceRestrictsEnvironment(candidate, context));
    if (excluded) restrictions.push({ role, kind: "not_resources", resource: excluded });
  }
  const allows = statements.filter((statement) => statement.effect === "allow");
  const scopedAllow = allows.find((statement) => statement.resources.some(resourceIsEnvironmentScoped));
  if (scopedAllow && !allows.some((statement) => statementCoversEnvironment(statement, context))) {
    restrictions.push({ role, kind: "scoped_elsewhere", resource: scopedAllow.resources.find(resourceIsEnvironmentScoped) ?? scopedAllow.resources[0] });
  }
  return restrictions;
}

function restrictionLabel(restriction: EnvironmentRestriction): string {
  switch (restriction.kind) {
    case "deny":
      return `${restriction.role}: deny ${restriction.resource}`;
    case "not_resources":
      return `${restriction.role}: allow excludes ${restriction.resource}`;
    case "scoped_elsewhere":
      return `${restriction.role}: allow scoped to ${restriction.resource}`;
    default: {
      const exhaustive: never = restriction.kind;
      return exhaustive;
    }
  }
}

export async function assessLaunchdarklyEnvironmentGovernance(
  client: EnvironmentGovernanceClient,
  options: LaunchdarklyEnvironmentGovernanceOptions = {},
): Promise<LaunchdarklyAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const productionPattern = buildRegex(options.productionPattern, DEFAULT_PRODUCTION_PATTERN);
  const testProjectPattern = buildRegex(options.testProjectPattern, DEFAULT_TEST_PROJECT_PATTERN);
  const sdkKeyMaxAgeDays = clampNumber(options.sdkKeyMaxAgeDays, DEFAULT_SDK_KEY_MAX_AGE_DAYS, 1, 3650);

  const inventory = await collectEnvironmentContexts(client, errors, {
    projectLimit: clampNumber(options.projectLimit, DEFAULT_PROJECT_LIMIT, 1, 1000),
    environmentLimit: clampNumber(options.environmentLimit, DEFAULT_ENVIRONMENT_LIMIT, 1, 500),
    projectKeys: options.projectKeys && options.projectKeys.length > 0 ? options.projectKeys : config.projectKeys,
    productionPattern,
  });
  const projects = inventory.projects.items;
  const environments = inventory.environments;
  const roleErrors: string[] = [];
  const roleCollection = await collectList(roleErrors, "custom_roles", () => client.listCustomRoles(DEFAULT_ROLE_LIMIT));
  errors.push(...roleErrors);
  const roles = roleCollection.items;
  const rolesReadable = roleErrors.length === 0;
  const roleStatements = roles.map((role) => ({ key: roleKey(role), statements: parseStatements(role.policy) }));

  const productionEnvironments = environments.filter((context) => context.production);
  const sdkKeyResults = await Promise.all(environments.map(async (context) => {
    const sdkKeyErrors: string[] = [];
    const collection = await collectList(
      sdkKeyErrors,
      `sdk_keys:${environmentLabel(context)}`,
      () => client.listSdkKeys(context.projectKey, context.key),
    );
    return { context, keys: collection.items, collection, readable: sdkKeyErrors.length === 0, error: sdkKeyErrors[0] };
  }));
  const unreadableSdkKeyEnvironments = sdkKeyResults.filter((result) => !result.readable);

  const roleNotes = truncationNote("custom_roles", "role_limit", roleCollection);
  const sdkKeyNotes = sdkKeyResults.flatMap((result) =>
    truncationNote("sdk_keys", undefined, result.collection, `environment ${environmentLabel(result.context)}`));
  const environmentFinding = truncationAwareFinding(inventory.notes);
  const restrictionFinding = truncationAwareFinding([...inventory.notes, ...roleNotes]);
  const sdkKeyFinding = truncationAwareFinding([...inventory.notes, ...sdkKeyNotes]);
  const staleSdkKeys = sdkKeyResults.flatMap((result) => result.keys
    .filter((key) => (asString(key.kind) ?? "sdk").toLowerCase() === "sdk")
    .filter((key) => {
      const created = asTimestamp(key._createdAt);
      const expiry = asTimestamp(key.expiry);
      return created !== undefined && daysBetween(created, now) > sdkKeyMaxAgeDays && (expiry === undefined || expiry > now + 30 * DAY_MS);
    })
    .map((key) => ({
      environment: environmentLabel(result.context),
      key: asString(key.key) ?? asString(key.name) ?? "sdk-key",
      created: isoDate(asTimestamp(key._createdAt)),
      age_days: daysBetween(asTimestamp(key._createdAt) ?? now, now),
      is_default: asBoolean(key.isDefault) === true,
    })));

  const productionRestrictions = productionEnvironments.map((context) => ({
    context,
    critical: asBoolean(context.environment.critical) === true,
    restrictions: roleStatements.flatMap((role) => roleEnvironmentRestrictions(role.key, role.statements, context)),
  }));
  const restrictedProduction = productionRestrictions.filter((entry) => entry.restrictions.length > 0);
  const criticalOnlyProduction = productionRestrictions.filter((entry) => entry.restrictions.length === 0 && entry.critical);
  const unrestrictedProduction = productionRestrictions
    .filter((entry) => entry.restrictions.length === 0 && !entry.critical)
    .map((entry) => entry.context);

  const approvalAnalyses = productionEnvironments.map((context) => ({
    context,
    approvals: analyzeApprovalSettings(context.environment.approvalSettings),
  }));
  const approvalsMissing = approvalAnalyses.filter((entry) => !entry.approvals.required).map((entry) => entry.context);
  const approvalsWeak = approvalAnalyses.filter((entry) => entry.approvals.required && entry.approvals.weaknesses.length > 0);
  const approvalWeaknessKinds = [...new Set(approvalsWeak.flatMap((entry) => entry.approvals.weaknesses))];

  const secureModeMissing = productionEnvironments.filter((context) => asBoolean(context.environment.secureMode) !== true);
  const ttlZero = productionEnvironments.filter((context) => (asNumber(context.environment.defaultTtl) ?? 0) <= 0);
  const changeSafeguardsMissing = productionEnvironments.filter((context) =>
    asBoolean(context.environment.confirmChanges) !== true || asBoolean(context.environment.requireComments) !== true);

  const testProjects = projects.filter((project) => {
    const haystack = [asString(project.key), asString(project.name), ...asStringArray(project.tags)].filter(Boolean).join(" ");
    return testProjectPattern.test(haystack);
  });

  const productionSummary = approvalAnalyses.map(({ context, approvals }) => ({
    environment: environmentLabel(context),
    critical: asBoolean(context.environment.critical) === true,
    secure_mode: asBoolean(context.environment.secureMode) === true,
    confirm_changes: asBoolean(context.environment.confirmChanges) === true,
    require_comments: asBoolean(context.environment.requireComments) === true,
    default_ttl: asNumber(context.environment.defaultTtl) ?? null,
    approvals_required: approvals.required,
    approval_settings: approvals.settings,
  }));

  const noProductionSummary = "No production environments were detected (environments marked critical or matching the production pattern); adjust production_pattern or mark production environments as critical in LaunchDarkly.";

  const findings: LaunchdarklyFinding[] = [
    restrictionFinding(
      16,
      productionEnvironments.length === 0 || !rolesReadable
        ? "warn"
        : unrestrictedProduction.length > 0 ? "fail" : criticalOnlyProduction.length > 0 ? "warn" : "pass",
      productionEnvironments.length === 0
        ? noProductionSummary
        : !rolesReadable
          ? `Custom roles could not be read (${roleErrors[0]}), so role-based access restrictions on the ${productionEnvironments.length} production environments could not be evaluated.`
          : unrestrictedProduction.length > 0
            ? `${unrestrictedProduction.length}/${productionEnvironments.length} production environments are not restricted by any custom role statement that denies, excludes, or scopes actions away from them${criticalOnlyProduction.length > 0 ? `, and ${criticalOnlyProduction.length} more rely on the critical designation alone` : ""}.`
            : criticalOnlyProduction.length > 0
              ? `${criticalOnlyProduction.length}/${productionEnvironments.length} production environments are marked critical, which only enables safeguards and UI prompts; no custom role denies, excludes, or scopes actions away from them (for example a deny on proj/*:env/*;{critical:true}:flag/*).`
              : `All ${productionEnvironments.length} production environments are restricted by custom role statements that deny, exclude, or scope actions away from them (${roles.length} custom roles evaluated).`,
      {
        production_environments: sample(productionEnvironments.map(environmentLabel)),
        restricted_production_environments: sample(restrictedProduction.map((entry) => ({
          environment: environmentLabel(entry.context),
          critical: entry.critical,
          restrictions: sample(entry.restrictions.map(restrictionLabel)),
        }))),
        critical_only_production_environments: sample(criticalOnlyProduction.map((entry) => environmentLabel(entry.context))),
        unrestricted_production_environments: sample(unrestrictedProduction.map(environmentLabel)),
        custom_roles_evaluated: roles.length,
      },
    ),
    environmentFinding(
      17,
      productionEnvironments.length === 0
        ? "warn"
        : approvalsMissing.length > 0 ? "fail" : approvalsWeak.length > 0 ? "warn" : "pass",
      productionEnvironments.length === 0
        ? noProductionSummary
        : approvalsMissing.length > 0
          ? `${approvalsMissing.length}/${productionEnvironments.length} production environments do not require approvals for flag changes.`
          : approvalsWeak.length > 0
            ? `All production environments require approvals, but ${approvalsWeak.length} weaken the gate: ${approvalWeaknessKinds.map(approvalWeaknessLabel).join("; ")}.`
            : `All ${productionEnvironments.length} production environments require approvals on every flag, with no bypass, self review, or declined-change application.`,
      {
        approvals_missing: sample(approvalsMissing.map(environmentLabel)),
        approvals_weak: sample(approvalsWeak.map((entry) => ({
          environment: environmentLabel(entry.context),
          weaknesses: entry.approvals.weaknesses,
          settings: entry.approvals.settings,
        }))),
        production_environment_settings: sample(productionSummary),
      },
    ),
    sdkKeyFinding(
      19,
      environments.length === 0
        ? "warn"
        : unreadableSdkKeyEnvironments.length === environments.length
          ? "manual"
          : staleSdkKeys.length > 0 ? "fail" : unreadableSdkKeyEnvironments.length > 0 ? "warn" : "pass",
      environments.length === 0
        ? "No environments were readable, so SDK key age could not be evaluated."
        : unreadableSdkKeyEnvironments.length === environments.length
          ? `The beta SDK keys endpoint was not readable for any environment (${unreadableSdkKeyEnvironments[0]?.error ?? "unknown error"}). Review Organization settings > SDK keys for each production environment and record the creation date of every active server-side SDK key; rotate keys older than ${sdkKeyMaxAgeDays} days.`
          : staleSdkKeys.length > 0
            ? `${staleSdkKeys.length} server-side SDK keys are older than ${sdkKeyMaxAgeDays} days without a near term expiry.`
            : unreadableSdkKeyEnvironments.length > 0
              ? `Readable SDK keys are within the ${sdkKeyMaxAgeDays} day policy, but ${unreadableSdkKeyEnvironments.length}/${environments.length} environments could not be inspected.`
              : `All server-side SDK keys across ${environments.length} environments are within the ${sdkKeyMaxAgeDays} day rotation policy.`,
      {
        sdk_key_max_age_days: sdkKeyMaxAgeDays,
        stale_sdk_keys: sample(staleSdkKeys),
        unreadable_environments: sample(unreadableSdkKeyEnvironments.map((result) => environmentLabel(result.context))),
        manual_evidence: unreadableSdkKeyEnvironments.length > 0
          ? ["Organization settings > SDK keys: creation dates of active server-side SDK keys per production environment"]
          : [],
      },
    ),
    environmentFinding(
      22,
      projects.length === 0 ? "warn" : testProjects.length === 0 ? "pass" : "warn",
      projects.length === 0
        ? "No projects were readable."
        : testProjects.length === 0
          ? `None of the ${projects.length} projects look like test or temporary projects.`
          : `${testProjects.length}/${projects.length} projects look like test or temporary projects; confirm they are intentional and not exposed to production SDK traffic.`,
      {
        projects: projects.length,
        test_like_projects: sample(testProjects.map((project) => asString(project.key) ?? asString(project.name) ?? "project")),
      },
    ),
    environmentFinding(
      23,
      productionEnvironments.length === 0
        ? "warn"
        : secureModeMissing.length > 0 ? "fail" : ttlZero.length > 0 || changeSafeguardsMissing.length > 0 ? "warn" : "pass",
      productionEnvironments.length === 0
        ? noProductionSummary
        : secureModeMissing.length > 0
          ? `${secureModeMissing.length}/${productionEnvironments.length} production environments do not enable secure mode.`
          : ttlZero.length > 0 || changeSafeguardsMissing.length > 0
            ? `Secure mode is enabled everywhere, but ${ttlZero.length} production environments use a zero default TTL and ${changeSafeguardsMissing.length} lack confirm changes or require comments.`
            : `All ${productionEnvironments.length} production environments enable secure mode, a non-zero default TTL, confirm changes, and required comments.`,
      {
        production_environment_settings: sample(productionSummary),
        secure_mode_missing: sample(secureModeMissing.map(environmentLabel)),
        zero_ttl: sample(ttlZero.map(environmentLabel)),
        change_safeguards_missing: sample(changeSafeguardsMissing.map(environmentLabel)),
      },
    ),
  ];

  return {
    title: "LaunchDarkly environment governance",
    category: "environment_governance",
    summary: {
      base_url: config.baseUrl,
      projects: projects.length,
      environments: environments.length,
      production_environments: productionEnvironments.length,
      restricted_production_environments: restrictedProduction.length,
      critical_only_production_environments: criticalOnlyProduction.length,
      unrestricted_production_environments: unrestrictedProduction.length,
      approvals_missing: approvalsMissing.length,
      approvals_weak: approvalsWeak.length,
      stale_sdk_keys: staleSdkKeys.length,
      test_like_projects: testProjects.length,
      secure_mode_missing: secureModeMissing.length,
      truncated_collections: inventory.notes.length + roleNotes.length + sdkKeyNotes.length,
      evaluated_at: new Date(now).toISOString(),
    },
    findings,
    errors,
    snapshots: {
      projects: collectionSnapshot(inventory.projects),
      environments: environmentsSnapshot(inventory),
      sdk_keys: sdkKeyResults.map((result) => ({
        environment: environmentLabel(result.context),
        readable: result.readable,
        ...collectionSnapshot(result.collection),
      })),
    },
  };
}

function flagKey(flag: JsonRecord): string {
  return asString(flag.key) ?? asString(flag.name) ?? "flag";
}

function flagStatusKey(status: JsonRecord): string | undefined {
  const href = asString(asObject(asObject(status._links)?.parent)?.href);
  if (!href) return undefined;
  const segments = href.split("/").filter(Boolean);
  const last = segments[segments.length - 1];
  return last ? decodeURIComponent(last) : undefined;
}

function detectPrerequisiteCycles(graph: Map<string, string[]>): string[][] {
  const cycles: string[][] = [];
  const state = new Map<string, "visiting" | "done">();
  const stack: string[] = [];

  const visit = (node: string) => {
    const status = state.get(node);
    if (status === "done") return;
    if (status === "visiting") {
      const start = stack.indexOf(node);
      cycles.push([...stack.slice(start), node]);
      return;
    }
    state.set(node, "visiting");
    stack.push(node);
    for (const dependency of graph.get(node) ?? []) {
      visit(dependency);
    }
    stack.pop();
    state.set(node, "done");
  };

  for (const node of graph.keys()) {
    visit(node);
  }
  return cycles;
}

export async function assessLaunchdarklyFlagHygiene(
  client: FlagHygieneClient,
  options: LaunchdarklyFlagHygieneOptions = {},
): Promise<LaunchdarklyAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const productionPattern = buildRegex(options.productionPattern, DEFAULT_PRODUCTION_PATTERN);
  const staleFlagDays = clampNumber(options.staleFlagDays, DEFAULT_STALE_FLAG_DAYS, 1, 3650);
  const flagLimit = clampNumber(options.flagLimit, DEFAULT_FLAG_LIMIT, 1, 10_000);

  const inventory = await collectEnvironmentContexts(client, errors, {
    projectLimit: clampNumber(options.projectLimit, DEFAULT_PROJECT_LIMIT, 1, 1000),
    environmentLimit: DEFAULT_ENVIRONMENT_LIMIT,
    projectKeys: options.projectKeys && options.projectKeys.length > 0 ? options.projectKeys : config.projectKeys,
    productionPattern,
  });
  const projects = inventory.projects.items;
  const environments = inventory.environments;

  const targetEnvironments: EnvironmentContext[] = [];
  for (const project of projects) {
    const projectKey = asString(project.key);
    if (!projectKey) continue;
    const projectEnvironments = environments.filter((context) => context.projectKey === projectKey);
    const production = projectEnvironments.filter((context) => context.production);
    targetEnvironments.push(...(production.length > 0 ? production : projectEnvironments.slice(0, 1)));
  }

  const environmentResults = await Promise.all(targetEnvironments.map(async (context) => {
    const flagCollection = await collectList(errors, `flags:${environmentLabel(context)}`, () => client.listFlags(context.projectKey, context.key, flagLimit));
    const statuses = await collect(errors, `flag_statuses:${environmentLabel(context)}`, () => client.listFlagStatuses(context.projectKey, context.key), [] as JsonRecord[]);
    return { context, flags: flagCollection.items, flagCollection, statuses };
  }));
  const flagNotes = environmentResults.flatMap((result) =>
    truncationNote("flags", "flag_limit", result.flagCollection, `environment ${environmentLabel(result.context)}`));
  const flagFinding = truncationAwareFinding([...inventory.notes, ...flagNotes]);

  const individuallyTargetedFlags: Array<{ environment: string; flag: string; targets: number; context_kinds: string[] }> = [];
  const staleFlags: Array<{ environment: string; flag: string; status: string | null; last_requested: string | null }> = [];
  const prerequisiteCycles: Array<{ environment: string; cycle: string[] }> = [];
  let evaluatedFlags = 0;

  for (const result of environmentResults) {
    const label = environmentLabel(result.context);
    const graph = new Map<string, string[]>();
    for (const flag of result.flags) {
      evaluatedFlags += 1;
      const environmentConfig = asObject(asObject(flag.environments)?.[result.context.key]);
      if (!environmentConfig) continue;
      const targets = [...asRecordArray(environmentConfig.targets), ...asRecordArray(environmentConfig.contextTargets)];
      const targetValues = targets.reduce((total, target) => total + asStringArray(target.values).length, 0);
      if (result.context.production && targetValues > 0) {
        individuallyTargetedFlags.push({
          environment: label,
          flag: flagKey(flag),
          targets: targetValues,
          context_kinds: uniqueStrings(targets.map((target) => asString(target.contextKind) ?? "user")),
        });
      }
      graph.set(flagKey(flag), asRecordArray(environmentConfig.prerequisites).map((prerequisite) => asString(prerequisite.key)).filter((key): key is string => Boolean(key)));
    }
    for (const cycle of detectPrerequisiteCycles(graph)) {
      prerequisiteCycles.push({ environment: label, cycle });
    }

    const flagCreation = new Map(result.flags.map((flag) => [flagKey(flag), asTimestamp(flag.creationDate)]));
    const archivedFlags = new Set(result.flags.filter((flag) => asBoolean(flag.archived) === true).map(flagKey));
    for (const status of result.statuses) {
      const key = flagStatusKey(status);
      if (!key || archivedFlags.has(key)) continue;
      const statusName = asString(status.name)?.toLowerCase();
      const lastRequested = asTimestamp(status.lastRequested);
      const created = flagCreation.get(key);
      const reference = lastRequested ?? created;
      const stale = statusName === "inactive"
        || (reference !== undefined && daysBetween(reference, now) > staleFlagDays)
        || (lastRequested === undefined && statusName !== "new" && created !== undefined && daysBetween(created, now) > staleFlagDays);
      if (stale) {
        staleFlags.push({ environment: label, flag: key, status: statusName ?? null, last_requested: isoDate(lastRequested) });
      }
    }
  }

  const productionTargets = targetEnvironments.filter((context) => context.production);
  const noFlagsSummary = `No flags were readable in the ${targetEnvironments.length} evaluated environments, so flag hygiene could not be evaluated.`;
  const findings: LaunchdarklyFinding[] = [
    flagFinding(
      14,
      productionTargets.length === 0 || evaluatedFlags === 0
        ? "warn"
        : individuallyTargetedFlags.length === 0 ? "pass" : "fail",
      productionTargets.length === 0
        ? "No production environments were detected, so individual targeting exposure in production could not be evaluated."
        : evaluatedFlags === 0
          ? noFlagsSummary
          : individuallyTargetedFlags.length === 0
            ? `None of the ${evaluatedFlags} evaluated flags use individual context targets in production environments.`
            : `${individuallyTargetedFlags.length} flags expose individual user or context keys through production targeting.`,
      {
        production_environments: sample(productionTargets.map(environmentLabel)),
        individually_targeted_flags: sample(individuallyTargetedFlags),
      },
    ),
    flagFinding(
      15,
      targetEnvironments.length === 0 || evaluatedFlags === 0 ? "warn" : staleFlags.length === 0 ? "pass" : "warn",
      targetEnvironments.length === 0
        ? "No environments were readable, so stale flags could not be identified."
        : evaluatedFlags === 0
          ? noFlagsSummary
          : staleFlags.length === 0
            ? `No flags in ${targetEnvironments.length} evaluated environments are inactive or unrequested for more than ${staleFlagDays} days.`
            : `${staleFlags.length} flags are inactive or have not been requested for more than ${staleFlagDays} days and should be reviewed for cleanup.`,
      {
        stale_flag_days: staleFlagDays,
        stale_flags: sample(staleFlags),
      },
    ),
    flagFinding(
      25,
      targetEnvironments.length === 0 || evaluatedFlags === 0 ? "warn" : prerequisiteCycles.length === 0 ? "pass" : "fail",
      targetEnvironments.length === 0
        ? "No environments were readable, so prerequisite dependencies could not be evaluated."
        : evaluatedFlags === 0
          ? noFlagsSummary
          : prerequisiteCycles.length === 0
            ? `No circular prerequisite chains were found across ${evaluatedFlags} evaluated flags.`
            : `${prerequisiteCycles.length} circular prerequisite chains were detected.`,
      {
        prerequisite_cycles: sample(prerequisiteCycles),
      },
    ),
  ];

  return {
    title: "LaunchDarkly flag hygiene",
    category: "flag_hygiene",
    summary: {
      base_url: config.baseUrl,
      projects: projects.length,
      evaluated_environments: targetEnvironments.length,
      evaluated_flags: evaluatedFlags,
      individually_targeted_flags: individuallyTargetedFlags.length,
      stale_flags: staleFlags.length,
      prerequisite_cycles: prerequisiteCycles.length,
      truncated_collections: inventory.notes.length + flagNotes.length,
      evaluated_at: new Date(now).toISOString(),
    },
    findings,
    errors,
    snapshots: {
      flags: environmentResults.map((result) => ({ environment: environmentLabel(result.context), ...collectionSnapshot(result.flagCollection) })),
      flag_statuses: environmentResults.map((result) => ({ environment: environmentLabel(result.context), items: result.statuses })),
    },
  };
}

function statementIsBroadScope(statement: PolicyStatement): boolean {
  const broadResource = statement.resources.length === 0
    || statement.resources.some((resource) => {
      const base = resource.split(";")[0].toLowerCase();
      return base === "*" || base === "proj/*" || base.startsWith("proj/*:env/*");
    });
  const broadActions = statement.actions.length === 0 || statement.actions.some((action) => action === "*");
  return statement.effect === "allow" && broadResource && broadActions;
}

function relayPolicyIsBroad(statements: PolicyStatement[]): boolean {
  return statements.some((statement) => statement.effect === "allow" && (
    statement.resources.length === 0
    || statement.resources.some((resource) => {
      const base = resource.split(";")[0].toLowerCase();
      return base === "*" || base === "proj/*" || base === "proj/*:env/*";
    })
  ));
}

function relayReferencedEnvironments(statements: PolicyStatement[]): Array<{ projectKey: string; environmentKey: string }> {
  const references: Array<{ projectKey: string; environmentKey: string }> = [];
  for (const statement of statements) {
    if (statement.effect !== "allow") continue;
    for (const resource of statement.resources) {
      const match = /^proj\/([^:;]+)(?:;[^:]*)?:env\/([^:;]+)/i.exec(resource);
      if (match) references.push({ projectKey: match[1], environmentKey: match[2] });
    }
  }
  return references;
}

export async function assessLaunchdarklyMonitoringIntegrations(
  client: MonitoringClient,
  options: LaunchdarklyMonitoringOptions = {},
): Promise<LaunchdarklyAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const now = options.now ?? Date.now();
  const retentionDays = clampNumber(options.retentionDays, DEFAULT_AUDIT_RETENTION_DAYS, 1, 3650);
  const relayConfigMaxAgeDays = clampNumber(options.relayConfigMaxAgeDays, DEFAULT_RELAY_CONFIG_MAX_AGE_DAYS, 1, 3650);
  const integrationKeys = uniqueStrings(options.integrationKeys && options.integrationKeys.length > 0 ? options.integrationKeys : DEFAULT_INTEGRATION_KEYS);
  const productionPattern = buildRegex(options.productionPattern, DEFAULT_PRODUCTION_PATTERN);

  const auditErrors: string[] = [];
  const webhookErrors: string[] = [];
  const [recentAuditCollection, retentionProbeCollection, memberAuditCollection, roleAuditCollection, relayConfigs, webhooks] = await Promise.all([
    collectList(auditErrors, "audit_log_recent", () => client.listAuditLogEntries({}, AUDIT_LOG_PAGE_SIZE)),
    collectList(auditErrors, "audit_log_retention_probe", () => client.listAuditLogEntries({ before: now - retentionDays * DAY_MS }, 1)),
    collectList(auditErrors, "audit_log_members", () => client.listAuditLogEntries({ spec: "member/*" }, AUDIT_LOG_PAGE_SIZE)),
    collectList(auditErrors, "audit_log_roles", () => client.listAuditLogEntries({ spec: "role/*" }, AUDIT_LOG_PAGE_SIZE)),
    collect(errors, "relay_proxy_configs", () => client.listRelayProxyConfigs(), [] as JsonRecord[]),
    collect(webhookErrors, "webhooks", () => client.listWebhooks(), [] as JsonRecord[]),
  ]);
  errors.push(...auditErrors, ...webhookErrors);
  const recentAuditEntries = recentAuditCollection.items;
  const retentionProbe = retentionProbeCollection.items;
  const memberAuditEntries = memberAuditCollection.items;
  const roleAuditEntries = roleAuditCollection.items;
  const auditReadable = auditErrors.length < 4;
  const webhooksReadable = webhookErrors.length === 0;

  const subscriptionResults = await Promise.all(integrationKeys.map(async (integrationKey) => ({
    integrationKey,
    subscriptions: await collect(errors, `integration_subscriptions:${integrationKey}`, () => client.listIntegrationSubscriptions(integrationKey), [] as JsonRecord[]),
  })));
  const subscriptions = subscriptionResults.flatMap((result) =>
    result.subscriptions.map((subscription) => ({ integrationKey: result.integrationKey, subscription })));

  const relayStatements = relayConfigs.map((relayConfig) => ({ relayConfig, statements: parseStatements(relayConfig.policy) }));
  const referencedProjects = uniqueStrings(relayStatements.flatMap((item) => relayReferencedEnvironments(item.statements).map((reference) => reference.projectKey)));
  const relayInventory = referencedProjects.length > 0
    ? await collectEnvironmentContexts(client, errors, {
      projectLimit: referencedProjects.length,
      environmentLimit: DEFAULT_ENVIRONMENT_LIMIT,
      projectKeys: referencedProjects,
      productionPattern,
    })
    : undefined;
  const relayEnvironments = relayInventory?.environments ?? [];
  const relayFinding = truncationAwareFinding(relayInventory?.notes ?? []);

  const oldestRecentEntry = recentAuditEntries
    .map((entry) => asTimestamp(entry.date))
    .filter((value): value is number => value !== undefined)
    .sort((left, right) => left - right)[0];
  const criticalActionsSeen = uniqueStrings([...memberAuditEntries, ...roleAuditEntries]
    .flatMap(auditActions)
    .filter((action) => CRITICAL_AUDIT_ACTIONS.has(action)));

  const broadRelayConfigs = relayStatements.filter((item) => relayPolicyIsBroad(item.statements));
  const insecureRelayEnvironments = relayStatements.flatMap((item) =>
    relayReferencedEnvironments(item.statements)
      .map((reference) => relayEnvironments.find((context) =>
        context.projectKey === reference.projectKey && (reference.environmentKey === "*" || context.key === reference.environmentKey)))
      .filter((context): context is EnvironmentContext => Boolean(context))
      .filter((context) => context.production && asBoolean(context.environment.secureMode) !== true)
      .map((context) => ({ relay_config: asString(item.relayConfig.name) ?? "relay", environment: environmentLabel(context) })));
  const staleRelayConfigs = relayStatements.filter((item) => {
    const reference = asTimestamp(item.relayConfig.lastModified) ?? asTimestamp(item.relayConfig.creationDate);
    return reference !== undefined && daysBetween(reference, now) > relayConfigMaxAgeDays;
  });

  const broadSubscriptions = subscriptions.filter((item) => parseStatements(item.subscription.statements).some(statementIsBroadScope));
  const broadEnabledSubscriptions = broadSubscriptions.filter((item) => asBoolean(item.subscription.on) !== false);

  const enabledWebhooks = webhooks.filter((webhook) => asBoolean(webhook.on) !== false);
  const insecureWebhook = (webhook: JsonRecord) => !/^https:\/\//i.test(asString(webhook.url) ?? "") || !asString(webhook.secret);
  const insecureEnabledWebhooks = enabledWebhooks.filter(insecureWebhook);
  const insecureDisabledWebhooks = webhooks.filter((webhook) => asBoolean(webhook.on) === false).filter(insecureWebhook);
  const webhookLabel = (webhook: JsonRecord) => ({
    webhook: asString(webhook.name) ?? asString(webhook._id) ?? "webhook",
    url: asString(webhook.url),
    https: /^https:\/\//i.test(asString(webhook.url) ?? ""),
    signed: Boolean(asString(webhook.secret)),
    enabled: asBoolean(webhook.on) !== false,
  });

  const findings: LaunchdarklyFinding[] = [
    buildFinding(
      12,
      !auditReadable
        ? "fail"
        : retentionProbe.length > 0 ? "pass" : recentAuditEntries.length === 0 ? "fail" : "warn",
      !auditReadable
        ? `The audit log could not be read (${auditErrors[0] ?? "unknown error"}), so retention cannot be demonstrated.`
        : retentionProbe.length > 0
          ? `Audit log entries older than ${retentionDays} days are still queryable through the API.`
          : recentAuditEntries.length === 0
            ? "The audit log returned no entries at all."
            : `No audit entries older than ${retentionDays} days were returned; the oldest recent entry is from ${isoDate(oldestRecentEntry) ?? "unknown"}. Confirm plan retention with LaunchDarkly or export the audit log to a SIEM for ${retentionDays}+ day retention.`,
      {
        retention_days: retentionDays,
        entries_older_than_retention: retentionProbe.length,
        oldest_recent_entry: isoDate(oldestRecentEntry),
        recent_entries_sampled: recentAuditEntries.length,
      },
    ),
    buildFinding(
      13,
      !auditReadable
        ? "fail"
        : criticalActionsSeen.length > 0 ? "pass" : "warn",
      !auditReadable
        ? "The audit log could not be read, so critical action coverage cannot be demonstrated."
        : criticalActionsSeen.length > 0
          ? `Audit log entries for member and role resources are present with critical actions (${criticalActionsSeen.slice(0, 6).join(", ")}).`
          : `The audit log is readable, but no recent member or role change entries were returned (${memberAuditEntries.length} member entries, ${roleAuditEntries.length} role entries). Verify that role changes and member additions appear in the audit log during the next change window.`,
      {
        member_entries: memberAuditEntries.length,
        role_entries: roleAuditEntries.length,
        critical_actions_seen: criticalActionsSeen,
        recent_entry_kinds: uniqueStrings(recentAuditEntries.map((entry) => asString(entry.kind) ?? "unknown")),
      },
    ),
    relayFinding(
      18,
      relayConfigs.length === 0
        ? "manual"
        : broadRelayConfigs.length > 0 || insecureRelayEnvironments.length > 0
          ? "fail"
          : staleRelayConfigs.length > 0 ? "warn" : "pass",
      relayConfigs.length === 0
        ? "No Relay Proxy automatic configurations exist in the account. If a Relay Proxy is deployed with static SDK keys, verify manually that it serves only production environments with secure mode enabled, uses TLS, and rotates its keys."
        : broadRelayConfigs.length > 0 || insecureRelayEnvironments.length > 0
          ? `${broadRelayConfigs.length} Relay Proxy configurations use wildcard project or environment scope and ${insecureRelayEnvironments.length} referenced production environments lack secure mode.`
          : staleRelayConfigs.length > 0
            ? `Relay Proxy configurations are scoped to specific environments with secure mode, but ${staleRelayConfigs.length} have not been rotated or modified in more than ${relayConfigMaxAgeDays} days.`
            : `All ${relayConfigs.length} Relay Proxy configurations are scoped to specific environments with secure mode enabled.`,
      {
        relay_configs: relayConfigs.length,
        broad_relay_configs: sample(broadRelayConfigs.map((item) => asString(item.relayConfig.name) ?? "relay")),
        insecure_relay_environments: sample(insecureRelayEnvironments),
        stale_relay_configs: sample(staleRelayConfigs.map((item) => ({
          relay_config: asString(item.relayConfig.name) ?? "relay",
          last_modified: isoDate(asTimestamp(item.relayConfig.lastModified)),
        }))),
        manual_evidence: relayConfigs.length === 0
          ? ["Relay Proxy deployment configuration (environment allowlist, TLS termination, key rotation records)"]
          : [],
      },
    ),
    buildFinding(
      20,
      subscriptions.length === 0
        ? "manual"
        : broadEnabledSubscriptions.length > 0 ? "fail" : broadSubscriptions.length > 0 ? "warn" : "pass",
      subscriptions.length === 0
        ? `No audit log subscriptions were found for the probed integration keys (${integrationKeys.join(", ")}). Review Organization settings > Integrations for other integration types the API cannot enumerate and confirm each is scoped to the minimum projects, environments, and actions.`
        : broadEnabledSubscriptions.length > 0
          ? `${broadEnabledSubscriptions.length}/${subscriptions.length} enabled integration subscriptions forward all actions across all projects and environments to a third party.`
          : broadSubscriptions.length > 0
            ? `${broadSubscriptions.length} disabled integration subscriptions still carry wildcard scopes.`
            : `All ${subscriptions.length} integration subscriptions are scoped to specific resources or actions.`,
      {
        probed_integration_keys: integrationKeys,
        subscriptions: subscriptions.length,
        broad_subscriptions: sample(broadSubscriptions.map((item) => ({
          integration: item.integrationKey,
          name: asString(item.subscription.name) ?? asString(item.subscription._id),
          enabled: asBoolean(item.subscription.on) !== false,
        }))),
        manual_evidence: subscriptions.length === 0
          ? ["Organization settings > Integrations: scope of each configured integration"]
          : [],
      },
    ),
    buildFinding(
      21,
      !webhooksReadable
        ? "warn"
        : webhooks.length === 0
          ? "pass"
          : insecureEnabledWebhooks.length > 0 ? "fail" : insecureDisabledWebhooks.length > 0 ? "warn" : "pass",
      !webhooksReadable
        ? `The webhooks endpoint could not be read (${webhookErrors[0]}), so webhook transport security could not be evaluated.`
        : webhooks.length === 0
          ? "No webhooks are configured."
          : insecureEnabledWebhooks.length > 0
            ? `${insecureEnabledWebhooks.length}/${enabledWebhooks.length} enabled webhooks use plain HTTP or have no signing secret.`
            : insecureDisabledWebhooks.length > 0
              ? `All enabled webhooks use HTTPS with signing, but ${insecureDisabledWebhooks.length} disabled webhooks would be insecure if re-enabled.`
              : `All ${webhooks.length} webhooks use HTTPS endpoints with a signing secret.`,
      {
        webhooks: webhooks.length,
        insecure_enabled_webhooks: sample(insecureEnabledWebhooks.map(webhookLabel)),
        insecure_disabled_webhooks: sample(insecureDisabledWebhooks.map(webhookLabel)),
      },
    ),
  ];

  return {
    title: "LaunchDarkly monitoring and integrations",
    category: "monitoring_integrations",
    summary: {
      base_url: config.baseUrl,
      audit_log_readable: auditReadable,
      entries_older_than_retention: retentionProbe.length,
      critical_actions_seen: criticalActionsSeen.length,
      relay_configs: relayConfigs.length,
      broad_relay_configs: broadRelayConfigs.length,
      integration_subscriptions: subscriptions.length,
      broad_subscriptions: broadSubscriptions.length,
      webhooks: webhooks.length,
      insecure_enabled_webhooks: insecureEnabledWebhooks.length,
      evaluated_at: new Date(now).toISOString(),
    },
    findings,
    errors,
    snapshots: {
      audit_log_recent: collectionSnapshot(recentAuditCollection),
      audit_log_retention_probe: collectionSnapshot(retentionProbeCollection),
      audit_log_members: collectionSnapshot(memberAuditCollection),
      audit_log_roles: collectionSnapshot(roleAuditCollection),
      relay_proxy_configs: relayConfigs,
      integration_subscriptions: subscriptionResults,
      webhooks,
    },
  };
}

function formatAccessCheckText(result: LaunchdarklyAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `LaunchDarkly access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: LaunchdarklyAssessmentResult): string {
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
  const errorLines = result.errors.length > 0
    ? ["", "Partial collection warnings:", ...result.errors.map((error) => `- ${error}`)]
    : [];

  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...errorLines,
  ].join("\n");
}

function markdownEscapePipes(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function sortFindings(findings: LaunchdarklyFinding[]): LaunchdarklyFinding[] {
  return [...findings].sort((left, right) =>
    statusRank(left.status) - statusRank(right.status)
    || severityRank(left.severity) - severityRank(right.severity)
    || left.control - right.control);
}

function buildExecutiveSummary(
  config: LaunchdarklyResolvedConfig,
  access: LaunchdarklyAccessCheckResult,
  assessments: LaunchdarklyAssessmentResult[],
  errors: string[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const count = (status: LaunchdarklyFindingStatus) => findings.filter((item) => item.status === status).length;
  const priority = sortFindings(findings).filter((item) => item.status === "fail" || item.status === "warn").slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");
  const truncated = collectTruncationNotes(findings);

  const lines = [
    "# LaunchDarkly Security Inspector Executive Summary",
    "",
    `- Instance: ${config.baseUrl}`,
    `- API version: ${config.apiVersion}`,
    `- Account ID: ${access.callerIdentity.accountId ?? "unknown"}`,
    `- Config source chain: ${config.sourceChain.join(" -> ")}`,
    `- Generated: ${new Date().toISOString()}`,
    `- Findings: Pass ${count("pass")}, Warn ${count("warn")}, Fail ${count("fail")}, Manual ${count("manual")} (${findings.length} of 25 spec controls evaluated)`,
    "",
    "## Highest Priority Findings",
    "",
  ];

  if (priority.length === 0) {
    lines.push("- No failing or warning findings were generated in this assessment set.");
  } else {
    for (const finding of priority) {
      lines.push(`- ${finding.id} (${finding.severity.toUpperCase()} / ${finding.status.toUpperCase()}) ${finding.title}: ${finding.summary}`);
    }
  }

  lines.push("", "## Manual Verification Required", "");
  if (manual.length === 0) {
    lines.push("- None.");
  } else {
    for (const finding of manual) {
      lines.push(`- ${finding.id} ${finding.title}: ${finding.summary}`);
    }
  }

  if (truncated.length > 0) {
    lines.push("", "## Truncated Listings", "");
    for (const note of truncated) {
      lines.push(`- ${note.collection}${note.scope ? ` (${note.scope})` : ""}: ${note.seen} of ${note.total ?? "an unknown total"} collected${note.option ? `; raise ${note.option}` : ""}`);
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

function collectTruncationNotes(findings: LaunchdarklyFinding[]): LaunchdarklyTruncationNote[] {
  const seen = new Set<string>();
  const notes: LaunchdarklyTruncationNote[] = [];
  for (const finding of findings) {
    for (const entry of asRecordArray(finding.evidence?.truncated_collections)) {
      const collection = asString(entry.collection);
      if (!collection) continue;
      const scope = asString(entry.scope);
      const key = `${collection}|${scope ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      notes.push({
        collection,
        ...(asString(entry.option) ? { option: asString(entry.option) } : {}),
        seen: asNumber(entry.seen) ?? 0,
        total: asNumber(entry.total) ?? null,
        ...(scope ? { scope } : {}),
      });
    }
  }
  return notes;
}

function buildUnifiedMatrix(findings: LaunchdarklyFinding[]): string {
  const header = ["Control", "Title", "Status", "Severity", ...FRAMEWORK_ORDER.map(frameworkLabel)];
  const lines = [
    "# LaunchDarkly Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
  ];
  for (const finding of [...findings].sort((left, right) => left.control - right.control)) {
    const cells = [
      finding.id,
      finding.title,
      finding.status,
      finding.severity,
      ...FRAMEWORK_ORDER.map((framework) => finding.frameworks[framework]),
    ].map(markdownEscapePipes);
    lines.push(`| ${cells.join(" | ")} |`);
  }
  return `${lines.join("\n")}\n`;
}

function buildFrameworkReport(title: string, framework: LaunchdarklyFramework, findings: LaunchdarklyFinding[]): string {
  const lines = [
    `# ${title}`,
    "",
    `Framework mappings are taken from the LaunchDarkly Security Inspector specification for ${frameworkLabel(framework)}.`,
    "",
    "| Control | Check | Mapping | Status | Severity | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
  ];
  for (const finding of [...findings].sort((left, right) => left.control - right.control)) {
    const cells = [
      finding.id,
      finding.title,
      finding.frameworks[framework],
      finding.status,
      finding.severity,
      finding.summary,
    ].map(markdownEscapePipes);
    lines.push(`| ${cells.join(" | ")} |`);
  }
  return `${lines.join("\n")}\n`;
}

function buildQuickReference(): string {
  return [
    "# LaunchDarkly Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw LaunchDarkly REST API v2 snapshots (SDK keys, mobile keys, relay keys, and webhook secrets are masked).",
    "- `analysis/` contains normalized findings plus one JSON summary per assessment category.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, ISMAP).",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Findings with status `manual` list the evidence a human must collect; review them before asserting compliance.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/findings.json` for the evidence behind each finding",
    "",
    "Access tokens are never written into the bundle.",
    "",
  ].join("\n");
}

const FRAMEWORK_REPORTS: Array<[LaunchdarklyFramework, string, string]> = [
  ["fedramp", "compliance/fedramp/fedramp_compliance_report.md", "FedRAMP / NIST 800-53 Compliance Report"],
  ["cmmc", "compliance/cmmc/cmmc_compliance_report.md", "CMMC Level 2 Compliance Report"],
  ["soc2", "compliance/soc2/soc2_compliance_report.md", "SOC 2 Compliance Report"],
  ["cis", "compliance/cis/cis_controls_report.md", "CIS Controls Report"],
  ["pci_dss", "compliance/pci_dss/pci_dss_compliance_report.md", "PCI-DSS Compliance Report"],
  ["stig", "compliance/disa_stig/stig_compliance_checklist.md", "DISA STIG / SRG Compliance Checklist"],
  ["irap", "compliance/irap/irap_compliance_report.md", "IRAP / ISM Compliance Report"],
  ["ismap", "compliance/ismap/ismap_compliance_report.md", "ISMAP Compliance Report"],
];

async function runAssessment(
  errors: string[],
  category: string,
  title: string,
  load: () => Promise<LaunchdarklyAssessmentResult>,
): Promise<LaunchdarklyAssessmentResult> {
  try {
    return await load();
  } catch (error) {
    errors.push(`${category}: ${errorMessage(error)}`);
    return { title, category, summary: { failed: true }, findings: [], errors: [errorMessage(error)], snapshots: {} };
  }
}

export async function exportLaunchdarklyAuditBundle(
  client: LaunchdarklyAuditClient,
  config: LaunchdarklyResolvedConfig,
  outputRoot: string,
  options: LaunchdarklyAuditBundleOptions = {},
): Promise<LaunchdarklyAuditBundleResult> {
  const errors: string[] = [];
  const access = await checkLaunchdarklyAccess(client);
  const assessments = [
    await runAssessment(errors, "identity", "LaunchDarkly identity posture", () => assessLaunchdarklyIdentity(client, options)),
    await runAssessment(errors, "access_control", "LaunchDarkly access control", () => assessLaunchdarklyAccessControl(client, options)),
    await runAssessment(errors, "environment_governance", "LaunchDarkly environment governance", () => assessLaunchdarklyEnvironmentGovernance(client, options)),
    await runAssessment(errors, "flag_hygiene", "LaunchDarkly flag hygiene", () => assessLaunchdarklyFlagHygiene(client, options)),
    await runAssessment(errors, "monitoring_integrations", "LaunchDarkly monitoring and integrations", () => assessLaunchdarklyMonitoringIntegrations(client, options)),
  ];
  for (const assessment of assessments) {
    errors.push(...assessment.errors.map((error) => `${assessment.category}: ${error}`));
  }
  for (const surface of access.surfaces) {
    if (surface.status === "not_readable" && surface.error) {
      errors.push(`access_check:${surface.name}: ${surface.error}`);
    }
  }
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const uniqueErrors = uniqueStrings(errors);

  ensurePrivateDir(outputRoot);
  const bundleName = safeDirName(`${new URL(config.baseUrl).hostname}-${access.callerIdentity.accountId ?? "account"}-audit-bundle`);
  const outputDir = await nextAvailableAuditDir(outputRoot, bundleName);

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    base_url: config.baseUrl,
    api_version: config.apiVersion,
    account_id: access.callerIdentity.accountId ?? null,
    token_name: access.callerIdentity.tokenName ?? null,
    source_chain: config.sourceChain,
    controls_evaluated: findings.length,
    controls_in_spec: 25,
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, snapshot] of Object.entries(assessment.snapshots)) {
      await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(snapshot));
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/summary.md", `${[
    formatAccessCheckText(access),
    "",
    ...assessments.map((assessment) => `${formatAssessmentText(assessment)}\n`),
  ].join("\n")}\n`);
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, access, assessments, uniqueErrors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const [framework, pathname, title] of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, pathname, buildFrameworkReport(title, framework, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  if (uniqueErrors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${uniqueErrors.join("\n")}\n`);
  }

  const zipPath = auditZipPath(outputDir);
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: uniqueErrors.length,
  };
}

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    token: asString(value.token) ?? asString(value.api_token),
    base_url: asString(value.base_url),
    api_version: asString(value.api_version),
    config_path: asString(value.config_path),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    member_limit: asNumber(value.member_limit),
    team_limit: asNumber(value.team_limit),
    max_owners: asNumber(value.max_owners),
    max_admins: asNumber(value.max_admins),
    allowed_domains: normalizeStringList(value.allowed_domains),
  };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    role_limit: asNumber(value.role_limit),
    token_limit: asNumber(value.token_limit),
    stale_token_days: asNumber(value.stale_token_days),
  };
}

function normalizeEnvironmentGovernanceArgs(args: unknown): EnvironmentGovernanceArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    project_limit: asNumber(value.project_limit),
    environment_limit: asNumber(value.environment_limit),
    project_keys: normalizeStringList(value.project_keys),
    production_pattern: asString(value.production_pattern),
    test_project_pattern: asString(value.test_project_pattern),
    sdk_key_max_age_days: asNumber(value.sdk_key_max_age_days),
  };
}

function normalizeFlagHygieneArgs(args: unknown): FlagHygieneArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    project_limit: asNumber(value.project_limit),
    flag_limit: asNumber(value.flag_limit),
    project_keys: normalizeStringList(value.project_keys),
    production_pattern: asString(value.production_pattern),
    stale_flag_days: asNumber(value.stale_flag_days),
  };
}

function normalizeMonitoringArgs(args: unknown): MonitoringArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    retention_days: asNumber(value.retention_days),
    integration_keys: normalizeStringList(value.integration_keys),
    relay_config_max_age_days: asNumber(value.relay_config_max_age_days),
    production_pattern: asString(value.production_pattern),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeAccessControlArgs(args),
    ...normalizeEnvironmentGovernanceArgs(args),
    ...normalizeFlagHygieneArgs(args),
    ...normalizeMonitoringArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toBundleOptions(args: ExportAuditBundleArgs): LaunchdarklyAuditBundleOptions {
  return {
    memberLimit: args.member_limit,
    teamLimit: args.team_limit,
    maxOwners: args.max_owners,
    maxAdmins: args.max_admins,
    allowedDomains: args.allowed_domains,
    roleLimit: args.role_limit,
    tokenLimit: args.token_limit,
    staleTokenDays: args.stale_token_days,
    projectLimit: args.project_limit,
    environmentLimit: args.environment_limit,
    projectKeys: args.project_keys,
    productionPattern: args.production_pattern,
    testProjectPattern: args.test_project_pattern,
    sdkKeyMaxAgeDays: args.sdk_key_max_age_days,
    flagLimit: args.flag_limit,
    staleFlagDays: args.stale_flag_days,
    retentionDays: args.retention_days,
    integrationKeys: args.integration_keys,
    relayConfigMaxAgeDays: args.relay_config_max_age_days,
  };
}

function createClient(args: AuthArgs): LaunchdarklyApiClient {
  return new LaunchdarklyApiClient(resolveLaunchdarklyConfiguration(args as JsonRecord));
}

const authParams = {
  token: Type.Optional(Type.String({ description: "LaunchDarkly personal or service access token. Defaults to LAUNCHDARKLY_API_TOKEN, then the config file token." })),
  base_url: Type.Optional(Type.String({ description: "LaunchDarkly base URL. Defaults to LAUNCHDARKLY_BASE_URL or https://app.launchdarkly.com (use https://app.launchdarkly.us for federal, https://app.eu.launchdarkly.com for EU)." })),
  api_version: Type.Optional(Type.String({ description: "LD-API-Version header value. Defaults to LAUNCHDARKLY_API_VERSION or 20240415." })),
  config_path: Type.Optional(Type.String({ description: "TOML config file path. Defaults to LAUNCHDARKLY_CONFIG or ~/.config/launchdarkly-sec-inspector/config.toml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const productionPatternParam = Type.Optional(Type.String({
  description: "Case-insensitive regular expression that marks production environments by key or name; environments flagged critical always count. Defaults to prod.",
}));

const projectKeysParam = Type.Optional(Type.String({
  description: "Comma-separated project keys to scope the assessment. Defaults to LAUNCHDARKLY_PROJECTS or every readable project.",
}));

export function registerLaunchdarklyTools(pi: any): void {
  pi.registerTool({
    name: "launchdarkly_check_access",
    label: "Check LaunchDarkly audit access",
    description:
      "Validate read-only LaunchDarkly REST API v2 access across caller identity, members, teams, custom roles, projects, environments, flags, access tokens, audit log, webhooks, Relay Proxy configs, and integration subscriptions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkLaunchdarklyAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "launchdarkly_check_access", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly access check failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_assess_identity",
    label: "Assess LaunchDarkly identity posture",
    description:
      "Assess LaunchDarkly identity posture: SSO/SAML enforcement evidence (manual), member MFA coverage, Owner and Admin concentration, orphaned members without teams, team custom role usage, and member email domain policy (spec controls 1, 2, 3, 6, 7, 24).",
    parameters: Type.Object({
      ...authParams,
      member_limit: Type.Optional(Type.Number({ description: "Maximum members to inspect. Defaults to 1000. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 1000 })),
      team_limit: Type.Optional(Type.Number({ description: "Maximum teams to inspect for custom role assignments. Defaults to 100. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 100 })),
      max_owners: Type.Optional(Type.Number({ description: "Maximum acceptable Owner base role members. Defaults to 1.", default: 1 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Admin base role members before warning. Defaults to 5.", default: 5 })),
      allowed_domains: Type.Optional(Type.String({ description: "Comma-separated approved member email domains. Defaults to LAUNCHDARKLY_ALLOWED_DOMAINS; without it control 24 is reported as manual." })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessLaunchdarklyIdentity(createClient(args), {
          memberLimit: args.member_limit,
          teamLimit: args.team_limit,
          maxOwners: args.max_owners,
          maxAdmins: args.max_admins,
          allowedDomains: args.allowed_domains,
        });
        return textResult(formatAssessmentText(result), { tool: "launchdarkly_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly identity assessment failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_assess_access_control",
    label: "Assess LaunchDarkly access control",
    description:
      "Assess LaunchDarkly custom roles and access tokens: wildcard actions, sensitive action grants, token expiry, stale tokens, service token role scoping, and personal token scope (spec controls 4, 5, 8, 9, 10, 11).",
    parameters: Type.Object({
      ...authParams,
      role_limit: Type.Optional(Type.Number({ description: "Maximum custom roles to inspect. Defaults to 200. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum access tokens to inspect. Defaults to 500. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 500 })),
      stale_token_days: Type.Optional(Type.Number({ description: "Days without use before a token is stale. Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await assessLaunchdarklyAccessControl(createClient(args), {
          roleLimit: args.role_limit,
          tokenLimit: args.token_limit,
          staleTokenDays: args.stale_token_days,
        });
        return textResult(formatAssessmentText(result), { tool: "launchdarkly_assess_access_control", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly access control assessment failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_assess_access_control" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_assess_environment_governance",
    label: "Assess LaunchDarkly environment governance",
    description:
      "Assess LaunchDarkly projects and environments: production access restrictions, required approvals, SDK key rotation age, test or temporary projects, and critical environment settings such as secure mode, TTL, confirm changes, and required comments (spec controls 16, 17, 19, 22, 23).",
    parameters: Type.Object({
      ...authParams,
      project_limit: Type.Optional(Type.Number({ description: "Maximum projects to inspect. Defaults to 50. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 50 })),
      environment_limit: Type.Optional(Type.Number({ description: "Maximum environments per project to inspect. Defaults to 50. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 50 })),
      project_keys: projectKeysParam,
      production_pattern: productionPatternParam,
      test_project_pattern: Type.Optional(Type.String({ description: "Case-insensitive regular expression that marks test or temporary projects by key, name, or tag." })),
      sdk_key_max_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable server-side SDK key age in days. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeEnvironmentGovernanceArgs,
    async execute(_toolCallId: string, args: EnvironmentGovernanceArgs) {
      try {
        const result = await assessLaunchdarklyEnvironmentGovernance(createClient(args), {
          projectLimit: args.project_limit,
          environmentLimit: args.environment_limit,
          projectKeys: args.project_keys,
          productionPattern: args.production_pattern,
          testProjectPattern: args.test_project_pattern,
          sdkKeyMaxAgeDays: args.sdk_key_max_age_days,
        });
        return textResult(formatAssessmentText(result), { tool: "launchdarkly_assess_environment_governance", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly environment governance assessment failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_assess_environment_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_assess_flag_hygiene",
    label: "Assess LaunchDarkly flag hygiene",
    description:
      "Assess LaunchDarkly feature flags in production environments: individual context targeting exposure, stale flags that are inactive or unrequested, and circular prerequisite chains (spec controls 14, 15, 25).",
    parameters: Type.Object({
      ...authParams,
      project_limit: Type.Optional(Type.Number({ description: "Maximum projects to inspect. Defaults to 50. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 50 })),
      flag_limit: Type.Optional(Type.Number({ description: "Maximum flags per environment to inspect. Defaults to 500. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 500 })),
      project_keys: projectKeysParam,
      production_pattern: productionPatternParam,
      stale_flag_days: Type.Optional(Type.Number({ description: "Days without evaluation before a flag is stale. Defaults to 30.", default: 30 })),
    }),
    prepareArguments: normalizeFlagHygieneArgs,
    async execute(_toolCallId: string, args: FlagHygieneArgs) {
      try {
        const result = await assessLaunchdarklyFlagHygiene(createClient(args), {
          projectLimit: args.project_limit,
          flagLimit: args.flag_limit,
          projectKeys: args.project_keys,
          productionPattern: args.production_pattern,
          staleFlagDays: args.stale_flag_days,
        });
        return textResult(formatAssessmentText(result), { tool: "launchdarkly_assess_flag_hygiene", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly flag hygiene assessment failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_assess_flag_hygiene" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_assess_monitoring_integrations",
    label: "Assess LaunchDarkly monitoring and integrations",
    description:
      "Assess LaunchDarkly audit log retention and critical action coverage, Relay Proxy configuration scope and secure mode, integration audit log subscription scopes, and webhook HTTPS plus signing (spec controls 12, 13, 18, 20, 21).",
    parameters: Type.Object({
      ...authParams,
      retention_days: Type.Optional(Type.Number({ description: "Required queryable audit log retention in days. Defaults to 90.", default: 90 })),
      integration_keys: Type.Optional(Type.String({ description: "Comma-separated integration keys to probe for audit log subscriptions. Defaults to datadog, dynatrace, elastic, honeycomb, logdna, msteams, new-relic-apm, signalfx, splunk." })),
      relay_config_max_age_days: Type.Optional(Type.Number({ description: "Days before an unmodified Relay Proxy configuration is flagged for rotation review. Defaults to 365.", default: 365 })),
      production_pattern: productionPatternParam,
    }),
    prepareArguments: normalizeMonitoringArgs,
    async execute(_toolCallId: string, args: MonitoringArgs) {
      try {
        const result = await assessLaunchdarklyMonitoringIntegrations(createClient(args), {
          retentionDays: args.retention_days,
          integrationKeys: args.integration_keys,
          relayConfigMaxAgeDays: args.relay_config_max_age_days,
          productionPattern: args.production_pattern,
        });
        return textResult(formatAssessmentText(result), { tool: "launchdarkly_assess_monitoring_integrations", ...result });
      } catch (error) {
        return errorResult(
          `LaunchDarkly monitoring and integrations assessment failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_assess_monitoring_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "launchdarkly_export_audit_bundle",
    label: "Export LaunchDarkly audit bundle",
    description:
      "Export a LaunchDarkly audit package covering all 25 spec controls: raw API snapshots in core_data/, normalized findings in analysis/, executive summary, unified matrix, and per-framework reports in compliance/, QUICK_REFERENCE.md, _errors.log on partial failures, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      member_limit: Type.Optional(Type.Number({ description: "Maximum members to inspect. Defaults to 1000. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 1000 })),
      team_limit: Type.Optional(Type.Number({ description: "Maximum teams to inspect. Defaults to 100. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 100 })),
      max_owners: Type.Optional(Type.Number({ description: "Maximum acceptable Owner base role members. Defaults to 1.", default: 1 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Admin base role members before warning. Defaults to 5.", default: 5 })),
      allowed_domains: Type.Optional(Type.String({ description: "Comma-separated approved member email domains. Defaults to LAUNCHDARKLY_ALLOWED_DOMAINS." })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum custom roles to inspect. Defaults to 200. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum access tokens to inspect. Defaults to 500. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 500 })),
      stale_token_days: Type.Optional(Type.Number({ description: "Days without use before a token is stale. Defaults to 90.", default: 90 })),
      project_limit: Type.Optional(Type.Number({ description: "Maximum projects to inspect. Defaults to 50. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 50 })),
      environment_limit: Type.Optional(Type.Number({ description: "Maximum environments per project to inspect. Defaults to 50. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 50 })),
      project_keys: projectKeysParam,
      production_pattern: productionPatternParam,
      test_project_pattern: Type.Optional(Type.String({ description: "Case-insensitive regular expression that marks test or temporary projects." })),
      sdk_key_max_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable server-side SDK key age in days. Defaults to 365.", default: 365 })),
      flag_limit: Type.Optional(Type.Number({ description: "Maximum flags per environment to inspect. Defaults to 500. Findings that depend on the listing warn instead of passing when it is truncated at this limit.", default: 500 })),
      stale_flag_days: Type.Optional(Type.Number({ description: "Days without evaluation before a flag is stale. Defaults to 30.", default: 30 })),
      retention_days: Type.Optional(Type.Number({ description: "Required queryable audit log retention in days. Defaults to 90.", default: 90 })),
      integration_keys: Type.Optional(Type.String({ description: "Comma-separated integration keys to probe for audit log subscriptions." })),
      relay_config_max_age_days: Type.Optional(Type.Number({ description: "Days before an unmodified Relay Proxy configuration is flagged. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveLaunchdarklyConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportLaunchdarklyAuditBundle(new LaunchdarklyApiClient(config), config, outputRoot, toBundleOptions(args));
        return textResult(
          [
            "LaunchDarkly audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "launchdarkly_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `LaunchDarkly audit bundle export failed: ${errorMessage(error)}`,
          { tool: "launchdarkly_export_audit_bundle" },
        );
      }
    },
  });
}
