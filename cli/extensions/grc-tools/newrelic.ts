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
const NRQL_MAX_ROWS = 2000;
const CAUSE_MAX_LENGTH = 200;
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
  coverage: string[];
  coreData: Record<string, unknown>;
}

export interface NewrelicAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface PagedList<T = JsonRecord> {
  items: T[];
  complete: boolean;
  totalCount?: number;
  note?: string;
  failures?: string[];
}

/**
 * Why a cursor walk stopped. Only `exhausted` (no next cursor and every reported item seen) may yield a complete
 * listing; every other exit is a cap or an anomaly and is reported as truncated so no verdict can pass on it.
 */
type PaginationStop =
  | { kind: "exhausted" }
  | { kind: "cursor_stalled" }
  | { kind: "empty_page" }
  | { kind: "limit"; limit: number }
  | { kind: "page_cap"; pages: number };

function describePagination(seen: number, totalCount: number | undefined, stop: PaginationStop): Pick<PagedList, "complete" | "note"> {
  const progress = `${seen}${totalCount !== undefined ? ` of ${totalCount}` : ""} items`;
  switch (stop.kind) {
    case "exhausted":
      if (totalCount !== undefined && seen < totalCount) {
        return { complete: false, note: `${progress} seen before the listing ended without a next cursor` };
      }
      return { complete: true };
    case "cursor_stalled":
      return { complete: false, note: `stopped after ${progress} because the next cursor did not advance` };
    case "empty_page":
      return { complete: false, note: `stopped after ${progress} because a page returned no items while a next cursor was reported` };
    case "limit":
      return { complete: false, note: `stopped after ${progress} with more pages available (${stop.limit} item limit)` };
    case "page_cap":
      return { complete: false, note: `stopped after ${progress} with more pages available (${stop.pages} page maximum)` };
    default: {
      const unhandled: never = stop;
      throw new Error(`Unhandled pagination stop ${String(unhandled)}`);
    }
  }
}

/** Classifies a page result; `undefined` means the walk continues with `nextCursor`. */
function paginationStopAfterPage(
  pageItemCount: number,
  keptCount: number,
  seen: number,
  limit: number,
  cursor: string | undefined,
  nextCursor: string | undefined,
): PaginationStop | undefined {
  if (keptCount < pageItemCount) return { kind: "limit", limit };
  if (!nextCursor) return { kind: "exhausted" };
  if (nextCursor === cursor) return { kind: "cursor_stalled" };
  if (pageItemCount === 0) return { kind: "empty_page" };
  if (seen >= limit) return { kind: "limit", limit };
  return undefined;
}

/**
 * One inventory as the collectors return it. `source` is the dataset label every status and coverage note uses
 * (for example `alerts.policiesSearch`). Exactly one of these states holds: complete (no flag set), truncated
 * (`truncated`, with `seen` and `total`), partly readable (`partial` lists the scopes that failed), unreadable
 * (`error`), or not collected (`notCollected`: the query was never issued because its input, such as the account
 * list, was unreadable or empty). Counts and lists derived from an inventory in any of the last three states render as
 * null beside a status naming the query path, never as 0, [], {}, or false.
 */
export interface Collected<T> {
  data: T;
  source: string;
  error?: string;
  notCollected?: string;
  partial?: string[];
  truncated?: boolean;
  seen?: number;
  total?: number;
  note?: string;
  /** The inventory this one was computed from (the script scan reads the monitor listing); its gaps are this one's gaps too. */
  derivedFrom?: Collected<unknown>;
}

/** Thrown by a scoped collector when it had no scopes to query; `collectList` records it as a not-collected inventory. */
class NotCollectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotCollectedError";
  }
}

/** Thrown by `resolveAccountIds` when `actor.accounts` answered with zero accounts and no account id is configured. */
export class NewrelicNoAccountsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NewrelicNoAccountsError";
  }
}

/**
 * The accounts the account-scoped collectors query, with how they were resolved. When neither configuration nor
 * `actor.accounts` yields an account, every account-scoped inventory is recorded as not collected, naming
 * `actor.accounts` and the reason, rather than as a complete empty listing.
 */
export interface AccountScope {
  accountIds: number[];
  source: "account_ids" | "actor.accounts";
  /** Why `actor.accounts` yielded no account: its error text, or `undefined` when it answered with an empty list. */
  error?: string;
}

interface ScopeSet {
  scopes: Array<{ id: string; label: string }>;
  /** Completes "<source> was not queried ..." when the set is empty, naming the upstream query and why it yielded no scope. */
  noScopesReason: string;
}

interface Verdict {
  status: NewrelicFindingStatus;
  summary: string;
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

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
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
    const pairedZip = resolveSecureOutputPath(root, `${preferredName}${suffix}.zip`);
    if (!existsSync(candidate) && !existsSync(pairedZip)) {
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

/**
 * aiNotifications.destinations and aiNotifications.channels document a per-account `error { details }` object beside
 * the entities list. A non-null error makes the account unreadable instead of an empty inventory.
 */
function notificationPageError(pageObject: JsonRecord): string | undefined {
  const error = asObject(pageObject.error);
  if (!error) return undefined;
  const details = asString(error.details) ?? asString(error.description) ?? asString(error.type);
  return details ?? JSON.stringify(error);
}

/**
 * NerdGraph reports a selection that does not match the schema with validation errors such as
 * `Cannot query field "nextCursor" on type "ApiAccessKeySearchResult"`, `Unknown argument "cursor" on field ...`,
 * `Unknown field`, or `Argument "query" has invalid value`. Authorization failures use different wording and must
 * not match, so they keep propagating as unreadable surfaces.
 */
function isSchemaMismatchError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /cannot query field|unknown argument|unknown field|has invalid value|is not defined|does not accept|undefined argument|undefined field|does not exist on type|field .* doesn't exist/i.test(message);
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

/*
 * NerdGraph selections. Every field requested below is traceable either to a public docs.newrelic.com page (cited as
 * "Documented", paths relative to docs.newrelic.com/docs/) or to the public NerdGraph schema (cited as "Schema
 * reference", using the type names shown in the GraphiQL explorer and mirrored by the generated types in
 * github.com/newrelic/newrelic-client-go pkg/<package>/types.go). Fields that are neither documented nor read by a
 * verdict are not requested, because one unknown field fails the whole document and every control that reads it.
 * The full selection set is exported as NEWRELIC_NERDGRAPH_SELECTIONS so tests can hold it to that allowlist.
 */

/**
 * Caller identity, organization, and account inventory.
 * Documented: apis/nerdgraph/examples/manage-live-dashboard-urls-via-api queries actor.user { name }; the user and
 *   group tutorials query under actor.organization; accounts/accounts-billing/account-structure/multi-tenancy/
 *   delegated-administration filters collections by organization id.
 * Schema reference: User { email id name } (pkg/users), Organization { id name } (pkg/organization),
 *   AccountOutline { id name } (pkg/accounts).
 */
const QUERY_CURRENT_USER = "{ actor { user { id email name } } }";
const QUERY_ORGANIZATION = "{ actor { organization { id name } } }";
const QUERY_ACCOUNTS = "{ actor { accounts { id name } } }";
/**
 * Authentication domains and their users.
 * Documented: apis/nerdgraph/examples/nerdgraph-manage-users ("Pagination"):
 *   userManagement.authenticationDomains(cursor) { nextCursor totalCount authenticationDomains { id name } } and
 *   authenticationDomains(id) { authenticationDomains { users(cursor) { nextCursor totalCount users { id name email
 *   lastActive type { displayName id } } } } }; apis/nerdgraph/examples/nerdgraph-manage-groups documents
 *   users { groups { groups { displayName } } } and groups { groups { displayName id } }.
 * Schema reference: UserManagementAuthenticationDomain.provisioningType (pkg/usermanagement), read by control 19.
 * emailVerificationState and timeZone are not requested because no verdict reads them.
 */
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
      id
      users(cursor: $cursor) {
        nextCursor totalCount
        users {
          id name email lastActive
          type { id displayName }
          groups { groups { id displayName } }
        }
      }
    } }
  } } }
}`;
/**
 * Group role grants.
 * Documented: apis/nerdgraph/examples/nerdgraph-manage-groups ("Query existing roles"):
 *   authorizationManagement.authenticationDomains { authenticationDomains { groups { groups { roles { roles
 *   { accountId displayName id name organizationId type } } } } } }, and groups { groups { displayName id } }.
 * Schema reference (pkg/organization): AuthorizationManagementAuthenticationDomainSearch { authenticationDomains
 *   nextCursor totalCount }, AuthorizationManagementAuthenticationDomain { id name groups },
 *   AuthorizationManagementGroupSearch { groups nextCursor totalCount }, AuthorizationManagementGroup { id displayName
 *   roles }, described as containers "enabling cursor based pagination". The `id` filter and `cursor` argument follow
 *   the documented userManagement shape for the same collections (nerdgraph-manage-users, "Pagination").
 * The authorizationManagement tutorial shows only the nested shape, so when NerdGraph rejects either argument
 *   QUERY_DOMAIN_GROUP_GRANTS_DOCUMENTED reads that shape as one page, filters it to the requested domain, and reports
 *   the listing as incomplete.
 */
const GROUP_GRANT_FIELDS = `groups {
          id displayName
          roles { roles { id name displayName type accountId organizationId } }
        }`;
const QUERY_DOMAIN_GROUP_GRANTS = `query($domainId: [ID!], $cursor: String) {
  actor { organization { authorizationManagement {
    authenticationDomains(id: $domainId) { authenticationDomains {
      id
      groups(cursor: $cursor) {
        nextCursor totalCount
        ${GROUP_GRANT_FIELDS}
      }
    } }
  } } }
}`;
const QUERY_DOMAIN_GROUP_GRANTS_DOCUMENTED = `{
  actor { organization { authorizationManagement {
    authenticationDomains { authenticationDomains {
      id
      groups {
        ${GROUP_GRANT_FIELDS}
      }
    } }
  } } }
}`;
/**
 * Role catalog. The documented catalog is
 *   customerAdministration.roles(filter: { organizationId: { eq } }) { items { id name scope type } }
 * Documented: docs.newrelic.com/docs/accounts/accounts-billing/account-structure/multi-tenancy/delegated-administration
 *   ("List roles"); the same page documents that customerAdministration requires the multi-tenancy entitlement, so
 *   the surface is optional in newrelic_check_access and control 20 renders manual when it is unavailable.
 *   The groups tutorial (nerdgraph-manage-groups) documents roles only nested under groups.roles, which
 *   QUERY_DOMAIN_GROUP_GRANTS reads.
 * Schema reference: MultiTenantAuthorizationRoleCollection { items nextCursor totalCount }; MultiTenantAuthorizationRole
 *   { id name scope type } where type is MultiTenantAuthorizationRoleTypeEnum with the values CUSTOM and STANDARD.
 *   The `cursor` argument is documented on the sibling customerAdministration collections (share-accounts:
 *   accountShares, accounts) and is only sent when a nextCursor was returned.
 */
const ROLE_FIELDS = "id name scope type";
const ROLE_COLLECTION_FIELDS = "nextCursor totalCount";
const ROLE_CATALOG_SOURCE = "customerAdministration.roles";
const ROLE_TYPE_CUSTOM = "CUSTOM";
const ROLE_TYPE_STANDARD = "STANDARD";
/**
 * Documented: delegated-administration ("Query authentication domains"):
 *   customerAdministration.authenticationDomains(filter: { organizationId: { eq } }) { items { id name provisioningType authenticationType } }
 * Schema reference: OrganizationAuthenticationDomainCollection { items nextCursor } and OrganizationAuthenticationDomain
 *   { id name organizationId provisioningType authenticationType }.
 */
const AUTHENTICATION_DOMAIN_FIELDS = "id name organizationId provisioningType authenticationType";
const AUTHENTICATION_DOMAIN_COLLECTION_FIELDS = "nextCursor";
/**
 * API key inventory. Three layers, tried in order; a schema mismatch on one layer falls through to the next.
 * Documented: docs.newrelic.com/docs/apis/nerdgraph/examples/use-nerdgraph-manage-license-keys-user-keys
 *   keySearch(query: { types, scope: { ingestTypes } }) { keys { name key type ... on ApiAccessIngestKey { ingestType } } }
 *   and the mutation responses createdKeys/updatedKeys { id key name notes type }. The key string is never requested.
 * Schema reference (public NerdGraph schema, mirrored by newrelic-client-go pkg/apiaccess/types.go):
 *   ApiAccessKeySearchResult { count keys nextCursor }; ApiAccessKeySearchScope { accountIds ingestTypes userIds };
 *   ApiAccessUserKey { accountId createdAt id name type userId }; ApiAccessIngestKey { accountId createdAt id ingestType name type }.
 * Layer 1 (QUERY_API_KEYS) adds the schema-cited pagination fields and the `cursor` argument, layer 2
 * (QUERY_API_KEYS_SINGLE_PAGE) keeps the schema-cited key fields without a cursor, and layer 3
 * (QUERY_API_KEYS_DOCUMENTED) reads only fields shown on the docs page. When layer 3 is used, createdAt, userId and
 * accountId are absent, so controls 4, 5 and 6 render manual for the parts that need them.
 */
const API_KEY_FIELDS = `keys {
        id name type createdAt
        ... on ApiAccessIngestKey { accountId ingestType }
        ... on ApiAccessUserKey { accountId userId }
      }`;
const API_KEY_DOCUMENTED_FIELDS = `keys {
        id name type
        ... on ApiAccessIngestKey { ingestType }
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
const QUERY_API_KEYS_DOCUMENTED = `query($query: ApiAccessKeySearchQuery!) {
  actor { apiAccess {
    keySearch(query: $query) {
      ${API_KEY_DOCUMENTED_FIELDS}
    }
  } }
}`;
export const API_KEY_DOCUMENTED_ONLY_NOTE = "keySearch rejected the schema-cited fields, so only the documented fields (id, name, type, ingestType) were read on a single page; createdAt, userId, accountId, and pagination are unavailable and completeness is unknown";
/**
 * NRQL (NrAuditEvent and usage queries).
 * Documented: apis/nerdgraph/examples/nerdgraph-nrql-tutorial: actor.account(id).nrql(query) { results }.
 */
const QUERY_NRQL = `query($accountId: Int!, $nrql: Nrql!) {
  actor { account(id: $accountId) { nrql(query: $nrql) { results } } }
}`;
/**
 * Entity search (alert coverage, dashboards, synthetic monitors, secure credentials, workloads).
 * Documented: apis/nerdgraph/examples/nerdgraph-entities-api-tutorial: entitySearch(query) { count results(cursor)
 *   { nextCursor entities { name entityType guid domain reporting ... on AlertableEntityOutline { alertSeverity } } } };
 *   apis/nerdgraph/examples/synthetics-api/query-synthetics-data: ... on SyntheticMonitorEntityOutline { guid name
 *   accountId monitorType tags { key values } } and ... on SecureCredentialEntityOutline { accountId guid name tags };
 *   apis/nerdgraph/examples/nerdgraph-workloads-api-tutorials: workloadStatus { statusValue } on WorkloadEntity;
 *   apis/nerdgraph/examples/nerdgraph-dashboards: permissions on DashboardEntity.
 * Schema reference (pkg/entities): EntityOutline.type; DashboardEntityOutline.permissions;
 *   WorkloadEntityOutline.workloadStatus { statusValue }.
 * Not requested because no verdict reads them: dashboardParentGuid, createdAt, updatedAt, owner { email userId }
 *   (dashboards), monitoredUrl, period, monitorId (monitors), and the SecureCredentialEntityOutline fields
 *   secureCredentialId, updatedAt, description; secure credentials are counted through the shared outline fields.
 */
const QUERY_ENTITY_SEARCH = `query($query: String!, $cursor: String) {
  actor { entitySearch(query: $query) {
    count
    results(cursor: $cursor) {
      nextCursor
      entities {
        guid name entityType domain type accountId reporting
        tags { key values }
        ... on AlertableEntityOutline { alertSeverity }
        ... on DashboardEntityOutline { permissions }
        ... on SyntheticMonitorEntityOutline { monitorType }
        ... on WorkloadEntityOutline { workloadStatus { statusValue } }
      }
    }
  } }
}`;
/**
 * Alert policies and NRQL conditions.
 * Documented: apis/nerdgraph/examples/nerdgraph-api-alerts-policies ("Paginating through policies"):
 *   alerts.policiesSearch(cursor) { nextCursor policies { id name incidentPreference } totalCount };
 *   apis/nerdgraph/examples/nerdgraph-api-nrql-condition-alerts ("List and filter NRQL conditions" and "Get all the
 *   conditions for a policy"): nrqlConditionsSearch(cursor) { nextCursor totalCount nrqlConditions { id name type
 *   enabled nrql { query } policyId } }.
 * The policy accountId field is not requested; the account is recorded from the queried account instead.
 */
const QUERY_ALERT_POLICIES = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { alerts {
    policiesSearch(cursor: $cursor) { nextCursor totalCount policies { id name incidentPreference } }
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
/**
 * Notification destinations.
 * Documented: docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-notifications-destinations:
 *   aiNotifications.destinations(cursor: "") { nextCursor totalCount entities { id name } error { details } }, plus the
 *   documented filters `type: EMAIL` and the mutation inputs `type` and `properties { key value }`.
 * Schema reference: AiNotificationsDestination { id name type properties }; AiNotificationsProperty { key value }.
 * The destination `active`, `status`, `isUserAuthenticated`, `lastSent`, and `properties.displayValue` fields are
 * not requested; control 10 verifies enablement through the documented workflowEnabled flag instead.
 */
const QUERY_DESTINATIONS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiNotifications {
    destinations(cursor: $cursor) {
      nextCursor totalCount
      entities { id name type properties { key value } }
      error { details }
    }
  } } }
}`;
/**
 * Notification channels.
 * Documented: docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-notifications-channels:
 *   aiNotifications.channels(cursor: "") { nextCursor totalCount entities { id name } error { details } }, plus the
 *   documented filters `destinationId` and `type`.
 * Schema reference: AiNotificationsChannel { id name type destinationId }.
 */
const QUERY_CHANNELS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiNotifications {
    channels(cursor: $cursor) {
      nextCursor totalCount
      entities { id name type destinationId }
      error { details }
    }
  } } }
}`;
/**
 * Workflows.
 * Documented: docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-workflows ("List workflows" and the
 *   create mutation response): aiWorkflows.workflows(filters: {}) { nextCursor totalCount entities { id name
 *   workflowEnabled destinationConfigurations { channelId name type notificationTriggers } enrichments { id name
 *   configurations { ... on AiWorkflowsNrqlConfiguration { query } } } enrichmentsEnabled destinationsEnabled } }.
 *   The page describes cursor pagination through nextCursor; if the `cursor` argument is rejected the first page is
 *   returned as an incomplete listing.
 */
const QUERY_WORKFLOWS = `query($accountId: Int!, $cursor: String) {
  actor { account(id: $accountId) { aiWorkflows {
    workflows(filters: {}, cursor: $cursor) {
      nextCursor totalCount
      entities {
        id name workflowEnabled enrichmentsEnabled destinationsEnabled
        destinationConfigurations { channelId name type notificationTriggers }
        enrichments { id name configurations { ... on AiWorkflowsNrqlConfiguration { query } } }
      }
    }
  } } }
}`;
const QUERY_WORKFLOWS_SINGLE_PAGE = QUERY_WORKFLOWS.replace("query($accountId: Int!, $cursor: String)", "query($accountId: Int!)").replace("workflows(filters: {}, cursor: $cursor)", "workflows(filters: {})");
/**
 * Data retention rules and customizable namespaces.
 * Documented: data-apis/manage-data/manage-data-retention ("List active rules on an account" and "List the
 *   customizable retention event namespaces"): dataManagement.eventRetentionRules { id deletedAt deletedById createdAt
 *   createdById retentionInDays namespace } and customizableRetention { eventNamespaces { namespace } }.
 */
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
/**
 * Log obfuscation rules and expressions.
 * Documented: logs/ui-data/obfuscation-ui ("Read an obfuscation rule" and "Read an obfuscation expression", the
 *   populated GraphiQL links): logConfigurations.obfuscationRules { id name description filter enabled actions
 *   { attributes expression { name } method } createdAt updatedAt } and obfuscationExpressions { id name regex
 *   description createdAt updatedAt }. The expression id inside an action is not requested; the documented read
 *   selects only its name.
 */
const QUERY_OBFUSCATION_RULES = `query($accountId: Int!) {
  actor { account(id: $accountId) { logConfigurations {
    obfuscationRules {
      id name description filter enabled createdAt updatedAt
      actions { attributes method expression { name } }
    }
  } } }
}`;
const QUERY_OBFUSCATION_EXPRESSIONS = `query($accountId: Int!) {
  actor { account(id: $accountId) { logConfigurations {
    obfuscationExpressions { id name regex description createdAt updatedAt }
  } } }
}`;
/**
 * Pipeline Control cloud rules.
 * Documented: new-relic-control/pipeline-control/cloud-rules/api-reference ("List all cloud rules"):
 *   entityManagement.entitySearch(query: "type = 'PIPELINE_CLOUD_RULE'") { entities { id type
 *   ... on EntityManagementPipelineCloudRuleEntity { id name nrql enabled } } }; the "Get a single cloud rule"
 *   example adds description on the same type.
 * Schema reference (pkg/pipelinecontrol): EntityManagementEntitySearchResult.nextCursor, read only to report that
 *   more pages exist.
 */
const QUERY_PIPELINE_CLOUD_RULES = `{
  actor { entityManagement {
    entitySearch(query: "type = 'PIPELINE_CLOUD_RULE'") {
      nextCursor
      entities {
        id type
        ... on EntityManagementPipelineCloudRuleEntity { id name nrql description enabled }
      }
    }
  } }
}`;
/**
 * NRQL drop rules.
 * Documented: data-apis/manage-data/drop-data-using-nerdgraph ("returns the drop rules set on an account"):
 *   nrqlDropRules.list { rules { id nrql accountId action createdBy createdAt description } error { reason description } }.
 */
const QUERY_NRQL_DROP_RULES = `query($accountId: Int!) {
  actor { account(id: $accountId) { nrqlDropRules {
    list { rules { id nrql accountId action createdBy createdAt description } error { reason description } }
  } } }
}`;
/**
 * Scripted monitor source.
 * Documented: apis/nerdgraph/examples/synthetics-api/query-synthetics-data ("Query monitor script"):
 *   account(id).synthetics.script(monitorGuid) { text }.
 */
const QUERY_SYNTHETIC_SCRIPT = `query($accountId: Int!, $monitorGuid: EntityGuid!) {
  actor { account(id: $accountId) { synthetics { script(monitorGuid: $monitorGuid) { text } } } }
}`;
/**
 * Public live URLs for dashboards and charts.
 * Documented: docs.newrelic.com/docs/apis/nerdgraph/examples/manage-live-chart-urls-via-api ("List all live chart URLs"):
 *   actor.dashboard.liveUrls { liveUrls { title url createdAt type } errors { description } } (unfiltered, returns
 *   DASHBOARD and WIDGET entries), and manage-live-dashboard-urls-via-api ("List the public dashboard URLs"):
 *   liveUrls(filter: { type: DASHBOARD }) { liveUrls { createdAt type uuid } }.
 * The query stays unfiltered because a public widget URL exposes data just as a public dashboard URL does; `url`
 * and `uuid` are never requested so link values do not land in evidence bundles.
 */
const QUERY_DASHBOARD_LIVE_URLS = `{
  actor { dashboard { liveUrls { liveUrls { title type createdAt } errors { description } } } }
}`;

/** Every NerdGraph selection the inspector can send, keyed by purpose, so tests can hold it to the documented allowlist. */
export const NEWRELIC_NERDGRAPH_SELECTIONS: Readonly<Record<string, string>> = Object.freeze({
  currentUser: QUERY_CURRENT_USER,
  organization: QUERY_ORGANIZATION,
  accounts: QUERY_ACCOUNTS,
  authenticationDomains: QUERY_AUTHENTICATION_DOMAINS,
  domainUsers: QUERY_DOMAIN_USERS,
  domainGroupGrants: QUERY_DOMAIN_GROUP_GRANTS,
  domainGroupGrantsDocumented: QUERY_DOMAIN_GROUP_GRANTS_DOCUMENTED,
  roleCatalogFields: `${ROLE_FIELDS} ${ROLE_COLLECTION_FIELDS}`,
  organizationAuthenticationDomainFields: `${AUTHENTICATION_DOMAIN_FIELDS} ${AUTHENTICATION_DOMAIN_COLLECTION_FIELDS}`,
  apiKeys: QUERY_API_KEYS,
  apiKeysSinglePage: QUERY_API_KEYS_SINGLE_PAGE,
  apiKeysDocumented: QUERY_API_KEYS_DOCUMENTED,
  nrql: QUERY_NRQL,
  entitySearch: QUERY_ENTITY_SEARCH,
  alertPolicies: QUERY_ALERT_POLICIES,
  nrqlConditions: QUERY_NRQL_CONDITIONS,
  destinations: QUERY_DESTINATIONS,
  channels: QUERY_CHANNELS,
  workflows: QUERY_WORKFLOWS,
  workflowsSinglePage: QUERY_WORKFLOWS_SINGLE_PAGE,
  retentionRules: QUERY_RETENTION_RULES,
  retentionNamespaces: QUERY_RETENTION_NAMESPACES,
  obfuscationRules: QUERY_OBFUSCATION_RULES,
  obfuscationExpressions: QUERY_OBFUSCATION_EXPRESSIONS,
  pipelineCloudRules: QUERY_PIPELINE_CLOUD_RULES,
  nrqlDropRules: QUERY_NRQL_DROP_RULES,
  syntheticScript: QUERY_SYNTHETIC_SCRIPT,
  dashboardLiveUrls: QUERY_DASHBOARD_LIVE_URLS,
});

/*
 * Stored record shapes.
 * Every record that reaches an assessment or an evidence bundle is projected to the fields its query selects plus the
 * scope fields this module attaches (queriedAccountId, authenticationDomainId, authenticationDomainName,
 * provisioningType on users, rolesReadable on group grants). A value the API volunteers beyond the selection is
 * dropped before it can reach core_data or a finding. `true` keeps a scalar or a list of scalars, a nested shape
 * projects an object or each object of a list, and a function supplies its own projection. Values are dropped, never
 * rewritten, with one exception: destination property values are kept only for the documented `email` key, because
 * the destinations tutorial documents the other property values as credential-bearing (webhook URLs with embedded
 * tokens, security codes, Slack access tokens, Authorization header values). NrAuditEvent.actorAPIKey is stored as
 * returned because the attribute dictionary documents it as the partially obfuscated key ID.
 * Drop-rule and pipeline-rule NRQL, obfuscation rule filters, and obfuscation expression regexes are stored verbatim
 * as evidence and may quote literals from the tenant's own configuration.
 */
type FieldShape = true | RecordShape | ((value: unknown) => unknown);
interface RecordShape {
  readonly [field: string]: FieldShape;
}

function isScalarValue(value: unknown): boolean {
  return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function projectScalar(value: unknown): unknown {
  if (isScalarValue(value)) return value;
  if (Array.isArray(value)) return value.filter(isScalarValue);
  return undefined;
}

function projectValue(value: unknown, shape: FieldShape): unknown {
  if (shape === true) return projectScalar(value);
  if (typeof shape === "function") return shape(value);
  if (Array.isArray(value)) {
    return value
      .map((entry) => asObject(entry))
      .filter((entry): entry is JsonRecord => entry !== undefined)
      .map((entry) => projectRecord(entry, shape));
  }
  if (value === null) return null;
  const record = asObject(value);
  return record ? projectRecord(record, shape) : undefined;
}

/** Keeps only the fields named by `shape`; anything else the API returned is dropped. */
export function projectRecord(record: JsonRecord, shape: RecordShape): JsonRecord {
  const projected: JsonRecord = {};
  for (const [field, fieldShape] of Object.entries(shape)) {
    if (!(field in record)) continue;
    const value = projectValue(record[field], fieldShape);
    if (value !== undefined) projected[field] = value;
  }
  return projected;
}

const DESTINATION_EMAIL_PROPERTY_KEY = "email";

/** Stores destination property keys, and a value only for the email address key that control 10 reads. */
function projectDestinationProperties(value: unknown): JsonRecord[] {
  return asRecords(value).flatMap((property) => {
    const key = asString(property.key);
    if (key === undefined) return [];
    if (key.toLowerCase() !== DESTINATION_EMAIL_PROPERTY_KEY) return [{ key }];
    const address = projectScalar(property.value);
    return [address === undefined ? { key } : { key, value: address }];
  });
}

const SCOPE_SHAPE: RecordShape = { queriedAccountId: true };
const ORGANIZATION_SHAPE: RecordShape = { id: true, name: true };
const CURRENT_USER_SHAPE: RecordShape = { id: true, email: true, name: true };
const ACCOUNT_SHAPE: RecordShape = { id: true, name: true };
const AUTHENTICATION_DOMAIN_SHAPE: RecordShape = { id: true, name: true, provisioningType: true };
const ORGANIZATION_AUTHENTICATION_DOMAIN_SHAPE: RecordShape = {
  id: true,
  name: true,
  organizationId: true,
  provisioningType: true,
  authenticationType: true,
};
const USER_SHAPE: RecordShape = {
  id: true,
  name: true,
  email: true,
  lastActive: true,
  type: { id: true, displayName: true },
  groups: { groups: { id: true, displayName: true } },
  authenticationDomainId: true,
  authenticationDomainName: true,
  provisioningType: true,
};
const GROUP_GRANT_SHAPE: RecordShape = {
  id: true,
  displayName: true,
  roles: { id: true, name: true, displayName: true, type: true, accountId: true, organizationId: true },
  rolesReadable: true,
  authenticationDomainId: true,
};
const ROLE_SHAPE: RecordShape = { id: true, name: true, scope: true, type: true };
const API_KEY_SHAPE: RecordShape = { id: true, name: true, type: true, createdAt: true, ingestType: true, accountId: true, userId: true };
const API_KEY_ACTOR_EVENT_SHAPE: RecordShape = {
  actorAPIKey: true,
  actorId: true,
  actorEmail: true,
  actionIdentifier: true,
  targetType: true,
  targetId: true,
  timestamp: true,
  ...SCOPE_SHAPE,
};
const API_KEY_CHANGE_EVENT_SHAPE: RecordShape = {
  actionIdentifier: true,
  actorEmail: true,
  actorType: true,
  description: true,
  targetType: true,
  targetId: true,
  timestamp: true,
  ...SCOPE_SHAPE,
};
const ALERT_POLICY_SHAPE: RecordShape = { id: true, name: true, incidentPreference: true, ...SCOPE_SHAPE };
const NRQL_CONDITION_SHAPE: RecordShape = { id: true, name: true, type: true, enabled: true, policyId: true, nrql: { query: true }, ...SCOPE_SHAPE };
const DESTINATION_SHAPE: RecordShape = { id: true, name: true, type: true, properties: projectDestinationProperties, ...SCOPE_SHAPE };
const CHANNEL_SHAPE: RecordShape = { id: true, name: true, type: true, destinationId: true, ...SCOPE_SHAPE };
const WORKFLOW_SHAPE: RecordShape = {
  id: true,
  name: true,
  workflowEnabled: true,
  enrichmentsEnabled: true,
  destinationsEnabled: true,
  destinationConfigurations: { channelId: true, name: true, type: true, notificationTriggers: true },
  enrichments: { id: true, name: true, configurations: { query: true } },
  ...SCOPE_SHAPE,
};
const ENTITY_SHAPE: RecordShape = {
  guid: true,
  name: true,
  entityType: true,
  domain: true,
  type: true,
  accountId: true,
  reporting: true,
  tags: { key: true, values: true },
  alertSeverity: true,
  permissions: true,
  monitorType: true,
  workloadStatus: { statusValue: true },
  ...SCOPE_SHAPE,
};
const RETENTION_RULE_SHAPE: RecordShape = {
  id: true,
  namespace: true,
  retentionInDays: true,
  createdAt: true,
  createdById: true,
  deletedAt: true,
  deletedById: true,
  ...SCOPE_SHAPE,
};
const RETENTION_NAMESPACE_SHAPE: RecordShape = { namespace: true, ...SCOPE_SHAPE };
const OBFUSCATION_RULE_SHAPE: RecordShape = {
  id: true,
  name: true,
  description: true,
  filter: true,
  enabled: true,
  createdAt: true,
  updatedAt: true,
  actions: { attributes: true, method: true, expression: { name: true } },
  ...SCOPE_SHAPE,
};
const OBFUSCATION_EXPRESSION_SHAPE: RecordShape = { id: true, name: true, regex: true, description: true, createdAt: true, updatedAt: true, ...SCOPE_SHAPE };
const PIPELINE_CLOUD_RULE_SHAPE: RecordShape = { id: true, type: true, name: true, nrql: true, description: true, enabled: true };
const NRQL_DROP_RULE_SHAPE: RecordShape = { id: true, nrql: true, accountId: true, action: true, createdBy: true, createdAt: true, description: true, ...SCOPE_SHAPE };
const LIVE_URL_SHAPE: RecordShape = { title: true, type: true, createdAt: true };
const SYNTHETIC_SCRIPT_SCAN_SHAPE: RecordShape = {
  guid: true,
  name: true,
  accountId: true,
  monitorType: true,
  scriptLength: true,
  usesSecureCredentials: true,
  secretIndicators: true,
};
const LOG_VOLUME_SHAPE: RecordShape = { logCount: true, ...SCOPE_SHAPE };
const LOG_SECRET_MATCH_SHAPE: RecordShape = { matchCount: true, ...SCOPE_SHAPE };
const INFRA_HOST_COUNT_SHAPE: RecordShape = { reportingHosts: true, ...SCOPE_SHAPE };
const INFRA_AGENT_VERSION_SHAPE: RecordShape = { agentVersion: true, facet: true, hosts: true, ...SCOPE_SHAPE };

/** Every stored record shape, keyed by purpose, so tests can hold each one to the fields its query selects. */
export const NEWRELIC_STORED_RECORD_SHAPES: Readonly<Record<string, RecordShape>> = Object.freeze({
  organization: ORGANIZATION_SHAPE,
  currentUser: CURRENT_USER_SHAPE,
  accounts: ACCOUNT_SHAPE,
  authenticationDomains: AUTHENTICATION_DOMAIN_SHAPE,
  organizationAuthenticationDomains: ORGANIZATION_AUTHENTICATION_DOMAIN_SHAPE,
  users: USER_SHAPE,
  groupGrants: GROUP_GRANT_SHAPE,
  roles: ROLE_SHAPE,
  apiKeys: API_KEY_SHAPE,
  apiKeyActorEvents: API_KEY_ACTOR_EVENT_SHAPE,
  apiKeyChangeEvents: API_KEY_CHANGE_EVENT_SHAPE,
  alertPolicies: ALERT_POLICY_SHAPE,
  nrqlConditions: NRQL_CONDITION_SHAPE,
  destinations: DESTINATION_SHAPE,
  channels: CHANNEL_SHAPE,
  workflows: WORKFLOW_SHAPE,
  entities: ENTITY_SHAPE,
  retentionRules: RETENTION_RULE_SHAPE,
  retentionNamespaces: RETENTION_NAMESPACE_SHAPE,
  obfuscationRules: OBFUSCATION_RULE_SHAPE,
  obfuscationExpressions: OBFUSCATION_EXPRESSION_SHAPE,
  pipelineCloudRules: PIPELINE_CLOUD_RULE_SHAPE,
  nrqlDropRules: NRQL_DROP_RULE_SHAPE,
  dashboardLiveUrls: LIVE_URL_SHAPE,
  syntheticScriptScan: SYNTHETIC_SCRIPT_SCAN_SHAPE,
  logVolume: LOG_VOLUME_SHAPE,
  logSecretMatches: LOG_SECRET_MATCH_SHAPE,
  infraHostCounts: INFRA_HOST_COUNT_SHAPE,
  infraAgentVersions: INFRA_AGENT_VERSION_SHAPE,
});

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
    totalPath?: Array<string | number>,
  ): Promise<PagedList> {
    const items: JsonRecord[] = [];
    const pageLabel = pagePath.filter((segment) => typeof segment === "string").join(".");
    let cursor: string | undefined;
    let totalCount: number | undefined;
    let stop: PaginationStop | undefined;
    for (let page = 0; page < MAX_PAGES && !stop; page += 1) {
      const data = await this.nerdgraph(query, cursor ? { ...variables, cursor } : variables);
      const pageObject = asObject(getNestedValue(data, pagePath));
      if (!pageObject) throw new Error(`NerdGraph response did not include ${pageLabel}.`);
      const pageError = notificationPageError(pageObject);
      if (pageError) throw new Error(`${pageLabel} returned an error: ${pageError}`);
      const pageItems = asRecords(pageObject[itemsKey]);
      totalCount = asNumber(totalPath ? getNestedValue(data, totalPath) : pageObject.totalCount ?? pageObject.count) ?? totalCount;
      const kept = pageItems.slice(0, Math.max(0, limit - items.length));
      items.push(...kept);
      const nextCursor = asString(pageObject.nextCursor);
      stop = paginationStopAfterPage(pageItems.length, kept.length, items.length, limit, cursor, nextCursor);
      cursor = nextCursor;
    }
    return { items, totalCount, ...describePagination(items.length, totalCount, stop ?? { kind: "page_cap", pages: MAX_PAGES }) };
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

  async restList(path: string, collectionKey: string, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let url: string | undefined = path;
    let limitReached = false;
    for (let page = 0; url && page < MAX_PAGES && items.length < limit; page += 1) {
      const { payload, nextUrl } = await this.restGet(url);
      const pageItems = asRecords(payload[collectionKey]);
      const kept = pageItems.slice(0, Math.max(0, limit - items.length));
      items.push(...kept);
      if (kept.length < pageItems.length) limitReached = true;
      url = nextUrl;
    }
    if (limitReached) {
      return { items, complete: false, note: `stopped after ${items.length} items at the ${limit} item limit with more items available` };
    }
    return {
      items,
      complete: url === undefined,
      note: url === undefined ? undefined : `stopped after ${items.length} items with a Link rel="next" page remaining`,
    };
  }

  async getCurrentUser(): Promise<JsonRecord> {
    const data = await this.nerdgraph(QUERY_CURRENT_USER);
    return asObject(getNestedValue(data, ["actor", "user"])) ?? {};
  }

  async getOrganization(): Promise<JsonRecord> {
    const data = await this.nerdgraph(QUERY_ORGANIZATION);
    return asObject(getNestedValue(data, ["actor", "organization"])) ?? {};
  }

  async listAccounts(): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_ACCOUNTS);
    return completeList(asRecords(getNestedValue(data, ["actor", "accounts"])));
  }

  async resolveAccountIds(): Promise<number[]> {
    if (this.config.accountIds.length > 0) return this.config.accountIds;
    if (!this.discoveredAccountIds) {
      this.discoveredAccountIds = this.listAccounts().then((accounts) => {
        const ids = accounts.items.map((account) => asNumber(account.id)).filter((id): id is number => id !== undefined);
        if (ids.length === 0) {
          throw new NewrelicNoAccountsError("No New Relic accounts were visible to the API key. Set NEW_RELIC_ACCOUNT_ID explicitly.");
        }
        return ids;
      });
      this.discoveredAccountIds.catch(() => {
        this.discoveredAccountIds = undefined;
      });
    }
    return this.discoveredAccountIds;
  }

  async listAuthenticationDomains(limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginate(
      QUERY_AUTHENTICATION_DOMAINS,
      {},
      ["actor", "organization", "userManagement", "authenticationDomains"],
      "authenticationDomains",
      limit,
    );
  }

  /**
   * Reads a customerAdministration collection filtered by organization. The first page never sends a cursor; follow-up
   * pages send the documented `cursor` argument, and if the collection rejects it the first page is returned as an
   * incomplete listing instead of failing the surface.
   */
  private async paginateCustomerAdministration(
    collection: string,
    organizationId: string,
    itemFields: string,
    collectionFields: string,
    limit: number,
  ): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let cursor: string | undefined;
    let totalCount: number | undefined;
    let stop: PaginationStop | undefined;
    for (let page = 0; page < MAX_PAGES && !stop; page += 1) {
      const cursorArgument = cursor ? `, cursor: ${JSON.stringify(cursor)}` : "";
      const query = `{ customerAdministration { ${collection}(filter: { organizationId: { eq: ${JSON.stringify(organizationId)} } }${cursorArgument}) { items { ${itemFields} } ${collectionFields} } } }`;
      let data: JsonRecord;
      try {
        data = await this.nerdgraph(query);
      } catch (error) {
        if (cursor && isSchemaMismatchError(error)) {
          return {
            items,
            complete: false,
            totalCount,
            note: `customerAdministration.${collection} rejected the cursor argument, so only the first page was read (${items.length}${totalCount !== undefined ? ` of ${totalCount}` : ""} items)`,
          };
        }
        throw error;
      }
      const result = asObject(getNestedValue(data, ["customerAdministration", collection]));
      if (!result) throw new Error(`NerdGraph response did not include customerAdministration.${collection}.`);
      const pageItems = asRecords(result.items);
      totalCount = asNumber(result.totalCount) ?? totalCount;
      const kept = pageItems.slice(0, Math.max(0, limit - items.length));
      items.push(...kept);
      const nextCursor = asString(result.nextCursor);
      stop = paginationStopAfterPage(pageItems.length, kept.length, items.length, limit, cursor, nextCursor);
      cursor = nextCursor;
    }
    return { items, totalCount, ...describePagination(items.length, totalCount, stop ?? { kind: "page_cap", pages: MAX_PAGES }) };
  }

  async listOrganizationAuthenticationDomains(organizationId: string, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginateCustomerAdministration(
      "authenticationDomains",
      organizationId,
      AUTHENTICATION_DOMAIN_FIELDS,
      AUTHENTICATION_DOMAIN_COLLECTION_FIELDS,
      limit,
    );
  }

  async listDomainUsers(domainId: string, limit = DEFAULT_USER_LIMIT): Promise<PagedList> {
    return this.paginate(
      QUERY_DOMAIN_USERS,
      { domainId: [domainId] },
      ["actor", "organization", "userManagement", "authenticationDomains", "authenticationDomains", 0, "users"],
      "users",
      limit,
    );
  }

  async listDomainGroupGrants(domainId: string, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    let groups: PagedList;
    try {
      groups = await this.paginate(
        QUERY_DOMAIN_GROUP_GRANTS,
        { domainId: [domainId] },
        ["actor", "organization", "authorizationManagement", "authenticationDomains", "authenticationDomains", 0, "groups"],
        "groups",
        limit,
      );
    } catch (error) {
      if (!isSchemaMismatchError(error)) throw error;
      groups = await this.listDomainGroupGrantsDocumented(domainId, limit);
    }
    return {
      ...groups,
      items: groups.items.map((group) => {
        const roleContainer = asObject(group.roles);
        return {
          id: group.id,
          displayName: group.displayName,
          roles: asRecords(roleContainer?.roles),
          rolesReadable: roleContainer !== undefined,
        };
      }),
    };
  }

  /**
   * Reads the documented (unfiltered, unpaginated) authorizationManagement shape and keeps the groups of one domain.
   * Without nextCursor the listing cannot be proven complete, so it is always reported as incomplete.
   */
  private async listDomainGroupGrantsDocumented(domainId: string, limit: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_DOMAIN_GROUP_GRANTS_DOCUMENTED);
    const domains = asRecords(getNestedValue(data, ["actor", "organization", "authorizationManagement", "authenticationDomains", "authenticationDomains"]));
    const domain = domains.find((candidate) => asString(candidate.id) === domainId);
    const items = asRecords(asObject(domain?.groups)?.groups).slice(0, limit);
    return {
      items,
      complete: false,
      note: domain
        ? `authorizationManagement.authenticationDomains rejected the domain filter or cursor argument, so the documented unpaginated shape was read (${items.length} groups on one page, completeness unknown)`
        : `authorizationManagement.authenticationDomains rejected the domain filter or cursor argument and the documented unpaginated shape did not include domain ${domainId} (${domains.length} domains returned)`,
    };
  }

  async listRoles(organizationId: string, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginateCustomerAdministration("roles", organizationId, ROLE_FIELDS, ROLE_COLLECTION_FIELDS, limit);
  }

  async listApiKeys(types: Array<"USER" | "INGEST">, accountIds?: number[], limit = DEFAULT_USER_LIMIT): Promise<PagedList> {
    const scope = accountIds && accountIds.length > 0 ? { accountIds } : undefined;
    const variables = { query: scope ? { types, scope } : { types } };
    try {
      return await this.paginate(QUERY_API_KEYS, variables, ["actor", "apiAccess", "keySearch"], "keys", limit);
    } catch (error) {
      if (!isSchemaMismatchError(error)) throw error;
    }
    try {
      const search = await this.keySearchPage(QUERY_API_KEYS_SINGLE_PAGE, variables);
      const keys = asRecords(search.keys).slice(0, limit);
      const totalCount = asNumber(search.count);
      return {
        items: keys,
        complete: totalCount !== undefined && keys.length >= totalCount,
        totalCount,
        note: `keySearch rejected the cursor argument, so only the first page was read (${keys.length}${totalCount !== undefined ? ` of ${totalCount}` : ""} keys)`,
      };
    } catch (error) {
      if (!isSchemaMismatchError(error)) throw error;
    }
    const search = await this.keySearchPage(QUERY_API_KEYS_DOCUMENTED, variables);
    const keys = asRecords(search.keys).slice(0, limit);
    return { items: keys, complete: false, note: `${API_KEY_DOCUMENTED_ONLY_NOTE} (${keys.length} keys read)` };
  }

  private async keySearchPage(query: string, variables: JsonRecord): Promise<JsonRecord> {
    const data = await this.nerdgraph(query, variables);
    const search = asObject(getNestedValue(data, ["actor", "apiAccess", "keySearch"]));
    if (!search) throw new Error("NerdGraph response did not include actor.apiAccess.keySearch.");
    return search;
  }

  async runNrql(accountId: number, nrql: string): Promise<JsonRecord[]> {
    const data = await this.nerdgraph(QUERY_NRQL, { accountId, nrql });
    return asRecords(getNestedValue(data, ["actor", "account", "nrql", "results"]));
  }

  async searchEntities(query: string, limit = DEFAULT_ENTITY_LIMIT): Promise<PagedList> {
    return this.paginate(
      QUERY_ENTITY_SEARCH,
      { query },
      ["actor", "entitySearch", "results"],
      "entities",
      limit,
      ["actor", "entitySearch", "count"],
    );
  }

  async countEntities(query: string): Promise<number> {
    const data = await this.nerdgraph(QUERY_ENTITY_SEARCH, { query });
    return asNumber(getNestedValue(data, ["actor", "entitySearch", "count"])) ?? 0;
  }

  async listAlertPolicies(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginate(QUERY_ALERT_POLICIES, { accountId }, ["actor", "account", "alerts", "policiesSearch"], "policies", limit);
  }

  async listNrqlConditions(accountId: number, limit = DEFAULT_USER_LIMIT): Promise<PagedList> {
    return this.paginate(
      QUERY_NRQL_CONDITIONS,
      { accountId },
      ["actor", "account", "alerts", "nrqlConditionsSearch"],
      "nrqlConditions",
      limit,
    );
  }

  async listNotificationDestinations(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginate(QUERY_DESTINATIONS, { accountId }, ["actor", "account", "aiNotifications", "destinations"], "entities", limit);
  }

  async listNotificationChannels(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.paginate(QUERY_CHANNELS, { accountId }, ["actor", "account", "aiNotifications", "channels"], "entities", limit);
  }

  async listWorkflows(accountId: number, limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    const pagePath = ["actor", "account", "aiWorkflows", "workflows"];
    try {
      return await this.paginate(QUERY_WORKFLOWS, { accountId }, pagePath, "entities", limit);
    } catch (error) {
      if (!isSchemaMismatchError(error)) throw error;
    }
    const data = await this.nerdgraph(QUERY_WORKFLOWS_SINGLE_PAGE, { accountId });
    const page = asObject(getNestedValue(data, pagePath));
    if (!page) throw new Error("NerdGraph response did not include actor.account.aiWorkflows.workflows.");
    const entities = asRecords(page.entities);
    const items = entities.slice(0, limit);
    const totalCount = asNumber(page.totalCount);
    const nextCursor = asString(page.nextCursor);
    const complete = !nextCursor && items.length === entities.length && (totalCount === undefined || items.length >= totalCount);
    return {
      items,
      complete,
      totalCount,
      note: complete ? undefined : `aiWorkflows.workflows rejected the cursor argument, so only the first page was read (${items.length}${totalCount !== undefined ? ` of ${totalCount}` : ""} workflows)`,
    };
  }

  async listEventRetentionRules(accountId: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_RETENTION_RULES, { accountId });
    return completeList(asRecords(getNestedValue(data, ["actor", "account", "dataManagement", "eventRetentionRules"])));
  }

  async listRetentionNamespaces(accountId: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_RETENTION_NAMESPACES, { accountId });
    return completeList(asRecords(getNestedValue(data, ["actor", "account", "dataManagement", "customizableRetention", "eventNamespaces"])));
  }

  async listObfuscationRules(accountId: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_OBFUSCATION_RULES, { accountId });
    return completeList(asRecords(getNestedValue(data, ["actor", "account", "logConfigurations", "obfuscationRules"])));
  }

  async listObfuscationExpressions(accountId: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_OBFUSCATION_EXPRESSIONS, { accountId });
    return completeList(asRecords(getNestedValue(data, ["actor", "account", "logConfigurations", "obfuscationExpressions"])));
  }

  async listPipelineCloudRules(): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_PIPELINE_CLOUD_RULES);
    const search = asObject(getNestedValue(data, ["actor", "entityManagement", "entitySearch"]));
    const nextCursor = asString(search?.nextCursor);
    return {
      items: asRecords(search?.entities),
      complete: !nextCursor,
      note: nextCursor ? "entityManagement.entitySearch returned more pages than were read" : undefined,
    };
  }

  async listNrqlDropRules(accountId: number): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_NRQL_DROP_RULES, { accountId });
    const list = asObject(getNestedValue(data, ["actor", "account", "nrqlDropRules", "list"]));
    const error = asObject(list?.error);
    if (error) {
      throw new Error(`NRQL drop rule listing failed: ${asString(error.reason) ?? "unknown"} ${asString(error.description) ?? ""}`.trim());
    }
    return completeList(asRecords(list?.rules));
  }

  async getSyntheticScript(accountId: number, monitorGuid: string): Promise<string> {
    const data = await this.nerdgraph(QUERY_SYNTHETIC_SCRIPT, { accountId, monitorGuid });
    return asString(getNestedValue(data, ["actor", "account", "synthetics", "script", "text"])) ?? "";
  }

  async listDashboardLiveUrls(): Promise<PagedList> {
    const data = await this.nerdgraph(QUERY_DASHBOARD_LIVE_URLS);
    const result = asObject(getNestedValue(data, ["actor", "dashboard", "liveUrls"]));
    if (!result) throw new Error("NerdGraph response did not include actor.dashboard.liveUrls.");
    const errors = asRecords(result.errors);
    if (errors.length > 0) {
      throw new Error(`Dashboard live URL listing failed: ${errors.map((error) => asString(error.description) ?? "unknown error").join("; ")}`);
    }
    if (!Array.isArray(result.liveUrls)) throw new Error("NerdGraph response did not include actor.dashboard.liveUrls.liveUrls.");
    return completeList(asRecords(result.liveUrls));
  }

  async listRestUsers(limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
    return this.restList("/v2/users.json", "users", limit);
  }

  async listRestAlertPolicies(limit = DEFAULT_PAGE_LIMIT): Promise<PagedList> {
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

type NewrelicClientSurfaceMethod = keyof NewrelicClientSurface;

/**
 * Every method of the client surface, as a runtime list so tests can tie their per-inventory denial tables to the
 * queries the collectors and `check_access` run. The `satisfies` clause rejects a name outside the surface and the
 * exhaustiveness check below fails to compile when a surface method is missing from the list.
 */
export const NEWRELIC_CLIENT_SURFACE_METHODS = [
  "getResolvedConfig",
  "getCurrentUser",
  "getOrganization",
  "listAccounts",
  "resolveAccountIds",
  "listAuthenticationDomains",
  "listOrganizationAuthenticationDomains",
  "listDomainUsers",
  "listDomainGroupGrants",
  "listRoles",
  "listApiKeys",
  "runNrql",
  "searchEntities",
  "countEntities",
  "listAlertPolicies",
  "listNrqlConditions",
  "listNotificationDestinations",
  "listNotificationChannels",
  "listWorkflows",
  "listEventRetentionRules",
  "listRetentionNamespaces",
  "listObfuscationRules",
  "listObfuscationExpressions",
  "listPipelineCloudRules",
  "listNrqlDropRules",
  "getSyntheticScript",
  "listDashboardLiveUrls",
  "listRestUsers",
] as const satisfies readonly NewrelicClientSurfaceMethod[];

type UnlistedSurfaceMethod = Exclude<NewrelicClientSurfaceMethod, (typeof NEWRELIC_CLIENT_SURFACE_METHODS)[number]>;
const surfaceMethodListIsExhaustive: [UnlistedSurfaceMethod] extends [never] ? true : never = true;
void surfaceMethodListIsExhaustive;

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
  | "getOrganization"
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

function completeList<T>(items: T[]): PagedList<T> {
  return { items, complete: true };
}

function toPagedList<T>(value: PagedList<T> | T[]): PagedList<T> {
  return Array.isArray(value) ? completeList(value) : value;
}

async function collectRecord(source: string, shape: RecordShape, load: () => Promise<JsonRecord>): Promise<Collected<JsonRecord>> {
  try {
    return { data: projectRecord(await load(), shape), source };
  } catch (error) {
    return { data: {}, source, error: `${source}: ${errorMessage(error)}` };
  }
}

async function collectList(source: string, shape: RecordShape, load: () => Promise<PagedList | JsonRecord[]>): Promise<Collected<JsonRecord[]>> {
  try {
    const page = toPagedList(await load());
    return {
      data: page.items.map((item) => projectRecord(item, shape)),
      source,
      partial: page.failures && page.failures.length > 0 ? page.failures.map((failure) => `${source}: ${failure}`) : undefined,
      truncated: page.complete ? undefined : true,
      seen: page.items.length,
      total: page.totalCount,
      note: page.note ? `${source}: ${page.note}` : undefined,
    };
  } catch (error) {
    if (error instanceof NotCollectedError) return { data: [], source, notCollected: `${source} ${error.message}` };
    return { data: [], source, error: `${source}: ${errorMessage(error)}` };
  }
}

/** Every failure and skipped query, uncompacted, for the errors array and `_errors.log`; summaries and statuses carry the compacted form. */
function collectedErrors(items: Array<Collected<unknown>>): string[] {
  return items.flatMap((item) => [...(item.error ? [item.error] : []), ...(item.notCollected ? [item.notCollected] : []), ...(item.partial ?? [])]);
}

type Inventories = Collected<unknown> | Array<Collected<unknown>>;

function inventoriesOf(items: Inventories): Array<Collected<unknown>> {
  return Array.isArray(items) ? items : [items];
}

/** True when the query was issued and answered: neither unreadable nor skipped. Partial and truncated inventories are readable. */
function isReadable(item: Collected<unknown>): boolean {
  return !item.error && !item.notCollected;
}

function hasUnreadableScope(item: Collected<unknown>): boolean {
  return (item.partial !== undefined && item.partial.length > 0) || (item.derivedFrom !== undefined && hasUnreadableScope(item.derivedFrom));
}

/** True when every scope answered: readable with no unreadable scope. Truncation is allowed because its status states the seen and total counts. */
function isFullyReadable(item: Collected<unknown>): boolean {
  return isReadable(item) && !hasUnreadableScope(item);
}

function isComplete(item: Collected<unknown>): boolean {
  return isFullyReadable(item) && !item.truncated && !item.note && (item.derivedFrom === undefined || isComplete(item.derivedFrom));
}

/** The unreadable scopes of a partly readable inventory (its own or inherited from the inventory it derives from), compacted. */
function partialCause(item: Collected<unknown>): string {
  const own = item.partial ?? [];
  if (own.length > 0) return compactCause(own.join("; "));
  return item.derivedFrom ? partialCause(item.derivedFrom) : "unknown scope";
}

/** "unreadable (cause)" or "not collected (cause)" for an inventory whose query failed or was never issued, for use inside a sentence. */
function unavailableDetail(item: Collected<unknown>): string {
  return item.notCollected ? `not collected (${causeOf(item)})` : `unreadable (${causeOf(item)})`;
}

/**
 * Names an unavailable input inside the not-collected reason of the query that depended on it: "<source> was
 * unreadable (<cause>)" with the source prefix of the cause removed, or the input's own not-collected text.
 */
function upstreamUnavailable(item: Collected<unknown>): string {
  if (item.notCollected) return item.notCollected;
  const cause = item.error ?? "unknown cause";
  const prefix = `${item.source}: `;
  return `${item.source} was unreadable (${cause.startsWith(prefix) ? cause.slice(prefix.length) : cause})`;
}

/** Skips a query whose organization id input was not readable, recording the dependent inventory as not collected. */
function requireOrganizationId(organization: Collected<JsonRecord>): string {
  const organizationId = asString(organization.data.id);
  if (organizationId) return organizationId;
  throw new NotCollectedError(`was not queried for any organization: ${organization.error ? upstreamUnavailable(organization) : "actor.organization returned no id"}`);
}

/**
 * Describes why a collected inventory is less than complete, or returns undefined when it is complete. A fully
 * unreadable or never collected inventory is described too (rule 1 corollary): a finding that lists such an inventory
 * in its coverage is limited below pass even when its primary inventory was complete, and the note names the dataset
 * and query path. A derived inventory repeats the gaps of the inventory it was computed from.
 */
function coverageDetail(item: Collected<unknown>): string | undefined {
  if (!isReadable(item)) return unavailableDetail(item);
  const parts: string[] = [];
  if (item.truncated) {
    const seen = item.seen ?? (Array.isArray(item.data) ? item.data.length : 0);
    parts.push(`${seen}${item.total !== undefined ? ` of ${item.total}` : ""} seen before pagination stopped`);
  }
  if (item.partial && item.partial.length > 0) {
    parts.push(`${item.partial.length} scope${item.partial.length === 1 ? "" : "s"} unreadable (${compactCause(item.partial.join("; "))})`);
  }
  if (item.note) parts.push(item.note);
  const upstream = item.derivedFrom ? coverageDetail(item.derivedFrom) : undefined;
  if (upstream && item.derivedFrom) parts.push(`derived from ${item.derivedFrom.source}: ${upstream}`);
  return parts.length > 0 ? parts.join("; ") : undefined;
}

function coverageNote(label: string, item: Collected<unknown>): string | undefined {
  const detail = coverageDetail(item);
  return detail ? `${label}: ${detail}` : undefined;
}

function coverageNotes(entries: Array<[string, Collected<unknown>]>): string[] {
  return entries.map(([label, item]) => coverageNote(label, item)).filter((note): note is string => Boolean(note));
}

/**
 * Evidence status for the inventories a value is derived from. The leading word classifies it: `complete` (naming the
 * queries that answered), `truncated` (a pagination cap, with seen and total counts, naming the query), `partial` (at
 * least one scope unreadable, named with its query path), `unreadable`, or `not collected` (naming the upstream query
 * that left nothing to query). A value beside a partial, unreadable, or not-collected status is always null.
 */
function collectionStatus(items: Inventories): string {
  const list = inventoriesOf(items);
  const skipped = list.filter((item) => item.notCollected);
  if (skipped.length > 0) return `not collected (${skipped.map(causeOf).join("; ")})`;
  const unreadable = list.filter((item) => item.error);
  if (unreadable.length > 0) return `unreadable (${unreadable.map(causeOf).join("; ")})`;
  const complete = list.filter(isComplete);
  const completeClause = `complete (${complete.map((item) => item.source).join(", ")})`;
  if (complete.length === list.length) return completeClause;
  const details = list
    .filter((item) => !isComplete(item))
    .map((item) => (hasUnreadableScope(item) ? coverageDetail(item) : `${coverageDetail(item)} (${item.source})`));
  const tail = complete.length > 0 ? `; ${completeClause}` : "";
  return `${list.some(hasUnreadableScope) ? "partial" : "truncated"}: ${details.join("; ")}${tail}`;
}

/**
 * A value derived from inventories that were unreadable, never collected, or only partly readable renders as null
 * beside its status, never as 0, [], {}, or false. A truncated inventory keeps its value because the status states
 * how many items were seen of how many reported.
 */
function unlessUnreadable<T>(items: Inventories, value: T): T | null {
  return inventoriesOf(items).every(isFullyReadable) ? value : null;
}

/** One evidence or summary field with its paired `<field>_status`, so every count says which queries it rests on. */
function measured(field: string, items: Inventories, value: unknown): JsonRecord {
  return { [field]: unlessUnreadable(items, value), [`${field}_status`]: collectionStatus(items) };
}

/**
 * Records for `core_data/`: the projected rows when every scope answered, otherwise an object whose `status` names the
 * gap and whose `records` are the readable rows, or null when the query failed or was never issued, never a bare [].
 */
function coreDataFile(item: Collected<unknown>, records: unknown = item.data): unknown {
  if (isFullyReadable(item)) return records;
  return { status: collectionStatus(item), records: isReadable(item) ? records : null };
}

/**
 * Errors to disclose for an account-scoped assessment: the failed account resolution first (so every such assessment
 * names the cause), then every failure and skipped query, each text once even when the accounts inventory failed
 * with the same message.
 */
function accountScopeErrors(scope: AccountScope, items: Array<Collected<unknown>>): string[] {
  const resolution = scope.error !== undefined ? [`actor.accounts: ${scope.error}`] : [];
  return [...new Set([...resolution, ...collectedErrors(items)])];
}

/** Evidence for the accounts in scope: the resolved ids with the query they came from, or null with the reason none resolved. */
function accountScopeEvidence(scope: AccountScope): JsonRecord {
  if (scope.accountIds.length > 0) return { accounts_in_scope: scope.accountIds, accounts_in_scope_status: `complete (${scope.source})` };
  return { accounts_in_scope: null, accounts_in_scope_status: `unknown (${accountScopes(scope).noScopesReason.replace(/^was not queried for any account: /, "")})` };
}

const SCOPE_FAILURE_PATTERN = /^(account \d+|authentication domain .+?): (.+)$/;

/**
 * Renders a collection error for a finding summary. The full text stays in the errors array and `_errors.log`. When
 * the text exceeds the summary budget, scopes that failed with the same message are merged ("account 111, account
 * 222: ...") so every query path survives, further scopes are counted rather than cut mid-path, and a single long
 * message is shortened ahead of its "(at path)" suffix, never through it.
 */
export function compactCause(cause: string): string {
  if (cause.length <= CAUSE_MAX_LENGTH) return cause;
  const separator = cause.indexOf(": ");
  const prefix = separator === -1 ? "" : `${cause.slice(0, separator)}: `;
  const groups = mergeScopeFailures((separator === -1 ? cause : cause.slice(separator + 2)).split("; "));
  // Keep a leading run of scope groups; each step budgets for the suffix that counts the scopes it would leave out.
  const kept: string[] = [];
  for (let index = 0; index < groups.length; index += 1) {
    const candidate = [...kept, groups[index]].join("; ");
    const suffixIfKept = omittedScopesSuffix(groups.length - index - 1);
    if (kept.length > 0 && prefix.length + candidate.length + suffixIfKept.length > CAUSE_MAX_LENGTH) break;
    kept.push(groups[index]);
  }
  const suffix = omittedScopesSuffix(groups.length - kept.length);
  return `${prefix}${truncateAheadOfPath(kept.join("; "), Math.max(CAUSE_MAX_LENGTH - prefix.length - suffix.length, 40))}${suffix}`;
}

function omittedScopesSuffix(omitted: number): string {
  if (omitted <= 0) return "";
  return `; ${omitted} more scope${omitted === 1 ? "" : "s"} failed and ${omitted === 1 ? "is" : "are"} listed in the errors array`;
}

function mergeScopeFailures(segments: string[]): string[] {
  const merged: Array<{ scopes: string[]; message: string }> = [];
  for (const segment of segments) {
    const match = SCOPE_FAILURE_PATTERN.exec(segment);
    if (!match) {
      merged.push({ scopes: [], message: segment });
      continue;
    }
    const existing = merged.find((entry) => entry.scopes.length > 0 && entry.message === match[2]);
    if (existing) existing.scopes.push(match[1]);
    else merged.push({ scopes: [match[1]], message: match[2] });
  }
  return merged.map((entry) => (entry.scopes.length > 0 ? `${entry.scopes.join(", ")}: ${entry.message}` : entry.message));
}

/**
 * Shortens one long cause to the budget while keeping its tail: the status text and the query path ("Not authorized
 * (at actor.x.y)") survive and the boilerplate ahead of them is cut, at a word boundary so no token is split. When the
 * status does not fit, the path alone is kept; a cause without a path is cut at the end.
 */
function truncateAheadOfPath(text: string, budget: number): string {
  if (text.length <= budget) return text;
  const pathStart = text.lastIndexOf(" (at ");
  if (pathStart !== -1) {
    const statusStart = text.lastIndexOf(": ", pathStart);
    const tailStarts = statusStart === -1 ? [pathStart] : [statusStart + 2, pathStart];
    for (const tailStart of tailStarts) {
      const tail = text.slice(tailStart);
      const room = budget - tail.length - 3;
      if (room > 0) return `${headToWordBoundary(text.slice(0, room))}...${tail}`;
    }
  }
  return `${text.slice(0, Math.max(budget - 3, 1))}...`;
}

/** Backs a cut head up to the last space (kept, so "domain: ...Not authorized" reads as words) instead of mid-token. */
function headToWordBoundary(head: string): string {
  const boundary = head.lastIndexOf(" ");
  return boundary > 0 ? head.slice(0, boundary + 1) : head;
}

function causeOf(item: Collected<unknown>): string {
  return compactCause(item.error ?? item.notCollected ?? "unknown cause");
}

function verdict(status: NewrelicFindingStatus, summary: string): Verdict {
  return { status, summary };
}

function manualVerdict(summary: string): Verdict {
  return { status: "manual", summary };
}

/**
 * Manual verdict for a finding whose inventory was unreadable (the query failed) or never collected (the query was
 * skipped because its input, such as the account list, was unreadable or empty). Both name the cause and query path.
 */
function unreadableVerdict(surface: string, item: Collected<unknown>, evidence: string): Verdict {
  if (item.notCollected) {
    return manualVerdict(`${surface} could not be collected (${causeOf(item)}), so this control is unknown rather than passing. Collect ${evidence}`);
  }
  return manualVerdict(`${surface} could not be read (${causeOf(item)}), so this control is unknown rather than passing. Collect ${evidence}`);
}

/**
 * Manual verdict for a listing whose readable scopes returned nothing while another scope was unreadable: the empty
 * readable subset says nothing about the denied scope, so the inventory is unknown rather than empty, and no zero
 * count is stated ahead of the cause.
 */
function unknownEmptyVerdict(surface: string, item: Collected<unknown[]>, evidence: string): Verdict {
  return manualVerdict(`${surface} returned nothing from the readable scopes while another scope was unreadable (${partialCause(item)}), so the inventory is unknown rather than empty. Collect ${evidence}`);
}

const UNREADABLE_NOTE_PATTERN = /: unreadable \(/;
const NOT_COLLECTED_NOTE_PATTERN = /: not collected \(/;
const UNAVAILABLE_NOTE_PATTERN = /: (?:unreadable|not collected) \((.*)\)$/;
const PARTIAL_NOTE_PATTERN = /\d+ scopes? unreadable \(/;

function limitedReason(notes: string[]): string {
  const unreadable = notes.some((note) => UNREADABLE_NOTE_PATTERN.test(note));
  const skipped = notes.some((note) => NOT_COLLECTED_NOTE_PATTERN.test(note));
  if (unreadable && skipped) return "A dataset this finding depends on was unreadable and another was never collected";
  if (unreadable) return "A dataset this finding depends on was unreadable";
  if (skipped) return "A dataset this finding depends on was never collected";
  if (notes.some((note) => PARTIAL_NOTE_PATTERN.test(note))) return "The inventory was incomplete and the counts that follow cover the readable scopes only";
  return "The inventory was incomplete";
}

/**
 * Caps a finding by the coverage of every inventory it lists. A passing verdict becomes warn when any listed inventory
 * was unreadable, never collected, partly unreadable, or truncated. The summary leads with the `Partial view:` clause
 * naming each dataset and query path, so no count computed from the readable scopes is read as a complete figure
 * before the gap is stated; the readable-scope summary follows. A verdict that is already below pass keeps its
 * status and gains the clause ahead of its summary, minus notes whose cause it already quotes.
 */
function limitCoverage(base: Verdict, notes: string[]): Verdict {
  const unseen = base.status === "pass"
    ? notes
    : notes.filter((note) => {
      const cause = UNAVAILABLE_NOTE_PATTERN.exec(note)?.[1];
      return cause === undefined || !base.summary.includes(cause);
    });
  if (unseen.length === 0) return base;
  const clause = `Partial view: ${unseen.join("; ")}.`;
  if (base.status === "pass") {
    return verdict("warn", `${clause} ${limitedReason(unseen)}, so the verdict is limited to warn instead of pass. Within the readable data: ${base.summary}`);
  }
  return verdict(base.status, `${clause} ${base.summary}`);
}

function finding(controlNumber: number, result: Verdict, evidence?: JsonRecord): NewrelicFinding {
  const control = CONTROLS[controlNumber];
  return {
    id: control.id,
    control: control.number,
    title: control.title,
    severity: control.severity,
    status: result.status,
    summary: result.summary,
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
  if (Array.isArray(value)) return value.length;
  const items = asObject(value)?.items;
  return Array.isArray(items) ? items.length : undefined;
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
      "role_catalog",
      "NerdGraph customerAdministration.roles (multi-tenancy entitlement)",
      false,
      async () => {
        const organizationId = asString((await client.getOrganization()).id);
        if (!organizationId) throw new Error("actor.organization returned no id, so customerAdministration.roles cannot be filtered.");
        return client.listRoles(organizationId, 50);
      },
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
      "The role catalog (customerAdministration.roles) is only served to organizations with the multi-tenancy entitlement; when it is not readable, control 20 renders manual and custom roles are reported from group grants only.",
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

/**
 * Runs one query per scope (account or authentication domain) and merges the pages. With no scope to query, nothing
 * was collected: the collector throws `NotCollectedError` naming the upstream query, so the inventory is recorded as
 * not collected (complete: false, no count) rather than as a complete empty listing.
 */
async function collectScoped(
  scopeSet: ScopeSet,
  load: (scopeId: string) => Promise<PagedList | JsonRecord[]>,
  decorate: (item: JsonRecord, scopeId: string) => JsonRecord,
  limit = Number.POSITIVE_INFINITY,
): Promise<PagedList> {
  const { scopes } = scopeSet;
  if (scopes.length === 0) throw new NotCollectedError(scopeSet.noScopesReason);
  const items: JsonRecord[] = [];
  const failures: string[] = [];
  const notes: string[] = [];
  let complete = true;
  let totalCount: number | undefined = 0;
  for (const scope of scopes) {
    const room = limit - items.length;
    if (room <= 0) {
      complete = false;
      notes.push(`${scope.label} skipped because the ${limit} item limit was reached`);
      continue;
    }
    try {
      const page = toPagedList(await load(scope.id));
      items.push(...page.items.slice(0, room).map((item) => decorate(item, scope.id)));
      if (page.items.length > room) {
        complete = false;
        notes.push(`${scope.label}: ${limit} item limit reached`);
      }
      if (!page.complete) complete = false;
      if (page.note) notes.push(`${scope.label}: ${page.note}`);
      if (page.failures) failures.push(...page.failures.map((failure) => `${scope.label}: ${failure}`));
      totalCount = totalCount === undefined || page.totalCount === undefined ? undefined : totalCount + page.totalCount;
    } catch (error) {
      failures.push(`${scope.label}: ${errorMessage(error)}`);
      totalCount = undefined;
    }
  }
  if (failures.length >= scopes.length) {
    throw new Error(failures.join("; "));
  }
  return {
    items,
    complete,
    totalCount: totalCount ?? (complete && failures.length === 0 ? items.length : undefined),
    note: notes.length > 0 ? notes.join("; ") : undefined,
    failures: failures.length > 0 ? failures : undefined,
  };
}

/** Skips a domain-scoped query whose domain listing was unavailable, recording the dependent inventory as not collected. */
function requireDomains(domains: Collected<JsonRecord[]>): JsonRecord[] {
  if (!isReadable(domains)) throw new NotCollectedError(`was not queried for any authentication domain: ${upstreamUnavailable(domains)}`);
  return domains.data;
}

function domainScopes(domains: JsonRecord[]): ScopeSet {
  return {
    scopes: domains
      .map((domain) => ({ id: asString(domain.id) ?? "", label: `authentication domain ${domainLabel(domain)}` }))
      .filter((scope) => scope.id.length > 0),
    noScopesReason: domains.length === 0
      ? "was not queried for any authentication domain: userManagement.authenticationDomains returned zero domains"
      : `was not queried for any authentication domain: none of the ${domains.length} domains userManagement.authenticationDomains returned exposed an id`,
  };
}

function accountScopes(scope: AccountScope): ScopeSet {
  const resolution = scope.error !== undefined
    ? `actor.accounts was unreadable (${scope.error})`
    : "actor.accounts returned zero accounts";
  return {
    scopes: scope.accountIds.map((accountId) => ({ id: String(accountId), label: `account ${accountId}` })),
    noScopesReason: `was not queried for any account: ${resolution} and no account_ids were configured`,
  };
}

/**
 * Resolves the accounts to query: the configured `account_ids`, else `actor.accounts`. A failed or empty discovery is
 * kept with its cause so every account-scoped inventory can say why it was not collected.
 */
async function resolveAccountScope(client: Pick<NewrelicClientSurface, "getResolvedConfig" | "resolveAccountIds">): Promise<AccountScope> {
  const configured = client.getResolvedConfig().accountIds;
  if (configured.length > 0) return { accountIds: configured, source: "account_ids" };
  try {
    return { accountIds: await client.resolveAccountIds(), source: "actor.accounts" };
  } catch (error) {
    if (error instanceof NewrelicNoAccountsError) return { accountIds: [], source: "actor.accounts" };
    return { accountIds: [], source: "actor.accounts", error: errorMessage(error) };
  }
}

async function collectUsers(
  client: Pick<NewrelicClientSurface, "listDomainUsers">,
  domains: JsonRecord[],
  limit: number,
): Promise<PagedList> {
  const domainById = new Map(domains.map((domain) => [asString(domain.id) ?? "", domain]));
  return collectScoped(
    domainScopes(domains),
    (domainId) => client.listDomainUsers(domainId, limit),
    (user, domainId) => ({
      ...user,
      authenticationDomainId: domainId,
      authenticationDomainName: asString(domainById.get(domainId)?.name),
      provisioningType: asString(domainById.get(domainId)?.provisioningType),
    }),
    limit,
  );
}

async function collectGroupGrants(
  client: Pick<NewrelicClientSurface, "listDomainGroupGrants">,
  domains: JsonRecord[],
): Promise<PagedList> {
  return collectScoped(
    domainScopes(domains),
    (domainId) => client.listDomainGroupGrants(domainId),
    (group, domainId) => ({ ...group, authenticationDomainId: domainId }),
  );
}

export async function collectNewrelicIdentityData(
  client: IdentityClient,
  options: { userLimit?: number } = {},
): Promise<NewrelicIdentityData> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 50_000);
  const organization = await collectRecord("actor.organization", ORGANIZATION_SHAPE, () => client.getOrganization());
  const authenticationDomains = await collectList("userManagement.authenticationDomains", AUTHENTICATION_DOMAIN_SHAPE, () => client.listAuthenticationDomains());
  const organizationAuthenticationDomains = await collectList(
    "customerAdministration.authenticationDomains",
    ORGANIZATION_AUTHENTICATION_DOMAIN_SHAPE,
    () => client.listOrganizationAuthenticationDomains(requireOrganizationId(organization)),
  );
  const users = await collectList("userManagement.users", USER_SHAPE, () => collectUsers(client, requireDomains(authenticationDomains), userLimit));
  const groupGrants = await collectList("authorizationManagement.groups", GROUP_GRANT_SHAPE, () => collectGroupGrants(client, requireDomains(authenticationDomains)));
  const roles = await collectRoles(client, organization);
  return { organization, authenticationDomains, organizationAuthenticationDomains, users, groupGrants, roles };
}

async function collectRoles(
  client: Pick<NewrelicClientSurface, "listRoles">,
  organization: Collected<JsonRecord>,
): Promise<Collected<JsonRecord[]>> {
  return collectList(ROLE_CATALOG_SOURCE, ROLE_SHAPE, () => client.listRoles(requireOrganizationId(organization)));
}

function roleType(role: JsonRecord): string {
  return (asString(role.type) ?? "").toUpperCase();
}

function isCustomRole(role: JsonRecord): boolean {
  return roleType(role) === ROLE_TYPE_CUSTOM;
}

function roleLabel(role: JsonRecord): string {
  return asString(role.name) ?? asString(role.displayName) ?? asString(role.id) ?? "role";
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
  return asString(role.displayName) ?? asString(role.name) ?? asString(role.id) ?? "role";
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

  const domainsReadable = isReadable(data.authenticationDomains);
  const usersReadable = isReadable(data.users);
  const grantsReadable = isReadable(data.groupGrants);
  const authTypeReadable = isReadable(data.organizationAuthenticationDomains);

  const domainAuthTypes = orgDomains.map((domain) => ({
    id: asString(domain.id),
    name: domainLabel(domain),
    authenticationType: asString(domain.authenticationType)?.toUpperCase() ?? "UNKNOWN",
    provisioningType: asString(domain.provisioningType)?.toUpperCase() ?? "UNKNOWN",
  }));
  const passwordDomains = domainAuthTypes.filter((domain) => domain.authenticationType === "PASSWORD");
  const ssoDomains = domainAuthTypes.filter((domain) => SSO_AUTHENTICATION_TYPES.has(domain.authenticationType));
  const unknownAuthTypeDomains = domainAuthTypes.filter((domain) => domain.authenticationType !== "PASSWORD" && !SSO_AUTHENTICATION_TYPES.has(domain.authenticationType));
  const authTypeDomainIds = new Set(domainAuthTypes.map((domain) => domain.id).filter((id): id is string => Boolean(id)));
  const domainProvisioning = domains.map((domain) => ({
    id: asString(domain.id),
    name: domainLabel(domain),
    provisioningType: asString(domain.provisioningType)?.toUpperCase() ?? "UNKNOWN",
  }));
  const domainsWithoutAuthType = domainProvisioning.filter((domain) => !domain.id || !authTypeDomainIds.has(domain.id));
  const manualProvisioningDomains = domainProvisioning.filter((domain) => domain.provisioningType === "MANUAL");
  const scimDomains = domainProvisioning.filter((domain) => domain.provisioningType === "SCIM");
  const unknownProvisioningDomains = domainProvisioning.filter((domain) => domain.provisioningType !== "MANUAL" && domain.provisioningType !== "SCIM");

  const fullPlatformUsers = users.filter(isFullPlatformUser);
  const unknownTypeUsers = users.filter((user) => userTypeId(user) === "UNKNOWN");
  const inactiveFullPlatformUsers = fullPlatformUsers.filter((user) => {
    const age = lastActiveAgeDays(user, now);
    return age !== undefined && age > inactiveDays;
  });
  const undatedFullPlatformUsers = fullPlatformUsers.filter((user) => lastActiveAgeDays(user, now) === undefined);
  const usersWithoutGroupData = users.filter((user) => asObject(user.groups) === undefined);
  const groupsWithoutRoleData = groupGrants.filter((group) => group.rolesReadable === false);
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
  const customRoles = roles.filter(isCustomRole);

  const domainCoverage = coverageNotes([["authentication domains", data.authenticationDomains]]);
  const authTypeCoverage = coverageNotes([["authentication domain settings", data.organizationAuthenticationDomains]]);
  const userCoverage = coverageNotes([["users", data.users]]);
  const groupCoverage = coverageNotes([["groups", data.groupGrants]]);
  const domainEvidence = "the Authentication method shown in Administration > Access Management > Authentication domains for every domain.";
  const userEvidence = "an export of Administration > Access Management > Users including the User type and Last active columns.";
  const groupEvidence = "Administration > Access Management > Groups with each group's roles and member counts.";

  const control1 = (): Verdict => {
    if (!domainsReadable) return unreadableVerdict("Authentication domains", data.authenticationDomains, domainEvidence);
    if (domains.length === 0) {
      return manualVerdict(`userManagement.authenticationDomains returned zero domains; every organization has at least one, so the key cannot see them and emptiness is treated as unknown rather than compliant. Collect ${domainEvidence}`);
    }
    if (!authTypeReadable) {
      return manualVerdict(`${domains.length} authentication domains were listed, but authenticationType is not available to this key (${causeOf(data.organizationAuthenticationDomains)}); customerAdministration is limited to multi-tenant organizations, so SSO enforcement is scoped out of the API check and not applicable to automated verification. Collect ${domainEvidence}`);
    }
    if (passwordDomains.length > 0) {
      return verdict("fail", `${passwordDomains.length}/${domainAuthTypes.length} authentication domains still authenticate users with New Relic passwords instead of SAML or OIDC SSO.`);
    }
    if (orgDomains.length === 0 || domainsWithoutAuthType.length > 0) {
      const missing = domainsWithoutAuthType.map((domain) => domain.name).join(", ");
      return manualVerdict(`customerAdministration.authenticationDomains exposed authenticationType for ${orgDomains.length}/${domains.length} domains; ${missing || "the listed domains"} had no readable authentication type, so SSO enforcement cannot be confirmed. Collect ${domainEvidence}`);
    }
    if (unknownAuthTypeDomains.length > 0) {
      return manualVerdict(`${unknownAuthTypeDomains.length}/${domainAuthTypes.length} authentication domains exposed an unrecognized authenticationType (${unknownAuthTypeDomains.map((domain) => `${domain.name}: ${domain.authenticationType}`).join(", ")}), so SSO enforcement cannot be confirmed for them. Collect ${domainEvidence}`);
    }
    return verdict("pass", `All ${domainAuthTypes.length} authentication domains authenticate through SSO (${ssoDomains.map((domain) => domain.authenticationType).join(", ")}).`);
  };

  const control2 = (): Verdict => {
    if (!usersReadable) return unreadableVerdict("Users", data.users, userEvidence);
    if (users.length === 0) {
      if (hasUnreadableScope(data.users)) return unknownEmptyVerdict("Users (userManagement.users)", data.users, userEvidence);
      return manualVerdict(`userManagement.users returned zero users across ${domains.length} authentication domains; at least the key owner must exist, so the inventory is unknown rather than compliant. Collect ${userEvidence}`);
    }
    if (inactiveFullPlatformUsers.length > 0) {
      return verdict("fail", `${inactiveFullPlatformUsers.length}/${fullPlatformUsers.length} full platform users have not been active in the last ${inactiveDays} days, indicating over-provisioned user types.`);
    }
    if (fullPlatformShare > maxFullPlatformPercent) {
      return verdict("warn", `${fullPlatformShare}% of ${users.length} users hold the full platform user type, above the ${maxFullPlatformPercent}% review threshold.`);
    }
    if (undatedFullPlatformUsers.length > 0 || unknownTypeUsers.length > 0) {
      return verdict("warn", `${fullPlatformUsers.length}/${users.length} users hold the full platform user type; ${undatedFullPlatformUsers.length} of them have no lastActive value and ${unknownTypeUsers.length} users expose no user type, so they cannot be counted as active or right-sized.`);
    }
    return verdict("pass", `${fullPlatformUsers.length}/${users.length} users hold the full platform user type, every user exposed a type, and all full platform users were active within ${inactiveDays} days.`);
  };

  const control3 = (): Verdict => {
    if (!grantsReadable) return unreadableVerdict("Group role grants", data.groupGrants, groupEvidence);
    if (!usersReadable) return unreadableVerdict("Users", data.users, userEvidence);
    if (groupGrants.length === 0) {
      if (hasUnreadableScope(data.groupGrants)) return unknownEmptyVerdict("Group role grants (authorizationManagement.groups)", data.groupGrants, groupEvidence);
      return manualVerdict(`authorizationManagement.groups returned zero groups across ${domains.length} authentication domains, so admin concentration cannot be measured; emptiness is unknown rather than compliant. Collect ${groupEvidence}`);
    }
    if (users.length === 0) {
      if (hasUnreadableScope(data.users)) return unknownEmptyVerdict("Users (userManagement.users)", data.users, userEvidence);
      return manualVerdict(`userManagement.users returned zero users, so admin group membership cannot be counted. Collect ${userEvidence}`);
    }
    if (groupsWithoutRoleData.length === groupGrants.length) {
      return manualVerdict(`Role grants were not exposed for any of the ${groupGrants.length} groups, so admin groups cannot be identified. Collect ${groupEvidence}`);
    }
    if (adminGroups.size === 0) {
      return verdict("warn", `No groups matched the admin role pattern /${adminRolePattern.source}/ across ${groupGrants.length} groups (${groupsWithoutRoleData.length} exposed no role data), so admin concentration could not be measured.`);
    }
    if (usersWithoutGroupData.length === users.length) {
      return manualVerdict(`Group membership was not exposed for any of the ${users.length} users, so members of the ${adminGroups.size} admin groups cannot be counted. Collect ${groupEvidence}`);
    }
    if (adminUsers.length > maxAdmins) return verdict("fail", `${adminUsers.length} users are members of admin groups, above the threshold of ${maxAdmins}.`);
    if (usersWithoutGroupData.length > 0 || groupsWithoutRoleData.length > 0) {
      return verdict("warn", `${adminUsers.length} users are members of admin groups (threshold ${maxAdmins}), but ${usersWithoutGroupData.length} users expose no group membership and ${groupsWithoutRoleData.length} groups expose no role grants, so the count may be understated.`);
    }
    return verdict("pass", `${adminUsers.length} users are members of admin groups, within the threshold of ${maxAdmins}.`);
  };

  const control18 = (): Verdict => {
    if (!domainsReadable) return unreadableVerdict("Authentication domains", data.authenticationDomains, "provisioning method, session timeout, and user upgrade settings from Administration > Access Management > Authentication domains.");
    if (domains.length === 0) {
      return manualVerdict(`userManagement.authenticationDomains returned zero domains, so provisioning and session settings are unknown rather than compliant. Collect ${domainEvidence}`);
    }
    if (manualProvisioningDomains.length > 0) {
      return verdict("warn", `${manualProvisioningDomains.length}/${domains.length} authentication domains provision users manually instead of through SCIM. Session duration and user upgrade approval settings are not exposed by NerdGraph; record them from Administration > Access Management > Authentication domains.`);
    }
    if (unknownProvisioningDomains.length > 0) {
      return manualVerdict(`${unknownProvisioningDomains.length}/${domains.length} authentication domains exposed no recognizable provisioningType (${unknownProvisioningDomains.map((domain) => domain.name).join(", ")}), so provisioning cannot be confirmed. Record provisioning, session, and user upgrade settings from Administration > Access Management > Authentication domains.`);
    }
    return manualVerdict(`All ${domains.length} authentication domains provision users through SCIM (${scimDomains.map((domain) => domain.name).join(", ")}). Session duration and user upgrade approval settings are not exposed by NerdGraph, so this control stays manual until those settings are recorded from Administration > Access Management > Authentication domains.`);
  };

  const control19 = (): Verdict => {
    if (!usersReadable) return unreadableVerdict("Users", data.users, `the user list with the Last active column, flagging anyone inactive for more than ${inactiveDays} days.`);
    if (users.length === 0) {
      if (hasUnreadableScope(data.users)) return unknownEmptyVerdict("Users (userManagement.users)", data.users, userEvidence);
      return manualVerdict(`userManagement.users returned zero users, so inactivity cannot be evaluated and emptiness is unknown rather than compliant. Collect ${userEvidence}`);
    }
    if (inactiveUsers.length > 0) return verdict("fail", `${inactiveUsers.length}/${users.length} users have not been active for more than ${inactiveDays} days.`);
    if (neverActiveUsers.length > 0) {
      return verdict("warn", `No dated user exceeded ${inactiveDays} days of inactivity, but ${neverActiveUsers.length} users have no lastActive value and cannot be counted as active; review them separately.`);
    }
    return verdict("pass", `All ${users.length} users were active within the last ${inactiveDays} days.`);
  };

  const findings: NewrelicFinding[] = [];

  const domainSettings = [data.authenticationDomains, data.organizationAuthenticationDomains];
  findings.push(finding(1, limitCoverage(control1(), [...domainCoverage, ...authTypeCoverage]), {
    ...measured("authentication_domains", data.authenticationDomains, domainProvisioning),
    ...measured("authentication_types", data.organizationAuthenticationDomains, domainAuthTypes),
    ...measured("password_domains", data.organizationAuthenticationDomains, passwordDomains.map((domain) => domain.name)),
    ...measured("domains_without_authentication_type", domainSettings, domainsWithoutAuthType.map((domain) => domain.name)),
    ...measured("unknown_authentication_type_domains", data.organizationAuthenticationDomains, unknownAuthTypeDomains.map((domain) => domain.name)),
    authentication_type_readable: authTypeReadable,
    manual_evidence: "Administration > Access Management > Authentication domains > Authentication: SAML SSO or OIDC SSO for each domain.",
  }));

  findings.push(finding(2, limitCoverage(control2(), userCoverage), {
    ...measured("users", data.users, users.length),
    ...measured("user_type_counts", data.users, userTypeCounts),
    ...measured("full_platform_percent", data.users, fullPlatformShare),
    max_full_platform_percent: maxFullPlatformPercent,
    ...measured("inactive_full_platform_users", data.users, sample(inactiveFullPlatformUsers.map(userLabel))),
    ...measured("undated_full_platform_users", data.users, sample(undatedFullPlatformUsers.map(userLabel))),
    ...measured("unknown_type_users", data.users, sample(unknownTypeUsers.map(userLabel))),
  }));

  const adminRoster = [data.users, data.groupGrants];
  findings.push(finding(3, limitCoverage(control3(), [...groupCoverage, ...userCoverage]), {
    ...measured("admin_groups", data.groupGrants, sample(adminGroupNames)),
    ...measured("admin_users", adminRoster, adminUsers.length),
    ...measured("admin_user_sample", adminRoster, sample(adminUsers.map(userLabel))),
    max_admins: maxAdmins,
    admin_role_pattern: adminRolePattern.source,
    ...measured("users_without_group_data", data.users, usersWithoutGroupData.length),
    ...measured("groups_without_role_data", data.groupGrants, groupsWithoutRoleData.length),
  }));

  findings.push(finding(18, limitCoverage(control18(), domainCoverage), {
    ...measured("authentication_domains", data.authenticationDomains, domainProvisioning),
    ...measured("manual_provisioning_domains", data.authenticationDomains, manualProvisioningDomains.map((domain) => domain.name)),
    ...measured("unknown_provisioning_domains", data.authenticationDomains, unknownProvisioningDomains.map((domain) => domain.name)),
    ...measured("custom_roles_visible", data.roles, customRoles.length),
    manual_evidence: "Administration > Access Management > Authentication domains: Session settings and User upgrade settings for each domain.",
  }));

  findings.push(finding(19, limitCoverage(control19(), userCoverage), {
    inactive_days: inactiveDays,
    ...measured("inactive_users", data.users, inactiveUsers.length),
    ...measured("inactive_user_sample", data.users, sample(inactiveUsers.map(userLabel))),
    ...measured("never_active_users", data.users, sample(neverActiveUsers.map(userLabel))),
  }));

  const allCollected = Object.values(data);
  return {
    category: "identity",
    title: "New Relic identity posture",
    summary: {
      region: config.region,
      ...measured("organization", data.organization, asString(data.organization.data.name) ?? asString(data.organization.data.id) ?? null),
      ...measured("authentication_domains", data.authenticationDomains, domains.length),
      ...measured("sso_domains", data.organizationAuthenticationDomains, ssoDomains.length),
      ...measured("password_domains", data.organizationAuthenticationDomains, passwordDomains.length),
      ...measured("scim_domains", data.authenticationDomains, scimDomains.length),
      ...measured("users", data.users, users.length),
      ...measured("full_platform_users", data.users, fullPlatformUsers.length),
      ...measured("admin_users", adminRoster, adminUsers.length),
      ...measured("inactive_users", data.users, inactiveUsers.length),
      ...measured("custom_roles", data.roles, customRoles.length),
      collection_errors: collectedErrors(allCollected).length,
      coverage_limitations: [...domainCoverage, ...authTypeCoverage, ...userCoverage, ...groupCoverage].length,
    },
    findings,
    errors: collectedErrors(allCollected),
    coverage: [...domainCoverage, ...authTypeCoverage, ...userCoverage, ...groupCoverage, ...coverageNotes([["roles", data.roles]])],
    coreData: {
      "core_data/organization.json": coreDataFile(data.organization),
      "core_data/authentication_domains.json": coreDataFile(data.authenticationDomains),
      "core_data/authentication_domain_settings.json": coreDataFile(data.organizationAuthenticationDomains),
      "core_data/users.json": coreDataFile(data.users),
      "core_data/group_role_grants.json": coreDataFile(data.groupGrants),
      "core_data/roles.json": coreDataFile(data.roles),
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
  accountScope: AccountScope;
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
  scope: AccountScope,
  nrql: string,
): Promise<PagedList> {
  return collectScoped(
    accountScopes(scope),
    async (accountId) => {
      const rows = await client.runNrql(Number(accountId), nrql);
      return {
        items: rows,
        complete: rows.length < NRQL_MAX_ROWS,
        note: rows.length >= NRQL_MAX_ROWS ? `NRQL returned the ${NRQL_MAX_ROWS} row maximum, so older events were not read` : undefined,
      };
    },
    (row, accountId) => ({ ...row, queriedAccountId: Number(accountId) }),
  );
}

export async function collectNewrelicAccessControlData(
  client: AccessControlClient,
  options: { userLimit?: number } = {},
): Promise<NewrelicAccessControlData> {
  const config = client.getResolvedConfig();
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 50_000);
  const accountScope = await resolveAccountScope(client);
  const accountIds = accountScope.accountIds;
  const organization = await collectRecord("actor.organization", ORGANIZATION_SHAPE, () => client.getOrganization());
  const accounts = await collectList("actor.accounts", ACCOUNT_SHAPE, () => client.listAccounts());
  const authenticationDomains = await collectList("userManagement.authenticationDomains", AUTHENTICATION_DOMAIN_SHAPE, () => client.listAuthenticationDomains());
  const users = await collectList("userManagement.users", USER_SHAPE, () => collectUsers(client, requireDomains(authenticationDomains), userLimit));
  const groupGrants = await collectList("authorizationManagement.groups", GROUP_GRANT_SHAPE, () => collectGroupGrants(client, requireDomains(authenticationDomains)));
  const roles = await collectRoles(client, organization);
  const apiKeys = await collectList("apiAccess.keySearch", API_KEY_SHAPE, () => client.listApiKeys(["USER", "INGEST"], accountIds.length > 0 ? accountIds : undefined));
  const window = config.auditWindowDays;
  const apiKeyAuditEvents = await collectList(
    "nrql.NrAuditEvent.api_key_actor",
    API_KEY_ACTOR_EVENT_SHAPE,
    () => runNrqlAcrossAccounts(
      client,
      accountScope,
      `SELECT actorAPIKey, actorId, actorEmail, actionIdentifier, targetType, targetId, timestamp FROM NrAuditEvent WHERE actorType = 'api_key' SINCE ${window} days ago LIMIT MAX`,
    ),
  );
  const apiKeyChangeEvents = await collectList(
    "nrql.NrAuditEvent.api_key_changes",
    API_KEY_CHANGE_EVENT_SHAPE,
    () => runNrqlAcrossAccounts(
      client,
      accountScope,
      `SELECT actionIdentifier, actorEmail, actorType, description, targetType, targetId, timestamp FROM NrAuditEvent WHERE actionIdentifier LIKE 'api_key%' SINCE ${window} days ago LIMIT MAX`,
    ),
  );
  return {
    accounts,
    accountScope,
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
  const keysReadable = isReadable(data.apiKeys);
  const usersReadable = isReadable(data.users);
  const grantsReadable = isReadable(data.groupGrants);
  const accountsReadable = isReadable(data.accounts);
  const rolesReadable = isReadable(data.roles);
  const auditReadable = isReadable(data.apiKeyAuditEvents);

  const userKeys = keys.filter((key) => (asString(key.type) ?? "").toUpperCase() === "USER");
  const ingestKeys = keys.filter((key) => (asString(key.type) ?? "").toUpperCase() === "INGEST");
  const unknownTypeKeys = keys.filter((key) => !["USER", "INGEST"].includes((asString(key.type) ?? "").toUpperCase()));
  const licenseKeys = ingestKeys.filter((key) => (asString(key.ingestType) ?? "").toUpperCase() === "LICENSE");
  const browserKeys = ingestKeys.filter((key) => (asString(key.ingestType) ?? "").toUpperCase() === "BROWSER");
  const unnamedKeys = keys.filter((key) => !asString(key.name));
  const visibleAccountIds = new Set(accounts.map((account) => asNumber(account.id)).filter((id): id is number => id !== undefined));
  // Which in-scope accounts the key cannot see is known only when actor.accounts answered; when it did not, the
  // account coverage note names the failure instead of listing every configured account as unseen.
  const unseenScopeAccounts = accountsReadable ? data.accountIds.filter((id) => !visibleAccountIds.has(id)) : [];
  const usersWithoutGroupData = users.filter((user) => asObject(user.groups) === undefined);
  const groupsWithoutRoleData = groupGrants.filter((group) => group.rolesReadable === false);

  const userById = new Map<string, JsonRecord>();
  for (const user of users) {
    const id = asString(user.id);
    if (id) userById.set(id, user);
  }
  const access = buildUserAccountAccess(users, groupGrants, adminRolePattern);
  const adminUserIds = new Set(access.filter((entry) => entry.admin).map((entry) => asString(entry.user.id) ?? ""));
  const adminOwnedUserKeys = userKeys.filter((key) => adminUserIds.has(asString(key.userId) ?? ""));
  // The admin roster is the join of users and group grants; a domain missing from either side hides admins, so the
  // absence of admin-owned keys is concluded only when both listings are complete.
  const adminRosterComplete = isComplete(data.users) && isComplete(data.groupGrants);
  const userKeysWithoutOwner = userKeys.filter((key) => asString(key.userId) === undefined);
  const ownerIdsUnavailable = userKeys.length > 0 && userKeysWithoutOwner.length === userKeys.length;
  const ownerIdsUnavailableNote = `none of the ${userKeys.length} user keys exposed a userId (the schema-cited ApiAccessUserKey.userId field was not returned)`;

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
  const undatedOwnerKeys = usersReadable ? userKeys.filter((key) => {
    const owner = userById.get(asString(key.userId) ?? "");
    return owner !== undefined && lastActiveAgeDays(owner, now) === undefined;
  }) : [];
  const distinctActorKeys = new Set(
    data.apiKeyAuditEvents.data.map((event) => asString(event.actorAPIKey)).filter((value): value is string => Boolean(value)),
  );

  const broadAccessUsers = access.filter((entry) => !entry.admin && (entry.organizationScoped || entry.accountIds.size > maxAccountsPerUser));
  const usersWithoutGrants = access.filter((entry) => entry.accountIds.size === 0 && !entry.organizationScoped);

  const productionAccounts = accounts.filter((account) => productionPattern.test(accountLabel(account)) && !nonproductionPattern.test(accountLabel(account)));
  const nonproductionAccounts = accounts.filter((account) => nonproductionPattern.test(accountLabel(account)));
  const unclassifiedAccounts = accounts.filter((account) => !productionPattern.test(accountLabel(account)) && !nonproductionPattern.test(accountLabel(account)));
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

  const customRoles = roles.filter(isCustomRole);
  const standardRoles = roles.filter((role) => roleType(role) === ROLE_TYPE_STANDARD);
  const unknownTypeRoles = roles.filter((role) => ![ROLE_TYPE_CUSTOM, ROLE_TYPE_STANDARD].includes(roleType(role)));
  const customRoleGrants = groupGrants.filter((group) => asRecords(group.roles).some(isCustomRole));
  const grantedCustomRoleNames = uniqueSorted(
    groupGrants.flatMap((group) => asRecords(group.roles).filter(isCustomRole).map(grantRoleName)),
  );

  const keyCoverage = coverageNotes([["API keys", data.apiKeys]]);
  const userCoverage = coverageNotes([["users", data.users]]);
  const groupCoverage = coverageNotes([["groups", data.groupGrants]]);
  const accountCoverage = coverageNotes([["accounts", data.accounts]]);
  const roleCoverage = coverageNotes([["roles", data.roles]]);
  const auditCoverage = coverageNotes([["NrAuditEvent api_key actors", data.apiKeyAuditEvents]]);
  // The account scope is an inventory of its own: with no account resolved, keySearch ran unscoped and coverage of
  // every account is unverified, so the note names actor.accounts and the finding is limited below pass.
  const scopeCoverage = data.accountIds.length === 0
    ? [`accounts in scope: ${data.accountScope.error !== undefined
      ? `unreadable (actor.accounts: ${compactCause(data.accountScope.error)})`
      : "not collected (actor.accounts returned zero accounts and no account_ids were configured)"}`]
    : unseenScopeAccounts.length > 0
      ? [`accounts in scope not visible to this key: ${unseenScopeAccounts.join(", ")}`]
      : [];
  const keyInventoryLabel = `${keys.length} keys inventoried (${userKeys.length} user, ${licenseKeys.length} license, ${browserKeys.length} browser${unknownTypeKeys.length > 0 ? `, ${unknownTypeKeys.length} unknown type` : ""})`;
  const keyEvidence = "the API keys UI list (all key types) for every account in scope with owners, creation dates, and purposes.";
  const groupEvidence = "Administration > Access Management > Groups with the accounts and roles each group grants.";
  const userEvidence = "an export of Administration > Access Management > Users with group membership.";
  const zeroKeysNote = data.accountIds.length > 0
    ? `apiAccess.keySearch returned zero keys for ${data.accountIds.length} accounts in scope (${data.accountIds.join(", ")})`
    : `apiAccess.keySearch returned zero keys with no account scope (${scopeCoverage.join("; ")})`;

  const control4 = (): Verdict => {
    if (!keysReadable) return unreadableVerdict("API keys (apiAccess.keySearch)", data.apiKeys, keyEvidence);
    if (keys.length === 0) {
      return manualVerdict(`${zeroKeysNote}; every account has at least its original license key, so an empty inventory means the key cannot see them and is unknown rather than compliant. Collect ${keyEvidence}`);
    }
    if (!usersReadable) return manualVerdict(`${keyInventoryLabel}, but users were ${unavailableDetail(data.users)}, so key owners cannot be matched to admin group members. Collect ${keyEvidence}`);
    if (!grantsReadable) return manualVerdict(`${keyInventoryLabel}, but group role grants were ${unavailableDetail(data.groupGrants)}, so admin group members cannot be identified as key owners. Collect ${keyEvidence}`);
    if (ownerIdsUnavailable) return manualVerdict(`${keyInventoryLabel}, but ${ownerIdsUnavailableNote}, so key owners cannot be matched to admin group members. Collect ${keyEvidence}`);
    if (unnamedKeys.length > 0 || adminOwnedUserKeys.length > 0 || unknownTypeKeys.length > 0) {
      const adminOwned = adminOwnedUserKeys.length > 0 ? ` (${sample(adminOwnedUserKeys.map(keyLabel)).join(", ")})` : "";
      const rosterScope = adminRosterComplete ? "" : " identified from the readable domains";
      return verdict("warn", `${keyInventoryLabel}; ${unnamedKeys.length} lack a name, ${adminOwnedUserKeys.length} user keys${adminOwned} inherit admin-level permissions from their owners${rosterScope}, and ${unknownTypeKeys.length} expose no key type.`);
    }
    if (usersWithoutGroupData.length > 0 || groupsWithoutRoleData.length > 0 || userKeysWithoutOwner.length > 0) {
      return verdict("warn", `${keyInventoryLabel} with names and readable key types, but ${usersWithoutGroupData.length} users expose no group membership, ${groupsWithoutRoleData.length} groups expose no role grants, and ${userKeysWithoutOwner.length} user keys expose no userId, so admin-owned user keys may be undercounted.`);
    }
    if (!adminRosterComplete) {
      return verdict("warn", `${keyInventoryLabel} with names and readable key types; none of the ${userKeys.length} user keys belongs to the ${adminUserIds.size} admin users visible so far, but the admin roster (userManagement.users joined to authorizationManagement.groups) is incomplete, so the absence of admin-owned keys is not concluded.`);
    }
    return verdict("pass", `${keyInventoryLabel} with names, readable key types, and no user keys owned by admin group members (${adminUserIds.size} admin users matched against ${userKeys.length} user keys, every one exposing a userId).`);
  };

  const control5 = (): Verdict => {
    if (!keysReadable) return unreadableVerdict("API keys (apiAccess.keySearch)", data.apiKeys, `the Created column of the API keys UI, flagging user keys older than ${maxKeyAgeDays} days.`);
    if (keys.length === 0) return manualVerdict(`${zeroKeysNote}; key age cannot be evaluated on an empty inventory, which is unknown rather than compliant. Collect ${keyEvidence}`);
    if (agedUserKeys.length > 0) return verdict("fail", `${agedUserKeys.length}/${userKeys.length} user keys are older than ${maxKeyAgeDays} days without rotation.`);
    if (keysWithoutCreatedAt.length === keys.length) {
      return manualVerdict(`createdAt (the schema-cited ApiAccessUserKey.createdAt and ApiAccessIngestKey.createdAt fields) was not exposed for any of the ${keys.length} keys, so key age cannot be evaluated through the API. Review the Created column of the API keys UI for every account in scope.`);
    }
    if (agedLicenseKeys.length > 0) {
      return verdict("warn", `No dated user keys exceed ${maxKeyAgeDays} days, but ${agedLicenseKeys.length} license keys are older than that threshold and should have a rotation plan${keysWithoutCreatedAt.length > 0 ? `; ${keysWithoutCreatedAt.length} keys have no createdAt and were not counted as fresh` : ""}.`);
    }
    if (keysWithoutCreatedAt.length > 0) {
      return verdict("warn", `${userKeys.length - agedUserKeys.length} dated user keys were created within ${maxKeyAgeDays} days, but ${keysWithoutCreatedAt.length}/${keys.length} keys have no createdAt value and cannot be counted as rotated.`);
    }
    if (userKeys.length === 0 && licenseKeys.length === 0) {
      return manualVerdict(`${keyInventoryLabel}; no user or license keys were returned, so there is nothing to age-check and the empty rotation population is unknown rather than compliant. Confirm in the API keys UI that no user or license keys exist.`);
    }
    return verdict("pass", `All ${userKeys.length} user keys and ${licenseKeys.length} license keys were created within the last ${maxKeyAgeDays} days and every one of the ${keys.length} keys exposed a creation date${browserKeys.length > 0 ? `; ${browserKeys.length} browser keys are inventoried but not age-checked` : ""}.`);
  };

  const control6 = (): Verdict => {
    if (!keysReadable) return unreadableVerdict("API keys (apiAccess.keySearch)", data.apiKeys, "key usage evidence from the API keys UI and NrAuditEvent queries for every key.");
    if (keys.length === 0) {
      const coverageReason = !accountsReadable
        ? ` Coverage of every account in scope also cannot be confirmed (${causeOf(data.accounts)}).`
        : unseenScopeAccounts.length > 0
          ? ` Accounts ${unseenScopeAccounts.join(", ")} are also not visible to this key.`
          : !isComplete(data.apiKeys)
            ? ` The listing was also incomplete (${keyCoverage.join("; ")}).`
            : "";
      return manualVerdict(`${zeroKeysNote}. The query includes INGEST keys and every account has at least its original license key, so a complete listing cannot be empty: the empty result means the key cannot see the keys and is unknown rather than compliant.${coverageReason} Collect ${keyEvidence}`);
    }
    const auditSummary = auditReadable
      ? `${distinctActorKeys.size} distinct API keys performed configuration changes in the last ${data.auditWindowDays} days${hasUnreadableScope(data.apiKeyAuditEvents) ? " in the readable accounts" : ""}`
      : `API key change activity is unknown (NrAuditEvent api_key actors ${unavailableDetail(data.apiKeyAuditEvents)})`;
    if (ownerIdsUnavailable) {
      return manualVerdict(`${keyInventoryLabel}, but ${ownerIdsUnavailableNote}, so orphaned and inactive-owner keys cannot be identified through the API; ${auditSummary}. Review every key with its owner in the API keys UI and revoke any without a documented consumer.`);
    }
    if (orphanedUserKeys.length > 0 || inactiveOwnerKeys.length > 0 || undatedOwnerKeys.length > 0) {
      return verdict("warn", `${orphanedUserKeys.length} user keys belong to users no longer visible, ${inactiveOwnerKeys.length} belong to users inactive for more than ${inactiveDays} days, and ${undatedOwnerKeys.length} belong to users with no lastActive value; ${auditSummary}.`);
    }
    return manualVerdict(`${auditSummary}. NrAuditEvent only records configuration changes, so read-only key usage cannot be confirmed through the API; review the remaining ${keys.length} keys with their owners${userKeysWithoutOwner.length > 0 ? ` (${userKeysWithoutOwner.length} user keys expose no userId)` : ""} and revoke any without a documented consumer.`);
  };

  const control7 = (): Verdict => {
    if (!grantsReadable) return unreadableVerdict("Group role grants", data.groupGrants, groupEvidence);
    if (!usersReadable) return unreadableVerdict("Users", data.users, userEvidence);
    if (groupGrants.length === 0) {
      if (hasUnreadableScope(data.groupGrants)) return unknownEmptyVerdict("Group role grants (authorizationManagement.groups)", data.groupGrants, groupEvidence);
      return manualVerdict(`authorizationManagement.groups returned zero groups, so account access cannot be mapped; emptiness is unknown rather than compliant. Collect ${groupEvidence}`);
    }
    if (users.length === 0) {
      if (hasUnreadableScope(data.users)) return unknownEmptyVerdict("Users (userManagement.users)", data.users, userEvidence);
      return manualVerdict(`userManagement.users returned zero users, so account access per user cannot be evaluated. Collect ${userEvidence}`);
    }
    if (groupsWithoutRoleData.length === groupGrants.length || usersWithoutGroupData.length === users.length) {
      return manualVerdict(`Role grants were exposed for ${groupGrants.length - groupsWithoutRoleData.length}/${groupGrants.length} groups and group membership for ${users.length - usersWithoutGroupData.length}/${users.length} users, so account access cannot be mapped. Collect ${groupEvidence}`);
    }
    if (broadAccessUsers.length > 0) {
      return verdict("warn", `${broadAccessUsers.length}/${users.length} non-admin users hold organization-scoped grants or access to more than ${maxAccountsPerUser} accounts.`);
    }
    if (!accountsReadable) return manualVerdict(`Accounts (actor.accounts) were ${unavailableDetail(data.accounts)}, so the account population is unknown; within the readable group grants, no non-admin user exceeds ${maxAccountsPerUser} accounts. Collect the account list from Administration > Access Management > Accounts.`);
    if (usersWithoutGroupData.length > 0 || groupsWithoutRoleData.length > 0) {
      return verdict("warn", `No mapped non-admin user exceeds ${maxAccountsPerUser} accounts, but ${usersWithoutGroupData.length} users expose no group membership and ${groupsWithoutRoleData.length} groups expose no role grants, so their access is unknown.`);
    }
    return verdict("pass", `No non-admin users exceed ${maxAccountsPerUser} accounts or hold organization-scoped grants across ${accounts.length} visible accounts.`);
  };

  const control8 = (): Verdict => {
    if (!grantsReadable) return unreadableVerdict("Group role grants", data.groupGrants, "each group's account access from the UI, flagging users who reach both production and non-production accounts.");
    if (!usersReadable) return unreadableVerdict("Users", data.users, userEvidence);
    if (!accountsReadable) return unreadableVerdict("Accounts (actor.accounts)", data.accounts, "the account inventory with environment classification from Administration > Access Management > Accounts.");
    if (accounts.length === 0) return manualVerdict("actor.accounts returned zero accounts, so environment separation cannot be evaluated; emptiness is unknown rather than compliant. Collect the account inventory from Administration > Access Management > Accounts.");
    if (accounts.length === 1) {
      return manualVerdict(`Not applicable through the API: only one account (${accountLabel(accounts[0])}) is visible to this key, so production and non-production separation has nothing to compare. Confirm in Administration > Access Management > Accounts that the organization has a single account.`);
    }
    if (!classifiable) {
      return manualVerdict(`Account names did not match both the production pattern /${productionPattern.source}/ and the non-production pattern /${nonproductionPattern.source}/. Classify the ${accounts.length} accounts manually or pass production_account_pattern and nonproduction_account_pattern.`);
    }
    if (groupGrants.length === 0 && hasUnreadableScope(data.groupGrants)) return unknownEmptyVerdict("Group role grants (authorizationManagement.groups)", data.groupGrants, groupEvidence);
    if (users.length === 0 && hasUnreadableScope(data.users)) return unknownEmptyVerdict("Users (userManagement.users)", data.users, userEvidence);
    if (groupGrants.length === 0 || users.length === 0) return manualVerdict(`${groupGrants.length} groups and ${users.length} users were returned, so cross-environment access cannot be mapped; emptiness is unknown rather than compliant. Collect ${groupEvidence}`);
    if (crossEnvironmentUsers.length > 0) {
      return verdict("warn", `${crossEnvironmentUsers.length} non-admin users can reach both production (${productionAccounts.length}) and non-production (${nonproductionAccounts.length}) accounts.`);
    }
    if (unclassifiedAccounts.length > 0 || usersWithoutGroupData.length > 0 || groupsWithoutRoleData.length > 0) {
      return verdict("warn", `No mapped non-admin user reaches both production (${productionAccounts.length}) and non-production (${nonproductionAccounts.length}) accounts, but ${unclassifiedAccounts.length} accounts matched neither pattern, ${usersWithoutGroupData.length} users expose no group membership, and ${groupsWithoutRoleData.length} groups expose no role grants.`);
    }
    return verdict("pass", `No non-admin users hold access to both production (${productionAccounts.length}) and non-production (${nonproductionAccounts.length}) accounts, and every account was classified.`);
  };

  const control20 = (): Verdict => {
    const grantedCustomRolesNote = grantsReadable
      ? grantedCustomRoleNames.length > 0
        ? `Group grants expose ${grantedCustomRoleNames.length} custom roles in use (${sample(grantedCustomRoleNames, 10).join(", ")}); custom roles that are defined but not granted to any group cannot be enumerated without the catalog.`
        : "No custom role appears in the readable group grants, but custom roles that are defined and not granted to any group cannot be enumerated without the catalog."
      : "Group grants were not readable either, so custom roles in use cannot be enumerated.";
    if (!rolesReadable) {
      return manualVerdict(`The role catalog (${ROLE_CATALOG_SOURCE}) was ${unavailableDetail(data.roles)}. The documented catalog is only served to organizations with the multi-tenancy entitlement. ${grantedCustomRolesNote} Collect every custom role's capabilities from Administration > Access Management > Roles.`);
    }
    if (roles.length === 0) return manualVerdict(`${ROLE_CATALOG_SOURCE} returned zero roles; New Relic always exposes standard roles, so the key cannot read them and emptiness is unknown rather than compliant. Collect the role list from Administration > Access Management > Roles.`);
    if (customRoles.length > 0) {
      return manualVerdict(`${customRoles.length} custom roles exist (${sample(customRoles.map(roleLabel), 10).join(", ")}). NerdGraph does not expose role capabilities, so open each role in Administration > Access Management > Roles and confirm no unnecessary manage or delete capabilities are granted.`);
    }
    if (unknownTypeRoles.length > 0) return manualVerdict(`${unknownTypeRoles.length}/${roles.length} roles exposed a type other than ${ROLE_TYPE_CUSTOM} or ${ROLE_TYPE_STANDARD} (the MultiTenantAuthorizationRoleTypeEnum values), so custom roles cannot be distinguished from standard ones. Collect the role list with types from Administration > Access Management > Roles.`);
    if (!isComplete(data.roles)) return verdict("warn", `No custom roles appeared among ${roles.length} roles, but the role listing was incomplete, so unseen custom roles cannot be ruled out.`);
    if (standardRoles.length === 0) return manualVerdict(`No custom roles appeared among ${roles.length} roles, but no ${ROLE_TYPE_STANDARD} roles were returned either, so the role listing is not trustworthy. Collect the role list from Administration > Access Management > Roles.`);
    const catalogClause = `the ${ROLE_CATALOG_SOURCE} query was readable and complete, and it returned ${standardRoles.length} ${ROLE_TYPE_STANDARD} roles`;
    // The gap leads and the catalog's zero count follows, so the absence of custom roles is not read as confirmed.
    if (!grantsReadable) {
      return verdict("warn", `Group grants (authorizationManagement.groups) were ${unavailableDetail(data.groupGrants)}, so the roles in use were not cross-checked against the catalog; the catalog itself lists no custom roles (${catalogClause}).`);
    }
    if (!isComplete(data.groupGrants)) {
      return verdict("warn", `The group grant listing (authorizationManagement.groups) is incomplete, so the roles in use were only partly cross-checked against the catalog; no custom role appears in the readable group grants and the catalog itself lists none (${catalogClause}).`);
    }
    return verdict("pass", `No custom roles exist. Both conditions for accepting this hold: ${catalogClause}. The complete group grant listing confirms none is in use.`);
  };

  const findings: NewrelicFinding[] = [];

  // NR-04 lists only the inventories its verdict reads (keys, users, group grants, accounts in scope); the NrAuditEvent
  // key-actor rows belong to NR-06, which renders them with their own status.
  const adminRoster = [data.users, data.groupGrants];
  const keyOwnership = [data.apiKeys, ...adminRoster];
  findings.push(finding(4, limitCoverage(control4(), [...keyCoverage, ...userCoverage, ...groupCoverage, ...accountCoverage, ...scopeCoverage]), {
    ...measured("keys_total", data.apiKeys, keys.length),
    keys_reported_total: data.apiKeys.total ?? null,
    ...measured("user_keys", data.apiKeys, userKeys.length),
    ...measured("license_keys", data.apiKeys, licenseKeys.length),
    ...measured("browser_keys", data.apiKeys, browserKeys.length),
    ...measured("unknown_type_keys", data.apiKeys, unknownTypeKeys.length),
    ...measured("unnamed_keys", data.apiKeys, sample(unnamedKeys.map(keyLabel))),
    ...measured("admin_owned_user_keys", keyOwnership, sample(adminOwnedUserKeys.map(keyLabel))),
    admin_roster_complete: adminRosterComplete,
    admin_roster_status: collectionStatus(adminRoster),
    ...measured("user_keys_without_user_id", data.apiKeys, userKeysWithoutOwner.length),
    key_listing_complete: isComplete(data.apiKeys),
    key_listing_status: collectionStatus(data.apiKeys),
    ...accountScopeEvidence(data.accountScope),
  }));

  findings.push(finding(5, limitCoverage(control5(), [...keyCoverage, ...accountCoverage, ...scopeCoverage]), {
    max_key_age_days: maxKeyAgeDays,
    ...measured("aged_user_keys", data.apiKeys, sample(agedUserKeys.map((key) => `${keyLabel(key)} (${keyAgeDays(key, now)} days)`))),
    ...measured("aged_license_keys", data.apiKeys, sample(agedLicenseKeys.map((key) => `${keyLabel(key)} (${keyAgeDays(key, now)} days)`))),
    ...measured("keys_without_created_at", data.apiKeys, sample(keysWithoutCreatedAt.map(keyLabel))),
    ...measured("keys_without_created_at_total", data.apiKeys, keysWithoutCreatedAt.length),
    key_listing_complete: isComplete(data.apiKeys),
    key_listing_status: collectionStatus(data.apiKeys),
    ...accountScopeEvidence(data.accountScope),
  }));

  const keyOwners = [data.apiKeys, data.users];
  findings.push(finding(6, limitCoverage(control6(), [...keyCoverage, ...userCoverage, ...auditCoverage, ...accountCoverage, ...scopeCoverage]), {
    ...measured("keys_total", data.apiKeys, keys.length),
    ...measured("user_keys_without_user_id", data.apiKeys, userKeysWithoutOwner.length),
    ...accountScopeEvidence(data.accountScope),
    ...measured("accounts_in_scope_not_visible", data.accounts, unseenScopeAccounts),
    key_listing_complete: isComplete(data.apiKeys),
    key_listing_status: collectionStatus(data.apiKeys),
    user_listing_status: collectionStatus(data.users),
    ...measured("distinct_api_keys_in_audit", data.apiKeyAuditEvents, distinctActorKeys.size),
    ...measured("audit_events_by_api_keys", data.apiKeyAuditEvents, data.apiKeyAuditEvents.data.length),
    audit_window_days: data.auditWindowDays,
    audit_readable: auditReadable,
    audit_status: collectionStatus(data.apiKeyAuditEvents),
    ...measured("orphaned_user_keys", keyOwners, sample(orphanedUserKeys.map(keyLabel))),
    ...measured("inactive_owner_user_keys", keyOwners, sample(inactiveOwnerKeys.map(keyLabel))),
    ...measured("undated_owner_user_keys", keyOwners, sample(undatedOwnerKeys.map(keyLabel))),
    manual_evidence: "API keys UI export plus owner confirmation for every key without a documented consumer; NrAuditEvent WHERE actorType = 'api_key' for change activity.",
  }));

  const accessMap = [...adminRoster, data.accounts];
  findings.push(finding(7, limitCoverage(control7(), [...groupCoverage, ...userCoverage, ...accountCoverage, ...scopeCoverage]), {
    ...measured("accounts_visible", data.accounts, accounts.length),
    max_accounts_per_user: maxAccountsPerUser,
    ...measured("broad_access_users", adminRoster, sample(broadAccessUsers.map((entry) => `${userLabel(entry.user)} (${entry.organizationScoped ? "organization scope" : `${entry.accountIds.size} accounts`})`))),
    ...measured("users_without_grants", adminRoster, usersWithoutGrants.length),
    ...measured("users_without_group_data", data.users, usersWithoutGroupData.length),
    ...measured("groups_without_role_data", data.groupGrants, groupsWithoutRoleData.length),
  }));

  findings.push(finding(8, limitCoverage(control8(), [...groupCoverage, ...userCoverage, ...accountCoverage, ...scopeCoverage]), {
    ...measured("accounts_visible", data.accounts, accounts.length),
    ...measured("production_accounts", data.accounts, sample(productionAccounts.map(accountLabel))),
    ...measured("nonproduction_accounts", data.accounts, sample(nonproductionAccounts.map(accountLabel))),
    ...measured("unclassified_accounts", data.accounts, sample(unclassifiedAccounts.map(accountLabel))),
    ...measured("cross_environment_users", accessMap, sample(crossEnvironmentUsers.map((entry) => userLabel(entry.user)))),
    ...measured("admin_users_excluded", adminRoster, adminUserIds.size),
    manual_evidence: "Account inventory with environment classification from Administration > Access Management > Accounts.",
  }));

  findings.push(finding(20, limitCoverage(control20(), [...roleCoverage, ...groupCoverage]), {
    role_catalog_source: ROLE_CATALOG_SOURCE,
    role_catalog_readable: rolesReadable,
    ...measured("roles_total", data.roles, roles.length),
    ...measured("standard_roles", data.roles, standardRoles.length),
    ...measured("unknown_type_roles", data.roles, unknownTypeRoles.length),
    role_listing_complete: isComplete(data.roles),
    ...measured("custom_roles", data.roles, sample(customRoles.map((role) => ({
      id: asString(role.id),
      name: roleLabel(role),
      scope: asString(role.scope),
      type: asString(role.type),
    })))),
    ...measured("custom_roles_in_group_grants", data.groupGrants, sample(grantedCustomRoleNames)),
    ...measured("groups_granted_custom_roles", data.groupGrants, sample(customRoleGrants.map((group) => asString(group.displayName) ?? asString(group.id) ?? "group"))),
    group_grants_status: collectionStatus(data.groupGrants),
    manual_evidence: "Capability list for each custom role from Administration > Access Management > Roles.",
  }));

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
  const coverage = [...accountCoverage, ...scopeCoverage, ...userCoverage, ...groupCoverage, ...roleCoverage, ...keyCoverage, ...auditCoverage];

  return {
    category: "access_control",
    title: "New Relic access control and API key hygiene",
    summary: {
      region: config.region,
      ...accountScopeEvidence(data.accountScope),
      ...measured("accounts_visible", data.accounts, accounts.length),
      ...measured("users", data.users, users.length),
      ...measured("keys_total", data.apiKeys, keys.length),
      ...measured("user_keys", data.apiKeys, userKeys.length),
      ...measured("aged_user_keys", data.apiKeys, agedUserKeys.length),
      ...measured("admin_users", adminRoster, adminUserIds.size),
      ...measured("broad_access_users", adminRoster, broadAccessUsers.length),
      ...measured("cross_environment_users", accessMap, crossEnvironmentUsers.length),
      ...measured("custom_roles", data.roles, customRoles.length),
      ...measured("api_key_audit_events", data.apiKeyAuditEvents, data.apiKeyAuditEvents.data.length),
      collection_errors: accountScopeErrors(data.accountScope, allCollected).length,
      coverage_limitations: coverage.length,
    },
    findings,
    errors: accountScopeErrors(data.accountScope, allCollected),
    coverage,
    coreData: {
      "core_data/accounts.json": coreDataFile(data.accounts),
      "core_data/api_keys.json": coreDataFile(data.apiKeys),
      "core_data/audit_api_key_actor_events.json": coreDataFile(data.apiKeyAuditEvents),
      "core_data/audit_api_key_change_events.json": coreDataFile(data.apiKeyChangeEvents),
      "core_data/users.json": coreDataFile(data.users),
      "core_data/group_role_grants.json": coreDataFile(data.groupGrants),
      "core_data/roles.json": coreDataFile(data.roles),
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
  accountScope: AccountScope;
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
  scope: AccountScope,
  load: (accountId: number) => Promise<PagedList | JsonRecord[]>,
): Promise<PagedList> {
  return collectScoped(
    accountScopes(scope),
    (accountId) => load(Number(accountId)),
    (row, accountId) => ({ ...row, queriedAccountId: Number(accountId) }),
  );
}

export async function collectNewrelicAlertingData(
  client: AlertingClient,
  options: { entityLimit?: number } = {},
): Promise<NewrelicAlertingData> {
  const entityLimit = clampNumber(options.entityLimit, DEFAULT_ENTITY_LIMIT, 1, 20_000);
  const accountScope = await resolveAccountScope(client);
  const currentUser = await collectRecord("actor.user", CURRENT_USER_SHAPE, () => client.getCurrentUser());
  const policies = await collectList("alerts.policiesSearch", ALERT_POLICY_SHAPE, () => collectPerAccount(accountScope, (id) => client.listAlertPolicies(id)));
  const conditions = await collectList("alerts.nrqlConditionsSearch", NRQL_CONDITION_SHAPE, () => collectPerAccount(accountScope, (id) => client.listNrqlConditions(id)));
  const destinations = await collectList("aiNotifications.destinations", DESTINATION_SHAPE, () => collectPerAccount(accountScope, (id) => client.listNotificationDestinations(id)));
  const channels = await collectList("aiNotifications.channels", CHANNEL_SHAPE, () => collectPerAccount(accountScope, (id) => client.listNotificationChannels(id)));
  const workflows = await collectList("aiWorkflows.workflows", WORKFLOW_SHAPE, () => collectPerAccount(accountScope, (id) => client.listWorkflows(id)));
  const alertableEntities = await collectList(
    "entitySearch.alertable",
    ENTITY_SHAPE,
    () => collectPerAccount(accountScope, (id) => client.searchEntities(`alertSeverity IS NOT NULL AND accountId = ${id}`, entityLimit)),
  );
  const workloads = await collectList(
    "entitySearch.workloads",
    ENTITY_SHAPE,
    () => collectPerAccount(accountScope, (id) => client.searchEntities(`type = 'WORKLOAD' AND accountId = ${id}`, entityLimit)),
  );
  return { accountScope, accountIds: accountScope.accountIds, currentUser, policies, conditions, destinations, channels, workflows, alertableEntities, workloads };
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

  const policiesReadable = isReadable(data.policies);
  const conditionsReadable = isReadable(data.conditions);
  const entitiesReadable = isReadable(data.alertableEntities);
  const destinationsReadable = isReadable(data.destinations);
  const channelsReadable = isReadable(data.channels);
  const workflowsReadable = isReadable(data.workflows);
  const currentUserReadable = isReadable(data.currentUser);

  const reportingEntities = entities.filter(isReporting);
  const uncoveredEntities = reportingEntities.filter((entity) => (asString(entity.alertSeverity) ?? "").toUpperCase() === "NOT_CONFIGURED");
  const uncoveredCritical = uncoveredEntities.filter((entity) => CRITICAL_ENTITY_TYPES.has(entityDomainType(entity)));
  const enabledConditions = conditions.filter((condition) => asBoolean(condition.enabled) === true);
  const conditionsWithoutEnabledFlag = conditions.filter((condition) => asBoolean(condition.enabled) === undefined);
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
  const emailDestinationsWithoutAddress = emailDestinations.filter((destination) => destinationEmails(destination).length === 0);
  const destinationsWithoutType = destinations.filter((destination) => !asString(destination.type));
  const enabledWorkflows = workflows.filter((workflow) => asBoolean(workflow.workflowEnabled) === true);
  const workflowsWithoutEnabledFlag = workflows.filter((workflow) => asBoolean(workflow.workflowEnabled) === undefined);
  const possiblyEnabledWorkflows = workflows.filter((workflow) => asBoolean(workflow.workflowEnabled) !== false);
  const enablementUnverifiable = workflows.length > 0 && workflowsWithoutEnabledFlag.length === workflows.length;
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
  const resolveDestinationIds = (workflow: JsonRecord): Set<string> => {
    const ids = new Set<string>();
    for (const configuration of asRecords(workflow.destinationConfigurations)) {
      const channel = channelById.get(asString(configuration.channelId) ?? "");
      const destinationId = asString(channel?.destinationId);
      if (destinationId && destinationById.has(destinationId)) ids.add(destinationId);
    }
    return ids;
  };
  const routedDestinationIds = new Set(enabledWorkflows.flatMap((workflow) => [...resolveDestinationIds(workflow)]));
  const unroutedEnabledWorkflows = enabledWorkflows.filter((workflow) => resolveDestinationIds(workflow).size === 0);
  const enrichedWorkflows = possiblyEnabledWorkflows.filter((workflow) => asRecords(workflow.enrichments).length > 0 && asBoolean(workflow.enrichmentsEnabled) !== false);
  const enrichedExternalWorkflows = enrichedWorkflows.filter((workflow) =>
    asRecords(workflow.destinationConfigurations).some((configuration) => {
      const channel = channelById.get(asString(configuration.channelId) ?? "");
      const destination = destinationById.get(asString(channel?.destinationId) ?? "");
      const type = (asString(configuration.type) ?? asString(channel?.type) ?? asString(destination?.type) ?? "").toUpperCase();
      return type === "" || EXTERNAL_DESTINATION_TYPES.has(type);
    }),
  );
  const enrichmentQueries = enrichedWorkflows.flatMap((workflow) =>
    asRecords(workflow.enrichments).flatMap((enrichment) =>
      asRecords(enrichment.configurations).map((configuration) => asString(configuration.query)).filter((query): query is string => Boolean(query)),
    ),
  );

  const policyCoverage = coverageNotes([["alert policies", data.policies]]);
  const conditionCoverage = coverageNotes([["NRQL conditions", data.conditions]]);
  const entityCoverage = coverageNotes([["alertable entities", data.alertableEntities]]);
  const workloadCoverage = coverageNotes([["workloads", data.workloads]]);
  const destinationCoverage = coverageNotes([["destinations", data.destinations]]);
  const channelCoverage = coverageNotes([["channels", data.channels]]);
  const workflowCoverage = coverageNotes([["workflows", data.workflows]]);
  const accountCount = data.accountIds.length;
  const policyEvidence = "the Alerts > Alert policies list with condition counts for every account in scope.";
  const entityEvidence = "the entity explorer alert status column for every reporting APM application, host, and synthetic monitor.";
  const destinationEvidence = "Alerts > Destinations with the address or endpoint of every destination and its status.";
  const workflowEvidence = "Alerts > Workflows with each workflow's enabled state and destinations.";
  const activeStateNote = "Destination active state is not among the documented aiNotifications.destinations fields and is not read; enablement is verified through the documented workflowEnabled flag";

  const control9 = (): Verdict => {
    if (!policiesReadable) return unreadableVerdict("Alert policies (alerts.policiesSearch)", data.policies, policyEvidence);
    if (!conditionsReadable) return unreadableVerdict("NRQL conditions (alerts.nrqlConditionsSearch)", data.conditions, policyEvidence);
    if (!entitiesReadable) return unreadableVerdict("Alertable entities (entitySearch)", data.alertableEntities, entityEvidence);
    if (policies.length === 0 && hasUnreadableScope(data.policies)) return unknownEmptyVerdict("Alert policies (alerts.policiesSearch)", data.policies, policyEvidence);
    if (entities.length === 0 && hasUnreadableScope(data.alertableEntities)) return unknownEmptyVerdict("Alertable entities (entitySearch)", data.alertableEntities, entityEvidence);
    if (policies.length === 0 && reportingEntities.length === 0) {
      return manualVerdict(`No alert policies and no reporting alertable entities were returned across ${accountCount} accounts, so there is nothing to compare; emptiness is unknown rather than compliant. Confirm the accounts are unused or that this key can see their entities, and collect ${policyEvidence}`);
    }
    if (policies.length === 0) return verdict("fail", `No alert policies exist across ${accountCount} accounts while ${reportingEntities.length} reporting entities are monitored.`);
    if (enabledConditions.length === 0) {
      if (conditions.length === 0 && hasUnreadableScope(data.conditions)) return unknownEmptyVerdict("NRQL conditions (alerts.nrqlConditionsSearch)", data.conditions, policyEvidence);
      return verdict("fail", `${policies.length} policies exist but none has a NRQL condition with enabled = true (${conditions.length} conditions returned, ${conditionsWithoutEnabledFlag.length} without an enabled flag), so no alerting is active.`);
    }
    if (uncoveredCritical.length > 0) {
      return verdict("fail", `${uncoveredCritical.length} reporting APM applications, infrastructure hosts, or synthetic monitors have no alert conditions targeting them (${uncoveredEntities.length}/${reportingEntities.length} alertable entities uncovered).`);
    }
    if (reportingEntities.length === 0) {
      return manualVerdict(`${policies.length} policies with ${enabledConditions.length} enabled NRQL conditions exist, but entitySearch returned zero reporting alertable entities across ${accountCount} accounts, so coverage cannot be measured; emptiness is unknown rather than compliant. Confirm entity visibility for this key and collect ${entityEvidence}`);
    }
    if (uncoveredEntities.length > 0 || emptyPolicies.length > 0) {
      return verdict("warn", `${uncoveredEntities.length}/${reportingEntities.length} reporting alertable entities have no alert conditions and ${emptyPolicies.length}/${policies.length} policies have no enabled NRQL conditions.`);
    }
    if (conditionsWithoutEnabledFlag.length > 0) {
      return verdict("warn", `${enabledConditions.length} enabled NRQL conditions cover all ${reportingEntities.length} reporting alertable entities, but ${conditionsWithoutEnabledFlag.length} conditions did not expose the enabled flag and were not counted as active.`);
    }
    return verdict("pass", `${policies.length} policies with ${enabledConditions.length} enabled NRQL conditions cover all ${reportingEntities.length} reporting alertable entities.`);
  };

  const control10 = (): Verdict => {
    if (!destinationsReadable) return unreadableVerdict("Notification destinations (aiNotifications.destinations)", data.destinations, destinationEvidence);
    if (!workflowsReadable) return unreadableVerdict("Workflows (aiWorkflows.workflows)", data.workflows, workflowEvidence);
    if (!channelsReadable) return unreadableVerdict("Notification channels (aiNotifications.channels)", data.channels, destinationEvidence);
    if (personalEmailDestinations.length > 0) return verdict("fail", `${personalEmailDestinations.length} email destinations route alerts to personal email providers.`);
    if (destinations.length === 0) {
      if (hasUnreadableScope(data.destinations)) return unknownEmptyVerdict("Notification destinations (aiNotifications.destinations)", data.destinations, destinationEvidence);
      if (!policiesReadable) {
        return manualVerdict(`No notification destinations were returned across ${accountCount} accounts and alert policies were not readable (${causeOf(data.policies)}), so it is unknown whether alerts have anywhere to go. Collect ${destinationEvidence}`);
      }
      return policies.length > 0
        ? verdict("fail", `No notification destinations exist across ${accountCount} accounts while ${policies.length} alert policies are defined, so alerts cannot reach anyone.`)
        : manualVerdict(`No notification destinations and no alert policies exist across ${accountCount} accounts; emptiness is unknown rather than compliant. Confirm alerting is intentionally unused and collect ${destinationEvidence}`);
    }
    if (unapprovedEmailDestinations.length > 0) {
      return verdict("warn", `${unapprovedEmailDestinations.length} email destinations use domains outside the approved set (${[...approvedDomains].join(", ")}).`);
    }
    if (enablementUnverifiable) {
      return manualVerdict(`${destinations.length} destinations exist, but none of the ${workflows.length} workflows exposed the documented workflowEnabled flag, so enablement cannot be verified through the API. ${activeStateNote}. Collect ${workflowEvidence}`);
    }
    if (enabledWorkflows.length === 0) {
      if (workflows.length === 0 && hasUnreadableScope(data.workflows)) return unknownEmptyVerdict("Workflows (aiWorkflows.workflows)", data.workflows, workflowEvidence);
      const workflowInventory = `${workflows.length} workflows returned, ${workflowsWithoutEnabledFlag.length} without an enabled flag`;
      if (!policiesReadable) {
        return manualVerdict(`${destinations.length} destinations exist but no workflow has workflowEnabled = true (${workflowInventory}) and alert policies were not readable (${causeOf(data.policies)}), so routing cannot be evaluated. Collect ${workflowEvidence}`);
      }
      if (policies.length > 0) {
        return verdict("warn", `${policies.length} alert policies exist but no workflow has workflowEnabled = true (${workflowInventory}), so issues are not routed to destinations.`);
      }
      return manualVerdict(`${destinations.length} destinations exist but no enabled workflow routes to them (${workflowInventory}) and no alert policies exist across ${accountCount} accounts; emptiness is unknown rather than compliant. Confirm alerting is intentionally unused and collect ${workflowEvidence}`);
    }
    if (routedDestinationIds.size === 0) {
      return manualVerdict(`${enabledWorkflows.length} enabled workflows exist, but none of their destination configurations resolved to an inventoried destination through channels (channelId to channel.destinationId), so routing cannot be verified through the API. Collect ${workflowEvidence}`);
    }
    if (destinationsWithoutType.length > 0 || emailDestinationsWithoutAddress.length > 0 || workflowsWithoutEnabledFlag.length > 0 || unroutedEnabledWorkflows.length > 0) {
      return verdict("warn", `${destinations.length} destinations were inventoried and ${enabledWorkflows.length} enabled workflows route to ${routedDestinationIds.size} of them, but ${destinationsWithoutType.length} destinations expose no type, ${emailDestinationsWithoutAddress.length} email destinations expose no address, ${workflowsWithoutEnabledFlag.length} workflows expose no enabled flag, and ${unroutedEnabledWorkflows.length} enabled workflows resolve to no inventoried destination; those cannot be counted as approved and working.`);
    }
    if (emailDestinations.length > 0 && approvedDomains.size === 0) {
      return verdict("warn", `${emailDestinations.length} email destinations could not be checked against an approved domain list${currentUserReadable ? "" : ` (actor.user unreadable: ${causeOf(data.currentUser)})`}; pass approved_email_domains to confirm they are corporate addresses.`);
    }
    return verdict("pass", `${destinations.length} destinations across ${Object.keys(destinationTypeCounts).length} types receive ${enabledWorkflows.length} enabled workflows (${routedDestinationIds.size} destinations resolved through channels); every destination exposed its type, every workflow exposed workflowEnabled, and all ${emailDestinations.length} email destinations use approved domains${approvedDomains.size > 0 ? ` (${[...approvedDomains].join(", ")})` : ""}. ${activeStateNote}.`);
  };

  const control17 = (): Verdict => {
    if (!workflowsReadable) return unreadableVerdict("Workflows (aiWorkflows.workflows)", data.workflows, "Alerts > Workflows NRQL enrichments and Alerts > Correlation decisions settings that could expose sensitive attributes.");
    if (enrichedExternalWorkflows.length > 0) {
      return verdict("warn", `${enrichedExternalWorkflows.length} workflows attach NRQL enrichment results to notifications sent to external or unidentified destination types, so query output leaves the platform with each notification. Review the ${enrichmentQueries.length} enrichment queries and confirm they exclude sensitive attributes.`);
    }
    if (workflows.length === 0) {
      if (hasUnreadableScope(data.workflows)) return unknownEmptyVerdict("Workflows (aiWorkflows.workflows)", data.workflows, "Alerts > Workflows NRQL enrichments for every account.");
      return manualVerdict(`No workflows were returned across ${accountCount} accounts, so there are no enrichments to review through the API. Correlation decision settings are not exposed by NerdGraph: record Alerts > Correlation decisions and confirm custom decisions do not correlate on sensitive attributes.`);
    }
    return manualVerdict(`${enrichedWorkflows.length} enabled workflows use NRQL enrichments and none route to external destination types${channelsReadable && destinationsReadable ? "" : " (channel or destination types were partly unreadable, so unidentified types were treated as external)"}. Correlation decision settings are not exposed by NerdGraph: record Alerts > Correlation decisions and confirm custom decisions do not correlate on sensitive attributes.`);
  };

  const findings: NewrelicFinding[] = [];

  // NR-09 reads workloads for its disruption evidence, so the workload listing is part of its coverage.
  const policyConditions = [data.policies, data.conditions];
  findings.push(finding(9, limitCoverage(control9(), [...policyCoverage, ...conditionCoverage, ...entityCoverage, ...workloadCoverage]), {
    ...measured("policies", data.policies, policies.length),
    ...measured("conditions", data.conditions, conditions.length),
    ...measured("enabled_conditions", data.conditions, enabledConditions.length),
    ...measured("conditions_without_enabled_flag", data.conditions, conditionsWithoutEnabledFlag.length),
    ...measured("empty_policies", policyConditions, sample(emptyPolicies.map((policy) => asString(policy.name) ?? asString(policy.id) ?? "policy"))),
    ...measured("reporting_alertable_entities", data.alertableEntities, reportingEntities.length),
    alertable_entities_reported_total: data.alertableEntities.total ?? null,
    ...measured("uncovered_entities", data.alertableEntities, uncoveredEntities.length),
    ...measured("uncovered_critical_entities", data.alertableEntities, sample(uncoveredCritical.map(entityLabel))),
    ...measured("workloads", data.workloads, workloads.length),
    ...measured("disrupted_workloads", data.workloads, sample(disruptedWorkloads.map((workload) => asString(workload.name) ?? "workload"))),
  }));

  // NR-10 reads alert policies on its zero-destination and zero-workflow branches, so the policy listing is part of
  // its coverage and is disclosed with its status even on the pass path. The approved domain list is derived from
  // actor.user unless it was passed in, so it carries that query's status.
  const routing = [data.destinations, data.channels, data.workflows];
  const approvedDomainsEvidence = (options.approvedEmailDomains ?? []).length > 0
    ? { approved_email_domains: [...approvedDomains], approved_email_domains_status: "complete (approved_email_domains option)" }
    : measured("approved_email_domains", data.currentUser, [...approvedDomains]);
  findings.push(finding(10, limitCoverage(control10(), [...destinationCoverage, ...channelCoverage, ...workflowCoverage, ...policyCoverage]), {
    ...measured("destinations", data.destinations, destinations.length),
    ...measured("destination_types", data.destinations, destinationTypeCounts),
    ...measured("channels", data.channels, channels.length),
    ...measured("workflows", data.workflows, workflows.length),
    ...measured("enabled_workflows", data.workflows, enabledWorkflows.length),
    ...measured("workflows_without_enabled_flag", data.workflows, workflowsWithoutEnabledFlag.length),
    ...measured("alert_policies", data.policies, policies.length),
    ...approvedDomainsEvidence,
    current_user_status: collectionStatus(data.currentUser),
    ...measured("personal_email_destinations", data.destinations, sample(personalEmailDestinations.map((destination) => asString(destination.name) ?? "destination"))),
    ...measured("unapproved_email_destinations", data.destinations, sample(unapprovedEmailDestinations.map((destination) => asString(destination.name) ?? "destination"))),
    ...measured("destinations_routed_by_enabled_workflows", routing, routedDestinationIds.size),
    ...measured("enabled_workflows_without_resolved_destination", routing, sample(unroutedEnabledWorkflows.map((workflow) => asString(workflow.name) ?? asString(workflow.id) ?? "workflow"))),
    destination_active_state: "not read: not among the documented aiNotifications.destinations fields",
    ...measured("destinations_without_type", data.destinations, destinationsWithoutType.length),
    ...measured("email_destinations_without_address", data.destinations, emailDestinationsWithoutAddress.length),
  }));

  findings.push(finding(17, limitCoverage(control17(), [...workflowCoverage, ...channelCoverage, ...destinationCoverage]), {
    ...measured("workflows", data.workflows, workflows.length),
    ...measured("enabled_workflows", data.workflows, enabledWorkflows.length),
    ...measured("enriched_workflows", data.workflows, sample(enrichedWorkflows.map((workflow) => asString(workflow.name) ?? "workflow"))),
    ...measured("enriched_external_workflows", routing, sample(enrichedExternalWorkflows.map((workflow) => asString(workflow.name) ?? "workflow"))),
    ...measured("enrichment_queries", data.workflows, sample(enrichmentQueries, 10)),
    manual_evidence: "Alerts > Correlation decisions: list of enabled decisions and the attributes they correlate on.",
  }));

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
  const coverage = [
    ...policyCoverage,
    ...conditionCoverage,
    ...destinationCoverage,
    ...channelCoverage,
    ...workflowCoverage,
    ...entityCoverage,
    ...workloadCoverage,
  ];

  return {
    category: "alerting",
    title: "New Relic alerting and notification posture",
    summary: {
      region: config.region,
      ...accountScopeEvidence(data.accountScope),
      ...measured("policies", data.policies, policies.length),
      ...measured("enabled_conditions", data.conditions, enabledConditions.length),
      ...measured("reporting_alertable_entities", data.alertableEntities, reportingEntities.length),
      ...measured("uncovered_entities", data.alertableEntities, uncoveredEntities.length),
      ...measured("destinations", data.destinations, destinations.length),
      ...measured("personal_email_destinations", data.destinations, personalEmailDestinations.length),
      ...measured("enabled_workflows", data.workflows, enabledWorkflows.length),
      ...measured("enriched_external_workflows", routing, enrichedExternalWorkflows.length),
      ...measured("workloads", data.workloads, workloads.length),
      collection_errors: accountScopeErrors(data.accountScope, allCollected).length,
      coverage_limitations: coverage.length,
    },
    findings,
    errors: accountScopeErrors(data.accountScope, allCollected),
    coverage,
    coreData: {
      "core_data/alert_policies.json": coreDataFile(data.policies),
      "core_data/alert_nrql_conditions.json": coreDataFile(data.conditions),
      "core_data/notification_destinations.json": coreDataFile(data.destinations),
      "core_data/notification_channels.json": coreDataFile(data.channels),
      "core_data/workflows.json": coreDataFile(data.workflows),
      "core_data/alertable_entities.json": coreDataFile(data.alertableEntities),
      "core_data/workloads.json": coreDataFile(data.workloads),
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
  accountScope: AccountScope;
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

function isScriptedMonitor(monitor: JsonRecord): boolean {
  return SCRIPTED_MONITOR_TYPES.has((asString(monitor.monitorType) ?? "").toUpperCase());
}

const SYNTHETIC_SCRIPT_SOURCE = "synthetics.script";

/**
 * The script scan is computed from the monitor listing, so it inherits that listing's state: when the listing was
 * unreadable or never collected no script was fetched and the scan is recorded as not collected, naming
 * `entitySearch.syntheticMonitors`; a partly readable or truncated listing makes the scan partial or truncated too.
 */
async function collectSyntheticScripts(
  client: Pick<NewrelicClientSurface, "getSyntheticScript">,
  monitors: Collected<JsonRecord[]>,
  limit: number,
): Promise<Collected<JsonRecord[]>> {
  if (!isReadable(monitors)) {
    return {
      data: [],
      source: SYNTHETIC_SCRIPT_SOURCE,
      notCollected: `${SYNTHETIC_SCRIPT_SOURCE} was not queried for any monitor: ${upstreamUnavailable(monitors)}`,
    };
  }
  const scan = await collectList(SYNTHETIC_SCRIPT_SOURCE, SYNTHETIC_SCRIPT_SCAN_SHAPE, () => scanSyntheticScripts(client, monitors.data, limit));
  return isComplete(monitors) ? scan : { ...scan, derivedFrom: monitors };
}

async function scanSyntheticScripts(
  client: Pick<NewrelicClientSurface, "getSyntheticScript">,
  monitors: JsonRecord[],
  limit: number,
): Promise<PagedList> {
  const scripted = monitors.filter(isScriptedMonitor);
  const sampled = scripted.slice(0, limit);
  const snapshots: JsonRecord[] = [];
  const failures: string[] = [];
  for (const monitor of sampled) {
    const guid = asString(monitor.guid);
    const accountId = asNumber(monitor.accountId) ?? asNumber(monitor.queriedAccountId);
    const label = asString(monitor.name) ?? guid ?? "monitor";
    if (!guid || accountId === undefined) {
      failures.push(`${label}: monitor exposed no guid or account id`);
      continue;
    }
    try {
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
    } catch (error) {
      failures.push(`${label}: ${errorMessage(error)}`);
    }
  }
  if (sampled.length > 0 && failures.length >= sampled.length) throw new Error(failures.join("; "));
  return {
    items: snapshots,
    complete: scripted.length <= limit,
    totalCount: scripted.length,
    note: scripted.length > limit ? `only ${sampled.length} of ${scripted.length} scripted monitors were sampled (script_sample_limit ${limit})` : undefined,
    failures: failures.length > 0 ? failures : undefined,
  };
}

export async function collectNewrelicDataGovernanceData(
  client: DataGovernanceClient,
  options: { entityLimit?: number; scriptSampleLimit?: number } = {},
): Promise<NewrelicDataGovernanceData> {
  const entityLimit = clampNumber(options.entityLimit, DEFAULT_ENTITY_LIMIT, 1, 20_000);
  const scriptSampleLimit = clampNumber(options.scriptSampleLimit, DEFAULT_SCRIPT_SAMPLE_LIMIT, 0, 500);
  const accountScope = await resolveAccountScope(client);

  const retentionRules = await collectList("dataManagement.eventRetentionRules", RETENTION_RULE_SHAPE, () => collectPerAccount(accountScope, (id) => client.listEventRetentionRules(id)));
  const retentionNamespaces = await collectList("dataManagement.customizableRetention", RETENTION_NAMESPACE_SHAPE, () => collectPerAccount(accountScope, (id) => client.listRetentionNamespaces(id)));
  const obfuscationRules = await collectList("logConfigurations.obfuscationRules", OBFUSCATION_RULE_SHAPE, () => collectPerAccount(accountScope, (id) => client.listObfuscationRules(id)));
  const obfuscationExpressions = await collectList("logConfigurations.obfuscationExpressions", OBFUSCATION_EXPRESSION_SHAPE, () => collectPerAccount(accountScope, (id) => client.listObfuscationExpressions(id)));
  const cloudRules = await collectList("entityManagement.pipelineCloudRules", PIPELINE_CLOUD_RULE_SHAPE, () => client.listPipelineCloudRules());
  const dropRules = await collectList("nrqlDropRules.list", NRQL_DROP_RULE_SHAPE, () => collectPerAccount(accountScope, (id) => client.listNrqlDropRules(id)));
  const dashboards = await collectList(
    "entitySearch.dashboards",
    ENTITY_SHAPE,
    () => collectPerAccount(accountScope, (id) => client.searchEntities(`type = 'DASHBOARD' AND accountId = ${id}`, entityLimit)),
  );
  const dashboardLiveUrls = await collectList("dashboard.liveUrls", LIVE_URL_SHAPE, () => client.listDashboardLiveUrls());
  const syntheticMonitors = await collectList(
    "entitySearch.syntheticMonitors",
    ENTITY_SHAPE,
    () => collectPerAccount(accountScope, (id) => client.searchEntities(`domain = 'SYNTH' AND type = 'MONITOR' AND accountId = ${id}`, entityLimit)),
  );
  const secureCredentials = await collectList(
    "entitySearch.secureCredentials",
    ENTITY_SHAPE,
    () => collectPerAccount(accountScope, (id) => client.searchEntities(`domain = 'SYNTH' AND type = 'SECURE_CRED' AND accountId = ${id}`, entityLimit)),
  );
  const syntheticScripts = await collectSyntheticScripts(client, syntheticMonitors, scriptSampleLimit);
  const logVolume = await collectList(
    "nrql.Log.volume",
    LOG_VOLUME_SHAPE,
    () => runNrqlAcrossAccounts(client, accountScope, "SELECT count(*) AS logCount FROM Log SINCE 1 day ago"),
  );
  const logSecretMatches = await collectList(
    "nrql.Log.secret_patterns",
    LOG_SECRET_MATCH_SHAPE,
    () => runNrqlAcrossAccounts(client, accountScope, `SELECT count(*) AS matchCount FROM Log WHERE message RLIKE r'${LOG_SECRET_NRQL_PATTERN}' SINCE 1 day ago`),
  );
  const infraHosts = await collectList(
    "entitySearch.infraHosts",
    INFRA_HOST_COUNT_SHAPE,
    () => collectScoped(
      accountScopes(accountScope),
      async (accountId) => {
        const count = await client.countEntities(`domain = 'INFRA' AND type = 'HOST' AND reporting = 'true' AND accountId = ${accountId}`);
        return [{ reportingHosts: count }];
      },
      (row, accountId) => ({ ...row, queriedAccountId: Number(accountId) }),
    ),
  );
  const infraAgentVersions = await collectList(
    "nrql.SystemSample.agentVersion",
    INFRA_AGENT_VERSION_SHAPE,
    () => runNrqlAcrossAccounts(client, accountScope, "SELECT uniqueCount(entityGuid) AS hosts FROM SystemSample FACET agentVersion SINCE 1 day ago LIMIT 50"),
  );

  return {
    accountScope,
    accountIds: accountScope.accountIds,
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

  const shortRetentionRules = retentionRules.filter((rule) => {
    const days = asNumber(rule.retentionInDays);
    return days !== undefined && days < minRetentionDays;
  });
  const rulesWithoutRetentionDays = retentionRules.filter((rule) => asNumber(rule.retentionInDays) === undefined);
  const ruledNamespaces = new Set(retentionRules.map((rule) => `${asNumber(rule.queriedAccountId) ?? ""}:${asString(rule.namespace) ?? ""}`));
  const namespacesWithoutRules = data.retentionNamespaces.data.filter((row) =>
    !ruledNamespaces.has(`${asNumber(row.queriedAccountId) ?? ""}:${asString(row.namespace) ?? ""}`),
  );
  const enabledObfuscationRules = obfuscationRules.filter((rule) => asBoolean(rule.enabled) === true);
  const obfuscationRulesWithoutEnabledFlag = obfuscationRules.filter((rule) => asBoolean(rule.enabled) === undefined);
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

  const scriptedMonitors = monitors.filter(isScriptedMonitor);
  const monitorsWithoutType = monitors.filter((monitor) => !asString(monitor.monitorType));
  const monitorTypeCounts: Record<string, number> = {};
  for (const monitor of monitors) {
    const type = asString(monitor.monitorType)?.toUpperCase() ?? "UNKNOWN";
    monitorTypeCounts[type] = (monitorTypeCounts[type] ?? 0) + 1;
  }
  const scriptsWithSecrets = scripts.filter((script) => asArray(script.secretIndicators).length > 0);
  const scriptsUsingSecureCredentials = scripts.filter((script) => asBoolean(script.usesSecureCredentials) === true);

  const publicReadWriteDashboards = dashboards.filter((dashboard) => (asString(dashboard.permissions) ?? "").toUpperCase() === "PUBLIC_READ_WRITE");
  const privateDashboards = dashboards.filter((dashboard) => (asString(dashboard.permissions) ?? "").toUpperCase() === "PRIVATE");
  const dashboardsWithoutPermissions = dashboards.filter((dashboard) => !asString(dashboard.permissions));
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

  const accountCount = data.accountIds.length;
  const retentionReadable = isReadable(data.retentionRules);
  const namespacesReadable = isReadable(data.retentionNamespaces);
  const obfuscationReadable = isReadable(data.obfuscationRules);
  const expressionsReadable = isReadable(data.obfuscationExpressions);
  const cloudRulesReadable = isReadable(data.cloudRules);
  const dropRulesReadable = isReadable(data.dropRules);
  const monitorsReadable = isReadable(data.syntheticMonitors);
  const scriptsReadable = isReadable(data.syntheticScripts);
  const secureCredentialsReadable = isReadable(data.secureCredentials);
  const dashboardsReadable = isReadable(data.dashboards);
  const liveUrlsReadable = isReadable(data.dashboardLiveUrls);
  const logVolumeReadable = isReadable(data.logVolume);
  const secretMatchesReadable = isReadable(data.logSecretMatches);
  const infraReadable = isReadable(data.infraHosts);

  const retentionCoverage = coverageNotes([["retention rules", data.retentionRules], ["retention namespaces", data.retentionNamespaces]]);
  const obfuscationCoverage = coverageNotes([["obfuscation rules", data.obfuscationRules], ["obfuscation expressions", data.obfuscationExpressions]]);
  const attributeDropCoverage = coverageNotes([["Pipeline Control cloud rules", data.cloudRules], ["NRQL drop rules", data.dropRules]]);
  const logVolumeCoverage = coverageNotes([["log volume", data.logVolume]]);
  const monitorCoverage = coverageNotes([["synthetic monitors", data.syntheticMonitors], ["secure credentials", data.secureCredentials], ["synthetic scripts", data.syntheticScripts]]);
  const dashboardCoverage = coverageNotes([["dashboards", data.dashboards], ["dashboard live URLs", data.dashboardLiveUrls]]);
  const logCoverage = [...logVolumeCoverage, ...coverageNotes([["log secret matches", data.logSecretMatches]])];
  const infraCoverage = coverageNotes([["infrastructure hosts", data.infraHosts], ["agent versions", data.infraAgentVersions]]);
  const retentionEvidence = "the retention per data type from Administration > Data management > Data retention for every account.";
  const obfuscationEvidence = "the rules and expressions shown in Logs > Obfuscation for every account.";
  const scriptEvidence = "each scripted monitor's script from Synthetic monitoring, confirming credentials come from secure credentials ($secure.NAME).";
  const dashboardEvidence = "dashboard permissions and public sharing links from the Dashboards UI.";
  // Attribute-level drop coverage joins two inventories. A count is stated only when both were readable; otherwise the
  // clause names the unreadable dataset and query path, and the coverage list limits the finding below pass. A 403 on
  // entityManagement.pipelineCloudRules cannot be told apart from a missing Pipeline Control entitlement, so it is
  // reported as unverified rather than treated as "no rules".
  const attributeDropClause = (): string => {
    const unreadable = [
      ...(cloudRulesReadable ? [] : ["Pipeline Control cloud rules (entityManagement.pipelineCloudRules)"]),
      ...(dropRulesReadable ? [] : ["NRQL drop rules (nrqlDropRules.list)"]),
    ];
    if (unreadable.length > 0) return `attribute drop coverage is unverified because ${unreadable.join(" and ")} were not readable`;
    return `${attributeDropRules.length} pipeline or drop rules also drop sensitive attributes (${cloudRules.length} Pipeline Control cloud rules, ${dropRules.length} NRQL drop rules${hasUnreadableScope(data.dropRules) ? " in the readable accounts" : ""})`;
  };
  const logVolumeClause = logVolumeReadable && logCount > 0
    ? ` while ${logCount} log events were ingested in the last day${isComplete(data.logVolume) ? "" : " in the readable accounts"}`
    : "";

  const control11 = (): Verdict => {
    if (!retentionReadable) return unreadableVerdict("Data retention rules (dataManagement.eventRetentionRules)", data.retentionRules, retentionEvidence);
    if (shortRetentionRules.length > 0) return verdict("fail", `${shortRetentionRules.length}/${retentionRules.length} active retention rules keep data for less than ${minRetentionDays} days.`);
    if (retentionRules.length === 0) {
      if (hasUnreadableScope(data.retentionRules)) return unknownEmptyVerdict("Data retention rules (dataManagement.eventRetentionRules)", data.retentionRules, retentionEvidence);
      const namespaceScope = namespacesReadable && data.retentionNamespaces.data.length > 0
        ? `all ${data.retentionNamespaces.data.length} customizable namespaces`
        : "every customizable namespace";
      return manualVerdict(`No active custom retention rules exist across ${accountCount} accounts, so New Relic default retention applies to ${namespaceScope} and the API does not expose default values; emptiness is unknown rather than compliant. Confirm in Administration > Data management > Data retention that each namespace meets ${minRetentionDays} days.`);
    }
    if (rulesWithoutRetentionDays.length > 0) {
      return verdict("warn", `${rulesWithoutRetentionDays.length}/${retentionRules.length} active retention rules expose no retentionInDays value and cannot be counted as compliant; the remaining rules keep data for at least ${minRetentionDays} days.`);
    }
    if (!namespacesReadable) {
      return verdict("warn", `All ${retentionRules.length} active retention rules keep data for at least ${minRetentionDays} days, but customizable namespaces were not readable (${causeOf(data.retentionNamespaces)}), so namespaces relying on unexposed default retention cannot be enumerated.`);
    }
    if (namespacesWithoutRules.length > 0) {
      return verdict("warn", `All ${retentionRules.length} active retention rules keep data for at least ${minRetentionDays} days, but ${namespacesWithoutRules.length}/${data.retentionNamespaces.data.length} customizable namespaces have no rule and rely on New Relic defaults that the API does not expose (${sample(namespacesWithoutRules.map((row) => asString(row.namespace) ?? "namespace"), 10).join(", ")}). Confirm those defaults meet ${minRetentionDays} days in the Data retention UI.`);
    }
    return verdict("pass", `All ${retentionRules.length} active retention rules keep data for at least ${minRetentionDays} days and every one of the ${data.retentionNamespaces.data.length} customizable namespaces has an explicit rule.`);
  };

  const control12 = (): Verdict => {
    if (!obfuscationReadable) return unreadableVerdict("Log obfuscation rules (logConfigurations.obfuscationRules)", data.obfuscationRules, obfuscationEvidence);
    if (enabledObfuscationRules.length === 0) {
      if (obfuscationRules.length === 0 && hasUnreadableScope(data.obfuscationRules)) return unknownEmptyVerdict("Log obfuscation rules (logConfigurations.obfuscationRules)", data.obfuscationRules, obfuscationEvidence);
      if (obfuscationRules.length === 0 && logVolumeReadable && isComplete(data.logVolume) && logCount === 0) {
        return manualVerdict(`No log obfuscation rules exist and no log events were ingested in the last day across ${accountCount} accounts, so the control is not applicable through the API while logging stays disabled; emptiness is unknown rather than compliant. Confirm log ingestion is intentionally disabled and collect ${obfuscationEvidence}`);
      }
      return verdict("fail", `No obfuscation rule with enabled = true exists across ${accountCount} accounts (${obfuscationRules.length} rules returned, ${obfuscationRulesWithoutEnabledFlag.length} without an enabled flag)${logVolumeClause}.`);
    }
    if (!expressionsReadable) {
      return verdict("warn", `${enabledObfuscationRules.length} enabled obfuscation rules exist, but obfuscation expressions were not readable (${causeOf(data.obfuscationExpressions)}), so credential and PII coverage cannot be confirmed.`);
    }
    if (!credentialCoverage || !piiCoverage) {
      return verdict("warn", `${enabledObfuscationRules.length} enabled obfuscation rules exist, but the ${obfuscationExpressions.length} expressions do not clearly cover ${!credentialCoverage ? "credentials or tokens" : "PII"}.`);
    }
    if (obfuscationRulesWithoutEnabledFlag.length > 0) {
      return verdict("warn", `${enabledObfuscationRules.length} enabled obfuscation rules cover credential and PII patterns, but ${obfuscationRulesWithoutEnabledFlag.length} rules expose no enabled flag and were not counted as active.`);
    }
    return verdict("pass", `${enabledObfuscationRules.length} enabled obfuscation rules and ${obfuscationExpressions.length} expressions cover credential and PII patterns; ${attributeDropClause()}.`);
  };

  const control13 = (): Verdict => {
    if (!monitorsReadable) return unreadableVerdict("Synthetic monitors (entitySearch)", data.syntheticMonitors, scriptEvidence);
    if (scriptsWithSecrets.length > 0) {
      return verdict("fail", `${scriptsWithSecrets.length}/${scripts.length} sampled scripted monitors contain hardcoded credential patterns (${[...new Set(scriptsWithSecrets.flatMap((script) => asArray(script.secretIndicators).map(String)))].join(", ")}).`);
    }
    if (monitors.length === 0) {
      if (hasUnreadableScope(data.syntheticMonitors)) return unknownEmptyVerdict("Synthetic monitors (entitySearch)", data.syntheticMonitors, scriptEvidence);
      return manualVerdict(`Not applicable through the API: entitySearch returned zero synthetic monitors across ${accountCount} accounts, so there are no scripts to review; emptiness is unknown rather than compliant. Confirm in Synthetic monitoring that no monitors exist.`);
    }
    if (scriptedMonitors.length === 0 && monitorsWithoutType.length > 0) {
      return manualVerdict(`${monitorsWithoutType.length}/${monitors.length} synthetic monitors exposed no monitorType, so scripted monitors cannot be identified. Collect ${scriptEvidence}`);
    }
    if (scriptedMonitors.length === 0) {
      if (hasUnreadableScope(data.syntheticMonitors)) {
        return manualVerdict(`None of the ${monitors.length} synthetic monitors in the readable accounts is scripted, but another account's monitor listing was unreadable (${partialCause(data.syntheticMonitors)}), so scripted monitors cannot be ruled out. Collect ${scriptEvidence}`);
      }
      return manualVerdict(`Not applicable through the API: none of the ${monitors.length} synthetic monitors is scripted (${Object.entries(monitorTypeCounts).map(([type, count]) => `${type}: ${count}`).join(", ")}), so there are no scripts to review. Confirm in Synthetic monitoring that no scripted monitors exist.`);
    }
    if (!scriptsReadable) return manualVerdict(`${scriptedMonitors.length} scripted monitors exist but their scripts were not readable (${causeOf(data.syntheticScripts)}). Collect ${scriptEvidence}`);
    if (scripts.length === 0) {
      if (hasUnreadableScope(data.syntheticScripts)) return unknownEmptyVerdict("Synthetic scripts (synthetics.script)", data.syntheticScripts, scriptEvidence);
      return manualVerdict(`${scriptedMonitors.length} scripted monitors exist but zero scripts were sampled, so credential handling is unknown. Collect ${scriptEvidence}`);
    }
    if (hasUnreadableScope(data.syntheticScripts)) {
      return verdict("warn", `${scripts.length} scripted monitor scripts were scanned without hardcoded credential patterns, but the scan is partial (${partialCause(data.syntheticScripts)}), so the unscanned scripts cannot be counted as clean.`);
    }
    if (!isComplete(data.syntheticScripts)) {
      return verdict("warn", `${scripts.length} of ${scriptedMonitors.length} scripted monitors were sampled and none contains hardcoded credential patterns, but the unsampled scripts cannot be counted as clean.`);
    }
    if (!secureCredentialsReadable) {
      return verdict("warn", `All ${scripts.length} scripted monitor scripts were scanned without hardcoded credential patterns, but secure credentials were not readable (${causeOf(data.secureCredentials)}), so credential storage cannot be confirmed.`);
    }
    if (scriptsUsingSecureCredentials.length === 0 && secureCredentials.length === 0) {
      return verdict("warn", `All ${scripts.length} scripted monitor scripts were scanned without obvious hardcoded secrets, but no secure credentials exist and no script references $secure.*, so credential handling should be confirmed.`);
    }
    if (monitorsWithoutType.length > 0) {
      return verdict("warn", `All ${scripts.length} scripted monitor scripts were scanned without hardcoded credential patterns, but ${monitorsWithoutType.length} monitors exposed no monitorType and could not be classified.`);
    }
    return verdict("pass", `All ${scripts.length} scripted monitor scripts were scanned and contain no hardcoded credential patterns; ${scriptsUsingSecureCredentials.length} reference secure credentials and ${secureCredentials.length} secure credentials are stored.`);
  };

  const control14 = (): Verdict => {
    if (!dashboardsReadable) return unreadableVerdict("Dashboards (entitySearch)", data.dashboards, dashboardEvidence);
    if (liveUrls.length > 0) {
      return verdict("fail", `${dashboardLiveUrls.length} dashboards and ${widgetLiveUrls.length} widgets are shared through public live URLs that anyone with the link can open; ${publicReadWriteDashboards.length}/${dashboards.length} dashboards also allow every account user to edit.`);
    }
    if (!liveUrlsReadable) {
      return manualVerdict(`${dashboards.length} dashboards were inventoried (${publicReadWriteDashboards.length} PUBLIC_READ_WRITE), but the public live URL listing failed (${causeOf(data.dashboardLiveUrls)}), so public sharing cannot be ruled out. Collect ${dashboardEvidence}`);
    }
    if (dashboards.length === 0) {
      if (hasUnreadableScope(data.dashboards)) return unknownEmptyVerdict("Dashboards (entitySearch)", data.dashboards, dashboardEvidence);
      return manualVerdict(`Not applicable through the API: entitySearch returned zero dashboards across ${accountCount} accounts and no public live URLs are visible to this user; emptiness is unknown rather than compliant. Confirm in the Dashboards UI that no dashboards exist.`);
    }
    if (publicReadWriteDashboards.length > 0) {
      return verdict("warn", `${publicReadWriteDashboards.length}/${dashboards.length} dashboards grant edit access to everyone in the account (PUBLIC_READ_WRITE) and no public live URLs are visible to this user.`);
    }
    if (dashboardsWithoutPermissions.length > 0) {
      return verdict("warn", `${dashboardsWithoutPermissions.length}/${dashboards.length} dashboards exposed no permissions value and cannot be counted as restricted; no public live URLs are visible to this user.`);
    }
    return verdict("pass", `${dashboards.length} dashboards use read-only or private permissions and no public live URLs are visible to this user.`);
  };

  const control15 = (): Verdict => {
    if (!secretMatchesReadable) return unreadableVerdict("Log secret pattern query (NRQL over Log)", data.logSecretMatches, "a NRQL search over Log for password, token, API key, and private key patterns in every account.");
    if (secretMatchCount > 0) return verdict("fail", `${secretMatchCount} log messages in the last day matched credential or token patterns across ${accountCount} accounts.`);
    if (!logVolumeReadable) {
      return manualVerdict(`No log messages matched credential patterns, but the log volume query failed (${causeOf(data.logVolume)}), so it is unknown whether any logs were available to evaluate. Collect a NRQL count over Log for the last day in every account.`);
    }
    if (logCount === 0) {
      if (hasUnreadableScope(data.logVolume)) {
        return manualVerdict(`The readable accounts ingested no log events in the last day while another account's log volume was unreadable (${partialCause(data.logVolume)}), so plaintext secret exposure could not be evaluated and the volume is unknown rather than zero. Confirm whether logs are forwarded to New Relic.`);
      }
      return manualVerdict(`No log events were ingested in the last day across ${accountCount} accounts, so plaintext secret exposure could not be evaluated; emptiness is unknown rather than compliant. Confirm whether logs are forwarded to New Relic.`);
    }
    return verdict("pass", `${logCount} log events in the last day contained no messages matching credential or token patterns.`);
  };

  const control16 = (): Verdict => {
    if (!infraReadable) {
      return manualVerdict(`Infrastructure host counts were ${unavailableDetail(data.infraHosts)}. Agent transport settings are not exposed by the API: collect newrelic-infra.yml from a representative host and confirm HTTPS endpoints, proxy_validate_certificates, and ca_bundle settings, and that the agent version is current.`);
    }
    if (reportingHosts === 0 && hasUnreadableScope(data.infraHosts)) {
      return manualVerdict(`The readable accounts report no infrastructure hosts while another account's host count was unreadable (${partialCause(data.infraHosts)}), so the host population is unknown. If infrastructure agents are deployed, collect newrelic-infra.yml from a representative host and confirm TLS and proxy settings.`);
    }
    return manualVerdict(reportingHosts > 0
      ? `${reportingHosts} infrastructure hosts are reporting across ${agentVersions.length} agent versions${isReadable(data.infraAgentVersions) ? "" : ` (agent versions ${unavailableDetail(data.infraAgentVersions)})`}. Agent transport settings are not exposed by the API: collect newrelic-infra.yml from a representative host per version and confirm HTTPS endpoints, proxy_validate_certificates, and ca_bundle settings, and that the agent version is current.`
      : "No reporting infrastructure hosts were found. If infrastructure agents are deployed, collect newrelic-infra.yml from a representative host and confirm TLS and proxy settings.");
  };

  const findings: NewrelicFinding[] = [];

  const retention = [data.retentionRules, data.retentionNamespaces];
  findings.push(finding(11, limitCoverage(control11(), retentionCoverage), {
    min_retention_days: minRetentionDays,
    ...measured("active_rules", data.retentionRules, sample(retentionRules.map((rule) => `${asString(rule.namespace) ?? "namespace"}: ${asNumber(rule.retentionInDays) ?? "?"} days`), 50)),
    ...measured("short_retention_rules", data.retentionRules, sample(shortRetentionRules.map((rule) => `${asString(rule.namespace) ?? "namespace"}: ${asNumber(rule.retentionInDays) ?? "?"} days`))),
    ...measured("rules_without_retention_days", data.retentionRules, rulesWithoutRetentionDays.length),
    ...measured("customizable_namespaces", data.retentionNamespaces, data.retentionNamespaces.data.length),
    ...measured("namespaces_without_rules", retention, sample(namespacesWithoutRules.map((row) => asString(row.namespace) ?? "namespace"), 50)),
  }));

  // NR-12 joins obfuscation rules and expressions with Pipeline Control cloud rules, NRQL drop rules, and the log
  // volume query, so all five inventories are in its coverage and each count is null with its status when any
  // inventory it rests on was unreadable, never collected, or only partly readable. The attribute drop total is
  // derived from two inventories and carries a status merged from both.
  const obfuscation = [data.obfuscationRules, data.obfuscationExpressions];
  const attributeDrop = [data.cloudRules, data.dropRules];
  findings.push(finding(12, limitCoverage(control12(), [...obfuscationCoverage, ...attributeDropCoverage, ...logVolumeCoverage]), {
    ...measured("obfuscation_rules", data.obfuscationRules, obfuscationRules.length),
    ...measured("enabled_obfuscation_rules", data.obfuscationRules, enabledObfuscationRules.length),
    ...measured("obfuscation_rules_without_enabled_flag", data.obfuscationRules, obfuscationRulesWithoutEnabledFlag.length),
    ...measured("obfuscation_expressions", data.obfuscationExpressions, sample(obfuscationExpressions.map((expression) => asString(expression.name) ?? "expression"))),
    ...measured("credential_coverage", obfuscation, credentialCoverage),
    ...measured("pii_coverage", obfuscation, piiCoverage),
    ...measured("log_events_last_day", data.logVolume, logCount),
    ...measured("pipeline_cloud_rules", data.cloudRules, cloudRules.length),
    ...measured("legacy_drop_rules", data.dropRules, dropRules.length),
    ...measured("attribute_drop_rules", attributeDrop, attributeDropRules.length),
  }));

  findings.push(finding(13, limitCoverage(control13(), monitorCoverage), {
    ...measured("monitors", data.syntheticMonitors, monitors.length),
    ...measured("monitor_types", data.syntheticMonitors, monitorTypeCounts),
    ...measured("monitors_without_type", data.syntheticMonitors, monitorsWithoutType.length),
    ...measured("scripted_monitors", data.syntheticMonitors, scriptedMonitors.length),
    ...measured("scripts_sampled", data.syntheticScripts, scripts.length),
    // The sample flag is null, not false, when the scan was never issued or lost a monitor, since its status says why.
    scripts_sample_complete: unlessUnreadable(data.syntheticScripts, isComplete(data.syntheticScripts)),
    scripts_status: collectionStatus(data.syntheticScripts),
    ...measured("scripts_with_secret_indicators", data.syntheticScripts, sample(scriptsWithSecrets.map((script) => `${asString(script.name) ?? asString(script.guid)}: ${asArray(script.secretIndicators).join(", ")}`))),
    ...measured("scripts_using_secure_credentials", data.syntheticScripts, scriptsUsingSecureCredentials.length),
    ...measured("secure_credentials", data.secureCredentials, secureCredentials.length),
  }));

  findings.push(finding(14, limitCoverage(control14(), dashboardCoverage), {
    ...measured("dashboards", data.dashboards, dashboards.length),
    dashboards_reported_total: data.dashboards.total ?? null,
    ...measured("public_read_write_dashboards", data.dashboards, sample(publicReadWriteDashboards.map((dashboard) => asString(dashboard.name) ?? "dashboard"))),
    ...measured("private_dashboards", data.dashboards, privateDashboards.length),
    ...measured("dashboards_without_permissions", data.dashboards, dashboardsWithoutPermissions.length),
    ...measured("public_live_urls", data.dashboardLiveUrls, liveUrls.length),
    live_urls_readable: liveUrlsReadable,
    ...measured("public_dashboard_live_urls", data.dashboardLiveUrls, sample(dashboardLiveUrls.map((liveUrl) => liveUrl.title || "untitled dashboard"))),
    ...measured("public_widget_live_urls", data.dashboardLiveUrls, widgetLiveUrls.length),
    live_url_visibility_note: "liveUrls only lists public links visible to the authenticated user; link values are intentionally not collected.",
  }));

  findings.push(finding(15, limitCoverage(control15(), logCoverage), {
    ...measured("log_events_last_day", data.logVolume, logCount),
    log_volume_readable: logVolumeReadable,
    ...measured("secret_pattern_matches", data.logSecretMatches, secretMatchCount),
    nrql_pattern: LOG_SECRET_NRQL_PATTERN,
  }));

  findings.push(finding(16, limitCoverage(control16(), infraCoverage), {
    ...measured("reporting_hosts", data.infraHosts, reportingHosts),
    ...measured("agent_versions", data.infraAgentVersions, sample(agentVersions, 50)),
    manual_evidence: "newrelic-infra.yml (or fleet configuration) showing proxy, proxy_validate_certificates, ca_bundle_file, and agent version for each host group.",
  }));

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
  const coverage = [
    ...retentionCoverage,
    ...obfuscationCoverage,
    ...attributeDropCoverage,
    ...dashboardCoverage,
    ...monitorCoverage,
    ...logCoverage,
    ...infraCoverage,
  ];

  return {
    category: "data_governance",
    title: "New Relic data governance and telemetry security",
    summary: {
      region: config.region,
      ...accountScopeEvidence(data.accountScope),
      ...measured("retention_rules", data.retentionRules, retentionRules.length),
      ...measured("short_retention_rules", data.retentionRules, shortRetentionRules.length),
      ...measured("enabled_obfuscation_rules", data.obfuscationRules, enabledObfuscationRules.length),
      ...measured("pipeline_cloud_rules", data.cloudRules, cloudRules.length),
      ...measured("legacy_drop_rules", data.dropRules, dropRules.length),
      ...measured("attribute_drop_rules", attributeDrop, attributeDropRules.length),
      ...measured("scripted_monitors", data.syntheticMonitors, scriptedMonitors.length),
      ...measured("scripts_with_secret_indicators", data.syntheticScripts, scriptsWithSecrets.length),
      ...measured("dashboards", data.dashboards, dashboards.length),
      ...measured("public_live_urls", data.dashboardLiveUrls, liveUrls.length),
      ...measured("log_events_last_day", data.logVolume, logCount),
      ...measured("log_secret_pattern_matches", data.logSecretMatches, secretMatchCount),
      ...measured("reporting_hosts", data.infraHosts, reportingHosts),
      collection_errors: accountScopeErrors(data.accountScope, allCollected).length,
      coverage_limitations: coverage.length,
    },
    findings,
    errors: accountScopeErrors(data.accountScope, allCollected),
    coverage,
    coreData: {
      "core_data/retention_rules.json": coreDataFile(data.retentionRules),
      "core_data/retention_namespaces.json": coreDataFile(data.retentionNamespaces),
      "core_data/obfuscation_rules.json": coreDataFile(data.obfuscationRules),
      "core_data/obfuscation_expressions.json": coreDataFile(data.obfuscationExpressions),
      "core_data/pipeline_cloud_rules.json": coreDataFile(data.cloudRules),
      "core_data/nrql_drop_rules.json": coreDataFile(data.dropRules),
      "core_data/dashboards.json": coreDataFile(data.dashboards),
      "core_data/dashboard_live_urls.json": coreDataFile(data.dashboardLiveUrls, liveUrlSnapshots),
      "core_data/synthetic_monitors.json": coreDataFile(data.syntheticMonitors),
      "core_data/secure_credentials.json": coreDataFile(data.secureCredentials),
      "core_data/synthetic_script_scan.json": coreDataFile(data.syntheticScripts),
      "core_data/log_secret_scan.json": { volume: coreDataFile(data.logVolume), matches: coreDataFile(data.logSecretMatches) },
      "core_data/infrastructure_hosts.json": { hosts: coreDataFile(data.infraHosts), agentVersions: coreDataFile(data.infraAgentVersions) },
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
  if (result.coverage.length > 0) {
    lines.push("", "Coverage limitations (verdicts capped at warn or manual):", ...result.coverage.map((note) => `- ${note}`));
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
  const coverage = [...new Set(assessments.flatMap((assessment) => assessment.coverage))];
  if (coverage.length > 0) {
    lines.push("", "## Coverage Limitations", "", "Verdicts affected by these limits were capped at warn or manual instead of pass.", "");
    for (const note of coverage) {
      lines.push(`- ${note}`);
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
    "- `core_data/` contains the NerdGraph and REST API v2 records used during this assessment, projected to the fields each query selects (API key values are never requested; notification destination property values are stored only for the email key).",
    "- Drop-rule and pipeline-rule NRQL, obfuscation rule filters, and obfuscation expression regexes are stored verbatim as evidence and may quote literals from your configuration.",
    "- `analysis/` contains normalized findings and per-category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail, or are skipped because the account or domain list they iterate was unavailable, while the bundle still completes.",
    "- A `core_data/` file whose query failed, was skipped, or lost a scope is written as `{ status, records }` (records null when nothing was read) rather than as an empty list.",
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
      coverage: assessment.coverage,
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
