/**
 * KnowBe4 security awareness program audit tools for grclanker.
 *
 * Read-only inspection of KMSAT phishing, training, user, and account data
 * through the KnowBe4 Reporting API, with optional PhishER GraphQL enrichment.
 * Every finding maps to one of the twenty numbered controls in
 * specs/knowbe4-sec-inspector.spec.md.
 */
import { createHash } from "node:crypto";
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
import { parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type SleepImpl = (ms: number) => Promise<void>;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/knowbe4";
const DEFAULT_CONFIG_FILE = join(".knowbe4-inspector", "config.yaml");
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_SIZE = 500;
const TRAINING_CAMPAIGN_PAGE_SIZE = 10;
const PHISHER_PAGE_SIZE = 200;
const MIN_REQUEST_INTERVAL_MS = 250;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_MS = 1_000;
const MAX_RETRY_DELAY_MS = 60_000;
const DEFAULT_USER_LIMIT = 5_000;
const DEFAULT_ENROLLMENT_LIMIT = 20_000;
const DEFAULT_LIST_LIMIT = 20_000;
const DEFAULT_SECURITY_TEST_SAMPLE_LIMIT = 12;
const DEFAULT_PHISHER_MESSAGE_LIMIT = 1_000;
const DEFAULT_LOOKBACK_DAYS = 90;
const DEFAULT_TRAINING_LOOKBACK_DAYS = 365;
const DEFAULT_MAX_CAMPAIGN_GAP_DAYS = 30;
const DEFAULT_MAX_SCHEDULE_GAP_DAYS = 45;
const DEFAULT_MIN_COVERAGE_PCT = 90;
const DEFAULT_MIN_COMPLETION_PCT = 90;
const DEFAULT_FAIL_COMPLETION_PCT = 80;
const DEFAULT_ENROLLMENT_GRACE_DAYS = 30;
const DEFAULT_REMEDIAL_WINDOW_DAYS = 14;
const DEFAULT_MAX_CONTENT_AGE_DAYS = 365;
const DEFAULT_MAX_PHISH_PRONE_PCT = 15;
const DEFAULT_MIN_REPORT_RATE_PCT = 50;
const DEFAULT_MAX_MEAN_RISK_SCORE = 50;
const DEFAULT_MAX_RISK_STDDEV = 25;
const DEFAULT_INACTIVE_DAYS = 180;
const DEFAULT_MAX_ADMIN_COUNT = 3;
const TREND_FAIL_DELTA_PCT = 2;
const TREND_WARN_DELTA_PCT = 0.5;
const MIN_TREND_TESTS = 4;
const SAMPLE_SIZE = 25;
const DAY_MS = 86_400_000;

export type Knowbe4Region = "us" | "eu" | "ca" | "uk" | "de";
export type Knowbe4Scope = "phishing" | "training" | "risk" | "governance";
export type Knowbe4FrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis_v8"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap";

const KNOWBE4_REGIONS: readonly Knowbe4Region[] = ["us", "eu", "ca", "uk", "de"];

const REPORTING_BASE_URLS: Record<Knowbe4Region, string> = {
  us: "https://us.api.knowbe4.com",
  eu: "https://eu.api.knowbe4.com",
  ca: "https://ca.api.knowbe4.com",
  uk: "https://uk.api.knowbe4.com",
  de: "https://de.api.knowbe4.com",
};

const PHISHER_GRAPHQL_URLS: Record<Knowbe4Region, string> = {
  us: "https://training.knowbe4.com/graphql",
  eu: "https://eu.knowbe4.com/graphql",
  ca: "https://ca.knowbe4.com/graphql",
  uk: "https://uk.knowbe4.com/graphql",
  de: "https://de.knowbe4.com/graphql",
};

const FRAMEWORK_LABELS: Record<Knowbe4FrameworkKey, string> = {
  fedramp: "FedRAMP",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis_v8: "CIS Controls v8",
  pci_dss: "PCI-DSS",
  disa_stig: "DISA STIG",
  irap: "IRAP",
  ismap: "ISMAP",
};

const FRAMEWORK_KEYS: readonly Knowbe4FrameworkKey[] = [
  "fedramp",
  "cmmc",
  "soc2",
  "cis_v8",
  "pci_dss",
  "disa_stig",
  "irap",
  "ismap",
];

export interface Knowbe4ControlDefinition {
  number: number;
  title: string;
  area: Knowbe4Scope;
  frameworks: Record<Knowbe4FrameworkKey, string>;
}

function controlDefinition(
  number: number,
  title: string,
  area: Knowbe4Scope,
  mappings: [string, string, string, string, string, string, string, string],
): Knowbe4ControlDefinition {
  const [fedramp, cmmc, soc2, cisV8, pciDss, disaStig, irap, ismap] = mappings;
  return {
    number,
    title,
    area,
    frameworks: { fedramp, cmmc, soc2, cis_v8: cisV8, pci_dss: pciDss, disa_stig: disaStig, irap, ismap },
  };
}

export const KNOWBE4_CONTROLS: readonly Knowbe4ControlDefinition[] = [
  controlDefinition(1, "Phishing simulation frequency", "phishing", ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"]),
  controlDefinition(2, "Phishing simulation coverage", "phishing", ["AT-2(1)", "L2 3.2.2", "CC1.4", "14.2", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"]),
  controlDefinition(3, "Training completion rates", "training", ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"]),
  controlDefinition(4, "Training enrollment timeliness", "training", ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"]),
  controlDefinition(5, "User risk score distribution", "risk", ["RA-3", "L2 3.11.1", "CC3.2", "14.4", "12.6.2", "SRG-APP-000516", "ISM-0253", "RA-01"]),
  controlDefinition(6, "Phish-prone percentage tracking", "phishing", ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"]),
  controlDefinition(7, "Phishing failure rate trending", "phishing", ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"]),
  controlDefinition(8, "Group coverage analysis", "risk", ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-01"]),
  controlDefinition(9, "Campaign targeting completeness", "phishing", ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"]),
  controlDefinition(10, "Remedial training triggers", "training", ["AT-2(2)", "L2 3.2.3", "CC1.4", "14.3", "12.6.3", "SRG-APP-000516", "ISM-0253", "HR-04"]),
  controlDefinition(11, "Training content currency", "training", ["AT-3", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"]),
  controlDefinition(12, "Admin role audit", "governance", ["AC-6(5)", "L2 3.1.5", "CC6.3", "5.4", "7.2.2", "SRG-APP-000340", "ISM-0432", "AC-01"]),
  controlDefinition(13, "SSO integration status", "governance", ["IA-2(1)", "L2 3.5.3", "CC6.1", "6.5", "8.4.2", "SRG-APP-000149", "ISM-1401", "AM-01"]),
  controlDefinition(14, "Reporting frequency", "governance", ["CA-7", "L2 3.12.3", "CC7.2", "14.4", "12.6.2", "SRG-APP-000516", "ISM-0253", "SO-01"]),
  controlDefinition(15, "USB test campaign execution", "governance", ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-05"]),
  controlDefinition(16, "Vishing campaign execution", "governance", ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-05"]),
  controlDefinition(17, "Compliance training modules", "training", ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-06"]),
  controlDefinition(18, "Inactive user cleanup", "risk", ["AC-2(3)", "L2 3.1.1", "CC6.2", "5.3", "8.1.4", "SRG-APP-000025", "ISM-1648", "AC-02"]),
  controlDefinition(19, "Phishing report rate", "phishing", ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"]),
  controlDefinition(20, "Campaign scheduling regularity", "phishing", ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"]),
];

export interface Knowbe4ResolvedConfig {
  apiToken: string;
  region: Knowbe4Region;
  baseUrl: string;
  phisherApiToken?: string;
  phisherGraphqlUrl: string;
  timeoutMs: number;
  redactPii: boolean;
  configFile: string;
  sourceChain: string[];
}

export interface Knowbe4AccessSurface {
  name: string;
  /** The request the probe made; null when the surface was not configured and no request was made. */
  endpoint: string | null;
  status: "readable" | "not_readable" | "not_configured";
  /** Whether the probe completed; false for a denied, failed, or unconfigured surface. */
  collected: boolean;
  /** The HTTP status the failing probe observed; null when the probe succeeded or observed no response. */
  http_status: number | null;
  /** The count the probe established; null when it counted nothing or did not complete. */
  count: number | null;
  error?: string;
}

export interface Knowbe4AccessCheckResult {
  status: "healthy" | "limited";
  region: Knowbe4Region;
  baseUrl: string;
  accountName?: string;
  subscriptionLevel?: string;
  surfaces: Knowbe4AccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface Knowbe4Finding {
  id: string;
  control: number;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  manualEvidence?: string;
}

export interface Knowbe4AssessmentResult {
  area: Knowbe4Scope;
  title: string;
  summary: JsonRecord;
  findings: Knowbe4Finding[];
  errors: string[];
}

export interface Knowbe4Collected<T> {
  data: T;
  collected: boolean;
  error?: string;
  /** The HTTP status the failing request observed; null when the failure produced no response. */
  httpStatus?: number | null;
  /** The request that failed, as "METHOD /path"; unset when the error did not identify one. */
  endpoint?: string;
  /** The read stopped at a cap while the API could still hold more records. */
  truncated?: boolean;
  /** Server-reported total when the API exposes one (PhishER pagination). */
  total?: number;
  /** The cap applied to the read. */
  limit?: number;
}

/** A paginated Reporting API or PhishER listing together with how the pagination loop ended. */
export interface Knowbe4Listing {
  items: JsonRecord[];
  truncated: boolean;
  limit: number;
  pages: number;
  total?: number;
}

export interface Knowbe4SampledSecurityTest {
  pst_id: string;
  campaign_id?: string;
  name?: string;
  started_at?: string;
  recipients: JsonRecord[];
  recipients_truncated?: boolean;
}

/** One per-test recipient read that failed, with the request and status that read actually observed. */
export interface Knowbe4RecipientReadFailure {
  pst_id: string;
  /** The failed request as "METHOD /path"; null when the error did not identify one. */
  endpoint: string | null;
  http_status: number | null;
  error: string;
}

export type Knowbe4InventoryName =
  | "account"
  | "account_risk_score_history"
  | "users"
  | "groups"
  | "phishing_campaigns"
  | "security_tests"
  | "security_test_recipients"
  | "callback_security_tests"
  | "training_campaigns"
  | "training_enrollments"
  | "store_purchases"
  | "training_policies"
  | "phisher_messages";

export interface Knowbe4InventoryGap {
  inventory: Knowbe4InventoryName;
  /** The request that failed when the error identified one, otherwise the inventory's documented endpoint. */
  endpoint: string;
  /** The HTTP status the failing request observed; null when no response was observed. */
  http_status: number | null;
  error: string;
  not_checked: string;
  collect_manually: string;
}

/** Written to core_data (and any snapshot inside an analysis object) in place of a list that was never read, so a denial is not mistaken for an empty inventory. */
export interface Knowbe4NotCollectedMarker {
  collected: false;
  /** The HTTP status the failing request observed, "error" for a failure without a response, or "not-collected" when no request was made. */
  status: number | "error" | "not-collected";
  /** The request that failed; null when the dataset was never requested, so no unobserved endpoint is named. */
  endpoint: string | null;
  error: string | null;
  reason: "not_readable" | "not_requested" | "not_configured";
}

export interface Knowbe4TruncatedInventory {
  inventory: Knowbe4InventoryName;
  seen: number;
  total: number | null;
  limit: number | null;
  argument: string | null;
}

export interface Knowbe4Snapshot {
  collectedAt: string;
  scopes: Knowbe4Scope[];
  account: Knowbe4Collected<JsonRecord>;
  accountRiskHistory: Knowbe4Collected<JsonRecord[]>;
  activeUsers: Knowbe4Collected<JsonRecord[]>;
  groups: Knowbe4Collected<JsonRecord[]>;
  phishingCampaigns: Knowbe4Collected<JsonRecord[]>;
  securityTests: Knowbe4Collected<JsonRecord[]>;
  securityTestRecipients: Knowbe4Collected<Knowbe4SampledSecurityTest[]>;
  /** The per-test recipient reads that failed; each names the request it made. */
  securityTestRecipientFailures: Knowbe4RecipientReadFailure[];
  unsampledSecurityTestIds: string[];
  userLimit: number;
  /** Whether the user read stopped at user_limit; null when the user list was not read, so the flag never defaults. */
  userLimitReached: boolean | null;
  enrollmentLimit: number;
  /** Whether the enrollment read stopped at enrollment_limit; null when enrollments were not read. */
  enrollmentLimitReached: boolean | null;
  callbackSecurityTests: Knowbe4Collected<JsonRecord[]>;
  trainingCampaigns: Knowbe4Collected<JsonRecord[]>;
  trainingEnrollments: Knowbe4Collected<JsonRecord[]>;
  storePurchases: Knowbe4Collected<JsonRecord[]>;
  trainingPolicies: Knowbe4Collected<JsonRecord[]>;
  phisherMessages: Knowbe4Collected<JsonRecord[]>;
  errors: string[];
}

export interface Knowbe4AssessmentOptions {
  now?: Date;
  redactPii?: boolean;
  lookbackDays?: number;
  trainingLookbackDays?: number;
  maxCampaignGapDays?: number;
  maxScheduleGapDays?: number;
  minCoveragePct?: number;
  maxPhishPronePct?: number;
  minReportRatePct?: number;
  requireFullTargeting?: boolean;
  minCompletionPct?: number;
  failCompletionPct?: number;
  enrollmentGraceDays?: number;
  remedialWindowDays?: number;
  maxContentAgeDays?: number;
  requiredComplianceTopics?: string[];
  maxMeanRiskScore?: number;
  maxRiskScoreStddev?: number;
  inactiveDays?: number;
  maxAdminCount?: number;
  requireUsbTests?: boolean;
  requireVishingTests?: boolean;
}

export interface Knowbe4CollectOptions extends Knowbe4AssessmentOptions {
  scopes?: Knowbe4Scope[];
  userLimit?: number;
  enrollmentLimit?: number;
  securityTestSampleLimit?: number;
  phisherMessageLimit?: number;
}

export interface Knowbe4AuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  manualCount: number;
  errorCount: number;
}

type AuthArgs = {
  api_token?: string;
  region?: string;
  base_url?: string;
  phisher_api_token?: string;
  phisher_graphql_url?: string;
  config_file?: string;
  timeout_seconds?: number;
  redact_pii?: boolean;
};

type AssessmentArgs = AuthArgs & {
  lookback_days?: number;
  training_lookback_days?: number;
  max_campaign_gap_days?: number;
  max_schedule_gap_days?: number;
  min_coverage_pct?: number;
  max_phish_prone_pct?: number;
  min_report_rate_pct?: number;
  require_full_targeting?: boolean;
  min_completion_pct?: number;
  fail_completion_pct?: number;
  enrollment_grace_days?: number;
  remedial_window_days?: number;
  max_content_age_days?: number;
  required_compliance_topics?: string[];
  max_mean_risk_score?: number;
  max_risk_score_stddev?: number;
  inactive_days?: number;
  max_admin_count?: number;
  require_usb_tests?: boolean;
  require_vishing_tests?: boolean;
  user_limit?: number;
  enrollment_limit?: number;
  security_test_sample_limit?: number;
  phisher_message_limit?: number;
};

type ExportAuditBundleArgs = AssessmentArgs & {
  output_dir?: string;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asRecordArray(value: unknown): JsonRecord[] {
  return Array.isArray(value)
    ? value.map(asObject).filter((item): item is JsonRecord => Boolean(item))
    : [];
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
    if (/^(true|1|yes|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|off)$/i.test(value.trim())) return false;
  }
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const items = value.map(asString).filter((item): item is string => Boolean(item));
    return items.length > 0 ? items : undefined;
  }
  const text = asString(value);
  if (!text) return undefined;
  const items = text.split(",").map((item) => item.trim()).filter(Boolean);
  return items.length > 0 ? items : undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.isFinite(value) ? (value as number) : fallback;
  return Math.min(Math.max(parsed, min), max);
}

function clampInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  return Math.trunc(clampNumber(value, fallback, min, max));
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function normalizeRegion(value: string | undefined): Knowbe4Region | undefined {
  if (!value) return undefined;
  const lowered = value.trim().toLowerCase();
  const match = KNOWBE4_REGIONS.find((region) => region === lowered);
  if (!match) {
    throw new Error(`Unsupported KnowBe4 region "${value}". Use one of: ${KNOWBE4_REGIONS.join(", ")}.`);
  }
  return match;
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampInteger(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function toDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysBetween(from: Date, to: Date): number {
  return (to.getTime() - from.getTime()) / DAY_MS;
}

function daysAgo(now: Date, days: number): Date {
  return new Date(now.getTime() - days * DAY_MS);
}

function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function roundTo(value: number, digits = 1): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function percentage(numerator: number, denominator: number): number | undefined {
  return denominator > 0 ? roundTo((numerator / denominator) * 100) : undefined;
}

function mean(values: number[]): number | undefined {
  if (values.length === 0) return undefined;
  return values.reduce((total, value) => total + value, 0) / values.length;
}

function standardDeviation(values: number[]): number | undefined {
  const average = mean(values);
  if (average === undefined) return undefined;
  const variance = values.reduce((total, value) => total + (value - average) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function decimalToPercent(value: unknown): number | undefined {
  const parsed = asNumber(value);
  return parsed === undefined ? undefined : roundTo(parsed * 100, 2);
}

function pseudonymize(value: string): string {
  return `user-${createHash("sha256").update(value.trim().toLowerCase()).digest("hex").slice(0, 12)}`;
}

const PII_HASH_KEYS = new Set(["email", "manager_email", "reportedBy", "reported_by", "from", "to", "cc"]);
const PII_MASK_KEYS = new Set([
  "first_name",
  "last_name",
  "manager_name",
  "phone_number",
  "mobile_phone_number",
  "extension",
  "aliases",
  "employee_number",
  "comment",
  "subject",
  "ip",
  "ip_location",
  "custom_field_1",
  "custom_field_2",
  "custom_field_3",
  "custom_field_4",
  "custom_date_1",
  "custom_date_2",
]);

export function redactKnowbe4Pii(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactKnowbe4Pii);
  const record = asObject(value);
  if (!record) return value;
  const redacted: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    if (PII_HASH_KEYS.has(key)) {
      const text = asString(entry);
      redacted[key] = text ? pseudonymize(text) : entry;
    } else if (PII_MASK_KEYS.has(key)) {
      redacted[key] = entry === null || entry === undefined ? entry : "[redacted]";
    } else {
      redacted[key] = redactKnowbe4Pii(entry);
    }
  }
  return redacted;
}

const REDACTED = "[REDACTED]";
const CREDENTIAL_LAST_SEGMENTS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwd", "pwd", "passphrase", "apikey", "authorization",
  "credential", "credentials", "bearer",
]);
const CREDENTIAL_KEY_QUALIFIERS = new Set(["api", "private", "secret", "signing", "access", "shared", "session", "master", "client", "auth", "service"]);
const URL_KEY_SEGMENTS = new Set(["url", "urls", "uri", "endpoint", "link", "href"]);
const CREDENTIAL_QUERY_PATTERN = /token|secret|password|key|signature|sig|credential|auth/i;
const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
// Free-form buckets on the user record that the assessments never read and that could carry anything an admin typed.
const USER_FREE_FORM_KEYS = new Set(["comment", "custom_field_1", "custom_field_2", "custom_field_3", "custom_field_4", "custom_date_1", "custom_date_2"]);

function keySegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}

function isCredentialKey(name: string): boolean {
  const segments = keySegments(name);
  const last = segments[segments.length - 1];
  if (!last) return false;
  if (CREDENTIAL_LAST_SEGMENTS.has(last)) return true;
  if (last === "key" || last === "keys") return segments.slice(0, -1).some((segment) => CREDENTIAL_KEY_QUALIFIERS.has(segment));
  return false;
}

function isUrlKey(name: string): boolean {
  return keySegments(name).some((segment) => URL_KEY_SEGMENTS.has(segment));
}

/** Reduces an absolute URL to scheme plus host so path segments and query strings cannot carry a signed token. */
function reduceUrl(value: string): string {
  if (!ABSOLUTE_URL_PATTERN.test(value)) return CREDENTIAL_QUERY_PATTERN.test(value) ? REDACTED : value;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return REDACTED;
  }
}

/**
 * Defense-in-depth pass over everything written to core_data/: the value under any credential-shaped key becomes
 * [REDACTED] whether it is a string, a list, or a nested object (the key survives so an auditor can see the field
 * existed), URL-shaped keys keep only scheme and host, and {name, value} pairs whose name is credential-shaped lose
 * their value. Booleans, numbers, and nulls pass through, and other nested values recurse.
 */
export function redactCredentialValues(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactCredentialValues);
  const record = asObject(value);
  if (!record) return value;
  const pairName = asString(record.name);
  const redacted: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    const credential = isCredentialKey(key) || (key === "value" && pairName !== undefined && isCredentialKey(pairName));
    if (credential && (typeof entry === "string" || (typeof entry === "object" && entry !== null))) {
      redacted[key] = REDACTED;
    } else if (typeof entry === "string") {
      redacted[key] = isUrlKey(key) ? reduceUrl(entry) : entry;
    } else {
      redacted[key] = redactCredentialValues(entry);
    }
  }
  return redacted;
}

/** Drops the free-form user fields (comment, custom fields and dates) at collection time; nothing downstream reads them. */
export function projectKnowbe4User(user: JsonRecord): JsonRecord {
  return Object.fromEntries(Object.entries(user).filter(([key]) => !USER_FREE_FORM_KEYS.has(key)));
}

function projectRecipient(recipient: JsonRecord): JsonRecord {
  const embedded = asObject(recipient.user);
  return embedded ? { ...recipient, user: projectKnowbe4User(embedded) } : recipient;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "knowbe4";
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

type ConfigOverlay = {
  apiToken?: string;
  region?: Knowbe4Region;
  baseUrl?: string;
  phisherApiToken?: string;
  phisherGraphqlUrl?: string;
  timeoutSeconds?: number;
  redactPii?: boolean;
};

function readConfigFileOverlay(location: string): ConfigOverlay | undefined {
  if (!existsSync(location)) return undefined;
  const parsed = asObject(parseYaml(readFileSync(location, "utf8"))) ?? {};
  return {
    apiToken: asString(parsed.api_token),
    region: normalizeRegion(asString(parsed.region)),
    baseUrl: asString(parsed.base_url),
    phisherApiToken: asString(parsed.phisher_api_token),
    phisherGraphqlUrl: asString(parsed.phisher_graphql_url),
    timeoutSeconds: asNumber(parsed.timeout_seconds),
    redactPii: asBoolean(parsed.redact_pii),
  };
}

function pickConfigValue<T>(
  label: string,
  sourceChain: string[],
  candidates: Array<[source: string, value: T | undefined]>,
): T | undefined {
  for (const [source, value] of candidates) {
    if (value !== undefined) {
      sourceChain.push(`${source}-${label}`);
      return value;
    }
  }
  return undefined;
}

export function resolveKnowbe4Configuration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
  cwd: string = process.cwd(),
): Knowbe4ResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = resolve(
    cwd,
    asString(input.config_file) ?? asString(env.KNOWBE4_CONFIG_FILE) ?? join(homeDir, DEFAULT_CONFIG_FILE),
  );
  const file = readConfigFileOverlay(configFile) ?? {};
  if (Object.values(file).some((value) => value !== undefined)) {
    sourceChain.push(`config:${configFile}`);
  }

  const apiToken = pickConfigValue("token", sourceChain, [
    ["arguments", asString(input.api_token) ?? asString(input.token)],
    ["environment", asString(env.KNOWBE4_API_TOKEN)],
    ["config", file.apiToken],
  ]);
  if (!apiToken) {
    throw new Error(
      "KnowBe4 Reporting API token is required. Pass api_token, set KNOWBE4_API_TOKEN, or add api_token to ~/.knowbe4-inspector/config.yaml.",
    );
  }

  const region = pickConfigValue("region", sourceChain, [
    ["arguments", normalizeRegion(asString(input.region))],
    ["environment", normalizeRegion(asString(env.KNOWBE4_REGION))],
    ["config", file.region],
  ]) ?? "us";

  const baseUrl = pickConfigValue("base-url", sourceChain, [
    ["arguments", asString(input.base_url)],
    ["environment", asString(env.KNOWBE4_BASE_URL)],
    ["config", file.baseUrl],
  ]) ?? REPORTING_BASE_URLS[region];

  const phisherApiToken = pickConfigValue("phisher-token", sourceChain, [
    ["arguments", asString(input.phisher_api_token)],
    ["environment", asString(env.KNOWBE4_PHISHER_API_TOKEN)],
    ["config", file.phisherApiToken],
  ]);

  const phisherGraphqlUrl = pickConfigValue("phisher-url", sourceChain, [
    ["arguments", asString(input.phisher_graphql_url)],
    ["environment", asString(env.KNOWBE4_PHISHER_GRAPHQL_URL)],
    ["config", file.phisherGraphqlUrl],
  ]) ?? PHISHER_GRAPHQL_URLS[region];

  const timeoutSeconds = pickConfigValue("timeout", sourceChain, [
    ["arguments", asNumber(input.timeout_seconds)],
    ["environment", asNumber(env.KNOWBE4_TIMEOUT)],
    ["config", file.timeoutSeconds],
  ]);

  const redactPii = pickConfigValue("redact-pii", sourceChain, [
    ["arguments", asBoolean(input.redact_pii)],
    ["environment", asBoolean(env.KNOWBE4_REDACT_PII)],
    ["config", file.redactPii],
  ]) ?? false;

  return {
    apiToken,
    region,
    baseUrl: normalizeBaseUrl(baseUrl),
    phisherApiToken,
    phisherGraphqlUrl: normalizeBaseUrl(phisherGraphqlUrl),
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    redactPii,
    configFile,
    sourceChain: [...new Set(sourceChain)],
  };
}

function retryDelayMs(retryAfter: string | null, attempt: number): number {
  const seconds = retryAfter ? Number(retryAfter) : Number.NaN;
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_DELAY_MS);
  }
  const retryDate = retryAfter ? Date.parse(retryAfter) : Number.NaN;
  if (Number.isFinite(retryDate)) {
    return Math.min(Math.max(retryDate - Date.now(), 0), MAX_RETRY_DELAY_MS);
  }
  return Math.min(DEFAULT_RETRY_BASE_MS * 2 ** attempt, MAX_RETRY_DELAY_MS);
}

/**
 * Reduces every URL in the text to scheme, host, and path, dropping userinfo, query, and fragment wherever it appears.
 * An already-scrubbed `?[REDACTED]` tail is consumed whole so a second pass over the same string is a no-op.
 */
function scrubUrlsInText(text: string): string {
  return text.replace(/\b[a-z][a-z0-9+.-]*:\/\/(?:\[REDACTED\]|[^\s"'<>)\]])+/gi, (match) => {
    try {
      const parsed = new URL(match);
      const hadUserinfo = parsed.username.length > 0 || parsed.password.length > 0;
      const hadDetail = parsed.search.length > 0 || parsed.hash.length > 0 || hadUserinfo;
      return hadDetail ? `${parsed.protocol}//${parsed.host}${parsed.pathname}?${REDACTED}` : match;
    } catch {
      return REDACTED;
    }
  });
}

/**
 * Configuration-independent scrub applied to every error string before it is recorded anywhere (findings,
 * summaries, analysis objects, access surfaces, the bundle): authorization values, session and cookie values,
 * JWT-shaped strings, credential-shaped key/value pairs, and URL userinfo and query strings anywhere in the text.
 */
export function scrubErrorText(text: string): string {
  return scrubUrlsInText(text)
    .replace(/\b(authorization|proxy-authorization|x-api-key|x-phisher-token)\b(\s*[:=]\s*)(?:apikey|basic|bearer|token|digest)?\s*[^\s,;"']+/gi, `$1$2${REDACTED}`)
    .replace(/\b(bearer|basic|apikey)\s+[A-Za-z0-9+/=_.:-]{8,}/gi, `$1 ${REDACTED}`)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?/g, REDACTED)
    .replace(/\b((?:set-)?cookie|session(?:[_-]?(?:id|token))?|sid|jsessionid|xsrf[_-]?token|csrf[_-]?token)(["']?\s*[:=]\s*["']?)([^"';,\s}]+)/gi, `$1$2${REDACTED}`)
    .replace(/\b((?:api[_-]?key|x-api-key|app[_-]?key|application[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|private[_-]?key|credentials?)["']?\s*[:=]\s*["']?)([^"',;\s}]+)/gi, `$1${REDACTED}`);
}

/** The scrubbed message of any thrown value; the single point through which every recorded error string passes. */
function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

/** The HTTP status a failed request observed, or null when the failure produced no response or the error did not come from the client. */
function observedStatus(error: unknown): number | null {
  return error instanceof Knowbe4ApiError ? error.status : null;
}

/** The "METHOD /path" of the failed request when the error identifies one. */
function observedEndpoint(error: unknown): string | undefined {
  return error instanceof Knowbe4ApiError ? error.endpoint : undefined;
}

export class Knowbe4ApiError extends Error {
  /** The HTTP status observed, or null for a timeout or transport failure. */
  readonly status: number | null;
  /** The request that failed, as "METHOD /path". */
  readonly endpoint: string;

  constructor(message: string, status: number | null, endpoint: string) {
    super(message);
    this.name = "Knowbe4ApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

/** "403 Forbidden", or just "403" when the response carried no status text. */
function statusLine(response: Response): string {
  return response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
}

/**
 * Describes a body that is not the documented JSON error shape by status, content type, and length instead of
 * echoing it: an HTML or proxy error page can reflect the request (including its Authorization header) back at us.
 */
function describeOpaqueBody(response: Response, rawText: string): string {
  const contentType = (response.headers.get("content-type") ?? "").split(";")[0].trim() || "untyped";
  return `${statusLine(response)}: non-JSON body (${contentType}, ${Buffer.byteLength(rawText, "utf8")} bytes, not echoed)`;
}

// Only the documented JSON error fields (message, error, errors[].message) are quoted; anything else is described.
function knowbe4ErrorDetail(response: Response, rawText: string): string | undefined {
  if (rawText.length === 0) return undefined;
  try {
    const payload = asObject(JSON.parse(rawText));
    const detail = [
      asString(payload?.message),
      asString(payload?.error),
      ...asRecordArray(payload?.errors).map((item) => asString(item.message)),
    ].filter((item): item is string => Boolean(item));
    if (detail.length > 0) return detail.join("; ").replace(/\s+/g, " ").slice(0, 300);
    return `${statusLine(response)}: JSON body without a documented error field (${Buffer.byteLength(rawText, "utf8")} bytes, not echoed)`;
  } catch {
    return describeOpaqueBody(response, rawText);
  }
}

function emptyListing(limit: number): Knowbe4Listing {
  return { items: [], truncated: false, limit, pages: 0 };
}

// Argument and field names follow the public PhishER schema served to the developer portal's schema browser
// (introspection of POST https://training.knowbe4.com/graphql?scope=phisher, no auth required):
// phisherMessages(per: Int, page: Int, all: Boolean, query: String!, sortField, sortDirection, nextPageKey: String).
// The prose pagination page reuses the REST wording (page and per_page); GraphQL validation rejects unknown arguments, so the schema wins.
const PHISHER_MESSAGES_QUERY = `query GrclankerPhisherMessages($query: String!, $per: Int, $page: Int, $nextPageKey: String) {
  phisherMessages(query: $query, per: $per, page: $page, nextPageKey: $nextPageKey, sortField: REPORTED_AT, sortDirection: DESCENDING) {
    nodes {
      id
      reportedAt
      reportedBy
      from
      subject
      category
      severity
      actionStatus
      pipelineStatus
    }
    pagination {
      page
      pages
      per
      totalCount
      nextPageKey
    }
  }
}`;

const PHISHER_MESSAGE_COUNT_QUERY = `query GrclankerPhisherMessageCount($query: String!) {
  phisherMessages(query: $query, per: 1, page: 1) {
    pagination {
      totalCount
    }
  }
}`;

const PHISHER_RULES_QUERY = `query GrclankerPhisherRules($query: String!, $per: Int, $page: Int, $active: Boolean) {
  phisherRules(query: $query, per: $per, page: $page, active: $active) {
    nodes {
      id
      name
      active
      target
      hits
      createdAt
      updatedAt
    }
    pagination {
      page
      pages
      per
      totalCount
    }
  }
}`;

export class Knowbe4ApiClient {
  private readonly config: Knowbe4ResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: SleepImpl;
  private readonly maxRetries: number;
  private readonly minRequestIntervalMs: number;
  private lastRequestAt = 0;
  private requestCount = 0;

  constructor(
    config: Knowbe4ResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleepImpl?: SleepImpl;
      maxRetries?: number;
      minRequestIntervalMs?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.maxRetries = clampInteger(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
    this.minRequestIntervalMs = clampInteger(options.minRequestIntervalMs, MIN_REQUEST_INTERVAL_MS, 0, 10_000);
  }

  getResolvedConfig(): Knowbe4ResolvedConfig {
    return this.config;
  }

  getRequestCount(): number {
    return this.requestCount;
  }

  hasPhisherCredentials(): boolean {
    return Boolean(this.config.phisherApiToken);
  }

  /** Configured secrets first, then the configuration-independent scrub, so no client error string can bypass either. */
  private redact(message: string): string {
    let redacted = message;
    for (const secret of [this.config.apiToken, this.config.phisherApiToken]) {
      if (secret && secret.length > 0) {
        redacted = redacted.split(secret).join(REDACTED);
      }
    }
    return scrubErrorText(redacted);
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async throttle(): Promise<void> {
    const waitMs = this.lastRequestAt + this.minRequestIntervalMs - Date.now();
    if (waitMs > 0) await this.sleepImpl(waitMs);
    this.lastRequestAt = Date.now();
  }

  /**
   * Every failure surfaces as a Knowbe4ApiError naming the request that was actually made ("GET /v1/users") and the
   * status it observed (null for a timeout or transport failure), so the surfaces and findings downstream never
   * have to name an endpoint or status from a constant.
   */
  private async request(url: string, init: RequestInit, token: string, label?: string): Promise<unknown> {
    const method = init.method ?? "GET";
    const endpoint = `${method} ${new URL(url).pathname}`;
    const target = label ? `${endpoint} (${label})` : endpoint;
    for (let attempt = 0; ; attempt += 1) {
      await this.throttle();
      this.requestCount += 1;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      let response: Response;
      try {
        const headers = new Headers(init.headers ?? {});
        headers.set("accept", "application/json");
        headers.set("authorization", `Bearer ${token}`);
        response = await this.fetchImpl(url, { ...init, headers, signal: controller.signal });
      } catch (error) {
        if (controller.signal.aborted) {
          throw new Knowbe4ApiError(this.redact(`KnowBe4 request timed out after ${this.config.timeoutMs}ms: ${target}`), null, endpoint);
        }
        const message = error instanceof Error ? error.message : String(error);
        throw new Knowbe4ApiError(this.redact(`KnowBe4 request failed: ${target}: ${message}`), null, endpoint);
      } finally {
        clearTimeout(timeout);
      }

      const rawText = await response.text();
      if ((response.status === 429 || response.status === 503) && attempt < this.maxRetries) {
        await this.sleepImpl(retryDelayMs(response.headers.get("retry-after"), attempt));
        continue;
      }
      if (!response.ok) {
        const detail = knowbe4ErrorDetail(response, rawText);
        throw new Knowbe4ApiError(
          this.redact(`KnowBe4 request failed (${statusLine(response)}) ${target}${detail ? `: ${detail}` : ""}`),
          response.status,
          endpoint,
        );
      }
      if (rawText.length === 0) return {};
      try {
        return JSON.parse(rawText) as unknown;
      } catch {
        // A login page or proxy page served with a success status is not an empty inventory; it is an error.
        throw new Knowbe4ApiError(
          this.redact(`KnowBe4 request ${target} returned a ${describeOpaqueBody(response, rawText)}; the endpoint is not serving the JSON API`),
          response.status,
          endpoint,
        );
      }
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request(this.buildUrl(path, query), { method: "GET" }, this.config.apiToken);
  }

  /**
   * Walks page/per_page pagination up to limit items. The Reporting API returns bare arrays with no total, so the
   * only completion signal is a short page: the listing is reported truncated whenever the loop stopped at the cap
   * while the last page was still full (more pages may exist) or while items were dropped from it.
   */
  async list(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<Knowbe4Listing> {
    const limit = clampInteger(options.limit, DEFAULT_LIST_LIMIT, 1, 1_000_000);
    const pageSize = clampInteger(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const items: JsonRecord[] = [];
    let truncated = false;
    let pages = 0;

    for (let page = 1; ; page += 1) {
      const payload = await this.get(path, { ...query, page, per_page: pageSize });
      pages += 1;
      const pageItems = asRecordArray(payload);
      const room = limit - items.length;
      items.push(...pageItems.slice(0, room));
      if (pageItems.length > room) {
        truncated = true;
        break;
      }
      if (pageItems.length < pageSize) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
    }

    return { items, truncated, limit, pages };
  }

  async probe(path: string, query: JsonRecord = {}): Promise<JsonRecord[]> {
    return (await this.list(path, query, { limit: 1, pageSize: 1 })).items;
  }

  async getAccount(): Promise<JsonRecord> {
    return asObject(await this.get("/v1/account")) ?? {};
  }

  async getAccountRiskScoreHistory(full = true): Promise<Knowbe4Listing> {
    return this.list("/v1/account/risk_score_history", full ? { full: "true" } : {});
  }

  async listUsers(options: { status?: "active" | "archived"; groupId?: string; limit?: number } = {}): Promise<Knowbe4Listing> {
    return this.list("/v1/users", { status: options.status ?? "active", group_id: options.groupId }, { limit: options.limit ?? DEFAULT_USER_LIMIT });
  }

  async listGroups(options: { status?: "active" | "archived"; limit?: number } = {}): Promise<Knowbe4Listing> {
    return this.list("/v1/groups", { status: options.status ?? "active" }, { limit: options.limit });
  }

  async listGroupMembers(groupId: string, limit?: number): Promise<Knowbe4Listing> {
    return this.list(`/v1/groups/${encodeURIComponent(groupId)}/members`, {}, { limit });
  }

  async listPhishingCampaigns(limit?: number): Promise<Knowbe4Listing> {
    return this.list("/v1/phishing/campaigns", {}, { limit });
  }

  async listSecurityTests(options: { campaignType?: "callback"; limit?: number } = {}): Promise<Knowbe4Listing> {
    return this.list("/v1/phishing/security_tests", { campaign_type: options.campaignType }, { limit: options.limit });
  }

  async listSecurityTestRecipients(pstId: string, limit?: number): Promise<Knowbe4Listing> {
    return this.list(`/v1/phishing/security_tests/${encodeURIComponent(pstId)}/recipients`, {}, { limit });
  }

  async listTrainingCampaigns(limit?: number): Promise<Knowbe4Listing> {
    return this.list("/v1/training/campaigns", {}, { limit, pageSize: TRAINING_CAMPAIGN_PAGE_SIZE });
  }

  async listTrainingEnrollments(
    options: { campaignId?: string; userId?: string; storePurchaseId?: string; excludeArchivedUsers?: boolean; limit?: number } = {},
  ): Promise<Knowbe4Listing> {
    return this.list("/v1/training/enrollments", {
      campaign_id: options.campaignId,
      user_id: options.userId,
      store_purchase_id: options.storePurchaseId,
      exclude_archived_users: options.excludeArchivedUsers === false ? undefined : "true",
      include_campaign_id: "true",
      include_store_purchase_id: "true",
    }, { limit: options.limit ?? DEFAULT_ENROLLMENT_LIMIT });
  }

  async listStorePurchases(limit?: number): Promise<Knowbe4Listing> {
    return this.list("/v1/training/store_purchases", {}, { limit });
  }

  async listTrainingPolicies(limit?: number): Promise<Knowbe4Listing> {
    return this.list("/v1/training/policies", {}, { limit });
  }

  async graphql(query: string, variables: JsonRecord = {}): Promise<JsonRecord> {
    if (!this.config.phisherApiToken) {
      throw new Error("PhishER API token is not configured. Set KNOWBE4_PHISHER_API_TOKEN or pass phisher_api_token.");
    }
    const payload = asObject(await this.request(
      this.config.phisherGraphqlUrl,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query, variables }),
      },
      this.config.phisherApiToken,
      "PhishER GraphQL",
    )) ?? {};
    const errors = asRecordArray(payload.errors);
    if (errors.length > 0) {
      const detail = errors.map((item) => asString(item.message) ?? "unknown error").join("; ");
      throw new Knowbe4ApiError(
        this.redact(`PhishER GraphQL returned errors: ${detail}`),
        null,
        `POST ${new URL(this.config.phisherGraphqlUrl).pathname}`,
      );
    }
    return asObject(payload.data) ?? {};
  }

  /**
   * Walks a PhishER connection (nodes plus pagination { page, pages, totalCount, nextPageKey }) up to limit items.
   * The listing is truncated when the cap stopped the loop short of totalCount (or with pages still remaining), when
   * the server keeps returning the same nextPageKey, or when an empty page arrives while totalCount says more exist.
   */
  private async listPhisherConnection(
    query: string,
    field: string,
    variables: JsonRecord,
    limit: number,
    withNextPageKey: boolean,
  ): Promise<Knowbe4Listing> {
    const per = Math.min(PHISHER_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    let nextPageKey: string | undefined;
    let total: number | undefined;
    let truncated = false;
    let pages = 0;

    for (let page = 1; ; page += 1) {
      const data = await this.graphql(query, {
        ...variables,
        per,
        page,
        ...(withNextPageKey ? { nextPageKey } : {}),
      });
      pages += 1;
      const connection = asObject(data[field]) ?? {};
      const nodes = asRecordArray(connection.nodes);
      const pagination = asObject(connection.pagination) ?? {};
      total = asNumber(pagination.totalCount) ?? total;
      const totalPages = asNumber(pagination.pages);
      const previousKey = nextPageKey;
      nextPageKey = withNextPageKey ? asString(pagination.nextPageKey) || undefined : undefined;
      const room = limit - items.length;
      items.push(...nodes.slice(0, room));
      if (nodes.length > room) {
        truncated = true;
        break;
      }
      if (nodes.length === 0) break;
      const lastPage = totalPages !== undefined && page >= totalPages && !nextPageKey;
      if (lastPage) break;
      if (nextPageKey !== undefined && nextPageKey === previousKey) {
        truncated = true;
        break;
      }
      if (items.length >= limit) {
        truncated = true;
        break;
      }
    }

    if (total !== undefined) truncated = truncated || total > items.length;
    return { items, truncated, limit, pages, total };
  }

  async listPhisherMessages(options: { query?: string; limit?: number } = {}): Promise<Knowbe4Listing> {
    const limit = clampInteger(options.limit, DEFAULT_PHISHER_MESSAGE_LIMIT, 1, 100_000);
    return this.listPhisherConnection(PHISHER_MESSAGES_QUERY, "phisherMessages", { query: options.query ?? "" }, limit, true);
  }

  async countPhisherMessages(query = ""): Promise<number | undefined> {
    const data = await this.graphql(PHISHER_MESSAGE_COUNT_QUERY, { query });
    return asNumber(asObject(asObject(data.phisherMessages)?.pagination)?.totalCount);
  }

  async listPhisherRules(options: { query?: string; active?: boolean; limit?: number } = {}): Promise<Knowbe4Listing> {
    const limit = clampInteger(options.limit, 500, 1, 10_000);
    return this.listPhisherConnection(PHISHER_RULES_QUERY, "phisherRules", { query: options.query ?? "", active: options.active }, limit, false);
  }
}

export type Knowbe4DataClient = Pick<
  Knowbe4ApiClient,
  | "getResolvedConfig"
  | "hasPhisherCredentials"
  | "getAccount"
  | "getAccountRiskScoreHistory"
  | "listUsers"
  | "listGroups"
  | "listPhishingCampaigns"
  | "listSecurityTests"
  | "listSecurityTestRecipients"
  | "listTrainingCampaigns"
  | "listTrainingEnrollments"
  | "listStorePurchases"
  | "listTrainingPolicies"
  | "listPhisherMessages"
>;

type Knowbe4AccessClient = Pick<
  Knowbe4ApiClient,
  "getResolvedConfig" | "hasPhisherCredentials" | "getAccount" | "probe" | "countPhisherMessages"
>;

async function readableSurface(
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<Knowbe4AccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, status: "readable", collected: true, http_status: null, count: countResolver?.(value) ?? null };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      collected: false,
      http_status: observedStatus(error),
      count: null,
      error: errorMessage(error),
    };
  }
}

const CORE_ACCESS_SURFACES = 9;
const HEALTHY_SURFACE_THRESHOLD = 7;

export async function checkKnowbe4Access(client: Knowbe4AccessClient): Promise<Knowbe4AccessCheckResult> {
  const config = client.getResolvedConfig();
  let account: JsonRecord = {};
  const accountSurface = await readableSurface("account", "GET /v1/account", async () => {
    account = await client.getAccount();
    return account;
  }, (value) => asRecordArray(asObject(value)?.admins).length);

  // Each probe requests the first record of the documented listing, so the endpoint named here is the one requested.
  const surfaces: Knowbe4AccessSurface[] = [
    accountSurface,
    await readableSurface("users", "GET /v1/users?status=active", () => client.probe("/v1/users", { status: "active" })),
    await readableSurface("groups", "GET /v1/groups?status=active", () => client.probe("/v1/groups", { status: "active" })),
    await readableSurface("phishing_campaigns", "GET /v1/phishing/campaigns", () => client.probe("/v1/phishing/campaigns")),
    await readableSurface("security_tests", "GET /v1/phishing/security_tests", () => client.probe("/v1/phishing/security_tests")),
    await readableSurface("training_campaigns", "GET /v1/training/campaigns", () => client.probe("/v1/training/campaigns")),
    await readableSurface("training_enrollments", "GET /v1/training/enrollments", () => client.probe("/v1/training/enrollments")),
    await readableSurface("store_purchases", "GET /v1/training/store_purchases", () => client.probe("/v1/training/store_purchases")),
    await readableSurface("training_policies", "GET /v1/training/policies", () => client.probe("/v1/training/policies")),
  ];

  const phisherEndpoint = `POST ${new URL(config.phisherGraphqlUrl).pathname} phisherMessages`;
  if (client.hasPhisherCredentials()) {
    surfaces.push(await readableSurface(
      "phisher_messages",
      phisherEndpoint,
      () => client.countPhisherMessages(""),
      (value) => asNumber(value),
    ));
  } else {
    // No PhishER request is made without credentials, so no endpoint is named for the surface.
    surfaces.push({
      name: "phisher_messages",
      endpoint: null,
      status: "not_configured",
      collected: false,
      http_status: null,
      count: null,
    });
  }

  const readableCore = surfaces
    .slice(0, CORE_ACCESS_SURFACES)
    .filter((surface) => surface.status === "readable").length;
  const status = readableCore >= HEALTHY_SURFACE_THRESHOLD ? "healthy" : "limited";
  const accountName = asString(account.name);
  const subscriptionLevel = asString(account.subscription_level);

  return {
    status,
    region: config.region,
    baseUrl: config.baseUrl,
    accountName,
    subscriptionLevel,
    surfaces,
    notes: [
      `Using KnowBe4 region ${config.region} (${config.baseUrl}).`,
      accountName
        ? `Account: ${accountName}${subscriptionLevel ? ` (${subscriptionLevel})` : ""}.`
        : "Account details were not readable.",
      `${readableCore}/${CORE_ACCESS_SURFACES} Reporting API surfaces are readable.`,
      client.hasPhisherCredentials()
        ? "PhishER GraphQL credentials are configured."
        : "PhishER GraphQL credentials are not configured; report-rate enrichment will be skipped.",
      `Configuration sources: ${config.sourceChain.join(", ") || "defaults"}.`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run knowbe4_assess_phishing_program, knowbe4_assess_training_program, knowbe4_assess_user_risk, knowbe4_assess_account_governance, or knowbe4_export_audit_bundle."
        : "Regenerate the Reporting API key in the KnowBe4 console (Account Settings, API section) and confirm the region matches where the account is hosted.",
  };
}

function collected<T>(data: T, error?: string): Knowbe4Collected<T> {
  return { data, collected: true, error };
}

function skipped<T>(data: T): Knowbe4Collected<T> {
  return { data, collected: false };
}

/**
 * The single point at which a collection failure is recorded: the message is scrubbed, appended to the run's error
 * list, and returned with the status and endpoint the failing request actually observed.
 */
function recordFailure<T>(label: string, fallback: T, errors: string[], error: unknown): Knowbe4Collected<T> {
  const message = errorMessage(error);
  errors.push(`${label}: ${message}`);
  return { data: fallback, collected: true, error: message, httpStatus: observedStatus(error), endpoint: observedEndpoint(error) };
}

async function collectSurface<T>(
  label: string,
  fallback: T,
  errors: string[],
  load: () => Promise<T>,
): Promise<Knowbe4Collected<T>> {
  try {
    return collected(await load());
  } catch (error) {
    return recordFailure(label, fallback, errors, error);
  }
}

/**
 * Accepts either a Knowbe4Listing from the API client or a bare array (older callers and test doubles). A bare array
 * has no pagination signal, so it is treated as truncated only when it filled the cap.
 */
function toListing(value: unknown, limit: number): Knowbe4Listing {
  if (Array.isArray(value)) {
    return { items: asRecordArray(value), truncated: value.length >= limit, limit, pages: 1 };
  }
  const record = asObject(value);
  if (record && Array.isArray(record.items)) {
    return {
      items: asRecordArray(record.items),
      truncated: asBoolean(record.truncated) ?? false,
      limit: asNumber(record.limit) ?? limit,
      pages: asNumber(record.pages) ?? 1,
      total: asNumber(record.total),
    };
  }
  return emptyListing(limit);
}

async function collectListing(
  label: Knowbe4InventoryName,
  errors: string[],
  limit: number,
  load: () => Promise<unknown>,
  project: (item: JsonRecord) => JsonRecord = (item) => item,
): Promise<Knowbe4Collected<JsonRecord[]>> {
  try {
    const listing = toListing(await load(), limit);
    return { data: listing.items.map(project), collected: true, truncated: listing.truncated, total: listing.total, limit: listing.limit };
  } catch (error) {
    return { ...recordFailure<JsonRecord[]>(label, [], errors, error), limit };
  }
}

/** True when the inventory was requested and read without error. */
function isRead(collection: Knowbe4Collected<unknown>): boolean {
  return collection.collected && !collection.error;
}

/** True when the inventory was read and the listing did not stop at a cap, so counts and names derived from it are complete. */
function isComplete(collection: Knowbe4Collected<unknown>): boolean {
  return isRead(collection) && collection.truncated !== true;
}

/** A value derived from an inventory renders only when the inventory was read at all. */
function whenRead<T>(collection: Knowbe4Collected<unknown>, value: T): T | null {
  return isRead(collection) ? value : null;
}

/** A count or principal list derived from an inventory renders only when the inventory was read completely. */
function whenComplete<T>(collection: Knowbe4Collected<unknown>, value: T): T | null {
  return isComplete(collection) ? value : null;
}

/** A count or list joined across several inventories renders only when every one of them was read completely. */
function whenAllComplete<T>(collections: Knowbe4Collected<unknown>[], value: T): T | null {
  return collections.every(isComplete) ? value : null;
}

/** The truncation flag of an inventory; null when the inventory was never read, so a flag cannot default on a scan that did not run. */
function truncatedFlag(collection: Knowbe4Collected<unknown>): boolean | null {
  return isRead(collection) ? collection.truncated === true : null;
}

/**
 * Whether a violation was observed: true when at least one violator was found among the records read (a real
 * observation), false only when every set that proves the property was read completely, and null when any of them
 * was partial or unreadable, so "no violation" is never asserted from data that was not fully read.
 */
function violationFlag(sources: Array<Knowbe4Collected<unknown> | boolean>, observed: number): boolean | null {
  if (observed > 0) return true;
  return sources.every((source) => (typeof source === "boolean" ? source : isComplete(source))) ? false : null;
}

/**
 * A list of records observed to hold a property: the records found are real observations and always render, while an
 * empty list renders `[]` only when every set that could have revealed one was read completely, and null otherwise.
 */
function observedList<T>(sources: Knowbe4Collected<unknown>[], items: T[]): T[] | null {
  return items.length > 0 || sources.every(isComplete) ? items : null;
}

const INVENTORY_ENDPOINTS: Record<Knowbe4InventoryName, string> = {
  account: "GET /v1/account",
  account_risk_score_history: "GET /v1/account/risk_score_history?full=true",
  users: "GET /v1/users?status=active",
  groups: "GET /v1/groups?status=active",
  phishing_campaigns: "GET /v1/phishing/campaigns",
  security_tests: "GET /v1/phishing/security_tests",
  security_test_recipients: "GET /v1/phishing/security_tests/{pst_id}/recipients",
  callback_security_tests: "GET /v1/phishing/security_tests?campaign_type=callback",
  training_campaigns: "GET /v1/training/campaigns",
  training_enrollments: "GET /v1/training/enrollments",
  store_purchases: "GET /v1/training/store_purchases",
  training_policies: "GET /v1/training/policies",
  phisher_messages: "PhishER GraphQL phisherMessages",
};

// Console evidence that stands in for an inventory the API would not return.
const INVENTORY_MANUAL_EVIDENCE: Record<Knowbe4InventoryName, string> = {
  account: "the Account Settings page showing the account name, allowed domains, and console admin list",
  account_risk_score_history: "the organization Risk Score history chart (Dashboard > Risk Score)",
  users: "the active user export (Users > Download CSV) with join dates, last sign-in, and current risk scores",
  groups: "the groups list (Users > Groups) with member counts",
  phishing_campaigns: "the phishing campaign list (Phishing > Campaigns) with target groups, status, and last run dates",
  security_tests: "the phishing security test list (Phishing > Reports > Security Tests) with start dates, delivered, and reported counts",
  security_test_recipients: "the recipient results export of each security test in the window (Phishing > Security Test > Recipients > Download CSV)",
  callback_security_tests: "the Callback Phishing campaign list (Phishing > Callback Phishing) with test start dates",
  training_campaigns: "the training campaign list (Training > Campaigns) with content, start and end dates, and completion percentages",
  training_enrollments: "the training enrollment report (Training > Reports > Enrollments > Download CSV)",
  store_purchases: "the ModStore purchased content list (Training > Library) with publish dates and retirement status",
  training_policies: "the uploaded policies list (Training > Library > Policies)",
  phisher_messages: "the PhishER inbox export (PhishER > Inbox) for the assessment window",
};

const INVENTORY_LIMIT_ARGUMENTS: Partial<Record<Knowbe4InventoryName, string>> = {
  users: "user_limit",
  training_enrollments: "enrollment_limit",
  phisher_messages: "phisher_message_limit",
};

function inventoryCollection(snapshot: Knowbe4Snapshot, name: Knowbe4InventoryName): Knowbe4Collected<unknown> {
  switch (name) {
    case "account":
      return snapshot.account;
    case "account_risk_score_history":
      return snapshot.accountRiskHistory;
    case "users":
      return snapshot.activeUsers;
    case "groups":
      return snapshot.groups;
    case "phishing_campaigns":
      return snapshot.phishingCampaigns;
    case "security_tests":
      return snapshot.securityTests;
    case "security_test_recipients":
      return snapshot.securityTestRecipients;
    case "callback_security_tests":
      return snapshot.callbackSecurityTests;
    case "training_campaigns":
      return snapshot.trainingCampaigns;
    case "training_enrollments":
      return snapshot.trainingEnrollments;
    case "store_purchases":
      return snapshot.storePurchases;
    case "training_policies":
      return snapshot.trainingPolicies;
    case "phisher_messages":
      return snapshot.phisherMessages;
    default: {
      const exhaustive: never = name;
      throw new Error(`Unhandled KnowBe4 inventory: ${String(exhaustive)}`);
    }
  }
}

export const KNOWBE4_INVENTORIES: Knowbe4InventoryName[] = Object.keys(INVENTORY_ENDPOINTS) as Knowbe4InventoryName[];

/** The endpoint to name for an inventory: the request that actually failed when the error identified one, otherwise the documented one. */
function inventoryEndpoint(name: Knowbe4InventoryName, collection: Knowbe4Collected<unknown>): string {
  return collection.endpoint ?? INVENTORY_ENDPOINTS[name];
}

/**
 * One row per inventory describing how the read ended, for core_data/collection_status.json and the summaries.
 * Every flag and count is null for a read that never completed (denied, errored, or not requested), so a consumer
 * cannot mistake a scan that did not run for a complete, untruncated, empty one; the totals count those as unknown.
 */
export function knowbe4CollectionStatus(snapshot: Knowbe4Snapshot): { inventories: JsonRecord[]; totals: JsonRecord } {
  const inventories = KNOWBE4_INVENTORIES.map((name) => {
    const collection = inventoryCollection(snapshot, name);
    const read = isRead(collection);
    const seen = Array.isArray(collection.data) ? collection.data.length : 1;
    return {
      inventory: name,
      // A skipped inventory made no request, so no endpoint is named for it.
      endpoint: collection.collected ? inventoryEndpoint(name, collection) : null,
      status: !collection.collected ? "not_requested" : collection.error ? "not_readable" : "readable",
      collected: read,
      readable: collection.collected ? read : null,
      http_status: collection.error ? collection.httpStatus ?? null : null,
      error: collection.error ?? null,
      complete: read ? collection.truncated !== true : null,
      truncated: read ? collection.truncated === true : null,
      seen: read ? seen : null,
      total: read ? collection.total ?? null : null,
      limit: collection.collected ? collection.limit ?? null : null,
      limit_argument: INVENTORY_LIMIT_ARGUMENTS[name] ?? null,
    };
  });
  const readable = inventories.filter((row) => row.collected);
  return {
    inventories,
    totals: {
      inventories: inventories.length,
      readable: readable.length,
      not_readable: inventories.filter((row) => row.status === "not_readable").length,
      not_requested: inventories.filter((row) => row.status === "not_requested").length,
      complete: readable.filter((row) => row.complete === true).length,
      truncated: readable.filter((row) => row.truncated === true).length,
      truncation_unknown: inventories.length - readable.length,
    },
  };
}

/** The core_data payload for a list inventory: its records when it was read (an empty inventory stays `[]`), a marker otherwise. */
function coreDataValue<T>(name: Knowbe4InventoryName, collection: Knowbe4Collected<T>): T | Knowbe4NotCollectedMarker {
  if (isRead(collection)) return collection.data;
  if (!collection.collected) {
    return { collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested" };
  }
  return {
    collected: false,
    status: collection.httpStatus ?? "error",
    endpoint: inventoryEndpoint(name, collection),
    error: collection.error ?? null,
    reason: "not_readable",
  };
}

/** Marker for an inventory whose credentials were not configured, so no request was made and no endpoint is named. */
function notConfiguredMarker(): Knowbe4NotCollectedMarker {
  return { collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_configured" };
}

/**
 * The core_data payload for the per-test recipient reads: the loaded samples plus one marker per test whose read
 * failed (each naming the request it made), a single marker when every attempted read failed, and `[]` only when
 * there was nothing to read.
 */
function recipientsCoreData(snapshot: Knowbe4Snapshot): unknown {
  const collection = snapshot.securityTestRecipients;
  if (!collection.collected) return coreDataValue("security_test_recipients", collection);
  const failures = snapshot.securityTestRecipientFailures.map((failure) => ({
    pst_id: failure.pst_id,
    collected: false,
    status: failure.http_status ?? "error",
    endpoint: failure.endpoint,
    error: failure.error,
    reason: "not_readable",
  }));
  if (collection.data.length === 0 && failures.length > 0) {
    return { ...coreDataValue("security_test_recipients", collection), failed_reads: failures };
  }
  return [...collection.data, ...failures];
}

function recordId(record: JsonRecord): string | undefined {
  return asString(record.id);
}

function testId(test: JsonRecord): string | undefined {
  return asString(test.pst_id);
}

function testStartedAt(test: JsonRecord): Date | undefined {
  return toDate(test.started_at) ?? toDate(test.start_date);
}

function testName(test: JsonRecord): string {
  return asString(test.name) ?? `pst-${testId(test) ?? "unknown"}`;
}

function runTests(tests: JsonRecord[], now: Date): Array<{ test: JsonRecord; startedAt: Date }> {
  return tests
    .map((test) => ({ test, startedAt: testStartedAt(test) }))
    .filter((item): item is { test: JsonRecord; startedAt: Date } => Boolean(item.startedAt && item.startedAt.getTime() <= now.getTime()))
    .sort((left, right) => right.startedAt.getTime() - left.startedAt.getTime());
}

function testsWithin(tests: JsonRecord[], days: number, now: Date): Array<{ test: JsonRecord; startedAt: Date }> {
  const cutoff = daysAgo(now, days);
  return runTests(tests, now).filter((item) => item.startedAt.getTime() >= cutoff.getTime());
}

export async function collectKnowbe4Snapshot(
  client: Knowbe4DataClient,
  options: Knowbe4CollectOptions = {},
): Promise<Knowbe4Snapshot> {
  const scopes = new Set<Knowbe4Scope>(options.scopes && options.scopes.length > 0
    ? options.scopes
    : ["phishing", "training", "risk", "governance"]);
  const needs = (...required: Knowbe4Scope[]): boolean => required.some((scope) => scopes.has(scope));
  const now = options.now ?? new Date();
  const lookbackDays = clampInteger(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 3650);
  const inactiveDays = clampInteger(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650);
  const userLimit = clampInteger(options.userLimit, DEFAULT_USER_LIMIT, 1, 200_000);
  const enrollmentLimit = clampInteger(options.enrollmentLimit, DEFAULT_ENROLLMENT_LIMIT, 1, 1_000_000);
  const sampleLimit = clampInteger(options.securityTestSampleLimit, DEFAULT_SECURITY_TEST_SAMPLE_LIMIT, 0, 200);
  const phisherMessageLimit = clampInteger(options.phisherMessageLimit, DEFAULT_PHISHER_MESSAGE_LIMIT, 1, 100_000);
  const errors: string[] = [];

  const account = await collectSurface("account", {}, errors, () => client.getAccount());
  const accountRiskHistory = needs("phishing", "risk")
    ? await collectListing("account_risk_score_history", errors, DEFAULT_LIST_LIMIT, () => client.getAccountRiskScoreHistory(true))
    : skipped<JsonRecord[]>([]);
  const activeUsers = await collectListing("users", errors, userLimit, () => client.listUsers({ status: "active", limit: userLimit }), projectKnowbe4User);
  const groups = needs("phishing", "risk")
    ? await collectListing("groups", errors, DEFAULT_LIST_LIMIT, () => client.listGroups({ status: "active" }))
    : skipped<JsonRecord[]>([]);
  const phishingCampaigns = needs("phishing", "risk", "governance")
    ? await collectListing("phishing_campaigns", errors, DEFAULT_LIST_LIMIT, () => client.listPhishingCampaigns())
    : skipped<JsonRecord[]>([]);
  const securityTests = await collectListing("security_tests", errors, DEFAULT_LIST_LIMIT, () => client.listSecurityTests());

  let securityTestRecipients: Knowbe4Collected<Knowbe4SampledSecurityTest[]> = skipped([]);
  const securityTestRecipientFailures: Knowbe4RecipientReadFailure[] = [];
  const unsampledSecurityTestIds: string[] = [];
  if (needs("phishing", "training", "risk") && !securityTests.error) {
    const windowDays = Math.max(lookbackDays, needs("risk") ? inactiveDays : 0);
    const candidates = testsWithin(securityTests.data, windowDays, now);
    const sampled = candidates.slice(0, sampleLimit);
    for (const item of candidates.slice(sampleLimit)) {
      const id = testId(item.test);
      if (id) unsampledSecurityTestIds.push(id);
    }
    const samples: Knowbe4SampledSecurityTest[] = [];
    const recipientErrors: string[] = [];
    const failedEndpoints: string[] = [];
    const failedStatuses = new Set<number | null>();
    let recipientsTruncated = false;
    for (const item of sampled) {
      const id = testId(item.test);
      if (!id) continue;
      try {
        const listing = toListing(await client.listSecurityTestRecipients(id), DEFAULT_LIST_LIMIT);
        recipientsTruncated = recipientsTruncated || listing.truncated;
        samples.push({
          pst_id: id,
          campaign_id: asString(item.test.campaign_id),
          name: testName(item.test),
          started_at: item.startedAt.toISOString(),
          recipients: listing.items.map(projectRecipient),
          ...(listing.truncated ? { recipients_truncated: true } : {}),
        });
      } catch (error) {
        const message = errorMessage(error);
        recipientErrors.push(`security_test_recipients[${id}]: ${message}`);
        const endpoint = observedEndpoint(error);
        if (endpoint) failedEndpoints.push(endpoint);
        failedStatuses.add(observedStatus(error));
        securityTestRecipientFailures.push({ pst_id: id, endpoint: endpoint ?? null, http_status: observedStatus(error), error: message });
        unsampledSecurityTestIds.push(id);
      }
    }
    errors.push(...recipientErrors);
    // The per-test reads that failed are named individually (never the templated path) and share one status only
    // when every failure observed the same one.
    const singleStatus = failedStatuses.size === 1 ? [...failedStatuses][0] : null;
    securityTestRecipients = {
      ...collected(samples, recipientErrors.length > 0 ? recipientErrors.join("; ") : undefined),
      ...(recipientErrors.length > 0 ? { httpStatus: singleStatus } : {}),
      ...(failedEndpoints.length > 0 ? { endpoint: failedEndpoints.join(", ") } : {}),
      truncated: recipientsTruncated,
      limit: DEFAULT_LIST_LIMIT,
    };
  }

  const callbackSecurityTests = needs("governance")
    ? await collectListing("callback_security_tests", errors, DEFAULT_LIST_LIMIT, () => client.listSecurityTests({ campaignType: "callback" }))
    : skipped<JsonRecord[]>([]);
  const trainingCampaigns = needs("training", "risk", "governance")
    ? await collectListing("training_campaigns", errors, DEFAULT_LIST_LIMIT, () => client.listTrainingCampaigns())
    : skipped<JsonRecord[]>([]);
  const trainingEnrollments = needs("training", "risk")
    ? await collectListing("training_enrollments", errors, enrollmentLimit, () => client.listTrainingEnrollments({ limit: enrollmentLimit }))
    : skipped<JsonRecord[]>([]);
  const storePurchases = needs("training")
    ? await collectListing("store_purchases", errors, DEFAULT_LIST_LIMIT, () => client.listStorePurchases())
    : skipped<JsonRecord[]>([]);
  const trainingPolicies = needs("training")
    ? await collectListing("training_policies", errors, DEFAULT_LIST_LIMIT, () => client.listTrainingPolicies())
    : skipped<JsonRecord[]>([]);
  const phisherMessages = needs("phishing") && client.hasPhisherCredentials()
    ? await collectListing("phisher_messages", errors, phisherMessageLimit, () => client.listPhisherMessages({
      query: `reported_at:[${isoDay(daysAgo(now, lookbackDays))} TO *]`,
      limit: phisherMessageLimit,
    }))
    : skipped<JsonRecord[]>([]);

  return {
    collectedAt: now.toISOString(),
    scopes: [...scopes],
    account,
    accountRiskHistory,
    activeUsers,
    groups,
    phishingCampaigns,
    securityTests,
    securityTestRecipients,
    securityTestRecipientFailures,
    unsampledSecurityTestIds,
    userLimit,
    userLimitReached: truncatedFlag(activeUsers),
    enrollmentLimit,
    enrollmentLimitReached: truncatedFlag(trainingEnrollments),
    callbackSecurityTests,
    trainingCampaigns,
    trainingEnrollments,
    storePurchases,
    trainingPolicies,
    phisherMessages,
    errors,
  };
}

function controlById(number: number): Knowbe4ControlDefinition {
  const definition = KNOWBE4_CONTROLS.find((control) => control.number === number);
  if (!definition) throw new Error(`Unknown KnowBe4 control ${number}`);
  return definition;
}

export function knowbe4ControlMappings(number: number): string[] {
  const definition = controlById(number);
  return FRAMEWORK_KEYS.map((key) => `${FRAMEWORK_LABELS[key]} ${definition.frameworks[key]}`);
}

function findingId(number: number): string {
  return `KNOWBE4-${String(number).padStart(2, "0")}`;
}

function finding(
  number: number,
  severity: Knowbe4Finding["severity"],
  status: Knowbe4Finding["status"],
  summary: string,
  evidence?: JsonRecord,
  manualEvidence?: string,
): Knowbe4Finding {
  const definition = controlById(number);
  return {
    id: findingId(number),
    control: number,
    title: definition.title,
    severity,
    status,
    summary,
    evidence,
    mappings: knowbe4ControlMappings(number),
    manualEvidence,
  };
}

function inventoryGap(inventory: Knowbe4InventoryName, collection: Knowbe4Collected<unknown>, notChecked: string): Knowbe4InventoryGap {
  return {
    inventory,
    endpoint: inventoryEndpoint(inventory, collection),
    http_status: collection.httpStatus ?? null,
    error: collection.error ?? "the inventory was not read",
    not_checked: notChecked,
    collect_manually: INVENTORY_MANUAL_EVIDENCE[inventory],
  };
}

function inventoryGapCaveat(gap: Knowbe4InventoryGap): string {
  return `Unreadable inventory: ${gap.inventory} (${gap.endpoint}: ${gap.error}), so ${gap.not_checked}. Collect manually: ${gap.collect_manually}.`;
}

// An inventory the control cannot be judged without was not readable: the API cannot prove the control, so the
// finding is manual and names both the inventory and the console evidence that stands in for it.
function unavailableFinding(number: number, severity: Knowbe4Finding["severity"], inventory: Knowbe4InventoryName, snapshot: Knowbe4Snapshot): Knowbe4Finding {
  const definition = controlById(number);
  const collection = inventoryCollection(snapshot, inventory);
  const gap = inventoryGap(inventory, collection, `${definition.title.toLowerCase()} could not be evaluated from the API`);
  return finding(
    number,
    severity,
    "manual",
    inventoryGapCaveat(gap),
    { collection_error: gap.error, unreadable_inventories: [gap] },
    `Collect ${gap.collect_manually}.`,
  );
}

interface Knowbe4InventoryRead {
  inventory: Knowbe4InventoryName;
  /** What the finding could not check because the inventory was unreadable. */
  notChecked: string;
  /** An unreadable essential inventory makes the finding manual; otherwise it is warn. */
  essential?: boolean;
  /** Whether the verdict (not only the evidence) depends on the inventory; truncation only demotes verdict reads. */
  verdict?: boolean;
}

function truncationCaveat(item: Knowbe4TruncatedInventory): string {
  const cap = `${item.argument ?? "the collection cap"} (${item.limit ?? "unknown"})`;
  const raise = item.argument ? `; raise ${item.argument} to cover the full inventory` : "";
  return `Truncated listing: ${item.inventory} (${item.seen} of ${item.total ?? "unknown"} loaded, truncated at ${cap}), so this verdict only covers the records that were loaded${raise}.`;
}

/**
 * Rule 1 corollary and rule 10 gate for every finding that reads collected inventories: a passing verdict never
 * survives an unreadable inventory (manual when the inventory is essential, warn otherwise) or a truncated verdict
 * inventory, and the summary names the inventory, what was not checked, and the console evidence to collect.
 */
function withInventoryCaveats(item: Knowbe4Finding, snapshot: Knowbe4Snapshot, reads: Knowbe4InventoryRead[]): Knowbe4Finding {
  const gaps: Knowbe4InventoryGap[] = [];
  const truncated: Knowbe4TruncatedInventory[] = [];
  const truncatedVerdictReads: Knowbe4TruncatedInventory[] = [];
  let essentialGap = false;
  for (const read of reads) {
    const collection = inventoryCollection(snapshot, read.inventory);
    if (!collection.collected) continue;
    if (collection.error) {
      gaps.push(inventoryGap(read.inventory, collection, read.notChecked));
      essentialGap = essentialGap || Boolean(read.essential);
    } else if (collection.truncated) {
      const entry: Knowbe4TruncatedInventory = {
        inventory: read.inventory,
        seen: Array.isArray(collection.data) ? collection.data.length : 1,
        total: collection.total ?? null,
        limit: collection.limit ?? null,
        argument: INVENTORY_LIMIT_ARGUMENTS[read.inventory] ?? null,
      };
      truncated.push(entry);
      if (read.verdict ?? true) truncatedVerdictReads.push(entry);
    }
  }
  const verdictTruncated = truncatedVerdictReads.length > 0;

  const existingGaps = asRecordArray(item.evidence?.unreadable_inventories);
  const evidence: JsonRecord = {
    ...(item.evidence ?? {}),
    ...(reads.some((read) => read.inventory === "users") ? { user_limit: snapshot.userLimit, user_limit_reached: snapshot.userLimitReached } : {}),
    ...(gaps.length > 0 || existingGaps.length > 0 ? { unreadable_inventories: [...existingGaps, ...gaps] } : {}),
    ...(truncated.length > 0 ? { truncated_inventories: truncated } : {}),
  };
  if (gaps.length === 0 && truncated.length === 0) return { ...item, evidence };

  let status = item.status;
  if (status === "pass") {
    if (gaps.length > 0) status = essentialGap ? "manual" : "warn";
    else if (verdictTruncated) status = "warn";
  }
  // A truncated verdict inventory is always stated with seen versus total and the cap, whatever the verdict: a warn the
  // finding reached on its own from the partial read still has to say how much was read.
  const parts = [item.summary, ...gaps.map(inventoryGapCaveat)];
  if (verdictTruncated) parts.push(...truncatedVerdictReads.map(truncationCaveat));
  const manualEvidence = status === "manual"
    ? item.manualEvidence ?? `Collect ${gaps.map((gap) => gap.collect_manually).join("; ")}.`
    : item.manualEvidence;
  return { ...item, status, summary: parts.join(" "), evidence, manualEvidence };
}

// An empty user list is a data-access condition, not a clean population: anonymized KnowBe4 accounts cannot
// retrieve user data through the Reporting API, so controls computed over users must not pass on zero users.
function emptyUserListFinding(number: number, severity: Knowbe4Finding["severity"], subject: string, evidence: JsonRecord = {}): Knowbe4Finding {
  return finding(
    number,
    severity,
    "warn",
    `The Reporting API returned no active users, so ${subject} cannot be evaluated. Anonymized KnowBe4 accounts cannot retrieve user data through the API; confirm the account's anonymization setting and the API key before treating this control as met.`,
    { active_users: 0, user_list_empty: true, ...evidence },
  );
}

function userLabel(user: JsonRecord, redact: boolean): string {
  const email = asString(user.email);
  const id = recordId(user) ?? "unknown";
  if (redact) return pseudonymize(email ?? id);
  return email ?? id;
}

function sampleLabels(users: JsonRecord[], redact: boolean): string[] {
  return users.slice(0, SAMPLE_SIZE).map((user) => userLabel(user, redact));
}

function campaignGroups(campaign: JsonRecord): JsonRecord[] {
  return asRecordArray(campaign.groups);
}

function campaignTargetsAllUsers(campaign: JsonRecord): boolean {
  return campaignGroups(campaign).some((group) =>
    asNumber(group.group_id) === 0 || /^all users$/i.test(asString(group.name) ?? ""),
  );
}

function campaignGroupIds(campaign: JsonRecord): Set<string> {
  const ids = new Set<string>();
  for (const group of campaignGroups(campaign)) {
    const id = asString(group.group_id);
    if (id) ids.add(id);
  }
  return ids;
}

function campaignName(campaign: JsonRecord): string {
  return asString(campaign.name) ?? `campaign-${asString(campaign.campaign_id) ?? "unknown"}`;
}

const FAILURE_TIMESTAMP_KEYS = [
  "clicked_at",
  "replied_at",
  "attachment_opened_at",
  "macro_enabled_at",
  "data_entered_at",
  "qr_code_scanned",
];

function recipientFailureDate(recipient: JsonRecord): Date | undefined {
  const dates = FAILURE_TIMESTAMP_KEYS
    .map((key) => toDate(recipient[key]))
    .filter((value): value is Date => Boolean(value))
    .sort((left, right) => left.getTime() - right.getTime());
  return dates[0];
}

function recipientUser(recipient: JsonRecord): JsonRecord {
  return asObject(recipient.user) ?? {};
}

function recipientUserId(recipient: JsonRecord): string | undefined {
  return recordId(recipientUser(recipient));
}

function recipientDelivered(recipient: JsonRecord): boolean {
  return Boolean(toDate(recipient.delivered_at)) || (!toDate(recipient.bounced_at) && Boolean(toDate(recipient.scheduled_at)));
}

function sampledTestsWithin(snapshot: Knowbe4Snapshot, days: number, now: Date): Knowbe4SampledSecurityTest[] {
  const cutoff = daysAgo(now, days).getTime();
  return snapshot.securityTestRecipients.data.filter((sample) => {
    const startedAt = toDate(sample.started_at);
    return Boolean(startedAt && startedAt.getTime() >= cutoff && startedAt.getTime() <= now.getTime());
  });
}

function activeUserIds(snapshot: Knowbe4Snapshot): Set<string> {
  const ids = new Set<string>();
  for (const user of snapshot.activeUsers.data) {
    const id = recordId(user);
    if (id) ids.add(id);
  }
  return ids;
}

function weightedPhishPronePercent(tests: JsonRecord[]): number | undefined {
  let weightedTotal = 0;
  let weight = 0;
  for (const test of tests) {
    const ppp = decimalToPercent(test.phish_prone_percentage);
    const delivered = asNumber(test.delivered_count) ?? asNumber(test.scheduled_count) ?? 0;
    if (ppp === undefined || delivered <= 0) continue;
    weightedTotal += ppp * delivered;
    weight += delivered;
  }
  return weight > 0 ? roundTo(weightedTotal / weight, 2) : undefined;
}

function relevantErrors(snapshot: Knowbe4Snapshot, prefixes: string[]): string[] {
  return snapshot.errors.filter((error) => prefixes.some((prefix) => error.startsWith(prefix)));
}

function assessmentTitle(area: Knowbe4Scope): string {
  switch (area) {
    case "phishing":
      return "KnowBe4 phishing simulation program";
    case "training":
      return "KnowBe4 security awareness training program";
    case "risk":
      return "KnowBe4 user risk and coverage hygiene";
    case "governance":
      return "KnowBe4 account governance";
    default: {
      const exhaustive: never = area;
      throw new Error(`Unhandled KnowBe4 area: ${String(exhaustive)}`);
    }
  }
}

export function knowbe4ToolForArea(area: Knowbe4Scope): string {
  switch (area) {
    case "phishing":
      return "knowbe4_assess_phishing_program";
    case "training":
      return "knowbe4_assess_training_program";
    case "risk":
      return "knowbe4_assess_user_risk";
    case "governance":
      return "knowbe4_assess_account_governance";
    default: {
      const exhaustive: never = area;
      throw new Error(`Unhandled KnowBe4 area: ${String(exhaustive)}`);
    }
  }
}

function frameworkReportPath(key: Knowbe4FrameworkKey): string {
  switch (key) {
    case "fedramp":
      return "compliance/fedramp/fedramp_compliance_report.md";
    case "cmmc":
      return "compliance/cmmc/cmmc_compliance_report.md";
    case "soc2":
      return "compliance/soc2/soc2_compliance_report.md";
    case "cis_v8":
      return "compliance/cis_controls/cis_controls_v8_report.md";
    case "pci_dss":
      return "compliance/pci_dss/pci_dss_compliance_report.md";
    case "disa_stig":
      return "compliance/disa_stig/stig_compliance_checklist.md";
    case "irap":
      return "compliance/irap/irap_compliance_report.md";
    case "ismap":
      return "compliance/ismap/ismap_compliance_report.md";
    default: {
      const exhaustive: never = key;
      throw new Error(`Unhandled framework: ${String(exhaustive)}`);
    }
  }
}

function assessPhishingFrequency(snapshot: Knowbe4Snapshot, now: Date, maxGapDays: number, lookbackDays: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(1, "high", "security_tests", snapshot);
  const tests = runTests(snapshot.securityTests.data, now);
  const latest = tests[0];
  const daysSince = latest ? roundTo(daysBetween(latest.startedAt, now)) : undefined;
  const inLookback = testsWithin(snapshot.securityTests.data, lookbackDays, now).length;
  const status = !latest ? "fail" : daysSince !== undefined && daysSince <= maxGapDays ? "pass" : "fail";

  return withInventoryCaveats(finding(
    1,
    "high",
    status,
    !latest
      ? "No phishing security tests have ever run in this account."
      : status === "pass"
        ? `The most recent phishing security test started ${daysSince} days ago, within the ${maxGapDays}-day cadence policy.`
        : `The most recent phishing security test started ${daysSince} days ago, exceeding the ${maxGapDays}-day cadence policy.`,
    {
      latest_security_test: latest
        ? { pst_id: testId(latest.test), name: testName(latest.test), started_at: latest.startedAt.toISOString() }
        : null,
      days_since_last_test: daysSince ?? null,
      max_campaign_gap_days: maxGapDays,
      security_tests_in_lookback: whenComplete(snapshot.securityTests, inLookback),
      security_tests_read: snapshot.securityTests.data.length,
      lookback_days: lookbackDays,
    },
  ), snapshot, [{ inventory: "security_tests", notChecked: "the latest test date is unknown", essential: true }]);
}

/** How the sampled recipient reads ended: whether any loaded, and whether every test in the window was read in full. */
function recipientReadState(snapshot: Knowbe4Snapshot, samples: Knowbe4SampledSecurityTest[], testsInWindow: number): { anyRead: boolean; complete: boolean } {
  const collection = snapshot.securityTestRecipients;
  const anyRead = samples.length > 0 || (collection.collected && !collection.error && testsInWindow === 0);
  const complete = collection.collected && !collection.error && collection.truncated !== true && samples.length === testsInWindow;
  return { anyRead, complete };
}

const SECURITY_TEST_READ: Knowbe4InventoryRead = { inventory: "security_tests", notChecked: "security test results were not available", essential: true };
const USERS_READ: Knowbe4InventoryRead = { inventory: "users", notChecked: "the active user population was not available", essential: true };

function assessPhishingCoverage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCoveragePct: number, redact: boolean): Knowbe4Finding {
  const reads: Knowbe4InventoryRead[] = [
    SECURITY_TEST_READ,
    USERS_READ,
    { inventory: "security_test_recipients", notChecked: "recipients of the security tests whose results failed to load were not counted toward coverage" },
  ];
  if (snapshot.securityTests.error) return unavailableFinding(2, "high", "security_tests", snapshot);
  if (snapshot.activeUsers.error) return unavailableFinding(2, "high", "users", snapshot);
  const active = activeUserIds(snapshot);
  const testsInWindow = testsWithin(snapshot.securityTests.data, lookbackDays, now);
  // With no tests the fail below stands on the test data alone; only a measured coverage needs a user population.
  if (testsInWindow.length > 0 && snapshot.activeUsers.data.length === 0) {
    return withInventoryCaveats(emptyUserListFinding(2, "high", "phishing simulation coverage", {
      tested_users: 0,
      coverage_pct: null,
      min_coverage_pct: minCoveragePct,
      security_tests_in_window: testsInWindow.length,
    }), snapshot, reads);
  }
  const samples = sampledTestsWithin(snapshot, lookbackDays, now);
  const tested = new Set<string>();
  for (const sample of samples) {
    for (const recipient of sample.recipients) {
      const id = recipientUserId(recipient);
      if (id && active.has(id)) tested.add(id);
    }
  }
  const coverage = percentage(tested.size, active.size);
  const unsampled = testsInWindow.length - samples.length;
  const untested = snapshot.activeUsers.data.filter((user) => {
    const id = recordId(user);
    return Boolean(id && !tested.has(id));
  });
  // Coverage joins the user list with every recipient list in the window: a user is "untested" only when every test
  // was read in full, so a partial read renders the coverage unknown and names nobody as untested.
  const recipients = recipientReadState(snapshot, samples, testsInWindow.length);
  const complete = isComplete(snapshot.activeUsers) && recipients.complete;

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (testsInWindow.length === 0) {
    status = "fail";
    summary = `No phishing security tests ran in the last ${lookbackDays} days, so no active users were tested.`;
  } else if (samples.length === 0) {
    status = "warn";
    summary = `${testsInWindow.length} phishing security tests ran in the last ${lookbackDays} days but recipient results could not be read, so coverage is unknown.`;
  } else if (complete && coverage !== undefined && coverage >= minCoveragePct) {
    status = "pass";
    summary = `${coverage}% of ${active.size} active users received at least one phishing security test in the last ${lookbackDays} days (policy minimum ${minCoveragePct}%).`;
  } else if (!complete) {
    status = "warn";
    summary = `${tested.size} of the ${active.size} active users read appear in the ${samples.length} sampled security tests${unsampled > 0 ? `; ${unsampled} additional tests in the window were not sampled` : ""}, so coverage over the full population is unknown.`;
  } else {
    status = "fail";
    summary = `Only ${coverage ?? 0}% of ${active.size} active users were tested in the last ${lookbackDays} days (policy minimum ${minCoveragePct}%).`;
  }

  return withInventoryCaveats(finding(2, "high", status, summary, {
    active_users: whenComplete(snapshot.activeUsers, active.size),
    users_read: active.size,
    tested_users: complete ? tested.size : null,
    tested_users_in_read_samples: recipients.anyRead ? tested.size : null,
    coverage_pct: complete ? coverage ?? null : null,
    min_coverage_pct: minCoveragePct,
    security_tests_in_window: whenComplete(snapshot.securityTests, testsInWindow.length),
    sampled_security_tests: recipients.anyRead ? samples.map((sample) => sample.pst_id) : null,
    unsampled_security_tests: unsampled,
    recipient_reads_complete: recipients.anyRead ? recipients.complete : null,
    untested_user_sample: complete ? sampleLabels(untested, redact) : null,
  }), snapshot, reads);
}

function assessPhishPronePercentage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, maxPhishPronePct: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(6, "high", "security_tests", snapshot);
  const recent = testsWithin(snapshot.securityTests.data, lookbackDays, now).map((item) => item.test);
  const history = runTests(snapshot.securityTests.data, now).map((item) => item.test).reverse();
  const current = weightedPhishPronePercent(recent);
  // The per-user average is context only: never-tested users report 0%, so it cannot back a passing verdict.
  const userAverage = mean(snapshot.activeUsers.data.map((user) => asNumber(user.phish_prone_percentage)).filter((value): value is number => value !== undefined));
  const baseline = history.length >= MIN_TREND_TESTS ? weightedPhishPronePercent(history.slice(0, 3)) : undefined;
  const accountRisk = asNumber(snapshot.account.data.current_risk_score);

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (recent.length === 0) {
    status = "warn";
    summary = `No phishing security tests ran in the last ${lookbackDays} days, so the current phish-prone percentage cannot be verified from test results${userAverage === undefined ? "" : ` (the per-user average of ${roundTo(userAverage, 2)}% counts never-tested users as 0% and is not used for the verdict)`}.`;
  } else if (current === undefined) {
    status = "warn";
    summary = `${recent.length} phishing security tests ran in the last ${lookbackDays} days but none reported a phish-prone percentage with delivered counts, so the current rate cannot be verified.`;
  } else if (current > maxPhishPronePct) {
    status = "fail";
    summary = `The current phish-prone percentage is ${roundTo(current, 2)}%, above the ${maxPhishPronePct}% policy ceiling.`;
  } else if (baseline !== undefined && current > baseline) {
    status = "warn";
    summary = `The current phish-prone percentage (${roundTo(current, 2)}%) is under the ${maxPhishPronePct}% ceiling but above the program baseline of ${baseline}%.`;
  } else {
    status = "pass";
    summary = `The current phish-prone percentage is ${roundTo(current, 2)}%, within the ${maxPhishPronePct}% ceiling${baseline !== undefined ? ` and at or below the ${baseline}% baseline` : ""}.`;
  }

  return withInventoryCaveats(finding(6, "high", status, summary, {
    current_phish_prone_pct: current === undefined ? null : roundTo(current, 2),
    current_source: current === undefined ? "unverified" : "security_tests",
    // The per-user average is a population statistic, so it is unknown on a partial user list.
    user_average_phish_prone_pct: userAverage === undefined ? null : whenComplete(snapshot.activeUsers, roundTo(userAverage, 2)),
    baseline_phish_prone_pct: baseline === undefined ? null : whenComplete(snapshot.securityTests, baseline),
    max_phish_prone_pct: maxPhishPronePct,
    lookback_days: lookbackDays,
    security_tests_in_window: whenComplete(snapshot.securityTests, recent.length),
    security_tests_all_time: whenComplete(snapshot.securityTests, history.length),
    security_tests_read: snapshot.securityTests.data.length,
    account_current_risk_score: accountRisk ?? null,
  }), snapshot, [
    SECURITY_TEST_READ,
    { inventory: "users", notChecked: "the per-user phish-prone average was not computed", verdict: false },
    { inventory: "account", notChecked: "the account risk score was not attached", verdict: false },
  ]);
}

function assessFailureTrend(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(7, "medium", "security_tests", snapshot);
  const windowDays = lookbackDays * 2;
  const tests = testsWithin(snapshot.securityTests.data, windowDays, now)
    .reverse()
    .map((item) => ({ ...item, ppp: decimalToPercent(item.test.phish_prone_percentage) }))
    .filter((item): item is { test: JsonRecord; startedAt: Date; ppp: number } => item.ppp !== undefined);
  const riskHistory = snapshot.accountRiskHistory.data
    .map((point) => ({ score: asNumber(point.risk_score), date: asString(point.date) }))
    .filter((point): point is { score: number; date: string | undefined } => point.score !== undefined);

  const reads: Knowbe4InventoryRead[] = [
    SECURITY_TEST_READ,
    { inventory: "account_risk_score_history", notChecked: "the organization risk score history was not attached", verdict: false },
  ];
  if (tests.length < MIN_TREND_TESTS) {
    return withInventoryCaveats(finding(7, "medium", "warn", `Only ${tests.length} phishing security tests with results ran in the last ${windowDays} days; at least ${MIN_TREND_TESTS} are needed to evaluate a trend.`, {
      security_tests_considered: tests.length,
      window_days: windowDays,
      risk_score_history_points: whenComplete(snapshot.accountRiskHistory, riskHistory.length),
    }), snapshot, reads);
  }

  const midpoint = Math.floor(tests.length / 2);
  const earlier = mean(tests.slice(0, midpoint).map((item) => item.ppp)) ?? 0;
  const later = mean(tests.slice(midpoint).map((item) => item.ppp)) ?? 0;
  const delta = roundTo(later - earlier, 2);
  const status = delta > TREND_FAIL_DELTA_PCT ? "fail" : delta > TREND_WARN_DELTA_PCT ? "warn" : "pass";

  return withInventoryCaveats(finding(
    7,
    "medium",
    status,
    status === "pass"
      ? `Phish-prone results moved from ${roundTo(earlier, 2)}% to ${roundTo(later, 2)}% across ${tests.length} tests, which is stable or improving.`
      : `Phish-prone results worsened from ${roundTo(earlier, 2)}% to ${roundTo(later, 2)}% across ${tests.length} tests (+${delta} points).`,
    {
      security_tests_considered: tests.length,
      window_days: windowDays,
      earlier_mean_phish_prone_pct: roundTo(earlier, 2),
      later_mean_phish_prone_pct: roundTo(later, 2),
      delta_points: delta,
      series: tests.map((item) => ({ pst_id: testId(item.test), started_at: item.startedAt.toISOString(), phish_prone_pct: item.ppp })),
      risk_score_history_points: whenComplete(snapshot.accountRiskHistory, riskHistory.length),
      account_risk_score_first: riskHistory[0] ?? null,
      account_risk_score_last: riskHistory[riskHistory.length - 1] ?? null,
    },
  ), snapshot, reads);
}

function assessCampaignTargeting(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCoveragePct: number, requireFullTargeting: boolean): Knowbe4Finding {
  if (snapshot.phishingCampaigns.error) return unavailableFinding(9, "medium", "phishing_campaigns", snapshot);
  const cutoff = daysAgo(now, lookbackDays).getTime();
  const recentCampaignIds = new Set(
    testsWithin(snapshot.securityTests.data, lookbackDays, now)
      .map((item) => asString(item.test.campaign_id))
      .filter((value): value is string => Boolean(value)),
  );
  const activeCampaigns = snapshot.phishingCampaigns.data.filter((campaign) => {
    if (asBoolean(campaign.hidden) === true) return false;
    const id = asString(campaign.campaign_id);
    const lastRun = toDate(campaign.last_run);
    const status = asString(campaign.status) ?? "";
    return (id !== undefined && recentCampaignIds.has(id))
      || (lastRun !== undefined && lastRun.getTime() >= cutoff)
      || /active|scheduled|in progress/i.test(status);
  });
  const fullCampaigns = activeCampaigns.filter(campaignTargetsAllUsers);
  const partialCampaigns = activeCampaigns.filter((campaign) => !campaignTargetsAllUsers(campaign));
  // Without an All Users campaign the verdict is a coverage estimate over users and group member counts, so those
  // inventories become essential: an unreadable one leaves the estimate undefined and the control unprovable.
  if (partialCampaigns.length > 0 && fullCampaigns.length === 0) {
    if (snapshot.activeUsers.error) return unavailableFinding(9, "medium", "users", snapshot);
    if (snapshot.groups.error) return unavailableFinding(9, "medium", "groups", snapshot);
  }
  const activeUsers = activeUserIds(snapshot).size;
  const memberCounts = new Map<string, number>();
  for (const group of snapshot.groups.data) {
    const id = recordId(group);
    const count = asNumber(group.member_count);
    if (id && count !== undefined) memberCounts.set(id, count);
  }
  const targetedGroupIds = new Set<string>();
  for (const campaign of partialCampaigns) {
    for (const id of campaignGroupIds(campaign)) targetedGroupIds.add(id);
  }
  const targetedMembers = [...targetedGroupIds].reduce((total, id) => total + (memberCounts.get(id) ?? 0), 0);
  const estimatedCoverage = fullCampaigns.length > 0
    ? 100
    : activeUsers > 0
      ? Math.min(100, roundTo((targetedMembers / activeUsers) * 100))
      : undefined;

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (activeCampaigns.length === 0) {
    status = "fail";
    summary = `No phishing campaigns were active or ran in the last ${lookbackDays} days, so no users are targeted.`;
  } else if (fullCampaigns.length > 0) {
    status = "pass";
    summary = `${fullCampaigns.length} of ${activeCampaigns.length} active phishing campaigns target All Users, so every active user is in scope.`;
  } else if (estimatedCoverage !== undefined && estimatedCoverage >= minCoveragePct) {
    status = "pass";
    summary = `Active phishing campaigns target groups covering an estimated ${estimatedCoverage}% of active users (policy minimum ${minCoveragePct}%).`;
  } else if (!requireFullTargeting) {
    status = "pass";
    summary = `Active phishing campaigns target an estimated ${estimatedCoverage ?? 0}% of active users; the require_full_targeting policy is disabled, so partial targeting is accepted.`;
  } else {
    status = "fail";
    summary = `Active phishing campaigns target an estimated ${estimatedCoverage ?? 0}% of active users, below the ${minCoveragePct}% policy minimum.`;
  }

  // An All Users campaign proves coverage from the campaign list alone; otherwise the estimate joins users and groups.
  const estimateKnown = fullCampaigns.length > 0 || activeCampaigns.length === 0 || (isComplete(snapshot.activeUsers) && isComplete(snapshot.groups));
  return withInventoryCaveats(finding(9, "medium", status, summary, {
    active_campaigns: whenComplete(snapshot.phishingCampaigns, activeCampaigns.length),
    full_targeting_campaigns: fullCampaigns.map(campaignName),
    partial_targeting_campaigns: partialCampaigns.slice(0, SAMPLE_SIZE).map((campaign) => ({
      name: campaignName(campaign),
      groups: campaignGroups(campaign).map((group) => asString(group.name) ?? asString(group.group_id) ?? "group"),
    })),
    estimated_coverage_pct: estimateKnown ? estimatedCoverage ?? null : null,
    min_coverage_pct: minCoveragePct,
    require_full_targeting: requireFullTargeting,
    active_users: whenComplete(snapshot.activeUsers, activeUsers),
  }), snapshot, [
    { inventory: "phishing_campaigns", notChecked: "the campaign target groups were not available", essential: true },
    { inventory: "security_tests", notChecked: "campaigns were classed as active from their status and last run alone, not from the tests that actually ran" },
    { inventory: "users", notChecked: "the active user count behind the coverage estimate was not available" },
    { inventory: "groups", notChecked: "group member counts behind the coverage estimate were not available" },
  ]);
}

function assessReportRate(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minReportRatePct: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(19, "medium", "security_tests", snapshot);
  const recent = testsWithin(snapshot.securityTests.data, lookbackDays, now).map((item) => item.test);
  let delivered = 0;
  let reported = 0;
  for (const test of recent) {
    delivered += asNumber(test.delivered_count) ?? 0;
    reported += asNumber(test.reported_count) ?? 0;
  }
  const reportRate = percentage(reported, delivered);
  const phisher = snapshot.phisherMessages;
  // Inbox counts are population figures: unknown when the inbox was not read, partial (and so unknown) when the
  // read stopped at phisher_message_limit; only the number of messages actually read is stated then.
  const phisherEvidence: JsonRecord = phisher.collected
    ? {
      status: phisher.error ? "error" : "collected",
      error: phisher.error ?? null,
      http_status: phisher.error ? phisher.httpStatus ?? null : null,
      messages_in_window: whenComplete(phisher, phisher.data.length),
      messages_read: whenRead(phisher, phisher.data.length),
      messages_total: whenRead(phisher, phisher.total ?? null),
      truncated: truncatedFlag(phisher),
      message_limit: phisher.limit ?? null,
      by_category: whenComplete(phisher, countBy(phisher.data, "category")),
      by_action_status: whenComplete(phisher, countBy(phisher.data, "actionStatus")),
      unique_reporters: whenComplete(phisher, new Set(phisher.data.map((message) => asString(message.reportedBy)).filter(Boolean)).size),
    }
    : { status: "not_configured" };

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (recent.length === 0 || delivered === 0) {
    status = "warn";
    summary = `No delivered phishing security tests in the last ${lookbackDays} days, so the report rate cannot be measured.`;
  } else if (reportRate !== undefined && reportRate >= minReportRatePct) {
    status = "pass";
    summary = `${reportRate}% of ${delivered} delivered simulated phishing emails were reported with the Phish Alert Button (policy minimum ${minReportRatePct}%).`;
  } else if (reportRate !== undefined && reportRate >= minReportRatePct / 2) {
    status = "warn";
    summary = `${reportRate}% of ${delivered} delivered simulated phishing emails were reported, below the ${minReportRatePct}% policy minimum.`;
  } else {
    status = "fail";
    summary = `Only ${reportRate ?? 0}% of ${delivered} delivered simulated phishing emails were reported, far below the ${minReportRatePct}% policy minimum.`;
  }
  if (phisher.collected && !phisher.error) {
    const loaded = phisher.truncated
      ? ` (${phisher.data.length} of ${phisher.total ?? "unknown"} loaded, truncated at phisher_message_limit (${phisher.limit ?? "unknown"}))`
      : "";
    summary += ` PhishER inbox: ${phisher.data.length} user-reported messages in the window${loaded}.`;
  }

  return withInventoryCaveats(finding(19, "medium", status, summary, {
    delivered_count: whenComplete(snapshot.securityTests, delivered),
    reported_count: whenComplete(snapshot.securityTests, reported),
    report_rate_pct: reportRate === undefined ? null : whenComplete(snapshot.securityTests, reportRate),
    min_report_rate_pct: minReportRatePct,
    security_tests_in_window: whenComplete(snapshot.securityTests, recent.length),
    security_tests_read: snapshot.securityTests.data.length,
    phisher: phisherEvidence,
  }), snapshot, [
    SECURITY_TEST_READ,
    // PhishER enrichment is context: the rate itself comes from the security test counters, so the inbox only demotes when unreadable.
    { inventory: "phisher_messages", notChecked: "PhishER inbox categories and reporter counts were not cross-checked against the report rate", verdict: false },
  ]);
}

function countBy(records: JsonRecord[], key: string): JsonRecord {
  const counts: Record<string, number> = {};
  for (const record of records) {
    const value = asString(record[key]) ?? "unknown";
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

function assessScheduleRegularity(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, maxScheduleGapDays: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(20, "medium", "security_tests", snapshot);
  const allTests = runTests(snapshot.securityTests.data, now);
  if (allTests.length === 0) {
    return withInventoryCaveats(finding(20, "medium", "fail", "No phishing security tests have ever run, so there is no scheduling cadence to evaluate.", {
      security_tests_in_window: 0,
      security_tests_all_time: 0,
      lookback_days: lookbackDays,
      max_schedule_gap_days: maxScheduleGapDays,
    }), snapshot, [SECURITY_TEST_READ]);
  }
  const inWindow = testsWithin(snapshot.securityTests.data, lookbackDays, now).reverse();
  const cutoff = daysAgo(now, lookbackDays).getTime();
  // Anchor the series on the last test before the window so the gap into the window is measured too.
  const priorTest = allTests.find((item) => item.startedAt.getTime() < cutoff);
  const series = priorTest ? [priorTest, ...inWindow] : inWindow;
  const gaps: Array<{ from: string; to: string; days: number; boundary?: string }> = [];
  for (let index = 1; index < series.length; index += 1) {
    gaps.push({
      from: series[index - 1].startedAt.toISOString(),
      to: series[index].startedAt.toISOString(),
      days: roundTo(daysBetween(series[index - 1].startedAt, series[index].startedAt)),
    });
  }
  // A program that stopped running tests must not pass on historical gaps alone, so now is the final boundary.
  const latest = allTests[0];
  const daysSinceLatest = roundTo(daysBetween(latest.startedAt, now));
  gaps.push({ from: latest.startedAt.toISOString(), to: now.toISOString(), days: daysSinceLatest, boundary: "now" });
  const maxGap = Math.max(...gaps.map((gap) => gap.days));
  const averageGap = roundTo(mean(gaps.map((gap) => gap.days)) ?? 0);
  const overThreshold = gaps.filter((gap) => gap.days > maxScheduleGapDays);
  const status = overThreshold.length === 0 ? "pass" : "fail";
  const latestOverdue = daysSinceLatest > maxScheduleGapDays;

  return withInventoryCaveats(finding(
    20,
    "medium",
    status,
    status === "pass"
      ? `${inWindow.length} phishing security tests ran in the last ${lookbackDays} days with a maximum gap of ${maxGap} days including the ${daysSinceLatest} days since the latest test (policy maximum ${maxScheduleGapDays}); average gap ${averageGap} days.`
      : `${overThreshold.length} scheduling gaps exceeded ${maxScheduleGapDays} days (largest ${maxGap} days)${latestOverdue ? `, including the ${daysSinceLatest} days since the most recent test` : ""}, across ${inWindow.length} phishing security tests in the last ${lookbackDays} days.`,
    {
      security_tests_in_window: whenComplete(snapshot.securityTests, inWindow.length),
      security_tests_all_time: whenComplete(snapshot.securityTests, allTests.length),
      security_tests_read: allTests.length,
      lookback_days: lookbackDays,
      latest_test_started_at: latest.startedAt.toISOString(),
      days_since_latest_test: daysSinceLatest,
      max_gap_days: maxGap,
      average_gap_days: averageGap,
      max_schedule_gap_days: maxScheduleGapDays,
      gaps,
      gaps_over_threshold: overThreshold,
    },
  ), snapshot, [SECURITY_TEST_READ]);
}

export function assessKnowbe4PhishingProgram(
  snapshot: Knowbe4Snapshot,
  options: Knowbe4AssessmentOptions = {},
): Knowbe4AssessmentResult {
  const now = options.now ?? new Date();
  const redact = options.redactPii ?? false;
  const lookbackDays = clampInteger(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 3650);
  const maxCampaignGapDays = clampInteger(options.maxCampaignGapDays, DEFAULT_MAX_CAMPAIGN_GAP_DAYS, 1, 3650);
  const maxScheduleGapDays = clampInteger(options.maxScheduleGapDays, DEFAULT_MAX_SCHEDULE_GAP_DAYS, 1, 3650);
  const minCoveragePct = clampNumber(options.minCoveragePct, DEFAULT_MIN_COVERAGE_PCT, 0, 100);
  const maxPhishPronePct = clampNumber(options.maxPhishPronePct, DEFAULT_MAX_PHISH_PRONE_PCT, 0, 100);
  const minReportRatePct = clampNumber(options.minReportRatePct, DEFAULT_MIN_REPORT_RATE_PCT, 0, 100);
  const requireFullTargeting = options.requireFullTargeting ?? true;

  const findings = [
    assessPhishingFrequency(snapshot, now, maxCampaignGapDays, lookbackDays),
    assessPhishingCoverage(snapshot, now, lookbackDays, minCoveragePct, redact),
    assessPhishPronePercentage(snapshot, now, lookbackDays, maxPhishPronePct),
    assessFailureTrend(snapshot, now, lookbackDays),
    assessCampaignTargeting(snapshot, now, lookbackDays, minCoveragePct, requireFullTargeting),
    assessReportRate(snapshot, now, lookbackDays, minReportRatePct),
    assessScheduleRegularity(snapshot, now, lookbackDays, maxScheduleGapDays),
  ];

  const phishingInventories: Knowbe4InventoryName[] = ["account", "account_risk_score_history", "users", "groups", "phishing_campaigns", "security_tests", "security_test_recipients", "phisher_messages"];
  return {
    area: "phishing",
    title: assessmentTitle("phishing"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      active_users: whenComplete(snapshot.activeUsers, snapshot.activeUsers.data.length),
      users_read: whenRead(snapshot.activeUsers, snapshot.activeUsers.data.length),
      user_limit_reached: snapshot.userLimitReached,
      phishing_campaigns: whenComplete(snapshot.phishingCampaigns, snapshot.phishingCampaigns.data.length),
      security_tests: whenComplete(snapshot.securityTests, snapshot.securityTests.data.length),
      security_tests_in_lookback: whenComplete(snapshot.securityTests, testsWithin(snapshot.securityTests.data, lookbackDays, now).length),
      sampled_security_tests: sampledTestCount(snapshot),
      phisher_messages: whenComplete(snapshot.phisherMessages, snapshot.phisherMessages.data.length),
      phisher_messages_read: whenRead(snapshot.phisherMessages, snapshot.phisherMessages.data.length),
      inventories: inventoryStates(snapshot, phishingInventories),
      lookback_days: lookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "groups", "phishing_campaigns", "security_test", "phisher_messages"]),
  };
}

/** The number of security tests whose recipients were read; null when the recipient reads were not attempted or all failed. */
function sampledTestCount(snapshot: Knowbe4Snapshot): number | null {
  const collection = snapshot.securityTestRecipients;
  if (!collection.collected) return null;
  if (collection.error && collection.data.length === 0) return null;
  return collection.data.length;
}

/** The read state of each inventory an assessment summary counts, so a null count next to it can be traced to the read that did not complete. */
function inventoryStates(snapshot: Knowbe4Snapshot, names: Knowbe4InventoryName[]): JsonRecord[] {
  const rows = knowbe4CollectionStatus(snapshot).inventories;
  return names.map((name) => {
    const row = rows.find((entry) => entry.inventory === name) ?? {};
    return {
      inventory: name,
      endpoint: row.endpoint ?? null,
      status: row.status ?? null,
      read: row.collected ?? false,
      complete: row.complete ?? null,
      seen: row.seen ?? null,
      total: row.total ?? null,
      http_status: row.http_status ?? null,
    };
  });
}

function enrollmentUserId(enrollment: JsonRecord): string | undefined {
  return recordId(asObject(enrollment.user) ?? {});
}

function enrollmentCompleted(enrollment: JsonRecord): boolean {
  return /^(completed|passed)$/i.test(asString(enrollment.status) ?? "");
}

function enrollmentActivityDate(enrollment: JsonRecord): Date | undefined {
  return toDate(enrollment.completion_date) ?? toDate(enrollment.start_date);
}

function campaignEndDate(campaign: JsonRecord): Date | undefined {
  return toDate(campaign.end_date);
}

function campaignStartDate(campaign: JsonRecord): Date | undefined {
  return toDate(campaign.start_date);
}

function campaignCancelled(campaign: JsonRecord): boolean {
  return /cancelled|canceled/i.test(asString(campaign.status) ?? "");
}

function campaignCompletedOrEnded(campaign: JsonRecord, now: Date): boolean {
  const end = campaignEndDate(campaign);
  return /completed/i.test(asString(campaign.status) ?? "") || Boolean(end && end.getTime() <= now.getTime());
}

function campaignInWindow(campaign: JsonRecord, days: number, now: Date): boolean {
  const cutoff = daysAgo(now, days).getTime();
  const start = campaignStartDate(campaign);
  const end = campaignEndDate(campaign);
  const inProgress = /in progress|enrolling|created/i.test(asString(campaign.status) ?? "");
  return (start !== undefined && start.getTime() >= cutoff && start.getTime() <= now.getTime())
    || (end !== undefined && end.getTime() >= cutoff)
    || (inProgress && (end === undefined || end.getTime() >= cutoff));
}

function trainingCampaignId(campaign: JsonRecord): string | undefined {
  return asString(campaign.campaign_id);
}

function enrollmentCampaignId(enrollment: JsonRecord): string | undefined {
  return asString(enrollment.campaign_id);
}

function completionFromEnrollments(enrollments: JsonRecord[]): number | undefined {
  if (enrollments.length === 0) return undefined;
  return percentage(enrollments.filter(enrollmentCompleted).length, enrollments.length);
}

function assessTrainingCompletion(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCompletionPct: number, failCompletionPct: number, enrollmentLimitReached: boolean | null): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(3, "high", "training_campaigns", snapshot);
  const enrollmentsByCampaign = new Map<string, JsonRecord[]>();
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const id = enrollmentCampaignId(enrollment);
    if (!id) continue;
    const bucket = enrollmentsByCampaign.get(id) ?? [];
    bucket.push(enrollment);
    enrollmentsByCampaign.set(id, bucket);
  }

  const evaluated: Array<{ name: string; campaign_id: string | null; completion_pct: number; source: string; end_date: string | null }> = [];
  const truncated: Array<{ name: string; campaign_id: string | null; partial_completion_pct: number; enrollments_loaded: number; end_date: string | null }> = [];
  const unmeasured: string[] = [];
  for (const campaign of snapshot.trainingCampaigns.data) {
    if (campaignCancelled(campaign) || !campaignCompletedOrEnded(campaign, now) || !campaignInWindow(campaign, lookbackDays, now)) continue;
    const id = trainingCampaignId(campaign);
    const reported = asNumber(campaign.completion_percentage);
    const campaignEnrollments = id ? enrollmentsByCampaign.get(id) ?? [] : [];
    const computed = completionFromEnrollments(campaignEnrollments);
    const reportedUsable = reported !== undefined && reported >= 0;
    const completion = reportedUsable ? reported : computed;
    if (completion === undefined) {
      unmeasured.push(campaignName(campaign));
      continue;
    }
    if (!reportedUsable && enrollmentLimitReached === true) {
      // The -1 sentinel forces the enrollment fallback, and a truncated enrollment list cannot measure the campaign.
      truncated.push({
        name: campaignName(campaign),
        campaign_id: id ?? null,
        partial_completion_pct: roundTo(completion),
        enrollments_loaded: campaignEnrollments.length,
        end_date: campaignEndDate(campaign)?.toISOString() ?? null,
      });
      continue;
    }
    evaluated.push({
      name: campaignName(campaign),
      campaign_id: id ?? null,
      completion_pct: roundTo(completion),
      source: reportedUsable ? "completion_percentage" : "enrollments",
      end_date: campaignEndDate(campaign)?.toISOString() ?? null,
    });
  }

  const failing = evaluated.filter((item) => item.completion_pct < failCompletionPct);
  const warning = evaluated.filter((item) => item.completion_pct < minCompletionPct && item.completion_pct >= failCompletionPct);
  let status: Knowbe4Finding["status"];
  let summary: string;
  if (failing.length > 0) {
    status = "fail";
    summary = `${failing.length} of ${evaluated.length} completed training campaigns finished below ${failCompletionPct}% completion.`;
  } else if (warning.length > 0) {
    status = "warn";
    summary = `${warning.length} of ${evaluated.length} completed training campaigns finished between ${failCompletionPct}% and ${minCompletionPct}% completion.`;
  } else if (truncated.length > 0) {
    status = "warn";
    summary = `${truncated.length} completed training campaigns report the -1 completion sentinel and the enrollment list was truncated at enrollment_limit (${snapshot.enrollmentLimit}), so their completion cannot be measured: ${truncated.map((item) => item.name).join(", ")}. Raise enrollment_limit or export the campaign report from the console.`;
  } else if (unmeasured.length > 0) {
    // A campaign the API reports as "too large to calculate" with no enrollments loaded for it is not shown to meet the target.
    status = "warn";
    summary = `${unmeasured.length} completed training campaigns report the -1 completion sentinel and no enrollments were loaded for them, so their completion cannot be measured: ${unmeasured.join(", ")}${evaluated.length > 0 ? `; the other ${evaluated.length} met the ${minCompletionPct}% completion target` : ""}. Export the campaign report from the console.`;
  } else if (evaluated.length === 0) {
    status = "warn";
    summary = `No completed or ended training campaigns with measurable completion were found in the last ${lookbackDays} days.`;
  } else {
    status = "pass";
    summary = `All ${evaluated.length} completed training campaigns in the last ${lookbackDays} days met the ${minCompletionPct}% completion target.`;
  }

  return withInventoryCaveats(finding(3, "high", status, summary, {
    campaigns_evaluated: evaluated,
    // Which campaigns fell back to a truncated enrollment list is only known once the enrollment list was read at all.
    campaigns_with_truncated_enrollments: whenRead(snapshot.trainingEnrollments, truncated),
    campaigns_without_measurable_completion: unmeasured,
    enrollment_limit_reached: enrollmentLimitReached,
    min_completion_pct: minCompletionPct,
    fail_completion_pct: failCompletionPct,
    training_lookback_days: lookbackDays,
  }), snapshot, [
    TRAINING_CAMPAIGN_READ,
    // Enrollments only back the -1 sentinel fallback, which handles its own truncation above; an unreadable list still demotes.
    { inventory: "training_enrollments", notChecked: "campaigns reporting the -1 completion sentinel could not be measured from enrollments", verdict: false },
  ]);
}

const TRAINING_CAMPAIGN_READ: Knowbe4InventoryRead = { inventory: "training_campaigns", notChecked: "training campaign content, dates, and completion were not available", essential: true };
const ENROLLMENT_READ: Knowbe4InventoryRead = { inventory: "training_enrollments", notChecked: "training enrollments were not available", essential: true };

function assessEnrollmentTimeliness(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, graceDays: number, enrollmentLimitReached: boolean | null, redact: boolean): Knowbe4Finding {
  const reads: Knowbe4InventoryRead[] = [USERS_READ, ENROLLMENT_READ];
  if (snapshot.activeUsers.error) return unavailableFinding(4, "medium", "users", snapshot);
  if (snapshot.trainingEnrollments.error) return unavailableFinding(4, "medium", "training_enrollments", snapshot);
  if (snapshot.activeUsers.data.length === 0) {
    return withInventoryCaveats(emptyUserListFinding(4, "medium", "training enrollment timeliness for new users", {
      new_users_evaluated: 0,
      enrollment_grace_days: graceDays,
      training_lookback_days: lookbackDays,
      enrollment_limit_reached: enrollmentLimitReached,
    }), snapshot, reads);
  }
  // "No enrollment within the grace period" is only shown for a user when every enrollment could have been read.
  const enrollmentsComplete = isComplete(snapshot.trainingEnrollments);
  const populationComplete = enrollmentsComplete && isComplete(snapshot.activeUsers);
  const earliestEnrollment = new Map<string, Date>();
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const userId = enrollmentUserId(enrollment);
    const date = toDate(enrollment.enrollment_date) ?? toDate(enrollment.start_date);
    if (!userId || !date) continue;
    const existing = earliestEnrollment.get(userId);
    if (!existing || date.getTime() < existing.getTime()) earliestEnrollment.set(userId, date);
  }

  const cutoff = daysAgo(now, lookbackDays).getTime();
  const graceCutoff = daysAgo(now, graceDays).getTime();
  const newUsers = snapshot.activeUsers.data.filter((user) => {
    const joined = toDate(user.joined_on);
    return Boolean(joined && joined.getTime() >= cutoff && joined.getTime() <= graceCutoff);
  });
  const late = newUsers.filter((user) => {
    const id = recordId(user);
    const joined = toDate(user.joined_on);
    if (!id || !joined) return false;
    const enrolled = earliestEnrollment.get(id);
    return !enrolled || daysBetween(joined, enrolled) > graceDays;
  });
  const latePct = percentage(late.length, newUsers.length);

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (newUsers.length === 0) {
    status = "pass";
    summary = `No users joined between ${lookbackDays} and ${graceDays} days ago, so there are no enrollment deadlines to evaluate.`;
  } else if (late.length === 0) {
    status = "pass";
    summary = `All ${newUsers.length} users who joined in the last ${lookbackDays} days were enrolled in training within ${graceDays} days.`;
  } else if (!enrollmentsComplete) {
    // A missing enrollment in a truncated list is not a missing enrollment, so nobody is named late from it.
    status = "warn";
    summary = `${late.length} of ${newUsers.length} recently joined users have no training enrollment within ${graceDays} days among the ${snapshot.trainingEnrollments.data.length} enrollments loaded; the enrollment listing was truncated at enrollment_limit (${snapshot.enrollmentLimit}), so their enrollments may not have been read and they are not asserted late.`;
  } else if (latePct !== undefined && latePct <= 5) {
    status = "warn";
    summary = `${late.length} of ${newUsers.length} recently joined users had no training enrollment within ${graceDays} days.`;
  } else {
    status = "fail";
    summary = `${late.length} of ${newUsers.length} recently joined users (${latePct}%) had no training enrollment within ${graceDays} days of joining.`;
  }

  return withInventoryCaveats(finding(4, "medium", status, summary, {
    new_users_evaluated: whenComplete(snapshot.activeUsers, newUsers.length),
    new_users_read: newUsers.length,
    late_or_missing_enrollments: populationComplete ? late.length : null,
    late_or_missing_enrollments_among_read_users: enrollmentsComplete ? late.length : null,
    late_pct: populationComplete ? latePct ?? null : null,
    violation_observed: violationFlag([snapshot.activeUsers, snapshot.trainingEnrollments], enrollmentsComplete ? late.length : 0),
    enrollment_grace_days: graceDays,
    training_lookback_days: lookbackDays,
    enrollment_limit_reached: enrollmentLimitReached,
    late_user_sample: enrollmentsComplete ? sampleLabels(late, redact) : null,
  }), snapshot, reads);
}

function assessRemedialTraining(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, remedialWindowDays: number, redact: boolean): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(10, "medium", "security_tests", snapshot);
  if (snapshot.trainingEnrollments.error) return unavailableFinding(10, "medium", "training_enrollments", snapshot);
  const enrollmentsByUser = new Map<string, Date[]>();
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const userId = enrollmentUserId(enrollment);
    const date = toDate(enrollment.enrollment_date) ?? toDate(enrollment.start_date);
    if (!userId || !date) continue;
    const bucket = enrollmentsByUser.get(userId) ?? [];
    bucket.push(date);
    enrollmentsByUser.set(userId, bucket);
  }

  const testsInWindow = testsWithin(snapshot.securityTests.data, lookbackDays, now);
  const samples = sampledTestsWithin(snapshot, lookbackDays, now);
  const unsampled = Math.max(0, testsInWindow.length - samples.length);
  const failures = new Map<string, { user: JsonRecord; failedAt: Date }>();
  for (const sample of samples) {
    for (const recipient of sample.recipients) {
      const failedAt = recipientFailureDate(recipient);
      const userId = recipientUserId(recipient);
      if (!failedAt || !userId) continue;
      const existing = failures.get(userId);
      if (!existing || failedAt.getTime() < existing.failedAt.getTime()) {
        failures.set(userId, { user: recipientUser(recipient), failedAt });
      }
    }
  }

  const evaluable = [...failures.entries()].filter(([, item]) => daysBetween(item.failedAt, now) >= remedialWindowDays);
  const remediated = evaluable.filter(([userId, item]) =>
    (enrollmentsByUser.get(userId) ?? []).some((date) => date.getTime() >= item.failedAt.getTime() - DAY_MS),
  );
  const unremediated = evaluable.filter(([userId]) => !remediated.some(([remediatedId]) => remediatedId === userId));
  const remediatedPct = percentage(remediated.length, evaluable.length);
  const autoEnrollCampaigns = snapshot.trainingCampaigns.data
    .filter((campaign) => asBoolean(campaign.auto_enroll) === true && !campaignCancelled(campaign) && !campaignCompletedOrEnded(campaign, now))
    .map(campaignName);
  // A failed user is "unremediated" only when every enrollment could have been read; the failures themselves are
  // real observations, but the population of failures is only known once every test in the window was read.
  const enrollmentsComplete = isComplete(snapshot.trainingEnrollments);
  const recipients = recipientReadState(snapshot, samples, testsInWindow.length);

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (samples.length === 0) {
    status = "warn";
    summary = testsInWindow.length === 0
      ? `No phishing security tests ran in the last ${lookbackDays} days, so remedial training follow-up could not be verified.`
      : `None of the ${testsInWindow.length} phishing security tests in the last ${lookbackDays} days had recipient results available, so remedial training follow-up could not be verified.`;
  } else if (evaluable.length === 0) {
    status = failures.size === 0 && unsampled === 0 ? "pass" : "warn";
    summary = failures.size === 0
      ? `No users failed the ${samples.length} sampled phishing security tests, so no remedial training was due${unsampled > 0 ? `; ${unsampled} additional tests in the window were not sampled, so failures may be missing` : ""}.`
      : `${failures.size} users failed sampled tests within the last ${remedialWindowDays} days; their remedial enrollment window is still open.`;
  } else if (!enrollmentsComplete && unremediated.length > 0) {
    status = "warn";
    summary = `${unremediated.length} of ${evaluable.length} users who failed a sampled phishing test have no training enrollment after the failure among the ${snapshot.trainingEnrollments.data.length} enrollments loaded; the enrollment listing was truncated at enrollment_limit (${snapshot.enrollmentLimit}), so their remedial enrollments may not have been read and they are not asserted unremediated.`;
  } else if (remediatedPct !== undefined && remediatedPct >= 90 && unsampled > 0) {
    // Mirror controls 2 and 18: a clean result on a partial sample cannot pass outright.
    status = "warn";
    summary = `${remediated.length} of ${evaluable.length} users who failed a sampled phishing test (${remediatedPct}%) were enrolled in training after the failure, but ${unsampled} of ${testsInWindow.length} tests in the window were not sampled, so unremediated failures may be missing.`;
  } else if (remediatedPct !== undefined && remediatedPct >= 90) {
    status = "pass";
    summary = `${remediated.length} of ${evaluable.length} users who failed a sampled phishing test (${remediatedPct}%) were enrolled in training after the failure across all ${samples.length} tests in the window.`;
  } else if (remediatedPct !== undefined && remediatedPct >= 50) {
    status = "warn";
    summary = `Only ${remediated.length} of ${evaluable.length} users who failed a sampled phishing test (${remediatedPct}%) were enrolled in training after the failure.`;
  } else {
    status = "fail";
    summary = `${unremediated.length} of ${evaluable.length} users who failed a sampled phishing test have no training enrollment after the failure.`;
  }

  return withInventoryCaveats(finding(10, "medium", status, summary, {
    security_tests_in_window: whenComplete(snapshot.securityTests, testsInWindow.length),
    sampled_security_tests: samples.map((sample) => sample.pst_id),
    unsampled_security_tests: unsampled,
    recipient_reads_complete: recipients.anyRead ? recipients.complete : null,
    failed_users_in_window: recipients.complete ? failures.size : null,
    failed_users_in_sampled_tests: failures.size,
    failed_users_evaluated: evaluable.length,
    remediated_users: remediated.length,
    unremediated_users: enrollmentsComplete ? unremediated.length : null,
    remediated_pct: enrollmentsComplete ? remediatedPct ?? null : null,
    violation_observed: violationFlag([enrollmentsComplete, recipients.complete], enrollmentsComplete ? unremediated.length : 0),
    remedial_window_days: remedialWindowDays,
    auto_enroll_training_campaigns: whenRead(snapshot.trainingCampaigns, autoEnrollCampaigns),
    unremediated_user_sample: enrollmentsComplete
      ? unremediated.slice(0, SAMPLE_SIZE).map(([, item]) => ({
        user: userLabel(item.user, redact),
        failed_at: item.failedAt.toISOString(),
      }))
      : null,
  }), snapshot, [
    SECURITY_TEST_READ,
    ENROLLMENT_READ,
    { inventory: "security_test_recipients", notChecked: "failures in the security tests whose recipient results did not load were not evaluated for remediation" },
    { inventory: "training_campaigns", notChecked: "auto-enroll remedial campaigns were not listed", verdict: false },
  ]);
}

function campaignContentItems(campaign: JsonRecord): JsonRecord[] {
  return asRecordArray(campaign.content);
}

function storePurchaseId(item: JsonRecord): string | undefined {
  return asString(item.store_purchase_id) ?? asString(item.store_purchased_id);
}

function assessContentCurrency(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, maxContentAgeDays: number): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(11, "low", "training_campaigns", snapshot);
  const retiredPurchases = new Set<string>();
  const catalogPublishDates = new Map<string, Date>();
  for (const purchase of snapshot.storePurchases.data) {
    const id = storePurchaseId(purchase);
    if (!id) continue;
    if (asBoolean(purchase.retired) === true) retiredPurchases.add(id);
    const published = toDate(purchase.publish_date);
    if (published) catalogPublishDates.set(id, published);
  }
  const cutoff = daysAgo(now, maxContentAgeDays).getTime();
  const stale: Array<{ campaign: string; module: string; publish_date: string | null }> = [];
  const retired: Array<{ campaign: string; module: string }> = [];
  const undated: Array<{ campaign: string; module: string }> = [];
  let reviewed = 0;
  let dated = 0;
  for (const campaign of snapshot.trainingCampaigns.data) {
    if (campaignCancelled(campaign) || !campaignInWindow(campaign, lookbackDays, now)) continue;
    for (const item of campaignContentItems(campaign)) {
      if (!/store purchase/i.test(asString(item.content_type) ?? "store purchase")) continue;
      reviewed += 1;
      const moduleName = asString(item.name) ?? "module";
      const id = storePurchaseId(item);
      if (asBoolean(item.retired) === true || (id && retiredPurchases.has(id))) {
        retired.push({ campaign: campaignName(campaign), module: moduleName });
        continue;
      }
      const published = toDate(item.publish_date) ?? (id ? catalogPublishDates.get(id) : undefined);
      if (!published) {
        // An undated module cannot be shown to be current, so it must not count as fresh.
        undated.push({ campaign: campaignName(campaign), module: moduleName });
        continue;
      }
      dated += 1;
      if (published.getTime() < cutoff) {
        stale.push({ campaign: campaignName(campaign), module: moduleName, publish_date: published.toISOString() });
      }
    }
  }

  // Retirement and publish dates come from the campaign content or the ModStore catalog: a module found retired or
  // stale is a real observation, but "none retired" and "undated" need the catalog to have been read in full.
  const catalogRead = isRead(snapshot.storePurchases);
  let status: Knowbe4Finding["status"];
  let summary: string;
  if (reviewed === 0) {
    status = "warn";
    summary = `No store-purchased training modules are assigned in campaigns from the last ${lookbackDays} days.`;
  } else if (retired.length > 0) {
    status = "fail";
    summary = `${retired.length} assigned training modules are retired by the publisher and should be replaced.`;
  } else if (stale.length > 0 || undated.length > 0) {
    status = "warn";
    const parts: string[] = [];
    if (stale.length > 0) parts.push(`${stale.length} were published more than ${maxContentAgeDays} days ago`);
    if (undated.length > 0) {
      parts.push(catalogRead
        ? `${undated.length} have no publish date in the Reporting API or store catalog, so their currency cannot be verified`
        : `${undated.length} have no publish date in the campaign content and the ModStore catalog was not read, so their currency cannot be verified`);
    }
    summary = `Of ${reviewed} assigned training modules, ${parts.join(" and ")}.`;
  } else {
    status = "pass";
    summary = catalogRead
      ? `All ${reviewed} assigned training modules have publish dates within the last ${maxContentAgeDays} days and none are retired.`
      : `All ${reviewed} assigned training modules carry campaign-content publish dates within the last ${maxContentAgeDays} days and none are marked retired in the campaign content; the ModStore catalog was not read, so publisher retirement was not cross-checked.`;
  }

  return withInventoryCaveats(finding(11, "low", status, summary, {
    modules_reviewed: reviewed,
    modules_with_publish_date: whenComplete(snapshot.storePurchases, dated),
    retired_modules: observedList([snapshot.storePurchases], retired.slice(0, SAMPLE_SIZE)),
    stale_modules: observedList([snapshot.storePurchases], stale.slice(0, SAMPLE_SIZE)),
    undated_module_count: whenComplete(snapshot.storePurchases, undated.length),
    undated_modules: whenComplete(snapshot.storePurchases, undated.slice(0, SAMPLE_SIZE)),
    violation_observed: violationFlag([snapshot.storePurchases], retired.length + stale.length),
    max_content_age_days: maxContentAgeDays,
    training_lookback_days: lookbackDays,
  }), snapshot, [
    TRAINING_CAMPAIGN_READ,
    { inventory: "store_purchases", notChecked: "assigned modules were not cross-checked against the ModStore catalog for retirement and publish dates" },
  ]);
}

const COMPLIANCE_TOPIC_PATTERN = /\b(hipaa|pci|gdpr|sox|ferpa|ccpa|cpra|glba|cmmc|nist|iso\s?27001|fedramp|privacy|compliance|acceptable use|insider threat)\b/i;

function assessComplianceModules(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCompletionPct: number, requiredTopics: string[], enrollmentLimitReached: boolean | null): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(17, "medium", "training_campaigns", snapshot);
  const enrollmentList = snapshot.trainingEnrollments;
  const enrollmentsUnavailable = !isRead(enrollmentList);
  const assignedModules = new Map<string, Set<string>>();
  for (const campaign of snapshot.trainingCampaigns.data) {
    if (campaignCancelled(campaign) || !campaignInWindow(campaign, lookbackDays, now)) continue;
    for (const item of campaignContentItems(campaign)) {
      const moduleName = asString(item.name);
      if (!moduleName) continue;
      const campaigns = assignedModules.get(moduleName) ?? new Set<string>();
      campaigns.add(campaignName(campaign));
      assignedModules.set(moduleName, campaigns);
    }
  }
  const enrollmentsByModule = new Map<string, JsonRecord[]>();
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const moduleName = asString(enrollment.module_name);
    if (!moduleName) continue;
    const bucket = enrollmentsByModule.get(moduleName) ?? [];
    bucket.push(enrollment);
    enrollmentsByModule.set(moduleName, bucket);
  }

  const topics = requiredTopics.length > 0
    ? requiredTopics.map((topic) => ({ topic, matcher: (name: string) => name.toLowerCase().includes(topic.toLowerCase()) }))
    : [{ topic: "compliance-themed content", matcher: (name: string) => COMPLIANCE_TOPIC_PATTERN.test(name) }];

  const topicResults = topics.map(({ topic, matcher }) => {
    const modules = [...assignedModules.keys()].filter(matcher);
    const enrollments = modules.flatMap((moduleName) => enrollmentsByModule.get(moduleName) ?? []);
    return {
      topic,
      modules,
      campaigns: [...new Set(modules.flatMap((moduleName) => [...(assignedModules.get(moduleName) ?? [])]))],
      loaded: enrollments.length,
      completion: completionFromEnrollments(enrollments),
    };
  });
  const missing = topicResults.filter((item) => item.modules.length === 0);
  // Assigned but never enrolled means nobody can have completed the topic, so it cannot pass.
  const unenrolled = topicResults.filter((item) => item.modules.length > 0 && item.loaded === 0);
  const lowCompletion = topicResults.filter((item) => item.completion !== undefined && item.completion < minCompletionPct);
  const enrollmentDataPartial = !isComplete(enrollmentList);
  const topicList = (items: typeof topicResults): string => items.map((item) => item.topic).join(", ");

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (missing.length > 0) {
    status = requiredTopics.length > 0 ? "fail" : "warn";
    summary = requiredTopics.length > 0
      ? `Required compliance topics with no assigned training module in the last ${lookbackDays} days: ${topicList(missing)}.`
      : `No compliance-themed training modules were assigned in the last ${lookbackDays} days; pass required_compliance_topics to assert the modules your policy requires.`;
  } else if (unenrolled.length > 0 && requiredTopics.length > 0 && !enrollmentDataPartial) {
    status = "fail";
    summary = `Required compliance topics are assigned in campaigns but have zero training enrollments, so no user has completed them: ${topicList(unenrolled)}.`;
  } else if (unenrolled.length > 0) {
    status = "warn";
    summary = enrollmentDataPartial
      ? `Compliance topics are assigned but no enrollments were loaded for ${topicList(unenrolled)}; enrollment data is ${enrollmentsUnavailable ? "unavailable" : "truncated at enrollment_limit"}, so completion could not be verified.`
      : `Compliance-themed modules are assigned but have zero training enrollments, so nobody has completed them: ${topicList(unenrolled)}.`;
  } else if (lowCompletion.length > 0) {
    status = "warn";
    summary = `Compliance modules are assigned but completion is below ${minCompletionPct}% for: ${lowCompletion.map((item) => `${item.topic} (${item.completion}%)`).join(", ")}${enrollmentDataPartial ? `; the figures cover only the ${enrollmentList.data.length} enrollments loaded before the listing was truncated at enrollment_limit (${snapshot.enrollmentLimit})` : ""}.`;
  } else if (enrollmentDataPartial) {
    // Completion figures computed over a truncated enrollment list cannot back a passing verdict.
    status = "warn";
    summary = `Compliance training modules are assigned and enrolled for ${topicList(topicResults)}, but enrollment data is ${enrollmentsUnavailable ? "unavailable" : `truncated at enrollment_limit (${snapshot.enrollmentLimit})`}, so the completion figures cover only the loaded enrollments and cannot be verified.`;
  } else {
    status = "pass";
    summary = `Compliance training modules are assigned and enrolled for ${topicList(topicResults)} with completion at or above ${minCompletionPct}%.`;
  }

  return withInventoryCaveats(finding(17, "medium", status, summary, {
    required_compliance_topics: requiredTopics,
    // Population figures need the whole enrollment list; the "_loaded" figures describe only the records read.
    topics: topicResults.map((item) => ({
      topic: item.topic,
      assigned_modules: item.modules,
      campaigns: item.campaigns,
      enrollments: whenComplete(enrollmentList, item.loaded),
      enrollments_loaded: whenRead(enrollmentList, item.loaded),
      completion_pct: whenComplete(enrollmentList, item.completion ?? null),
      completion_pct_loaded: whenRead(enrollmentList, item.completion ?? null),
    })),
    topics_without_enrollments: whenComplete(enrollmentList, unenrolled.map((item) => item.topic)),
    topics_without_loaded_enrollments: whenRead(enrollmentList, unenrolled.map((item) => item.topic)),
    min_completion_pct: minCompletionPct,
    training_lookback_days: lookbackDays,
    enrollments_available: !enrollmentsUnavailable,
    enrollment_limit_reached: enrollmentLimitReached,
    completion_data_partial: enrollmentDataPartial,
    uploaded_policies: whenComplete(snapshot.trainingPolicies, snapshot.trainingPolicies.data.length),
  }), snapshot, [
    TRAINING_CAMPAIGN_READ,
    // Completion over enrollments never passes while the list is unreadable or truncated (handled above), so the gate only annotates.
    { inventory: "training_enrollments", notChecked: "completion of the assigned compliance modules could not be measured" },
    { inventory: "training_policies", notChecked: "uploaded policy documents were not counted alongside the compliance modules", verdict: false },
  ]);
}

export function assessKnowbe4TrainingProgram(
  snapshot: Knowbe4Snapshot,
  options: Knowbe4AssessmentOptions = {},
): Knowbe4AssessmentResult {
  const now = options.now ?? new Date();
  const redact = options.redactPii ?? false;
  const lookbackDays = clampInteger(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 3650);
  const trainingLookbackDays = clampInteger(options.trainingLookbackDays, DEFAULT_TRAINING_LOOKBACK_DAYS, 1, 3650);
  const minCompletionPct = clampNumber(options.minCompletionPct, DEFAULT_MIN_COMPLETION_PCT, 0, 100);
  const failCompletionPct = Math.min(clampNumber(options.failCompletionPct, DEFAULT_FAIL_COMPLETION_PCT, 0, 100), minCompletionPct);
  const graceDays = clampInteger(options.enrollmentGraceDays, DEFAULT_ENROLLMENT_GRACE_DAYS, 1, 365);
  const remedialWindowDays = clampInteger(options.remedialWindowDays, DEFAULT_REMEDIAL_WINDOW_DAYS, 1, 365);
  const maxContentAgeDays = clampInteger(options.maxContentAgeDays, DEFAULT_MAX_CONTENT_AGE_DAYS, 1, 3650);
  const requiredTopics = options.requiredComplianceTopics ?? [];
  const enrollmentLimitReached = snapshot.enrollmentLimitReached;

  const findings = [
    assessTrainingCompletion(snapshot, now, trainingLookbackDays, minCompletionPct, failCompletionPct, enrollmentLimitReached),
    assessEnrollmentTimeliness(snapshot, now, trainingLookbackDays, graceDays, enrollmentLimitReached, redact),
    assessRemedialTraining(snapshot, now, lookbackDays, remedialWindowDays, redact),
    assessContentCurrency(snapshot, now, trainingLookbackDays, maxContentAgeDays),
    assessComplianceModules(snapshot, now, trainingLookbackDays, minCompletionPct, requiredTopics, enrollmentLimitReached),
  ];

  const trainingInventories: Knowbe4InventoryName[] = ["account", "users", "security_tests", "security_test_recipients", "training_campaigns", "training_enrollments", "store_purchases", "training_policies"];
  return {
    area: "training",
    title: assessmentTitle("training"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      active_users: whenComplete(snapshot.activeUsers, snapshot.activeUsers.data.length),
      users_read: whenRead(snapshot.activeUsers, snapshot.activeUsers.data.length),
      training_campaigns: whenComplete(snapshot.trainingCampaigns, snapshot.trainingCampaigns.data.length),
      training_enrollments: whenComplete(snapshot.trainingEnrollments, snapshot.trainingEnrollments.data.length),
      training_enrollments_read: whenRead(snapshot.trainingEnrollments, snapshot.trainingEnrollments.data.length),
      enrollment_limit_reached: enrollmentLimitReached,
      user_limit_reached: snapshot.userLimitReached,
      store_purchases: whenComplete(snapshot.storePurchases, snapshot.storePurchases.data.length),
      uploaded_policies: whenComplete(snapshot.trainingPolicies, snapshot.trainingPolicies.data.length),
      sampled_security_tests: sampledTestCount(snapshot),
      inventories: inventoryStates(snapshot, trainingInventories),
      training_lookback_days: trainingLookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "training_", "store_purchases", "security_test"]),
  };
}

const RISK_DISTRIBUTION_READS: Knowbe4InventoryRead[] = [
  USERS_READ,
  { inventory: "account", notChecked: "the organization risk score was not attached for comparison", verdict: false },
  { inventory: "account_risk_score_history", notChecked: "the organization risk score trend was not attached", verdict: false },
];

function assessRiskDistribution(snapshot: Knowbe4Snapshot, maxMeanRiskScore: number, maxStddev: number, redact: boolean): Knowbe4Finding {
  if (snapshot.activeUsers.error) return unavailableFinding(5, "medium", "users", snapshot);
  if (snapshot.activeUsers.data.length === 0) {
    return withInventoryCaveats(emptyUserListFinding(5, "medium", "the user risk score distribution", {
      users_scored: 0,
      max_mean_risk_score: maxMeanRiskScore,
      max_risk_score_stddev: maxStddev,
      account_current_risk_score: asNumber(snapshot.account.data.current_risk_score) ?? null,
    }), snapshot, RISK_DISTRIBUTION_READS);
  }
  const scored = snapshot.activeUsers.data
    .map((user) => ({ user, score: asNumber(user.current_risk_score) }))
    .filter((item): item is { user: JsonRecord; score: number } => item.score !== undefined);
  const scores = scored.map((item) => item.score);
  const average = mean(scores);
  const deviation = standardDeviation(scores);
  const highest = [...scored].sort((left, right) => right.score - left.score).slice(0, 10);
  const history = snapshot.accountRiskHistory.data
    .map((point) => ({ risk_score: asNumber(point.risk_score) ?? null, date: asString(point.date) ?? null }))
    .filter((point) => point.risk_score !== null);

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (average === undefined || deviation === undefined) {
    status = "warn";
    summary = "No active users exposed a current_risk_score, so the risk distribution could not be analyzed.";
  } else if (average > maxMeanRiskScore) {
    status = "fail";
    summary = `The mean user risk score is ${roundTo(average)} across ${scores.length} active users, above the ${maxMeanRiskScore} policy ceiling.`;
  } else if (deviation > maxStddev) {
    status = "warn";
    summary = `The mean user risk score is ${roundTo(average)} but the standard deviation of ${roundTo(deviation)} exceeds ${maxStddev}, indicating uneven risk across users.`;
  } else {
    status = "pass";
    summary = `The mean user risk score is ${roundTo(average)} with a standard deviation of ${roundTo(deviation)} across ${scores.length} active users.`;
  }

  // The statistics describe the users read; they are population figures only when the user list was read in full.
  const ranked = highest.map((item) => ({ user: userLabel(item.user, redact), risk_score: item.score }));
  return withInventoryCaveats(finding(5, "medium", status, summary, {
    users_scored: whenComplete(snapshot.activeUsers, scores.length),
    users_scored_read: scores.length,
    mean_risk_score: average === undefined ? null : roundTo(average),
    stddev_risk_score: deviation === undefined ? null : roundTo(deviation),
    max_risk_score: scores.length > 0 ? Math.max(...scores) : null,
    max_mean_risk_score: maxMeanRiskScore,
    max_risk_score_stddev: maxStddev,
    account_current_risk_score: asNumber(snapshot.account.data.current_risk_score) ?? null,
    account_risk_history_points: whenComplete(snapshot.accountRiskHistory, history.length),
    account_risk_history_first: history[0] ?? null,
    account_risk_history_last: history[history.length - 1] ?? null,
    highest_risk_users: whenComplete(snapshot.activeUsers, ranked),
    highest_risk_users_among_read: ranked,
  }), snapshot, RISK_DISTRIBUTION_READS);
}

function phishingCampaignInWindow(campaign: JsonRecord, days: number, now: Date): boolean {
  const cutoff = daysAgo(now, days).getTime();
  const lastRun = toDate(campaign.last_run);
  if (lastRun && lastRun.getTime() >= cutoff && lastRun.getTime() <= now.getTime()) return true;
  return asRecordArray(campaign.psts).some((pst) => {
    const started = toDate(pst.start_date);
    return Boolean(started && started.getTime() >= cutoff && started.getTime() <= now.getTime());
  });
}

const GROUP_COVERAGE_READS: Knowbe4InventoryRead[] = [
  { inventory: "groups", notChecked: "the active group list was not available", essential: true },
  { inventory: "phishing_campaigns", notChecked: "phishing campaign target groups were not available", essential: true },
  TRAINING_CAMPAIGN_READ,
];

function assessGroupCoverage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number): Knowbe4Finding {
  if (snapshot.groups.error) return unavailableFinding(8, "medium", "groups", snapshot);
  if (snapshot.phishingCampaigns.error) return unavailableFinding(8, "medium", "phishing_campaigns", snapshot);
  if (snapshot.trainingCampaigns.error) return unavailableFinding(8, "medium", "training_campaigns", snapshot);
  const groups = snapshot.groups.data.filter((group) => (asNumber(group.member_count) ?? 1) > 0);
  const phishingCampaigns = snapshot.phishingCampaigns.data.filter((campaign) => phishingCampaignInWindow(campaign, lookbackDays, now));
  const trainingCampaigns = snapshot.trainingCampaigns.data.filter((campaign) => !campaignCancelled(campaign) && campaignInWindow(campaign, lookbackDays, now));

  const coverage = (campaigns: JsonRecord[]): { all: boolean; ids: Set<string> } => {
    const ids = new Set<string>();
    let all = false;
    for (const campaign of campaigns) {
      if (campaignTargetsAllUsers(campaign)) all = true;
      for (const id of campaignGroupIds(campaign)) ids.add(id);
    }
    return { all, ids };
  };
  const phishing = coverage(phishingCampaigns);
  const training = coverage(trainingCampaigns);
  const describe = (group: JsonRecord): JsonRecord => ({
    id: recordId(group) ?? null,
    name: asString(group.name) ?? null,
    group_type: asString(group.group_type) ?? null,
    member_count: asNumber(group.member_count) ?? null,
  });
  const missingPhishing = groups.filter((group) => !phishing.all && !phishing.ids.has(recordId(group) ?? ""));
  const missingTraining = groups.filter((group) => !training.all && !training.ids.has(recordId(group) ?? ""));
  // A group "lacks a campaign" only when every campaign that could target it was read; a truncated campaign list
  // leaves the uncovered groups unknown rather than named.
  const phishingComplete = isComplete(snapshot.phishingCampaigns);
  const trainingComplete = isComplete(snapshot.trainingCampaigns);
  const campaignsComplete = phishingComplete && trainingComplete;

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (groups.length === 0) {
    status = "warn";
    summary = "No active groups with members were visible, so group coverage could not be evaluated.";
  } else if (missingPhishing.length === 0 && missingTraining.length === 0) {
    status = "pass";
    summary = `All ${groups.length} active groups were included in at least one phishing and one training campaign in the last ${lookbackDays} days.`;
  } else if (!campaignsComplete) {
    status = "warn";
    summary = `${missingPhishing.length} groups appear in none of the ${phishingCampaigns.length} phishing campaigns loaded and ${missingTraining.length} in none of the ${trainingCampaigns.length} training campaigns loaded for the last ${lookbackDays} days; the campaign listing was truncated, so the uncovered groups are unknown rather than named.`;
  } else {
    status = "fail";
    summary = `${missingPhishing.length} groups lacked a phishing campaign and ${missingTraining.length} groups lacked a training campaign in the last ${lookbackDays} days.`;
  }

  return withInventoryCaveats(finding(8, "medium", status, summary, {
    active_groups: whenComplete(snapshot.groups, groups.length),
    active_groups_read: groups.length,
    phishing_campaigns_in_window: whenComplete(snapshot.phishingCampaigns, phishingCampaigns.length),
    training_campaigns_in_window: whenComplete(snapshot.trainingCampaigns, trainingCampaigns.length),
    // An All Users campaign found is a real observation; its absence is only known from a complete campaign list.
    phishing_targets_all_users: phishing.all ? true : whenComplete(snapshot.phishingCampaigns, false),
    training_targets_all_users: training.all ? true : whenComplete(snapshot.trainingCampaigns, false),
    groups_missing_phishing: phishingComplete ? missingPhishing.slice(0, SAMPLE_SIZE).map(describe) : null,
    groups_missing_training: trainingComplete ? missingTraining.slice(0, SAMPLE_SIZE).map(describe) : null,
    violation_observed: violationFlag([snapshot.groups, snapshot.phishingCampaigns, snapshot.trainingCampaigns], campaignsComplete ? missingPhishing.length + missingTraining.length : 0),
    lookback_days: lookbackDays,
  }), snapshot, GROUP_COVERAGE_READS);
}

// Activity signals are cross-checks on the user list: sign-in dates alone can still judge the control, so a missing
// signal source demotes to warn while an unreadable user list is manual.
const INACTIVE_USER_READS: Knowbe4InventoryRead[] = [
  USERS_READ,
  { inventory: "security_tests", notChecked: "phishing participation could not be used as an activity signal" },
  { inventory: "security_test_recipients", notChecked: "deliveries in the security tests whose recipient results did not load were not counted as activity" },
  { inventory: "training_enrollments", notChecked: "training activity could not be used as an activity signal" },
];

function assessInactiveUsers(snapshot: Knowbe4Snapshot, now: Date, inactiveDays: number, redact: boolean): Knowbe4Finding {
  if (snapshot.activeUsers.error) return unavailableFinding(18, "medium", "users", snapshot);
  if (snapshot.activeUsers.data.length === 0) {
    return withInventoryCaveats(emptyUserListFinding(18, "medium", "inactive user cleanup", {
      users_evaluated: 0,
      inactive_users: 0,
      inactive_days: inactiveDays,
    }), snapshot, INACTIVE_USER_READS);
  }
  const cutoff = daysAgo(now, inactiveDays).getTime();
  const activeSignals = new Set<string>();
  for (const sample of sampledTestsWithin(snapshot, inactiveDays, now)) {
    for (const recipient of sample.recipients) {
      const id = recipientUserId(recipient);
      if (id && recipientDelivered(recipient)) activeSignals.add(id);
    }
  }
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const id = enrollmentUserId(enrollment);
    const activity = enrollmentActivityDate(enrollment);
    if (id && activity && activity.getTime() >= cutoff) activeSignals.add(id);
  }

  const candidates = snapshot.activeUsers.data.filter((user) => {
    const joined = toDate(user.joined_on);
    return !joined || joined.getTime() <= cutoff;
  });
  const inactive = candidates.filter((user) => {
    const id = recordId(user);
    const lastSignIn = toDate(user.last_sign_in);
    if (lastSignIn && lastSignIn.getTime() >= cutoff) return false;
    return !(id && activeSignals.has(id));
  });
  const inactivePct = percentage(inactive.length, candidates.length);
  // A user is inactive only when every activity signal could have been read: an unread or truncated enrollment list,
  // security test list, or recipient result may hold the activity that would clear them, so nobody is named from it.
  const partialData = snapshot.unsampledSecurityTestIds.length > 0
    || !isComplete(snapshot.trainingEnrollments)
    || !isComplete(snapshot.securityTests)
    || !isComplete(snapshot.securityTestRecipients);
  const populationComplete = !partialData && isComplete(snapshot.activeUsers);

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (candidates.length === 0) {
    status = "pass";
    summary = `Every active user joined within the last ${inactiveDays} days, so none can be considered inactive yet.`;
  } else if (inactive.length === 0) {
    status = "pass";
    summary = `All ${candidates.length} long-standing active users show phishing, training, or sign-in activity in the last ${inactiveDays} days.`;
  } else if (partialData) {
    status = "warn";
    summary = `${inactive.length} of ${candidates.length} long-standing active users show no sign-in and no activity in the campaign data that was loaded for ${inactiveDays} days; activity data was partial, so they may have activity that was not read and are not asserted inactive. Review before archiving.`;
  } else if (inactivePct !== undefined && inactivePct <= 5) {
    status = "warn";
    summary = `${inactive.length} of ${candidates.length} active users (${inactivePct}%) show no campaign or sign-in activity in ${inactiveDays} days.`;
  } else {
    status = "fail";
    summary = `${inactive.length} of ${candidates.length} active users (${inactivePct}%) have not participated in any campaign or signed in for ${inactiveDays}+ days and should be reviewed for archival.`;
  }

  return withInventoryCaveats(finding(18, "medium", status, summary, {
    users_evaluated: whenComplete(snapshot.activeUsers, candidates.length),
    users_evaluated_read: candidates.length,
    inactive_users: populationComplete ? inactive.length : null,
    users_without_loaded_activity: inactive.length,
    inactive_pct: populationComplete ? inactivePct ?? null : null,
    violation_observed: violationFlag([!partialData, snapshot.activeUsers], partialData ? 0 : inactive.length),
    inactive_days: inactiveDays,
    partial_activity_data: partialData,
    unsampled_security_tests: whenRead(snapshot.securityTests, snapshot.unsampledSecurityTestIds.length),
    inactive_user_sample: partialData ? null : observedList([snapshot.activeUsers], sampleLabels(inactive, redact)),
  }), snapshot, INACTIVE_USER_READS);
}

export function assessKnowbe4UserRisk(
  snapshot: Knowbe4Snapshot,
  options: Knowbe4AssessmentOptions = {},
): Knowbe4AssessmentResult {
  const now = options.now ?? new Date();
  const redact = options.redactPii ?? false;
  const lookbackDays = clampInteger(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 3650);
  const inactiveDays = clampInteger(options.inactiveDays, DEFAULT_INACTIVE_DAYS, 1, 3650);
  const maxMeanRiskScore = clampNumber(options.maxMeanRiskScore, DEFAULT_MAX_MEAN_RISK_SCORE, 0, 100);
  const maxStddev = clampNumber(options.maxRiskScoreStddev, DEFAULT_MAX_RISK_STDDEV, 0, 100);

  const findings = [
    assessRiskDistribution(snapshot, maxMeanRiskScore, maxStddev, redact),
    assessGroupCoverage(snapshot, now, lookbackDays),
    assessInactiveUsers(snapshot, now, inactiveDays, redact),
  ];

  const riskInventories: Knowbe4InventoryName[] = ["account", "account_risk_score_history", "users", "groups", "phishing_campaigns", "security_tests", "security_test_recipients", "training_campaigns", "training_enrollments"];
  return {
    area: "risk",
    title: assessmentTitle("risk"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      account_current_risk_score: asNumber(snapshot.account.data.current_risk_score) ?? null,
      active_users: whenComplete(snapshot.activeUsers, snapshot.activeUsers.data.length),
      users_read: whenRead(snapshot.activeUsers, snapshot.activeUsers.data.length),
      user_limit_reached: snapshot.userLimitReached,
      enrollment_limit_reached: snapshot.enrollmentLimitReached,
      active_groups: whenComplete(snapshot.groups, snapshot.groups.data.length),
      phishing_campaigns: whenComplete(snapshot.phishingCampaigns, snapshot.phishingCampaigns.data.length),
      training_campaigns: whenComplete(snapshot.trainingCampaigns, snapshot.trainingCampaigns.data.length),
      training_enrollments: whenComplete(snapshot.trainingEnrollments, snapshot.trainingEnrollments.data.length),
      sampled_security_tests: sampledTestCount(snapshot),
      inventories: inventoryStates(snapshot, riskInventories),
      inactive_days: inactiveDays,
      lookback_days: lookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "groups", "phishing_campaigns", "security_test", "training_"]),
  };
}

function emailDomain(email: string | undefined): string | undefined {
  const at = email?.lastIndexOf("@") ?? -1;
  return email && at >= 0 ? email.slice(at + 1).toLowerCase() : undefined;
}

function accountDomains(snapshot: Knowbe4Snapshot): string[] {
  return asStringArray(snapshot.account.data.domains) ?? [];
}

function assessAdminRoles(snapshot: Knowbe4Snapshot, maxAdminCount: number, redact: boolean): Knowbe4Finding {
  if (snapshot.account.error) return unavailableFinding(12, "high", "account", snapshot);
  const admins = asRecordArray(snapshot.account.data.admins);
  const allowedDomains = new Set(accountDomains(snapshot).map((domain) => domain.toLowerCase()));
  const externalAdmins = allowedDomains.size > 0
    ? admins.filter((admin) => {
      const domain = emailDomain(asString(admin.email));
      return Boolean(domain && !allowedDomains.has(domain));
    })
    : [];

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (admins.length === 0) {
    status = "warn";
    summary = "The account endpoint returned no admins, so console administrator membership could not be enumerated.";
  } else if (admins.length > maxAdminCount) {
    status = "fail";
    summary = `${admins.length} console administrators exceed the policy maximum of ${maxAdminCount}.`;
  } else if (externalAdmins.length > 0) {
    status = "warn";
    summary = `${admins.length} console administrators are within the ${maxAdminCount} maximum, but ${externalAdmins.length} use email domains outside the account's allowed domains.`;
  } else {
    status = "pass";
    summary = `${admins.length} console administrators are within the policy maximum of ${maxAdminCount} and all use allowed account domains.`;
  }

  return finding(12, "high", status, summary, {
    admin_count: admins.length,
    max_admin_count: maxAdminCount,
    admins: admins.slice(0, SAMPLE_SIZE).map((admin) => ({ id: recordId(admin) ?? null, user: userLabel(admin, redact) })),
    allowed_domains: [...allowedDomains],
    external_domain_admins: externalAdmins.map((admin) => userLabel(admin, redact)),
    violation_observed: violationFlag([snapshot.account], admins.length > maxAdminCount ? 1 : externalAdmins.length),
  });
}

function assessSsoStatus(snapshot: Knowbe4Snapshot): Knowbe4Finding {
  return finding(
    13,
    "high",
    "manual",
    "The KMSAT Reporting API does not expose SAML SSO or admin MFA settings, so SSO enforcement for the KnowBe4 console must be verified manually.",
    {
      api_visibility: "not_exposed_by_reporting_api",
      account_name: asString(snapshot.account.data.name) ?? null,
      admin_count: whenRead(snapshot.account, asRecordArray(snapshot.account.data.admins).length),
      automation_note: "The KSAT GraphQL API exposes account { samlEnabled forceMfa samlSettings { disableNonSamlLogins allowAdminWithMfaLoginBypass } } for accounts entitled to it.",
    },
    "In the KnowBe4 console open Account Settings and capture the SAML configuration under Account Integrations showing SAML SSO enabled, non-SAML logins disabled, and MFA required for admins. Attach the screenshot (or the KSAT GraphQL account samlEnabled and forceMfa output) as evidence.",
  );
}

function assessReportingFrequency(snapshot: Knowbe4Snapshot, now: Date): Knowbe4Finding {
  const latestTest = runTests(snapshot.securityTests.data, now)[0];
  const completedCampaigns = snapshot.trainingCampaigns.data
    .filter((campaign) => campaignCompletedOrEnded(campaign, now) && !campaignCancelled(campaign))
    .map((campaign) => ({ campaign, ended: campaignEndDate(campaign) ?? campaignStartDate(campaign) }))
    .filter((item): item is { campaign: JsonRecord; ended: Date } => Boolean(item.ended))
    .sort((left, right) => right.ended.getTime() - left.ended.getTime());
  const latestTraining = completedCampaigns[0];

  return finding(
    14,
    "medium",
    "manual",
    "The KMSAT Reporting API has no log of generated or reviewed reports, so report generation and review cadence must be evidenced from console report schedules and review records.",
    {
      api_visibility: "not_exposed_by_reporting_api",
      // The latest dates are context from other inventories; each is only known when its inventory was read in full.
      security_tests_read: isRead(snapshot.securityTests),
      latest_security_test: latestTest && isComplete(snapshot.securityTests)
        ? { pst_id: testId(latestTest.test), started_at: latestTest.startedAt.toISOString(), days_ago: roundTo(daysBetween(latestTest.startedAt, now)) }
        : null,
      training_campaigns_read: isRead(snapshot.trainingCampaigns),
      latest_completed_training_campaign: latestTraining && isComplete(snapshot.trainingCampaigns)
        ? { name: campaignName(latestTraining.campaign), ended_at: latestTraining.ended.toISOString(), days_ago: roundTo(daysBetween(latestTraining.ended, now)) }
        : null,
    },
    "Collect the scheduled and saved report configurations from the console Reports area (including recipients and cadence of scheduled executive reports), plus review records such as meeting minutes or tickets showing phishing and training results were reviewed at the interval your policy requires.",
  );
}

function assessUsbTests(now: Date, lookbackDays: number, requireUsbTests: boolean): Knowbe4Finding {
  if (!requireUsbTests) {
    // Scoping a control out by configuration is not evidence that it is met, so it stays a manual item.
    return finding(
      15,
      "low",
      "manual",
      "USB drop testing was scoped out by configuration (require_usb_tests is false); this control was not evaluated and is not satisfied by the API. Record the documented risk decision that physical media testing is out of scope, or enable require_usb_tests and evidence the tests.",
      {
        require_usb_tests: false,
        scoped_out_by_configuration: true,
        lookback_days: lookbackDays,
        evaluated_at: now.toISOString(),
      },
      "Attach the approved policy or risk-acceptance record stating that physical media (USB drop) testing is out of scope for the awareness program. If it is in scope, export the USB Drive Test campaign list from the KnowBe4 console (Phishing, USB Drive Test) with results from the assessment period.",
    );
  }
  return finding(
    15,
    "low",
    "manual",
    "USB Drive Test campaigns are not exposed by the KMSAT Reporting API, so physical security awareness testing must be evidenced from the console.",
    {
      api_visibility: "not_exposed_by_reporting_api",
      require_usb_tests: true,
      lookback_days: lookbackDays,
      evaluated_at: now.toISOString(),
      automation_note: "The KSAT GraphQL API usbCampaigns query lists USB Drive Test campaigns for accounts entitled to it.",
    },
    `Export the USB Drive Test campaign list from the KnowBe4 console (Phishing, USB Drive Test) showing at least one test started in the last ${lookbackDays} days with its results, or record a policy statement that physical media testing is out of scope.`,
  );
}

function assessVishingTests(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, requireVishingTests: boolean): Knowbe4Finding {
  if (!requireVishingTests) {
    return finding(
      16,
      "low",
      "manual",
      "Voice-channel (vishing) testing was scoped out by configuration (require_vishing_tests is false); this control was not evaluated and is not satisfied by the API. Record the documented risk decision that voice-channel testing is out of scope, or enable require_vishing_tests to evaluate callback phishing tests.",
      {
        require_vishing_tests: false,
        scoped_out_by_configuration: true,
        lookback_days: lookbackDays,
        evaluated_at: now.toISOString(),
        callback_tests_all_time: whenComplete(snapshot.callbackSecurityTests, runTests(snapshot.callbackSecurityTests.data, now).length),
      },
      "Attach the approved policy or risk-acceptance record stating that voice-channel (vishing) testing is out of scope for the awareness program. If it is in scope, export the Callback Phishing campaign list from the KnowBe4 console (Phishing, Callback Phishing) showing tests started in the assessment period.",
    );
  }
  if (snapshot.callbackSecurityTests.error) return unavailableFinding(16, "low", "callback_security_tests", snapshot);
  if (!snapshot.callbackSecurityTests.collected) {
    // The governance scope was not collected, so no request was made and no endpoint or status is named.
    return finding(
      16,
      "low",
      "manual",
      "Callback phishing security tests were not requested in this run (the governance scope was not collected), so voice-channel testing must be evidenced from the console.",
      {
        api_visibility: "callback_security_tests_not_requested",
        collection_error: null,
        lookback_days: lookbackDays,
      },
      `Export the Callback Phishing campaign list from the KnowBe4 console (Phishing, Callback Phishing) showing at least one test started in the last ${lookbackDays} days, or record a policy statement that voice-channel testing is out of scope.`,
    );
  }
  const recent = testsWithin(snapshot.callbackSecurityTests.data, lookbackDays, now);
  const allTime = runTests(snapshot.callbackSecurityTests.data, now);
  const listComplete = isComplete(snapshot.callbackSecurityTests);
  // A test found in the window is a real observation; "none ran" is only known from a complete list.
  const status = recent.length > 0 ? "pass" : listComplete ? "fail" : "warn";

  return withInventoryCaveats(finding(
    16,
    "low",
    status,
    status === "pass"
      ? `${recent.length} callback (voice-channel) phishing security tests started in the last ${lookbackDays} days.`
      : status === "warn"
        ? `None of the ${allTime.length} callback (voice-channel) phishing security tests loaded started in the last ${lookbackDays} days; the listing was truncated, so a recent test may not have been read.`
        : `No callback (voice-channel) phishing security tests started in the last ${lookbackDays} days${allTime.length > 0 ? `; the last one started ${roundTo(daysBetween(allTime[0].startedAt, now))} days ago` : " and none have ever run"}.`,
    {
      callback_tests_in_window: whenComplete(snapshot.callbackSecurityTests, recent.length),
      callback_tests_all_time: whenComplete(snapshot.callbackSecurityTests, allTime.length),
      callback_tests_read: allTime.length,
      latest_callback_test: allTime[0]
        ? { pst_id: testId(allTime[0].test), name: testName(allTime[0].test), started_at: allTime[0].startedAt.toISOString() }
        : null,
      lookback_days: lookbackDays,
      evaluation_note: "Vishing is evaluated through KnowBe4 callback phishing tests, the voice-channel simulation the Reporting API exposes via campaign_type=callback.",
    },
  ), snapshot, [{ inventory: "callback_security_tests", notChecked: "callback test dates were not available", essential: true }]);
}

export function assessKnowbe4AccountGovernance(
  snapshot: Knowbe4Snapshot,
  options: Knowbe4AssessmentOptions = {},
): Knowbe4AssessmentResult {
  const now = options.now ?? new Date();
  const redact = options.redactPii ?? false;
  const lookbackDays = clampInteger(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 3650);
  const maxAdminCount = clampInteger(options.maxAdminCount, DEFAULT_MAX_ADMIN_COUNT, 0, 10_000);
  const requireUsbTests = options.requireUsbTests ?? true;
  const requireVishingTests = options.requireVishingTests ?? true;

  const findings = [
    assessAdminRoles(snapshot, maxAdminCount, redact),
    assessSsoStatus(snapshot),
    assessReportingFrequency(snapshot, now),
    assessUsbTests(now, lookbackDays, requireUsbTests),
    assessVishingTests(snapshot, now, lookbackDays, requireVishingTests),
  ];

  const governanceInventories: Knowbe4InventoryName[] = ["account", "security_tests", "callback_security_tests", "training_campaigns"];
  return {
    area: "governance",
    title: assessmentTitle("governance"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      account_type: asString(snapshot.account.data.type) ?? null,
      subscription_level: asString(snapshot.account.data.subscription_level) ?? null,
      number_of_seats: asNumber(snapshot.account.data.number_of_seats) ?? null,
      admin_count: whenRead(snapshot.account, asRecordArray(snapshot.account.data.admins).length),
      allowed_domains: whenRead(snapshot.account, accountDomains(snapshot).length),
      callback_security_tests: whenComplete(snapshot.callbackSecurityTests, snapshot.callbackSecurityTests.data.length),
      manual_controls: findings.filter((item) => item.status === "manual").map((item) => item.id),
      inventories: inventoryStates(snapshot, governanceInventories),
      lookback_days: lookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "callback_security_tests", "security_tests", "training_campaigns", "phishing_campaigns"]),
  };
}

function formatAccessCheckText(result: Knowbe4AccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === null || surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `KnowBe4 access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

// A null summary value is a count or flag whose inventory was not read (or not read in full), never a zero.
function formatSummaryValue(value: unknown): string {
  if (typeof value === "number") return String(Number(value.toFixed(2)));
  if (Array.isArray(value)) return value.length > 0 ? value.map(String).join(", ") : "none";
  if (value === null || value === undefined) return "unknown";
  return String(value);
}

function formatCell(value: unknown): string {
  return value === null || value === undefined ? "unknown" : String(value);
}

function formatAssessmentText(result: Knowbe4AssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const inventories = asRecordArray(result.summary.inventories);
  const summary = Object.entries(result.summary)
    .filter(([key]) => key !== "inventories")
    .map(([key, value]) => `- ${key}: ${formatSummaryValue(value)}`)
    .join("\n");
  const manual = result.findings
    .filter((item) => item.status === "manual" && item.manualEvidence)
    .map((item) => `- ${item.id}: ${item.manualEvidence}`);
  const lines = [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
  ];
  if (inventories.length > 0) {
    lines.push("", "Inventories read:", formatTable(
      ["Inventory", "Status", "Endpoint", "HTTP", "Seen", "Total", "Complete"],
      inventories.map((row) => [
        formatCell(row.inventory),
        formatCell(row.status),
        formatCell(row.endpoint),
        formatCell(row.http_status),
        formatCell(row.seen),
        formatCell(row.total),
        formatCell(row.complete),
      ]),
    ));
  }
  if (manual.length > 0) {
    lines.push("", "Manual evidence to collect:", ...manual);
  }
  if (result.errors.length > 0) {
    lines.push("", "Collection warnings:", ...result.errors.map((error) => `- ${error}`));
  }
  return lines.join("\n");
}

function summarizeStatuses(findings: Knowbe4Finding[]): Record<Knowbe4Finding["status"], number> {
  const counts: Record<Knowbe4Finding["status"], number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function markdownEscapePipes(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function buildExecutiveSummary(config: Knowbe4ResolvedConfig, snapshot: Knowbe4Snapshot, assessments: Knowbe4AssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeStatuses(findings);
  const priority = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => (left.status === right.status ? 0 : left.status === "fail" ? -1 : 1))
    .slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");

  const lines = [
    "# KnowBe4 Executive Summary",
    "",
    `- Account: ${asString(snapshot.account.data.name) ?? "unknown"}`,
    `- Region: ${config.region} (${config.baseUrl})`,
    `- Subscription: ${asString(snapshot.account.data.subscription_level) ?? "unknown"}`,
    `- Generated: ${snapshot.collectedAt}`,
    `- Config sources: ${config.sourceChain.join(", ") || "defaults"}`,
    `- PII redaction: ${config.redactPii ? "enabled" : "disabled"}`,
    `- Controls: ${findings.length} evaluated, Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "## Highest Priority Findings",
  ];
  if (priority.length === 0) {
    lines.push("- No failing or warning findings were generated.");
  } else {
    for (const item of priority) {
      lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}) ${item.title}: ${item.summary}`);
    }
  }
  lines.push("", "## Manual Evidence Required");
  if (manual.length === 0) {
    lines.push("- None.");
  } else {
    for (const item of manual) {
      lines.push(`- ${item.id} ${item.title}: ${item.manualEvidence ?? item.summary}`);
    }
  }
  if (snapshot.errors.length > 0) {
    lines.push("", "## Partial Collection Warnings");
    for (const error of snapshot.errors) lines.push(`- ${error}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: Knowbe4Finding[]): string {
  const header = ["Control", "Title", ...FRAMEWORK_KEYS.map((key) => FRAMEWORK_LABELS[key]), "Status"];
  const lines = [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
  ];
  for (const item of findings) {
    const definition = controlById(item.control);
    lines.push(`| ${[
      item.id,
      item.title,
      ...FRAMEWORK_KEYS.map((key) => definition.frameworks[key]),
      item.status.toUpperCase(),
    ].map(markdownEscapePipes).join(" | ")} |`);
  }
  return `${lines.join("\n")}\n`;
}

function buildFrameworkReport(key: Knowbe4FrameworkKey, findings: Knowbe4Finding[]): string {
  const lines = [
    `# ${FRAMEWORK_LABELS[key]} Compliance Report`,
    "",
    "| Control | Title | Mapping | Status | Severity | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
  ];
  for (const item of findings) {
    const definition = controlById(item.control);
    lines.push(`| ${[
      item.id,
      item.title,
      definition.frameworks[key],
      item.status.toUpperCase(),
      item.severity.toUpperCase(),
      item.summary,
    ].map(markdownEscapePipes).join(" | ")} |`);
  }
  const manual = findings.filter((item) => item.status === "manual");
  if (manual.length > 0) {
    lines.push("", "## Manual Evidence");
    for (const item of manual) lines.push(`- ${item.id}: ${item.manualEvidence ?? item.summary}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildQuickReference(): string {
  return [
    "# KnowBe4 Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains the KnowBe4 Reporting API (and PhishER GraphQL) responses used during this assessment. User records drop free-form comment and custom fields at collection time; credential-shaped values are replaced with [REDACTED] and URLs are reduced to scheme and host before writing.",
    "- `core_data/collection_status.json` records, per inventory (`inventories[]`), whether the read succeeded, the HTTP status and request of a failed read, how the read ended (complete or truncated at a cap), how many records were loaded, and the server total when the API exposes one. Every flag and count is `null` for a read that never completed, and `totals` counts those reads as unknown rather than as complete or untruncated.",
    "- A list inventory that was denied, errored, or never requested is written as a marker object (`{ collected: false, status, endpoint, error, reason }`) instead of an empty array; a readable but empty inventory stays `[]`. Per-test recipient reads that failed appear as per-test markers alongside the loaded samples.",
    "- `analysis/` contains normalized findings, per-area assessment summaries, and the 20-control coverage map. A `null` count or list in a finding or summary means the inventory behind it was not read in full; named users, groups, or modules only appear when the inventories that prove the property were read completely.",
    "- `compliance/` contains the executive summary, unified matrix, and one report per mapped framework.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Manual findings list the exact console evidence a human must collect; review them before asserting compliance.",
    "- A finding whose inventories were unreadable or truncated says so in its summary (`Unreadable inventory:` / `Truncated listing:`) and never reports pass on the missing records.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/control_coverage.json` and `analysis/findings.json` for supporting evidence",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

function buildControlCoverage(assessments: Knowbe4AssessmentResult[]): JsonRecord[] {
  const findings = new Map(assessments.flatMap((assessment) => assessment.findings).map((item) => [item.control, item]));
  return KNOWBE4_CONTROLS.map((control) => {
    const item = findings.get(control.number);
    return {
      control: control.number,
      title: control.title,
      area: control.area,
      tool: knowbe4ToolForArea(control.area),
      finding_id: item?.id ?? findingId(control.number),
      status: item?.status ?? "not_evaluated",
      severity: item?.severity ?? null,
      mappings: knowbe4ControlMappings(control.number),
    };
  });
}

type Knowbe4BundleClient = Knowbe4DataClient & Knowbe4AccessClient;

export async function exportKnowbe4AuditBundle(
  client: Knowbe4BundleClient,
  config: Knowbe4ResolvedConfig,
  outputRoot: string,
  options: Knowbe4CollectOptions = {},
): Promise<Knowbe4AuditBundleResult> {
  const access = await checkKnowbe4Access(client);
  const snapshot = await collectKnowbe4Snapshot(client, { ...options, scopes: ["phishing", "training", "risk", "governance"] });
  const assessmentOptions = { ...options, redactPii: options.redactPii ?? config.redactPii };
  const assessments = [
    assessKnowbe4PhishingProgram(snapshot, assessmentOptions),
    assessKnowbe4TrainingProgram(snapshot, assessmentOptions),
    assessKnowbe4UserRisk(snapshot, assessmentOptions),
    assessKnowbe4AccountGovernance(snapshot, assessmentOptions),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  // Credential-shaped values and token-bearing URLs never leave the process regardless of the PII setting.
  const redact = (value: unknown): unknown => redactCredentialValues(config.redactPii ? redactKnowbe4Pii(value) : value);

  ensurePrivateDir(outputRoot);
  const accountName = asString(snapshot.account.data.name) ?? `knowbe4-${config.region}`;
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(accountName)}-knowbe4-audit-bundle`);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: snapshot.collectedAt,
    region: config.region,
    base_url: config.baseUrl,
    phisher_graphql_url: config.phisherGraphqlUrl,
    phisher_configured: Boolean(config.phisherApiToken),
    account_name: asString(snapshot.account.data.name) ?? null,
    redact_pii: config.redactPii,
    source_chain: config.sourceChain,
  }));

  // A dataset that was denied, errored, or never requested is written as a marker object, never as `[]`, so a
  // consumer cannot mistake a denial for an empty inventory; a readable but empty inventory stays `[]`.
  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access.json", access],
    ["core_data/collection_status.json", knowbe4CollectionStatus(snapshot)],
    ["core_data/account.json", coreDataValue("account", snapshot.account)],
    ["core_data/account_risk_score_history.json", coreDataValue("account_risk_score_history", snapshot.accountRiskHistory)],
    ["core_data/users_active.json", coreDataValue("users", snapshot.activeUsers)],
    ["core_data/groups.json", coreDataValue("groups", snapshot.groups)],
    ["core_data/phishing_campaigns.json", coreDataValue("phishing_campaigns", snapshot.phishingCampaigns)],
    ["core_data/security_tests.json", coreDataValue("security_tests", snapshot.securityTests)],
    ["core_data/security_test_recipients.json", recipientsCoreData(snapshot)],
    ["core_data/callback_security_tests.json", coreDataValue("callback_security_tests", snapshot.callbackSecurityTests)],
    ["core_data/training_campaigns.json", coreDataValue("training_campaigns", snapshot.trainingCampaigns)],
    ["core_data/training_enrollments.json", coreDataValue("training_enrollments", snapshot.trainingEnrollments)],
    ["core_data/store_purchases.json", coreDataValue("store_purchases", snapshot.storePurchases)],
    ["core_data/training_policies.json", coreDataValue("training_policies", snapshot.trainingPolicies)],
    ["core_data/phisher_messages.json", snapshot.phisherMessages.collected ? coreDataValue("phisher_messages", snapshot.phisherMessages) : notConfiguredMarker()],
  ];
  for (const [pathName, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathName, serializeJson(redact(value)));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.md`, `${formatAssessmentText(assessment)}\n`);
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/control_coverage.json", serializeJson(buildControlCoverage(assessments)));
  await writeSecureTextFile(outputDir, "analysis/access_check.md", `${formatAccessCheckText(access)}\n`);

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, snapshot, assessments));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const key of FRAMEWORK_KEYS) {
    await writeSecureTextFile(outputDir, frameworkReportPath(key), buildFrameworkReport(key, findings));
  }

  if (snapshot.errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${snapshot.errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    manualCount: findings.filter((item) => item.status === "manual").length,
    errorCount: snapshot.errors.length,
  };
}

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    api_token: asString(value.api_token) ?? asString(value.token),
    region: asString(value.region),
    base_url: asString(value.base_url),
    phisher_api_token: asString(value.phisher_api_token),
    phisher_graphql_url: asString(value.phisher_graphql_url),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
    redact_pii: asBoolean(value.redact_pii),
  };
}

function normalizeAssessmentArgs(args: unknown): AssessmentArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    lookback_days: asNumber(value.lookback_days),
    training_lookback_days: asNumber(value.training_lookback_days),
    max_campaign_gap_days: asNumber(value.max_campaign_gap_days),
    max_schedule_gap_days: asNumber(value.max_schedule_gap_days),
    min_coverage_pct: asNumber(value.min_coverage_pct),
    max_phish_prone_pct: asNumber(value.max_phish_prone_pct),
    min_report_rate_pct: asNumber(value.min_report_rate_pct),
    require_full_targeting: asBoolean(value.require_full_targeting),
    min_completion_pct: asNumber(value.min_completion_pct),
    fail_completion_pct: asNumber(value.fail_completion_pct),
    enrollment_grace_days: asNumber(value.enrollment_grace_days),
    remedial_window_days: asNumber(value.remedial_window_days),
    max_content_age_days: asNumber(value.max_content_age_days),
    required_compliance_topics: asStringArray(value.required_compliance_topics),
    max_mean_risk_score: asNumber(value.max_mean_risk_score),
    max_risk_score_stddev: asNumber(value.max_risk_score_stddev),
    inactive_days: asNumber(value.inactive_days),
    max_admin_count: asNumber(value.max_admin_count),
    require_usb_tests: asBoolean(value.require_usb_tests),
    require_vishing_tests: asBoolean(value.require_vishing_tests),
    user_limit: asNumber(value.user_limit),
    enrollment_limit: asNumber(value.enrollment_limit),
    security_test_sample_limit: asNumber(value.security_test_sample_limit),
    phisher_message_limit: asNumber(value.phisher_message_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessmentArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toCollectOptions(args: AssessmentArgs, config: Knowbe4ResolvedConfig): Knowbe4CollectOptions {
  return {
    redactPii: args.redact_pii ?? config.redactPii,
    lookbackDays: args.lookback_days,
    trainingLookbackDays: args.training_lookback_days,
    maxCampaignGapDays: args.max_campaign_gap_days,
    maxScheduleGapDays: args.max_schedule_gap_days,
    minCoveragePct: args.min_coverage_pct,
    maxPhishPronePct: args.max_phish_prone_pct,
    minReportRatePct: args.min_report_rate_pct,
    requireFullTargeting: args.require_full_targeting,
    minCompletionPct: args.min_completion_pct,
    failCompletionPct: args.fail_completion_pct,
    enrollmentGraceDays: args.enrollment_grace_days,
    remedialWindowDays: args.remedial_window_days,
    maxContentAgeDays: args.max_content_age_days,
    requiredComplianceTopics: args.required_compliance_topics,
    maxMeanRiskScore: args.max_mean_risk_score,
    maxRiskScoreStddev: args.max_risk_score_stddev,
    inactiveDays: args.inactive_days,
    maxAdminCount: args.max_admin_count,
    requireUsbTests: args.require_usb_tests,
    requireVishingTests: args.require_vishing_tests,
    userLimit: args.user_limit,
    enrollmentLimit: args.enrollment_limit,
    securityTestSampleLimit: args.security_test_sample_limit,
    phisherMessageLimit: args.phisher_message_limit,
  };
}

function createClient(args: AuthArgs): Knowbe4ApiClient {
  return new Knowbe4ApiClient(resolveKnowbe4Configuration(args));
}

async function runAssessment(
  area: Knowbe4Scope,
  args: AssessmentArgs,
): Promise<Knowbe4AssessmentResult> {
  const config = resolveKnowbe4Configuration(args);
  const client = new Knowbe4ApiClient(config);
  const options = toCollectOptions(args, config);
  const snapshot = await collectKnowbe4Snapshot(client, { ...options, scopes: [area] });
  switch (area) {
    case "phishing":
      return assessKnowbe4PhishingProgram(snapshot, options);
    case "training":
      return assessKnowbe4TrainingProgram(snapshot, options);
    case "risk":
      return assessKnowbe4UserRisk(snapshot, options);
    case "governance":
      return assessKnowbe4AccountGovernance(snapshot, options);
    default: {
      const exhaustive: never = area;
      throw new Error(`Unhandled KnowBe4 area: ${String(exhaustive)}`);
    }
  }
}

const authParams = {
  api_token: Type.Optional(Type.String({ description: "KnowBe4 Reporting API key. Defaults to KNOWBE4_API_TOKEN, then api_token in ~/.knowbe4-inspector/config.yaml." })),
  region: Type.Optional(Type.Union(
    KNOWBE4_REGIONS.map((region) => Type.Literal(region)),
    { description: "KnowBe4 hosting region that selects the API base URL. Defaults to KNOWBE4_REGION, then the config file, then us." },
  )),
  base_url: Type.Optional(Type.String({ description: "Override for the Reporting API base URL (normally derived from region, for example https://us.api.knowbe4.com). Defaults to KNOWBE4_BASE_URL." })),
  phisher_api_token: Type.Optional(Type.String({ description: "Optional PhishER Product API key for GraphQL enrichment. Defaults to KNOWBE4_PHISHER_API_TOKEN, then phisher_api_token in the config file." })),
  phisher_graphql_url: Type.Optional(Type.String({ description: "Override for the PhishER GraphQL endpoint (normally derived from region, for example https://training.knowbe4.com/graphql). Defaults to KNOWBE4_PHISHER_GRAPHQL_URL." })),
  config_file: Type.Optional(Type.String({ description: "Path to a YAML config file with api_token, region, and optional phisher_api_token. Defaults to KNOWBE4_CONFIG_FILE or ~/.knowbe4-inspector/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  redact_pii: Type.Optional(Type.Boolean({ description: "Replace user emails and names with stable pseudonyms in findings and exported data. Defaults to KNOWBE4_REDACT_PII or false.", default: false })),
};

const scopeParams = {
  lookback_days: Type.Optional(Type.Number({ description: "Analysis window in days for phishing cadence, coverage, report rate, callback tests, and group coverage. Defaults to 90.", default: 90 })),
  user_limit: Type.Optional(Type.Number({ description: "Maximum active users to load. Findings computed over the user list degrade to warn with user_limit_reached when the cap is hit. Defaults to 5000.", default: 5000 })),
  security_test_sample_limit: Type.Optional(Type.Number({ description: "Number of most recent phishing security tests whose recipient results are loaded. Defaults to 12.", default: 12 })),
};

const phishingParams = {
  ...scopeParams,
  max_campaign_gap_days: Type.Optional(Type.Number({ description: "Maximum days since the last phishing security test before control 1 fails. Defaults to 30.", default: 30 })),
  min_coverage_pct: Type.Optional(Type.Number({ description: "Minimum percentage of active users that must be tested or targeted (controls 2 and 9). Defaults to 90.", default: 90 })),
  max_phish_prone_pct: Type.Optional(Type.Number({ description: "Maximum acceptable phish-prone percentage (control 6). Defaults to 15.", default: 15 })),
  min_report_rate_pct: Type.Optional(Type.Number({ description: "Minimum Phish Alert Button report rate percentage (control 19). Defaults to 50.", default: 50 })),
  max_schedule_gap_days: Type.Optional(Type.Number({ description: "Maximum days between consecutive phishing security tests (control 20). Defaults to 45.", default: 45 })),
  require_full_targeting: Type.Optional(Type.Boolean({ description: "Whether policy requires active phishing campaigns to target all active users (control 9). Defaults to true.", default: true })),
  phisher_message_limit: Type.Optional(Type.Number({ description: "Maximum PhishER messages to load for report-rate enrichment when a PhishER key is configured. Defaults to 1000.", default: 1000 })),
};

const trainingParams = {
  ...scopeParams,
  training_lookback_days: Type.Optional(Type.Number({ description: "Window in days for training campaigns, enrollments, and content review. Defaults to 365.", default: 365 })),
  min_completion_pct: Type.Optional(Type.Number({ description: "Training completion target percentage (controls 3 and 17). Defaults to 90.", default: 90 })),
  fail_completion_pct: Type.Optional(Type.Number({ description: "Completion percentage below which a training campaign fails control 3. Defaults to 80.", default: 80 })),
  enrollment_grace_days: Type.Optional(Type.Number({ description: "Days after joining within which a new user must be enrolled in training (control 4). Defaults to 30.", default: 30 })),
  remedial_window_days: Type.Optional(Type.Number({ description: "Days after a phishing failure allowed for remedial enrollment before the user counts as unremediated (control 10). Defaults to 14.", default: 14 })),
  max_content_age_days: Type.Optional(Type.Number({ description: "Maximum age in days of assigned training module publish dates before they are flagged stale (control 11). Defaults to 365.", default: 365 })),
  required_compliance_topics: Type.Optional(Type.Array(Type.String(), { description: "Compliance topics that must appear in assigned module names, for example HIPAA, PCI, GDPR (control 17). Defaults to auto-detecting compliance-themed content." })),
  enrollment_limit: Type.Optional(Type.Number({ description: "Maximum training enrollments to load. Defaults to 20000.", default: 20000 })),
};

const riskParams = {
  ...scopeParams,
  inactive_days: Type.Optional(Type.Number({ description: "Days without campaign participation or sign-in before an active user is considered inactive (control 18). Defaults to 180.", default: 180 })),
  max_mean_risk_score: Type.Optional(Type.Number({ description: "Maximum acceptable mean user risk score (control 5). Defaults to 50.", default: 50 })),
  max_risk_score_stddev: Type.Optional(Type.Number({ description: "Maximum acceptable standard deviation of user risk scores (control 5). Defaults to 25.", default: 25 })),
  enrollment_limit: Type.Optional(Type.Number({ description: "Maximum training enrollments to load for activity signals. Defaults to 20000.", default: 20000 })),
};

const governanceParams = {
  lookback_days: Type.Optional(Type.Number({ description: "Analysis window in days for callback phishing tests. Defaults to 90.", default: 90 })),
  user_limit: Type.Optional(Type.Number({ description: "Maximum active users to load. Findings computed over the user list degrade to warn with user_limit_reached when the cap is hit. Defaults to 5000.", default: 5000 })),
  max_admin_count: Type.Optional(Type.Number({ description: "Maximum console administrators before control 12 fails. Defaults to 3.", default: 3 })),
  require_usb_tests: Type.Optional(Type.Boolean({ description: "Whether policy requires USB drop tests (control 15). Set false to scope the control out; it is then reported as manual with the policy evidence to attach, never as pass. Defaults to true.", default: true })),
  require_vishing_tests: Type.Optional(Type.Boolean({ description: "Whether policy requires voice-channel (callback) phishing tests (control 16). Set false to scope the control out; it is then reported as manual with the policy evidence to attach, never as pass. Defaults to true.", default: true })),
};

function assessmentTool(
  pi: any,
  area: Knowbe4Scope,
  label: string,
  description: string,
  parameters: Record<string, unknown>,
): void {
  const name = knowbe4ToolForArea(area);
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object({ ...authParams, ...parameters }),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const result = await runAssessment(area, args);
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(
          `KnowBe4 ${area} assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: name },
        );
      }
    },
  });
}

export function registerKnowbe4Tools(pi: any): void {
  pi.registerTool({
    name: "knowbe4_check_access",
    label: "Check KnowBe4 audit access",
    description:
      "Validate read-only KnowBe4 Reporting API access across account, users, groups, phishing campaigns, security tests, training campaigns, enrollments, store purchases, and policies, plus optional PhishER GraphQL access.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkKnowbe4Access(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "knowbe4_check_access", ...result });
      } catch (error) {
        return errorResult(
          `KnowBe4 access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "knowbe4_check_access" },
        );
      }
    },
  });

  assessmentTool(
    pi,
    "phishing",
    "Assess KnowBe4 phishing program",
    "Assess the KnowBe4 phishing simulation program: test cadence, active-user coverage, phish-prone percentage, failure-rate trend, campaign targeting, Phish Alert Button report rate (with optional PhishER enrichment), and scheduling regularity (spec controls 1, 2, 6, 7, 9, 19, 20).",
    phishingParams,
  );

  assessmentTool(
    pi,
    "training",
    "Assess KnowBe4 training program",
    "Assess the KnowBe4 security awareness training program: campaign completion rates, new-user enrollment timeliness, remedial training after phishing failures, training content currency, and required compliance modules (spec controls 3, 4, 10, 11, 17).",
    trainingParams,
  );

  assessmentTool(
    pi,
    "risk",
    "Assess KnowBe4 user risk and coverage",
    "Assess KnowBe4 user risk and hygiene: organization risk score distribution, group coverage across phishing and training campaigns, and inactive users who have not participated in any campaign (spec controls 5, 8, 18).",
    riskParams,
  );

  assessmentTool(
    pi,
    "governance",
    "Assess KnowBe4 account governance",
    "Assess KnowBe4 account governance: console administrator count and domains, SSO enforcement (manual evidence), report review cadence (manual evidence), USB drop tests (manual evidence), and callback voice-phishing tests (spec controls 12, 13, 14, 15, 16).",
    governanceParams,
  );

  pi.registerTool({
    name: "knowbe4_export_audit_bundle",
    label: "Export KnowBe4 audit bundle",
    description:
      "Export a KnowBe4 audit package covering all 20 spec controls: raw Reporting API snapshots in core_data/, normalized findings and control coverage in analysis/, executive summary, unified matrix, and per-framework reports in compliance/, QUICK_REFERENCE.md, an _errors.log when collection is partial, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...phishingParams,
      ...trainingParams,
      ...riskParams,
      ...governanceParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveKnowbe4Configuration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportKnowbe4AuditBundle(new Knowbe4ApiClient(config), config, outputRoot, toCollectOptions(args, config));
        return textResult(
          [
            "KnowBe4 audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount} (${result.manualCount} manual)`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "knowbe4_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            manual_count: result.manualCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `KnowBe4 audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "knowbe4_export_audit_bundle" },
        );
      }
    },
  });
}
