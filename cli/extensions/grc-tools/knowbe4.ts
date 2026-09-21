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
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
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
}

export interface Knowbe4SampledSecurityTest {
  pst_id: string;
  campaign_id?: string;
  name?: string;
  started_at?: string;
  recipients: JsonRecord[];
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
  unsampledSecurityTestIds: string[];
  userLimit: number;
  userLimitReached: boolean;
  enrollmentLimit: number;
  enrollmentLimitReached: boolean;
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

function knowbe4ErrorDetail(rawText: string): string | undefined {
  if (rawText.length === 0) return undefined;
  try {
    const payload = asObject(JSON.parse(rawText));
    const detail = [
      asString(payload?.message),
      asString(payload?.error),
      ...asRecordArray(payload?.errors).map((item) => asString(item.message)),
    ].filter((item): item is string => Boolean(item));
    if (detail.length > 0) return detail.join("; ");
  } catch {
    // fall through to the raw snippet
  }
  return rawText.replace(/\s+/g, " ").slice(0, 200);
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

  private redact(message: string): string {
    let redacted = message;
    for (const secret of [this.config.apiToken, this.config.phisherApiToken]) {
      if (secret && secret.length > 0) {
        redacted = redacted.split(secret).join("[REDACTED]");
      }
    }
    return redacted;
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

  private async request(url: string, init: RequestInit, token: string, label: string): Promise<unknown> {
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
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(this.redact(`KnowBe4 request to ${label} failed: ${message}`));
      } finally {
        clearTimeout(timeout);
      }

      const rawText = await response.text();
      if ((response.status === 429 || response.status === 503) && attempt < this.maxRetries) {
        await this.sleepImpl(retryDelayMs(response.headers.get("retry-after"), attempt));
        continue;
      }
      if (!response.ok) {
        const detail = knowbe4ErrorDetail(rawText);
        throw new Error(this.redact(
          `KnowBe4 request failed (${response.status} ${response.statusText}) for ${label}${detail ? `: ${detail}` : ""}`,
        ));
      }
      if (rawText.length === 0) return {};
      try {
        return JSON.parse(rawText) as unknown;
      } catch {
        throw new Error(this.redact(`KnowBe4 response for ${label} was not valid JSON.`));
      }
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request(this.buildUrl(path, query), { method: "GET" }, this.config.apiToken, path);
  }

  async list(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampInteger(options.limit, DEFAULT_ENROLLMENT_LIMIT, 1, 1_000_000);
    const pageSize = clampInteger(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const items: JsonRecord[] = [];

    for (let page = 1; items.length < limit; page += 1) {
      const payload = await this.get(path, { ...query, page, per_page: pageSize });
      const pageItems = asRecordArray(payload);
      items.push(...pageItems.slice(0, limit - items.length));
      if (pageItems.length < pageSize) break;
    }

    return items;
  }

  async probe(path: string, query: JsonRecord = {}): Promise<JsonRecord[]> {
    return this.list(path, query, { limit: 1, pageSize: 1 });
  }

  async getAccount(): Promise<JsonRecord> {
    return asObject(await this.get("/v1/account")) ?? {};
  }

  async getAccountRiskScoreHistory(full = true): Promise<JsonRecord[]> {
    return this.list("/v1/account/risk_score_history", full ? { full: "true" } : {});
  }

  async listUsers(options: { status?: "active" | "archived"; groupId?: string; limit?: number } = {}): Promise<JsonRecord[]> {
    return this.list("/v1/users", { status: options.status ?? "active", group_id: options.groupId }, { limit: options.limit ?? DEFAULT_USER_LIMIT });
  }

  async listGroups(options: { status?: "active" | "archived"; limit?: number } = {}): Promise<JsonRecord[]> {
    return this.list("/v1/groups", { status: options.status ?? "active" }, { limit: options.limit });
  }

  async listGroupMembers(groupId: string, limit?: number): Promise<JsonRecord[]> {
    return this.list(`/v1/groups/${encodeURIComponent(groupId)}/members`, {}, { limit });
  }

  async listPhishingCampaigns(limit?: number): Promise<JsonRecord[]> {
    return this.list("/v1/phishing/campaigns", {}, { limit });
  }

  async listSecurityTests(options: { campaignType?: "callback"; limit?: number } = {}): Promise<JsonRecord[]> {
    return this.list("/v1/phishing/security_tests", { campaign_type: options.campaignType }, { limit: options.limit });
  }

  async listSecurityTestRecipients(pstId: string, limit?: number): Promise<JsonRecord[]> {
    return this.list(`/v1/phishing/security_tests/${encodeURIComponent(pstId)}/recipients`, {}, { limit });
  }

  async listTrainingCampaigns(limit?: number): Promise<JsonRecord[]> {
    return this.list("/v1/training/campaigns", {}, { limit, pageSize: TRAINING_CAMPAIGN_PAGE_SIZE });
  }

  async listTrainingEnrollments(
    options: { campaignId?: string; userId?: string; storePurchaseId?: string; excludeArchivedUsers?: boolean; limit?: number } = {},
  ): Promise<JsonRecord[]> {
    return this.list("/v1/training/enrollments", {
      campaign_id: options.campaignId,
      user_id: options.userId,
      store_purchase_id: options.storePurchaseId,
      exclude_archived_users: options.excludeArchivedUsers === false ? undefined : "true",
      include_campaign_id: "true",
      include_store_purchase_id: "true",
    }, { limit: options.limit ?? DEFAULT_ENROLLMENT_LIMIT });
  }

  async listStorePurchases(limit?: number): Promise<JsonRecord[]> {
    return this.list("/v1/training/store_purchases", {}, { limit });
  }

  async listTrainingPolicies(limit?: number): Promise<JsonRecord[]> {
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
      throw new Error(this.redact(`PhishER GraphQL returned errors: ${detail}`));
    }
    return asObject(payload.data) ?? {};
  }

  async listPhisherMessages(options: { query?: string; limit?: number } = {}): Promise<JsonRecord[]> {
    const limit = clampInteger(options.limit, DEFAULT_PHISHER_MESSAGE_LIMIT, 1, 100_000);
    const per = Math.min(PHISHER_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    let nextPageKey: string | undefined;

    for (let page = 1; items.length < limit; page += 1) {
      const data = await this.graphql(PHISHER_MESSAGES_QUERY, {
        query: options.query ?? "",
        per,
        page,
        nextPageKey,
      });
      const connection = asObject(data.phisherMessages) ?? {};
      const nodes = asRecordArray(connection.nodes);
      items.push(...nodes.slice(0, limit - items.length));
      const pagination = asObject(connection.pagination) ?? {};
      const totalPages = asNumber(pagination.pages);
      nextPageKey = asString(pagination.nextPageKey);
      if (nodes.length === 0 || (totalPages !== undefined && page >= totalPages && !nextPageKey)) break;
    }

    return items;
  }

  async countPhisherMessages(query = ""): Promise<number | undefined> {
    const data = await this.graphql(PHISHER_MESSAGE_COUNT_QUERY, { query });
    return asNumber(asObject(asObject(data.phisherMessages)?.pagination)?.totalCount);
  }

  async listPhisherRules(options: { query?: string; active?: boolean; limit?: number } = {}): Promise<JsonRecord[]> {
    const limit = clampInteger(options.limit, 500, 1, 10_000);
    const per = Math.min(PHISHER_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];

    for (let page = 1; items.length < limit; page += 1) {
      const data = await this.graphql(PHISHER_RULES_QUERY, {
        query: options.query ?? "",
        per,
        page,
        active: options.active,
      });
      const connection = asObject(data.phisherRules) ?? {};
      const nodes = asRecordArray(connection.nodes);
      items.push(...nodes.slice(0, limit - items.length));
      const totalPages = asNumber(asObject(connection.pagination)?.pages);
      if (nodes.length === 0 || (totalPages !== undefined && page >= totalPages)) break;
    }

    return items;
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
    return { name, endpoint, status: "readable", count: countResolver?.(value) };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

const CORE_ACCESS_SURFACES = 9;
const HEALTHY_SURFACE_THRESHOLD = 7;

export async function checkKnowbe4Access(client: Knowbe4AccessClient): Promise<Knowbe4AccessCheckResult> {
  const config = client.getResolvedConfig();
  let account: JsonRecord = {};
  const accountSurface = await readableSurface("account", "/v1/account", async () => {
    account = await client.getAccount();
    return account;
  }, (value) => asRecordArray(asObject(value)?.admins).length);

  const surfaces: Knowbe4AccessSurface[] = [
    accountSurface,
    await readableSurface("users", "/v1/users?status=active", () => client.probe("/v1/users", { status: "active" })),
    await readableSurface("groups", "/v1/groups?status=active", () => client.probe("/v1/groups", { status: "active" })),
    await readableSurface("phishing_campaigns", "/v1/phishing/campaigns", () => client.probe("/v1/phishing/campaigns")),
    await readableSurface("security_tests", "/v1/phishing/security_tests", () => client.probe("/v1/phishing/security_tests")),
    await readableSurface("training_campaigns", "/v1/training/campaigns", () => client.probe("/v1/training/campaigns")),
    await readableSurface("training_enrollments", "/v1/training/enrollments", () => client.probe("/v1/training/enrollments")),
    await readableSurface("store_purchases", "/v1/training/store_purchases", () => client.probe("/v1/training/store_purchases")),
    await readableSurface("training_policies", "/v1/training/policies", () => client.probe("/v1/training/policies")),
  ];

  if (client.hasPhisherCredentials()) {
    surfaces.push(await readableSurface(
      "phisher_messages",
      `${config.phisherGraphqlUrl} phisherMessages`,
      () => client.countPhisherMessages(""),
      (value) => asNumber(value),
    ));
  } else {
    surfaces.push({
      name: "phisher_messages",
      endpoint: `${config.phisherGraphqlUrl} phisherMessages`,
      status: "not_configured",
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

async function collectSurface<T>(
  label: string,
  fallback: T,
  errors: string[],
  load: () => Promise<T>,
): Promise<Knowbe4Collected<T>> {
  try {
    return collected(await load());
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`${label}: ${message}`);
    return collected(fallback, message);
  }
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
    ? await collectSurface("account_risk_score_history", [], errors, () => client.getAccountRiskScoreHistory(true))
    : skipped<JsonRecord[]>([]);
  const activeUsers = await collectSurface("users", [], errors, () => client.listUsers({ status: "active", limit: userLimit }));
  const groups = needs("phishing", "risk")
    ? await collectSurface("groups", [], errors, () => client.listGroups({ status: "active" }))
    : skipped<JsonRecord[]>([]);
  const phishingCampaigns = needs("phishing", "risk", "governance")
    ? await collectSurface("phishing_campaigns", [], errors, () => client.listPhishingCampaigns())
    : skipped<JsonRecord[]>([]);
  const securityTests = await collectSurface("security_tests", [], errors, () => client.listSecurityTests());

  let securityTestRecipients: Knowbe4Collected<Knowbe4SampledSecurityTest[]> = skipped([]);
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
    for (const item of sampled) {
      const id = testId(item.test);
      if (!id) continue;
      try {
        samples.push({
          pst_id: id,
          campaign_id: asString(item.test.campaign_id),
          name: testName(item.test),
          started_at: item.startedAt.toISOString(),
          recipients: await client.listSecurityTestRecipients(id),
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        recipientErrors.push(`security_test_recipients[${id}]: ${message}`);
        unsampledSecurityTestIds.push(id);
      }
    }
    errors.push(...recipientErrors);
    securityTestRecipients = collected(samples, recipientErrors.length > 0 ? recipientErrors.join("; ") : undefined);
  }

  const callbackSecurityTests = needs("governance")
    ? await collectSurface("callback_security_tests", [], errors, () => client.listSecurityTests({ campaignType: "callback" }))
    : skipped<JsonRecord[]>([]);
  const trainingCampaigns = needs("training", "risk", "governance")
    ? await collectSurface("training_campaigns", [], errors, () => client.listTrainingCampaigns())
    : skipped<JsonRecord[]>([]);
  const trainingEnrollments = needs("training", "risk")
    ? await collectSurface("training_enrollments", [], errors, () => client.listTrainingEnrollments({ limit: enrollmentLimit }))
    : skipped<JsonRecord[]>([]);
  const storePurchases = needs("training")
    ? await collectSurface("store_purchases", [], errors, () => client.listStorePurchases())
    : skipped<JsonRecord[]>([]);
  const trainingPolicies = needs("training")
    ? await collectSurface("training_policies", [], errors, () => client.listTrainingPolicies())
    : skipped<JsonRecord[]>([]);
  const phisherMessages = needs("phishing") && client.hasPhisherCredentials()
    ? await collectSurface("phisher_messages", [], errors, () => client.listPhisherMessages({
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
    unsampledSecurityTestIds,
    userLimit,
    userLimitReached: activeUsers.data.length >= userLimit,
    enrollmentLimit,
    enrollmentLimitReached: trainingEnrollments.data.length >= enrollmentLimit,
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

function unavailableFinding(number: number, severity: Knowbe4Finding["severity"], error: string): Knowbe4Finding {
  return finding(
    number,
    severity,
    "warn",
    `Could not evaluate this control because the required KnowBe4 data was not readable: ${error}`,
    { collection_error: error },
  );
}

// Findings computed over the active user list cannot pass when user_limit truncated that list.
function withUserCapCaveat(item: Knowbe4Finding, snapshot: Knowbe4Snapshot): Knowbe4Finding {
  const evidence = { ...(item.evidence ?? {}), user_limit: snapshot.userLimit, user_limit_reached: snapshot.userLimitReached };
  if (!snapshot.userLimitReached || item.status !== "pass") return { ...item, evidence };
  return {
    ...item,
    status: "warn",
    summary: `${item.summary} The active user list was truncated at user_limit (${snapshot.userLimit}), so this verdict only covers the users that were loaded.`,
    evidence,
  };
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
  if (snapshot.securityTests.error) return unavailableFinding(1, "high", snapshot.securityTests.error);
  const tests = runTests(snapshot.securityTests.data, now);
  const latest = tests[0];
  const daysSince = latest ? roundTo(daysBetween(latest.startedAt, now)) : undefined;
  const inLookback = testsWithin(snapshot.securityTests.data, lookbackDays, now).length;
  const status = !latest ? "fail" : daysSince !== undefined && daysSince <= maxGapDays ? "pass" : "fail";

  return finding(
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
      security_tests_in_lookback: inLookback,
      lookback_days: lookbackDays,
    },
  );
}

function assessPhishingCoverage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCoveragePct: number, redact: boolean): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(2, "high", snapshot.securityTests.error);
  if (snapshot.activeUsers.error) return unavailableFinding(2, "high", snapshot.activeUsers.error);
  const active = activeUserIds(snapshot);
  const testsInWindow = testsWithin(snapshot.securityTests.data, lookbackDays, now);
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

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (testsInWindow.length === 0) {
    status = "fail";
    summary = `No phishing security tests ran in the last ${lookbackDays} days, so no active users were tested.`;
  } else if (samples.length === 0) {
    status = "warn";
    summary = `${testsInWindow.length} phishing security tests ran in the last ${lookbackDays} days but recipient results could not be read, so coverage is unknown.`;
  } else if (coverage !== undefined && coverage >= minCoveragePct) {
    status = "pass";
    summary = `${coverage}% of ${active.size} active users received at least one phishing security test in the last ${lookbackDays} days (policy minimum ${minCoveragePct}%).`;
  } else if (unsampled > 0) {
    status = "warn";
    summary = `${coverage ?? 0}% of active users appear in the ${samples.length} sampled security tests; ${unsampled} additional tests in the window were not sampled, so coverage may be understated.`;
  } else {
    status = "fail";
    summary = `Only ${coverage ?? 0}% of ${active.size} active users were tested in the last ${lookbackDays} days (policy minimum ${minCoveragePct}%).`;
  }

  return finding(2, "high", status, summary, {
    active_users: active.size,
    tested_users: tested.size,
    coverage_pct: coverage ?? null,
    min_coverage_pct: minCoveragePct,
    security_tests_in_window: testsInWindow.length,
    sampled_security_tests: samples.map((sample) => sample.pst_id),
    unsampled_security_tests: unsampled,
    untested_user_sample: sampleLabels(untested, redact),
  });
}

function assessPhishPronePercentage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, maxPhishPronePct: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(6, "high", snapshot.securityTests.error);
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

  return finding(6, "high", status, summary, {
    current_phish_prone_pct: current === undefined ? null : roundTo(current, 2),
    current_source: current === undefined ? "unverified" : "security_tests",
    user_average_phish_prone_pct: userAverage === undefined ? null : roundTo(userAverage, 2),
    baseline_phish_prone_pct: baseline ?? null,
    max_phish_prone_pct: maxPhishPronePct,
    lookback_days: lookbackDays,
    security_tests_in_window: recent.length,
    security_tests_all_time: history.length,
    account_current_risk_score: accountRisk ?? null,
  });
}

function assessFailureTrend(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(7, "medium", snapshot.securityTests.error);
  const windowDays = lookbackDays * 2;
  const tests = testsWithin(snapshot.securityTests.data, windowDays, now)
    .reverse()
    .map((item) => ({ ...item, ppp: decimalToPercent(item.test.phish_prone_percentage) }))
    .filter((item): item is { test: JsonRecord; startedAt: Date; ppp: number } => item.ppp !== undefined);
  const riskHistory = snapshot.accountRiskHistory.data
    .map((point) => ({ score: asNumber(point.risk_score), date: asString(point.date) }))
    .filter((point): point is { score: number; date: string | undefined } => point.score !== undefined);

  if (tests.length < MIN_TREND_TESTS) {
    return finding(7, "medium", "warn", `Only ${tests.length} phishing security tests with results ran in the last ${windowDays} days; at least ${MIN_TREND_TESTS} are needed to evaluate a trend.`, {
      security_tests_considered: tests.length,
      window_days: windowDays,
      risk_score_history_points: riskHistory.length,
    });
  }

  const midpoint = Math.floor(tests.length / 2);
  const earlier = mean(tests.slice(0, midpoint).map((item) => item.ppp)) ?? 0;
  const later = mean(tests.slice(midpoint).map((item) => item.ppp)) ?? 0;
  const delta = roundTo(later - earlier, 2);
  const status = delta > TREND_FAIL_DELTA_PCT ? "fail" : delta > TREND_WARN_DELTA_PCT ? "warn" : "pass";

  return finding(
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
      account_risk_score_first: riskHistory[0] ?? null,
      account_risk_score_last: riskHistory[riskHistory.length - 1] ?? null,
    },
  );
}

function assessCampaignTargeting(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCoveragePct: number, requireFullTargeting: boolean): Knowbe4Finding {
  if (snapshot.phishingCampaigns.error) return unavailableFinding(9, "medium", snapshot.phishingCampaigns.error);
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

  return finding(9, "medium", status, summary, {
    active_campaigns: activeCampaigns.length,
    full_targeting_campaigns: fullCampaigns.map(campaignName),
    partial_targeting_campaigns: partialCampaigns.slice(0, SAMPLE_SIZE).map((campaign) => ({
      name: campaignName(campaign),
      groups: campaignGroups(campaign).map((group) => asString(group.name) ?? asString(group.group_id) ?? "group"),
    })),
    estimated_coverage_pct: estimatedCoverage ?? null,
    min_coverage_pct: minCoveragePct,
    require_full_targeting: requireFullTargeting,
    active_users: activeUsers,
  });
}

function assessReportRate(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minReportRatePct: number): Knowbe4Finding {
  if (snapshot.securityTests.error) return unavailableFinding(19, "medium", snapshot.securityTests.error);
  const recent = testsWithin(snapshot.securityTests.data, lookbackDays, now).map((item) => item.test);
  let delivered = 0;
  let reported = 0;
  for (const test of recent) {
    delivered += asNumber(test.delivered_count) ?? 0;
    reported += asNumber(test.reported_count) ?? 0;
  }
  const reportRate = percentage(reported, delivered);
  const phisher = snapshot.phisherMessages;
  const phisherEvidence: JsonRecord = phisher.collected
    ? {
      status: phisher.error ? "error" : "collected",
      error: phisher.error ?? null,
      messages_in_window: phisher.data.length,
      by_category: countBy(phisher.data, "category"),
      by_action_status: countBy(phisher.data, "actionStatus"),
      unique_reporters: new Set(phisher.data.map((message) => asString(message.reportedBy)).filter(Boolean)).size,
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

  return finding(19, "medium", status, summary, {
    delivered_count: delivered,
    reported_count: reported,
    report_rate_pct: reportRate ?? null,
    min_report_rate_pct: minReportRatePct,
    security_tests_in_window: recent.length,
    phisher: phisherEvidence,
  });
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
  if (snapshot.securityTests.error) return unavailableFinding(20, "medium", snapshot.securityTests.error);
  const allTests = runTests(snapshot.securityTests.data, now);
  if (allTests.length === 0) {
    return finding(20, "medium", "fail", "No phishing security tests have ever run, so there is no scheduling cadence to evaluate.", {
      security_tests_in_window: 0,
      security_tests_all_time: 0,
      lookback_days: lookbackDays,
      max_schedule_gap_days: maxScheduleGapDays,
    });
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

  return finding(
    20,
    "medium",
    status,
    status === "pass"
      ? `${inWindow.length} phishing security tests ran in the last ${lookbackDays} days with a maximum gap of ${maxGap} days including the ${daysSinceLatest} days since the latest test (policy maximum ${maxScheduleGapDays}); average gap ${averageGap} days.`
      : `${overThreshold.length} scheduling gaps exceeded ${maxScheduleGapDays} days (largest ${maxGap} days)${latestOverdue ? `, including the ${daysSinceLatest} days since the most recent test` : ""}, across ${inWindow.length} phishing security tests in the last ${lookbackDays} days.`,
    {
      security_tests_in_window: inWindow.length,
      security_tests_all_time: allTests.length,
      lookback_days: lookbackDays,
      latest_test_started_at: latest.startedAt.toISOString(),
      days_since_latest_test: daysSinceLatest,
      max_gap_days: maxGap,
      average_gap_days: averageGap,
      max_schedule_gap_days: maxScheduleGapDays,
      gaps,
      gaps_over_threshold: overThreshold,
    },
  );
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
    withUserCapCaveat(assessPhishingCoverage(snapshot, now, lookbackDays, minCoveragePct, redact), snapshot),
    assessPhishPronePercentage(snapshot, now, lookbackDays, maxPhishPronePct),
    assessFailureTrend(snapshot, now, lookbackDays),
    withUserCapCaveat(assessCampaignTargeting(snapshot, now, lookbackDays, minCoveragePct, requireFullTargeting), snapshot),
    assessReportRate(snapshot, now, lookbackDays, minReportRatePct),
    assessScheduleRegularity(snapshot, now, lookbackDays, maxScheduleGapDays),
  ];

  return {
    area: "phishing",
    title: assessmentTitle("phishing"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      active_users: snapshot.activeUsers.data.length,
      user_limit_reached: snapshot.userLimitReached,
      phishing_campaigns: snapshot.phishingCampaigns.data.length,
      security_tests: snapshot.securityTests.data.length,
      security_tests_in_lookback: testsWithin(snapshot.securityTests.data, lookbackDays, now).length,
      sampled_security_tests: snapshot.securityTestRecipients.data.length,
      phisher_messages: snapshot.phisherMessages.collected ? snapshot.phisherMessages.data.length : null,
      lookback_days: lookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "groups", "phishing_campaigns", "security_test", "phisher_messages"]),
  };
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

function assessTrainingCompletion(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCompletionPct: number, failCompletionPct: number): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(3, "high", snapshot.trainingCampaigns.error);
  const enrollmentsByCampaign = new Map<string, JsonRecord[]>();
  for (const enrollment of snapshot.trainingEnrollments.data) {
    const id = enrollmentCampaignId(enrollment);
    if (!id) continue;
    const bucket = enrollmentsByCampaign.get(id) ?? [];
    bucket.push(enrollment);
    enrollmentsByCampaign.set(id, bucket);
  }

  const evaluated: Array<{ name: string; campaign_id: string | null; completion_pct: number; source: string; end_date: string | null }> = [];
  const unmeasured: string[] = [];
  for (const campaign of snapshot.trainingCampaigns.data) {
    if (campaignCancelled(campaign) || !campaignCompletedOrEnded(campaign, now) || !campaignInWindow(campaign, lookbackDays, now)) continue;
    const id = trainingCampaignId(campaign);
    const reported = asNumber(campaign.completion_percentage);
    const computed = id ? completionFromEnrollments(enrollmentsByCampaign.get(id) ?? []) : undefined;
    const completion = reported !== undefined && reported >= 0 ? reported : computed;
    if (completion === undefined) {
      unmeasured.push(campaignName(campaign));
      continue;
    }
    evaluated.push({
      name: campaignName(campaign),
      campaign_id: id ?? null,
      completion_pct: roundTo(completion),
      source: reported !== undefined && reported >= 0 ? "completion_percentage" : "enrollments",
      end_date: campaignEndDate(campaign)?.toISOString() ?? null,
    });
  }

  const failing = evaluated.filter((item) => item.completion_pct < failCompletionPct);
  const warning = evaluated.filter((item) => item.completion_pct < minCompletionPct && item.completion_pct >= failCompletionPct);
  let status: Knowbe4Finding["status"];
  let summary: string;
  if (evaluated.length === 0) {
    status = "warn";
    summary = `No completed or ended training campaigns with measurable completion were found in the last ${lookbackDays} days.`;
  } else if (failing.length > 0) {
    status = "fail";
    summary = `${failing.length} of ${evaluated.length} completed training campaigns finished below ${failCompletionPct}% completion.`;
  } else if (warning.length > 0) {
    status = "warn";
    summary = `${warning.length} of ${evaluated.length} completed training campaigns finished between ${failCompletionPct}% and ${minCompletionPct}% completion.`;
  } else {
    status = "pass";
    summary = `All ${evaluated.length} completed training campaigns in the last ${lookbackDays} days met the ${minCompletionPct}% completion target.`;
  }

  return finding(3, "high", status, summary, {
    campaigns_evaluated: evaluated,
    campaigns_without_measurable_completion: unmeasured,
    min_completion_pct: minCompletionPct,
    fail_completion_pct: failCompletionPct,
    training_lookback_days: lookbackDays,
  });
}

function assessEnrollmentTimeliness(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, graceDays: number, enrollmentLimitReached: boolean, redact: boolean): Knowbe4Finding {
  if (snapshot.activeUsers.error) return unavailableFinding(4, "medium", snapshot.activeUsers.error);
  if (snapshot.trainingEnrollments.error) return unavailableFinding(4, "medium", snapshot.trainingEnrollments.error);
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
  } else if (enrollmentLimitReached || (latePct !== undefined && latePct <= 5)) {
    status = "warn";
    summary = `${late.length} of ${newUsers.length} recently joined users had no training enrollment within ${graceDays} days${enrollmentLimitReached ? " (enrollment collection hit its limit, so some enrollments may be missing)" : ""}.`;
  } else {
    status = "fail";
    summary = `${late.length} of ${newUsers.length} recently joined users (${latePct}%) had no training enrollment within ${graceDays} days of joining.`;
  }

  return finding(4, "medium", status, summary, {
    new_users_evaluated: newUsers.length,
    late_or_missing_enrollments: late.length,
    late_pct: latePct ?? null,
    enrollment_grace_days: graceDays,
    training_lookback_days: lookbackDays,
    enrollment_limit_reached: enrollmentLimitReached,
    late_user_sample: sampleLabels(late, redact),
  });
}

function assessRemedialTraining(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, remedialWindowDays: number, redact: boolean): Knowbe4Finding {
  if (snapshot.trainingEnrollments.error) return unavailableFinding(10, "medium", snapshot.trainingEnrollments.error);
  if (snapshot.securityTests.error) return unavailableFinding(10, "medium", snapshot.securityTests.error);
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

  return finding(10, "medium", status, summary, {
    security_tests_in_window: testsInWindow.length,
    sampled_security_tests: samples.map((sample) => sample.pst_id),
    unsampled_security_tests: unsampled,
    failed_users_in_window: failures.size,
    failed_users_evaluated: evaluable.length,
    remediated_users: remediated.length,
    remediated_pct: remediatedPct ?? null,
    remedial_window_days: remedialWindowDays,
    auto_enroll_training_campaigns: autoEnrollCampaigns,
    unremediated_user_sample: unremediated.slice(0, SAMPLE_SIZE).map(([, item]) => ({
      user: userLabel(item.user, redact),
      failed_at: item.failedAt.toISOString(),
    })),
  });
}

function campaignContentItems(campaign: JsonRecord): JsonRecord[] {
  return asRecordArray(campaign.content);
}

function storePurchaseId(item: JsonRecord): string | undefined {
  return asString(item.store_purchase_id) ?? asString(item.store_purchased_id);
}

function assessContentCurrency(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, maxContentAgeDays: number): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(11, "low", snapshot.trainingCampaigns.error);
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
    if (undated.length > 0) parts.push(`${undated.length} have no publish date in the Reporting API or store catalog, so their currency cannot be verified`);
    summary = `Of ${reviewed} assigned training modules, ${parts.join(" and ")}.`;
  } else {
    status = "pass";
    summary = `All ${reviewed} assigned training modules have publish dates within the last ${maxContentAgeDays} days and none are retired.`;
  }

  return finding(11, "low", status, summary, {
    modules_reviewed: reviewed,
    modules_with_publish_date: dated,
    retired_modules: retired.slice(0, SAMPLE_SIZE),
    stale_modules: stale.slice(0, SAMPLE_SIZE),
    undated_module_count: undated.length,
    undated_modules: undated.slice(0, SAMPLE_SIZE),
    max_content_age_days: maxContentAgeDays,
    training_lookback_days: lookbackDays,
  });
}

const COMPLIANCE_TOPIC_PATTERN = /\b(hipaa|pci|gdpr|sox|ferpa|ccpa|cpra|glba|cmmc|nist|iso\s?27001|fedramp|privacy|compliance|acceptable use|insider threat)\b/i;

function assessComplianceModules(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number, minCompletionPct: number, requiredTopics: string[], enrollmentLimitReached: boolean): Knowbe4Finding {
  if (snapshot.trainingCampaigns.error) return unavailableFinding(17, "medium", snapshot.trainingCampaigns.error);
  const enrollmentsUnavailable = Boolean(snapshot.trainingEnrollments.error) || !snapshot.trainingEnrollments.collected;
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
      assigned_modules: modules,
      campaigns: [...new Set(modules.flatMap((moduleName) => [...(assignedModules.get(moduleName) ?? [])]))],
      enrollments: enrollments.length,
      completion_pct: completionFromEnrollments(enrollments) ?? null,
    };
  });
  const missing = topicResults.filter((item) => item.assigned_modules.length === 0);
  // Assigned but never enrolled means nobody can have completed the topic, so it cannot pass.
  const unenrolled = topicResults.filter((item) => item.assigned_modules.length > 0 && item.enrollments === 0);
  const lowCompletion = topicResults.filter((item) => item.completion_pct !== null && item.completion_pct < minCompletionPct);
  const enrollmentDataPartial = enrollmentsUnavailable || enrollmentLimitReached;
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
    summary = `Compliance modules are assigned but completion is below ${minCompletionPct}% for: ${lowCompletion.map((item) => `${item.topic} (${item.completion_pct}%)`).join(", ")}.`;
  } else {
    status = "pass";
    summary = `Compliance training modules are assigned and enrolled for ${topicList(topicResults)} with completion at or above ${minCompletionPct}%.`;
  }

  return finding(17, "medium", status, summary, {
    required_compliance_topics: requiredTopics,
    topics: topicResults,
    topics_without_enrollments: unenrolled.map((item) => item.topic),
    min_completion_pct: minCompletionPct,
    training_lookback_days: lookbackDays,
    enrollments_available: !enrollmentsUnavailable,
    enrollment_limit_reached: enrollmentLimitReached,
    uploaded_policies: snapshot.trainingPolicies.data.length,
  });
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
    assessTrainingCompletion(snapshot, now, trainingLookbackDays, minCompletionPct, failCompletionPct),
    withUserCapCaveat(assessEnrollmentTimeliness(snapshot, now, trainingLookbackDays, graceDays, enrollmentLimitReached, redact), snapshot),
    assessRemedialTraining(snapshot, now, lookbackDays, remedialWindowDays, redact),
    assessContentCurrency(snapshot, now, trainingLookbackDays, maxContentAgeDays),
    assessComplianceModules(snapshot, now, trainingLookbackDays, minCompletionPct, requiredTopics, enrollmentLimitReached),
  ];

  return {
    area: "training",
    title: assessmentTitle("training"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      active_users: snapshot.activeUsers.data.length,
      training_campaigns: snapshot.trainingCampaigns.data.length,
      training_enrollments: snapshot.trainingEnrollments.data.length,
      enrollment_limit_reached: enrollmentLimitReached,
      user_limit_reached: snapshot.userLimitReached,
      store_purchases: snapshot.storePurchases.data.length,
      uploaded_policies: snapshot.trainingPolicies.data.length,
      training_lookback_days: trainingLookbackDays,
    },
    findings,
    errors: relevantErrors(snapshot, ["account", "users", "training_", "store_purchases", "security_test"]),
  };
}

function assessRiskDistribution(snapshot: Knowbe4Snapshot, maxMeanRiskScore: number, maxStddev: number, redact: boolean): Knowbe4Finding {
  if (snapshot.activeUsers.error) return unavailableFinding(5, "medium", snapshot.activeUsers.error);
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

  return finding(5, "medium", status, summary, {
    users_scored: scores.length,
    mean_risk_score: average === undefined ? null : roundTo(average),
    stddev_risk_score: deviation === undefined ? null : roundTo(deviation),
    max_risk_score: scores.length > 0 ? Math.max(...scores) : null,
    max_mean_risk_score: maxMeanRiskScore,
    max_risk_score_stddev: maxStddev,
    account_current_risk_score: asNumber(snapshot.account.data.current_risk_score) ?? null,
    account_risk_history_first: history[0] ?? null,
    account_risk_history_last: history[history.length - 1] ?? null,
    highest_risk_users: highest.map((item) => ({ user: userLabel(item.user, redact), risk_score: item.score })),
  });
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

function assessGroupCoverage(snapshot: Knowbe4Snapshot, now: Date, lookbackDays: number): Knowbe4Finding {
  if (snapshot.groups.error) return unavailableFinding(8, "medium", snapshot.groups.error);
  if (snapshot.phishingCampaigns.error) return unavailableFinding(8, "medium", snapshot.phishingCampaigns.error);
  if (snapshot.trainingCampaigns.error) return unavailableFinding(8, "medium", snapshot.trainingCampaigns.error);
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

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (groups.length === 0) {
    status = "warn";
    summary = "No active groups with members were visible, so group coverage could not be evaluated.";
  } else if (missingPhishing.length === 0 && missingTraining.length === 0) {
    status = "pass";
    summary = `All ${groups.length} active groups were included in at least one phishing and one training campaign in the last ${lookbackDays} days.`;
  } else {
    status = "fail";
    summary = `${missingPhishing.length} groups lacked a phishing campaign and ${missingTraining.length} groups lacked a training campaign in the last ${lookbackDays} days.`;
  }

  return finding(8, "medium", status, summary, {
    active_groups: groups.length,
    phishing_campaigns_in_window: phishingCampaigns.length,
    training_campaigns_in_window: trainingCampaigns.length,
    phishing_targets_all_users: phishing.all,
    training_targets_all_users: training.all,
    groups_missing_phishing: missingPhishing.slice(0, SAMPLE_SIZE).map(describe),
    groups_missing_training: missingTraining.slice(0, SAMPLE_SIZE).map(describe),
    lookback_days: lookbackDays,
  });
}

function assessInactiveUsers(snapshot: Knowbe4Snapshot, now: Date, inactiveDays: number, enrollmentLimitReached: boolean, redact: boolean): Knowbe4Finding {
  if (snapshot.activeUsers.error) return unavailableFinding(18, "medium", snapshot.activeUsers.error);
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
  const partialData = snapshot.unsampledSecurityTestIds.length > 0
    || enrollmentLimitReached
    || Boolean(snapshot.trainingEnrollments.error)
    || Boolean(snapshot.securityTestRecipients.error)
    || !snapshot.securityTestRecipients.collected;

  let status: Knowbe4Finding["status"];
  let summary: string;
  if (candidates.length === 0) {
    status = "pass";
    summary = `Every active user joined within the last ${inactiveDays} days, so none can be considered inactive yet.`;
  } else if (inactive.length === 0) {
    status = "pass";
    summary = `All ${candidates.length} long-standing active users show phishing, training, or sign-in activity in the last ${inactiveDays} days.`;
  } else if (partialData || (inactivePct !== undefined && inactivePct <= 5)) {
    status = "warn";
    summary = `${inactive.length} of ${candidates.length} active users (${inactivePct}%) show no campaign or sign-in activity in ${inactiveDays} days${partialData ? "; activity data was partial, so review before archiving" : ""}.`;
  } else {
    status = "fail";
    summary = `${inactive.length} of ${candidates.length} active users (${inactivePct}%) have not participated in any campaign or signed in for ${inactiveDays}+ days and should be reviewed for archival.`;
  }

  return finding(18, "medium", status, summary, {
    users_evaluated: candidates.length,
    inactive_users: inactive.length,
    inactive_pct: inactivePct ?? null,
    inactive_days: inactiveDays,
    partial_activity_data: partialData,
    unsampled_security_tests: snapshot.unsampledSecurityTestIds.length,
    inactive_user_sample: sampleLabels(inactive, redact),
  });
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
  const enrollmentLimitReached = snapshot.enrollmentLimitReached;

  const findings = [
    withUserCapCaveat(assessRiskDistribution(snapshot, maxMeanRiskScore, maxStddev, redact), snapshot),
    assessGroupCoverage(snapshot, now, lookbackDays),
    withUserCapCaveat(assessInactiveUsers(snapshot, now, inactiveDays, enrollmentLimitReached, redact), snapshot),
  ];

  return {
    area: "risk",
    title: assessmentTitle("risk"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      account_current_risk_score: asNumber(snapshot.account.data.current_risk_score) ?? null,
      active_users: snapshot.activeUsers.data.length,
      user_limit_reached: snapshot.userLimitReached,
      enrollment_limit_reached: enrollmentLimitReached,
      active_groups: snapshot.groups.data.length,
      phishing_campaigns: snapshot.phishingCampaigns.data.length,
      training_campaigns: snapshot.trainingCampaigns.data.length,
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
  if (snapshot.account.error) return unavailableFinding(12, "high", snapshot.account.error);
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
      admin_count: asRecordArray(snapshot.account.data.admins).length,
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
      latest_security_test: latestTest
        ? { pst_id: testId(latestTest.test), started_at: latestTest.startedAt.toISOString(), days_ago: roundTo(daysBetween(latestTest.startedAt, now)) }
        : null,
      latest_completed_training_campaign: latestTraining
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
        callback_tests_all_time: snapshot.callbackSecurityTests.collected ? runTests(snapshot.callbackSecurityTests.data, now).length : null,
      },
      "Attach the approved policy or risk-acceptance record stating that voice-channel (vishing) testing is out of scope for the awareness program. If it is in scope, export the Callback Phishing campaign list from the KnowBe4 console (Phishing, Callback Phishing) showing tests started in the assessment period.",
    );
  }
  if (!snapshot.callbackSecurityTests.collected || snapshot.callbackSecurityTests.error) {
    return finding(
      16,
      "low",
      "manual",
      `Callback phishing security tests could not be read from the Reporting API${snapshot.callbackSecurityTests.error ? ` (${snapshot.callbackSecurityTests.error})` : ""}, so voice-channel testing must be evidenced from the console.`,
      {
        api_visibility: "callback_security_tests_unreadable",
        collection_error: snapshot.callbackSecurityTests.error ?? null,
        lookback_days: lookbackDays,
      },
      `Export the Callback Phishing campaign list from the KnowBe4 console (Phishing, Callback Phishing) showing at least one test started in the last ${lookbackDays} days, or record a policy statement that voice-channel testing is out of scope.`,
    );
  }
  const recent = testsWithin(snapshot.callbackSecurityTests.data, lookbackDays, now);
  const allTime = runTests(snapshot.callbackSecurityTests.data, now);
  const status = recent.length > 0 ? "pass" : "fail";

  return finding(
    16,
    "low",
    status,
    status === "pass"
      ? `${recent.length} callback (voice-channel) phishing security tests started in the last ${lookbackDays} days.`
      : `No callback (voice-channel) phishing security tests started in the last ${lookbackDays} days${allTime.length > 0 ? `; the last one started ${roundTo(daysBetween(allTime[0].startedAt, now))} days ago` : " and none have ever run"}.`,
    {
      callback_tests_in_window: recent.length,
      callback_tests_all_time: allTime.length,
      latest_callback_test: allTime[0]
        ? { pst_id: testId(allTime[0].test), name: testName(allTime[0].test), started_at: allTime[0].startedAt.toISOString() }
        : null,
      lookback_days: lookbackDays,
      evaluation_note: "Vishing is evaluated through KnowBe4 callback phishing tests, the voice-channel simulation the Reporting API exposes via campaign_type=callback.",
    },
  );
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

  return {
    area: "governance",
    title: assessmentTitle("governance"),
    summary: {
      account_name: asString(snapshot.account.data.name) ?? null,
      account_type: asString(snapshot.account.data.type) ?? null,
      subscription_level: asString(snapshot.account.data.subscription_level) ?? null,
      number_of_seats: asNumber(snapshot.account.data.number_of_seats) ?? null,
      admin_count: asRecordArray(snapshot.account.data.admins).length,
      allowed_domains: accountDomains(snapshot).length,
      callback_security_tests: snapshot.callbackSecurityTests.data.length,
      manual_controls: findings.filter((item) => item.status === "manual").map((item) => item.id),
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
    surface.count === undefined ? "-" : String(surface.count),
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

function formatSummaryValue(value: unknown): string {
  if (typeof value === "number") return String(Number(value.toFixed(2)));
  if (Array.isArray(value)) return value.length > 0 ? value.map(String).join(", ") : "none";
  if (value === null || value === undefined) return "n/a";
  return String(value);
}

function formatAssessmentText(result: Knowbe4AssessmentResult): string {
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
    "- `core_data/` contains raw KnowBe4 Reporting API (and PhishER GraphQL) responses used during this assessment.",
    "- `analysis/` contains normalized findings, per-area assessment summaries, and the 20-control coverage map.",
    "- `compliance/` contains the executive summary, unified matrix, and one report per mapped framework.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Manual findings list the exact console evidence a human must collect; review them before asserting compliance.",
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
  const redact = (value: unknown): unknown => (config.redactPii ? redactKnowbe4Pii(value) : value);

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

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access.json", access],
    ["core_data/account.json", snapshot.account.data],
    ["core_data/account_risk_score_history.json", snapshot.accountRiskHistory.data],
    ["core_data/users_active.json", snapshot.activeUsers.data],
    ["core_data/groups.json", snapshot.groups.data],
    ["core_data/phishing_campaigns.json", snapshot.phishingCampaigns.data],
    ["core_data/security_tests.json", snapshot.securityTests.data],
    ["core_data/security_test_recipients.json", snapshot.securityTestRecipients.data],
    ["core_data/callback_security_tests.json", snapshot.callbackSecurityTests.data],
    ["core_data/training_campaigns.json", snapshot.trainingCampaigns.data],
    ["core_data/training_enrollments.json", snapshot.trainingEnrollments.data],
    ["core_data/store_purchases.json", snapshot.storePurchases.data],
    ["core_data/training_policies.json", snapshot.trainingPolicies.data],
  ];
  if (snapshot.phisherMessages.collected) {
    coreDataFiles.push(["core_data/phisher_messages.json", snapshot.phisherMessages.data]);
  }
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
