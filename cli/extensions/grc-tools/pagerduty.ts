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
  count?: number;
  error?: string;
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
 */
export type PagerdutyListCompletion = "more_flag" | "short_page";

function pageHasMore(payload: JsonRecord, pageLength: number, requestLimit: number, completion: PagerdutyListCompletion): boolean {
  if (pageLength === 0) return false;
  if (typeof payload.more === "boolean" || completion === "more_flag") return payload.more === true;
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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

function readConfigFile(pathname: string | undefined): JsonRecord {
  if (!pathname || !existsSync(pathname)) return {};
  try {
    return asObject(JSON.parse(readFileSync(pathname, "utf8"))) ?? {};
  } catch (error) {
    throw new Error(`Unable to parse PagerDuty config file ${pathname}: ${errorMessage(error)}`);
  }
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
  const configPath = asString(input.config_file)
    ?? asString(env.PAGERDUTY_CONFIG_FILE)
    ?? join(homedir(), DEFAULT_CONFIG_FILE);
  const file = readConfigFile(configPath);
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

function pagerdutyErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  const error = asObject(object?.error);
  if (!error) return asString(object?.message);
  const parts = [
    asString(error.message),
    asString(error.code) ? `code ${asString(error.code)}` : undefined,
    ...asArray(error.errors).map((item) => asString(item)),
  ].filter((item): item is string => Boolean(item));
  return parts.length > 0 ? parts.join("; ") : undefined;
}

export class PagerdutyRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "PagerdutyRequestError";
    this.status = status;
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
  }

  getResolvedConfig(): PagerdutyResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  redact(text: string): string {
    let redacted = text;
    for (const secret of [this.config.apiToken, this.config.accessToken, this.config.clientSecret, this.bearerToken]) {
      if (secret && secret.length > 0) redacted = redacted.split(secret).join("[REDACTED]");
    }
    return redacted;
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
      const payload = rawText.length > 0 ? asObject(JSON.parse(rawText)) ?? {} : {};
      if (!response.ok) {
        throw new PagerdutyRequestError(
          response.status,
          this.redact(`PagerDuty OAuth token request failed (${response.status}): ${asString(payload.error_description) ?? asString(payload.error) ?? rawText.slice(0, 200)}`),
        );
      }
      const token = asString(payload.access_token);
      if (!token) throw new Error("PagerDuty OAuth token response did not include access_token.");
      const expiresIn = asNumber(payload.expires_in) ?? 3600;
      this.bearerToken = token;
      this.bearerExpiresAt = this.now().getTime() + Math.max((expiresIn - 60) * 1000, 60_000);
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
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`PagerDuty request timed out after ${this.config.timeoutMs}ms: ${this.redact(url)}`);
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
      let payload: JsonRecord = {};
      if (rawText.length > 0) {
        try {
          payload = asObject(JSON.parse(rawText)) ?? {};
        } catch {
          payload = {};
        }
      }
      if (!response.ok) {
        const detail = pagerdutyErrorSummary(payload) ?? rawText.slice(0, 240);
        throw new PagerdutyRequestError(
          response.status,
          this.redact(`PagerDuty request failed (${response.status} ${response.statusText}) for ${path}${detail ? `: ${detail}` : ""}`),
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

    while (items.length < limit && offset < CLASSIC_PAGINATION_CAP) {
      const requestLimit = Math.min(pageSize, limit - items.length, CLASSIC_PAGINATION_CAP - offset);
      const payload = await this.get(path, { ...query, limit: requestLimit, offset, total: true });
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      offset += pageItems.length;
      total = asNumber(payload.total) ?? total;
      more = pageHasMore(payload, pageItems.length, requestLimit, completion);
      if (!more) break;
    }

    if (!more) return { items, complete: true, total: total ?? items.length };
    const truncation = offset >= CLASSIC_PAGINATION_CAP
      ? `stopped at the ${CLASSIC_PAGINATION_CAP} record pagination ceiling with more results available`
      : completion === "short_page"
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
    let cursor: string | undefined;

    while (items.length < limit) {
      const payload = await this.get(path, { ...query, limit: Math.min(pageSize, limit - items.length), cursor });
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      cursor = asString(payload.next_cursor);
      if (!cursor || pageItems.length === 0) {
        cursor = undefined;
        break;
      }
    }

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

async function capture<T>(fallback: T, load: () => Promise<T>): Promise<Snapshot<T>> {
  try {
    return { data: await load() };
  } catch (error) {
    return { data: fallback, error: errorMessage(error) };
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
      surfaces.push({ name, endpoint, status: "not_readable", error: message });
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
    capture<PagerdutyCollection>(emptyCollection(), () => client.listUsers(userLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listTeams(teamLimit)),
  ]);
  const teamMembers = await capture<Record<string, JsonRecord[]>>({}, async () => {
    const entries: Record<string, JsonRecord[]> = {};
    for (const team of teams.data.items.slice(0, teamLimit)) {
      const id = asString(team.id);
      if (!id) continue;
      entries[id] = (await client.listTeamMembers(id)).items;
    }
    return entries;
  });
  return { scope, abilities, users, teams, teamMembers };
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
            ? `The account exposes the "sso" ability and ${ssoUsers.length}/${users.seen} returned users were created via SSO. The REST API does not expose whether SSO login is required, so collect a screenshot of Account Settings > Single Sign-On showing SSO enabled and password login disallowed.`
            : `The account exposes ${abilities.length} abilities and "sso" is not one of them, so SSO is not available or not configured for this account.`,
      {
        sso_ability: ssoAbility,
        abilities: abilities.slice(0, 50),
        users_created_via_sso: ssoUsers.length,
        users_not_created_via_sso: nonSsoUsers.slice(0, 25).map(userLabel),
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
        privileged_users: privilegedUsers.slice(0, 25).map((user) => `${userLabel(user)} (${roleOf(user)})`),
        users_without_role: usersWithoutRole.slice(0, 25).map(userLabel),
        role_counts: roleCounts,
        max_admins: maxAdmins,
        users_seen: users.seen,
        users_total: users.total ?? null,
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
      { owners: owners.slice(0, 10).map(userLabel), users_without_role: usersWithoutRole.slice(0, 25).map(userLabel) },
      userNotes,
    ),
    finding(
      4,
      userDirectoryStatus()
        ?? (!teams.readable
          ? "manual"
          : teams.empty || (abilitiesReadable && !abilitiesEmpty && !teamsAbility)
            ? "fail"
            : usersWithoutTeams.length === 0
              ? "pass"
              : usersWithoutTeams.length / users.seen > 0.5
                ? "fail"
                : "warn"),
      userDirectoryStatus()
        ? userDirectorySummary("Review Teams in the web app and confirm every responder belongs to at least one team.")
        : !teams.readable
          ? unreadable(teams, "Review Teams in the web app and confirm every responder belongs to at least one team.")
          : teams.empty || (abilitiesReadable && !abilitiesEmpty && !teamsAbility)
            ? `GET /teams returned ${teams.seen} teams${abilitiesReadable && !teamsAbility ? " and the \"teams\" ability is absent" : ""}, so access is not scoped by team; an empty team list fails this control.`
            : usersWithoutTeams.length === 0
              ? `${countSeen(teams)} are configured and every one of ${countSeen(users)} belongs to at least one team (${teamManagers} team manager assignments sampled${data.teamMembers.error ? `; team membership listing failed: ${data.teamMembers.error}` : ""}).`
              : `${usersWithoutTeams.length} of ${countSeen(users)} do not belong to any team.`,
      {
        teams_ability: abilitiesReadable ? teamsAbility : null,
        teams_seen: teams.seen,
        teams_total: teams.total ?? null,
        team_manager_assignments: teamManagers,
        users_without_teams: usersWithoutTeams.slice(0, 25).map(userLabel),
      },
      partialNotes(data.scope, users, teams),
    ),
    finding(
      24,
      "manual",
      `${abilitiesReadable ? `The REST API exposes ${analyticsAbilities.length} analytics-related abilities` : `Abilities could not be read (${data.abilities.error})`} and never exposes per-role analytics permissions, so this control is outside the API's scope. Record which roles can open Analytics and Insights in the web app (compare the Users page role list against your approved analytics viewer list) and attach that review as evidence.`,
      {
        analytics_abilities: analyticsAbilities,
        role_counts: roleCounts,
      },
    ),
  ];

  return {
    category: "access_control",
    title: "PagerDuty access control",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      abilities: abilities.length,
      sso_ability: ssoAbility,
      users_seen: users.seen,
      users_total: users.total ?? null,
      privileged_users: privilegedUsers.length,
      owners: owners.length,
      teams_seen: teams.seen,
      users_without_teams: usersWithoutTeams.length,
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
    capture<PagerdutyCollection>(emptyCollection(), () => client.listServices(serviceLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listEscalationPolicies()),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listPriorities()),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listIncidentWorkflows()),
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
        services_seen: services.seen,
        services_total: services.total ?? null,
        active_services: active.length,
        services_without_policy: servicesWithoutPolicy.slice(0, 25).map(nameOf),
        disabled_services: services.seen - active.length,
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
        policies_seen: policies.seen,
        policies_total: policies.total ?? null,
        attached_policies: attachedPolicies.length,
        single_level_policies: singleLevelPolicies.slice(0, 25).map(nameOf),
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
        empty_target_policies: emptyTargetPolicies.slice(0, 25).map(nameOf),
        non_repeating_policies: nonRepeatingPolicies.slice(0, 25).map(nameOf),
        policies_missing_num_loops: missingLoops.slice(0, 25).map(nameOf),
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
            ? "pass"
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
            ? `${enabledWorkflows.length} incident workflows with is_enabled true (of ${countSeen(workflows)}) and ${enabledTriggers.length} enabled triggers (of ${countSeen(triggers)}; ${enabledTriggers.length - triggersVerifiedByParent} verified by is_disabled false, ${triggersVerifiedByParent} by the parent workflow's is_enabled) are configured (response plays are deprecated in the REST API; ${legacyResponsePlays.length} services still reference one).`
            : workflows.items.length > 0 || triggers.items.length > 0 || legacyResponsePlays.length > 0
              ? `${countSeen(workflows)} (${enabledWorkflows.length} with is_enabled true) and ${triggerCounts} were read, so automated incident response is not verified${unresolvedTriggers.length > 0 ? " because a trigger without the is_disabled flag could not be matched to a returned workflow with an is_enabled value" : ""}; ${legacyResponsePlays.length} services reference deprecated response plays. Confirm workflow and trigger state in Automation > Incident Workflows.`
              : `The Incident Workflows API is readable and returned zero workflows and zero triggers, and no service references a response play, so no automated incident response is configured; emptiness fails this control.`,
      {
        incident_workflows_seen: workflows.seen,
        enabled_workflows: enabledWorkflows.length,
        triggers_seen: triggers.seen,
        enabled_triggers: enabledTriggers.length,
        disabled_triggers: disabledTriggers.length,
        unresolved_triggers: unresolvedTriggers.slice(0, 25).map((item) => nameOf(item.trigger)),
        triggers_missing_is_disabled_flag: triggersMissingDisabledFlag,
        triggers_verified_by_parent_workflow: triggersVerifiedByParent,
        services_with_legacy_response_plays: legacyResponsePlays.slice(0, 25).map(nameOf),
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
        active_services: active.length,
        services_without_urgency_rule: missingUrgency.slice(0, 25).map(nameOf),
        urgency_modes: urgencyModes.reduce<Record<string, number>>((acc, mode) => ({ ...acc, [mode]: (acc[mode] ?? 0) + 1 }), {}),
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
      { priorities: priorities.items.slice(0, 10).map(nameOf), priorities_seen: priorities.seen },
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
      { active_services: active.length, services_without_ack_timeout: noAckTimeout.slice(0, 25).map(nameOf) },
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
      { active_services: active.length, services_without_auto_resolve: noAutoResolve.slice(0, 25).map(nameOf) },
      serviceNotes,
    ),
  ];

  return {
    category: "incident_response",
    title: "PagerDuty incident response configuration",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      services_seen: services.seen,
      services_total: services.total ?? null,
      active_services: active.length,
      escalation_policies_seen: policies.seen,
      incident_workflows_seen: workflows.seen,
      workflow_triggers_seen: triggers.seen,
      enabled_workflow_triggers: enabledTriggers.length,
      priorities_seen: priorities.seen,
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
    capture<PagerdutyCollection>(emptyCollection(), () => client.listUsers(userLimit)),
  ]);
  const scheduleDetails = await capture<JsonRecord[]>([], async () => {
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
        schedules_seen: schedules.seen,
        attached_schedules: attached.length,
        schedules_with_gaps: schedulesWithGaps.slice(0, 25).map((item) => ({
          schedule: nameOf(item.schedule),
          gaps: item.coverage.gaps.slice(0, 5),
          rendered_coverage_percentage: asNumber(asObject(item.schedule.final_schedule)?.rendered_coverage_percentage) ?? null,
        })),
        schedules_with_undated_entries: schedulesWithUndatedEntries.slice(0, 25).map((item) => ({
          schedule: nameOf(item.schedule),
          entries_missing_dates: item.coverage.entriesMissingDates,
        })),
        unattached_schedules: details.length - attached.length,
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
      { attached_schedules: attached.length, single_participant_schedules: singleParticipant.slice(0, 25).map(nameOf) },
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
        responders: responders.length,
        users_without_role: usersWithoutRole.slice(0, 25).map(userLabel),
        responders_without_rules: respondersWithoutRules.slice(0, 25).map(userLabel),
        responders_without_high_urgency_rule: respondersWithoutHighUrgencyRule.slice(0, 25).map(userLabel),
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
        current_oncall_users: oncallUsers.length,
        oncall_entries_seen: oncalls.seen,
        oncall_users_not_in_returned_set: unresolvedOncallUsers.length,
        oncall_without_contact_methods: oncallWithoutContact.slice(0, 25).map(userLabel),
        oncall_email_only: oncallEmailOnly.slice(0, 25).map(userLabel),
        oncall_unverifiable_methods: oncallUnverifiable.slice(0, 25).map(userLabel),
      },
      partialNotes(data.scope, users, oncalls),
    ),
  ];

  return {
    category: "oncall_coverage",
    title: "PagerDuty on-call coverage",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      schedules_seen: schedules.seen,
      attached_schedules: attached.length,
      schedules_with_gaps: schedulesWithGaps.length,
      single_participant_schedules: singleParticipant.length,
      responders: responders.length,
      current_oncall_users: oncallUsers.length,
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
    capture<PagerdutyCollection>(emptyCollection(), () => client.listAuditRecords(recentSince, now, auditLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listAuditRecords(retentionSince, retentionUntil, 25)),
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
        records_returned: recent.seen,
        records_dated_in_window: recentDated.dated.length,
        records_missing_execution_time: recentDated.undated,
        records_outside_window: recentDated.outside,
        method_types: methodCounts,
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
        probe_records_returned: probe.seen,
        probe_records_dated_in_window: probeDated.dated.length,
        probe_records_missing_execution_time: probeDated.undated,
      },
      auditNotes,
    ),
    finding(
      13,
      "manual",
      recentError
        ? `The REST API has no endpoint that lists API keys or their creation dates, and audit records could not be read (${recentError}). Open Integrations > API Access Keys and each user's User Settings > API Access in the web app, record the Created date of every key, and rotate keys older than ${apiKeyMaxAgeDays} days.`
        : `The REST API has no endpoint that lists API keys or their creation dates; ${apiTokens.length} distinct API tokens (by truncated suffix) performed configuration changes in the last window. Open Integrations > API Access Keys and each user's User Settings > API Access in the web app, record the Created date of every key, and rotate keys older than ${apiKeyMaxAgeDays} days.`,
      { api_key_max_age_days: apiKeyMaxAgeDays, api_tokens_observed: apiTokens.slice(0, 25) },
    ),
  ];

  return {
    category: "audit_logging",
    title: "PagerDuty audit logging",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      recent_records_returned: recent.seen,
      recent_records_dated_in_window: recentDated.dated.length,
      retention_probe_records: probe.seen,
      api_tokens_observed: apiTokens.length,
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
    capture<PagerdutyCollection>(emptyCollection(), () => client.listServices(serviceLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listExtensions()),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listWebhookSubscriptions()),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listBusinessServices(businessServiceLimit)),
    capture<PagerdutyCollection>(emptyCollection(), () => client.listChangeEvents(since, now)),
  ]);
  const businessServiceDependencies = await capture<Record<string, JsonRecord[]>>({}, async () => {
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
        extensions_seen: extensions.seen,
        subscriptions_seen: subscriptions.seen,
        insecure_extensions: insecureExtensions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(item.endpoint_url) ?? "missing"}`),
        insecure_subscriptions: insecureSubscriptions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(asObject(item.delivery_method)?.url) ?? "missing"}`),
        temporarily_disabled_deliveries: disabledDeliveries.slice(0, 25),
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
        extensions_seen: extensions.seen,
        legacy_webhook_extensions: legacyWebhookExtensions.slice(0, 25).map(nameOf),
        unclassified_extensions: unclassifiedExtensions.slice(0, 25).map(nameOf),
        subscriptions_seen: subscriptions.seen,
        active_v3_subscriptions: activeSubscriptions.length,
        subscriptions_missing_active_flag: subscriptionsMissingActive.length,
        subscriptions_with_custom_headers: subscriptions.items.filter((item) => asArray(asObject(item.delivery_method)?.custom_headers).length > 0).length,
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
        services_seen: services.seen,
        integrations: integrations.length,
        services_without_integration_expansion: servicesWithoutIntegrationField.slice(0, 25).map(nameOf),
        legacy_integrations: legacyIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)} (${asString(item.integration.type)})`),
        unfiltered_email_integrations: unfilteredEmailIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)}`),
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
      { business_services_seen: businessServices.seen, unmapped_business_services: unmappedBusinessServices.slice(0, 25).map(nameOf) },
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
        change_events_returned: changeEvents.seen,
        change_events_complete: changeEvents.complete,
        change_events_pagination: CHANGE_EVENTS_PAGINATION_NOTE,
        change_events_dated_in_window: changeEventsDated.dated.length,
        change_events_missing_timestamp: changeEventsDated.undated,
        services_with_change_events: servicesWithChangeEvents.size,
        events_v2_services: eventsV2Services.length,
      },
      partialNotes(data.scope, changeEvents, services),
    ),
  ];

  return {
    category: "integration_security",
    title: "PagerDuty integration security",
    summary: {
      credential_scope: data.scope.error ? "unknown" : data.scope.data.kind,
      extensions_seen: extensions.seen,
      webhook_subscriptions_seen: subscriptions.seen,
      service_integrations: integrations.length,
      business_services_seen: businessServices.seen,
      change_events_returned: changeEvents.seen,
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
    "- `core_data/` contains raw PagerDuty REST API responses captured during this assessment (credentials are never written).",
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

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/credential_scope.json", accessControlData.scope.data],
    ["core_data/abilities.json", accessControlData.abilities.data],
    ["core_data/users.json", accessControlData.users.data],
    ["core_data/teams.json", accessControlData.teams.data],
    ["core_data/team_members.json", accessControlData.teamMembers.data],
    ["core_data/services.json", incidentResponseData.services.data],
    ["core_data/escalation_policies.json", incidentResponseData.escalationPolicies.data],
    ["core_data/priorities.json", incidentResponseData.priorities.data],
    ["core_data/incident_workflows.json", incidentResponseData.incidentWorkflows.data],
    ["core_data/incident_workflow_triggers.json", incidentResponseData.workflowTriggers.data],
    ["core_data/schedules.json", oncallData.schedules.data],
    ["core_data/schedule_details.json", oncallData.scheduleDetails.data],
    ["core_data/oncalls.json", oncallData.oncalls.data],
    ["core_data/audit_records_recent.json", auditData.recentRecords.data],
    ["core_data/audit_records_retention_probe.json", auditData.retentionProbe.data],
    ["core_data/extensions.json", integrationData.extensions.data],
    ["core_data/webhook_subscriptions.json", integrationData.webhookSubscriptions.data],
    ["core_data/business_services.json", integrationData.businessServices.data],
    ["core_data/business_service_dependencies.json", integrationData.businessServiceDependencies.data],
    ["core_data/change_events.json", integrationData.changeEvents.data],
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
      "Export a PagerDuty audit package covering all 25 spec controls with raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified matrix and per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log for partial failures, and a zip archive.",
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
