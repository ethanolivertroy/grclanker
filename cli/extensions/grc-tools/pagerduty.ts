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
const DEFAULT_AUDIT_LIMIT = 500;
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
): PagerdutyFinding {
  const definition = controlDefinition(controlNumber);
  return {
    id: findingId(controlNumber),
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: mappingsFor(definition),
  };
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
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, CLASSIC_PAGINATION_CAP);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const items: JsonRecord[] = [];
    let offset = 0;

    while (items.length < limit && offset < CLASSIC_PAGINATION_CAP) {
      const requestLimit = Math.min(pageSize, limit - items.length, CLASSIC_PAGINATION_CAP - offset);
      const payload = await this.get(path, { ...query, limit: requestLimit, offset });
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      offset += pageItems.length;
      if (payload.more !== true || pageItems.length === 0) break;
    }

    return items;
  }

  async listCursor(
    path: string,
    collectionKey: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 100_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, DEFAULT_PAGE_SIZE);
    const items: JsonRecord[] = [];
    let cursor: string | undefined;

    while (items.length < limit) {
      const payload = await this.get(path, { ...query, limit: Math.min(pageSize, limit - items.length), cursor });
      const pageItems = asRecords(payload[collectionKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      cursor = asString(payload.next_cursor);
      if (!cursor || pageItems.length === 0) break;
    }

    return items;
  }

  async getAbilities(): Promise<string[]> {
    const payload = await this.get("/abilities");
    return asArray(payload.abilities).map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.list("/users", "users", { "include[]": ["contact_methods", "notification_rules", "teams"] }, { limit });
  }

  async listTeams(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/teams", "teams", {}, { limit });
  }

  async listTeamMembers(teamId: string, limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list(`/teams/${encodeURIComponent(teamId)}/members`, "members", {}, { limit });
  }

  async listServices(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/services", "services", { "include[]": ["integrations", "escalation_policies", "teams"] }, { limit });
  }

  async listEscalationPolicies(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/escalation_policies", "escalation_policies", { "include[]": ["services", "teams"] }, { limit });
  }

  async listSchedules(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
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

  async listOncalls(since: Date, until: Date, limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/oncalls", "oncalls", { since: isoDate(since), until: isoDate(until), time_zone: "UTC" }, { limit });
  }

  async listAuditRecords(since: Date, until: Date, limit = DEFAULT_AUDIT_LIMIT): Promise<JsonRecord[]> {
    return this.listCursor("/audit/records", "records", { since: isoDate(since), until: isoDate(until) }, { limit });
  }

  async listExtensions(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/extensions", "extensions", { "include[]": ["extension_schemas"] }, { limit });
  }

  async listWebhookSubscriptions(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/webhook_subscriptions", "webhook_subscriptions", {}, { limit });
  }

  async listBusinessServices(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/business_services", "business_services", {}, { limit });
  }

  async getBusinessServiceDependencies(businessServiceId: string): Promise<JsonRecord[]> {
    const payload = await this.get(`/service_dependencies/business_services/${encodeURIComponent(businessServiceId)}`);
    return asRecords(payload.relationships);
  }

  async listPriorities(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/priorities", "priorities", {}, { limit });
  }

  async listIncidentWorkflows(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/incident_workflows", "incident_workflows", {}, { limit });
  }

  async listIncidentWorkflowTriggers(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.listCursor("/incident_workflows/triggers", "triggers", {}, { limit });
  }

  async listChangeEvents(since: Date, until: Date, limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.list("/change_events", "change_events", { since: isoDate(since), until: isoDate(until) }, { limit });
  }
}

export type PagerdutyClientSurface = Pick<
  PagerdutyApiClient,
  | "getResolvedConfig"
  | "getNow"
  | "getAbilities"
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
      surfaces.push({ name, endpoint, status: "readable", count: Array.isArray(value) ? value.length : undefined });
    } catch (error) {
      const message = errorMessage(error);
      surfaces.push({ name, endpoint, status: "not_readable", error: message });
      missingPermissions.push(`${endpoint}: ${permission}`);
    }
  }

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const coreSurfaces = ["abilities", "users", "teams", "services", "escalation_policies", "schedules"];
  const coreReadable = surfaces.filter((surface) => coreSurfaces.includes(surface.name) && surface.status === "readable").length;
  const status = coreReadable === coreSurfaces.length && readableCount >= surfaces.length - 2 ? "healthy" : "limited";

  return {
    status,
    region: config.region,
    authMode: config.authMode,
    surfaces,
    missingPermissions,
    notes: [
      `Using PagerDuty ${config.region.toUpperCase()} service region at ${config.baseUrl} with ${config.authMode} authentication.`,
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
  abilities: Snapshot<string[]>;
  users: Snapshot<JsonRecord[]>;
  teams: Snapshot<JsonRecord[]>;
  teamMembers: Snapshot<Record<string, JsonRecord[]>>;
}

export async function collectPagerdutyAccessControlData(
  client: PagerdutyClientSurface,
  options: { userLimit?: number; teamLimit?: number } = {},
): Promise<PagerdutyAccessControlData> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const teamLimit = clampNumber(options.teamLimit, DEFAULT_TEAM_LIMIT, 1, 500);
  const [abilities, users, teams] = await Promise.all([
    capture<string[]>([], () => client.getAbilities()),
    capture<JsonRecord[]>([], () => client.listUsers(userLimit)),
    capture<JsonRecord[]>([], () => client.listTeams(teamLimit)),
  ]);
  const teamMembers = await capture<Record<string, JsonRecord[]>>({}, async () => {
    const entries: Record<string, JsonRecord[]> = {};
    for (const team of teams.data.slice(0, teamLimit)) {
      const id = asString(team.id);
      if (!id) continue;
      entries[id] = await client.listTeamMembers(id);
    }
    return entries;
  });
  return { abilities, users, teams, teamMembers };
}

export function assessPagerdutyAccessControl(
  data: PagerdutyAccessControlData,
  options: { maxAdmins?: number } = {},
): PagerdutyAssessmentResult {
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 1, 1000);
  const abilities = data.abilities.data;
  const users = data.users.data;
  const teams = data.teams.data;
  const ssoAbility = abilities.includes("sso");
  const teamsAbility = abilities.includes("teams");
  const ssoUsers = users.filter((user) => user.created_via_sso === true);
  const nonSsoUsers = users.filter((user) => user.created_via_sso !== true);
  const privilegedUsers = users.filter((user) => PRIVILEGED_ROLES.has(roleOf(user)));
  const owners = users.filter((user) => roleOf(user) === "owner");
  const usersWithoutTeams = users.filter((user) => asArray(user.teams).length === 0);
  const teamManagers = Object.values(data.teamMembers.data)
    .flat()
    .filter((member) => /manager/i.test(asString(member.role) ?? "")).length;
  const roleCounts: Record<string, number> = {};
  for (const user of users) roleCounts[roleOf(user)] = (roleCounts[roleOf(user)] ?? 0) + 1;
  const analyticsAbilities = abilities.filter((ability) => /analytic|insight|report/i.test(ability));
  const usersVisible = !data.users.error && users.length > 0;

  const findings: PagerdutyFinding[] = [
    finding(
      1,
      data.abilities.error ? "manual" : ssoAbility ? "manual" : "fail",
      data.abilities.error
        ? `Abilities could not be read (${data.abilities.error}). Collect a screenshot of Account Settings > Single Sign-On showing SSO configured and the option that requires SSO login enabled.`
        : ssoAbility
          ? `The account exposes the "sso" ability and ${ssoUsers.length}/${users.length} sampled users were created via SSO. The REST API does not expose whether SSO login is required, so collect a screenshot of Account Settings > Single Sign-On showing SSO enabled and password login disallowed.`
          : "The account does not expose the \"sso\" ability, so SSO is not available or not configured for this account.",
      {
        sso_ability: ssoAbility,
        abilities: abilities.slice(0, 50),
        users_created_via_sso: ssoUsers.length,
        users_not_created_via_sso: nonSsoUsers.slice(0, 25).map(userLabel),
      },
    ),
    finding(
      2,
      !usersVisible ? "manual" : privilegedUsers.length <= maxAdmins ? "pass" : "fail",
      !usersVisible
        ? `Users could not be read (${data.users.error ?? "no users returned"}). Export the Users page with roles from the web app and confirm the number of Account Owner and Global Admin users.`
        : privilegedUsers.length <= maxAdmins
          ? `${privilegedUsers.length}/${users.length} sampled users hold owner or admin roles, within the threshold of ${maxAdmins}.`
          : `${privilegedUsers.length}/${users.length} sampled users hold owner or admin roles, exceeding the threshold of ${maxAdmins}.`,
      {
        privileged_users: privilegedUsers.slice(0, 25).map((user) => `${userLabel(user)} (${roleOf(user)})`),
        role_counts: roleCounts,
        max_admins: maxAdmins,
      },
    ),
    finding(
      3,
      !usersVisible ? "manual" : owners.length === 1 ? "pass" : owners.length === 0 ? "warn" : "fail",
      !usersVisible
        ? `Users could not be read (${data.users.error ?? "no users returned"}). Confirm on the Users page that exactly one user holds the Account Owner role.`
        : owners.length === 1
          ? "Exactly one sampled user holds the owner role."
          : owners.length === 0
            ? "No sampled user exposed the owner role; confirm the account owner is within the sampled user set."
            : `${owners.length} sampled users hold the owner role; PagerDuty accounts should have a single account owner.`,
      { owners: owners.slice(0, 10).map(userLabel) },
    ),
    finding(
      4,
      !usersVisible
        ? "manual"
        : !teamsAbility || teams.length === 0
          ? "fail"
          : usersWithoutTeams.length === 0
            ? "pass"
            : usersWithoutTeams.length / users.length > 0.5
              ? "fail"
              : "warn",
      !usersVisible
        ? `Users could not be read (${data.users.error ?? "no users returned"}). Review Teams in the web app and confirm every responder belongs to at least one team.`
        : !teamsAbility || teams.length === 0
          ? "No teams are configured (or the teams ability is missing), so access is not scoped by team."
          : usersWithoutTeams.length === 0
            ? `${teams.length} teams are configured and every sampled user belongs to at least one team (${teamManagers} team manager assignments sampled).`
            : `${usersWithoutTeams.length}/${users.length} sampled users do not belong to any team.`,
      {
        teams_ability: teamsAbility,
        teams: teams.length,
        team_manager_assignments: teamManagers,
        users_without_teams: usersWithoutTeams.slice(0, 25).map(userLabel),
      },
    ),
    finding(
      24,
      "manual",
      `The REST API exposes ${analyticsAbilities.length} analytics-related abilities but not per-role analytics permissions. Record which roles can open Analytics and Insights in the web app (compare the Users page role list against your approved analytics viewer list) and attach that review as evidence.`,
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
      abilities: abilities.length,
      sso_ability: ssoAbility,
      sampled_users: users.length,
      privileged_users: privilegedUsers.length,
      owners: owners.length,
      teams: teams.length,
      users_without_teams: usersWithoutTeams.length,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("access_control", {
      abilities: data.abilities,
      users: data.users,
      teams: data.teams,
      team_members: data.teamMembers,
    }),
  };
}

export interface PagerdutyIncidentResponseData {
  services: Snapshot<JsonRecord[]>;
  escalationPolicies: Snapshot<JsonRecord[]>;
  priorities: Snapshot<JsonRecord[]>;
  incidentWorkflows: Snapshot<JsonRecord[]>;
  workflowTriggers: Snapshot<JsonRecord[]>;
}

export async function collectPagerdutyIncidentResponseData(
  client: PagerdutyClientSurface,
  options: { serviceLimit?: number } = {},
): Promise<PagerdutyIncidentResponseData> {
  const serviceLimit = clampNumber(options.serviceLimit, DEFAULT_LIST_LIMIT, 1, CLASSIC_PAGINATION_CAP);
  const [services, escalationPolicies, priorities, incidentWorkflows, workflowTriggers] = await Promise.all([
    capture<JsonRecord[]>([], () => client.listServices(serviceLimit)),
    capture<JsonRecord[]>([], () => client.listEscalationPolicies()),
    capture<JsonRecord[]>([], () => client.listPriorities()),
    capture<JsonRecord[]>([], () => client.listIncidentWorkflows()),
    capture<JsonRecord[]>([], () => client.listIncidentWorkflowTriggers()),
  ]);
  return { services, escalationPolicies, priorities, incidentWorkflows, workflowTriggers };
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

export function assessPagerdutyIncidentResponse(data: PagerdutyIncidentResponseData): PagerdutyAssessmentResult {
  const services = data.services.data;
  const active = activeServices(services);
  const policies = data.escalationPolicies.data;
  const servicesVisible = !data.services.error;
  const policiesVisible = !data.escalationPolicies.error;

  const servicesWithoutPolicy = active.filter((service) => !referenceId(service.escalation_policy));
  const attachedPolicies = policies.filter((policy) => asArray(policy.services).length > 0);
  const singleLevelPolicies = attachedPolicies.filter((policy) => asArray(policy.escalation_rules).length < 2);
  const emptyTargetPolicies = policies.filter((policy) =>
    asRecords(policy.escalation_rules).some((rule) => asArray(rule.targets).length === 0));
  const nonRepeatingPolicies = attachedPolicies.filter((policy) => (asNumber(policy.num_loops) ?? 0) === 0);
  const workflows = data.incidentWorkflows.data;
  const enabledWorkflows = workflows.filter((workflow) => workflow.is_enabled !== false);
  const triggers = data.workflowTriggers.data;
  const legacyResponsePlays = services.filter((service) => asArray(service.response_play).length > 0 || asObject(service.response_play));
  const urgencyModes = active.map(urgencySummary);
  const constantHighOnly = urgencyModes.length > 0 && urgencyModes.every((mode) => mode === "constant:high");
  const missingUrgency = active.filter((service) => !asObject(service.incident_urgency_rule));
  const priorities = data.priorities.data;
  const noAckTimeout = active.filter((service) => asNumber(service.acknowledgement_timeout) === undefined);
  const noAutoResolve = active.filter((service) => asNumber(service.auto_resolve_timeout) === undefined);

  const manualServices = (subject: string) =>
    `Services could not be read (${data.services.error}). Review each service's Settings page in the web app and record ${subject}.`;

  const findings: PagerdutyFinding[] = [
    finding(
      5,
      !servicesVisible ? "manual" : servicesWithoutPolicy.length === 0 ? "pass" : "fail",
      !servicesVisible
        ? manualServices("the assigned escalation policy")
        : servicesWithoutPolicy.length === 0
          ? `All ${active.length} active services reference an escalation policy.`
          : `${servicesWithoutPolicy.length}/${active.length} active services have no escalation policy.`,
      { services_without_policy: servicesWithoutPolicy.slice(0, 25).map(nameOf), disabled_services: services.length - active.length },
    ),
    finding(
      6,
      !policiesVisible ? "manual" : singleLevelPolicies.length === 0 ? "pass" : "warn",
      !policiesVisible
        ? `Escalation policies could not be read (${data.escalationPolicies.error}). Review each escalation policy in the web app and record the number of escalation levels.`
        : singleLevelPolicies.length === 0
          ? `All ${attachedPolicies.length} escalation policies attached to services define two or more escalation levels.`
          : `${singleLevelPolicies.length}/${attachedPolicies.length} escalation policies attached to services define a single escalation level.`,
      { single_level_policies: singleLevelPolicies.slice(0, 25).map(nameOf), total_policies: policies.length },
    ),
    finding(
      7,
      !policiesVisible ? "manual" : emptyTargetPolicies.length > 0 ? "fail" : nonRepeatingPolicies.length > 0 ? "warn" : "pass",
      !policiesVisible
        ? `Escalation policies could not be read (${data.escalationPolicies.error}). Confirm every escalation rule has at least one target and the policy repeats if nobody acknowledges.`
        : emptyTargetPolicies.length > 0
          ? `${emptyTargetPolicies.length} escalation policies contain rules with no notification targets.`
          : nonRepeatingPolicies.length > 0
            ? `${nonRepeatingPolicies.length}/${attachedPolicies.length} attached escalation policies never repeat (num_loops is 0), so an unacknowledged incident stops notifying after the final level.`
            : "Every attached escalation policy has targets on each level and repeats after the final level.",
      { empty_target_policies: emptyTargetPolicies.slice(0, 25).map(nameOf), non_repeating_policies: nonRepeatingPolicies.slice(0, 25).map(nameOf) },
    ),
    finding(
      10,
      data.incidentWorkflows.error
        ? "manual"
        : enabledWorkflows.length > 0 && triggers.length > 0
          ? "pass"
          : workflows.length > 0 || legacyResponsePlays.length > 0
            ? "warn"
            : "fail",
      data.incidentWorkflows.error
        ? `Incident workflows could not be read (${data.incidentWorkflows.error}). Record the configured Incident Workflows and their service triggers from Automation > Incident Workflows in the web app.`
        : enabledWorkflows.length > 0 && triggers.length > 0
          ? `${enabledWorkflows.length} enabled incident workflows with ${triggers.length} triggers are configured (response plays are deprecated in the REST API; ${legacyResponsePlays.length} services still reference one).`
          : workflows.length > 0 || legacyResponsePlays.length > 0
            ? `${workflows.length} incident workflows exist but none are both enabled and attached to a trigger; ${legacyResponsePlays.length} services reference deprecated response plays.`
            : "No incident workflows or response plays are configured for automated incident response.",
      {
        incident_workflows: workflows.length,
        enabled_workflows: enabledWorkflows.length,
        triggers: triggers.length,
        services_with_legacy_response_plays: legacyResponsePlays.slice(0, 25).map(nameOf),
      },
    ),
    finding(
      19,
      !servicesVisible ? "manual" : missingUrgency.length > 0 ? "fail" : constantHighOnly ? "warn" : "pass",
      !servicesVisible
        ? manualServices("the incident urgency rule")
        : missingUrgency.length > 0
          ? `${missingUrgency.length} active services do not expose an incident urgency rule.`
          : constantHighOnly
            ? `All ${active.length} active services use a constant high urgency; consider support-hours or severity-based urgency for lower-impact services.`
            : `Active services use a mix of urgency rules: ${[...new Set(urgencyModes)].join(", ")}.`,
      { urgency_modes: urgencyModes.reduce<Record<string, number>>((acc, mode) => ({ ...acc, [mode]: (acc[mode] ?? 0) + 1 }), {}) },
    ),
    finding(
      20,
      data.priorities.error ? "manual" : priorities.length > 0 ? "pass" : "fail",
      data.priorities.error
        ? `Priorities could not be read (${data.priorities.error}). Record the incident priority levels from Account Settings > Incident Priority.`
        : priorities.length > 0
          ? `${priorities.length} incident priorities are defined (${priorities.slice(0, 10).map(nameOf).join(", ")}); confirm they are applied to incidents during postmortem review.`
          : "No incident priorities are defined for the account.",
      { priorities: priorities.slice(0, 10).map(nameOf) },
    ),
    finding(
      22,
      !servicesVisible ? "manual" : noAckTimeout.length === 0 ? "pass" : "warn",
      !servicesVisible
        ? manualServices("the acknowledgement timeout")
        : noAckTimeout.length === 0
          ? `All ${active.length} active services configure an acknowledgement timeout.`
          : `${noAckTimeout.length}/${active.length} active services have acknowledgement timeout disabled.`,
      { services_without_ack_timeout: noAckTimeout.slice(0, 25).map(nameOf) },
    ),
    finding(
      23,
      !servicesVisible ? "manual" : noAutoResolve.length === 0 ? "pass" : "warn",
      !servicesVisible
        ? manualServices("the auto-resolve timeout")
        : noAutoResolve.length === 0
          ? `All ${active.length} active services configure an auto-resolve timeout.`
          : `${noAutoResolve.length}/${active.length} active services have auto-resolve disabled.`,
      { services_without_auto_resolve: noAutoResolve.slice(0, 25).map(nameOf) },
    ),
  ];

  return {
    category: "incident_response",
    title: "PagerDuty incident response configuration",
    summary: {
      services: services.length,
      active_services: active.length,
      escalation_policies: policies.length,
      incident_workflows: workflows.length,
      priorities: priorities.length,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("incident_response", {
      services: data.services,
      escalation_policies: data.escalationPolicies,
      priorities: data.priorities,
      incident_workflows: data.incidentWorkflows,
      workflow_triggers: data.workflowTriggers,
    }),
  };
}

export interface PagerdutyOncallCoverageData {
  schedules: Snapshot<JsonRecord[]>;
  scheduleDetails: Snapshot<JsonRecord[]>;
  oncalls: Snapshot<JsonRecord[]>;
  users: Snapshot<JsonRecord[]>;
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
  const [schedules, oncalls, users] = await Promise.all([
    capture<JsonRecord[]>([], () => client.listSchedules(scheduleLimit)),
    capture<JsonRecord[]>([], () => client.listOncalls(now, daysAhead(now, 1))),
    capture<JsonRecord[]>([], () => client.listUsers(userLimit)),
  ]);
  const scheduleDetails = await capture<JsonRecord[]>([], async () => {
    const details: JsonRecord[] = [];
    for (const schedule of schedules.data.slice(0, scheduleLimit)) {
      const id = asString(schedule.id);
      if (!id) continue;
      details.push(await client.getSchedule(id, now, until));
    }
    return details;
  });
  return {
    schedules,
    scheduleDetails,
    oncalls,
    users,
    coverageWindow: { since: isoDate(now), until: isoDate(until), days: coverageDays },
  };
}

export function scheduleCoverageGaps(schedule: JsonRecord, since: Date, until: Date): Array<{ start: string; end: string }> {
  const entries = asRecords(asObject(schedule.final_schedule)?.rendered_schedule_entries)
    .map((entry) => ({ start: parseDate(entry.start), end: parseDate(entry.end) }))
    .filter((entry): entry is { start: Date; end: Date | undefined } => Boolean(entry.start))
    .sort((left, right) => left.start.getTime() - right.start.getTime());
  const gaps: Array<{ start: string; end: string }> = [];
  let cursor = since.getTime();
  for (const entry of entries) {
    const start = entry.start.getTime();
    const end = entry.end ? entry.end.getTime() : until.getTime();
    if (start > cursor) gaps.push({ start: isoDate(new Date(cursor)), end: isoDate(new Date(start)) });
    cursor = Math.max(cursor, end);
    if (cursor >= until.getTime()) break;
  }
  if (cursor < until.getTime()) gaps.push({ start: isoDate(new Date(cursor)), end: isoDate(until) });
  return gaps;
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

function contactMethodTypes(user: JsonRecord): string[] {
  return asRecords(user.contact_methods)
    .filter((method) => method.blacklisted !== true && method.enabled !== false)
    .map((method) => asString(method.type) ?? "unknown");
}

export function assessPagerdutyOncallCoverage(data: PagerdutyOncallCoverageData): PagerdutyAssessmentResult {
  const since = new Date(data.coverageWindow.since);
  const until = new Date(data.coverageWindow.until);
  const details = data.scheduleDetails.data;
  const attached = details.filter(scheduleIsAttached);
  const schedulesWithGaps = attached
    .map((schedule) => ({ schedule, gaps: scheduleCoverageGaps(schedule, since, until) }))
    .filter((item) => item.gaps.length > 0);
  const singleParticipant = attached.filter((schedule) => distinctScheduleUsers(schedule).size < 2);
  const users = data.users.data;
  const responders = users.filter((user) => RESPONDER_ROLES.has(roleOf(user)));
  const respondersWithoutRules = responders.filter((user) => asArray(user.notification_rules).length === 0);
  const respondersWithoutHighUrgencyRule = responders.filter((user) =>
    asArray(user.notification_rules).length > 0
    && !asRecords(user.notification_rules).some((rule) => asString(rule.urgency) === "high"));
  const oncallUserIds = new Set(
    data.oncalls.data.map((oncall) => referenceId(oncall.user)).filter((id): id is string => Boolean(id)),
  );
  const oncallUsers = users.filter((user) => oncallUserIds.has(asString(user.id) ?? ""));
  const oncallWithoutContact = oncallUsers.filter((user) => contactMethodTypes(user).length === 0);
  const oncallEmailOnly = oncallUsers.filter((user) => {
    const types = contactMethodTypes(user);
    return types.length > 0 && types.every((type) => type === "email_contact_method");
  });
  const unresolvedOncallUsers = [...oncallUserIds].filter((id) => !users.some((user) => asString(user.id) === id));
  const schedulesVisible = !data.schedules.error && !data.scheduleDetails.error;
  const usersVisible = !data.users.error;
  const oncallsVisible = !data.oncalls.error;

  const findings: PagerdutyFinding[] = [
    finding(
      8,
      !schedulesVisible ? "manual" : schedulesWithGaps.length === 0 ? "pass" : "fail",
      !schedulesVisible
        ? `Schedules could not be read (${data.schedules.error ?? data.scheduleDetails.error}). Open each on-call schedule in the web app, switch to the final schedule view for the next ${data.coverageWindow.days} days, and record any uncovered time.`
        : schedulesWithGaps.length === 0
          ? `All ${attached.length} schedules attached to escalation policies render continuous final-schedule coverage from ${data.coverageWindow.since} to ${data.coverageWindow.until}.`
          : `${schedulesWithGaps.length}/${attached.length} attached schedules have coverage gaps in the next ${data.coverageWindow.days} days.`,
      {
        coverage_window: data.coverageWindow,
        schedules_with_gaps: schedulesWithGaps.slice(0, 25).map((item) => ({
          schedule: nameOf(item.schedule),
          gaps: item.gaps.slice(0, 5),
          rendered_coverage_percentage: asNumber(asObject(item.schedule.final_schedule)?.rendered_coverage_percentage) ?? null,
        })),
        unattached_schedules: details.length - attached.length,
      },
    ),
    finding(
      9,
      !schedulesVisible ? "manual" : singleParticipant.length === 0 ? "pass" : "fail",
      !schedulesVisible
        ? `Schedules could not be read (${data.schedules.error ?? data.scheduleDetails.error}). Record the number of distinct participants on each on-call schedule from the web app.`
        : singleParticipant.length === 0
          ? `All ${attached.length} attached schedules include at least two distinct participants.`
          : `${singleParticipant.length}/${attached.length} attached schedules rely on a single participant.`,
      { single_participant_schedules: singleParticipant.slice(0, 25).map(nameOf) },
    ),
    finding(
      17,
      !usersVisible
        ? "manual"
        : respondersWithoutRules.length === 0 && respondersWithoutHighUrgencyRule.length === 0
          ? "pass"
          : respondersWithoutRules.length / Math.max(responders.length, 1) > 0.25
            ? "fail"
            : "warn",
      !usersVisible
        ? `Users could not be read (${data.users.error}). Review each responder's notification rules in the web app and record users with no high-urgency rule.`
        : respondersWithoutRules.length === 0 && respondersWithoutHighUrgencyRule.length === 0
          ? `All ${responders.length} sampled responders define notification rules including a high-urgency rule.`
          : `${respondersWithoutRules.length} sampled responders have no notification rules and ${respondersWithoutHighUrgencyRule.length} have no high-urgency rule.`,
      {
        sampled_responders: responders.length,
        responders_without_rules: respondersWithoutRules.slice(0, 25).map(userLabel),
        responders_without_high_urgency_rule: respondersWithoutHighUrgencyRule.slice(0, 25).map(userLabel),
      },
    ),
    finding(
      18,
      !oncallsVisible || !usersVisible
        ? "manual"
        : oncallWithoutContact.length > 0
          ? "fail"
          : oncallEmailOnly.length > 0
            ? "warn"
            : "pass",
      !oncallsVisible || !usersVisible
        ? `On-call or user data could not be read (${data.oncalls.error ?? data.users.error}). Review the contact methods of every current on-call responder in the web app and record any unverified phone or SMS methods.`
        : oncallWithoutContact.length > 0
          ? `${oncallWithoutContact.length}/${oncallUsers.length} current on-call users have no active contact methods.`
          : oncallEmailOnly.length > 0
            ? `${oncallEmailOnly.length}/${oncallUsers.length} current on-call users rely on email only; the REST API does not expose phone verification status, so confirm phone or push methods are verified in the web app.`
            : `All ${oncallUsers.length} current on-call users have phone, SMS, or push contact methods that are enabled and not blocked.`,
      {
        current_oncall_users: oncallUsers.length,
        oncall_users_not_in_sample: unresolvedOncallUsers.length,
        oncall_without_contact_methods: oncallWithoutContact.slice(0, 25).map(userLabel),
        oncall_email_only: oncallEmailOnly.slice(0, 25).map(userLabel),
      },
    ),
  ];

  return {
    category: "oncall_coverage",
    title: "PagerDuty on-call coverage",
    summary: {
      schedules: details.length,
      attached_schedules: attached.length,
      schedules_with_gaps: schedulesWithGaps.length,
      single_participant_schedules: singleParticipant.length,
      sampled_responders: responders.length,
      current_oncall_users: oncallUsers.length,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("oncall_coverage", {
      schedules: data.schedules,
      schedule_details: data.scheduleDetails,
      oncalls: data.oncalls,
      users: data.users,
    }),
  };
}

export interface PagerdutyAuditLoggingData {
  recentRecords: Snapshot<JsonRecord[]>;
  retentionProbe: Snapshot<JsonRecord[]>;
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
  const [recentRecords, retentionProbe] = await Promise.all([
    capture<JsonRecord[]>([], () => client.listAuditRecords(recentSince, now, auditLimit)),
    capture<JsonRecord[]>([], () => client.listAuditRecords(retentionSince, retentionUntil, 25)),
  ]);
  return {
    recentRecords,
    retentionProbe,
    windows: {
      recent: { since: isoDate(recentSince), until: isoDate(now) },
      retention: { since: isoDate(retentionSince), until: isoDate(retentionUntil) },
    },
  };
}

export function assessPagerdutyAuditLogging(
  data: PagerdutyAuditLoggingData,
  options: { minRetentionDays?: number; apiKeyMaxAgeDays?: number } = {},
): PagerdutyAssessmentResult {
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 1, 3650);
  const apiKeyMaxAgeDays = clampNumber(options.apiKeyMaxAgeDays, DEFAULT_API_KEY_MAX_AGE_DAYS, 1, 3650);
  const records = data.recentRecords.data;
  const recentError = data.recentRecords.error;
  const recentStatus = requestStatus(recentError);
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

  const findings: PagerdutyFinding[] = [
    finding(
      11,
      recentError
        ? recentStatus === 402
          ? "fail"
          : "manual"
        : records.length > 0
          ? "pass"
          : "warn",
      recentError
        ? recentStatus === 402
          ? `The audit records API returned 402, so the Audit Trail feature is not included in this account's plan (${recentError}).`
          : `Audit records could not be read (${recentError}). Use an admin or global API key, or export the audit trail from the web app to evidence that logging is active.`
        : records.length > 0
          ? `${records.length} audit records were retrieved for ${data.windows.recent.since} to ${data.windows.recent.until}.`
          : `The audit records API is readable but returned no records between ${data.windows.recent.since} and ${data.windows.recent.until}.`,
      { window: data.windows.recent, records: records.length, method_types: methodCounts },
    ),
    finding(
      12,
      recentError
        ? "manual"
        : minRetentionDays > 365
          ? "manual"
          : data.retentionProbe.error
            ? "warn"
            : data.retentionProbe.data.length > 0
              ? "pass"
              : "warn",
      recentError
        ? `Audit records could not be read (${recentError}), so retention could not be probed. Confirm audit records or a SIEM export cover at least ${minRetentionDays} days.`
        : minRetentionDays > 365
          ? `PagerDuty documents 12 months of audit record retention, which is shorter than the required ${minRetentionDays} days; attach evidence that audit records are exported to a SIEM or archive that meets the requirement.`
          : data.retentionProbe.error
            ? `The 11-to-12-month retention window could not be probed (${data.retentionProbe.error}); PagerDuty documents 12 months of retention.`
            : data.retentionProbe.data.length > 0
              ? `${data.retentionProbe.data.length} audit records were retrievable from ${data.windows.retention.since} to ${data.windows.retention.until}, consistent with the documented 12-month retention and the ${minRetentionDays}-day requirement.`
              : `No audit records were returned for ${data.windows.retention.since} to ${data.windows.retention.until}; the account may be younger than 12 months or had no configuration changes then. PagerDuty documents 12 months of retention.`,
      { documented_retention_days: 365, required_retention_days: minRetentionDays, probe_window: data.windows.retention, probe_records: data.retentionProbe.data.length },
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
      recent_records: records.length,
      retention_probe_records: data.retentionProbe.data.length,
      api_tokens_observed: apiTokens.length,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("audit_logging", {
      recent_records: data.recentRecords,
      retention_probe: data.retentionProbe,
    }),
  };
}

export interface PagerdutyIntegrationSecurityData {
  services: Snapshot<JsonRecord[]>;
  extensions: Snapshot<JsonRecord[]>;
  webhookSubscriptions: Snapshot<JsonRecord[]>;
  businessServices: Snapshot<JsonRecord[]>;
  businessServiceDependencies: Snapshot<Record<string, JsonRecord[]>>;
  changeEvents: Snapshot<JsonRecord[]>;
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
  const [services, extensions, webhookSubscriptions, businessServices, changeEvents] = await Promise.all([
    capture<JsonRecord[]>([], () => client.listServices(serviceLimit)),
    capture<JsonRecord[]>([], () => client.listExtensions()),
    capture<JsonRecord[]>([], () => client.listWebhookSubscriptions()),
    capture<JsonRecord[]>([], () => client.listBusinessServices(businessServiceLimit)),
    capture<JsonRecord[]>([], () => client.listChangeEvents(since, now)),
  ]);
  const businessServiceDependencies = await capture<Record<string, JsonRecord[]>>({}, async () => {
    const entries: Record<string, JsonRecord[]> = {};
    for (const businessService of businessServices.data.slice(0, businessServiceLimit)) {
      const id = asString(businessService.id);
      if (!id) continue;
      entries[id] = await client.getBusinessServiceDependencies(id);
    }
    return entries;
  });
  return {
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

function isGenericWebhookExtension(extension: JsonRecord): boolean {
  const schema = asObject(extension.extension_schema);
  const label = `${asString(schema?.summary) ?? ""} ${asString(schema?.key) ?? ""} ${asString(schema?.label) ?? ""}`;
  return /webhook/i.test(label);
}

function isHttpsUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

export function assessPagerdutyIntegrationSecurity(data: PagerdutyIntegrationSecurityData): PagerdutyAssessmentResult {
  const extensions = data.extensions.data;
  const subscriptions = data.webhookSubscriptions.data;
  const webhooksVisible = !data.extensions.error && !data.webhookSubscriptions.error;
  const insecureExtensions = extensions.filter((extension) => !isHttpsUrl(asString(extension.endpoint_url)));
  const insecureSubscriptions = subscriptions.filter((subscription) => !isHttpsUrl(asString(asObject(subscription.delivery_method)?.url)));
  const disabledDeliveries = [
    ...extensions.filter((extension) => extension.temporarily_disabled === true).map(nameOf),
    ...subscriptions.filter((subscription) => asObject(subscription.delivery_method)?.temporarily_disabled === true).map(nameOf),
  ];
  const legacyWebhookExtensions = extensions.filter(isGenericWebhookExtension);
  const activeSubscriptions = subscriptions.filter((subscription) => subscription.active !== false);

  const services = data.services.data;
  const integrations = services.flatMap((service) =>
    asRecords(service.integrations).map((integration) => ({ service: nameOf(service), integration })));
  const legacyIntegrations = integrations.filter((item) => LEGACY_INTEGRATION_TYPES.has(asString(item.integration.type) ?? ""));
  const unfilteredEmailIntegrations = integrations.filter((item) =>
    asString(item.integration.type) === "generic_email_inbound_integration"
    && (asString(item.integration.email_filter_mode) ?? "all-email") === "all-email");
  const eventsV2Services = services.filter((service) =>
    asRecords(service.integrations).some((integration) => asString(integration.type) === "events_api_v2_inbound_integration"));

  const businessServices = data.businessServices.data;
  const dependencyMap = data.businessServiceDependencies.data;
  const unmappedBusinessServices = businessServices.filter((businessService) =>
    (dependencyMap[asString(businessService.id) ?? ""] ?? []).length === 0);
  const changeEvents = data.changeEvents.data;
  const servicesWithChangeEvents = new Set(
    changeEvents.flatMap((event) => asRecords(event.services).map((service) => asString(service.id)).filter(Boolean)),
  );

  const findings: PagerdutyFinding[] = [
    finding(
      14,
      !webhooksVisible ? "manual" : insecureExtensions.length + insecureSubscriptions.length === 0 ? "pass" : "fail",
      !webhooksVisible
        ? `Extensions or webhook subscriptions could not be read (${data.extensions.error ?? data.webhookSubscriptions.error}). Record every webhook destination URL from Integrations > Generic Webhooks and each service's Integrations tab and confirm they use https.`
        : insecureExtensions.length + insecureSubscriptions.length === 0
          ? `All ${extensions.length} extensions and ${subscriptions.length} v3 webhook subscriptions deliver to https endpoints.`
          : `${insecureExtensions.length} extensions and ${insecureSubscriptions.length} webhook subscriptions deliver to non-https endpoints.`,
      {
        insecure_extensions: insecureExtensions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(item.endpoint_url) ?? "missing"}`),
        insecure_subscriptions: insecureSubscriptions.slice(0, 25).map((item) => `${nameOf(item)} -> ${asString(asObject(item.delivery_method)?.url) ?? "missing"}`),
        temporarily_disabled_deliveries: disabledDeliveries.slice(0, 25),
      },
    ),
    finding(
      15,
      !webhooksVisible ? "manual" : legacyWebhookExtensions.length > 0 ? "warn" : "pass",
      !webhooksVisible
        ? `Extensions or webhook subscriptions could not be read (${data.extensions.error ?? data.webhookSubscriptions.error}). Record which webhooks are v3 subscriptions (signed with X-PagerDuty-Signature) versus legacy generic webhook extensions.`
        : legacyWebhookExtensions.length > 0
          ? `${legacyWebhookExtensions.length} legacy generic webhook extensions are configured; they are not signed. Migrate them to v3 webhook subscriptions, which sign every delivery with an HMAC-SHA256 X-PagerDuty-Signature header, and confirm receivers verify it.`
          : `${activeSubscriptions.length} active v3 webhook subscriptions are configured and no legacy generic webhook extensions remain; v3 deliveries carry an HMAC-SHA256 X-PagerDuty-Signature header. Confirm receiving systems verify the signature.`,
      {
        legacy_webhook_extensions: legacyWebhookExtensions.slice(0, 25).map(nameOf),
        active_v3_subscriptions: activeSubscriptions.length,
        subscriptions_with_custom_headers: subscriptions.filter((item) => asArray(asObject(item.delivery_method)?.custom_headers).length > 0).length,
      },
    ),
    finding(
      16,
      data.services.error ? "manual" : legacyIntegrations.length + unfilteredEmailIntegrations.length === 0 ? "pass" : "warn",
      data.services.error
        ? `Services could not be read (${data.services.error}). Review each service's Integrations tab and record legacy or unfiltered inbound integrations.`
        : legacyIntegrations.length + unfilteredEmailIntegrations.length === 0
          ? `All ${integrations.length} sampled service integrations use current integration types and email integrations apply filters.`
          : `${legacyIntegrations.length} legacy inbound integrations and ${unfilteredEmailIntegrations.length} email integrations that accept all email were found across ${services.length} services.`,
      {
        integrations: integrations.length,
        legacy_integrations: legacyIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)} (${asString(item.integration.type)})`),
        unfiltered_email_integrations: unfilteredEmailIntegrations.slice(0, 25).map((item) => `${item.service}: ${nameOf(item.integration)}`),
      },
    ),
    finding(
      21,
      data.businessServices.error
        ? "manual"
        : businessServices.length === 0
          ? "fail"
          : unmappedBusinessServices.length === 0 && !data.businessServiceDependencies.error
            ? "pass"
            : "warn",
      data.businessServices.error
        ? `Business services could not be read (${data.businessServices.error}). Record the business services and their supporting technical services from Service Directory > Business Services.`
        : businessServices.length === 0
          ? "No business services are defined, so service dependencies are not mapped for impact analysis."
          : unmappedBusinessServices.length === 0 && !data.businessServiceDependencies.error
            ? `All ${businessServices.length} business services have at least one mapped dependency.`
            : `${unmappedBusinessServices.length}/${businessServices.length} business services have no mapped dependencies${data.businessServiceDependencies.error ? ` (${data.businessServiceDependencies.error})` : ""}.`,
      { business_services: businessServices.length, unmapped_business_services: unmappedBusinessServices.slice(0, 25).map(nameOf) },
    ),
    finding(
      25,
      data.changeEvents.error || data.services.error
        ? "manual"
        : changeEvents.length > 0
          ? "pass"
          : eventsV2Services.length > 0
            ? "warn"
            : "fail",
      data.changeEvents.error || data.services.error
        ? `Change events or services could not be read (${data.changeEvents.error ?? data.services.error}). Record which services receive change events from each service's Activity or Change Events tab.`
        : changeEvents.length > 0
          ? `${changeEvents.length} change events across ${servicesWithChangeEvents.size} services were received between ${data.changeWindow.since} and ${data.changeWindow.until}.`
          : eventsV2Services.length > 0
            ? `No change events were received in the window even though ${eventsV2Services.length} services have Events API v2 integrations capable of change events.`
            : "No services expose Events API v2 integrations and no change events were received, so change tracking is not enabled.",
      { change_window: data.changeWindow, change_events: changeEvents.length, services_with_change_events: servicesWithChangeEvents.size, events_v2_services: eventsV2Services.length },
    ),
  ];

  return {
    category: "integration_security",
    title: "PagerDuty integration security",
    summary: {
      extensions: extensions.length,
      webhook_subscriptions: subscriptions.length,
      service_integrations: integrations.length,
      business_services: businessServices.length,
      change_events: changeEvents.length,
      ...countByStatus(findings),
    },
    findings,
    errors: snapshotErrors("integration_security", {
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
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(`pagerduty-${config.region}`)}-audit-bundle`,
  );

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
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

  const zipPath = resolveSecureOutputPath(outputRoot, `${safeDirName(`pagerduty-${config.region}`)}-audit-bundle.zip`);
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
      audit_limit: Type.Optional(Type.Number({ description: "Maximum recent audit records to fetch. Defaults to 500.", default: 500 })),
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
      audit_limit: Type.Optional(Type.Number({ description: "Maximum recent audit records to fetch. Defaults to 500.", default: 500 })),
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
