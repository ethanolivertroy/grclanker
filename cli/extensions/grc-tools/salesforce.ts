/**
 * Salesforce security inspector tools for grclanker.
 *
 * Read-only Salesforce org assessment across platform security settings,
 * identity and access, data protection, and monitoring plus integrations.
 * Uses the REST API (SOQL), the Tooling API, and the Metadata API readMetadata
 * call. Nothing in this module mutates the org.
 */
import { createSign } from "node:crypto";
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

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

export const SALESFORCE_API_VERSION = "64.0";
const DEFAULT_OUTPUT_DIR = "./export/salesforce";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RECORD_LIMIT = 2000;
const DEFAULT_LOGIN_HISTORY_DAYS = 30;
const DEFAULT_AUDIT_TRAIL_DAYS = 90;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_CERT_EXPIRY_WARNING_DAYS = 30;
const DEFAULT_STALE_LOGIN_DAYS = 90;
const PRODUCTION_LOGIN_URL = "https://login.salesforce.com";
const SANDBOX_LOGIN_URL = "https://test.salesforce.com";
const JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const METADATA_NAMESPACE = "http://soap.sforce.com/2006/04/metadata";

export type SalesforceAuthMode = "jwt-bearer" | "password" | "refresh-token" | "access-token";
export type SalesforceSeverity = "critical" | "high" | "medium" | "low" | "info";
export type SalesforceFindingStatus = "pass" | "warn" | "fail" | "manual";
export type SalesforceArea = "platform_security" | "identity_access" | "data_protection" | "monitoring_integrations";
export type SalesforceFramework = "FedRAMP" | "CMMC" | "SOC 2" | "CIS" | "PCI-DSS" | "STIG" | "IRAP" | "ISMAP";
export type DatasetStatus = "ok" | "forbidden" | "unavailable" | "error";

export interface SalesforceResolvedConfig {
  authMode: SalesforceAuthMode;
  loginUrl: string;
  instanceUrl?: string;
  apiVersion: string;
  username?: string;
  password?: string;
  securityToken?: string;
  consumerKey?: string;
  consumerSecret?: string;
  privateKey?: string;
  refreshToken?: string;
  accessToken?: string;
  timeoutMs: number;
  maxRetries: number;
  sourceChain: string[];
}

export interface SalesforceQueryResult {
  records: JsonRecord[];
  totalSize: number;
  done: boolean;
  truncated: boolean;
  pages: number;
}

export interface SalesforceDataset<T> {
  name: string;
  status: DatasetStatus;
  data: T;
  error?: string;
  truncated: boolean;
  seen: number;
  total?: number;
}

export interface SalesforceAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
  permissionHint?: string;
}

export interface SalesforceAccessCheckResult {
  status: "healthy" | "limited";
  authMode: SalesforceAuthMode;
  instanceUrl?: string;
  organization?: JsonRecord;
  surfaces: SalesforceAccessSurface[];
  missingPermissions: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface SalesforceFinding {
  id: string;
  control: number;
  title: string;
  severity: SalesforceSeverity;
  status: SalesforceFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  manualEvidence?: string;
}

export interface SalesforceAssessmentResult {
  area: SalesforceArea;
  title: string;
  summary: JsonRecord;
  findings: SalesforceFinding[];
  errors: string[];
}

export interface SalesforceAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface SalesforceAssessmentOptions {
  recordLimit?: number;
  loginHistoryDays?: number;
  auditTrailDays?: number;
  maxAdmins?: number;
  certificateExpiryWarningDays?: number;
  staleLoginDays?: number;
  now?: Date;
}

type AuthArgs = {
  instance_url?: string;
  login_url?: string;
  username?: string;
  password?: string;
  security_token?: string;
  consumer_key?: string;
  consumer_secret?: string;
  private_key_file?: string;
  private_key?: string;
  refresh_token?: string;
  access_token?: string;
  credentials_file?: string;
  api_version?: string;
  sandbox?: boolean;
  timeout_seconds?: number;
};

type AssessArgs = AuthArgs & {
  record_limit?: number;
  login_history_days?: number;
  audit_trail_days?: number;
  max_admins?: number;
  certificate_expiry_warning_days?: number;
  stale_login_days?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

interface ControlDefinition {
  control: number;
  title: string;
  mappings: Record<SalesforceFramework, string>;
}

const CONTROLS: ControlDefinition[] = [
  { control: 1, title: "Health Check score", mappings: { FedRAMP: "CA-2", CMMC: "L2 CA.L2-3.12.1", "SOC 2": "CC4.1", CIS: "1.1", "PCI-DSS": "11.3.1", STIG: "SRG-APP-000516", IRAP: "ISM-1526", ISMAP: "11.3.1" } },
  { control: 2, title: "Session timeout", mappings: { FedRAMP: "AC-12", CMMC: "L2 AC.L2-3.1.10", "SOC 2": "CC6.1", CIS: "2.1", "PCI-DSS": "8.2.8", STIG: "SRG-APP-000295", IRAP: "ISM-1164", ISMAP: "8.2.8" } },
  { control: 3, title: "Password policy", mappings: { FedRAMP: "IA-5(1)", CMMC: "L2 IA.L2-3.5.7", "SOC 2": "CC6.1", CIS: "2.2", "PCI-DSS": "8.3.6", STIG: "SRG-APP-000164", IRAP: "ISM-0421", ISMAP: "8.3.6" } },
  { control: 4, title: "MFA enforcement", mappings: { FedRAMP: "IA-2(1)", CMMC: "L2 IA.L2-3.5.3", "SOC 2": "CC6.1", CIS: "2.3", "PCI-DSS": "8.4.1", STIG: "SRG-APP-000149", IRAP: "ISM-1401", ISMAP: "8.4.1" } },
  { control: 5, title: "IP range restrictions", mappings: { FedRAMP: "AC-3, SC-7", CMMC: "L2 SC.L2-3.13.1", "SOC 2": "CC6.6", CIS: "2.4", "PCI-DSS": "1.3.1", STIG: "SRG-APP-000142", IRAP: "ISM-1416", ISMAP: "1.3.1" } },
  { control: 6, title: "Login hour restrictions", mappings: { FedRAMP: "AC-2(5)", CMMC: "L2 AC.L2-3.1.8", "SOC 2": "CC6.1", CIS: "2.5", "PCI-DSS": "7.2.1", STIG: "SRG-APP-000025", IRAP: "ISM-0988", ISMAP: "7.2.1" } },
  { control: 7, title: "API access controls", mappings: { FedRAMP: "AC-3", CMMC: "L2 AC.L2-3.1.2", "SOC 2": "CC6.3", CIS: "3.1", "PCI-DSS": "7.2.2", STIG: "SRG-APP-000033", IRAP: "ISM-1508", ISMAP: "7.2.2" } },
  { control: 8, title: "Field-level security", mappings: { FedRAMP: "AC-3", CMMC: "L2 AC.L2-3.1.3", "SOC 2": "CC6.1", CIS: "3.2", "PCI-DSS": "7.2.1", STIG: "SRG-APP-000033", IRAP: "ISM-0405", ISMAP: "7.2.1" } },
  { control: 9, title: "Permission set review", mappings: { FedRAMP: "AC-6(1)", CMMC: "L2 AC.L2-3.1.5", "SOC 2": "CC6.3", CIS: "3.3", "PCI-DSS": "7.2.2", STIG: "SRG-APP-000340", IRAP: "ISM-1508", ISMAP: "7.2.2" } },
  { control: 10, title: "Profile permissions", mappings: { FedRAMP: "AC-6(5)", CMMC: "L2 AC.L2-3.1.6", "SOC 2": "CC6.3", CIS: "3.4", "PCI-DSS": "7.2.1", STIG: "SRG-APP-000340", IRAP: "ISM-1508", ISMAP: "7.2.1" } },
  { control: 11, title: "Connected app OAuth policies", mappings: { FedRAMP: "AC-3", CMMC: "L2 AC.L2-3.1.2", "SOC 2": "CC6.1", CIS: "4.1", "PCI-DSS": "6.4.1", STIG: "SRG-APP-000033", IRAP: "ISM-1508", ISMAP: "6.4.1" } },
  { control: 12, title: "Sharing settings", mappings: { FedRAMP: "AC-4", CMMC: "L2 AC.L2-3.1.3", "SOC 2": "CC6.1", CIS: "3.5", "PCI-DSS": "7.2.1", STIG: "SRG-APP-000038", IRAP: "ISM-0405", ISMAP: "7.2.1" } },
  { control: 13, title: "Guest user access", mappings: { FedRAMP: "AC-14", CMMC: "L2 AC.L2-3.1.1", "SOC 2": "CC6.1", CIS: "3.6", "PCI-DSS": "7.2.5", STIG: "SRG-APP-000033", IRAP: "ISM-1508", ISMAP: "7.2.5" } },
  { control: 14, title: "Login forensics", mappings: { FedRAMP: "AU-6", CMMC: "L2 AU.L2-3.3.5", "SOC 2": "CC7.2", CIS: "5.1", "PCI-DSS": "10.6.1", STIG: "SRG-APP-000343", IRAP: "ISM-0580", ISMAP: "10.6.1" } },
  { control: 15, title: "Setup change tracking", mappings: { FedRAMP: "AU-2, AU-3", CMMC: "L2 AU.L2-3.3.1", "SOC 2": "CC7.2", CIS: "5.2", "PCI-DSS": "10.2.1", STIG: "SRG-APP-000089", IRAP: "ISM-0580", ISMAP: "10.2.1" } },
  { control: 16, title: "Data encryption status", mappings: { FedRAMP: "SC-28(1)", CMMC: "L2 SC.L2-3.13.16", "SOC 2": "CC6.1", CIS: "6.1", "PCI-DSS": "3.4.1", STIG: "SRG-APP-000231", IRAP: "ISM-0457", ISMAP: "3.4.1" } },
  { control: 17, title: "Certificate management", mappings: { FedRAMP: "SC-17", CMMC: "L2 SC.L2-3.13.10", "SOC 2": "CC6.1", CIS: "6.2", "PCI-DSS": "4.1.1", STIG: "SRG-APP-000514", IRAP: "ISM-1139", ISMAP: "4.1.1" } },
  { control: 18, title: "My Domain enforcement", mappings: { FedRAMP: "IA-8", CMMC: "L2 IA.L2-3.5.2", "SOC 2": "CC6.1", CIS: "2.6", "PCI-DSS": "2.2.1", STIG: "SRG-APP-000516", IRAP: "ISM-1590", ISMAP: "2.2.1" } },
  { control: 19, title: "Clickjack protection", mappings: { FedRAMP: "SC-18", CMMC: "L2 SC.L2-3.13.1", "SOC 2": "CC6.1", CIS: "7.1", "PCI-DSS": "6.2.4", STIG: "SRG-APP-000516", IRAP: "ISM-1486", ISMAP: "6.2.4" } },
  { control: 20, title: "CSRF protection", mappings: { FedRAMP: "SC-18", CMMC: "L2 SC.L2-3.13.1", "SOC 2": "CC6.1", CIS: "7.2", "PCI-DSS": "6.2.4", STIG: "SRG-APP-000516", IRAP: "ISM-1486", ISMAP: "6.2.4" } },
];

const FRAMEWORK_REPORTS: Array<{ framework: SalesforceFramework; path: string; title: string }> = [
  { framework: "FedRAMP", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { framework: "CMMC", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC 2.0 Level 2 Compliance Report" },
  { framework: "SOC 2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { framework: "CIS", path: "compliance/cis/cis_compliance_report.md", title: "CIS Salesforce Benchmark Alignment Report" },
  { framework: "PCI-DSS", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS 4.0 Compliance Report" },
  { framework: "STIG", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG SRG Compliance Checklist" },
  { framework: "IRAP", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { framework: "ISMAP", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

const FRAMEWORK_LABELS: Record<SalesforceFramework, string> = {
  FedRAMP: "FedRAMP",
  CMMC: "CMMC 2.0",
  "SOC 2": "SOC 2",
  CIS: "CIS Salesforce",
  "PCI-DSS": "PCI-DSS 4.0",
  STIG: "DISA STIG",
  IRAP: "IRAP",
  ISMAP: "ISMAP",
};

const SENSITIVE_FIELD_PATTERNS = [
  "SSN", "Social", "Tax", "Credit", "Card", "Passport", "Salary", "Bank", "Routing", "Account_Number",
  "DOB", "Birth", "Password", "Secret", "Health", "Medical", "Diagnos", "National", "License",
];

const HIGH_RISK_AUDIT_SECTIONS = /manage users|permission set|profile|security controls|session settings|password polic|network access|connected app|certificate|sharing|my domain|login|identity|oauth|encryption|remote site|named credential/i;
const HIGH_RISK_AUDIT_ACTIONS = /permset|profile|permission|admin|password|session|networkaccess|iprange|connectedapp|certificate|sharing|encrypt|mfa|twofactor|loginhour|apienabled|modifyalldata|viewalldata/i;

const SESSION_TIMEOUT_MINUTES: Record<string, number> = {
  FifteenMinutes: 15,
  ThirtyMinutes: 30,
  SixtyMinutes: 60,
  NinetyMinutes: 90,
  TwoHours: 120,
  FourHours: 240,
  EightHours: 480,
  TwelveHours: 720,
  TwentyFourHours: 1440,
};

const PASSWORD_EXPIRATION_DAYS: Record<string, number> = {
  ThirtyDays: 30,
  SixtyDays: 60,
  NinetyDays: 90,
  SixMonths: 180,
  OneYear: 365,
};

const PASSWORD_COMPLEXITY_RANK: Record<string, number> = {
  NoRestriction: 0,
  AlphaNumeric: 1,
  SpecialCharacters: 2,
  UpperLowerCaseNumeric: 3,
  UpperLowerCaseNumericSpecialCharacters: 4,
  Any3UpperLowerCaseNumericSpecialCharacters: 3,
};

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
    if (/^(true|1|yes)$/i.test(value.trim())) return true;
    if (/^(false|0|no)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
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

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "salesforce";
}

function truncateList<T>(items: T[], max = 25): T[] {
  return items.slice(0, max);
}

function daysBetween(later: Date, earlier: Date): number {
  return Math.floor((later.getTime() - earlier.getTime()) / 86_400_000);
}

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
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
  if (relativeTarget === ".." || relativeTarget.startsWith("..")) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
  }

  const pathSegments = relativeTarget.split(/[\\/]+/).filter(Boolean);
  let currentPath = realBase;
  for (const segment of pathSegments) {
    currentPath = join(currentPath, segment);
    if (!existsSync(currentPath)) break;
    if (lstatSync(currentPath).isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked parent directory: ${currentPath}`);
    }
  }

  const parent = dirname(resolvedTarget);
  ensurePrivateDir(parent);
  if (lstatSync(realpathSync(parent)).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }
  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  for (let index = 1; index <= 50; index += 1) {
    const suffix = index === 1 ? "" : `-${index}`;
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    const zipCandidate = resolveSecureOutputPath(root, `${preferredName}${suffix}.zip`);
    if (!existsSync(candidate) && !existsSync(zipCandidate)) {
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

export class SalesforceApiError extends Error {
  readonly status?: number;
  readonly errorCode?: string;

  constructor(message: string, options: { status?: number; errorCode?: string } = {}) {
    super(message);
    this.name = "SalesforceApiError";
    this.status = options.status;
    this.errorCode = options.errorCode;
  }
}

function redactSecrets(message: string, secrets: Array<string | undefined>): string {
  let redacted = message
    .replace(/assertion=[^&\s"]+/gi, "assertion=[REDACTED]")
    .replace(/access_token"?\s*[:=]\s*"?[^"&\s,}]+/gi, "access_token=[REDACTED]")
    .replace(/refresh_token"?\s*[:=]\s*"?[^"&\s,}]+/gi, "refresh_token=[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._!~-]+/g, "Bearer [REDACTED]")
    .replace(/<sessionId>[^<]*<\/sessionId>/gi, "<sessionId>[REDACTED]</sessionId>");
  for (const secret of secrets) {
    if (secret && secret.length >= 6) {
      redacted = redacted.split(secret).join("[REDACTED]");
    }
  }
  return redacted;
}

function salesforceErrorSummary(payload: unknown): { message?: string; errorCode?: string } {
  const list = Array.isArray(payload) ? payload : [payload];
  for (const item of list) {
    const object = asObject(item);
    if (!object) continue;
    const message = asString(object.message) ?? asString(object.error_description) ?? asString(object.error);
    const errorCode = asString(object.errorCode) ?? asString(object.error);
    if (message || errorCode) return { message, errorCode };
  }
  return {};
}

function isForbiddenError(error: unknown): boolean {
  if (!(error instanceof SalesforceApiError)) return false;
  if (error.status === 401 || error.status === 403) return true;
  return /INSUFFICIENT_ACCESS|INVALID_SESSION_ID|API_DISABLED_FOR_ORG|INSUFFICIENT_PRIVILEGES|REQUEST_LIMIT_EXCEEDED|API_CURRENTLY_DISABLED/i.test(error.errorCode ?? error.message);
}

function isUnavailableError(error: unknown): boolean {
  if (!(error instanceof SalesforceApiError)) return false;
  return /INVALID_TYPE|INVALID_FIELD|NOT_FOUND|INVALID_TYPE_FOR_OPERATION|sObject type .* is not supported|No such column|UNKNOWN_EXCEPTION/i.test(`${error.errorCode ?? ""} ${error.message}`);
}

function readCredentialsFile(pathname: string): JsonRecord {
  const resolved = resolve(pathname);
  if (!existsSync(resolved)) {
    throw new Error(`Salesforce credentials file not found: ${resolved}`);
  }
  const parsed = JSON.parse(readFileSync(resolved, "utf8")) as unknown;
  const object = asObject(parsed);
  if (!object) {
    throw new Error(`Salesforce credentials file must contain a JSON object: ${resolved}`);
  }
  return object;
}

function loadPrivateKey(inline: string | undefined, pathname: string | undefined): string | undefined {
  if (inline) return inline.replace(/\\n/g, "\n");
  if (!pathname) return undefined;
  const resolved = resolve(pathname);
  if (!existsSync(resolved)) {
    throw new Error(`Salesforce private key file not found: ${resolved}`);
  }
  return readFileSync(resolved, "utf8");
}

function looksLikeSandbox(instanceUrl: string | undefined, loginUrl: string | undefined): boolean {
  const haystack = `${instanceUrl ?? ""} ${loginUrl ?? ""}`.toLowerCase();
  return /test\.salesforce\.com|\.sandbox\.my\.salesforce\.com|--[a-z0-9]+\.(cs\d+|sandbox)\./.test(haystack);
}

function normalizeApiVersion(value: string | undefined): string {
  const text = (value ?? SALESFORCE_API_VERSION).trim().replace(/^v/i, "");
  if (!/^\d{2,3}\.\d$/.test(text)) {
    throw new Error(`Salesforce API version must look like 64.0, received: ${value}`);
  }
  return text;
}

function normalizeGrantType(value: string | undefined): SalesforceAuthMode | undefined {
  const text = value?.trim().toLowerCase().replace(/_/g, "-");
  if (!text) return undefined;
  if (text === "jwt-bearer" || text === "jwt" || text === JWT_GRANT_TYPE) return "jwt-bearer";
  if (text === "password" || text === "username-password") return "password";
  if (text === "authorization-code" || text === "refresh-token") return "refresh-token";
  if (text === "access-token" || text === "token") return "access-token";
  throw new Error(`Unsupported Salesforce grant_type: ${value}`);
}

export function resolveSalesforceConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): SalesforceResolvedConfig {
  const sourceChain: string[] = [];
  const credentialsPath = asString(input.credentials_file) ?? asString(env.SF_CREDENTIALS_FILE);
  const file = credentialsPath ? readCredentialsFile(credentialsPath) : {};
  if (credentialsPath) sourceChain.push(`credentials-file:${basename(credentialsPath)}`);

  const pick = (argKey: string, envKeys: string[], fileKeys: string[]): string | undefined => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) {
      sourceChain.push(`arguments-${argKey.replace(/_/g, "-")}`);
      return fromArgs;
    }
    for (const envKey of envKeys) {
      const fromEnv = asString(env[envKey]);
      if (fromEnv) {
        sourceChain.push(`environment-${envKey}`);
        return fromEnv;
      }
    }
    for (const fileKey of fileKeys) {
      const fromFile = asString(file[fileKey]);
      if (fromFile) {
        sourceChain.push(`credentials-file-${fileKey.replace(/_/g, "-")}`);
        return fromFile;
      }
    }
    return undefined;
  };

  const instanceUrlRaw = pick("instance_url", ["SF_INSTANCE_URL"], ["instance_url", "instanceUrl"]);
  const loginUrlRaw = pick("login_url", ["SF_LOGIN_URL"], ["login_url", "loginUrl"]);
  const username = pick("username", ["SF_USERNAME"], ["username"]);
  const password = pick("password", ["SF_PASSWORD"], ["password"]);
  const securityToken = pick("security_token", ["SF_SECURITY_TOKEN"], ["security_token", "securityToken"]);
  const consumerKey = pick("consumer_key", ["SF_CONSUMER_KEY", "SF_CLIENT_ID"], ["consumer_key", "client_id", "consumerKey", "clientId"]);
  const consumerSecret = pick("consumer_secret", ["SF_CONSUMER_SECRET", "SF_CLIENT_SECRET"], ["consumer_secret", "client_secret", "consumerSecret", "clientSecret"]);
  const privateKeyFile = pick("private_key_file", ["SF_PRIVATE_KEY_FILE"], ["private_key_file", "privateKeyFile"]);
  const privateKeyInline = pick("private_key", ["SF_PRIVATE_KEY"], ["private_key", "privateKey"]);
  const refreshToken = pick("refresh_token", ["SF_REFRESH_TOKEN"], ["refresh_token", "refreshToken"]);
  const accessToken = pick("access_token", ["SF_ACCESS_TOKEN"], ["access_token", "accessToken"]);
  const apiVersion = normalizeApiVersion(pick("api_version", ["SF_API_VERSION"], ["api_version", "apiVersion"]));
  const grantType = normalizeGrantType(pick("grant_type", ["SF_GRANT_TYPE"], ["grant_type", "grantType"]));
  const sandboxFlag = asBoolean(input.sandbox) ?? asBoolean(env.SF_SANDBOX) ?? asBoolean(file.sandbox);

  const instanceUrl = instanceUrlRaw ? normalizeBaseUrl(instanceUrlRaw) : undefined;
  const privateKey = loadPrivateKey(privateKeyInline, privateKeyFile);

  let authMode: SalesforceAuthMode | undefined = grantType;
  if (!authMode) {
    if (accessToken) authMode = "access-token";
    else if (privateKey && consumerKey && username) authMode = "jwt-bearer";
    else if (refreshToken && consumerKey) authMode = "refresh-token";
    else if (username && password) authMode = "password";
  }
  if (!authMode) {
    throw new Error(
      "Salesforce credentials are required: JWT bearer (SF_CONSUMER_KEY, SF_USERNAME, SF_PRIVATE_KEY_FILE), "
      + "username-password (SF_USERNAME, SF_PASSWORD, SF_SECURITY_TOKEN, SF_CONSUMER_KEY, SF_CONSUMER_SECRET), "
      + "a refresh token, an access token with SF_INSTANCE_URL, or SF_CREDENTIALS_FILE.",
    );
  }

  switch (authMode) {
    case "jwt-bearer":
      if (!consumerKey || !username || !privateKey) {
        throw new Error("JWT bearer flow requires SF_CONSUMER_KEY, SF_USERNAME, and SF_PRIVATE_KEY_FILE (or SF_PRIVATE_KEY).");
      }
      break;
    case "password":
      if (!username || !password || !consumerKey || !consumerSecret) {
        throw new Error("Username-password flow requires SF_USERNAME, SF_PASSWORD, SF_CONSUMER_KEY, and SF_CONSUMER_SECRET (SF_SECURITY_TOKEN when the login IP is not trusted).");
      }
      break;
    case "refresh-token":
      if (!refreshToken || !consumerKey) {
        throw new Error("Refresh token flow requires SF_REFRESH_TOKEN and SF_CONSUMER_KEY (plus SF_CONSUMER_SECRET unless the connected app skips the secret).");
      }
      break;
    case "access-token":
      if (!accessToken || !instanceUrl) {
        throw new Error("Access token mode requires SF_ACCESS_TOKEN and SF_INSTANCE_URL.");
      }
      break;
    default: {
      const exhaustive: never = authMode;
      throw new Error(`Unhandled auth mode: ${String(exhaustive)}`);
    }
  }

  const sandbox = sandboxFlag ?? looksLikeSandbox(instanceUrl, loginUrlRaw);
  const loginUrl = normalizeBaseUrl(loginUrlRaw ?? (sandbox ? SANDBOX_LOGIN_URL : PRODUCTION_LOGIN_URL));
  sourceChain.push(loginUrlRaw ? "login-host-explicit" : sandbox ? "login-host-sandbox" : "login-host-production");

  return {
    authMode,
    loginUrl,
    instanceUrl,
    apiVersion,
    username,
    password,
    securityToken,
    consumerKey,
    consumerSecret,
    privateKey,
    refreshToken,
    accessToken,
    timeoutMs: clampNumber(asNumber(input.timeout_seconds) ?? asNumber(env.SF_TIMEOUT), DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000,
    maxRetries: clampNumber(asNumber(input.max_retries) ?? asNumber(env.SF_MAX_RETRIES), DEFAULT_MAX_RETRIES, 0, 8),
    sourceChain: [...new Set(sourceChain)],
  };
}

export function buildJwtAssertion(config: SalesforceResolvedConfig, now: Date = new Date()): string {
  if (!config.consumerKey || !config.username || !config.privateKey) {
    throw new Error("JWT bearer assertion requires consumer key, username, and private key.");
  }
  const header = base64Url(JSON.stringify({ alg: "RS256" }));
  const claims = base64Url(JSON.stringify({
    iss: config.consumerKey,
    sub: config.username,
    aud: config.loginUrl,
    exp: Math.floor(now.getTime() / 1000) + 180,
  }));
  const signingInput = `${header}.${claims}`;
  const signature = createSign("RSA-SHA256").update(signingInput).sign(config.privateKey);
  return `${signingInput}.${base64Url(signature)}`;
}

export function decodeJwtClaims(assertion: string): JsonRecord {
  const parts = assertion.split(".");
  if (parts.length !== 3) throw new Error("Malformed JWT assertion.");
  const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(Buffer.from(normalized, "base64").toString("utf8")) as JsonRecord;
}

interface XmlNode {
  [key: string]: unknown;
}

function decodeXmlEntities(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function stripNamespace(tagName: string): string {
  const index = tagName.indexOf(":");
  return index >= 0 ? tagName.slice(index + 1) : tagName;
}

/**
 * Minimal XML to JSON conversion sufficient for Metadata API readMetadata
 * responses: nested elements become objects, repeated elements become arrays,
 * leaf text becomes strings, and xsi:nil elements become null.
 */
export function parseSimpleXml(xml: string): XmlNode {
  const cleaned = xml.replace(/<\?xml[^>]*\?>/g, "").replace(/<!--[\s\S]*?-->/g, "");
  const tagPattern = /<(\/?)([A-Za-z_][\w.:-]*)([^>]*?)(\/?)>|([^<]+)/g;
  const root: XmlNode = {};
  const stack: Array<{ name: string; node: XmlNode; text: string }> = [{ name: "", node: root, text: "" }];

  const attach = (parent: XmlNode, name: string, value: unknown): void => {
    const existing = parent[name];
    if (existing === undefined) {
      parent[name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      parent[name] = [existing, value];
    }
  };

  let match: RegExpExecArray | null;
  while ((match = tagPattern.exec(cleaned)) !== null) {
    const [, closing, rawName, attributes, selfClosing, text] = match;
    if (text !== undefined) {
      stack[stack.length - 1].text += text;
      continue;
    }
    const name = stripNamespace(rawName);
    if (closing) {
      const finished = stack.pop();
      if (!finished) break;
      const parent = stack[stack.length - 1];
      const hasChildren = Object.keys(finished.node).length > 0;
      const value = hasChildren ? finished.node : decodeXmlEntities(finished.text.trim());
      attach(parent.node, name, hasChildren ? value : (finished.text.trim().length > 0 ? value : ""));
      continue;
    }
    if (selfClosing) {
      attach(stack[stack.length - 1].node, name, /nil="true"/i.test(attributes) ? null : "");
      continue;
    }
    stack.push({ name, node: {}, text: "" });
  }
  return root;
}

function findXmlNode(node: unknown, path: string[]): unknown {
  let current: unknown = node;
  for (const segment of path) {
    const object = asObject(current);
    if (!object) return undefined;
    current = object[segment];
  }
  return current;
}

function firstRecord(value: unknown): JsonRecord | undefined {
  if (Array.isArray(value)) return value.map(asObject).find((item): item is JsonRecord => Boolean(item));
  return asObject(value);
}

export class SalesforceApiClient {
  private readonly config: SalesforceResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => Date;
  private session?: { accessToken: string; instanceUrl: string };
  private sessionPromise?: Promise<{ accessToken: string; instanceUrl: string }>;

  constructor(
    config: SalesforceResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: (ms: number) => Promise<void>;
      now?: () => Date;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    this.now = options.now ?? (() => new Date());
    if (config.authMode === "access-token" && config.accessToken && config.instanceUrl) {
      this.session = { accessToken: config.accessToken, instanceUrl: config.instanceUrl };
    }
  }

  getResolvedConfig(): SalesforceResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private secrets(): Array<string | undefined> {
    return [
      this.config.password,
      this.config.securityToken,
      this.config.consumerSecret,
      this.config.refreshToken,
      this.config.accessToken,
      this.session?.accessToken,
    ];
  }

  private redact(message: string): string {
    return redactSecrets(message, this.secrets());
  }

  private async rawFetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new SalesforceApiError(this.redact(`Salesforce request to ${new URL(url).pathname} failed: ${message}`));
    } finally {
      clearTimeout(timeout);
    }
  }

  private async fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
    let attempt = 0;
    for (;;) {
      let response: Response | undefined;
      let failure: SalesforceApiError | undefined;
      try {
        response = await this.rawFetch(url, init);
      } catch (error) {
        failure = error instanceof SalesforceApiError ? error : new SalesforceApiError(String(error));
      }
      const retryable = failure !== undefined || (response !== undefined && (response.status === 429 || response.status >= 500));
      if (!retryable && response) return response;
      if (attempt >= this.config.maxRetries) {
        if (response) return response;
        throw failure ?? new SalesforceApiError("Salesforce request failed.");
      }
      const retryAfter = asNumber(response?.headers.get("retry-after"));
      await this.sleep(retryAfter !== undefined ? retryAfter * 1000 : 500 * 2 ** attempt);
      attempt += 1;
    }
  }

  private async requestToken(form: Record<string, string>): Promise<{ accessToken: string; instanceUrl: string }> {
    const body = new URLSearchParams(form).toString();
    const response = await this.fetchWithRetry(`${this.config.loginUrl}/services/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body,
    });
    const rawText = await response.text();
    let payload: unknown = {};
    try {
      payload = rawText.length > 0 ? JSON.parse(rawText) : {};
    } catch {
      payload = {};
    }
    if (!response.ok) {
      const summary = salesforceErrorSummary(payload);
      throw new SalesforceApiError(
        this.redact(`Salesforce token request failed (${response.status})${summary.message ? `: ${summary.message}` : ""}`),
        { status: response.status, errorCode: summary.errorCode },
      );
    }
    const object = asObject(payload) ?? {};
    const accessToken = asString(object.access_token);
    if (!accessToken) throw new SalesforceApiError("Salesforce token response did not include access_token.");
    const instanceUrl = asString(object.instance_url) ? normalizeBaseUrl(asString(object.instance_url) as string) : this.config.instanceUrl;
    if (!instanceUrl) throw new SalesforceApiError("Salesforce token response did not include instance_url and SF_INSTANCE_URL is not set.");
    return { accessToken, instanceUrl };
  }

  private async authenticate(): Promise<{ accessToken: string; instanceUrl: string }> {
    const mode = this.config.authMode;
    switch (mode) {
      case "access-token":
        if (!this.config.accessToken || !this.config.instanceUrl) throw new SalesforceApiError("Access token mode is missing token or instance URL.");
        return { accessToken: this.config.accessToken, instanceUrl: this.config.instanceUrl };
      case "jwt-bearer":
        return this.requestToken({ grant_type: JWT_GRANT_TYPE, assertion: buildJwtAssertion(this.config, this.now()) });
      case "password":
        return this.requestToken({
          grant_type: "password",
          client_id: this.config.consumerKey ?? "",
          client_secret: this.config.consumerSecret ?? "",
          username: this.config.username ?? "",
          password: `${this.config.password ?? ""}${this.config.securityToken ?? ""}`,
        });
      case "refresh-token":
        return this.requestToken({
          grant_type: "refresh_token",
          client_id: this.config.consumerKey ?? "",
          ...(this.config.consumerSecret ? { client_secret: this.config.consumerSecret } : {}),
          refresh_token: this.config.refreshToken ?? "",
        });
      default: {
        const exhaustive: never = mode;
        throw new SalesforceApiError(`Unhandled auth mode: ${String(exhaustive)}`);
      }
    }
  }

  async getSession(): Promise<{ accessToken: string; instanceUrl: string }> {
    if (this.session) return this.session;
    if (!this.sessionPromise) {
      this.sessionPromise = this.authenticate().then((session) => {
        this.session = session;
        return session;
      });
    }
    try {
      return await this.sessionPromise;
    } finally {
      this.sessionPromise = undefined;
    }
  }

  private dataPath(suffix: string): string {
    return `/services/data/v${this.config.apiVersion}${suffix}`;
  }

  async getJson(pathOrUrl: string, query: Record<string, string> = {}): Promise<unknown> {
    const session = await this.getSession();
    const url = new URL(pathOrUrl.startsWith("http") ? pathOrUrl : `${session.instanceUrl}${pathOrUrl}`);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const response = await this.fetchWithRetry(url.toString(), {
      method: "GET",
      headers: { authorization: `Bearer ${session.accessToken}`, accept: "application/json" },
    });
    const rawText = await response.text();
    let payload: unknown = {};
    try {
      payload = rawText.length > 0 ? JSON.parse(rawText) : {};
    } catch {
      payload = { message: rawText.slice(0, 200) };
    }
    if (!response.ok) {
      const summary = salesforceErrorSummary(payload);
      throw new SalesforceApiError(
        this.redact(`Salesforce request ${url.pathname} failed (${response.status})${summary.errorCode ? ` ${summary.errorCode}` : ""}${summary.message ? `: ${summary.message}` : ""}`),
        { status: response.status, errorCode: summary.errorCode },
      );
    }
    return payload;
  }

  private async runQuery(resource: string, soql: string, limit: number): Promise<SalesforceQueryResult> {
    const recordLimit = clampNumber(limit, DEFAULT_RECORD_LIMIT, 1, 200_000);
    const records: JsonRecord[] = [];
    let payload = asObject(await this.getJson(this.dataPath(resource), { q: soql })) ?? {};
    let pages = 1;
    let done = asBoolean(payload.done) ?? true;
    const totalSize = asNumber(payload.totalSize) ?? asRecords(payload.records).length;
    records.push(...asRecords(payload.records));

    while (!done && records.length < recordLimit) {
      const nextUrl = asString(payload.nextRecordsUrl);
      if (!nextUrl) break;
      payload = asObject(await this.getJson(nextUrl)) ?? {};
      pages += 1;
      records.push(...asRecords(payload.records));
      done = asBoolean(payload.done) ?? true;
    }

    const truncated = !done || records.length > recordLimit || totalSize > records.length;
    return { records: records.slice(0, recordLimit), totalSize, done, truncated, pages };
  }

  async query(soql: string, limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.runQuery("/query", soql, limit);
  }

  async toolingQuery(soql: string, limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.runQuery("/tooling/query", soql, limit);
  }

  async getLimits(): Promise<JsonRecord> {
    return asObject(await this.getJson(this.dataPath("/limits"))) ?? {};
  }

  async describeSObject(name: string): Promise<JsonRecord> {
    return asObject(await this.getJson(this.dataPath(`/sobjects/${encodeURIComponent(name)}/describe`))) ?? {};
  }

  async readMetadata(metadataType: string, fullNames: string[]): Promise<JsonRecord[]> {
    const session = await this.getSession();
    const escape = (value: string): string => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const envelope = [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:met="${METADATA_NAMESPACE}">`,
      "<soapenv:Header><met:SessionHeader><met:sessionId>",
      escape(session.accessToken),
      "</met:sessionId></met:SessionHeader></soapenv:Header>",
      "<soapenv:Body><met:readMetadata>",
      `<met:type>${escape(metadataType)}</met:type>`,
      ...fullNames.map((name) => `<met:fullNames>${escape(name)}</met:fullNames>`),
      "</met:readMetadata></soapenv:Body></soapenv:Envelope>",
    ].join("");
    const response = await this.fetchWithRetry(`${session.instanceUrl}/services/Soap/m/${this.config.apiVersion}`, {
      method: "POST",
      headers: { "content-type": "text/xml; charset=UTF-8", soapaction: "\"\"" },
      body: envelope,
    });
    const rawText = await response.text();
    const parsed = parseSimpleXml(rawText);
    const fault = firstRecord(findXmlNode(parsed, ["Envelope", "Body", "Fault"]));
    if (fault || !response.ok) {
      const faultCode = asString(fault?.faultcode)?.replace(/^.*:/, "");
      const faultString = asString(fault?.faultstring);
      throw new SalesforceApiError(
        this.redact(`Salesforce Metadata API readMetadata(${metadataType}) failed (${response.status})${faultCode ? ` ${faultCode}` : ""}${faultString ? `: ${faultString}` : ""}`),
        { status: response.status, errorCode: faultCode },
      );
    }
    const result = findXmlNode(parsed, ["Envelope", "Body", "readMetadataResponse", "result", "records"]);
    return asRecords(Array.isArray(result) ? result : result === undefined || result === null ? [] : [result]);
  }

  async getOrganization(): Promise<JsonRecord | undefined> {
    const result = await this.query(
      "SELECT Id, Name, OrganizationType, IsSandbox, InstanceName, DefaultAccountAccess, DefaultContactAccess, DefaultCaseAccess, DefaultLeadAccess, DefaultOpportunityAccess, DefaultCampaignAccess, DefaultCalendarAccess, DefaultPricebookAccess FROM Organization",
      1,
    );
    return result.records[0];
  }

  async getHealthCheck(): Promise<JsonRecord | undefined> {
    const result = await this.toolingQuery("SELECT Score FROM SecurityHealthCheck", 1);
    return result.records[0];
  }

  async listHealthCheckRisks(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.toolingQuery(
      "SELECT DurableId, Setting, SettingGroup, SettingRiskCategory, RiskType, OrgValue, OrgValueRaw, StandardValue, StandardValueRaw FROM SecurityHealthCheckRisks",
      limit,
    );
  }

  async readSecuritySettings(): Promise<JsonRecord | undefined> {
    const records = await this.readMetadata("SecuritySettings", ["Security"]);
    return records[0];
  }

  async readMyDomainSettings(): Promise<JsonRecord | undefined> {
    const records = await this.readMetadata("MyDomainSettings", ["MyDomain"]);
    return records[0];
  }

  async listUsers(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, Username, Name, Email, IsActive, UserType, ProfileId, Profile.Name, LastLoginDate, CreatedDate FROM User ORDER BY CreatedDate",
      limit,
    );
  }

  async listProfiles(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, Name, UserType, UserLicense.Name, PermissionsApiEnabled, PermissionsApiUserOnly, PermissionsModifyAllData, PermissionsViewAllData, PermissionsManageUsers, PermissionsAuthorApex, PermissionsCustomizeApplication, PermissionsViewSetup, PermissionsManageProfilesPermissionsets, PermissionsPasswordNeverExpires FROM Profile ORDER BY Name",
      limit,
    );
  }

  async listPermissionSets(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, Name, Label, IsOwnedByProfile, IsCustom, Type, ProfileId, NamespacePrefix, PermissionsApiEnabled, PermissionsModifyAllData, PermissionsViewAllData, PermissionsManageUsers, PermissionsAuthorApex, PermissionsCustomizeApplication, PermissionsViewSetup, PermissionsManageProfilesPermissionsets, PermissionsPasswordNeverExpires FROM PermissionSet WHERE IsOwnedByProfile = false ORDER BY Name",
      limit,
    );
  }

  async listPermissionSetAssignments(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, AssigneeId, Assignee.Username, Assignee.IsActive, PermissionSetId, PermissionSet.Name, PermissionSet.IsOwnedByProfile, ExpirationDate, IsActive FROM PermissionSetAssignment WHERE PermissionSet.IsOwnedByProfile = false",
      limit,
    );
  }

  async listTwoFactorMethods(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, UserId, HasTotp, HasU2F, HasSecurityKey, HasSalesforceAuthenticator, HasBuiltInAuthenticator, HasTempCode, HasUserVerifiedMobileNumber, HasUserVerifiedEmailAddress FROM TwoFactorMethodsInfo",
      limit,
    );
  }

  async listSensitiveFieldPermissions(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    const filter = SENSITIVE_FIELD_PATTERNS.map((pattern) => `Field LIKE '%${pattern}%'`).join(" OR ");
    return this.query(
      `SELECT Id, SobjectType, Field, ParentId, Parent.Name, Parent.IsOwnedByProfile, Parent.Profile.Name, PermissionsRead, PermissionsEdit FROM FieldPermissions WHERE (${filter}) ORDER BY Field`,
      limit,
    );
  }

  async listTenantSecrets(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query("SELECT Id, Status, Type, Version, CreatedDate, Description, KeyDerivationMode, Source FROM TenantSecret ORDER BY CreatedDate DESC", limit);
  }

  async listCertificates(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query("SELECT Id, DeveloperName, MasterLabel, ExpirationDate, KeySize, NamespacePrefix, CreatedDate FROM Certificate ORDER BY ExpirationDate", limit);
  }

  async listConnectedApplications(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query(
      "SELECT Id, Name, OptionsAllowAdminApprovedUsersOnly, OptionsRefreshTokenValidityMetric, RefreshTokenValidityPeriod, OptionsHasSessionLevelPolicy, OptionsIsInternal, OptionsCodeCredentialGuestEnabled, StartUrl, MobileStartUrl, MobileSessionTimeout, PinLength, CreatedDate, LastModifiedDate FROM ConnectedApplication ORDER BY Name",
      limit,
    );
  }

  async listOauthTokens(limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    return this.query("SELECT Id, AppName, AppMenuItemId, UserId, User.Username, LastUsedDate, UseCount, CreatedDate FROM OauthToken ORDER BY LastUsedDate DESC NULLS LAST", limit);
  }

  async listLoginHistory(days = DEFAULT_LOGIN_HISTORY_DAYS, limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    const window = clampNumber(days, DEFAULT_LOGIN_HISTORY_DAYS, 1, 180);
    return this.query(
      `SELECT Id, UserId, LoginTime, LoginType, SourceIp, Status, Application, Browser, Platform, LoginUrl, CountryIso, TlsProtocol FROM LoginHistory WHERE LoginTime = LAST_N_DAYS:${window} ORDER BY LoginTime DESC`,
      limit,
    );
  }

  async listSetupAuditTrail(days = DEFAULT_AUDIT_TRAIL_DAYS, limit = DEFAULT_RECORD_LIMIT): Promise<SalesforceQueryResult> {
    const window = clampNumber(days, DEFAULT_AUDIT_TRAIL_DAYS, 1, 180);
    return this.query(
      `SELECT Id, Action, Section, CreatedDate, CreatedById, CreatedBy.Username, Display, DelegateUser FROM SetupAuditTrail WHERE CreatedDate = LAST_N_DAYS:${window} ORDER BY CreatedDate DESC`,
      limit,
    );
  }

  async listEventLogFiles(days = 7, limit = 200): Promise<SalesforceQueryResult> {
    const window = clampNumber(days, 7, 1, 30);
    return this.query(`SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE LogDate = LAST_N_DAYS:${window} ORDER BY LogDate DESC`, limit);
  }
}

type ReadClient = Pick<
  SalesforceApiClient,
  | "getResolvedConfig"
  | "getNow"
  | "getSession"
  | "getLimits"
  | "getOrganization"
  | "getHealthCheck"
  | "listHealthCheckRisks"
  | "readSecuritySettings"
  | "readMyDomainSettings"
  | "listUsers"
  | "listProfiles"
  | "listPermissionSets"
  | "listPermissionSetAssignments"
  | "listTwoFactorMethods"
  | "listSensitiveFieldPermissions"
  | "listTenantSecrets"
  | "listCertificates"
  | "listConnectedApplications"
  | "listOauthTokens"
  | "listLoginHistory"
  | "listSetupAuditTrail"
  | "listEventLogFiles"
>;

function classifyError(error: unknown): DatasetStatus {
  if (isForbiddenError(error)) return "forbidden";
  if (isUnavailableError(error)) return "unavailable";
  return "error";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function collectRecords(name: string, load: () => Promise<SalesforceQueryResult>): Promise<SalesforceDataset<JsonRecord[]>> {
  try {
    const result = await load();
    return {
      name,
      status: "ok",
      data: result.records,
      truncated: result.truncated,
      seen: result.records.length,
      total: result.totalSize,
    };
  } catch (error) {
    return { name, status: classifyError(error), data: [], error: errorMessage(error), truncated: false, seen: 0 };
  }
}

async function collectRecord(name: string, load: () => Promise<JsonRecord | undefined>): Promise<SalesforceDataset<JsonRecord | undefined>> {
  try {
    const data = await load();
    return { name, status: "ok", data, truncated: false, seen: data ? 1 : 0, total: data ? 1 : 0 };
  } catch (error) {
    return { name, status: classifyError(error), data: undefined, error: errorMessage(error), truncated: false, seen: 0 };
  }
}

function datasetErrors(...datasets: Array<SalesforceDataset<unknown>>): string[] {
  return datasets
    .filter((dataset) => dataset.status !== "ok")
    .map((dataset) => `${dataset.name}: ${dataset.status}${dataset.error ? ` (${dataset.error})` : ""}`);
}

function unreadableReason(dataset: SalesforceDataset<unknown>): string {
  switch (dataset.status) {
    case "forbidden":
      return `the ${dataset.name} query was forbidden (${dataset.error ?? "401/403 or INSUFFICIENT_ACCESS"})`;
    case "unavailable":
      return `the ${dataset.name} object or field is unavailable in this org (${dataset.error ?? "INVALID_TYPE"})`;
    case "error":
      return `the ${dataset.name} query failed (${dataset.error ?? "unknown error"})`;
    case "ok":
      return `the ${dataset.name} data was readable`;
    default: {
      const exhaustive: never = dataset.status;
      return String(exhaustive);
    }
  }
}

function controlDefinition(control: number): ControlDefinition {
  const definition = CONTROLS.find((item) => item.control === control);
  if (!definition) throw new Error(`Unknown Salesforce control ${control}`);
  return definition;
}

function mappingsFor(control: number): string[] {
  const definition = controlDefinition(control);
  return (Object.keys(definition.mappings) as SalesforceFramework[]).map((framework) => `${FRAMEWORK_LABELS[framework]} ${definition.mappings[framework]}`);
}

function severityFor(control: number): SalesforceSeverity {
  if ([2, 3, 4, 10, 13, 16].includes(control)) return "critical";
  if ([1, 5, 7, 8, 9, 11, 12, 14, 15, 17, 18].includes(control)) return "high";
  if ([6, 19, 20].includes(control)) return "medium";
  return "low";
}

function finding(
  control: number,
  status: SalesforceFindingStatus,
  summary: string,
  evidence?: JsonRecord,
  manualEvidence?: string,
): SalesforceFinding {
  const definition = controlDefinition(control);
  return {
    id: `SF-${String(control).padStart(2, "0")}`,
    control,
    title: definition.title,
    severity: severityFor(control),
    status,
    summary,
    evidence,
    mappings: mappingsFor(control),
    manualEvidence,
  };
}

function manualForUnreadable(control: number, dataset: SalesforceDataset<unknown>, manualEvidence: string, evidence: JsonRecord = {}): SalesforceFinding {
  return finding(
    control,
    "manual",
    `${controlDefinition(control).title} could not be verified because ${unreadableReason(dataset)}.`,
    { ...evidence, dataset: dataset.name, dataset_status: dataset.status, error: dataset.error ?? null },
    manualEvidence,
  );
}

function partialNote(dataset: SalesforceDataset<JsonRecord[]>): string {
  return dataset.truncated
    ? ` Only ${dataset.seen} of ${dataset.total ?? "an unknown total of"} ${dataset.name} records were read, so the verdict is downgraded.`
    : "";
}

function withPartialDowngrade(status: SalesforceFindingStatus, dataset: SalesforceDataset<JsonRecord[]>): SalesforceFindingStatus {
  if (!dataset.truncated) return status;
  return status === "pass" ? "warn" : status;
}

function metadataBoolean(value: unknown): boolean | undefined {
  return asBoolean(value);
}

function metadataString(value: unknown): string | undefined {
  return asString(value);
}

function riskLookup(risks: JsonRecord[], pattern: RegExp): JsonRecord | undefined {
  return risks.find((risk) => pattern.test(asString(risk.Setting) ?? ""));
}

export interface SalesforcePlatformData {
  organization: SalesforceDataset<JsonRecord | undefined>;
  healthCheck: SalesforceDataset<JsonRecord | undefined>;
  healthCheckRisks: SalesforceDataset<JsonRecord[]>;
  securitySettings: SalesforceDataset<JsonRecord | undefined>;
  myDomainSettings: SalesforceDataset<JsonRecord | undefined>;
  instanceUrl?: string;
}

export interface SalesforceIdentityData {
  users: SalesforceDataset<JsonRecord[]>;
  profiles: SalesforceDataset<JsonRecord[]>;
  permissionSets: SalesforceDataset<JsonRecord[]>;
  assignments: SalesforceDataset<JsonRecord[]>;
  twoFactorMethods: SalesforceDataset<JsonRecord[]>;
  securitySettings: SalesforceDataset<JsonRecord | undefined>;
  healthCheckRisks: SalesforceDataset<JsonRecord[]>;
}

export interface SalesforceDataProtectionData {
  organization: SalesforceDataset<JsonRecord | undefined>;
  fieldPermissions: SalesforceDataset<JsonRecord[]>;
  tenantSecrets: SalesforceDataset<JsonRecord[]>;
  certificates: SalesforceDataset<JsonRecord[]>;
}

export interface SalesforceMonitoringData {
  connectedApplications: SalesforceDataset<JsonRecord[]>;
  oauthTokens: SalesforceDataset<JsonRecord[]>;
  loginHistory: SalesforceDataset<JsonRecord[]>;
  setupAuditTrail: SalesforceDataset<JsonRecord[]>;
  eventLogFiles: SalesforceDataset<JsonRecord[]>;
  loginHistoryDays: number;
  auditTrailDays: number;
}

export async function collectSalesforcePlatformData(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforcePlatformData> {
  const limit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 200_000);
  const [organization, healthCheck, healthCheckRisks, securitySettings, myDomainSettings] = await Promise.all([
    collectRecord("Organization", () => client.getOrganization()),
    collectRecord("SecurityHealthCheck", () => client.getHealthCheck()),
    collectRecords("SecurityHealthCheckRisks", () => client.listHealthCheckRisks(limit)),
    collectRecord("SecuritySettings", () => client.readSecuritySettings()),
    collectRecord("MyDomainSettings", () => client.readMyDomainSettings()),
  ]);
  let instanceUrl = client.getResolvedConfig().instanceUrl;
  try {
    instanceUrl = (await client.getSession()).instanceUrl;
  } catch {
    instanceUrl = client.getResolvedConfig().instanceUrl;
  }
  return { organization, healthCheck, healthCheckRisks, securitySettings, myDomainSettings, instanceUrl };
}

export function assessSalesforcePlatformData(data: SalesforcePlatformData): SalesforceAssessmentResult {
  const findings: SalesforceFinding[] = [];
  const settings = data.securitySettings.data ?? {};
  const session = asObject(settings.sessionSettings) ?? {};
  const passwords = asObject(settings.passwordPolicies) ?? {};
  const network = asObject(settings.networkAccess) ?? {};
  const settingsReadable = data.securitySettings.status === "ok" && data.securitySettings.data !== undefined;
  const risks = data.healthCheckRisks.data;
  const isSandbox = asBoolean(data.organization.data?.IsSandbox);

  const score = asNumber(data.healthCheck.data?.Score);
  if (data.healthCheck.status !== "ok") {
    findings.push(manualForUnreadable(1, data.healthCheck, "Setup > Security > Health Check: record the score and export the risk list.", { requires: "View Setup and Configuration, View Health Check" }));
  } else if (score === undefined) {
    findings.push(finding(1, "manual", "SecurityHealthCheck returned no Score value; the Health Check page may not have been generated yet.", { record: data.healthCheck.data ?? null }, "Setup > Security > Health Check: open the page so a score is generated, then record it."));
  } else {
    const highRisks = risks.filter((risk) => asString(risk.RiskType) === "HIGH_RISK");
    const mediumRisks = risks.filter((risk) => asString(risk.RiskType) === "MEDIUM_RISK");
    const risksReadable = data.healthCheckRisks.status === "ok";
    const status: SalesforceFindingStatus = !risksReadable ? "manual" : score >= 90 && highRisks.length === 0 ? withPartialDowngrade("pass", data.healthCheckRisks) : score >= 70 ? "warn" : "fail";
    findings.push(finding(
      1,
      status,
      !risksReadable
        ? `Health Check score is ${score}, but the per-setting risk list could not be read because ${unreadableReason(data.healthCheckRisks)}.`
        : `Health Check score is ${score} with ${highRisks.length} high-risk and ${mediumRisks.length} medium-risk settings out of ${risks.length} evaluated.${partialNote(data.healthCheckRisks)}`,
      {
        score,
        high_risk_settings: truncateList(highRisks.map((risk) => `${asString(risk.SettingGroup) ?? ""}: ${asString(risk.Setting) ?? ""} = ${asString(risk.OrgValue) ?? ""} (standard ${asString(risk.StandardValue) ?? ""})`)),
        medium_risk_settings: mediumRisks.length,
        settings_evaluated: risks.length,
        risks_truncated: data.healthCheckRisks.truncated,
      },
      !risksReadable ? "Setup > Security > Health Check: export the High-Risk and Medium-Risk setting tables." : undefined,
    ));
  }

  const sessionManual = "Setup > Security > Session Settings: record Timeout value, Force logout on session timeout, and Lock sessions to the IP address from which they originated.";
  if (!settingsReadable) {
    findings.push(manualForUnreadable(2, data.securitySettings, sessionManual, { requires: "Modify Metadata Through Metadata API Functions or Modify All Data" }));
  } else {
    const timeoutName = metadataString(session.sessionTimeout);
    const timeoutMinutes = timeoutName ? SESSION_TIMEOUT_MINUTES[timeoutName] : undefined;
    const forceLogout = metadataBoolean(session.forceLogoutOnSessionTimeout);
    const lockToIp = metadataBoolean(session.lockSessionsToIp);
    const evidence = { session_timeout: timeoutName ?? null, session_timeout_minutes: timeoutMinutes ?? null, force_logout_on_session_timeout: forceLogout ?? null, lock_sessions_to_ip: lockToIp ?? null };
    if (timeoutMinutes === undefined || forceLogout === undefined) {
      findings.push(finding(2, "manual", `SecuritySettings.sessionSettings did not expose a recognized sessionTimeout (${timeoutName ?? "absent"}) or forceLogoutOnSessionTimeout (${forceLogout ?? "absent"}), so the session policy cannot be confirmed.`, evidence, sessionManual));
    } else if (timeoutMinutes <= 120 && forceLogout) {
      findings.push(finding(2, lockToIp === true ? "pass" : "warn", `Session timeout is ${timeoutMinutes} minutes with forced logout on timeout enabled${lockToIp === true ? " and sessions locked to the originating IP." : "; lockSessionsToIp is not enabled, so hijacked sessions are not IP-bound."}`, evidence));
    } else {
      findings.push(finding(2, "fail", `Session timeout is ${timeoutMinutes} minutes (target <= 120) and forceLogoutOnSessionTimeout is ${forceLogout}.`, evidence));
    }
  }

  const passwordManual = "Setup > Security > Password Policies: record minimum length, complexity, expiration, history, lockout attempts, and lockout period.";
  if (!settingsReadable) {
    findings.push(manualForUnreadable(3, data.securitySettings, passwordManual));
  } else {
    const minimumLength = asNumber(passwords.minimumPasswordLength);
    const complexity = metadataString(passwords.complexity);
    const expirationName = metadataString(passwords.expiration);
    const expirationDays = expirationName === "Never" ? Number.POSITIVE_INFINITY : expirationName ? PASSWORD_EXPIRATION_DAYS[expirationName] : undefined;
    const history = asNumber(passwords.historyRestriction);
    const maxAttempts = metadataString(passwords.maxLoginAttempts);
    const lockout = metadataString(passwords.lockoutInterval);
    const evidence = { minimum_password_length: minimumLength ?? null, complexity: complexity ?? null, expiration: expirationName ?? null, history_restriction: history ?? null, max_login_attempts: maxAttempts ?? null, lockout_interval: lockout ?? null };
    if (minimumLength === undefined || complexity === undefined || expirationDays === undefined || history === undefined) {
      findings.push(finding(3, "manual", "SecuritySettings.passwordPolicies did not expose all of minimumPasswordLength, complexity, expiration, and historyRestriction, so the password policy cannot be confirmed.", evidence, passwordManual));
    } else {
      const gaps: string[] = [];
      if (minimumLength < 12) gaps.push(`minimum length ${minimumLength} < 12`);
      if ((PASSWORD_COMPLEXITY_RANK[complexity] ?? 0) < 3) gaps.push(`complexity ${complexity} is below upper, lower, and numeric`);
      if (expirationDays > 90) gaps.push(`expiration ${expirationName} exceeds 90 days`);
      if (history < 12) gaps.push(`history ${history} < 12`);
      if (maxAttempts === "NoLimit") gaps.push("no lockout after failed attempts");
      findings.push(finding(3, gaps.length === 0 ? "pass" : gaps.length <= 1 ? "warn" : "fail", gaps.length === 0 ? `Password policy meets the baseline: length ${minimumLength}, complexity ${complexity}, expiration ${expirationName}, history ${history}.` : `Password policy gaps: ${gaps.join("; ")}.`, evidence));
    }
  }

  const ipManual = "Setup > Security > Network Access: record trusted IP ranges; then Setup > Profiles > (each sensitive profile) > Login IP Ranges: confirm ranges are defined.";
  if (!settingsReadable) {
    findings.push(manualForUnreadable(5, data.securitySettings, ipManual));
  } else {
    const rawRanges = network.ipRanges;
    const ranges = asRecords(Array.isArray(rawRanges) ? rawRanges : rawRanges ? [rawRanges] : []);
    const enforceEveryRequest = metadataBoolean(session.enforceIpRangesEveryRequest);
    const evidence = { trusted_ip_ranges: ranges.length, ranges: truncateList(ranges.map((range) => `${asString(range.start) ?? "?"}-${asString(range.end) ?? "?"}`)), enforce_ip_ranges_every_request: enforceEveryRequest ?? null };
    if (ranges.length === 0) {
      findings.push(finding(5, "warn", "No org-wide trusted IP ranges are defined in SecuritySettings.networkAccess; per-profile login IP ranges are not exposed by readMetadata on SecuritySettings and must be reviewed manually.", evidence, ipManual));
    } else {
      findings.push(finding(5, enforceEveryRequest === true ? "pass" : "warn", `${ranges.length} org-wide trusted IP ranges are defined${enforceEveryRequest === true ? " and login IP ranges are enforced on every request." : ", but enforceIpRangesEveryRequest is not enabled and per-profile ranges still need manual review."}`, evidence, enforceEveryRequest === true ? undefined : ipManual));
    }
  }

  const domainManual = "Setup > My Domain > Policies: confirm 'Prevent login from https://login.salesforce.com' and 'Require My Domain for API logins' are enabled.";
  const myDomain = data.myDomainSettings.data ?? {};
  if (data.myDomainSettings.status !== "ok") {
    findings.push(manualForUnreadable(18, data.myDomainSettings, domainManual, { instance_url: data.instanceUrl ?? null }));
  } else {
    const preventLegacyLogin = metadataBoolean(myDomain.canOnlyLoginWithMyDomainUrl);
    const requireDomainForApi = metadataBoolean(myDomain.doesApiLoginRequireOrgDomain);
    const domainName = metadataString(myDomain.myDomainName);
    const hasMyDomain = Boolean(domainName) || /\.my\.salesforce\.com/i.test(data.instanceUrl ?? "");
    const evidence = { my_domain_name: domainName ?? null, instance_url: data.instanceUrl ?? null, can_only_login_with_my_domain_url: preventLegacyLogin ?? null, does_api_login_require_org_domain: requireDomainForApi ?? null, is_sandbox: isSandbox ?? null };
    if (!hasMyDomain) {
      findings.push(finding(18, "fail", "No My Domain name was exposed by MyDomainSettings and the instance URL is not a My Domain host.", evidence));
    } else if (preventLegacyLogin === undefined) {
      findings.push(finding(18, "manual", `My Domain ${domainName ?? data.instanceUrl} is configured, but canOnlyLoginWithMyDomainUrl was not exposed, so the login policy cannot be confirmed.`, evidence, domainManual));
    } else if (preventLegacyLogin) {
      findings.push(finding(18, requireDomainForApi === true ? "pass" : "warn", `My Domain ${domainName ?? data.instanceUrl} prevents login from login.salesforce.com${requireDomainForApi === true ? " and requires My Domain for API logins." : "; doesApiLoginRequireOrgDomain is not enabled."}`, evidence));
    } else {
      findings.push(finding(18, "fail", `My Domain ${domainName ?? data.instanceUrl} still allows login from login.salesforce.com (canOnlyLoginWithMyDomainUrl=false).`, evidence));
    }
  }

  const clickjackManual = "Setup > Security > Session Settings > Clickjack Protection: confirm all four clickjack options are enabled.";
  if (!settingsReadable) {
    findings.push(manualForUnreadable(19, data.securitySettings, clickjackManual));
  } else {
    const flags = {
      enable_clickjack_setup: metadataBoolean(session.enableClickjackSetup),
      enable_clickjack_nonsetup_sfdc: metadataBoolean(session.enableClickjackNonsetupSFDC),
      enable_clickjack_nonsetup_user: metadataBoolean(session.enableClickjackNonsetupUser),
      enable_clickjack_nonsetup_user_headerless: metadataBoolean(session.enableClickjackNonsetupUserHeaderless),
    };
    const values = Object.values(flags);
    const disabled = Object.entries(flags).filter(([, value]) => value === false).map(([key]) => key);
    const missing = Object.entries(flags).filter(([, value]) => value === undefined).map(([key]) => key);
    if (values.every((value) => value === true)) {
      findings.push(finding(19, "pass", "Clickjack protection is enabled for setup pages, non-setup Salesforce pages, and Visualforce pages with and without headers.", flags));
    } else if (disabled.length > 0) {
      findings.push(finding(19, disabled.length >= 2 ? "fail" : "warn", `Clickjack protection is disabled for: ${disabled.join(", ")}.`, { ...flags, missing_flags: missing }));
    } else {
      findings.push(finding(19, "manual", `Clickjack flags were not exposed by SecuritySettings: ${missing.join(", ")}.`, flags, clickjackManual));
    }
  }

  const csrfManual = "Setup > Security > Session Settings > Cross-Site Request Forgery (CSRF) Protection: confirm GET and POST protection are enabled.";
  if (!settingsReadable) {
    findings.push(manualForUnreadable(20, data.securitySettings, csrfManual));
  } else {
    const csrfGet = metadataBoolean(session.enableCSRFOnGet);
    const csrfPost = metadataBoolean(session.enableCSRFOnPost);
    const evidence = { enable_csrf_on_get: csrfGet ?? null, enable_csrf_on_post: csrfPost ?? null };
    if (csrfGet === true && csrfPost === true) {
      findings.push(finding(20, "pass", "CSRF protection is enabled for GET and POST requests on non-setup pages.", evidence));
    } else if (csrfGet === false || csrfPost === false) {
      findings.push(finding(20, "fail", `CSRF protection is disabled for ${[csrfGet === false ? "GET" : undefined, csrfPost === false ? "POST" : undefined].filter(Boolean).join(" and ")} requests.`, evidence));
    } else {
      findings.push(finding(20, "manual", "CSRF flags enableCSRFOnGet and enableCSRFOnPost were not exposed by SecuritySettings.", evidence, csrfManual));
    }
  }

  const mfaRisk = riskLookup(risks, /multi-factor|mfa|two-factor/i);
  return {
    area: "platform_security",
    title: "Salesforce platform security settings",
    summary: {
      organization: asString(data.organization.data?.Name) ?? null,
      organization_type: asString(data.organization.data?.OrganizationType) ?? null,
      is_sandbox: isSandbox ?? null,
      instance_url: data.instanceUrl ?? null,
      health_check_score: score ?? null,
      health_check_risks: risks.length,
      security_settings_readable: settingsReadable,
      my_domain_settings_readable: data.myDomainSettings.status === "ok",
      mfa_health_check_setting: mfaRisk ? `${asString(mfaRisk.Setting)} = ${asString(mfaRisk.OrgValue)}` : null,
    },
    findings: findings.sort((left, right) => left.control - right.control),
    errors: datasetErrors(data.organization, data.healthCheck, data.healthCheckRisks, data.securitySettings, data.myDomainSettings),
  };
}

export async function assessSalesforcePlatformSecurity(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceAssessmentResult> {
  return assessSalesforcePlatformData(await collectSalesforcePlatformData(client, options));
}

function hasElevatedPermission(record: JsonRecord): string[] {
  const flags: Array<[string, string]> = [
    ["PermissionsModifyAllData", "Modify All Data"],
    ["PermissionsViewAllData", "View All Data"],
    ["PermissionsManageUsers", "Manage Users"],
    ["PermissionsAuthorApex", "Author Apex"],
    ["PermissionsCustomizeApplication", "Customize Application"],
    ["PermissionsManageProfilesPermissionsets", "Manage Profiles and Permission Sets"],
    ["PermissionsPasswordNeverExpires", "Password Never Expires"],
  ];
  return flags.filter(([key]) => asBoolean(record[key]) === true).map(([, label]) => label);
}

function userLabel(user: JsonRecord): string {
  return asString(user.Username) ?? asString(user.Name) ?? asString(user.Id) ?? "user";
}

export async function collectSalesforceIdentityData(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceIdentityData> {
  const limit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 200_000);
  const [users, profiles, permissionSets, assignments, twoFactorMethods, securitySettings, healthCheckRisks] = await Promise.all([
    collectRecords("User", () => client.listUsers(limit)),
    collectRecords("Profile", () => client.listProfiles(limit)),
    collectRecords("PermissionSet", () => client.listPermissionSets(limit)),
    collectRecords("PermissionSetAssignment", () => client.listPermissionSetAssignments(limit)),
    collectRecords("TwoFactorMethodsInfo", () => client.listTwoFactorMethods(limit)),
    collectRecord("SecuritySettings", () => client.readSecuritySettings()),
    collectRecords("SecurityHealthCheckRisks", () => client.listHealthCheckRisks(limit)),
  ]);
  return { users, profiles, permissionSets, assignments, twoFactorMethods, securitySettings, healthCheckRisks };
}

export function assessSalesforceIdentityData(data: SalesforceIdentityData, options: SalesforceAssessmentOptions = {}): SalesforceAssessmentResult {
  const findings: SalesforceFinding[] = [];
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10_000);
  const users = data.users.data;
  const activeUsers = users.filter((user) => asBoolean(user.IsActive) === true);
  const standardActiveUsers = activeUsers.filter((user) => asString(user.UserType) === "Standard");
  const profiles = data.profiles.data;
  const profileById = new Map(profiles.map((profile) => [asString(profile.Id) ?? "", profile]));
  const usersReadable = data.users.status === "ok";
  const profilesReadable = data.profiles.status === "ok";

  const mfaManual = "Setup > Identity Verification (Session Settings): confirm 'Require multi-factor authentication (MFA) for all direct UI logins to your org' is enabled; then Setup > Users > (each active user): confirm registered MFA methods.";
  const session = asObject(data.securitySettings.data?.sessionSettings) ?? {};
  const mfaRequired = asBoolean(session.enableMFADirectUILoginOptIn);
  const mfaRisk = riskLookup(data.healthCheckRisks.data, /multi-factor|mfa/i);
  const mfaRiskMeets = mfaRisk ? asString(mfaRisk.RiskType) === "MEETS_STANDARD" : undefined;
  const enrollment = new Map(data.twoFactorMethods.data.map((row) => [asString(row.UserId) ?? "", row]));
  const enrolled = (userIdValue: string): boolean => {
    const row = enrollment.get(userIdValue);
    if (!row) return false;
    return ["HasTotp", "HasU2F", "HasSecurityKey", "HasSalesforceAuthenticator", "HasBuiltInAuthenticator"].some((key) => asBoolean(row[key]) === true);
  };
  const unenrolled = standardActiveUsers.filter((user) => !enrolled(asString(user.Id) ?? ""));
  const mfaEvidence = {
    enable_mfa_direct_ui_login_opt_in: mfaRequired ?? null,
    health_check_mfa_setting: mfaRisk ? { setting: asString(mfaRisk.Setting), org_value: asString(mfaRisk.OrgValue), risk_type: asString(mfaRisk.RiskType) } : null,
    active_standard_users: standardActiveUsers.length,
    users_without_registered_mfa_method: unenrolled.length,
    sample_users_without_mfa: truncateList(unenrolled.map(userLabel)),
    two_factor_methods_readable: data.twoFactorMethods.status === "ok",
    users_truncated: data.users.truncated,
  };
  if (data.securitySettings.status !== "ok" && !mfaRisk) {
    findings.push(finding(4, "manual", `MFA enforcement could not be verified because ${unreadableReason(data.securitySettings)} and Health Check exposed no MFA setting.`, mfaEvidence, mfaManual));
  } else if (mfaRequired === false || mfaRiskMeets === false) {
    findings.push(finding(4, "fail", `MFA is not required for all direct UI logins (enableMFADirectUILoginOptIn=${mfaRequired ?? "absent"}${mfaRisk ? `, Health Check: ${asString(mfaRisk.Setting)} = ${asString(mfaRisk.OrgValue)}` : ""}).`, mfaEvidence));
  } else if (mfaRequired === true || mfaRiskMeets === true) {
    if (!usersReadable || data.twoFactorMethods.status !== "ok") {
      findings.push(finding(4, "manual", `MFA is required for direct UI logins, but per-user enrollment could not be verified because ${!usersReadable ? unreadableReason(data.users) : unreadableReason(data.twoFactorMethods)}.`, mfaEvidence, mfaManual));
    } else if (standardActiveUsers.length === 0) {
      findings.push(finding(4, "manual", "MFA is required for direct UI logins, but zero active standard users were returned, which indicates a partial user view rather than a compliant org.", mfaEvidence, mfaManual));
    } else if (unenrolled.length === 0) {
      findings.push(finding(4, withPartialDowngrade("pass", data.users), `MFA is required for direct UI logins and all ${standardActiveUsers.length} active standard users have a registered verification method.${partialNote(data.users)}`, mfaEvidence));
    } else {
      findings.push(finding(4, unenrolled.length > standardActiveUsers.length / 4 ? "fail" : "warn", `MFA is required for direct UI logins, but ${unenrolled.length}/${standardActiveUsers.length} active standard users have no registered MFA method (SSO-only users may be exempt by design).`, mfaEvidence));
    }
  } else {
    findings.push(finding(4, "manual", "Neither SecuritySettings.sessionSettings.enableMFADirectUILoginOptIn nor a Health Check MFA setting exposed a value, so MFA enforcement cannot be confirmed.", mfaEvidence, mfaManual));
  }

  findings.push(finding(
    6,
    "manual",
    "Login hour restrictions live in Profile metadata (loginHours), which this inspector does not retrieve; verify sensitive profiles in Setup.",
    { profiles_visible: profiles.length, sensitive_profiles: truncateList(profiles.filter((profile) => hasElevatedPermission(profile).length > 0).map((profile) => asString(profile.Name) ?? "")) },
    "Setup > Profiles > (System Administrator and other elevated profiles) > Login Hours: record configured hours or the decision not to restrict them.",
  ));

  const apiManual = "Setup > Profiles: for each profile with API Enabled, confirm the assigned users require API access; record API Only User profiles.";
  if (!profilesReadable) {
    findings.push(manualForUnreadable(7, data.profiles, apiManual));
  } else if (profiles.length === 0) {
    findings.push(finding(7, "manual", "Zero profiles were returned, which is not possible for a real org and indicates a permission-limited view.", { profiles: 0 }, apiManual));
  } else {
    const apiProfiles = profiles.filter((profile) => asBoolean(profile.PermissionsApiEnabled) === true);
    const apiOnlyProfiles = profiles.filter((profile) => asBoolean(profile.PermissionsApiUserOnly) === true);
    const usersOnApiProfiles = activeUsers.filter((user) => asBoolean(profileById.get(asString(user.ProfileId) ?? "")?.PermissionsApiEnabled) === true);
    const ratio = profiles.length > 0 ? apiProfiles.length / profiles.length : 0;
    const evidence = {
      profiles: profiles.length,
      api_enabled_profiles: truncateList(apiProfiles.map((profile) => asString(profile.Name) ?? "")),
      api_only_profiles: truncateList(apiOnlyProfiles.map((profile) => asString(profile.Name) ?? "")),
      active_users_on_api_enabled_profiles: usersReadable ? usersOnApiProfiles.length : null,
      profiles_truncated: data.profiles.truncated,
    };
    const status: SalesforceFindingStatus = ratio > 0.5 ? "fail" : ratio > 0.25 ? "warn" : withPartialDowngrade("pass", data.profiles);
    findings.push(finding(7, status, `${apiProfiles.length}/${profiles.length} profiles grant API Enabled${usersReadable ? ` covering ${usersOnApiProfiles.length} active users` : ""}; ${apiOnlyProfiles.length} are API Only User profiles.${partialNote(data.profiles)}`, evidence, status === "pass" ? undefined : apiManual));
  }

  const permSetManual = "Setup > Permission Sets: filter by Modify All Data, View All Data, Manage Users, and Author Apex; export the assignment list and confirm each assignee is justified.";
  const permissionSets = data.permissionSets.data;
  if (data.permissionSets.status !== "ok") {
    findings.push(manualForUnreadable(9, data.permissionSets, permSetManual));
  } else if (permissionSets.length === 0) {
    findings.push(finding(9, "manual", "Zero permission sets were returned; even orgs without custom permission sets expose standard ones, so this indicates a permission-limited view.", { permission_sets: 0 }, permSetManual));
  } else {
    const elevated = permissionSets.map((set) => ({ set, perms: hasElevatedPermission(set) })).filter((item) => item.perms.length > 0);
    const assignmentsReadable = data.assignments.status === "ok";
    const elevatedIds = new Set(elevated.map((item) => asString(item.set.Id) ?? ""));
    const elevatedAssignments = data.assignments.data.filter((assignment) => elevatedIds.has(asString(assignment.PermissionSetId) ?? ""));
    const activeElevatedAssignments = elevatedAssignments.filter((assignment) => asBoolean(asObject(assignment.Assignee)?.IsActive) !== false);
    const assignees = new Set(activeElevatedAssignments.map((assignment) => asString(assignment.AssigneeId) ?? ""));
    const evidence = {
      permission_sets: permissionSets.length,
      elevated_permission_sets: truncateList(elevated.map((item) => `${asString(item.set.Name) ?? ""} [${item.perms.join(", ")}]`)),
      elevated_assignments: assignmentsReadable ? activeElevatedAssignments.length : null,
      distinct_assignees: assignmentsReadable ? assignees.size : null,
      assignments_truncated: data.assignments.truncated,
      permission_sets_truncated: data.permissionSets.truncated,
    };
    if (elevated.length === 0) {
      findings.push(finding(9, withPartialDowngrade("pass", data.permissionSets), `None of the ${permissionSets.length} permission sets grant Modify All Data, View All Data, Manage Users, Author Apex, or other elevated permissions.${partialNote(data.permissionSets)}`, evidence));
    } else if (!assignmentsReadable) {
      findings.push(finding(9, "manual", `${elevated.length} permission sets grant elevated permissions, but assignments could not be read because ${unreadableReason(data.assignments)}.`, evidence, permSetManual));
    } else {
      const status: SalesforceFindingStatus = assignees.size > maxAdmins ? "fail" : assignees.size > 0 ? "warn" : withPartialDowngrade("pass", data.assignments);
      findings.push(finding(9, status, `${elevated.length} permission sets grant elevated permissions and are assigned to ${assignees.size} distinct active users (threshold ${maxAdmins}).${partialNote(data.assignments)}`, evidence, status === "pass" ? undefined : permSetManual));
    }
  }

  const adminManual = "Setup > Users: filter by System Administrator profile and export the list; confirm each administrator is justified.";
  if (!profilesReadable || !usersReadable) {
    findings.push(manualForUnreadable(10, profilesReadable ? data.users : data.profiles, adminManual));
  } else if (users.length === 0) {
    findings.push(finding(10, "manual", "Zero users were returned; the auditing user cannot see the org population (View All Users is likely missing).", { users: 0 }, adminManual));
  } else {
    const adminProfiles = profiles.filter((profile) => asBoolean(profile.PermissionsModifyAllData) === true || asString(profile.Name) === "System Administrator");
    const adminProfileIds = new Set(adminProfiles.map((profile) => asString(profile.Id) ?? ""));
    const admins = activeUsers.filter((user) => adminProfileIds.has(asString(user.ProfileId) ?? ""));
    const now = options.now ?? new Date();
    const staleDays = clampNumber(options.staleLoginDays, DEFAULT_STALE_LOGIN_DAYS, 1, 3650);
    const adminsWithoutLogin = admins.filter((user) => asDate(user.LastLoginDate) === undefined);
    const staleAdmins = admins.filter((user) => {
      const lastLogin = asDate(user.LastLoginDate);
      return lastLogin !== undefined && daysBetween(now, lastLogin) > staleDays;
    });
    const evidence = {
      active_users: activeUsers.length,
      admin_profiles: truncateList(adminProfiles.map((profile) => asString(profile.Name) ?? "")),
      active_admins: admins.length,
      admin_threshold: maxAdmins,
      admins_without_login_date: truncateList(adminsWithoutLogin.map(userLabel)),
      stale_admins: truncateList(staleAdmins.map(userLabel)),
      users_truncated: data.users.truncated,
      users_seen: data.users.seen,
      users_total: data.users.total ?? null,
    };
    const status: SalesforceFindingStatus = admins.length > maxAdmins || staleAdmins.length > 0 ? "fail" : adminsWithoutLogin.length > 0 ? "warn" : withPartialDowngrade("pass", data.users);
    findings.push(finding(10, status, `${admins.length} active users hold administrator-class profiles (threshold ${maxAdmins}); ${staleAdmins.length} have not logged in for ${staleDays}+ days and ${adminsWithoutLogin.length} have no LastLoginDate and are not counted as active administrators.${partialNote(data.users)}`, evidence, status === "pass" ? undefined : adminManual));
  }

  const guestManual = "Setup > Sites and Digital Experiences > (each site) > Public Access Settings: confirm guest profiles have no API access, no View All or Modify All permissions, and object access limited to what the site needs.";
  if (!usersReadable) {
    findings.push(manualForUnreadable(13, data.users, guestManual));
  } else {
    const guests = users.filter((user) => asString(user.UserType) === "Guest");
    const activeGuests = guests.filter((user) => asBoolean(user.IsActive) === true);
    const riskyGuests = activeGuests.filter((user) => {
      const profile = profileById.get(asString(user.ProfileId) ?? "");
      return profile !== undefined && (asBoolean(profile.PermissionsApiEnabled) === true || hasElevatedPermission(profile).length > 0);
    });
    const evidence = {
      guest_users: guests.length,
      active_guest_users: truncateList(activeGuests.map(userLabel)),
      risky_guest_users: truncateList(riskyGuests.map(userLabel)),
      profiles_readable: profilesReadable,
      users_truncated: data.users.truncated,
    };
    if (data.users.truncated) {
      findings.push(finding(13, "warn", `Only ${data.users.seen} of ${data.users.total ?? "unknown"} users were read, so guest user coverage is partial; ${activeGuests.length} active guest users were seen.`, evidence, guestManual));
    } else if (activeGuests.length === 0) {
      findings.push(finding(13, "pass", "No active guest users exist, so no Sites or Experience Cloud public access is exposed through guest profiles (emptiness is compliant for this control).", evidence));
    } else if (!profilesReadable) {
      findings.push(finding(13, "manual", `${activeGuests.length} active guest users exist, but their profiles could not be read because ${unreadableReason(data.profiles)}.`, evidence, guestManual));
    } else if (riskyGuests.length > 0) {
      findings.push(finding(13, "fail", `${riskyGuests.length}/${activeGuests.length} active guest users sit on profiles with API Enabled or elevated data permissions.`, evidence));
    } else {
      findings.push(finding(13, "warn", `${activeGuests.length} active guest users exist without API or elevated permissions; object and field access for each public site still needs manual review.`, evidence, guestManual));
    }
  }

  return {
    area: "identity_access",
    title: "Salesforce identity and access",
    summary: {
      users: users.length,
      active_users: activeUsers.length,
      users_truncated: data.users.truncated,
      profiles: profiles.length,
      permission_sets: permissionSets.length,
      permission_set_assignments: data.assignments.data.length,
      two_factor_method_rows: data.twoFactorMethods.data.length,
      mfa_required_for_direct_ui_login: mfaRequired ?? null,
    },
    findings: findings.sort((left, right) => left.control - right.control),
    errors: datasetErrors(data.users, data.profiles, data.permissionSets, data.assignments, data.twoFactorMethods, data.securitySettings, data.healthCheckRisks),
  };
}

export async function assessSalesforceIdentityAccess(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceAssessmentResult> {
  return assessSalesforceIdentityData(await collectSalesforceIdentityData(client, options), { ...options, now: options.now ?? client.getNow() });
}

export async function collectSalesforceDataProtectionData(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceDataProtectionData> {
  const limit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 200_000);
  const [organization, fieldPermissions, tenantSecrets, certificates] = await Promise.all([
    collectRecord("Organization", () => client.getOrganization()),
    collectRecords("FieldPermissions", () => client.listSensitiveFieldPermissions(limit)),
    collectRecords("TenantSecret", () => client.listTenantSecrets(limit)),
    collectRecords("Certificate", () => client.listCertificates(limit)),
  ]);
  return { organization, fieldPermissions, tenantSecrets, certificates };
}

const PUBLIC_OWD_VALUES = /^(Edit|Read|ReadWrite|ReadWriteTransfer|ShowDetails|ShowDetailsInsert|HideDetailsInsert|ControlledByLeadOrContact|ControlledByCampaign)$/;
const STRICT_OWD_VALUES = /^(None|Private|ControlledByParent|HideDetails)$/;

export function assessSalesforceDataProtectionData(data: SalesforceDataProtectionData, options: SalesforceAssessmentOptions = {}): SalesforceAssessmentResult {
  const findings: SalesforceFinding[] = [];
  const now = options.now ?? new Date();

  const flsManual = "Setup > Object Manager > (objects holding SSN, payment card, health, or credential data) > Fields > Set Field-Level Security: export which profiles and permission sets can read or edit each sensitive field.";
  const fieldPermissions = data.fieldPermissions.data;
  if (data.fieldPermissions.status !== "ok") {
    findings.push(manualForUnreadable(8, data.fieldPermissions, flsManual));
  } else if (fieldPermissions.length === 0) {
    findings.push(finding(8, "manual", `No FieldPermissions rows matched the sensitive-name patterns (${SENSITIVE_FIELD_PATTERNS.length} patterns); sensitive fields may use other names, so classification must be confirmed manually.`, { patterns: SENSITIVE_FIELD_PATTERNS }, flsManual));
  } else {
    const byField = new Map<string, JsonRecord[]>();
    for (const row of fieldPermissions) {
      const key = asString(row.Field) ?? "";
      byField.set(key, [...(byField.get(key) ?? []), row]);
    }
    const broad = [...byField.entries()].filter(([, rows]) => rows.length > 5);
    const editable = fieldPermissions.filter((row) => asBoolean(row.PermissionsEdit) === true);
    const evidence = {
      sensitive_fields: byField.size,
      grants: fieldPermissions.length,
      edit_grants: editable.length,
      broadly_readable_fields: truncateList(broad.map(([field, rows]) => `${field} (${rows.length} grants)`)),
      truncated: data.fieldPermissions.truncated,
    };
    const status: SalesforceFindingStatus = broad.length > 0 ? "warn" : withPartialDowngrade("pass", data.fieldPermissions);
    findings.push(finding(8, status, `${byField.size} fields matching sensitive-name patterns carry ${fieldPermissions.length} profile or permission set grants; ${broad.length} fields are readable by more than 5 grants.${partialNote(data.fieldPermissions)}`, evidence, flsManual));
  }

  const sharingManual = "Setup > Security > Sharing Settings: record organization-wide defaults for every standard and custom object, plus the sharing rules that widen access.";
  const organization = data.organization.data;
  if (data.organization.status !== "ok" || !organization) {
    findings.push(manualForUnreadable(12, data.organization, sharingManual));
  } else {
    const owdKeys = ["DefaultAccountAccess", "DefaultContactAccess", "DefaultCaseAccess", "DefaultLeadAccess", "DefaultOpportunityAccess", "DefaultCampaignAccess", "DefaultCalendarAccess", "DefaultPricebookAccess"];
    const values = owdKeys.map((key) => ({ key, value: asString(organization[key]) }));
    const missing = values.filter((item) => item.value === undefined);
    const open = values.filter((item) => item.value !== undefined && PUBLIC_OWD_VALUES.test(item.value) && !/^(ReadSelect|Read)$/.test(item.key === "DefaultPricebookAccess" ? item.value : ""));
    const strict = values.filter((item) => item.value !== undefined && STRICT_OWD_VALUES.test(item.value));
    const evidence = { organization_wide_defaults: Object.fromEntries(values.map((item) => [item.key, item.value ?? null])), open_defaults: open.map((item) => `${item.key}=${item.value}`), strict_defaults: strict.length };
    if (missing.length === owdKeys.length) {
      findings.push(finding(12, "manual", "Organization returned no Default*Access fields, so organization-wide defaults cannot be read.", evidence, sharingManual));
    } else if (open.length === 0) {
      findings.push(finding(12, "warn", "Standard object organization-wide defaults are Private or Controlled by Parent; custom object defaults and sharing rules are not exposed here and still need manual review.", evidence, sharingManual));
    } else {
      findings.push(finding(12, open.length >= 3 ? "fail" : "warn", `${open.length} standard objects use public organization-wide defaults: ${open.map((item) => `${item.key}=${item.value}`).join(", ")}.`, evidence, sharingManual));
    }
  }

  const encryptionManual = "Setup > Security > Platform Encryption > Key Management: record active tenant secrets, last rotation dates, and Encryption Policy for sensitive fields (Shield Platform Encryption license required).";
  const secrets = data.tenantSecrets.data;
  if (data.tenantSecrets.status === "forbidden" || data.tenantSecrets.status === "unavailable") {
    findings.push(finding(16, "manual", `Shield Platform Encryption is not applicable or not visible: ${unreadableReason(data.tenantSecrets)}. This is a not-applicable or scoped-out result, not a pass.`, { dataset_status: data.tenantSecrets.status, error: data.tenantSecrets.error ?? null }, encryptionManual));
  } else if (data.tenantSecrets.status !== "ok") {
    findings.push(manualForUnreadable(16, data.tenantSecrets, encryptionManual));
  } else if (secrets.length === 0) {
    findings.push(finding(16, "fail", "TenantSecret is readable but no tenant secrets exist, so Shield Platform Encryption has no active keys and no fields are encrypted.", { tenant_secrets: 0 }, encryptionManual));
  } else {
    const active = secrets.filter((secret) => asString(secret.Status) === "Active");
    const dated = active.filter((secret) => asDate(secret.CreatedDate) !== undefined);
    const undated = active.length - dated.length;
    const oldest = dated.map((secret) => daysBetween(now, asDate(secret.CreatedDate) as Date)).sort((left, right) => right - left)[0];
    const evidence = { tenant_secrets: secrets.length, active_secrets: active.length, active_types: [...new Set(active.map((secret) => asString(secret.Type) ?? ""))], oldest_active_secret_days: oldest ?? null, active_secrets_without_created_date: undated };
    if (active.length === 0) {
      findings.push(finding(16, "fail", `${secrets.length} tenant secrets exist but none are Active.`, evidence, encryptionManual));
    } else if (undated > 0) {
      findings.push(finding(16, "warn", `${active.length} active tenant secrets exist but ${undated} have no CreatedDate, so rotation age cannot be confirmed for them.`, evidence, encryptionManual));
    } else {
      findings.push(finding(16, (oldest ?? 0) > 365 ? "warn" : withPartialDowngrade("pass", data.tenantSecrets), `${active.length} active tenant secrets (${evidence.active_types.join(", ")}); oldest active key is ${oldest} days old. Field-level encryption policy still needs manual confirmation.${partialNote(data.tenantSecrets)}`, evidence, encryptionManual));
    }
  }

  const certManual = "Setup > Security > Certificate and Key Management: record each certificate, its expiration, key size, and whether it is CA-signed.";
  const certificates = data.certificates.data;
  const warningDays = clampNumber(options.certificateExpiryWarningDays, DEFAULT_CERT_EXPIRY_WARNING_DAYS, 1, 365);
  if (data.certificates.status !== "ok") {
    findings.push(manualForUnreadable(17, data.certificates, certManual));
  } else if (certificates.length === 0) {
    findings.push(finding(17, "manual", "No certificates were returned from the Certificate object; confirm that SSO, JWT connected apps, and outbound callouts do not rely on unmanaged certificates.", { certificates: 0 }, certManual));
  } else {
    const undated = certificates.filter((cert) => asDate(cert.ExpirationDate) === undefined);
    const expired = certificates.filter((cert) => { const date = asDate(cert.ExpirationDate); return date !== undefined && date.getTime() < now.getTime(); });
    const expiring = certificates.filter((cert) => { const date = asDate(cert.ExpirationDate); return date !== undefined && date.getTime() >= now.getTime() && daysBetween(date, now) <= warningDays; });
    const weakKeys = certificates.filter((cert) => (asNumber(cert.KeySize) ?? 2048) < 2048);
    const label = (cert: JsonRecord): string => `${asString(cert.DeveloperName) ?? asString(cert.MasterLabel) ?? "certificate"} (${asString(cert.ExpirationDate) ?? "no expiration date"})`;
    const evidence = { certificates: certificates.length, expired: truncateList(expired.map(label)), expiring_within_days: warningDays, expiring: truncateList(expiring.map(label)), missing_expiration_date: truncateList(undated.map(label)), weak_keys: truncateList(weakKeys.map(label)), truncated: data.certificates.truncated };
    const status: SalesforceFindingStatus = expired.length > 0 || weakKeys.length > 0 ? "fail" : expiring.length > 0 || undated.length > 0 ? "warn" : withPartialDowngrade("pass", data.certificates);
    findings.push(finding(17, status, `${certificates.length} certificates: ${expired.length} expired, ${expiring.length} expiring within ${warningDays} days, ${undated.length} without an expiration date (not counted as valid), ${weakKeys.length} with keys under 2048 bits. CA-signed status is not exposed by the query and needs manual confirmation.${partialNote(data.certificates)}`, evidence, certManual));
  }

  return {
    area: "data_protection",
    title: "Salesforce data protection",
    summary: {
      sensitive_field_grants: fieldPermissions.length,
      tenant_secrets: secrets.length,
      tenant_secret_status: data.tenantSecrets.status,
      certificates: certificates.length,
      organization_readable: data.organization.status === "ok",
    },
    findings: findings.sort((left, right) => left.control - right.control),
    errors: datasetErrors(data.organization, data.fieldPermissions, data.tenantSecrets, data.certificates),
  };
}

export async function assessSalesforceDataProtection(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceAssessmentResult> {
  return assessSalesforceDataProtectionData(await collectSalesforceDataProtectionData(client, options), { ...options, now: options.now ?? client.getNow() });
}

export async function collectSalesforceMonitoringData(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceMonitoringData> {
  const limit = clampNumber(options.recordLimit, DEFAULT_RECORD_LIMIT, 1, 200_000);
  const loginHistoryDays = clampNumber(options.loginHistoryDays, DEFAULT_LOGIN_HISTORY_DAYS, 1, 180);
  const auditTrailDays = clampNumber(options.auditTrailDays, DEFAULT_AUDIT_TRAIL_DAYS, 1, 180);
  const [connectedApplications, oauthTokens, loginHistory, setupAuditTrail, eventLogFiles] = await Promise.all([
    collectRecords("ConnectedApplication", () => client.listConnectedApplications(limit)),
    collectRecords("OauthToken", () => client.listOauthTokens(limit)),
    collectRecords("LoginHistory", () => client.listLoginHistory(loginHistoryDays, limit)),
    collectRecords("SetupAuditTrail", () => client.listSetupAuditTrail(auditTrailDays, limit)),
    collectRecords("EventLogFile", () => client.listEventLogFiles(7, 200)),
  ]);
  return { connectedApplications, oauthTokens, loginHistory, setupAuditTrail, eventLogFiles, loginHistoryDays, auditTrailDays };
}

export function assessSalesforceMonitoringData(data: SalesforceMonitoringData): SalesforceAssessmentResult {
  const findings: SalesforceFinding[] = [];

  const appManual = "Setup > Apps > Connected Apps > Manage Connected Apps: for each app record Permitted Users, IP Relaxation, Refresh Token Policy, and OAuth scopes; Setup > Connected Apps OAuth Usage: review apps with active tokens.";
  const apps = data.connectedApplications.data;
  if (data.connectedApplications.status !== "ok") {
    findings.push(manualForUnreadable(11, data.connectedApplications, appManual));
  } else if (apps.length === 0) {
    findings.push(finding(11, "manual", "ConnectedApplication returned zero apps; apps without org-managed policies do not appear here, so OAuth usage must be reviewed manually.", { connected_applications: 0, oauth_tokens: data.oauthTokens.status === "ok" ? data.oauthTokens.data.length : null }, appManual));
  } else {
    const openApps = apps.filter((app) => asBoolean(app.OptionsAllowAdminApprovedUsersOnly) === false);
    const unknownPolicy = apps.filter((app) => asBoolean(app.OptionsAllowAdminApprovedUsersOnly) === undefined);
    const unboundedRefresh = apps.filter((app) => asNumber(app.RefreshTokenValidityPeriod) === undefined && asBoolean(app.OptionsRefreshTokenValidityMetric) !== true);
    const tokensReadable = data.oauthTokens.status === "ok";
    const tokensByApp = new Map<string, number>();
    for (const token of data.oauthTokens.data) {
      const key = asString(token.AppName) ?? "unknown";
      tokensByApp.set(key, (tokensByApp.get(key) ?? 0) + 1);
    }
    const evidence = {
      connected_applications: apps.length,
      self_authorizing_apps: truncateList(openApps.map((app) => asString(app.Name) ?? "")),
      apps_without_policy_flag: truncateList(unknownPolicy.map((app) => asString(app.Name) ?? "")),
      apps_without_refresh_token_limit: truncateList(unboundedRefresh.map((app) => asString(app.Name) ?? "")),
      oauth_tokens: tokensReadable ? data.oauthTokens.data.length : null,
      tokens_by_app: tokensReadable ? Object.fromEntries([...tokensByApp.entries()].slice(0, 25)) : null,
      truncated: data.connectedApplications.truncated,
    };
    if (unknownPolicy.length === apps.length) {
      findings.push(finding(11, "manual", `${apps.length} connected apps were returned but none exposed OptionsAllowAdminApprovedUsersOnly, so the pre-authorization policy cannot be confirmed.`, evidence, appManual));
    } else if (openApps.length > 0) {
      findings.push(finding(11, openApps.length > apps.length / 2 ? "fail" : "warn", `${openApps.length}/${apps.length} connected apps allow all users to self-authorize instead of admin pre-approval; ${unboundedRefresh.length} have no refresh token expiry. OAuth scopes are not exposed by SOQL and need manual review.`, evidence, appManual));
    } else {
      findings.push(finding(11, "warn", `All ${apps.length} connected apps with visible policies require admin pre-approval, but OAuth scopes and IP relaxation are not exposed by SOQL and still need manual review.${partialNote(data.connectedApplications)}`, evidence, appManual));
    }
  }

  const loginManual = `Setup > Identity > Login History: export the last ${data.loginHistoryDays} days and review failed logins, unexpected countries, and legacy TLS or API-only logins.`;
  const logins = data.loginHistory.data;
  if (data.loginHistory.status !== "ok") {
    findings.push(manualForUnreadable(14, data.loginHistory, loginManual));
  } else if (logins.length === 0) {
    findings.push(finding(14, "manual", `LoginHistory returned zero rows for the last ${data.loginHistoryDays} days, which is implausible for an active org and indicates a permission-limited or empty view.`, { login_rows: 0, window_days: data.loginHistoryDays }, loginManual));
  } else {
    const failed = logins.filter((login) => { const status = asString(login.Status); return status !== undefined && status !== "Success"; });
    const undated = logins.filter((login) => asDate(login.LoginTime) === undefined);
    const failuresByIp = new Map<string, number>();
    for (const login of failed) {
      const ip = asString(login.SourceIp) ?? "unknown";
      failuresByIp.set(ip, (failuresByIp.get(ip) ?? 0) + 1);
    }
    const bruteForceIps = [...failuresByIp.entries()].filter(([, count]) => count >= 10).map(([ip, count]) => `${ip} (${count} failures)`);
    const countries = [...new Set(logins.map((login) => asString(login.CountryIso)).filter((value): value is string => Boolean(value)))];
    const legacyTls = logins.filter((login) => /TLS 1\.[01]/i.test(asString(login.TlsProtocol) ?? ""));
    const failureRatio = failed.length / logins.length;
    const evidence = {
      login_rows: logins.length,
      window_days: data.loginHistoryDays,
      failed_logins: failed.length,
      failure_ratio: Number(failureRatio.toFixed(3)),
      brute_force_sources: truncateList(bruteForceIps),
      countries,
      legacy_tls_logins: legacyTls.length,
      rows_without_login_time: undated.length,
      truncated: data.loginHistory.truncated,
      seen: data.loginHistory.seen,
      total: data.loginHistory.total ?? null,
    };
    const status: SalesforceFindingStatus = bruteForceIps.length > 0 || failureRatio > 0.25 || legacyTls.length > 0 ? "fail" : failureRatio > 0.1 || countries.length > 5 || undated.length > 0 || data.loginHistory.truncated ? "warn" : "pass";
    findings.push(finding(14, status, `${logins.length} logins in ${data.loginHistoryDays} days: ${failed.length} failures (${Math.round(failureRatio * 100)}%), ${bruteForceIps.length} sources with 10+ failures, ${countries.length} countries, ${legacyTls.length} legacy TLS logins.${partialNote(data.loginHistory)}`, evidence, status === "pass" ? undefined : loginManual));
  }

  const auditManual = `Setup > Security > View Setup Audit Trail: download the last ${data.auditTrailDays} days and review permission, profile, admin, session, password, and network access changes.`;
  const trail = data.setupAuditTrail.data;
  if (data.setupAuditTrail.status !== "ok") {
    findings.push(manualForUnreadable(15, data.setupAuditTrail, auditManual, { requires: "View Setup and Configuration" }));
  } else if (trail.length === 0) {
    findings.push(finding(15, "manual", `SetupAuditTrail returned zero rows for the last ${data.auditTrailDays} days; an active org almost always has setup changes, so this indicates a permission-limited view.`, { audit_rows: 0, window_days: data.auditTrailDays }, auditManual));
  } else {
    const highRisk = trail.filter((row) => HIGH_RISK_AUDIT_SECTIONS.test(asString(row.Section) ?? "") || HIGH_RISK_AUDIT_ACTIONS.test(asString(row.Action) ?? ""));
    const undated = trail.filter((row) => asDate(row.CreatedDate) === undefined);
    const actors = [...new Set(highRisk.map((row) => asString(asObject(row.CreatedBy)?.Username) ?? asString(row.CreatedById) ?? "unknown"))];
    const eventLogReadable = data.eventLogFiles.status === "ok";
    const eventTypes = [...new Set(data.eventLogFiles.data.map((row) => asString(row.EventType) ?? ""))].filter(Boolean);
    const evidence = {
      audit_rows: trail.length,
      window_days: data.auditTrailDays,
      high_risk_changes: highRisk.length,
      high_risk_actors: truncateList(actors),
      sample_high_risk_changes: truncateList(highRisk.map((row) => `${asString(row.CreatedDate) ?? "?"} ${asString(row.Section) ?? ""}/${asString(row.Action) ?? ""}: ${asString(row.Display) ?? ""}`), 15),
      rows_without_created_date: undated.length,
      event_monitoring: eventLogReadable ? { event_log_files_last_7_days: data.eventLogFiles.data.length, event_types: eventTypes } : { status: data.eventLogFiles.status, error: data.eventLogFiles.error ?? null },
      truncated: data.setupAuditTrail.truncated,
    };
    const status: SalesforceFindingStatus = data.setupAuditTrail.truncated || undated.length > 0 ? "warn" : highRisk.length > 0 ? "warn" : "pass";
    findings.push(finding(15, status, `${trail.length} setup changes in ${data.auditTrailDays} days with ${highRisk.length} high-risk security changes by ${actors.length} actors; Event Monitoring ${eventLogReadable ? `exposed ${data.eventLogFiles.data.length} EventLogFile rows in 7 days` : `is not readable (${data.eventLogFiles.status})`}.${partialNote(data.setupAuditTrail)}`, evidence, status === "pass" ? undefined : auditManual));
  }

  return {
    area: "monitoring_integrations",
    title: "Salesforce monitoring and integrations",
    summary: {
      connected_applications: apps.length,
      oauth_tokens: data.oauthTokens.data.length,
      login_rows: logins.length,
      login_history_days: data.loginHistoryDays,
      audit_rows: trail.length,
      audit_trail_days: data.auditTrailDays,
      event_log_files: data.eventLogFiles.data.length,
      event_log_status: data.eventLogFiles.status,
    },
    findings: findings.sort((left, right) => left.control - right.control),
    errors: datasetErrors(data.connectedApplications, data.oauthTokens, data.loginHistory, data.setupAuditTrail, data.eventLogFiles),
  };
}

export async function assessSalesforceMonitoringIntegrations(client: ReadClient, options: SalesforceAssessmentOptions = {}): Promise<SalesforceAssessmentResult> {
  return assessSalesforceMonitoringData(await collectSalesforceMonitoringData(client, options));
}

async function probeSurface(
  name: string,
  endpoint: string,
  permissionHint: string,
  load: () => Promise<unknown>,
  count?: (value: unknown) => number | undefined,
): Promise<SalesforceAccessSurface> {
  try {
    const value = await load();
    return { name, endpoint, status: "readable", count: count?.(value), permissionHint };
  } catch (error) {
    return { name, endpoint, status: "not_readable", error: errorMessage(error), permissionHint };
  }
}

function queryCount(value: unknown): number | undefined {
  const object = asObject(value);
  return object ? asNumber(object.totalSize) ?? asRecords(object.records).length : undefined;
}

export async function checkSalesforceAccess(client: ReadClient): Promise<SalesforceAccessCheckResult> {
  const config = client.getResolvedConfig();
  const version = config.apiVersion;
  let instanceUrl = config.instanceUrl;
  let sessionError: string | undefined;
  try {
    instanceUrl = (await client.getSession()).instanceUrl;
  } catch (error) {
    sessionError = errorMessage(error);
  }

  const organization = await collectRecord("Organization", () => client.getOrganization());
  const surfaces: SalesforceAccessSurface[] = [
    {
      name: "oauth_session",
      endpoint: `${config.loginUrl}/services/oauth2/token`,
      status: sessionError ? "not_readable" : "readable",
      error: sessionError,
      permissionHint: "API Enabled plus a valid connected app grant",
    },
    { name: "organization", endpoint: `/services/data/v${version}/query (Organization)`, status: organization.status === "ok" ? "readable" : "not_readable", count: organization.seen, error: organization.error, permissionHint: "API Enabled" },
    await probeSurface("limits", `/services/data/v${version}/limits`, "API Enabled", () => client.getLimits(), () => 1),
    await probeSurface("health_check", `/services/data/v${version}/tooling/query (SecurityHealthCheck)`, "View Setup and Configuration, View Health Check", () => client.getHealthCheck(), (value) => (value ? 1 : 0)),
    await probeSurface("health_check_risks", `/services/data/v${version}/tooling/query (SecurityHealthCheckRisks)`, "View Setup and Configuration", () => client.listHealthCheckRisks(50), queryCount),
    await probeSurface("security_settings", `/services/Soap/m/${version} readMetadata(SecuritySettings)`, "Modify Metadata Through Metadata API Functions or Modify All Data", () => client.readSecuritySettings(), (value) => (value ? 1 : 0)),
    await probeSurface("users", `/services/data/v${version}/query (User)`, "View All Users (Manage Users read)", () => client.listUsers(50), queryCount),
    await probeSurface("profiles", `/services/data/v${version}/query (Profile)`, "View Setup and Configuration", () => client.listProfiles(50), queryCount),
    await probeSurface("permission_sets", `/services/data/v${version}/query (PermissionSet)`, "View Setup and Configuration", () => client.listPermissionSets(50), queryCount),
    await probeSurface("login_history", `/services/data/v${version}/query (LoginHistory)`, "Manage Users or View All Users", () => client.listLoginHistory(7, 50), queryCount),
    await probeSurface("setup_audit_trail", `/services/data/v${version}/query (SetupAuditTrail)`, "View Setup and Configuration", () => client.listSetupAuditTrail(30, 50), queryCount),
    await probeSurface("connected_applications", `/services/data/v${version}/query (ConnectedApplication)`, "View Setup and Configuration", () => client.listConnectedApplications(50), queryCount),
    await probeSurface("event_log_files", `/services/data/v${version}/query (EventLogFile)`, "View Event Log Files (Event Monitoring license)", () => client.listEventLogFiles(1, 10), queryCount),
  ];

  const missingPermissions = [...new Set(surfaces.filter((surface) => surface.status === "not_readable").map((surface) => surface.permissionHint ?? "").filter(Boolean))];
  const coreNames = new Set(["oauth_session", "organization", "health_check", "security_settings", "users", "profiles", "permission_sets", "setup_audit_trail", "login_history"]);
  const coreReadable = surfaces.filter((surface) => coreNames.has(surface.name) && surface.status === "readable").length;
  const status: SalesforceAccessCheckResult["status"] = coreReadable === coreNames.size ? "healthy" : "limited";
  const org = organization.data;

  return {
    status,
    authMode: config.authMode,
    instanceUrl,
    organization: org ? { id: asString(org.Id) ?? null, name: asString(org.Name) ?? null, type: asString(org.OrganizationType) ?? null, is_sandbox: asBoolean(org.IsSandbox) ?? null, instance: asString(org.InstanceName) ?? null } : undefined,
    surfaces,
    missingPermissions,
    notes: [
      `Auth mode ${config.authMode} against ${config.loginUrl}${instanceUrl ? `, instance ${instanceUrl}` : ""}, API v${version}.`,
      org ? `Org ${asString(org.Name) ?? asString(org.Id)} (${asString(org.OrganizationType) ?? "unknown edition"}, sandbox=${String(asBoolean(org.IsSandbox) ?? "unknown")}).` : "Organization record was not readable.",
      `${surfaces.filter((surface) => surface.status === "readable").length}/${surfaces.length} Salesforce audit surfaces are readable.`,
      ...(missingPermissions.length > 0 ? [`Likely missing permissions: ${missingPermissions.join("; ")}.`] : []),
    ],
    recommendedNextStep: status === "healthy"
      ? "Run salesforce_assess_platform_security, salesforce_assess_identity_access, salesforce_assess_data_protection, salesforce_assess_monitoring_integrations, or salesforce_export_audit_bundle."
      : "Grant the auditing user View Setup and Configuration, View Health Check, API Enabled, View All Users, and Modify Metadata Through Metadata API Functions, then re-run salesforce_check_access.",
  };
}

function formatAccessCheckText(result: SalesforceAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Salesforce access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SalesforceAssessmentResult): string {
  const rows = result.findings.map((item) => [item.id, item.severity.toUpperCase(), item.status.toUpperCase(), item.title, item.summary]);
  const summary = Object.entries(result.summary).map(([key, value]) => `- ${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`).join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function summarizeFindingStatuses(findings: SalesforceFinding[]): Record<SalesforceFindingStatus, number> {
  const counts: Record<SalesforceFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(config: SalesforceResolvedConfig, orgLabel: string, assessments: SalesforceAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeFindingStatuses(findings);
  const healthScore = assessments.find((assessment) => assessment.area === "platform_security")?.summary.health_check_score;
  return [
    "# Salesforce Security Inspector: Executive Summary",
    "",
    `Org: ${orgLabel}`,
    `Auth mode: ${config.authMode}`,
    `API version: v${config.apiVersion}`,
    `Generated: ${new Date().toISOString()}`,
    `Health Check score: ${healthScore ?? "not available"}`,
    "",
    "## Result Counts",
    "",
    `- Controls assessed: ${findings.length} of ${CONTROLS.length}`,
    `- Failed: ${counts.fail}`,
    `- Warning: ${counts.warn}`,
    `- Manual verification required: ${counts.manual}`,
    `- Passing: ${counts.pass}`,
    `- Collection errors: ${errors.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((left, right) => (left.status === right.status ? left.control - right.control : left.status === "fail" ? -1 : 1))
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Verification Queue",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id} ${item.title}: ${item.manualEvidence ?? item.summary}`),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: SalesforceFinding[]): string {
  const frameworks = Object.keys(FRAMEWORK_LABELS) as SalesforceFramework[];
  const rows = findings.map((item) => {
    const definition = controlDefinition(item.control);
    return [item.id, item.title, item.status.toUpperCase(), ...frameworks.map((framework) => definition.mappings[framework])];
  });
  return [
    "# Unified Compliance Matrix",
    "",
    formatTable(["Control", "Title", "Status", ...frameworks.map((framework) => FRAMEWORK_LABELS[framework])], rows),
    "",
  ].join("\n");
}

function buildFrameworkReport(title: string, framework: SalesforceFramework, findings: SalesforceFinding[]): string {
  const rows = findings.map((item) => [controlDefinition(item.control).mappings[framework], item.id, item.title, item.status.toUpperCase(), item.summary]);
  return [
    `# ${title}`,
    "",
    `Framework: ${FRAMEWORK_LABELS[framework]}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    formatTable([FRAMEWORK_LABELS[framework], "Finding", "Title", "Status", "Summary"], rows),
    "",
    "## Manual Evidence",
    "",
    ...findings.filter((item) => item.manualEvidence).map((item) => `- ${item.id}: ${item.manualEvidence}`),
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# Salesforce Audit Bundle Quick Reference",
    "",
    "This bundle was generated by grclanker's native Salesforce security inspector. It is read-only evidence; no org settings were changed.",
    "",
    "## Layout",
    "",
    "- `core_data/`: raw API snapshots (Organization, Health Check, SecuritySettings, users, profiles, permission sets, login history, audit trail, connected apps, certificates, tenant secrets, event log files)",
    "- `analysis/findings.json`: all normalized findings with framework mappings",
    "- `analysis/<area>.json`: per-area assessment results and collection errors",
    "- `compliance/executive_summary.md`: prioritized summary and manual verification queue",
    "- `compliance/unified_compliance_matrix.md`: control to framework matrix",
    "- `compliance/<framework>/`: one report per framework (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP)",
    "- `_errors.log`: present only when some collection failed; the affected controls render as manual, never pass",
    "",
    "## Status Semantics",
    "",
    "- `pass`: evidence was read completely and meets the control baseline",
    "- `warn`: evidence was read but is partial, borderline, or needs supplemental manual review",
    "- `fail`: evidence shows the control is not met",
    "- `manual`: evidence was unreadable, not applicable, or requires a human to collect from Setup",
    "",
    "Credentials, tokens, and private keys are never written into the bundle.",
    "",
  ].join("\n");
}

export async function exportSalesforceAuditBundle(
  client: ReadClient,
  config: SalesforceResolvedConfig,
  outputRoot: string,
  options: SalesforceAssessmentOptions = {},
): Promise<SalesforceAuditBundleResult> {
  const access = await checkSalesforceAccess(client);
  const platformData = await collectSalesforcePlatformData(client, options);
  const identityData = await collectSalesforceIdentityData(client, options);
  const dataProtection = await collectSalesforceDataProtectionData(client, options);
  const monitoring = await collectSalesforceMonitoringData(client, options);
  const now = options.now ?? client.getNow();
  const assessments = [
    assessSalesforcePlatformData(platformData),
    assessSalesforceIdentityData(identityData, { ...options, now }),
    assessSalesforceDataProtectionData(dataProtection, { ...options, now }),
    assessSalesforceMonitoringData(monitoring),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];
  const orgLabel = asString(platformData.organization.data?.Name) ?? asString(platformData.organization.data?.Id) ?? (platformData.instanceUrl ? new URL(platformData.instanceUrl).hostname : "salesforce-org");

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(orgLabel)}-audit-bundle`);

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access_check.json", access],
    ["core_data/organization.json", platformData.organization],
    ["core_data/security_health_check.json", platformData.healthCheck],
    ["core_data/security_health_check_risks.json", platformData.healthCheckRisks],
    ["core_data/security_settings.json", platformData.securitySettings],
    ["core_data/my_domain_settings.json", platformData.myDomainSettings],
    ["core_data/users.json", identityData.users],
    ["core_data/profiles.json", identityData.profiles],
    ["core_data/permission_sets.json", identityData.permissionSets],
    ["core_data/permission_set_assignments.json", identityData.assignments],
    ["core_data/two_factor_methods_info.json", identityData.twoFactorMethods],
    ["core_data/field_permissions_sensitive.json", dataProtection.fieldPermissions],
    ["core_data/tenant_secrets.json", dataProtection.tenantSecrets],
    ["core_data/certificates.json", dataProtection.certificates],
    ["core_data/connected_applications.json", monitoring.connectedApplications],
    ["core_data/oauth_tokens.json", monitoring.oauthTokens],
    ["core_data/login_history.json", monitoring.loginHistory],
    ["core_data/setup_audit_trail.json", monitoring.setupAuditTrail],
    ["core_data/event_log_files.json", monitoring.eventLogFiles],
  ];
  for (const [pathname, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathname, serializeJson(value));
  }
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    generated_at: now.toISOString(),
    organization: orgLabel,
    auth_mode: config.authMode,
    api_version: config.apiVersion,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    controls_defined: CONTROLS.length,
    status_counts: summarizeFindingStatuses(findings),
    errors,
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, orgLabel, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, report.path, buildFrameworkReport(report.title, report.framework, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: now.toISOString(),
    organization: orgLabel,
    instance_url: platformData.instanceUrl ?? null,
    login_url: config.loginUrl,
    auth_mode: config.authMode,
    api_version: config.apiVersion,
    source_chain: config.sourceChain,
  }));
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
    instance_url: asString(value.instance_url),
    login_url: asString(value.login_url),
    username: asString(value.username),
    password: asString(value.password),
    security_token: asString(value.security_token),
    consumer_key: asString(value.consumer_key),
    consumer_secret: asString(value.consumer_secret),
    private_key_file: asString(value.private_key_file),
    private_key: asString(value.private_key),
    refresh_token: asString(value.refresh_token),
    access_token: asString(value.access_token),
    credentials_file: asString(value.credentials_file),
    api_version: asString(value.api_version),
    sandbox: asBoolean(value.sandbox),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    record_limit: asNumber(value.record_limit),
    login_history_days: asNumber(value.login_history_days),
    audit_trail_days: asNumber(value.audit_trail_days),
    max_admins: asNumber(value.max_admins),
    certificate_expiry_warning_days: asNumber(value.certificate_expiry_warning_days),
    stale_login_days: asNumber(value.stale_login_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAssessArgs(args), output_dir: asString(value.output_dir) ?? asString(value.output) };
}

function toOptions(args: AssessArgs): SalesforceAssessmentOptions {
  return {
    recordLimit: args.record_limit,
    loginHistoryDays: args.login_history_days,
    auditTrailDays: args.audit_trail_days,
    maxAdmins: args.max_admins,
    certificateExpiryWarningDays: args.certificate_expiry_warning_days,
    staleLoginDays: args.stale_login_days,
  };
}

function createClient(args: AuthArgs): SalesforceApiClient {
  return new SalesforceApiClient(resolveSalesforceConfiguration(args as JsonRecord));
}

const authParams = {
  instance_url: Type.Optional(Type.String({ description: "Salesforce instance or My Domain URL, for example https://acme.my.salesforce.com. Defaults to SF_INSTANCE_URL." })),
  login_url: Type.Optional(Type.String({ description: "OAuth login host. Defaults to SF_LOGIN_URL, else https://test.salesforce.com for sandboxes or https://login.salesforce.com." })),
  username: Type.Optional(Type.String({ description: "Salesforce username for JWT bearer or username-password flows. Defaults to SF_USERNAME." })),
  password: Type.Optional(Type.String({ description: "Password for the username-password flow. Defaults to SF_PASSWORD." })),
  security_token: Type.Optional(Type.String({ description: "Security token appended to the password. Defaults to SF_SECURITY_TOKEN." })),
  consumer_key: Type.Optional(Type.String({ description: "Connected app consumer key (client_id). Defaults to SF_CONSUMER_KEY." })),
  consumer_secret: Type.Optional(Type.String({ description: "Connected app consumer secret. Defaults to SF_CONSUMER_SECRET." })),
  private_key_file: Type.Optional(Type.String({ description: "PEM private key path for the JWT bearer flow. Defaults to SF_PRIVATE_KEY_FILE." })),
  refresh_token: Type.Optional(Type.String({ description: "OAuth refresh token from a prior authorization code grant. Defaults to SF_REFRESH_TOKEN." })),
  access_token: Type.Optional(Type.String({ description: "Pre-issued access token (requires instance_url). Defaults to SF_ACCESS_TOKEN." })),
  credentials_file: Type.Optional(Type.String({ description: "JSON credentials file with grant_type jwt-bearer, password, or authorization_code. Defaults to SF_CREDENTIALS_FILE." })),
  api_version: Type.Optional(Type.String({ description: `Salesforce API version. Defaults to ${SALESFORCE_API_VERSION}.` })),
  sandbox: Type.Optional(Type.Boolean({ description: "Force the sandbox login host https://test.salesforce.com. Defaults to SF_SANDBOX or detection from the instance URL." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const assessParams = {
  ...authParams,
  record_limit: Type.Optional(Type.Number({ description: "Maximum records to read per SOQL query before recording truncation. Defaults to 2000.", default: 2000 })),
};

export function registerSalesforceTools(pi: any): void {
  pi.registerTool({
    name: "salesforce_check_access",
    label: "Check Salesforce audit access",
    description:
      "Validate read-only Salesforce access across OAuth session, Organization, limits, Security Health Check, SecuritySettings metadata, users, profiles, permission sets, login history, setup audit trail, connected apps, and event log files, and report likely missing permissions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkSalesforceAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "salesforce_check_access", ...result });
      } catch (error) {
        return errorResult(`Salesforce access check failed: ${errorMessage(error)}`, { tool: "salesforce_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "salesforce_assess_platform_security",
    label: "Assess Salesforce platform security settings",
    description:
      "Assess Salesforce Health Check score, session timeout, password policy, trusted IP ranges, My Domain login policy, clickjack protection, and CSRF protection (controls 1, 2, 3, 5, 18, 19, 20) via the Tooling API and Metadata API readMetadata.",
    parameters: Type.Object(assessParams),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessSalesforcePlatformSecurity(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "salesforce_assess_platform_security", ...result });
      } catch (error) {
        return errorResult(`Salesforce platform security assessment failed: ${errorMessage(error)}`, { tool: "salesforce_assess_platform_security" });
      }
    },
  });

  pi.registerTool({
    name: "salesforce_assess_identity_access",
    label: "Assess Salesforce identity and access",
    description:
      "Assess Salesforce MFA enforcement and enrollment, login hour restrictions, API access controls, elevated permission sets and assignments, administrator profiles, and guest user access (controls 4, 6, 7, 9, 10, 13).",
    parameters: Type.Object({
      ...assessParams,
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable administrator-class users or elevated assignees before failing. Defaults to 5.", default: 5 })),
      stale_login_days: Type.Optional(Type.Number({ description: "Days without login after which an administrator is stale. Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessSalesforceIdentityAccess(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "salesforce_assess_identity_access", ...result });
      } catch (error) {
        return errorResult(`Salesforce identity and access assessment failed: ${errorMessage(error)}`, { tool: "salesforce_assess_identity_access" });
      }
    },
  });

  pi.registerTool({
    name: "salesforce_assess_data_protection",
    label: "Assess Salesforce data protection",
    description:
      "Assess Salesforce field-level security on sensitive fields, organization-wide sharing defaults, Shield Platform Encryption tenant secrets, and certificate expiry (controls 8, 12, 16, 17).",
    parameters: Type.Object({
      ...assessParams,
      certificate_expiry_warning_days: Type.Optional(Type.Number({ description: "Warn when a certificate expires within this many days. Defaults to 30.", default: 30 })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessSalesforceDataProtection(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "salesforce_assess_data_protection", ...result });
      } catch (error) {
        return errorResult(`Salesforce data protection assessment failed: ${errorMessage(error)}`, { tool: "salesforce_assess_data_protection" });
      }
    },
  });

  pi.registerTool({
    name: "salesforce_assess_monitoring_integrations",
    label: "Assess Salesforce monitoring and integrations",
    description:
      "Assess Salesforce connected app OAuth policies and token usage, login history forensics, setup audit trail high-risk changes, and Event Monitoring availability (controls 11, 14, 15).",
    parameters: Type.Object({
      ...assessParams,
      login_history_days: Type.Optional(Type.Number({ description: "Login history lookback window in days. Defaults to 30.", default: 30 })),
      audit_trail_days: Type.Optional(Type.Number({ description: "Setup audit trail lookback window in days (max 180). Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessSalesforceMonitoringIntegrations(createClient(args), toOptions(args));
        return textResult(formatAssessmentText(result), { tool: "salesforce_assess_monitoring_integrations", ...result });
      } catch (error) {
        return errorResult(`Salesforce monitoring and integrations assessment failed: ${errorMessage(error)}`, { tool: "salesforce_assess_monitoring_integrations" });
      }
    },
  });

  pi.registerTool({
    name: "salesforce_export_audit_bundle",
    label: "Export Salesforce audit bundle",
    description:
      "Export a Salesforce audit package with raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive.",
    parameters: Type.Object({
      ...assessParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable administrator-class users before failing. Defaults to 5.", default: 5 })),
      login_history_days: Type.Optional(Type.Number({ description: "Login history lookback window in days. Defaults to 30.", default: 30 })),
      audit_trail_days: Type.Optional(Type.Number({ description: "Setup audit trail lookback window in days. Defaults to 90.", default: 90 })),
      certificate_expiry_warning_days: Type.Optional(Type.Number({ description: "Warn when a certificate expires within this many days. Defaults to 30.", default: 30 })),
      stale_login_days: Type.Optional(Type.Number({ description: "Days without login after which an administrator is stale. Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveSalesforceConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSalesforceAuditBundle(new SalesforceApiClient(config), config, outputRoot, toOptions(args));
        return textResult(
          [
            "Salesforce audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Collection errors: ${result.errorCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "salesforce_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            error_count: result.errorCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(`Salesforce audit bundle export failed: ${errorMessage(error)}`, { tool: "salesforce_export_audit_bundle" });
      }
    },
  });
}
