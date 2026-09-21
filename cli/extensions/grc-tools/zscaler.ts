/**
 * Zscaler security inspector tools for grclanker.
 *
 * Read-only ZIA (legacy API key plus session login) and ZPA (client
 * credentials) collectors that evaluate the 25 controls in
 * specs/zscaler-sec-inspector.spec.md. Every endpoint and field used here is
 * documented in the ZIA and ZPA API references on help.zscaler.com; see
 * src/content/docs/docs/integrations/zscaler.md for the citation table.
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

const DEFAULT_OUTPUT_DIR = "./export/zscaler";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const MAX_RETRY_AFTER_MS = 60_000;
const ZIA_PAGE_SIZE = 1000;
const ZIA_URL_RULE_PAGE_SIZE = 100;
const ZIA_FIREWALL_RULE_PAGE_SIZE = 5000;
const ZIA_MAX_PAGES = 50;
const ZPA_PAGE_SIZE = 500;
const ZPA_MAX_PAGES = 200;
const DEFAULT_MAX_SUPER_ADMINS = 5;
const DEFAULT_CERT_EXPIRY_WARN_DAYS = 30;
const DEFAULT_STALE_CONNECTOR_DAYS = 30;
const DEFAULT_MAX_TIMEOUT_HOURS = 24;
const HIGH_RISK_URL_CATEGORIES = [
  "OTHER_SECURITY",
  "MALWARE_SITES",
  "PHISHING",
  "BOTNET",
  "SPYWARE_ADWARE",
  "ADULT_THEMES",
  "PORNOGRAPHY",
  "GAMBLING",
  "ANONYMIZER",
  "ADULT_SEX_EDUCATION",
  "NUDITY",
];

export type ZscalerSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ZscalerFindingStatus = "pass" | "warn" | "fail" | "manual";
export type ZscalerArea = "zia_access_control" | "zia_policy" | "zpa";
export type ZscalerFramework = "FedRAMP" | "CMMC 2.0" | "SOC 2" | "CIS" | "PCI-DSS 4.0" | "DISA STIG" | "IRAP" | "ISMAP";
export type ZscalerProduct = "zia" | "zpa";

export interface ZiaResolvedConfig {
  cloud: string;
  baseUrl: string;
  apiKey: string;
  username: string;
  password: string;
}

export interface ZpaResolvedConfig {
  cloud: string;
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  customerId: string;
}

export interface ZscalerResolvedConfig {
  zia?: ZiaResolvedConfig;
  zpa?: ZpaResolvedConfig;
  oneApiDetected: boolean;
  zdxDetected: boolean;
  timeoutMs: number;
  maxRetries: number;
  sourceChain: string[];
  configFile?: string;
}

export interface ZscalerAccessSurface {
  product: ZscalerProduct;
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  statusCode?: number;
  error?: string;
}

export interface ZscalerAccessCheckResult {
  status: "healthy" | "limited" | "unavailable";
  products: Record<ZscalerProduct, "configured" | "not_configured">;
  surfaces: ZscalerAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface ZscalerFinding {
  id: string;
  control: number;
  title: string;
  severity: ZscalerSeverity;
  status: ZscalerFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  manualEvidence?: string;
}

export interface ZscalerAssessmentResult {
  title: string;
  area: ZscalerArea;
  summary: JsonRecord;
  findings: ZscalerFinding[];
  errors: string[];
  truncated: string[];
}

export interface ZscalerAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface CollectedDataset<T> {
  data: T;
  error?: string;
  statusCode?: number;
  truncated?: boolean;
  seen?: number;
  total?: number;
}

export interface PagedList {
  items: JsonRecord[];
  truncated: boolean;
  pagesFetched: number;
  totalPages?: number;
}

interface ControlDefinition {
  title: string;
  severity: ZscalerSeverity;
  area: ZscalerArea;
  mappings: Record<ZscalerFramework, string>;
}

const FRAMEWORK_ORDER: ZscalerFramework[] = ["FedRAMP", "CMMC 2.0", "SOC 2", "CIS", "PCI-DSS 4.0", "DISA STIG", "IRAP", "ISMAP"];

function control(
  title: string,
  severity: ZscalerSeverity,
  area: ZscalerArea,
  ids: [string, string, string, string, string, string, string, string],
): ControlDefinition {
  return {
    title,
    severity,
    area,
    mappings: {
      "FedRAMP": ids[0],
      "CMMC 2.0": ids[1],
      "SOC 2": ids[2],
      "CIS": ids[3],
      "PCI-DSS 4.0": ids[4],
      "DISA STIG": ids[5],
      "IRAP": ids[6],
      "ISMAP": ids[7],
    },
  };
}

const ZSCALER_CONTROLS: Record<number, ControlDefinition> = {
  1: control("URL Filtering Policy Audit", "high", "zia_policy", ["SC-7, SI-4", "C.3.13, C.5.3", "CC6.1, CC6.8", "CIS CSC 9", "1.2, 6.2", "V-XXXXX", "ISM-0261", "7.3.1"]),
  2: control("Firewall Rule Audit", "high", "zia_policy", ["AC-4, SC-7", "C.3.13, C.4.6", "CC6.1, CC6.6", "CIS CSC 9, 12", "1.2, 1.3", "V-XXXXX", "ISM-1416", "7.1.1"]),
  3: control("DLP Engine Configuration", "high", "zia_policy", ["SC-28, SI-4", "C.3.8, C.5.3", "CC6.1, CC6.7", "CIS CSC 3", "3.4, 3.5", "V-XXXXX", "ISM-0457", "7.2.1"]),
  4: control("SSL Inspection Coverage", "high", "zia_policy", ["SC-8, SI-4", "C.3.8, C.5.3", "CC6.1, CC6.7", "CIS CSC 9", "4.1, 4.2", "V-XXXXX", "ISM-0490", "7.2.2"]),
  5: control("Cloud Sandbox Analysis", "medium", "zia_policy", ["SI-3, SI-4", "C.5.2, C.5.3", "CC6.8, CC7.1", "CIS CSC 8, 10", "5.2", "V-XXXXX", "ISM-1288", "8.2.1"]),
  6: control("Admin MFA Enforcement", "critical", "zia_access_control", ["IA-2, IA-5", "C.1.1, C.3.7", "CC6.1, CC6.2", "CIS CSC 5, 6", "8.3, 8.4", "V-XXXXX", "ISM-1504", "6.2.1"]),
  7: control("RBAC & Admin Role Audit", "high", "zia_access_control", ["AC-2, AC-6", "C.1.1, C.1.4", "CC6.1, CC6.3", "CIS CSC 5, 6", "7.1, 7.2", "V-XXXXX", "ISM-1506", "6.1.1"]),
  8: control("Application Segmentation", "high", "zpa", ["SC-7, AC-4", "C.3.12, C.3.13", "CC6.1, CC6.6", "CIS CSC 12", "1.2, 1.4", "V-XXXXX", "ISM-1181", "7.1.2"]),
  9: control("Zero Trust Access Policies", "critical", "zpa", ["AC-3, AC-4", "C.1.1, C.3.13", "CC6.1, CC6.3", "CIS CSC 6, 14", "7.1, 7.2", "V-XXXXX", "ISM-1416", "6.1.2"]),
  10: control("Posture Profile Enforcement", "high", "zpa", ["CM-6, SI-4", "C.2.3, C.5.3", "CC6.1, CC6.8", "CIS CSC 4, 10", "5.2, 5.3", "V-XXXXX", "ISM-1407", "5.1.1"]),
  11: control("App Connector Health & Coverage", "medium", "zpa", ["SI-4, CM-8", "C.2.4, C.5.1", "CC6.1, CC7.1", "CIS CSC 1, 2", "11.4", "V-XXXXX", "ISM-1034", "8.1.1"]),
  12: control("IdP Integration & SAML Config", "critical", "zpa", ["IA-2, IA-8", "C.1.1, C.3.7", "CC6.1, CC6.2", "CIS CSC 5, 16", "8.3", "V-XXXXX", "ISM-1504", "6.2.2"]),
  13: control("Session Timeout Configuration", "medium", "zpa", ["AC-11, AC-12", "C.1.10, C.3.7", "CC6.1", "CIS CSC 4, 16", "8.6", "V-XXXXX", "ISM-0853", "6.3.1"]),
  14: control("Audit Logging Enabled", "high", "zia_access_control", ["AU-2, AU-6", "C.3.1, C.3.3", "CC7.2, CC7.3", "CIS CSC 6, 8", "10.1, 10.2", "V-XXXXX", "ISM-0580", "8.4.1"]),
  15: control("Trusted Network Detection", "medium", "zpa", ["AC-17, SC-7", "C.3.7, C.3.13", "CC6.1, CC6.6", "CIS CSC 12", "1.2", "V-XXXXX", "ISM-1416", "7.1.3"]),
  16: control("Bandwidth Control Policies", "low", "zia_policy", ["SC-7, SC-5", "C.3.13, C.4.6", "CC6.1", "CIS CSC 9", "1.2", "V-XXXXX", "ISM-1416", "7.4.1"]),
  17: control("Browser Isolation Policies", "medium", "zia_policy", ["SC-7, SI-3", "C.5.2, C.5.3", "CC6.1, CC6.8", "CIS CSC 9", "5.2, 6.2", "V-XXXXX", "ISM-1288", "8.2.2"]),
  18: control("Location & GRE/VPN Configuration", "medium", "zia_policy", ["SC-8, AC-17", "C.3.7, C.3.8", "CC6.1, CC6.6", "CIS CSC 12", "4.1", "V-XXXXX", "ISM-0490", "7.1.4"]),
  19: control("Cloud Application Control", "medium", "zia_policy", ["SC-7, SI-4", "C.3.13, C.5.3", "CC6.1, CC6.8", "CIS CSC 2, 9", "1.2, 6.2", "V-XXXXX", "ISM-0261", "7.3.2"]),
  20: control("DNS Security Configuration", "high", "zia_policy", ["SC-7, SI-4", "C.3.13, C.5.3", "CC6.1, CC6.8", "CIS CSC 9", "1.2", "V-XXXXX", "ISM-1416", "7.1.5"]),
  21: control("Service Edge Deployment", "low", "zpa", ["SI-4, CM-8", "C.2.4, C.5.1", "CC6.1, CC7.1", "CIS CSC 1, 2", "11.4", "V-XXXXX", "ISM-1034", "8.1.2"]),
  22: control("Forwarding Policy Audit", "medium", "zpa", ["AC-4, SC-7", "C.3.13, C.4.6", "CC6.1, CC6.6", "CIS CSC 9, 12", "1.2, 1.3", "V-XXXXX", "ISM-1416", "7.1.6"]),
  23: control("Emergency Access Configuration", "medium", "zpa", ["AC-2, CP-2", "C.1.1, C.3.6", "CC6.1, A1.2", "CIS CSC 5, 16", "8.6", "V-XXXXX", "ISM-1610", "6.4.1"]),
  24: control("Certificate Management", "high", "zpa", ["SC-12, SC-17", "C.3.8, C.3.10", "CC6.1, CC6.7", "CIS CSC 3", "4.1", "V-XXXXX", "ISM-0490", "7.2.3"]),
  25: control("Security Policy Baseline", "high", "zia_policy", ["SI-3, SI-4", "C.5.2, C.5.3", "CC6.8, CC7.1", "CIS CSC 8, 10", "5.2, 5.3", "V-XXXXX", "ISM-1288", "8.2.3"]),
};

const FRAMEWORK_REPORTS: Array<{ framework: ZscalerFramework; path: string; title: string }> = [
  { framework: "FedRAMP", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { framework: "CMMC 2.0", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC 2.0 Compliance Report" },
  { framework: "SOC 2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { framework: "CIS", path: "compliance/cis/cis_compliance_report.md", title: "CIS Controls Alignment Report" },
  { framework: "PCI-DSS 4.0", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS 4.0 Compliance Report" },
  { framework: "DISA STIG", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { framework: "IRAP", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { framework: "ISMAP", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

export function mappingsForControl(controlNumber: number): string[] {
  const definition = ZSCALER_CONTROLS[controlNumber];
  if (!definition) return [];
  return FRAMEWORK_ORDER.map((framework) => `${framework} ${definition.mappings[framework]}`);
}

export function listZscalerControls(): Array<{ control: number; id: string; title: string; severity: ZscalerSeverity; area: ZscalerArea }> {
  return Object.entries(ZSCALER_CONTROLS).map(([key, definition]) => ({
    control: Number(key),
    id: findingId(Number(key)),
    title: definition.title,
    severity: definition.severity,
    area: definition.area,
  }));
}

function findingId(controlNumber: number): string {
  return `ZS-${String(controlNumber).padStart(2, "0")}`;
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
    if (/^(true|1|yes|enabled)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asStringList(value: unknown): string[] {
  return asArray(value).map(asString).filter((item): item is string => Boolean(item));
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

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "zscaler";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function truncateList<T>(items: T[], max = 25): T[] {
  return items.slice(0, max);
}

function epochToDate(value: unknown): Date | undefined {
  const numeric = asNumber(value);
  if (numeric === undefined || numeric <= 0) return undefined;
  const millis = numeric < 1e11 ? numeric * 1000 : numeric;
  const date = new Date(millis);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function isoDateToDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (text === undefined || asNumber(text) !== undefined) return undefined;
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function certificateValidTo(item: JsonRecord): Date | undefined {
  return epochToDate(item.validToInEpochSec) ?? isoDateToDate(item.validTo);
}

function daysBetween(later: Date, earlier: Date): number {
  return Math.floor((later.getTime() - earlier.getTime()) / 86_400_000);
}

export function redactSecrets(message: string, secrets: Array<string | undefined>): string {
  let redacted = message;
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted.replace(/JSESSIONID=[^;\s"]+/g, "JSESSIONID=[REDACTED]");
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
  if (existsSync(root) && lstatSync(root).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked output directory: ${root}`);
  }
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
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

const ZIA_CLOUD_HOSTS: Record<string, string> = {
  zscaler: "https://zsapi.zscaler.net",
  zscalerone: "https://zsapi.zscalerone.net",
  zscalertwo: "https://zsapi.zscalertwo.net",
  zscalerthree: "https://zsapi.zscalerthree.net",
  zscloud: "https://zsapi.zscloud.net",
  zscalerbeta: "https://zsapi.zscalerbeta.net",
  zscalergov: "https://zsapi.zscalergov.net",
  zscalerten: "https://zsapi.zscalerten.net",
  zspreview: "https://admin.zspreview.net",
};

const ZPA_CLOUD_HOSTS: Record<string, string> = {
  PRODUCTION: "https://config.private.zscaler.com",
  ZPATWO: "https://config.zpatwo.net",
  BETA: "https://config.zpabeta.net",
  GOV: "https://config.zpagov.net",
  GOVUS: "https://config.zpagov.us",
  PREVIEW: "https://config.zpapreview.net",
};

export function resolveZiaBaseUrl(cloud: string): string {
  const normalized = cloud.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^zsapi\./, "").replace(/\.net.*$/, "");
  const host = ZIA_CLOUD_HOSTS[normalized];
  if (!host) {
    throw new Error(`Unknown ZIA cloud "${cloud}". Expected one of ${Object.keys(ZIA_CLOUD_HOSTS).join(", ")} or an explicit zia_base_url.`);
  }
  return `${host}/api/v1`;
}

export function resolveZpaBaseUrl(cloud: string): string {
  const normalized = cloud.trim().toUpperCase();
  const host = ZPA_CLOUD_HOSTS[normalized === "" ? "PRODUCTION" : normalized];
  if (!host) {
    throw new Error(`Unknown ZPA cloud "${cloud}". Expected one of ${Object.keys(ZPA_CLOUD_HOSTS).join(", ")} or an explicit zpa_base_url.`);
  }
  return host;
}

interface ConfigOverlay {
  ziaCloud?: string;
  ziaBaseUrl?: string;
  ziaApiKey?: string;
  ziaUsername?: string;
  ziaPassword?: string;
  zpaCloud?: string;
  zpaBaseUrl?: string;
  zpaClientId?: string;
  zpaClientSecret?: string;
  zpaCustomerId?: string;
  oneApiClientId?: string;
  oneApiClientSecret?: string;
  zdxClientId?: string;
  zdxClientSecret?: string;
  timeoutSeconds?: number;
  maxRetries?: number;
}

function overlayFromArgs(input: JsonRecord): ConfigOverlay {
  return {
    ziaCloud: asString(input.zia_cloud),
    ziaBaseUrl: asString(input.zia_base_url),
    ziaApiKey: asString(input.zia_api_key),
    ziaUsername: asString(input.zia_username),
    ziaPassword: asString(input.zia_password),
    zpaCloud: asString(input.zpa_cloud),
    zpaBaseUrl: asString(input.zpa_base_url),
    zpaClientId: asString(input.zpa_client_id),
    zpaClientSecret: asString(input.zpa_client_secret),
    zpaCustomerId: asString(input.zpa_customer_id),
    timeoutSeconds: asNumber(input.timeout_seconds),
    maxRetries: asNumber(input.max_retries),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): ConfigOverlay {
  return {
    ziaCloud: asString(env.ZIA_CLOUD),
    ziaBaseUrl: asString(env.ZIA_BASE_URL),
    ziaApiKey: asString(env.ZIA_API_KEY),
    ziaUsername: asString(env.ZIA_USERNAME),
    ziaPassword: asString(env.ZIA_PASSWORD),
    zpaCloud: asString(env.ZPA_CLOUD),
    zpaBaseUrl: asString(env.ZPA_BASE_URL),
    zpaClientId: asString(env.ZPA_CLIENT_ID),
    zpaClientSecret: asString(env.ZPA_CLIENT_SECRET),
    zpaCustomerId: asString(env.ZPA_CUSTOMER_ID),
    oneApiClientId: asString(env.ZSCALER_CLIENT_ID),
    oneApiClientSecret: asString(env.ZSCALER_CLIENT_SECRET),
    zdxClientId: asString(env.ZDX_CLIENT_ID),
    zdxClientSecret: asString(env.ZDX_CLIENT_SECRET),
    timeoutSeconds: asNumber(env.ZSCALER_TIMEOUT),
    maxRetries: asNumber(env.ZSCALER_MAX_RETRIES),
  };
}

function overlayFromConfigFile(pathname: string): ConfigOverlay {
  const parsed = asObject(parseYaml(readFileSync(pathname, "utf8"))) ?? {};
  const zia = asObject(asObject(parsed.zia)?.client) ?? asObject(parsed.zia) ?? {};
  const zpa = asObject(asObject(parsed.zpa)?.client) ?? asObject(parsed.zpa) ?? {};
  const oneApi = asObject(asObject(parsed.zscaler)?.client) ?? asObject(parsed.zscaler) ?? {};
  return {
    ziaCloud: asString(zia.cloud) ?? asString(zia.ZIA_CLOUD),
    ziaBaseUrl: asString(zia.baseUrl),
    ziaApiKey: asString(zia.apiKey) ?? asString(zia.ZIA_API_KEY),
    ziaUsername: asString(zia.username) ?? asString(zia.ZIA_USERNAME),
    ziaPassword: asString(zia.password) ?? asString(zia.ZIA_PASSWORD),
    zpaCloud: asString(zpa.cloud) ?? asString(zpa.ZPA_CLOUD),
    zpaBaseUrl: asString(zpa.baseUrl),
    zpaClientId: asString(zpa.clientId) ?? asString(zpa.ZPA_CLIENT_ID),
    zpaClientSecret: asString(zpa.clientSecret) ?? asString(zpa.ZPA_CLIENT_SECRET),
    zpaCustomerId: asString(zpa.customerId) ?? asString(zpa.ZPA_CUSTOMER_ID),
    oneApiClientId: asString(oneApi.clientId),
    oneApiClientSecret: asString(oneApi.clientSecret),
  };
}

function mergeOverlays(layers: Array<{ name: string; overlay: ConfigOverlay }>): { merged: ConfigOverlay; sourceChain: string[] } {
  const merged: ConfigOverlay = {};
  const sourceChain: string[] = [];
  for (const layer of layers) {
    for (const [key, value] of Object.entries(layer.overlay) as Array<[keyof ConfigOverlay, unknown]>) {
      if (value === undefined || merged[key] !== undefined) continue;
      (merged as Record<string, unknown>)[key] = value;
      sourceChain.push(`${layer.name}-${key}`);
    }
  }
  return { merged, sourceChain };
}

export function resolveZscalerConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): ZscalerResolvedConfig {
  const configFile = asString(input.config_file)
    ?? asString(env.ZSCALER_CONFIG_FILE)
    ?? (existsSync(join(homedir(), ".zscaler", "zscaler.yaml")) ? join(homedir(), ".zscaler", "zscaler.yaml") : undefined);
  const layers = [
    { name: "arguments", overlay: overlayFromArgs(input) },
    { name: "environment", overlay: overlayFromEnv(env) },
  ];
  if (configFile && existsSync(configFile)) {
    layers.push({ name: "config-file", overlay: overlayFromConfigFile(configFile) });
  }
  const { merged, sourceChain } = mergeOverlays(layers);

  let zia: ZiaResolvedConfig | undefined;
  if (merged.ziaApiKey || merged.ziaUsername || merged.ziaPassword || merged.ziaCloud) {
    if (!merged.ziaApiKey || !merged.ziaUsername || !merged.ziaPassword) {
      throw new Error("ZIA requires ZIA_API_KEY, ZIA_USERNAME, and ZIA_PASSWORD (or the matching zia_* arguments) together with ZIA_CLOUD or zia_base_url.");
    }
    if (!merged.ziaCloud && !merged.ziaBaseUrl) {
      throw new Error("ZIA requires ZIA_CLOUD (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten) or zia_base_url.");
    }
    zia = {
      cloud: merged.ziaCloud ?? "custom",
      baseUrl: merged.ziaBaseUrl ? normalizeBaseUrl(merged.ziaBaseUrl) : resolveZiaBaseUrl(merged.ziaCloud ?? ""),
      apiKey: merged.ziaApiKey,
      username: merged.ziaUsername,
      password: merged.ziaPassword,
    };
  }

  let zpa: ZpaResolvedConfig | undefined;
  if (merged.zpaClientId || merged.zpaClientSecret || merged.zpaCustomerId) {
    if (!merged.zpaClientId || !merged.zpaClientSecret || !merged.zpaCustomerId) {
      throw new Error("ZPA requires ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, and ZPA_CUSTOMER_ID (or the matching zpa_* arguments).");
    }
    zpa = {
      cloud: (merged.zpaCloud ?? "PRODUCTION").toUpperCase(),
      baseUrl: merged.zpaBaseUrl ? normalizeBaseUrl(merged.zpaBaseUrl) : resolveZpaBaseUrl(merged.zpaCloud ?? "PRODUCTION"),
      clientId: merged.zpaClientId,
      clientSecret: merged.zpaClientSecret,
      customerId: merged.zpaCustomerId,
    };
  }

  if (!zia && !zpa) {
    throw new Error(
      "No Zscaler credentials found. Provide ZIA (ZIA_CLOUD, ZIA_API_KEY, ZIA_USERNAME, ZIA_PASSWORD) and/or ZPA (ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID, ZPA_CLOUD) credentials via arguments, environment, or ~/.zscaler/zscaler.yaml.",
    );
  }

  return {
    zia,
    zpa,
    oneApiDetected: Boolean(merged.oneApiClientId && merged.oneApiClientSecret),
    zdxDetected: Boolean(merged.zdxClientId && merged.zdxClientSecret),
    timeoutMs: parseTimeoutSeconds(merged.timeoutSeconds),
    maxRetries: clampNumber(merged.maxRetries, DEFAULT_MAX_RETRIES, 0, 10),
    sourceChain: [...new Set(sourceChain)],
    configFile: configFile && existsSync(configFile) ? configFile : undefined,
  };
}

export class ZscalerApiError extends Error {
  readonly status: number;
  readonly product: ZscalerProduct;

  constructor(product: ZscalerProduct, status: number, message: string) {
    super(message);
    this.name = "ZscalerApiError";
    this.status = status;
    this.product = product;
  }
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

function retryDelayMs(response: Response, attempt: number): number {
  const header = response.headers.get("retry-after");
  const seconds = header ? Number(header) : Number.NaN;
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS);
  }
  return Math.min(500 * 2 ** attempt, MAX_RETRY_AFTER_MS);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function pageSignature(items: JsonRecord[]): string {
  return JSON.stringify(items.map((item) => item.id ?? JSON.stringify(item)));
}

function payloadErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  return [asString(object.message), asString(object.code), asString(object.reason), asString(object.error)]
    .filter((item): item is string => Boolean(item))
    .join("; ") || undefined;
}

function parseJsonText(rawText: string): unknown {
  if (rawText.length === 0) return {};
  try {
    return JSON.parse(rawText) as unknown;
  } catch {
    return { nonJsonBodyBytes: rawText.length };
  }
}

const ECHOED_ERROR_MAX_LENGTH = 160;
const ECHOED_SECRET_ASSIGNMENT = /([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|passphrase|credential|community|preshared|key)[A-Za-z0-9_.-]*"?\s*[:=]\s*"?)[^",;\s}]*/gi;
const ECHOED_LONG_TOKEN = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{16,}(?![A-Za-z0-9+/=_-])/g;
const ERROR_CODE_SHAPE = /^[A-Z][A-Z_.-]*$/;

// Error bodies are tenant-controlled text that ends up in findings, _errors.log, and the bundle, so only the
// documented error fields are echoed, capped, with credential-shaped content removed: secret-named key/value
// pairs lose their value, and any token of 16 or more characters is dropped unless it is shaped like an
// uppercase error code (letters only, such as INVALID_INPUT_ARGUMENT). Configured secrets are removed separately.
function scrubEchoedText(text: string): string {
  return text
    .replace(ECHOED_SECRET_ASSIGNMENT, "$1[REDACTED]")
    .replace(ECHOED_LONG_TOKEN, (token) => (ERROR_CODE_SHAPE.test(token) ? token : "[REDACTED]"))
    .slice(0, ECHOED_ERROR_MAX_LENGTH);
}

function errorDetail(payload: unknown, rawText: string): string | undefined {
  const summary = payloadErrorSummary(payload);
  if (summary !== undefined) return scrubEchoedText(summary);
  return rawText.length > 0 ? `non-JSON response body of ${rawText.length} bytes omitted` : undefined;
}

/**
 * ZIA API key obfuscation as documented in the ZIA API "Getting Started"
 * guide: the last six digits of the millisecond timestamp select characters
 * from the key, then the same digits shifted right by one bit select
 * characters offset by two.
 */
export function obfuscateZiaApiKey(apiKey: string, timestampMs: string): string {
  if (timestampMs.length < 6 || apiKey.length < 12) {
    throw new Error("ZIA API key obfuscation requires a 12+ character API key and a millisecond timestamp.");
  }
  const high = timestampMs.slice(-6);
  const low = String(Number.parseInt(high, 10) >> 1).padStart(6, "0");
  let obfuscated = "";
  for (const digit of high) {
    obfuscated += apiKey.charAt(Number.parseInt(digit, 10));
  }
  for (const digit of low) {
    obfuscated += apiKey.charAt(Number.parseInt(digit, 10) + 2);
  }
  return obfuscated;
}

function extractSessionCookie(response: Response): string | undefined {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  const cookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  const single = response.headers.get("set-cookie");
  const candidates = cookies.length > 0 ? cookies : single ? [single] : [];
  for (const cookie of candidates) {
    const match = /JSESSIONID=([^;,\s]+)/.exec(cookie);
    if (match) return match[1];
  }
  return undefined;
}

export interface ZiaReadClient {
  getResolvedConfig(): ZiaResolvedConfig;
  getNow(): Date;
  listAdminUsers(): Promise<PagedList>;
  listAdminRoles(): Promise<JsonRecord[]>;
  getAuthSettings(): Promise<JsonRecord>;
  getPasswordExpirySettings(): Promise<JsonRecord>;
  getAuditLogReportStatus(): Promise<JsonRecord>;
  listNssFeeds(): Promise<JsonRecord[]>;
  listUrlFilteringRules(): Promise<PagedList>;
  listFirewallFilteringRules(): Promise<PagedList>;
  listFirewallDnsRules(): Promise<JsonRecord[]>;
  listDlpEngines(): Promise<JsonRecord[]>;
  listDlpDictionaries(): Promise<JsonRecord[]>;
  listWebDlpRules(): Promise<JsonRecord[]>;
  listSslInspectionRules(): Promise<JsonRecord[]>;
  getSslExemptedUrls(): Promise<JsonRecord>;
  listSandboxRules(): Promise<JsonRecord[]>;
  getSandboxAdvancedSettings(): Promise<JsonRecord>;
  getAdvancedThreatSettings(): Promise<JsonRecord>;
  getMalwarePolicy(): Promise<JsonRecord>;
  getMalwareSettings(): Promise<JsonRecord>;
  getSecurityAllowlist(): Promise<JsonRecord>;
  getSecurityDenylist(): Promise<JsonRecord>;
  listLocations(): Promise<PagedList>;
  listSubLocations(locationId: string): Promise<JsonRecord[]>;
  listGreTunnels(): Promise<PagedList>;
  listVpnCredentials(): Promise<PagedList>;
  listBandwidthControlRules(): Promise<JsonRecord[]>;
  listBrowserIsolationProfiles(): Promise<JsonRecord[]>;
  listCloudAppRuleTypes(): Promise<string[]>;
  listCloudAppRules(ruleType: string): Promise<JsonRecord[]>;
  logout(): Promise<void>;
}

export class ZiaApiClient implements ZiaReadClient {
  private readonly config: ZiaResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly now: () => Date;
  private sessionId?: string;
  private loginPromise?: Promise<string>;

  constructor(
    config: ZiaResolvedConfig,
    options: { fetchImpl?: FetchImpl; timeoutMs?: number; maxRetries?: number; now?: () => Date } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): ZiaResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private redact(message: string): string {
    return redactSecrets(message, [this.config.apiKey, this.config.password, this.sessionId]);
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async rawRequest(url: string, init: RequestInit): Promise<Response> {
    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      let response: Response;
      try {
        response = await this.fetchImpl(url, { ...init, signal: controller.signal });
      } catch (error) {
        clearTimeout(timeout);
        if (attempt < this.maxRetries && (error instanceof Error && error.name === "AbortError")) {
          continue;
        }
        throw new Error(this.redact(`ZIA request failed: ${errorMessage(error)}`));
      }
      clearTimeout(timeout);
      if (isRetryableStatus(response.status) && attempt < this.maxRetries) {
        await sleep(retryDelayMs(response, attempt));
        continue;
      }
      return response;
    }
  }

  private async login(): Promise<string> {
    const timestamp = String(this.now().getTime());
    const response = await this.rawRequest(this.buildUrl("/authenticatedSession"), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        apiKey: obfuscateZiaApiKey(this.config.apiKey, timestamp),
        username: this.config.username,
        password: this.config.password,
        timestamp,
      }),
    });
    const rawText = await response.text();
    if (!response.ok) {
      const detail = errorDetail(parseJsonText(rawText), rawText);
      throw new ZscalerApiError("zia", response.status, this.redact(`ZIA login failed (${response.status})${detail ? `: ${detail}` : ""}`));
    }
    const sessionId = extractSessionCookie(response);
    if (!sessionId) {
      throw new ZscalerApiError("zia", response.status, "ZIA login response did not include a JSESSIONID cookie.");
    }
    this.sessionId = sessionId;
    return sessionId;
  }

  private async getSession(): Promise<string> {
    if (this.sessionId) return this.sessionId;
    if (!this.loginPromise) {
      this.loginPromise = this.login();
    }
    try {
      return await this.loginPromise;
    } finally {
      this.loginPromise = undefined;
    }
  }

  private async request(method: "GET" | "DELETE", path: string, query: JsonRecord = {}): Promise<unknown> {
    const sessionId = await this.getSession();
    const response = await this.rawRequest(this.buildUrl(path, query), {
      method,
      headers: { accept: "application/json", cookie: `JSESSIONID=${sessionId}` },
    });
    const rawText = await response.text();
    const payload = parseJsonText(rawText);
    if (!response.ok) {
      const detail = errorDetail(payload, rawText);
      throw new ZscalerApiError("zia", response.status, this.redact(`ZIA ${method} ${path} failed (${response.status})${detail ? `: ${detail}` : ""}`));
    }
    return payload;
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    return asObject(await this.request("GET", path, query)) ?? {};
  }

  async getList(path: string, query: JsonRecord = {}): Promise<JsonRecord[]> {
    return asRecordArray(await this.request("GET", path, query));
  }

  // Offset paging for the ZIA endpoints whose reference documents page and pageSize. The requested
  // pageSize is the documented maximum (1000) or, where the reference states no maximum, the documented
  // default, so a short page is a reliable end-of-list signal and a full final page costs one extra call.
  async getPaged(path: string, query: JsonRecord = {}, pageSize = ZIA_PAGE_SIZE): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let page = 1;
    for (; page <= ZIA_MAX_PAGES; page += 1) {
      const pageItems = await this.getList(path, { ...query, page, pageSize });
      items.push(...pageItems);
      if (pageItems.length < pageSize) {
        return { items, truncated: false, pagesFetched: page };
      }
    }
    return { items, truncated: true, pagesFetched: ZIA_MAX_PAGES };
  }

  async logout(): Promise<void> {
    if (!this.sessionId) return;
    try {
      await this.request("DELETE", "/authenticatedSession");
    } catch {
      // A failed logout only shortens the server-side session; nothing else depends on it.
    } finally {
      this.sessionId = undefined;
    }
  }

  listAdminUsers(): Promise<PagedList> {
    return this.getPaged("/adminUsers", { includeAuditorUsers: true, includeAdminUsers: true });
  }

  listAdminRoles(): Promise<JsonRecord[]> {
    return this.getList("/adminRoles/lite", { includeAuditorRole: true, includePartnerRole: true, includeApiRole: true });
  }

  getAuthSettings(): Promise<JsonRecord> {
    return this.get("/authSettings");
  }

  getPasswordExpirySettings(): Promise<JsonRecord> {
    return this.get("/passwordExpiry/settings");
  }

  // The reference marks statusId as a required query parameter on GET /auditlogEntryReport but documents no
  // value for it; it refers to an export task that POST /auditlogEntryReport creates, which this read-only
  // inspector never issues. zscaler-sdk-go (adminauditlogs.GetAll) and zscaler-sdk-python (audit_logs.get_status)
  // both send the bare GET, so the same request is sent here and a 400 is reported as unreadable, never pass.
  getAuditLogReportStatus(): Promise<JsonRecord> {
    return this.get("/auditlogEntryReport");
  }

  listNssFeeds(): Promise<JsonRecord[]> {
    return this.getList("/nssFeeds");
  }

  listUrlFilteringRules(): Promise<PagedList> {
    return this.getPaged("/urlFilteringRules", {}, ZIA_URL_RULE_PAGE_SIZE);
  }

  listFirewallFilteringRules(): Promise<PagedList> {
    return this.getPaged("/firewallFilteringRules", {}, ZIA_FIREWALL_RULE_PAGE_SIZE);
  }

  listFirewallDnsRules(): Promise<JsonRecord[]> {
    return this.getList("/firewallDnsRules");
  }

  listDlpEngines(): Promise<JsonRecord[]> {
    return this.getList("/dlpEngines");
  }

  listDlpDictionaries(): Promise<JsonRecord[]> {
    return this.getList("/dlpDictionaries");
  }

  listWebDlpRules(): Promise<JsonRecord[]> {
    return this.getList("/webDlpRules");
  }

  listSslInspectionRules(): Promise<JsonRecord[]> {
    return this.getList("/sslInspectionRules");
  }

  getSslExemptedUrls(): Promise<JsonRecord> {
    return this.get("/sslSettings/exemptedUrls");
  }

  listSandboxRules(): Promise<JsonRecord[]> {
    return this.getList("/sandboxRules");
  }

  getSandboxAdvancedSettings(): Promise<JsonRecord> {
    return this.get("/behavioralAnalysisAdvancedSettings");
  }

  getAdvancedThreatSettings(): Promise<JsonRecord> {
    return this.get("/cyberThreatProtection/advancedThreatSettings");
  }

  getMalwarePolicy(): Promise<JsonRecord> {
    return this.get("/cyberThreatProtection/malwarePolicy");
  }

  getMalwareSettings(): Promise<JsonRecord> {
    return this.get("/cyberThreatProtection/malwareSettings");
  }

  getSecurityAllowlist(): Promise<JsonRecord> {
    return this.get("/security");
  }

  getSecurityDenylist(): Promise<JsonRecord> {
    return this.get("/security/advanced");
  }

  listLocations(): Promise<PagedList> {
    return this.getPaged("/locations");
  }

  listSubLocations(locationId: string): Promise<JsonRecord[]> {
    return this.getList(`/locations/${encodeURIComponent(locationId)}/sublocations`);
  }

  listGreTunnels(): Promise<PagedList> {
    return this.getPaged("/greTunnels");
  }

  // includeOnlyWithoutLocation defaults to true in the reference, which would hide every credential bound
  // to a location, so it is sent explicitly as false to read the whole inventory.
  listVpnCredentials(): Promise<PagedList> {
    return this.getPaged("/vpnCredentials", { includeOnlyWithoutLocation: false });
  }

  listBandwidthControlRules(): Promise<JsonRecord[]> {
    return this.getList("/bandwidthControlRules");
  }

  listBrowserIsolationProfiles(): Promise<JsonRecord[]> {
    return this.getList("/browserIsolation/profiles");
  }

  async listCloudAppRuleTypes(): Promise<string[]> {
    const payload = await this.request("GET", "/webApplicationRules/ruleTypeMapping");
    const object = asObject(payload);
    if (object) return Object.keys(object);
    return asStringList(payload);
  }

  listCloudAppRules(ruleType: string): Promise<JsonRecord[]> {
    return this.getList(`/webApplicationRules/${encodeURIComponent(ruleType)}`);
  }
}

async function collect<T>(product: ZscalerProduct, loader: () => Promise<T>, fallback: T): Promise<CollectedDataset<T>> {
  try {
    return { data: await loader() };
  } catch (error) {
    return {
      data: fallback,
      error: errorMessage(error),
      statusCode: error instanceof ZscalerApiError && error.product === product ? error.status : undefined,
    };
  }
}

async function collectPaged(product: ZscalerProduct, loader: () => Promise<PagedList>): Promise<CollectedDataset<JsonRecord[]>> {
  const collected = await collect(product, loader, { items: [], truncated: false, pagesFetched: 0 } satisfies PagedList);
  return {
    data: collected.data.items,
    error: collected.error,
    statusCode: collected.statusCode,
    truncated: collected.data.truncated,
    seen: collected.data.pagesFetched,
    total: collected.data.totalPages,
  };
}

function datasetErrors(label: string, dataset: CollectedDataset<unknown>): string[] {
  return dataset.error ? [`${label}: ${dataset.error}`] : [];
}

function readExtent(dataset: CollectedDataset<unknown>, unit: string): string {
  const seen = dataset.seen ?? 0;
  return dataset.total !== undefined
    ? `only ${seen} of ${dataset.total} ${unit} were read`
    : `only ${seen} ${unit} were read and the total is unknown`;
}

function datasetTruncations(label: string, dataset: CollectedDataset<unknown>, unit = "pages"): string[] {
  if (!dataset.truncated) return [];
  return [`${label}: ${readExtent(dataset, unit)}, so the inventory is partial and absence of a record cannot support a pass`];
}

function unreadableReason(dataset: CollectedDataset<unknown>): string {
  if (dataset.statusCode === 401 || dataset.statusCode === 403) {
    return `the API returned ${dataset.statusCode} (credential lacks read access to this surface)`;
  }
  return `the read failed (${dataset.error ?? "unknown error"})`;
}

function finding(
  controlNumber: number,
  status: ZscalerFindingStatus,
  summary: string,
  evidence?: JsonRecord,
  manualEvidence?: string,
): ZscalerFinding {
  const definition = ZSCALER_CONTROLS[controlNumber];
  return {
    id: findingId(controlNumber),
    control: controlNumber,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: mappingsForControl(controlNumber),
    manualEvidence,
  };
}

function unreadableFinding(controlNumber: number, label: string, dataset: CollectedDataset<unknown>, manualEvidence: string): ZscalerFinding {
  return finding(
    controlNumber,
    "manual",
    `Verdict unknown: ${label} could not be read because ${unreadableReason(dataset)}. ${manualEvidence}`,
    { status_code: dataset.statusCode ?? null, error: dataset.error ?? null },
    manualEvidence,
  );
}

function notConfiguredFinding(controlNumber: number, product: ZscalerProduct, manualEvidence: string): ZscalerFinding {
  const credentials = product === "zpa"
    ? "ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID (and ZPA_CLOUD)"
    : "ZIA_CLOUD, ZIA_API_KEY, ZIA_USERNAME, ZIA_PASSWORD";
  return finding(
    controlNumber,
    "manual",
    `Not configured: ${product.toUpperCase()} credentials were not provided (${credentials}), so this control was not assessed. ${manualEvidence}`,
    { product, configured: false },
    manualEvidence,
  );
}

function partialSuffix(dataset: CollectedDataset<JsonRecord[]>, label: string): string {
  if (!dataset.truncated) return "";
  const extent = dataset.total !== undefined
    ? `${dataset.seen ?? 0} of ${dataset.total} pages`
    : `${dataset.seen ?? 0} pages, total unknown`;
  return ` The ${label} inventory is partial (${dataset.data.length} records over ${extent}), so this verdict is capped at warn.`;
}

function capForPartial(status: ZscalerFindingStatus, dataset: CollectedDataset<JsonRecord[]>): ZscalerFindingStatus {
  if (status === "pass" && dataset.truncated) return "warn";
  return status;
}

function capForPartialAll(status: ZscalerFindingStatus, datasets: CollectedDataset<JsonRecord[]>[]): ZscalerFindingStatus {
  return status === "pass" && datasets.some((dataset) => dataset.truncated) ? "warn" : status;
}

interface InventoryDependency {
  inventory: string;
  endpoint: string;
  dataset: CollectedDataset<unknown>;
}

function dependsOn(inventory: string, endpoint: string, dataset: CollectedDataset<unknown>): InventoryDependency {
  return { inventory, endpoint, dataset };
}

function unreadableCause({ endpoint, dataset }: InventoryDependency): string {
  return dataset.statusCode !== undefined
    ? `${endpoint} returned ${dataset.statusCode}`
    : `${endpoint} failed: ${dataset.error ?? "unknown error"}`;
}

function capForUnreadableAll(item: ZscalerFinding, dependencies: InventoryDependency[], manualEvidence: string): ZscalerFinding {
  const unreadable = dependencies.filter((dependency) => dependency.dataset.error !== undefined);
  const evidence: JsonRecord = {
    ...(item.evidence ?? {}),
    unreadable_inventories: unreadable.map((dependency) => ({
      inventory: dependency.inventory,
      endpoint: dependency.endpoint,
      status_code: dependency.dataset.statusCode ?? null,
      error: dependency.dataset.error ?? null,
    })),
  };
  if (unreadable.length === 0) return { ...item, evidence };
  const status: ZscalerFindingStatus = item.status === "pass" ? "warn" : item.status;
  const causes = unreadable.map((dependency) => `${dependency.inventory} inventory could not be read (${unreadableCause(dependency)})`);
  const consequence = status === "warn" ? ", so this verdict is capped at warn" : "";
  return {
    ...item,
    status,
    summary: `${item.summary} The ${causes.join(" and the ")}${consequence}.`,
    evidence,
    manualEvidence: item.manualEvidence ?? manualEvidence,
  };
}

function isEnabledState(record: JsonRecord): boolean {
  return asString(record.state)?.toUpperCase() === "ENABLED";
}

function ruleLabel(record: JsonRecord): string {
  return asString(record.name) ?? asString(record.id) ?? "unnamed";
}

export interface ZiaAccessControlData {
  adminUsers: CollectedDataset<JsonRecord[]>;
  adminRoles: CollectedDataset<JsonRecord[]>;
  authSettings: CollectedDataset<JsonRecord>;
  passwordExpiry: CollectedDataset<JsonRecord>;
  auditLogReport: CollectedDataset<JsonRecord>;
  nssFeeds: CollectedDataset<JsonRecord[]>;
}

export async function collectZiaAccessControlData(client: ZiaReadClient): Promise<ZiaAccessControlData> {
  return {
    adminUsers: await collectPaged("zia", () => client.listAdminUsers()),
    adminRoles: await collect("zia", () => client.listAdminRoles(), []),
    authSettings: await collect("zia", () => client.getAuthSettings(), {}),
    passwordExpiry: await collect("zia", () => client.getPasswordExpirySettings(), {}),
    auditLogReport: await collect("zia", () => client.getAuditLogReportStatus(), {}),
    nssFeeds: await collect("zia", () => client.listNssFeeds(), []),
  };
}

function adminLabel(admin: JsonRecord): string {
  return asString(admin.loginName) ?? asString(admin.userName) ?? asString(admin.email) ?? asString(admin.id) ?? "admin";
}

function adminRoleName(admin: JsonRecord): string {
  return asString(asObject(admin.role)?.name) ?? "unknown";
}

function isSuperAdminRole(role: JsonRecord): boolean {
  return /super/i.test(asString(role.name) ?? "");
}

type AdminScopeSource = "adminScope.Type" | "adminScopeType" | "absent";

// The reference documents adminScope as an object whose Type attribute carries the scope enum (ORGANIZATION,
// DEPARTMENT, LOCATION, LOCATION_GROUP, ZDX_APP, USER_GROUP) and warns that the attribute name is subject to
// change. The flattened adminScopeType key exists only in zscaler-sdk-go (adminusers.go) and is read as legacy
// evidence; an admin with neither is reported as unscoped-unknown rather than assumed organization-wide.
function adminScopeType(admin: JsonRecord): { type?: string; source: AdminScopeSource } {
  const scope = asObject(admin.adminScope);
  const documented = asString(scope?.Type) ?? asString(scope?.type);
  if (documented) return { type: documented.toUpperCase(), source: "adminScope.Type" };
  const legacy = asString(admin.adminScopeType);
  if (legacy) return { type: legacy.toUpperCase(), source: "adminScopeType" };
  return { source: "absent" };
}

const AUDIT_REPORT_STATUS_ID_NOTE = "the published reference marks statusId as a required query parameter that names an export task created by POST /auditlogEntryReport, which this read-only inspector never issues, and both zscaler-sdk-go and zscaler-sdk-python send the same bare GET";

export function assessZiaAccessControlData(
  data: ZiaAccessControlData,
  options: { maxSuperAdmins?: number } = {},
): ZscalerAssessmentResult {
  const maxSuperAdmins = clampNumber(options.maxSuperAdmins, DEFAULT_MAX_SUPER_ADMINS, 0, 500);
  const verdicts: ZscalerFinding[] = [];
  const admins = data.adminUsers.data;
  const enabledAdmins = admins.filter((admin) => asBoolean(admin.disabled) !== true);
  const passwordLoginAdmins = enabledAdmins.filter((admin) => asBoolean(admin.isPasswordLoginAllowed) === true);
  const samlEnabled = asBoolean(data.authSettings.data.samlEnabled);

  const mfaEvidence = "Collect a screenshot of Administration > Administrator Management showing the administrator authentication settings (SAML SSO for administrators and enforced multi-factor authentication), since the ZIA API does not expose per-administrator MFA state.";
  if (data.adminUsers.error) {
    verdicts.push(unreadableFinding(6, "GET /adminUsers", data.adminUsers, mfaEvidence));
  } else if (admins.length === 0) {
    verdicts.push(finding(6, "manual", `Empty inventory: GET /adminUsers returned zero administrators, which is not possible for a live tenant, so the credential is probably scoped. ${mfaEvidence}`, { admin_count: 0 }, mfaEvidence));
  } else {
    const summary = passwordLoginAdmins.length > 0
      ? `${passwordLoginAdmins.length} of ${enabledAdmins.length} enabled administrators allow password login (isPasswordLoginAllowed=true), a local sign-in path that bypasses IdP MFA. Per-admin MFA is not exposed by the API, so the verdict is capped at warn.`
      : `All ${enabledAdmins.length} enabled administrators have password login disabled (SSO only). Per-admin MFA is not exposed by the API, so this remains manual until portal evidence is attached.`;
    verdicts.push(finding(6, passwordLoginAdmins.length > 0 ? "warn" : "manual", summary + partialSuffix(data.adminUsers, "administrator"), {
      enabled_admins: enabledAdmins.length,
      password_login_admins: truncateList(passwordLoginAdmins.map(adminLabel)),
      end_user_saml_enabled: samlEnabled ?? null,
      partial_inventory: data.adminUsers.truncated === true,
    }, mfaEvidence));
  }

  const rbacEvidence = "Export Administration > Role Management and Administrator Management, confirm each administrator maps to a least-privilege role, and list Cloud Service API keys with their owners (the API key inventory is not part of the verified read surface).";
  if (data.adminUsers.error) {
    verdicts.push(unreadableFinding(7, "GET /adminUsers", data.adminUsers, rbacEvidence));
  } else if (data.adminRoles.error) {
    verdicts.push(unreadableFinding(7, "GET /adminRoles/lite", data.adminRoles, rbacEvidence));
  } else if (admins.length === 0 || data.adminRoles.data.length === 0) {
    verdicts.push(finding(7, "manual", `Empty inventory: ${admins.length} administrators and ${data.adminRoles.data.length} roles were returned, so the role assignment picture is incomplete. ${rbacEvidence}`, { admin_count: admins.length, role_count: data.adminRoles.data.length }, rbacEvidence));
  } else {
    const superRoleIds = new Set(data.adminRoles.data.filter(isSuperAdminRole).map((role) => asString(role.id)).filter((id): id is string => Boolean(id)));
    const superAdmins = enabledAdmins.filter((admin) => {
      const roleId = asString(asObject(admin.role)?.id);
      return (roleId !== undefined && superRoleIds.has(roleId)) || /super/i.test(adminRoleName(admin));
    });
    const scopes = enabledAdmins.map(adminScopeType);
    const unscopedAdmins = scopes.filter((scope) => scope.type === "ORGANIZATION");
    const scopeUnknown = scopes.filter((scope) => scope.type === undefined);
    const legacyScopeField = scopes.filter((scope) => scope.source === "adminScopeType");
    const scopeNote = scopeUnknown.length > 0 ? ` (${scopeUnknown.length} returned no adminScope and are not counted as scoped)` : "";
    const disabledAdmins = admins.length - enabledAdmins.length;
    let status: ZscalerFindingStatus = "pass";
    let summary = `${superAdmins.length} of ${enabledAdmins.length} enabled administrators hold a Super Admin role (threshold ${maxSuperAdmins}); ${unscopedAdmins.length} are organization-scoped${scopeNote}.`;
    if (superRoleIds.size === 0) {
      status = "warn";
      summary = `No role returned by GET /adminRoles/lite was identifiable as Super Admin, so privilege concentration could not be measured across ${enabledAdmins.length} enabled administrators.`;
    } else if (superAdmins.length > maxSuperAdmins) {
      status = "fail";
      summary = `${superAdmins.length} enabled administrators hold a Super Admin role, above the threshold of ${maxSuperAdmins}.`;
    } else if (superAdmins.length === enabledAdmins.length) {
      status = "warn";
      summary = `Every one of the ${enabledAdmins.length} enabled administrators holds a Super Admin role; no least-privilege roles are in use.`;
    }
    verdicts.push(finding(7, capForPartial(status, data.adminUsers), summary + partialSuffix(data.adminUsers, "administrator"), {
      enabled_admins: enabledAdmins.length,
      disabled_admins: disabledAdmins,
      super_admins: truncateList(superAdmins.map(adminLabel)),
      roles: truncateList(data.adminRoles.data.map((role) => ({ name: asString(role.name) ?? null, roleType: asString(role.roleType) ?? null }))),
      organization_scoped_admins: unscopedAdmins.length,
      admins_without_scope: scopeUnknown.length,
      admins_scoped_via_legacy_field: legacyScopeField.length,
      admin_scope_field_source: "adminScope.Type per the published reference; adminScopeType is accepted only as zscaler-sdk-go legacy evidence",
      password_expiration_enabled: asBoolean(data.passwordExpiry.data.passwordExpirationEnabled) ?? null,
      password_expiry_days: asNumber(data.passwordExpiry.data.passwordExpiryDays) ?? null,
      partial_inventory: data.adminUsers.truncated === true,
    }));
  }

  const auditEvidence = "Confirm in Analytics > Insights > Audit Logs that administrator actions are recorded, and document the NSS or Cloud NSS feed (Administration > Nanolog Streaming Service) that exports admin audit logs plus the SIEM retention period.";
  if (data.auditLogReport.statusCode === 400) {
    verdicts.push(finding(14, "manual", `Verdict unknown: GET /auditlogEntryReport returned 400 (${data.auditLogReport.error ?? "bad request"}); ${AUDIT_REPORT_STATUS_ID_NOTE}. The tenant enforces the documented statusId requirement, so audit log reachability cannot be verified through the API. ${auditEvidence}`, {
      status_code: 400,
      error: data.auditLogReport.error ?? null,
      documented_request_shape: "GET /auditlogEntryReport?statusId={export task id}",
      request_sent: "GET /auditlogEntryReport (bare, matching zscaler-sdk-go and zscaler-sdk-python)",
      nss_feeds: data.nssFeeds.error ? null : data.nssFeeds.data.length,
    }, auditEvidence));
  } else if (data.auditLogReport.error) {
    verdicts.push(unreadableFinding(14, "GET /auditlogEntryReport", data.auditLogReport, auditEvidence));
  } else {
    const feeds = data.nssFeeds.data;
    const enabledFeeds = feeds.filter((feed) => (asString(feed.feedStatus) ?? "").toUpperCase() === "ENABLED");
    const adminAuditFeeds = enabledFeeds.filter((feed) => /ADMIN_AUDIT|AUDIT/i.test(asString(feed.nssLogType) ?? ""));
    if (data.nssFeeds.error) {
      verdicts.push(finding(14, "manual", `The audit log report interface is reachable (GET /auditlogEntryReport status ${asString(data.auditLogReport.data.status) ?? "unknown"}), but the NSS feed inventory could not be read, so log export configuration is unverified. ${auditEvidence}`, { audit_report_status: asString(data.auditLogReport.data.status) ?? null }, auditEvidence));
    } else if (adminAuditFeeds.length > 0) {
      verdicts.push(finding(14, "pass", `Admin audit logging is reachable and ${adminAuditFeeds.length} enabled NSS feed(s) export admin audit logs (${adminAuditFeeds.map(ruleLabel).join(", ")}). Retention is enforced by the receiving SIEM and must be documented separately.`, {
        audit_report_status: asString(data.auditLogReport.data.status) ?? null,
        nss_feeds: feeds.length,
        enabled_feeds: enabledFeeds.length,
        admin_audit_feeds: truncateList(adminAuditFeeds.map((feed) => ({ name: ruleLabel(feed), nssLogType: asString(feed.nssLogType) ?? null, feedStatus: asString(feed.feedStatus) ?? null }))),
      }));
    } else {
      verdicts.push(finding(14, feeds.length === 0 ? "warn" : "fail", feeds.length === 0
        ? "Admin audit logging is reachable, but zero NSS feeds are configured, so audit logs are only retained inside the Zscaler portal window and are not exported for long-term retention."
        : `${feeds.length} NSS feed(s) exist but none that is enabled exports admin audit logs (nssLogType ADMIN_AUDIT).`, {
        audit_report_status: asString(data.auditLogReport.data.status) ?? null,
        nss_feeds: truncateList(feeds.map((feed) => ({ name: ruleLabel(feed), nssLogType: asString(feed.nssLogType) ?? null, feedStatus: asString(feed.feedStatus) ?? null }))),
      }, auditEvidence));
    }
  }

  const secondaryInventories: Partial<Record<number, [InventoryDependency[], string]>> = {
    6: [[dependsOn("authentication settings", "GET /authSettings", data.authSettings)], mfaEvidence],
    7: [[dependsOn("password expiry settings", "GET /passwordExpiry/settings", data.passwordExpiry)], rbacEvidence],
    14: [[dependsOn("NSS feed", "GET /nssFeeds", data.nssFeeds)], auditEvidence],
  };
  const findings = verdicts.map((item) => {
    const entry = secondaryInventories[item.control];
    return entry ? capForUnreadableAll(item, entry[0], entry[1]) : item;
  });

  const errors = [
    ...datasetErrors("adminUsers", data.adminUsers),
    ...datasetErrors("adminRoles", data.adminRoles),
    ...datasetErrors("authSettings", data.authSettings),
    ...datasetErrors("passwordExpiry", data.passwordExpiry),
    ...datasetErrors("auditlogEntryReport", data.auditLogReport),
    ...datasetErrors("nssFeeds", data.nssFeeds),
  ];
  return {
    title: "Zscaler ZIA administrative access control",
    area: "zia_access_control",
    summary: {
      admin_count: admins.length,
      enabled_admins: enabledAdmins.length,
      password_login_admins: passwordLoginAdmins.length,
      admin_roles: data.adminRoles.data.length,
      end_user_saml_enabled: samlEnabled ?? null,
      nss_feeds: data.nssFeeds.data.length,
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors,
    truncated: datasetTruncations("adminUsers", data.adminUsers),
  };
}

export async function assessZiaAccessControl(
  client: ZiaReadClient | undefined,
  options: { maxSuperAdmins?: number } = {},
): Promise<ZscalerAssessmentResult> {
  if (!client) {
    return notConfiguredAssessment("zia_access_control", "Zscaler ZIA administrative access control", "zia", [6, 7, 14]);
  }
  return assessZiaAccessControlData(await collectZiaAccessControlData(client), options);
}

function notConfiguredAssessment(area: ZscalerArea, title: string, product: ZscalerProduct, controls: number[]): ZscalerAssessmentResult {
  const findings = controls.map((controlNumber) => notConfiguredFinding(controlNumber, product, `Provide ${product.toUpperCase()} credentials and rerun, or attach portal evidence for ${ZSCALER_CONTROLS[controlNumber].title}.`));
  return {
    title,
    area,
    summary: { product, configured: false, status_counts: summarizeFindingStatuses(findings) },
    findings,
    errors: [],
    truncated: [],
  };
}

export function summarizeFindingStatuses(findings: ZscalerFinding[]): Record<ZscalerFindingStatus, number> {
  const counts: Record<ZscalerFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function statusLabel(status: ZscalerFindingStatus): string {
  switch (status) {
    case "pass":
      return "PASS";
    case "warn":
      return "WARN";
    case "fail":
      return "FAIL";
    case "manual":
      return "MANUAL";
    default: {
      const exhaustive: never = status;
      throw new Error(`Unhandled status: ${String(exhaustive)}`);
    }
  }
}

function severityRank(severity: ZscalerSeverity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default: {
      const exhaustive: never = severity;
      throw new Error(`Unhandled severity: ${String(exhaustive)}`);
    }
  }
}

async function readableSurface(
  product: ZscalerProduct,
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
): Promise<ZscalerAccessSurface> {
  try {
    const value = await load();
    const count = Array.isArray(value)
      ? value.length
      : asObject(value) && Array.isArray(asObject(value)?.items)
        ? asArray(asObject(value)?.items).length
        : undefined;
    return { product, name, endpoint, status: "readable", count };
  } catch (error) {
    return {
      product,
      name,
      endpoint,
      status: "not_readable",
      statusCode: error instanceof ZscalerApiError ? error.status : undefined,
      error: errorMessage(error),
    };
  }
}

export interface ZscalerClients {
  config: ZscalerResolvedConfig;
  zia?: ZiaReadClient;
  zpa?: ZpaReadClient;
}

export async function checkZscalerAccess(clients: ZscalerClients): Promise<ZscalerAccessCheckResult> {
  const surfaces: ZscalerAccessSurface[] = [];
  const notes: string[] = [];
  if (clients.zia) {
    const zia = clients.zia;
    notes.push(`ZIA cloud ${zia.getResolvedConfig().cloud} at ${zia.getResolvedConfig().baseUrl} (API key plus session login as ${zia.getResolvedConfig().username}).`);
    surfaces.push(
      await readableSurface("zia", "admin_users", "/adminUsers", () => zia.listAdminUsers()),
      await readableSurface("zia", "admin_roles", "/adminRoles/lite", () => zia.listAdminRoles()),
      await readableSurface("zia", "auth_settings", "/authSettings", () => zia.getAuthSettings()),
      await readableSurface("zia", "audit_log_report", "/auditlogEntryReport", () => zia.getAuditLogReportStatus()),
      await readableSurface("zia", "url_filtering_rules", "/urlFilteringRules", () => zia.listUrlFilteringRules()),
      await readableSurface("zia", "firewall_filtering_rules", "/firewallFilteringRules", () => zia.listFirewallFilteringRules()),
      await readableSurface("zia", "dlp_engines", "/dlpEngines", () => zia.listDlpEngines()),
      await readableSurface("zia", "ssl_inspection_rules", "/sslInspectionRules", () => zia.listSslInspectionRules()),
      await readableSurface("zia", "advanced_threat_settings", "/cyberThreatProtection/advancedThreatSettings", () => zia.getAdvancedThreatSettings()),
      await readableSurface("zia", "locations", "/locations", () => zia.listLocations()),
    );
  } else {
    notes.push("ZIA is not configured (ZIA_CLOUD, ZIA_API_KEY, ZIA_USERNAME, ZIA_PASSWORD); ZIA controls will render as manual.");
  }

  if (clients.zpa) {
    const zpa = clients.zpa;
    notes.push(`ZPA cloud ${zpa.getResolvedConfig().cloud} at ${zpa.getResolvedConfig().baseUrl} (client credentials for customer ${zpa.getResolvedConfig().customerId}).`);
    surfaces.push(
      await readableSurface("zpa", "application_segments", "/mgmtconfig/v1/admin/customers/{customerId}/application", () => zpa.listApplicationSegments()),
      await readableSurface("zpa", "segment_groups", "/mgmtconfig/v1/admin/customers/{customerId}/segmentGroup", () => zpa.listSegmentGroups()),
      await readableSurface("zpa", "access_policy_rules", "/mgmtconfig/v1/admin/customers/{customerId}/policySet/rules/policyType/ACCESS_POLICY", () => zpa.listPolicyRules("ACCESS_POLICY")),
      await readableSurface("zpa", "app_connectors", "/mgmtconfig/v1/admin/customers/{customerId}/connector", () => zpa.listAppConnectors()),
      await readableSurface("zpa", "idp_controllers", "/mgmtconfig/v2/admin/customers/{customerId}/idp", () => zpa.listIdpControllers()),
      await readableSurface("zpa", "posture_profiles", "/mgmtconfig/v2/admin/customers/{customerId}/posture", () => zpa.listPostureProfiles()),
      await readableSurface("zpa", "administrators", "/mgmtconfig/v1/admin/customers/{customerId}/administrators", () => zpa.listAdministrators()),
    );
  } else {
    notes.push("ZPA is not configured (ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID, ZPA_CLOUD); ZPA controls will render as manual.");
  }
  if (clients.config.oneApiDetected) {
    notes.push("OneAPI (ZSCALER_CLIENT_ID/ZSCALER_CLIENT_SECRET) credentials were detected but OneAPI OAuth mode is not implemented in this release; legacy ZIA and ZPA credentials are used.");
  }
  if (clients.config.zdxDetected) {
    notes.push("ZDX credentials were detected; ZDX enrichment is not implemented in this release and no control depends on it.");
  }

  const readable = surfaces.filter((surface) => surface.status === "readable").length;
  const status: ZscalerAccessCheckResult["status"] = surfaces.length === 0
    ? "unavailable"
    : readable === surfaces.length
      ? "healthy"
      : "limited";
  notes.push(`${readable}/${surfaces.length} Zscaler audit surfaces are readable.`);

  return {
    status,
    products: {
      zia: clients.zia ? "configured" : "not_configured",
      zpa: clients.zpa ? "configured" : "not_configured",
    },
    surfaces,
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run zscaler_assess_zia_access_control, zscaler_assess_zia_policy, zscaler_assess_zpa, or zscaler_export_audit_bundle."
      : "Grant the ZIA admin a read-capable role for every surface above and the ZPA API client a read role, then rerun zscaler_check_access. Unreadable surfaces produce manual findings, never passes.",
  };
}

function formatAccessCheckText(result: ZscalerAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.product.toUpperCase(),
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Zscaler access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Product", "Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ZscalerAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    statusLabel(item.status),
    item.title,
    item.summary,
  ]);
  const counts = summarizeFindingStatuses(result.findings);
  const summary = Object.entries(result.summary)
    .filter(([key]) => key !== "status_counts")
    .map(([key, value]) => `- ${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
    .join("\n");
  const manualNotes = result.findings
    .filter((item) => item.status === "manual" && item.manualEvidence)
    .map((item) => `- ${item.id}: ${item.manualEvidence}`);
  return [
    result.title,
    "",
    `Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(manualNotes.length > 0 ? ["", "Manual evidence to collect:", ...manualNotes] : []),
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
    ...(result.truncated.length > 0 ? ["", "Partial inventories:", ...result.truncated.map((note) => `- ${note}`)] : []),
  ].join("\n");
}

export type ZpaPolicyType =
  | "ACCESS_POLICY"
  | "TIMEOUT_POLICY"
  | "CLIENT_FORWARDING_POLICY"
  | "ISOLATION_POLICY"
  | "INSPECTION_POLICY";

export interface ZpaReadClient {
  getResolvedConfig(): ZpaResolvedConfig;
  getNow(): Date;
  listApplicationSegments(): Promise<PagedList>;
  listSegmentGroups(): Promise<PagedList>;
  listPolicyRules(policyType: ZpaPolicyType): Promise<PagedList>;
  listAppConnectorGroups(): Promise<PagedList>;
  listAppConnectors(): Promise<PagedList>;
  listServiceEdgeGroups(): Promise<PagedList>;
  listServiceEdges(): Promise<PagedList>;
  listPostureProfiles(): Promise<PagedList>;
  listTrustedNetworks(): Promise<PagedList>;
  listIdpControllers(): Promise<PagedList>;
  listSamlAttributes(): Promise<PagedList>;
  listScimGroups(idpId: string): Promise<PagedList>;
  listEnrollmentCertificates(): Promise<PagedList>;
  listBrowserAccessCertificates(): Promise<PagedList>;
  listEmergencyAccessUsers(): Promise<PagedList>;
  listAdministrators(): Promise<PagedList>;
}

export class ZpaApiClient implements ZpaReadClient {
  private readonly config: ZpaResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly now: () => Date;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private tokenPromise?: Promise<string>;

  constructor(
    config: ZpaResolvedConfig,
    options: { fetchImpl?: FetchImpl; timeoutMs?: number; maxRetries?: number; now?: () => Date } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): ZpaResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private redact(message: string): string {
    return redactSecrets(message, [this.config.clientSecret, this.accessToken]);
  }

  private async rawRequest(url: string, init: RequestInit): Promise<Response> {
    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      let response: Response;
      try {
        response = await this.fetchImpl(url, { ...init, signal: controller.signal });
      } catch (error) {
        clearTimeout(timeout);
        if (attempt < this.maxRetries && (error instanceof Error && error.name === "AbortError")) {
          continue;
        }
        throw new Error(this.redact(`ZPA request failed: ${errorMessage(error)}`));
      }
      clearTimeout(timeout);
      if (isRetryableStatus(response.status) && attempt < this.maxRetries) {
        await sleep(retryDelayMs(response, attempt));
        continue;
      }
      return response;
    }
  }

  private async signIn(): Promise<string> {
    const body = new URLSearchParams({ client_id: this.config.clientId, client_secret: this.config.clientSecret });
    const response = await this.rawRequest(`${this.config.baseUrl}/signin`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
    });
    const rawText = await response.text();
    const payload = asObject(parseJsonText(rawText)) ?? {};
    if (!response.ok) {
      const detail = errorDetail(payload, rawText);
      throw new ZscalerApiError("zpa", response.status, this.redact(`ZPA signin failed (${response.status})${detail ? `: ${detail}` : ""}`));
    }
    const token = asString(payload.access_token);
    if (!token) {
      throw new ZscalerApiError("zpa", response.status, "ZPA signin response did not include access_token.");
    }
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.accessToken = token;
    this.accessTokenExpiresAt = this.now().getTime() + Math.max((expiresIn - 60) * 1000, 60_000);
    return token;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && this.now().getTime() < this.accessTokenExpiresAt) return this.accessToken;
    if (!this.tokenPromise) {
      this.tokenPromise = this.signIn();
    }
    try {
      return await this.tokenPromise;
    } finally {
      this.tokenPromise = undefined;
    }
  }

  private customerPath(version: "v1" | "v2", path: string): string {
    return `/mgmtconfig/${version}/admin/customers/${encodeURIComponent(this.config.customerId)}${path}`;
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    const token = await this.getAccessToken();
    const url = new URL(`${this.config.baseUrl}${path}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    const response = await this.rawRequest(url.toString(), {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${token}` },
    });
    const rawText = await response.text();
    const payload = parseJsonText(rawText);
    if (!response.ok) {
      const detail = errorDetail(payload, rawText);
      throw new ZscalerApiError("zpa", response.status, this.redact(`ZPA GET ${path} failed (${response.status})${detail ? `: ${detail}` : ""}`));
    }
    return payload;
  }

  // Offset paging for the ZPA list endpoints documented with page and pagesize and a list/totalPages wrapper.
  // A response without totalPages (a bare array or a wrapper that omits it) leaves the total unknown: paging
  // continues while pages are full and a page identical to the previous one means the server stopped
  // advancing, so the read is reported truncated with no total rather than as a complete single page.
  async getPaged(path: string, query: JsonRecord = {}): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let previousSignature: string | undefined;
    let totalPages: number | undefined;
    for (let page = 1; page <= ZPA_MAX_PAGES; page += 1) {
      const payload = await this.get(path, { ...query, page, pagesize: ZPA_PAGE_SIZE });
      const wrapper = Array.isArray(payload) ? undefined : asObject(payload);
      const pageItems = asRecordArray(Array.isArray(payload) ? payload : wrapper?.list);
      totalPages = wrapper ? asNumber(wrapper.totalPages) : undefined;
      const signature = pageSignature(pageItems);
      if (page > 1 && pageItems.length > 0 && signature === previousSignature) {
        return { items, truncated: true, pagesFetched: page };
      }
      previousSignature = signature;
      items.push(...pageItems);
      if (totalPages !== undefined) {
        if (page >= totalPages) return { items, truncated: false, pagesFetched: page, totalPages };
      } else if (pageItems.length < ZPA_PAGE_SIZE) {
        return { items, truncated: false, pagesFetched: page };
      }
    }
    return { items, truncated: true, pagesFetched: ZPA_MAX_PAGES, totalPages };
  }

  // Cursor paging for GET /emergencyAccess/users, the one ZPA surface documented with pageId and pageSize
  // query parameters and an items/nextPage wrapper instead of list/totalPages. An absent nextPage is the end of
  // the list; a cursor that repeats or cycles means the server stopped advancing and the total is unknown.
  async getCursorPaged(path: string, query: JsonRecord = {}, idKeys: string[] = ["id"]): Promise<PagedList> {
    const items: JsonRecord[] = [];
    const seen = new Set<string>();
    const cursors = new Set<string>();
    let pageId: string | undefined;
    for (let page = 1; page <= ZPA_MAX_PAGES; page += 1) {
      const object = asObject(await this.get(path, { ...query, pageSize: ZPA_PAGE_SIZE, pageId })) ?? {};
      for (const item of asRecordArray(object.items)) {
        const key = idKeys.map((idKey) => asString(item[idKey])).find((value) => value !== undefined) ?? JSON.stringify(item);
        if (seen.has(key)) continue;
        seen.add(key);
        items.push(item);
      }
      const nextPage = asString(object.nextPage);
      if (!nextPage) {
        return { items, truncated: false, pagesFetched: page };
      }
      if (nextPage === pageId || cursors.has(nextPage)) {
        return { items, truncated: true, pagesFetched: page };
      }
      cursors.add(nextPage);
      pageId = nextPage;
    }
    return { items, truncated: true, pagesFetched: ZPA_MAX_PAGES };
  }

  listApplicationSegments(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/application"));
  }

  listSegmentGroups(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/segmentGroup"));
  }

  listPolicyRules(policyType: ZpaPolicyType): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", `/policySet/rules/policyType/${policyType}`));
  }

  listAppConnectorGroups(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/appConnectorGroup"));
  }

  listAppConnectors(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/connector"));
  }

  listServiceEdgeGroups(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/serviceEdgeGroup"));
  }

  listServiceEdges(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/serviceEdge"));
  }

  listPostureProfiles(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/posture"));
  }

  listTrustedNetworks(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/network"));
  }

  listIdpControllers(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/idp"));
  }

  listSamlAttributes(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/samlAttribute"));
  }

  listScimGroups(idpId: string): Promise<PagedList> {
    return this.getPaged(`/userconfig/v1/customers/${encodeURIComponent(this.config.customerId)}/scimgroup/idpId/${encodeURIComponent(idpId)}`);
  }

  listEnrollmentCertificates(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/enrollmentCert"));
  }

  listBrowserAccessCertificates(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v2", "/clientlessCertificate/issued"));
  }

  listEmergencyAccessUsers(): Promise<PagedList> {
    return this.getCursorPaged(this.customerPath("v1", "/emergencyAccess/users"), {}, ["userId", "emailId"]);
  }

  // GET /administrators is absent from the published ZPA API reference; it is documented only by zscaler-sdk-go
  // (administratorcontroller). Findings that use it say so and never let it carry a pass on its own.
  listAdministrators(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/administrators"));
  }
}

const MAX_SUBLOCATION_PARENTS = 100;
const MAX_CLOUD_APP_RULE_TYPES = 25;
const DEFAULT_MAX_SSL_EXEMPTIONS = 50;
const REQUIRED_URL_BLOCK_CATEGORIES = ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"];
const REQUIRED_ATP_FLAGS = [
  "malwareSitesBlocked",
  "cmdCtlServerBlocked",
  "cmdCtlTrafficBlocked",
  "knownPhishingSitesBlocked",
  "suspectedPhishingSitesBlocked",
  "browserExploitsBlocked",
  "potentialMaliciousRequestsBlocked",
];
const REQUIRED_MALWARE_FLAGS = ["virusBlocked", "trojanBlocked", "wormBlocked", "ransomwareBlocked", "spywareBlocked"];

export interface ZiaPolicyData {
  urlFilteringRules: CollectedDataset<JsonRecord[]>;
  firewallRules: CollectedDataset<JsonRecord[]>;
  dnsRules: CollectedDataset<JsonRecord[]>;
  dlpEngines: CollectedDataset<JsonRecord[]>;
  dlpDictionaries: CollectedDataset<JsonRecord[]>;
  webDlpRules: CollectedDataset<JsonRecord[]>;
  sslInspectionRules: CollectedDataset<JsonRecord[]>;
  sslExemptedUrls: CollectedDataset<JsonRecord>;
  sandboxRules: CollectedDataset<JsonRecord[]>;
  sandboxSettings: CollectedDataset<JsonRecord>;
  advancedThreatSettings: CollectedDataset<JsonRecord>;
  malwarePolicy: CollectedDataset<JsonRecord>;
  malwareSettings: CollectedDataset<JsonRecord>;
  securityAllowlist: CollectedDataset<JsonRecord>;
  securityDenylist: CollectedDataset<JsonRecord>;
  locations: CollectedDataset<JsonRecord[]>;
  subLocations: CollectedDataset<JsonRecord[]>;
  greTunnels: CollectedDataset<JsonRecord[]>;
  vpnCredentials: CollectedDataset<JsonRecord[]>;
  bandwidthRules: CollectedDataset<JsonRecord[]>;
  isolationProfiles: CollectedDataset<JsonRecord[]>;
  cloudAppRules: CollectedDataset<JsonRecord[]>;
}

async function collectSubLocations(client: ZiaReadClient, locations: CollectedDataset<JsonRecord[]>): Promise<CollectedDataset<JsonRecord[]>> {
  if (locations.error) {
    return { data: [], error: `skipped because locations were unreadable: ${locations.error}`, statusCode: locations.statusCode };
  }
  const parents = locations.data.map((location) => asString(location.id)).filter((id): id is string => Boolean(id));
  const items: JsonRecord[] = [];
  const errors: string[] = [];
  for (const parentId of parents.slice(0, MAX_SUBLOCATION_PARENTS)) {
    try {
      items.push(...(await client.listSubLocations(parentId)));
    } catch (error) {
      errors.push(`${parentId}: ${errorMessage(error)}`);
    }
  }
  return {
    data: items,
    error: errors.length > 0 ? errors.slice(0, 5).join("; ") : undefined,
    truncated: parents.length > MAX_SUBLOCATION_PARENTS,
    seen: Math.min(parents.length, MAX_SUBLOCATION_PARENTS),
    total: parents.length,
  };
}

async function collectCloudAppRules(client: ZiaReadClient): Promise<CollectedDataset<JsonRecord[]>> {
  let ruleTypes: string[];
  try {
    ruleTypes = await client.listCloudAppRuleTypes();
  } catch (error) {
    return {
      data: [],
      error: errorMessage(error),
      statusCode: error instanceof ZscalerApiError ? error.status : undefined,
    };
  }
  const items: JsonRecord[] = [];
  const errors: string[] = [];
  for (const ruleType of ruleTypes.slice(0, MAX_CLOUD_APP_RULE_TYPES)) {
    try {
      for (const rule of await client.listCloudAppRules(ruleType)) {
        items.push({ ...rule, ruleType });
      }
    } catch (error) {
      errors.push(`${ruleType}: ${errorMessage(error)}`);
    }
  }
  return {
    data: items,
    error: errors.length > 0 ? errors.slice(0, 5).join("; ") : undefined,
    truncated: ruleTypes.length > MAX_CLOUD_APP_RULE_TYPES,
    seen: Math.min(ruleTypes.length, MAX_CLOUD_APP_RULE_TYPES),
    total: ruleTypes.length,
  };
}

export async function collectZiaPolicyData(client: ZiaReadClient): Promise<ZiaPolicyData> {
  const locations = await collectPaged("zia", () => client.listLocations());
  return {
    urlFilteringRules: await collectPaged("zia", () => client.listUrlFilteringRules()),
    firewallRules: await collectPaged("zia", () => client.listFirewallFilteringRules()),
    dnsRules: await collect("zia", () => client.listFirewallDnsRules(), []),
    dlpEngines: await collect("zia", () => client.listDlpEngines(), []),
    dlpDictionaries: await collect("zia", () => client.listDlpDictionaries(), []),
    webDlpRules: await collect("zia", () => client.listWebDlpRules(), []),
    sslInspectionRules: await collect("zia", () => client.listSslInspectionRules(), []),
    sslExemptedUrls: await collect("zia", () => client.getSslExemptedUrls(), {}),
    sandboxRules: await collect("zia", () => client.listSandboxRules(), []),
    sandboxSettings: await collect("zia", () => client.getSandboxAdvancedSettings(), {}),
    advancedThreatSettings: await collect("zia", () => client.getAdvancedThreatSettings(), {}),
    malwarePolicy: await collect("zia", () => client.getMalwarePolicy(), {}),
    malwareSettings: await collect("zia", () => client.getMalwareSettings(), {}),
    securityAllowlist: await collect("zia", () => client.getSecurityAllowlist(), {}),
    securityDenylist: await collect("zia", () => client.getSecurityDenylist(), {}),
    locations,
    subLocations: await collectSubLocations(client, locations),
    greTunnels: await collectPaged("zia", () => client.listGreTunnels()),
    vpnCredentials: await collectPaged("zia", () => client.listVpnCredentials()),
    bandwidthRules: await collect("zia", () => client.listBandwidthControlRules(), []),
    isolationProfiles: await collect("zia", () => client.listBrowserIsolationProfiles(), []),
    cloudAppRules: await collectCloudAppRules(client),
  };
}

function enabledRules(rules: JsonRecord[]): JsonRecord[] {
  return rules.filter(isEnabledState);
}

function ruleSummaries(rules: JsonRecord[], actionKey = "action"): Array<{ name: string; action: string | null; state: string | null }> {
  return truncateList(rules.map((rule) => ({
    name: ruleLabel(rule),
    action: asString(rule[actionKey]) ?? asString(asObject(rule[actionKey])?.type) ?? null,
    state: asString(rule.state) ?? null,
  })));
}

function assessUrlFiltering(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > URL & Cloud App Control > URL Filtering Policy and show that anonymizer, security-risk, adult, and gambling categories are blocked by enabled rules.";
  const rules = data.urlFilteringRules;
  if (rules.error) return unreadableFinding(1, "GET /urlFilteringRules", rules, evidenceNote);
  if (rules.data.length === 0) {
    return finding(1, "fail", "Empty inventory: zero URL filtering rules exist, so no web category is blocked and all traffic is implicitly allowed.", { rule_count: 0 }, evidenceNote);
  }
  const active = enabledRules(rules.data);
  const blockRules = active.filter((rule) => (asString(rule.action) ?? "").toUpperCase() === "BLOCK");
  const blockedCategories = new Set(blockRules.flatMap((rule) => asStringList(rule.urlCategories).map((category) => category.toUpperCase())));
  const missing = REQUIRED_URL_BLOCK_CATEGORIES.filter((category) => !blockedCategories.has(category));
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: active.length,
    disabled_rules: rules.data.length - active.length,
    block_rules: blockRules.length,
    blocked_categories: blockedCategories.size,
    missing_required_categories: missing,
    rules: ruleSummaries(rules.data),
    partial_inventory: rules.truncated === true,
  };
  if (active.length === 0) {
    return finding(1, "fail", `${rules.data.length} URL filtering rules exist but every rule has state DISABLED, so nothing is enforced.`, evidence, evidenceNote);
  }
  if (blockRules.length === 0) {
    return finding(1, "fail", `${active.length} enabled URL filtering rules exist but none uses action BLOCK; high-risk categories are not blocked.`, evidence, evidenceNote);
  }
  if (missing.length > 0) {
    return finding(1, "warn", `${blockRules.length} enabled BLOCK rules cover ${blockedCategories.size} categories, but these baseline categories are not blocked: ${missing.join(", ")}.${partialSuffix(rules, "URL filtering rule")}`, evidence, evidenceNote);
  }
  return finding(1, capForPartial("pass", rules), `${blockRules.length} enabled BLOCK rules cover all ${REQUIRED_URL_BLOCK_CATEGORIES.length} baseline high-risk categories across ${blockedCategories.size} blocked categories.${partialSuffix(rules, "URL filtering rule")}`, evidence, rules.truncated ? evidenceNote : undefined);
}

function isUnboundedAllow(rule: JsonRecord): boolean {
  if ((asString(rule.action) ?? "").toUpperCase() !== "ALLOW") return false;
  const scopeKeys = ["nwServices", "nwServiceGroups", "nwApplications", "nwApplicationGroups", "destAddresses", "destCountries", "destIpCategories", "destIpGroups", "srcIps", "srcIpGroups", "locations", "locationGroups", "users", "groups", "departments", "appServices", "appServiceGroups", "labels", "devices", "deviceGroups"];
  return scopeKeys.every((key) => asArray(rule[key]).length === 0);
}

function assessFirewall(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > Firewall Control > Firewall Filtering Policy showing the Default Firewall Filtering Rule action and every rule that allows traffic without destination or service restrictions.";
  const rules = data.firewallRules;
  if (rules.error) return unreadableFinding(2, "GET /firewallFilteringRules", rules, evidenceNote);
  if (rules.data.length === 0) {
    return finding(2, "fail", "Empty inventory: zero firewall filtering rules were returned, so no cloud firewall policy is enforced (a live tenant always returns at least the default rule, so the credential may also be scoped).", { rule_count: 0 }, evidenceNote);
  }
  const active = enabledRules(rules.data);
  const defaultRules = rules.data.filter((rule) => asBoolean(rule.defaultRule) === true);
  const defaultRule = defaultRules[0];
  const defaultAction = defaultRule ? (asString(defaultRule.action) ?? "").toUpperCase() : undefined;
  const unbounded = active.filter((rule) => asBoolean(rule.defaultRule) !== true && isUnboundedAllow(rule));
  // enableFullLogging is not part of the published GET /firewallFilteringRules schema; it is documented only by
  // zscaler-sdk-go (filteringrules.go, EnableFullLogging). It is read as supplementary evidence: an explicit false
  // downgrades the verdict, while an absent field is reported as unevaluated and never counts toward pass.
  const blockRules = active.filter((rule) => (asString(rule.action) ?? "").toUpperCase().startsWith("BLOCK"));
  const blockWithoutLogging = blockRules.filter((rule) => asBoolean(rule.enableFullLogging) === false);
  const blockLoggingUnknown = blockRules.filter((rule) => asBoolean(rule.enableFullLogging) === undefined);
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: active.length,
    default_rule_action: defaultAction ?? null,
    unbounded_allow_rules: truncateList(unbounded.map(ruleLabel)),
    block_rules_without_full_logging: blockWithoutLogging.length,
    block_rules_with_unknown_logging: blockLoggingUnknown.length,
    full_logging_field_source: "enableFullLogging is documented by zscaler-sdk-go only, not by the published response schema",
    rules: ruleSummaries(rules.data),
    partial_inventory: rules.truncated === true,
  };
  if (!defaultRule) {
    return finding(2, "warn", `${rules.data.length} firewall rules were returned but none is flagged defaultRule, so the fallback action is unknown; the inventory may be partial.${partialSuffix(rules, "firewall rule")}`, evidence, evidenceNote);
  }
  if (defaultAction === "ALLOW") {
    return finding(2, "fail", `The Default Firewall Filtering Rule action is ALLOW, so any traffic not matched by ${active.length} enabled rules is permitted.`, evidence, evidenceNote);
  }
  if (unbounded.length > 0) {
    return finding(2, "fail", `${unbounded.length} enabled ALLOW rule(s) have no service, destination, source, or user restriction: ${unbounded.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  if (active.length === defaultRules.length) {
    return finding(2, "warn", `Only the default rule (${defaultAction}) is enabled; no explicit firewall rules define allowed services, so review whether required egress is being blocked or bypassed elsewhere.`, evidence, evidenceNote);
  }
  const loggingNote = blockWithoutLogging.length > 0
    ? `; ${blockWithoutLogging.length} block rule(s) have full logging disabled`
    : blockLoggingUnknown.length > 0
      ? `; block-rule logging was not evaluated for ${blockLoggingUnknown.length} rule(s) because enableFullLogging is absent from the response`
      : "";
  const status: ZscalerFindingStatus = blockWithoutLogging.length > 0 ? "warn" : "pass";
  return finding(2, capForPartial(status, rules), `Default rule action is ${defaultAction}, ${active.length} enabled rules are scoped, and no unbounded allow rules exist${loggingNote}.${partialSuffix(rules, "firewall rule")}`, evidence, status === "warn" || rules.truncated ? evidenceNote : undefined);
}

function assessDlp(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > Data Loss Prevention showing enabled DLP engines, dictionaries, and web DLP rules with their actions.";
  return capForUnreadableAll(dlpVerdict(data, evidenceNote), [dependsOn("DLP dictionary", "GET /dlpDictionaries", data.dlpDictionaries)], evidenceNote);
}

function dlpVerdict(data: ZiaPolicyData, evidenceNote: string): ZscalerFinding {
  if (data.webDlpRules.error) return unreadableFinding(3, "GET /webDlpRules", data.webDlpRules, evidenceNote);
  if (data.dlpEngines.error) return unreadableFinding(3, "GET /dlpEngines", data.dlpEngines, evidenceNote);
  const rules = data.webDlpRules.data;
  const engines = data.dlpEngines.data;
  const active = enabledRules(rules);
  const blocking = active.filter((rule) => ["BLOCK", "ICAP_RESPONSE"].includes((asString(rule.action) ?? "").toUpperCase()));
  const withEngines = blocking.filter((rule) => asArray(rule.dlpEngines).length > 0 || asBoolean(rule.withoutContentInspection) === true);
  const evidence = {
    engine_count: engines.length,
    dictionary_count: data.dlpDictionaries.error ? null : data.dlpDictionaries.data.length,
    rule_count: rules.length,
    enabled_rules: active.length,
    blocking_rules: blocking.length,
    rules: ruleSummaries(rules),
  };
  if (rules.length === 0) {
    return finding(3, "fail", `Empty inventory: zero web DLP rules exist (${engines.length} engines defined), so no data loss prevention is enforced on web traffic.`, evidence, evidenceNote);
  }
  if (engines.length === 0) {
    return finding(3, "fail", `${rules.length} web DLP rules exist but zero DLP engines are defined, so rules cannot match sensitive content.`, evidence, evidenceNote);
  }
  if (active.length === 0) {
    return finding(3, "fail", `${rules.length} web DLP rules exist but all are DISABLED.`, evidence, evidenceNote);
  }
  if (blocking.length === 0) {
    return finding(3, "warn", `${active.length} enabled web DLP rules only monitor (action ALLOW); no rule blocks or quarantines sensitive data.`, evidence, evidenceNote);
  }
  if (withEngines.length === 0) {
    return finding(3, "warn", `${blocking.length} blocking DLP rules reference no DLP engine and do not use withoutContentInspection, so they may never match.`, evidence, evidenceNote);
  }
  return finding(3, "pass", `${engines.length} DLP engines and ${blocking.length} enabled blocking web DLP rules are in force (${active.length} enabled rules total).`, evidence);
}

function assessSslInspection(data: ZiaPolicyData, maxExemptions: number): ZscalerFinding {
  const evidenceNote = "Export Policy > SSL Inspection showing enabled DECRYPT rules, the exempted URL list, and per-location SSL scanning state.";
  return capForUnreadableAll(sslInspectionVerdict(data, maxExemptions, evidenceNote), [
    dependsOn("SSL exemption list", "GET /sslSettings/exemptedUrls", data.sslExemptedUrls),
    dependsOn("location", "GET /locations", data.locations),
  ], evidenceNote);
}

function sslInspectionVerdict(data: ZiaPolicyData, maxExemptions: number, evidenceNote: string): ZscalerFinding {
  const rules = data.sslInspectionRules;
  if (rules.error) return unreadableFinding(4, "GET /sslInspectionRules", rules, evidenceNote);
  const exempted = data.sslExemptedUrls.error ? undefined : asStringList(data.sslExemptedUrls.data.urls);
  const active = enabledRules(rules.data);
  const actionType = (rule: JsonRecord): string => (asString(asObject(rule.action)?.type) ?? asString(rule.action) ?? "").toUpperCase();
  const decrypt = active.filter((rule) => actionType(rule) === "DECRYPT");
  const blanketBypass = active.filter((rule) => actionType(rule) === "DO_NOT_DECRYPT" && asArray(rule.urlCategories).length === 0 && asArray(rule.cloudApplications).length === 0 && asArray(rule.destIpGroups).length === 0 && asArray(rule.locations).length === 0 && asArray(rule.users).length === 0 && asArray(rule.groups).length === 0 && asArray(rule.departments).length === 0);
  const locationsWithoutScan = data.locations.error ? undefined : data.locations.data.filter((location) => asBoolean(location.sslScanEnabled) === false).length;
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: active.length,
    decrypt_rules: decrypt.length,
    blanket_do_not_decrypt_rules: truncateList(blanketBypass.map(ruleLabel)),
    exempted_urls: exempted ? exempted.length : null,
    exempted_urls_readable: exempted !== undefined,
    locations_without_ssl_scan: locationsWithoutScan ?? null,
    location_inventory_partial: data.locations.truncated === true,
    rules: ruleSummaries(rules.data),
  };
  if (rules.data.length === 0) {
    return finding(4, "fail", "Empty inventory: zero SSL inspection rules exist, so encrypted traffic is not decrypted for inspection.", evidence, evidenceNote);
  }
  if (decrypt.length === 0) {
    return finding(4, "fail", `${active.length} enabled SSL inspection rules exist but none has action type DECRYPT.`, evidence, evidenceNote);
  }
  if (blanketBypass.length > 0) {
    return finding(4, "fail", `${blanketBypass.length} enabled DO_NOT_DECRYPT rule(s) apply to all traffic with no category, application, location, or user scope: ${blanketBypass.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  if (exempted === undefined) {
    return finding(4, "warn", `${decrypt.length} enabled DECRYPT rules exist, but the exempted URL list could not be read, so exemption hygiene is unverified.`, evidence, evidenceNote);
  }
  if (exempted.length > maxExemptions) {
    return finding(4, "warn", `${decrypt.length} enabled DECRYPT rules exist, but ${exempted.length} URLs are exempted from inspection (threshold ${maxExemptions}).`, evidence, evidenceNote);
  }
  if ((locationsWithoutScan ?? 0) > 0) {
    return finding(4, "warn", `${decrypt.length} enabled DECRYPT rules and ${exempted.length} exemptions, but ${locationsWithoutScan} location(s) have sslScanEnabled=false.`, evidence, evidenceNote);
  }
  const status = capForPartial("pass", data.locations);
  return finding(4, status, `${decrypt.length} enabled DECRYPT rules, ${exempted.length} exempted URLs (threshold ${maxExemptions}), no blanket bypass rules${locationsWithoutScan === undefined ? "" : ", and SSL scanning enabled on every location that was read"}.${partialSuffix(data.locations, "location")}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessSandbox(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Confirm the Cloud Sandbox subscription under Administration > Company Profile > Subscriptions and export Policy > Sandbox showing enabled rules with Block or Quarantine actions.";
  return capForUnreadableAll(sandboxVerdict(data, evidenceNote), [dependsOn("sandbox advanced settings", "GET /behavioralAnalysisAdvancedSettings", data.sandboxSettings)], evidenceNote);
}

function sandboxVerdict(data: ZiaPolicyData, evidenceNote: string): ZscalerFinding {
  const rules = data.sandboxRules;
  if (rules.error) return unreadableFinding(5, "GET /sandboxRules", rules, `${evidenceNote} A 4xx here can also mean Cloud Sandbox is not licensed.`);
  const active = enabledRules(rules.data);
  const blocking = active.filter((rule) => (asString(rule.baRuleAction) ?? "").toUpperCase() === "BLOCK");
  const quarantineFirst = active.filter((rule) => asBoolean(rule.firstTimeEnable) === true && (asString(rule.firstTimeOperation) ?? "").toUpperCase() === "QUARANTINE");
  // GET /behavioralAnalysisAdvancedSettings documents md5HashValueList; fileHashesToBeBlocked is the legacy shape
  // kept by zscaler-sdk-go (sandbox_settings.go) and is recorded only as evidence when a tenant still returns it.
  const legacyHashes = data.sandboxSettings.error ? [] : asArray(data.sandboxSettings.data.fileHashesToBeBlocked);
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: active.length,
    blocking_rules: blocking.length,
    quarantine_first_time_rules: quarantineFirst.length,
    blocked_file_hashes: data.sandboxSettings.error ? null : asArray(data.sandboxSettings.data.md5HashValueList).length,
    legacy_file_hashes_to_be_blocked: legacyHashes.length > 0 ? legacyHashes.length : null,
    rules: ruleSummaries(rules.data, "baRuleAction"),
  };
  if (rules.data.length === 0) {
    return finding(5, "manual", "Not configured: zero sandbox rules were returned, which means Cloud Sandbox is either unlicensed or unconfigured; the control cannot pass until a rule inventory exists.", evidence, evidenceNote);
  }
  if (active.length === 0) {
    return finding(5, "fail", `${rules.data.length} sandbox rules exist but all are DISABLED.`, evidence, evidenceNote);
  }
  if (blocking.length === 0) {
    return finding(5, "warn", `${active.length} enabled sandbox rules only ALLOW; no rule blocks malicious verdicts.`, evidence, evidenceNote);
  }
  return finding(5, "pass", `${blocking.length} enabled sandbox rules block malicious verdicts (${quarantineFirst.length} quarantine first-time files).`, evidence);
}

function assessBandwidth(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Confirm whether Bandwidth Control is licensed and, if so, export Policy > Bandwidth Control showing enabled rules for critical application classes.";
  const rules = data.bandwidthRules;
  if (rules.error) return unreadableFinding(16, "GET /bandwidthControlRules", rules, evidenceNote);
  const active = enabledRules(rules.data);
  const evidence = { rule_count: rules.data.length, enabled_rules: active.length, rules: truncateList(rules.data.map((rule) => ({ name: ruleLabel(rule), state: asString(rule.state) ?? null, minBandwidth: asNumber(rule.minBandwidth) ?? null, maxBandwidth: asNumber(rule.maxBandwidth) ?? null }))) };
  if (rules.data.length === 0) {
    return finding(16, "manual", "Not configured: zero bandwidth control rules exist; confirm whether bandwidth control is licensed and required for this tenant before treating this as compliant.", evidence, evidenceNote);
  }
  if (active.length === 0) {
    return finding(16, "warn", `${rules.data.length} bandwidth control rules exist but all are DISABLED.`, evidence, evidenceNote);
  }
  return finding(16, "pass", `${active.length} enabled bandwidth control rules are in force.`, evidence);
}

function assessBrowserIsolation(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Confirm the Cloud Browser Isolation subscription and export the URL filtering rules that use the Isolate action together with the isolation profiles under Administration > Isolation Profile.";
  const profiles = data.isolationProfiles;
  if (profiles.error) return unreadableFinding(17, "GET /browserIsolation/profiles", profiles, `${evidenceNote} A 4xx here can also mean Cloud Browser Isolation is not licensed.`);
  if (data.urlFilteringRules.error) return unreadableFinding(17, "GET /urlFilteringRules", data.urlFilteringRules, evidenceNote);
  const urlRules = data.urlFilteringRules;
  const isolateRules = enabledRules(urlRules.data).filter((rule) => (asString(rule.action) ?? "").toUpperCase() === "ISOLATE");
  const evidence = {
    profile_count: profiles.data.length,
    profiles: truncateList(profiles.data.map((profile) => asString(profile.name) ?? asString(profile.id) ?? "profile")),
    isolate_url_rules: truncateList(isolateRules.map(ruleLabel)),
    url_rule_inventory_partial: urlRules.truncated === true,
    partial_inventory: urlRules.truncated === true,
  };
  if (profiles.data.length === 0) {
    return finding(17, "manual", "Not configured: zero browser isolation profiles exist, so Cloud Browser Isolation is unlicensed or unconfigured.", evidence, evidenceNote);
  }
  if (isolateRules.length === 0) {
    return finding(17, "warn", `${profiles.data.length} isolation profile(s) exist but no enabled URL filtering rule uses action ISOLATE, so isolation is never applied.${partialSuffix(urlRules, "URL filtering rule")}`, evidence, evidenceNote);
  }
  return finding(17, capForPartial("pass", urlRules), `${profiles.data.length} isolation profile(s) are applied by ${isolateRules.length} enabled ISOLATE URL filtering rule(s).${partialSuffix(urlRules, "URL filtering rule")}`, evidence, urlRules.truncated ? evidenceNote : undefined);
}

function locationLabel(location: JsonRecord): string {
  return asString(location.name) ?? asString(location.id) ?? "location";
}

function assessLocations(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Administration > Location Management showing per-location authentication, SSL inspection, firewall enablement, and the GRE tunnel or IPSec VPN credentials that carry each site.";
  return capForUnreadableAll(locationsVerdict(data, evidenceNote), [
    dependsOn("sub-location", "GET /locations/{locationId}/sublocations", data.subLocations),
    dependsOn("GRE tunnel", "GET /greTunnels", data.greTunnels),
    dependsOn("VPN credential", "GET /vpnCredentials", data.vpnCredentials),
  ], evidenceNote);
}

function locationsVerdict(data: ZiaPolicyData, evidenceNote: string): ZscalerFinding {
  const locations = data.locations;
  if (locations.error) return unreadableFinding(18, "GET /locations", locations, evidenceNote);
  const subLocations = data.subLocations;
  const all = [...locations.data, ...subLocations.data];
  const noAuth = all.filter((location) => asBoolean(location.authRequired) !== true);
  const noSsl = all.filter((location) => asBoolean(location.sslScanEnabled) !== true);
  const noFirewall = all.filter((location) => asBoolean(location.ofwEnabled) !== true);
  const subLocationParentsRead = subLocations.seen ?? locations.data.length;
  const subLocationParentsTotal = subLocations.total ?? locations.data.length;
  const subLocationsPartial = subLocations.truncated === true || subLocations.error !== undefined;
  const tunnelsPartial = data.greTunnels.truncated === true || data.vpnCredentials.truncated === true;
  const subLocationSuffix = subLocations.truncated
    ? ` Sub-locations were read for only ${subLocationParentsRead} of ${subLocationParentsTotal} parent locations, so the sub-location inventory is partial and this verdict is capped at warn.`
    : subLocations.error
      ? " Sub-locations could not be read for every parent, so the sub-location inventory is partial and this verdict is capped at warn."
      : "";
  const tunnelSuffix = `${partialSuffix(data.greTunnels, "GRE tunnel")}${partialSuffix(data.vpnCredentials, "VPN credential")}`;
  const evidence = {
    location_count: locations.data.length,
    sub_location_count: subLocations.data.length,
    sub_locations_readable: !subLocations.error,
    sub_location_parents_read: subLocationParentsRead,
    sub_location_parents_total: subLocationParentsTotal,
    gre_tunnels: data.greTunnels.error ? null : data.greTunnels.data.length,
    gre_tunnel_inventory_partial: data.greTunnels.truncated === true,
    vpn_credentials: data.vpnCredentials.error ? null : data.vpnCredentials.data.length,
    vpn_credential_inventory_partial: data.vpnCredentials.truncated === true,
    locations_without_auth: truncateList(noAuth.map(locationLabel)),
    locations_without_ssl_scan: truncateList(noSsl.map(locationLabel)),
    locations_without_firewall: truncateList(noFirewall.map(locationLabel)),
    partial_inventory: locations.truncated === true || subLocationsPartial || tunnelsPartial,
  };
  if (locations.data.length === 0) {
    return finding(18, "manual", "Empty inventory: zero locations exist, so the tenant may forward traffic only through Zscaler Client Connector; confirm that no GRE or IPSec sites are expected.", evidence, evidenceNote);
  }
  const issues: string[] = [];
  if (noAuth.length > 0) issues.push(`${noAuth.length} without authRequired`);
  if (noSsl.length > 0) issues.push(`${noSsl.length} without sslScanEnabled`);
  if (noFirewall.length > 0) issues.push(`${noFirewall.length} without ofwEnabled`);
  if (issues.length > 0) {
    return finding(18, "warn", `${all.length} locations and sub-locations reviewed: ${issues.join(", ")}.${partialSuffix(locations, "location")}${subLocationSuffix}${tunnelSuffix}`, evidence, evidenceNote);
  }
  const status = subLocationsPartial || tunnelsPartial ? "warn" : capForPartial("pass", locations);
  return finding(18, status, `All ${all.length} locations and sub-locations that were read enforce authentication, SSL inspection, and the cloud firewall.${partialSuffix(locations, "location")}${subLocationSuffix}${tunnelSuffix}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessCloudAppControl(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > URL & Cloud App Control > Cloud App Control Policy showing enabled rules that block or isolate unsanctioned applications per rule type.";
  const rules = data.cloudAppRules;
  if (rules.error && rules.data.length === 0) return unreadableFinding(19, "GET /webApplicationRules/{ruleType}", rules, evidenceNote);
  const active = enabledRules(rules.data);
  const restrictive = active.filter((rule) => asStringList(rule.actions).some((action) => /^(BLOCK|ISOLATE|CAUTION|DENY)/i.test(action)));
  const evidence = {
    rule_types_seen: rules.seen ?? null,
    rule_types_total: rules.total ?? null,
    rule_count: rules.data.length,
    enabled_rules: active.length,
    restrictive_rules: restrictive.length,
    partial_reads: rules.error ?? null,
    partial_inventory: rules.truncated === true,
    rules: truncateList(rules.data.map((rule) => ({ name: ruleLabel(rule), type: asString(rule.ruleType) ?? asString(rule.type) ?? null, state: asString(rule.state) ?? null, actions: asStringList(rule.actions) }))),
  };
  if (rules.error) {
    return finding(19, "manual", `Some cloud app control rule types could not be read (${rules.error}), so the ${rules.data.length} rules seen are a partial view.`, evidence, evidenceNote);
  }
  if (rules.data.length === 0) {
    return finding(19, "fail", "Empty inventory: zero cloud app control rules exist, so no application-level restrictions apply to unsanctioned SaaS.", evidence, evidenceNote);
  }
  if (restrictive.length === 0) {
    return finding(19, "fail", `${active.length} enabled cloud app control rules exist but none blocks, isolates, or cautions any application.`, evidence, evidenceNote);
  }
  if (rules.truncated) {
    return finding(19, "warn", `${restrictive.length} restrictive rules were found, but only ${rules.seen} of ${rules.total} rule types were read, so the view is partial.`, evidence, evidenceNote);
  }
  return finding(19, "pass", `${restrictive.length} enabled cloud app control rules block, isolate, or caution applications across ${rules.total ?? rules.seen} rule types.`, evidence);
}

function assessDnsSecurity(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > Firewall Control > DNS Control showing enabled block or redirect rules and the Advanced Threat Protection DGA domain setting.";
  return capForUnreadableAll(dnsSecurityVerdict(data, evidenceNote), [dependsOn("advanced threat protection settings", "GET /cyberThreatProtection/advancedThreatSettings", data.advancedThreatSettings)], evidenceNote);
}

function dnsSecurityVerdict(data: ZiaPolicyData, evidenceNote: string): ZscalerFinding {
  const rules = data.dnsRules;
  if (rules.error) return unreadableFinding(20, "GET /firewallDnsRules", rules, evidenceNote);
  const active = enabledRules(rules.data);
  const protective = active.filter((rule) => asBoolean(rule.defaultRule) !== true && /^(BLOCK|REDIR)/i.test(asString(rule.action) ?? ""));
  const defaultRule = rules.data.find((rule) => asBoolean(rule.defaultRule) === true);
  const dgaBlocked = data.advancedThreatSettings.error ? undefined : asBoolean(data.advancedThreatSettings.data.dgaDomainsBlocked);
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: active.length,
    protective_rules: truncateList(protective.map(ruleLabel)),
    default_rule_action: defaultRule ? asString(defaultRule.action) ?? null : null,
    dga_domains_blocked: dgaBlocked ?? null,
    rules: ruleSummaries(rules.data),
  };
  if (rules.data.length === 0) {
    return finding(20, "fail", "Empty inventory: zero DNS control rules were returned, so DNS traffic is not filtered by the cloud firewall.", evidence, evidenceNote);
  }
  if (protective.length === 0) {
    return finding(20, "fail", `${active.length} enabled DNS control rules exist but none blocks or redirects DNS requests beyond the default rule.`, evidence, evidenceNote);
  }
  if (dgaBlocked !== true) {
    return finding(20, "warn", `${protective.length} protective DNS rules are enabled, but dgaDomainsBlocked is ${dgaBlocked === undefined ? "unreadable" : "false"} in Advanced Threat Protection.`, evidence, evidenceNote);
  }
  return finding(20, "pass", `${protective.length} enabled DNS control rules block or redirect DNS requests and DGA domains are blocked.`, evidence);
}

function assessSecurityBaseline(data: ZiaPolicyData): ZscalerFinding {
  const evidenceNote = "Export Policy > Malware Protection and Policy > Advanced Threat Protection showing every blocked category and the unscannable file handling.";
  return capForUnreadableAll(securityBaselineVerdict(data, evidenceNote), [
    dependsOn("malware policy", "GET /cyberThreatProtection/malwarePolicy", data.malwarePolicy),
    dependsOn("security allowlist", "GET /security", data.securityAllowlist),
    dependsOn("security denylist", "GET /security/advanced", data.securityDenylist),
  ], evidenceNote);
}

function securityBaselineVerdict(data: ZiaPolicyData, evidenceNote: string): ZscalerFinding {
  if (data.advancedThreatSettings.error) return unreadableFinding(25, "GET /cyberThreatProtection/advancedThreatSettings", data.advancedThreatSettings, evidenceNote);
  if (data.malwareSettings.error) return unreadableFinding(25, "GET /cyberThreatProtection/malwareSettings", data.malwareSettings, evidenceNote);
  const atp = data.advancedThreatSettings.data;
  const malware = data.malwareSettings.data;
  const missingAtp = REQUIRED_ATP_FLAGS.filter((flag) => asBoolean(atp[flag]) !== true);
  const missingMalware = REQUIRED_MALWARE_FLAGS.filter((flag) => asBoolean(malware[flag]) !== true);
  const blockUnscannable = data.malwarePolicy.error ? undefined : asBoolean(data.malwarePolicy.data.blockUnscannableFiles);
  const allowlist = data.securityAllowlist.error ? undefined : asStringList(data.securityAllowlist.data.whitelistUrls);
  const denylist = data.securityDenylist.error ? undefined : asStringList(data.securityDenylist.data.blacklistUrls);
  const evidence = {
    required_atp_flags_not_enabled: missingAtp,
    required_malware_flags_not_enabled: missingMalware,
    risk_tolerance: asNumber(atp.riskTolerance) ?? null,
    block_unscannable_files: blockUnscannable ?? null,
    block_password_protected_archives: data.malwarePolicy.error ? null : asBoolean(data.malwarePolicy.data.blockPasswordProtectedArchiveFiles) ?? null,
    allowlist_urls: allowlist ? allowlist.length : null,
    denylist_urls: denylist ? denylist.length : null,
  };
  if (Object.keys(atp).length === 0 || Object.keys(malware).length === 0) {
    return finding(25, "fail", "Empty response: the ATP or malware settings object contained no flags, so none of the required protections can be confirmed enabled.", evidence, evidenceNote);
  }
  if (missingAtp.length > 0 || missingMalware.length > 0) {
    return finding(25, "fail", `Required protections are not enabled: ${[...missingAtp, ...missingMalware].join(", ")}.`, evidence, evidenceNote);
  }
  if (blockUnscannable !== true) {
    return finding(25, "warn", `All ${REQUIRED_ATP_FLAGS.length + REQUIRED_MALWARE_FLAGS.length} required ATP and malware protections are enabled, but blockUnscannableFiles is ${blockUnscannable === undefined ? "unreadable" : "false"}.`, evidence, evidenceNote);
  }
  if ((allowlist?.length ?? 0) > 100) {
    return finding(25, "warn", `All required protections are enabled, but ${allowlist?.length} URLs bypass security policy via the allowlist.`, evidence, evidenceNote);
  }
  return finding(25, "pass", `All ${REQUIRED_ATP_FLAGS.length} required ATP protections and ${REQUIRED_MALWARE_FLAGS.length} malware protections are enabled, unscannable files are blocked, and the allowlist holds ${allowlist?.length ?? "an unreadable number of"} URLs.`, evidence);
}

export function assessZiaPolicyData(data: ZiaPolicyData, options: { maxSslExemptions?: number } = {}): ZscalerAssessmentResult {
  const maxExemptions = clampNumber(options.maxSslExemptions, DEFAULT_MAX_SSL_EXEMPTIONS, 0, 100_000);
  const findings = [
    assessUrlFiltering(data),
    assessFirewall(data),
    assessDlp(data),
    assessSslInspection(data, maxExemptions),
    assessSandbox(data),
    assessBandwidth(data),
    assessBrowserIsolation(data),
    assessLocations(data),
    assessCloudAppControl(data),
    assessDnsSecurity(data),
    assessSecurityBaseline(data),
  ];
  const datasets: Array<[string, CollectedDataset<unknown>, string?]> = [
    ["urlFilteringRules", data.urlFilteringRules],
    ["firewallFilteringRules", data.firewallRules],
    ["firewallDnsRules", data.dnsRules],
    ["dlpEngines", data.dlpEngines],
    ["dlpDictionaries", data.dlpDictionaries],
    ["webDlpRules", data.webDlpRules],
    ["sslInspectionRules", data.sslInspectionRules],
    ["sslSettings/exemptedUrls", data.sslExemptedUrls],
    ["sandboxRules", data.sandboxRules],
    ["behavioralAnalysisAdvancedSettings", data.sandboxSettings],
    ["advancedThreatSettings", data.advancedThreatSettings],
    ["malwarePolicy", data.malwarePolicy],
    ["malwareSettings", data.malwareSettings],
    ["security", data.securityAllowlist],
    ["security/advanced", data.securityDenylist],
    ["locations", data.locations],
    ["locations/{locationId}/sublocations", data.subLocations, "parent locations"],
    ["greTunnels", data.greTunnels],
    ["vpnCredentials", data.vpnCredentials],
    ["bandwidthControlRules", data.bandwidthRules],
    ["browserIsolation/profiles", data.isolationProfiles],
    ["webApplicationRules/{ruleType}", data.cloudAppRules, "rule types"],
  ];
  return {
    title: "Zscaler ZIA security policy",
    area: "zia_policy",
    summary: {
      url_filtering_rules: data.urlFilteringRules.data.length,
      firewall_rules: data.firewallRules.data.length,
      dns_rules: data.dnsRules.data.length,
      dlp_engines: data.dlpEngines.data.length,
      web_dlp_rules: data.webDlpRules.data.length,
      ssl_inspection_rules: data.sslInspectionRules.data.length,
      sandbox_rules: data.sandboxRules.data.length,
      locations: data.locations.data.length,
      sub_locations: data.subLocations.data.length,
      cloud_app_rules: data.cloudAppRules.data.length,
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors: datasets.flatMap(([label, dataset]) => datasetErrors(label, dataset)),
    truncated: datasets.flatMap(([label, dataset, unit]) => datasetTruncations(label, dataset, unit)),
  };
}

export async function assessZiaPolicy(client: ZiaReadClient | undefined, options: { maxSslExemptions?: number } = {}): Promise<ZscalerAssessmentResult> {
  if (!client) {
    return notConfiguredAssessment("zia_policy", "Zscaler ZIA security policy", "zia", [1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 25]);
  }
  return assessZiaPolicyData(await collectZiaPolicyData(client), options);
}

const ZPA_CONNECTED_STATUS = "ZPN_STATUS_AUTHENTICATED";
const ZPA_ADMINISTRATORS_PROVENANCE = "a surface documented only by zscaler-sdk-go, not by the published ZPA API reference";
const IDENTITY_OPERAND_TYPES = ["USER", "USER_GROUP", "SCIM_GROUP", "SCIM", "SAML", "IDP", "POSTURE", "TRUSTED_NETWORK", "CLIENT_TYPE", "MACHINE_GRP", "PLATFORM", "COUNTRY_CODE", "RISK_FACTOR_TYPE", "CHROME_ENTERPRISE", "BRANCH_CONNECTOR_GROUP", "EDGE_CONNECTOR_GROUP", "USER_PORTAL", "CONSOLE"];

export interface ZpaData {
  applicationSegments: CollectedDataset<JsonRecord[]>;
  segmentGroups: CollectedDataset<JsonRecord[]>;
  accessRules: CollectedDataset<JsonRecord[]>;
  timeoutRules: CollectedDataset<JsonRecord[]>;
  forwardingRules: CollectedDataset<JsonRecord[]>;
  isolationRules: CollectedDataset<JsonRecord[]>;
  appConnectorGroups: CollectedDataset<JsonRecord[]>;
  appConnectors: CollectedDataset<JsonRecord[]>;
  serviceEdgeGroups: CollectedDataset<JsonRecord[]>;
  serviceEdges: CollectedDataset<JsonRecord[]>;
  postureProfiles: CollectedDataset<JsonRecord[]>;
  trustedNetworks: CollectedDataset<JsonRecord[]>;
  idpControllers: CollectedDataset<JsonRecord[]>;
  samlAttributes: CollectedDataset<JsonRecord[]>;
  scimGroups: CollectedDataset<JsonRecord[]>;
  enrollmentCertificates: CollectedDataset<JsonRecord[]>;
  browserAccessCertificates: CollectedDataset<JsonRecord[]>;
  emergencyAccessUsers: CollectedDataset<JsonRecord[]>;
  administrators: CollectedDataset<JsonRecord[]>;
  now: Date;
}

async function collectScimGroups(client: ZpaReadClient, idps: CollectedDataset<JsonRecord[]>): Promise<CollectedDataset<JsonRecord[]>> {
  if (idps.error) {
    return { data: [], error: `skipped because IdP controllers were unreadable: ${idps.error}`, statusCode: idps.statusCode };
  }
  const items: JsonRecord[] = [];
  const errors: string[] = [];
  let truncated = false;
  for (const idp of idps.data.filter((item) => asBoolean(item.scimEnabled) === true)) {
    const idpId = asString(idp.id);
    if (!idpId) continue;
    try {
      const page = await client.listScimGroups(idpId);
      items.push(...page.items.map((group) => ({ ...group, idpId })));
      truncated = truncated || page.truncated;
    } catch (error) {
      errors.push(`${idpId}: ${errorMessage(error)}`);
    }
  }
  return { data: items, error: errors.length > 0 ? errors.join("; ") : undefined, truncated };
}

export async function collectZpaData(client: ZpaReadClient): Promise<ZpaData> {
  const idpControllers = await collectPaged("zpa", () => client.listIdpControllers());
  return {
    applicationSegments: await collectPaged("zpa", () => client.listApplicationSegments()),
    segmentGroups: await collectPaged("zpa", () => client.listSegmentGroups()),
    accessRules: await collectPaged("zpa", () => client.listPolicyRules("ACCESS_POLICY")),
    timeoutRules: await collectPaged("zpa", () => client.listPolicyRules("TIMEOUT_POLICY")),
    forwardingRules: await collectPaged("zpa", () => client.listPolicyRules("CLIENT_FORWARDING_POLICY")),
    isolationRules: await collectPaged("zpa", () => client.listPolicyRules("ISOLATION_POLICY")),
    appConnectorGroups: await collectPaged("zpa", () => client.listAppConnectorGroups()),
    appConnectors: await collectPaged("zpa", () => client.listAppConnectors()),
    serviceEdgeGroups: await collectPaged("zpa", () => client.listServiceEdgeGroups()),
    serviceEdges: await collectPaged("zpa", () => client.listServiceEdges()),
    postureProfiles: await collectPaged("zpa", () => client.listPostureProfiles()),
    trustedNetworks: await collectPaged("zpa", () => client.listTrustedNetworks()),
    idpControllers,
    samlAttributes: await collectPaged("zpa", () => client.listSamlAttributes()),
    scimGroups: await collectScimGroups(client, idpControllers),
    enrollmentCertificates: await collectPaged("zpa", () => client.listEnrollmentCertificates()),
    browserAccessCertificates: await collectPaged("zpa", () => client.listBrowserAccessCertificates()),
    emergencyAccessUsers: await collectPaged("zpa", () => client.listEmergencyAccessUsers()),
    administrators: await collectPaged("zpa", () => client.listAdministrators()),
    now: client.getNow(),
  };
}

function zpaRuleEnabled(rule: JsonRecord): boolean {
  return asBoolean(rule.disabled) !== true;
}

function ruleOperandTypes(rule: JsonRecord): string[] {
  return asRecordArray(rule.conditions).flatMap((condition) => asRecordArray(condition.operands).map((operand) => (asString(operand.objectType) ?? "").toUpperCase()));
}

function ruleUsesOperand(rules: JsonRecord[], objectType: string): JsonRecord[] {
  return rules.filter((rule) => ruleOperandTypes(rule).includes(objectType));
}

function isFullPortRange(segment: JsonRecord): boolean {
  const pairs = [...asRecordArray(segment.tcpPortRange), ...asRecordArray(segment.udpPortRange)];
  if (pairs.some((pair) => asNumber(pair.from) === 1 && asNumber(pair.to) === 65535)) return true;
  const flat = [...asStringList(segment.tcpPortRanges), ...asStringList(segment.udpPortRanges)];
  for (let index = 0; index + 1 < flat.length; index += 2) {
    if (asNumber(flat[index]) === 1 && asNumber(flat[index + 1]) === 65535) return true;
  }
  return false;
}

function hasWildcardDomain(segment: JsonRecord): boolean {
  return asStringList(segment.domainNames).some((domain) => domain === "*" || /^\*\.[a-z0-9-]+$/i.test(domain));
}

function assessSegmentation(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Administration > Application Segments and Segment Groups showing domain and port scoping for every enabled segment.";
  return capForUnreadableAll(segmentationVerdict(data, evidenceNote), [dependsOn("segment group", "GET /segmentGroup", data.segmentGroups)], evidenceNote);
}

function segmentationVerdict(data: ZpaData, evidenceNote: string): ZscalerFinding {
  const segments = data.applicationSegments;
  if (segments.error) return unreadableFinding(8, "GET /application", segments, evidenceNote);
  const enabled = segments.data.filter((segment) => asBoolean(segment.enabled) === true);
  const wildcard = enabled.filter(hasWildcardDomain);
  const fullRange = enabled.filter(isFullPortRange);
  const bothBroad = enabled.filter((segment) => hasWildcardDomain(segment) && isFullPortRange(segment));
  const bypassAlways = enabled.filter((segment) => (asString(segment.bypassType) ?? "").toUpperCase() === "ALWAYS");
  const ungrouped = enabled.filter((segment) => !asString(segment.segmentGroupId));
  const evidence = {
    segment_count: segments.data.length,
    enabled_segments: enabled.length,
    segment_groups: data.segmentGroups.error ? null : data.segmentGroups.data.length,
    wildcard_domain_segments: truncateList(wildcard.map(ruleLabel)),
    full_port_range_segments: truncateList(fullRange.map(ruleLabel)),
    bypass_always_segments: truncateList(bypassAlways.map(ruleLabel)),
    ungrouped_segments: ungrouped.length,
    partial_inventory: segments.truncated === true || data.segmentGroups.truncated === true,
  };
  if (segments.data.length === 0) {
    return finding(8, "fail", "Empty inventory: zero application segments are defined, so ZPA is not brokering access to any private application.", evidence, evidenceNote);
  }
  if (enabled.length === 0) {
    return finding(8, "fail", `${segments.data.length} application segments exist but none is enabled.`, evidence, evidenceNote);
  }
  if (bothBroad.length > 0) {
    return finding(8, "fail", `${bothBroad.length} enabled segment(s) combine a wildcard domain with the full 1-65535 port range, which is flat network access rather than segmentation: ${bothBroad.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  const issues: string[] = [];
  if (wildcard.length > 0) issues.push(`${wildcard.length} use wildcard domains`);
  if (fullRange.length > 0) issues.push(`${fullRange.length} expose the full port range`);
  if (bypassAlways.length > 0) issues.push(`${bypassAlways.length} have bypassType ALWAYS`);
  const partialNote = `${partialSuffix(segments, "application segment")}${partialSuffix(data.segmentGroups, "segment group")}`;
  if (issues.length > 0) {
    return finding(8, "warn", `${enabled.length} enabled segments: ${issues.join(", ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [segments, data.segmentGroups]);
  return finding(8, status, `${enabled.length} enabled application segments are scoped to explicit domains and ports with no ZPA bypass.${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessAccessPolicies(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Policy > Access Policy showing each enabled ALLOW rule's criteria (SCIM groups, SAML attributes, posture, trusted network, client type).";
  const rules = data.accessRules;
  if (rules.error) return unreadableFinding(9, "GET /policySet/rules/policyType/ACCESS_POLICY", rules, evidenceNote);
  const enabled = rules.data.filter(zpaRuleEnabled);
  const allow = enabled.filter((rule) => (asString(rule.action) ?? "").toUpperCase() === "ALLOW");
  const unconditional = allow.filter((rule) => asRecordArray(rule.conditions).length === 0);
  const noIdentity = allow.filter((rule) => asRecordArray(rule.conditions).length > 0 && !ruleOperandTypes(rule).some((type) => IDENTITY_OPERAND_TYPES.includes(type)));
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: enabled.length,
    allow_rules: allow.length,
    deny_rules: enabled.length - allow.length,
    unconditional_allow_rules: truncateList(unconditional.map(ruleLabel)),
    allow_rules_without_identity_criteria: truncateList(noIdentity.map(ruleLabel)),
    partial_inventory: rules.truncated === true,
    rules: truncateList(rules.data.map((rule) => ({ name: ruleLabel(rule), action: asString(rule.action) ?? null, disabled: asBoolean(rule.disabled) ?? false, operands: ruleOperandTypes(rule) }))),
  };
  if (rules.data.length === 0) {
    return finding(9, "fail", "Empty inventory: zero access policy rules exist, so no user can be granted least-privilege access and ZPA is effectively unused.", evidence, evidenceNote);
  }
  if (allow.length === 0) {
    return finding(9, "warn", `${enabled.length} enabled access rules exist but none allows access, so either ZPA is unused or the inventory is incomplete.`, evidence, evidenceNote);
  }
  if (unconditional.length > 0) {
    return finding(9, "fail", `${unconditional.length} enabled ALLOW rule(s) have no conditions and grant every authenticated user access: ${unconditional.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  if (noIdentity.length > 0) {
    return finding(9, "warn", `${noIdentity.length} enabled ALLOW rule(s) match only applications with no identity, posture, or network criteria: ${noIdentity.map(ruleLabel).join(", ")}.${partialSuffix(rules, "access rule")}`, evidence, evidenceNote);
  }
  return finding(9, capForPartial("pass", rules), `All ${allow.length} enabled ALLOW rules carry identity, posture, or network criteria.${partialSuffix(rules, "access rule")}`, evidence);
}

function assessPosture(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Administration > Posture Profiles and show which access rules reference them under Policy > Access Policy.";
  const profiles = data.postureProfiles;
  if (profiles.error) return unreadableFinding(10, "GET /posture", profiles, evidenceNote);
  if (data.accessRules.error) return unreadableFinding(10, "GET /policySet/rules/policyType/ACCESS_POLICY", data.accessRules, evidenceNote);
  const allow = data.accessRules.data.filter((rule) => zpaRuleEnabled(rule) && (asString(rule.action) ?? "").toUpperCase() === "ALLOW");
  const postureRules = ruleUsesOperand(allow, "POSTURE");
  const evidence = {
    profile_count: profiles.data.length,
    profiles: truncateList(profiles.data.map((profile) => ({ name: asString(profile.name) ?? null, postureType: asString(profile.postureType) ?? null }))),
    allow_rules: allow.length,
    allow_rules_with_posture: postureRules.length,
    partial_inventory: profiles.truncated === true || data.accessRules.truncated === true,
  };
  if (profiles.data.length === 0) {
    return finding(10, "fail", "Empty inventory: zero posture profiles are defined, so device posture is never evaluated before access.", evidence, evidenceNote);
  }
  if (allow.length === 0) {
    return finding(10, "warn", `${profiles.data.length} posture profiles exist but no enabled ALLOW access rule exists to enforce them.`, evidence, evidenceNote);
  }
  if (postureRules.length === 0) {
    return finding(10, "fail", `${profiles.data.length} posture profiles exist but none of the ${allow.length} enabled ALLOW rules uses a POSTURE condition.`, evidence, evidenceNote);
  }
  if (postureRules.length < allow.length) {
    return finding(10, "warn", `${postureRules.length} of ${allow.length} enabled ALLOW rules enforce posture; the remaining ${allow.length - postureRules.length} grant access without a device check.`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [profiles, data.accessRules]);
  return finding(10, status, `All ${allow.length} enabled ALLOW rules enforce one of ${profiles.data.length} posture profiles.${partialSuffix(profiles, "posture profile")}${partialSuffix(data.accessRules, "access rule")}`, evidence, status === "warn" ? evidenceNote : undefined);
}

interface ConnectorHealth {
  connected: JsonRecord[];
  stale: JsonRecord[];
  undated: JsonRecord[];
  disconnected: JsonRecord[];
}

// A connector counts as healthy only when controlChannelStatus is ZPN_STATUS_AUTHENTICATED and lastBrokerConnectTime
// is present and within staleDays. Authenticated connectors with an older timestamp are stale and those with no
// timestamp are undated; both cap the verdict at warn because freshness cannot be shown (rule 4).
function connectorHealth(items: JsonRecord[], now: Date, staleDays: number): ConnectorHealth {
  const health: ConnectorHealth = { connected: [], stale: [], undated: [], disconnected: [] };
  for (const item of items) {
    const status = (asString(item.controlChannelStatus) ?? "").toUpperCase();
    const lastConnect = epochToDate(item.lastBrokerConnectTime);
    if (status !== ZPA_CONNECTED_STATUS) {
      health.disconnected.push(item);
    } else if (!lastConnect) {
      health.undated.push(item);
    } else if (daysBetween(now, lastConnect) > staleDays) {
      health.stale.push(item);
    } else {
      health.connected.push(item);
    }
  }
  return health;
}

function connectorHealthIssues(health: ConnectorHealth, staleDays: number): string[] {
  const issues: string[] = [];
  if (health.disconnected.length > 0) issues.push(`${health.disconnected.length} not authenticated (controlChannelStatus is not ${ZPA_CONNECTED_STATUS})`);
  if (health.stale.length > 0) issues.push(`${health.stale.length} authenticated but with lastBrokerConnectTime older than ${staleDays} days (stale_connector_days)`);
  if (health.undated.length > 0) issues.push(`${health.undated.length} authenticated but with no lastBrokerConnectTime (cannot be counted as fresh, capped at warn)`);
  return issues;
}

function assessConnectors(data: ZpaData, staleDays: number): ZscalerFinding {
  const evidenceNote = "Export Administration > App Connectors showing control channel status per connector and the connector count per App Connector Group.";
  return capForUnreadableAll(connectorsVerdict(data, staleDays, evidenceNote), [dependsOn("connector group", "GET /appConnectorGroup", data.appConnectorGroups)], evidenceNote);
}

function connectorsVerdict(data: ZpaData, staleDays: number, evidenceNote: string): ZscalerFinding {
  const connectors = data.appConnectors;
  if (connectors.error) return unreadableFinding(11, "GET /connector", connectors, evidenceNote);
  const enabled = connectors.data.filter((item) => asBoolean(item.enabled) !== false);
  const health = connectorHealth(enabled, data.now, staleDays);
  const perGroup = new Map<string, number>();
  for (const connector of health.connected) {
    const group = asString(connector.appConnectorGroupName) ?? asString(connector.appConnectorGroupId) ?? "ungrouped";
    perGroup.set(group, (perGroup.get(group) ?? 0) + 1);
  }
  const groups = data.appConnectorGroups.error ? [] : data.appConnectorGroups.data.filter((group) => asBoolean(group.enabled) !== false);
  const singleConnectorGroups = groups.filter((group) => (perGroup.get(asString(group.name) ?? asString(group.id) ?? "") ?? 0) < 2).map(ruleLabel);
  const authenticated = health.connected.length + health.stale.length + health.undated.length;
  const evidence = {
    connector_count: connectors.data.length,
    enabled_connectors: enabled.length,
    connected: health.connected.length,
    stale_connector_days: staleDays,
    stale: truncateList(health.stale.map(ruleLabel)),
    authenticated_without_connect_time: truncateList(health.undated.map(ruleLabel)),
    disconnected: truncateList(health.disconnected.map(ruleLabel)),
    connector_groups: data.appConnectorGroups.error ? null : groups.length,
    groups_without_redundancy: truncateList(singleConnectorGroups),
    partial_inventory: connectors.truncated === true || data.appConnectorGroups.truncated === true,
  };
  const partialNote = `${partialSuffix(connectors, "connector")}${partialSuffix(data.appConnectorGroups, "connector group")}`;
  if (connectors.data.length === 0) {
    return finding(11, "fail", "Empty inventory: zero app connectors are enrolled, so no private application can be reached through ZPA.", evidence, evidenceNote);
  }
  if (authenticated === 0) {
    return finding(11, "fail", `None of the ${enabled.length} enabled connectors reports controlChannelStatus ${ZPA_CONNECTED_STATUS}.`, evidence, evidenceNote);
  }
  const issues = connectorHealthIssues(health, staleDays);
  if (singleConnectorGroups.length > 0) issues.push(`${singleConnectorGroups.length} group(s) with fewer than two connected connectors`);
  if (issues.length > 0) {
    return finding(11, "warn", `${health.connected.length} of ${enabled.length} enabled connectors are authenticated with a broker connect time within ${staleDays} days; ${issues.join(", ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [connectors, data.appConnectorGroups]);
  return finding(11, status, `All ${health.connected.length} enabled connectors are authenticated with a broker connect time within ${staleDays} days, and every enabled connector group that was read has at least two connected connectors.${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessIdp(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Administration > IdP Configuration (SSO type, SCIM sync, SAML request signing) and Administration > Administrators showing local login and two-factor settings for ZPA admins.";
  return capForUnreadableAll(idpVerdict(data, evidenceNote), [
    dependsOn("ZPA administrator", "GET /administrators", data.administrators),
    dependsOn("SAML attribute", "GET /samlAttribute", data.samlAttributes),
    dependsOn("SCIM group", "GET /scimgroup/idpId/{idpId}", data.scimGroups),
  ], evidenceNote);
}

function idpVerdict(data: ZpaData, evidenceNote: string): ZscalerFinding {
  const idps = data.idpControllers;
  if (idps.error) return unreadableFinding(12, "GET /idp", idps, evidenceNote);
  const enabled = idps.data.filter((idp) => asBoolean(idp.enabled) === true);
  const userIdps = enabled.filter((idp) => asStringList(idp.ssoType).some((type) => type.toUpperCase() === "USER"));
  const adminIdps = enabled.filter((idp) => asStringList(idp.ssoType).some((type) => type.toUpperCase() === "ADMIN"));
  const scimIdps = userIdps.filter((idp) => asBoolean(idp.scimEnabled) === true);
  const unsignedIdps = userIdps.filter((idp) => asBoolean(idp.signSamlRequest) !== true);
  const admins = data.administrators.error ? undefined : data.administrators.data.filter((admin) => asBoolean(admin.isEnabled) !== false);
  const weakAdmins = (admins ?? []).filter((admin) => asBoolean(admin.localLoginDisabled) !== true && asBoolean(admin.twoFactorAuthEnabled) !== true);
  const evidence = {
    idp_count: idps.data.length,
    enabled_idps: enabled.length,
    user_sso_idps: userIdps.map(ruleLabel),
    admin_sso_idps: adminIdps.map(ruleLabel),
    scim_enabled_idps: scimIdps.map(ruleLabel),
    idps_without_signed_saml_requests: unsignedIdps.map(ruleLabel),
    scim_groups: data.scimGroups.error ? null : data.scimGroups.data.length,
    saml_attributes: data.samlAttributes.error ? null : data.samlAttributes.data.length,
    zpa_admins_enabled: admins ? admins.length : null,
    zpa_admins_local_login_without_2fa: truncateList(weakAdmins.map((admin) => asString(admin.username) ?? asString(admin.email) ?? asString(admin.id) ?? "admin")),
    zpa_administrators_surface: `${ZPA_ADMINISTRATORS_PROVENANCE}; it supplements the IdP evidence and is never the sole basis for pass`,
    partial_inventory: [idps, data.administrators, data.samlAttributes, data.scimGroups].some((dataset) => dataset.truncated === true),
  };
  if (idps.data.length === 0) {
    return finding(12, "fail", "Empty inventory: zero identity providers are configured, so ZPA cannot authenticate users through SAML.", evidence, evidenceNote);
  }
  if (userIdps.length === 0) {
    return finding(12, "fail", `${idps.data.length} IdP(s) exist but none is enabled for user SSO (ssoType USER).`, evidence, evidenceNote);
  }
  const issues: string[] = [];
  if (scimIdps.length === 0) issues.push("no user IdP has SCIM provisioning enabled");
  if (unsignedIdps.length > 0) issues.push(`${unsignedIdps.length} user IdP(s) do not sign SAML requests`);
  if (admins === undefined) issues.push(`ZPA administrators could not be read from GET /administrators (${ZPA_ADMINISTRATORS_PROVENANCE})`);
  if (weakAdmins.length > 0) issues.push(`${weakAdmins.length} enabled ZPA administrator(s) allow local login without two-factor authentication`);
  if (adminIdps.length === 0) issues.push("no IdP is enabled for admin SSO");
  const partialNote = `${partialSuffix(idps, "IdP")}${partialSuffix(data.administrators, "ZPA administrator")}${partialSuffix(data.samlAttributes, "SAML attribute")}${partialSuffix(data.scimGroups, "SCIM group")}`;
  if (issues.length > 0) {
    return finding(12, "warn", `${userIdps.length} enabled user IdP(s) found, but: ${issues.join("; ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [idps, data.administrators, data.samlAttributes, data.scimGroups]);
  return finding(12, status, `${userIdps.length} enabled user IdP(s) with SCIM provisioning and signed SAML requests, ${adminIdps.length} admin SSO IdP(s), and every enabled ZPA administrator has local login disabled or two-factor authentication (administrator state read from GET /administrators, ${ZPA_ADMINISTRATORS_PROVENANCE}).${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessTimeoutPolicy(data: ZpaData, maxTimeoutHours: number): ZscalerFinding {
  const evidenceNote = "Export Policy > Timeout Policy showing reauthentication timeout and idle timeout per rule.";
  const rules = data.timeoutRules;
  if (rules.error) return unreadableFinding(13, "GET /policySet/rules/policyType/TIMEOUT_POLICY", rules, evidenceNote);
  const enabled = rules.data.filter(zpaRuleEnabled);
  const maxSeconds = maxTimeoutHours * 3600;
  const excessive = enabled.filter((rule) => {
    const timeout = asNumber(rule.reauthTimeout);
    return timeout !== undefined && (timeout <= 0 || timeout > maxSeconds);
  });
  const undated = enabled.filter((rule) => asNumber(rule.reauthTimeout) === undefined);
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: enabled.length,
    max_allowed_hours: maxTimeoutHours,
    rules: truncateList(rules.data.map((rule) => ({ name: ruleLabel(rule), reauthTimeout: asNumber(rule.reauthTimeout) ?? null, reauthIdleTimeout: asNumber(rule.reauthIdleTimeout) ?? null, disabled: asBoolean(rule.disabled) ?? false }))),
    excessive_rules: truncateList(excessive.map(ruleLabel)),
    rules_without_timeout_value: truncateList(undated.map(ruleLabel)),
    partial_inventory: rules.truncated === true,
  };
  if (rules.data.length === 0) {
    return finding(13, "fail", "Empty inventory: zero timeout policy rules exist, so user sessions are never forced to reauthenticate.", evidence, evidenceNote);
  }
  if (enabled.length === 0) {
    return finding(13, "fail", `${rules.data.length} timeout rules exist but all are disabled.`, evidence, evidenceNote);
  }
  if (excessive.length > 0) {
    return finding(13, "fail", `${excessive.length} enabled timeout rule(s) never expire or exceed ${maxTimeoutHours} hours: ${excessive.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  if (undated.length > 0) {
    return finding(13, "warn", `${undated.length} enabled timeout rule(s) have no reauthTimeout value and cannot be counted as compliant: ${undated.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  return finding(13, capForPartial("pass", rules), `All ${enabled.length} enabled timeout rules reauthenticate within ${maxTimeoutHours} hours.${partialSuffix(rules, "timeout rule")}`, evidence);
}

function assessTrustedNetworks(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Administration > Trusted Networks and identify the access or forwarding rules that reference them; if no on-premises detection is required, document that decision.";
  return capForUnreadableAll(trustedNetworksVerdict(data, evidenceNote), [
    dependsOn("access rule", "GET /policySet/rules/policyType/ACCESS_POLICY", data.accessRules),
    dependsOn("forwarding rule", "GET /policySet/rules/policyType/CLIENT_FORWARDING_POLICY", data.forwardingRules),
  ], evidenceNote);
}

function trustedNetworksVerdict(data: ZpaData, evidenceNote: string): ZscalerFinding {
  const networks = data.trustedNetworks;
  if (networks.error) return unreadableFinding(15, "GET /network", networks, evidenceNote);
  const referencing = [
    ...(data.accessRules.error ? [] : ruleUsesOperand(data.accessRules.data.filter(zpaRuleEnabled), "TRUSTED_NETWORK")),
    ...(data.forwardingRules.error ? [] : ruleUsesOperand(data.forwardingRules.data.filter(zpaRuleEnabled), "TRUSTED_NETWORK")),
  ];
  const evidence = {
    trusted_network_count: networks.data.length,
    networks: truncateList(networks.data.map(ruleLabel)),
    rules_referencing_trusted_networks: truncateList(referencing.map(ruleLabel)),
    policy_rules_readable: !data.accessRules.error && !data.forwardingRules.error,
    partial_inventory: [networks, data.accessRules, data.forwardingRules].some((dataset) => dataset.truncated === true),
  };
  const partialNote = `${partialSuffix(networks, "trusted network")}${partialSuffix(data.accessRules, "access rule")}${partialSuffix(data.forwardingRules, "forwarding rule")}`;
  if (networks.data.length === 0) {
    return finding(15, "manual", "Not configured: zero trusted networks are defined, so on-network detection is not in use; confirm whether the architecture requires it.", evidence, evidenceNote);
  }
  if (data.accessRules.error && data.forwardingRules.error) {
    return finding(15, "manual", `${networks.data.length} trusted networks exist but policy rules could not be read, so their enforcement is unverified.`, evidence, evidenceNote);
  }
  if (referencing.length === 0) {
    return finding(15, "warn", `${networks.data.length} trusted networks are defined but no enabled access or forwarding rule references a TRUSTED_NETWORK condition.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [networks, data.accessRules, data.forwardingRules]);
  return finding(15, status, `${networks.data.length} trusted networks are referenced by ${referencing.length} enabled policy rule(s).${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessServiceEdges(data: ZpaData, staleDays: number): ZscalerFinding {
  const evidenceNote = "If Private Service Edges are deployed, export Administration > Service Edges with control channel status; otherwise document reliance on Zscaler-hosted public service edges.";
  return capForUnreadableAll(serviceEdgesVerdict(data, staleDays, evidenceNote), [dependsOn("service edge group", "GET /serviceEdgeGroup", data.serviceEdgeGroups)], evidenceNote);
}

function serviceEdgesVerdict(data: ZpaData, staleDays: number, evidenceNote: string): ZscalerFinding {
  const edges = data.serviceEdges;
  if (edges.error) return unreadableFinding(21, "GET /serviceEdge", edges, evidenceNote);
  const enabled = edges.data.filter((item) => asBoolean(item.enabled) !== false);
  const health = connectorHealth(enabled, data.now, staleDays);
  const evidence = {
    service_edge_count: edges.data.length,
    enabled: enabled.length,
    connected: health.connected.length,
    stale_connector_days: staleDays,
    stale: truncateList(health.stale.map(ruleLabel)),
    authenticated_without_connect_time: truncateList(health.undated.map(ruleLabel)),
    disconnected: truncateList(health.disconnected.map(ruleLabel)),
    service_edge_groups: data.serviceEdgeGroups.error ? null : data.serviceEdgeGroups.data.length,
    partial_inventory: edges.truncated === true || data.serviceEdgeGroups.truncated === true,
  };
  const partialNote = `${partialSuffix(edges, "service edge")}${partialSuffix(data.serviceEdgeGroups, "service edge group")}`;
  if (edges.data.length === 0) {
    return finding(21, "manual", "Not applicable or not configured: zero private service edges are enrolled, so the tenant relies on Zscaler public service edges; document that decision.", evidence, evidenceNote);
  }
  if (health.connected.length + health.stale.length + health.undated.length === 0) {
    return finding(21, "fail", `None of the ${enabled.length} enabled private service edges reports controlChannelStatus ${ZPA_CONNECTED_STATUS}.`, evidence, evidenceNote);
  }
  const issues = connectorHealthIssues(health, staleDays);
  if (issues.length > 0) {
    return finding(21, "warn", `${health.connected.length} of ${enabled.length} enabled private service edges are authenticated with a broker connect time within ${staleDays} days; ${issues.join(", ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [edges, data.serviceEdgeGroups]);
  return finding(21, status, `All ${health.connected.length} enabled private service edges are authenticated with a broker connect time within ${staleDays} days.${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function assessForwardingPolicy(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Policy > Client Forwarding Policy and justify every BYPASS rule; confirm the default action forwards traffic through ZPA.";
  const rules = data.forwardingRules;
  if (rules.error) return unreadableFinding(22, "GET /policySet/rules/policyType/CLIENT_FORWARDING_POLICY", rules, evidenceNote);
  const enabled = rules.data.filter(zpaRuleEnabled);
  const bypass = enabled.filter((rule) => (asString(rule.action) ?? "").toUpperCase() === "BYPASS");
  const unconditionalBypass = bypass.filter((rule) => asRecordArray(rule.conditions).length === 0);
  const evidence = {
    rule_count: rules.data.length,
    enabled_rules: enabled.length,
    bypass_rules: truncateList(bypass.map(ruleLabel)),
    unconditional_bypass_rules: truncateList(unconditionalBypass.map(ruleLabel)),
    rules: truncateList(rules.data.map((rule) => ({ name: ruleLabel(rule), action: asString(rule.action) ?? null, disabled: asBoolean(rule.disabled) ?? false, operands: ruleOperandTypes(rule) }))),
    partial_inventory: rules.truncated === true,
  };
  if (rules.data.length === 0) {
    return finding(22, "manual", "Empty inventory: zero client forwarding rules exist, so the platform default applies; confirm in the portal that the default forwards all application traffic through ZPA.", evidence, evidenceNote);
  }
  if (unconditionalBypass.length > 0) {
    return finding(22, "fail", `${unconditionalBypass.length} enabled BYPASS rule(s) have no conditions and send all matching traffic around ZPA: ${unconditionalBypass.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  if (bypass.length > 0) {
    return finding(22, "warn", `${bypass.length} enabled BYPASS rule(s) exist and need documented justification: ${bypass.map(ruleLabel).join(", ")}.`, evidence, evidenceNote);
  }
  return finding(22, capForPartial("pass", rules), `${enabled.length} enabled forwarding rules and none bypasses ZPA.${partialSuffix(rules, "forwarding rule")}`, evidence);
}

function assessEmergencyAccess(data: ZpaData): ZscalerFinding {
  const evidenceNote = "Export Administration > Emergency Access showing each break-glass user, activation state, and last login, plus the procedure that governs activation.";
  const users = data.emergencyAccessUsers;
  if (users.error) return unreadableFinding(23, "GET /emergencyAccess/users", users, evidenceNote);
  const active = users.data.filter((user) => /ACTIV/i.test(asString(user.userStatus) ?? "") && !/DEACTIV|INACTIV/i.test(asString(user.userStatus) ?? ""));
  const undated = users.data.filter((user) => !epochToDate(user.lastLoginTime));
  const evidence = {
    emergency_user_count: users.data.length,
    active_users: truncateList(active.map((user) => asString(user.emailId) ?? asString(user.userId) ?? "user")),
    users_without_last_login: undated.length,
    users: truncateList(users.data.map((user) => ({ email: asString(user.emailId) ?? null, status: asString(user.userStatus) ?? null, lastLoginTime: asString(user.lastLoginTime) ?? null }))),
    partial_inventory: users.truncated === true,
  };
  if (users.data.length === 0) {
    return finding(23, "manual", "Not configured: zero emergency access users exist; confirm the documented break-glass procedure covers ZPA outages without them.", evidence, evidenceNote);
  }
  const partialNote = partialSuffix(users, "emergency access user");
  if (active.length > 0) {
    return finding(23, "warn", `${active.length} of ${users.data.length} emergency access users are currently active and should be deactivated when the incident closes: ${active.map((user) => asString(user.emailId) ?? "user").join(", ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartial("pass", users);
  return finding(23, status, `${users.data.length} emergency access users are defined and none is currently active (${undated.length} have never logged in).${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

function certificateExpiry(items: JsonRecord[], now: Date, warnDays: number): { expired: string[]; expiring: string[]; undated: string[]; healthy: number } {
  const expired: string[] = [];
  const expiring: string[] = [];
  const undated: string[] = [];
  let healthy = 0;
  for (const item of items) {
    const validTo = certificateValidTo(item);
    const label = ruleLabel(item);
    if (!validTo) {
      undated.push(label);
    } else if (validTo.getTime() <= now.getTime()) {
      expired.push(label);
    } else if (daysBetween(validTo, now) <= warnDays) {
      expiring.push(label);
    } else {
      healthy += 1;
    }
  }
  return { expired, expiring, undated, healthy };
}

function assessCertificates(data: ZpaData, warnDays: number): ZscalerFinding {
  const evidenceNote = "Export Administration > Enrollment Certificates and Browser Access Certificates with validity dates, and confirm the ZIA intermediate CA certificate expiry under Policy > SSL Inspection (not part of the verified read surface).";
  return capForUnreadableAll(certificatesVerdict(data, warnDays, evidenceNote), [dependsOn("browser access certificate", "GET /clientlessCertificate/issued", data.browserAccessCertificates)], evidenceNote);
}

function certificatesVerdict(data: ZpaData, warnDays: number, evidenceNote: string): ZscalerFinding {
  const enrollment = data.enrollmentCertificates;
  if (enrollment.error) return unreadableFinding(24, "GET /enrollmentCert", enrollment, evidenceNote);
  const enrollmentExpiry = certificateExpiry(enrollment.data, data.now, warnDays);
  const baItems = data.browserAccessCertificates.error ? [] : data.browserAccessCertificates.data;
  const baExpiry = certificateExpiry(baItems, data.now, warnDays);
  const evidence = {
    enrollment_certificates: enrollment.data.length,
    enrollment_expired: enrollmentExpiry.expired,
    enrollment_expiring_within_days: enrollmentExpiry.expiring,
    enrollment_without_validity: enrollmentExpiry.undated,
    browser_access_certificates: data.browserAccessCertificates.error ? null : baItems.length,
    browser_access_expired: baExpiry.expired,
    browser_access_expiring_within_days: baExpiry.expiring,
    browser_access_without_validity: baExpiry.undated,
    warn_days: warnDays,
    partial_inventory: enrollment.truncated === true || data.browserAccessCertificates.truncated === true,
  };
  const partialNote = `${partialSuffix(enrollment, "enrollment certificate")}${partialSuffix(data.browserAccessCertificates, "browser access certificate")}`;
  if (enrollment.data.length === 0) {
    return finding(24, "manual", "Empty inventory: zero enrollment certificates were returned although every ZPA tenant has Zscaler-managed enrollment certificates, so the credential is probably scoped.", evidence, evidenceNote);
  }
  const expired = [...enrollmentExpiry.expired, ...baExpiry.expired];
  const expiring = [...enrollmentExpiry.expiring, ...baExpiry.expiring];
  const undated = [...enrollmentExpiry.undated, ...baExpiry.undated];
  if (expired.length > 0) {
    return finding(24, "fail", `${expired.length} certificate(s) have expired: ${expired.join(", ")}.`, evidence, evidenceNote);
  }
  if (expiring.length > 0 || undated.length > 0 || data.browserAccessCertificates.error) {
    const issues: string[] = [];
    if (expiring.length > 0) issues.push(`${expiring.length} expire within ${warnDays} days`);
    if (undated.length > 0) issues.push(`${undated.length} have no validToInEpochSec or validTo and cannot be counted as valid`);
    if (data.browserAccessCertificates.error) issues.push("browser access certificates could not be read");
    return finding(24, "warn", `${enrollmentExpiry.healthy + baExpiry.healthy} certificates are valid beyond ${warnDays} days, but ${issues.join("; ")}.${partialNote}`, evidence, evidenceNote);
  }
  const status = capForPartialAll("pass", [enrollment, data.browserAccessCertificates]);
  return finding(24, status, `All ${enrollmentExpiry.healthy} enrollment and ${baExpiry.healthy} browser access certificates that were read are valid for more than ${warnDays} days.${partialNote}`, evidence, status === "warn" ? evidenceNote : undefined);
}

export interface ZpaAssessmentOptions {
  certExpiryWarnDays?: number;
  staleConnectorDays?: number;
  maxTimeoutHours?: number;
}

export function assessZpaData(data: ZpaData, options: ZpaAssessmentOptions = {}): ZscalerAssessmentResult {
  const warnDays = clampNumber(options.certExpiryWarnDays, DEFAULT_CERT_EXPIRY_WARN_DAYS, 1, 3650);
  const staleDays = clampNumber(options.staleConnectorDays, DEFAULT_STALE_CONNECTOR_DAYS, 1, 3650);
  const maxTimeoutHours = clampNumber(options.maxTimeoutHours, DEFAULT_MAX_TIMEOUT_HOURS, 1, 8760);
  const findings = [
    assessSegmentation(data),
    assessAccessPolicies(data),
    assessPosture(data),
    assessConnectors(data, staleDays),
    assessIdp(data),
    assessTimeoutPolicy(data, maxTimeoutHours),
    assessTrustedNetworks(data),
    assessServiceEdges(data, staleDays),
    assessForwardingPolicy(data),
    assessEmergencyAccess(data),
    assessCertificates(data, warnDays),
  ];
  const datasets: Array<[string, CollectedDataset<unknown>]> = [
    ["application", data.applicationSegments],
    ["segmentGroup", data.segmentGroups],
    ["policySet/rules/policyType/ACCESS_POLICY", data.accessRules],
    ["policySet/rules/policyType/TIMEOUT_POLICY", data.timeoutRules],
    ["policySet/rules/policyType/CLIENT_FORWARDING_POLICY", data.forwardingRules],
    ["policySet/rules/policyType/ISOLATION_POLICY", data.isolationRules],
    ["appConnectorGroup", data.appConnectorGroups],
    ["connector", data.appConnectors],
    ["serviceEdgeGroup", data.serviceEdgeGroups],
    ["serviceEdge", data.serviceEdges],
    ["posture", data.postureProfiles],
    ["network", data.trustedNetworks],
    ["idp", data.idpControllers],
    ["samlAttribute", data.samlAttributes],
    ["scimgroup", data.scimGroups],
    ["enrollmentCert", data.enrollmentCertificates],
    ["clientlessCertificate/issued", data.browserAccessCertificates],
    ["emergencyAccess/users", data.emergencyAccessUsers],
    ["administrators", data.administrators],
  ];
  return {
    title: "Zscaler ZPA zero trust access",
    area: "zpa",
    summary: {
      application_segments: data.applicationSegments.data.length,
      segment_groups: data.segmentGroups.data.length,
      access_rules: data.accessRules.data.length,
      timeout_rules: data.timeoutRules.data.length,
      forwarding_rules: data.forwardingRules.data.length,
      isolation_rules: data.isolationRules.data.length,
      app_connectors: data.appConnectors.data.length,
      service_edges: data.serviceEdges.data.length,
      posture_profiles: data.postureProfiles.data.length,
      trusted_networks: data.trustedNetworks.data.length,
      idps: data.idpControllers.data.length,
      administrators: data.administrators.data.length,
      status_counts: summarizeFindingStatuses(findings),
    },
    findings,
    errors: datasets.flatMap(([label, dataset]) => datasetErrors(label, dataset)),
    truncated: datasets.flatMap(([label, dataset]) => datasetTruncations(label, dataset)),
  };
}

export async function assessZpa(client: ZpaReadClient | undefined, options: ZpaAssessmentOptions = {}): Promise<ZscalerAssessmentResult> {
  if (!client) {
    return notConfiguredAssessment("zpa", "Zscaler ZPA zero trust access", "zpa", [8, 9, 10, 11, 12, 13, 15, 21, 22, 23, 24]);
  }
  return assessZpaData(await collectZpaData(client), options);
}

// Exact keys the published ZIA and ZPA schemas document as credentials (kerberosPwd on GET /authSettings,
// scimSharedSecret on GET .../idp, preSharedKey on VPN credentials, the enrollment certificate key material),
// plus the documented free-text comment fields on VPN credentials and GRE tunnels, which operators use to
// store pre-shared keys.
const SENSITIVE_EXPORT_KEYS = new Set([
  "authenticationToken", "clientSecret", "preSharedKey", "password", "privateKey", "zrsaencryptedprivatekey",
  "zrsaencryptedsessionkey", "tmpPassword", "kerberosPwd", "scimSharedSecret", "comment", "comments",
]);
// Any other key whose normalized name (lowercase, alphanumerics only) reads like credential material is redacted
// as well, so a field this module does not know about never ships in cleartext.
const SENSITIVE_KEY_PATTERN = /password|passwd|pwd|secret|token|passphrase|credential|private|community|preshared|apikey|keymaterial|sharedkey|sessionkey|encryptedkey|signingkey|accesskey|key$/;
// Normalized names that match the pattern but carry no secret in the published schemas or in this module's
// evidence objects.
const BENIGN_SECRET_LIKE_KEYS = new Set([
  "ispasswordloginallowed", "ispasswordexpired", "passwordexpirationenabled", "passwordexpirydays", "passwordexpiry",
  "passwordstrength", "passwordloginadmins", "blockpasswordprotectedarchivefiles", "blockpasswordprotectedarchives", "tokentype",
  "scimsharedsecretexists", "privatekeypresent", "publickey", "privateip", "vpncredentials", "vpncredentialinventorypartial",
]);

function isSensitiveExportKey(key: string): boolean {
  if (SENSITIVE_EXPORT_KEYS.has(key)) return true;
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (BENIGN_SECRET_LIKE_KEYS.has(normalized)) return false;
  return SENSITIVE_KEY_PATTERN.test(normalized);
}

export function redactForExport(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactForExport);
  const object = asObject(value);
  if (!object) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    const carriesValue = entry !== null && entry !== undefined && typeof entry !== "boolean";
    output[key] = isSensitiveExportKey(key) && carriesValue ? "[REDACTED]" : redactForExport(entry);
  }
  return output;
}

export interface ZscalerExportOptions extends ZpaAssessmentOptions {
  outputDir?: string;
  maxSuperAdmins?: number;
  maxSslExemptions?: number;
}

function statusCell(status: ZscalerFindingStatus): string {
  return statusLabel(status);
}

function frameworkMapping(item: ZscalerFinding, framework: ZscalerFramework): string {
  return ZSCALER_CONTROLS[item.control]?.mappings[framework] ?? "";
}

function renderExecutiveSummary(findings: ZscalerFinding[], access: ZscalerAccessCheckResult, generatedAt: string): string {
  const counts = summarizeFindingStatuses(findings);
  const prioritized = [...findings]
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
  return [
    "# Zscaler Security Assessment: Executive Summary",
    "",
    `Generated: ${generatedAt}`,
    "",
    `Access check: ${access.status} (ZIA ${access.products.zia}, ZPA ${access.products.zpa})`,
    "",
    "## Results",
    "",
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    `- Total controls: ${findings.length} of ${Object.keys(ZSCALER_CONTROLS).length}`,
    "",
    "## Priority findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.map((item) => `- ${item.id} ${item.title} (${item.severity}, ${statusCell(item.status)}): ${item.summary}`)
      : ["- No failing or warning findings."]),
    "",
    "## Manual evidence required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id} ${item.title}: ${item.manualEvidence ?? item.summary}`),
    "",
  ].join("\n");
}

function renderComplianceMatrix(findings: ZscalerFinding[]): string {
  const header = ["Control", "Title", "Status", ...FRAMEWORK_ORDER];
  const rows = findings.map((item) => [item.id, item.title, statusCell(item.status), ...FRAMEWORK_ORDER.map((framework) => frameworkMapping(item, framework))]);
  return [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
    "",
  ].join("\n");
}

function renderFrameworkReport(title: string, framework: ZscalerFramework, findings: ZscalerFinding[], generatedAt: string): string {
  const counts = summarizeFindingStatuses(findings);
  return [
    `# ${title}`,
    "",
    `Generated: ${generatedAt}`,
    "",
    `Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    `| Control | ${framework} requirement | Status | Summary |`,
    "| --- | --- | --- | --- |",
    ...findings.map((item) => `| ${item.id} ${item.title} | ${frameworkMapping(item, framework)} | ${statusCell(item.status)} | ${item.summary.replace(/\|/g, "/")} |`),
    "",
  ].join("\n");
}

function renderQuickReference(outputDir: string, findings: ZscalerFinding[], errors: string[], generatedAt: string): string {
  const counts = summarizeFindingStatuses(findings);
  return [
    "# Zscaler Audit Bundle Quick Reference",
    "",
    `Generated: ${generatedAt}`,
    `Bundle directory: ${basename(outputDir)}`,
    "",
    "## Layout",
    "",
    "- core_data/: raw API snapshots (secrets redacted) per assessment area plus the access check",
    "- analysis/findings.json: every normalized finding with evidence and framework mappings",
    "- analysis/<area>.json: per-area summaries",
    "- compliance/executive_summary.md and compliance/unified_compliance_matrix.md",
    "- compliance/<framework>/: one report per framework in the spec mapping table",
    ...(errors.length > 0 ? ["- _errors.log: collection failures that downgraded verdicts to manual"] : []),
    "",
    "## Results",
    "",
    `Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "## Verdict semantics",
    "",
    "- pass: the documented enabling flags were read and satisfy the control",
    "- warn: partially satisfied, partial inventory, or undated records",
    "- fail: a documented flag or inventory contradicts the control",
    "- manual: unreadable endpoint, unconfigured product, or evidence the API does not expose; the summary names what to collect",
    "",
  ].join("\n");
}

export async function exportZscalerAuditBundle(clients: ZscalerClients, options: ZscalerExportOptions = {}): Promise<ZscalerAuditBundleResult> {
  const root = resolve(options.outputDir ?? DEFAULT_OUTPUT_DIR);
  const generatedAt = new Date().toISOString();
  const tenantLabel = safeDirName(clients.zia?.getResolvedConfig().cloud ?? clients.zpa?.getResolvedConfig().customerId ?? "zscaler");
  const outputDir = await nextAvailableAuditDir(root, `zscaler-audit-${tenantLabel}-${generatedAt.slice(0, 10)}`);

  const access = await checkZscalerAccess(clients);
  const ziaAccessData = clients.zia ? await collectZiaAccessControlData(clients.zia) : undefined;
  const ziaPolicyData = clients.zia ? await collectZiaPolicyData(clients.zia) : undefined;
  const zpaData = clients.zpa ? await collectZpaData(clients.zpa) : undefined;

  const assessments: ZscalerAssessmentResult[] = [
    ziaAccessData && clients.zia
      ? assessZiaAccessControlData(ziaAccessData, { maxSuperAdmins: options.maxSuperAdmins })
      : await assessZiaAccessControl(undefined),
    ziaPolicyData ? assessZiaPolicyData(ziaPolicyData, { maxSslExemptions: options.maxSslExemptions }) : await assessZiaPolicy(undefined),
    zpaData ? assessZpaData(zpaData, options) : await assessZpa(undefined),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings).sort((left, right) => left.control - right.control);
  const errors = [
    ...access.surfaces.filter((surface) => surface.status === "not_readable").map((surface) => `access_check ${surface.product} ${surface.name}: ${surface.error ?? "unreadable"}`),
    ...assessments.flatMap((assessment) => assessment.errors.map((error) => `${assessment.area}: ${error}`)),
    ...assessments.flatMap((assessment) => assessment.truncated.map((note) => `${assessment.area} partial: ${note}`)),
  ];

  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(redactForExport(access)));
  await writeSecureTextFile(outputDir, "core_data/zia_access_control.json", serializeJson(redactForExport(ziaAccessData ?? { configured: false })));
  await writeSecureTextFile(outputDir, "core_data/zia_policy.json", serializeJson(redactForExport(ziaPolicyData ?? { configured: false })));
  await writeSecureTextFile(outputDir, "core_data/zpa.json", serializeJson(redactForExport(zpaData ?? { configured: false })));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(redactForExport(findings)));
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    generated_at: generatedAt,
    access_status: access.status,
    products: access.products,
    status_counts: summarizeFindingStatuses(findings),
    controls_assessed: findings.length,
    controls_in_spec: Object.keys(ZSCALER_CONTROLS).length,
  }));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson({ title: assessment.title, summary: assessment.summary, errors: assessment.errors, truncated: assessment.truncated }));
  }
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", renderExecutiveSummary(findings, access, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", renderComplianceMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, report.path, renderFrameworkReport(report.title, report.framework, findings, generatedAt));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", renderQuickReference(outputDir, findings, errors, generatedAt));
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
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
  zia_cloud?: string;
  zia_base_url?: string;
  zia_api_key?: string;
  zia_username?: string;
  zia_password?: string;
  zpa_cloud?: string;
  zpa_base_url?: string;
  zpa_client_id?: string;
  zpa_client_secret?: string;
  zpa_customer_id?: string;
  config_file?: string;
  timeout_seconds?: number;
  max_retries?: number;
};

type AccessControlArgs = AuthArgs & { max_super_admins?: number };

type PolicyArgs = AuthArgs & { max_ssl_exemptions?: number };

type ZpaArgs = AuthArgs & {
  cert_expiry_warn_days?: number;
  stale_connector_days?: number;
  max_timeout_hours?: number;
};

type ExportArgs = AccessControlArgs & PolicyArgs & ZpaArgs & { output_dir?: string };

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    zia_cloud: asString(value.zia_cloud),
    zia_base_url: asString(value.zia_base_url),
    zia_api_key: asString(value.zia_api_key),
    zia_username: asString(value.zia_username),
    zia_password: asString(value.zia_password),
    zpa_cloud: asString(value.zpa_cloud),
    zpa_base_url: asString(value.zpa_base_url),
    zpa_client_id: asString(value.zpa_client_id),
    zpa_client_secret: asString(value.zpa_client_secret),
    zpa_customer_id: asString(value.zpa_customer_id),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
    max_retries: asNumber(value.max_retries),
  };
}

function normalizeAccessControlArgs(args: unknown): AccessControlArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_super_admins: asNumber(value.max_super_admins) };
}

function normalizePolicyArgs(args: unknown): PolicyArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_ssl_exemptions: asNumber(value.max_ssl_exemptions) };
}

function normalizeZpaArgs(args: unknown): ZpaArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    cert_expiry_warn_days: asNumber(value.cert_expiry_warn_days),
    stale_connector_days: asNumber(value.stale_connector_days),
    max_timeout_hours: asNumber(value.max_timeout_hours),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAccessControlArgs(args),
    ...normalizePolicyArgs(args),
    ...normalizeZpaArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

export function createZscalerClients(args: AuthArgs, env: NodeJS.ProcessEnv = process.env): ZscalerClients {
  const config = resolveZscalerConfiguration(args as JsonRecord, env);
  return {
    config,
    zia: config.zia ? new ZiaApiClient(config.zia, { timeoutMs: config.timeoutMs, maxRetries: config.maxRetries }) : undefined,
    zpa: config.zpa ? new ZpaApiClient(config.zpa, { timeoutMs: config.timeoutMs, maxRetries: config.maxRetries }) : undefined,
  };
}

async function withClients<T>(args: AuthArgs, run: (clients: ZscalerClients) => Promise<T>): Promise<T> {
  const clients = createZscalerClients(args);
  try {
    return await run(clients);
  } finally {
    await clients.zia?.logout();
  }
}

const authParams = {
  zia_cloud: Type.Optional(Type.String({ description: "ZIA cloud name (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalerbeta, zscalergov, zscalerten). Defaults to ZIA_CLOUD." })),
  zia_base_url: Type.Optional(Type.String({ description: "Explicit ZIA API base URL such as https://zsapi.zscalerthree.net/api/v1. Defaults to the cloud mapping." })),
  zia_api_key: Type.Optional(Type.String({ description: "ZIA Cloud Service API key. Defaults to ZIA_API_KEY." })),
  zia_username: Type.Optional(Type.String({ description: "ZIA administrator login name. Defaults to ZIA_USERNAME." })),
  zia_password: Type.Optional(Type.String({ description: "ZIA administrator password. Defaults to ZIA_PASSWORD." })),
  zpa_cloud: Type.Optional(Type.String({ description: "ZPA cloud (PRODUCTION, ZPATWO, BETA, GOV, GOVUS, PREVIEW). Defaults to ZPA_CLOUD or PRODUCTION." })),
  zpa_base_url: Type.Optional(Type.String({ description: "Explicit ZPA base URL such as https://config.private.zscaler.com. Defaults to the cloud mapping." })),
  zpa_client_id: Type.Optional(Type.String({ description: "ZPA API client ID. Defaults to ZPA_CLIENT_ID." })),
  zpa_client_secret: Type.Optional(Type.String({ description: "ZPA API client secret. Defaults to ZPA_CLIENT_SECRET." })),
  zpa_customer_id: Type.Optional(Type.String({ description: "ZPA customer ID. Defaults to ZPA_CUSTOMER_ID." })),
  config_file: Type.Optional(Type.String({ description: "YAML config file. Defaults to ZSCALER_CONFIG_FILE or ~/.zscaler/zscaler.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
  max_retries: Type.Optional(Type.Number({ description: "Retries for 429/5xx responses, honoring Retry-After. Defaults to 3.", default: 3 })),
};

export function registerZscalerTools(pi: any): void {
  pi.registerTool({
    name: "zscaler_check_access",
    label: "Check Zscaler audit access",
    description:
      "Validate read-only Zscaler access: ZIA (admin users, roles, auth settings, audit log report, URL filtering, firewall, DLP, SSL inspection, ATP, locations) and ZPA (application segments, segment groups, access policy, connectors, IdP, posture, administrators). Products without credentials are reported as not configured.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await withClients(args, (clients) => checkZscalerAccess(clients));
        return textResult(formatAccessCheckText(result), { tool: "zscaler_check_access", ...result });
      } catch (error) {
        return errorResult(`Zscaler access check failed: ${errorMessage(error)}`, { tool: "zscaler_check_access" });
      }
    },
  });

  pi.registerTool({
    name: "zscaler_assess_zia_access_control",
    label: "Assess ZIA administrative access control",
    description:
      "Assess ZIA administrator security (spec controls 6, 7, 14): password-login bypasses and MFA evidence, Super Admin concentration and role scoping, and admin audit log export via NSS feeds. Unreadable or empty surfaces render manual, never pass.",
    parameters: Type.Object({
      ...authParams,
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Admin count before failing. Defaults to 5.", default: 5 })),
    }),
    prepareArguments: normalizeAccessControlArgs,
    async execute(_toolCallId: string, args: AccessControlArgs) {
      try {
        const result = await withClients(args, (clients) => assessZiaAccessControl(clients.zia, { maxSuperAdmins: args.max_super_admins }));
        return textResult(formatAssessmentText(result), { tool: "zscaler_assess_zia_access_control", ...result });
      } catch (error) {
        return errorResult(`ZIA access control assessment failed: ${errorMessage(error)}`, { tool: "zscaler_assess_zia_access_control" });
      }
    },
  });

  pi.registerTool({
    name: "zscaler_assess_zia_policy",
    label: "Assess ZIA security policy",
    description:
      "Assess ZIA policy posture (spec controls 1-5, 16-20, 25): URL filtering, cloud firewall, DLP, SSL inspection and exemptions, sandbox, bandwidth control, browser isolation, locations and sub-locations with GRE/VPN, cloud app control, DNS control, and the ATP/malware baseline. Empty inventories fail or render manual per control intent; unreadable surfaces never pass.",
    parameters: Type.Object({
      ...authParams,
      max_ssl_exemptions: Type.Optional(Type.Number({ description: "Maximum acceptable SSL inspection exempted URLs before warning. Defaults to 50.", default: 50 })),
    }),
    prepareArguments: normalizePolicyArgs,
    async execute(_toolCallId: string, args: PolicyArgs) {
      try {
        const result = await withClients(args, (clients) => assessZiaPolicy(clients.zia, { maxSslExemptions: args.max_ssl_exemptions }));
        return textResult(formatAssessmentText(result), { tool: "zscaler_assess_zia_policy", ...result });
      } catch (error) {
        return errorResult(`ZIA policy assessment failed: ${errorMessage(error)}`, { tool: "zscaler_assess_zia_policy" });
      }
    },
  });

  pi.registerTool({
    name: "zscaler_assess_zpa",
    label: "Assess ZPA zero trust access",
    description:
      "Assess ZPA posture (spec controls 8-13, 15, 21-24): application segmentation, access policy criteria, posture enforcement, app connector health and redundancy, IdP/SAML/SCIM and admin login hardening, timeout policy, trusted networks, private service edges, client forwarding bypasses, emergency access, and certificate expiry. Renders manual when ZPA credentials are absent.",
    parameters: Type.Object({
      ...authParams,
      cert_expiry_warn_days: Type.Optional(Type.Number({ description: "Warn when a certificate expires within this many days. Defaults to 30.", default: 30 })),
      stale_connector_days: Type.Optional(Type.Number({ description: "Days since last broker connect before a connector is reported stale. Defaults to 30.", default: 30 })),
      max_timeout_hours: Type.Optional(Type.Number({ description: "Maximum acceptable reauthentication timeout in hours. Defaults to 24.", default: 24 })),
    }),
    prepareArguments: normalizeZpaArgs,
    async execute(_toolCallId: string, args: ZpaArgs) {
      try {
        const result = await withClients(args, (clients) => assessZpa(clients.zpa, {
          certExpiryWarnDays: args.cert_expiry_warn_days,
          staleConnectorDays: args.stale_connector_days,
          maxTimeoutHours: args.max_timeout_hours,
        }));
        return textResult(formatAssessmentText(result), { tool: "zscaler_assess_zpa", ...result });
      } catch (error) {
        return errorResult(`ZPA assessment failed: ${errorMessage(error)}`, { tool: "zscaler_assess_zpa" });
      }
    },
  });

  pi.registerTool({
    name: "zscaler_export_audit_bundle",
    label: "Export Zscaler audit bundle",
    description:
      "Run every Zscaler assessment and write an evidence bundle: core_data/ raw snapshots (secrets redacted), analysis/ findings, compliance/ executive summary, unified matrix, and per-framework reports (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP), QUICK_REFERENCE.md, _errors.log on partial collection, and a zip named after the allocated directory. Reruns never overwrite a prior bundle.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: "Root directory for bundles. Defaults to ./export/zscaler.", default: DEFAULT_OUTPUT_DIR })),
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Admin count. Defaults to 5.", default: 5 })),
      max_ssl_exemptions: Type.Optional(Type.Number({ description: "Maximum acceptable SSL exempted URLs. Defaults to 50.", default: 50 })),
      cert_expiry_warn_days: Type.Optional(Type.Number({ description: "Certificate expiry warning window in days. Defaults to 30.", default: 30 })),
      stale_connector_days: Type.Optional(Type.Number({ description: "Stale connector threshold in days. Defaults to 30.", default: 30 })),
      max_timeout_hours: Type.Optional(Type.Number({ description: "Maximum acceptable reauthentication timeout in hours. Defaults to 24.", default: 24 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const result = await withClients(args, (clients) => exportZscalerAuditBundle(clients, {
          outputDir: args.output_dir,
          maxSuperAdmins: args.max_super_admins,
          maxSslExemptions: args.max_ssl_exemptions,
          certExpiryWarnDays: args.cert_expiry_warn_days,
          staleConnectorDays: args.stale_connector_days,
          maxTimeoutHours: args.max_timeout_hours,
        }));
        return textResult(
          [
            "Zscaler audit bundle exported",
            `Directory: ${result.outputDir}`,
            `Archive: ${result.zipPath}`,
            `Files: ${result.fileCount}`,
            `Findings: ${result.findingCount}`,
            `Collection errors: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
          ].join("\n"),
          { tool: "zscaler_export_audit_bundle", ...result },
        );
      } catch (error) {
        return errorResult(`Zscaler audit bundle export failed: ${errorMessage(error)}`, { tool: "zscaler_export_audit_bundle" });
      }
    },
  });
}
