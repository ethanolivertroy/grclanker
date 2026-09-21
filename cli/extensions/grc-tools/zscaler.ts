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
    return { raw: rawText.slice(0, 240) };
  }
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
  listUrlFilteringRules(): Promise<JsonRecord[]>;
  listFirewallFilteringRules(): Promise<JsonRecord[]>;
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
  listGreTunnels(): Promise<JsonRecord[]>;
  listVpnCredentials(): Promise<JsonRecord[]>;
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
      const detail = payloadErrorSummary(parseJsonText(rawText)) ?? rawText.slice(0, 240);
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
      const detail = payloadErrorSummary(payload) ?? rawText.slice(0, 240);
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

  async getPaged(path: string, query: JsonRecord = {}): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let page = 1;
    for (; page <= ZIA_MAX_PAGES; page += 1) {
      const pageItems = await this.getList(path, { ...query, page, pageSize: ZIA_PAGE_SIZE });
      items.push(...pageItems);
      if (pageItems.length < ZIA_PAGE_SIZE) {
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

  getAuditLogReportStatus(): Promise<JsonRecord> {
    return this.get("/auditlogEntryReport");
  }

  listNssFeeds(): Promise<JsonRecord[]> {
    return this.getList("/nssFeeds");
  }

  listUrlFilteringRules(): Promise<JsonRecord[]> {
    return this.getList("/urlFilteringRules");
  }

  listFirewallFilteringRules(): Promise<JsonRecord[]> {
    return this.getList("/firewallFilteringRules");
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

  listGreTunnels(): Promise<JsonRecord[]> {
    return this.getList("/greTunnels");
  }

  listVpnCredentials(): Promise<JsonRecord[]> {
    return this.getList("/vpnCredentials");
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

function datasetTruncations(label: string, dataset: CollectedDataset<unknown>): string[] {
  if (!dataset.truncated) return [];
  const pages = dataset.total !== undefined ? `${dataset.seen ?? 0} of ${dataset.total} pages` : `${dataset.seen ?? 0} pages`;
  return [`${label}: only ${pages} were read, so the inventory is partial and absence of a record cannot support a pass`];
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
  return dataset.truncated ? ` The ${label} inventory is partial (${dataset.data.length} records over ${dataset.seen ?? 0} pages), so this verdict is capped at warn.` : "";
}

function capForPartial(status: ZscalerFindingStatus, dataset: CollectedDataset<JsonRecord[]>): ZscalerFindingStatus {
  if (status === "pass" && dataset.truncated) return "warn";
  return status;
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

export function assessZiaAccessControlData(
  data: ZiaAccessControlData,
  options: { maxSuperAdmins?: number } = {},
): ZscalerAssessmentResult {
  const maxSuperAdmins = clampNumber(options.maxSuperAdmins, DEFAULT_MAX_SUPER_ADMINS, 0, 500);
  const findings: ZscalerFinding[] = [];
  const admins = data.adminUsers.data;
  const enabledAdmins = admins.filter((admin) => asBoolean(admin.disabled) !== true);
  const passwordLoginAdmins = enabledAdmins.filter((admin) => asBoolean(admin.isPasswordLoginAllowed) === true);
  const samlEnabled = asBoolean(data.authSettings.data.samlEnabled);

  const mfaEvidence = "Collect a screenshot of Administration > Administrator Management showing the administrator authentication settings (SAML SSO for administrators and enforced multi-factor authentication), since the ZIA API does not expose per-administrator MFA state.";
  if (data.adminUsers.error) {
    findings.push(unreadableFinding(6, "GET /adminUsers", data.adminUsers, mfaEvidence));
  } else if (admins.length === 0) {
    findings.push(finding(6, "manual", `Empty inventory: GET /adminUsers returned zero administrators, which is not possible for a live tenant, so the credential is probably scoped. ${mfaEvidence}`, { admin_count: 0 }, mfaEvidence));
  } else {
    const summary = passwordLoginAdmins.length > 0
      ? `${passwordLoginAdmins.length} of ${enabledAdmins.length} enabled administrators allow password login (isPasswordLoginAllowed=true), a local sign-in path that bypasses IdP MFA. Per-admin MFA is not exposed by the API, so the verdict is capped at warn.`
      : `All ${enabledAdmins.length} enabled administrators have password login disabled (SSO only). Per-admin MFA is not exposed by the API, so this remains manual until portal evidence is attached.`;
    findings.push(finding(6, passwordLoginAdmins.length > 0 ? "warn" : "manual", summary + partialSuffix(data.adminUsers, "administrator"), {
      enabled_admins: enabledAdmins.length,
      password_login_admins: truncateList(passwordLoginAdmins.map(adminLabel)),
      end_user_saml_enabled: samlEnabled ?? null,
      partial_inventory: data.adminUsers.truncated === true,
    }, mfaEvidence));
  }

  const rbacEvidence = "Export Administration > Role Management and Administrator Management, confirm each administrator maps to a least-privilege role, and list Cloud Service API keys with their owners (the API key inventory is not part of the verified read surface).";
  if (data.adminUsers.error) {
    findings.push(unreadableFinding(7, "GET /adminUsers", data.adminUsers, rbacEvidence));
  } else if (data.adminRoles.error) {
    findings.push(unreadableFinding(7, "GET /adminRoles/lite", data.adminRoles, rbacEvidence));
  } else if (admins.length === 0 || data.adminRoles.data.length === 0) {
    findings.push(finding(7, "manual", `Empty inventory: ${admins.length} administrators and ${data.adminRoles.data.length} roles were returned, so the role assignment picture is incomplete. ${rbacEvidence}`, { admin_count: admins.length, role_count: data.adminRoles.data.length }, rbacEvidence));
  } else {
    const superRoleIds = new Set(data.adminRoles.data.filter(isSuperAdminRole).map((role) => asString(role.id)).filter((id): id is string => Boolean(id)));
    const superAdmins = enabledAdmins.filter((admin) => {
      const roleId = asString(asObject(admin.role)?.id);
      return (roleId !== undefined && superRoleIds.has(roleId)) || /super/i.test(adminRoleName(admin));
    });
    const unscopedAdmins = enabledAdmins.filter((admin) => (asString(admin.adminScopeType) ?? "ORGANIZATION").toUpperCase() === "ORGANIZATION");
    const disabledAdmins = admins.length - enabledAdmins.length;
    let status: ZscalerFindingStatus = "pass";
    let summary = `${superAdmins.length} of ${enabledAdmins.length} enabled administrators hold a Super Admin role (threshold ${maxSuperAdmins}); ${unscopedAdmins.length} are organization-scoped.`;
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
    findings.push(finding(7, capForPartial(status, data.adminUsers), summary + partialSuffix(data.adminUsers, "administrator"), {
      enabled_admins: enabledAdmins.length,
      disabled_admins: disabledAdmins,
      super_admins: truncateList(superAdmins.map(adminLabel)),
      roles: truncateList(data.adminRoles.data.map((role) => ({ name: asString(role.name) ?? null, roleType: asString(role.roleType) ?? null }))),
      organization_scoped_admins: unscopedAdmins.length,
      password_expiration_enabled: asBoolean(data.passwordExpiry.data.passwordExpirationEnabled) ?? null,
      password_expiry_days: asNumber(data.passwordExpiry.data.passwordExpiryDays) ?? null,
    }));
  }

  const auditEvidence = "Confirm in Analytics > Insights > Audit Logs that administrator actions are recorded, and document the NSS or Cloud NSS feed (Administration > Nanolog Streaming Service) that exports admin audit logs plus the SIEM retention period.";
  if (data.auditLogReport.error) {
    findings.push(unreadableFinding(14, "GET /auditlogEntryReport", data.auditLogReport, auditEvidence));
  } else {
    const feeds = data.nssFeeds.data;
    const enabledFeeds = feeds.filter((feed) => (asString(feed.feedStatus) ?? "").toUpperCase() === "ENABLED");
    const adminAuditFeeds = enabledFeeds.filter((feed) => /ADMIN_AUDIT|AUDIT/i.test(asString(feed.nssLogType) ?? ""));
    if (data.nssFeeds.error) {
      findings.push(finding(14, "manual", `The audit log report interface is reachable (GET /auditlogEntryReport status ${asString(data.auditLogReport.data.status) ?? "unknown"}), but GET /nssFeeds could not be read because ${unreadableReason(data.nssFeeds)}, so log export configuration is unverified. ${auditEvidence}`, { audit_report_status: asString(data.auditLogReport.data.status) ?? null }, auditEvidence));
    } else if (adminAuditFeeds.length > 0) {
      findings.push(finding(14, "pass", `Admin audit logging is reachable and ${adminAuditFeeds.length} enabled NSS feed(s) export admin audit logs (${adminAuditFeeds.map(ruleLabel).join(", ")}). Retention is enforced by the receiving SIEM and must be documented separately.`, {
        audit_report_status: asString(data.auditLogReport.data.status) ?? null,
        nss_feeds: feeds.length,
        enabled_feeds: enabledFeeds.length,
        admin_audit_feeds: truncateList(adminAuditFeeds.map((feed) => ({ name: ruleLabel(feed), nssLogType: asString(feed.nssLogType) ?? null, feedStatus: asString(feed.feedStatus) ?? null }))),
      }));
    } else {
      findings.push(finding(14, feeds.length === 0 ? "warn" : "fail", feeds.length === 0
        ? "Admin audit logging is reachable, but zero NSS feeds are configured, so audit logs are only retained inside the Zscaler portal window and are not exported for long-term retention."
        : `${feeds.length} NSS feed(s) exist but none that is enabled exports admin audit logs (nssLogType ADMIN_AUDIT).`, {
        audit_report_status: asString(data.auditLogReport.data.status) ?? null,
        nss_feeds: truncateList(feeds.map((feed) => ({ name: ruleLabel(feed), nssLogType: asString(feed.nssLogType) ?? null, feedStatus: asString(feed.feedStatus) ?? null }))),
      }, auditEvidence));
    }
  }

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
  listRoles(): Promise<PagedList>;
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
      const detail = payloadErrorSummary(payload) ?? rawText.slice(0, 240);
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
      const detail = payloadErrorSummary(payload) ?? rawText.slice(0, 240);
      throw new ZscalerApiError("zpa", response.status, this.redact(`ZPA GET ${path} failed (${response.status})${detail ? `: ${detail}` : ""}`));
    }
    return payload;
  }

  async getPaged(path: string, query: JsonRecord = {}): Promise<PagedList> {
    const items: JsonRecord[] = [];
    let totalPages: number | undefined;
    for (let page = 1; page <= ZPA_MAX_PAGES; page += 1) {
      const payload = await this.get(path, { ...query, page, pagesize: ZPA_PAGE_SIZE });
      if (Array.isArray(payload)) {
        return { items: asRecordArray(payload), truncated: false, pagesFetched: 1, totalPages: 1 };
      }
      const object = asObject(payload) ?? {};
      items.push(...asRecordArray(object.list ?? object.items));
      totalPages = asNumber(object.totalPages) ?? (asString(object.nextPage) ? page + 1 : 1);
      if (page >= totalPages) {
        return { items, truncated: false, pagesFetched: page, totalPages };
      }
    }
    return { items, truncated: true, pagesFetched: ZPA_MAX_PAGES, totalPages };
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
    return this.getPaged(this.customerPath("v2", "/trustedNetwork"));
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
    return this.getPaged(this.customerPath("v1", "/emergencyAccess/users"));
  }

  listAdministrators(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/administrators"));
  }

  listRoles(): Promise<PagedList> {
    return this.getPaged(this.customerPath("v1", "/roles"));
  }
}

// ZIA_POLICY_PLACEHOLDER

// ZPA_ASSESSMENT_PLACEHOLDER

// EXPORT_PLACEHOLDER

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

  // REGISTER_PLACEHOLDER
}
