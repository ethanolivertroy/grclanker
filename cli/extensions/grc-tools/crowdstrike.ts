/**
 * CrowdStrike Falcon security inspector tools for grclanker.
 *
 * Read-only Falcon API access across prevention, response, device control,
 * firewall, sensor coverage, RBAC, exclusions, detections, identity
 * protection, and Zero Trust Assessment surfaces.
 *
 * Verdict safety: unreadable endpoints, empty inventories, unlicensed
 * modules, undated records, and partial (truncated or sampled) reads never
 * produce a pass. Each of those conditions is surfaced in the finding.
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

const DEFAULT_OUTPUT_DIR = "./export/crowdstrike";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_LIMIT = 4;
const DEFAULT_RETRY_BASE_MS = 250;
const MAX_RETRY_DELAY_MS = 15_000;
const TOKEN_SKEW_MS = 60_000;
const DEFAULT_TOKEN_TTL_SECONDS = 1799;
const DEFAULT_POLICY_PAGE_SIZE = 500;
const DEFAULT_POLICY_LIMIT = 5000;
const DEFAULT_HOST_PAGE_SIZE = 1000;
const DEFAULT_ID_BATCH_SIZE = 100;
const DEFAULT_HOST_LIMIT = 5000;
const DEFAULT_USER_LIMIT = 500;
const DEFAULT_ALERT_LIMIT = 2000;
const DEFAULT_EXCLUSION_LIMIT = 500;
const DEFAULT_RULE_LIMIT = 1000;
const DEFAULT_SESSION_LIMIT = 500;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_STALE_SENSOR_DAYS = 7;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_MAX_ROLES_PER_USER = 5;
const DEFAULT_MAX_USB_EXCEPTIONS = 25;
const DEFAULT_MAX_WRITE_CLIENTS = 3;
const DEFAULT_MIN_ZTA_SCORE = 60;
const DEFAULT_STALE_ADMIN_LOGIN_DAYS = 90;
const DEFAULT_STALE_API_CLIENT_DAYS = 90;
const DEFAULT_MAX_SESSION_MINUTES = 30;
const DEFAULT_MAX_CONCURRENT_SESSIONS = 3;
const CRITICAL_SLA_HOURS = 24;
const HIGH_SLA_HOURS = 72;
const CRITICAL_SEVERITY_FLOOR = 90;
const HIGH_SEVERITY_FLOOR = 70;

export const CROWDSTRIKE_CLOUDS: Readonly<Record<string, string>> = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
  "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
};

const ML_SLIDER_RANK: Readonly<Record<string, number>> = {
  DISABLED: 0,
  CAUTIOUS: 1,
  MODERATE: 2,
  AGGRESSIVE: 3,
  EXTRA_AGGRESSIVE: 4,
};

const PRIMARY_ML_SLIDERS = ["CloudAntiMalware", "OnSensorMLSlider"];
const SUPPLEMENTAL_ML_SLIDERS = [
  "AdwarePUP",
  "CloudAntiMalwareForMicrosoftOfficeFiles",
  "CloudMLSliderForPupAdwareCloudEndUserScans",
  "OnSensorMLAdwarePUPSlider",
  "OnSensorMLSliderForSensorEndUserScans",
  "OnSensorMLSliderForCloudEndUserScans",
];
const CORE_EXPLOIT_MITIGATIONS = [
  "ForceASLR",
  "ForceDEP",
  "HeapSprayPreallocation",
  "NullPageAllocation",
  "SEHOverwriteProtection",
];
const EXTENDED_EXPLOIT_MITIGATIONS = [
  "ApplicationExploitationActivity",
  "ChopperWebshell",
  "DriveByDownload",
  "ProcessHollowing",
  "JavaScriptViaRundll32",
  "HardwareEnhancedExploitDetection",
];
const SCRIPT_CONTROL_SETTINGS = ["ScriptBasedExecutionMonitoring", "InterpreterProtection", "EngineProtectionV2"];
const SUPPLEMENTAL_SCRIPT_SETTINGS = ["MaliciousPowershell", "OnWriteScriptFileVisibility"];
const TAMPER_PROTECTION_SETTING = "SensorTamperingProtection";
const ON_WRITE_DETECT_SETTING = "DetectOnWrite";
const ON_WRITE_QUARANTINE_SETTING = "QuarantineOnWrite";
const SUPPLEMENTAL_ON_WRITE_SETTINGS = ["DetectPackageOnWrite", "QuarantinePackageOnWrite", "OnWriteScriptFileVisibility"];
const RESPONSE_POLICY_SETTINGS = [
  "RealTimeFunctionality",
  "CustomScripts",
  "GetCommand",
  "PutCommand",
  "ExecCommand",
  "FalconScripts",
  "MemDumpCommand",
  "XMemDumpCommand",
  "PutAndRunCommand",
];
const SENSITIVE_WRITE_SCOPE_PATTERNS = [
  /prevention/i,
  /response/i,
  /sensor-update/i,
  /device-control/i,
  /firewall/i,
  /user-management/i,
  /api-clients?/i,
  /real-time-response/i,
  /hosts?/i,
  /host-groups?/i,
  /exclusions?/i,
  /identity-protection/i,
  /alerts?/i,
  /detects?/i,
  /incidents?/i,
];
const SENSITIVE_EXCLUSION_PATH_PATTERNS = [
  /^(\\\\\?\\)?[a-z]:\\(windows|program files|program files \(x86\)|programdata|users|temp)(\\|$)/i,
  /^\/(usr|bin|sbin|etc|var|tmp|home|root|library|system)(\/|$)/i,
  /^%(systemroot|windir|programfiles|programdata|userprofile|temp|appdata)%/i,
];
const SHARED_ACCOUNT_PATTERN = /(^|[._-])(admin|administrator|root|shared|service|svc|soc|security|ops|team|helpdesk|noreply|generic|test)([._-]|$|@)/i;

type FrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig" | "irap" | "ismap";

interface FrameworkDefinition {
  key: FrameworkKey;
  label: string;
  title: string;
}

export const CROWDSTRIKE_FRAMEWORKS: ReadonlyArray<FrameworkDefinition> = [
  { key: "fedramp", label: "FedRAMP", title: "FedRAMP (NIST SP 800-53) Compliance Report" },
  { key: "cmmc", label: "CMMC", title: "CMMC 2.0 Compliance Report" },
  { key: "soc2", label: "SOC 2", title: "SOC 2 Compliance Report" },
  { key: "cis", label: "CIS", title: "CIS Controls Report" },
  { key: "pci_dss", label: "PCI-DSS", title: "PCI-DSS 4.0 Compliance Report" },
  { key: "disa_stig", label: "DISA STIG", title: "DISA STIG Compliance Checklist" },
  { key: "irap", label: "IRAP", title: "IRAP (ISM) Compliance Report" },
  { key: "ismap", label: "ISMAP", title: "ISMAP Compliance Report" },
];

type ControlId =
  | "CS-01" | "CS-02" | "CS-03" | "CS-04" | "CS-05"
  | "CS-06" | "CS-07" | "CS-08" | "CS-09" | "CS-10"
  | "CS-11" | "CS-12" | "CS-13" | "CS-14" | "CS-15"
  | "CS-16" | "CS-17" | "CS-18" | "CS-19" | "CS-20"
  | "CS-21" | "CS-22" | "CS-23" | "CS-24" | "CS-25";

interface ControlDefinition {
  id: ControlId;
  title: string;
  severity: CrowdstrikeFinding["severity"];
  frameworks: Record<FrameworkKey, string[]>;
}

function control(
  id: ControlId,
  title: string,
  severity: CrowdstrikeFinding["severity"],
  mappings: [string[], string[], string[], string[], string[], string[], string[], string[]],
): ControlDefinition {
  return {
    id,
    title,
    severity,
    frameworks: {
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

export const CROWDSTRIKE_CONTROLS: ReadonlyArray<ControlDefinition> = [
  control("CS-01", "Prevention Policy - ML Detection Levels", "high", [["SI-3", "SI-3(1)"], ["SI.L2-3.14.2"], ["CC6.8"], ["10.1"], ["5.2"], ["V-256374"], ["ISM-1417"], ["8.1.1"]]),
  control("CS-02", "Prevention Policy - Exploit Mitigation", "high", [["SI-16"], ["SI.L2-3.14.7"], ["CC6.8"], ["10.5"], ["5.2"], ["V-256375"], ["ISM-1490"], ["8.1.1"]]),
  control("CS-03", "Prevention Policy - Script-Based Execution Control", "medium", [["CM-7(2)"], ["CM.L2-3.4.7"], ["CC6.8"], ["2.7"], ["5.2"], ["V-256376"], ["ISM-1490"], ["8.1.2"]]),
  control("CS-04", "Prevention Policy - Sensor Tamper Protection", "critical", [["SC-7(12)", "SI-7"], ["SI.L2-3.14.6"], ["CC6.1"], ["10.4"], ["5.2.3"], ["V-256377"], ["ISM-1418"], ["8.1.1"]]),
  control("CS-05", "Prevention Policy - On-Write Detection", "medium", [["SI-3"], ["SI.L2-3.14.2"], ["CC6.8"], ["10.1"], ["5.2"], ["V-256374"], ["ISM-1417"], ["8.1.1"]]),
  control("CS-06", "Response Policy - RTR Enabled", "medium", [["IR-4", "IR-5"], ["IR.L2-3.6.1"], ["CC7.3"], ["10.7"], ["12.10"], ["V-256378"], ["ISM-0576"], ["7.1.1"]]),
  control("CS-07", "Response Policy - Session Limits", "low", [["AC-12", "SC-10"], ["AC.L2-3.1.11"], ["CC6.1"], ["5.6"], ["8.2.8"], ["V-256379"], ["ISM-1164"], ["5.1.2"]]),
  control("CS-08", "Device Control - USB Blocking", "high", [["MP-7"], ["MP.L2-3.8.7"], ["CC6.4"], ["10.3"], ["9.5"], ["V-256380"], ["ISM-0340"], ["11.1.1"]]),
  control("CS-09", "Device Control - Peripheral Restrictions", "medium", [["MP-7"], ["MP.L2-3.8.7"], ["CC6.4"], ["10.3"], ["9.5"], ["V-256380"], ["ISM-0340"], ["11.1.1"]]),
  control("CS-10", "Firewall - Host Firewall Enabled", "medium", [["SC-7"], ["SC.L2-3.13.1"], ["CC6.6"], ["4.8"], ["1.3"], ["V-256381"], ["ISM-1416"], ["10.1.1"]]),
  control("CS-11", "Firewall - Default Deny", "high", [["SC-7(5)"], ["SC.L2-3.13.6"], ["CC6.6"], ["4.8"], ["1.2.1"], ["V-256382"], ["ISM-1416"], ["10.1.1"]]),
  control("CS-12", "Sensor Update - Auto-Update Enabled", "high", [["SI-2"], ["SI.L2-3.14.1"], ["CC6.8"], ["10.2"], ["6.3"], ["V-256383"], ["ISM-1143"], ["8.2.1"]]),
  control("CS-13", "Sensor Coverage - Deployment Completeness", "high", [["CM-8"], ["CM.L2-3.4.1"], ["CC6.1"], ["1.1"], ["2.4"], ["V-256384"], ["ISM-1301"], ["6.1.1"]]),
  control("CS-14", "Sensor Coverage - Host Group Assignment", "medium", [["CM-8", "CM-6"], ["CM.L2-3.4.2"], ["CC6.1"], ["1.1"], ["2.4"], ["V-256384"], ["ISM-1301"], ["6.1.1"]]),
  control("CS-15", "Unmanaged Asset Detection", "medium", [["CM-8(3)"], ["CM.L2-3.4.1"], ["CC6.1"], ["1.1"], ["2.4"], ["V-256385"], ["ISM-1301"], ["6.1.1"]]),
  control("CS-16", "RBAC - Admin Count", "medium", [["AC-6(5)"], ["AC.L2-3.1.7"], ["CC6.3"], ["5.1"], ["7.2"], ["V-256386"], ["ISM-1380"], ["5.2.1"]]),
  control("CS-17", "RBAC - Least Privilege", "medium", [["AC-6"], ["AC.L2-3.1.5"], ["CC6.3"], ["5.4"], ["7.2.2"], ["V-256387"], ["ISM-1380"], ["5.2.1"]]),
  control("CS-18", "RBAC - API Client Permissions", "high", [["AC-6(10)"], ["AC.L2-3.1.7"], ["CC6.3"], ["5.4"], ["7.2.2"], ["V-256388"], ["ISM-1380"], ["5.2.1"]]),
  control("CS-19", "Exclusion Review - IOA Exclusions", "medium", [["SI-3(10)", "CM-7"], ["SI.L2-3.14.2"], ["CC6.8"], ["10.6"], ["5.2.3"], ["V-256389"], ["ISM-1417"], ["8.1.3"]]),
  control("CS-20", "Exclusion Review - ML Exclusions", "medium", [["SI-3(10)"], ["SI.L2-3.14.2"], ["CC6.8"], ["10.6"], ["5.2.3"], ["V-256389"], ["ISM-1417"], ["8.1.3"]]),
  control("CS-21", "Exclusion Review - Sensor Visibility", "high", [["SI-4(2)"], ["SI.L2-3.14.6"], ["CC7.2"], ["10.6"], ["5.2.3"], ["V-256390"], ["ISM-1418"], ["8.1.3"]]),
  control("CS-22", "Detection Response SLA", "high", [["IR-4(1)", "IR-6"], ["IR.L2-3.6.2"], ["CC7.3"], ["17.4"], ["12.10.1"], ["V-256391"], ["ISM-0123"], ["7.1.2"]]),
  control("CS-23", "Containment Policy", "medium", [["IR-4", "SC-7(20)"], ["IR.L2-3.6.1"], ["CC7.4"], ["17.8"], ["12.10"], ["V-256392"], ["ISM-0576"], ["7.1.1"]]),
  control("CS-24", "Identity Protection", "medium", [["IA-2", "IA-5"], ["IA.L2-3.5.1"], ["CC6.1"], ["6.1"], ["8.3"], ["V-256393"], ["ISM-1557"], ["5.3.1"]]),
  control("CS-25", "Zero Trust Assessment", "low", [["RA-5", "CA-7"], ["CA.L2-3.12.3"], ["CC7.1"], ["1.3"], ["11.3"], ["V-256394"], ["ISM-1526"], ["6.2.1"]]),
];

const CONTROL_BY_ID = new Map(CROWDSTRIKE_CONTROLS.map((definition) => [definition.id, definition]));

export interface CrowdstrikeResolvedConfig {
  clientId: string;
  clientSecret: string;
  baseUrl: string;
  cloud?: string;
  memberCid?: string;
  timeoutMs: number;
  sourceChain: string[];
}

export interface CrowdstrikePage<T> {
  items: T[];
  total?: number;
  truncated: boolean;
}

export interface CrowdstrikeAccessSurface {
  name: string;
  endpoint: string;
  scope: string;
  status: "readable" | "forbidden" | "not_readable";
  count?: number;
  error?: string;
}

export interface CrowdstrikeAccessCheckResult {
  status: "healthy" | "limited";
  baseUrl: string;
  memberCid?: string;
  surfaces: CrowdstrikeAccessSurface[];
  missingScopes: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface CrowdstrikeFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface CrowdstrikeAssessmentResult {
  title: string;
  category: string;
  summary: JsonRecord;
  findings: CrowdstrikeFinding[];
  errors: string[];
  snapshots: Record<string, unknown>;
}

export interface CrowdstrikeAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface CrowdstrikeAssessmentOptions {
  hostLimit?: number;
  userLimit?: number;
  alertLimit?: number;
  exclusionLimit?: number;
  ruleLimit?: number;
  lookbackDays?: number;
  staleSensorDays?: number;
  maxAdmins?: number;
  maxRolesPerUser?: number;
  maxUsbExceptions?: number;
  maxWriteClients?: number;
  minZtaScore?: number;
  maxSessionMinutes?: number;
  maxConcurrentSessions?: number;
}

type CheckAccessArgs = {
  client_id?: string;
  client_secret?: string;
  base_url?: string;
  cloud?: string;
  member_cid?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AssessArgs = CheckAccessArgs & {
  host_limit?: number;
  user_limit?: number;
  alert_limit?: number;
  exclusion_limit?: number;
  rule_limit?: number;
  lookback_days?: number;
  stale_sensor_days?: number;
  max_admins?: number;
  max_roles_per_user?: number;
  max_usb_exceptions?: number;
  max_write_clients?: number;
  min_zta_score?: number;
  max_session_minutes?: number;
  max_concurrent_sessions?: number;
};

type ExportAuditBundleArgs = AssessArgs & {
  output_dir?: string;
};

interface CollectedDataset<T> {
  data: T;
  error?: string;
  status?: number;
}

interface PartialInventory {
  dataset: string;
  seen: number;
  total?: number;
}

export class CrowdstrikeHttpError extends Error {
  readonly status: number;
  readonly path: string;

  constructor(message: string, status: number, path: string) {
    super(message);
    this.name = "CrowdstrikeHttpError";
    this.status = status;
    this.path = path;
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

function asStringArray(value: unknown): string[] {
  return asArray(value).map((item) => asString(item)).filter((item): item is string => Boolean(item));
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

function normalizeBaseUrl(rawUrl: string): string {
  const candidate = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(candidate);
  if (parsed.protocol !== "https:") {
    throw new Error("CrowdStrike base URL must use https.");
  }
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function normalizeCloudAlias(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase().replace(/_/g, "-");
  const aliases: Record<string, string> = {
    us1: "us-1",
    us2: "us-2",
    eu1: "eu-1",
    usgov1: "us-gov-1",
    usgov2: "us-gov-2",
    "gov-1": "us-gov-1",
    gov: "us-gov-1",
    laggar: "us-gov-1",
  };
  return aliases[normalized] ?? normalized;
}

function cloudForBaseUrl(baseUrl: string): string | undefined {
  return Object.entries(CROWDSTRIKE_CLOUDS).find(([, url]) => url === baseUrl)?.[0];
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
  return normalized || "crowdstrike";
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
    const output = createWriteStream(zipPath, { mode: 0o600, flags: "wx" });
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

function parseTimestamp(value: unknown): number | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function hoursBetween(startMs: number, endMs: number): number {
  return Math.max(0, (endMs - startMs) / 3_600_000);
}

function percentage(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 1000) / 10;
}

function worstStatus(statuses: CrowdstrikeFinding["status"][]): CrowdstrikeFinding["status"] {
  if (statuses.includes("fail")) return "fail";
  if (statuses.includes("warn")) return "warn";
  if (statuses.includes("manual")) return "manual";
  return "pass";
}

function mappingStrings(definition: ControlDefinition): string[] {
  const mappings: string[] = [];
  for (const framework of CROWDSTRIKE_FRAMEWORKS) {
    for (const value of definition.frameworks[framework.key]) {
      mappings.push(`${framework.label} ${value}`);
    }
  }
  return mappings;
}

function finding(
  id: ControlId,
  status: CrowdstrikeFinding["status"],
  summary: string,
  evidence?: JsonRecord,
): CrowdstrikeFinding {
  const definition = CONTROL_BY_ID.get(id);
  if (!definition) {
    throw new Error(`Unknown CrowdStrike control ${id}`);
  }
  return {
    id,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: mappingStrings(definition),
  };
}

function manualFinding(id: ControlId, reason: string, consoleEvidence: string, evidence?: JsonRecord): CrowdstrikeFinding {
  return finding(id, "manual", `${reason} Verdict: manual (unknown). Collect manually: ${consoleEvidence}`, evidence);
}

function unreadableFinding(id: ControlId, dataset: string, error: string, consoleEvidence: string): CrowdstrikeFinding {
  return manualFinding(
    id,
    `The ${dataset} read failed (${error}), so no API evidence supports this control.`,
    consoleEvidence,
    { unreadable_dataset: dataset, error },
  );
}

function unlicensedFinding(id: ControlId, module: string, error: string, consoleEvidence: string): CrowdstrikeFinding {
  return manualFinding(
    id,
    `${module} is unlicensed or not applicable to this tenant, or the API client lacks its read scope (${error}).`,
    consoleEvidence,
    { module, error, not_applicable: true },
  );
}

function summarizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isForbiddenOrMissing(dataset: CollectedDataset<unknown>): boolean {
  return dataset.status === 401 || dataset.status === 403 || dataset.status === 404;
}

async function collectDataset<T>(load: () => Promise<T>, fallback: T, label: string): Promise<CollectedDataset<T>> {
  try {
    return { data: await load() };
  } catch (error) {
    return {
      data: fallback,
      error: `${label}: ${summarizeError(error)}`,
      status: error instanceof CrowdstrikeHttpError ? error.status : undefined,
    };
  }
}

function listErrors(datasets: Array<CollectedDataset<unknown>>): string[] {
  return datasets.map((dataset) => dataset.error).filter((error): error is string => Boolean(error));
}

function emptyPage<T>(): CrowdstrikePage<T> {
  return { items: [], truncated: false };
}

function partialInventory(page: CrowdstrikePage<unknown>, dataset: string): PartialInventory | undefined {
  if (!page.truncated) return undefined;
  return { dataset, seen: page.items.length, total: page.total };
}

function withPartialInventory(
  item: CrowdstrikeFinding,
  partials: Array<PartialInventory | undefined>,
): CrowdstrikeFinding {
  const present = partials.filter((partial): partial is PartialInventory => Boolean(partial));
  if (present.length === 0) return item;
  const description = present
    .map((partial) => `${partial.seen} of ${partial.total === undefined ? "an unknown total of" : partial.total} ${partial.dataset}`)
    .join("; ");
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary} Partial inventory: only ${description} were read (sampled or truncated), so this verdict cannot exceed warn.`,
    evidence: { ...(item.evidence ?? {}), partial_inventory: present },
  };
}

function withUndatedItems(item: CrowdstrikeFinding, count: number, label: string, field: string): CrowdstrikeFinding {
  if (count <= 0) return item;
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary} ${count} ${label} have no ${field} timestamp; they were excluded from freshness counts and cap this verdict at warn.`,
    evidence: { ...(item.evidence ?? {}), undated_items: { label, field, count } },
  };
}

function withUnreadableSecondary(item: CrowdstrikeFinding, dataset: string, errors: Array<string | undefined>, consequence: string): CrowdstrikeFinding {
  const present = errors.filter((error): error is string => Boolean(error));
  if (present.length === 0) return item;
  const previous = asRecordArray(asObject(item.evidence)?.unreadable_secondary_reads);
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary} The ${dataset} read failed (${present.join("; ")}), so ${consequence} and this verdict cannot exceed warn.`,
    evidence: { ...(item.evidence ?? {}), unreadable_secondary_reads: [...previous, { dataset, errors: present }] },
  };
}

function readJsonConfigFile(location: string): JsonRecord | undefined {
  if (!existsSync(location)) return undefined;
  const raw = readFileSync(location, "utf8");
  const parsed = asObject(JSON.parse(raw) as unknown);
  if (!parsed) {
    throw new Error(`CrowdStrike config file ${location} must contain a JSON object.`);
  }
  return parsed;
}

function configFileValue(config: JsonRecord | undefined, keys: string[]): string | undefined {
  if (!config) return undefined;
  for (const key of keys) {
    const value = asString(config[key]);
    if (value) return value;
  }
  return undefined;
}

export function resolveCrowdstrikeConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  homeDir: string = homedir(),
): CrowdstrikeResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file)
    ?? asString(env.CS_CONFIG_FILE)
    ?? join(homeDir, ".crowdstrike", "config.json");
  const fileConfig = readJsonConfigFile(configPath);
  if (fileConfig) {
    sourceChain.push(`config:${configPath}`);
  }

  const pick = (
    argKey: string,
    envKeys: string[],
    fileKeys: string[],
    label: string,
  ): string | undefined => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) {
      sourceChain.push(`arguments-${label}`);
      return fromArgs;
    }
    for (const envKey of envKeys) {
      const fromEnv = asString(env[envKey]);
      if (fromEnv) {
        sourceChain.push(`environment-${label}`);
        return fromEnv;
      }
    }
    const fromFile = configFileValue(fileConfig, fileKeys);
    if (fromFile) {
      sourceChain.push(`config-${label}`);
      return fromFile;
    }
    return undefined;
  };

  const clientId = pick("client_id", ["CS_CLIENT_ID", "FALCON_CLIENT_ID"], ["client_id", "clientId"], "client-id");
  const clientSecret = pick("client_secret", ["CS_CLIENT_SECRET", "FALCON_CLIENT_SECRET"], ["client_secret", "clientSecret"], "client-secret");
  if (!clientId || !clientSecret) {
    throw new Error(
      "CrowdStrike API credentials are required. Set CS_CLIENT_ID and CS_CLIENT_SECRET, configure ~/.crowdstrike/config.json, or pass client_id and client_secret explicitly.",
    );
  }

  const cloudAlias = normalizeCloudAlias(pick("cloud", ["CS_CLOUD", "FALCON_CLOUD"], ["cloud", "region"], "cloud"));
  const explicitBaseUrl = pick("base_url", ["CS_BASE_URL", "FALCON_BASE_URL"], ["base_url", "baseUrl"], "base-url");
  let baseUrl: string;
  if (explicitBaseUrl) {
    baseUrl = normalizeBaseUrl(explicitBaseUrl);
  } else if (cloudAlias) {
    const cloudUrl = CROWDSTRIKE_CLOUDS[cloudAlias];
    if (!cloudUrl) {
      throw new Error(`Unknown CrowdStrike cloud "${cloudAlias}". Use one of: ${Object.keys(CROWDSTRIKE_CLOUDS).join(", ")}.`);
    }
    baseUrl = cloudUrl;
  } else {
    baseUrl = CROWDSTRIKE_CLOUDS["us-1"];
    sourceChain.push("default-base-url");
  }

  const memberCid = pick("member_cid", ["CS_MEMBER_CID", "FALCON_MEMBER_CID"], ["member_cid", "memberCid"], "member-cid");
  const timeoutSeconds = asNumber(input.timeout_seconds) ?? asNumber(env.CS_TIMEOUT) ?? asNumber(configFileValue(fileConfig, ["timeout_seconds"]));

  return {
    clientId,
    clientSecret,
    baseUrl,
    cloud: cloudAlias && CROWDSTRIKE_CLOUDS[cloudAlias] === baseUrl ? cloudAlias : cloudForBaseUrl(baseUrl),
    memberCid,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    sourceChain: [...new Set(sourceChain)],
  };
}

function redactSecrets(text: string, secrets: Array<string | undefined>): string {
  let redacted = text;
  for (const secret of secrets) {
    if (secret && secret.length >= 6) {
      redacted = redacted.split(secret).join("[REDACTED]");
    }
  }
  return redacted;
}

function falconErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const messages = asRecordArray(object.errors)
    .map((item) => asString(item.message))
    .filter((item): item is string => Boolean(item));
  if (messages.length > 0) return messages.join("; ");
  return asString(object.error_description) ?? asString(object.error) ?? asString(object.message);
}

function paginationOf(payload: JsonRecord): JsonRecord {
  return asObject(asObject(payload.meta)?.pagination) ?? {};
}

function retryDelayFromResponse(response: Response, attempt: number): number {
  const retryAfterHeader = response.headers.get("x-ratelimit-retryafter") ?? response.headers.get("retry-after");
  if (retryAfterHeader) {
    const parsed = Number(retryAfterHeader);
    if (Number.isFinite(parsed) && parsed >= 0) {
      let deltaMs: number;
      if (parsed > 1_000_000_000_000) {
        deltaMs = parsed - Date.now();
      } else if (parsed > 1_000_000_000) {
        deltaMs = parsed * 1000 - Date.now();
      } else {
        deltaMs = parsed * 1000;
      }
      return Math.min(Math.max(deltaMs, DEFAULT_RETRY_BASE_MS), MAX_RETRY_DELAY_MS);
    }
    const asDate = Date.parse(retryAfterHeader);
    if (Number.isFinite(asDate)) {
      return Math.min(Math.max(asDate - Date.now(), DEFAULT_RETRY_BASE_MS), MAX_RETRY_DELAY_MS);
    }
  }
  return Math.min(DEFAULT_RETRY_BASE_MS * 2 ** attempt, MAX_RETRY_DELAY_MS);
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function parseJsonText(rawText: string): JsonRecord {
  if (rawText.length === 0) return {};
  try {
    return asObject(JSON.parse(rawText) as unknown) ?? {};
  } catch {
    return {};
  }
}

function pageOf<T>(items: T[], total: number | undefined, moreAvailable: boolean): CrowdstrikePage<T> {
  const truncated = moreAvailable || (total !== undefined && items.length < total);
  return { items, total, truncated };
}

function recordPage<T>(page: CrowdstrikePage<T>, entities: JsonRecord[]): CrowdstrikePage<JsonRecord> {
  return { items: entities, total: page.total, truncated: page.truncated };
}

export class CrowdstrikeApiClient {
  private readonly config: CrowdstrikeResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleep: SleepImpl;
  private readonly retryLimit: number;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private accessTokenPromise?: Promise<string>;

  constructor(
    config: CrowdstrikeResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleep?: SleepImpl;
      retryLimit?: number;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? defaultSleep;
    this.retryLimit = clampNumber(options.retryLimit, DEFAULT_RETRY_LIMIT, 0, 10);
  }

  getResolvedConfig(): CrowdstrikeResolvedConfig {
    return this.config;
  }

  private redact(text: string): string {
    return redactSecrets(text, [this.config.clientSecret, this.accessToken]);
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(`${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          url.searchParams.append(key, String(item));
        }
        continue;
      }
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`CrowdStrike request timed out after ${this.config.timeoutMs}ms: ${new URL(url).pathname}`);
      }
      throw new Error(this.redact(`CrowdStrike request failed: ${summarizeError(error)}`));
    } finally {
      clearTimeout(timeout);
    }
  }

  private async fetchAccessToken(): Promise<string> {
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });
    if (this.config.memberCid) {
      body.set("member_cid", this.config.memberCid);
    }

    const response = await this.fetchWithTimeout(`${this.config.baseUrl}/oauth2/token`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    const rawText = await response.text();
    const payload = parseJsonText(rawText);
    if (!response.ok) {
      const detail = falconErrorSummary(payload) ?? rawText.slice(0, 200);
      throw new CrowdstrikeHttpError(
        this.redact(`CrowdStrike OAuth2 token request failed (${response.status})${detail ? `: ${detail}` : ""}`),
        response.status,
        "/oauth2/token",
      );
    }

    const accessToken = asString(payload.access_token);
    if (!accessToken) {
      throw new Error("CrowdStrike OAuth2 token response did not include access_token.");
    }
    const expiresIn = asNumber(payload.expires_in) ?? DEFAULT_TOKEN_TTL_SECONDS;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = Date.now() + Math.max(expiresIn * 1000 - TOKEN_SKEW_MS, TOKEN_SKEW_MS);
    return accessToken;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.accessTokenExpiresAt) {
      return this.accessToken;
    }
    if (!this.accessTokenPromise) {
      this.accessTokenPromise = this.fetchAccessToken();
    }
    try {
      return await this.accessTokenPromise;
    } finally {
      this.accessTokenPromise = undefined;
    }
  }

  private invalidateToken(): void {
    this.accessToken = undefined;
    this.accessTokenExpiresAt = 0;
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    options: { query?: JsonRecord; body?: unknown } = {},
  ): Promise<JsonRecord> {
    const url = this.buildUrl(path, options.query);
    let refreshedToken = false;
    for (let attempt = 0; ; attempt += 1) {
      const headers = new Headers({ accept: "application/json" });
      headers.set("authorization", `Bearer ${await this.getAccessToken()}`);
      if (options.body !== undefined) headers.set("content-type", "application/json");

      const response = await this.fetchWithTimeout(url, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });

      if (response.status === 401 && !refreshedToken) {
        refreshedToken = true;
        this.invalidateToken();
        continue;
      }

      if ((response.status === 429 || response.status >= 500) && attempt < this.retryLimit) {
        await this.sleep(retryDelayFromResponse(response, attempt));
        continue;
      }

      const rawText = await response.text();
      const payload = parseJsonText(rawText);
      if (!response.ok) {
        const detail = falconErrorSummary(payload) ?? rawText.slice(0, 200);
        throw new CrowdstrikeHttpError(
          this.redact(`CrowdStrike request failed for ${path} (${response.status})${detail ? `: ${detail}` : ""}`),
          response.status,
          path,
        );
      }
      return payload;
    }
  }

  async getJson(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    return this.request("GET", path, { query });
  }

  async postJson(path: string, body: unknown, query: JsonRecord = {}): Promise<JsonRecord> {
    return this.request("POST", path, { query, body });
  }

  async getResources(path: string, query: JsonRecord = {}): Promise<unknown[]> {
    const payload = await this.getJson(path, query);
    return asArray(payload.resources);
  }

  async getTotal(path: string, query: JsonRecord = {}): Promise<number | undefined> {
    const payload = await this.getJson(path, { ...query, limit: 1 });
    return asNumber(paginationOf(payload).total);
  }

  async listOffset(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<CrowdstrikePage<unknown>> {
    const limit = clampNumber(options.limit, DEFAULT_POLICY_LIMIT, 1, 100_000);
    const pageSize = Math.min(clampNumber(options.pageSize, DEFAULT_POLICY_PAGE_SIZE, 1, 10_000), limit);
    const items: unknown[] = [];
    const seenCursors = new Set<string>();
    let offset: number | string = 0;
    let total: number | undefined;
    let moreAvailable = false;

    while (items.length < limit) {
      const requested = Math.min(pageSize, limit - items.length);
      const payload = await this.getJson(path, {
        ...query,
        limit: requested,
        offset: offset === 0 ? undefined : offset,
      });
      const pageItems = asArray(payload.resources);
      items.push(...pageItems);
      const pagination = paginationOf(payload);
      total = asNumber(pagination.total) ?? total;
      if (pageItems.length === 0) break;
      if (total !== undefined && items.length >= total) break;

      const nextCursor = asString(pagination.next) ?? asString(pagination.offset);
      const opaqueCursor = nextCursor !== undefined && !/^\d+$/.test(nextCursor) ? nextCursor : undefined;
      if (items.length >= limit) {
        moreAvailable = total !== undefined ? items.length < total : opaqueCursor !== undefined || pageItems.length >= requested;
        break;
      }
      if (opaqueCursor !== undefined) {
        if (seenCursors.has(opaqueCursor)) {
          moreAvailable = true;
          break;
        }
        seenCursors.add(opaqueCursor);
        offset = opaqueCursor;
        continue;
      }
      offset = (typeof offset === "number" ? offset : 0) + pageItems.length;
    }

    return pageOf(items.slice(0, limit), total, moreAvailable);
  }

  private async paginateAfter(
    loadPage: (after: string | undefined, pageLimit: number) => Promise<JsonRecord>,
    limit: number,
    pageSize: number,
  ): Promise<CrowdstrikePage<unknown>> {
    const items: unknown[] = [];
    let after: string | undefined;
    let total: number | undefined;
    let moreAvailable = false;

    while (items.length < limit) {
      const payload = await loadPage(after, Math.min(pageSize, limit - items.length));
      const pageItems = asArray(payload.resources);
      items.push(...pageItems);
      const pagination = paginationOf(payload);
      total = asNumber(pagination.total) ?? total;
      const nextAfter = asString(pagination.after);
      if (!nextAfter) break;
      if (items.length >= limit || pageItems.length === 0 || nextAfter === after) {
        moreAvailable = total === undefined || items.length < total;
        break;
      }
      after = nextAfter;
    }

    return pageOf(items.slice(0, limit), total, moreAvailable);
  }

  async listAfter(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<CrowdstrikePage<unknown>> {
    const limit = clampNumber(options.limit, DEFAULT_HOST_PAGE_SIZE, 1, 100_000);
    const pageSize = Math.min(clampNumber(options.pageSize, DEFAULT_HOST_PAGE_SIZE, 1, 10_000), limit);
    return this.paginateAfter((after, pageLimit) => this.getJson(path, { ...query, limit: pageLimit, after }), limit, pageSize);
  }

  async getByIds(path: string, ids: string[], batchSize = DEFAULT_ID_BATCH_SIZE): Promise<JsonRecord[]> {
    const results: JsonRecord[] = [];
    for (let index = 0; index < ids.length; index += batchSize) {
      const batch = ids.slice(index, index + batchSize);
      if (batch.length === 0) continue;
      const payload = await this.getJson(path, { ids: batch });
      results.push(...asRecordArray(payload.resources));
    }
    return results;
  }

  private async listRecords(path: string, query: JsonRecord = {}, options: { limit?: number; pageSize?: number } = {}): Promise<CrowdstrikePage<JsonRecord>> {
    const page = await this.listOffset(path, query, options);
    return recordPage(page, asRecordArray(page.items));
  }

  private async listEntitiesByQuery(
    queryPath: string,
    entityPath: string,
    query: JsonRecord,
    options: { limit?: number; pageSize?: number },
  ): Promise<CrowdstrikePage<JsonRecord>> {
    const idPage = await this.listOffset(queryPath, query, options);
    const entities = await this.getByIds(entityPath, asStringArray(idPage.items));
    return recordPage(idPage, entities);
  }

  private async listEntitiesBySinglePageQuery(queryPath: string, entityPath: string, query: JsonRecord = {}): Promise<CrowdstrikePage<JsonRecord>> {
    const payload = await this.getJson(queryPath, query);
    const ids = asStringArray(asArray(payload.resources));
    const total = asNumber(paginationOf(payload).total);
    const idPage = pageOf(ids, total, total === undefined);
    const entities = await this.getByIds(entityPath, ids);
    return recordPage(idPage, entities);
  }

  async listPreventionPolicies(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/policy/combined/prevention/v1", {}, { limit });
  }

  async listResponsePolicies(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/policy/combined/response/v1", {}, { limit });
  }

  async listDeviceControlPolicies(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/policy/combined/device-control/v1", {}, { limit });
  }

  async getDeviceControlPoliciesV2(ids: string[]): Promise<JsonRecord[]> {
    return this.getByIds("/policy/entities/device-control/v2", ids);
  }

  async listFirewallPolicies(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/policy/combined/firewall/v1", {}, { limit });
  }

  async getFirewallPolicyContainers(ids: string[]): Promise<JsonRecord[]> {
    return this.getByIds("/fwmgr/entities/policies/v1", ids);
  }

  async listFirewallRuleGroups(limit = DEFAULT_RULE_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/fwmgr/queries/rule-groups/v1", "/fwmgr/entities/rule-groups/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async listFirewallRules(limit = DEFAULT_RULE_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/fwmgr/queries/rules/v1", "/fwmgr/entities/rules/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async listSensorUpdatePolicies(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/policy/combined/sensor-update/v2", {}, { limit });
  }

  async listSensorUpdateBuilds(platform: string): Promise<JsonRecord[]> {
    return asRecordArray(await this.getResources("/policy/combined/sensor-update-builds/v1", { platform }));
  }

  async listHosts(limit = DEFAULT_HOST_LIMIT, filter?: string): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords(
      "/devices/combined/devices/v1",
      {
        filter,
        sort: "device_id.asc",
        fields: "device_id,hostname,platform_name,os_version,agent_version,last_seen,first_seen,status,groups,product_type_desc,reduced_functionality_mode,modified_timestamp",
      },
      { limit, pageSize: DEFAULT_HOST_PAGE_SIZE },
    );
  }

  async listHostGroups(limit = DEFAULT_POLICY_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords("/devices/combined/host-groups/v1", {}, { limit });
  }

  async listUserUuids(limit = DEFAULT_USER_LIMIT): Promise<CrowdstrikePage<string>> {
    const page = await this.listOffset("/user-management/queries/users/v1", {}, { limit, pageSize: Math.min(limit, 500) });
    return { items: asStringArray(page.items), total: page.total, truncated: page.truncated };
  }

  async getUsers(uuids: string[]): Promise<JsonRecord[]> {
    const results: JsonRecord[] = [];
    for (let index = 0; index < uuids.length; index += DEFAULT_ID_BATCH_SIZE) {
      const batch = uuids.slice(index, index + DEFAULT_ID_BATCH_SIZE);
      const payload = await this.postJson("/user-management/entities/users/GET/v1", { ids: batch });
      results.push(...asRecordArray(payload.resources));
    }
    return results;
  }

  async listUserRoles(userUuid: string): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords(
      "/user-management/combined/user-roles/v2",
      { user_uuid: userUuid, direct_only: false },
      { limit: 500, pageSize: 500 },
    );
  }

  async listRoles(): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesBySinglePageQuery("/user-management/queries/roles/v1", "/user-management/entities/roles/v1");
  }

  async listApiClients(limit = DEFAULT_USER_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/api-clients/queries/api-clients/v1", "/api-clients/entities/api-clients/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async countDiscoverHosts(filter: string): Promise<number | undefined> {
    return this.getTotal("/discover/queries/hosts/v1", { filter });
  }

  async listDiscoverHosts(filter: string, limit = 100): Promise<CrowdstrikePage<JsonRecord>> {
    const page = await this.listAfter("/discover/combined/hosts/v1", { filter }, { limit, pageSize: Math.min(limit, 1000) });
    return recordPage(page, asRecordArray(page.items));
  }

  async listAlerts(filter: string, limit = DEFAULT_ALERT_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    const page = await this.paginateAfter(
      (after, pageLimit) => this.postJson("/alerts/combined/alerts/v1", {
        filter,
        limit: pageLimit,
        sort: "created_timestamp|desc",
        ...(after ? { after } : {}),
      }),
      clampNumber(limit, DEFAULT_ALERT_LIMIT, 1, 100_000),
      1000,
    );
    return recordPage(page, asRecordArray(page.items));
  }

  async listIoaExclusions(limit = DEFAULT_EXCLUSION_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/policy/queries/ioa-exclusions/v1", "/policy/entities/ioa-exclusions/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async listMlExclusions(limit = DEFAULT_EXCLUSION_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/policy/queries/ml-exclusions/v1", "/policy/entities/ml-exclusions/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async listSensorVisibilityExclusions(limit = DEFAULT_EXCLUSION_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesByQuery("/policy/queries/sv-exclusions/v1", "/policy/entities/sv-exclusions/v1", {}, { limit, pageSize: Math.min(limit, 500) });
  }

  async countZtaAssessments(filter: string): Promise<number | undefined> {
    return this.getTotal("/zero-trust-assessment/queries/assessments/v1", { filter });
  }

  async listZtaAssessments(filter: string, limit = 1000): Promise<CrowdstrikePage<JsonRecord>> {
    const page = await this.listAfter(
      "/zero-trust-assessment/queries/assessments/v1",
      { filter, sort: "score|asc" },
      { limit, pageSize: Math.min(limit, 1000) },
    );
    return recordPage(page, asRecordArray(page.items));
  }

  async listIdentityProtectionRules(): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listEntitiesBySinglePageQuery("/identity-protection/queries/policy-rules/v1", "/identity-protection/entities/policy-rules/v1");
  }

  async listRtrSessions(filter: string, limit = DEFAULT_SESSION_LIMIT): Promise<CrowdstrikePage<JsonRecord>> {
    return this.listRecords(
      "/real-time-response-audit/combined/sessions/v1",
      { filter, sort: "created_at|desc" },
      { limit, pageSize: Math.min(limit, 500) },
    );
  }
}

type AccessProbeClient = Pick<CrowdstrikeApiClient, "getResolvedConfig" | "getJson" | "postJson">;

interface AccessProbe {
  name: string;
  endpoint: string;
  scope: string;
  load: (client: AccessProbeClient) => Promise<JsonRecord>;
}

function totalOrResourceCount(payload: JsonRecord): number | undefined {
  return asNumber(paginationOf(payload).total) ?? asArray(payload.resources).length;
}

const ACCESS_PROBES: AccessProbe[] = [
  { name: "prevention_policies", endpoint: "/policy/combined/prevention/v1", scope: "Prevention policies: Read", load: (client) => client.getJson("/policy/combined/prevention/v1", { limit: 1 }) },
  { name: "response_policies", endpoint: "/policy/combined/response/v1", scope: "Response policies: Read", load: (client) => client.getJson("/policy/combined/response/v1", { limit: 1 }) },
  { name: "device_control_policies", endpoint: "/policy/combined/device-control/v1", scope: "Device control policies: Read", load: (client) => client.getJson("/policy/combined/device-control/v1", { limit: 1 }) },
  { name: "firewall_policies", endpoint: "/policy/combined/firewall/v1", scope: "Firewall management: Read", load: (client) => client.getJson("/policy/combined/firewall/v1", { limit: 1 }) },
  { name: "firewall_rule_groups", endpoint: "/fwmgr/queries/rule-groups/v1", scope: "Firewall management: Read", load: (client) => client.getJson("/fwmgr/queries/rule-groups/v1", { limit: 1 }) },
  { name: "sensor_update_policies", endpoint: "/policy/combined/sensor-update/v2", scope: "Sensor update policies: Read", load: (client) => client.getJson("/policy/combined/sensor-update/v2", { limit: 1 }) },
  { name: "hosts", endpoint: "/devices/combined/devices/v1", scope: "Hosts: Read", load: (client) => client.getJson("/devices/combined/devices/v1", { limit: 1 }) },
  { name: "host_groups", endpoint: "/devices/combined/host-groups/v1", scope: "Host groups: Read", load: (client) => client.getJson("/devices/combined/host-groups/v1", { limit: 1 }) },
  { name: "users", endpoint: "/user-management/queries/users/v1", scope: "User management: Read", load: (client) => client.getJson("/user-management/queries/users/v1", { limit: 1 }) },
  { name: "roles", endpoint: "/user-management/queries/roles/v1", scope: "User management: Read", load: (client) => client.getJson("/user-management/queries/roles/v1") },
  { name: "api_clients", endpoint: "/api-clients/queries/api-clients/v1", scope: "API integrations (Api Client Mgmt): Read", load: (client) => client.getJson("/api-clients/queries/api-clients/v1", { limit: 1 }) },
  { name: "discover_hosts", endpoint: "/discover/queries/hosts/v1", scope: "Assets (Falcon Discover): Read", load: (client) => client.getJson("/discover/queries/hosts/v1", { limit: 1 }) },
  { name: "alerts", endpoint: "/alerts/queries/alerts/v2", scope: "Alerts: Read", load: (client) => client.getJson("/alerts/queries/alerts/v2", { limit: 1 }) },
  { name: "ioa_exclusions", endpoint: "/policy/queries/ioa-exclusions/v1", scope: "IOA Exclusions: Read", load: (client) => client.getJson("/policy/queries/ioa-exclusions/v1", { limit: 1 }) },
  { name: "ml_exclusions", endpoint: "/policy/queries/ml-exclusions/v1", scope: "Machine Learning Exclusions: Read", load: (client) => client.getJson("/policy/queries/ml-exclusions/v1", { limit: 1 }) },
  { name: "sensor_visibility_exclusions", endpoint: "/policy/queries/sv-exclusions/v1", scope: "Sensor Visibility Exclusions: Read", load: (client) => client.getJson("/policy/queries/sv-exclusions/v1", { limit: 1 }) },
  { name: "zero_trust_assessment", endpoint: "/zero-trust-assessment/queries/assessments/v1", scope: "Zero Trust Assessment: Read", load: (client) => client.getJson("/zero-trust-assessment/queries/assessments/v1", { filter: "score:>=0", limit: 1 }) },
  { name: "identity_protection_rules", endpoint: "/identity-protection/queries/policy-rules/v1", scope: "Identity Protection Policy Rules: Read", load: (client) => client.getJson("/identity-protection/queries/policy-rules/v1") },
  { name: "rtr_audit_sessions", endpoint: "/real-time-response-audit/combined/sessions/v1", scope: "Real time response audit: Read", load: (client) => client.getJson("/real-time-response-audit/combined/sessions/v1", { limit: 1 }) },
];

const HEALTHY_SURFACE_FLOOR = 15;

export async function checkCrowdstrikeAccess(client: AccessProbeClient): Promise<CrowdstrikeAccessCheckResult> {
  const config = client.getResolvedConfig();
  const surfaces: CrowdstrikeAccessSurface[] = [];
  for (const probe of ACCESS_PROBES) {
    try {
      const payload = await probe.load(client);
      surfaces.push({
        name: probe.name,
        endpoint: probe.endpoint,
        scope: probe.scope,
        status: "readable",
        count: totalOrResourceCount(payload),
      });
    } catch (error) {
      const forbidden = error instanceof CrowdstrikeHttpError && (error.status === 401 || error.status === 403);
      surfaces.push({
        name: probe.name,
        endpoint: probe.endpoint,
        scope: probe.scope,
        status: forbidden ? "forbidden" : "not_readable",
        error: summarizeError(error),
      });
    }
  }

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const missingScopes = [...new Set(surfaces.filter((surface) => surface.status === "forbidden").map((surface) => surface.scope))];
  const status = readableCount >= HEALTHY_SURFACE_FLOOR ? "healthy" : "limited";

  return {
    status,
    baseUrl: config.baseUrl,
    memberCid: config.memberCid,
    surfaces,
    missingScopes,
    notes: [
      `Using Falcon API ${config.baseUrl}${config.cloud ? ` (${config.cloud})` : ""}${config.memberCid ? ` for member CID ${config.memberCid}` : ""}.`,
      `${readableCount}/${surfaces.length} CrowdStrike audit surfaces are readable.`,
      missingScopes.length > 0
        ? `Missing API client scopes: ${missingScopes.join("; ")}.`
        : "No 401 or 403 responses were observed, so the API client scopes cover the probed read surfaces.",
      config.memberCid
        ? `Scope: results cover member CID ${config.memberCid} only; other Flight Control children need separate runs.`
        : "Scope: results cover the CID that issued the API client; Flight Control child tenants need CS_MEMBER_CID runs.",
      "All probes are read-only; the tools never modify the Falcon tenant.",
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run crowdstrike_assess_prevention_policies, crowdstrike_assess_response_readiness, crowdstrike_assess_device_firewall, crowdstrike_assess_sensor_coverage, crowdstrike_assess_access_governance, or crowdstrike_export_audit_bundle."
        : "Grant the missing read scopes to the Falcon API client (Support and resources > API clients and keys) and rerun crowdstrike_check_access.",
  };
}

interface FlatSetting {
  id: string;
  type?: string;
  value: JsonRecord;
}

function flattenPolicySettings(policy: JsonRecord, key: "prevention_settings" | "settings"): Map<string, FlatSetting> {
  const flattened = new Map<string, FlatSetting>();
  for (const category of asRecordArray(policy[key])) {
    for (const setting of asRecordArray(category.settings)) {
      const id = asString(setting.id);
      if (!id) continue;
      flattened.set(id, { id, type: asString(setting.type), value: asObject(setting.value) ?? {} });
    }
  }
  return flattened;
}

function toggleState(settings: Map<string, FlatSetting>, id: string): boolean | undefined {
  const setting = settings.get(id);
  if (!setting) return undefined;
  return asBoolean(setting.value.enabled);
}

function sliderLevels(settings: Map<string, FlatSetting>, id: string): { detection?: string; prevention?: string } | undefined {
  const setting = settings.get(id);
  if (!setting) return undefined;
  return {
    detection: asString(setting.value.detection)?.toUpperCase(),
    prevention: asString(setting.value.prevention)?.toUpperCase(),
  };
}

function sliderRank(level: string | undefined): number | undefined {
  if (!level) return undefined;
  return ML_SLIDER_RANK[level];
}

function policyLabel(policy: JsonRecord): string {
  const name = asString(policy.name) ?? asString(policy.id) ?? "policy";
  const platform = asString(policy.platform_name);
  return platform ? `${name} (${platform})` : name;
}

function enabledPolicies(policies: JsonRecord[]): JsonRecord[] {
  return policies.filter((policy) => asBoolean(policy.enabled) === true);
}

function isPlatformDefaultPolicy(policy: JsonRecord): boolean {
  return asBoolean(policy.platform_default) === true || (asString(policy.name) ?? "").toLowerCase() === "platform_default";
}

function policyAppliesToHosts(policy: JsonRecord): boolean {
  return asBoolean(policy.enabled) === true && (asArray(policy.groups).length > 0 || isPlatformDefaultPolicy(policy));
}

function assignedPolicies(policies: JsonRecord[]): JsonRecord[] {
  return policies.filter(policyAppliesToHosts);
}

function unassignedEnabledPolicies(policies: JsonRecord[]): JsonRecord[] {
  return enabledPolicies(policies).filter((policy) => !policyAppliesToHosts(policy));
}

function policyInventory(policies: JsonRecord[]): JsonRecord {
  return {
    total_policies: policies.length,
    enabled_policies: enabledPolicies(policies).length,
    enabled_and_assigned_policies: assignedPolicies(policies).length,
    enabled_but_unassigned_policies: unassignedEnabledPolicies(policies).map(policyLabel),
  };
}

function platformsCovered(policies: JsonRecord[]): string[] {
  return [...new Set(policies.map((policy) => asString(policy.platform_name)).filter((item): item is string => Boolean(item)))].sort();
}

function missingPlatforms(policies: JsonRecord[]): string[] {
  const covered = new Set(platformsCovered(policies).map((platform) => platform.toLowerCase()));
  return ["Windows", "Mac", "Linux"].filter((platform) => !covered.has(platform.toLowerCase()));
}

function noAssignedPolicyFinding(id: ControlId, policyKind: string, policies: JsonRecord[]): CrowdstrikeFinding {
  const inventory = policyInventory(policies);
  if (policies.length === 0) {
    return finding(id, "fail", `The ${policyKind} policies endpoint was readable but returned zero policies; with no ${policyKind} policy defined this control fails.`, inventory);
  }
  return finding(
    id,
    "fail",
    `None of the ${policies.length} ${policyKind} policies is both enabled and assigned to host groups (${inventory.enabled_policies as number} enabled, ${(inventory.enabled_but_unassigned_policies as string[]).length} enabled but unassigned), so the control is not enforced on any host.`,
    inventory,
  );
}

function evaluateMlDetectionLevels(policies: JsonRecord[]): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-01", "prevention", policies);

  const perPolicy = applied.map((policy) => {
    const settings = flattenPolicySettings(policy, "prevention_settings");
    const sliders: JsonRecord = {};
    let minRank: number | undefined;
    let incomplete = false;
    for (const sliderId of PRIMARY_ML_SLIDERS) {
      const levels = sliderLevels(settings, sliderId);
      if (!levels) {
        incomplete = true;
        continue;
      }
      sliders[sliderId] = levels;
      const detectionRank = sliderRank(levels.detection);
      const preventionRank = sliderRank(levels.prevention);
      if (detectionRank === undefined || preventionRank === undefined) incomplete = true;
      for (const rank of [detectionRank, preventionRank]) {
        if (rank === undefined) continue;
        minRank = minRank === undefined ? rank : Math.min(minRank, rank);
      }
    }
    for (const sliderId of SUPPLEMENTAL_ML_SLIDERS) {
      const levels = sliderLevels(settings, sliderId);
      if (levels) sliders[sliderId] = levels;
    }
    const status: CrowdstrikeFinding["status"] = minRank !== undefined && minRank <= ML_SLIDER_RANK.CAUTIOUS
      ? "fail"
      : incomplete || minRank === undefined
        ? "warn"
        : minRank >= ML_SLIDER_RANK.AGGRESSIVE
          ? "pass"
          : "warn";
    return { policy: policyLabel(policy), status, min_rank: minRank, sliders_complete: !incomplete, sliders };
  });

  const missing = missingPlatforms(applied);
  const statuses = perPolicy.map((item) => item.status);
  if (missing.length > 0) statuses.push("warn");
  const status = worstStatus(statuses);
  const weak = perPolicy.filter((item) => item.status !== "pass").map((item) => item.policy);
  return finding(
    "CS-01",
    status,
    status === "pass"
      ? `All ${applied.length} enabled and host-assigned prevention policies keep Cloud and Sensor Anti-malware detection and prevention at AGGRESSIVE or higher.`
      : `${weak.length}/${applied.length} enabled and host-assigned prevention policies have ML sliders below AGGRESSIVE, missing, or incomplete${missing.length > 0 ? `; no assigned policy covers ${missing.join(", ")}` : ""}.`,
    { ...policyInventory(policies), platforms_without_policy: missing, policies: perPolicy },
  );
}

function evaluateToggleControl(
  id: ControlId,
  policies: JsonRecord[],
  requiredToggles: string[],
  supplementalToggles: string[],
  options: { policyKind: string; passSummary: string; skipPoliciesWithoutSettings?: boolean; failWhenDisabled: string[] },
): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding(id, options.policyKind, policies);

  const perPolicy: Array<{ policy: string; status: CrowdstrikeFinding["status"]; disabled: string[]; missing: string[]; toggles: JsonRecord }> = [];
  for (const policy of applied) {
    const settings = flattenPolicySettings(policy, "prevention_settings");
    const present = requiredToggles.filter((toggle) => settings.has(toggle));
    if (present.length === 0 && options.skipPoliciesWithoutSettings) continue;
    const disabled = present.filter((toggle) => toggleState(settings, toggle) !== true);
    const missing = requiredToggles.filter((toggle) => !settings.has(toggle));
    const toggles: JsonRecord = {};
    for (const toggle of [...requiredToggles, ...supplementalToggles]) {
      const state = toggleState(settings, toggle);
      if (state !== undefined) toggles[toggle] = state;
    }
    const hardFail = disabled.some((toggle) => options.failWhenDisabled.includes(toggle));
    const status: CrowdstrikeFinding["status"] = disabled.length === 0
      ? (present.length === 0 ? "warn" : "pass")
      : hardFail
        ? "fail"
        : "warn";
    perPolicy.push({ policy: policyLabel(policy), status, disabled, missing, toggles });
  }

  if (perPolicy.length === 0) {
    return finding(id, "warn", `None of the ${applied.length} enabled and host-assigned ${options.policyKind} policies expose ${requiredToggles.join(", ")}, so the control could not be evaluated from the API and cannot pass.`, { ...policyInventory(policies), required_settings: requiredToggles });
  }

  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  return finding(
    id,
    status,
    status === "pass"
      ? `${options.passSummary} across ${perPolicy.length} enabled and host-assigned ${options.policyKind} policies.`
      : `${weak.length}/${perPolicy.length} enabled and host-assigned ${options.policyKind} policies have ${requiredToggles.join(", ")} disabled or missing: ${weak.map((item) => `${item.policy} [${[...item.disabled, ...item.missing.map((toggle) => `${toggle}?`)].join(", ")}]`).join("; ")}.`,
    { ...policyInventory(policies), evaluated_policies: perPolicy.length, required_settings: requiredToggles, policies: perPolicy },
  );
}

function evaluateOnWriteDetection(policies: JsonRecord[]): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-05", "prevention", policies);

  const perPolicy = applied.map((policy) => {
    const settings = flattenPolicySettings(policy, "prevention_settings");
    const detect = toggleState(settings, ON_WRITE_DETECT_SETTING);
    const quarantine = toggleState(settings, ON_WRITE_QUARANTINE_SETTING);
    const supplemental: JsonRecord = {};
    for (const toggle of SUPPLEMENTAL_ON_WRITE_SETTINGS) {
      const state = toggleState(settings, toggle);
      if (state !== undefined) supplemental[toggle] = state;
    }
    const status: CrowdstrikeFinding["status"] = detect === undefined
      ? "warn"
      : detect !== true
        ? "fail"
        : quarantine === true
          ? "pass"
          : "warn";
    return { policy: policyLabel(policy), status, detect_on_write: detect, quarantine_on_write: quarantine, supplemental };
  });

  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  return finding(
    "CS-05",
    status,
    status === "pass"
      ? `DetectOnWrite and QuarantineOnWrite are enabled across ${perPolicy.length} enabled and host-assigned prevention policies.`
      : `${weak.length}/${perPolicy.length} enabled and host-assigned prevention policies do not fully enable on-write detection and quarantine: ${weak.map((item) => item.policy).join(", ")}.`,
    { ...policyInventory(policies), evaluated_policies: perPolicy.length, policies: perPolicy },
  );
}

function assessmentSummaryBase(config: CrowdstrikeResolvedConfig): JsonRecord {
  return {
    base_url: config.baseUrl,
    scope: config.memberCid ? `member CID ${config.memberCid} only` : "issuing CID only (Flight Control children need CS_MEMBER_CID runs)",
  };
}

function statusCounts(findings: CrowdstrikeFinding[]): JsonRecord {
  return {
    failing_controls: findings.filter((item) => item.status === "fail").length,
    warning_controls: findings.filter((item) => item.status === "warn").length,
    manual_controls: findings.filter((item) => item.status === "manual").length,
    passing_controls: findings.filter((item) => item.status === "pass").length,
  };
}

const PREVENTION_CONSOLE_EVIDENCE = "export each prevention policy from Falcon console > Endpoint security > Prevention policies and capture the ML slider, exploit mitigation, script control, tamper protection, and on-write settings together with the assigned host groups.";

export async function assessCrowdstrikePreventionPolicies(
  client: Pick<CrowdstrikeApiClient, "getResolvedConfig" | "listPreventionPolicies">,
): Promise<CrowdstrikeAssessmentResult> {
  const policiesDataset = await collectDataset(() => client.listPreventionPolicies(), emptyPage<JsonRecord>(), "prevention policies");
  const policies = policiesDataset.data.items;
  const partial = partialInventory(policiesDataset.data, "prevention policies");
  const controls: ControlId[] = ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05"];

  const findings = policiesDataset.error
    ? controls.map((id) => unreadableFinding(id, "prevention policies", policiesDataset.error ?? "unknown error", PREVENTION_CONSOLE_EVIDENCE))
    : [
      evaluateMlDetectionLevels(policies),
      evaluateToggleControl("CS-02", policies, [...CORE_EXPLOIT_MITIGATIONS, ...EXTENDED_EXPLOIT_MITIGATIONS], [], {
        policyKind: "prevention",
        passSummary: "Exploit mitigation toggles are enabled",
        skipPoliciesWithoutSettings: true,
        failWhenDisabled: CORE_EXPLOIT_MITIGATIONS,
      }),
      evaluateToggleControl("CS-03", policies, SCRIPT_CONTROL_SETTINGS, SUPPLEMENTAL_SCRIPT_SETTINGS, {
        policyKind: "prevention",
        passSummary: "Script-based execution monitoring, interpreter protection, and engine protection are enabled",
        skipPoliciesWithoutSettings: true,
        failWhenDisabled: SCRIPT_CONTROL_SETTINGS,
      }),
      evaluateToggleControl("CS-04", policies, [TAMPER_PROTECTION_SETTING], [], {
        policyKind: "prevention",
        passSummary: "Sensor tampering protection is enabled",
        failWhenDisabled: [TAMPER_PROTECTION_SETTING],
      }),
      evaluateOnWriteDetection(policies),
    ].map((item) => withPartialInventory(item, [partial]));

  return {
    title: "CrowdStrike prevention policy posture",
    category: "prevention_policies",
    summary: {
      ...assessmentSummaryBase(client.getResolvedConfig()),
      ...policyInventory(policies),
      policies_truncated: policiesDataset.data.truncated,
      platforms_covered: platformsCovered(assignedPolicies(policies)).join(", ") || "none",
      ...statusCounts(findings),
    },
    findings,
    errors: listErrors([policiesDataset]),
    snapshots: { prevention_policies: policies },
  };
}

function evaluateRtrPolicies(policies: JsonRecord[]): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-06", "response", policies);

  const perPolicy = applied.map((policy) => {
    const settings = flattenPolicySettings(policy, "settings");
    const toggles: JsonRecord = {};
    for (const id of RESPONSE_POLICY_SETTINGS) {
      const state = toggleState(settings, id);
      if (state !== undefined) toggles[id] = state;
    }
    const rtrEnabled = toggleState(settings, "RealTimeFunctionality");
    const customScripts = toggleState(settings, "CustomScripts");
    const status: CrowdstrikeFinding["status"] = rtrEnabled !== true
      ? "fail"
      : customScripts === true
        ? "warn"
        : "pass";
    return { policy: policyLabel(policy), status, rtr_enabled: rtrEnabled, custom_scripts: customScripts, toggles };
  });

  const anyRtr = perPolicy.some((item) => item.rtr_enabled === true);
  const status: CrowdstrikeFinding["status"] = !anyRtr
    ? "fail"
    : worstStatus(perPolicy.map((item) => item.status === "fail" ? "warn" : item.status));
  return finding(
    "CS-06",
    status,
    !anyRtr
      ? "Real Time Response is disabled in every enabled and host-assigned response policy, which removes remote investigation and containment capability."
      : status === "pass"
        ? `Real Time Response is enabled and custom scripts are restricted across ${perPolicy.length} enabled and host-assigned response policies.`
        : `Real Time Response is enabled, but ${perPolicy.filter((item) => item.status !== "pass").length}/${perPolicy.length} enabled and host-assigned response policies allow custom scripts or disable RTR: ${perPolicy.filter((item) => item.status !== "pass").map((item) => item.policy).join(", ")}.`,
    { ...policyInventory(policies), policies: perPolicy },
  );
}

function sessionWindow(session: JsonRecord): { start?: number; end?: number; minutes?: number } {
  const start = parseTimestamp(session.created_at);
  const end = parseTimestamp(session.deleted_at) ?? parseTimestamp(session.updated_at);
  const durationSeconds = asNumber(session.duration);
  const minutes = durationSeconds !== undefined && durationSeconds > 0
    ? durationSeconds / 60
    : start !== undefined && end !== undefined
      ? (end - start) / 60_000
      : undefined;
  return { start, end, minutes };
}

function maxConcurrentSessionsPerUser(sessions: JsonRecord[]): { user: string; concurrent: number } {
  let best = { user: "none", concurrent: 0 };
  const byUser = new Map<string, Array<{ start: number; end: number }>>();
  for (const session of sessions) {
    const window = sessionWindow(session);
    if (window.start === undefined) continue;
    const user = asString(session.user_id) ?? asString(session.user_uuid) ?? "unknown";
    const list = byUser.get(user) ?? [];
    list.push({ start: window.start, end: window.end ?? window.start });
    byUser.set(user, list);
  }
  for (const [user, windows] of byUser) {
    for (const window of windows) {
      const concurrent = windows.filter((other) => other.start <= window.start && other.end >= window.start).length;
      if (concurrent > best.concurrent) best = { user, concurrent };
    }
  }
  return best;
}

const SESSION_CONSOLE_EVIDENCE = "capture the Real Time Response session timeout and concurrent session limit from Falcon console > Endpoint security > Response policies, and attach the RTR audit log export for the review period.";

function evaluateSessionLimits(
  sessions: CollectedDataset<CrowdstrikePage<JsonRecord>>,
  maxSessionMinutes: number,
  maxConcurrentSessions: number,
  lookbackDays: number,
): CrowdstrikeFinding {
  if (sessions.error) {
    return unreadableFinding("CS-07", "RTR audit sessions", sessions.error, SESSION_CONSOLE_EVIDENCE);
  }
  const windows = sessions.data.items.map((session) => ({ session, window: sessionWindow(session) }));
  const undated = windows.filter((item) => item.window.start === undefined).length;
  const long = windows.filter((item) => item.window.minutes !== undefined && item.window.minutes > maxSessionMinutes);
  const concurrency = maxConcurrentSessionsPerUser(sessions.data.items);
  const evidence: JsonRecord = {
    lookback_days: lookbackDays,
    sessions_reviewed: sessions.data.items.length,
    sessions_without_created_at: undated,
    sessions_over_limit: long.length,
    longest_session_minutes: Math.round(Math.max(0, ...windows.map((item) => item.window.minutes ?? 0))),
    max_session_minutes: maxSessionMinutes,
    max_concurrent_sessions: maxConcurrentSessions,
    peak_concurrent_sessions: concurrency,
    long_session_samples: long.slice(0, 10).map((item) => ({
      id: asString(item.session.id),
      user: asString(item.session.user_id),
      hostname: asString(item.session.hostname),
      minutes: Math.round(item.window.minutes ?? 0),
    })),
  };
  const partial = partialInventory(sessions.data, "RTR audit sessions");
  if (long.length > 0 || concurrency.concurrent > maxConcurrentSessions) {
    return withPartialInventory(finding(
      "CS-07",
      "warn",
      `${long.length}/${sessions.data.items.length} RTR sessions in the last ${lookbackDays} days exceeded ${maxSessionMinutes} minutes and peak per-user concurrency was ${concurrency.concurrent}; the Falcon API does not expose the configured timeout, so confirm the policy values in the console.`,
      evidence,
    ), [partial]);
  }
  return withPartialInventory(manualFinding(
    "CS-07",
    `The RTR audit endpoint was readable and returned ${sessions.data.items.length} sessions in the last ${lookbackDays} days (none longer than ${maxSessionMinutes} minutes, peak per-user concurrency ${concurrency.concurrent}${undated > 0 ? `, ${undated} without a created_at timestamp` : ""}), but the Falcon API does not expose the configured session timeout or concurrent session limit.`,
    SESSION_CONSOLE_EVIDENCE,
    evidence,
  ), [partial]);
}

function alertSlaHours(alert: JsonRecord): number {
  const severity = asNumber(alert.severity) ?? 0;
  const severityName = asString(alert.severity_name)?.toLowerCase();
  return severity >= CRITICAL_SEVERITY_FLOOR || severityName === "critical" ? CRITICAL_SLA_HOURS : HIGH_SLA_HOURS;
}

function alertResolutionHours(alert: JsonRecord, created: number, now: number): { resolved: boolean; hours?: number } {
  const status = asString(alert.status)?.toLowerCase();
  const resolvedSeconds = asNumber(alert.seconds_to_resolved);
  if (status === "closed") {
    if (resolvedSeconds !== undefined && resolvedSeconds > 0) return { resolved: true, hours: resolvedSeconds / 3600 };
    const updated = parseTimestamp(alert.updated_timestamp);
    if (updated !== undefined) return { resolved: true, hours: hoursBetween(created, updated) };
    return { resolved: true };
  }
  return { resolved: false, hours: hoursBetween(created, now) };
}

const ALERT_CONSOLE_EVIDENCE = "export critical and high detections for the review period from Falcon console > Endpoint detections with status and resolution timestamps.";

function evaluateDetectionSla(alerts: CollectedDataset<CrowdstrikePage<JsonRecord>>, lookbackDays: number, now = Date.now()): CrowdstrikeFinding {
  if (alerts.error) {
    return unreadableFinding("CS-22", "alerts", alerts.error, ALERT_CONSOLE_EVIDENCE);
  }
  let withinSla = 0;
  let resolvedCount = 0;
  let undated = 0;
  let dated = 0;
  const breaches: JsonRecord[] = [];
  for (const alert of alerts.data.items) {
    const created = parseTimestamp(alert.created_timestamp) ?? parseTimestamp(alert.timestamp);
    if (created === undefined) {
      undated += 1;
      continue;
    }
    dated += 1;
    const sla = alertSlaHours(alert);
    const resolution = alertResolutionHours(alert, created, now);
    if (resolution.resolved) resolvedCount += 1;
    if (resolution.hours !== undefined && resolution.hours <= sla) {
      if (resolution.resolved) withinSla += 1;
      continue;
    }
    breaches.push({
      id: asString(alert.composite_id) ?? asString(alert.id),
      severity: asString(alert.severity_name) ?? asString(alert.severity),
      status: asString(alert.status),
      hours_open: resolution.hours === undefined ? undefined : Math.round(resolution.hours),
      sla_hours: sla,
    });
  }
  const openBreaches = breaches.filter((item) => item.status !== "closed").length;
  const openWithinSla = Math.max(0, dated - resolvedCount - openBreaches);
  const compliant = withinSla + openWithinSla;
  const pct = percentage(compliant, dated);
  const status: CrowdstrikeFinding["status"] = dated === 0 ? "pass" : pct >= 95 ? "pass" : pct >= 80 ? "warn" : "fail";
  const base = finding(
    "CS-22",
    status,
    dated === 0
      ? `The alerts endpoint was readable and returned no dated critical or high alerts created in the last ${lookbackDays} days (window stated), so there was nothing to respond to; emptiness is compliant for this control.`
      : `${pct}% of ${dated} dated critical/high alerts from the last ${lookbackDays} days were resolved (or remain open) within the ${CRITICAL_SLA_HOURS}h critical / ${HIGH_SLA_HOURS}h high SLA; ${breaches.length} breached the SLA.`,
    {
      lookback_days: lookbackDays,
      alerts_reviewed: alerts.data.items.length,
      alerts_with_created_timestamp: dated,
      resolved_alerts: resolvedCount,
      resolved_within_sla: withinSla,
      sla_breaches: breaches.length,
      breach_samples: breaches.slice(0, 15),
    },
  );
  return withPartialInventory(withUndatedItems(base, undated, "alerts", "created_timestamp"), [partialInventory(alerts.data, "critical/high alerts")]);
}

const CONTAINMENT_CONSOLE_EVIDENCE = "export the contained host list from Falcon console > Host setup and management > Host management filtered by containment status, with containment start dates and incident references.";

function evaluateContainment(hosts: CollectedDataset<CrowdstrikePage<JsonRecord>>, maxContainmentHours: number, now = Date.now()): CrowdstrikeFinding {
  if (hosts.error) {
    return unreadableFinding("CS-23", "contained hosts", hosts.error, CONTAINMENT_CONSOLE_EVIDENCE);
  }
  const contained = hosts.data.items.map((host) => {
    const modified = parseTimestamp(host.modified_timestamp);
    return {
      hostname: asString(host.hostname),
      device_id: asString(host.device_id),
      status: asString(host.status),
      last_seen: asString(host.last_seen),
      hours_since_status_change: modified === undefined ? undefined : Math.round(hoursBetween(modified, now)),
    };
  });
  const undated = contained.filter((host) => host.hours_since_status_change === undefined).length;
  const aged = contained.filter((host) => (host.hours_since_status_change ?? 0) > maxContainmentHours);
  const status: CrowdstrikeFinding["status"] = contained.length === 0 ? "pass" : "warn";
  const base = finding(
    "CS-23",
    status,
    contained.length === 0
      ? "The Hosts API was readable and the containment status filter returned no hosts, so there is no active containment to document; emptiness is compliant for this control."
      : `${contained.length} hosts are network contained or pending containment changes${aged.length > 0 ? `, ${aged.length} for more than ${maxContainmentHours} hours (based on last host record change)` : ""}; document each containment and its incident reference.`,
    { contained_hosts: contained.length, aged_over_hours: maxContainmentHours, hosts: contained.slice(0, 50) },
  );
  return withPartialInventory(withUndatedItems(base, undated, "contained hosts", "modified_timestamp"), [partialInventory(hosts.data, "contained hosts")]);
}

const ALERT_SNAPSHOT_FIELDS = [
  "id",
  "composite_id",
  "aggregate_id",
  "cid",
  "agent_id",
  "product",
  "type",
  "scenario",
  "objective",
  "tactic",
  "tactic_id",
  "technique",
  "technique_id",
  "pattern_id",
  "name",
  "display_name",
  "severity",
  "severity_name",
  "confidence",
  "status",
  "assigned_to_name",
  "resolution",
  "created_timestamp",
  "updated_timestamp",
  "timestamp",
  "seconds_to_triaged",
  "seconds_to_resolved",
  "data_domains",
  "tags",
];
const ALERT_DEVICE_SNAPSHOT_FIELDS = ["device_id", "hostname", "platform_name", "os_version", "agent_version"];
const RTR_SESSION_SNAPSHOT_FIELDS = [
  "id",
  "cid",
  "device_id",
  "hostname",
  "platform_name",
  "platform_id",
  "user_id",
  "user_uuid",
  "created_at",
  "updated_at",
  "deleted_at",
  "duration",
];

function pickFields(record: JsonRecord, fields: string[]): JsonRecord {
  const output: JsonRecord = {};
  for (const field of fields) {
    if (record[field] !== undefined) output[field] = record[field];
  }
  return output;
}

function projectAlert(alert: JsonRecord): JsonRecord {
  const device = asObject(alert.device);
  return {
    ...pickFields(alert, ALERT_SNAPSHOT_FIELDS),
    ...(device ? { device: pickFields(device, ALERT_DEVICE_SNAPSHOT_FIELDS) } : {}),
  };
}

function projectRtrSession(session: JsonRecord): JsonRecord {
  const commands = asRecordArray(session.commands);
  return {
    ...pickFields(session, RTR_SESSION_SNAPSHOT_FIELDS),
    command_count: commands.length,
    base_commands: [...new Set(commands.map((command) => asString(command.base_command)).filter((command): command is string => Boolean(command)))],
  };
}

function projectPage(
  dataset: CollectedDataset<CrowdstrikePage<JsonRecord>>,
  project: (record: JsonRecord) => JsonRecord,
): CollectedDataset<CrowdstrikePage<JsonRecord>> {
  return { ...dataset, data: { ...dataset.data, items: dataset.data.items.map(project) } };
}

export async function assessCrowdstrikeResponseReadiness(
  client: Pick<CrowdstrikeApiClient, "getResolvedConfig" | "listResponsePolicies" | "listRtrSessions" | "listAlerts" | "listHosts">,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAssessmentResult> {
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const alertLimit = clampNumber(options.alertLimit, DEFAULT_ALERT_LIMIT, 1, 10_000);
  const hostLimit = clampNumber(options.hostLimit, DEFAULT_HOST_LIMIT, 1, 100_000);
  const maxSessionMinutes = clampNumber(options.maxSessionMinutes, DEFAULT_MAX_SESSION_MINUTES, 1, 1440);
  const maxConcurrentSessions = clampNumber(options.maxConcurrentSessions, DEFAULT_MAX_CONCURRENT_SESSIONS, 1, 100);

  const policies = await collectDataset(() => client.listResponsePolicies(), emptyPage<JsonRecord>(), "response policies");
  const sessions = projectPage(
    await collectDataset(() => client.listRtrSessions(`created_at:>'now-${lookbackDays}d'`), emptyPage<JsonRecord>(), "rtr audit sessions"),
    projectRtrSession,
  );
  const alerts = projectPage(
    await collectDataset(
      () => client.listAlerts(`severity:>=${HIGH_SEVERITY_FLOOR}+created_timestamp:>'now-${lookbackDays}d'`, alertLimit),
      emptyPage<JsonRecord>(),
      "alerts",
    ),
    projectAlert,
  );
  const containedHosts = await collectDataset(
    () => client.listHosts(hostLimit, "status:['contained','containment_pending','lift_containment_pending']"),
    emptyPage<JsonRecord>(),
    "contained hosts",
  );

  const findings = [
    policies.error
      ? unreadableFinding("CS-06", "response policies", policies.error, "export each response policy from Falcon console > Endpoint security > Response policies showing Real Time Response and custom script settings and the assigned host groups.")
      : withPartialInventory(evaluateRtrPolicies(policies.data.items), [partialInventory(policies.data, "response policies")]),
    evaluateSessionLimits(sessions, maxSessionMinutes, maxConcurrentSessions, lookbackDays),
    evaluateDetectionSla(alerts, lookbackDays),
    evaluateContainment(containedHosts, HIGH_SLA_HOURS),
  ];

  return {
    title: "CrowdStrike response readiness",
    category: "response_readiness",
    summary: {
      ...assessmentSummaryBase(client.getResolvedConfig()),
      lookback_days: lookbackDays,
      response_policies: policies.data.items.length,
      enabled_and_assigned_response_policies: assignedPolicies(policies.data.items).length,
      rtr_sessions_reviewed: sessions.data.items.length,
      critical_high_alerts: alerts.data.items.length,
      alerts_truncated: alerts.data.truncated,
      contained_hosts: containedHosts.data.items.length,
      ...statusCounts(findings),
    },
    findings,
    errors: listErrors([policies, sessions, alerts, containedHosts]),
    snapshots: {
      response_policies: policies.data.items,
      rtr_audit_sessions: sessions.data.items,
      alerts: alerts.data.items,
      contained_hosts: containedHosts.data.items,
    },
  };
}

interface DeviceControlView {
  policy: string;
  applied: boolean;
  usb_enforcement_mode?: string;
  mass_storage_action?: string;
  mass_storage_exceptions: number;
  class_actions: JsonRecord;
  bluetooth_enforcement_mode?: string;
  bluetooth_restricted_classes: number;
  pcie_enforcement_mode?: string;
}

function deviceControlView(policy: JsonRecord, detail: JsonRecord | undefined): DeviceControlView {
  const usbSettings = asObject(detail?.usb_settings) ?? {};
  const bluetoothSettings = asObject(detail?.bluetooth_settings);
  const classActions: JsonRecord = {};
  let massStorageAction: string | undefined;
  let massStorageExceptions = 0;
  for (const deviceClass of asRecordArray(usbSettings.classes)) {
    const id = asString(deviceClass.id) ?? asString(deviceClass.class);
    if (!id) continue;
    const action = asString(deviceClass.action)?.toUpperCase();
    classActions[id] = action;
    if (id.toUpperCase() === "MASS_STORAGE") {
      massStorageAction = action;
      massStorageExceptions = asArray(deviceClass.exceptions).length;
    }
  }
  const bluetoothClasses = bluetoothSettings ? asRecordArray(bluetoothSettings.classes) : [];
  return {
    policy: policyLabel(policy),
    applied: policyAppliesToHosts(policy),
    usb_enforcement_mode: asString(usbSettings.enforcement_mode)?.toUpperCase(),
    mass_storage_action: massStorageAction,
    mass_storage_exceptions: massStorageExceptions,
    class_actions: classActions,
    bluetooth_enforcement_mode: bluetoothSettings ? asString(bluetoothSettings.enforcement_mode)?.toUpperCase() : undefined,
    bluetooth_restricted_classes: bluetoothClasses.filter((item) => asString(item.action)?.toUpperCase() !== "FULL_ACCESS").length,
    pcie_enforcement_mode: asString(usbSettings.pcie_enforcement_mode)?.toUpperCase(),
  };
}

function evaluateUsbBlocking(views: DeviceControlView[], policies: JsonRecord[], maxExceptions: number): CrowdstrikeFinding {
  const applied = views.filter((view) => view.applied);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-08", "device control", policies);

  const perPolicy = applied.map((view) => {
    const enforcing = view.usb_enforcement_mode === "MONITOR_ENFORCE";
    const blocking = view.mass_storage_action !== undefined && view.mass_storage_action !== "FULL_ACCESS";
    const status: CrowdstrikeFinding["status"] = !enforcing || !blocking
      ? "fail"
      : view.mass_storage_exceptions > maxExceptions
        ? "warn"
        : "pass";
    return { ...view, status };
  });
  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  return finding(
    "CS-08",
    status,
    status === "pass"
      ? `All ${perPolicy.length} enabled and host-assigned device control policies enforce USB mass storage blocking with at most ${maxExceptions} exceptions each.`
      : `${weak.length}/${perPolicy.length} enabled and host-assigned device control policies do not enforce USB mass storage blocking or carry more than ${maxExceptions} exceptions: ${weak.map((item) => `${item.policy} [${item.usb_enforcement_mode ?? "mode?"}/${item.mass_storage_action ?? "action?"}/${item.mass_storage_exceptions} exceptions]`).join("; ")}.`,
    { ...policyInventory(policies), max_exceptions: maxExceptions, policies: perPolicy },
  );
}

function evaluatePeripheralRestrictions(views: DeviceControlView[], policies: JsonRecord[]): CrowdstrikeFinding {
  const applied = views.filter((view) => view.applied);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-09", "device control", policies);

  const perPolicy = applied.map((view) => {
    const bluetooth = view.bluetooth_enforcement_mode === "MONITOR_ENFORCE" && view.bluetooth_restricted_classes > 0;
    const pcie = view.pcie_enforcement_mode === "MONITOR_ENFORCE";
    const massStorage = view.mass_storage_action !== undefined && view.mass_storage_action !== "FULL_ACCESS";
    const configured = [bluetooth, pcie, massStorage].filter(Boolean).length;
    const status: CrowdstrikeFinding["status"] = configured === 3 ? "pass" : configured >= 1 ? "warn" : "fail";
    return { ...view, bluetooth_enforced: bluetooth, pcie_enforced: pcie, sd_card_via_mass_storage_blocked: massStorage, status };
  });
  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  return finding(
    "CS-09",
    status,
    status === "pass"
      ? `Bluetooth, PCIe/Thunderbolt, and mass storage (SD card) restrictions are enforced across ${perPolicy.length} enabled and host-assigned device control policies.`
      : `${weak.length}/${perPolicy.length} enabled and host-assigned device control policies leave Bluetooth, PCIe/Thunderbolt, or mass storage (SD card) unenforced: ${weak.map((item) => item.policy).join(", ")}.`,
    { ...policyInventory(policies), policies: perPolicy },
  );
}

function evaluateHostFirewall(policies: JsonRecord[], containers: JsonRecord[], ruleGroups: JsonRecord[]): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-10", "firewall", policies);
  const containerById = new Map(containers.map((container) => [asString(container.policy_id) ?? "", container]));
  const ruleGroupById = new Map(ruleGroups.map((group) => [asString(group.id) ?? "", group]));

  const perPolicy = applied.map((policy) => {
    const container = containerById.get(asString(policy.id) ?? "");
    const groupIds = asStringArray(container?.rule_group_ids);
    const knownGroups = groupIds.filter((id) => ruleGroupById.has(id));
    const activeGroups = knownGroups.filter((id) => {
      const group = ruleGroupById.get(id);
      return group !== undefined && asBoolean(group.enabled) === true && asArray(group.rule_ids).length > 0;
    });
    const unknownGroups = groupIds.length - knownGroups.length;
    const enforce = asBoolean(container?.enforce);
    const testMode = asBoolean(container?.test_mode);
    const status: CrowdstrikeFinding["status"] = container === undefined
      ? "warn"
      : enforce === true && testMode !== true && activeGroups.length > 0
        ? "pass"
        : enforce === true && (activeGroups.length > 0 || unknownGroups > 0)
          ? "warn"
          : "fail";
    return {
      policy: policyLabel(policy),
      status,
      container_returned: container !== undefined,
      enforce,
      test_mode: testMode,
      rule_groups: groupIds.length,
      active_rule_groups: activeGroups.length,
      unknown_rule_groups: unknownGroups,
      host_groups: asArray(policy.groups).length,
    };
  });
  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  return finding(
    "CS-10",
    status,
    status === "pass"
      ? `All ${perPolicy.length} enabled and host-assigned firewall policies enforce at least one enabled, non-empty rule group outside test mode.`
      : `${weak.length}/${perPolicy.length} enabled and host-assigned firewall policies are not verifiably enforcing active rule groups: ${weak.map((item) => `${item.policy} [container=${String(item.container_returned)}, enforce=${String(item.enforce)}, test_mode=${String(item.test_mode)}, active_groups=${item.active_rule_groups}, unknown_groups=${item.unknown_rule_groups}]`).join("; ")}.`,
    { ...policyInventory(policies), rule_groups_total: ruleGroups.length, policies: perPolicy },
  );
}

function evaluateDefaultDeny(policies: JsonRecord[], containers: JsonRecord[], rules: JsonRecord[]): CrowdstrikeFinding {
  const appliedIds = new Set(assignedPolicies(policies).map((policy) => asString(policy.id) ?? ""));
  const activeContainers = containers.filter((container) => appliedIds.has(asString(container.policy_id) ?? ""));
  if (activeContainers.length === 0) {
    return finding("CS-11", "fail", `No firewall policy containers were returned for enabled and host-assigned firewall policies (${appliedIds.size} applied policies, ${containers.length} containers), so a default deny posture cannot be demonstrated.`, { ...policyInventory(policies), containers: containers.length });
  }
  const perContainer = activeContainers.map((container) => {
    const inbound = asString(container.default_inbound)?.toUpperCase();
    const outbound = asString(container.default_outbound)?.toUpperCase();
    const status: CrowdstrikeFinding["status"] = inbound === "DENY" ? (asBoolean(container.enforce) === true ? "pass" : "warn") : "fail";
    return { policy_id: asString(container.policy_id), platform_id: asString(container.platform_id), default_inbound: inbound, default_outbound: outbound, enforce: asBoolean(container.enforce), status };
  });
  const allowRules = rules.filter((rule) => asString(rule.action)?.toUpperCase() === "ALLOW" && asBoolean(rule.enabled) === true);
  const undocumentedAllows = allowRules.filter((rule) => !asString(rule.description));
  const statuses = perContainer.map((item) => item.status);
  if (undocumentedAllows.length > 0) statuses.push("warn");
  if (rules.length === 0) statuses.push("warn");
  const status = worstStatus(statuses);
  return finding(
    "CS-11",
    status,
    status === "pass"
      ? `All ${perContainer.length} enforced firewall policy containers default inbound traffic to DENY and every one of the ${allowRules.length} enabled allow rules carries a description.`
      : rules.length === 0 && perContainer.every((item) => item.status === "pass")
        ? `All ${perContainer.length} enforced firewall policy containers default inbound traffic to DENY, but the firewall rules endpoint returned zero rules, so the documented allow-rule inventory could not be confirmed.`
        : `${perContainer.filter((item) => item.status !== "pass").length}/${perContainer.length} firewall policy containers do not enforce inbound DENY, and ${undocumentedAllows.length}/${allowRules.length} enabled allow rules have no description.`,
    {
      containers: perContainer,
      rules_reviewed: rules.length,
      enabled_allow_rules: allowRules.length,
      undocumented_allow_rules: undocumentedAllows.slice(0, 25).map((rule) => asString(rule.name) ?? asString(rule.id)),
    },
  );
}

const DEVICE_CONTROL_CONSOLE_EVIDENCE = "export each device control policy from Falcon console > Endpoint security > Device control policies showing USB, Bluetooth, and PCIe enforcement, class actions, exceptions, and assigned host groups.";
const FIREWALL_CONSOLE_EVIDENCE = "export firewall policies with their default inbound and outbound actions, enforcement state, assigned rule groups, documented allow rules, and assigned host groups from Falcon console > Endpoint security > Firewall policies.";

export async function assessCrowdstrikeDeviceFirewall(
  client: Pick<
    CrowdstrikeApiClient,
    | "getResolvedConfig"
    | "listDeviceControlPolicies"
    | "getDeviceControlPoliciesV2"
    | "listFirewallPolicies"
    | "getFirewallPolicyContainers"
    | "listFirewallRuleGroups"
    | "listFirewallRules"
  >,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAssessmentResult> {
  const maxUsbExceptions = clampNumber(options.maxUsbExceptions, DEFAULT_MAX_USB_EXCEPTIONS, 0, 10_000);
  const ruleLimit = clampNumber(options.ruleLimit, DEFAULT_RULE_LIMIT, 1, 10_000);

  const deviceControl = await collectDataset(() => client.listDeviceControlPolicies(), emptyPage<JsonRecord>(), "device control policies");
  const deviceControlIds = deviceControl.data.items.map((policy) => asString(policy.id)).filter((id): id is string => Boolean(id));
  const deviceControlDetails: CollectedDataset<JsonRecord[]> = deviceControlIds.length > 0
    ? await collectDataset(() => client.getDeviceControlPoliciesV2(deviceControlIds), [] as JsonRecord[], "device control policy details")
    : { data: [] };
  const firewallPolicies = await collectDataset(() => client.listFirewallPolicies(), emptyPage<JsonRecord>(), "firewall policies");
  const firewallIds = assignedPolicies(firewallPolicies.data.items).map((policy) => asString(policy.id)).filter((id): id is string => Boolean(id));
  const containers: CollectedDataset<JsonRecord[]> = firewallIds.length > 0
    ? await collectDataset(() => client.getFirewallPolicyContainers(firewallIds), [] as JsonRecord[], "firewall policy containers")
    : { data: [] };
  const ruleGroups = await collectDataset(() => client.listFirewallRuleGroups(ruleLimit), emptyPage<JsonRecord>(), "firewall rule groups");
  const rules = await collectDataset(() => client.listFirewallRules(ruleLimit), emptyPage<JsonRecord>(), "firewall rules");

  const detailById = new Map(deviceControlDetails.data.map((detail) => [asString(detail.id) ?? "", detail]));
  const views = deviceControl.data.items.map((policy) => deviceControlView(policy, detailById.get(asString(policy.id) ?? "")));
  const deviceControlError = deviceControl.error ?? deviceControlDetails.error;
  const devicePartial = partialInventory(deviceControl.data, "device control policies");
  const firewallPartial = partialInventory(firewallPolicies.data, "firewall policies");
  const ruleGroupPartial = partialInventory(ruleGroups.data, "firewall rule groups");
  const rulePartial = partialInventory(rules.data, "firewall rules");

  const findings = [
    deviceControlError
      ? unreadableFinding("CS-08", deviceControl.error ? "device control policies" : "device control policy details", deviceControlError, DEVICE_CONTROL_CONSOLE_EVIDENCE)
      : withPartialInventory(evaluateUsbBlocking(views, deviceControl.data.items, maxUsbExceptions), [devicePartial]),
    deviceControlError
      ? unreadableFinding("CS-09", deviceControl.error ? "device control policies" : "device control policy details", deviceControlError, DEVICE_CONTROL_CONSOLE_EVIDENCE)
      : withPartialInventory(evaluatePeripheralRestrictions(views, deviceControl.data.items), [devicePartial]),
    firewallPolicies.error ?? containers.error ?? ruleGroups.error
      ? unreadableFinding("CS-10", firewallPolicies.error ? "firewall policies" : containers.error ? "firewall policy containers" : "firewall rule groups", firewallPolicies.error ?? containers.error ?? ruleGroups.error ?? "unknown error", FIREWALL_CONSOLE_EVIDENCE)
      : withPartialInventory(evaluateHostFirewall(firewallPolicies.data.items, containers.data, ruleGroups.data.items), [firewallPartial, ruleGroupPartial]),
    firewallPolicies.error ?? containers.error ?? rules.error
      ? unreadableFinding("CS-11", firewallPolicies.error ? "firewall policies" : containers.error ? "firewall policy containers" : "firewall rules", firewallPolicies.error ?? containers.error ?? rules.error ?? "unknown error", FIREWALL_CONSOLE_EVIDENCE)
      : withPartialInventory(evaluateDefaultDeny(firewallPolicies.data.items, containers.data, rules.data.items), [firewallPartial, rulePartial]),
  ];

  return {
    title: "CrowdStrike device control and firewall posture",
    category: "device_firewall",
    summary: {
      ...assessmentSummaryBase(client.getResolvedConfig()),
      device_control_policies: deviceControl.data.items.length,
      enabled_and_assigned_device_control_policies: views.filter((view) => view.applied).length,
      firewall_policies: firewallPolicies.data.items.length,
      enabled_and_assigned_firewall_policies: firewallIds.length,
      firewall_rule_groups: ruleGroups.data.items.length,
      firewall_rules_reviewed: rules.data.items.length,
      firewall_rules_truncated: rules.data.truncated,
      ...statusCounts(findings),
    },
    findings,
    errors: listErrors([deviceControl, deviceControlDetails, firewallPolicies, containers, ruleGroups, rules]),
    snapshots: {
      device_control_policies: deviceControl.data.items,
      device_control_policy_details: deviceControlDetails.data,
      firewall_policies: firewallPolicies.data.items,
      firewall_policy_containers: containers.data,
      firewall_rule_groups: ruleGroups.data.items,
      firewall_rules: rules.data.items,
    },
  };
}

type BuildMode = "auto" | "pinned" | "off" | "unknown";

function classifyBuild(build: string | undefined): { mode: BuildMode; tag?: string; number?: string } {
  if (build === undefined || build.trim().length === 0) return { mode: "off" };
  const normalized = build.trim().toLowerCase();
  const tagMatch = normalized.match(/(?:^|\|)(n(?:-[12])?)(?:\||$)/);
  if (tagMatch) return { mode: "auto", tag: tagMatch[1] };
  const numberMatch = normalized.match(/^(?:\d+\.\d+\.)?(\d+)(?:\||$)/);
  if (numberMatch) return { mode: "pinned", number: numberMatch[1] };
  return { mode: "unknown" };
}

function supportedBuildNumbers(builds: JsonRecord[]): Map<string, string> {
  const supported = new Map<string, string>();
  for (const build of builds) {
    const classified = classifyBuild(asString(build.build));
    const numberFromBuild = asString(build.build)?.match(/^(\d+)/)?.[1];
    const numberFromVersion = asString(build.sensor_version)?.match(/(\d+)$/)?.[1];
    const number = numberFromBuild ?? numberFromVersion;
    if (classified.tag && number) supported.set(number, classified.tag);
  }
  return supported;
}

function evaluateSensorUpdate(policies: JsonRecord[], buildsByPlatform: Map<string, CollectedDataset<JsonRecord[]>>): CrowdstrikeFinding {
  const applied = assignedPolicies(policies);
  if (applied.length === 0) return noAssignedPolicyFinding("CS-12", "sensor update", policies);

  const perPolicy = applied.map((policy) => {
    const settings = asObject(policy.settings) ?? {};
    const platform = (asString(policy.platform_name) ?? "").toLowerCase();
    const builds = buildsByPlatform.get(platform);
    const supported = builds && !builds.error ? supportedBuildNumbers(builds.data) : undefined;
    const buildValues = [asString(settings.build), ...asRecordArray(settings.variants).map((variant) => asString(variant.build))];
    const classifications = buildValues.map((value, index) => ({ source: index === 0 ? "build" : `variant-${index}`, value, ...classifyBuild(value) }));
    const statuses = classifications
      .filter((item, index) => index === 0 || item.value !== undefined)
      .map((item): CrowdstrikeFinding["status"] => {
        switch (item.mode) {
          case "auto":
            return "pass";
          case "pinned":
            if (!supported) return "warn";
            return item.number !== undefined && supported.has(item.number) ? "pass" : "fail";
          case "off":
            return "fail";
          case "unknown":
            return "warn";
          default: {
            const exhaustive: never = item.mode;
            return exhaustive;
          }
        }
      });
    const uninstallProtection = asString(settings.uninstall_protection)?.toUpperCase();
    if (uninstallProtection !== "ENABLED") statuses.push("warn");
    return {
      policy: policyLabel(policy),
      status: worstStatus(statuses),
      builds: classifications,
      uninstall_protection: uninstallProtection,
      sensor_version: asString(settings.sensor_version),
      stage: asString(settings.stage),
      supported_builds: supported ? Object.fromEntries(supported) : undefined,
      builds_catalog_error: builds?.error,
    };
  });

  const status = worstStatus(perPolicy.map((item) => item.status));
  const weak = perPolicy.filter((item) => item.status !== "pass");
  const catalogErrors = [...buildsByPlatform.values()].map((dataset) => dataset.error);
  return withUnreadableSecondary(
    finding(
      "CS-12",
      status,
      status === "pass"
        ? `All ${perPolicy.length} enabled and host-assigned sensor update policies auto-update or pin a build within N-2 with uninstall protection enabled.`
        : `${weak.length}/${perPolicy.length} enabled and host-assigned sensor update policies disable updates, pin builds older than N-2 or unverifiable against the build catalog, or lack uninstall protection: ${weak.map((item) => item.policy).join(", ")}.`,
      { ...policyInventory(policies), policies: perPolicy },
    ),
    "sensor build catalog",
    catalogErrors,
    "build tags and pinned builds could not be verified against the catalog for that platform",
  );
}

const HOST_CONSOLE_EVIDENCE = "export the host inventory from Falcon console > Host setup and management > Host management with last seen timestamps and compare it to the authoritative asset inventory.";

function evaluateDeploymentCompleteness(hosts: CollectedDataset<CrowdstrikePage<JsonRecord>>, staleDays: number, now = Date.now()): CrowdstrikeFinding {
  if (hosts.error) {
    return unreadableFinding("CS-13", "hosts", hosts.error, HOST_CONSOLE_EVIDENCE);
  }
  const items = hosts.data.items;
  const staleCutoff = now - staleDays * 86_400_000;
  const dated = items.filter((host) => parseTimestamp(host.last_seen) !== undefined);
  const undated = items.length - dated.length;
  const active = dated.filter((host) => (parseTimestamp(host.last_seen) ?? 0) >= staleCutoff);
  const stale = dated.filter((host) => (parseTimestamp(host.last_seen) ?? 0) < staleCutoff);
  const rfm = items.filter((host) => asBoolean(host.reduced_functionality_mode) === true);
  const versions = new Map<string, number>();
  for (const host of items) {
    const version = asString(host.agent_version) ?? "unknown";
    versions.set(version, (versions.get(version) ?? 0) + 1);
  }
  const pct = percentage(active.length, dated.length);
  const status: CrowdstrikeFinding["status"] = items.length === 0
    ? "fail"
    : dated.length === 0
      ? "warn"
      : pct >= 95
        ? "pass"
        : pct >= 85
          ? "warn"
          : "fail";
  const base = finding(
    "CS-13",
    status,
    items.length === 0
      ? "The Hosts API was readable but returned zero hosts, so no sensor deployment coverage can be demonstrated; emptiness fails this control."
      : dated.length === 0
        ? `None of the ${items.length} sampled hosts carries a last_seen timestamp, so sensor freshness cannot be demonstrated from the API.`
        : `${pct}% of ${dated.length} dated hosts (${items.length} sampled) reported to Falcon within the last ${staleDays} days; ${stale.length} are stale, ${undated} have no last_seen, and ${rfm.length} run in reduced functionality mode.`,
    {
      sampled_hosts: items.length,
      reported_total_hosts: hosts.data.total,
      active_hosts: active.length,
      stale_hosts: stale.length,
      hosts_without_last_seen: undated,
      stale_days: staleDays,
      reduced_functionality_hosts: rfm.length,
      agent_version_distribution: Object.fromEntries([...versions.entries()].sort((left, right) => right[1] - left[1]).slice(0, 15)),
      stale_samples: stale.slice(0, 25).map((host) => ({ hostname: asString(host.hostname), last_seen: asString(host.last_seen), platform: asString(host.platform_name) })),
    },
  );
  return withPartialInventory(withUndatedItems(base, undated, "hosts", "last_seen"), [partialInventory(hosts.data, "hosts")]);
}

const HOST_GROUP_CONSOLE_EVIDENCE = "export host group membership from Falcon console > Host setup and management > Host groups and confirm every managed host belongs to at least one policy-bearing group.";

function evaluateHostGroupAssignment(hosts: CollectedDataset<CrowdstrikePage<JsonRecord>>, groups: CollectedDataset<CrowdstrikePage<JsonRecord>>): CrowdstrikeFinding {
  if (hosts.error) {
    return unreadableFinding("CS-14", "hosts", hosts.error, HOST_GROUP_CONSOLE_EVIDENCE);
  }
  if (groups.error) {
    return unreadableFinding("CS-14", "host groups", groups.error, HOST_GROUP_CONSOLE_EVIDENCE);
  }
  const items = hosts.data.items;
  const assigned = items.filter((host) => asArray(host.groups).length > 0);
  const pct = percentage(assigned.length, items.length);
  const groupTypes = new Map<string, number>();
  for (const group of groups.data.items) {
    const type = asString(group.group_type) ?? "unknown";
    groupTypes.set(type, (groupTypes.get(type) ?? 0) + 1);
  }
  const status: CrowdstrikeFinding["status"] = items.length === 0 || groups.data.items.length === 0 ? "fail" : pct >= 95 ? "pass" : pct >= 80 ? "warn" : "fail";
  const base = finding(
    "CS-14",
    status,
    groups.data.items.length === 0
      ? "The host groups endpoint was readable but returned zero host groups, so no policy assignment coverage can be demonstrated; emptiness fails this control."
      : items.length === 0
        ? "The Hosts API was readable but returned zero hosts, so host group assignment coverage cannot be demonstrated; emptiness fails this control."
        : `${pct}% of ${items.length} sampled hosts belong to at least one of ${groups.data.items.length} host groups.`,
    {
      sampled_hosts: items.length,
      reported_total_hosts: hosts.data.total,
      assigned_hosts: assigned.length,
      unassigned_hosts: items.length - assigned.length,
      host_groups: groups.data.items.length,
      host_group_types: Object.fromEntries(groupTypes),
      unassigned_samples: items.filter((host) => asArray(host.groups).length === 0).slice(0, 25).map((host) => ({ hostname: asString(host.hostname), platform: asString(host.platform_name) })),
    },
  );
  return withPartialInventory(base, [partialInventory(hosts.data, "hosts"), partialInventory(groups.data, "host groups")]);
}

const DISCOVER_CONSOLE_EVIDENCE = "provide the Falcon Discover unmanaged asset report (Falcon console > Exposure management > Assets) or an equivalent network discovery inventory for the review period.";

function evaluateUnmanagedAssets(
  unmanagedCount: CollectedDataset<number | undefined>,
  managedCount: CollectedDataset<number | undefined>,
  samples: CollectedDataset<CrowdstrikePage<JsonRecord>>,
): CrowdstrikeFinding {
  if (unmanagedCount.error) {
    if (isForbiddenOrMissing(unmanagedCount)) {
      return unlicensedFinding("CS-15", "Falcon Discover", unmanagedCount.error, DISCOVER_CONSOLE_EVIDENCE);
    }
    return unreadableFinding("CS-15", "Falcon Discover unmanaged asset count", unmanagedCount.error, DISCOVER_CONSOLE_EVIDENCE);
  }
  if (managedCount.error) {
    return unreadableFinding("CS-15", "Falcon Discover managed asset count", managedCount.error, DISCOVER_CONSOLE_EVIDENCE);
  }
  const unmanaged = unmanagedCount.data;
  const managed = managedCount.data;
  if (unmanaged === undefined || managed === undefined) {
    const missingTotals = [
      unmanaged === undefined ? "unmanaged" : undefined,
      managed === undefined ? "managed" : undefined,
    ].filter((label): label is string => Boolean(label));
    return manualFinding(
      "CS-15",
      `Falcon Discover was readable but did not report a server-side total (meta.pagination.total) for ${missingTotals.join(" and ")} assets, so the unmanaged asset ratio cannot be computed from API data; ${samples.data.items.length} unmanaged assets were sampled as a lower bound only.`,
      DISCOVER_CONSOLE_EVIDENCE,
      {
        unmanaged_assets: unmanaged,
        managed_assets: managed,
        totals_missing: missingTotals,
        unmanaged_samples_seen: samples.data.items.length,
        unmanaged_samples_truncated: samples.data.truncated,
      },
    );
  }
  if (managed + unmanaged === 0) {
    return manualFinding(
      "CS-15",
      "Falcon Discover was readable but reported zero managed and zero unmanaged assets, which indicates Discover is not collecting for this tenant rather than a clean inventory.",
      DISCOVER_CONSOLE_EVIDENCE,
      { unmanaged_assets: 0, managed_assets: 0 },
    );
  }
  const pct = Math.round((unmanaged / (managed + unmanaged)) * 1000) / 10;
  const status: CrowdstrikeFinding["status"] = unmanaged === 0 ? "pass" : pct <= 5 ? "warn" : "fail";
  return finding(
    "CS-15",
    status,
    unmanaged === 0
      ? `Falcon Discover reports no unmanaged assets against ${managed} managed assets (server-side totals).`
      : `Falcon Discover reports ${unmanaged} unmanaged assets (${pct}% of ${managed + unmanaged} discovered assets, server-side totals).`,
    {
      unmanaged_assets: unmanaged,
      managed_assets: managed,
      unmanaged_percentage: pct,
      unmanaged_samples_truncated: samples.data.truncated,
      unmanaged_samples: samples.data.items.slice(0, 25).map((asset) => ({
        hostname: asString(asset.hostname),
        platform: asString(asset.platform_name),
        last_seen: asString(asset.last_seen_timestamp),
        local_ips: asStringArray(asset.local_ip_addresses).slice(0, 3),
      })),
    },
  );
}

const ZTA_CONSOLE_EVIDENCE = "export the Zero Trust Assessment score report from Falcon console > Zero Trust Assessment and list hosts below the organizational threshold.";

function evaluateZeroTrust(
  total: CollectedDataset<number | undefined>,
  belowThreshold: CollectedDataset<CrowdstrikePage<JsonRecord>>,
  belowTotal: CollectedDataset<number | undefined>,
  minScore: number,
): CrowdstrikeFinding {
  if (total.error) {
    if (isForbiddenOrMissing(total)) {
      return unlicensedFinding("CS-25", "Zero Trust Assessment", total.error, ZTA_CONSOLE_EVIDENCE);
    }
    return unreadableFinding("CS-25", "Zero Trust Assessment score totals", total.error, ZTA_CONSOLE_EVIDENCE);
  }
  if (belowTotal.error ?? belowThreshold.error) {
    return unreadableFinding("CS-25", "Zero Trust Assessment below-threshold scores", belowTotal.error ?? belowThreshold.error ?? "unknown error", ZTA_CONSOLE_EVIDENCE);
  }
  const scored = total.data;
  if (scored === undefined) {
    return manualFinding(
      "CS-25",
      "Zero Trust Assessment was readable but did not report a server-side total (meta.pagination.total) for scored hosts, so the share of hosts below the threshold cannot be computed from API data.",
      ZTA_CONSOLE_EVIDENCE,
      { min_score: minScore, scored_hosts: undefined, totals_missing: ["scored"], lowest_scores_seen: belowThreshold.data.items.length },
    );
  }
  if (scored === 0) {
    return manualFinding(
      "CS-25",
      "Zero Trust Assessment was readable but returned zero scored hosts, which indicates ZTA is not producing scores for this tenant rather than a compliant fleet.",
      ZTA_CONSOLE_EVIDENCE,
      { min_score: minScore, scored_hosts: 0 },
    );
  }
  const belowTotalReported = belowTotal.data !== undefined;
  const below = belowTotal.data ?? belowThreshold.data.items.length;
  const pct = percentage(below, scored);
  const computed: CrowdstrikeFinding["status"] = below === 0 ? "pass" : pct <= 10 ? "warn" : "fail";
  const status: CrowdstrikeFinding["status"] = belowTotalReported ? computed : computed === "pass" ? "warn" : computed;
  return finding(
    "CS-25",
    status,
    belowTotalReported
      ? `${below} of ${scored} scored hosts (${pct}%, server-side totals) fall below the ZTA threshold of ${minScore}.`
      : `At least ${below} of ${scored} scored hosts (${pct}%) fall below the ZTA threshold of ${minScore}; the API did not report a server-side total for the below-threshold query, so the sampled count is a lower bound and this verdict cannot exceed warn.`,
    {
      min_score: minScore,
      scored_hosts: scored,
      hosts_below_threshold: below,
      below_threshold_total_reported: belowTotalReported,
      lowest_scores_truncated: belowThreshold.data.truncated,
      lowest_scores: belowThreshold.data.items.slice(0, 25).map((item) => ({ aid: asString(item.aid), score: asNumber(item.score) })),
    },
  );
}

export async function assessCrowdstrikeSensorCoverage(
  client: Pick<
    CrowdstrikeApiClient,
    | "getResolvedConfig"
    | "listSensorUpdatePolicies"
    | "listSensorUpdateBuilds"
    | "listHosts"
    | "listHostGroups"
    | "countDiscoverHosts"
    | "listDiscoverHosts"
    | "countZtaAssessments"
    | "listZtaAssessments"
  >,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAssessmentResult> {
  const hostLimit = clampNumber(options.hostLimit, DEFAULT_HOST_LIMIT, 1, 100_000);
  const staleDays = clampNumber(options.staleSensorDays, DEFAULT_STALE_SENSOR_DAYS, 1, 365);
  const minScore = clampNumber(options.minZtaScore, DEFAULT_MIN_ZTA_SCORE, 1, 100);

  const sensorUpdate = await collectDataset(() => client.listSensorUpdatePolicies(), emptyPage<JsonRecord>(), "sensor update policies");
  const platforms = [...new Set(assignedPolicies(sensorUpdate.data.items).map((policy) => (asString(policy.platform_name) ?? "").toLowerCase()).filter(Boolean))];
  const buildsByPlatform = new Map<string, CollectedDataset<JsonRecord[]>>();
  for (const platform of platforms) {
    buildsByPlatform.set(platform, await collectDataset(() => client.listSensorUpdateBuilds(platform), [] as JsonRecord[], `sensor builds (${platform})`));
  }
  const hosts = await collectDataset(() => client.listHosts(hostLimit), emptyPage<JsonRecord>(), "hosts");
  const hostGroups = await collectDataset(() => client.listHostGroups(), emptyPage<JsonRecord>(), "host groups");
  const unmanagedCount = await collectDataset(() => client.countDiscoverHosts("entity_type:'unmanaged'"), undefined as number | undefined, "discover unmanaged hosts");
  const managedCount: CollectedDataset<number | undefined> = unmanagedCount.error
    ? { data: undefined }
    : await collectDataset(() => client.countDiscoverHosts("entity_type:'managed'"), undefined as number | undefined, "discover managed hosts");
  const unmanagedSamples: CollectedDataset<CrowdstrikePage<JsonRecord>> = unmanagedCount.error
    ? { data: emptyPage<JsonRecord>() }
    : await collectDataset(() => client.listDiscoverHosts("entity_type:'unmanaged'", 100), emptyPage<JsonRecord>(), "discover unmanaged samples");
  const ztaTotal = await collectDataset(() => client.countZtaAssessments("score:>=0"), undefined as number | undefined, "zero trust assessment totals");
  const ztaBelow: CollectedDataset<CrowdstrikePage<JsonRecord>> = ztaTotal.error
    ? { data: emptyPage<JsonRecord>() }
    : await collectDataset(() => client.listZtaAssessments(`score:<${minScore}`, 1000), emptyPage<JsonRecord>(), "zero trust assessments below threshold");
  const ztaBelowTotal: CollectedDataset<number | undefined> = ztaTotal.error
    ? { data: undefined }
    : await collectDataset(() => client.countZtaAssessments(`score:<${minScore}`), undefined as number | undefined, "zero trust assessment below-threshold totals");

  const findings = [
    sensorUpdate.error
      ? unreadableFinding("CS-12", "sensor update policies", sensorUpdate.error, "export each sensor update policy from Falcon console > Host setup and management > Sensor update policies showing the sensor version setting, uninstall protection, and assigned host groups.")
      : withPartialInventory(evaluateSensorUpdate(sensorUpdate.data.items, buildsByPlatform), [partialInventory(sensorUpdate.data, "sensor update policies")]),
    evaluateDeploymentCompleteness(hosts, staleDays),
    evaluateHostGroupAssignment(hosts, hostGroups),
    withUnreadableSecondary(
      evaluateUnmanagedAssets(unmanagedCount, managedCount, unmanagedSamples),
      "Falcon Discover unmanaged asset samples",
      [unmanagedSamples.error],
      "the unmanaged asset sample list is unavailable",
    ),
    evaluateZeroTrust(ztaTotal, ztaBelow, ztaBelowTotal, minScore),
  ];

  return {
    title: "CrowdStrike sensor coverage",
    category: "sensor_coverage",
    summary: {
      ...assessmentSummaryBase(client.getResolvedConfig()),
      sensor_update_policies: sensorUpdate.data.items.length,
      enabled_and_assigned_sensor_update_policies: assignedPolicies(sensorUpdate.data.items).length,
      sampled_hosts: hosts.data.items.length,
      reported_total_hosts: hosts.data.total ?? "unknown",
      hosts_truncated: hosts.data.truncated,
      host_groups: hostGroups.data.items.length,
      unmanaged_assets: unmanagedCount.data ?? "unavailable",
      zta_scored_hosts: ztaTotal.data ?? "unavailable",
      ...statusCounts(findings),
    },
    findings,
    errors: listErrors([sensorUpdate, ...buildsByPlatform.values(), hosts, hostGroups, unmanagedCount, managedCount, unmanagedSamples, ztaTotal, ztaBelow, ztaBelowTotal]),
    snapshots: {
      sensor_update_policies: sensorUpdate.data.items,
      sensor_update_builds: Object.fromEntries([...buildsByPlatform.entries()].map(([platform, dataset]) => [platform, dataset.data])),
      hosts: hosts.data.items,
      host_groups: hostGroups.data.items,
      discover_unmanaged_samples: unmanagedSamples.data.items,
      zero_trust_assessments_below_threshold: ztaBelow.data.items,
    },
  };
}

interface UserView {
  uuid: string;
  uid?: string;
  status?: string;
  last_login_at?: string;
  roles: string[];
  admin_roles: string[];
  roles_readable: boolean;
  suspected_shared: boolean;
}

function isAdminRoleName(value: string): boolean {
  return /admin/i.test(value);
}

function buildUserViews(users: JsonRecord[], rolesByUser: Map<string, JsonRecord[]>): UserView[] {
  return users.map((user) => {
    const uuid = asString(user.uuid) ?? asString(user.id) ?? "";
    const uid = asString(user.uid) ?? asString(user.email);
    const roleRecords = rolesByUser.get(uuid);
    const roles = [...new Set((roleRecords ?? []).map((role) => asString(role.role_id) ?? asString(role.role_name)).filter((role): role is string => Boolean(role)))];
    const adminRoles = (roleRecords ?? [])
      .filter((role) => isAdminRoleName(asString(role.role_name) ?? "") || isAdminRoleName(asString(role.role_id) ?? ""))
      .map((role) => asString(role.role_name) ?? asString(role.role_id) ?? "admin");
    const localPart = (uid ?? "").split("@")[0] ?? "";
    return {
      uuid,
      uid,
      status: asString(user.status),
      last_login_at: asString(user.last_login_at),
      roles,
      admin_roles: [...new Set(adminRoles)],
      roles_readable: roleRecords !== undefined,
      suspected_shared: SHARED_ACCOUNT_PATTERN.test(localPart) || /shared/i.test(localPart),
    };
  });
}

function evaluateAdminCount(views: UserView[], maxAdmins: number): CrowdstrikeFinding {
  const admins = views.filter((view) => view.admin_roles.length > 0);
  const sharedAdmins = admins.filter((view) => view.suspected_shared);
  const sharedOthers = views.filter((view) => view.suspected_shared && view.admin_roles.length === 0);
  const status: CrowdstrikeFinding["status"] = sharedAdmins.length > 0 || admins.length > maxAdmins * 2
    ? "fail"
    : admins.length > maxAdmins || sharedOthers.length > 0
      ? "warn"
      : "pass";
  return finding(
    "CS-16",
    status,
    `${admins.length} of ${views.length} Falcon users hold admin roles (threshold ${maxAdmins}); ${sharedAdmins.length} admin and ${sharedOthers.length} non-admin accounts look like shared or generic identities.`,
    {
      users_reviewed: views.length,
      admin_users: admins.length,
      max_admins: maxAdmins,
      admins: admins.slice(0, 50).map((view) => ({ uid: view.uid, roles: view.admin_roles, last_login_at: view.last_login_at })),
      suspected_shared_accounts: [...sharedAdmins, ...sharedOthers].slice(0, 25).map((view) => view.uid),
    },
  );
}

function evaluateLeastPrivilege(views: UserView[], maxRoles: number, staleLoginDays: number, now = Date.now()): CrowdstrikeFinding {
  const staleCutoff = now - staleLoginDays * 86_400_000;
  const overprivileged = views.filter((view) => view.roles.length > maxRoles || (view.admin_roles.length > 0 && view.roles.length > view.admin_roles.length + 1));
  const admins = views.filter((view) => view.admin_roles.length > 0);
  const stalePrivileged = admins.filter((view) => {
    const lastLogin = parseTimestamp(view.last_login_at);
    return lastLogin !== undefined && lastLogin < staleCutoff;
  });
  const undatedPrivileged = admins.filter((view) => parseTimestamp(view.last_login_at) === undefined);
  const status: CrowdstrikeFinding["status"] = stalePrivileged.length > 0 ? "fail" : overprivileged.length > 0 ? "warn" : "pass";
  const base = finding(
    "CS-17",
    status,
    status === "pass"
      ? `No user exceeds ${maxRoles} roles or stacks extra roles on an admin grant, and every dated admin login is within ${staleLoginDays} days.`
      : `${overprivileged.length} users carry more than ${maxRoles} roles or redundant roles on top of admin, and ${stalePrivileged.length} admin accounts have a last login older than ${staleLoginDays} days.`,
    {
      users_reviewed: views.length,
      max_roles_per_user: maxRoles,
      stale_login_days: staleLoginDays,
      overprivileged: overprivileged.slice(0, 25).map((view) => ({ uid: view.uid, roles: view.roles })),
      stale_privileged: stalePrivileged.slice(0, 25).map((view) => ({ uid: view.uid, last_login_at: view.last_login_at, roles: view.admin_roles })),
      admins_without_login_date: undatedPrivileged.slice(0, 25).map((view) => view.uid),
    },
  );
  return withUndatedItems(base, undatedPrivileged.length, "admin accounts", "last_login_at");
}

function withRoleVisibility(item: CrowdstrikeFinding, views: UserView[], roleErrors: string[], truncatedRolePages: number): CrowdstrikeFinding {
  const unreadable = views.filter((view) => !view.roles_readable).length;
  if (unreadable === 0 && truncatedRolePages === 0) return item;
  const gaps = [
    unreadable > 0 ? `Role grants could not be read for ${unreadable} of ${views.length} users (${roleErrors.length} role lookups failed)` : undefined,
    truncatedRolePages > 0 ? `role grant pages were truncated for ${truncatedRolePages} of ${views.length} users` : undefined,
  ].filter((gap): gap is string => Boolean(gap));
  return {
    ...item,
    status: item.status === "pass" ? "warn" : item.status,
    summary: `${item.summary} ${gaps.join("; ")}, so admin and privilege counts are a lower bound and this verdict cannot exceed warn.`,
    evidence: {
      ...(item.evidence ?? {}),
      users_without_readable_roles: unreadable,
      users_with_truncated_role_pages: truncatedRolePages,
      role_lookup_errors: roleErrors.slice(0, 10),
    },
  };
}

interface ApiClientScope {
  id?: string;
  group?: string;
  action?: string;
}

function parseScopeText(text: string | undefined): { group?: string; action?: string } {
  if (!text) return {};
  const match = /^\s*([^:]+?)\s*:\s*([A-Za-z_-]+)\s*$/.exec(text);
  if (!match) return { group: text.trim() || undefined };
  return { group: match[1], action: match[2] };
}

function apiClientScopes(client: JsonRecord): ApiClientScope[] {
  return asArray(client.scopes).map((scope): ApiClientScope => {
    const object = asObject(scope);
    if (object) {
      const id = asString(object.id) ?? asString(object.name) ?? asString(object.scope);
      const parsed = parseScopeText(id);
      return {
        id,
        group: asString(object.group) ?? parsed.group,
        action: asString(object.action) ?? parsed.action,
      };
    }
    const text = asString(scope);
    return { id: text, ...parseScopeText(text) };
  });
}

function normalizeScopeSubject(value: string): string {
  return value.trim().toLowerCase().replace(/[\s_]+/g, "-");
}

function isWriteAction(action: string | undefined): boolean {
  return action !== undefined && /write|admin/i.test(action);
}

function isSensitiveWriteScope(scope: ApiClientScope): boolean {
  if (!isWriteAction(scope.action)) return false;
  const subjects = [scope.group, scope.id].filter((value): value is string => Boolean(value)).map(normalizeScopeSubject);
  return subjects.some((subject) => SENSITIVE_WRITE_SCOPE_PATTERNS.some((pattern) => pattern.test(subject)));
}

function scopeLabel(scope: ApiClientScope): string {
  return `${scope.group ?? scope.id ?? "unknown"}:${scope.action ?? "unknown"}`;
}

const API_CLIENT_CONSOLE_EVIDENCE = "export the API client list with scopes and last-used dates from Falcon console > Support and resources > API clients and keys and confirm write scopes are limited to documented integrations.";

function evaluateApiClients(clients: CollectedDataset<CrowdstrikePage<JsonRecord>>, maxWriteClients: number, staleDays: number, now = Date.now()): CrowdstrikeFinding {
  if (clients.error) {
    return unreadableFinding("CS-18", "API clients", clients.error, API_CLIENT_CONSOLE_EVIDENCE);
  }
  if (clients.data.items.length === 0) {
    return manualFinding(
      "CS-18",
      "The API clients endpoint was readable but returned zero clients, which cannot be true for a tenant that issued the credential running this assessment; the inventory is not visible to this credential.",
      API_CLIENT_CONSOLE_EVIDENCE,
      { api_clients: 0 },
    );
  }
  const staleCutoff = now - staleDays * 86_400_000;
  const views = clients.data.items.map((client) => {
    const scopes = apiClientScopes(client);
    const writeScopes = scopes.filter(isSensitiveWriteScope);
    const actionless = scopes.filter((scope) => scope.action === undefined);
    const lastUsed = parseTimestamp(client.last_used_at) ?? parseTimestamp(client.last_used) ?? parseTimestamp(client.last_used_timestamp);
    return {
      id: asString(client.id) ?? asString(client.client_id),
      name: asString(client.name),
      scopes_count: scopes.length,
      sensitive_write_scopes: writeScopes.map(scopeLabel),
      scopes_exposed: Array.isArray(client.scopes),
      scope_actions_readable: actionless.length === 0,
      scopes_without_action: actionless.map(scopeLabel),
      last_used_at: lastUsed === undefined ? undefined : new Date(lastUsed).toISOString(),
      stale: lastUsed !== undefined && lastUsed < staleCutoff,
    };
  });
  const writeClients = views.filter((view) => view.sensitive_write_scopes.length > 0);
  const unexposed = views.filter((view) => !view.scopes_exposed);
  const actionsUnreadable = views.filter((view) => view.scopes_exposed && !view.scope_actions_readable);
  const staleWriteClients = writeClients.filter((view) => view.stale);
  const withoutLastUsed = views.filter((view) => view.last_used_at === undefined).length;
  const lastUsedCoverage = withoutLastUsed === views.length
    ? "The public API reference documents no last-used field for API clients and none was returned, so unused-client staleness was not evaluated from API data; review last-used dates in the Falcon console."
    : `Last-used timestamps were returned for ${views.length - withoutLastUsed} of ${views.length} clients${staleWriteClients.length > 0 ? `; ${staleWriteClients.length} write clients were unused for more than ${staleDays} days` : ""}.`;
  const status: CrowdstrikeFinding["status"] = writeClients.length > maxWriteClients
    ? "fail"
    : writeClients.length > 0 || unexposed.length > 0 || actionsUnreadable.length > 0
      ? "warn"
      : "pass";
  const coverageNotes = [
    unexposed.length > 0 ? `${unexposed.length} clients did not expose a scopes array` : undefined,
    actionsUnreadable.length > 0 ? `${actionsUnreadable.length} clients expose scopes without an action field, so their read or write level is unknown` : undefined,
  ].filter((note): note is string => Boolean(note));
  return withPartialInventory(finding(
    "CS-18",
    status,
    status === "pass"
      ? `None of the ${views.length} API clients hold write-action scopes on sensitive collections; the scopes array with its action and group fields was read for every client. ${lastUsedCoverage}`
      : `${writeClients.length} of ${views.length} API clients hold write-action scopes on sensitive collections (threshold ${maxWriteClients})${coverageNotes.length > 0 ? `; ${coverageNotes.join("; ")}` : ""}. ${lastUsedCoverage}`,
    {
      api_clients: views.length,
      reported_total_api_clients: clients.data.total,
      max_write_clients: maxWriteClients,
      write_clients: writeClients.slice(0, 25),
      stale_write_clients: staleWriteClients.slice(0, 25).map((view) => view.name ?? view.id),
      clients_without_scope_data: unexposed.length,
      clients_without_scope_action_data: actionsUnreadable.length,
      clients_without_last_used_data: withoutLastUsed,
      last_used_evaluated_from_api: withoutLastUsed < views.length,
    },
  ), [partialInventory(clients.data, "API clients")]);
}

function isBroadRegex(value: string | undefined): boolean {
  if (!value) return false;
  const trimmed = value.trim();
  return /^\^?(\(\?[a-z]*\))?(\.[*+]|\(\.[*+]\)|\[\^\]?\][*+]|\\\\?\.\*)+\$?$/i.test(trimmed) || trimmed === "*" || trimmed === ".*" || trimmed === ".+";
}

function evaluateIoaExclusions(exclusions: CollectedDataset<CrowdstrikePage<JsonRecord>>): CrowdstrikeFinding {
  if (exclusions.error) {
    return unreadableFinding("CS-19", "IOA exclusions", exclusions.error, "export the IOA exclusion list from Falcon console > Endpoint security > Exclusions > IOA exclusions with patterns and scope.");
  }
  const views = exclusions.data.items.map((exclusion) => ({
    id: asString(exclusion.id),
    name: asString(exclusion.name),
    pattern: asString(exclusion.pattern_name),
    ifn_regex: asString(exclusion.ifn_regex),
    cl_regex: asString(exclusion.cl_regex),
    applied_globally: asBoolean(exclusion.applied_globally) === true,
    groups: asArray(exclusion.groups).length,
    broad: isBroadRegex(asString(exclusion.ifn_regex)) || isBroadRegex(asString(exclusion.cl_regex)),
  }));
  const broad = views.filter((view) => view.broad);
  const broadGlobal = broad.filter((view) => view.applied_globally);
  const status: CrowdstrikeFinding["status"] = broadGlobal.length > 0 ? "fail" : broad.length > 0 ? "warn" : "pass";
  return withPartialInventory(finding(
    "CS-19",
    status,
    views.length === 0
      ? "The IOA exclusions endpoint was readable and returned zero exclusions; no detection logic is being suppressed, so emptiness is compliant for this control."
      : `${views.length} IOA exclusions reviewed; ${broad.length} use wildcard-only image or command line patterns (${broadGlobal.length} applied globally).`,
    { exclusions: views.length, reported_total_exclusions: exclusions.data.total, broad_exclusions: broad.slice(0, 25), globally_applied: views.filter((view) => view.applied_globally).length, listing: views.slice(0, 100) },
  ), [partialInventory(exclusions.data, "IOA exclusions")]);
}

function isSensitivePath(value: string | undefined): boolean {
  if (!value) return false;
  const trimmed = value.trim();
  if (/^(\*|\*\*|\/|\/\*|\/\*\*|[a-z]:\\?\*?|[a-z]:\\\*\*)$/i.test(trimmed)) return true;
  return SENSITIVE_EXCLUSION_PATH_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function evaluateMlExclusions(exclusions: CollectedDataset<CrowdstrikePage<JsonRecord>>): CrowdstrikeFinding {
  if (exclusions.error) {
    return unreadableFinding("CS-20", "ML exclusions", exclusions.error, "export the machine learning exclusion list from Falcon console > Endpoint security > Exclusions > Machine learning exclusions.");
  }
  const views = exclusions.data.items.map((exclusion) => ({
    id: asString(exclusion.id),
    value: asString(exclusion.value),
    excluded_from: asStringArray(exclusion.excluded_from),
    applied_globally: asBoolean(exclusion.applied_globally) === true,
    groups: asArray(exclusion.groups).length,
    sensitive: isSensitivePath(asString(exclusion.value)),
  }));
  const sensitive = views.filter((view) => view.sensitive);
  const sensitiveGlobal = sensitive.filter((view) => view.applied_globally);
  const status: CrowdstrikeFinding["status"] = sensitiveGlobal.length > 0 ? "fail" : sensitive.length > 0 ? "warn" : "pass";
  return withPartialInventory(finding(
    "CS-20",
    status,
    views.length === 0
      ? "The ML exclusions endpoint was readable and returned zero exclusions; no machine learning coverage is being suppressed, so emptiness is compliant for this control."
      : `${views.length} ML exclusions reviewed; ${sensitive.length} cover system, program, user, or temp directories or broad wildcards (${sensitiveGlobal.length} applied globally).`,
    { exclusions: views.length, reported_total_exclusions: exclusions.data.total, sensitive_exclusions: sensitive.slice(0, 25), globally_applied: views.filter((view) => view.applied_globally).length, listing: views.slice(0, 100) },
  ), [partialInventory(exclusions.data, "ML exclusions")]);
}

function hidesDirectory(value: string | undefined): boolean {
  if (!value) return false;
  const trimmed = value.trim();
  return /(\\|\/)\*{1,2}$/.test(trimmed) || /^(\*|\*\*|\/|[a-z]:\\?)$/i.test(trimmed) || isSensitivePath(trimmed);
}

function evaluateSensorVisibilityExclusions(exclusions: CollectedDataset<CrowdstrikePage<JsonRecord>>): CrowdstrikeFinding {
  if (exclusions.error) {
    return unreadableFinding("CS-21", "sensor visibility exclusions", exclusions.error, "export the sensor visibility exclusion list from Falcon console > Endpoint security > Exclusions > Sensor visibility exclusions with paths and scope.");
  }
  const views = exclusions.data.items.map((exclusion) => ({
    id: asString(exclusion.id),
    value: asString(exclusion.value),
    applied_globally: asBoolean(exclusion.applied_globally) === true,
    groups: asArray(exclusion.groups).length,
    is_descendant_process: asBoolean(exclusion.is_descendant_process) === true,
    hides_directory: hidesDirectory(asString(exclusion.value)),
  }));
  const hiding = views.filter((view) => view.hides_directory);
  const hidingGlobal = hiding.filter((view) => view.applied_globally);
  const status: CrowdstrikeFinding["status"] = hidingGlobal.length > 0 ? "fail" : hiding.length > 0 ? "warn" : "pass";
  return withPartialInventory(finding(
    "CS-21",
    status,
    views.length === 0
      ? "The sensor visibility exclusions endpoint was readable and returned zero exclusions; nothing is hidden from the sensor, so emptiness is compliant for this control."
      : `${views.length} sensor visibility exclusions reviewed; ${hiding.length} hide entire directories or sensitive paths from the sensor (${hidingGlobal.length} applied globally).`,
    { exclusions: views.length, reported_total_exclusions: exclusions.data.total, directory_exclusions: hiding.slice(0, 25), globally_applied: views.filter((view) => view.applied_globally).length, listing: views.slice(0, 100) },
  ), [partialInventory(exclusions.data, "sensor visibility exclusions")]);
}

const IDENTITY_CONSOLE_EVIDENCE = "capture the Identity Protection policy rule list (enabled, enforcement action, simulation mode) from Falcon console > Identity protection > Policy management, or provide evidence of an equivalent identity threat protection control.";

function evaluateIdentityProtection(rules: CollectedDataset<CrowdstrikePage<JsonRecord>>): CrowdstrikeFinding {
  if (rules.error) {
    if (isForbiddenOrMissing(rules)) {
      return unlicensedFinding("CS-24", "Falcon Identity Protection", rules.error, IDENTITY_CONSOLE_EVIDENCE);
    }
    return unreadableFinding("CS-24", "Identity Protection policy rules", rules.error, IDENTITY_CONSOLE_EVIDENCE);
  }
  const views = rules.data.items.map((rule) => {
    const action = asString(rule.action)?.toUpperCase();
    const simulation = asBoolean(rule.simulationMode) ?? asBoolean(rule.simulation_mode) ?? false;
    const enabled = asBoolean(rule.enabled) === true;
    return {
      id: asString(rule.id),
      name: asString(rule.name),
      enabled,
      simulation_mode: simulation,
      action,
      trigger: asString(rule.trigger),
      enforcing: enabled && !simulation && /block|deny|mfa|verif|challenge|identity/i.test(action ?? ""),
    };
  });
  const active = views.filter((view) => view.enabled && !view.simulation_mode);
  const enforcing = views.filter((view) => view.enforcing);
  const status: CrowdstrikeFinding["status"] = views.length === 0 ? "fail" : enforcing.length > 0 ? "pass" : active.length > 0 ? "warn" : "fail";
  return withPartialInventory(finding(
    "CS-24",
    status,
    views.length === 0
      ? "Identity Protection policy rules were readable but zero rules exist, so identity-based lateral movement is not being prevented; emptiness fails this control."
      : `${enforcing.length} of ${views.length} Identity Protection policy rules actively enforce (block, MFA, or verification) outside simulation mode; ${active.length} rules are enabled in total.`,
    { rules: views.length, active_rules: active.length, enforcing_rules: enforcing.length, listing: views.slice(0, 50) },
  ), [partialInventory(rules.data, "Identity Protection policy rules")]);
}

const USER_CONSOLE_EVIDENCE = "export the user list with roles and last login dates from Falcon console > Users and roles and count Falcon Administrator grants.";

export async function assessCrowdstrikeAccessGovernance(
  client: Pick<
    CrowdstrikeApiClient,
    | "getResolvedConfig"
    | "listUserUuids"
    | "getUsers"
    | "listUserRoles"
    | "listRoles"
    | "listApiClients"
    | "listIoaExclusions"
    | "listMlExclusions"
    | "listSensorVisibilityExclusions"
    | "listIdentityProtectionRules"
  >,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAssessmentResult> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 10_000);
  const exclusionLimit = clampNumber(options.exclusionLimit, DEFAULT_EXCLUSION_LIMIT, 1, 10_000);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 10_000);
  const maxRoles = clampNumber(options.maxRolesPerUser, DEFAULT_MAX_ROLES_PER_USER, 1, 100);
  const maxWriteClients = clampNumber(options.maxWriteClients, DEFAULT_MAX_WRITE_CLIENTS, 0, 10_000);

  const uuids = await collectDataset(() => client.listUserUuids(userLimit), emptyPage<string>(), "user uuids");
  const users: CollectedDataset<JsonRecord[]> = uuids.error
    ? { data: [] }
    : await collectDataset(() => client.getUsers(uuids.data.items), [] as JsonRecord[], "users");
  const rolesByUser = new Map<string, JsonRecord[]>();
  const roleErrors: string[] = [];
  let rolesTruncated = 0;
  for (const user of users.data) {
    const uuid = asString(user.uuid) ?? asString(user.id);
    if (!uuid) continue;
    try {
      const rolePage = await client.listUserRoles(uuid);
      rolesByUser.set(uuid, rolePage.items);
      if (rolePage.truncated) rolesTruncated += 1;
    } catch (error) {
      roleErrors.push(`user roles (${uuid}): ${summarizeError(error)}`);
    }
  }
  const roleCatalog = await collectDataset(() => client.listRoles(), emptyPage<JsonRecord>(), "role catalog");
  const apiClients = await collectDataset(() => client.listApiClients(userLimit), emptyPage<JsonRecord>(), "api clients");
  const ioa = await collectDataset(() => client.listIoaExclusions(exclusionLimit), emptyPage<JsonRecord>(), "ioa exclusions");
  const ml = await collectDataset(() => client.listMlExclusions(exclusionLimit), emptyPage<JsonRecord>(), "ml exclusions");
  const sv = await collectDataset(() => client.listSensorVisibilityExclusions(exclusionLimit), emptyPage<JsonRecord>(), "sensor visibility exclusions");
  const identity = await collectDataset(() => client.listIdentityProtectionRules(), emptyPage<JsonRecord>(), "identity protection rules");

  const views = buildUserViews(users.data, rolesByUser);
  const usersUnavailable = uuids.error ?? users.error;
  const allRolesFailed = views.length > 0 && views.every((view) => !view.roles_readable);
  const userPartial = partialInventory(uuids.data, "users");
  const userFinding = (id: ControlId, evaluate: () => CrowdstrikeFinding): CrowdstrikeFinding => {
    if (usersUnavailable) {
      return unreadableFinding(id, uuids.error ? "user list" : "user details", usersUnavailable, USER_CONSOLE_EVIDENCE);
    }
    if (views.length === 0) {
      return manualFinding(
        id,
        "The user management endpoints were readable but returned zero users, which cannot be true for a live tenant; the user inventory is not visible to this credential (check the CID scope and User management read grant).",
        USER_CONSOLE_EVIDENCE,
        { users_reviewed: 0 },
      );
    }
    if (allRolesFailed) {
      return unreadableFinding(id, "user role grants", roleErrors[0] ?? "role lookups failed", USER_CONSOLE_EVIDENCE);
    }
    return withUnreadableSecondary(
      withPartialInventory(
        withRoleVisibility(evaluate(), views, roleErrors, rolesTruncated),
        [userPartial, partialInventory(roleCatalog.data, "roles in the role catalog")],
      ),
      "role catalog",
      [roleCatalog.error],
      "the role inventory could not be checked for completeness against the catalog",
    );
  };

  const findings = [
    userFinding("CS-16", () => evaluateAdminCount(views, maxAdmins)),
    userFinding("CS-17", () => evaluateLeastPrivilege(views, maxRoles, DEFAULT_STALE_ADMIN_LOGIN_DAYS)),
    evaluateApiClients(apiClients, maxWriteClients, DEFAULT_STALE_API_CLIENT_DAYS),
    evaluateIoaExclusions(ioa),
    evaluateMlExclusions(ml),
    evaluateSensorVisibilityExclusions(sv),
    evaluateIdentityProtection(identity),
  ];

  return {
    title: "CrowdStrike access governance and exclusions",
    category: "access_governance",
    summary: {
      ...assessmentSummaryBase(client.getResolvedConfig()),
      users_reviewed: views.length,
      reported_total_users: uuids.data.total ?? "unknown",
      users_truncated: uuids.data.truncated,
      role_lookups_failed: roleErrors.length,
      role_pages_truncated: rolesTruncated,
      admin_users: views.filter((view) => view.admin_roles.length > 0).length,
      roles_in_catalog: roleCatalog.error ? "unavailable" : roleCatalog.data.items.length,
      reported_total_roles: roleCatalog.error ? "unavailable" : roleCatalog.data.total ?? "unknown",
      role_catalog_truncated: roleCatalog.error ? "unavailable" : roleCatalog.data.truncated,
      api_clients: apiClients.data.items.length,
      ioa_exclusions: ioa.data.items.length,
      ml_exclusions: ml.data.items.length,
      sensor_visibility_exclusions: sv.data.items.length,
      identity_protection_rules: identity.error ? "unavailable" : identity.data.items.length,
      identity_protection_rules_truncated: identity.error ? "unavailable" : identity.data.truncated,
      ...statusCounts(findings),
    },
    findings,
    errors: [...listErrors([uuids, users, roleCatalog, apiClients, ioa, ml, sv, identity]), ...roleErrors],
    snapshots: {
      users: users.data,
      user_roles: Object.fromEntries(rolesByUser),
      roles: roleCatalog.data.items,
      api_clients: apiClients.data.items,
      ioa_exclusions: ioa.data.items,
      ml_exclusions: ml.data.items,
      sensor_visibility_exclusions: sv.data.items,
      identity_protection_rules: identity.data.items,
    },
  };
}

function formatAccessCheckText(result: CrowdstrikeAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.scope,
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);

  return [
    `CrowdStrike access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Scope", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: CrowdstrikeAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : Array.isArray(value) ? value.join(", ") || "none" : String(value)}`)
    .join("\n");

  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function countByStatus(findings: CrowdstrikeFinding[]): Record<CrowdstrikeFinding["status"], number> {
  const counts: Record<CrowdstrikeFinding["status"], number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function severityRank(severity: CrowdstrikeFinding["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    case "info":
      return 0;
    default: {
      const exhaustive: never = severity;
      return exhaustive;
    }
  }
}

function buildExecutiveSummary(config: CrowdstrikeResolvedConfig, assessments: CrowdstrikeAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
  const partial = findings.filter((item) => asObject(item.evidence)?.partial_inventory !== undefined);

  return [
    "# CrowdStrike Falcon Audit Executive Summary",
    "",
    `- Falcon API: ${config.baseUrl}${config.cloud ? ` (${config.cloud})` : ""}`,
    `- Member CID: ${config.memberCid ?? "not set (results cover the issuing CID only)"}`,
    `- Generated: ${new Date().toISOString()}`,
    `- Source chain: ${config.sourceChain.join(" -> ") || "direct"}`,
    "",
    "## Result Counts",
    "",
    `- Controls evaluated: ${findings.length} of ${CROWDSTRIKE_CONTROLS.length}`,
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    `- Findings limited by partial inventory: ${partial.length}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.slice(0, 10).map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`)
      : ["- No failing or warning controls."]),
    "",
    "## Manual Evidence Required",
    "",
    ...(counts.manual > 0
      ? findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`)
      : ["- None."]),
    ...(errors.length > 0 ? ["", "## Collection Warnings", "", ...errors.map((error) => `- ${error}`)] : []),
    "",
  ].join("\n");
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

function buildUnifiedMatrix(findings: CrowdstrikeFinding[]): string {
  return [
    "# Unified CrowdStrike Compliance Matrix",
    "",
    "| Control | Title | Status | Severity | Mappings |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map((item) => `| ${item.id} | ${markdownCell(item.title)} | ${item.status} | ${item.severity} | ${markdownCell(item.mappings.join(", "))} |`),
    "",
  ].join("\n");
}

function frameworkMappings(finding: CrowdstrikeFinding, framework: FrameworkDefinition): string[] {
  const prefix = `${framework.label} `;
  return finding.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length));
}

function buildFrameworkReport(framework: FrameworkDefinition, findings: CrowdstrikeFinding[]): string {
  const relevant = findings.filter((item) => frameworkMappings(item, framework).length > 0);
  const counts = countByStatus(relevant);
  return [
    `# ${framework.title}`,
    "",
    `Controls mapped: ${relevant.length}. Pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual}.`,
    "",
    `| Control | Title | Status | Severity | ${framework.label} Requirement | Summary |`,
    "| --- | --- | --- | --- | --- | --- |",
    ...relevant.map((item) => `| ${item.id} | ${markdownCell(item.title)} | ${item.status} | ${item.severity} | ${markdownCell(frameworkMappings(item, framework).join(", "))} | ${markdownCell(item.summary)} |`),
    "",
  ].join("\n");
}

function buildQuickReference(assessments: CrowdstrikeAssessmentResult[], hasErrors: boolean): string {
  return [
    "# CrowdStrike Falcon Audit Bundle Quick Reference",
    "",
    "This bundle was generated by grclanker's read-only CrowdStrike tools. Credentials are never written into the bundle.",
    "",
    "## Verdict Semantics",
    "",
    "- `pass`: API evidence satisfies the control across the complete inventory that was read.",
    "- `warn`: partial evidence, threshold-adjacent values, undated records, or a sampled or truncated inventory; a partial read never produces pass.",
    "- `fail`: evidence contradicts the control, or an inventory the control depends on is empty.",
    "- `manual`: the endpoint was unreadable, forbidden, unlicensed, or the control cannot be verified through the API; the summary names the console evidence to collect.",
    "",
    "## Contents",
    "",
    "- `metadata.json`: non-secret run metadata (API base URL, member CID scope, source chain, timestamps).",
    "- `core_data/<category>/*.json`: Falcon API snapshots collected for each assessment; alerts and RTR audit sessions are projected to verdict fields, so process command lines, file paths, and RTR command strings are never exported.",
    "- `analysis/findings.json`: every normalized finding with severity, status, evidence, and framework mappings.",
    "- `analysis/<category>.json`: per-assessment summaries and findings.",
    "- `analysis/access_check.json`: readable Falcon API surfaces and missing scopes.",
    "- `compliance/executive_summary.md`: prioritized summary for leadership and auditors.",
    "- `compliance/unified_compliance_matrix.md`: every control mapped across all frameworks.",
    "- `compliance/frameworks/<framework>.md`: one report per framework (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP).",
    hasErrors ? "- `_errors.log`: reads that failed while the bundle still completed." : "- `_errors.log`: absent, every read succeeded.",
    "",
    "## Assessments",
    "",
    ...assessments.map((assessment) => `- ${assessment.category}: ${assessment.findings.map((item) => item.id).join(", ")}`),
    "",
    "## Reading Order",
    "",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report your assessor needs",
    "4. `analysis/findings.json` for evidence details, then `core_data/` for raw payloads",
    "",
  ].join("\n");
}

type BundleClient = Pick<
  CrowdstrikeApiClient,
  | "getResolvedConfig"
  | "getJson"
  | "postJson"
  | "listPreventionPolicies"
  | "listResponsePolicies"
  | "listRtrSessions"
  | "listAlerts"
  | "listHosts"
  | "listDeviceControlPolicies"
  | "getDeviceControlPoliciesV2"
  | "listFirewallPolicies"
  | "getFirewallPolicyContainers"
  | "listFirewallRuleGroups"
  | "listFirewallRules"
  | "listSensorUpdatePolicies"
  | "listSensorUpdateBuilds"
  | "listHostGroups"
  | "countDiscoverHosts"
  | "listDiscoverHosts"
  | "countZtaAssessments"
  | "listZtaAssessments"
  | "listUserUuids"
  | "getUsers"
  | "listUserRoles"
  | "listRoles"
  | "listApiClients"
  | "listIoaExclusions"
  | "listMlExclusions"
  | "listSensorVisibilityExclusions"
  | "listIdentityProtectionRules"
>;

export async function runAllCrowdstrikeAssessments(
  client: BundleClient,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAssessmentResult[]> {
  return [
    await assessCrowdstrikePreventionPolicies(client),
    await assessCrowdstrikeResponseReadiness(client, options),
    await assessCrowdstrikeDeviceFirewall(client, options),
    await assessCrowdstrikeSensorCoverage(client, options),
    await assessCrowdstrikeAccessGovernance(client, options),
  ];
}

function stripSnapshots(assessment: CrowdstrikeAssessmentResult): Omit<CrowdstrikeAssessmentResult, "snapshots"> {
  const { snapshots: _snapshots, ...rest } = assessment;
  return rest;
}

export async function exportCrowdstrikeAuditBundle(
  client: BundleClient,
  config: CrowdstrikeResolvedConfig,
  outputRoot: string,
  options: CrowdstrikeAssessmentOptions = {},
): Promise<CrowdstrikeAuditBundleResult> {
  const access = await checkCrowdstrikeAccess(client);
  const assessments = await runAllCrowdstrikeAssessments(client, options);
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors.map((error) => `[${assessment.category}] ${error}`));

  ensurePrivateDir(outputRoot);
  const bundleName = safeDirName(`${config.cloud ?? new URL(config.baseUrl).hostname}${config.memberCid ? `-${config.memberCid}` : ""}-audit-bundle`);
  const outputDir = await nextAvailableAuditDir(outputRoot, bundleName);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference(assessments, errors.length > 0));
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    base_url: config.baseUrl,
    cloud: config.cloud,
    member_cid: config.memberCid,
    scope: config.memberCid ? `member CID ${config.memberCid} only` : "issuing CID only",
    source_chain: config.sourceChain,
    controls_evaluated: findings.length,
    controls_defined: CROWDSTRIKE_CONTROLS.length,
    status_counts: countByStatus(findings),
  }));

  for (const assessment of assessments) {
    for (const [name, snapshot] of Object.entries(assessment.snapshots)) {
      await writeSecureTextFile(outputDir, `core_data/${assessment.category}/${name}.json`, serializeJson(snapshot));
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(stripSnapshots(assessment)));
  }
  await writeSecureTextFile(outputDir, "analysis/access_check.json", serializeJson(access));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of CROWDSTRIKE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.key}.md`, buildFrameworkReport(framework, findings));
  }
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

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    base_url: asString(value.base_url),
    cloud: asString(value.cloud),
    member_cid: asString(value.member_cid),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    host_limit: asNumber(value.host_limit),
    user_limit: asNumber(value.user_limit),
    alert_limit: asNumber(value.alert_limit),
    exclusion_limit: asNumber(value.exclusion_limit),
    rule_limit: asNumber(value.rule_limit),
    lookback_days: asNumber(value.lookback_days),
    stale_sensor_days: asNumber(value.stale_sensor_days),
    max_admins: asNumber(value.max_admins),
    max_roles_per_user: asNumber(value.max_roles_per_user),
    max_usb_exceptions: asNumber(value.max_usb_exceptions),
    max_write_clients: asNumber(value.max_write_clients),
    min_zta_score: asNumber(value.min_zta_score),
    max_session_minutes: asNumber(value.max_session_minutes),
    max_concurrent_sessions: asNumber(value.max_concurrent_sessions),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function assessmentOptions(args: AssessArgs): CrowdstrikeAssessmentOptions {
  return {
    hostLimit: args.host_limit,
    userLimit: args.user_limit,
    alertLimit: args.alert_limit,
    exclusionLimit: args.exclusion_limit,
    ruleLimit: args.rule_limit,
    lookbackDays: args.lookback_days,
    staleSensorDays: args.stale_sensor_days,
    maxAdmins: args.max_admins,
    maxRolesPerUser: args.max_roles_per_user,
    maxUsbExceptions: args.max_usb_exceptions,
    maxWriteClients: args.max_write_clients,
    minZtaScore: args.min_zta_score,
    maxSessionMinutes: args.max_session_minutes,
    maxConcurrentSessions: args.max_concurrent_sessions,
  };
}

function createClient(args: CheckAccessArgs): CrowdstrikeApiClient {
  return new CrowdstrikeApiClient(resolveCrowdstrikeConfiguration(args as JsonRecord));
}

const authParams = {
  client_id: Type.Optional(Type.String({ description: "Falcon API client ID. Defaults to CS_CLIENT_ID (or FALCON_CLIENT_ID), then ~/.crowdstrike/config.json." })),
  client_secret: Type.Optional(Type.String({ description: "Falcon API client secret. Defaults to CS_CLIENT_SECRET (or FALCON_CLIENT_SECRET), then the config file." })),
  base_url: Type.Optional(Type.String({ description: "Falcon API base URL. Defaults to CS_BASE_URL, then the cloud alias, then https://api.crowdstrike.com." })),
  cloud: Type.Optional(Type.String({ description: "Falcon cloud alias: us-1, us-2, eu-1, us-gov-1, or us-gov-2. Defaults to CS_CLOUD. Ignored when base_url is set." })),
  member_cid: Type.Optional(Type.String({ description: "Optional child CID for Flight Control (MSSP) tenants. Defaults to CS_MEMBER_CID. Results cover that CID only." })),
  config_file: Type.Optional(Type.String({ description: "Optional JSON config file with client_id, client_secret, base_url, cloud, and member_cid. Defaults to CS_CONFIG_FILE or ~/.crowdstrike/config.json." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const hostParams = {
  host_limit: Type.Optional(Type.Number({ description: "Maximum hosts to sample. Defaults to 5000. Verdicts that depend on a truncated host sample are capped at warn.", default: DEFAULT_HOST_LIMIT })),
};

export function registerCrowdstrikeTools(pi: any): void {
  pi.registerTool({
    name: "crowdstrike_check_access",
    label: "Check CrowdStrike Falcon audit access",
    description:
      "Validate read-only Falcon API access across prevention, response, device control, firewall, sensor update, hosts, host groups, users, API clients, Discover, alerts, exclusions, Zero Trust Assessment, Identity Protection, and RTR audit surfaces, and report missing API client scopes.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkCrowdstrikeAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "crowdstrike_check_access", ...result });
      } catch (error) {
        return errorResult(
          `CrowdStrike access check failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_assess_prevention_policies",
    label: "Assess CrowdStrike prevention policies",
    description:
      "Assess Falcon prevention policies for CS-01 through CS-05: ML detection and prevention slider levels, exploit mitigation toggles, script-based execution control, sensor tampering protection, and on-write detection and quarantine. Only enabled policies assigned to host groups (or platform_default) count as enforcement.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessCrowdstrikePreventionPolicies(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "crowdstrike_assess_prevention_policies", ...stripSnapshots(result) });
      } catch (error) {
        return errorResult(
          `CrowdStrike prevention policy assessment failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_assess_prevention_policies" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_assess_response_readiness",
    label: "Assess CrowdStrike response readiness",
    description:
      "Assess Falcon response readiness for CS-06, CS-07, CS-22, and CS-23: Real Time Response enablement and custom script restrictions, RTR session limits (manual confirmation with audit evidence), critical/high alert response SLA, and network containment documentation.",
    parameters: Type.Object({
      ...authParams,
      ...hostParams,
      lookback_days: Type.Optional(Type.Number({ description: "Alert and RTR session lookback window in days. Defaults to 30.", default: DEFAULT_LOOKBACK_DAYS })),
      alert_limit: Type.Optional(Type.Number({ description: "Maximum critical/high alerts to review. Defaults to 2000. A truncated alert page caps CS-22 at warn.", default: DEFAULT_ALERT_LIMIT })),
      max_session_minutes: Type.Optional(Type.Number({ description: "RTR session duration threshold in minutes. Defaults to 30.", default: DEFAULT_MAX_SESSION_MINUTES })),
      max_concurrent_sessions: Type.Optional(Type.Number({ description: "Per-user concurrent RTR session threshold. Defaults to 3.", default: DEFAULT_MAX_CONCURRENT_SESSIONS })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessCrowdstrikeResponseReadiness(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "crowdstrike_assess_response_readiness", ...stripSnapshots(result) });
      } catch (error) {
        return errorResult(
          `CrowdStrike response readiness assessment failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_assess_response_readiness" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_assess_device_firewall",
    label: "Assess CrowdStrike device control and firewall",
    description:
      "Assess Falcon device control and host firewall posture for CS-08 through CS-11: USB mass storage blocking and exceptions, Bluetooth and PCIe/Thunderbolt restrictions, firewall policy enforcement with active rule groups, and default inbound DENY with documented allow rules.",
    parameters: Type.Object({
      ...authParams,
      max_usb_exceptions: Type.Optional(Type.Number({ description: "Maximum acceptable USB mass storage exceptions per policy before warning. Defaults to 25.", default: DEFAULT_MAX_USB_EXCEPTIONS })),
      rule_limit: Type.Optional(Type.Number({ description: "Maximum firewall rules and rule groups to review. Defaults to 1000. A truncated read caps CS-10 and CS-11 at warn.", default: DEFAULT_RULE_LIMIT })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessCrowdstrikeDeviceFirewall(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "crowdstrike_assess_device_firewall", ...stripSnapshots(result) });
      } catch (error) {
        return errorResult(
          `CrowdStrike device control and firewall assessment failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_assess_device_firewall" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_assess_sensor_coverage",
    label: "Assess CrowdStrike sensor coverage",
    description:
      "Assess Falcon sensor coverage for CS-12 through CS-15 and CS-25: sensor update auto-update or N-2 pinning with uninstall protection, deployment completeness by last-seen age, host group assignment coverage, Falcon Discover unmanaged assets, and Zero Trust Assessment scores below threshold.",
    parameters: Type.Object({
      ...authParams,
      ...hostParams,
      stale_sensor_days: Type.Optional(Type.Number({ description: "Days since last seen before a host counts as stale. Defaults to 7.", default: DEFAULT_STALE_SENSOR_DAYS })),
      min_zta_score: Type.Optional(Type.Number({ description: "Minimum acceptable Zero Trust Assessment score. Defaults to 60.", default: DEFAULT_MIN_ZTA_SCORE })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessCrowdstrikeSensorCoverage(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "crowdstrike_assess_sensor_coverage", ...stripSnapshots(result) });
      } catch (error) {
        return errorResult(
          `CrowdStrike sensor coverage assessment failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_assess_sensor_coverage" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_assess_access_governance",
    label: "Assess CrowdStrike access governance and exclusions",
    description:
      "Assess Falcon RBAC, API client, exclusion, and identity protection posture for CS-16 through CS-21 and CS-24: admin count and shared accounts, least privilege and stale admins, API client write scopes, IOA/ML/sensor visibility exclusion review, and Identity Protection enforcement.",
    parameters: Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum users and API clients to review. Defaults to 500. A truncated read caps the affected verdicts at warn.", default: DEFAULT_USER_LIMIT })),
      exclusion_limit: Type.Optional(Type.Number({ description: "Maximum exclusions per type to review. Defaults to 500.", default: DEFAULT_EXCLUSION_LIMIT })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 5.", default: DEFAULT_MAX_ADMINS })),
      max_roles_per_user: Type.Optional(Type.Number({ description: "Maximum roles per user before flagging as overprivileged. Defaults to 5.", default: DEFAULT_MAX_ROLES_PER_USER })),
      max_write_clients: Type.Optional(Type.Number({ description: "Maximum API clients with sensitive write scopes before failing. Defaults to 3.", default: DEFAULT_MAX_WRITE_CLIENTS })),
    }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assessCrowdstrikeAccessGovernance(createClient(args), assessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: "crowdstrike_assess_access_governance", ...stripSnapshots(result) });
      } catch (error) {
        return errorResult(
          `CrowdStrike access governance assessment failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_assess_access_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "crowdstrike_export_audit_bundle",
    label: "Export CrowdStrike audit bundle",
    description:
      "Export a CrowdStrike Falcon audit package covering all 25 spec controls: raw API snapshots, normalized findings, executive summary, unified compliance matrix, per-framework reports (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP), quick reference, error log, and a zip archive named after the allocated bundle directory.",
    parameters: Type.Object({
      ...authParams,
      ...hostParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}. Re-runs allocate a new suffixed directory and matching zip instead of overwriting.` })),
      lookback_days: Type.Optional(Type.Number({ description: "Alert and RTR session lookback window in days. Defaults to 30.", default: DEFAULT_LOOKBACK_DAYS })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum users and API clients to review. Defaults to 500.", default: DEFAULT_USER_LIMIT })),
      alert_limit: Type.Optional(Type.Number({ description: "Maximum critical/high alerts to review. Defaults to 2000.", default: DEFAULT_ALERT_LIMIT })),
      exclusion_limit: Type.Optional(Type.Number({ description: "Maximum exclusions per type to review. Defaults to 500.", default: DEFAULT_EXCLUSION_LIMIT })),
      rule_limit: Type.Optional(Type.Number({ description: "Maximum firewall rules and rule groups to review. Defaults to 1000.", default: DEFAULT_RULE_LIMIT })),
      stale_sensor_days: Type.Optional(Type.Number({ description: "Days since last seen before a host counts as stale. Defaults to 7.", default: DEFAULT_STALE_SENSOR_DAYS })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 5.", default: DEFAULT_MAX_ADMINS })),
      max_roles_per_user: Type.Optional(Type.Number({ description: "Maximum roles per user before flagging as overprivileged. Defaults to 5.", default: DEFAULT_MAX_ROLES_PER_USER })),
      max_usb_exceptions: Type.Optional(Type.Number({ description: "Maximum acceptable USB mass storage exceptions per policy. Defaults to 25.", default: DEFAULT_MAX_USB_EXCEPTIONS })),
      max_write_clients: Type.Optional(Type.Number({ description: "Maximum API clients with sensitive write scopes before failing. Defaults to 3.", default: DEFAULT_MAX_WRITE_CLIENTS })),
      min_zta_score: Type.Optional(Type.Number({ description: "Minimum acceptable Zero Trust Assessment score. Defaults to 60.", default: DEFAULT_MIN_ZTA_SCORE })),
      max_session_minutes: Type.Optional(Type.Number({ description: "RTR session duration threshold in minutes. Defaults to 30.", default: DEFAULT_MAX_SESSION_MINUTES })),
      max_concurrent_sessions: Type.Optional(Type.Number({ description: "Per-user concurrent RTR session threshold. Defaults to 3.", default: DEFAULT_MAX_CONCURRENT_SESSIONS })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveCrowdstrikeConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportCrowdstrikeAuditBundle(new CrowdstrikeApiClient(config), config, outputRoot, assessmentOptions(args));
        return textResult(
          [
            "CrowdStrike audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "crowdstrike_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `CrowdStrike audit bundle export failed: ${summarizeError(error)}`,
          { tool: "crowdstrike_export_audit_bundle" },
        );
      }
    },
  });
}
