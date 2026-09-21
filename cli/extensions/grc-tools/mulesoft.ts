/**
 * MuleSoft Anypoint Platform security inspector tools for grclanker.
 *
 * Read-only assessment of an Anypoint Platform organization across access
 * management, API Manager policies, runtime infrastructure, and audit logging.
 * Endpoint paths follow the public Anypoint Platform API specifications
 * published on Anypoint Exchange.
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
import { connect as tlsConnect } from "node:tls";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;
type SleepImpl = (ms: number) => Promise<void>;

export type MulesoftControlPlane = "us" | "eu" | "gov" | "custom";
export type MulesoftAuthMode = "token" | "connected_app" | "credentials";
export type MulesoftFramework =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap";
export type MulesoftSeverity = "critical" | "high" | "medium" | "low" | "info";
export type MulesoftFindingStatus = "pass" | "warn" | "fail" | "manual";
export type MulesoftAssessmentCategory =
  | "identity_access"
  | "api_gateway"
  | "runtime_infrastructure"
  | "audit_monitoring";

const DEFAULT_OUTPUT_DIR = "./export/mulesoft";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 500;
const MAX_RETRY_DELAY_MS = 30_000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_LIST_LIMIT = 500;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_MAX_ADMINS = 5;
const DEFAULT_MAX_ROLES_PER_GROUP = 15;
const DEFAULT_MAX_CONNECTED_APP_SCOPES = 10;
const DEFAULT_STALE_CONNECTED_APP_DAYS = 90;
const DEFAULT_ENVIRONMENT_LIMIT = 10;
const DEFAULT_API_LIMIT = 100;
const DEFAULT_APPLICATION_LIMIT = 200;
const DEFAULT_VPC_LIMIT = 20;
const DEFAULT_LOAD_BALANCER_LIMIT = 10;
const DEFAULT_RUNTIME_SUPPORT_WARNING_DAYS = 90;
const DEFAULT_CERTIFICATE_FAIL_DAYS = 30;
const DEFAULT_CERTIFICATE_WARNING_DAYS = 60;
const DEFAULT_AUDIT_LOOKBACK_HOURS = 24;
const AUDIT_FALLBACK_LOOKBACK_DAYS = 7;
const AUDIT_QUERY_PAGE_LIMIT = 200;
const MAX_EVIDENCE_SAMPLES = 25;
const MAX_ORG_WIDE_ENVIRONMENT_ROLES = 5;
const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_CONFIG_FILE_SEGMENTS = [".config", "mulesoft-sec-inspector", "config.toml"];
const CLOUDHUB_STANDARD_INGRESS_PORTS = new Set([8081, 8082, 8091, 8092]);

const CONTROL_PLANE_BASE_URLS: Record<Exclude<MulesoftControlPlane, "custom">, string> = {
  us: "https://anypoint.mulesoft.com",
  eu: "https://eu1.anypoint.mulesoft.com",
  gov: "https://gov.anypoint.mulesoft.com",
};

const FRAMEWORKS: MulesoftFramework[] = [
  "fedramp",
  "cmmc",
  "soc2",
  "cis",
  "pci_dss",
  "disa_stig",
  "irap",
  "ismap",
];

const FRAMEWORK_LABELS: Record<MulesoftFramework, string> = {
  fedramp: "FedRAMP",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis: "CIS",
  pci_dss: "PCI-DSS",
  disa_stig: "DISA STIG",
  irap: "IRAP",
  ismap: "ISMAP",
};

const FRAMEWORK_REPORT_TITLES: Record<MulesoftFramework, string> = {
  fedramp: "FedRAMP / NIST 800-53 Compliance Report",
  cmmc: "CMMC Level 2 Compliance Report",
  soc2: "SOC 2 Compliance Report",
  cis: "CIS Controls Compliance Report",
  pci_dss: "PCI-DSS Compliance Report",
  disa_stig: "DISA STIG Compliance Checklist",
  irap: "IRAP / ISM Compliance Report",
  ismap: "ISMAP Compliance Report",
};

const ORG_ADMIN_ROLE_PATTERN = /organization\s+(administrator|owner)/i;
const ENVIRONMENT_ROLE_PATTERN =
  /cloudhub|runtime|api\s+(manager|version)|application|server|alert|secret|\bmq\b|anypoint mq|environment|monitoring|visualizer|flex gateway|object store/i;
const ADMIN_SCOPE_PATTERN = /^full$|admin|owner|^manage|manage:/i;
const AUTHENTICATION_POLICY_PATTERN =
  /client-id-enforcement|jwt|oauth|openid|basic-auth|http-basic|saml|mtls|tls/i;
const RATE_LIMIT_POLICY_PATTERN = /rate-limit|spike-control/i;
const SENSITIVE_PROPERTY_PATTERN = /pass(word|wd)?|secret|token|api[-_]?key|private[-_]?key|credential/i;
const SECRET_KEY_PATTERN = /secret|password|passwd|token|private[_-]?key|authorization/i;
const PRODUCTION_NAME_PATTERN = /\bprod(uction)?\b/i;
const NON_PRODUCTION_NAME_PATTERN = /\b(sandbox|dev(elopment)?|test|qa|uat|staging|stage)\b/i;

export interface MulesoftControlDefinition {
  number: number;
  id: string;
  title: string;
  severity: MulesoftSeverity;
  mappings: Record<MulesoftFramework, string>;
}

function control(
  number: number,
  id: string,
  title: string,
  severity: MulesoftSeverity,
  mappings: [string, string, string, string, string, string, string, string],
): MulesoftControlDefinition {
  const [fedramp, cmmc, soc2, cis, pciDss, disaStig, irap, ismap] = mappings;
  return {
    number,
    id,
    title,
    severity,
    mappings: { fedramp, cmmc, soc2, cis, pci_dss: pciDss, disa_stig: disaStig, irap, ismap },
  };
}

const CONTROL_CATALOG: MulesoftControlDefinition[] = [
  control(1, "MULESOFT-IAM-01", "External identity provider (SAML or OIDC) configured", "critical", ["IA-2(1)", "L2 3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000148", "ISM-1546", "CPS-7.1"]),
  control(2, "MULESOFT-IAM-02", "MFA enforced for all organization members", "critical", ["IA-2(2)", "L2 3.5.3", "CC6.1", "16.3", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-7.2"]),
  control(3, "MULESOFT-IAM-03", "Organization Administrator membership minimized", "high", ["AC-6(5)", "L2 3.1.5", "CC6.3", "16.8", "7.1.1", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  control(4, "MULESOFT-IAM-04", "Role groups follow least privilege", "high", ["AC-6", "L2 3.1.7", "CC6.3", "16.8", "7.1.2", "SRG-APP-000342", "ISM-1507", "CPS-8.2"]),
  control(5, "MULESOFT-IAM-05", "Role groups scoped to specific environments", "high", ["AC-3", "L2 3.1.2", "CC6.1", "16.8", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.3"]),
  control(6, "MULESOFT-IAM-06", "Production and sandbox environments isolated", "critical", ["SC-7", "L2 3.13.1", "CC6.6", "12.1", "1.3.1", "SRG-APP-000516", "ISM-1528", "CPS-11.1"]),
  control(7, "MULESOFT-API-07", "Authentication policies enforced on production APIs", "critical", ["IA-3", "L2 3.5.2", "CC6.1", "16.7", "8.3.1", "SRG-APP-000158", "ISM-1550", "CPS-7.3"]),
  control(8, "MULESOFT-API-08", "Rate limiting policies applied to APIs", "high", ["SC-5", "L2 3.13.6", "CC6.6", "13.10", "6.6", "SRG-APP-000246", "ISM-1019", "CPS-11.2"]),
  control(9, "MULESOFT-API-09", "API client credentials rotated within policy period", "medium", ["SC-12(1)", "L2 3.13.10", "CC6.1", "16.4", "3.6.4", "SRG-APP-000176", "ISM-1557", "CPS-7.4"]),
  control(10, "MULESOFT-RT-10", "CloudHub applications run supported Mule runtime versions", "high", ["SI-2", "L2 3.14.1", "CC7.1", "7.4", "6.2", "SRG-APP-000456", "ISM-1143", "CPS-13.1"]),
  control(11, "MULESOFT-RT-11", "CloudHub worker sizing reviewed", "low", ["CM-2", "L2 3.4.1", "CC8.1", "4.1", "2.2.1", "SRG-APP-000131", "ISM-1407", "CPS-10.1"]),
  control(12, "MULESOFT-RT-12", "CloudHub persistent queues encrypted", "medium", ["SC-28", "L2 3.13.16", "CC6.7", "14.8", "3.4.1", "SRG-APP-000428", "ISM-0457", "CPS-11.3"]),
  control(13, "MULESOFT-RT-13", "VPC firewall rules restrictive", "high", ["SC-7(5)", "L2 3.13.1", "CC6.6", "12.3", "1.3.2", "SRG-APP-000142", "ISM-1416", "CPS-11.4"]),
  control(14, "MULESOFT-RT-14", "No open 0.0.0.0/0 VPC ingress rules", "critical", ["SC-7", "L2 3.13.1", "CC6.6", "12.3", "1.3.4", "SRG-APP-000142", "ISM-1416", "CPS-11.5"]),
  control(15, "MULESOFT-RT-15", "Dedicated load balancers enforce TLS 1.2+", "high", ["SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.6"]),
  control(16, "MULESOFT-RT-16", "Dedicated load balancer certificates valid beyond 30 days", "high", ["SC-17", "L2 3.13.15", "CC6.7", "14.2", "4.1", "SRG-APP-000175", "ISM-1557", "CPS-7.5"]),
  control(17, "MULESOFT-AUD-17", "Audit logging active and queryable", "high", ["AU-12", "L2 3.3.1", "CC7.2", "8.5", "10.2", "SRG-APP-000507", "ISM-0580", "CPS-12.1"]),
  control(18, "MULESOFT-IAM-18", "Connected apps use minimum required scopes", "high", ["AC-6(1)", "L2 3.1.5", "CC6.3", "16.8", "7.1.2", "SRG-APP-000340", "ISM-1508", "CPS-8.1"]),
  control(19, "MULESOFT-IAM-19", "Stale connected apps reviewed", "medium", ["AC-2(3)", "L2 3.1.12", "CC6.2", "16.9", "8.1.4", "SRG-APP-000025", "ISM-1552", "CPS-9.1"]),
  control(20, "MULESOFT-API-20", "Exchange assets follow governance review", "medium", ["CM-3", "L2 3.4.3", "CC8.1", "4.8", "6.4.2", "SRG-APP-000380", "ISM-1210", "CPS-10.2"]),
  control(21, "MULESOFT-RT-21", "Anypoint MQ access restricted by environment", "medium", ["AC-3", "L2 3.1.1", "CC6.1", "16.8", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.3"]),
  control(22, "MULESOFT-RT-22", "Secrets Manager used for sensitive configuration", "high", ["SC-28(1)", "L2 3.13.16", "CC6.1", "14.8", "3.4.1", "SRG-APP-000429", "ISM-0457", "CPS-11.7"]),
  control(23, "MULESOFT-RT-23", "Hybrid runtime servers registered and reporting", "medium", ["CM-8", "L2 3.4.1", "CC6.8", "1.1", "2.4", "SRG-APP-000383", "ISM-1409", "CPS-10.3"]),
  control(24, "MULESOFT-AUD-24", "Alerts configured for production applications", "medium", ["SI-4", "L2 3.14.6", "CC7.2", "8.11", "10.6.1", "SRG-APP-000516", "ISM-0576", "CPS-12.2"]),
  control(25, "MULESOFT-IAM-25", "Business groups separate tenants", "medium", ["AC-4", "L2 3.1.3", "CC6.6", "12.1", "7.1.4", "SRG-APP-000100", "ISM-1528", "CPS-11.8"]),
];

export function getMulesoftControlCatalog(): MulesoftControlDefinition[] {
  return CONTROL_CATALOG.map((definition) => ({ ...definition, mappings: { ...definition.mappings } }));
}

export interface MulesoftResolvedConfig {
  organizationId: string;
  controlPlane: MulesoftControlPlane;
  baseUrl: string;
  authMode: MulesoftAuthMode;
  token?: string;
  clientId?: string;
  clientSecret?: string;
  username?: string;
  password?: string;
  environmentFilter: string[];
  timeoutMs: number;
  sourceChain: string[];
}

export interface MulesoftAccessSurface {
  name: string;
  endpoint: string;
  permission: string;
  status: "readable" | "not_readable" | "skipped";
  count?: number;
  httpStatus?: number;
  error?: string;
}

export interface MulesoftAccessCheckResult {
  status: "healthy" | "limited";
  organizationId: string;
  controlPlane: MulesoftControlPlane;
  baseUrl: string;
  authMode: MulesoftAuthMode;
  surfaces: MulesoftAccessSurface[];
  missingPermissions: string[];
  notes: string[];
  recommendedNextStep: string;
}

export interface MulesoftFinding {
  id: string;
  control: number;
  title: string;
  severity: MulesoftSeverity;
  status: MulesoftFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface MulesoftAssessmentResult {
  category: MulesoftAssessmentCategory;
  title: string;
  summary: JsonRecord;
  findings: MulesoftFinding[];
  snapshots: Record<string, unknown>;
  errors: string[];
}

export interface MulesoftAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface MulesoftCertificateSummary {
  host: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
}

export type MulesoftCertificateProbe = (host: string, timeoutMs: number) => Promise<MulesoftCertificateSummary>;

export class MulesoftApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "MulesoftApiError";
    this.status = status;
  }
}

type CheckAccessArgs = {
  organization_id?: string;
  client_id?: string;
  client_secret?: string;
  username?: string;
  password?: string;
  token?: string;
  base_url?: string;
  control_plane?: string;
  config_file?: string;
  environments?: string;
  timeout_seconds?: number;
};

type IdentityAccessArgs = CheckAccessArgs & {
  user_limit?: number;
  max_admins?: number;
  max_roles_per_group?: number;
  max_connected_app_scopes?: number;
  stale_connected_app_days?: number;
};

type ApiGatewayArgs = CheckAccessArgs & {
  environment_limit?: number;
  api_limit?: number;
};

type RuntimeInfrastructureArgs = CheckAccessArgs & {
  environment_limit?: number;
  application_limit?: number;
  runtime_support_warning_days?: number;
  certificate_warning_days?: number;
};

type AuditMonitoringArgs = CheckAccessArgs & {
  environment_limit?: number;
  audit_lookback_hours?: number;
};

type ExportAuditBundleArgs = IdentityAccessArgs &
  ApiGatewayArgs &
  RuntimeInfrastructureArgs &
  AuditMonitoringArgs & {
    output_dir?: string;
  };

export interface MulesoftIdentityAccessOptions {
  userLimit?: number;
  maxAdmins?: number;
  maxRolesPerGroup?: number;
  maxConnectedAppScopes?: number;
  staleConnectedAppDays?: number;
}

export interface MulesoftApiGatewayOptions {
  environmentLimit?: number;
  apiLimit?: number;
}

export interface MulesoftRuntimeInfrastructureOptions {
  environmentLimit?: number;
  applicationLimit?: number;
  runtimeSupportWarningDays?: number;
  certificateWarningDays?: number;
}

export interface MulesoftAuditMonitoringOptions {
  environmentLimit?: number;
  auditLookbackHours?: number;
}

export type MulesoftAuditBundleOptions = MulesoftIdentityAccessOptions &
  MulesoftApiGatewayOptions &
  MulesoftRuntimeInfrastructureOptions &
  MulesoftAuditMonitoringOptions;

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
    if (/^(true|yes|1)$/i.test(value.trim())) return true;
    if (/^(false|no|0)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asDate(value: unknown): Date | undefined {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value;
  if (typeof value === "number" && Number.isFinite(value)) {
    const date = new Date(value < 1e11 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return asDate(numeric);
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  return undefined;
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }
  const text = asString(value);
  if (!text) return [];
  return text.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sample<T>(items: T[], limit = MAX_EVIDENCE_SAMPLES): T[] {
  return items.slice(0, limit);
}

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
}

function firstDefined(value: unknown, paths: string[][]): unknown {
  for (const path of paths) {
    const candidate = getNestedValue(value, path);
    if (candidate !== undefined && candidate !== null) return candidate;
  }
  return undefined;
}

function extractCollection(payload: unknown, keys: string[] = ["data"]): JsonRecord[] {
  if (Array.isArray(payload)) return asRecordArray(payload);
  const object = asObject(payload);
  if (!object) return [];
  for (const key of keys) {
    if (Array.isArray(object[key])) return asRecordArray(object[key]);
  }
  return [];
}

export function redactSnapshot(value: unknown, depth = 0): unknown {
  if (depth > 16) return value;
  if (Array.isArray(value)) return value.map((item) => redactSnapshot(item, depth + 1));
  const object = asObject(value);
  if (!object) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    const isScalar = typeof entry === "string" || typeof entry === "number";
    output[key] = SECRET_KEY_PATTERN.test(key) && isScalar ? "[REDACTED]" : redactSnapshot(entry, depth + 1);
  }
  return output;
}

export function redactSecretText(text: string, secrets: Array<string | undefined> = []): string {
  let output = text.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
  output = output.replace(
    /("?(?:client_secret|password|access_token|refresh_token|accessToken|token)"?\s*[:=]\s*"?)([^"&\s,}]+)/gi,
    "$1[REDACTED]",
  );
  for (const secret of secrets) {
    if (secret && secret.length >= 4) output = output.split(secret).join("[REDACTED]");
  }
  return output;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "mulesoft";
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

function stripTomlComment(line: string): string {
  let quote: string | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "#") return line.slice(0, index);
  }
  return line;
}

function unquoteTomlString(value: string): string {
  if (value.startsWith("\"") && value.endsWith("\"") && value.length >= 2) {
    return value
      .slice(1, -1)
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\"/g, "\"")
      .replace(/\\\\/g, "\\");
  }
  if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
    return value.slice(1, -1);
  }
  return value;
}

function splitTomlArray(value: string): string[] {
  const items: string[] = [];
  let current = "";
  let quote: string | undefined;
  for (const character of value) {
    if (quote) {
      current += character;
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      current += character;
      continue;
    }
    if (character === ",") {
      items.push(current.trim());
      current = "";
      continue;
    }
    current += character;
  }
  if (current.trim().length > 0) items.push(current.trim());
  return items;
}

function parseTomlValue(raw: string): unknown {
  const value = raw.trim();
  if (value.startsWith("[") && value.endsWith("]")) {
    return splitTomlArray(value.slice(1, -1)).map((item) => parseTomlValue(item));
  }
  if (value.startsWith("\"") || value.startsWith("'")) return unquoteTomlString(value);
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  const numeric = Number(value.replace(/_/g, ""));
  if (value.length > 0 && Number.isFinite(numeric)) return numeric;
  return value;
}

export function parseSimpleToml(contents: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let section = "";
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (line.length === 0) continue;
    const sectionMatch = /^\[([^\]]+)\]$/.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1].trim().replace(/^["']|["']$/g, "");
      continue;
    }
    const separator = line.indexOf("=");
    if (separator === -1) continue;
    const key = unquoteTomlString(line.slice(0, separator).trim());
    const value = parseTomlValue(line.slice(separator + 1));
    result[section ? `${section}.${key}` : key] = value;
  }
  return result;
}

function normalizeConfigKey(key: string): string {
  return key.trim().toLowerCase().replace(/-/g, "_");
}

function configFileValue(values: Record<string, unknown> | undefined, keys: string[]): unknown {
  if (!values) return undefined;
  const wanted = new Set(keys.map(normalizeConfigKey));
  for (const [key, value] of Object.entries(values)) {
    const segment = key.split(".").pop() ?? key;
    if (wanted.has(normalizeConfigKey(segment))) return value;
  }
  return undefined;
}

function loadConfigFile(path: string): Record<string, unknown> | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return parseSimpleToml(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read MuleSoft config file ${path}: ${errorMessage(error)}`);
  }
}

type ConfigSource = "arguments" | "environment" | "config";

interface ResolvedValue {
  value?: string;
  source?: ConfigSource;
}

function pickValue(
  argumentValue: unknown,
  environmentValues: Array<string | undefined>,
  fileValue: unknown,
): ResolvedValue {
  const fromArguments = asString(argumentValue);
  if (fromArguments) return { value: fromArguments, source: "arguments" };
  for (const candidate of environmentValues) {
    const fromEnvironment = asString(candidate);
    if (fromEnvironment) return { value: fromEnvironment, source: "environment" };
  }
  const fromFile = asString(fileValue);
  if (fromFile) return { value: fromFile, source: "config" };
  return {};
}

function pickList(
  argumentValue: unknown,
  environmentValue: string | undefined,
  fileValue: unknown,
): { value: string[]; source?: ConfigSource } {
  const fromArguments = asStringList(argumentValue);
  if (fromArguments.length > 0) return { value: fromArguments, source: "arguments" };
  const fromEnvironment = asStringList(environmentValue);
  if (fromEnvironment.length > 0) return { value: fromEnvironment, source: "environment" };
  const fromFile = asStringList(fileValue);
  if (fromFile.length > 0) return { value: fromFile, source: "config" };
  return { value: [] };
}

function controlPlaneFromBaseUrl(baseUrl: string): MulesoftControlPlane {
  const host = new URL(baseUrl).hostname.toLowerCase();
  for (const [plane, planeUrl] of Object.entries(CONTROL_PLANE_BASE_URLS) as Array<[Exclude<MulesoftControlPlane, "custom">, string]>) {
    if (new URL(planeUrl).hostname === host) return plane;
  }
  return "custom";
}

function parseControlPlane(value: string | undefined): Exclude<MulesoftControlPlane, "custom"> | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return undefined;
  if (normalized === "us" || normalized === "eu" || normalized === "gov") return normalized;
  throw new Error(`Unsupported MuleSoft control plane "${value}". Use us, eu, or gov, or pass base_url.`);
}

export function resolveMulesoftConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDir?: string } = {},
): MulesoftResolvedConfig {
  const sourceChain: string[] = [];
  const homeDir = options.homeDir ?? homedir();
  const configPath = asString(input.config_file)
    ?? asString(env.MULESOFT_SEC_INSPECTOR_CONFIG)
    ?? asString(env.ANYPOINT_CONFIG_FILE)
    ?? join(homeDir, ...DEFAULT_CONFIG_FILE_SEGMENTS);
  const fileValues = loadConfigFile(configPath);
  if (fileValues) sourceChain.push(`config:${configPath}`);

  const record = (resolved: ResolvedValue, label: string): string | undefined => {
    if (resolved.source) sourceChain.push(`${resolved.source}-${label}`);
    return resolved.value;
  };

  const organizationId = record(
    pickValue(
      input.organization_id ?? input.org_id,
      [env.ANYPOINT_ORG_ID, env.ANYPOINT_ORGANIZATION_ID],
      configFileValue(fileValues, ["org_id", "organization_id", "orgId", "organizationId"]),
    ),
    "organization",
  );
  if (!organizationId) {
    throw new Error("ANYPOINT_ORG_ID, an organization_id argument, or org_id in config.toml is required.");
  }

  const token = record(
    pickValue(input.token, [env.ANYPOINT_TOKEN, env.ANYPOINT_ACCESS_TOKEN], configFileValue(fileValues, ["token", "access_token"])),
    "token",
  );
  const clientId = record(
    pickValue(input.client_id, [env.ANYPOINT_CLIENT_ID], configFileValue(fileValues, ["client_id", "clientId"])),
    "client-id",
  );
  const clientSecret = record(
    pickValue(input.client_secret, [env.ANYPOINT_CLIENT_SECRET], configFileValue(fileValues, ["client_secret", "clientSecret"])),
    "client-secret",
  );
  const username = record(
    pickValue(input.username, [env.ANYPOINT_USERNAME], configFileValue(fileValues, ["username", "user"])),
    "username",
  );
  const password = record(
    pickValue(input.password, [env.ANYPOINT_PASSWORD], configFileValue(fileValues, ["password"])),
    "password",
  );

  let authMode: MulesoftAuthMode;
  if (token) {
    authMode = "token";
  } else if (clientId && clientSecret) {
    authMode = "connected_app";
  } else if (username && password) {
    authMode = "credentials";
  } else {
    throw new Error(
      "Provide connected app credentials (ANYPOINT_CLIENT_ID and ANYPOINT_CLIENT_SECRET), "
      + "username and password (ANYPOINT_USERNAME and ANYPOINT_PASSWORD), a pre-issued ANYPOINT_TOKEN, "
      + "or the matching arguments or config.toml keys.",
    );
  }

  const explicitBaseUrl = record(
    pickValue(input.base_url, [env.ANYPOINT_BASE_URL], configFileValue(fileValues, ["base_url", "baseUrl", "url"])),
    "base-url",
  );
  const explicitPlane = parseControlPlane(record(
    pickValue(input.control_plane, [env.ANYPOINT_CONTROL_PLANE], configFileValue(fileValues, ["control_plane", "controlPlane", "region"])),
    "control-plane",
  ));
  const baseUrl = normalizeBaseUrl(explicitBaseUrl ?? CONTROL_PLANE_BASE_URLS[explicitPlane ?? "us"]);
  const controlPlane = explicitBaseUrl ? controlPlaneFromBaseUrl(baseUrl) : explicitPlane ?? "us";

  const environments = pickList(
    input.environments ?? input.environment_ids ?? input.environment,
    env.ANYPOINT_ENVIRONMENTS ?? env.ANYPOINT_ENVIRONMENT_IDS,
    configFileValue(fileValues, ["environments", "environment", "environment_ids"]),
  );
  if (environments.source) sourceChain.push(`${environments.source}-environments`);

  const timeoutSeconds = asNumber(input.timeout_seconds)
    ?? asNumber(env.ANYPOINT_TIMEOUT)
    ?? asNumber(configFileValue(fileValues, ["timeout", "timeout_seconds"]));

  return {
    organizationId,
    controlPlane,
    baseUrl,
    authMode,
    token,
    clientId,
    clientSecret,
    username,
    password,
    environmentFilter: environments.value,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    sourceChain: [...new Set(sourceChain)],
  };
}

interface RequestOptions {
  method?: "GET" | "POST";
  query?: JsonRecord;
  body?: unknown;
  headers?: Record<string, string>;
  skipAuth?: boolean;
}

interface ListOptions {
  collectionKeys?: string[];
  query?: JsonRecord;
  headers?: Record<string, string>;
  limit?: number;
  pageSize?: number;
}

function parseJsonText(rawText: string): unknown {
  if (rawText.trim().length === 0) return {};
  try {
    return JSON.parse(rawText) as unknown;
  } catch {
    throw new Error("Anypoint response was not valid JSON.");
  }
}

function anypointErrorDetail(payload: unknown, rawText: string): string {
  const object = asObject(payload);
  const detail = object
    ? [
      asString(object.message),
      asString(object.error_description),
      asString(object.error),
      asString(getNestedValue(object, ["errors", "0", "message"])),
    ].filter((item): item is string => Boolean(item)).join("; ")
    : rawText.slice(0, 240);
  return detail ? `: ${detail}` : "";
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function certificateName(value: unknown): string | undefined {
  const object = asObject(value);
  return asString(object?.CN) ?? asString(object?.O);
}

export function defaultCertificateProbe(host: string, timeoutMs: number): Promise<MulesoftCertificateSummary> {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = tlsConnect({ host, port: 443, servername: host, rejectUnauthorized: false }, () => {
      const certificate = socket.getPeerCertificate();
      socket.end();
      resolvePromise({
        host,
        subject: certificateName(certificate.subject),
        issuer: certificateName(certificate.issuer),
        validFrom: asString(certificate.valid_from),
        validTo: asString(certificate.valid_to),
      });
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`TLS probe of ${host} timed out.`));
    });
    socket.on("error", (error) => rejectPromise(error));
  });
}

export class MulesoftApiClient {
  private readonly config: MulesoftResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: SleepImpl;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly certificateProbe: MulesoftCertificateProbe;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private accessTokenPromise?: Promise<string>;

  constructor(
    config: MulesoftResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleepImpl?: SleepImpl;
      maxRetries?: number;
      retryBaseDelayMs?: number;
      certificateProbe?: MulesoftCertificateProbe;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? defaultSleep;
    this.maxRetries = clampNumber(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 10);
    this.retryBaseDelayMs = clampNumber(options.retryBaseDelayMs, DEFAULT_RETRY_BASE_DELAY_MS, 0, MAX_RETRY_DELAY_MS);
    this.certificateProbe = options.certificateProbe ?? defaultCertificateProbe;
    if (config.authMode === "token" && config.token) {
      this.accessToken = config.token;
      this.accessTokenExpiresAt = Number.MAX_SAFE_INTEGER;
    }
  }

  getResolvedConfig(): MulesoftResolvedConfig {
    return this.config;
  }

  redact(text: string): string {
    return redactSecretText(text, [
      this.config.clientSecret,
      this.config.password,
      this.config.token,
      this.accessToken,
    ]);
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const url = new URL(
      path.startsWith("http://") || path.startsWith("https://")
        ? path
        : `${this.config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private retryDelayMs(response: Response | undefined, attempt: number): number {
    const retryAfter = asNumber(response?.headers.get("retry-after"));
    if (retryAfter !== undefined && retryAfter > 0) {
      return Math.min(retryAfter * 1000, MAX_RETRY_DELAY_MS);
    }
    return Math.min(this.retryBaseDelayMs * 2 ** attempt, MAX_RETRY_DELAY_MS);
  }

  private async requestJson(path: string, init: RequestOptions = {}): Promise<unknown> {
    const method = init.method ?? "GET";
    const url = this.buildUrl(path, init.query ?? {});
    const pathLabel = new URL(url).pathname;
    const bearer = init.skipAuth ? undefined : await this.getAccessToken();

    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const headers = new Headers(init.headers ?? {});
        if (!headers.has("accept")) headers.set("accept", "application/json");
        if (init.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
        if (bearer) headers.set("authorization", `Bearer ${bearer}`);

        const response = await this.fetchImpl(url, {
          method,
          headers,
          body: init.body === undefined ? undefined : JSON.stringify(init.body),
          signal: controller.signal,
        });
        const rawText = await response.text();
        if (response.ok) return parseJsonText(rawText);

        if (isRetryableStatus(response.status) && attempt < this.maxRetries) {
          await this.sleepImpl(this.retryDelayMs(response, attempt));
          continue;
        }

        let payload: unknown;
        try {
          payload = parseJsonText(rawText);
        } catch {
          payload = undefined;
        }
        throw new MulesoftApiError(
          response.status,
          this.redact(
            `Anypoint request failed (${response.status} ${response.statusText}) for ${method} ${pathLabel}`
            + anypointErrorDetail(payload, rawText),
          ),
        );
      } catch (error) {
        if (error instanceof MulesoftApiError) throw error;
        if (attempt < this.maxRetries) {
          await this.sleepImpl(this.retryDelayMs(undefined, attempt));
          continue;
        }
        throw new Error(this.redact(`Anypoint request failed for ${method} ${pathLabel}: ${errorMessage(error)}`));
      } finally {
        clearTimeout(timer);
      }
    }
  }

  private async fetchAccessToken(): Promise<string> {
    const authMode = this.config.authMode;
    let payload: unknown;
    switch (authMode) {
      case "token": {
        if (!this.config.token) throw new Error("A pre-issued Anypoint token is required for token auth mode.");
        return this.config.token;
      }
      case "connected_app": {
        payload = await this.requestJson("/accounts/api/v2/oauth2/token", {
          method: "POST",
          body: {
            grant_type: "client_credentials",
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
          },
          skipAuth: true,
        });
        break;
      }
      case "credentials": {
        payload = await this.requestJson("/accounts/login", {
          method: "POST",
          body: {
            username: this.config.username,
            password: this.config.password,
          },
          skipAuth: true,
        });
        break;
      }
      default: {
        const exhaustive: never = authMode;
        throw new Error(`Unsupported MuleSoft auth mode: ${String(exhaustive)}`);
      }
    }

    const record = asObject(payload) ?? {};
    const accessToken = asString(record.access_token);
    if (!accessToken) {
      throw new Error("Anypoint token response did not include access_token.");
    }
    const expiresIn = asNumber(record.expires_in) ?? 3600;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = Date.now() + Math.max((expiresIn - 60) * 1000, 60_000);
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

  async get(path: string, query: JsonRecord = {}, headers: Record<string, string> = {}): Promise<unknown> {
    return this.requestJson(path, { method: "GET", query, headers });
  }

  async post(path: string, body: unknown, query: JsonRecord = {}, headers: Record<string, string> = {}): Promise<unknown> {
    return this.requestJson(path, { method: "POST", body, query, headers });
  }

  async listOffset(path: string, options: ListOptions = {}): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 100_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 250);
    const items: JsonRecord[] = [];
    let offset = 0;

    while (items.length < limit) {
      const payload = await this.get(path, {
        ...(options.query ?? {}),
        limit: Math.min(pageSize, limit - items.length),
        offset,
      }, options.headers);
      const pageItems = extractCollection(payload, options.collectionKeys ?? ["data"]);
      items.push(...pageItems.slice(0, limit - items.length));
      offset += pageItems.length;
      const total = asNumber(asObject(payload)?.total);
      if (pageItems.length === 0 || pageItems.length < Math.min(pageSize, limit) || (total !== undefined && offset >= total)) {
        break;
      }
    }

    return items;
  }

  private orgPath(suffix = ""): string {
    return `/accounts/api/organizations/${encodeURIComponent(this.config.organizationId)}${suffix}`;
  }

  private environmentHeaders(environmentId: string): Record<string, string> {
    return {
      "X-ANYPNT-ENV-ID": environmentId,
      "X-ANYPNT-ORG-ID": this.config.organizationId,
    };
  }

  async getCurrentUser(): Promise<JsonRecord> {
    return asObject(await this.get("/accounts/api/me")) ?? {};
  }

  async getOrganization(): Promise<JsonRecord> {
    return asObject(await this.get(this.orgPath())) ?? {};
  }

  async getOrganizationHierarchy(): Promise<JsonRecord> {
    return asObject(await this.get(this.orgPath("/hierarchy"))) ?? {};
  }

  async listIdentityProviders(): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath("/identityProviders"));
  }

  async getIdentityProviderSettings(): Promise<JsonRecord> {
    return asObject(await this.get(this.orgPath("/identityProviderSettings"))) ?? {};
  }

  async listMembers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath("/members"), { limit });
  }

  async listMfaExemptUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath("/users"), { query: { mfaVerificationExcluded: true }, limit });
  }

  async listRoleGroups(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath("/rolegroups"), { limit });
  }

  async listRoleGroupRoles(roleGroupId: string, limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath(`/rolegroups/${encodeURIComponent(roleGroupId)}/roles`), { limit });
  }

  async listRoleGroupUsers(roleGroupId: string, limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath(`/rolegroups/${encodeURIComponent(roleGroupId)}/users`), { limit });
  }

  async listEnvironments(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(this.orgPath("/environments")));
  }

  async listConnectedApplications(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath("/connectedApplications"), { query: { includeUsage: true }, limit });
  }

  async listConnectedApplicationScopes(clientId: string): Promise<JsonRecord[]> {
    return this.listOffset(this.orgPath(`/connectedApplications/${encodeURIComponent(clientId)}/scopes`));
  }

  async listManagedApis(environmentId: string, limit = DEFAULT_API_LIMIT): Promise<JsonRecord[]> {
    const assets = await this.listOffset(
      `/apimanager/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}/apis`,
      { collectionKeys: ["assets"], limit },
    );
    const apis: JsonRecord[] = [];
    for (const asset of assets) {
      for (const api of asRecordArray(asset.apis)) {
        apis.push({
          ...api,
          assetName: asString(asset.name),
          assetGroupId: asString(asset.groupId),
          assetId: asString(asset.assetId),
          environmentId: asString(api.environmentId) ?? environmentId,
        });
      }
    }
    return apis.slice(0, limit);
  }

  async listApiPolicies(environmentId: string, apiId: string): Promise<JsonRecord[]> {
    const payload = await this.get(
      `/apimanager/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}/apis/${encodeURIComponent(apiId)}/policies`,
      { fullInfo: false },
    );
    return extractCollection(payload, ["policies", "data"]);
  }

  async listExchangeAssets(limit = DEFAULT_LIST_LIMIT): Promise<JsonRecord[]> {
    return this.listOffset("/exchange/api/v2/assets/search", { limit, pageSize: 100 });
  }

  async listCloudhubApplications(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/cloudhub/api/v2/applications", {}, this.environmentHeaders(environmentId)));
  }

  async listCloudhubAlerts(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/cloudhub/api/v2/alerts", {}, this.environmentHeaders(environmentId)));
  }

  async listVpcs(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(`/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/vpcs`));
  }

  async getVpc(vpcId: string): Promise<JsonRecord> {
    return asObject(await this.get(`/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/vpcs/${encodeURIComponent(vpcId)}`)) ?? {};
  }

  async listLoadBalancers(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(`/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/loadbalancers`));
  }

  async probeCertificate(host: string): Promise<MulesoftCertificateSummary> {
    return this.certificateProbe(host, this.config.timeoutMs);
  }

  async listHybridServers(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/hybrid/api/v1/servers", {}, this.environmentHeaders(environmentId)));
  }

  async listHybridAlerts(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/hybrid/api/v1/alerts", {}, this.environmentHeaders(environmentId)));
  }

  async listAuditPlatforms(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(`/audit/v2/organizations/${encodeURIComponent(this.config.organizationId)}/platforms`));
  }

  async queryAuditLogs(query: { startDate: string; endDate?: string; limit?: number; offset?: number }): Promise<JsonRecord> {
    const payload = await this.post(`/audit/v2/organizations/${encodeURIComponent(this.config.organizationId)}/query`, {
      startDate: query.startDate,
      endDate: query.endDate,
      limit: clampNumber(query.limit, AUDIT_QUERY_PAGE_LIMIT, 1, AUDIT_QUERY_PAGE_LIMIT),
      offset: query.offset ?? 0,
    });
    return asObject(payload) ?? {};
  }

  private mqPath(environmentId: string, suffix = ""): string {
    return `/mq/admin/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}${suffix}`;
  }

  async listMqRegions(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get(this.mqPath(environmentId, "/regions")));
  }

  async listMqQueues(environmentId: string, regionId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get(this.mqPath(environmentId, `/regions/${encodeURIComponent(regionId)}/destinations/queues`)));
  }

  async listMqClients(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get(this.mqPath(environmentId, "/clients")));
  }

  async listSecretGroups(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(
      await this.get(`/secrets-manager/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}/secretGroups`),
    );
  }
}

type IdentityClient = Pick<
  MulesoftApiClient,
  | "getResolvedConfig"
  | "getOrganization"
  | "getOrganizationHierarchy"
  | "listIdentityProviders"
  | "getIdentityProviderSettings"
  | "listMembers"
  | "listMfaExemptUsers"
  | "listRoleGroups"
  | "listRoleGroupRoles"
  | "listRoleGroupUsers"
  | "listEnvironments"
  | "listConnectedApplications"
  | "listConnectedApplicationScopes"
>;

type ApiGatewayClient = Pick<
  MulesoftApiClient,
  "getResolvedConfig" | "listEnvironments" | "listManagedApis" | "listApiPolicies" | "listExchangeAssets"
>;

type RuntimeClient = Pick<
  MulesoftApiClient,
  | "getResolvedConfig"
  | "listEnvironments"
  | "listCloudhubApplications"
  | "listVpcs"
  | "getVpc"
  | "listLoadBalancers"
  | "probeCertificate"
  | "listHybridServers"
  | "listMqRegions"
  | "listMqQueues"
  | "listMqClients"
  | "listSecretGroups"
>;

type AuditClient = Pick<
  MulesoftApiClient,
  | "getResolvedConfig"
  | "listEnvironments"
  | "listAuditPlatforms"
  | "queryAuditLogs"
  | "listCloudhubAlerts"
  | "listHybridAlerts"
  | "listCloudhubApplications"
>;

type AccessClient = IdentityClient & ApiGatewayClient & RuntimeClient & AuditClient & Pick<MulesoftApiClient, "getCurrentUser">;

export type MulesoftBundleClient = AccessClient;

async function collect<T>(label: string, fallback: T, load: () => Promise<T>, errors: string[]): Promise<T> {
  try {
    return await load();
  } catch (error) {
    errors.push(`${label}: ${errorMessage(error)}`);
    return fallback;
  }
}

function finding(
  number: number,
  status: MulesoftFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): MulesoftFinding {
  const definition = CONTROL_CATALOG.find((item) => item.number === number);
  if (!definition) throw new Error(`Unknown MuleSoft control ${number}`);
  return {
    id: definition.id,
    control: number,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: FRAMEWORKS.map((framework) => `${FRAMEWORK_LABELS[framework]} ${definition.mappings[framework]}`),
  };
}

function isProductionEnvironment(environment: JsonRecord): boolean {
  return asBoolean(environment.isProduction) === true || /^production$/i.test(asString(environment.type) ?? "");
}

function environmentLabel(environment: JsonRecord): string {
  return asString(environment.name) ?? asString(environment.id) ?? "environment";
}

function matchesEnvironmentFilter(environment: JsonRecord, filter: string[]): boolean {
  if (filter.length === 0) return true;
  const wanted = new Set(filter.map((item) => item.toLowerCase()));
  return wanted.has((asString(environment.name) ?? "").toLowerCase())
    || wanted.has((asString(environment.id) ?? "").toLowerCase());
}

async function loadEnvironments(
  client: Pick<MulesoftApiClient, "getResolvedConfig" | "listEnvironments">,
  limit: number,
  errors: string[],
): Promise<JsonRecord[]> {
  const config = client.getResolvedConfig();
  const environments = await collect("environments", [], () => client.listEnvironments(), errors);
  return environments
    .filter((environment) => matchesEnvironmentFilter(environment, config.environmentFilter))
    .sort((left, right) => Number(isProductionEnvironment(right)) - Number(isProductionEnvironment(left)))
    .slice(0, limit);
}

function roleGroupName(roleGroup: JsonRecord): string {
  return asString(roleGroup.name) ?? asString(roleGroup.role_group_id) ?? "role group";
}

function roleGroupId(roleGroup: JsonRecord): string | undefined {
  return asString(roleGroup.role_group_id) ?? asString(roleGroup.id);
}

function roleName(assignment: JsonRecord): string {
  return asString(assignment.name) ?? asString(assignment.role_id) ?? "role";
}

function assignmentEnvironmentId(assignment: JsonRecord): string | undefined {
  return asString(getNestedValue(assignment, ["context_params", "envId"]));
}

function isOrgAdminRoleGroup(roleGroup: JsonRecord, roles: JsonRecord[]): boolean {
  return ORG_ADMIN_ROLE_PATTERN.test(roleGroupName(roleGroup)) || roles.some((role) => ORG_ADMIN_ROLE_PATTERN.test(roleName(role)));
}

function isBuiltInAdminGroup(roleGroup: JsonRecord): boolean {
  return /^organization administrators?$/i.test(roleGroupName(roleGroup)) || asBoolean(roleGroup.editable) === false;
}

function memberLabel(member: JsonRecord): string {
  return asString(member.username) ?? asString(member.email) ?? asString(member.id) ?? "user";
}

function connectedAppName(app: JsonRecord): string {
  return asString(app.client_name) ?? asString(app.name) ?? asString(app.client_id) ?? "connected app";
}

function connectedAppLastUsed(app: JsonRecord): Date | undefined {
  return asDate(firstDefined(app, [
    ["last_used"],
    ["lastUsed"],
    ["last_used_at"],
    ["usage", "last_used"],
    ["usage", "lastUsed"],
    ["usage", "last_used_at"],
    ["usage", "lastUsedAt"],
  ]));
}

function connectedAppCreatedAt(app: JsonRecord): Date | undefined {
  return asDate(firstDefined(app, [["created_at"], ["createdAt"], ["created"]]));
}

function connectedAppHasUsageData(app: JsonRecord): boolean {
  return connectedAppLastUsed(app) !== undefined || firstDefined(app, [["usage"], ["last_used"], ["lastUsed"]]) !== undefined;
}

function scopeName(scope: JsonRecord): string {
  return asString(scope.scope) ?? asString(scope.name) ?? "scope";
}

export async function assessMulesoftIdentityAccess(
  client: IdentityClient,
  options: MulesoftIdentityAccessOptions = {},
): Promise<MulesoftAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 10_000);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 5000);
  const maxRolesPerGroup = clampNumber(options.maxRolesPerGroup, DEFAULT_MAX_ROLES_PER_GROUP, 1, 500);
  const maxConnectedAppScopes = clampNumber(options.maxConnectedAppScopes, DEFAULT_MAX_CONNECTED_APP_SCOPES, 1, 500);
  const staleDays = clampNumber(options.staleConnectedAppDays, DEFAULT_STALE_CONNECTED_APP_DAYS, 1, 3650);

  const organization = await collect("organization", {}, () => client.getOrganization(), errors);
  const hierarchy = await collect("organization_hierarchy", {}, () => client.getOrganizationHierarchy(), errors);
  const identityProviders = await collect("identity_providers", [], () => client.listIdentityProviders(), errors);
  const identityProviderSettings = await collect("identity_provider_settings", {}, () => client.getIdentityProviderSettings(), errors);
  const members = await collect("members", [], () => client.listMembers(userLimit), errors);
  const mfaExemptUsers = await collect("mfa_exempt_users", [], () => client.listMfaExemptUsers(userLimit), errors);
  const roleGroups = await collect("role_groups", [], () => client.listRoleGroups(), errors);
  const environments = await collect("environments", [], () => client.listEnvironments(), errors);
  const connectedApps = await collect("connected_applications", [], () => client.listConnectedApplications(), errors);

  const roleGroupDetails: Array<{ roleGroup: JsonRecord; roles: JsonRecord[]; users: JsonRecord[] }> = [];
  for (const roleGroup of roleGroups) {
    const id = roleGroupId(roleGroup);
    if (!id) continue;
    const roles = await collect(`role_group_roles:${roleGroupName(roleGroup)}`, [], () => client.listRoleGroupRoles(id), errors);
    const users = isOrgAdminRoleGroup(roleGroup, roles)
      ? await collect(`role_group_users:${roleGroupName(roleGroup)}`, [], () => client.listRoleGroupUsers(id), errors)
      : [];
    roleGroupDetails.push({ roleGroup, roles, users });
  }

  const connectedAppScopes: Array<{ app: JsonRecord; scopes: JsonRecord[] }> = [];
  for (const app of connectedApps) {
    const clientId = asString(app.client_id);
    const scopes = clientId
      ? await collect(`connected_app_scopes:${connectedAppName(app)}`, [], () => client.listConnectedApplicationScopes(clientId), errors)
      : [];
    connectedAppScopes.push({ app, scopes });
  }

  const providerSummaries = identityProviders.map((provider) => ({
    name: asString(provider.name) ?? asString(provider.provider_id) ?? "identity provider",
    type: asString(getNestedValue(provider, ["type", "name"])) ?? asString(provider.type) ?? "unknown",
  }));
  const allowNewNonSsoUsers = asBoolean(identityProviderSettings.allow_new_non_sso_users);
  const isFederated = asBoolean(organization.isFederated) === true || asBoolean(hierarchy.isFederated) === true;

  const adminGroups = roleGroupDetails.filter((detail) => isOrgAdminRoleGroup(detail.roleGroup, detail.roles));
  const adminUsers = new Map<string, string>();
  for (const detail of adminGroups) {
    for (const user of detail.users) {
      const id = asString(user.id) ?? memberLabel(user);
      adminUsers.set(id, memberLabel(user));
    }
  }

  const overPrivilegedGroups = roleGroupDetails
    .filter((detail) => !isBuiltInAdminGroup(detail.roleGroup) && detail.roles.some((role) => ORG_ADMIN_ROLE_PATTERN.test(roleName(role))))
    .map((detail) => roleGroupName(detail.roleGroup));
  const broadGroups = roleGroupDetails
    .filter((detail) => detail.roles.length > maxRolesPerGroup)
    .map((detail) => ({ role_group: roleGroupName(detail.roleGroup), roles: detail.roles.length }));

  const allAssignments = roleGroupDetails.flatMap((detail) =>
    detail.roles.map((role) => ({ roleGroup: roleGroupName(detail.roleGroup), role })),
  );
  const environmentScopedAssignments = allAssignments.filter((item) => assignmentEnvironmentId(item.role) !== undefined);
  const orgWideEnvironmentRoles = allAssignments.filter((item) =>
    assignmentEnvironmentId(item.role) === undefined
    && ENVIRONMENT_ROLE_PATTERN.test(roleName(item.role))
    && !ORG_ADMIN_ROLE_PATTERN.test(roleName(item.role)),
  );

  const productionEnvironments = environments.filter(isProductionEnvironment);
  const sandboxEnvironments = environments.filter((environment) => !isProductionEnvironment(environment));
  const misclassifiedEnvironments = environments.filter((environment) => {
    const name = environmentLabel(environment);
    const production = isProductionEnvironment(environment);
    return (PRODUCTION_NAME_PATTERN.test(name) && !production) || (NON_PRODUCTION_NAME_PATTERN.test(name) && production);
  });

  const adminScopedApps = connectedAppScopes
    .filter((item) => item.scopes.some((scope) => ADMIN_SCOPE_PATTERN.test(scopeName(scope))))
    .map((item) => connectedAppName(item.app));
  const broadScopedApps = connectedAppScopes
    .filter((item) => item.scopes.length > maxConnectedAppScopes)
    .map((item) => ({ app: connectedAppName(item.app), scopes: item.scopes.length }));

  const now = Date.now();
  const staleThreshold = now - staleDays * DAY_MS;
  const appsWithUsage = connectedApps.filter(connectedAppHasUsageData);
  const staleApps = connectedApps.filter((app) => {
    const lastUsed = connectedAppLastUsed(app);
    if (lastUsed) return lastUsed.getTime() < staleThreshold;
    const created = connectedAppCreatedAt(app);
    return connectedAppHasUsageData(app) && created !== undefined && created.getTime() < staleThreshold;
  });
  const disabledApps = connectedApps.filter((app) => asBoolean(app.enabled) === false);

  const subOrganizations = asRecordArray(hierarchy.subOrganizations);
  const canCreateSubOrgs = asBoolean(getNestedValue(organization, ["entitlements", "createSubOrgs"]));

  const findings: MulesoftFinding[] = [
    finding(
      1,
      identityProviders.length === 0 ? "fail" : allowNewNonSsoUsers === true ? "warn" : "pass",
      identityProviders.length === 0
        ? "No external identity provider is configured; users authenticate with Anypoint Platform passwords."
        : allowNewNonSsoUsers === true
          ? `${identityProviders.length} external identity provider(s) configured, but new non-SSO users are still allowed.`
          : `${identityProviders.length} external identity provider(s) configured and non-SSO user creation is not allowed.`,
      {
        identity_providers: providerSummaries,
        is_federated: isFederated,
        allow_new_non_sso_users: allowNewNonSsoUsers ?? null,
      },
    ),
    finding(
      2,
      mfaExemptUsers.length > 0 ? "fail" : "manual",
      mfaExemptUsers.length > 0
        ? `${mfaExemptUsers.length} user(s) are excluded from MFA verification.`
        : "No MFA-exempt users are visible. The organization-wide MFA requirement is not exposed by the Access Management API: capture the Access Management > Organization > multi-factor authentication setting, or the external identity provider MFA policy, as evidence.",
      {
        mfa_exempt_users: sample(mfaExemptUsers.map(memberLabel)),
        members_sampled: members.length,
        is_federated: isFederated,
      },
    ),
    finding(
      3,
      adminGroups.length === 0 ? "warn" : adminUsers.size <= maxAdmins ? "pass" : "fail",
      adminGroups.length === 0
        ? "No Organization Administrator or Organization Owner role group was visible, so admin membership could not be counted."
        : adminUsers.size <= maxAdmins
          ? `${adminUsers.size} organization administrator(s) across ${adminGroups.length} admin role group(s), within the threshold of ${maxAdmins}.`
          : `${adminUsers.size} organization administrator(s) exceed the threshold of ${maxAdmins}.`,
      {
        admin_role_groups: adminGroups.map((detail) => roleGroupName(detail.roleGroup)),
        admin_users: sample([...adminUsers.values()]),
        max_admins: maxAdmins,
        members_sampled: members.length,
      },
    ),
    finding(
      4,
      roleGroups.length === 0 ? "warn" : overPrivilegedGroups.length > 0 ? "fail" : broadGroups.length > 0 ? "warn" : "pass",
      roleGroups.length === 0
        ? "No role groups were visible."
        : overPrivilegedGroups.length > 0
          ? `${overPrivilegedGroups.length} custom role group(s) grant Organization Administrator or Organization Owner roles.`
          : broadGroups.length > 0
            ? `${broadGroups.length} role group(s) carry more than ${maxRolesPerGroup} role assignments.`
            : `${roleGroups.length} role group(s) reviewed with no organization-wide admin grants outside the built-in administrators group.`,
      {
        role_groups: roleGroups.length,
        over_privileged_groups: sample(overPrivilegedGroups),
        broad_groups: sample(broadGroups),
        max_roles_per_group: maxRolesPerGroup,
      },
    ),
    finding(
      5,
      orgWideEnvironmentRoles.length === 0 ? "pass" : orgWideEnvironmentRoles.length <= MAX_ORG_WIDE_ENVIRONMENT_ROLES ? "warn" : "fail",
      orgWideEnvironmentRoles.length === 0
        ? `${environmentScopedAssignments.length} environment role assignment(s) are scoped to specific environments.`
        : `${orgWideEnvironmentRoles.length} environment-level role assignment(s) apply to all environments instead of a specific environment.`,
      {
        environment_scoped_assignments: environmentScopedAssignments.length,
        org_wide_environment_roles: sample(orgWideEnvironmentRoles.map((item) => `${item.roleGroup}: ${roleName(item.role)}`)),
      },
    ),
    finding(
      6,
      misclassifiedEnvironments.length > 0
        ? "fail"
        : productionEnvironments.length === 0 || sandboxEnvironments.length === 0
          ? "warn"
          : "pass",
      misclassifiedEnvironments.length > 0
        ? `${misclassifiedEnvironments.length} environment(s) have names that contradict their production or sandbox type.`
        : productionEnvironments.length === 0 || sandboxEnvironments.length === 0
          ? `Only ${productionEnvironments.length} production and ${sandboxEnvironments.length} sandbox environment(s) exist, so production workloads may share an environment with development.`
          : `${productionEnvironments.length} production and ${sandboxEnvironments.length} sandbox environment(s) are typed separately.`,
      {
        production_environments: sample(productionEnvironments.map(environmentLabel)),
        sandbox_environments: sample(sandboxEnvironments.map(environmentLabel)),
        misclassified_environments: sample(misclassifiedEnvironments.map(environmentLabel)),
      },
    ),
    finding(
      18,
      connectedApps.length === 0 ? "pass" : adminScopedApps.length > 0 ? "fail" : broadScopedApps.length > 0 ? "warn" : "pass",
      connectedApps.length === 0
        ? "No connected apps are registered in this organization."
        : adminScopedApps.length > 0
          ? `${adminScopedApps.length} connected app(s) hold administrative or full-access scopes.`
          : broadScopedApps.length > 0
            ? `${broadScopedApps.length} connected app(s) hold more than ${maxConnectedAppScopes} scopes.`
            : `${connectedApps.length} connected app(s) reviewed with no administrative scopes.`,
      {
        connected_apps: connectedApps.length,
        admin_scoped_apps: sample(adminScopedApps),
        broad_scoped_apps: sample(broadScopedApps),
        max_connected_app_scopes: maxConnectedAppScopes,
      },
    ),
    finding(
      19,
      connectedApps.length === 0
        ? "pass"
        : staleApps.length > 0 || disabledApps.length > 0
          ? "warn"
          : appsWithUsage.length === 0
            ? "manual"
            : "pass",
      connectedApps.length === 0
        ? "No connected apps are registered in this organization."
        : staleApps.length > 0 || disabledApps.length > 0
          ? `${staleApps.length} connected app(s) unused for more than ${staleDays} days and ${disabledApps.length} disabled app(s) should be reviewed for removal.`
          : appsWithUsage.length === 0
            ? "The API did not return usage data for connected apps. Export the connected apps list with last-used timestamps from Access Management > Connected Apps and confirm each app is still required."
            : `${connectedApps.length} connected app(s) show activity within the last ${staleDays} days.`,
      {
        connected_apps: connectedApps.length,
        apps_with_usage_data: appsWithUsage.length,
        stale_apps: sample(staleApps.map(connectedAppName)),
        disabled_apps: sample(disabledApps.map(connectedAppName)),
        stale_days: staleDays,
      },
    ),
    finding(
      25,
      subOrganizations.length > 0 ? "pass" : "manual",
      subOrganizations.length > 0
        ? `${subOrganizations.length} business group(s) separate teams or tenants under the root organization.`
        : "No business groups exist. Confirm whether multiple business units or tenants share this organization; if they do, create business groups so ownership, environments, and permissions are isolated.",
      {
        sub_organizations: sample(subOrganizations.map((item) => asString(item.name) ?? asString(item.id) ?? "business group")),
        can_create_sub_orgs: canCreateSubOrgs ?? null,
        is_root: asBoolean(hierarchy.isRoot) ?? null,
      },
    ),
  ];

  return {
    category: "identity_access",
    title: "MuleSoft identity and access posture",
    summary: {
      organization_id: config.organizationId,
      identity_providers: identityProviders.length,
      members_sampled: members.length,
      mfa_exempt_users: mfaExemptUsers.length,
      organization_admins: adminUsers.size,
      role_groups: roleGroups.length,
      environments: environments.length,
      connected_apps: connectedApps.length,
      stale_connected_apps: staleApps.length,
      business_groups: subOrganizations.length,
    },
    findings,
    snapshots: {
      organization: redactSnapshot(organization),
      organization_hierarchy: redactSnapshot(hierarchy),
      identity_providers: redactSnapshot(identityProviders),
      identity_provider_settings: redactSnapshot(identityProviderSettings),
      members: redactSnapshot(members),
      mfa_exempt_users: redactSnapshot(mfaExemptUsers),
      role_groups: redactSnapshot(roleGroupDetails.map((detail) => ({
        role_group: detail.roleGroup,
        roles: detail.roles,
        users: detail.users,
      }))),
      environments: redactSnapshot(environments),
      connected_applications: redactSnapshot(connectedAppScopes.map((item) => ({ ...item.app, scopes: item.scopes }))),
    },
    errors,
  };
}

function policyAssetId(policy: JsonRecord): string {
  return asString(firstDefined(policy, [
    ["assetId"],
    ["template", "assetId"],
    ["implementationAsset", "assetId"],
    ["policyTemplateId"],
  ])) ?? "policy";
}

function isActivePolicy(policy: JsonRecord): boolean {
  return asBoolean(policy.disabled) !== true;
}

function apiLabel(api: JsonRecord): string {
  const name = asString(api.assetName) ?? asString(api.assetId) ?? asString(api.autodiscoveryInstanceName) ?? asString(api.id) ?? "api";
  const label = asString(api.instanceLabel);
  return label ? `${name} (${label})` : name;
}

export async function assessMulesoftApiGateway(
  client: ApiGatewayClient,
  options: MulesoftApiGatewayOptions = {},
): Promise<MulesoftAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const environmentLimit = clampNumber(options.environmentLimit, DEFAULT_ENVIRONMENT_LIMIT, 1, 100);
  const apiLimit = clampNumber(options.apiLimit, DEFAULT_API_LIMIT, 1, 2000);

  const environments = await loadEnvironments(client, environmentLimit, errors);
  const apiRecords: Array<{ environment: JsonRecord; api: JsonRecord; policies: JsonRecord[] }> = [];
  for (const environment of environments) {
    const environmentId = asString(environment.id);
    if (!environmentId || apiRecords.length >= apiLimit) continue;
    const apis = await collect(`managed_apis:${environmentLabel(environment)}`, [], () => client.listManagedApis(environmentId, apiLimit - apiRecords.length), errors);
    for (const api of apis) {
      if (apiRecords.length >= apiLimit) break;
      const apiId = asString(api.id);
      const policies = apiId
        ? await collect(`api_policies:${apiLabel(api)}`, [], () => client.listApiPolicies(environmentId, apiId), errors)
        : [];
      apiRecords.push({ environment, api, policies });
    }
  }

  const exchangeAssets = await collect("exchange_assets", [], () => client.listExchangeAssets(), errors);
  const organizationAssets = exchangeAssets.filter((asset) => {
    const owner = asString(asset.organizationId);
    return owner === undefined || owner === config.organizationId;
  });

  const productionApis = apiRecords.filter((record) => isProductionEnvironment(record.environment));
  const nonProductionApis = apiRecords.filter((record) => !isProductionEnvironment(record.environment));
  const lacksPolicy = (pattern: RegExp) => (record: { policies: JsonRecord[] }) =>
    !record.policies.some((policy) => isActivePolicy(policy) && pattern.test(policyAssetId(policy)));

  const productionWithoutAuth = productionApis.filter(lacksPolicy(AUTHENTICATION_POLICY_PATTERN));
  const nonProductionWithoutAuth = nonProductionApis.filter(lacksPolicy(AUTHENTICATION_POLICY_PATTERN));
  const productionWithoutRateLimit = productionApis.filter(lacksPolicy(RATE_LIMIT_POLICY_PATTERN));
  const nonProductionWithoutRateLimit = nonProductionApis.filter(lacksPolicy(RATE_LIMIT_POLICY_PATTERN));
  const activeContracts = apiRecords.reduce((total, record) => total + (asNumber(record.api.activeContractsCount) ?? 0), 0);

  const publicAssets = organizationAssets.filter((asset) => asBoolean(asset.isPublic) === true);
  const assetStatusCounts: Record<string, number> = {};
  const assetTypeCounts: Record<string, number> = {};
  for (const asset of organizationAssets) {
    const status = asString(asset.status) ?? "unknown";
    const type = asString(asset.type) ?? "unknown";
    assetStatusCounts[status] = (assetStatusCounts[status] ?? 0) + 1;
    assetTypeCounts[type] = (assetTypeCounts[type] ?? 0) + 1;
  }

  const describeApis = (records: Array<{ environment: JsonRecord; api: JsonRecord }>) =>
    sample(records.map((record) => `${environmentLabel(record.environment)}: ${apiLabel(record.api)}`));

  const findings: MulesoftFinding[] = [
    finding(
      7,
      apiRecords.length === 0
        ? "warn"
        : productionWithoutAuth.length > 0
          ? "fail"
          : nonProductionWithoutAuth.length > 0
            ? "warn"
            : "pass",
      apiRecords.length === 0
        ? "No managed API instances were visible in the sampled environments."
        : productionWithoutAuth.length > 0
          ? `${productionWithoutAuth.length}/${productionApis.length} production API instance(s) have no active authentication policy (client ID enforcement, JWT, OAuth, basic auth, SAML, or TLS).`
          : nonProductionWithoutAuth.length > 0
            ? `All ${productionApis.length} production API instance(s) enforce authentication, but ${nonProductionWithoutAuth.length} non-production instance(s) do not.`
            : `All ${apiRecords.length} sampled API instance(s) enforce an authentication policy.`,
      {
        apis_sampled: apiRecords.length,
        production_apis: productionApis.length,
        production_without_authentication: describeApis(productionWithoutAuth),
        non_production_without_authentication: describeApis(nonProductionWithoutAuth),
      },
    ),
    finding(
      8,
      apiRecords.length === 0
        ? "warn"
        : productionWithoutRateLimit.length > 0
          ? "fail"
          : nonProductionWithoutRateLimit.length > 0
            ? "warn"
            : "pass",
      apiRecords.length === 0
        ? "No managed API instances were visible in the sampled environments."
        : productionWithoutRateLimit.length > 0
          ? `${productionWithoutRateLimit.length}/${productionApis.length} production API instance(s) have no active rate limiting or spike control policy.`
          : nonProductionWithoutRateLimit.length > 0
            ? `All production API instances are rate limited, but ${nonProductionWithoutRateLimit.length} non-production instance(s) are not.`
            : `All ${apiRecords.length} sampled API instance(s) apply rate limiting or spike control.`,
      {
        apis_sampled: apiRecords.length,
        production_without_rate_limiting: describeApis(productionWithoutRateLimit),
        non_production_without_rate_limiting: describeApis(nonProductionWithoutRateLimit),
      },
    ),
    finding(
      9,
      "manual",
      `Anypoint Platform does not expose client secret rotation timestamps. Export the ${activeContracts} active contract(s) from API Manager > API instance > Contracts and the client applications from Exchange > My Applications, then confirm each client secret was reset within the rotation period.`,
      {
        active_contracts: activeContracts,
        apis_sampled: apiRecords.length,
      },
    ),
    finding(
      20,
      publicAssets.length > 0 ? "warn" : "manual",
      publicAssets.length > 0
        ? `${publicAssets.length}/${organizationAssets.length} Exchange asset(s) are published to the public portal; confirm each public asset passed governance review.`
        : `${organizationAssets.length} Exchange asset(s) inventoried. Exchange does not expose review approvals: export the API Governance conformance report and the publishing settings that require review before publication.`,
      {
        assets: organizationAssets.length,
        public_assets: sample(publicAssets.map((asset) => asString(asset.name) ?? asString(asset.assetId) ?? "asset")),
        status_counts: assetStatusCounts,
        type_counts: assetTypeCounts,
      },
    ),
  ];

  return {
    category: "api_gateway",
    title: "MuleSoft API gateway and Exchange posture",
    summary: {
      organization_id: config.organizationId,
      environments_sampled: environments.length,
      apis_sampled: apiRecords.length,
      production_apis: productionApis.length,
      production_without_authentication: productionWithoutAuth.length,
      production_without_rate_limiting: productionWithoutRateLimit.length,
      active_contracts: activeContracts,
      exchange_assets: organizationAssets.length,
      public_exchange_assets: publicAssets.length,
    },
    findings,
    snapshots: {
      api_manager_apis: redactSnapshot(apiRecords.map((record) => ({
        environment: environmentLabel(record.environment),
        environment_id: asString(record.environment.id),
        api: record.api,
        policies: record.policies,
      }))),
      exchange_assets: redactSnapshot(organizationAssets),
    },
    errors,
  };
}

function applicationLabel(application: JsonRecord): string {
  return asString(application.domain) ?? asString(application.name) ?? asString(application.id) ?? "application";
}

function muleVersion(application: JsonRecord): string | undefined {
  return asString(firstDefined(application, [["muleVersion", "version"], ["muleVersion"], ["runtimeVersion"]]));
}

function endOfSupportDate(application: JsonRecord): Date | undefined {
  return asDate(firstDefined(application, [["muleVersion", "endOfSupportDate"], ["muleVersion", "endOfLifeDate"]]));
}

function workerAmount(application: JsonRecord): number {
  return asNumber(getNestedValue(application, ["workers", "amount"])) ?? 1;
}

function workerWeight(application: JsonRecord): number | undefined {
  return asNumber(getNestedValue(application, ["workers", "type", "weight"]));
}

function workerCpu(application: JsonRecord): number | undefined {
  return asNumber(getNestedValue(application, ["workers", "recentStatistics", "cpu"]));
}

function usesPersistentQueues(application: JsonRecord): boolean {
  return asBoolean(application.persistentQueues) === true;
}

function persistentQueuesEncrypted(application: JsonRecord): boolean {
  return asBoolean(application.persistentQueuesEncrypted) === true
    || asBoolean(application.persistentQueuesEncryptionEnabled) === true;
}

function insecureSensitiveProperties(application: JsonRecord): string[] {
  const properties = asObject(application.properties) ?? {};
  const propertyOptions = asObject(application.propertiesOptions) ?? {};
  return Object.entries(properties)
    .filter(([key, value]) => {
      if (!SENSITIVE_PROPERTY_PATTERN.test(key)) return false;
      const secure = asBoolean(getNestedValue(propertyOptions, [key, "secure"])) === true;
      const masked = typeof value === "string" && /^\*+$/.test(value);
      return !secure && !masked;
    })
    .map(([key]) => key);
}

function cidrPrefixLength(cidr: string): number | undefined {
  const match = /\/(\d{1,3})$/.exec(cidr.trim());
  return match ? Number(match[1]) : undefined;
}

function isOpenCidr(cidr: string | undefined): boolean {
  return cidr === "0.0.0.0/0" || cidr === "::/0";
}

function ruleLabel(vpc: JsonRecord, rule: JsonRecord): string {
  const fromPort = asNumber(rule.fromPort);
  const toPort = asNumber(rule.toPort);
  const ports = fromPort === undefined ? "any" : fromPort === toPort || toPort === undefined ? String(fromPort) : `${fromPort}-${toPort}`;
  return `${asString(vpc.name) ?? asString(vpc.id) ?? "vpc"}: ${asString(rule.protocol) ?? "any"} ${ports} from ${asString(rule.cidrBlock) ?? "unknown"}`;
}

function ruleTargetsStandardPorts(rule: JsonRecord): boolean {
  const fromPort = asNumber(rule.fromPort);
  const toPort = asNumber(rule.toPort) ?? fromPort;
  if (fromPort === undefined || toPort === undefined) return false;
  for (let port = fromPort; port <= toPort; port += 1) {
    if (!CLOUDHUB_STANDARD_INGRESS_PORTS.has(port)) return false;
  }
  return true;
}

function isAllProtocolRule(rule: JsonRecord): boolean {
  const protocol = (asString(rule.protocol) ?? "").toLowerCase();
  return protocol === "all" || protocol === "-1" || protocol === "any";
}

function isWidePortRange(rule: JsonRecord): boolean {
  const fromPort = asNumber(rule.fromPort);
  const toPort = asNumber(rule.toPort);
  return fromPort !== undefined && toPort !== undefined && toPort - fromPort > 2;
}

function isBroadCidr(rule: JsonRecord): boolean {
  const cidr = asString(rule.cidrBlock);
  if (!cidr || isOpenCidr(cidr)) return false;
  const prefix = cidrPrefixLength(cidr);
  return prefix !== undefined && prefix < 16;
}

function loadBalancerLabel(loadBalancer: JsonRecord): string {
  return asString(loadBalancer.name) ?? asString(loadBalancer.domain) ?? asString(loadBalancer.id) ?? "load balancer";
}

function daysUntil(date: Date, now: number): number {
  return Math.floor((date.getTime() - now) / DAY_MS);
}

function serverLabel(server: JsonRecord): string {
  return asString(server.name) ?? asString(server.id) ?? "server";
}

function isServerRunning(server: JsonRecord): boolean {
  return /^(running|connected)$/i.test(asString(server.status) ?? "");
}

export async function assessMulesoftRuntimeInfrastructure(
  client: RuntimeClient,
  options: MulesoftRuntimeInfrastructureOptions = {},
): Promise<MulesoftAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const environmentLimit = clampNumber(options.environmentLimit, DEFAULT_ENVIRONMENT_LIMIT, 1, 100);
  const applicationLimit = clampNumber(options.applicationLimit, DEFAULT_APPLICATION_LIMIT, 1, 5000);
  const supportWarningDays = clampNumber(options.runtimeSupportWarningDays, DEFAULT_RUNTIME_SUPPORT_WARNING_DAYS, 0, 3650);
  const certificateWarningDays = clampNumber(options.certificateWarningDays, DEFAULT_CERTIFICATE_WARNING_DAYS, DEFAULT_CERTIFICATE_FAIL_DAYS, 3650);
  const now = Date.now();

  const environments = await loadEnvironments(client, environmentLimit, errors);
  const applications: Array<{ environment: JsonRecord; application: JsonRecord }> = [];
  const servers: Array<{ environment: JsonRecord; server: JsonRecord }> = [];
  const mqInventory: Array<{ environment: string; region: string; queues: JsonRecord[] }> = [];
  const mqClients: Array<{ environment: string; clients: JsonRecord[] }> = [];
  const secretGroupsByEnvironment: Array<{ environment: JsonRecord; secretGroups: JsonRecord[] }> = [];

  for (const environment of environments) {
    const environmentId = asString(environment.id);
    if (!environmentId) continue;
    const label = environmentLabel(environment);
    const environmentApplications = await collect(`cloudhub_applications:${label}`, [], () => client.listCloudhubApplications(environmentId), errors);
    for (const application of environmentApplications) {
      if (applications.length >= applicationLimit) break;
      applications.push({ environment, application });
    }
    const environmentServers = await collect(`hybrid_servers:${label}`, [], () => client.listHybridServers(environmentId), errors);
    servers.push(...environmentServers.map((server) => ({ environment, server })));

    const regions = await collect(`mq_regions:${label}`, [], () => client.listMqRegions(environmentId), errors);
    for (const region of regions) {
      const regionId = asString(region.regionId) ?? asString(region.id);
      if (!regionId) continue;
      const queues = await collect(`mq_queues:${label}:${regionId}`, [], () => client.listMqQueues(environmentId, regionId), errors);
      mqInventory.push({ environment: label, region: regionId, queues });
    }
    if (regions.length > 0) {
      const clients = await collect(`mq_clients:${label}`, [], () => client.listMqClients(environmentId), errors);
      mqClients.push({ environment: label, clients });
    }

    const secretGroups = await collect(`secret_groups:${label}`, [], () => client.listSecretGroups(environmentId), errors);
    secretGroupsByEnvironment.push({ environment, secretGroups });
  }

  const vpcSummaries = await collect("vpcs", [], () => client.listVpcs(), errors);
  const vpcs: JsonRecord[] = [];
  for (const vpc of vpcSummaries.slice(0, DEFAULT_VPC_LIMIT)) {
    const vpcId = asString(vpc.id);
    const detail = vpcId ? await collect(`vpc:${asString(vpc.name) ?? vpcId}`, vpc, () => client.getVpc(vpcId), errors) : vpc;
    vpcs.push({ ...vpc, ...detail });
  }

  const loadBalancers = (await collect("load_balancers", [], () => client.listLoadBalancers(), errors)).slice(0, DEFAULT_LOAD_BALANCER_LIMIT);
  const certificateProbes: Array<{ loadBalancer: JsonRecord; certificate?: MulesoftCertificateSummary; error?: string }> = [];
  for (const loadBalancer of loadBalancers) {
    const host = asString(loadBalancer.domain);
    if (!host) {
      certificateProbes.push({ loadBalancer, error: "Load balancer did not expose a domain to probe." });
      continue;
    }
    try {
      certificateProbes.push({ loadBalancer, certificate: await client.probeCertificate(host) });
    } catch (error) {
      const message = errorMessage(error);
      errors.push(`certificate_probe:${host}: ${message}`);
      certificateProbes.push({ loadBalancer, error: message });
    }
  }

  const applicationRecords = applications.map((item) => ({
    label: `${environmentLabel(item.environment)}: ${applicationLabel(item.application)}`,
    production: isProductionEnvironment(item.environment),
    application: item.application,
  }));
  const unsupportedRuntime = applicationRecords.filter((item) => {
    const version = muleVersion(item.application);
    const eos = endOfSupportDate(item.application);
    return (version !== undefined && /^3\./.test(version)) || (eos !== undefined && eos.getTime() < now);
  });
  const expiringRuntime = applicationRecords.filter((item) => {
    const eos = endOfSupportDate(item.application);
    return eos !== undefined && eos.getTime() >= now && daysUntil(eos, now) <= supportWarningDays && !unsupportedRuntime.includes(item);
  });
  const unknownRuntimeSupport = applicationRecords.filter((item) => endOfSupportDate(item.application) === undefined && !unsupportedRuntime.includes(item));

  const oversizedApplications = applicationRecords.filter((item) => {
    const amount = workerAmount(item.application);
    const weight = workerWeight(item.application);
    const cpu = workerCpu(item.application);
    if (!item.production && (amount > 1 || (weight !== undefined && weight >= 2))) return true;
    return amount >= 4 && cpu !== undefined && cpu < 10;
  });

  const persistentQueueApplications = applicationRecords.filter((item) => usesPersistentQueues(item.application));
  const unencryptedQueueApplications = persistentQueueApplications.filter((item) => !persistentQueuesEncrypted(item.application));

  const firewallRules = vpcs.flatMap((vpc) => asRecordArray(vpc.firewallRules).map((rule) => ({ vpc, rule })));
  const allProtocolRules = firewallRules.filter((item) => isAllProtocolRule(item.rule));
  const widePortRules = firewallRules.filter((item) => isWidePortRange(item.rule));
  const broadCidrRules = firewallRules.filter((item) => isBroadCidr(item.rule));
  const openRules = firewallRules.filter((item) => isOpenCidr(asString(item.rule.cidrBlock)));
  const openNonStandardRules = openRules.filter((item) => !ruleTargetsStandardPorts(item.rule) || isAllProtocolRule(item.rule));
  const openStandardRules = openRules.filter((item) => !openNonStandardRules.includes(item));

  const tls10LoadBalancers = loadBalancers.filter((item) => asBoolean(item.tlsv1) === true);
  const plainHttpLoadBalancers = loadBalancers.filter((item) => /^on$/i.test(asString(item.httpMode) ?? ""));

  const certificateResults = certificateProbes.map((probe) => {
    const validTo = probe.certificate?.validTo ? asDate(probe.certificate.validTo) : undefined;
    return {
      load_balancer: loadBalancerLabel(probe.loadBalancer),
      host: asString(probe.loadBalancer.domain) ?? null,
      subject: probe.certificate?.subject ?? null,
      issuer: probe.certificate?.issuer ?? null,
      valid_to: validTo ? validTo.toISOString() : null,
      days_remaining: validTo ? daysUntil(validTo, now) : null,
      error: probe.error ?? null,
    };
  });
  const expiringCertificates = certificateResults.filter((item) => item.days_remaining !== null && item.days_remaining <= DEFAULT_CERTIFICATE_FAIL_DAYS);
  const warningCertificates = certificateResults.filter((item) =>
    item.days_remaining !== null && item.days_remaining > DEFAULT_CERTIFICATE_FAIL_DAYS && item.days_remaining <= certificateWarningDays,
  );
  const probedCertificates = certificateResults.filter((item) => item.days_remaining !== null);

  const allQueues = mqInventory.flatMap((item) => item.queues.map((queue) => ({ environment: item.environment, region: item.region, queue })));
  const unencryptedQueues = allQueues.filter((item) => asBoolean(item.queue.encrypted) !== true);
  const totalMqClients = mqClients.reduce((total, item) => total + item.clients.length, 0);

  const productionSecretGroups = secretGroupsByEnvironment.filter((item) => isProductionEnvironment(item.environment));
  const productionWithoutSecretGroups = productionSecretGroups.filter((item) => item.secretGroups.length === 0);
  const totalSecretGroups = secretGroupsByEnvironment.reduce((total, item) => total + item.secretGroups.length, 0);
  const insecureProperties = applicationRecords
    .map((item) => ({ application: item.label, keys: insecureSensitiveProperties(item.application) }))
    .filter((item) => item.keys.length > 0);
  const applicationsWithPropertyData = applicationRecords.filter((item) => asObject(item.application.properties) !== undefined).length;

  const disconnectedServers = servers.filter((item) => !isServerRunning(item.server));
  const describeServers = (records: Array<{ environment: JsonRecord; server: JsonRecord }>) =>
    sample(records.map((item) => `${environmentLabel(item.environment)}: ${serverLabel(item.server)} (${asString(item.server.status) ?? "unknown"})`));

  const noVpcSummary = "No CloudHub VPCs are visible. If applications run in CloudHub 2.0 private spaces or Runtime Fabric, export the private space firewall rules or cluster network policy from Runtime Manager as evidence.";

  const findings: MulesoftFinding[] = [
    finding(
      10,
      applicationRecords.length === 0
        ? "pass"
        : unsupportedRuntime.length > 0
          ? "fail"
          : expiringRuntime.length > 0 || unknownRuntimeSupport.length > 0
            ? "warn"
            : "pass",
      applicationRecords.length === 0
        ? "No CloudHub applications were visible in the sampled environments."
        : unsupportedRuntime.length > 0
          ? `${unsupportedRuntime.length}/${applicationRecords.length} CloudHub application(s) run a Mule runtime that is past end of support or on Mule 3.`
          : expiringRuntime.length > 0
            ? `${expiringRuntime.length} CloudHub application(s) run a runtime reaching end of support within ${supportWarningDays} days.`
            : unknownRuntimeSupport.length > 0
              ? `${unknownRuntimeSupport.length} CloudHub application(s) did not expose an end of support date.`
              : `All ${applicationRecords.length} CloudHub application(s) run supported Mule runtime versions.`,
      {
        applications: applicationRecords.length,
        unsupported_runtime: sample(unsupportedRuntime.map((item) => `${item.label} (${muleVersion(item.application) ?? "unknown"})`)),
        expiring_runtime: sample(expiringRuntime.map((item) => `${item.label} (${muleVersion(item.application) ?? "unknown"})`)),
        unknown_support_dates: unknownRuntimeSupport.length,
        support_warning_days: supportWarningDays,
      },
    ),
    finding(
      11,
      oversizedApplications.length > 0 ? "warn" : "pass",
      applicationRecords.length === 0
        ? "No CloudHub applications were visible in the sampled environments."
        : oversizedApplications.length > 0
          ? `${oversizedApplications.length} CloudHub application(s) look over-provisioned (multiple or large workers in non-production, or four or more workers with low CPU).`
          : `${applicationRecords.length} CloudHub application(s) reviewed with no obvious over-provisioning.`,
      {
        applications: applicationRecords.length,
        oversized_applications: sample(oversizedApplications.map((item) =>
          `${item.label}: ${workerAmount(item.application)} x ${asString(getNestedValue(item.application, ["workers", "type", "name"])) ?? "worker"}`,
        )),
      },
    ),
    finding(
      12,
      unencryptedQueueApplications.length > 0 ? "fail" : "pass",
      persistentQueueApplications.length === 0
        ? "No CloudHub applications use persistent queues."
        : unencryptedQueueApplications.length > 0
          ? `${unencryptedQueueApplications.length}/${persistentQueueApplications.length} application(s) with persistent queues do not encrypt them.`
          : `All ${persistentQueueApplications.length} application(s) with persistent queues encrypt them.`,
      {
        persistent_queue_applications: persistentQueueApplications.length,
        unencrypted_queue_applications: sample(unencryptedQueueApplications.map((item) => item.label)),
      },
    ),
    finding(
      13,
      vpcs.length === 0
        ? "manual"
        : allProtocolRules.length > 0
          ? "fail"
          : widePortRules.length > 0 || broadCidrRules.length > 0
            ? "warn"
            : "pass",
      vpcs.length === 0
        ? noVpcSummary
        : allProtocolRules.length > 0
          ? `${allProtocolRules.length} VPC firewall rule(s) allow all protocols.`
          : widePortRules.length > 0 || broadCidrRules.length > 0
            ? `${widePortRules.length} firewall rule(s) span wide port ranges and ${broadCidrRules.length} allow CIDR blocks broader than /16.`
            : `${firewallRules.length} firewall rule(s) across ${vpcs.length} VPC(s) are limited to specific ports and networks.`,
      {
        vpcs: vpcs.length,
        firewall_rules: firewallRules.length,
        all_protocol_rules: sample(allProtocolRules.map((item) => ruleLabel(item.vpc, item.rule))),
        wide_port_rules: sample(widePortRules.map((item) => ruleLabel(item.vpc, item.rule))),
        broad_cidr_rules: sample(broadCidrRules.map((item) => ruleLabel(item.vpc, item.rule))),
      },
    ),
    finding(
      14,
      vpcs.length === 0
        ? "manual"
        : openNonStandardRules.length > 0
          ? "fail"
          : openStandardRules.length > 0
            ? "warn"
            : "pass",
      vpcs.length === 0
        ? noVpcSummary
        : openNonStandardRules.length > 0
          ? `${openNonStandardRules.length} VPC firewall rule(s) allow 0.0.0.0/0 ingress on ports other than the CloudHub HTTP listener ports.`
          : openStandardRules.length > 0
            ? `${openStandardRules.length} VPC firewall rule(s) allow 0.0.0.0/0 ingress on CloudHub HTTP listener ports; confirm the applications are intended to be internet-facing.`
            : `No VPC firewall rules allow 0.0.0.0/0 ingress.`,
      {
        vpcs: vpcs.length,
        open_non_standard_rules: sample(openNonStandardRules.map((item) => ruleLabel(item.vpc, item.rule))),
        open_standard_port_rules: sample(openStandardRules.map((item) => ruleLabel(item.vpc, item.rule))),
      },
    ),
    finding(
      15,
      loadBalancers.length === 0
        ? "pass"
        : tls10LoadBalancers.length > 0
          ? "fail"
          : plainHttpLoadBalancers.length > 0
            ? "warn"
            : "pass",
      loadBalancers.length === 0
        ? "No dedicated load balancers exist; control not applicable."
        : tls10LoadBalancers.length > 0
          ? `${tls10LoadBalancers.length}/${loadBalancers.length} dedicated load balancer(s) still accept TLS 1.0 and 1.1.`
          : plainHttpLoadBalancers.length > 0
            ? `${plainHttpLoadBalancers.length} dedicated load balancer(s) accept plain HTTP without redirecting to HTTPS.`
            : `All ${loadBalancers.length} dedicated load balancer(s) disable TLS 1.0 and 1.1; cipher suite selection is managed by Anypoint and should be confirmed in Runtime Manager.`,
      {
        load_balancers: loadBalancers.map((item) => ({
          name: loadBalancerLabel(item),
          http_mode: asString(item.httpMode) ?? null,
          tlsv1: asBoolean(item.tlsv1) ?? null,
          tlsv13: asBoolean(item.tlsv13) ?? null,
          state: asString(item.state) ?? null,
        })),
      },
    ),
    finding(
      16,
      loadBalancers.length === 0
        ? "pass"
        : expiringCertificates.length > 0
          ? "fail"
          : warningCertificates.length > 0
            ? "warn"
            : probedCertificates.length === 0
              ? "manual"
              : "pass",
      loadBalancers.length === 0
        ? "No dedicated load balancers exist; control not applicable."
        : expiringCertificates.length > 0
          ? `${expiringCertificates.length} dedicated load balancer certificate(s) are expired or expire within ${DEFAULT_CERTIFICATE_FAIL_DAYS} days.`
          : warningCertificates.length > 0
            ? `${warningCertificates.length} dedicated load balancer certificate(s) expire within ${certificateWarningDays} days.`
            : probedCertificates.length === 0
              ? "The load balancer certificates could not be probed over TLS. Open Runtime Manager > Load Balancers > certificates and record each certificate expiry date."
              : `All ${probedCertificates.length} probed dedicated load balancer certificate(s) remain valid for more than ${certificateWarningDays} days.`,
      {
        certificates: certificateResults,
        fail_days: DEFAULT_CERTIFICATE_FAIL_DAYS,
        warning_days: certificateWarningDays,
      },
    ),
    finding(
      21,
      mqInventory.length === 0
        ? "pass"
        : unencryptedQueues.length > 0
          ? "warn"
          : "manual",
      mqInventory.length === 0
        ? "Anypoint MQ is not in use in the sampled environments; control not applicable."
        : unencryptedQueues.length > 0
          ? `${unencryptedQueues.length}/${allQueues.length} Anypoint MQ queue(s) are not encrypted; MQ client apps are environment-scoped by design, so also confirm credentials are not shared across environments.`
          : `${allQueues.length} queue(s) and ${totalMqClients} MQ client app(s) inventoried per environment. Confirm MQ client app credentials are not reused across environments and MQ roles are environment-scoped in Access Management.`,
      {
        environments_with_mq: [...new Set(mqInventory.map((item) => item.environment))],
        queues: allQueues.length,
        unencrypted_queues: sample(unencryptedQueues.map((item) => `${item.environment}/${item.region}: ${asString(item.queue.queueId) ?? "queue"}`)),
        mq_clients: mqClients.map((item) => ({ environment: item.environment, clients: item.clients.length })),
      },
    ),
    finding(
      22,
      insecureProperties.length > 0
        ? "fail"
        : productionSecretGroups.length === 0 || productionWithoutSecretGroups.length > 0
          ? "warn"
          : "pass",
      insecureProperties.length > 0
        ? `${insecureProperties.length} CloudHub application(s) expose sensitive-looking properties that are not marked secure.`
        : productionSecretGroups.length === 0
          ? "No production environment was sampled, so Secrets Manager coverage could not be confirmed."
          : productionWithoutSecretGroups.length > 0
            ? `${productionWithoutSecretGroups.length} production environment(s) have no Secrets Manager secret groups.`
            : `All ${productionSecretGroups.length} production environment(s) have Secrets Manager secret groups and no insecure sensitive properties were visible.`,
      {
        secret_groups_by_environment: secretGroupsByEnvironment.map((item) => ({
          environment: environmentLabel(item.environment),
          production: isProductionEnvironment(item.environment),
          secret_groups: item.secretGroups.length,
        })),
        applications_with_property_data: applicationsWithPropertyData,
        insecure_property_keys: sample(insecureProperties.map((item) => `${item.application}: ${item.keys.join(", ")}`)),
      },
    ),
    finding(
      23,
      servers.length === 0
        ? "pass"
        : disconnectedServers.length === servers.length
          ? "fail"
          : disconnectedServers.length > 0
            ? "warn"
            : "pass",
      servers.length === 0
        ? "No hybrid runtime servers are registered in the sampled environments; control not applicable."
        : disconnectedServers.length === servers.length
          ? `All ${servers.length} hybrid runtime server(s) are disconnected or not reporting.`
          : disconnectedServers.length > 0
            ? `${disconnectedServers.length}/${servers.length} hybrid runtime server(s) are not in RUNNING state.`
            : `All ${servers.length} hybrid runtime server(s) are registered and reporting RUNNING.`,
      {
        servers: servers.length,
        disconnected_servers: describeServers(disconnectedServers),
        mule_versions: [...new Set(servers.map((item) => asString(item.server.muleVersion) ?? "unknown"))],
      },
    ),
  ];

  return {
    category: "runtime_infrastructure",
    title: "MuleSoft runtime and infrastructure posture",
    summary: {
      organization_id: config.organizationId,
      environments_sampled: environments.length,
      cloudhub_applications: applicationRecords.length,
      unsupported_runtime_applications: unsupportedRuntime.length,
      vpcs: vpcs.length,
      firewall_rules: firewallRules.length,
      load_balancers: loadBalancers.length,
      hybrid_servers: servers.length,
      mq_queues: allQueues.length,
      secret_groups: totalSecretGroups,
    },
    findings,
    snapshots: {
      cloudhub_applications: redactSnapshot(applications.map((item) => ({
        environment: environmentLabel(item.environment),
        environment_id: asString(item.environment.id),
        application: item.application,
      }))),
      vpcs: redactSnapshot(vpcs),
      load_balancers: redactSnapshot(loadBalancers),
      load_balancer_certificates: certificateResults,
      hybrid_servers: redactSnapshot(servers.map((item) => ({ environment: environmentLabel(item.environment), server: item.server }))),
      mq_queues: redactSnapshot(mqInventory),
      mq_clients: redactSnapshot(mqClients),
      secret_groups: redactSnapshot(secretGroupsByEnvironment.map((item) => ({
        environment: environmentLabel(item.environment),
        secret_groups: item.secretGroups,
      }))),
    },
    errors,
  };
}

function alertIsEnabled(alert: JsonRecord): boolean {
  return asBoolean(alert.enabled) !== false;
}

function alertResources(alert: JsonRecord): string[] {
  return asStringList(firstDefined(alert, [["condition", "resources"], ["resources"]]));
}

function alertCoversApplication(alert: JsonRecord, domain: string): boolean {
  const resources = alertResources(alert);
  if (resources.length === 0) return true;
  return resources.some((resource) => resource === "*" || resource.toLowerCase() === domain.toLowerCase());
}

function auditEntrySummary(entry: JsonRecord): JsonRecord {
  return {
    timestamp: asString(firstDefined(entry, [["timestamp"], ["time"], ["createdAt"]])) ?? null,
    platform: asString(firstDefined(entry, [["platform"], ["product"]])) ?? null,
    action: asString(firstDefined(entry, [["action"], ["actionType"], ["type"]])) ?? null,
    object_type: asString(firstDefined(entry, [["objectType"], ["objectTypes", "0"]])) ?? null,
  };
}

export async function assessMulesoftAuditMonitoring(
  client: AuditClient,
  options: MulesoftAuditMonitoringOptions = {},
): Promise<MulesoftAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const environmentLimit = clampNumber(options.environmentLimit, DEFAULT_ENVIRONMENT_LIMIT, 1, 100);
  const lookbackHours = clampNumber(options.auditLookbackHours, DEFAULT_AUDIT_LOOKBACK_HOURS, 1, 24 * 90);
  const now = Date.now();

  const platforms = await collect("audit_platforms", [], () => client.listAuditPlatforms(), errors);
  const startDate = new Date(now - lookbackHours * 60 * 60 * 1000).toISOString();
  const endDate = new Date(now).toISOString();
  let queryError: string | undefined;
  let recentEntries: JsonRecord[] = [];
  let fallbackEntries: JsonRecord[] = [];
  let recentTotal: number | undefined;
  try {
    const result = await client.queryAuditLogs({ startDate, endDate, limit: AUDIT_QUERY_PAGE_LIMIT });
    recentEntries = extractCollection(result);
    recentTotal = asNumber(result.total);
    if (recentEntries.length === 0) {
      const fallback = await client.queryAuditLogs({
        startDate: new Date(now - AUDIT_FALLBACK_LOOKBACK_DAYS * DAY_MS).toISOString(),
        endDate,
        limit: 1,
      });
      fallbackEntries = extractCollection(fallback);
    }
  } catch (error) {
    queryError = errorMessage(error);
    errors.push(`audit_query: ${queryError}`);
  }

  const environments = await loadEnvironments(client, environmentLimit, errors);
  const productionEnvironments = environments.filter(isProductionEnvironment);
  const alertCoverage: Array<{
    environment: string;
    cloudhubAlerts: JsonRecord[];
    hybridAlerts: JsonRecord[];
    applications: JsonRecord[];
    uncoveredApplications: string[];
  }> = [];
  for (const environment of productionEnvironments) {
    const environmentId = asString(environment.id);
    if (!environmentId) continue;
    const label = environmentLabel(environment);
    const cloudhubAlerts = await collect(`cloudhub_alerts:${label}`, [], () => client.listCloudhubAlerts(environmentId), errors);
    const hybridAlerts = await collect(`hybrid_alerts:${label}`, [], () => client.listHybridAlerts(environmentId), errors);
    const applications = await collect(`cloudhub_applications:${label}`, [], () => client.listCloudhubApplications(environmentId), errors);
    const enabledAlerts = [...cloudhubAlerts, ...hybridAlerts].filter(alertIsEnabled);
    const uncoveredApplications = applications
      .map(applicationLabel)
      .filter((domain) => !enabledAlerts.some((alert) => alertCoversApplication(alert, domain)));
    alertCoverage.push({ environment: label, cloudhubAlerts, hybridAlerts, applications, uncoveredApplications });
  }

  const environmentsWithoutAlerts = alertCoverage.filter((item) =>
    [...item.cloudhubAlerts, ...item.hybridAlerts].filter(alertIsEnabled).length === 0,
  );
  const uncoveredApplications = alertCoverage.flatMap((item) => item.uncoveredApplications.map((domain) => `${item.environment}: ${domain}`));
  const totalEnabledAlerts = alertCoverage.reduce(
    (total, item) => total + [...item.cloudhubAlerts, ...item.hybridAlerts].filter(alertIsEnabled).length,
    0,
  );

  const findings: MulesoftFinding[] = [
    finding(
      17,
      queryError
        ? "fail"
        : recentEntries.length > 0
          ? "pass"
          : fallbackEntries.length > 0
            ? "warn"
            : "fail",
      queryError
        ? `The audit log query failed: ${queryError}`
        : recentEntries.length > 0
          ? `${recentTotal ?? recentEntries.length} audit log entr${(recentTotal ?? recentEntries.length) === 1 ? "y" : "ies"} recorded within the last ${lookbackHours} hours across ${platforms.length} platform(s).`
          : fallbackEntries.length > 0
            ? `Audit logging is queryable but no entries were recorded in the last ${lookbackHours} hours; the most recent activity is older than that window.`
            : `Audit logging returned no entries in the last ${AUDIT_FALLBACK_LOOKBACK_DAYS} days.`,
      {
        lookback_hours: lookbackHours,
        entries_in_window: recentTotal ?? recentEntries.length,
        platforms: platforms.map((platform) => asString(platform.name) ?? asString(platform.label) ?? "platform"),
        recent_entries: sample(recentEntries.map(auditEntrySummary), 10),
      },
    ),
    finding(
      24,
      productionEnvironments.length === 0
        ? "warn"
        : environmentsWithoutAlerts.length > 0
          ? "fail"
          : uncoveredApplications.length > 0
            ? "warn"
            : "pass",
      productionEnvironments.length === 0
        ? "No production environment was sampled, so alert coverage could not be evaluated."
        : environmentsWithoutAlerts.length > 0
          ? `${environmentsWithoutAlerts.length} production environment(s) have no enabled CloudHub or Runtime Manager alerts.`
          : uncoveredApplications.length > 0
            ? `${uncoveredApplications.length} production application(s) are not covered by an enabled alert; Anypoint Monitoring advanced alerts must be exported manually.`
            : `${totalEnabledAlerts} enabled alert(s) cover all sampled production applications; export Anypoint Monitoring advanced alerts manually if they are relied upon.`,
      {
        production_environments: alertCoverage.map((item) => ({
          environment: item.environment,
          cloudhub_alerts: item.cloudhubAlerts.length,
          runtime_manager_alerts: item.hybridAlerts.length,
          applications: item.applications.length,
          uncovered_applications: sample(item.uncoveredApplications),
        })),
        environments_without_alerts: environmentsWithoutAlerts.map((item) => item.environment),
      },
    ),
  ];

  return {
    category: "audit_monitoring",
    title: "MuleSoft audit logging and monitoring posture",
    summary: {
      organization_id: config.organizationId,
      audit_platforms: platforms.length,
      audit_entries_in_window: recentTotal ?? recentEntries.length,
      audit_lookback_hours: lookbackHours,
      production_environments: productionEnvironments.length,
      enabled_alerts: totalEnabledAlerts,
      uncovered_production_applications: uncoveredApplications.length,
    },
    findings,
    snapshots: {
      audit_platforms: redactSnapshot(platforms),
      audit_log_recent: redactSnapshot(recentEntries),
      alerts: redactSnapshot(alertCoverage.map((item) => ({
        environment: item.environment,
        cloudhub_alerts: item.cloudhubAlerts,
        runtime_manager_alerts: item.hybridAlerts,
      }))),
    },
    errors,
  };
}

interface SurfaceDefinition {
  name: string;
  endpoint: string;
  permission: string;
  load: () => Promise<unknown>;
  count?: (value: unknown) => number | undefined;
}

function countItems(value: unknown): number | undefined {
  return Array.isArray(value) ? value.length : undefined;
}

async function probeSurface(definition: SurfaceDefinition): Promise<MulesoftAccessSurface> {
  try {
    const value = await definition.load();
    return {
      name: definition.name,
      endpoint: definition.endpoint,
      permission: definition.permission,
      status: "readable",
      count: definition.count?.(value),
    };
  } catch (error) {
    return {
      name: definition.name,
      endpoint: definition.endpoint,
      permission: definition.permission,
      status: "not_readable",
      httpStatus: error instanceof MulesoftApiError ? error.status : undefined,
      error: errorMessage(error),
    };
  }
}

function skippedSurface(name: string, endpoint: string, permission: string, reason: string): MulesoftAccessSurface {
  return { name, endpoint, permission, status: "skipped", error: reason };
}

export async function checkMulesoftAccess(client: AccessClient): Promise<MulesoftAccessCheckResult> {
  const config = client.getResolvedConfig();
  const orgPath = `/accounts/api/organizations/${config.organizationId}`;
  const errors: string[] = [];

  let currentUser: JsonRecord = {};
  const currentUserSurface = await probeSurface({
    name: "current_user",
    endpoint: "/accounts/api/me",
    permission: "Any authenticated principal (profile scope)",
    load: async () => {
      currentUser = await client.getCurrentUser();
      return currentUser;
    },
    count: () => 1,
  });
  const environments = await loadEnvironments(client, 1, errors);
  const environment = environments[0];
  const environmentId = environment ? asString(environment.id) : undefined;
  const environmentName = environment ? environmentLabel(environment) : undefined;

  const environmentSurface = (
    name: string,
    endpoint: string,
    permission: string,
    load: (id: string) => Promise<unknown>,
    count: (value: unknown) => number | undefined = countItems,
  ): Promise<MulesoftAccessSurface> => {
    if (!environmentId) {
      return Promise.resolve(skippedSurface(name, endpoint, permission, "No environment was readable to scope the probe."));
    }
    return probeSurface({ name, endpoint: endpoint.replace("{envId}", environmentId), permission, load: () => load(environmentId), count });
  };

  const surfaces: MulesoftAccessSurface[] = [
    currentUserSurface,
    await probeSurface({ name: "organization", endpoint: orgPath, permission: "Access Management: View Organization", load: () => client.getOrganization(), count: () => 1 }),
    await probeSurface({ name: "identity_providers", endpoint: `${orgPath}/identityProviders`, permission: "Access Management: Organization Administrator (identity provider settings)", load: () => client.listIdentityProviders(), count: countItems }),
    await probeSurface({ name: "members", endpoint: `${orgPath}/members`, permission: "Access Management: View Users", load: () => client.listMembers(100), count: countItems }),
    await probeSurface({ name: "mfa_exempt_users", endpoint: `${orgPath}/users?mfaVerificationExcluded=true`, permission: "Access Management: View Users", load: () => client.listMfaExemptUsers(100), count: countItems }),
    await probeSurface({ name: "role_groups", endpoint: `${orgPath}/rolegroups`, permission: "Access Management: View Role Groups", load: () => client.listRoleGroups(), count: countItems }),
    await probeSurface({ name: "environments", endpoint: `${orgPath}/environments`, permission: "Access Management: View Environment", load: () => client.listEnvironments(), count: countItems }),
    await probeSurface({ name: "connected_applications", endpoint: `${orgPath}/connectedApplications`, permission: "Access Management: View Connected Applications", load: () => client.listConnectedApplications(100), count: countItems }),
    await probeSurface({ name: "organization_hierarchy", endpoint: `${orgPath}/hierarchy`, permission: "Access Management: View Organization", load: () => client.getOrganizationHierarchy(), count: () => 1 }),
    await environmentSurface("api_manager_apis", `/apimanager/api/v1/organizations/${config.organizationId}/environments/{envId}/apis`, "API Manager: View APIs Configuration", (id) => client.listManagedApis(id, 50)),
    await probeSurface({ name: "exchange_assets", endpoint: "/exchange/api/v2/assets/search", permission: "Exchange: Exchange Viewer", load: () => client.listExchangeAssets(50), count: countItems }),
    await environmentSurface("cloudhub_applications", "/cloudhub/api/v2/applications (X-ANYPNT-ENV-ID {envId})", "Runtime Manager: Read Applications", (id) => client.listCloudhubApplications(id)),
    await environmentSurface("cloudhub_alerts", "/cloudhub/api/v2/alerts (X-ANYPNT-ENV-ID {envId})", "Runtime Manager: Read Alerts", (id) => client.listCloudhubAlerts(id)),
    await probeSurface({ name: "vpcs", endpoint: `/cloudhub/api/organizations/${config.organizationId}/vpcs`, permission: "CloudHub Network: CloudHub Network Viewer", load: () => client.listVpcs(), count: countItems }),
    await probeSurface({ name: "load_balancers", endpoint: `/cloudhub/api/organizations/${config.organizationId}/loadbalancers`, permission: "CloudHub Network: CloudHub Network Viewer", load: () => client.listLoadBalancers(), count: countItems }),
    await environmentSurface("hybrid_servers", "/hybrid/api/v1/servers (X-ANYPNT-ENV-ID {envId})", "Runtime Manager: Read Servers", (id) => client.listHybridServers(id)),
    await probeSurface({ name: "audit_platforms", endpoint: `/audit/v2/organizations/${config.organizationId}/platforms`, permission: "Audit Log: Audit Log Viewer", load: () => client.listAuditPlatforms(), count: countItems }),
    await probeSurface({
      name: "audit_query",
      endpoint: `/audit/v2/organizations/${config.organizationId}/query`,
      permission: "Audit Log: Audit Log Viewer",
      load: () => client.queryAuditLogs({ startDate: new Date(Date.now() - DAY_MS).toISOString(), limit: 1 }),
      count: (value) => extractCollection(value).length,
    }),
    await environmentSurface("mq_regions", `/mq/admin/api/v1/organizations/${config.organizationId}/environments/{envId}/regions`, "Anypoint MQ: MQ Viewer", (id) => client.listMqRegions(id)),
    await environmentSurface("secret_groups", `/secrets-manager/api/v1/organizations/${config.organizationId}/environments/{envId}/secretGroups`, "Secrets Manager: Read Secret Groups", (id) => client.listSecretGroups(id)),
  ];

  const readable = surfaces.filter((surface) => surface.status === "readable");
  const coreSurfaces = new Set(["current_user", "organization", "members", "role_groups", "environments"]);
  const coreReadable = surfaces.filter((surface) => coreSurfaces.has(surface.name) && surface.status === "readable").length;
  const status = coreReadable === coreSurfaces.size && readable.length >= Math.ceil(surfaces.length * 0.75) ? "healthy" : "limited";
  const missingPermissions = [...new Set(
    surfaces
      .filter((surface) => surface.status === "not_readable" && (surface.httpStatus === 401 || surface.httpStatus === 403))
      .map((surface) => surface.permission),
  )];

  const notes = [
    `Using Anypoint organization ${config.organizationId} on the ${config.controlPlane.toUpperCase()} control plane (${config.baseUrl}).`,
    `Authenticated via ${config.authMode.replace("_", " ")} as ${asString(getNestedValue(currentUser, ["user", "username"])) ?? asString(getNestedValue(currentUser, ["client", "name"])) ?? asString(getNestedValue(currentUser, ["user", "email"])) ?? "the current principal"}.`,
    environmentName
      ? `Environment-scoped probes used ${environmentName}${config.environmentFilter.length > 0 ? " (from the configured environment filter)" : ""}.`
      : "No environment was readable, so environment-scoped surfaces were skipped.",
    `${readable.length}/${surfaces.length} Anypoint audit surfaces are readable.`,
    ...errors.map((error) => `Note: ${error}`),
  ];

  return {
    status,
    organizationId: config.organizationId,
    controlPlane: config.controlPlane,
    baseUrl: config.baseUrl,
    authMode: config.authMode,
    surfaces,
    missingPermissions,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run mulesoft_assess_identity_access, mulesoft_assess_api_gateway, mulesoft_assess_runtime_infrastructure, mulesoft_assess_audit_monitoring, or mulesoft_export_audit_bundle."
        : missingPermissions.length > 0
          ? `Grant the connected app or user these read permissions and retry: ${missingPermissions.join("; ")}.`
          : "Confirm the organization ID, control plane, and credentials, then retry.",
  };
}

function formatAccessCheckText(result: MulesoftAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `MuleSoft access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    result.missingPermissions.length > 0 ? `Missing permissions: ${result.missingPermissions.join("; ")}` : "Missing permissions: none detected",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatSummaryValue(value: unknown): string {
  if (typeof value === "number") return String(Number(value.toFixed(2)));
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ") || "-";
  return String(value ?? "-");
}

function formatAssessmentText(result: MulesoftAssessmentResult): string {
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
  const errorLines = result.errors.length > 0
    ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)]
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

function statusCounts(findings: MulesoftFinding[]): Record<MulesoftFindingStatus, number> {
  const counts: Record<MulesoftFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function statusLabel(status: MulesoftFindingStatus): string {
  switch (status) {
    case "pass":
      return "Pass";
    case "warn":
      return "Warning";
    case "fail":
      return "Fail";
    case "manual":
      return "Manual";
    default: {
      const exhaustive: never = status;
      return String(exhaustive);
    }
  }
}

function severityRank(severity: MulesoftSeverity): number {
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
      return Number(exhaustive);
    }
  }
}

function frameworkMapping(findingItem: MulesoftFinding, framework: MulesoftFramework): string {
  const definition = CONTROL_CATALOG.find((item) => item.number === findingItem.control);
  return definition?.mappings[framework] ?? "-";
}

function buildExecutiveSummary(config: MulesoftResolvedConfig, assessments: MulesoftAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = statusCounts(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
    .slice(0, 10);

  const lines = [
    "# MuleSoft Anypoint Platform Audit Bundle",
    "",
    `Organization: ${config.organizationId}`,
    `Control plane: ${config.controlPlane.toUpperCase()} (${config.baseUrl})`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Passing controls: ${counts.pass}`,
    `- Manual controls: ${counts.manual}`,
    `- Total controls assessed: ${findings.length} of ${CONTROL_CATALOG.length}`,
    "",
    "## Assessment Areas",
    "",
    ...assessments.map((assessment) => {
      const areaCounts = statusCounts(assessment.findings);
      return `- ${assessment.title}: ${areaCounts.fail} fail, ${areaCounts.warn} warn, ${areaCounts.pass} pass, ${areaCounts.manual} manual`;
    }),
    "",
    "## Highest Priority Findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${statusLabel(item.status)}): ${item.summary}`)
      : ["- No failing or warning controls."]),
    "",
    "## Manual Evidence Required",
    "",
    ...(counts.manual > 0
      ? findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`)
      : ["- None."]),
  ];

  if (errors.length > 0) {
    lines.push("", "## Collection Errors", "", ...errors.map((error) => `- ${error}`));
  }

  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: MulesoftFinding[]): string {
  const headers = ["Finding", "Spec #", "Severity", "Status", "Title", ...FRAMEWORKS.map((framework) => FRAMEWORK_LABELS[framework])];
  const rows = [...findings]
    .sort((left, right) => left.control - right.control)
    .map((item) => [
      item.id,
      String(item.control),
      item.severity.toUpperCase(),
      statusLabel(item.status),
      item.title,
      ...FRAMEWORKS.map((framework) => frameworkMapping(item, framework)),
    ]);
  return [
    "# MuleSoft Unified Compliance Matrix",
    "",
    "Status semantics: Pass means the API evidence satisfied the control; Warning means partial or ambiguous evidence; Fail means the API evidence contradicts the control; Manual means the control cannot be verified through the Anypoint Platform API and the summary states what evidence to collect.",
    "",
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n") + "\n";
}

function buildFrameworkReport(framework: MulesoftFramework, findings: MulesoftFinding[]): string {
  const counts = statusCounts(findings);
  const rows = [...findings]
    .sort((left, right) => left.control - right.control)
    .map((item) => `| ${item.id} | ${frameworkMapping(item, framework)} | ${item.severity.toUpperCase()} | ${statusLabel(item.status)} | ${item.title} | ${item.summary.replace(/\|/g, "/")} |`);
  return [
    `# ${FRAMEWORK_REPORT_TITLES[framework]}`,
    "",
    `Framework: ${FRAMEWORK_LABELS[framework]}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    `Pass: ${counts.pass}, Warning: ${counts.warn}, Fail: ${counts.fail}, Manual: ${counts.manual}`,
    "",
    `| Finding | ${FRAMEWORK_LABELS[framework]} Requirement | Severity | Status | Control | Summary |`,
    "| --- | --- | --- | --- | --- | --- |",
    ...rows,
    "",
    "Manual findings require human-collected evidence before this framework mapping can be asserted as satisfied.",
  ].join("\n") + "\n";
}

function buildQuickReference(): string {
  return [
    "# MuleSoft Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw Anypoint Platform API responses used during this assessment, with secret-bearing fields redacted.",
    "- `analysis/findings.json` contains every normalized finding; `analysis/<category>.json` contains each assessment with its summary.",
    "- `analysis/summary.json` contains per-category status counts.",
    "- `compliance/` contains the executive summary, the unified matrix, and one report per framework (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, ISMAP).",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Manual findings state exactly what evidence a human must collect from Anypoint Platform.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n") + "\n";
}

export async function exportMulesoftAuditBundle(
  client: MulesoftBundleClient,
  config: MulesoftResolvedConfig,
  outputRoot: string,
  options: MulesoftAuditBundleOptions = {},
): Promise<MulesoftAuditBundleResult> {
  const access = await checkMulesoftAccess(client);
  const assessments = [
    await assessMulesoftIdentityAccess(client, options),
    await assessMulesoftApiGateway(client, options),
    await assessMulesoftRuntimeInfrastructure(client, options),
    await assessMulesoftAuditMonitoring(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors.map((error) => `[${assessment.category}] ${error}`));

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(config.organizationId)}-audit-bundle`);

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    organization_id: config.organizationId,
    control_plane: config.controlPlane,
    base_url: config.baseUrl,
    auth_mode: config.authMode,
    environment_filter: config.environmentFilter,
    source_chain: config.sourceChain,
    controls_assessed: findings.length,
    controls_in_catalog: CONTROL_CATALOG.length,
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, snapshot] of Object.entries(assessment.snapshots)) {
      await writeSecureTextFile(outputDir, `core_data/${name}.json`, serializeJson(snapshot));
    }
    const { snapshots: _snapshots, ...analysis } = assessment;
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(analysis));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    total: statusCounts(findings),
    categories: assessments.map((assessment) => ({
      category: assessment.category,
      title: assessment.title,
      counts: statusCounts(assessment.findings),
      summary: assessment.summary,
    })),
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${framework}/${framework}_compliance_report.md`, buildFrameworkReport(framework, findings));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${relative(realpathSync(outputRoot), outputDir)}.zip`);
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
    organization_id: asString(value.organization_id) ?? asString(value.org_id),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    username: asString(value.username),
    password: asString(value.password),
    token: asString(value.token),
    base_url: asString(value.base_url),
    control_plane: asString(value.control_plane),
    config_file: asString(value.config_file),
    environments: asStringList(value.environments ?? value.environment_ids).join(",") || undefined,
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityAccessArgs(args: unknown): IdentityAccessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    max_admins: asNumber(value.max_admins),
    max_roles_per_group: asNumber(value.max_roles_per_group),
    max_connected_app_scopes: asNumber(value.max_connected_app_scopes),
    stale_connected_app_days: asNumber(value.stale_connected_app_days),
  };
}

function normalizeApiGatewayArgs(args: unknown): ApiGatewayArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    environment_limit: asNumber(value.environment_limit),
    api_limit: asNumber(value.api_limit),
  };
}

function normalizeRuntimeInfrastructureArgs(args: unknown): RuntimeInfrastructureArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    environment_limit: asNumber(value.environment_limit),
    application_limit: asNumber(value.application_limit),
    runtime_support_warning_days: asNumber(value.runtime_support_warning_days),
    certificate_warning_days: asNumber(value.certificate_warning_days),
  };
}

function normalizeAuditMonitoringArgs(args: unknown): AuditMonitoringArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    environment_limit: asNumber(value.environment_limit),
    audit_lookback_hours: asNumber(value.audit_lookback_hours),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityAccessArgs(args),
    ...normalizeApiGatewayArgs(args),
    ...normalizeRuntimeInfrastructureArgs(args),
    ...normalizeAuditMonitoringArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toIdentityOptions(args: IdentityAccessArgs): MulesoftIdentityAccessOptions {
  return {
    userLimit: args.user_limit,
    maxAdmins: args.max_admins,
    maxRolesPerGroup: args.max_roles_per_group,
    maxConnectedAppScopes: args.max_connected_app_scopes,
    staleConnectedAppDays: args.stale_connected_app_days,
  };
}

function toApiGatewayOptions(args: ApiGatewayArgs): MulesoftApiGatewayOptions {
  return { environmentLimit: args.environment_limit, apiLimit: args.api_limit };
}

function toRuntimeOptions(args: RuntimeInfrastructureArgs): MulesoftRuntimeInfrastructureOptions {
  return {
    environmentLimit: args.environment_limit,
    applicationLimit: args.application_limit,
    runtimeSupportWarningDays: args.runtime_support_warning_days,
    certificateWarningDays: args.certificate_warning_days,
  };
}

function toAuditOptions(args: AuditMonitoringArgs): MulesoftAuditMonitoringOptions {
  return { environmentLimit: args.environment_limit, auditLookbackHours: args.audit_lookback_hours };
}

function createClient(args: CheckAccessArgs): MulesoftApiClient {
  return new MulesoftApiClient(resolveMulesoftConfiguration(args as JsonRecord));
}

const authParams = {
  organization_id: Type.Optional(Type.String({ description: "Anypoint Platform organization (business group) ID. Defaults to ANYPOINT_ORG_ID or org_id in config.toml." })),
  client_id: Type.Optional(Type.String({ description: "Connected app client ID for the client credentials grant. Defaults to ANYPOINT_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "Connected app client secret. Defaults to ANYPOINT_CLIENT_SECRET." })),
  username: Type.Optional(Type.String({ description: "Anypoint Platform username for password login when no connected app is available. Defaults to ANYPOINT_USERNAME." })),
  password: Type.Optional(Type.String({ description: "Anypoint Platform password. Defaults to ANYPOINT_PASSWORD." })),
  token: Type.Optional(Type.String({ description: "Pre-issued Anypoint bearer token. Defaults to ANYPOINT_TOKEN." })),
  base_url: Type.Optional(Type.String({ description: "Anypoint Platform base URL. Overrides control_plane. Defaults to ANYPOINT_BASE_URL or the control plane URL." })),
  control_plane: Type.Optional(Type.Union([Type.Literal("us"), Type.Literal("eu"), Type.Literal("gov")], { description: "Anypoint control plane: us (anypoint.mulesoft.com), eu (eu1.anypoint.mulesoft.com), or gov (gov.anypoint.mulesoft.com). Defaults to ANYPOINT_CONTROL_PLANE or us." })),
  config_file: Type.Optional(Type.String({ description: "TOML config file path. Defaults to ~/.config/mulesoft-sec-inspector/config.toml." })),
  environments: Type.Optional(Type.String({ description: "Comma-separated environment names or IDs to limit environment-scoped checks. Defaults to ANYPOINT_ENVIRONMENTS or all environments." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

const identityParams = {
  user_limit: Type.Optional(Type.Number({ description: "Maximum members and MFA-exempt users to inspect. Defaults to 1000.", default: 1000 })),
  max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Organization Administrators before failing control 3. Defaults to 5.", default: 5 })),
  max_roles_per_group: Type.Optional(Type.Number({ description: "Role assignments per role group before warning on control 4. Defaults to 15.", default: 15 })),
  max_connected_app_scopes: Type.Optional(Type.Number({ description: "Scopes per connected app before warning on control 18. Defaults to 10.", default: 10 })),
  stale_connected_app_days: Type.Optional(Type.Number({ description: "Days without use before a connected app is stale for control 19. Defaults to 90.", default: 90 })),
};

const apiGatewayParams = {
  environment_limit: Type.Optional(Type.Number({ description: "Maximum environments to sample, production first. Defaults to 10.", default: 10 })),
  api_limit: Type.Optional(Type.Number({ description: "Maximum API instances to inspect across environments. Defaults to 100.", default: 100 })),
};

const runtimeParams = {
  environment_limit: Type.Optional(Type.Number({ description: "Maximum environments to sample, production first. Defaults to 10.", default: 10 })),
  application_limit: Type.Optional(Type.Number({ description: "Maximum CloudHub applications to inspect. Defaults to 200.", default: 200 })),
  runtime_support_warning_days: Type.Optional(Type.Number({ description: "Days before Mule runtime end of support to warn. Defaults to 90.", default: 90 })),
  certificate_warning_days: Type.Optional(Type.Number({ description: "Days before load balancer certificate expiry to warn (expiry within 30 days always fails). Defaults to 60.", default: 60 })),
};

const auditParams = {
  environment_limit: Type.Optional(Type.Number({ description: "Maximum environments to sample for alert coverage. Defaults to 10.", default: 10 })),
  audit_lookback_hours: Type.Optional(Type.Number({ description: "Audit log lookback window in hours. Defaults to 24.", default: 24 })),
};

export function registerMulesoftTools(pi: any): void {
  pi.registerTool({
    name: "mulesoft_check_access",
    label: "Check MuleSoft Anypoint audit access",
    description:
      "Validate read-only Anypoint Platform access across Access Management, API Manager, Exchange, CloudHub, Runtime Manager, audit logs, Anypoint MQ, and Secrets Manager surfaces, and report missing connected app permissions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkMulesoftAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "mulesoft_check_access", ...result });
      } catch (error) {
        return errorResult(
          `MuleSoft access check failed: ${errorMessage(error)}`,
          { tool: "mulesoft_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "mulesoft_assess_identity_access",
    label: "Assess MuleSoft identity and access",
    description:
      "Assess Anypoint Platform identity and access posture: external identity providers, MFA exemptions, Organization Administrator count, role group least privilege and environment scoping, environment isolation, connected app scopes and staleness, and business group isolation (spec controls 1-6, 18, 19, 25).",
    parameters: Type.Object({ ...authParams, ...identityParams }),
    prepareArguments: normalizeIdentityAccessArgs,
    async execute(_toolCallId: string, args: IdentityAccessArgs) {
      try {
        const result = await assessMulesoftIdentityAccess(createClient(args), toIdentityOptions(args));
        return textResult(formatAssessmentText(result), { tool: "mulesoft_assess_identity_access", ...result });
      } catch (error) {
        return errorResult(
          `MuleSoft identity and access assessment failed: ${errorMessage(error)}`,
          { tool: "mulesoft_assess_identity_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "mulesoft_assess_api_gateway",
    label: "Assess MuleSoft API gateway policies",
    description:
      "Assess API Manager and Exchange posture: authentication policies on production APIs, rate limiting, client credential rotation evidence, and Exchange asset governance (spec controls 7-9, 20).",
    parameters: Type.Object({ ...authParams, ...apiGatewayParams }),
    prepareArguments: normalizeApiGatewayArgs,
    async execute(_toolCallId: string, args: ApiGatewayArgs) {
      try {
        const result = await assessMulesoftApiGateway(createClient(args), toApiGatewayOptions(args));
        return textResult(formatAssessmentText(result), { tool: "mulesoft_assess_api_gateway", ...result });
      } catch (error) {
        return errorResult(
          `MuleSoft API gateway assessment failed: ${errorMessage(error)}`,
          { tool: "mulesoft_assess_api_gateway" },
        );
      }
    },
  });

  pi.registerTool({
    name: "mulesoft_assess_runtime_infrastructure",
    label: "Assess MuleSoft runtime infrastructure",
    description:
      "Assess CloudHub, VPC, dedicated load balancer, hybrid server, Anypoint MQ, and Secrets Manager posture: supported runtimes, worker sizing, persistent queue encryption, firewall rules, open ingress, TLS versions, certificate expiry, MQ access, secret usage, and server health (spec controls 10-16, 21-23).",
    parameters: Type.Object({ ...authParams, ...runtimeParams }),
    prepareArguments: normalizeRuntimeInfrastructureArgs,
    async execute(_toolCallId: string, args: RuntimeInfrastructureArgs) {
      try {
        const result = await assessMulesoftRuntimeInfrastructure(createClient(args), toRuntimeOptions(args));
        return textResult(formatAssessmentText(result), { tool: "mulesoft_assess_runtime_infrastructure", ...result });
      } catch (error) {
        return errorResult(
          `MuleSoft runtime infrastructure assessment failed: ${errorMessage(error)}`,
          { tool: "mulesoft_assess_runtime_infrastructure" },
        );
      }
    },
  });

  pi.registerTool({
    name: "mulesoft_assess_audit_monitoring",
    label: "Assess MuleSoft audit logging and alerts",
    description:
      "Assess audit log availability through the Audit Log Query API and alert coverage for production applications through CloudHub and Runtime Manager alerts (spec controls 17, 24).",
    parameters: Type.Object({ ...authParams, ...auditParams }),
    prepareArguments: normalizeAuditMonitoringArgs,
    async execute(_toolCallId: string, args: AuditMonitoringArgs) {
      try {
        const result = await assessMulesoftAuditMonitoring(createClient(args), toAuditOptions(args));
        return textResult(formatAssessmentText(result), { tool: "mulesoft_assess_audit_monitoring", ...result });
      } catch (error) {
        return errorResult(
          `MuleSoft audit and monitoring assessment failed: ${errorMessage(error)}`,
          { tool: "mulesoft_assess_audit_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "mulesoft_export_audit_bundle",
    label: "Export MuleSoft audit bundle",
    description:
      "Export a MuleSoft Anypoint Platform audit package covering all 25 spec controls: raw API snapshots in core_data/, findings and category summaries in analysis/, executive summary, unified matrix, and per-framework reports in compliance/, a QUICK_REFERENCE.md, an _errors.log when collection partially fails, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...identityParams,
      ...apiGatewayParams,
      ...runtimeParams,
      ...auditParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveMulesoftConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportMulesoftAuditBundle(new MulesoftApiClient(config), config, outputRoot, {
          ...toIdentityOptions(args),
          ...toApiGatewayOptions(args),
          ...toRuntimeOptions(args),
          ...toAuditOptions(args),
        });
        return textResult(
          [
            "MuleSoft audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "mulesoft_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `MuleSoft audit bundle export failed: ${errorMessage(error)}`,
          { tool: "mulesoft_export_audit_bundle" },
        );
      }
    },
  });
}
