/**
 * GCP GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the gcp-sec-inspector spec.
 * Every endpoint, query parameter, and response field read here is traced to
 * the official REST reference listed in GCP_DOCS. The tools stay read-only.
 */
import { execFileSync } from "node:child_process";
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
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/gcp";
const DEFAULT_MAX_PROJECTS = 20;
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_MAX_KEYS = 200;
const DEFAULT_MAX_FINDINGS = 200;
const DEFAULT_MAX_ASSETS = 2000;
const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
const MAX_KMS_ROTATION_DAYS = 365;
const MIN_LOG_RETENTION_DAYS = 90;
const OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
const ADMIN_PORTS = [22, 3389];

/** Official reference pages backing each request and field read in this module. */
export const GCP_DOCS = {
  serviceAccountJwt: "https://developers.google.com/identity/protocols/oauth2/service-account#httprest",
  refreshToken: "https://developers.google.com/identity/protocols/oauth2/web-server#offline",
  adc: "https://cloud.google.com/docs/authentication/application-default-credentials#personal",
  organizationsGet: "https://cloud.google.com/resource-manager/reference/rest/v1/organizations/get",
  effectiveOrgPolicy: "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getEffectiveOrgPolicy",
  orgPolicyResource: "https://cloud.google.com/resource-manager/reference/rest/v1/Policy",
  searchAllResources: "https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllResources",
  searchAllIamPolicies: "https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies",
  iamPolicyQuery: "https://cloud.google.com/asset-inventory/docs/searching-iam-policies#how_to_construct_a_query",
  assetsList: "https://cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list",
  supportedAssetTypes: "https://cloud.google.com/asset-inventory/docs/supported-asset-types",
  serviceAccountsList: "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list",
  serviceAccountKeysList: "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list",
  loggingSettings: "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects/getSettings",
  sinksList: "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks/list",
  logBucketsList: "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/list",
  entriesList: "https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list",
  sccSources: "https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources/list",
  sccFindings: "https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list",
  bucketsList: "https://cloud.google.com/storage/docs/json_api/v1/buckets/list",
  bucketResource: "https://cloud.google.com/storage/docs/json_api/v1/buckets",
  cryptoKey: "https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKey",
  firewallsList: "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list",
  subnetworksAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/aggregatedList",
  routersAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/routers/aggregatedList",
  sslPoliciesAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/sslPolicies/aggregatedList",
  targetHttpsProxiesAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies/aggregatedList",
  backendServicesAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/backendServices/aggregatedList",
  disksAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList",
  instancesAggregatedList: "https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList",
  computeProjectsGet: "https://cloud.google.com/compute/docs/reference/rest/v1/projects/get",
  osLoginMetadata: "https://cloud.google.com/compute/docs/oslogin/set-up-oslogin",
  serialConsoleMetadata: "https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console",
  sslPolicyConcepts: "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts",
  managedZonesList: "https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list",
  apiKeysList: "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list",
  accessPoliciesList: "https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies/list",
  servicePerimetersList: "https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies.servicePerimeters/list",
  binaryAuthorizationPolicy: "https://cloud.google.com/binary-authorization/docs/reference/rest/v1/projects/getPolicy",
} as const;

/** Exact Cloud Asset Inventory IAM query used for public exposure (GCP_DOCS.iamPolicyQuery). */
export const PUBLIC_MEMBER_IAM_QUERY = "policy:(allUsers OR allAuthenticatedUsers)";

/** Spec compliance mapping table, keyed by spec control number. */
export const GCP_CONTROL_MAPPINGS: Record<number, { name: string; mappings: string[] }> = {
  1: { name: "Service Account Key Rotation", mappings: ["FedRAMP IA-5(1)", "CMMC IA.L2-3.5.10", "SOC 2 CC6.1", "CIS GCP 1.17", "PCI-DSS 8.3.9", "DISA STIG SRG-APP-000516", "IRAP ISM-1590", "ISMAP 8.1.1"] },
  2: { name: "Overprivileged IAM Roles", mappings: ["FedRAMP AC-6(1)", "CMMC AC.L2-3.1.5", "SOC 2 CC6.3", "CIS GCP 1.1-1.5", "PCI-DSS 7.2.1", "DISA STIG SRG-APP-000033", "IRAP ISM-1508", "ISMAP 7.1.1"] },
  3: { name: "Public Resource Exposure", mappings: ["FedRAMP AC-3", "FedRAMP SC-7", "CMMC AC.L2-3.1.3", "SOC 2 CC6.1", "CIS GCP 5.1", "CIS GCP 6.2", "PCI-DSS 1.3.1", "DISA STIG SRG-APP-000142", "IRAP ISM-1037", "ISMAP 1.3.1"] },
  4: { name: "VPC Firewall Rules", mappings: ["FedRAMP SC-7(5)", "CMMC SC.L2-3.13.5", "SOC 2 CC6.6", "CIS GCP 3.6-3.9", "PCI-DSS 1.3.2", "DISA STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP 1.3.2"] },
  5: { name: "Audit Logging Configuration", mappings: ["FedRAMP AU-2", "FedRAMP AU-3", "CMMC AU.L2-3.3.1", "SOC 2 CC7.2", "CIS GCP 2.1-2.4", "PCI-DSS 10.2.1", "DISA STIG SRG-APP-000089", "IRAP ISM-0580", "ISMAP 10.2.1"] },
  6: { name: "Organization Policy Constraints", mappings: ["FedRAMP CM-7", "CMMC CM.L2-3.4.7", "SOC 2 CC6.1", "CIS GCP 1.14-1.15", "PCI-DSS 2.2.1", "DISA STIG SRG-APP-000141", "IRAP ISM-1467", "ISMAP 2.2.1"] },
  7: { name: "KMS Key Rotation", mappings: ["FedRAMP SC-12(1)", "CMMC SC.L2-3.13.10", "SOC 2 CC6.1", "CIS GCP 1.18", "PCI-DSS 3.6.4", "DISA STIG SRG-APP-000514", "IRAP ISM-0457", "ISMAP 3.6.4"] },
  8: { name: "Binary Authorization", mappings: ["FedRAMP SI-7", "CMMC SI.L2-3.14.1", "SOC 2 CC7.1", "CIS GCP 6.13", "PCI-DSS 6.3.2", "DISA STIG SRG-APP-000131", "IRAP ISM-1657", "ISMAP 6.3.2"] },
  9: { name: "VPC Flow Logs", mappings: ["FedRAMP AU-12", "CMMC AU.L2-3.3.1", "SOC 2 CC7.2", "CIS GCP 3.1", "PCI-DSS 10.6.1", "DISA STIG SRG-APP-000089", "IRAP ISM-0580", "ISMAP 10.6.1"] },
  10: { name: "Cloud NAT Configuration", mappings: ["FedRAMP SC-7", "CMMC SC.L2-3.13.1", "SOC 2 CC6.6", "CIS GCP 3.10", "PCI-DSS 1.3.4", "DISA STIG SRG-APP-000142", "IRAP ISM-1037", "ISMAP 1.3.4"] },
  11: { name: "OS Login Enforcement", mappings: ["FedRAMP IA-2(1)", "CMMC IA.L2-3.5.3", "SOC 2 CC6.1", "CIS GCP 4.4", "PCI-DSS 8.3.1", "DISA STIG SRG-APP-000149", "IRAP ISM-1401", "ISMAP 8.3.1"] },
  12: { name: "Serial Port Disabled", mappings: ["FedRAMP CM-7", "CMMC CM.L2-3.4.7", "SOC 2 CC6.1", "CIS GCP 4.5", "PCI-DSS 2.2.2", "DISA STIG SRG-APP-000141", "IRAP ISM-1467", "ISMAP 2.2.2"] },
  13: { name: "Default Service Account Usage", mappings: ["FedRAMP AC-6(5)", "CMMC AC.L2-3.1.6", "SOC 2 CC6.3", "CIS GCP 1.6", "PCI-DSS 7.2.2", "DISA STIG SRG-APP-000340", "IRAP ISM-1508", "ISMAP 7.2.2"] },
  14: { name: "Cross-Project Access", mappings: ["FedRAMP AC-3", "CMMC AC.L2-3.1.3", "SOC 2 CC6.3", "CIS GCP 1.8", "PCI-DSS 7.2.1", "DISA STIG SRG-APP-000033", "IRAP ISM-1508", "ISMAP 7.2.1"] },
  15: { name: "Uniform Bucket-Level Access", mappings: ["FedRAMP AC-3", "CMMC AC.L2-3.1.2", "SOC 2 CC6.1", "CIS GCP 5.2", "PCI-DSS 7.2.1", "DISA STIG SRG-APP-000033", "IRAP ISM-0988", "ISMAP 7.2.1"] },
  16: { name: "Customer-Managed Encryption Keys", mappings: ["FedRAMP SC-28(1)", "CMMC SC.L2-3.13.16", "SOC 2 CC6.1", "CIS GCP 1.18", "PCI-DSS 3.4.1", "DISA STIG SRG-APP-000231", "IRAP ISM-0457", "ISMAP 3.4.1"] },
  17: { name: "DNS Security (DNSSEC)", mappings: ["FedRAMP SC-20", "CMMC SC.L2-3.13.15", "SOC 2 CC6.1", "CIS GCP 3.3", "DISA STIG SRG-APP-000516", "IRAP ISM-1590"] },
  18: { name: "Load Balancer SSL Policies", mappings: ["FedRAMP SC-8", "CMMC SC.L2-3.13.8", "SOC 2 CC6.1", "CIS GCP 3.11", "PCI-DSS 4.1.1", "DISA STIG SRG-APP-000014", "IRAP ISM-1139", "ISMAP 4.1.1"] },
  19: { name: "Cloud Armor WAF", mappings: ["FedRAMP SC-7(5)", "CMMC SC.L2-3.13.5", "SOC 2 CC6.6", "CIS GCP 3.12", "PCI-DSS 6.6", "DISA STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP 6.6"] },
  20: { name: "API Key Restrictions", mappings: ["FedRAMP AC-3", "CMMC AC.L2-3.1.2", "SOC 2 CC6.1", "CIS GCP 1.12-1.13", "PCI-DSS 7.2.1", "DISA STIG SRG-APP-000033", "IRAP ISM-0988", "ISMAP 7.2.1"] },
  21: { name: "VPC Service Controls", mappings: ["FedRAMP AC-4", "CMMC AC.L2-3.1.3", "SOC 2 CC6.6", "CIS GCP 3.14", "PCI-DSS 1.3.1", "DISA STIG SRG-APP-000038", "IRAP ISM-1037", "ISMAP 1.3.1"] },
  22: { name: "Private Google Access", mappings: ["FedRAMP SC-7", "CMMC SC.L2-3.13.1", "SOC 2 CC6.6", "CIS GCP 3.2", "PCI-DSS 1.3.4", "DISA STIG SRG-APP-000142", "IRAP ISM-1037", "ISMAP 1.3.4"] },
  23: { name: "Shielded VM Configuration", mappings: ["FedRAMP SI-7(1)", "CMMC SI.L2-3.14.1", "SOC 2 CC7.1", "CIS GCP 4.8-4.9", "PCI-DSS 2.2.1", "DISA STIG SRG-APP-000131", "IRAP ISM-1657", "ISMAP 2.2.1"] },
};

export const GCP_FRAMEWORKS: Array<{ slug: string; title: string; prefix: string }> = [
  { slug: "fedramp", title: "FedRAMP / NIST 800-53", prefix: "FedRAMP " },
  { slug: "cmmc", title: "CMMC 2.0 Level 2", prefix: "CMMC " },
  { slug: "soc2", title: "SOC 2 Trust Services Criteria", prefix: "SOC 2 " },
  { slug: "cis_gcp", title: "CIS Google Cloud Platform Benchmark", prefix: "CIS GCP " },
  { slug: "pci_dss", title: "PCI-DSS 4.0", prefix: "PCI-DSS " },
  { slug: "disa_stig", title: "DISA STIG SRG", prefix: "DISA STIG " },
  { slug: "irap", title: "IRAP / ISM", prefix: "IRAP " },
  { slug: "ismap", title: "ISMAP", prefix: "ISMAP " },
];

function controlMappings(...controls: number[]): string[] {
  return [...new Set(controls.flatMap((control) => GCP_CONTROL_MAPPINGS[control]?.mappings ?? []))];
}

export interface GcpServiceAccountCredentials {
  type: "service_account";
  clientEmail: string;
  privateKey: string;
  tokenUri: string;
  projectId?: string;
}

export interface GcpAuthorizedUserCredentials {
  type: "authorized_user";
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  tokenUri: string;
}

export type GcpFileCredentials = GcpServiceAccountCredentials | GcpAuthorizedUserCredentials;

export interface GcpResolvedConfig {
  organizationId?: string;
  projectId?: string;
  accessToken?: string;
  credentials?: GcpFileCredentials;
  credentialsPath?: string;
  sourceChain: string[];
}

export interface GcpAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface GcpAccessCheckResult {
  status: "healthy" | "limited";
  organizationId?: string;
  projectId?: string;
  surfaces: GcpAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type GcpFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface GcpFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: GcpFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  controls: number[];
}

export interface GcpAssessmentResult {
  title: string;
  category: string;
  summary: JsonRecord;
  findings: GcpFinding[];
  errors: string[];
  snapshot: JsonRecord;
}

export interface GcpAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface GcpListResult {
  items: JsonRecord[];
  truncated: boolean;
}

export interface GcpProjectInventory {
  projects: JsonRecord[];
  truncated: boolean;
}

type GcpCommandRunner = (command: string, args: string[]) => string | undefined;
type GcpFileReader = (pathname: string) => string | undefined;
type FetchImpl = typeof fetch;

type CheckAccessArgs = {
  organization_id?: string;
  project_id?: string;
  access_token?: string;
  credentials_file?: string;
};

type ScopedArgs = CheckAccessArgs & {
  max_projects?: number;
  project_limit?: number;
};

type IdentityArgs = ScopedArgs & {
  stale_days?: number;
  max_keys?: number;
};

type LoggingArgs = ScopedArgs & {
  max_findings?: number;
};

type OrgGuardrailArgs = ScopedArgs;

type InventoryArgs = ScopedArgs & {
  max_assets?: number;
};

type ExportAuditBundleArgs = IdentityArgs & LoggingArgs & InventoryArgs & {
  output_dir?: string;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asObjectArray(value: unknown): JsonRecord[] {
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

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return value;
  return undefined;
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isPermissionError(message: string): boolean {
  return /^(401|403)\b/.test(message);
}

function isApiDisabledError(message: string): boolean {
  return /SERVICE_DISABLED|has not been used in project|is not enabled|API not enabled/i.test(message);
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
  return normalized || "gcp";
}

function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  const record = asObject(value);
  if (!record) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    output[key] = /token|secret|private_key|privatekey|password|credential/i.test(key) ? "[REDACTED]" : redactSecrets(entry);
  }
  return output;
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
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    if (entry.isDirectory()) count += await countFilesRecursively(fullPath);
    else count += 1;
  }
  return count;
}

function defaultCommandRunner(command: string, args: string[]): string | undefined {
  try {
    const output = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: DEFAULT_COMMAND_TIMEOUT_MS,
    });
    const trimmed = output.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

function defaultFileReader(pathname: string): string | undefined {
  try {
    return existsSync(pathname) ? readFileSync(pathname, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Parses a Google credentials JSON file. Service account keys carry
 * type "service_account", client_email, private_key, and token_uri; ADC user
 * credentials carry type "authorized_user", client_id, client_secret, and
 * refresh_token (GCP_DOCS.serviceAccountJwt, GCP_DOCS.adc).
 */
export function parseGcpCredentialsJson(text: string): GcpFileCredentials {
  const parsed = asObject(JSON.parse(text));
  if (!parsed) throw new Error("Credentials file did not contain a JSON object.");
  const type = asString(parsed.type);
  switch (type) {
    case "service_account": {
      const clientEmail = asString(parsed.client_email);
      const privateKey = typeof parsed.private_key === "string" ? parsed.private_key : undefined;
      if (!clientEmail || !privateKey) {
        throw new Error("Service account credentials require client_email and private_key.");
      }
      return {
        type: "service_account",
        clientEmail,
        privateKey,
        tokenUri: asString(parsed.token_uri) ?? DEFAULT_TOKEN_URI,
        projectId: asString(parsed.project_id),
      };
    }
    case "authorized_user": {
      const clientId = asString(parsed.client_id);
      const clientSecret = asString(parsed.client_secret);
      const refreshToken = asString(parsed.refresh_token);
      if (!clientId || !clientSecret || !refreshToken) {
        throw new Error("Authorized user credentials require client_id, client_secret, and refresh_token.");
      }
      return { type: "authorized_user", clientId, clientSecret, refreshToken, tokenUri: DEFAULT_TOKEN_URI };
    }
    default:
      throw new Error(`Unsupported credentials type "${type ?? "unknown"}"; expected service_account or authorized_user.`);
  }
}

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Builds the RS256 JWT assertion for the service account flow
 * (GCP_DOCS.serviceAccountJwt): header {alg RS256, typ JWT}; claims iss,
 * scope, aud (token URI), iat, exp (at most one hour after iat).
 */
export function createGcpServiceAccountAssertion(
  credentials: GcpServiceAccountCredentials,
  now: Date = new Date(),
  scope: string = OAUTH_SCOPE,
): string {
  const issuedAt = Math.floor(now.getTime() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64Url(JSON.stringify({
    iss: credentials.clientEmail,
    scope,
    aud: credentials.tokenUri,
    iat: issuedAt,
    exp: issuedAt + 3600,
  }));
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${claims}`);
  const signature = signer.sign(credentials.privateKey);
  return `${header}.${claims}.${base64Url(signature)}`;
}

async function postTokenRequest(tokenUri: string, form: URLSearchParams, fetchImpl: FetchImpl): Promise<string> {
  const response = await fetchImpl(tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const text = await response.text().catch(() => "");
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText}${text ? `: ${text.slice(0, 160)}` : ""}`);
  }
  const payload = asObject(JSON.parse(text));
  const accessToken = asString(payload?.access_token);
  if (!accessToken) throw new Error("Token exchange response did not include access_token.");
  return accessToken;
}

/**
 * Exchanges file credentials for a bearer token. Service accounts use the
 * jwt-bearer grant (GCP_DOCS.serviceAccountJwt); authorized users use the
 * refresh_token grant (GCP_DOCS.refreshToken).
 */
export async function exchangeGcpCredentials(
  credentials: GcpFileCredentials,
  fetchImpl: FetchImpl = fetch,
  now: Date = new Date(),
): Promise<string> {
  switch (credentials.type) {
    case "service_account": {
      const form = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: createGcpServiceAccountAssertion(credentials, now),
      });
      return postTokenRequest(credentials.tokenUri, form, fetchImpl);
    }
    case "authorized_user": {
      const form = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        refresh_token: credentials.refreshToken,
      });
      return postTokenRequest(credentials.tokenUri, form, fetchImpl);
    }
    default: {
      const exhaustive: never = credentials;
      throw new Error(`Unsupported credentials ${String(exhaustive)}`);
    }
  }
}

/** Well-known ADC file location per GCP_DOCS.adc. */
export function defaultAdcPath(env: NodeJS.ProcessEnv = process.env): string {
  if (process.platform === "win32" && env.APPDATA) {
    return join(env.APPDATA, "gcloud", "application_default_credentials.json");
  }
  const configHome = asString(env.CLOUDSDK_CONFIG);
  return configHome
    ? join(configHome, "application_default_credentials.json")
    : join(homedir(), ".config", "gcloud", "application_default_credentials.json");
}

export function resolveGcpConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  commandRunner: GcpCommandRunner = defaultCommandRunner,
  fileReader: GcpFileReader = defaultFileReader,
): GcpResolvedConfig {
  const sourceChain: string[] = [];
  const organizationId = asString(input.organization_id) ?? asString(env.GCP_ORGANIZATION_ID) ?? asString(env.GCP_ORG_ID);
  if (organizationId) {
    sourceChain.push(asString(input.organization_id) ? "arguments-organization" : "environment-organization");
  }

  let credentials: GcpFileCredentials | undefined;
  let credentialsPath: string | undefined;
  const explicitToken = asString(input.access_token);
  const envToken = asString(env.GCP_ACCESS_TOKEN) ?? asString(env.GOOGLE_OAUTH_ACCESS_TOKEN) ?? asString(env.GOOGLE_ACCESS_TOKEN);
  let accessToken = explicitToken ?? envToken;
  if (explicitToken) sourceChain.push("arguments-access-token");
  else if (envToken) sourceChain.push("environment-access-token");

  if (!accessToken) {
    const candidates: Array<[string, string | undefined]> = [
      ["arguments-credentials-file", asString(input.credentials_file)],
      ["environment-credentials-file", asString(env.GCP_CREDENTIALS_FILE)],
      ["google-application-credentials", asString(env.GOOGLE_APPLICATION_CREDENTIALS)],
      ["application-default-credentials", defaultAdcPath(env)],
    ];
    for (const [source, candidate] of candidates) {
      if (!candidate) continue;
      const text = fileReader(candidate);
      if (!text) {
        if (source !== "application-default-credentials") {
          throw new Error(`Credentials file not readable: ${candidate}`);
        }
        continue;
      }
      credentials = parseGcpCredentialsJson(text);
      credentialsPath = candidate;
      sourceChain.push(source);
      break;
    }
  }

  if (!accessToken && !credentials) {
    accessToken = commandRunner("gcloud", ["auth", "print-access-token"]);
    if (accessToken) sourceChain.push("gcloud-access-token");
  }

  const projectId = asString(input.project_id)
    ?? asString(env.GCP_PROJECT_ID)
    ?? asString(env.GOOGLE_CLOUD_PROJECT)
    ?? asString(env.GCLOUD_PROJECT)
    ?? (credentials?.type === "service_account" ? credentials.projectId : undefined);
  if (projectId) {
    sourceChain.push(asString(input.project_id) ? "arguments-project" : "environment-project");
  }

  if (!accessToken && !credentials) {
    throw new Error(
      "Unable to resolve GCP credentials from arguments, GCP_ACCESS_TOKEN, GCP_CREDENTIALS_FILE, GOOGLE_APPLICATION_CREDENTIALS, the ADC file, or gcloud auth print-access-token.",
    );
  }
  if (!organizationId && !projectId) {
    throw new Error("Set organization_id (GCP_ORGANIZATION_ID or GCP_ORG_ID) or project_id to scope the GCP audit.");
  }

  return {
    organizationId,
    projectId,
    accessToken,
    credentials,
    credentialsPath,
    sourceChain: [...new Set(sourceChain)],
  };
}

function describeSourceChain(config: GcpResolvedConfig): string {
  if (config.organizationId) {
    return `GCP organization ${config.organizationId}${config.projectId ? ` with project hint ${config.projectId}` : ""}`;
  }
  return `GCP project ${config.projectId ?? "unknown"}`;
}

function inferRootScope(config: GcpResolvedConfig): string {
  if (config.organizationId) return `organizations/${config.organizationId}`;
  if (config.projectId) return `projects/${config.projectId}`;
  throw new Error("A GCP audit scope requires organizationId or projectId.");
}

function parseProjectId(resource: JsonRecord): string | undefined {
  const name = asString(resource.name);
  return (
    asString(resource.projectId)
    ?? (name?.includes("/projects/") ? name.split("/projects/").at(-1)?.split("/")[0] : undefined)
    ?? asString(resource.displayName)
    ?? name?.split("/").at(-1)
  );
}

function parsePolicyBindings(value: unknown): JsonRecord[] {
  const policy = asObject(value);
  return policy ? asObjectArray(policy.bindings) : [];
}

function isOwnerLikeRole(role?: string): boolean {
  return [
    "roles/owner",
    "roles/editor",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
  ].includes(role ?? "");
}

function isDefaultServiceAccount(member: string): boolean {
  return /compute@developer\.gserviceaccount\.com$/.test(member)
    || /appspot\.gserviceaccount\.com$/.test(member)
    || /cloudbuild\.gserviceaccount\.com$/.test(member);
}

function normalizeMember(member: unknown): string | undefined {
  return asString(member)?.toLowerCase();
}

/**
 * Reads the effective OrgPolicy shape (GCP_DOCS.orgPolicyResource): boolean
 * constraints expose booleanPolicy.enforced, list constraints expose
 * listPolicy.allowedValues, deniedValues, or allValues, and restoreDefault
 * resets the constraint to its default.
 */
function interpretOrgPolicyEnabled(policyResponse: JsonRecord | null | undefined): boolean {
  if (!policyResponse) return false;
  const policy = asObject(policyResponse.policy) ?? policyResponse;
  if (asObject(policy.restoreDefault)) return false;
  const booleanPolicy = asObject(policy.booleanPolicy);
  if (booleanPolicy) return booleanPolicy.enforced === true;
  const listPolicy = asObject(policy.listPolicy);
  if (!listPolicy) return false;
  return asArray(listPolicy.allowedValues).length > 0
    || asArray(listPolicy.deniedValues).length > 0
    || asString(listPolicy.allValues) === "DENY";
}

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<GcpAccessSurface> {
  try {
    const value = await load();
    return { name, service, status: "readable", count: countResolver?.(value) };
  } catch (error) {
    return { name, service, status: "not_readable", error: describeError(error) };
  }
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const text = query.toString();
  return text ? `?${text}` : "";
}

export class GcpAuditorClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private tokenPromise?: Promise<string>;

  constructor(
    private readonly config: GcpResolvedConfig,
    options: { fetchImpl?: FetchImpl; now?: () => Date } = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): GcpResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  async getAccessToken(): Promise<string> {
    if (this.config.accessToken) return this.config.accessToken;
    if (!this.config.credentials) throw new Error("No GCP access token or credentials file was resolved.");
    this.tokenPromise ??= exchangeGcpCredentials(this.config.credentials, this.fetchImpl, this.now());
    return this.tokenPromise;
  }

  private async requestJson(url: string, init: { method?: string; body?: unknown } = {}): Promise<JsonRecord> {
    const token = await this.getAccessToken();
    const response = await this.fetchImpl(url, {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`${response.status} ${response.statusText}${text ? `: ${text.slice(0, 200)}` : ""} (${url.split("?")[0]})`);
    }
    const text = await response.text();
    return text.trim().length > 0 ? (JSON.parse(text) as JsonRecord) : {};
  }

  private async paginate(
    buildUrl: (pageToken?: string) => string,
    collect: (response: JsonRecord) => JsonRecord[],
    limit: number,
  ): Promise<GcpListResult> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    let truncated = false;
    do {
      const response = await this.requestJson(buildUrl(pageToken));
      items.push(...collect(response));
      pageToken = asString(response.nextPageToken);
      if (pageToken && items.length >= limit) {
        truncated = true;
        break;
      }
    } while (pageToken);
    return { items, truncated };
  }

  /** GCP_DOCS.organizationsGet */
  async getOrganization(): Promise<JsonRecord | null> {
    if (!this.config.organizationId) return null;
    return this.requestJson(`https://cloudresourcemanager.googleapis.com/v1/organizations/${this.config.organizationId}`);
  }

  /**
   * GCP_DOCS.searchAllResources: GET {scope}:searchAllResources with query
   * parameters assetTypes, pageSize (capped at 500), and pageToken; results[]
   * carry name, assetType, project, displayName, and state.
   */
  async listProjectInventory(limit = DEFAULT_MAX_PROJECTS): Promise<GcpProjectInventory> {
    if (!this.config.organizationId) {
      return {
        projects: this.config.projectId ? [{ projectId: this.config.projectId, name: this.config.projectId }] : [],
        truncated: false,
      };
    }
    const scope = `organizations/${this.config.organizationId}`;
    const result = await this.paginate(
      (pageToken) => `https://cloudasset.googleapis.com/v1/${scope}:searchAllResources${buildQuery({
        assetTypes: "cloudresourcemanager.googleapis.com/Project",
        pageSize: Math.min(500, limit),
        pageToken,
      })}`,
      (response) => asObjectArray(response.results),
      limit,
    );
    return { projects: result.items.slice(0, limit), truncated: result.truncated || result.items.length > limit };
  }

  async listProjects(limit = DEFAULT_MAX_PROJECTS): Promise<JsonRecord[]> {
    return (await this.listProjectInventory(limit)).projects;
  }

  /**
   * GCP_DOCS.searchAllIamPolicies: GET {scope}:searchAllIamPolicies with
   * query, pageSize (capped at 500), and pageToken; results[] carry resource,
   * assetType, project, and policy.bindings[].
   */
  async searchAllIamPolicies(limit = 500, query?: string): Promise<GcpListResult> {
    const scope = inferRootScope(this.config);
    return this.paginate(
      (pageToken) => `https://cloudasset.googleapis.com/v1/${scope}:searchAllIamPolicies${buildQuery({
        query,
        pageSize: Math.min(500, limit),
        pageToken,
      })}`,
      (response) => asObjectArray(response.results),
      limit,
    );
  }

  /** GCP_DOCS.iamPolicyQuery: field query on policy principals with OR grouping. */
  async searchPublicIamBindings(limit = 500): Promise<GcpListResult> {
    return this.searchAllIamPolicies(limit, PUBLIC_MEMBER_IAM_QUERY);
  }

  /**
   * GCP_DOCS.assetsList: GET {parent}/assets with contentType=RESOURCE,
   * assetTypes, pageSize (max 1000), pageToken; assets[].resource.data holds
   * the resource in the owning service's REST schema.
   */
  async listAssets(assetType: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    const parent = inferRootScope(this.config);
    return this.paginate(
      (pageToken) => `https://cloudasset.googleapis.com/v1/${parent}/assets${buildQuery({
        contentType: "RESOURCE",
        assetTypes: assetType,
        pageSize: Math.min(1000, limit),
        pageToken,
      })}`,
      (response) => asObjectArray(response.assets).map((asset) => ({
        name: asset.name,
        assetType: asset.assetType,
        ...(asObject(asObject(asset.resource)?.data) ?? {}),
      })),
      limit,
    );
  }

  /** GCP_DOCS.cryptoKey via GCP_DOCS.assetsList (cloudkms.googleapis.com/CryptoKey). */
  async listCryptoKeys(limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAssets("cloudkms.googleapis.com/CryptoKey", limit);
  }

  /** GCP_DOCS.serviceAccountsList: pageSize max 100, response accounts[] and nextPageToken. */
  async listServiceAccounts(projectId: string): Promise<JsonRecord[]> {
    const result = await this.paginate(
      (pageToken) => `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.accounts),
      5000,
    );
    return result.items;
  }

  /** GCP_DOCS.serviceAccountKeysList: keyTypes filter, response keys[] with validAfterTime. */
  async listServiceAccountKeys(projectId: string, serviceAccountEmail: string): Promise<JsonRecord[]> {
    const encoded = encodeURIComponent(serviceAccountEmail);
    const response = await this.requestJson(
      `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${encoded}/keys?keyTypes=USER_MANAGED`,
    );
    return asObjectArray(response.keys);
  }

  /** GCP_DOCS.loggingSettings */
  async getLoggingSettings(projectId: string): Promise<JsonRecord> {
    return this.requestJson(`https://logging.googleapis.com/v2/projects/${projectId}/settings`);
  }

  /** GCP_DOCS.sinksList: response sinks[] and nextPageToken. */
  async listLogSinks(projectId: string): Promise<JsonRecord[]> {
    const result = await this.paginate(
      (pageToken) => `https://logging.googleapis.com/v2/projects/${projectId}/sinks${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.sinks),
      5000,
    );
    return result.items;
  }

  /** GCP_DOCS.logBucketsList: parent projects/{p}/locations/-; response buckets[] with retentionDays. */
  async listLogBuckets(projectId: string): Promise<JsonRecord[]> {
    const result = await this.paginate(
      (pageToken) => `https://logging.googleapis.com/v2/projects/${projectId}/locations/-/buckets${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.buckets),
      5000,
    );
    return result.items;
  }

  /** GCP_DOCS.entriesList: POST entries:list with resourceNames, filter, orderBy, pageSize; response entries[]. */
  private async listAuditEntries(projectId: string, logId: string): Promise<JsonRecord[]> {
    const response = await this.requestJson("https://logging.googleapis.com/v2/entries:list", {
      method: "POST",
      body: {
        resourceNames: [`projects/${projectId}`],
        filter: `logName="projects/${projectId}/logs/cloudaudit.googleapis.com%2F${logId}"`,
        orderBy: "timestamp desc",
        pageSize: 20,
      },
    });
    return asObjectArray(response.entries);
  }

  async listRecentAdminActivity(projectId: string): Promise<JsonRecord[]> {
    return this.listAuditEntries(projectId, "activity");
  }

  async listRecentDataAccess(projectId: string): Promise<JsonRecord[]> {
    return this.listAuditEntries(projectId, "data_access");
  }

  /** GCP_DOCS.sccSources: response sources[] and nextPageToken. */
  async listSccSources(): Promise<JsonRecord[]> {
    if (!this.config.organizationId) return [];
    const result = await this.paginate(
      (pageToken) => `https://securitycenter.googleapis.com/v1/organizations/${this.config.organizationId}/sources${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.sources),
      1000,
    );
    return result.items;
  }

  /** GCP_DOCS.sccFindings: response listFindingsResults[] and nextPageToken. */
  async listSccFindings(limit = DEFAULT_MAX_FINDINGS): Promise<GcpListResult> {
    if (!this.config.organizationId) return { items: [], truncated: false };
    return this.paginate(
      (pageToken) => `https://securitycenter.googleapis.com/v1/organizations/${this.config.organizationId}/sources/-/findings${buildQuery({
        pageSize: Math.min(1000, limit),
        pageToken,
      })}`,
      (response) => asObjectArray(response.listFindingsResults),
      limit,
    );
  }

  /** GCP_DOCS.effectiveOrgPolicy: POST projects/{p}:getEffectiveOrgPolicy with {constraint}. */
  async getEffectiveOrgPolicy(projectId: string, constraint: string): Promise<JsonRecord | null> {
    const response = await this.requestJson(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getEffectiveOrgPolicy`,
      { method: "POST", body: { constraint } },
    );
    return Object.keys(response).length > 0 ? response : null;
  }

  /** GCP_DOCS.bucketsList: GET storage/v1/b?project=&maxResults (max 1000)&pageToken; response items[] (GCP_DOCS.bucketResource). */
  async listStorageBuckets(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://storage.googleapis.com/storage/v1/b${buildQuery({ project: projectId, maxResults: Math.min(1000, limit), pageToken })}`,
      (response) => asObjectArray(response.items),
      limit,
    );
  }

  /** GCP_DOCS.firewallsList: maxResults 0..500; response items[]. */
  async listFirewalls(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/firewalls${buildQuery({ maxResults: 500, pageToken })}`,
      (response) => asObjectArray(response.items),
      limit,
    );
  }

  /**
   * Compute aggregatedList family (GCP_DOCS.*AggregatedList): maxResults 0..500,
   * response items is a map of scope -> {<collection>: [...], warning}.
   */
  private async listAggregated(projectId: string, collection: string, limit: number): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/${collection}${buildQuery({ maxResults: 500, pageToken })}`,
      (response) => Object.values(asObject(response.items) ?? {}).flatMap((scoped) => asObjectArray(asObject(scoped)?.[collection])),
      limit,
    );
  }

  async listSubnetworks(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "subnetworks", limit);
  }

  async listRouters(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "routers", limit);
  }

  async listSslPolicies(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "sslPolicies", limit);
  }

  async listTargetHttpsProxies(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "targetHttpsProxies", limit);
  }

  async listBackendServices(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "backendServices", limit);
  }

  async listDisks(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "disks", limit);
  }

  async listInstances(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.listAggregated(projectId, "instances", limit);
  }

  /** GCP_DOCS.computeProjectsGet: response commonInstanceMetadata.items[] {key, value}. */
  async getComputeProject(projectId: string): Promise<JsonRecord> {
    return this.requestJson(`https://compute.googleapis.com/compute/v1/projects/${projectId}`);
  }

  /** GCP_DOCS.managedZonesList: response managedZones[] and nextPageToken. */
  async listManagedZones(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones${buildQuery({ pageToken })}`,
      (response) => asObjectArray(response.managedZones),
      limit,
    );
  }

  /** GCP_DOCS.apiKeysList: parent projects/{p}/locations/global; response keys[] and nextPageToken. */
  async listApiKeys(projectId: string, limit = DEFAULT_MAX_ASSETS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://apikeys.googleapis.com/v2/projects/${projectId}/locations/global/keys${buildQuery({ pageToken })}`,
      (response) => asObjectArray(response.keys),
      limit,
    );
  }

  /** GCP_DOCS.accessPoliciesList: GET accessPolicies?parent=organizations/{org}; response accessPolicies[]. */
  async listAccessPolicies(): Promise<JsonRecord[]> {
    if (!this.config.organizationId) return [];
    const result = await this.paginate(
      (pageToken) => `https://accesscontextmanager.googleapis.com/v1/accessPolicies${buildQuery({ parent: `organizations/${this.config.organizationId}`, pageToken })}`,
      (response) => asObjectArray(response.accessPolicies),
      1000,
    );
    return result.items;
  }

  /** GCP_DOCS.servicePerimetersList: GET {accessPolicies/id}/servicePerimeters; response servicePerimeters[]. */
  async listServicePerimeters(accessPolicyName: string): Promise<JsonRecord[]> {
    const result = await this.paginate(
      (pageToken) => `https://accesscontextmanager.googleapis.com/v1/${accessPolicyName}/servicePerimeters${buildQuery({ pageToken })}`,
      (response) => asObjectArray(response.servicePerimeters),
      5000,
    );
    return result.items;
  }

  /** GCP_DOCS.binaryAuthorizationPolicy: GET projects/{p}/policy; response defaultAdmissionRule. */
  async getBinaryAuthorizationPolicy(projectId: string): Promise<JsonRecord> {
    return this.requestJson(`https://binaryauthorization.googleapis.com/v1/projects/${projectId}/policy`);
  }
}

interface Collected<T> {
  data: T;
  error?: string;
  truncated: boolean;
}

async function attempt<T>(load: () => Promise<T>, fallback: T): Promise<Collected<T>> {
  try {
    const data = await load();
    const list = asObject(data);
    const truncated = Boolean(list && Array.isArray(list.items) && list.truncated === true);
    return { data, truncated };
  } catch (error) {
    return { data: fallback, error: describeError(error), truncated: false };
  }
}

const EMPTY_LIST: GcpListResult = { items: [], truncated: false };

interface ProjectScanRow<T> {
  projectId: string;
  data: T;
}

interface ProjectScan<T> {
  rows: ProjectScanRow<T>[];
  denied: Array<{ projectId: string; error: string }>;
  apiDisabled: string[];
  truncated: boolean;
}

async function scanProjects<T>(
  projectIds: string[],
  load: (projectId: string) => Promise<T>,
): Promise<ProjectScan<T>> {
  const scan: ProjectScan<T> = { rows: [], denied: [], apiDisabled: [], truncated: false };
  for (const projectId of projectIds) {
    try {
      const data = await load(projectId);
      const list = asObject(data);
      if (list && list.truncated === true) scan.truncated = true;
      scan.rows.push({ projectId, data });
    } catch (error) {
      const message = describeError(error);
      if (isApiDisabledError(message)) scan.apiDisabled.push(projectId);
      else scan.denied.push({ projectId, error: message });
    }
  }
  return scan;
}

function flattenScan(scan: ProjectScan<GcpListResult>): Array<JsonRecord & { projectId: string }> {
  return scan.rows.flatMap((row) => row.data.items.map((item) => ({ ...item, projectId: row.projectId })));
}

interface VerdictInput {
  id: string;
  title: string;
  severity: GcpFinding["severity"];
  controls: number[];
  evidence: JsonRecord;
  total: number;
  violations: number;
  unknown?: number;
  violationStatus?: "fail" | "warn";
  inventoryError?: string;
  deniedProjects?: number;
  scannedProjects?: number;
  apiDisabledProjects?: number;
  truncated?: boolean;
  emptyVerdict: "pass" | "fail" | "manual";
  passSummary: string;
  failSummary: string;
  emptySummary: string;
  manualEvidence: string;
}

function partialNote(input: VerdictInput): string {
  const notes: string[] = [];
  if (input.deniedProjects) notes.push(`${input.deniedProjects} of ${input.scannedProjects ?? 0} projects denied`);
  if (input.apiDisabledProjects) notes.push(`${input.apiDisabledProjects} projects without the API enabled`);
  if (input.truncated) notes.push(`inventory truncated at ${input.total} items`);
  return notes.length > 0 ? ` Partial view: ${notes.join("; ")}.` : "";
}

function verdict(input: VerdictInput): GcpFinding {
  const mappings = controlMappings(...input.controls);
  const partial = partialNote(input);
  const isPartial = partial.length > 0;
  const allDenied = (input.deniedProjects ?? 0) > 0 && input.deniedProjects === input.scannedProjects;
  const allDisabled = (input.apiDisabledProjects ?? 0) > 0 && input.apiDisabledProjects === input.scannedProjects;
  const evidence = { ...input.evidence, seen: input.total, truncated: input.truncated ?? false, denied_projects: input.deniedProjects ?? 0 };
  const base = { id: input.id, title: input.title, severity: input.severity, mappings, controls: input.controls, evidence };

  if (input.inventoryError) {
    return {
      ...base,
      status: "manual",
      summary: `Manual: inventory unreadable (${input.inventoryError}). Collect manually: ${input.manualEvidence}`,
    };
  }
  if (input.scannedProjects === 0) {
    return {
      ...base,
      status: "manual",
      summary: `Manual: no projects were inventoried in the scope, so per-project evidence could not be collected. Collect manually: ${input.manualEvidence}`,
    };
  }
  if (input.total === 0 && (allDenied || allDisabled)) {
    return {
      ...base,
      status: "manual",
      summary: `Manual: ${allDenied ? "every sampled project denied the read" : "the API is not enabled in any sampled project"}.${partial} Collect manually: ${input.manualEvidence}`,
    };
  }
  if (input.total === 0) {
    switch (input.emptyVerdict) {
      case "pass":
        return isPartial
          ? { ...base, status: "warn", summary: `${input.emptySummary}${partial}` }
          : { ...base, status: "pass", summary: `${input.emptySummary} Emptiness is compliant by intent.` };
      case "fail":
        return { ...base, status: "fail", summary: `${input.emptySummary} Emptiness is treated as fail.${partial}` };
      case "manual":
        return { ...base, status: "manual", summary: `Manual: ${input.emptySummary} Emptiness is treated as manual.${partial} Collect manually: ${input.manualEvidence}` };
      default: {
        const exhaustive: never = input.emptyVerdict;
        throw new Error(`Unhandled empty verdict ${String(exhaustive)}`);
      }
    }
  }
  if (input.violations > 0) {
    return { ...base, status: input.violationStatus ?? "fail", summary: `${input.failSummary}${partial}` };
  }
  if ((input.unknown ?? 0) > 0) {
    return { ...base, status: "warn", summary: `${input.unknown} of ${input.total} items lacked the documented flag needed to confirm compliance.${partial}` };
  }
  if (isPartial) {
    return { ...base, status: "warn", summary: `${input.passSummary}${partial} A partial view cannot pass.` };
  }
  return { ...base, status: "pass", summary: input.passSummary };
}

function manualFinding(
  id: string,
  title: string,
  severity: GcpFinding["severity"],
  controls: number[],
  reason: string,
  manualEvidence: string,
  evidence: JsonRecord = {},
): GcpFinding {
  return {
    id,
    title,
    severity,
    status: "manual",
    summary: `Manual: ${reason} Collect manually: ${manualEvidence}`,
    evidence,
    mappings: controlMappings(...controls),
    controls,
  };
}

function summarizeProject(resource: JsonRecord): JsonRecord {
  return {
    projectId: parseProjectId(resource),
    name: asString(resource.displayName) ?? asString(resource.name),
    state: asString(resource.state),
  };
}

interface ProjectContext {
  projectIds: string[];
  truncated: boolean;
  error?: string;
}

async function loadProjectContext(
  client: Pick<GcpAuditorClient, "listProjectInventory">,
  maxProjects: number,
): Promise<ProjectContext> {
  const inventory = await attempt(() => client.listProjectInventory(maxProjects), { projects: [], truncated: false });
  const projectIds = inventory.data.projects
    .map((resource) => asString(summarizeProject(resource).projectId))
    .filter((value): value is string => Boolean(value));
  return { projectIds, truncated: inventory.data.truncated, error: inventory.error };
}

function collectErrors(...groups: Array<Array<{ projectId?: string; error: string } | string | undefined>>): string[] {
  const errors: string[] = [];
  for (const group of groups) {
    for (const entry of group) {
      if (!entry) continue;
      errors.push(typeof entry === "string" ? entry : `${entry.projectId ? `${entry.projectId}: ` : ""}${entry.error}`);
    }
  }
  return errors;
}

export async function checkGcpAccess(
  client: Pick<
    GcpAuditorClient,
    | "getResolvedConfig"
    | "getOrganization"
    | "listProjectInventory"
    | "searchAllIamPolicies"
    | "getLoggingSettings"
    | "listLogSinks"
    | "listSccSources"
    | "getEffectiveOrgPolicy"
    | "listFirewalls"
    | "listStorageBuckets"
    | "listCryptoKeys"
  >,
): Promise<GcpAccessCheckResult> {
  const config = client.getResolvedConfig();
  const inventory = await attempt(() => client.listProjectInventory(5), { projects: [], truncated: false });
  const projects = inventory.data.projects;
  const targetProject = parseProjectId(projects[0] ?? {}) ?? config.projectId;
  const requireProject = (): string => {
    if (!targetProject) throw new Error("No project available for the sample query.");
    return targetProject;
  };
  const surfaces = await Promise.all([
    surface("organization", "cloudresourcemanager", () => client.getOrganization(), () => (config.organizationId ? 1 : 0)),
    surface("projects", "cloudasset", async () => {
      if (inventory.error) throw new Error(inventory.error);
      return projects;
    }, (value) => (Array.isArray(value) ? value.length : undefined)),
    surface("iam_policies", "cloudasset", () => client.searchAllIamPolicies(20), (value) => asObject(value)?.items ? asArray(asObject(value)?.items).length : undefined),
    surface("logging_settings", "logging", () => client.getLoggingSettings(requireProject()), () => 1),
    surface("log_sinks", "logging", () => client.listLogSinks(requireProject()), (value) => (Array.isArray(value) ? value.length : undefined)),
    surface("security_command_center", "securitycenter", () => client.listSccSources(), (value) => (Array.isArray(value) ? value.length : undefined)),
    surface("org_policy", "cloudresourcemanager", () => client.getEffectiveOrgPolicy(requireProject(), "constraints/iam.disableServiceAccountKeyCreation"), () => 1),
    surface("compute_firewalls", "compute", () => client.listFirewalls(requireProject(), 500), (value) => asArray(asObject(value)?.items).length),
    surface("storage_buckets", "storage", () => client.listStorageBuckets(requireProject(), 1000), (value) => asArray(asObject(value)?.items).length),
    surface("kms_crypto_keys", "cloudasset", () => client.listCryptoKeys(100), (value) => asArray(asObject(value)?.items).length),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 7 ? "healthy" : "limited";
  const notes = [
    `Authenticated against ${describeSourceChain(config)}.`,
    `${readableCount}/${surfaces.length} GCP audit surfaces are readable.`,
    targetProject ? `Primary sampled project: ${targetProject}.` : "No project was available for sample queries.",
  ];

  return {
    status,
    organizationId: config.organizationId,
    projectId: targetProject ?? config.projectId,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run gcp_assess_identity, gcp_assess_logging_detection, gcp_assess_org_guardrails, gcp_assess_data_protection, gcp_assess_network_security, or gcp_export_audit_bundle."
        : "Grant roles/cloudasset.viewer, roles/iam.securityReviewer, roles/logging.viewer, roles/orgpolicy.policyViewer, roles/compute.viewer, roles/storage.admin (read), and roles/securitycenter.findingsViewer to the audit principal and enable the corresponding APIs.",
  };
}

export async function assessGcpIdentity(
  client: Pick<
    GcpAuditorClient,
    "getNow" | "listProjectInventory" | "listServiceAccounts" | "listServiceAccountKeys" | "searchAllIamPolicies"
  >,
  options: { maxProjects?: number; staleDays?: number; maxKeys?: number } = {},
): Promise<GcpAssessmentResult> {
  const now = client.getNow();
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const maxKeys = clampNumber(options.maxKeys, DEFAULT_MAX_KEYS, 1, 5000);

  const context = await loadProjectContext(client, maxProjects);
  const iamPolicies = await attempt(() => client.searchAllIamPolicies(500), EMPTY_LIST);
  const accountScan = await scanProjects(context.projectIds, (projectId) => client.listServiceAccounts(projectId));

  const staleKeys: JsonRecord[] = [];
  const undatedKeys: JsonRecord[] = [];
  const userManagedKeys: JsonRecord[] = [];
  const keyErrors: Array<{ projectId: string; error: string }> = [];
  let serviceAccountCount = 0;
  let keyInventoryTruncated = false;

  for (const row of accountScan.rows) {
    for (const serviceAccount of row.data) {
      serviceAccountCount += 1;
      const email = asString(serviceAccount.email);
      if (!email) continue;
      if (userManagedKeys.length >= maxKeys) {
        keyInventoryTruncated = true;
        break;
      }
      try {
        const keys = await client.listServiceAccountKeys(row.projectId, email);
        for (const key of keys) {
          const keyName = asString(key.name);
          const record = { projectId: row.projectId, serviceAccount: email, key: keyName, disabled: key.disabled === true };
          userManagedKeys.push(record);
          const ageDays = daysBetween(now, extractTimestamp(key.validAfterTime));
          if (ageDays === undefined) undatedKeys.push(record);
          else if (ageDays > staleDays) staleKeys.push({ ...record, ageDays: Number(ageDays.toFixed(1)) });
        }
      } catch (error) {
        keyErrors.push({ projectId: row.projectId, error: `${email}: ${describeError(error)}` });
      }
    }
  }

  const privilegedBindings: JsonRecord[] = [];
  const crossProjectBindings: JsonRecord[] = [];
  const privilegedDefaultServiceAccounts: JsonRecord[] = [];
  for (const result of iamPolicies.data.items) {
    const resource = asString(result.resource);
    const resourceProject = resource?.match(/projects\/([^/]+)/)?.[1];
    for (const binding of parsePolicyBindings(result.policy)) {
      const role = asString(binding.role);
      for (const rawMember of asArray(binding.members)) {
        const member = normalizeMember(rawMember);
        if (!member) continue;
        if (isOwnerLikeRole(role)) privilegedBindings.push({ resource, role, member });
        if (member.startsWith("serviceaccount:")) {
          const email = member.replace("serviceaccount:", "");
          const emailProject = email.split("@").at(1)?.split(".").at(0);
          if (resourceProject && emailProject && emailProject !== resourceProject && !isDefaultServiceAccount(email)) {
            crossProjectBindings.push({ resource, member, role });
          }
          if (isOwnerLikeRole(role) && isDefaultServiceAccount(email)) {
            privilegedDefaultServiceAccounts.push({ resource, member, role });
          }
        }
      }
    }
  }

  const policyBase = {
    total: iamPolicies.data.items.length,
    inventoryError: iamPolicies.error,
    truncated: iamPolicies.truncated || context.truncated,
    emptyVerdict: "manual" as const,
    emptySummary: "Cloud Asset Inventory returned no IAM policies for the scope; an org or project always carries at least one binding, so treat this as a denied or empty scope.",
    manualEvidence: "export the IAM policy bindings for the organization, folders, and projects and review privileged roles.",
  };
  const keyBase = {
    deniedProjects: accountScan.denied.length + keyErrors.length,
    scannedProjects: context.projectIds.length,
    truncated: context.truncated || keyInventoryTruncated,
  };

  const findings: GcpFinding[] = [
    verdict({
      ...policyBase,
      id: "GCP-IAM-01",
      title: "Privileged IAM bindings",
      severity: "high",
      controls: [2],
      evidence: { bindings: privilegedBindings.slice(0, 25), policies_scanned: iamPolicies.data.items.length },
      violations: privilegedBindings.length,
      passSummary: `No owner/editor-style bindings were found across ${iamPolicies.data.items.length} IAM policies.`,
      failSummary: `${privilegedBindings.length} owner/editor-style bindings were found across ${iamPolicies.data.items.length} IAM policies.`,
    }),
    serviceAccountCount === 0 && !context.error && accountScan.denied.length !== context.projectIds.length
      ? manualFinding(
          "GCP-IAM-02",
          "Service account key rotation",
          "high",
          [1],
          "no service accounts were listed in the sampled projects; every project with Compute or App Engine enabled has default service accounts, so an empty list usually means iam.serviceAccounts.list was not permitted.",
          "list service accounts and user-managed keys per project and verify key age.",
          { sampled_projects: context.projectIds.length, project_error: context.error ?? null },
        )
      : verdict({
          ...keyBase,
          id: "GCP-IAM-02",
          title: "Service account key rotation",
          severity: "high",
          controls: [1],
          evidence: { stale_keys: staleKeys.slice(0, 25), undated_keys: undatedKeys.slice(0, 25), service_accounts: serviceAccountCount },
          inventoryError: context.error,
          total: userManagedKeys.length,
          violations: staleKeys.length,
          unknown: undatedKeys.length,
          emptyVerdict: "pass",
          passSummary: `None of ${userManagedKeys.length} user-managed keys exceeded ${staleDays} days.`,
          failSummary: `${staleKeys.length} of ${userManagedKeys.length} user-managed service account keys exceed the ${staleDays}-day threshold.`,
          emptySummary: `No user-managed service account keys exist across ${serviceAccountCount} service accounts.`,
          manualEvidence: "list user-managed keys per service account and check validAfterTime.",
        }),
    verdict({
      ...keyBase,
      id: "GCP-IAM-03",
      title: "User-managed service account key minimization",
      severity: "medium",
      controls: [1],
      evidence: { user_managed_keys: userManagedKeys.slice(0, 25), service_accounts: serviceAccountCount },
      inventoryError: context.error,
      total: serviceAccountCount,
      violations: userManagedKeys.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `${serviceAccountCount} service accounts carry no user-managed keys.`,
      failSummary: `${userManagedKeys.length} user-managed service account keys are present across ${serviceAccountCount} service accounts; prefer Workload Identity Federation.`,
      emptySummary: "No service accounts were listed.",
      manualEvidence: "list service accounts per project and confirm no user-managed keys exist.",
    }),
    verdict({
      ...policyBase,
      id: "GCP-IAM-04",
      title: "Cross-project service account access",
      severity: "medium",
      controls: [14],
      evidence: { cross_project_bindings: crossProjectBindings.slice(0, 25) },
      violations: crossProjectBindings.length,
      violationStatus: "warn",
      passSummary: "No cross-project service account bindings were found in the IAM policy inventory.",
      failSummary: `${crossProjectBindings.length} cross-project service account bindings were found.`,
    }),
    verdict({
      ...policyBase,
      id: "GCP-IAM-05",
      title: "Default service account privilege",
      severity: "high",
      controls: [13],
      evidence: { privileged_default_service_accounts: privilegedDefaultServiceAccounts.slice(0, 25) },
      violations: privilegedDefaultServiceAccounts.length,
      passSummary: "No default service accounts hold owner/editor-style roles in the IAM policy inventory.",
      failSummary: `${privilegedDefaultServiceAccounts.length} default service accounts hold owner/editor-style roles.`,
    }),
  ];

  const errors = collectErrors([context.error, iamPolicies.error], accountScan.denied, keyErrors);
  return {
    title: "GCP identity posture",
    category: "identity",
    summary: {
      sampled_projects: context.projectIds.length,
      projects_truncated: context.truncated,
      iam_policies: iamPolicies.data.items.length,
      service_accounts: serviceAccountCount,
      privileged_bindings: privilegedBindings.length,
      stale_service_account_keys: staleKeys.length,
      undated_service_account_keys: undatedKeys.length,
      user_managed_service_account_keys: userManagedKeys.length,
      cross_project_service_accounts: crossProjectBindings.length,
      privileged_default_service_accounts: privilegedDefaultServiceAccounts.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: context.projectIds,
      iam_policies: iamPolicies.data.items,
      service_accounts: accountScan.rows.map((row) => ({ projectId: row.projectId, accounts: row.data.map((account) => asString(account.email)) })),
      user_managed_keys: userManagedKeys,
    },
  };
}

export async function assessGcpLoggingDetection(
  client: Pick<
    GcpAuditorClient,
    "listProjectInventory" | "getLoggingSettings" | "listLogSinks" | "listLogBuckets" | "listRecentAdminActivity" | "listRecentDataAccess" | "listSccSources" | "listSccFindings"
  >,
  options: { maxProjects?: number; maxFindings?: number } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const maxFindings = clampNumber(options.maxFindings, DEFAULT_MAX_FINDINGS, 1, 5000);
  const context = await loadProjectContext(client, maxProjects);

  const adminScan = await scanProjects(context.projectIds, (projectId) => client.listRecentAdminActivity(projectId));
  const dataAccessScan = await scanProjects(context.projectIds, (projectId) => client.listRecentDataAccess(projectId));
  const sinkScan = await scanProjects(context.projectIds, (projectId) => client.listLogSinks(projectId));
  const bucketScan = await scanProjects(context.projectIds, (projectId) => client.listLogBuckets(projectId));
  const settingsScan = await scanProjects(context.projectIds, (projectId) => client.getLoggingSettings(projectId));
  const sccSources = await attempt(() => client.listSccSources(), [] as JsonRecord[]);
  const sccFindings = await attempt(() => client.listSccFindings(maxFindings), EMPTY_LIST);

  const projectsWithoutAdmin = adminScan.rows.filter((row) => row.data.length === 0).map((row) => row.projectId);
  const projectsWithoutDataAccess = dataAccessScan.rows.filter((row) => row.data.length === 0).map((row) => row.projectId);
  const projectsWithoutSinks = sinkScan.rows.filter((row) => row.data.length === 0).map((row) => row.projectId);

  const shortRetention: JsonRecord[] = [];
  const unknownRetention: JsonRecord[] = [];
  let bucketCount = 0;
  for (const row of bucketScan.rows) {
    for (const bucket of row.data) {
      const name = asString(bucket.name) ?? "";
      if (name.endsWith("/buckets/_Required")) continue;
      bucketCount += 1;
      const retention = asNumber(bucket.retentionDays);
      if (retention === undefined) unknownRetention.push({ projectId: row.projectId, bucket: name });
      else if (retention < MIN_LOG_RETENTION_DAYS) shortRetention.push({ projectId: row.projectId, bucket: name, retentionDays: retention });
    }
  }

  const scanBase = (scan: ProjectScan<unknown>) => ({
    inventoryError: context.error,
    deniedProjects: scan.denied.length,
    scannedProjects: context.projectIds.length,
    apiDisabledProjects: scan.apiDisabled.length,
    truncated: context.truncated,
  });

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(adminScan),
      id: "GCP-LOG-01",
      title: "Admin Activity visibility",
      severity: "medium",
      controls: [5],
      evidence: { projects_without_admin_activity: projectsWithoutAdmin.slice(0, 25), projects_read: adminScan.rows.length },
      total: adminScan.rows.length,
      violations: projectsWithoutAdmin.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `Recent Admin Activity audit entries were readable in all ${adminScan.rows.length} sampled projects.`,
      failSummary: `${projectsWithoutAdmin.length} of ${adminScan.rows.length} sampled projects returned no recent Admin Activity entries.`,
      emptySummary: "No projects were available for Admin Activity sampling.",
      manualEvidence: "query cloudaudit.googleapis.com/activity entries per project in Logs Explorer.",
    }),
    verdict({
      ...scanBase(dataAccessScan),
      id: "GCP-LOG-02",
      title: "Data Access logging coverage",
      severity: "high",
      controls: [5],
      evidence: { projects_without_data_access: projectsWithoutDataAccess.slice(0, 25), projects_read: dataAccessScan.rows.length },
      total: dataAccessScan.rows.length,
      violations: projectsWithoutDataAccess.length,
      emptyVerdict: "manual",
      passSummary: `Recent Data Access audit entries were readable in all ${dataAccessScan.rows.length} sampled projects.`,
      failSummary: `${projectsWithoutDataAccess.length} of ${dataAccessScan.rows.length} sampled projects returned no recent Data Access entries; Data Access logs are opt-in per service.`,
      emptySummary: "No projects were available for Data Access sampling.",
      manualEvidence: "review the IAM audit config (auditConfigs) on each project for DATA_READ and DATA_WRITE log types.",
    }),
    verdict({
      ...scanBase(sinkScan),
      id: "GCP-LOG-03",
      title: "Log sink coverage",
      severity: "high",
      controls: [5],
      evidence: { projects_without_sinks: projectsWithoutSinks.slice(0, 25), projects_read: sinkScan.rows.length },
      total: sinkScan.rows.length,
      violations: projectsWithoutSinks.length,
      emptyVerdict: "manual",
      passSummary: `Every one of ${sinkScan.rows.length} sampled projects has at least one log sink.`,
      failSummary: `${projectsWithoutSinks.length} of ${sinkScan.rows.length} sampled projects have no configured log sink.`,
      emptySummary: "No projects were available for log sink sampling.",
      manualEvidence: "list log sinks per project and at the organization level.",
    }),
    verdict({
      ...scanBase(bucketScan),
      id: "GCP-LOG-04",
      title: "Log bucket retention",
      severity: "medium",
      controls: [5],
      evidence: { short_retention_buckets: shortRetention.slice(0, 25), unknown_retention_buckets: unknownRetention.slice(0, 25), buckets_read: bucketCount },
      total: bucketCount,
      violations: shortRetention.length,
      unknown: unknownRetention.length,
      emptyVerdict: "manual",
      passSummary: `All ${bucketCount} configurable log buckets retain logs for at least ${MIN_LOG_RETENTION_DAYS} days (the fixed 400-day _Required bucket is excluded).`,
      failSummary: `${shortRetention.length} of ${bucketCount} configurable log buckets retain logs for fewer than ${MIN_LOG_RETENTION_DAYS} days (the fixed 400-day _Required bucket is excluded).`,
      emptySummary: "No configurable log buckets were listed; every project exposes a _Default bucket, so an empty list indicates a denied read.",
      manualEvidence: "read retentionDays on each project's _Default and custom log buckets.",
    }),
    sccSources.error
      ? manualFinding(
          "GCP-LOG-05",
          "Security Command Center visibility",
          "info",
          [5],
          `Security Command Center sources were not readable (${sccSources.error}). This finding is visibility only and does not score a control.`,
          "confirm Security Command Center tier and export findings from the console.",
          { scc_findings: sccFindings.data.items.length },
        )
      : {
          id: "GCP-LOG-05",
          title: "Security Command Center visibility",
          severity: "info",
          status: sccSources.data.length > 0 && !context.truncated ? "pass" : "warn",
          summary: sccSources.data.length > 0
            ? `Security Command Center returned ${sccSources.data.length} sources and ${sccFindings.data.items.length}${sccFindings.truncated ? "+" : ""} findings. Visibility only; findings are not scored as controls.`
            : "Security Command Center returned no sources for the scope; verify the tier or organization scope. Visibility only.",
          evidence: { scc_sources: sccSources.data.length, scc_findings: sccFindings.data.items.length, findings_truncated: sccFindings.truncated, findings_error: sccFindings.error ?? null },
          mappings: controlMappings(5),
          controls: [5],
        },
  ];

  const errors = collectErrors(
    [context.error, sccSources.error, sccFindings.error],
    adminScan.denied,
    dataAccessScan.denied,
    sinkScan.denied,
    bucketScan.denied,
    settingsScan.denied,
  );
  return {
    title: "GCP logging and detection posture",
    category: "logging-detection",
    summary: {
      sampled_projects: context.projectIds.length,
      projects_truncated: context.truncated,
      projects_with_admin_activity: adminScan.rows.length - projectsWithoutAdmin.length,
      projects_with_data_access: dataAccessScan.rows.length - projectsWithoutDataAccess.length,
      projects_with_log_sinks: sinkScan.rows.length - projectsWithoutSinks.length,
      configurable_log_buckets: bucketCount,
      short_retention_buckets: shortRetention.length,
      scc_sources: sccSources.data.length,
      scc_findings: sccFindings.data.items.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: context.projectIds,
      logging_settings: settingsScan.rows,
      sinks: sinkScan.rows,
      log_buckets: bucketScan.rows,
      scc_sources: sccSources.data,
    },
  };
}

function metadataValue(metadata: unknown, key: string): string | undefined {
  for (const item of asObjectArray(asObject(metadata)?.items)) {
    if (asString(item.key) === key) return asString(item.value);
  }
  return undefined;
}

function isTruthyMetadata(value: string | undefined): boolean {
  return value !== undefined && /^(true|1)$/i.test(value);
}

function orgPolicyFinding(
  id: string,
  title: string,
  severity: GcpFinding["severity"],
  controls: number[],
  policy: Collected<JsonRecord | null>,
  passSummary: string,
  failSummary: string,
  failStatus: "fail" | "warn",
  manualEvidence: string,
  partial: boolean,
): GcpFinding {
  if (policy.error) {
    return manualFinding(id, title, severity, controls, `the effective org policy was not readable (${policy.error}).`, manualEvidence, { policy: null });
  }
  const enabled = interpretOrgPolicyEnabled(policy.data);
  return {
    id,
    title,
    severity,
    status: enabled ? (partial ? "warn" : "pass") : failStatus,
    summary: enabled
      ? `${passSummary}${partial ? " Partial view: the project inventory was truncated, so other projects may resolve a different effective policy." : ""}`
      : failSummary,
    evidence: { policy: policy.data ?? null, partial },
    mappings: controlMappings(...controls),
    controls,
  };
}

export async function assessGcpOrgGuardrails(
  client: Pick<
    GcpAuditorClient,
    "getResolvedConfig" | "getOrganization" | "listProjectInventory" | "getEffectiveOrgPolicy" | "getComputeProject" | "listInstances" | "getBinaryAuthorizationPolicy"
  >,
  options: { maxProjects?: number; maxAssets?: number } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const maxAssets = clampNumber(options.maxAssets, DEFAULT_MAX_ASSETS, 1, 50_000);
  const config = client.getResolvedConfig();
  const organization = await attempt(() => client.getOrganization(), null as JsonRecord | null);
  const context = await loadProjectContext(client, maxProjects);
  const targetProjectId = context.projectIds[0] ?? config.projectId;

  const readPolicy = (constraint: string): Promise<Collected<JsonRecord | null>> =>
    targetProjectId
      ? attempt(() => client.getEffectiveOrgPolicy(targetProjectId, constraint), null as JsonRecord | null)
      : Promise.resolve({ data: null, error: "no project available to compute the effective policy", truncated: false });

  const [domainPolicy, keyCreationPolicy, keyUploadPolicy, serialPortPolicy, shieldedVmPolicy, osLoginPolicy] = await Promise.all([
    readPolicy("constraints/iam.allowedPolicyMemberDomains"),
    readPolicy("constraints/iam.disableServiceAccountKeyCreation"),
    readPolicy("constraints/iam.disableServiceAccountKeyUpload"),
    readPolicy("constraints/compute.disableSerialPortAccess"),
    readPolicy("constraints/compute.requireShieldedVm"),
    readPolicy("constraints/compute.requireOsLogin"),
  ]);

  const computeProjectScan = await scanProjects(context.projectIds, (projectId) => client.getComputeProject(projectId));
  const instanceScan = await scanProjects(context.projectIds, (projectId) => client.listInstances(projectId, maxAssets));
  const binaryAuthScan = await scanProjects(context.projectIds, (projectId) => client.getBinaryAuthorizationPolicy(projectId));

  const projectsWithoutOsLogin = computeProjectScan.rows
    .filter((row) => !isTruthyMetadata(metadataValue(row.data.commonInstanceMetadata, "enable-oslogin")))
    .map((row) => row.projectId);
  const instances = flattenScan(instanceScan);
  const osLoginOverrides = instances
    .filter((instance) => {
      const value = metadataValue(instance.metadata, "enable-oslogin");
      return value !== undefined && !isTruthyMetadata(value);
    })
    .map((instance) => ({ projectId: instance.projectId, instance: asString(instance.name) }));
  const orgOsLoginEnforced = !osLoginPolicy.error && interpretOrgPolicyEnabled(osLoginPolicy.data);

  const shieldedViolations: JsonRecord[] = [];
  const shieldedUnknown: JsonRecord[] = [];
  const serialPortViolations: JsonRecord[] = [];
  for (const instance of instances) {
    const shielded = asObject(instance.shieldedInstanceConfig);
    const record = { projectId: instance.projectId, instance: asString(instance.name) };
    if (!shielded) shieldedUnknown.push(record);
    else if (shielded.enableSecureBoot !== true || shielded.enableVtpm !== true || shielded.enableIntegrityMonitoring !== true) {
      shieldedViolations.push({ ...record, shieldedInstanceConfig: shielded });
    }
    if (isTruthyMetadata(metadataValue(instance.metadata, "serial-port-enable"))) serialPortViolations.push(record);
  }

  const binaryAuthViolations: JsonRecord[] = [];
  const binaryAuthDryRun: JsonRecord[] = [];
  for (const row of binaryAuthScan.rows) {
    const rule = asObject(row.data.defaultAdmissionRule);
    const evaluationMode = asString(rule?.evaluationMode);
    const enforcementMode = asString(rule?.enforcementMode);
    if (evaluationMode !== "REQUIRE_ATTESTATION" && evaluationMode !== "ALWAYS_DENY") {
      binaryAuthViolations.push({ projectId: row.projectId, evaluationMode: evaluationMode ?? null });
    } else if (enforcementMode !== "ENFORCED_BLOCK_AND_AUDIT_LOG") {
      binaryAuthDryRun.push({ projectId: row.projectId, enforcementMode: enforcementMode ?? null });
    }
  }

  const scanBase = (scan: ProjectScan<unknown>) => ({
    inventoryError: context.error,
    deniedProjects: scan.denied.length,
    scannedProjects: context.projectIds.length,
    apiDisabledProjects: scan.apiDisabled.length,
    truncated: context.truncated || scan.truncated,
  });

  const organizationFinding: GcpFinding = !config.organizationId
    ? manualFinding("GCP-ORG-01", "Organization visibility", "medium", [6], "no organization ID was configured, so organization-level guardrails are outside this run's scope.", "run with GCP_ORGANIZATION_ID set or review organization metadata in the console.", { sampled_projects: context.projectIds.length })
    : organization.error
      ? manualFinding("GCP-ORG-01", "Organization visibility", "medium", [6], `organization metadata was not readable (${organization.error}).`, "confirm resourcemanager.organizations.get on the audit principal.", { sampled_projects: context.projectIds.length })
      : {
          id: "GCP-ORG-01",
          title: "Organization visibility",
          severity: "medium",
          status: context.error
            ? "manual"
            : context.truncated || context.projectIds.length === 0 || !asString(organization.data?.name)
              ? "warn"
              : "pass",
          summary: context.error
            ? `Manual: organization ${config.organizationId} was readable but the project inventory failed (${context.error}). Collect manually: list projects under the organization.`
            : !asString(organization.data?.name)
              ? `Organization ${config.organizationId} answered without the documented name field; confirm the organization resource manually.`
              : `Organization ${asString(organization.data?.displayName) ?? config.organizationId} was readable and ${context.projectIds.length} projects were sampled${context.truncated ? " (project inventory truncated by the project cap)" : context.projectIds.length === 0 ? " (no projects inventoried)" : ""}.`,
          evidence: { sampled_projects: context.projectIds.length, projects_truncated: context.truncated, target_project: targetProjectId ?? null },
          mappings: controlMappings(6),
          controls: [6],
        };

  const findings: GcpFinding[] = [
    organizationFinding,
    orgPolicyFinding("GCP-ORG-02", "Domain-restricted sharing", "high", [6], domainPolicy,
      "constraints/iam.allowedPolicyMemberDomains is enforced in the effective policy of the sampled project.",
      "constraints/iam.allowedPolicyMemberDomains is not enforced in the effective policy of the sampled project.",
      "warn", "review constraints/iam.allowedPolicyMemberDomains at the organization.", context.truncated),
    orgPolicyFinding("GCP-ORG-03", "Service account key creation restriction", "high", [6, 1], keyCreationPolicy,
      "constraints/iam.disableServiceAccountKeyCreation is enforced in the effective policy of the sampled project.",
      "constraints/iam.disableServiceAccountKeyCreation is not enforced in the effective policy of the sampled project.",
      "fail", "review constraints/iam.disableServiceAccountKeyCreation at the organization.", context.truncated),
    orgPolicyFinding("GCP-ORG-04", "Service account key upload restriction", "high", [6, 1], keyUploadPolicy,
      "constraints/iam.disableServiceAccountKeyUpload is enforced in the effective policy of the sampled project.",
      "constraints/iam.disableServiceAccountKeyUpload is not enforced in the effective policy of the sampled project.",
      "warn", "review constraints/iam.disableServiceAccountKeyUpload at the organization.", context.truncated),
    serialPortPolicy.error || shieldedVmPolicy.error
      ? manualFinding("GCP-ORG-05", "Serial port and Shielded VM guardrails", "medium", [12, 23], `the effective compute org policies were not readable (${serialPortPolicy.error ?? shieldedVmPolicy.error}).`, "review constraints/compute.disableSerialPortAccess and constraints/compute.requireShieldedVm.")
      : {
          id: "GCP-ORG-05",
          title: "Serial port and Shielded VM guardrails",
          severity: "medium",
          status: interpretOrgPolicyEnabled(serialPortPolicy.data) && interpretOrgPolicyEnabled(shieldedVmPolicy.data)
            ? (context.truncated ? "warn" : "pass")
            : interpretOrgPolicyEnabled(serialPortPolicy.data) || interpretOrgPolicyEnabled(shieldedVmPolicy.data)
              ? "warn"
              : "fail",
          summary: interpretOrgPolicyEnabled(serialPortPolicy.data) && interpretOrgPolicyEnabled(shieldedVmPolicy.data)
            ? "constraints/compute.disableSerialPortAccess and constraints/compute.requireShieldedVm are both enforced."
            : `Compute hardening guardrails missing: ${[!interpretOrgPolicyEnabled(serialPortPolicy.data) && "compute.disableSerialPortAccess", !interpretOrgPolicyEnabled(shieldedVmPolicy.data) && "compute.requireShieldedVm"].filter(Boolean).join(", ")}.`,
          evidence: { serial_port_policy: serialPortPolicy.data ?? null, shielded_vm_policy: shieldedVmPolicy.data ?? null },
          mappings: controlMappings(12, 23),
          controls: [12, 23],
        },
    orgOsLoginEnforced
      ? {
          id: "GCP-ORG-06",
          title: "OS Login enforcement",
          severity: "high",
          status: osLoginOverrides.length > 0 || context.truncated || instanceScan.denied.length > 0 || instanceScan.truncated ? "warn" : "pass",
          summary: osLoginOverrides.length > 0
            ? `constraints/compute.requireOsLogin is enforced but ${osLoginOverrides.length} instances carry an enable-oslogin metadata override that is not TRUE.`
            : `constraints/compute.requireOsLogin is enforced in the effective policy and no instance overrides enable-oslogin.${context.truncated || instanceScan.denied.length > 0 || instanceScan.truncated ? " Partial view: the instance inventory was truncated or partly denied." : ""}`,
          evidence: { policy: osLoginPolicy.data ?? null, instance_overrides: osLoginOverrides.slice(0, 25) },
          mappings: controlMappings(11),
          controls: [11],
        }
      : verdict({
          ...scanBase(computeProjectScan),
          id: "GCP-ORG-06",
          title: "OS Login enforcement",
          severity: "high",
          controls: [11],
          evidence: { projects_without_os_login: projectsWithoutOsLogin.slice(0, 25), instance_overrides: osLoginOverrides.slice(0, 25), org_policy_error: osLoginPolicy.error ?? null },
          total: computeProjectScan.rows.length,
          violations: projectsWithoutOsLogin.length + osLoginOverrides.length,
          emptyVerdict: "manual",
          passSummary: `enable-oslogin=TRUE is set in commonInstanceMetadata for all ${computeProjectScan.rows.length} sampled projects with Compute Engine and no instance overrides it.`,
          failSummary: `${projectsWithoutOsLogin.length} of ${computeProjectScan.rows.length} sampled projects lack enable-oslogin=TRUE in commonInstanceMetadata and ${osLoginOverrides.length} instances override it.`,
          emptySummary: "No Compute Engine project metadata was readable.",
          manualEvidence: "check enable-oslogin in project and instance metadata, or enforce constraints/compute.requireOsLogin.",
        }),
    verdict({
      ...scanBase(binaryAuthScan),
      id: "GCP-ORG-07",
      title: "Binary Authorization admission policy",
      severity: "medium",
      controls: [8],
      evidence: { permissive_policies: binaryAuthViolations.slice(0, 25), dry_run_policies: binaryAuthDryRun.slice(0, 25), projects_read: binaryAuthScan.rows.length },
      total: binaryAuthScan.rows.length,
      violations: binaryAuthViolations.length,
      unknown: binaryAuthDryRun.length,
      emptyVerdict: "manual",
      passSummary: `All ${binaryAuthScan.rows.length} sampled projects with Binary Authorization enabled require attestation (or deny) with ENFORCED_BLOCK_AND_AUDIT_LOG.`,
      failSummary: `${binaryAuthViolations.length} of ${binaryAuthScan.rows.length} sampled projects use a defaultAdmissionRule that does not require attestation.`,
      emptySummary: "No Binary Authorization policy was readable.",
      manualEvidence: "review the Binary Authorization policy for every project running GKE or Cloud Run.",
    }),
    verdict({
      ...scanBase(instanceScan),
      id: "GCP-ORG-08",
      title: "Shielded VM and serial port instance configuration",
      severity: "medium",
      controls: [12, 23],
      evidence: { shielded_violations: shieldedViolations.slice(0, 25), shielded_unknown: shieldedUnknown.slice(0, 25), serial_port_enabled: serialPortViolations.slice(0, 25), instances_read: instances.length },
      total: instances.length,
      violations: shieldedViolations.length + serialPortViolations.length,
      unknown: shieldedUnknown.length,
      emptyVerdict: "manual",
      passSummary: `All ${instances.length} instances enable Secure Boot, vTPM, and integrity monitoring, and none set serial-port-enable.`,
      failSummary: `${shieldedViolations.length} instances lack full Shielded VM settings and ${serialPortViolations.length} enable the serial port via metadata (of ${instances.length}).`,
      emptySummary: "No Compute Engine instances were listed in the sampled projects.",
      manualEvidence: "review shieldedInstanceConfig and serial-port-enable metadata on each instance.",
    }),
  ];

  const errors = collectErrors(
    [organization.error, context.error, domainPolicy.error, keyCreationPolicy.error, keyUploadPolicy.error, serialPortPolicy.error, shieldedVmPolicy.error, osLoginPolicy.error],
    computeProjectScan.denied,
    instanceScan.denied,
    binaryAuthScan.denied,
  );
  return {
    title: "GCP organization guardrails",
    category: "org-guardrails",
    summary: {
      sampled_projects: context.projectIds.length,
      projects_truncated: context.truncated,
      organization_visible: Boolean(organization.data) && !organization.error,
      target_project: targetProjectId ?? null,
      domain_restricted_sharing: interpretOrgPolicyEnabled(domainPolicy.data),
      service_account_key_creation_disabled: interpretOrgPolicyEnabled(keyCreationPolicy.data),
      service_account_key_upload_disabled: interpretOrgPolicyEnabled(keyUploadPolicy.data),
      serial_port_disabled: interpretOrgPolicyEnabled(serialPortPolicy.data),
      shielded_vm_required: interpretOrgPolicyEnabled(shieldedVmPolicy.data),
      os_login_required_by_policy: orgOsLoginEnforced,
      instances: instances.length,
      binary_authorization_projects: binaryAuthScan.rows.length,
      binary_authorization_api_disabled: binaryAuthScan.apiDisabled.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      organization: organization.data,
      projects: context.projectIds,
      effective_policies: {
        allowedPolicyMemberDomains: domainPolicy.data,
        disableServiceAccountKeyCreation: keyCreationPolicy.data,
        disableServiceAccountKeyUpload: keyUploadPolicy.data,
        disableSerialPortAccess: serialPortPolicy.data,
        requireShieldedVm: shieldedVmPolicy.data,
        requireOsLogin: osLoginPolicy.data,
      },
      compute_projects: computeProjectScan.rows,
      instances,
      binary_authorization: binaryAuthScan.rows,
    },
  };
}

function parseDurationSeconds(value: unknown): number | undefined {
  const text = asString(value);
  const match = text?.match(/^(\d+(?:\.\d+)?)s$/);
  return match ? Number(match[1]) : undefined;
}

function isPublicMember(member: string): boolean {
  return member === "allusers" || member === "allauthenticatedusers";
}

export async function assessGcpDataProtection(
  client: Pick<
    GcpAuditorClient,
    | "getResolvedConfig"
    | "getNow"
    | "listProjectInventory"
    | "listStorageBuckets"
    | "searchPublicIamBindings"
    | "listCryptoKeys"
    | "listDisks"
    | "listManagedZones"
    | "listApiKeys"
    | "listAccessPolicies"
    | "listServicePerimeters"
  >,
  options: { maxProjects?: number; maxAssets?: number } = {},
): Promise<GcpAssessmentResult> {
  const now = client.getNow();
  const config = client.getResolvedConfig();
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const maxAssets = clampNumber(options.maxAssets, DEFAULT_MAX_ASSETS, 1, 50_000);
  const context = await loadProjectContext(client, maxProjects);

  const bucketScan = await scanProjects(context.projectIds, (projectId) => client.listStorageBuckets(projectId, maxAssets));
  const publicBindings = await attempt(() => client.searchPublicIamBindings(maxAssets), EMPTY_LIST);
  const cryptoKeys = await attempt(() => client.listCryptoKeys(maxAssets), EMPTY_LIST);
  const diskScan = await scanProjects(context.projectIds, (projectId) => client.listDisks(projectId, maxAssets));
  const zoneScan = await scanProjects(context.projectIds, (projectId) => client.listManagedZones(projectId, maxAssets));
  const apiKeyScan = await scanProjects(context.projectIds, (projectId) => client.listApiKeys(projectId, maxAssets));
  const accessPolicies = config.organizationId
    ? await attempt(() => client.listAccessPolicies(), [] as JsonRecord[])
    : { data: [] as JsonRecord[], truncated: false };
  const perimeters: JsonRecord[] = [];
  const perimeterErrors: string[] = [];
  for (const policy of accessPolicies.data) {
    const name = asString(policy.name);
    if (!name) continue;
    const perimeterList = await attempt(() => client.listServicePerimeters(name), [] as JsonRecord[]);
    if (perimeterList.error) perimeterErrors.push(perimeterList.error);
    perimeters.push(...perimeterList.data);
  }

  const buckets = flattenScan(bucketScan);
  const nonUniformBuckets = buckets
    .filter((bucket) => asObject(asObject(bucket.iamConfiguration)?.uniformBucketLevelAccess)?.enabled !== true)
    .map((bucket) => ({ projectId: bucket.projectId, bucket: asString(bucket.name) }));
  const bucketsWithoutCmek = buckets
    .filter((bucket) => !asString(asObject(bucket.encryption)?.defaultKmsKeyName))
    .map((bucket) => ({ projectId: bucket.projectId, bucket: asString(bucket.name) }));

  const publicResources: JsonRecord[] = [];
  for (const result of publicBindings.data.items) {
    for (const binding of parsePolicyBindings(result.policy)) {
      const members = asArray(binding.members).map(normalizeMember).filter((member): member is string => Boolean(member) && isPublicMember(member as string));
      if (members.length > 0) {
        publicResources.push({ resource: asString(result.resource), assetType: asString(result.assetType), role: asString(binding.role), members });
      }
    }
  }

  const rotatingKeys = cryptoKeys.data.items.filter((key) => asString(key.purpose) === "ENCRYPT_DECRYPT" && asString(asObject(key.primary)?.state) !== "DESTROYED");
  const rotationViolations: JsonRecord[] = [];
  const rotationUnknown: JsonRecord[] = [];
  for (const key of rotatingKeys) {
    const rotationSeconds = parseDurationSeconds(key.rotationPeriod);
    const nextRotation = extractTimestamp(key.nextRotationTime);
    const record = { key: asString(key.name), rotationPeriod: asString(key.rotationPeriod) ?? null, nextRotationTime: nextRotation ?? null };
    if (rotationSeconds === undefined || !nextRotation) rotationViolations.push({ ...record, reason: "no automatic rotation configured" });
    else if (rotationSeconds > MAX_KMS_ROTATION_DAYS * 24 * 60 * 60) rotationViolations.push({ ...record, reason: `rotation period exceeds ${MAX_KMS_ROTATION_DAYS} days` });
    else if (new Date(nextRotation).getTime() < now.getTime()) rotationUnknown.push({ ...record, reason: "nextRotationTime is in the past" });
  }

  const disks = flattenScan(diskScan);
  const disksWithoutCmek = disks
    .filter((disk) => !asString(asObject(disk.diskEncryptionKey)?.kmsKeyName))
    .map((disk) => ({ projectId: disk.projectId, disk: asString(disk.name) }));

  const zones = flattenScan(zoneScan);
  const publicZones = zones.filter((zone) => asString(zone.visibility) === "public");
  const dnssecViolations: JsonRecord[] = [];
  for (const zone of publicZones) {
    const dnssec = asObject(zone.dnssecConfig);
    const state = asString(dnssec?.state);
    const weakAlgorithms = asObjectArray(dnssec?.defaultKeySpecs).map((spec) => asString(spec.algorithm)).filter((algorithm) => algorithm === "rsasha1");
    if (state !== "on") dnssecViolations.push({ projectId: zone.projectId, zone: asString(zone.name), state: state ?? null, reason: "dnssecConfig.state is not on" });
    else if (weakAlgorithms.length > 0) dnssecViolations.push({ projectId: zone.projectId, zone: asString(zone.name), state, reason: "rsasha1 signing algorithm" });
  }

  const apiKeys = flattenScan(apiKeyScan).filter((key) => !asString(key.deleteTime));
  const unrestrictedKeys: JsonRecord[] = [];
  for (const key of apiKeys) {
    const restrictions = asObject(key.restrictions);
    const hasApiTargets = asObjectArray(restrictions?.apiTargets).length > 0;
    const hasApplicationRestriction = Boolean(
      asObject(restrictions?.browserKeyRestrictions)
      ?? asObject(restrictions?.serverKeyRestrictions)
      ?? asObject(restrictions?.androidKeyRestrictions)
      ?? asObject(restrictions?.iosKeyRestrictions),
    );
    if (!hasApiTargets || !hasApplicationRestriction) {
      unrestrictedKeys.push({ projectId: key.projectId, key: asString(key.name), displayName: asString(key.displayName), apiTargets: hasApiTargets, applicationRestriction: hasApplicationRestriction });
    }
  }

  const enforcedPerimeters = perimeters.filter((perimeter) => {
    const status = asObject(perimeter.status);
    return asArray(status?.resources).length > 0 && asArray(status?.restrictedServices).length > 0;
  });
  const dryRunOnlyPerimeters = perimeters.filter((perimeter) => !enforcedPerimeters.includes(perimeter) && asObject(perimeter.spec));

  const scanBase = (scan: ProjectScan<unknown>) => ({
    inventoryError: context.error,
    deniedProjects: scan.denied.length,
    scannedProjects: context.projectIds.length,
    apiDisabledProjects: scan.apiDisabled.length,
    truncated: context.truncated || scan.truncated,
  });

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(bucketScan),
      id: "GCP-DATA-01",
      title: "Uniform bucket-level access",
      severity: "high",
      controls: [15],
      evidence: { non_uniform_buckets: nonUniformBuckets.slice(0, 25), buckets_read: buckets.length },
      total: buckets.length,
      violations: nonUniformBuckets.length,
      emptyVerdict: "manual",
      passSummary: `All ${buckets.length} buckets enable iamConfiguration.uniformBucketLevelAccess.`,
      failSummary: `${nonUniformBuckets.length} of ${buckets.length} buckets do not enable uniform bucket-level access.`,
      emptySummary: "No Cloud Storage buckets were listed in the sampled projects.",
      manualEvidence: "list buckets per project and check iamConfiguration.uniformBucketLevelAccess.enabled.",
    }),
    verdict({
      id: "GCP-DATA-02",
      title: "Public resource exposure",
      severity: "critical",
      controls: [3],
      evidence: { public_bindings: publicResources.slice(0, 25), query: PUBLIC_MEMBER_IAM_QUERY, policies_matched: publicBindings.data.items.length },
      total: buckets.length + publicBindings.data.items.length,
      violations: publicResources.length,
      inventoryError: publicBindings.error ?? context.error,
      deniedProjects: bucketScan.denied.length,
      scannedProjects: context.projectIds.length,
      truncated: publicBindings.truncated || context.truncated,
      emptyVerdict: "manual",
      passSummary: `No IAM binding in the scope grants a role to allUsers or allAuthenticatedUsers (${buckets.length} buckets inventoried).`,
      failSummary: `${publicResources.length} IAM bindings grant roles to allUsers or allAuthenticatedUsers.`,
      emptySummary: "No buckets or public bindings were inventoried, so exposure could not be evaluated.",
      manualEvidence: "search IAM policies for allUsers and allAuthenticatedUsers members across the organization.",
    }),
    verdict({
      id: "GCP-DATA-03",
      title: "KMS key rotation",
      severity: "medium",
      controls: [7],
      evidence: { keys_without_rotation: rotationViolations.slice(0, 25), overdue_rotation: rotationUnknown.slice(0, 25), keys_read: rotatingKeys.length },
      total: rotatingKeys.length,
      violations: rotationViolations.length,
      unknown: rotationUnknown.length,
      inventoryError: cryptoKeys.error,
      truncated: cryptoKeys.truncated || context.truncated,
      emptyVerdict: "manual",
      passSummary: `All ${rotatingKeys.length} ENCRYPT_DECRYPT keys rotate automatically within ${MAX_KMS_ROTATION_DAYS} days and have a future nextRotationTime.`,
      failSummary: `${rotationViolations.length} of ${rotatingKeys.length} ENCRYPT_DECRYPT keys lack automatic rotation within ${MAX_KMS_ROTATION_DAYS} days.`,
      emptySummary: "No customer-managed ENCRYPT_DECRYPT keys were found in Cloud Asset Inventory for the scope.",
      manualEvidence: "list Cloud KMS keys per location and review rotationPeriod and nextRotationTime.",
    }),
    verdict({
      ...scanBase(bucketScan),
      deniedProjects: bucketScan.denied.length + diskScan.denied.length,
      truncated: context.truncated || bucketScan.truncated || diskScan.truncated,
      id: "GCP-DATA-04",
      title: "Customer-managed encryption keys",
      severity: "medium",
      controls: [16],
      evidence: { buckets_without_cmek: bucketsWithoutCmek.slice(0, 25), disks_without_cmek: disksWithoutCmek.slice(0, 25), buckets_read: buckets.length, disks_read: disks.length },
      total: buckets.length + disks.length,
      violations: bucketsWithoutCmek.length + disksWithoutCmek.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `All ${buckets.length} buckets set encryption.defaultKmsKeyName and all ${disks.length} disks set diskEncryptionKey.kmsKeyName.`,
      failSummary: `${bucketsWithoutCmek.length} of ${buckets.length} buckets and ${disksWithoutCmek.length} of ${disks.length} disks rely on Google-managed encryption instead of CMEK.`,
      emptySummary: "No buckets or disks were listed in the sampled projects.",
      manualEvidence: "review default KMS keys on buckets and disk encryption keys.",
    }),
    verdict({
      ...scanBase(zoneScan),
      id: "GCP-DATA-05",
      title: "Cloud DNS DNSSEC",
      severity: "medium",
      controls: [17],
      evidence: { zones_without_dnssec: dnssecViolations.slice(0, 25), public_zones: publicZones.length, private_zones: zones.length - publicZones.length },
      total: publicZones.length,
      violations: dnssecViolations.length,
      emptyVerdict: "manual",
      passSummary: `All ${publicZones.length} public managed zones have dnssecConfig.state on without rsasha1 keys.`,
      failSummary: `${dnssecViolations.length} of ${publicZones.length} public managed zones lack DNSSEC or use rsasha1.`,
      emptySummary: `No public Cloud DNS managed zones were listed (${zones.length} private zones ignored).`,
      manualEvidence: "list managed zones per project and check dnssecConfig.state.",
    }),
    verdict({
      ...scanBase(apiKeyScan),
      id: "GCP-DATA-06",
      title: "API key restrictions",
      severity: "medium",
      controls: [20],
      evidence: { unrestricted_keys: unrestrictedKeys.slice(0, 25), keys_read: apiKeys.length },
      total: apiKeys.length,
      violations: unrestrictedKeys.length,
      emptyVerdict: "pass",
      passSummary: `All ${apiKeys.length} API keys define restrictions.apiTargets and an application restriction.`,
      failSummary: `${unrestrictedKeys.length} of ${apiKeys.length} API keys lack API target or application restrictions.`,
      emptySummary: `No API keys exist in the ${apiKeyScan.rows.length} sampled projects where the API Keys API answered.`,
      manualEvidence: "list API keys per project and review restrictions.",
    }),
    !config.organizationId
      ? manualFinding("GCP-DATA-07", "VPC Service Controls perimeters", "medium", [21], "VPC Service Controls perimeters are organization-scoped and no organization ID was configured.", "review Access Context Manager perimeters at the organization.")
      : verdict({
          id: "GCP-DATA-07",
          title: "VPC Service Controls perimeters",
          severity: "medium",
          controls: [21],
          evidence: {
            enforced_perimeters: enforcedPerimeters.map((perimeter) => ({ name: asString(perimeter.name), resources: asArray(asObject(perimeter.status)?.resources).length, restrictedServices: asArray(asObject(perimeter.status)?.restrictedServices).length })).slice(0, 25),
            dry_run_only_perimeters: dryRunOnlyPerimeters.map((perimeter) => asString(perimeter.name)).slice(0, 25),
            access_policies: accessPolicies.data.length,
          },
          total: accessPolicies.data.length,
          violations: enforcedPerimeters.length === 0 ? 1 : 0,
          violationStatus: "warn",
          unknown: dryRunOnlyPerimeters.length,
          inventoryError: accessPolicies.error ?? perimeterErrors[0],
          truncated: context.truncated,
          emptyVerdict: "fail",
          passSummary: `${enforcedPerimeters.length} enforced service perimeters protect resources with restricted services.`,
          failSummary: `${perimeters.length} perimeters exist but none is enforced with both resources and restricted services.`,
          emptySummary: "No Access Context Manager access policy exists for the organization, so no VPC Service Controls perimeter protects any project.",
          manualEvidence: "confirm whether sensitive projects require a service perimeter.",
        }),
  ];

  const errors = collectErrors(
    [context.error, publicBindings.error, cryptoKeys.error, accessPolicies.error, ...perimeterErrors],
    bucketScan.denied,
    diskScan.denied,
    zoneScan.denied,
    apiKeyScan.denied,
  );
  return {
    title: "GCP data protection posture",
    category: "data-protection",
    summary: {
      sampled_projects: context.projectIds.length,
      projects_truncated: context.truncated,
      buckets: buckets.length,
      non_uniform_buckets: nonUniformBuckets.length,
      public_bindings: publicResources.length,
      crypto_keys: rotatingKeys.length,
      keys_without_rotation: rotationViolations.length,
      disks: disks.length,
      resources_without_cmek: bucketsWithoutCmek.length + disksWithoutCmek.length,
      public_dns_zones: publicZones.length,
      zones_without_dnssec: dnssecViolations.length,
      api_keys: apiKeys.length,
      unrestricted_api_keys: unrestrictedKeys.length,
      enforced_perimeters: enforcedPerimeters.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: context.projectIds,
      buckets,
      public_bindings: publicBindings.data.items,
      crypto_keys: cryptoKeys.data.items,
      disks,
      managed_zones: zones,
      api_keys: apiKeys,
      service_perimeters: perimeters,
    },
  };
}

function portRangeIncludes(port: string, target: number): boolean {
  const [start, end] = port.split("-").map((value) => Number(value));
  if (!Number.isFinite(start)) return false;
  return end === undefined || Number.isNaN(end) ? start === target : target >= start && target <= end;
}

/** Firewall fields per GCP_DOCS.firewallsList: direction (default INGRESS), disabled, sourceRanges[], allowed[].IPProtocol, allowed[].ports[]. */
function isOpenAdminFirewall(rule: JsonRecord): boolean {
  if ((asString(rule.direction) ?? "INGRESS") !== "INGRESS" || rule.disabled === true) return false;
  const ranges = asArray(rule.sourceRanges).map(asString);
  if (!ranges.includes("0.0.0.0/0") && !ranges.includes("::/0")) return false;
  return asObjectArray(rule.allowed).some((allowed) => {
    const protocol = asString(allowed.IPProtocol)?.toLowerCase();
    if (protocol !== "tcp" && protocol !== "all") return false;
    const ports = asArray(allowed.ports).map(asString).filter((port): port is string => Boolean(port));
    return ports.length === 0 || ports.some((port) => ADMIN_PORTS.some((admin) => portRangeIncludes(port, admin)));
  });
}

const FLOW_LOG_UNSUPPORTED_PURPOSES = new Set(["REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER", "PRIVATE_SERVICE_CONNECT", "PRIVATE_NAT"]);

function lastSegment(value: unknown): string | undefined {
  return asString(value)?.split("/").at(-1);
}

export async function assessGcpNetworkSecurity(
  client: Pick<
    GcpAuditorClient,
    "listProjectInventory" | "listFirewalls" | "listSubnetworks" | "listRouters" | "listInstances" | "listSslPolicies" | "listTargetHttpsProxies" | "listBackendServices"
  >,
  options: { maxProjects?: number; maxAssets?: number } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const maxAssets = clampNumber(options.maxAssets, DEFAULT_MAX_ASSETS, 1, 50_000);
  const context = await loadProjectContext(client, maxProjects);

  const firewallScan = await scanProjects(context.projectIds, (projectId) => client.listFirewalls(projectId, maxAssets));
  const subnetScan = await scanProjects(context.projectIds, (projectId) => client.listSubnetworks(projectId, maxAssets));
  const routerScan = await scanProjects(context.projectIds, (projectId) => client.listRouters(projectId, maxAssets));
  const instanceScan = await scanProjects(context.projectIds, (projectId) => client.listInstances(projectId, maxAssets));
  const sslPolicyScan = await scanProjects(context.projectIds, (projectId) => client.listSslPolicies(projectId, maxAssets));
  const proxyScan = await scanProjects(context.projectIds, (projectId) => client.listTargetHttpsProxies(projectId, maxAssets));
  const backendScan = await scanProjects(context.projectIds, (projectId) => client.listBackendServices(projectId, maxAssets));

  const firewalls = flattenScan(firewallScan);
  const openAdminRules = firewalls.filter(isOpenAdminFirewall).map((rule) => ({ projectId: rule.projectId, rule: asString(rule.name), network: lastSegment(rule.network), allowed: rule.allowed }));

  const subnets = flattenScan(subnetScan).filter((subnet) => !FLOW_LOG_UNSUPPORTED_PURPOSES.has(asString(subnet.purpose) ?? ""));
  const subnetsWithoutFlowLogs = subnets
    .filter((subnet) => asObject(subnet.logConfig)?.enable !== true)
    .map((subnet) => ({ projectId: subnet.projectId, subnetwork: asString(subnet.name), region: lastSegment(subnet.region) }));
  const subnetsWithoutPrivateAccess = subnets
    .filter((subnet) => subnet.privateIpGoogleAccess !== true)
    .map((subnet) => ({ projectId: subnet.projectId, subnetwork: asString(subnet.name), region: lastSegment(subnet.region) }));

  const routers = flattenScan(routerScan);
  const natCoverage = new Set(
    routers
      .filter((router) => asObjectArray(router.nats).length > 0)
      .map((router) => `${router.projectId}|${lastSegment(router.network)}|${lastSegment(router.region)}`),
  );
  const subnetsWithoutNat = subnets
    .filter((subnet) => !natCoverage.has(`${subnet.projectId}|${lastSegment(subnet.network)}|${lastSegment(subnet.region)}`))
    .map((subnet) => ({ projectId: subnet.projectId, subnetwork: asString(subnet.name), network: lastSegment(subnet.network), region: lastSegment(subnet.region) }));
  const instances = flattenScan(instanceScan);
  const publicInstances = instances
    .filter((instance) => asObjectArray(instance.networkInterfaces).some((nic) => asObjectArray(nic.accessConfigs).length > 0))
    .map((instance) => ({ projectId: instance.projectId, instance: asString(instance.name) }));

  const sslPolicies = flattenScan(sslPolicyScan);
  const sslPolicyByLink = new Map<string, JsonRecord>();
  for (const policy of sslPolicies) {
    const name = asString(policy.name);
    if (name) sslPolicyByLink.set(`${policy.projectId}|${name}`, policy);
  }
  const proxies = flattenScan(proxyScan);
  const weakProxies: JsonRecord[] = [];
  const unresolvedProxies: JsonRecord[] = [];
  for (const proxy of proxies) {
    const policyName = lastSegment(proxy.sslPolicy);
    const record = { projectId: proxy.projectId, proxy: asString(proxy.name), sslPolicy: policyName ?? null };
    if (!policyName) {
      weakProxies.push({ ...record, reason: "no SSL policy attached; the default policy allows TLS 1.0 with the COMPATIBLE profile" });
      continue;
    }
    const policy = sslPolicyByLink.get(`${proxy.projectId}|${policyName}`);
    if (!policy) {
      unresolvedProxies.push({ ...record, reason: "attached SSL policy not found in the project inventory" });
      continue;
    }
    const minTls = asString(policy.minTlsVersion);
    const profile = asString(policy.profile);
    if (minTls !== "TLS_1_2" && minTls !== "TLS_1_3") weakProxies.push({ ...record, minTlsVersion: minTls ?? null, reason: "minTlsVersion below TLS_1_2" });
    else if (profile === "COMPATIBLE") weakProxies.push({ ...record, profile, reason: "COMPATIBLE profile permits weak cipher suites" });
    else if (profile === "CUSTOM") unresolvedProxies.push({ ...record, profile, reason: "CUSTOM profile requires manual cipher review" });
  }

  const externalBackends = flattenScan(backendScan).filter((backend) => {
    const scheme = asString(backend.loadBalancingScheme);
    const protocol = asString(backend.protocol);
    return (scheme === "EXTERNAL" || scheme === "EXTERNAL_MANAGED") && ["HTTP", "HTTPS", "HTTP2"].includes(protocol ?? "");
  });
  const backendsWithoutArmor = externalBackends
    .filter((backend) => !asString(backend.securityPolicy))
    .map((backend) => ({ projectId: backend.projectId, backendService: asString(backend.name), loadBalancingScheme: asString(backend.loadBalancingScheme) }));

  const scanBase = (...scans: ProjectScan<unknown>[]) => ({
    inventoryError: context.error,
    deniedProjects: scans.reduce((count, scan) => count + scan.denied.length, 0),
    scannedProjects: context.projectIds.length,
    apiDisabledProjects: Math.max(...scans.map((scan) => scan.apiDisabled.length)),
    truncated: context.truncated || scans.some((scan) => scan.truncated),
  });

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(firewallScan),
      id: "GCP-NET-01",
      title: "Firewall rules open to the internet on administrative ports",
      severity: "high",
      controls: [4],
      evidence: { open_admin_rules: openAdminRules.slice(0, 25), firewalls_read: firewalls.length, admin_ports: ADMIN_PORTS },
      total: firewalls.length,
      violations: openAdminRules.length,
      emptyVerdict: "manual",
      passSummary: `None of ${firewalls.length} firewall rules allow TCP ${ADMIN_PORTS.join("/")} ingress from 0.0.0.0/0 or ::/0.`,
      failSummary: `${openAdminRules.length} of ${firewalls.length} enabled ingress firewall rules allow TCP ${ADMIN_PORTS.join("/")} from 0.0.0.0/0 or ::/0.`,
      emptySummary: "No VPC firewall rules were listed; projects with a VPC network always carry rules, so confirm compute.firewalls.list access.",
      manualEvidence: "list firewall rules per project and review ingress rules with source 0.0.0.0/0.",
    }),
    verdict({
      ...scanBase(subnetScan),
      id: "GCP-NET-02",
      title: "VPC flow logs",
      severity: "medium",
      controls: [9],
      evidence: { subnets_without_flow_logs: subnetsWithoutFlowLogs.slice(0, 25), subnets_read: subnets.length },
      total: subnets.length,
      violations: subnetsWithoutFlowLogs.length,
      emptyVerdict: "manual",
      passSummary: `All ${subnets.length} eligible subnetworks set logConfig.enable=true (proxy-only and Private Service Connect subnets excluded).`,
      failSummary: `${subnetsWithoutFlowLogs.length} of ${subnets.length} eligible subnetworks do not enable flow logs (logConfig.enable).`,
      emptySummary: "No eligible subnetworks were listed in the sampled projects.",
      manualEvidence: "review logConfig.enable on each subnetwork.",
    }),
    verdict({
      ...scanBase(subnetScan),
      id: "GCP-NET-03",
      title: "Private Google Access",
      severity: "low",
      controls: [22],
      evidence: { subnets_without_private_google_access: subnetsWithoutPrivateAccess.slice(0, 25), subnets_read: subnets.length },
      total: subnets.length,
      violations: subnetsWithoutPrivateAccess.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `All ${subnets.length} eligible subnetworks set privateIpGoogleAccess=true.`,
      failSummary: `${subnetsWithoutPrivateAccess.length} of ${subnets.length} eligible subnetworks do not enable Private Google Access.`,
      emptySummary: "No eligible subnetworks were listed in the sampled projects.",
      manualEvidence: "review privateIpGoogleAccess on each subnetwork.",
    }),
    verdict({
      ...scanBase(subnetScan, routerScan, instanceScan),
      id: "GCP-NET-04",
      title: "Cloud NAT coverage and external IP usage",
      severity: "medium",
      controls: [10],
      evidence: { subnets_without_nat: subnetsWithoutNat.slice(0, 25), instances_with_external_ip: publicInstances.slice(0, 25), routers_read: routers.length, instances_read: instances.length },
      total: subnets.length + instances.length,
      violations: subnetsWithoutNat.length + publicInstances.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `Every eligible subnetwork region has a Cloud Router with NAT and none of ${instances.length} instances has an external access config.`,
      failSummary: `${subnetsWithoutNat.length} subnetworks lack a Cloud NAT in their network and region, and ${publicInstances.length} of ${instances.length} instances carry external IP access configs.`,
      emptySummary: "No subnetworks or instances were listed in the sampled projects.",
      manualEvidence: "review Cloud Routers with nats[] per region and instance networkInterfaces[].accessConfigs.",
    }),
    verdict({
      ...scanBase(proxyScan, sslPolicyScan),
      id: "GCP-NET-05",
      title: "Load balancer SSL policies",
      severity: "high",
      controls: [18],
      evidence: { weak_proxies: weakProxies.slice(0, 25), unresolved_proxies: unresolvedProxies.slice(0, 25), proxies_read: proxies.length, ssl_policies_read: sslPolicies.length },
      total: proxies.length,
      violations: weakProxies.length,
      unknown: unresolvedProxies.length,
      emptyVerdict: "manual",
      passSummary: `All ${proxies.length} HTTPS target proxies attach an SSL policy with minTlsVersion TLS_1_2 or higher and a MODERN, RESTRICTED, or FIPS_202205 profile.`,
      failSummary: `${weakProxies.length} of ${proxies.length} HTTPS target proxies allow TLS below 1.2 or the COMPATIBLE profile (including proxies without an SSL policy).`,
      emptySummary: "No HTTPS target proxies were listed in the sampled projects.",
      manualEvidence: "review sslPolicy on each target HTTPS proxy and the policy's minTlsVersion and profile.",
    }),
    verdict({
      ...scanBase(backendScan),
      id: "GCP-NET-06",
      title: "Cloud Armor on external backend services",
      severity: "medium",
      controls: [19],
      evidence: { backends_without_security_policy: backendsWithoutArmor.slice(0, 25), external_backends_read: externalBackends.length },
      total: externalBackends.length,
      violations: backendsWithoutArmor.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `All ${externalBackends.length} external HTTP(S) backend services reference a Cloud Armor securityPolicy.`,
      failSummary: `${backendsWithoutArmor.length} of ${externalBackends.length} external HTTP(S) backend services have no Cloud Armor securityPolicy.`,
      emptySummary: "No external HTTP(S) backend services were listed in the sampled projects.",
      manualEvidence: "review securityPolicy on each external backend service.",
    }),
  ];

  const errors = collectErrors(
    [context.error],
    firewallScan.denied,
    subnetScan.denied,
    routerScan.denied,
    instanceScan.denied,
    sslPolicyScan.denied,
    proxyScan.denied,
    backendScan.denied,
  );
  return {
    title: "GCP network security posture",
    category: "network-security",
    summary: {
      sampled_projects: context.projectIds.length,
      projects_truncated: context.truncated,
      firewalls: firewalls.length,
      open_admin_rules: openAdminRules.length,
      subnetworks: subnets.length,
      subnets_without_flow_logs: subnetsWithoutFlowLogs.length,
      subnets_without_private_google_access: subnetsWithoutPrivateAccess.length,
      subnets_without_nat: subnetsWithoutNat.length,
      instances_with_external_ip: publicInstances.length,
      https_proxies: proxies.length,
      weak_ssl_proxies: weakProxies.length,
      external_backends: externalBackends.length,
      backends_without_cloud_armor: backendsWithoutArmor.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: context.projectIds,
      firewalls,
      subnetworks: subnets,
      routers,
      instances: instances.map((instance) => ({ projectId: instance.projectId, name: instance.name, networkInterfaces: instance.networkInterfaces })),
      ssl_policies: sslPolicies,
      target_https_proxies: proxies,
      backend_services: externalBackends,
    },
  };
}

function formatAccessCheckText(result: GcpAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `GCP access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: GcpAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", `Collection errors (${result.errors.length}):`, ...result.errors.slice(0, 10).map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function countStatuses(findings: GcpFinding[]): Record<GcpFindingStatus, number> {
  const counts: Record<GcpFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(config: GcpResolvedConfig, assessments: GcpAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countStatuses(findings);
  return [
    "# GCP Audit Bundle Executive Summary",
    "",
    `Organization: ${config.organizationId ?? "n/a"}`,
    `Project hint: ${config.projectId ?? "n/a"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual controls: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    `- Collection errors: ${errors.length}${errors.length > 0 ? " (see _errors.log)" : ""}`,
    "",
    "## Category Summaries",
    "",
    ...assessments.map((assessment) => {
      const categoryCounts = countStatuses(assessment.findings);
      return `- ${assessment.title}: ${categoryCounts.fail} fail, ${categoryCounts.warn} warn, ${categoryCounts.manual} manual, ${categoryCounts.pass} pass`;
    }),
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .slice(0, 15)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Verification Required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedMatrix(findings: GcpFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.controls.map((control) => `#${control} ${GCP_CONTROL_MAPPINGS[control]?.name ?? ""}`).join("; "),
    item.status.toUpperCase(),
    ...GCP_FRAMEWORKS.map((framework) => item.mappings.filter((mapping) => mapping.startsWith(framework.prefix)).map((mapping) => mapping.slice(framework.prefix.length)).join(", ") || "-"),
  ]);
  return [
    "# GCP Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Spec control", "Status", ...GCP_FRAMEWORKS.map((framework) => framework.title)], rows),
  ].join("\n");
}

function buildFrameworkReport(framework: { slug: string; title: string; prefix: string }, findings: GcpFinding[]): string {
  const relevant = findings.filter((item) => item.mappings.some((mapping) => mapping.startsWith(framework.prefix)));
  const counts = countStatuses(relevant);
  const rows = relevant.map((item) => [
    item.mappings.filter((mapping) => mapping.startsWith(framework.prefix)).map((mapping) => mapping.slice(framework.prefix.length)).join(", "),
    item.id,
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  return [
    `# ${framework.title} Compliance Report`,
    "",
    `Findings mapped: ${relevant.length} (${counts.fail} fail, ${counts.warn} warn, ${counts.manual} manual, ${counts.pass} pass)`,
    "",
    formatTable(["Requirement", "Finding", "Status", "Title", "Summary"], rows),
    "",
  ].join("\n");
}

function buildQuickReference(assessments: GcpAssessmentResult[]): string {
  return [
    "# GCP Evidence Bundle Quick Reference",
    "",
    "Start with `compliance/executive_summary.md`, then `compliance/unified_compliance_matrix.md`.",
    "",
    "## Layout",
    "",
    "- `core_data/`: raw API snapshots per assessment with secrets redacted",
    "- `analysis/findings.json`: every finding with status, evidence, spec control numbers, and framework mappings",
    "- `analysis/<category>.json`: per-assessment summary, findings, and collection errors",
    "- `analysis/category_summaries.json`: status counts per category",
    "- `compliance/executive_summary.md`: prioritized readout",
    "- `compliance/unified_compliance_matrix.md`: finding to framework matrix",
    "- `compliance/frameworks/<framework>.md`: one report per framework in the spec mapping table",
    "- `_errors.log`: present only when some reads failed; every failed read renders the dependent finding as manual or partial",
    "- `metadata.json`: non-secret run metadata",
    "",
    "## Status Semantics",
    "",
    "- pass: the documented setting was read for the full inventory and met the control",
    "- warn: violations of a lower-severity control, items missing the documented flag, or a partial inventory",
    "- fail: the documented setting violates the control",
    "- manual: unreadable endpoint, denied permission, API not enabled, empty inventory, or out-of-scope control; the summary names what to collect",
    "",
    "## Assessments",
    "",
    ...assessments.map((assessment) => `- ${assessment.category}: ${assessment.findings.map((item) => item.id).join(", ")}`),
    "",
    "Resolved access tokens and credentials are never written to this bundle.",
  ].join("\n");
}

export async function exportGcpAuditBundle(
  client: Parameters<typeof checkGcpAccess>[0]
    & Parameters<typeof assessGcpIdentity>[0]
    & Parameters<typeof assessGcpLoggingDetection>[0]
    & Parameters<typeof assessGcpOrgGuardrails>[0]
    & Parameters<typeof assessGcpDataProtection>[0]
    & Parameters<typeof assessGcpNetworkSecurity>[0],
  config: GcpResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<GcpAuditBundleResult> {
  const maxProjects = options.project_limit ?? options.max_projects;
  const access = await checkGcpAccess(client);
  const identity = await assessGcpIdentity(client, { maxProjects, staleDays: options.stale_days, maxKeys: options.max_keys });
  const loggingDetection = await assessGcpLoggingDetection(client, { maxProjects, maxFindings: options.max_findings });
  const orgGuardrails = await assessGcpOrgGuardrails(client, { maxProjects, maxAssets: options.max_assets });
  const dataProtection = await assessGcpDataProtection(client, { maxProjects, maxAssets: options.max_assets });
  const networkSecurity = await assessGcpNetworkSecurity(client, { maxProjects, maxAssets: options.max_assets });

  const assessments = [identity, loggingDetection, orgGuardrails, dataProtection, networkSecurity];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors.map((error) => `[${assessment.category}] ${error}`));
  const targetName = safeDirName(`${config.organizationId ?? config.projectId ?? "gcp-scope"}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference(assessments));
  await writeSecureTextFile(outputDir, "README.md", buildQuickReference(assessments));
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    organization_id: config.organizationId ?? null,
    project_id: config.projectId ?? null,
    source_chain: config.sourceChain,
    credentials_path: config.credentialsPath ?? null,
    generated_at: new Date().toISOString(),
    options: {
      max_projects: maxProjects ?? DEFAULT_MAX_PROJECTS,
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      max_keys: options.max_keys ?? DEFAULT_MAX_KEYS,
      max_findings: options.max_findings ?? DEFAULT_MAX_FINDINGS,
      max_assets: options.max_assets ?? DEFAULT_MAX_ASSETS,
    },
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(redactSecrets(access)));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `core_data/${assessment.category}.json`, serializeJson(redactSecrets(assessment.snapshot)));
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson({
      title: assessment.title,
      category: assessment.category,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    }));
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.md`, formatAssessmentText(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/category_summaries.json", serializeJson(
    assessments.map((assessment) => ({ category: assessment.category, title: assessment.title, counts: countStatuses(assessment.findings), summary: assessment.summary })),
  ));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of GCP_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.slug}.md`, buildFrameworkReport(framework, findings));
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);
  return { outputDir, zipPath, fileCount, findingCount: findings.length, errorCount: errors.length };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    organization_id: asString(value.organization_id),
    project_id: asString(value.project_id),
    access_token: asString(value.access_token),
    credentials_file: asString(value.credentials_file),
  };
}

function normalizeScopedArgs(args: unknown): ScopedArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_projects: asNumber(value.max_projects),
    project_limit: asNumber(value.project_limit),
  };
}

function projectLimit(args: ScopedArgs): number | undefined {
  return args.project_limit ?? args.max_projects;
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopedArgs(args),
    stale_days: asNumber(value.stale_days),
    max_keys: asNumber(value.max_keys),
  };
}

function normalizeLoggingArgs(args: unknown): LoggingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopedArgs(args),
    max_findings: asNumber(value.max_findings),
  };
}

function normalizeInventoryArgs(args: unknown): InventoryArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopedArgs(args),
    max_assets: asNumber(value.max_assets),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeLoggingArgs(args),
    ...normalizeInventoryArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): GcpAuditorClient {
  return new GcpAuditorClient(resolveGcpConfiguration(args));
}

const authParams = {
  organization_id: Type.Optional(Type.String({ description: "GCP organization ID to audit. Defaults to GCP_ORGANIZATION_ID or GCP_ORG_ID." })),
  project_id: Type.Optional(Type.String({ description: "GCP project ID for project-scoped fallback or focused checks. Defaults to GCP_PROJECT_ID or GOOGLE_CLOUD_PROJECT." })),
  access_token: Type.Optional(Type.String({ description: "Explicit OAuth bearer token. Defaults to GCP_ACCESS_TOKEN, then a credentials file, then gcloud auth print-access-token." })),
  credentials_file: Type.Optional(Type.String({ description: "Path to a service account key or ADC JSON file. Defaults to GCP_CREDENTIALS_FILE, GOOGLE_APPLICATION_CREDENTIALS, or the ADC well-known file." })),
};

const scopeParams = {
  max_projects: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 20.", default: 20 })),
  project_limit: Type.Optional(Type.Number({ description: "Alias of max_projects; when the cap truncates the inventory every dependent finding is flagged as partial." })),
};

const inventoryParams = {
  ...scopeParams,
  max_assets: Type.Optional(Type.Number({ description: "Maximum resources to inventory per list. Defaults to 2000; truncation downgrades verdicts.", default: 2000 })),
};

function runTool<TArgs>(
  toolName: string,
  failurePrefix: string,
  run: (args: TArgs) => Promise<{ text: string; details: JsonRecord }>,
) {
  return async (_toolCallId: string, args: TArgs) => {
    try {
      const result = await run(args);
      return textResult(result.text, { tool: toolName, ...result.details });
    } catch (error) {
      return errorResult(`${failurePrefix}: ${describeError(error)}`, { tool: toolName });
    }
  };
}

export function registerGcpTools(pi: any): void {
  pi.registerTool({
    name: "gcp_check_access",
    label: "Check GCP audit access",
    description:
      "Validate read-only GCP audit access across Cloud Resource Manager, Cloud Asset Inventory, IAM, Logging, Compute Engine, Cloud Storage, Cloud KMS, and Security Command Center surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    execute: runTool<CheckAccessArgs>("gcp_check_access", "GCP access check failed", async (args) => {
      const result = await checkGcpAccess(createClient(args));
      return { text: formatAccessCheckText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_assess_identity",
    label: "Assess GCP identity posture",
    description:
      "Assess GCP IAM posture across privileged bindings, service account key rotation, user-managed keys, cross-project access, and default service account privilege.",
    parameters: Type.Object({
      ...authParams,
      ...scopeParams,
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for service account keys. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum service account keys to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    execute: runTool<IdentityArgs>("gcp_assess_identity", "GCP identity assessment failed", async (args) => {
      const result = await assessGcpIdentity(createClient(args), { maxProjects: projectLimit(args), staleDays: args.stale_days, maxKeys: args.max_keys });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_assess_logging_detection",
    label: "Assess GCP logging and detection",
    description:
      "Assess GCP Logging coverage (Admin Activity, Data Access, sinks, bucket retention) with Security Command Center visibility reported for context only.",
    parameters: Type.Object({
      ...authParams,
      ...scopeParams,
      max_findings: Type.Optional(Type.Number({ description: "Maximum Security Command Center findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeLoggingArgs,
    execute: runTool<LoggingArgs>("gcp_assess_logging_detection", "GCP logging and detection assessment failed", async (args) => {
      const result = await assessGcpLoggingDetection(createClient(args), { maxProjects: projectLimit(args), maxFindings: args.max_findings });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_assess_org_guardrails",
    label: "Assess GCP organization guardrails",
    description:
      "Assess GCP organization and project guardrails: domain-restricted sharing, service account key constraints, serial port and Shielded VM policies, OS Login, Binary Authorization, and instance hardening.",
    parameters: Type.Object({ ...authParams, ...inventoryParams }),
    prepareArguments: normalizeInventoryArgs,
    execute: runTool<InventoryArgs>("gcp_assess_org_guardrails", "GCP organization guardrail assessment failed", async (args) => {
      const result = await assessGcpOrgGuardrails(createClient(args), { maxProjects: projectLimit(args), maxAssets: args.max_assets });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_assess_data_protection",
    label: "Assess GCP data protection",
    description:
      "Assess GCP data protection: uniform bucket-level access, public IAM exposure, KMS key rotation, CMEK on buckets and disks, Cloud DNS DNSSEC, API key restrictions, and VPC Service Controls perimeters.",
    parameters: Type.Object({ ...authParams, ...inventoryParams }),
    prepareArguments: normalizeInventoryArgs,
    execute: runTool<InventoryArgs>("gcp_assess_data_protection", "GCP data protection assessment failed", async (args) => {
      const result = await assessGcpDataProtection(createClient(args), { maxProjects: projectLimit(args), maxAssets: args.max_assets });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_assess_network_security",
    label: "Assess GCP network security",
    description:
      "Assess GCP network security: internet-open firewall rules on admin ports, VPC flow logs, Private Google Access, Cloud NAT and external IPs, load balancer SSL policies, and Cloud Armor coverage.",
    parameters: Type.Object({ ...authParams, ...inventoryParams }),
    prepareArguments: normalizeInventoryArgs,
    execute: runTool<InventoryArgs>("gcp_assess_network_security", "GCP network security assessment failed", async (args) => {
      const result = await assessGcpNetworkSecurity(createClient(args), { maxProjects: projectLimit(args), maxAssets: args.max_assets });
      return { text: formatAssessmentText(result), details: { ...result } };
    }),
  });

  pi.registerTool({
    name: "gcp_export_audit_bundle",
    label: "Export GCP audit bundle",
    description:
      "Export a GCP audit bundle with core_data snapshots, analysis JSON, compliance reports per framework, a quick reference, an error log when reads fail, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      ...inventoryParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for service account keys. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum service account keys to inspect. Defaults to 200.", default: 200 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Security Command Center findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    execute: runTool<ExportAuditBundleArgs>("gcp_export_audit_bundle", "GCP audit bundle export failed", async (args) => {
      const config = resolveGcpConfiguration(args);
      const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
      const result = await exportGcpAuditBundle(new GcpAuditorClient(config), config, outputRoot, args);
      return {
        text: [
          "GCP audit bundle exported.",
          `Output dir: ${result.outputDir}`,
          `Zip archive: ${result.zipPath}`,
          `Findings: ${result.findingCount}`,
          `Files: ${result.fileCount}`,
          `Collection errors: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
        ].join("\n"),
        details: {
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          finding_count: result.findingCount,
          file_count: result.fileCount,
          error_count: result.errorCount,
        },
      };
    }),
  });
}
