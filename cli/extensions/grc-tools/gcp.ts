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
/** Pages fetched per list before the cursor is abandoned and the list is recorded as truncated. */
export const GCP_MAX_LIST_PAGES = 250;
const MAX_SERVICE_ACCOUNTS = 5000;
const MAX_LOGGING_RESOURCES = 5000;
const MAX_SCC_SOURCES = 1000;
const MAX_ACCESS_POLICIES = 1000;
const MAX_SERVICE_PERIMETERS = 5000;
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
  resourceNameFormat: "https://cloud.google.com/asset-inventory/docs/resource-name-format",
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

/** A dataset the assessments read, named so an unreadable read can be reported with its endpoint. */
export interface GcpInventory {
  dataset: string;
  endpoint: string;
}

/**
 * Every inventory a verdict or its evidence depends on. When any of them is
 * unreadable (401, 403, or an error) the dependent finding drops below pass and
 * its summary names the dataset and endpoint listed here.
 */
export const GCP_INVENTORIES = {
  organization: { dataset: "organization metadata", endpoint: "cloudresourcemanager.googleapis.com/v1/organizations/{organization}" },
  projects: { dataset: "project inventory", endpoint: "cloudasset.googleapis.com/v1/{scope}:searchAllResources" },
  iamPolicies: { dataset: "IAM policy search", endpoint: "cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies" },
  publicBindings: { dataset: "public IAM binding search", endpoint: `cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies?query=${PUBLIC_MEMBER_IAM_QUERY}` },
  cryptoKeys: { dataset: "Cloud KMS keys", endpoint: "cloudasset.googleapis.com/v1/{scope}/assets?assetTypes=cloudkms.googleapis.com/CryptoKey" },
  serviceAccounts: { dataset: "service accounts", endpoint: "iam.googleapis.com/v1/projects/{project}/serviceAccounts" },
  serviceAccountKeys: { dataset: "service account keys", endpoint: "iam.googleapis.com/v1/projects/{project}/serviceAccounts/{account}/keys" },
  adminActivity: { dataset: "Admin Activity audit entries", endpoint: "logging.googleapis.com/v2/entries:list (cloudaudit.googleapis.com/activity)" },
  dataAccess: { dataset: "Data Access audit entries", endpoint: "logging.googleapis.com/v2/entries:list (cloudaudit.googleapis.com/data_access)" },
  sinks: { dataset: "log sinks", endpoint: "logging.googleapis.com/v2/projects/{project}/sinks" },
  logBuckets: { dataset: "log buckets", endpoint: "logging.googleapis.com/v2/projects/{project}/locations/-/buckets" },
  loggingSettings: { dataset: "logging settings", endpoint: "logging.googleapis.com/v2/projects/{project}/settings" },
  sccSources: { dataset: "Security Command Center sources", endpoint: "securitycenter.googleapis.com/v1/organizations/{organization}/sources" },
  sccFindings: { dataset: "Security Command Center findings", endpoint: "securitycenter.googleapis.com/v1/organizations/{organization}/sources/-/findings" },
  effectiveOrgPolicy: { dataset: "effective org policy", endpoint: "cloudresourcemanager.googleapis.com/v1/projects/{project}:getEffectiveOrgPolicy" },
  computeProject: { dataset: "Compute Engine project metadata", endpoint: "compute.googleapis.com/compute/v1/projects/{project}" },
  instances: { dataset: "Compute Engine instances", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances" },
  binaryAuthorization: { dataset: "Binary Authorization policy", endpoint: "binaryauthorization.googleapis.com/v1/projects/{project}/policy" },
  buckets: { dataset: "Cloud Storage buckets", endpoint: "storage.googleapis.com/storage/v1/b?project={project}" },
  disks: { dataset: "Compute Engine disks", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/disks" },
  managedZones: { dataset: "Cloud DNS managed zones", endpoint: "dns.googleapis.com/dns/v1/projects/{project}/managedZones" },
  apiKeys: { dataset: "API keys", endpoint: "apikeys.googleapis.com/v2/projects/{project}/locations/global/keys" },
  accessPolicies: { dataset: "Access Context Manager access policies", endpoint: "accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations/{organization}" },
  servicePerimeters: { dataset: "VPC Service Controls perimeters", endpoint: "accesscontextmanager.googleapis.com/v1/{accessPolicy}/servicePerimeters" },
  firewalls: { dataset: "VPC firewall rules", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/global/firewalls" },
  subnetworks: { dataset: "VPC subnetworks", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/subnetworks" },
  routers: { dataset: "Cloud Routers", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/routers" },
  sslPolicies: { dataset: "SSL policies", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/sslPolicies" },
  targetHttpsProxies: { dataset: "target HTTPS proxies", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/targetHttpsProxies" },
  backendServices: { dataset: "backend services", endpoint: "compute.googleapis.com/compute/v1/projects/{project}/aggregated/backendServices" },
} as const satisfies Record<string, GcpInventory>;

function orgPolicyInventory(constraint: string): GcpInventory {
  return { dataset: `${GCP_INVENTORIES.effectiveOrgPolicy.dataset} ${constraint}`, endpoint: GCP_INVENTORIES.effectiveOrgPolicy.endpoint };
}

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
  /** Scopes (zones or regions) the API reported as not enumerated; any entry marks the list as truncated. */
  unreachable?: string[];
}

export interface GcpProjectInventory {
  projects: JsonRecord[];
  truncated: boolean;
}

type GcpCommandRunner = (command: string, args: string[]) => string | undefined;
/** Returns the file text, undefined when the file does not exist, or throws (a Node system error by preference) when it cannot be read. */
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

// ---------------------------------------------------------------------------------------------
// Rule 9, error-body class. Every error string this module creates passes through scrubErrorText:
// GcpApiError, the only error the client throws, scrubs in its constructor with the configured
// credentials as exact secrets, and describeError scrubs every other thrown value before it becomes
// a surface error, an unreadable_inventories[].error, a not_collected reason, a core_data marker, or
// an errors[] entry. A response body is never echoed: a non-JSON body contributes its content type
// and byte length, and a JSON body contributes only the documented google.rpc.Status fields. Every
// pattern is unanchored so an embedded URL, header, or name-value pair anywhere in free text is
// caught. The bundle writer applies the same rules once more to every file, without the long-token
// heuristic, because project ids, resource names, key names, and policy names are evidence.
// ---------------------------------------------------------------------------------------------

const REDACTED = "[REDACTED]";
/** Longest scrubbed google.rpc.Status message echoed in an error string; the cap runs after the scrub. */
const MAX_ERROR_MESSAGE_CHARS = 300;
/** Everything from the first ? of a scheme-prefixed URL found anywhere in the text; the host and path stay because they name the surface. */
const EMBEDDED_URL_QUERY_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()?#]+\?)[^\s"'<>()#]*/gi;
/** A fragment carrying name=value pairs (implicit-flow tokens); plain anchors stay. */
const EMBEDDED_URL_FRAGMENT_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()#]+#)[^\s"'<>()]*=[^\s"'<>()]*/gi;
/**
 * Sentence punctuation that follows an embedded URL is not part of a credential (no token, key, or JWT ends in
 * it), so it is kept outside the redaction. This also makes the scrub idempotent: "?[REDACTED]; details" scrubbed
 * again stays "?[REDACTED]; details" instead of losing its separator.
 */
const TRAILING_PUNCTUATION_PATTERN = /[;,.:!]+$/;

function redactUrlTail(match: string, prefix: string): string {
  const trailing = match.slice(prefix.length).match(TRAILING_PUNCTUATION_PATTERN)?.[0] ?? "";
  return `${prefix}${REDACTED}${trailing}`;
}
/** A plain lowercase word after the scheme ("bearer authentication", "basic auth") is prose, not a credential. */
const BEARER_PATTERN = /\b([Bb]earer)\s+(?![a-z]+\b)[A-Za-z0-9._~+/=-]{8,}/g;
const BASIC_AUTH_PATTERN = /\b([Bb]asic)\s+(?![a-z]+\b)[A-Za-z0-9+/=]{16,}/g;
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookie)(["']?\s*[:=]\s*)(?!\[REDACTED\])[^\s<>"'][^\r\n<>"']*/gi;
/** Google credential shapes: OAuth access tokens, API keys, OAuth client secrets, refresh tokens, and JWT assertions. */
const GOOGLE_ACCESS_TOKEN_PATTERN = /\bya29\.[A-Za-z0-9._~+/=-]{8,}/g;
const GOOGLE_API_KEY_PATTERN = /\bAIza[A-Za-z0-9_-]{20,}/g;
const GOOGLE_CLIENT_SECRET_PATTERN = /\bGOCSPX-[A-Za-z0-9_-]{8,}/g;
const GOOGLE_REFRESH_TOKEN_PATTERN = /(?<![A-Za-z0-9/])1\/\/[A-Za-z0-9_-]{10,}/g;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
/**
 * key=value, key: value, or "key": "value" where the key names a credential (api key, access, refresh, and id
 * tokens, client secret, private key, password, session, cookie, signature, authorization, assertion), quoted or
 * not. A short plain value such as "token: user" is prose, and a key that names a path, file, URI, type, count,
 * or identifier (credentials_path, token_uri, private_key_id) carries no credential and survives.
 */
const CREDENTIAL_KEY_WORDS = "token|secret|passw(?:or)?d|passphrase|passcode|pwd|session|api[_-]?key|apikey|key[_-]?string|private[_-]?key|signature|credential|cookie|authorization|assertion";
const CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
  `\\b([a-z0-9_-]*(?:${CREDENTIAL_KEY_WORDS})[a-z0-9_-]*)(["']?\\s*[:=]\\s*)(["']?)(?!bearer\\b|basic\\b|\\[REDACTED\\])[^\\s"'<>;,&]{6,}`,
  "gi",
);
const NON_CREDENTIAL_KEY_SUFFIX_PATTERN = /(?:[_-]|[a-z](?=[A-Z]))(?:path|file|uri|url|type|kind|count|source|chain|status|names?|ids?)$/i;
/**
 * "/", ".", ":", and "=" are not run characters, so endpoint paths, JWT segments, timestamps, and query pairs
 * split into short pieces that are judged on their own; base64url and hex material never contains them.
 */
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}/g;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_-]*$/;
/**
 * A segment made of words: an all-caps word, a lowercase or Capitalized word, or camelCase and PascalCase words
 * without digits (searchAllIamPolicies, PreconditionFailure, LocalizedMessage). Every capital must start a
 * lowercase run, so two adjacent capitals (AIza, base64 material) or any digit (ya29., hex) fail the test.
 */
const WORD_SEGMENT_PATTERN = /^(?:[A-Z]+|[A-Z]?[a-z]+(?:[A-Z][a-z]+)*)$/;

function hasTokenShape(value: string): boolean {
  return /\d/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
}

/**
 * A run of 16 or more token characters is a credential when it carries a digit or mixed case and is not made
 * of words: google.rpc codes and reasons (IAM_PERMISSION_DENIED), snake_case, camelCase, and PascalCase
 * identifiers (searchAllIamPolicies, allowedPolicyMemberDomains, PreconditionFailure), and Header-Style names
 * are left alone.
 */
function looksLikeToken(run: string): boolean {
  if (UPPERCASE_CODE_PATTERN.test(run)) return false;
  if (run.split(/[-_]/).every((segment) => WORD_SEGMENT_PATTERN.test(segment))) return false;
  return hasTokenShape(run);
}

export interface ScrubErrorTextOptions {
  /**
   * On by default because error text is the only place a bare token can arrive; data values and the bundle
   * writer turn it off because project ids, key names, and resource names are evidence, not secrets.
   */
  longTokens?: boolean;
}

/** Exact credential values known to this process: the configured access token and the credentials file material. */
export function credentialValues(config: Pick<GcpResolvedConfig, "accessToken" | "credentials">): string[] {
  const values: Array<string | undefined> = [config.accessToken];
  const credentials = config.credentials;
  switch (credentials?.type) {
    case "service_account":
      values.push(credentials.privateKey, ...credentials.privateKey.split(/\r?\n/).filter((line) => !line.startsWith("-----")));
      break;
    case "authorized_user":
      values.push(credentials.clientSecret, credentials.refreshToken);
      break;
    case undefined:
      break;
    default: {
      const exhaustive: never = credentials;
      throw new Error(`Unsupported credentials ${String(exhaustive)}`);
    }
  }
  return [...new Set(values.filter((value): value is string => typeof value === "string" && value.trim().length >= 8))];
}

export function scrubErrorText(text: string, secrets: string[] = [], options: ScrubErrorTextOptions = {}): string {
  let scrubbed = text;
  for (const secret of secrets) {
    if (secret.trim().length >= 8) scrubbed = scrubbed.split(secret).join(REDACTED);
  }
  scrubbed = scrubbed
    .replace(EMBEDDED_URL_QUERY_PATTERN, redactUrlTail)
    .replace(EMBEDDED_URL_FRAGMENT_PATTERN, redactUrlTail)
    .replace(BEARER_PATTERN, `$1 ${REDACTED}`)
    .replace(BASIC_AUTH_PATTERN, (match, scheme: string) => (hasTokenShape(match.slice(scheme.length)) ? `${scheme} ${REDACTED}` : match))
    .replace(GOOGLE_ACCESS_TOKEN_PATTERN, REDACTED)
    .replace(GOOGLE_API_KEY_PATTERN, REDACTED)
    .replace(GOOGLE_CLIENT_SECRET_PATTERN, REDACTED)
    .replace(GOOGLE_REFRESH_TOKEN_PATTERN, REDACTED)
    .replace(JWT_PATTERN, REDACTED)
    .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`)
    .replace(CREDENTIAL_ASSIGNMENT_PATTERN, (match, key: string, separator: string, quote: string) => (
      NON_CREDENTIAL_KEY_SUFFIX_PATTERN.test(key) ? match : `${key}${separator}${quote}${REDACTED}`
    ));
  if (options.longTokens === false) return scrubbed;
  return scrubbed.replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTED : run));
}

/** Data values and bundle content: every rule except the long-token heuristic (see ScrubErrorTextOptions). */
function scrubDataText(text: string, secrets: string[]): string {
  return scrubErrorText(text, secrets, { longTokens: false });
}

/**
 * The one error the client throws. Every failed request builds its message here, so no downstream consumer
 * (errors arrays, unreadable_inventories, not_collected reasons, finding summaries, core_data markers,
 * access.json, _errors.log, compliance reports) ever receives an unscrubbed string.
 */
export class GcpApiError extends Error {
  /** The HTTP status the endpoint answered with; undefined when no response arrived. */
  readonly status: number | undefined;
  readonly endpoint: string;

  constructor(message: string, endpoint: string, status: number | undefined, secrets: string[] = []) {
    super(scrubErrorText(message, secrets));
    this.name = "GcpApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

/** Every thrown value that becomes an error string goes through here, so an error raised outside the client gets the same treatment. */
function describeError(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

const HTTP_STATUS_PHRASES: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

/** "403 Forbidden": the status with its reason phrase when the server sent a plain one, else the canonical phrase. */
function httpStatusLine(response: Pick<Response, "status" | "statusText">): string {
  const phrase = /^[A-Za-z][A-Za-z '-]{0,39}$/.test(response.statusText) ? response.statusText : HTTP_STATUS_PHRASES[response.status] ?? "HTTP Error";
  return `${response.status} ${phrase}`;
}

function mediaType(contentType: string | null): string {
  const type = contentType?.split(";")[0].trim().toLowerCase();
  return type ? type : "unknown content type";
}

/** What a response body contributes when it carries no recognised envelope: its content type and byte length, never the body. */
function describeOpaqueBody(text: string, contentType: string | null, description: string): string {
  return `${description} (${mediaType(contentType)}; ${Buffer.byteLength(text, "utf8")} bytes)`;
}

function parseJsonObject(text: string): JsonRecord | undefined {
  try {
    return asObject(JSON.parse(text)) ?? undefined;
  } catch {
    return undefined;
  }
}

/** The documented detail type URL, type.googleapis.com/<package>.<Type>; only the type name (ErrorInfo, Help, BadRequest) is echoed. */
const GOOGLE_TYPE_URL_PATTERN = /^type\.googleapis\.com\/(?:[a-z][a-z0-9_]*\.)+([A-Z][A-Za-z0-9]*)$/;

/**
 * The documented google.rpc.Status envelope: error.code, error.status (a google.rpc.Code name), error.message
 * (free text, scrubbed before it is capped), and error.details[] with @type and reason (google.rpc.ErrorInfo,
 * UPPER_SNAKE_CASE). Every other field, a field without its documented shape, and any body that is not this
 * envelope are never echoed.
 */
function describeGoogleErrorBody(text: string, contentType: string | null, httpStatus: number, secrets: string[]): string {
  if (text.length === 0) return "";
  const payload = parseJsonObject(text);
  if (!payload) return describeOpaqueBody(text, contentType, "non-JSON error body");
  const error = asObject(payload.error);
  if (!error) return describeOpaqueBody(text, contentType, "JSON error body without a google.rpc.Status envelope");
  const parts: string[] = [];
  const code = typeof error.code === "number" ? error.code : undefined;
  if (code !== undefined && code !== httpStatus) parts.push(`code ${code}`);
  const status = asString(error.status);
  const message = asString(error.message)?.replace(/\s+/g, " ").trim();
  const head = [
    status && /^[A-Z][A-Z_]*$/.test(status) ? status : undefined,
    message ? scrubErrorText(message, secrets).slice(0, MAX_ERROR_MESSAGE_CHARS) : undefined,
  ].filter((part): part is string => Boolean(part)).join(": ");
  if (head) parts.push(head);
  const details = asObjectArray(error.details)
    .map((detail) => {
      const type = asString(detail["@type"])?.match(GOOGLE_TYPE_URL_PATTERN)?.[1];
      const reason = asString(detail.reason);
      const reasonText = reason && /^[A-Z][A-Z0-9_]*$/.test(reason) ? `reason ${reason}` : undefined;
      return [type, reasonText].filter(Boolean).join(" ");
    })
    .filter((detail) => detail.length > 0);
  if (details.length > 0) parts.push(`details ${details.join(", ")}`);
  return parts.length > 0 ? parts.join("; ") : "google.rpc.Status envelope without status, message, or details";
}

/** The documented OAuth 2.0 error response (RFC 6749 section 5.2): error and error_description (scrubbed before it is capped), never the raw body. */
function describeOAuthErrorBody(text: string, contentType: string | null, secrets: string[]): string {
  if (text.length === 0) return "";
  const payload = parseJsonObject(text);
  if (!payload) return describeOpaqueBody(text, contentType, "non-JSON error body");
  const code = asString(payload.error);
  const description = asString(payload.error_description)?.replace(/\s+/g, " ").trim();
  const envelope = [
    code && /^[a-z_]+$/.test(code) ? code : undefined,
    description ? scrubErrorText(description, secrets).slice(0, MAX_ERROR_MESSAGE_CHARS) : undefined,
  ].filter((part): part is string => Boolean(part)).join(": ");
  return envelope || describeOpaqueBody(text, contentType, "JSON error body without an OAuth error envelope");
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

/** A missing file is undefined; a file that exists but cannot be read (EACCES, EISDIR) throws the system error for readCredentialsFile to describe by code. */
function defaultFileReader(pathname: string): string | undefined {
  return existsSync(pathname) ? readFileSync(pathname, "utf8") : undefined;
}

/** The `code` of a Node system error (ENOENT, EACCES, EISDIR): a fixed identifier, never the message. */
function systemErrorCode(error: unknown): string | undefined {
  const code = asObject(error)?.code;
  return typeof code === "string" && /^E[A-Z0-9_]{1,30}$/.test(code) ? code : undefined;
}

/**
 * A structured parse position, when the runtime attaches one to the SyntaxError. V8 attaches none (its position
 * lives in the message text, which is never read), so on Node the description carries the path alone.
 */
function jsonErrorPosition(error: unknown): string | undefined {
  const record = asObject(error);
  const line = record?.lineNumber;
  const column = record?.columnNumber;
  const position = record?.position;
  if (typeof line === "number" && Number.isInteger(line) && line >= 0) {
    return typeof column === "number" && Number.isInteger(column) && column >= 0 ? ` at line ${line} column ${column}` : ` at line ${line}`;
  }
  return typeof position === "number" && Number.isInteger(position) && position >= 0 ? ` at position ${position}` : undefined;
}

/**
 * Loader errors carry fixed wording plus a path the operator configured, which is a data value: every shape rule
 * and exact secret applies, the long-token heuristic does not, so a directory named after a hash or a random suffix
 * survives as the pointer it is. Anything that surfaces through a tool still passes describeError's full scrub.
 */
function loaderError(message: string): Error {
  return new Error(scrubDataText(message, []));
}

/**
 * Reads a credentials file through the configured reader. The reader's error is never interpolated (a filesystem
 * message can quote the path and, for a non-standard reader, anything): the thrown text is a fixed description with
 * the path and the validated system error code, scrubbed like every other error this module raises.
 */
function readCredentialsFile(pathname: string, fileReader: GcpFileReader): string | undefined {
  try {
    return fileReader(pathname);
  } catch (error) {
    const code = systemErrorCode(error);
    throw loaderError(`unable to read ${pathname}${code ? ` (${code})` : ""}`);
  }
}

const CREDENTIALS_TYPE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * Parses a Google credentials JSON file. Service account keys carry
 * type "service_account", client_email, private_key, and token_uri; ADC user
 * credentials carry type "authorized_user", client_id, client_secret, and
 * refresh_token (GCP_DOCS.serviceAccountJwt, GCP_DOCS.adc).
 *
 * The parser's error is never interpolated: V8 quotes the characters around the fault, which for a malformed
 * private_key line is key material. A parse failure throws a fixed description with the path (and a position only
 * when the runtime attaches a structured one), and the type field is echoed only when it has the shape of a
 * documented credential type identifier.
 */
export function parseGcpCredentialsJson(text: string, pathname = "the credentials file"): GcpFileCredentials {
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    throw loaderError(`invalid JSON in ${pathname}${jsonErrorPosition(error) ?? ""}`);
  }
  const parsed = asObject(payload);
  if (!parsed) throw loaderError(`${pathname} did not contain a JSON object.`);
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
      throw loaderError(`Unsupported credentials type "${type && CREDENTIALS_TYPE_PATTERN.test(type) ? type : "unknown"}" in ${pathname}; expected service_account or authorized_user.`);
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

/** Every failure of the token endpoint is a GcpApiError built from the documented OAuth error fields or the body's content type and length. */
async function postTokenRequest(tokenUri: string, form: URLSearchParams, fetchImpl: FetchImpl, secrets: string[]): Promise<string> {
  let response: Response;
  try {
    response = await fetchImpl(tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
  } catch (error) {
    throw new GcpApiError(`Token exchange failed before a response arrived: ${describeError(error)} (POST ${tokenUri})`, tokenUri, undefined, secrets);
  }
  const text = await response.text().catch(() => "");
  const contentType = response.headers.get("content-type");
  if (!response.ok) {
    const body = describeOAuthErrorBody(text, contentType, secrets);
    throw new GcpApiError(`Token exchange failed: ${httpStatusLine(response)}${body ? `: ${body}` : ""} (POST ${tokenUri})`, tokenUri, response.status, secrets);
  }
  const payload = parseJsonObject(text);
  if (!payload) {
    throw new GcpApiError(`Token exchange failed: ${httpStatusLine(response)}: ${describeOpaqueBody(text, contentType, "non-JSON response body")} (POST ${tokenUri})`, tokenUri, response.status, secrets);
  }
  const accessToken = asString(payload.access_token);
  if (!accessToken) throw new GcpApiError(`Token exchange response did not include access_token (POST ${tokenUri})`, tokenUri, response.status, secrets);
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
  const secrets = credentialValues({ credentials });
  switch (credentials.type) {
    case "service_account": {
      const form = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: createGcpServiceAccountAssertion(credentials, now),
      });
      return postTokenRequest(credentials.tokenUri, form, fetchImpl, secrets);
    }
    case "authorized_user": {
      const form = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        refresh_token: credentials.refreshToken,
      });
      return postTokenRequest(credentials.tokenUri, form, fetchImpl, secrets);
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
      const text = readCredentialsFile(candidate, fileReader);
      if (!text) {
        if (source !== "application-default-credentials") {
          throw loaderError(`Credentials file not readable: ${candidate}`);
        }
        continue;
      }
      credentials = parseGcpCredentialsJson(text, candidate);
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

/**
 * ResourceSearchResult exposes no projectId field and documents
 * additionalAttributes as not for programmatic use, so the project identifier
 * is taken from the documented full resource name
 * //cloudresourcemanager.googleapis.com/projects/{PROJECT_ID or PROJECT_NUMBER}
 * (GCP_DOCS.resourceNameFormat). Either form is a valid project path segment.
 */
function parseProjectId(resource: JsonRecord): string | undefined {
  const name = asString(resource.name);
  if (!name?.includes("/projects/")) return undefined;
  return asString(name.split("/projects/").at(-1)?.split("/")[0]);
}

function projectResourceName(projectId: string): string {
  return `//cloudresourcemanager.googleapis.com/projects/${projectId}`;
}

/** Unreachable scopes in a Compute aggregatedList response: unreachables[] plus scopes whose warning.code is UNREACHABLE. */
function collectUnreachableScopes(response: JsonRecord): string[] {
  const scopes = asArray(response.unreachables).map(asString).filter((value): value is string => Boolean(value));
  for (const [scope, scoped] of Object.entries(asObject(response.items) ?? {})) {
    if (asString(asObject(asObject(scoped)?.warning)?.code) === "UNREACHABLE") scopes.push(scope);
  }
  return scopes;
}

/** Reduces a Compute Engine resource URL (full, partial, or self link) to its projects/... path. */
function computeResourcePath(value: unknown): string | undefined {
  const text = asString(value);
  const index = text?.indexOf("projects/") ?? -1;
  return text && index >= 0 ? text.slice(index) : undefined;
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
  private exchangedToken?: string;

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

  /** Exact secrets scrubbed from every error this client creates: the configured credentials plus any token it exchanged them for. */
  getKnownSecrets(): string[] {
    return [...new Set([...credentialValues(this.config), ...(this.exchangedToken ? [this.exchangedToken] : [])])];
  }

  async getAccessToken(): Promise<string> {
    if (this.config.accessToken) return this.config.accessToken;
    if (!this.config.credentials) throw new Error("No GCP access token or credentials file was resolved.");
    this.tokenPromise ??= exchangeGcpCredentials(this.config.credentials, this.fetchImpl, this.now()).then((token) => {
      this.exchangedToken = token;
      return token;
    });
    return this.tokenPromise;
  }

  /**
   * The single point where a request failure becomes an error string. The message carries the HTTP status,
   * method, and endpoint (the URL without its query); the body contributes only what describeGoogleErrorBody
   * admits, and the GcpApiError constructor scrubs the whole message with the known secrets.
   */
  private async requestJson(url: string, init: { method?: string; body?: unknown } = {}): Promise<JsonRecord> {
    const method = init.method ?? "GET";
    const endpoint = url.split("?")[0];
    let response: Response;
    try {
      const token = await this.getAccessToken();
      response = await this.fetchImpl(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
      });
    } catch (error) {
      throw new GcpApiError(`${method} ${endpoint} failed before a response arrived: ${describeError(error)}`, endpoint, undefined, this.getKnownSecrets());
    }
    const secrets = this.getKnownSecrets();
    const text = await response.text().catch(() => "");
    const contentType = response.headers.get("content-type");
    if (!response.ok) {
      const body = describeGoogleErrorBody(text, contentType, response.status, secrets);
      throw new GcpApiError(`${httpStatusLine(response)}${body ? `: ${body}` : ""} (${method} ${endpoint})`, endpoint, response.status, secrets);
    }
    // Every surface this client reads answers with a JSON object: the proto3 JSON mapping encodes a response message
    // whose fields all hold defaults, and google.protobuf.Empty itself, as `{}` (protobuf.dev/programming-guides/json,
    // "An empty JSON object"), and the Compute and Storage list responses always carry `kind`. A 2xx with nothing in
    // it is a proxy, captive portal, or gateway answering in the service's place, so it is an unreadable surface,
    // never an empty inventory.
    if (text.trim().length === 0) {
      throw new GcpApiError(`${httpStatusLine(response)}: ${describeOpaqueBody(text, contentType, "empty response body")} (${method} ${endpoint})`, endpoint, response.status, secrets);
    }
    const payload = parseJsonObject(text);
    if (!payload) {
      throw new GcpApiError(`${httpStatusLine(response)}: ${describeOpaqueBody(text, contentType, "non-JSON response body")} (${method} ${endpoint})`, endpoint, response.status, secrets);
    }
    return payload;
  }

  private async paginate(
    buildUrl: (pageToken?: string) => string,
    collect: (response: JsonRecord) => JsonRecord[],
    limit: number,
    collectUnreachable?: (response: JsonRecord) => string[],
  ): Promise<GcpListResult> {
    const items: JsonRecord[] = [];
    const unreachable = new Set<string>();
    let pageToken: string | undefined;
    let pages = 0;
    let truncated = false;
    for (;;) {
      const response = await this.requestJson(buildUrl(pageToken));
      pages += 1;
      items.push(...collect(response));
      for (const scope of collectUnreachable?.(response) ?? []) unreachable.add(scope);
      const nextPageToken = asString(response.nextPageToken);
      if (!nextPageToken) break;
      if (items.length >= limit || nextPageToken === pageToken || pages >= GCP_MAX_LIST_PAGES) {
        truncated = true;
        break;
      }
      pageToken = nextPageToken;
    }
    if (unreachable.size === 0) return { items, truncated };
    return { items, truncated: true, unreachable: [...unreachable] };
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
        projects: this.config.projectId
          ? [{ name: projectResourceName(this.config.projectId), displayName: this.config.projectId }]
          : [],
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
  async listServiceAccounts(projectId: string, limit = MAX_SERVICE_ACCOUNTS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.accounts),
      limit,
    );
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
  async listLogSinks(projectId: string, limit = MAX_LOGGING_RESOURCES): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://logging.googleapis.com/v2/projects/${projectId}/sinks${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.sinks),
      limit,
    );
  }

  /** GCP_DOCS.logBucketsList: parent projects/{p}/locations/-; response buckets[] with retentionDays. */
  async listLogBuckets(projectId: string, limit = MAX_LOGGING_RESOURCES): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://logging.googleapis.com/v2/projects/${projectId}/locations/-/buckets${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.buckets),
      limit,
    );
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
  async listSccSources(limit = MAX_SCC_SOURCES): Promise<GcpListResult> {
    if (!this.config.organizationId) return { items: [], truncated: false };
    return this.paginate(
      (pageToken) => `https://securitycenter.googleapis.com/v1/organizations/${this.config.organizationId}/sources${buildQuery({ pageSize: 100, pageToken })}`,
      (response) => asObjectArray(response.sources),
      limit,
    );
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
   * response items is a map of scope -> {<collection>: [...], warning}. The
   * top-level unreachables[] ("Output only. Unreachable resources") and any
   * scope whose warning.code is UNREACHABLE mean the inventory is partial.
   */
  private async listAggregated(projectId: string, collection: string, limit: number): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://compute.googleapis.com/compute/v1/projects/${projectId}/aggregated/${collection}${buildQuery({ maxResults: 500, pageToken })}`,
      (response) => Object.values(asObject(response.items) ?? {}).flatMap((scoped) => asObjectArray(asObject(scoped)?.[collection])),
      limit,
      collectUnreachableScopes,
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
  async listAccessPolicies(limit = MAX_ACCESS_POLICIES): Promise<GcpListResult> {
    if (!this.config.organizationId) return { items: [], truncated: false };
    return this.paginate(
      (pageToken) => `https://accesscontextmanager.googleapis.com/v1/accessPolicies${buildQuery({ parent: `organizations/${this.config.organizationId}`, pageToken })}`,
      (response) => asObjectArray(response.accessPolicies),
      limit,
    );
  }

  /** GCP_DOCS.servicePerimetersList: GET {accessPolicies/id}/servicePerimeters; response servicePerimeters[]. */
  async listServicePerimeters(accessPolicyName: string, limit = MAX_SERVICE_PERIMETERS): Promise<GcpListResult> {
    return this.paginate(
      (pageToken) => `https://accesscontextmanager.googleapis.com/v1/${accessPolicyName}/servicePerimeters${buildQuery({ pageToken })}`,
      (response) => asObjectArray(response.servicePerimeters),
      limit,
    );
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
  inventory: GcpInventory;
  rows: ProjectScanRow<T>[];
  denied: Array<{ projectId: string; error: string }>;
  apiDisabled: string[];
  unreachable: string[];
  truncated: boolean;
  /** Set when no project could be attempted, naming the upstream project inventory call and why it yielded nothing. */
  notAttempted?: string;
}

/** Why a per-project read was never attempted: the project inventory was denied or listed nothing. */
function scanNotAttempted(context: ProjectContext): string | undefined {
  if (context.error) return `no project could be enumerated because ${GCP_INVENTORIES.projects.dataset} was unreadable via ${GCP_INVENTORIES.projects.endpoint} (${shortError(context.error)})`;
  if (context.projectIds.length === 0) return `${GCP_INVENTORIES.projects.dataset} listed no projects in the scope via ${GCP_INVENTORIES.projects.endpoint}`;
  return undefined;
}

async function scanProjects<T>(
  context: ProjectContext,
  inventory: GcpInventory,
  load: (projectId: string) => Promise<T>,
): Promise<ProjectScan<T>> {
  const scan: ProjectScan<T> = { inventory, rows: [], denied: [], apiDisabled: [], unreachable: [], truncated: false, notAttempted: scanNotAttempted(context) };
  for (const projectId of context.projectIds) {
    try {
      const data = await load(projectId);
      const list = asObject(data);
      if (list && list.truncated === true) scan.truncated = true;
      for (const scope of asArray(list?.unreachable).map(asString)) {
        if (scope) scan.unreachable.push(`${projectId}: ${scope}`);
      }
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

/** Whether the endpoint answered with an error, or was never called because an upstream inventory yielded nothing. */
export type UnreadableInventoryStatus = "unreadable" | "not_collected";

/** One dataset the finding depends on that could not be read, with the endpoint a human must query instead. */
export interface UnreadableInventory {
  dataset: string;
  endpoint: string;
  scope: string;
  status: UnreadableInventoryStatus;
  /** The request error for an unreadable dataset; for a dataset that was not collected, the upstream call and its status. */
  error: string;
}

/**
 * HTTP status text ("403 Forbidden") from the request error itself, optionally behind a
 * single identifier prefix such as the service account email; a status quoted inside
 * nested text belongs to another call and is never harvested. Non-HTTP errors keep their start.
 */
function shortError(error: string): string {
  return error.match(/^(?:[^\s():]+: )?(\d{3} [A-Za-z][A-Za-z ]*)/)?.[1]?.trim() ?? truncateAtWord(error, 80);
}

/**
 * About `max` characters cut at a space: back to the last space when that keeps at least half, otherwise forward
 * to the next one, so a note that starts with an endpoint keeps the endpoint whole instead of a URL fragment.
 */
function truncateAtWord(text: string, max: number): string {
  if (text.length <= max) return text;
  const back = text.lastIndexOf(" ", max);
  const cut = back > max / 2 ? back : text.indexOf(" ", max);
  return cut === -1 ? text : `${text.slice(0, cut).trimEnd()}...`;
}

function describeUnreadable(entry: UnreadableInventory): string {
  switch (entry.status) {
    case "unreadable":
      return `${entry.dataset} unreadable for ${entry.scope} via ${entry.endpoint} (${shortError(entry.error)})`;
    case "not_collected":
      return `${entry.dataset} not collected for ${entry.scope} (${entry.endpoint} was not called): ${entry.error}`;
    default: {
      const exhaustive: never = entry.status;
      throw new Error(`Unhandled inventory status ${String(exhaustive)}`);
    }
  }
}

function notCollected(inventory: GcpInventory, scope: string, reason: string): UnreadableInventory {
  return { ...inventory, scope, status: "not_collected", error: reason };
}

/** Describes every entry, merging datasets whose reads were all skipped for the same upstream reason into one clause. */
function describeUnreadableAll(entries: UnreadableInventory[]): string {
  const groups = new Map<string, UnreadableInventory[]>();
  entries.forEach((entry, index) => {
    const key = entry.status === "not_collected" ? `${entry.scope}\u0000${entry.error}` : `#${index}`;
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  });
  return [...groups.values()]
    .map((group) => {
      const [first] = group;
      if (group.length === 1) return describeUnreadable(first);
      const endpoints = [...new Set(group.map((entry) => entry.endpoint))];
      return `${group.map((entry) => entry.dataset).join(" and ")} not collected for ${first.scope} (${endpoints.join(" and ")} ${endpoints.length > 1 ? "were" : "was"} not called): ${first.error}`;
    })
    .join("; ");
}

function unreadableCollected(inventory: GcpInventory, collected: Collected<unknown>, scope = "the organization scope"): UnreadableInventory[] {
  return collected.error ? [{ ...inventory, scope, status: "unreadable", error: collected.error }] : [];
}

function unreadableScans(...scans: ProjectScan<unknown>[]): UnreadableInventory[] {
  return scans.flatMap((scan) => {
    if (scan.notAttempted) return [notCollected(scan.inventory, "the scope", scan.notAttempted)];
    if (scan.denied.length === 0) return [];
    const attempted = scan.rows.length + scan.denied.length + scan.apiDisabled.length;
    const named = scan.denied.map((entry) => entry.projectId).slice(0, 3);
    return [{
      ...scan.inventory,
      scope: `${scan.denied.length} of ${attempted} projects (${named.join(", ")}${scan.denied.length > named.length ? ", ..." : ""})`,
      status: "unreadable",
      error: scan.denied[0].error,
    }];
  });
}

/**
 * False when no project answered the scan: the read was denied everywhere, or no project was
 * attempted because the project inventory was unreadable or empty. Projects that only reported
 * the API as disabled still count as answered, since that is a definitive statement about them.
 */
function scanReadable(scan: ProjectScan<unknown>): boolean {
  return scan.rows.length > 0 || (scan.denied.length === 0 && scan.apiDisabled.length > 0);
}

/**
 * Three-valued OR over collection flags: true when any received list was cut short, null when
 * any list was never received, false only when every list arrived in full.
 */
function anyTruncated(flags: Array<boolean | null>): boolean | null {
  if (flags.includes(true)) return true;
  return flags.includes(null) ? null : false;
}

/** Whether the project inventory was cut short; null when it was never received. */
function projectsTruncated(context: ProjectContext): boolean | null {
  return context.error ? null : context.truncated;
}

function scanTruncation(scan: ProjectScan<unknown>): boolean | null {
  if (scan.truncated) return true;
  return scanReadable(scan) ? false : null;
}

function collectedTruncation(collected: Collected<unknown>): boolean | null {
  if (collected.truncated) return true;
  return collected.error ? null : false;
}

/** Scopes the received lists reported as unreachable; null when a list the finding reads was never received. */
function unreachableScopesOf(scans: ProjectScan<unknown>[]): string[] | null {
  const scopes = scans.flatMap((scan) => scan.unreachable);
  if (scopes.length > 0) return scopes;
  return scans.every(scanReadable) ? [] : null;
}

/** A value derived from a scan that no project answered is not a value; render null beside the named status instead. */
function readableValue<T>(scan: ProjectScan<unknown>, value: T): T | null {
  return scanReadable(scan) ? value : null;
}

/** The same rule for an organization-scoped read: a failed read yields null, never a count or list built from its fallback. */
function collectedValue<T>(collected: Collected<unknown>, value: T): T | null {
  return collected.error ? null : value;
}

/** A value derived from several inventories is a value only when every one of them was readable. */
function jointValue<T>(readable: boolean[], value: T): T | null {
  return readable.every(Boolean) ? value : null;
}

/** The sampled project count, null when the project inventory itself was unreadable. */
function sampledProjects(context: ProjectContext): number | null {
  return context.error ? null : context.projectIds.length;
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
  unknownSummary?: string;
  violationStatus?: "fail" | "warn";
  /** The primary inventory this finding is computed from, named in the all-denied manual verdict. */
  inventory?: GcpInventory;
  /** The primary inventory was unreadable at its whole scope, so the finding is manual. */
  inventoryError?: UnreadableInventory;
  /** Dependent inventories unreadable in part or in whole; any entry keeps the finding below pass. */
  unreadable?: UnreadableInventory[];
  /** The count rendered as evidence.seen; defaults to total. Null when total sums a list that was never received. */
  seen?: number | null;
  deniedProjects?: number;
  /** Projects the per-project scan could attempt; undefined for findings computed from organization-scoped reads only. */
  scannedProjects?: number;
  apiDisabledProjects?: number;
  /** Collection status of every list the finding reads: null when one of them was never received. */
  truncated: boolean | null;
  unreachableScopes?: string[] | null;
  emptyVerdict: "pass" | "fail" | "manual";
  passSummary: string;
  failSummary: string;
  emptySummary: string;
  manualEvidence: string;
}

type PartialViewInput = Pick<VerdictInput, "total" | "deniedProjects" | "scannedProjects" | "apiDisabledProjects" | "truncated" | "unreachableScopes" | "unreadable">;

function partialNote(input: PartialViewInput): string {
  const notes: string[] = [];
  const unreachable = input.unreachableScopes ?? [];
  const unreadable = input.unreadable ?? [];
  for (const entry of unreadable) notes.push(describeUnreadable(entry));
  if (input.deniedProjects && unreadable.length === 0) notes.push(`${input.deniedProjects} of ${input.scannedProjects ?? 0} projects denied`);
  if (input.apiDisabledProjects) notes.push(`${input.apiDisabledProjects} projects without the API enabled`);
  if (unreachable.length > 0) {
    notes.push(`${unreachable.length} unreachable scopes not enumerated (${unreachable.slice(0, 5).join(", ")}${unreachable.length > 5 ? ", ..." : ""})`);
  }
  if (input.truncated) notes.push(`${input.total} seen, total unknown (inventory incomplete)`);
  return notes.length > 0 ? ` Partial view: ${notes.join("; ")}.` : "";
}

function verdict(input: VerdictInput): GcpFinding {
  const mappings = controlMappings(...input.controls);
  const partial = partialNote(input);
  const isPartial = partial.length > 0;
  const allDenied = (input.deniedProjects ?? 0) > 0 && input.deniedProjects === input.scannedProjects;
  const allDisabled = (input.apiDisabledProjects ?? 0) > 0 && input.apiDisabledProjects === input.scannedProjects;
  const unreadable = [...(input.inventoryError ? [input.inventoryError] : []), ...(input.unreadable ?? [])];
  /** Per-project scan status is a value only when at least one project was attempted; a scan of nothing reports null. */
  const perProjectStatus = input.scannedProjects === undefined
    ? {}
    : {
        denied_projects: input.scannedProjects > 0 ? input.deniedProjects ?? 0 : null,
        unreachable_scopes: input.unreachableScopes === null || input.scannedProjects === 0 ? null : (input.unreachableScopes ?? []).slice(0, 25),
      };
  const evidence = {
    ...input.evidence,
    seen: input.seen === undefined ? input.total : input.seen,
    truncated: input.truncated,
    ...perProjectStatus,
    unreadable_inventories: unreadable,
  };
  const base = { id: input.id, title: input.title, severity: input.severity, mappings, controls: input.controls, evidence };
  const unseen = { ...base, evidence: { ...evidence, seen: null } };

  if (input.inventoryError) {
    return {
      ...unseen,
      status: "manual",
      summary: `Manual: ${input.inventoryError.dataset} unreadable for ${input.inventoryError.scope} via ${input.inventoryError.endpoint} (${input.inventoryError.error}). Collect manually: ${input.manualEvidence}`,
    };
  }
  if (input.scannedProjects === 0) {
    return {
      ...unseen,
      status: "manual",
      summary: `Manual: no projects were inventoried in the scope, so per-project evidence could not be collected. Collect manually: ${input.manualEvidence}`,
    };
  }
  if (input.total === 0 && (allDenied || allDisabled)) {
    const dataset = input.inventory?.dataset ?? "the inventory";
    return {
      ...unseen,
      status: "manual",
      summary: `Manual: ${allDenied ? `every sampled project denied the read of ${dataset}${input.inventory ? ` (${input.inventory.endpoint})` : ""}` : `the API serving ${dataset} is not enabled in any sampled project`}.${partial} Collect manually: ${input.manualEvidence}`,
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
    return { ...base, status: "warn", summary: `${input.unknownSummary ?? `${input.unknown} of ${input.total} items lacked the documented flag needed to confirm compliance.`}${partial}` };
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
  /** Set when the project inventory itself was unreadable; every finding in the scope depends on it. */
  unreadable: UnreadableInventory[];
}

async function loadProjectContext(
  client: Pick<GcpAuditorClient, "listProjectInventory">,
  maxProjects: number,
): Promise<ProjectContext> {
  const inventory = await attempt(() => client.listProjectInventory(maxProjects), { projects: [], truncated: false });
  const projectIds = inventory.data.projects
    .map((resource) => asString(summarizeProject(resource).projectId))
    .filter((value): value is string => Boolean(value));
  return {
    projectIds,
    truncated: inventory.data.truncated,
    error: inventory.error,
    unreadable: unreadableCollected(GCP_INVENTORIES.projects, inventory, "the configured scope"),
  };
}

/** Shared verdict inputs for a finding computed from one primary per-project scan plus any dependent scans. */
function scanVerdictBase(context: ProjectContext, primary: ProjectScan<unknown>, ...dependent: ProjectScan<unknown>[]) {
  const scans = [primary, ...dependent];
  return {
    inventory: primary.inventory,
    inventoryError: context.unreadable[0],
    deniedProjects: primary.denied.length,
    scannedProjects: context.projectIds.length,
    apiDisabledProjects: primary.apiDisabled.length,
    truncated: anyTruncated([projectsTruncated(context), ...scans.map(scanTruncation)]),
    unreachableScopes: unreachableScopesOf(scans),
    unreadable: unreadableScans(...scans),
  };
}

/** A marker written in place of a dataset that was denied or never collected, so a snapshot never shows [] for data that was not read. */
function snapshotMarker(entry: UnreadableInventory): JsonRecord {
  return { status: entry.status, dataset: entry.dataset, endpoint: entry.endpoint, scope: entry.scope, error: entry.error, data: null };
}

/** The projected rows of a per-project dataset when any project answered, otherwise the marker naming why nothing was read. */
function snapshotScan(scan: ProjectScan<unknown>, rows: unknown[]): unknown {
  return scanReadable(scan) ? rows : snapshotMarker(unreadableScans(scan)[0]);
}

/** The projected value of an organization-scoped dataset, or the marker naming the failed read. */
function snapshotCollected(inventory: GcpInventory, collected: Collected<unknown>, value: unknown, scope?: string): unknown {
  return collected.error ? snapshotMarker(unreadableCollected(inventory, collected, scope)[0]) : value;
}

/** The sampled project IDs, or the marker for a project inventory that could not be read. */
function snapshotProjects(context: ProjectContext): unknown {
  return context.error ? snapshotMarker(context.unreadable[0]) : context.projectIds;
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
    surface("log_sinks", "logging", () => client.listLogSinks(requireProject()), (value) => asArray(asObject(value)?.items).length),
    surface("security_command_center", "securitycenter", () => client.listSccSources(), (value) => asArray(asObject(value)?.items).length),
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

/*
 * Snapshot projections. Bundles and finding evidence never carry whole API
 * resources: metadata items, labels, annotations, descriptions, filters, key
 * material, and any other free-form value stay out, and each projection keeps
 * only the documented fields the verdicts read plus resource identifiers.
 */

function snapshotIamPolicy(result: JsonRecord): JsonRecord {
  return {
    resource: asString(result.resource) ?? null,
    assetType: asString(result.assetType) ?? null,
    project: asString(result.project) ?? null,
    bindings: parsePolicyBindings(result.policy).map((binding) => ({
      role: asString(binding.role) ?? null,
      members: asArray(binding.members).map(asString).filter((member): member is string => Boolean(member)),
    })),
  };
}

function snapshotOrganization(organization: JsonRecord | null | undefined): JsonRecord | null {
  if (!organization) return null;
  return {
    name: asString(organization.name) ?? null,
    displayName: asString(organization.displayName) ?? null,
    lifecycleState: asString(organization.lifecycleState) ?? null,
  };
}

function snapshotOrgPolicy(policyResponse: JsonRecord | null | undefined): JsonRecord | null {
  if (!policyResponse) return null;
  const policy = asObject(policyResponse.policy) ?? policyResponse;
  const booleanPolicy = asObject(policy.booleanPolicy);
  const listPolicy = asObject(policy.listPolicy);
  return {
    constraint: asString(policy.constraint) ?? null,
    enforced: interpretOrgPolicyEnabled(policyResponse),
    booleanPolicy: booleanPolicy ? { enforced: booleanPolicy.enforced === true } : null,
    listPolicy: listPolicy
      ? {
          allValues: asString(listPolicy.allValues) ?? null,
          allowedValues: stringList(listPolicy.allowedValues),
          deniedValues: stringList(listPolicy.deniedValues),
        }
      : null,
    restoreDefault: Boolean(asObject(policy.restoreDefault)),
  };
}

/** Documented string[] constraint values such as directory customer IDs or cipher names; never credentials. */
function stringList(value: unknown): string[] {
  return asArray(value).map(asString).filter((entry): entry is string => Boolean(entry));
}

function snapshotShieldedConfig(config: JsonRecord | undefined): JsonRecord | null {
  if (!config) return null;
  return {
    enableSecureBoot: config.enableSecureBoot === true,
    enableVtpm: config.enableVtpm === true,
    enableIntegrityMonitoring: config.enableIntegrityMonitoring === true,
  };
}

function resolvedMetadataFlag(metadata: unknown, key: string): boolean | null {
  const value = metadataValue(metadata, key);
  return value === undefined ? null : isTruthyMetadata(value);
}

function snapshotComputeProject(row: ProjectScanRow<JsonRecord>): JsonRecord {
  return {
    projectId: row.projectId,
    name: asString(row.data.name) ?? null,
    enable_oslogin: resolvedMetadataFlag(row.data.commonInstanceMetadata, "enable-oslogin"),
  };
}

function snapshotGuardrailInstance(instance: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: instance.projectId,
    name: asString(instance.name) ?? null,
    enable_oslogin: resolvedMetadataFlag(instance.metadata, "enable-oslogin"),
    serial_port_enable: resolvedMetadataFlag(instance.metadata, "serial-port-enable"),
    shieldedInstanceConfig: snapshotShieldedConfig(asObject(instance.shieldedInstanceConfig)),
  };
}

function snapshotBinaryAuthorization(row: ProjectScanRow<JsonRecord>): JsonRecord {
  return {
    projectId: row.projectId,
    name: asString(row.data.name) ?? null,
    rules: binaryAuthorizationRules(row.data).map(({ scope, rule }) => ({
      rule: scope,
      evaluationMode: asString(rule?.evaluationMode) ?? null,
      enforcementMode: asString(rule?.enforcementMode) ?? null,
    })),
  };
}

function snapshotLoggingSettings(row: ProjectScanRow<JsonRecord>): JsonRecord {
  return { projectId: row.projectId, name: asString(row.data.name) ?? null };
}

/** GCP_DOCS.sinksList: LogSink.disabled true means the sink exports no log entries, so it never counts toward coverage. */
function sinkDisabled(sink: JsonRecord): boolean {
  return sink.disabled === true;
}

function snapshotLogSinks(row: ProjectScanRow<GcpListResult>): JsonRecord {
  return {
    projectId: row.projectId,
    truncated: row.data.truncated,
    sinks: row.data.items.map((sink) => ({
      name: asString(sink.name) ?? null,
      destination: asString(sink.destination) ?? null,
      disabled: sinkDisabled(sink),
    })),
  };
}

function snapshotLogBuckets(row: ProjectScanRow<GcpListResult>): JsonRecord {
  return {
    projectId: row.projectId,
    truncated: row.data.truncated,
    buckets: row.data.items.map((bucket) => ({
      name: asString(bucket.name) ?? null,
      retentionDays: asNumber(bucket.retentionDays) ?? null,
    })),
  };
}

function snapshotSccSource(source: JsonRecord): JsonRecord {
  return { name: asString(source.name) ?? null, displayName: asString(source.displayName) ?? null };
}

function snapshotStorageBucket(bucket: JsonRecord & { projectId: string }): JsonRecord {
  const iamConfiguration = asObject(bucket.iamConfiguration);
  return {
    projectId: bucket.projectId,
    name: asString(bucket.name) ?? null,
    uniformBucketLevelAccess: asObject(iamConfiguration?.uniformBucketLevelAccess)?.enabled === true,
    publicAccessPrevention: asString(iamConfiguration?.publicAccessPrevention) ?? null,
    defaultKmsKeyName: asString(asObject(bucket.encryption)?.defaultKmsKeyName) ?? null,
  };
}

function snapshotCryptoKey(key: JsonRecord): JsonRecord {
  return {
    name: asString(key.name) ?? null,
    purpose: asString(key.purpose) ?? null,
    rotationPeriod: asString(key.rotationPeriod) ?? null,
    nextRotationTime: asString(key.nextRotationTime) ?? null,
    primaryState: asString(asObject(key.primary)?.state) ?? null,
  };
}

function snapshotDisk(disk: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: disk.projectId,
    name: asString(disk.name) ?? null,
    kmsKeyName: asString(asObject(disk.diskEncryptionKey)?.kmsKeyName) ?? null,
  };
}

function snapshotManagedZone(zone: JsonRecord & { projectId: string }): JsonRecord {
  const dnssec = asObject(zone.dnssecConfig);
  return {
    projectId: zone.projectId,
    name: asString(zone.name) ?? null,
    dnsName: asString(zone.dnsName) ?? null,
    visibility: asString(zone.visibility) ?? null,
    dnssecState: asString(dnssec?.state) ?? null,
    defaultKeySpecs: asObjectArray(dnssec?.defaultKeySpecs).map((spec) => ({
      keyType: asString(spec.keyType) ?? null,
      algorithm: asString(spec.algorithm) ?? null,
    })),
  };
}

/** API keys keep name, displayName, and the documented restriction sub-objects; keyString is never copied. */
function snapshotApiKey(key: JsonRecord & { projectId: string }): JsonRecord {
  const restrictions = asObject(key.restrictions);
  return {
    projectId: key.projectId,
    name: asString(key.name) ?? null,
    displayName: asString(key.displayName) ?? null,
    restrictions: {
      apiTargets: asObjectArray(restrictions?.apiTargets).map((target) => ({
        service: asString(target.service) ?? null,
        methods: asArray(target.methods).map(asString).filter((method): method is string => Boolean(method)),
      })),
      browserKeyRestrictions: asObject(restrictions?.browserKeyRestrictions)
        ? { allowedReferrers: asArray(asObject(restrictions?.browserKeyRestrictions)?.allowedReferrers).length }
        : null,
      serverKeyRestrictions: asObject(restrictions?.serverKeyRestrictions)
        ? { allowedIps: asArray(asObject(restrictions?.serverKeyRestrictions)?.allowedIps).length }
        : null,
      androidKeyRestrictions: asObject(restrictions?.androidKeyRestrictions)
        ? { allowedApplications: asArray(asObject(restrictions?.androidKeyRestrictions)?.allowedApplications).length }
        : null,
      iosKeyRestrictions: asObject(restrictions?.iosKeyRestrictions)
        ? { allowedBundleIds: asArray(asObject(restrictions?.iosKeyRestrictions)?.allowedBundleIds).length }
        : null,
    },
  };
}

function snapshotServicePerimeter(perimeter: JsonRecord): JsonRecord {
  const status = asObject(perimeter.status);
  return {
    name: asString(perimeter.name) ?? null,
    perimeterType: asString(perimeter.perimeterType) ?? null,
    status: status
      ? { resources: asArray(status.resources).length, restrictedServices: asArray(status.restrictedServices).length }
      : null,
    dryRunSpec: Boolean(asObject(perimeter.spec)),
  };
}

function snapshotFirewall(rule: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: rule.projectId,
    name: asString(rule.name) ?? null,
    network: asString(rule.network) ?? null,
    direction: asString(rule.direction) ?? null,
    disabled: rule.disabled === true,
    priority: asNumber(rule.priority) ?? null,
    sourceRanges: asArray(rule.sourceRanges).map(asString).filter((range): range is string => Boolean(range)),
    allowed: asObjectArray(rule.allowed).map((entry) => ({
      IPProtocol: asString(entry.IPProtocol) ?? null,
      ports: asArray(entry.ports).map(asString).filter((port): port is string => Boolean(port)),
    })),
  };
}

function snapshotSubnetwork(subnet: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: subnet.projectId,
    name: asString(subnet.name) ?? null,
    region: lastSegment(subnet.region) ?? null,
    network: lastSegment(subnet.network) ?? null,
    purpose: asString(subnet.purpose) ?? null,
    flowLogsEnabled: flowLogsEnabled(subnet),
    privateIpGoogleAccess: subnet.privateIpGoogleAccess === true,
  };
}

function snapshotRouter(router: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: router.projectId,
    name: asString(router.name) ?? null,
    region: lastSegment(router.region) ?? null,
    network: lastSegment(router.network) ?? null,
    nats: asObjectArray(router.nats).map((nat) => ({
      name: asString(nat.name) ?? null,
      sourceSubnetworkIpRangesToNat: asString(nat.sourceSubnetworkIpRangesToNat) ?? null,
      subnetworks: asObjectArray(nat.subnetworks).map((entry) => computeResourcePath(entry.name) ?? null),
    })),
  };
}

function snapshotNetworkInstance(instance: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: instance.projectId,
    name: asString(instance.name) ?? null,
    networkInterfaces: asObjectArray(instance.networkInterfaces).map((nic) => ({
      network: lastSegment(nic.network) ?? null,
      subnetwork: lastSegment(nic.subnetwork) ?? null,
      accessConfigs: asObjectArray(nic.accessConfigs).length,
      ipv6AccessConfigs: asObjectArray(nic.ipv6AccessConfigs).length,
    })),
  };
}

function snapshotSslPolicy(policy: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: policy.projectId,
    path: sslPolicyPath(policy) ?? null,
    name: asString(policy.name) ?? null,
    minTlsVersion: asString(policy.minTlsVersion) ?? null,
    profile: asString(policy.profile) ?? null,
    customFeatures: stringList(policy.customFeatures),
  };
}

function snapshotHttpsProxy(proxy: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: proxy.projectId,
    name: asString(proxy.name) ?? null,
    region: lastSegment(proxy.region) ?? null,
    sslPolicy: attachedSslPolicyPath(proxy) ?? null,
  };
}

function snapshotBackendService(backend: JsonRecord & { projectId: string }): JsonRecord {
  return {
    projectId: backend.projectId,
    name: asString(backend.name) ?? null,
    loadBalancingScheme: asString(backend.loadBalancingScheme) ?? null,
    protocol: asString(backend.protocol) ?? null,
    securityPolicy: computeResourcePath(backend.securityPolicy) ?? null,
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
  const accountScan = await scanProjects(context, GCP_INVENTORIES.serviceAccounts, (projectId) => client.listServiceAccounts(projectId));

  const staleKeys: JsonRecord[] = [];
  const undatedKeys: JsonRecord[] = [];
  const userManagedKeys: JsonRecord[] = [];
  const keyErrors: Array<{ projectId: string; error: string }> = [];
  let serviceAccountCount = 0;
  let keyListsAttempted = 0;
  let keyInventoryTruncated = false;

  for (const row of accountScan.rows) {
    for (const serviceAccount of row.data.items) {
      serviceAccountCount += 1;
      const email = asString(serviceAccount.email);
      if (!email) continue;
      if (userManagedKeys.length >= maxKeys) {
        keyInventoryTruncated = true;
        break;
      }
      keyListsAttempted += 1;
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
    inventory: GCP_INVENTORIES.iamPolicies,
    inventoryError: unreadableCollected(GCP_INVENTORIES.iamPolicies, iamPolicies)[0],
    unreadable: context.unreadable,
    truncated: anyTruncated([projectsTruncated(context), collectedTruncation(iamPolicies)]),
    emptyVerdict: "manual" as const,
    emptySummary: "Cloud Asset Inventory returned no IAM policies for the scope; an org or project always carries at least one binding, so treat this as a denied or empty scope.",
    manualEvidence: "export the IAM policy bindings for the organization, folders, and projects and review privileged roles.",
  };
  const keyErrorProjects = [...new Set(keyErrors.map((entry) => entry.projectId))];
  const keyReadsUnreadable: UnreadableInventory[] = keyErrors.length > 0
    ? [{
        ...GCP_INVENTORIES.serviceAccountKeys,
        scope: `${keyErrors.length} of ${keyListsAttempted} service accounts (${keyErrorProjects.slice(0, 3).join(", ")}${keyErrorProjects.length > 3 ? ", ..." : ""})`,
        status: "unreadable",
        error: keyErrors[0].error,
      }]
    : [];
  const keysReadable = keyListsAttempted === 0 || keyErrors.length < keyListsAttempted;
  /** Key lists are values only when the account list they hang off was readable and not every key read failed. */
  const keyList = <T>(value: T): T | null => jointValue([scanReadable(accountScan), keysReadable], value);
  const keyTruncation: boolean | null = keyInventoryTruncated ? true : keyList(false);
  const accountBase = scanVerdictBase(context, accountScan);
  /** Key lists were never requested when no account list arrived, and unreadable when every requested list failed. */
  const keysUnreadable: UnreadableInventory | undefined = !scanReadable(accountScan)
    ? notCollected(GCP_INVENTORIES.serviceAccountKeys, "the scope", `no service account could be listed because ${accountScan.notAttempted ?? `${GCP_INVENTORIES.serviceAccounts.dataset} were unreadable via ${GCP_INVENTORIES.serviceAccounts.endpoint} (${shortError(accountScan.denied[0]?.error ?? "")})`}`)
    : keysReadable
      ? undefined
      : keyReadsUnreadable[0];
  const keyBase = {
    ...accountBase,
    inventoryError: accountBase.inventoryError ?? (keysReadable ? undefined : keyReadsUnreadable[0]),
    truncated: anyTruncated([projectsTruncated(context), scanTruncation(accountScan), keyTruncation]),
    /** The key lists are part of the scan these findings describe, so their status is unknown when every key read failed. */
    unreachableScopes: keysReadable ? accountBase.unreachableScopes : null,
    unreadable: [
      ...unreadableScans(accountScan),
      ...(keysUnreadable?.status === "not_collected" ? [keysUnreadable] : []),
      ...(keysReadable ? keyReadsUnreadable : []),
    ],
  };

  const findings: GcpFinding[] = [
    verdict({
      ...policyBase,
      id: "GCP-IAM-01",
      title: "Privileged IAM bindings",
      severity: "high",
      controls: [2],
      evidence: { bindings: collectedValue(iamPolicies, privilegedBindings.slice(0, 25)), policies_scanned: collectedValue(iamPolicies, iamPolicies.data.items.length) },
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
          { sampled_projects: sampledProjects(context), project_error: context.error ?? null, unreadable_inventories: unreadableScans(accountScan) },
        )
      : verdict({
          ...keyBase,
          id: "GCP-IAM-02",
          title: "Service account key rotation",
          severity: "high",
          controls: [1],
          evidence: { stale_keys: keyList(staleKeys.slice(0, 25)), undated_keys: keyList(undatedKeys.slice(0, 25)), service_accounts: readableValue(accountScan, serviceAccountCount) },
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
      evidence: { user_managed_keys: keyList(userManagedKeys.slice(0, 25)), service_accounts: readableValue(accountScan, serviceAccountCount) },
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
      evidence: { cross_project_bindings: collectedValue(iamPolicies, crossProjectBindings.slice(0, 25)) },
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
      evidence: { privileged_default_service_accounts: collectedValue(iamPolicies, privilegedDefaultServiceAccounts.slice(0, 25)) },
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
      sampled_projects: sampledProjects(context),
      projects_truncated: projectsTruncated(context),
      iam_policies: collectedValue(iamPolicies, iamPolicies.data.items.length),
      service_accounts: readableValue(accountScan, serviceAccountCount),
      privileged_bindings: collectedValue(iamPolicies, privilegedBindings.length),
      stale_service_account_keys: keyList(staleKeys.length),
      undated_service_account_keys: keyList(undatedKeys.length),
      user_managed_service_account_keys: keyList(userManagedKeys.length),
      cross_project_service_accounts: collectedValue(iamPolicies, crossProjectBindings.length),
      privileged_default_service_accounts: collectedValue(iamPolicies, privilegedDefaultServiceAccounts.length),
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: snapshotProjects(context),
      iam_policies: snapshotCollected(GCP_INVENTORIES.iamPolicies, iamPolicies, iamPolicies.data.items.map(snapshotIamPolicy)),
      service_accounts: snapshotScan(accountScan, accountScan.rows.map((row) => ({
        projectId: row.projectId,
        truncated: row.data.truncated,
        accounts: row.data.items.map((account) => asString(account.email) ?? null),
      }))),
      user_managed_keys: keysUnreadable ? snapshotMarker(keysUnreadable) : userManagedKeys,
      unreadable_inventories: [
        ...context.unreadable,
        ...unreadableCollected(GCP_INVENTORIES.iamPolicies, iamPolicies),
        ...unreadableScans(accountScan),
        ...(keysUnreadable?.status === "not_collected" ? [keysUnreadable] : []),
        ...keyReadsUnreadable,
      ],
    },
  };
}

export async function assessGcpLoggingDetection(
  client: Pick<
    GcpAuditorClient,
    | "getResolvedConfig"
    | "listProjectInventory"
    | "getLoggingSettings"
    | "listLogSinks"
    | "listLogBuckets"
    | "listRecentAdminActivity"
    | "listRecentDataAccess"
    | "listSccSources"
    | "listSccFindings"
  >,
  options: { maxProjects?: number; maxFindings?: number } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 500);
  const maxFindings = clampNumber(options.maxFindings, DEFAULT_MAX_FINDINGS, 1, 5000);
  const config = client.getResolvedConfig();
  const context = await loadProjectContext(client, maxProjects);

  const adminScan = await scanProjects(context, GCP_INVENTORIES.adminActivity, (projectId) => client.listRecentAdminActivity(projectId));
  const dataAccessScan = await scanProjects(context, GCP_INVENTORIES.dataAccess, (projectId) => client.listRecentDataAccess(projectId));
  const sinkScan = await scanProjects(context, GCP_INVENTORIES.sinks, (projectId) => client.listLogSinks(projectId));
  const bucketScan = await scanProjects(context, GCP_INVENTORIES.logBuckets, (projectId) => client.listLogBuckets(projectId));
  const settingsScan = await scanProjects(context, GCP_INVENTORIES.loggingSettings, (projectId) => client.getLoggingSettings(projectId));
  /** Security Command Center is organization-scoped: without an organization ID neither list is requested. */
  const sccScoped = Boolean(config.organizationId);
  const sccSources: Collected<GcpListResult> = sccScoped ? await attempt(() => client.listSccSources(), EMPTY_LIST) : { data: EMPTY_LIST, truncated: false };
  const sccFindings: Collected<GcpListResult> = sccScoped ? await attempt(() => client.listSccFindings(maxFindings), EMPTY_LIST) : { data: EMPTY_LIST, truncated: false };
  const sccNotCollected = sccScoped
    ? []
    : [GCP_INVENTORIES.sccSources, GCP_INVENTORIES.sccFindings].map((inventory) => notCollected(inventory, "this run", "Security Command Center is organization-scoped and no organization ID was configured"));
  const sccFindingCount = sccFindings.error || !sccScoped ? null : sccFindings.data.items.length;
  const sccUnreadable = [...unreadableCollected(GCP_INVENTORIES.sccFindings, sccFindings), ...context.unreadable];
  const sccPartialNotes = [
    ...sccUnreadable.map(describeUnreadable),
    ...(sccSources.truncated ? ["the source list was truncated"] : []),
    ...(sccFindings.truncated ? ["the findings list was truncated"] : []),
    ...(context.truncated ? ["the project inventory was truncated by the project cap"] : []),
  ];
  const sccPartialNote = sccPartialNotes.length > 0 ? ` Partial view: ${sccPartialNotes.join("; ")}.` : "";

  const projectsWithoutAdmin = adminScan.rows.filter((row) => row.data.length === 0).map((row) => row.projectId);
  const projectsWithoutDataAccess = dataAccessScan.rows.filter((row) => row.data.length === 0).map((row) => row.projectId);
  const disabledSinks: JsonRecord[] = [];
  const projectsWithoutSinks: string[] = [];
  for (const row of sinkScan.rows) {
    let enabledSinks = 0;
    for (const sink of row.data.items) {
      if (sinkDisabled(sink)) disabledSinks.push({ projectId: row.projectId, sink: asString(sink.name) ?? null, destination: asString(sink.destination) ?? null });
      else enabledSinks += 1;
    }
    if (enabledSinks === 0) projectsWithoutSinks.push(row.projectId);
  }

  const shortRetention: JsonRecord[] = [];
  const unknownRetention: JsonRecord[] = [];
  let bucketCount = 0;
  for (const row of bucketScan.rows) {
    for (const bucket of row.data.items) {
      const name = asString(bucket.name) ?? "";
      if (name.endsWith("/buckets/_Required")) continue;
      bucketCount += 1;
      const retention = asNumber(bucket.retentionDays);
      if (retention === undefined) unknownRetention.push({ projectId: row.projectId, bucket: name });
      else if (retention < MIN_LOG_RETENTION_DAYS) shortRetention.push({ projectId: row.projectId, bucket: name, retentionDays: retention });
    }
  }

  const scanBase = (scan: ProjectScan<unknown>) => scanVerdictBase(context, scan);

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(adminScan),
      id: "GCP-LOG-01",
      title: "Admin Activity visibility",
      severity: "medium",
      controls: [5],
      evidence: { projects_without_admin_activity: readableValue(adminScan, projectsWithoutAdmin.slice(0, 25)), projects_read: readableValue(adminScan, adminScan.rows.length) },
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
      evidence: { projects_without_data_access: readableValue(dataAccessScan, projectsWithoutDataAccess.slice(0, 25)), projects_read: readableValue(dataAccessScan, dataAccessScan.rows.length) },
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
      evidence: { projects_without_sinks: readableValue(sinkScan, projectsWithoutSinks.slice(0, 25)), disabled_sinks: readableValue(sinkScan, disabledSinks.slice(0, 25)), projects_read: readableValue(sinkScan, sinkScan.rows.length) },
      total: sinkScan.rows.length,
      violations: projectsWithoutSinks.length,
      emptyVerdict: "manual",
      passSummary: `Every one of ${sinkScan.rows.length} sampled projects has at least one enabled log sink${disabledSinks.length > 0 ? ` (${disabledSinks.length} disabled sinks were not counted)` : ""}.`,
      failSummary: `${projectsWithoutSinks.length} of ${sinkScan.rows.length} sampled projects have no enabled log sink${disabledSinks.length > 0 ? ` (${disabledSinks.length} sinks are disabled and export nothing)` : ""}.`,
      emptySummary: "No projects were available for log sink sampling.",
      manualEvidence: "list log sinks per project and at the organization level and confirm each sink's disabled flag is not set.",
    }),
    verdict({
      ...scanBase(bucketScan),
      id: "GCP-LOG-04",
      title: "Log bucket retention",
      severity: "medium",
      controls: [5],
      evidence: { short_retention_buckets: readableValue(bucketScan, shortRetention.slice(0, 25)), unknown_retention_buckets: readableValue(bucketScan, unknownRetention.slice(0, 25)), buckets_read: readableValue(bucketScan, bucketCount) },
      total: bucketCount,
      violations: shortRetention.length,
      unknown: unknownRetention.length,
      emptyVerdict: "manual",
      passSummary: `All ${bucketCount} configurable log buckets retain logs for at least ${MIN_LOG_RETENTION_DAYS} days (the fixed 400-day _Required bucket is excluded).`,
      failSummary: `${shortRetention.length} of ${bucketCount} configurable log buckets retain logs for fewer than ${MIN_LOG_RETENTION_DAYS} days (the fixed 400-day _Required bucket is excluded).`,
      emptySummary: "No configurable log buckets were listed; every project exposes a _Default bucket, so an empty list indicates a denied read.",
      manualEvidence: "read retentionDays on each project's _Default and custom log buckets.",
    }),
    !sccScoped
      ? manualFinding(
          "GCP-LOG-05",
          "Security Command Center visibility",
          "info",
          [5],
          `${describeUnreadableAll(sccNotCollected)}. This finding is visibility only and does not score a control.`,
          "confirm Security Command Center tier and export findings from the console.",
          {
            scc_sources: null,
            sources_truncated: null,
            scc_findings: null,
            findings_truncated: null,
            unreadable_inventories: [...sccNotCollected, ...context.unreadable],
          },
        )
      : sccSources.error
      ? manualFinding(
          "GCP-LOG-05",
          "Security Command Center visibility",
          "info",
          [5],
          `${GCP_INVENTORIES.sccSources.dataset} were not readable via ${GCP_INVENTORIES.sccSources.endpoint} (${sccSources.error}). This finding is visibility only and does not score a control.`,
          "confirm Security Command Center tier and export findings from the console.",
          {
            scc_sources: null,
            sources_truncated: null,
            scc_findings: sccFindingCount,
            findings_truncated: collectedTruncation(sccFindings),
            unreadable_inventories: [...unreadableCollected(GCP_INVENTORIES.sccSources, sccSources), ...sccUnreadable],
          },
        )
      : {
          id: "GCP-LOG-05",
          title: "Security Command Center visibility",
          severity: "info",
          status: sccSources.data.items.length > 0 && sccPartialNotes.length === 0 ? "pass" : "warn",
          summary: sccSources.data.items.length > 0
            ? `Security Command Center returned ${sccSources.data.items.length}${sccSources.truncated ? "+" : ""} sources and ${sccFindingCount === null ? "an unreadable findings list" : `${sccFindingCount}${sccFindings.truncated ? "+" : ""} findings`}. Visibility only; findings are not scored as controls.${sccPartialNote}${sccPartialNotes.length > 0 ? " A partial view cannot pass." : ""}`
            : `Security Command Center returned no sources for the scope; verify the tier or organization scope. Visibility only.${sccPartialNote}`,
          evidence: {
            scc_sources: sccSources.data.items.length,
            sources_truncated: collectedTruncation(sccSources),
            scc_findings: sccFindingCount,
            findings_truncated: collectedTruncation(sccFindings),
            unreadable_inventories: sccUnreadable,
          },
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
      sampled_projects: sampledProjects(context),
      projects_truncated: projectsTruncated(context),
      projects_with_admin_activity: readableValue(adminScan, adminScan.rows.length - projectsWithoutAdmin.length),
      projects_with_data_access: readableValue(dataAccessScan, dataAccessScan.rows.length - projectsWithoutDataAccess.length),
      projects_with_log_sinks: readableValue(sinkScan, sinkScan.rows.length - projectsWithoutSinks.length),
      disabled_log_sinks: readableValue(sinkScan, disabledSinks.length),
      configurable_log_buckets: readableValue(bucketScan, bucketCount),
      short_retention_buckets: readableValue(bucketScan, shortRetention.length),
      scc_sources: sccScoped ? collectedValue(sccSources, sccSources.data.items.length) : null,
      scc_findings: sccFindingCount,
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: snapshotProjects(context),
      logging_settings: snapshotScan(settingsScan, settingsScan.rows.map(snapshotLoggingSettings)),
      sinks: snapshotScan(sinkScan, sinkScan.rows.map(snapshotLogSinks)),
      log_buckets: snapshotScan(bucketScan, bucketScan.rows.map(snapshotLogBuckets)),
      scc_sources: sccScoped
        ? snapshotCollected(GCP_INVENTORIES.sccSources, sccSources, sccSources.data.items.map(snapshotSccSource))
        : snapshotMarker(sccNotCollected[0]),
      unreadable_inventories: [
        ...context.unreadable,
        ...unreadableScans(settingsScan, sinkScan, bucketScan),
        ...unreadableCollected(GCP_INVENTORIES.sccSources, sccSources),
        ...unreadableCollected(GCP_INVENTORIES.sccFindings, sccFindings),
        ...sccNotCollected,
      ],
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

/** Binary Authorization Policy rule maps (GCP_DOCS.binaryAuthorizationPolicy); each overrides defaultAdmissionRule for its key. */
const BINARY_AUTHORIZATION_RULE_MAPS = [
  "clusterAdmissionRules",
  "kubernetesNamespaceAdmissionRules",
  "kubernetesServiceAccountAdmissionRules",
  "istioServiceIdentityAdmissionRules",
] as const;

function binaryAuthorizationRules(policy: JsonRecord): Array<{ scope: string; rule: JsonRecord | undefined }> {
  const rules: Array<{ scope: string; rule: JsonRecord | undefined }> = [
    { scope: "defaultAdmissionRule", rule: asObject(policy.defaultAdmissionRule) },
  ];
  for (const mapName of BINARY_AUTHORIZATION_RULE_MAPS) {
    for (const [key, rule] of Object.entries(asObject(policy[mapName]) ?? {})) {
      rules.push({ scope: `${mapName}[${key}]`, rule: asObject(rule) });
    }
  }
  return rules;
}

/** How far the sampled project's effective policy can be generalised to the scope. */
interface OrgPolicyView {
  partial: boolean;
  note: string;
  unreadable: UnreadableInventory[];
}

function orgPolicyView(context: ProjectContext, targetProjectId: string | undefined): OrgPolicyView {
  if (context.unreadable.length > 0) {
    const entry = context.unreadable[0];
    return {
      partial: true,
      unreadable: context.unreadable,
      note: ` Partial view: ${describeUnreadable(entry)}, so the effective policy was resolved only for the configured project ${targetProjectId ?? "(none)"} and other projects in the scope may differ. A partial view cannot pass.`,
    };
  }
  if (context.truncated) {
    return { partial: true, unreadable: [], note: " Partial view: the project inventory was truncated, so other projects may resolve a different effective policy. A partial view cannot pass." };
  }
  return { partial: false, unreadable: [], note: "" };
}

interface OrgPolicyRead {
  constraint: string;
  policy: Collected<JsonRecord | null>;
  unreadable: UnreadableInventory[];
}

/** The projected effective policy, or the marker naming why the read failed or was not attempted. */
function snapshotPolicyRead(read: OrgPolicyRead): JsonRecord | null {
  const entry = read.unreadable[0];
  return entry ? snapshotMarker(entry) : snapshotOrgPolicy(read.policy.data);
}

function orgPolicyFinding(
  id: string,
  title: string,
  severity: GcpFinding["severity"],
  controls: number[],
  read: OrgPolicyRead,
  passSummary: string,
  failSummary: string,
  failStatus: "fail" | "warn",
  manualEvidence: string,
  view: OrgPolicyView,
): GcpFinding {
  if (read.policy.error) {
    const entry = read.unreadable[0];
    /** A not-collected entry already carries the upstream call and its status; only a real request error adds its body. */
    const reason = entry === undefined
      ? `the effective org policy ${read.constraint} was not readable: ${read.policy.error}.`
      : entry.status === "not_collected"
        ? `${describeUnreadable(entry)}.`
        : `${describeUnreadable(entry)}: ${read.policy.error}.`;
    return manualFinding(id, title, severity, controls, reason, manualEvidence, { policy: null, unreadable_inventories: [...read.unreadable, ...view.unreadable] });
  }
  const enabled = interpretOrgPolicyEnabled(read.policy.data);
  return {
    id,
    title,
    severity,
    status: enabled ? (view.partial ? "warn" : "pass") : failStatus,
    summary: enabled ? `${passSummary}${view.note}` : `${failSummary}${view.note}`,
    evidence: { policy: snapshotOrgPolicy(read.policy.data), partial: view.partial, unreadable_inventories: view.unreadable },
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

  /** Without a project the effective policy cannot be computed, so the read is not attempted and names the upstream inventory instead. */
  const policyNotAttempted = `${scanNotAttempted(context) ?? `${GCP_INVENTORIES.projects.dataset} listed no projects in the scope via ${GCP_INVENTORIES.projects.endpoint}`}, so no project was available to compute the effective policy`;
  const readPolicy = async (constraint: string): Promise<OrgPolicyRead> => {
    const inventory = orgPolicyInventory(constraint);
    if (!targetProjectId) {
      return { constraint, policy: { data: null, error: policyNotAttempted, truncated: false }, unreadable: [notCollected(inventory, "the scope", policyNotAttempted)] };
    }
    const policy = await attempt(() => client.getEffectiveOrgPolicy(targetProjectId, constraint), null as JsonRecord | null);
    return { constraint, policy, unreadable: unreadableCollected(inventory, policy, `the sampled project ${targetProjectId}`) };
  };

  const [domainPolicy, keyCreationPolicy, keyUploadPolicy, serialPortPolicy, shieldedVmPolicy, osLoginPolicy] = await Promise.all([
    readPolicy("constraints/iam.allowedPolicyMemberDomains"),
    readPolicy("constraints/iam.disableServiceAccountKeyCreation"),
    readPolicy("constraints/iam.disableServiceAccountKeyUpload"),
    readPolicy("constraints/compute.disableSerialPortAccess"),
    readPolicy("constraints/compute.requireShieldedVm"),
    readPolicy("constraints/compute.requireOsLogin"),
  ]);
  const policyView = orgPolicyView(context, targetProjectId);

  const computeProjectScan = await scanProjects(context, GCP_INVENTORIES.computeProject, (projectId) => client.getComputeProject(projectId));
  const instanceScan = await scanProjects(context, GCP_INVENTORIES.instances, (projectId) => client.listInstances(projectId, maxAssets));
  const binaryAuthScan = await scanProjects(context, GCP_INVENTORIES.binaryAuthorization, (projectId) => client.getBinaryAuthorizationPolicy(projectId));

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
  const orgOsLoginEnforced = !osLoginPolicy.policy.error && interpretOrgPolicyEnabled(osLoginPolicy.policy.data);
  /**
   * constraints/compute.requireOsLogin enables OS Login on newly created projects and
   * rejects metadata updates that disable it; it never enables OS Login on a project or
   * instance that already had the flag absent or FALSE, so metadata is always inspected.
   */
  const osLoginPolicyClause = osLoginPolicy.policy.error
    ? ""
    : orgOsLoginEnforced
      ? " constraints/compute.requireOsLogin is enforced in the effective policy, which protects newly created projects and blocks future disabling but does not enable OS Login on existing resources."
      : " constraints/compute.requireOsLogin is not enforced in the effective policy, so newly created projects will not default to OS Login.";
  const namedOverrides = osLoginOverrides.length > 0
    ? ` (${osLoginOverrides.slice(0, 5).map((entry) => `${entry.projectId}/${entry.instance ?? "?"}`).join(", ")}${osLoginOverrides.length > 5 ? ", ..." : ""})`
    : "";
  const instancesUnreadableClause = `instance overrides could not be checked because ${GCP_INVENTORIES.instances.dataset} were unreadable`;
  const osLoginPassOverrideClause = scanReadable(instanceScan) ? `none of ${instances.length} instances overrides it` : instancesUnreadableClause;
  const osLoginFailOverrideClause = scanReadable(instanceScan) ? `${osLoginOverrides.length} instances override it${namedOverrides}` : instancesUnreadableClause;

  const shieldedViolations: JsonRecord[] = [];
  const shieldedUnknown: JsonRecord[] = [];
  const serialPortViolations: JsonRecord[] = [];
  for (const instance of instances) {
    const shielded = asObject(instance.shieldedInstanceConfig);
    const record = { projectId: instance.projectId, instance: asString(instance.name) };
    if (!shielded) shieldedUnknown.push(record);
    else if (shielded.enableSecureBoot !== true || shielded.enableVtpm !== true || shielded.enableIntegrityMonitoring !== true) {
      shieldedViolations.push({ ...record, shieldedInstanceConfig: snapshotShieldedConfig(shielded) });
    }
    if (isTruthyMetadata(metadataValue(instance.metadata, "serial-port-enable"))) serialPortViolations.push(record);
  }

  const binaryAuthViolations: JsonRecord[] = [];
  const binaryAuthDryRun: JsonRecord[] = [];
  for (const row of binaryAuthScan.rows) {
    for (const { scope, rule } of binaryAuthorizationRules(row.data)) {
      const evaluationMode = asString(rule?.evaluationMode);
      const enforcementMode = asString(rule?.enforcementMode);
      if (evaluationMode !== "REQUIRE_ATTESTATION" && evaluationMode !== "ALWAYS_DENY") {
        binaryAuthViolations.push({ projectId: row.projectId, rule: scope, evaluationMode: evaluationMode ?? null });
      } else if (enforcementMode !== "ENFORCED_BLOCK_AND_AUDIT_LOG") {
        binaryAuthDryRun.push({ projectId: row.projectId, rule: scope, enforcementMode: enforcementMode ?? null });
      }
    }
  }
  const binaryAuthViolatingProjects = new Set(binaryAuthViolations.map((violation) => violation.projectId)).size;

  const scanBase = (scan: ProjectScan<unknown>, ...dependent: ProjectScan<unknown>[]) => scanVerdictBase(context, scan, ...dependent);
  const osLoginBase = scanBase(computeProjectScan, instanceScan);

  const organizationNotCollected = notCollected(GCP_INVENTORIES.organization, "this run", "no organization ID was configured");
  const organizationFinding: GcpFinding = !config.organizationId
    ? manualFinding(
        "GCP-ORG-01",
        "Organization visibility",
        "medium",
        [6],
        "no organization ID was configured, so organization-level guardrails are outside this run's scope and the organization was not collected.",
        "run with GCP_ORGANIZATION_ID set or review organization metadata in the console.",
        { sampled_projects: sampledProjects(context), projects_truncated: projectsTruncated(context), target_project: targetProjectId ?? null, unreadable_inventories: [organizationNotCollected, ...context.unreadable] },
      )
    : organization.error
      ? manualFinding("GCP-ORG-01", "Organization visibility", "medium", [6], `${GCP_INVENTORIES.organization.dataset} was not readable via ${GCP_INVENTORIES.organization.endpoint} (${organization.error}).`, "confirm resourcemanager.organizations.get on the audit principal.", { sampled_projects: sampledProjects(context), unreadable_inventories: [...unreadableCollected(GCP_INVENTORIES.organization, organization), ...context.unreadable] })
      : {
          id: "GCP-ORG-01",
          title: "Organization visibility",
          severity: "medium",
          status: context.error
            ? "manual"
            : context.truncated || context.projectIds.length === 0 || !asString(organization.data?.name)
              ? "warn"
              : "pass",
          summary: context.unreadable[0]
            ? `Manual: organization ${config.organizationId} was readable but the ${describeUnreadable(context.unreadable[0])}: ${context.error}. Collect manually: list projects under the organization.`
            : !asString(organization.data?.name)
              ? `Organization ${config.organizationId} answered without the documented name field; confirm the organization resource manually.`
              : `Organization ${asString(organization.data?.displayName) ?? config.organizationId} was readable and ${context.projectIds.length} projects were sampled${context.truncated ? " (project inventory truncated by the project cap)" : context.projectIds.length === 0 ? " (no projects inventoried)" : ""}.`,
          evidence: { sampled_projects: sampledProjects(context), projects_truncated: projectsTruncated(context), target_project: targetProjectId ?? null, unreadable_inventories: context.unreadable },
          mappings: controlMappings(6),
          controls: [6],
        };

  const computeGuardrailsEnforced = interpretOrgPolicyEnabled(serialPortPolicy.policy.data) && interpretOrgPolicyEnabled(shieldedVmPolicy.policy.data);
  const computeGuardrailsUnreadable = [...serialPortPolicy.unreadable, ...shieldedVmPolicy.unreadable];
  /** A not-collected entry already carries the upstream call and its status; only a real request error adds its body. */
  const computeGuardrailsReason = `${describeUnreadableAll(computeGuardrailsUnreadable)}${computeGuardrailsUnreadable[0]?.status === "unreadable" ? `: ${computeGuardrailsUnreadable[0].error}` : ""}.`;

  const findings: GcpFinding[] = [
    organizationFinding,
    orgPolicyFinding("GCP-ORG-02", "Domain-restricted sharing", "high", [6], domainPolicy,
      "constraints/iam.allowedPolicyMemberDomains is enforced in the effective policy of the sampled project.",
      "constraints/iam.allowedPolicyMemberDomains is not enforced in the effective policy of the sampled project.",
      "warn", "review constraints/iam.allowedPolicyMemberDomains at the organization.", policyView),
    orgPolicyFinding("GCP-ORG-03", "Service account key creation restriction", "high", [6, 1], keyCreationPolicy,
      "constraints/iam.disableServiceAccountKeyCreation is enforced in the effective policy of the sampled project.",
      "constraints/iam.disableServiceAccountKeyCreation is not enforced in the effective policy of the sampled project.",
      "fail", "review constraints/iam.disableServiceAccountKeyCreation at the organization.", policyView),
    orgPolicyFinding("GCP-ORG-04", "Service account key upload restriction", "high", [6, 1], keyUploadPolicy,
      "constraints/iam.disableServiceAccountKeyUpload is enforced in the effective policy of the sampled project.",
      "constraints/iam.disableServiceAccountKeyUpload is not enforced in the effective policy of the sampled project.",
      "warn", "review constraints/iam.disableServiceAccountKeyUpload at the organization.", policyView),
    computeGuardrailsUnreadable.length > 0
      ? manualFinding(
          "GCP-ORG-05",
          "Serial port and Shielded VM guardrails",
          "medium",
          [12, 23],
          computeGuardrailsReason,
          "review constraints/compute.disableSerialPortAccess and constraints/compute.requireShieldedVm.",
          { serial_port_policy: serialPortPolicy.policy.error ? null : snapshotOrgPolicy(serialPortPolicy.policy.data), shielded_vm_policy: shieldedVmPolicy.policy.error ? null : snapshotOrgPolicy(shieldedVmPolicy.policy.data), unreadable_inventories: [...computeGuardrailsUnreadable, ...policyView.unreadable] },
        )
      : {
          id: "GCP-ORG-05",
          title: "Serial port and Shielded VM guardrails",
          severity: "medium",
          status: computeGuardrailsEnforced
            ? (policyView.partial ? "warn" : "pass")
            : interpretOrgPolicyEnabled(serialPortPolicy.policy.data) || interpretOrgPolicyEnabled(shieldedVmPolicy.policy.data)
              ? "warn"
              : "fail",
          summary: computeGuardrailsEnforced
            ? `constraints/compute.disableSerialPortAccess and constraints/compute.requireShieldedVm are both enforced in the effective policy of the sampled project.${policyView.note}`
            : `Compute hardening guardrails missing: ${[!interpretOrgPolicyEnabled(serialPortPolicy.policy.data) && "compute.disableSerialPortAccess", !interpretOrgPolicyEnabled(shieldedVmPolicy.policy.data) && "compute.requireShieldedVm"].filter(Boolean).join(", ")}.${policyView.note}`,
          evidence: { serial_port_policy: snapshotOrgPolicy(serialPortPolicy.policy.data), shielded_vm_policy: snapshotOrgPolicy(shieldedVmPolicy.policy.data), partial: policyView.partial, unreadable_inventories: policyView.unreadable },
          mappings: controlMappings(12, 23),
          controls: [12, 23],
        },
    verdict({
      ...osLoginBase,
      unreadable: [...osLoginBase.unreadable, ...osLoginPolicy.unreadable],
      id: "GCP-ORG-06",
      title: "OS Login enforcement",
      severity: "high",
      controls: [11],
      evidence: {
        policy: osLoginPolicy.policy.error ? null : snapshotOrgPolicy(osLoginPolicy.policy.data),
        policy_enforced: osLoginPolicy.policy.error ? null : orgOsLoginEnforced,
        projects_without_os_login: readableValue(computeProjectScan, projectsWithoutOsLogin.slice(0, 25)),
        instance_overrides: readableValue(instanceScan, osLoginOverrides.slice(0, 25)),
        projects_read: readableValue(computeProjectScan, computeProjectScan.rows.length),
        instances_read: readableValue(instanceScan, instances.length),
      },
      total: computeProjectScan.rows.length,
      violations: projectsWithoutOsLogin.length + osLoginOverrides.length,
      emptyVerdict: "manual",
      passSummary: `enable-oslogin=TRUE is set in commonInstanceMetadata for all ${computeProjectScan.rows.length} sampled projects with Compute Engine and ${osLoginPassOverrideClause}.${osLoginPolicyClause}`,
      failSummary: `${projectsWithoutOsLogin.length} of ${computeProjectScan.rows.length} sampled projects lack enable-oslogin=TRUE in commonInstanceMetadata${projectsWithoutOsLogin.length > 0 ? ` (${projectsWithoutOsLogin.slice(0, 5).join(", ")}${projectsWithoutOsLogin.length > 5 ? ", ..." : ""})` : ""} and ${osLoginFailOverrideClause}.${osLoginPolicyClause}`,
      emptySummary: "No Compute Engine project metadata was readable.",
      manualEvidence: "check enable-oslogin in project and instance metadata for every existing project, and enforce constraints/compute.requireOsLogin for new ones.",
    }),
    verdict({
      ...scanBase(binaryAuthScan),
      id: "GCP-ORG-07",
      title: "Binary Authorization admission policy",
      severity: "medium",
      controls: [8],
      evidence: { permissive_rules: readableValue(binaryAuthScan, binaryAuthViolations.slice(0, 25)), dry_run_rules: readableValue(binaryAuthScan, binaryAuthDryRun.slice(0, 25)), projects_read: readableValue(binaryAuthScan, binaryAuthScan.rows.length) },
      total: binaryAuthScan.rows.length,
      violations: binaryAuthViolations.length,
      unknown: binaryAuthDryRun.length,
      emptyVerdict: "manual",
      passSummary: `All ${binaryAuthScan.rows.length} sampled projects with Binary Authorization enabled require attestation (or deny) with ENFORCED_BLOCK_AND_AUDIT_LOG in the default rule and every per-cluster, namespace, service account, and Istio identity rule.`,
      failSummary: `${binaryAuthViolatingProjects} of ${binaryAuthScan.rows.length} sampled projects carry ${binaryAuthViolations.length} admission rules (default or scoped) that do not require attestation.`,
      emptySummary: "No Binary Authorization policy was readable.",
      manualEvidence: "review the Binary Authorization policy, including cluster and namespace admission rules, for every project running GKE or Cloud Run.",
    }),
    verdict({
      ...scanBase(instanceScan),
      id: "GCP-ORG-08",
      title: "Shielded VM and serial port instance configuration",
      severity: "medium",
      controls: [12, 23],
      evidence: {
        shielded_violations: readableValue(instanceScan, shieldedViolations.slice(0, 25)),
        shielded_unknown: readableValue(instanceScan, shieldedUnknown.slice(0, 25)),
        serial_port_enabled: readableValue(instanceScan, serialPortViolations.slice(0, 25)),
        instances_read: readableValue(instanceScan, instances.length),
      },
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

  const policyReads = [domainPolicy, keyCreationPolicy, keyUploadPolicy, serialPortPolicy, shieldedVmPolicy, osLoginPolicy];
  const policyEnforced = (read: OrgPolicyRead): boolean | null => (read.policy.error ? null : interpretOrgPolicyEnabled(read.policy.data));
  const errors = collectErrors(
    [organization.error, context.error, ...policyReads.map((read) => read.policy.error)],
    computeProjectScan.denied,
    instanceScan.denied,
    binaryAuthScan.denied,
  );
  return {
    title: "GCP organization guardrails",
    category: "org-guardrails",
    summary: {
      sampled_projects: sampledProjects(context),
      projects_truncated: projectsTruncated(context),
      organization_visible: config.organizationId ? collectedValue(organization, Boolean(organization.data)) : null,
      target_project: targetProjectId ?? null,
      domain_restricted_sharing: policyEnforced(domainPolicy),
      service_account_key_creation_disabled: policyEnforced(keyCreationPolicy),
      service_account_key_upload_disabled: policyEnforced(keyUploadPolicy),
      serial_port_disabled: policyEnforced(serialPortPolicy),
      shielded_vm_required: policyEnforced(shieldedVmPolicy),
      os_login_required_by_policy: policyEnforced(osLoginPolicy),
      instances: readableValue(instanceScan, instances.length),
      binary_authorization_projects: readableValue(binaryAuthScan, binaryAuthScan.rows.length),
      binary_authorization_api_disabled: readableValue(binaryAuthScan, binaryAuthScan.apiDisabled.length),
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      organization: config.organizationId
        ? snapshotCollected(GCP_INVENTORIES.organization, organization, snapshotOrganization(organization.data))
        : snapshotMarker(organizationNotCollected),
      projects: snapshotProjects(context),
      effective_policies: {
        allowedPolicyMemberDomains: snapshotPolicyRead(domainPolicy),
        disableServiceAccountKeyCreation: snapshotPolicyRead(keyCreationPolicy),
        disableServiceAccountKeyUpload: snapshotPolicyRead(keyUploadPolicy),
        disableSerialPortAccess: snapshotPolicyRead(serialPortPolicy),
        requireShieldedVm: snapshotPolicyRead(shieldedVmPolicy),
        requireOsLogin: snapshotPolicyRead(osLoginPolicy),
      },
      compute_projects: snapshotScan(computeProjectScan, computeProjectScan.rows.map(snapshotComputeProject)),
      instances: snapshotScan(instanceScan, instances.map(snapshotGuardrailInstance)),
      binary_authorization: snapshotScan(binaryAuthScan, binaryAuthScan.rows.map(snapshotBinaryAuthorization)),
      unreadable_inventories: [
        ...(config.organizationId ? unreadableCollected(GCP_INVENTORIES.organization, organization) : [organizationNotCollected]),
        ...context.unreadable,
        ...policyReads.flatMap((read) => read.unreadable),
        ...unreadableScans(computeProjectScan, instanceScan, binaryAuthScan),
      ],
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

  const bucketScan = await scanProjects(context, GCP_INVENTORIES.buckets, (projectId) => client.listStorageBuckets(projectId, maxAssets));
  const publicBindings = await attempt(() => client.searchPublicIamBindings(maxAssets), EMPTY_LIST);
  const cryptoKeys = await attempt(() => client.listCryptoKeys(maxAssets), EMPTY_LIST);
  const diskScan = await scanProjects(context, GCP_INVENTORIES.disks, (projectId) => client.listDisks(projectId, maxAssets));
  const zoneScan = await scanProjects(context, GCP_INVENTORIES.managedZones, (projectId) => client.listManagedZones(projectId, maxAssets));
  const apiKeyScan = await scanProjects(context, GCP_INVENTORIES.apiKeys, (projectId) => client.listApiKeys(projectId, maxAssets));
  const accessPolicies: Collected<GcpListResult> = config.organizationId
    ? await attempt(() => client.listAccessPolicies(), EMPTY_LIST)
    : { data: EMPTY_LIST, truncated: false };
  const perimeters: JsonRecord[] = [];
  const perimeterErrors: string[] = [];
  const perimetersUnreadable: UnreadableInventory[] = [];
  let perimetersTruncated = false;
  let perimetersReceived = 0;
  for (const policy of accessPolicies.data.items) {
    const name = asString(policy.name);
    if (!name) continue;
    const perimeterList = await attempt(() => client.listServicePerimeters(name), EMPTY_LIST);
    if (perimeterList.error) perimeterErrors.push(perimeterList.error);
    else perimetersReceived += 1;
    perimetersUnreadable.push(...unreadableCollected(GCP_INVENTORIES.servicePerimeters, perimeterList, `access policy ${name}`));
    if (perimeterList.truncated) perimetersTruncated = true;
    perimeters.push(...perimeterList.data.items);
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

  const scanBase = (scan: ProjectScan<unknown>, ...dependent: ProjectScan<unknown>[]) => scanVerdictBase(context, scan, ...dependent);
  const publicBindingsUnreadable = unreadableCollected(GCP_INVENTORIES.publicBindings, publicBindings);
  /** Perimeter data is a value only when the organization-scoped lists were requested and every one arrived. */
  const perimetersReadable = Boolean(config.organizationId) && !accessPolicies.error && perimetersUnreadable.length === 0;
  const perimeterTruncation: boolean | null = perimetersTruncated ? true : perimetersUnreadable.length > 0 ? null : false;
  /** Perimeters hang off the access policy list: never requested without one, unreadable when every list failed. */
  const perimetersMarker: UnreadableInventory | undefined = !config.organizationId
    ? notCollected(GCP_INVENTORIES.servicePerimeters, "this run", "VPC Service Controls perimeters are organization-scoped and no organization ID was configured")
    : accessPolicies.error
      ? notCollected(GCP_INVENTORIES.servicePerimeters, "the organization scope", `no access policy could be listed because ${GCP_INVENTORIES.accessPolicies.dataset} were unreadable via ${GCP_INVENTORIES.accessPolicies.endpoint} (${shortError(accessPolicies.error)})`)
      : perimetersReadable
        ? undefined
        : perimetersUnreadable[0];
  const cmekBucketClause = scanReadable(bucketScan) ? `all ${buckets.length} buckets set encryption.defaultKmsKeyName` : `${GCP_INVENTORIES.buckets.dataset} were unreadable`;
  const cmekDiskClause = scanReadable(diskScan) ? `all ${disks.length} disks set diskEncryptionKey.kmsKeyName` : `${GCP_INVENTORIES.disks.dataset} were unreadable`;
  const cmekFailClauses = [
    scanReadable(bucketScan) ? `${bucketsWithoutCmek.length} of ${buckets.length} buckets` : undefined,
    scanReadable(diskScan) ? `${disksWithoutCmek.length} of ${disks.length} disks` : undefined,
  ].filter((clause): clause is string => clause !== undefined);
  const cmekUnreadableClauses: string[] = [
    ...(scanReadable(bucketScan) ? [] : [GCP_INVENTORIES.buckets.dataset]),
    ...(scanReadable(diskScan) ? [] : [GCP_INVENTORIES.disks.dataset]),
  ];

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(bucketScan),
      id: "GCP-DATA-01",
      title: "Uniform bucket-level access",
      severity: "high",
      controls: [15],
      evidence: { non_uniform_buckets: readableValue(bucketScan, nonUniformBuckets.slice(0, 25)), buckets_read: readableValue(bucketScan, buckets.length) },
      total: buckets.length,
      violations: nonUniformBuckets.length,
      emptyVerdict: "manual",
      passSummary: `All ${buckets.length} buckets enable iamConfiguration.uniformBucketLevelAccess.`,
      failSummary: `${nonUniformBuckets.length} of ${buckets.length} buckets do not enable uniform bucket-level access.`,
      emptySummary: "No Cloud Storage buckets were listed in the sampled projects.",
      manualEvidence: "list buckets per project and check iamConfiguration.uniformBucketLevelAccess.enabled.",
    }),
    verdict({
      ...scanBase(bucketScan),
      inventoryError: publicBindingsUnreadable[0] ?? context.unreadable[0],
      truncated: anyTruncated([projectsTruncated(context), scanTruncation(bucketScan), collectedTruncation(publicBindings)]),
      seen: jointValue([scanReadable(bucketScan), !publicBindings.error], buckets.length + publicBindings.data.items.length),
      id: "GCP-DATA-02",
      title: "Public resource exposure",
      severity: "critical",
      controls: [3],
      evidence: {
        public_bindings: collectedValue(publicBindings, publicResources.slice(0, 25)),
        query: PUBLIC_MEMBER_IAM_QUERY,
        policies_matched: collectedValue(publicBindings, publicBindings.data.items.length),
        buckets_read: readableValue(bucketScan, buckets.length),
      },
      total: buckets.length + publicBindings.data.items.length,
      violations: publicResources.length,
      emptyVerdict: "manual",
      passSummary: `No IAM binding in the scope grants a role to allUsers or allAuthenticatedUsers (${scanReadable(bucketScan) ? `${buckets.length} buckets inventoried` : `${GCP_INVENTORIES.buckets.dataset} were unreadable`}).`,
      failSummary: `${publicResources.length} IAM bindings grant roles to allUsers or allAuthenticatedUsers.`,
      emptySummary: "No buckets or public bindings were inventoried, so exposure could not be evaluated.",
      manualEvidence: "search IAM policies for allUsers and allAuthenticatedUsers members across the organization.",
    }),
    verdict({
      id: "GCP-DATA-03",
      title: "KMS key rotation",
      severity: "medium",
      controls: [7],
      evidence: {
        keys_without_rotation: collectedValue(cryptoKeys, rotationViolations.slice(0, 25)),
        overdue_rotation: collectedValue(cryptoKeys, rotationUnknown.slice(0, 25)),
        keys_read: collectedValue(cryptoKeys, rotatingKeys.length),
      },
      total: rotatingKeys.length,
      violations: rotationViolations.length,
      unknown: rotationUnknown.length,
      inventory: GCP_INVENTORIES.cryptoKeys,
      inventoryError: unreadableCollected(GCP_INVENTORIES.cryptoKeys, cryptoKeys)[0],
      unreadable: context.unreadable,
      truncated: anyTruncated([projectsTruncated(context), collectedTruncation(cryptoKeys)]),
      emptyVerdict: "manual",
      passSummary: `All ${rotatingKeys.length} ENCRYPT_DECRYPT keys rotate automatically within ${MAX_KMS_ROTATION_DAYS} days and have a future nextRotationTime.`,
      failSummary: `${rotationViolations.length} of ${rotatingKeys.length} ENCRYPT_DECRYPT keys lack automatic rotation within ${MAX_KMS_ROTATION_DAYS} days.`,
      emptySummary: "No customer-managed ENCRYPT_DECRYPT keys were found in Cloud Asset Inventory for the scope.",
      manualEvidence: "list Cloud KMS keys per location and review rotationPeriod and nextRotationTime.",
    }),
    verdict({
      ...scanBase(bucketScan, diskScan),
      id: "GCP-DATA-04",
      title: "Customer-managed encryption keys",
      severity: "medium",
      controls: [16],
      evidence: {
        buckets_without_cmek: readableValue(bucketScan, bucketsWithoutCmek.slice(0, 25)),
        disks_without_cmek: readableValue(diskScan, disksWithoutCmek.slice(0, 25)),
        buckets_read: readableValue(bucketScan, buckets.length),
        disks_read: readableValue(diskScan, disks.length),
      },
      total: buckets.length + disks.length,
      seen: jointValue([scanReadable(bucketScan), scanReadable(diskScan)], buckets.length + disks.length),
      violations: bucketsWithoutCmek.length + disksWithoutCmek.length,
      violationStatus: "warn",
      emptyVerdict: "manual",
      passSummary: `${cmekBucketClause.charAt(0).toUpperCase()}${cmekBucketClause.slice(1)} and ${cmekDiskClause}.`,
      failSummary: `${cmekFailClauses.join(" and ")} rely on Google-managed encryption instead of CMEK${cmekUnreadableClauses.length > 0 ? ` (${cmekUnreadableClauses.join(" and ")} were unreadable)` : ""}.`,
      emptySummary: "No buckets or disks were listed in the sampled projects.",
      manualEvidence: "review default KMS keys on buckets and disk encryption keys.",
    }),
    verdict({
      ...scanBase(zoneScan),
      id: "GCP-DATA-05",
      title: "Cloud DNS DNSSEC",
      severity: "medium",
      controls: [17],
      evidence: {
        zones_without_dnssec: readableValue(zoneScan, dnssecViolations.slice(0, 25)),
        public_zones: readableValue(zoneScan, publicZones.length),
        private_zones: readableValue(zoneScan, zones.length - publicZones.length),
      },
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
      evidence: { unrestricted_keys: readableValue(apiKeyScan, unrestrictedKeys.slice(0, 25)), keys_read: readableValue(apiKeyScan, apiKeys.length) },
      total: apiKeys.length,
      violations: unrestrictedKeys.length,
      emptyVerdict: "pass",
      passSummary: `All ${apiKeys.length} API keys define restrictions.apiTargets and an application restriction.`,
      failSummary: `${unrestrictedKeys.length} of ${apiKeys.length} API keys lack API target or application restrictions.`,
      emptySummary: `No API keys exist in the ${apiKeyScan.rows.length} sampled projects where the API Keys API answered.`,
      manualEvidence: "list API keys per project and review restrictions.",
    }),
    !config.organizationId
      ? manualFinding(
          "GCP-DATA-07",
          "VPC Service Controls perimeters",
          "medium",
          [21],
          "VPC Service Controls perimeters are organization-scoped and no organization ID was configured, so access policies and perimeters were not collected.",
          "review Access Context Manager perimeters at the organization.",
          {
            enforced_perimeters: null,
            dry_run_only_perimeters: null,
            access_policies: null,
            unreadable_inventories: [
              notCollected(GCP_INVENTORIES.accessPolicies, "this run", "VPC Service Controls perimeters are organization-scoped and no organization ID was configured"),
              ...(perimetersMarker ? [perimetersMarker] : []),
            ],
          },
        )
      : verdict({
          id: "GCP-DATA-07",
          title: "VPC Service Controls perimeters",
          severity: "medium",
          controls: [21],
          evidence: {
            enforced_perimeters: jointValue([perimetersReadable], enforcedPerimeters.map((perimeter) => ({ name: asString(perimeter.name), resources: asArray(asObject(perimeter.status)?.resources).length, restrictedServices: asArray(asObject(perimeter.status)?.restrictedServices).length })).slice(0, 25)),
            dry_run_only_perimeters: jointValue([perimetersReadable], dryRunOnlyPerimeters.map((perimeter) => asString(perimeter.name)).slice(0, 25)),
            access_policies: collectedValue(accessPolicies, accessPolicies.data.items.length),
          },
          total: accessPolicies.data.items.length,
          violations: enforcedPerimeters.length === 0 ? 1 : 0,
          violationStatus: "warn",
          unknown: dryRunOnlyPerimeters.length,
          inventory: GCP_INVENTORIES.accessPolicies,
          inventoryError: unreadableCollected(GCP_INVENTORIES.accessPolicies, accessPolicies)[0] ?? perimetersUnreadable[0],
          unreadable: [...context.unreadable, ...(perimetersMarker?.status === "not_collected" ? [perimetersMarker] : [])],
          truncated: anyTruncated([projectsTruncated(context), collectedTruncation(accessPolicies), perimeterTruncation]),
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
      sampled_projects: sampledProjects(context),
      projects_truncated: projectsTruncated(context),
      buckets: readableValue(bucketScan, buckets.length),
      non_uniform_buckets: readableValue(bucketScan, nonUniformBuckets.length),
      public_bindings: collectedValue(publicBindings, publicResources.length),
      crypto_keys: collectedValue(cryptoKeys, rotatingKeys.length),
      keys_without_rotation: collectedValue(cryptoKeys, rotationViolations.length),
      disks: readableValue(diskScan, disks.length),
      resources_without_cmek: jointValue([scanReadable(bucketScan), scanReadable(diskScan)], bucketsWithoutCmek.length + disksWithoutCmek.length),
      public_dns_zones: readableValue(zoneScan, publicZones.length),
      zones_without_dnssec: readableValue(zoneScan, dnssecViolations.length),
      api_keys: readableValue(apiKeyScan, apiKeys.length),
      unrestricted_api_keys: readableValue(apiKeyScan, unrestrictedKeys.length),
      enforced_perimeters: jointValue([perimetersReadable], enforcedPerimeters.length),
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: snapshotProjects(context),
      buckets: snapshotScan(bucketScan, buckets.map(snapshotStorageBucket)),
      public_bindings: snapshotCollected(GCP_INVENTORIES.publicBindings, publicBindings, publicBindings.data.items.map(snapshotIamPolicy)),
      crypto_keys: snapshotCollected(GCP_INVENTORIES.cryptoKeys, cryptoKeys, cryptoKeys.data.items.map(snapshotCryptoKey)),
      disks: snapshotScan(diskScan, disks.map(snapshotDisk)),
      managed_zones: snapshotScan(zoneScan, zones.map(snapshotManagedZone)),
      api_keys: snapshotScan(apiKeyScan, apiKeys.map(snapshotApiKey)),
      service_perimeters: perimetersMarker && perimetersReceived === 0 ? snapshotMarker(perimetersMarker) : perimeters.map(snapshotServicePerimeter),
      unreadable_inventories: [
        ...context.unreadable,
        ...unreadableScans(bucketScan, diskScan, zoneScan, apiKeyScan),
        ...publicBindingsUnreadable,
        ...unreadableCollected(GCP_INVENTORIES.cryptoKeys, cryptoKeys),
        ...(config.organizationId ? unreadableCollected(GCP_INVENTORIES.accessPolicies, accessPolicies) : []),
        ...(perimetersMarker ? [perimetersMarker] : []),
      ],
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

/** BackendService.protocol values that front HTTP(S) traffic (GCP_DOCS.backendServicesAggregatedList). */
const HTTP_BACKEND_PROTOCOLS = new Set(["HTTP", "HTTPS", "HTTP2", "H2C"]);

function lastSegment(value: unknown): string | undefined {
  return asString(value)?.split("/").at(-1);
}

/** Subnetwork flow logging is documented on both logConfig.enable and the top-level enableFlowLogs field. */
function flowLogsEnabled(subnet: JsonRecord): boolean {
  return asObject(subnet.logConfig)?.enable === true || subnet.enableFlowLogs === true;
}

/** Instance has a public address when any interface carries accessConfigs (IPv4) or ipv6AccessConfigs (DIRECT_IPV6). */
function hasExternalAddress(instance: JsonRecord): boolean {
  return asObjectArray(instance.networkInterfaces).some(
    (nic) => asObjectArray(nic.accessConfigs).length > 0 || asObjectArray(nic.ipv6AccessConfigs).length > 0,
  );
}

function subnetworkPath(subnet: JsonRecord & { projectId: string }): string | undefined {
  const selfLink = computeResourcePath(subnet.selfLink);
  if (selfLink) return selfLink;
  const name = asString(subnet.name);
  const region = lastSegment(subnet.region);
  return name && region ? `projects/${subnet.projectId}/regions/${region}/subnetworks/${name}` : undefined;
}

/**
 * RouterNat.sourceSubnetworkIpRangesToNat (GCP_DOCS.routersAggregatedList):
 * ALL_SUBNETWORKS_* options cover every subnetwork in the router's network and
 * region; LIST_OF_SUBNETWORKS covers only the subnetworks[].name URLs listed.
 */
function natCoversSubnetwork(nat: JsonRecord, subnetPath: string): boolean {
  const option = asString(nat.sourceSubnetworkIpRangesToNat);
  if (option === "ALL_SUBNETWORKS_ALL_IP_RANGES" || option === "ALL_SUBNETWORKS_ALL_PRIMARY_IP_RANGES") return true;
  if (option !== "LIST_OF_SUBNETWORKS") return false;
  return asObjectArray(nat.subnetworks).some((entry) => computeResourcePath(entry.name) === subnetPath);
}

function networkScopeKey(resource: JsonRecord & { projectId: string }): string {
  return `${resource.projectId}|${lastSegment(resource.network)}|${lastSegment(resource.region)}`;
}

/**
 * Global and regional SSL policies are separate namespaces that may share a
 * name, so policies are keyed by their full projects/... path (selfLink, else
 * the documented region field plus name) and proxies by their sslPolicy URL.
 */
function sslPolicyPath(policy: JsonRecord & { projectId: string }): string | undefined {
  const selfLink = computeResourcePath(policy.selfLink);
  if (selfLink) return selfLink;
  const name = asString(policy.name);
  if (!name) return undefined;
  const region = lastSegment(policy.region);
  return `projects/${policy.projectId}/${region ? `regions/${region}` : "global"}/sslPolicies/${name}`;
}

function attachedSslPolicyPath(proxy: JsonRecord & { projectId: string }): string | undefined {
  const reference = asString(proxy.sslPolicy);
  if (!reference) return undefined;
  return computeResourcePath(reference) ?? `projects/${proxy.projectId}/${reference.replace(/^\/+/, "")}`;
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

  const firewallScan = await scanProjects(context, GCP_INVENTORIES.firewalls, (projectId) => client.listFirewalls(projectId, maxAssets));
  const subnetScan = await scanProjects(context, GCP_INVENTORIES.subnetworks, (projectId) => client.listSubnetworks(projectId, maxAssets));
  const routerScan = await scanProjects(context, GCP_INVENTORIES.routers, (projectId) => client.listRouters(projectId, maxAssets));
  const instanceScan = await scanProjects(context, GCP_INVENTORIES.instances, (projectId) => client.listInstances(projectId, maxAssets));
  const sslPolicyScan = await scanProjects(context, GCP_INVENTORIES.sslPolicies, (projectId) => client.listSslPolicies(projectId, maxAssets));
  const proxyScan = await scanProjects(context, GCP_INVENTORIES.targetHttpsProxies, (projectId) => client.listTargetHttpsProxies(projectId, maxAssets));
  const backendScan = await scanProjects(context, GCP_INVENTORIES.backendServices, (projectId) => client.listBackendServices(projectId, maxAssets));
  const projectsWithoutRouterList = new Set(routerScan.denied.map((entry) => entry.projectId));
  const projectsWithoutSslPolicyList = new Set(sslPolicyScan.denied.map((entry) => entry.projectId));

  const firewalls = flattenScan(firewallScan);
  const openAdminRules = firewalls.filter(isOpenAdminFirewall).map((rule) => ({ projectId: rule.projectId, rule: asString(rule.name), network: lastSegment(rule.network), allowed: rule.allowed }));

  const subnets = flattenScan(subnetScan).filter((subnet) => !FLOW_LOG_UNSUPPORTED_PURPOSES.has(asString(subnet.purpose) ?? ""));
  const subnetsWithoutFlowLogs = subnets
    .filter((subnet) => !flowLogsEnabled(subnet))
    .map((subnet) => ({ projectId: subnet.projectId, subnetwork: asString(subnet.name), region: lastSegment(subnet.region) }));
  const subnetsWithoutPrivateAccess = subnets
    .filter((subnet) => subnet.privateIpGoogleAccess !== true)
    .map((subnet) => ({ projectId: subnet.projectId, subnetwork: asString(subnet.name), region: lastSegment(subnet.region) }));

  const routers = flattenScan(routerScan);
  const routersByScope = new Map<string, JsonRecord[]>();
  for (const router of routers) {
    const key = networkScopeKey(router);
    routersByScope.set(key, [...(routersByScope.get(key) ?? []), router]);
  }
  const subnetsWithoutNat: JsonRecord[] = [];
  const subnetsWithUnknownNat: JsonRecord[] = [];
  for (const subnet of subnets) {
    const record = { projectId: subnet.projectId, subnetwork: asString(subnet.name), network: lastSegment(subnet.network), region: lastSegment(subnet.region) };
    if (projectsWithoutRouterList.has(subnet.projectId)) {
      subnetsWithUnknownNat.push({ ...record, reason: `${GCP_INVENTORIES.routers.dataset} unreadable in this project via ${GCP_INVENTORIES.routers.endpoint}` });
      continue;
    }
    const path = subnetworkPath(subnet);
    const covered = (routersByScope.get(networkScopeKey(subnet)) ?? []).some((router) =>
      asObjectArray(router.nats).some((nat) => path !== undefined && natCoversSubnetwork(nat, path)),
    );
    if (!covered) subnetsWithoutNat.push(record);
  }
  const instances = flattenScan(instanceScan);
  const publicInstances = instances
    .filter(hasExternalAddress)
    .map((instance) => ({ projectId: instance.projectId, instance: asString(instance.name) }));

  const sslPolicies = flattenScan(sslPolicyScan);
  const sslPolicyByPath = new Map<string, JsonRecord>();
  for (const policy of sslPolicies) {
    const path = sslPolicyPath(policy);
    if (path) sslPolicyByPath.set(path, policy);
  }
  const proxies = flattenScan(proxyScan);
  const weakProxies: JsonRecord[] = [];
  const unresolvedProxies: JsonRecord[] = [];
  for (const proxy of proxies) {
    const policyPath = attachedSslPolicyPath(proxy);
    const record = { projectId: proxy.projectId, proxy: asString(proxy.name), sslPolicy: policyPath ?? null };
    if (!policyPath) {
      weakProxies.push({ ...record, reason: "no SSL policy attached; the default policy allows TLS 1.0 with the COMPATIBLE profile" });
      continue;
    }
    const policy = sslPolicyByPath.get(policyPath);
    if (!policy) {
      unresolvedProxies.push({
        ...record,
        reason: projectsWithoutSslPolicyList.has(proxy.projectId)
          ? `${GCP_INVENTORIES.sslPolicies.dataset} unreadable in this project via ${GCP_INVENTORIES.sslPolicies.endpoint}`
          : "attached SSL policy not found in the project inventory",
      });
      continue;
    }
    const minTls = asString(policy.minTlsVersion);
    const profile = asString(policy.profile);
    if (minTls !== "TLS_1_2" && minTls !== "TLS_1_3") weakProxies.push({ ...record, minTlsVersion: minTls ?? null, reason: "minTlsVersion below TLS_1_2" });
    else if (profile === "COMPATIBLE") weakProxies.push({ ...record, profile, reason: "COMPATIBLE profile permits weak cipher suites" });
    else if (profile === "CUSTOM") unresolvedProxies.push({ ...record, profile, customFeatures: stringList(policy.customFeatures), reason: "CUSTOM profile requires manual cipher review" });
  }

  const externalBackends = flattenScan(backendScan).filter((backend) => {
    const scheme = asString(backend.loadBalancingScheme);
    return (scheme === "EXTERNAL" || scheme === "EXTERNAL_MANAGED") && HTTP_BACKEND_PROTOCOLS.has(asString(backend.protocol) ?? "");
  });
  const backendsWithoutArmor = externalBackends
    .filter((backend) => !asString(backend.securityPolicy))
    .map((backend) => ({ projectId: backend.projectId, backendService: asString(backend.name), loadBalancingScheme: asString(backend.loadBalancingScheme) }));

  const scanBase = (scan: ProjectScan<unknown>, ...dependent: ProjectScan<unknown>[]) => scanVerdictBase(context, scan, ...dependent);
  const unresolvedReasons = [...new Set(unresolvedProxies.map((proxy) => asString(proxy.reason)).filter((reason): reason is string => Boolean(reason)))];
  const natCoverageReadable = [scanReadable(subnetScan), scanReadable(routerScan)];
  const natUnreadableClause = `Cloud NAT coverage could not be checked because ${scanReadable(subnetScan) ? GCP_INVENTORIES.routers.dataset : GCP_INVENTORIES.subnetworks.dataset} were unreadable`;
  const natPassClause = natCoverageReadable.every(Boolean)
    ? "Every eligible subnetwork is covered by a Cloud NAT (sourceSubnetworkIpRangesToNat) in its network and region"
    : natUnreadableClause;
  const natFailClause = natCoverageReadable.every(Boolean)
    ? `${subnetsWithoutNat.length} subnetworks are not covered by a Cloud NAT in their network and region${subnetsWithUnknownNat.length > 0 ? ` (${subnetsWithUnknownNat.length} more could not be evaluated because ${GCP_INVENTORIES.routers.dataset} were unreadable in their project)` : ""}`
    : natUnreadableClause;
  const externalIpPassClause = scanReadable(instanceScan)
    ? `none of ${instances.length} instances has an IPv4 or IPv6 external access config`
    : `external IP usage could not be checked because ${GCP_INVENTORIES.instances.dataset} were unreadable`;
  const externalIpFailClause = scanReadable(instanceScan)
    ? `${publicInstances.length} of ${instances.length} instances carry external IPv4 or IPv6 access configs`
    : `external IP usage could not be checked because ${GCP_INVENTORIES.instances.dataset} were unreadable`;
  /** The weak set is complete only when attached policies could be resolved; without the policy list it is a lower bound, not a value. */
  const weakSetReadable = [scanReadable(proxyScan), scanReadable(sslPolicyScan)];
  const sslFailSummary = scanReadable(sslPolicyScan)
    ? `${weakProxies.length} of ${proxies.length} HTTPS target proxies allow TLS below 1.2 or the COMPATIBLE profile (including proxies without an SSL policy).`
    : `${weakProxies.length} of ${proxies.length} HTTPS target proxies attach no SSL policy (the default policy allows TLS 1.0); attached policies could not be evaluated because ${GCP_INVENTORIES.sslPolicies.dataset} were unreadable.`;

  const findings: GcpFinding[] = [
    verdict({
      ...scanBase(firewallScan),
      id: "GCP-NET-01",
      title: "Firewall rules open to the internet on administrative ports",
      severity: "high",
      controls: [4],
      evidence: { open_admin_rules: readableValue(firewallScan, openAdminRules.slice(0, 25)), firewalls_read: readableValue(firewallScan, firewalls.length), admin_ports: ADMIN_PORTS },
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
      evidence: { subnets_without_flow_logs: readableValue(subnetScan, subnetsWithoutFlowLogs.slice(0, 25)), subnets_read: readableValue(subnetScan, subnets.length) },
      total: subnets.length,
      violations: subnetsWithoutFlowLogs.length,
      emptyVerdict: "manual",
      passSummary: `All ${subnets.length} eligible subnetworks enable flow logs via logConfig.enable or enableFlowLogs (proxy-only and Private Service Connect subnets excluded).`,
      failSummary: `${subnetsWithoutFlowLogs.length} of ${subnets.length} eligible subnetworks do not enable flow logs (neither logConfig.enable nor enableFlowLogs is true).`,
      emptySummary: "No eligible subnetworks were listed in the sampled projects.",
      manualEvidence: "review logConfig.enable and enableFlowLogs on each subnetwork.",
    }),
    verdict({
      ...scanBase(subnetScan),
      id: "GCP-NET-03",
      title: "Private Google Access",
      severity: "low",
      controls: [22],
      evidence: { subnets_without_private_google_access: readableValue(subnetScan, subnetsWithoutPrivateAccess.slice(0, 25)), subnets_read: readableValue(subnetScan, subnets.length) },
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
      evidence: {
        subnets_without_nat: jointValue(natCoverageReadable, subnetsWithoutNat.slice(0, 25)),
        subnets_with_unknown_nat: readableValue(subnetScan, subnetsWithUnknownNat.slice(0, 25)),
        instances_with_external_ip: readableValue(instanceScan, publicInstances.slice(0, 25)),
        subnets_read: readableValue(subnetScan, subnets.length),
        routers_read: readableValue(routerScan, routers.length),
        instances_read: readableValue(instanceScan, instances.length),
      },
      total: subnets.length + instances.length,
      seen: jointValue([scanReadable(subnetScan), scanReadable(instanceScan)], subnets.length + instances.length),
      violations: subnetsWithoutNat.length + publicInstances.length,
      violationStatus: "warn",
      unknown: subnetsWithUnknownNat.length,
      unknownSummary: `${subnetsWithUnknownNat.length} of ${subnets.length} eligible subnetworks could not be evaluated for Cloud NAT coverage because ${GCP_INVENTORIES.routers.dataset} were unreadable in their project (${GCP_INVENTORIES.routers.endpoint}).`,
      emptyVerdict: "manual",
      passSummary: `${natPassClause}, and ${externalIpPassClause}.`,
      failSummary: `${natFailClause}, and ${externalIpFailClause}.`,
      emptySummary: "No subnetworks or instances were listed in the sampled projects.",
      manualEvidence: "review Cloud Router nats[].sourceSubnetworkIpRangesToNat and subnetworks[] per region, plus instance networkInterfaces[].accessConfigs and ipv6AccessConfigs.",
    }),
    verdict({
      ...scanBase(proxyScan, sslPolicyScan),
      id: "GCP-NET-05",
      title: "Load balancer SSL policies",
      severity: "high",
      controls: [18],
      evidence: {
        weak_proxies: jointValue(weakSetReadable, weakProxies.slice(0, 25)),
        unresolved_proxies: readableValue(proxyScan, unresolvedProxies.slice(0, 25)),
        proxies_read: readableValue(proxyScan, proxies.length),
        ssl_policies_read: readableValue(sslPolicyScan, sslPolicies.length),
      },
      total: proxies.length,
      violations: weakProxies.length,
      unknown: unresolvedProxies.length,
      unknownSummary: `${unresolvedProxies.length} of ${proxies.length} HTTPS target proxies could not be evaluated: ${unresolvedReasons.join("; ")}.`,
      emptyVerdict: "manual",
      passSummary: `All ${proxies.length} HTTPS target proxies attach an SSL policy with minTlsVersion TLS_1_2 or higher and a MODERN, RESTRICTED, or FIPS_202205 profile.`,
      failSummary: sslFailSummary,
      emptySummary: "No HTTPS target proxies were listed in the sampled projects.",
      manualEvidence: "review sslPolicy on each target HTTPS proxy and the policy's minTlsVersion and profile.",
    }),
    verdict({
      ...scanBase(backendScan),
      id: "GCP-NET-06",
      title: "Cloud Armor on external backend services",
      severity: "medium",
      controls: [19],
      evidence: { backends_without_security_policy: readableValue(backendScan, backendsWithoutArmor.slice(0, 25)), external_backends_read: readableValue(backendScan, externalBackends.length) },
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
      sampled_projects: sampledProjects(context),
      projects_truncated: projectsTruncated(context),
      firewalls: readableValue(firewallScan, firewalls.length),
      open_admin_rules: readableValue(firewallScan, openAdminRules.length),
      subnetworks: readableValue(subnetScan, subnets.length),
      subnets_without_flow_logs: readableValue(subnetScan, subnetsWithoutFlowLogs.length),
      subnets_without_private_google_access: readableValue(subnetScan, subnetsWithoutPrivateAccess.length),
      subnets_without_nat: jointValue(natCoverageReadable, subnetsWithoutNat.length),
      subnets_with_unknown_nat: readableValue(subnetScan, subnetsWithUnknownNat.length),
      instances_with_external_ip: readableValue(instanceScan, publicInstances.length),
      https_proxies: readableValue(proxyScan, proxies.length),
      weak_ssl_proxies: jointValue(weakSetReadable, weakProxies.length),
      external_backends: readableValue(backendScan, externalBackends.length),
      backends_without_cloud_armor: readableValue(backendScan, backendsWithoutArmor.length),
      collection_errors: errors.length,
    },
    findings,
    errors,
    snapshot: {
      projects: snapshotProjects(context),
      firewalls: snapshotScan(firewallScan, firewalls.map(snapshotFirewall)),
      subnetworks: snapshotScan(subnetScan, subnets.map(snapshotSubnetwork)),
      routers: snapshotScan(routerScan, routers.map(snapshotRouter)),
      instances: snapshotScan(instanceScan, instances.map(snapshotNetworkInstance)),
      ssl_policies: snapshotScan(sslPolicyScan, sslPolicies.map(snapshotSslPolicy)),
      target_https_proxies: snapshotScan(proxyScan, proxies.map(snapshotHttpsProxy)),
      backend_services: snapshotScan(backendScan, externalBackends.map(snapshotBackendService)),
      unreadable_inventories: [
        ...context.unreadable,
        ...unreadableScans(firewallScan, subnetScan, routerScan, instanceScan, sslPolicyScan, proxyScan, backendScan),
      ],
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
    "- `core_data/`: projected API snapshots per assessment (only the identifiers and documented fields each control reads; metadata values, labels, key material, and other free-form values are never written); a dataset that was denied or never collected is written as a `{status, dataset, endpoint, scope, error, data: null}` marker, never as `[]`",
    "- `analysis/findings.json`: every finding with status, evidence, spec control numbers, and framework mappings",
    "- `analysis/<category>.json`: per-assessment summary, findings, and collection errors",
    "- `analysis/category_summaries.json`: status counts per category",
    "- `compliance/executive_summary.md`: prioritized readout",
    "- `compliance/unified_compliance_matrix.md`: finding to framework matrix",
    "- `compliance/frameworks/<framework>.md`: one report per framework in the spec mapping table",
    "- `_errors.log`: present only when some reads failed; every failed read keeps each dependent finding below pass (manual when the primary inventory is unreadable, warn otherwise), names the dataset and endpoint in the summary, lists it under `evidence.unreadable_inventories`, and renders every count or list derived from it as null, never as 0 or []",
    "- collection status: `truncated`, `denied_projects`, `unreachable_scopes`, `projects_truncated`, `sources_truncated`, and `findings_truncated` are null whenever the scan they describe was denied or never ran; `false`, `0`, or `[]` is written only when that scan ran to completion. A read skipped because its upstream discovery failed (for example an effective org policy read with no project to resolve it against) is listed with `status: not_collected` naming the upstream call and its status, and no HTTP status is ever attributed to a call that was not made",
    "- error text: a failed request is described by its HTTP status, method, and endpoint plus the documented google.rpc.Status fields (status, message, details reason and type) or, for any other body, the content type and byte length; a response body is never copied into an error, and every error string and every bundle file is scrubbed of bearer, cookie, API key, client secret, refresh token, tokenised URL, and credential name-value shapes",
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
    & Parameters<typeof assessGcpNetworkSecurity>[0]
    & Partial<Pick<GcpAuditorClient, "getKnownSecrets">>,
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
  /**
   * Second layer for every bundle file, .md files and _errors.log included: the same rules the error constructor
   * applies, with the configured credentials and any exchanged token as exact secrets and without the long-token
   * heuristic (project ids, key names, and resource names are evidence). The first layer is the constructor plus
   * the per-control projection of every snapshot.
   */
  const secrets = [...new Set([...credentialValues(config), ...(client.getKnownSecrets?.() ?? [])])];
  const write = (relativePathname: string, content: string) => writeSecureTextFile(outputDir, relativePathname, scrubDataText(content, secrets));

  await write("QUICK_REFERENCE.md", buildQuickReference(assessments));
  await write("README.md", buildQuickReference(assessments));
  await write("metadata.json", serializeJson({
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
  await write("core_data/access.json", serializeJson(redactSecrets(access)));
  for (const assessment of assessments) {
    await write(`core_data/${assessment.category}.json`, serializeJson(redactSecrets(assessment.snapshot)));
    await write(`analysis/${assessment.category}.json`, serializeJson(redactSecrets({
      title: assessment.title,
      category: assessment.category,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    })));
    await write(`analysis/${assessment.category}.md`, formatAssessmentText(assessment));
  }
  await write("analysis/findings.json", serializeJson(redactSecrets(findings)));
  await write("analysis/category_summaries.json", serializeJson(redactSecrets(
    assessments.map((assessment) => ({ category: assessment.category, title: assessment.title, counts: countStatuses(assessment.findings), summary: assessment.summary })),
  )));
  await write("compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await write("compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of GCP_FRAMEWORKS) {
    await write(`compliance/frameworks/${framework.slug}.md`, buildFrameworkReport(framework, findings));
  }
  if (errors.length > 0) {
    await write("_errors.log", `${errors.join("\n")}\n`);
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
