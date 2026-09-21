/**
 * AWS GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the aws-sec-inspector spec.
 * The first slice stays read-only and focuses on IAM hygiene, logging and
 * detective controls, plus organization-level guardrails.
 */
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
} from "@aws-sdk/client-accessanalyzer";
import { AccountClient, GetAlternateContactCommand } from "@aws-sdk/client-account";
import { AuditManagerClient, ListAssessmentsCommand } from "@aws-sdk/client-auditmanager";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  GetTrailStatusCommand,
  LookupEventsCommand,
} from "@aws-sdk/client-cloudtrail";
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
} from "@aws-sdk/client-config-service";
import { fromIni } from "@aws-sdk/credential-providers";
import {
  DescribeFlowLogsCommand,
  DescribeNetworkAclsCommand,
  DescribeRegionsCommand,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  EC2Client,
  GetEbsEncryptionByDefaultCommand,
} from "@aws-sdk/client-ec2";
import {
  GuardDutyClient,
  GetDetectorCommand,
  ListDetectorsCommand,
} from "@aws-sdk/client-guardduty";
import {
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  KMSClient,
  ListKeysCommand,
} from "@aws-sdk/client-kms";
import { DescribeDBInstancesCommand, RDSClient } from "@aws-sdk/client-rds";
import {
  GetBucketEncryptionCommand,
  GetBucketPolicyCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
  ListBucketsCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
  S3ControlClient,
} from "@aws-sdk/client-s3-control";
import {
  GetAccountAuthorizationDetailsCommand,
  GetAccountPasswordPolicyCommand,
  GetAccountSummaryCommand,
  GetAccessKeyLastUsedCommand,
  GetPolicyVersionCommand,
  IAMClient,
  ListAccessKeysCommand,
  ListMFADevicesCommand,
  ListPoliciesCommand as ListIamPoliciesCommand,
  ListUsersCommand,
} from "@aws-sdk/client-iam";
import {
  ListTargetsForPolicyCommand,
  ListAccountsCommand,
  ListPoliciesCommand,
  OrganizationsClient,
  DescribeOrganizationCommand,
} from "@aws-sdk/client-organizations";
import {
  DescribeHubCommand,
  GetEnabledStandardsCommand,
  SecurityHubClient,
} from "@aws-sdk/client-securityhub";
import { ListInstancesCommand, SSOAdminClient } from "@aws-sdk/client-sso-admin";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;

const DEFAULT_REGION = "us-east-1";
const DEFAULT_OUTPUT_DIR = "./export/aws";
const DEFAULT_USER_LIMIT = 500;
const DEFAULT_ROLE_LIMIT = 500;
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_MAX_PRIVILEGED_ROLES = 5;
const DEFAULT_MAX_FINDINGS = 200;
const DEFAULT_REGION_LIMIT = 30;
const DEFAULT_BUCKET_LIMIT = 1000;
const DEFAULT_KEY_LIMIT = 1000;
const DEFAULT_INSTANCE_LIMIT = 500;
const DEFAULT_RESOURCE_LIMIT = 2000;
const DEFAULT_POLICY_LIMIT = 1000;
const DEFAULT_EVENT_LIMIT = 500;
const DEFAULT_ROOT_LOOKBACK_DAYS = 90;
const DEFAULT_CONCURRENCY = 8;
const DEFAULT_SENSITIVE_PORTS = [21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017];
const ANY_IPV4 = "0.0.0.0/0";
const ANY_IPV6 = "::/0";
const REQUIRED_PUBLIC_ACCESS_FLAGS = [
  "BlockPublicAcls",
  "IgnorePublicAcls",
  "BlockPublicPolicy",
  "RestrictPublicBuckets",
] as const;

export type AwsFrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap";

export interface AwsFrameworkDescriptor {
  key: AwsFrameworkKey;
  label: string;
  file: string;
}

/** Framework labels double as mapping prefixes, matching the existing "CIS AWS 1.4" style. */
export const AWS_FRAMEWORKS: ReadonlyArray<AwsFrameworkDescriptor> = [
  { key: "fedramp", label: "FedRAMP", file: "fedramp" },
  { key: "cmmc", label: "CMMC", file: "cmmc" },
  { key: "soc2", label: "SOC 2", file: "soc2" },
  { key: "cis", label: "CIS AWS", file: "cis" },
  { key: "pci_dss", label: "PCI-DSS", file: "pci-dss" },
  { key: "disa_stig", label: "DISA STIG", file: "disa-stig" },
  { key: "irap", label: "IRAP", file: "irap" },
  { key: "ismap", label: "ISMAP", file: "ismap" },
];

export interface AwsControlDescriptor {
  title: string;
  frameworks: Record<AwsFrameworkKey, string[]>;
}

function control(
  title: string,
  fedramp: string[],
  cmmc: string[],
  soc2: string[],
  cis: string[],
  pciDss: string[],
  disaStig: string[],
  irap: string[],
  ismap: string[],
): AwsControlDescriptor {
  return {
    title,
    frameworks: { fedramp, cmmc, soc2, cis, pci_dss: pciDss, disa_stig: disaStig, irap, ismap },
  };
}

/** Section 5 of specs/aws-sec-inspector.spec.md, one row per numbered control. */
export const AWS_CONTROL_CATALOG: Record<number, AwsControlDescriptor> = {
  1: control("MFA Enforcement", ["IA-2(1)", "IA-2(2)"], ["AC.L2-3.1.1"], ["CC6.1", "CC6.6"], ["1.5", "1.6", "1.10"], ["8.4.2"], ["SRG-APP-000149"], ["ISM-1401"], ["7.2.1"]),
  2: control("Password Policy", ["IA-5(1)"], ["IA.L2-3.5.7"], ["CC6.1"], ["1.8", "1.9"], ["8.3.6"], ["SRG-APP-000166"], ["ISM-0421"], ["7.2.2"]),
  3: control("Access Key Rotation", ["IA-5(1)"], ["IA.L2-3.5.8"], ["CC6.1", "CC6.2"], ["1.12", "1.14"], ["8.6.3"], ["SRG-APP-000175"], ["ISM-1590"], ["7.2.3"]),
  4: control("Root Account Usage", ["AC-6(1)", "AC-6(5)"], ["AC.L2-3.1.5"], ["CC6.1", "CC6.3"], ["1.4", "1.7"], ["8.6.1"], ["SRG-APP-000340"], ["ISM-1507"], ["7.1.1"]),
  5: control("Unused Credentials", ["AC-2(3)"], ["AC.L2-3.1.12"], ["CC6.2"], ["1.12"], ["8.1.4"], ["SRG-APP-000163"], ["ISM-1404"], ["7.2.4"]),
  6: control("CloudTrail Enabled", ["AU-2", "AU-3", "AU-12"], ["AU.L2-3.3.1"], ["CC7.2", "CC7.3"], ["3.1", "3.2"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.1"]),
  7: control("CloudTrail Log Integrity", ["AU-9", "AU-10"], ["AU.L2-3.3.8"], ["CC7.2"], ["3.4", "3.7"], ["10.3.2"], ["SRG-APP-000125"], ["ISM-0859"], ["8.1.2"]),
  8: control("Security Hub Enabled", ["CA-7", "SI-4"], ["CA.L2-3.12.3"], ["CC7.1", "CC7.2"], [], ["11.5.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.1"]),
  9: control("GuardDuty Enabled", ["SI-4", "IR-4"], ["SI.L2-3.14.6"], ["CC7.2", "CC7.3"], [], ["11.5.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.2"]),
  10: control("Config Enabled", ["CM-2", "CM-6", "CM-8"], ["CM.L2-3.4.1"], ["CC7.1"], ["3.5"], ["10.2.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.2.3"]),
  11: control("S3 Public Access", ["AC-3", "AC-4"], ["AC.L2-3.1.3"], ["CC6.1", "CC6.6"], ["2.1.4"], ["1.3.1"], ["SRG-APP-000516"], ["ISM-0263"], ["6.1.1"]),
  12: control("Encryption at Rest", ["SC-28"], ["SC.L2-3.13.16"], ["CC6.1", "CC6.7"], ["2.2.1"], ["3.4.1"], ["SRG-APP-000231"], ["ISM-0457"], ["6.2.1"]),
  13: control("Encryption in Transit", ["SC-8", "SC-23"], ["SC.L2-3.13.8"], ["CC6.1", "CC6.7"], [], ["4.1.1"], ["SRG-APP-000014"], ["ISM-0469"], ["6.2.2"]),
  14: control("VPC Flow Logs", ["AU-12", "SI-4"], ["AU.L2-3.3.1"], ["CC7.2"], ["3.9"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.3"]),
  15: control("Cross-Account Access", ["AC-3", "AC-6"], ["AC.L2-3.1.2"], ["CC6.1", "CC6.3"], ["1.16"], ["7.2.1"], ["SRG-APP-000033"], ["ISM-1380"], ["7.1.2"]),
  16: control("SCP Enforcement", ["AC-3", "CM-7"], ["AC.L2-3.1.7"], ["CC6.1", "CC6.8"], [], ["7.2.1"], ["SRG-APP-000246"], ["ISM-1380"], ["7.1.3"]),
  17: control("Permission Boundaries", ["AC-6(1)", "AC-6(2)"], ["AC.L2-3.1.5"], ["CC6.3"], [], ["7.2.2"], ["SRG-APP-000340"], ["ISM-1380"], ["7.1.4"]),
  18: control("Least Privilege", ["AC-6"], ["AC.L2-3.1.5"], ["CC6.1", "CC6.3"], ["1.16"], ["7.2.2"], ["SRG-APP-000342"], ["ISM-1380"], ["7.1.5"]),
  19: control("Logging Configuration", ["AU-2", "AU-3", "AU-6"], ["AU.L2-3.3.1"], ["CC7.2", "CC7.3"], ["3.1", "3.3", "3.5"], ["10.2.1"], ["SRG-APP-000089"], ["ISM-0580"], ["8.1.4"]),
  20: control("Network ACLs", ["AC-4", "SC-7"], ["SC.L2-3.13.1"], ["CC6.1", "CC6.6"], ["5.1"], ["1.3.1"], ["SRG-APP-000142"], ["ISM-1416"], ["6.1.2"]),
  21: control("Security Group Rules", ["AC-4", "SC-7"], ["SC.L2-3.13.1"], ["CC6.1", "CC6.6"], ["5.2", "5.3"], ["1.3.2"], ["SRG-APP-000142"], ["ISM-1416"], ["6.1.3"]),
  22: control("KMS Key Rotation", ["SC-12", "SC-28"], ["SC.L2-3.13.10"], ["CC6.1", "CC6.7"], ["3.8"], ["3.6.4"], ["SRG-APP-000231"], ["ISM-0457"], ["6.2.3"]),
  23: control("Identity Center Configuration", ["AC-2", "IA-2"], ["AC.L2-3.1.1"], ["CC6.1", "CC6.2"], [], ["8.4.2"], ["SRG-APP-000149"], ["ISM-1401"], ["7.2.5"]),
  24: control("Audit Manager Evidence", ["CA-2", "CA-7"], ["CA.L2-3.12.1"], ["CC4.1"], [], ["12.4.1"], ["SRG-APP-000516"], ["ISM-1228"], ["8.3.1"]),
  25: control("Account Contacts", ["IR-6", "PM-2"], ["IR.L2-3.6.2"], ["CC7.4"], ["1.1", "1.2"], ["12.10.5"], ["SRG-APP-000516"], ["ISM-0072"], ["9.1.1"]),
};

/** Spec control numbers covered by each finding id, used for coverage and framework reports. */
export const AWS_FINDING_CONTROLS: Record<string, number[]> = {
  "AWS-IAM-01": [1, 4],
  "AWS-IAM-02": [1],
  "AWS-IAM-03": [2],
  "AWS-IAM-04": [3],
  "AWS-IAM-05": [17],
  "AWS-IAM-06": [5],
  "AWS-IAM-07": [4],
  "AWS-IAM-08": [18],
  "AWS-LOG-01": [6, 7],
  "AWS-LOG-02": [19],
  "AWS-LOG-03": [8],
  "AWS-LOG-04": [9],
  "AWS-LOG-05": [10],
  "AWS-ORG-01": [16],
  "AWS-ORG-02": [16],
  "AWS-ORG-03": [15],
  "AWS-ORG-04": [15],
  "AWS-ORG-05": [23],
  "AWS-ORG-06": [24],
  "AWS-ORG-07": [25],
  "AWS-DATA-11": [11],
  "AWS-DATA-12": [12],
  "AWS-DATA-13": [13],
  "AWS-DATA-22": [22],
  "AWS-NET-14": [14],
  "AWS-NET-20": [20],
  "AWS-NET-21": [21],
};

export function buildAwsMappings(controlNumber: number): string[] {
  const descriptor = AWS_CONTROL_CATALOG[controlNumber];
  if (!descriptor) return [];
  const mappings: string[] = [];
  for (const framework of AWS_FRAMEWORKS) {
    for (const reference of descriptor.frameworks[framework.key]) {
      mappings.push(`${framework.label} ${reference}`);
    }
  }
  return mappings;
}

export interface AwsResolvedConfig {
  region: string;
  profile?: string;
  accountId?: string;
  sourceChain: string[];
}

export interface AwsAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface AwsAccessCheckResult {
  status: "healthy" | "limited";
  accountId?: string;
  arn?: string;
  surfaces: AwsAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface AwsFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface AwsAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: AwsFinding[];
  errors?: string[];
}

/** Outcome of one API read; a denied or errored surface never contributes to a pass. */
export interface AwsSurfaceResult<T> {
  value?: T;
  error?: string;
  denied?: boolean;
}

export interface AwsRegionScope {
  regions: string[];
  regionsTotal: number;
  regionsSeen: number;
  partial: boolean;
  source: "arguments" | "describe-regions" | "configured-region-fallback";
  error?: string;
}

export interface AwsPagedList<T> {
  items: T[];
  truncated: boolean;
}

export interface AwsAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type CheckAccessArgs = {
  region?: string;
  profile?: string;
  account_id?: string;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  stale_days?: number;
  role_limit?: number;
  max_privileged_roles?: number;
  lookback_days?: number;
  policy_limit?: number;
};

type LoggingArgs = CheckAccessArgs & {
  max_security_hub_standards?: number;
};

type OrgGuardrailArgs = CheckAccessArgs & {
  max_findings?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  user_limit?: number;
  stale_days?: number;
  role_limit?: number;
  max_privileged_roles?: number;
  lookback_days?: number;
  policy_limit?: number;
  max_findings?: number;
  regions?: string[];
  region_limit?: number;
  bucket_limit?: number;
  key_limit?: number;
  instance_limit?: number;
  resource_limit?: number;
  sensitive_ports?: number[];
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
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
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  const object = asObject(value);
  if (!object) return undefined;
  return (
    extractTimestamp(object.LastUsedDate)
    ?? extractTimestamp(object.CreateDate)
    ?? extractTimestamp(object.PasswordLastUsed)
    ?? extractTimestamp(object.UpdatedAt)
    ?? extractTimestamp(object.created)
  );
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function finding(
  id: string,
  title: string,
  severity: AwsFinding["severity"],
  status: AwsFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): AwsFinding {
  return { id, title, severity, status, summary, mappings, evidence };
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function errorCode(error: unknown): string {
  const object = asObject(error);
  return asString(object?.name) ?? asString(object?.Code) ?? asString(object?.code) ?? "";
}

function errorHttpStatus(error: unknown): number | undefined {
  const metadata = asObject(asObject(error)?.$metadata);
  return asNumber(metadata?.httpStatusCode);
}

export function isAwsAccessDenied(error: unknown): boolean {
  const code = errorCode(error);
  if (/AccessDenied|Unauthorized|Forbidden|AuthorizationError|NotAuthorized|AuthFailure|InvalidClientTokenId|ExpiredToken/i.test(code)) {
    return true;
  }
  return errorHttpStatus(error) === 403;
}

function isErrorCode(error: unknown, ...codes: string[]): boolean {
  const code = errorCode(error);
  return codes.some((candidate) => candidate === code);
}

function describeError(error: unknown): string {
  const code = errorCode(error);
  const message = error instanceof Error ? error.message : String(error);
  return code && !message.startsWith(code) ? `${code}: ${message}` : message;
}

/** Run one read and classify the outcome instead of throwing. */
export async function attemptAwsRead<T>(
  label: string,
  loader: () => Promise<T>,
  errors: string[],
): Promise<AwsSurfaceResult<T>> {
  try {
    return { value: await loader() };
  } catch (error) {
    const denied = isAwsAccessDenied(error);
    const message = `${label}: ${denied ? "AccessDenied" : "error"} (${describeError(error)})`;
    errors.push(message);
    return { error: message, denied };
  }
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

function parseRegionList(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const regions = value.map(asString).filter((item): item is string => Boolean(item));
    return regions.length > 0 ? regions : undefined;
  }
  const text = asString(value);
  if (!text) return undefined;
  const regions = text.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  return regions.length > 0 ? [...new Set(regions)] : undefined;
}

function boolFlag(record: JsonRecord | undefined, key: string): boolean | undefined {
  const value = record?.[key];
  return typeof value === "boolean" ? value : undefined;
}

function publicAccessFlags(configuration: JsonRecord | undefined): Record<string, boolean | undefined> {
  const flags: Record<string, boolean | undefined> = {};
  for (const key of REQUIRED_PUBLIC_ACCESS_FLAGS) {
    flags[key] = boolFlag(configuration, key);
  }
  return flags;
}

function allPublicAccessFlagsTrue(flags: Record<string, boolean | undefined>): boolean {
  return REQUIRED_PUBLIC_ACCESS_FLAGS.every((key) => flags[key] === true);
}

function conditionValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item).toLowerCase());
  if (value === undefined || value === null) return [];
  return [String(value).toLowerCase()];
}

/** True when a statement denies requests where aws:SecureTransport is false (TLS-only bucket policy). */
export function statementDeniesInsecureTransport(statement: JsonRecord): boolean {
  if (asString(statement.Effect)?.toLowerCase() !== "deny") return false;
  const condition = asObject(statement.Condition);
  if (!condition) return false;
  for (const [operator, operands] of Object.entries(condition)) {
    if (!/^bool(ifexists)?$/i.test(operator)) continue;
    const operandRecord = asObject(operands);
    if (!operandRecord) continue;
    for (const [key, value] of Object.entries(operandRecord)) {
      if (key.toLowerCase() === "aws:securetransport" && conditionValues(value).includes("false")) {
        return true;
      }
    }
  }
  return false;
}

export function resolveRegionScope(
  requested: string[] | undefined,
  described: AwsSurfaceResult<string[]>,
  fallbackRegion: string,
  regionLimit: number,
): AwsRegionScope {
  if (requested && requested.length > 0) {
    const regions = requested.slice(0, regionLimit);
    return {
      regions,
      regionsTotal: requested.length,
      regionsSeen: regions.length,
      partial: regions.length < requested.length,
      source: "arguments",
    };
  }
  if (described.value && described.value.length > 0) {
    const regions = described.value.slice(0, regionLimit);
    return {
      regions,
      regionsTotal: described.value.length,
      regionsSeen: regions.length,
      partial: regions.length < described.value.length,
      source: "describe-regions",
    };
  }
  return {
    regions: [fallbackRegion],
    regionsTotal: 1,
    regionsSeen: 1,
    partial: true,
    source: "configured-region-fallback",
    error: described.error ?? "DescribeRegions returned no enabled regions",
  };
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "aws";
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
  const stat = lstatSync(realParent);
  if (stat.isSymbolicLink()) {
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
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    if (entry.isDirectory()) {
      count += await countFilesRecursively(fullPath);
    } else {
      count += 1;
    }
  }
  return count;
}

export function resolveAwsConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
): AwsResolvedConfig {
  const sourceChain: string[] = [];
  const region = asString(input.region)
    ?? asString(env.AWS_REGION)
    ?? asString(env.AWS_DEFAULT_REGION)
    ?? DEFAULT_REGION;
  if (asString(input.region)) sourceChain.push("arguments-region");
  else if (asString(env.AWS_REGION) || asString(env.AWS_DEFAULT_REGION)) sourceChain.push("environment-region");
  else sourceChain.push("default-region");

  const profile = asString(input.profile) ?? asString(env.AWS_PROFILE);
  if (profile) sourceChain.push(asString(input.profile) ? "arguments-profile" : "environment-profile");

  const accountId = asString(input.account_id) ?? asString(env.AWS_ACCOUNT_ID);
  if (accountId) sourceChain.push(asString(input.account_id) ? "arguments-account" : "environment-account");

  return {
    region,
    profile,
    accountId,
    sourceChain: [...new Set(sourceChain)],
  };
}

function normalizePolicyDocument(policyDocument: unknown): JsonRecord | undefined {
  if (typeof policyDocument === "string") {
    const decoded = decodeURIComponent(policyDocument);
    try {
      return asObject(JSON.parse(decoded));
    } catch {
      return undefined;
    }
  }
  return asObject(policyDocument);
}

function normalizeStatements(policyDocument: unknown): JsonRecord[] {
  const document = normalizePolicyDocument(policyDocument);
  if (!document) return [];
  const statement = document.Statement;
  if (Array.isArray(statement)) {
    return statement.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  const one = asObject(statement);
  return one ? [one] : [];
}

function matchesWildcard(value: unknown): boolean {
  if (typeof value === "string") return value === "*";
  if (Array.isArray(value)) return value.map(String).includes("*");
  return false;
}

function hasAdministratorPolicy(role: JsonRecord): boolean {
  const attached = Array.isArray(role.AttachedManagedPolicies) ? role.AttachedManagedPolicies : [];
  if (attached.some((policy) => {
    const item = asObject(policy);
    return asString(item?.PolicyName) === "AdministratorAccess";
  })) {
    return true;
  }

  const inline = Array.isArray(role.RolePolicyList) ? role.RolePolicyList : [];
  return inline.some((policy) => {
    const item = asObject(policy);
    const statements = normalizeStatements(item?.PolicyDocument);
    return statements.some((statement) => matchesWildcard(statement.Action) && matchesWildcard(statement.Resource));
  });
}

function describeSourceChain(config: AwsResolvedConfig): string {
  return config.profile
    ? `AWS profile ${config.profile} in ${config.region}`
    : `AWS default credential chain in ${config.region}`;
}

export class AwsAuditorClient {
  private readonly sts: STSClient;
  private readonly iam: IAMClient;
  private readonly cloudTrail: CloudTrailClient;
  private readonly securityHub: SecurityHubClient;
  private readonly configService: ConfigServiceClient;
  private readonly guardDuty: GuardDutyClient;
  private readonly organizations: OrganizationsClient;
  private readonly accessAnalyzer: AccessAnalyzerClient;
  private readonly ssoAdmin: SSOAdminClient;
  private readonly s3: S3Client;
  private readonly s3Control: S3ControlClient;
  private readonly auditManager: AuditManagerClient;
  private readonly account: AccountClient;
  private readonly credentials: ReturnType<typeof fromIni> | undefined;
  private readonly ec2Clients = new Map<string, EC2Client>();
  private readonly rdsClients = new Map<string, RDSClient>();
  private readonly kmsClients = new Map<string, KMSClient>();
  private readonly now: () => Date;

  constructor(
    private readonly config: AwsResolvedConfig,
    options: { now?: () => Date } = {},
  ) {
    const credentials = config.profile ? fromIni({ profile: config.profile }) : undefined;
    const clientConfig = { region: config.region, credentials };
    this.credentials = credentials;
    this.sts = new STSClient(clientConfig);
    this.iam = new IAMClient(clientConfig);
    this.cloudTrail = new CloudTrailClient(clientConfig);
    this.securityHub = new SecurityHubClient(clientConfig);
    this.configService = new ConfigServiceClient(clientConfig);
    this.guardDuty = new GuardDutyClient(clientConfig);
    this.organizations = new OrganizationsClient(clientConfig);
    this.accessAnalyzer = new AccessAnalyzerClient(clientConfig);
    this.ssoAdmin = new SSOAdminClient(clientConfig);
    this.s3 = new S3Client({ ...clientConfig, followRegionRedirects: true });
    this.s3Control = new S3ControlClient(clientConfig);
    this.auditManager = new AuditManagerClient(clientConfig);
    this.account = new AccountClient(clientConfig);
    this.now = options.now ?? (() => new Date());
  }

  /** IAM ListPolicies with Scope Local (customer managed), paginated to completion up to limit. */
  async listCustomerManagedPolicies(limit = DEFAULT_POLICY_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const policies: JsonRecord[] = [];
    let marker: string | undefined;
    let truncated = false;
    do {
      const result = await this.iam.send(new ListIamPoliciesCommand({ Scope: "Local", OnlyAttached: false, Marker: marker, MaxItems: 100 }));
      for (const policy of result.Policies ?? []) {
        policies.push({
          PolicyName: policy.PolicyName,
          Arn: policy.Arn,
          DefaultVersionId: policy.DefaultVersionId,
          AttachmentCount: policy.AttachmentCount,
          PermissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount,
        });
      }
      marker = result.IsTruncated ? result.Marker : undefined;
      if (policies.length > limit) {
        truncated = true;
        policies.length = limit;
        break;
      }
    } while (marker);
    return { items: policies, truncated };
  }

  /** IAM GetPolicyVersion; the Document is URL-encoded JSON per the API reference. */
  async getPolicyVersionDocument(policyArn: string, versionId: string): Promise<JsonRecord | null> {
    const result = await this.iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }));
    return normalizePolicyDocument(result.PolicyVersion?.Document) ?? null;
  }

  /** CloudTrail LookupEvents filtered on Username root within the window (management events, 90-day history). */
  async lookupRootEvents(startTime: Date, endTime: Date, limit = DEFAULT_EVENT_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const events: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.cloudTrail.send(new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: "Username", AttributeValue: "root" }],
        StartTime: startTime,
        EndTime: endTime,
        MaxResults: 50,
        NextToken: nextToken,
      }));
      for (const event of result.Events ?? []) {
        events.push({
          EventId: event.EventId,
          EventName: event.EventName,
          EventTime: event.EventTime,
          EventSource: event.EventSource,
          Username: event.Username,
          ReadOnly: event.ReadOnly,
        });
      }
      nextToken = result.NextToken;
      if (events.length > limit) {
        truncated = true;
        events.length = limit;
        break;
      }
    } while (nextToken);
    return { items: events, truncated };
  }

  /** Audit Manager ListAssessments with status ACTIVE. */
  async listActiveAuditManagerAssessments(limit = DEFAULT_MAX_FINDINGS): Promise<AwsPagedList<JsonRecord>> {
    const assessments: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.auditManager.send(new ListAssessmentsCommand({ status: "ACTIVE", maxResults: 100, nextToken }));
      for (const assessment of result.assessmentMetadata ?? []) {
        assessments.push({
          id: assessment.id,
          name: assessment.name,
          status: assessment.status,
          complianceType: assessment.complianceType,
          creationTime: assessment.creationTime,
          lastUpdated: assessment.lastUpdated,
        });
      }
      nextToken = result.nextToken;
      if (assessments.length > limit) {
        truncated = true;
        assessments.length = limit;
        break;
      }
    } while (nextToken);
    return { items: assessments, truncated };
  }

  /** Account GetAlternateContact SECURITY; null when ResourceNotFoundException (no contact set). */
  async getSecurityAlternateContact(): Promise<JsonRecord | null> {
    try {
      const result = await this.account.send(new GetAlternateContactCommand({ AlternateContactType: "SECURITY" }));
      const contact = result.AlternateContact;
      return contact
        ? {
            AlternateContactType: contact.AlternateContactType,
            Name: contact.Name,
            Title: contact.Title,
            EmailAddress: contact.EmailAddress,
            PhoneNumber: contact.PhoneNumber,
          }
        : {};
    } catch (error) {
      if (isErrorCode(error, "ResourceNotFoundException")) return null;
      throw error;
    }
  }

  private ec2For(region: string): EC2Client {
    let client = this.ec2Clients.get(region);
    if (!client) {
      client = new EC2Client({ region, credentials: this.credentials });
      this.ec2Clients.set(region, client);
    }
    return client;
  }

  private rdsFor(region: string): RDSClient {
    let client = this.rdsClients.get(region);
    if (!client) {
      client = new RDSClient({ region, credentials: this.credentials });
      this.rdsClients.set(region, client);
    }
    return client;
  }

  private kmsFor(region: string): KMSClient {
    let client = this.kmsClients.get(region);
    if (!client) {
      client = new KMSClient({ region, credentials: this.credentials });
      this.kmsClients.set(region, client);
    }
    return client;
  }

  /** Enabled regions via EC2 DescribeRegions (opt-in-status opted-in or opt-in-not-required). */
  async describeRegions(): Promise<string[]> {
    const result = await this.ec2For(this.config.region).send(new DescribeRegionsCommand({
      Filters: [{ Name: "opt-in-status", Values: ["opt-in-not-required", "opted-in"] }],
    }));
    return (result.Regions ?? [])
      .map((region) => asString(region.RegionName))
      .filter((name): name is string => Boolean(name))
      .sort();
  }

  /** S3 Control GetPublicAccessBlock; null when NoSuchPublicAccessBlockConfiguration. */
  async getAccountPublicAccessBlock(accountId: string): Promise<JsonRecord | null> {
    try {
      const result = await this.s3Control.send(new GetAccountPublicAccessBlockCommand({ AccountId: accountId }));
      return asObject(result.PublicAccessBlockConfiguration) ?? {};
    } catch (error) {
      if (isErrorCode(error, "NoSuchPublicAccessBlockConfiguration")) return null;
      throw error;
    }
  }

  async listBuckets(limit = DEFAULT_BUCKET_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const buckets: JsonRecord[] = [];
    let continuationToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.s3.send(new ListBucketsCommand({
        ContinuationToken: continuationToken,
        MaxBuckets: Math.min(1000, Math.max(1, limit - buckets.length + 1)),
      }));
      for (const bucket of result.Buckets ?? []) {
        buckets.push({ Name: bucket.Name, CreationDate: bucket.CreationDate, BucketRegion: bucket.BucketRegion });
      }
      continuationToken = result.ContinuationToken;
      if (buckets.length > limit) {
        truncated = true;
        buckets.length = limit;
        break;
      }
    } while (continuationToken);
    return { items: buckets, truncated };
  }

  /** S3 GetPublicAccessBlock for one bucket; null when NoSuchPublicAccessBlockConfiguration. */
  async getBucketPublicAccessBlock(bucket: string): Promise<JsonRecord | null> {
    try {
      const result = await this.s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket }));
      return asObject(result.PublicAccessBlockConfiguration) ?? {};
    } catch (error) {
      if (isErrorCode(error, "NoSuchPublicAccessBlockConfiguration")) return null;
      throw error;
    }
  }

  /** S3 GetBucketPolicyStatus; null when the bucket has no policy (NoSuchBucketPolicy). */
  async getBucketPolicyStatus(bucket: string): Promise<JsonRecord | null> {
    try {
      const result = await this.s3.send(new GetBucketPolicyStatusCommand({ Bucket: bucket }));
      return { IsPublic: result.PolicyStatus?.IsPublic };
    } catch (error) {
      if (isErrorCode(error, "NoSuchBucketPolicy")) return null;
      throw error;
    }
  }

  /** S3 GetBucketEncryption; null when ServerSideEncryptionConfigurationNotFoundError. */
  async getBucketEncryption(bucket: string): Promise<JsonRecord | null> {
    try {
      const result = await this.s3.send(new GetBucketEncryptionCommand({ Bucket: bucket }));
      return {
        Rules: (result.ServerSideEncryptionConfiguration?.Rules ?? []).map((rule) => ({
          SSEAlgorithm: rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm,
          KMSMasterKeyID: rule.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID,
          BucketKeyEnabled: rule.BucketKeyEnabled,
        })),
      };
    } catch (error) {
      if (isErrorCode(error, "ServerSideEncryptionConfigurationNotFoundError")) return null;
      throw error;
    }
  }

  /** S3 GetBucketPolicy document; null when NoSuchBucketPolicy. */
  async getBucketPolicy(bucket: string): Promise<string | null> {
    try {
      const result = await this.s3.send(new GetBucketPolicyCommand({ Bucket: bucket }));
      return result.Policy ?? null;
    } catch (error) {
      if (isErrorCode(error, "NoSuchBucketPolicy")) return null;
      throw error;
    }
  }

  async getEbsEncryptionByDefault(region: string): Promise<JsonRecord> {
    const result = await this.ec2For(region).send(new GetEbsEncryptionByDefaultCommand({}));
    return { EbsEncryptionByDefault: result.EbsEncryptionByDefault, SseType: result.SseType };
  }

  async describeVpcs(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const vpcs: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.ec2For(region).send(new DescribeVpcsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      for (const vpc of result.Vpcs ?? []) {
        vpcs.push({ VpcId: vpc.VpcId, IsDefault: vpc.IsDefault, CidrBlock: vpc.CidrBlock, State: vpc.State });
      }
      nextToken = result.NextToken;
      if (vpcs.length > limit) {
        truncated = true;
        vpcs.length = limit;
        break;
      }
    } while (nextToken);
    return { items: vpcs, truncated };
  }

  async describeFlowLogs(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const flowLogs: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.ec2For(region).send(new DescribeFlowLogsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      for (const flowLog of result.FlowLogs ?? []) {
        flowLogs.push({
          FlowLogId: flowLog.FlowLogId,
          ResourceId: flowLog.ResourceId,
          FlowLogStatus: flowLog.FlowLogStatus,
          TrafficType: flowLog.TrafficType,
          LogDestinationType: flowLog.LogDestinationType,
          LogDestination: flowLog.LogDestination,
          LogGroupName: flowLog.LogGroupName,
        });
      }
      nextToken = result.NextToken;
      if (flowLogs.length > limit) {
        truncated = true;
        flowLogs.length = limit;
        break;
      }
    } while (nextToken);
    return { items: flowLogs, truncated };
  }

  async describeNetworkAcls(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const acls: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.ec2For(region).send(new DescribeNetworkAclsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      for (const acl of result.NetworkAcls ?? []) {
        acls.push({
          NetworkAclId: acl.NetworkAclId,
          VpcId: acl.VpcId,
          IsDefault: acl.IsDefault,
          Entries: (acl.Entries ?? []).map((entry) => ({
            RuleNumber: entry.RuleNumber,
            Protocol: entry.Protocol,
            RuleAction: entry.RuleAction,
            Egress: entry.Egress,
            CidrBlock: entry.CidrBlock,
            Ipv6CidrBlock: entry.Ipv6CidrBlock,
            PortRange: entry.PortRange ? { From: entry.PortRange.From, To: entry.PortRange.To } : undefined,
          })),
        });
      }
      nextToken = result.NextToken;
      if (acls.length > limit) {
        truncated = true;
        acls.length = limit;
        break;
      }
    } while (nextToken);
    return { items: acls, truncated };
  }

  async describeSecurityGroups(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const groups: JsonRecord[] = [];
    let nextToken: string | undefined;
    let truncated = false;
    do {
      const result = await this.ec2For(region).send(new DescribeSecurityGroupsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      for (const group of result.SecurityGroups ?? []) {
        groups.push({
          GroupId: group.GroupId,
          GroupName: group.GroupName,
          VpcId: group.VpcId,
          IpPermissions: (group.IpPermissions ?? []).map((permission) => ({
            IpProtocol: permission.IpProtocol,
            FromPort: permission.FromPort,
            ToPort: permission.ToPort,
            IpRanges: (permission.IpRanges ?? []).map((range) => ({ CidrIp: range.CidrIp, Description: range.Description })),
            Ipv6Ranges: (permission.Ipv6Ranges ?? []).map((range) => ({ CidrIpv6: range.CidrIpv6, Description: range.Description })),
          })),
        });
      }
      nextToken = result.NextToken;
      if (groups.length > limit) {
        truncated = true;
        groups.length = limit;
        break;
      }
    } while (nextToken);
    return { items: groups, truncated };
  }

  async describeDbInstances(region: string, limit = DEFAULT_INSTANCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const instances: JsonRecord[] = [];
    let marker: string | undefined;
    let truncated = false;
    do {
      const result = await this.rdsFor(region).send(new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }));
      for (const instance of result.DBInstances ?? []) {
        instances.push({
          DBInstanceIdentifier: instance.DBInstanceIdentifier,
          DBInstanceArn: instance.DBInstanceArn,
          Engine: instance.Engine,
          StorageEncrypted: instance.StorageEncrypted,
          KmsKeyId: instance.KmsKeyId,
        });
      }
      marker = result.Marker;
      if (instances.length > limit) {
        truncated = true;
        instances.length = limit;
        break;
      }
    } while (marker);
    return { items: instances, truncated };
  }

  async listKmsKeys(region: string, limit = DEFAULT_KEY_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    const keys: JsonRecord[] = [];
    let marker: string | undefined;
    let truncated = false;
    do {
      const result = await this.kmsFor(region).send(new ListKeysCommand({ Marker: marker, Limit: 1000 }));
      for (const key of result.Keys ?? []) {
        keys.push({ KeyId: key.KeyId, KeyArn: key.KeyArn });
      }
      marker = result.Truncated ? result.NextMarker : undefined;
      if (keys.length > limit) {
        truncated = true;
        keys.length = limit;
        break;
      }
    } while (marker);
    return { items: keys, truncated };
  }

  async describeKmsKey(region: string, keyId: string): Promise<JsonRecord> {
    const result = await this.kmsFor(region).send(new DescribeKeyCommand({ KeyId: keyId }));
    const metadata = result.KeyMetadata;
    return {
      KeyId: metadata?.KeyId,
      Arn: metadata?.Arn,
      KeyManager: metadata?.KeyManager,
      KeyState: metadata?.KeyState,
      KeySpec: metadata?.KeySpec,
      KeyUsage: metadata?.KeyUsage,
      Origin: metadata?.Origin,
      MultiRegion: metadata?.MultiRegion,
    };
  }

  async getKeyRotationStatus(region: string, keyId: string): Promise<JsonRecord> {
    const result = await this.kmsFor(region).send(new GetKeyRotationStatusCommand({ KeyId: keyId }));
    return {
      KeyRotationEnabled: result.KeyRotationEnabled,
      RotationPeriodInDays: result.RotationPeriodInDays,
      NextRotationDate: result.NextRotationDate,
    };
  }

  getNow(): Date {
    return this.now();
  }

  getResolvedConfig(): AwsResolvedConfig {
    return this.config;
  }

  async getCallerIdentity(): Promise<JsonRecord> {
    const result = await this.sts.send(new GetCallerIdentityCommand({}));
    return {
      Account: result.Account,
      Arn: result.Arn,
      UserId: result.UserId,
    };
  }

  async getAccountSummary(): Promise<JsonRecord> {
    const result = await this.iam.send(new GetAccountSummaryCommand({}));
    return { SummaryMap: result.SummaryMap ?? {} };
  }

  async getPasswordPolicy(): Promise<JsonRecord | null> {
    try {
      const result = await this.iam.send(new GetAccountPasswordPolicyCommand({}));
      return asObject(result.PasswordPolicy) ?? null;
    } catch {
      return null;
    }
  }

  async listIamUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    const users: JsonRecord[] = [];
    let marker: string | undefined;
    while (users.length < limit) {
      const result = await this.iam.send(new ListUsersCommand({ Marker: marker, MaxItems: Math.min(100, limit - users.length) }));
      for (const user of result.Users ?? []) {
        users.push({
          UserName: user.UserName,
          Arn: user.Arn,
          CreateDate: user.CreateDate,
          PasswordLastUsed: user.PasswordLastUsed,
        });
      }
      if (!result.IsTruncated || !result.Marker) break;
      marker = result.Marker;
    }
    return users;
  }

  async listMfaDevices(userName: string): Promise<JsonRecord[]> {
    const result = await this.iam.send(new ListMFADevicesCommand({ UserName: userName }));
    return (result.MFADevices ?? []).map((device) => ({
      SerialNumber: device.SerialNumber,
      UserName: device.UserName,
    }));
  }

  async listAccessKeys(userName: string): Promise<JsonRecord[]> {
    const result = await this.iam.send(new ListAccessKeysCommand({ UserName: userName }));
    return (result.AccessKeyMetadata ?? []).map((key) => ({
      AccessKeyId: key.AccessKeyId,
      Status: key.Status,
      CreateDate: key.CreateDate,
      UserName: key.UserName,
    }));
  }

  async getAccessKeyLastUsed(accessKeyId: string): Promise<JsonRecord | null> {
    const result = await this.iam.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: accessKeyId }));
    return asObject(result.AccessKeyLastUsed) ?? null;
  }

  async getAccountAuthorizationDetails(limit = DEFAULT_ROLE_LIMIT): Promise<JsonRecord[]> {
    const roles: JsonRecord[] = [];
    let marker: string | undefined;
    while (roles.length < limit) {
      const result = await this.iam.send(new GetAccountAuthorizationDetailsCommand({
        Filter: ["Role"],
        Marker: marker,
        MaxItems: Math.min(100, limit - roles.length),
      }));
      for (const role of result.RoleDetailList ?? []) {
        roles.push({
          RoleName: role.RoleName,
          Arn: role.Arn,
          PermissionsBoundary: role.PermissionsBoundary,
          AttachedManagedPolicies: role.AttachedManagedPolicies,
          RolePolicyList: role.RolePolicyList,
        });
      }
      if (!result.IsTruncated || !result.Marker) break;
      marker = result.Marker;
    }
    return roles;
  }

  async describeTrails(): Promise<JsonRecord[]> {
    const result = await this.cloudTrail.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
    return (result.trailList ?? []).map((trail) => ({
      Name: trail.Name,
      TrailARN: trail.TrailARN,
      IsMultiRegionTrail: trail.IsMultiRegionTrail,
      LogFileValidationEnabled: trail.LogFileValidationEnabled,
      HomeRegion: trail.HomeRegion,
      S3BucketName: trail.S3BucketName,
    }));
  }

  async getTrailStatus(nameOrArn: string): Promise<JsonRecord> {
    const result = await this.cloudTrail.send(new GetTrailStatusCommand({ Name: nameOrArn }));
    return {
      IsLogging: result.IsLogging,
      LatestCloudWatchLogsDeliveryError: result.LatestCloudWatchLogsDeliveryError,
      LatestDeliveryError: result.LatestDeliveryError,
    };
  }

  async getEventSelectors(nameOrArn: string): Promise<JsonRecord> {
    const result = await this.cloudTrail.send(new GetEventSelectorsCommand({ TrailName: nameOrArn }));
    return {
      EventSelectors: result.EventSelectors ?? [],
      AdvancedEventSelectors: result.AdvancedEventSelectors ?? [],
    };
  }

  async describeSecurityHub(): Promise<JsonRecord | null> {
    try {
      const result = await this.securityHub.send(new DescribeHubCommand({}));
      return {
        HubArn: result.HubArn,
        AutoEnableControls: result.AutoEnableControls,
        SubscribedAt: result.SubscribedAt,
      };
    } catch {
      return null;
    }
  }

  async getEnabledSecurityHubStandards(): Promise<JsonRecord[]> {
    const standards: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.securityHub.send(new GetEnabledStandardsCommand({ MaxResults: 100, NextToken: nextToken }));
      for (const standard of result.StandardsSubscriptions ?? []) {
        standards.push({
          StandardsArn: standard.StandardsArn,
          StandardsStatus: standard.StandardsStatus,
          StandardsSubscriptionArn: standard.StandardsSubscriptionArn,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return standards;
  }

  async describeConfigurationRecorders(): Promise<JsonRecord[]> {
    const result = await this.configService.send(new DescribeConfigurationRecordersCommand({}));
    return (result.ConfigurationRecorders ?? []).map((recorder) => ({
      name: recorder.name,
      recordingGroup: recorder.recordingGroup,
      roleARN: recorder.roleARN,
    }));
  }

  async describeConfigurationRecorderStatus(): Promise<JsonRecord[]> {
    const result = await this.configService.send(new DescribeConfigurationRecorderStatusCommand({}));
    return (result.ConfigurationRecordersStatus ?? []).map((status) => ({
      name: status.name,
      recording: status.recording,
      lastStatus: status.lastStatus,
      lastErrorCode: status.lastErrorCode,
      lastErrorMessage: status.lastErrorMessage,
    }));
  }

  async listDetectors(): Promise<string[]> {
    const result = await this.guardDuty.send(new ListDetectorsCommand({}));
    return result.DetectorIds ?? [];
  }

  async getDetector(detectorId: string): Promise<JsonRecord> {
    const result = await this.guardDuty.send(new GetDetectorCommand({ DetectorId: detectorId }));
    return {
      Status: result.Status,
      FindingPublishingFrequency: result.FindingPublishingFrequency,
      DataSources: result.DataSources,
      Features: result.Features,
    };
  }

  async listAnalyzers(): Promise<JsonRecord[]> {
    const analyzers: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.accessAnalyzer.send(new ListAnalyzersCommand({ nextToken, maxResults: 100 }));
      for (const analyzer of result.analyzers ?? []) {
        analyzers.push({
          arn: analyzer.arn,
          name: analyzer.name,
          type: analyzer.type,
          status: analyzer.status,
        });
      }
      nextToken = result.nextToken;
    } while (nextToken);
    return analyzers;
  }

  async listAccessAnalyzerFindings(analyzerArn: string, limit = DEFAULT_MAX_FINDINGS): Promise<JsonRecord[]> {
    const findings: JsonRecord[] = [];
    let nextToken: string | undefined;
    while (findings.length < limit) {
      const result = await this.accessAnalyzer.send(new ListFindingsCommand({
        analyzerArn,
        maxResults: Math.min(100, limit - findings.length),
        nextToken,
      }));
      for (const finding of result.findings ?? []) {
        findings.push({
          id: finding.id,
          status: finding.status,
          resourceType: finding.resourceType,
          resource: finding.resource,
          principal: finding.principal,
          condition: finding.condition,
        });
      }
      if (!result.nextToken) break;
      nextToken = result.nextToken;
    }
    return findings;
  }

  async describeOrganization(): Promise<JsonRecord | null> {
    try {
      const result = await this.organizations.send(new DescribeOrganizationCommand({}));
      return {
        Id: result.Organization?.Id,
        FeatureSet: result.Organization?.FeatureSet,
        ManagementAccountId: result.Organization?.MasterAccountId,
      };
    } catch {
      return null;
    }
  }

  async listAccounts(limit = 1000): Promise<JsonRecord[]> {
    const accounts: JsonRecord[] = [];
    let nextToken: string | undefined;
    while (accounts.length < limit) {
      const result = await this.organizations.send(new ListAccountsCommand({ NextToken: nextToken, MaxResults: Math.min(20, limit - accounts.length) }));
      for (const account of result.Accounts ?? []) {
        accounts.push({
          Id: account.Id,
          Name: account.Name,
          Status: account.Status,
        });
      }
      if (!result.NextToken) break;
      nextToken = result.NextToken;
    }
    return accounts;
  }

  async listScps(): Promise<JsonRecord[]> {
    const policies: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.organizations.send(new ListPoliciesCommand({
        Filter: "SERVICE_CONTROL_POLICY",
        NextToken: nextToken,
        MaxResults: 20,
      }));
      for (const policy of result.Policies ?? []) {
        policies.push({
          Id: policy.Id,
          Name: policy.Name,
          AwsManaged: policy.AwsManaged,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return policies;
  }

  async listPolicyTargets(policyId: string): Promise<JsonRecord[]> {
    const targets: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.organizations.send(new ListTargetsForPolicyCommand({
        PolicyId: policyId,
        NextToken: nextToken,
      }));
      for (const target of result.Targets ?? []) {
        targets.push({
          TargetId: target.TargetId,
          Name: target.Name,
          Type: target.Type,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return targets;
  }

  async listIdentityCenterInstances(): Promise<JsonRecord[]> {
    try {
      const result = await this.ssoAdmin.send(new ListInstancesCommand({}));
      return (result.Instances ?? []).map((instance) => ({
        InstanceArn: instance.InstanceArn,
        IdentityStoreId: instance.IdentityStoreId,
      }));
    } catch {
      return [];
    }
  }
}

async function surface(
  name: string,
  service: string,
  loader: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<AwsAccessSurface> {
  try {
    const value = await loader();
    return {
      name,
      service,
      status: "readable",
      count: countResolver?.(value),
    };
  } catch (error) {
    return {
      name,
      service,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function checkAwsAccess(
  client: Pick<
    AwsAuditorClient,
    "getCallerIdentity" | "getAccountSummary" | "describeTrails" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "listDetectors" | "listAnalyzers" | "describeOrganization" | "listIdentityCenterInstances" | "getResolvedConfig"
  >,
): Promise<AwsAccessCheckResult> {
  const caller = await client.getCallerIdentity();
  const config = client.getResolvedConfig();
  const surfaces = await Promise.all([
    surface("iam_summary", "iam", () => client.getAccountSummary(), () => 1),
    surface("cloudtrail", "cloudtrail", () => client.describeTrails(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("security_hub", "securityhub", () => client.getEnabledSecurityHubStandards(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("config", "config", () => client.describeConfigurationRecorders(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("guardduty", "guardduty", () => client.listDetectors(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("access_analyzer", "access-analyzer", () => client.listAnalyzers(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("organizations", "organizations", () => client.describeOrganization(), () => 1),
    surface("identity_center", "sso-admin", () => client.listIdentityCenterInstances(), (value) => Array.isArray(value) ? value.length : undefined),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 5 ? "healthy" : "limited";
  const accountId = asString(caller.Account);
  const notes = [
    `Authenticated via ${describeSourceChain(config)}.`,
    accountId ? `Current AWS account: ${accountId}` : "Current AWS account could not be determined.",
    `${readableCount}/${surfaces.length} AWS audit surfaces are readable.`,
  ];

  if (config.accountId && config.accountId !== accountId) {
    notes.push(`Requested account hint ${config.accountId} does not match caller account ${accountId ?? "unknown"}.`);
  }

  return {
    status,
    accountId,
    arn: asString(caller.Arn),
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run aws_assess_identity, aws_assess_logging_detection, aws_assess_org_guardrails, or aws_export_audit_bundle."
        : "Grant read-only access to IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, and Organizations APIs for the audit principal.",
  };
}

function isServiceWildcardAction(value: unknown): boolean {
  const actions = Array.isArray(value) ? value.map(String) : typeof value === "string" ? [value] : [];
  return actions.some((action) => /^[a-z0-9-]+:\*$/i.test(action));
}

function classifyPolicyStatements(document: JsonRecord | null): { fullAdmin: number; serviceWildcard: number } {
  let fullAdmin = 0;
  let serviceWildcard = 0;
  for (const statement of normalizeStatements(document)) {
    if (asString(statement.Effect)?.toLowerCase() !== "allow") continue;
    if (matchesWildcard(statement.Action) && matchesWildcard(statement.Resource)) {
      fullAdmin += 1;
    } else if (isServiceWildcardAction(statement.Action) && matchesWildcard(statement.Resource)) {
      serviceWildcard += 1;
    }
  }
  return { fullAdmin, serviceWildcard };
}

export type AwsIdentityClient = Pick<
  AwsAuditorClient,
  | "getNow"
  | "getResolvedConfig"
  | "getAccountSummary"
  | "getPasswordPolicy"
  | "listIamUsers"
  | "listMfaDevices"
  | "listAccessKeys"
  | "getAccessKeyLastUsed"
  | "getAccountAuthorizationDetails"
  | "lookupRootEvents"
  | "listCustomerManagedPolicies"
  | "getPolicyVersionDocument"
>;

export interface AwsIdentityOptions {
  userLimit?: number;
  staleDays?: number;
  roleLimit?: number;
  maxPrivilegedRoles?: number;
  lookbackDays?: number;
  policyLimit?: number;
}

export async function assessAwsIdentity(
  client: AwsIdentityClient,
  options: AwsIdentityOptions = {},
): Promise<AwsAssessmentResult> {
  const now = client.getNow();
  const errors: string[] = [];
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 5000);
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const roleLimit = clampNumber(options.roleLimit, DEFAULT_ROLE_LIMIT, 1, 5000);
  const maxPrivilegedRoles = clampNumber(options.maxPrivilegedRoles, DEFAULT_MAX_PRIVILEGED_ROLES, 1, 100);
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_ROOT_LOOKBACK_DAYS, 1, 90);
  const policyLimit = clampNumber(options.policyLimit, DEFAULT_POLICY_LIMIT, 1, 10000);
  const lookbackStart = new Date(now.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
  const region = typeof client.getResolvedConfig === "function" ? client.getResolvedConfig().region : DEFAULT_REGION;

  const [summary, passwordPolicy, users, roles, rootEvents, customerPolicies] = await Promise.all([
    client.getAccountSummary(),
    client.getPasswordPolicy(),
    client.listIamUsers(userLimit),
    client.getAccountAuthorizationDetails(roleLimit),
    attemptAwsRead("cloudtrail:LookupEvents Username=root", () => client.lookupRootEvents(lookbackStart, now, DEFAULT_EVENT_LIMIT), errors),
    attemptAwsRead("iam:ListPolicies Scope=Local", () => client.listCustomerManagedPolicies(policyLimit), errors),
  ]);

  const policyRows = await mapWithConcurrency(customerPolicies.value?.items ?? [], DEFAULT_CONCURRENCY, async (policy) => {
    const arn = asString(policy.Arn) ?? "";
    const versionId = asString(policy.DefaultVersionId) ?? "v1";
    const document = await attemptAwsRead(`iam:GetPolicyVersion ${arn}`, () => client.getPolicyVersionDocument(arn, versionId), errors);
    const attached = (asNumber(policy.AttachmentCount) ?? 0) > 0 || (asNumber(policy.PermissionsBoundaryUsageCount) ?? 0) > 0;
    const classification = document.error ? { fullAdmin: 0, serviceWildcard: 0 } : classifyPolicyStatements(document.value ?? null);
    return {
      name: asString(policy.PolicyName) ?? arn,
      arn,
      attached,
      attachment_count: asNumber(policy.AttachmentCount) ?? 0,
      unreadable: Boolean(document.error),
      ...classification,
    };
  });

  const summaryMap = asObject(summary.SummaryMap) ?? {};
  const accountMfaEnabled = asNumber(summaryMap.AccountMFAEnabled) ?? 0;
  const accountAccessKeysPresent = asNumber(summaryMap.AccountAccessKeysPresent) ?? 0;

  const usersWithoutMfa: string[] = [];
  const staleAccessKeys: Array<{ userName: string; accessKeyId: string; ageDays?: number }> = [];
  const dormantUsers: string[] = [];

  for (const user of users) {
    const userName = asString(user.UserName) ?? "unknown";
    const mfaDevices = await client.listMfaDevices(userName);
    if (mfaDevices.length === 0) usersWithoutMfa.push(userName);

    const passwordAge = daysBetween(now, extractTimestamp(user.PasswordLastUsed));
    const accessKeys = await client.listAccessKeys(userName);
    for (const key of accessKeys) {
      const accessKeyId = asString(key.AccessKeyId);
      if (!accessKeyId) continue;
      const lastUsed = await client.getAccessKeyLastUsed(accessKeyId);
      const ageDays = daysBetween(now, extractTimestamp(lastUsed) ?? extractTimestamp(key.CreateDate));
      if (ageDays !== undefined && ageDays > staleDays) {
        staleAccessKeys.push({ userName, accessKeyId, ageDays });
      }
    }

    if ((passwordAge !== undefined && passwordAge > staleDays) || (passwordAge === undefined && accessKeys.length === 0)) {
      dormantUsers.push(userName);
    }
  }

  const privilegedRoles = roles.filter(hasAdministratorPolicy);
  const rolesWithoutBoundaries = privilegedRoles.filter((role) => !role.PermissionsBoundary);

  const findings = [
    finding(
      "AWS-IAM-01",
      "Root account MFA and access keys",
      "critical",
      accountMfaEnabled !== 1 || accountAccessKeysPresent > 0 ? "fail" : "pass",
      accountMfaEnabled !== 1 || accountAccessKeysPresent > 0
        ? `Root MFA enabled=${accountMfaEnabled === 1}; root access keys present=${accountAccessKeysPresent}.`
        : "Root account shows MFA enabled and no access keys present.",
      ["FedRAMP IA-2(1)", "FedRAMP AC-6(1)", "CMMC 3.1.5", "CIS AWS 1.4"],
      { account_mfa_enabled: accountMfaEnabled, account_access_keys_present: accountAccessKeysPresent },
    ),
    finding(
      "AWS-IAM-02",
      "IAM user MFA coverage",
      "high",
      usersWithoutMfa.length > 0 ? "fail" : "pass",
      usersWithoutMfa.length > 0
        ? `${usersWithoutMfa.length}/${users.length} IAM users are missing MFA.`
        : "All sampled IAM users have MFA devices.",
      ["FedRAMP IA-2(1)", "FedRAMP IA-2(2)", "CMMC 3.5.3", "PCI-DSS 8.4.2"],
      { user_count: users.length, users_without_mfa: usersWithoutMfa.slice(0, 25) },
    ),
    finding(
      "AWS-IAM-03",
      "Password policy strength",
      "high",
      !passwordPolicy
        || (asNumber(passwordPolicy.MinimumPasswordLength) ?? 0) < 14
        || passwordPolicy.RequireSymbols !== true
        || passwordPolicy.RequireNumbers !== true
        || passwordPolicy.RequireUppercaseCharacters !== true
        || passwordPolicy.RequireLowercaseCharacters !== true
        ? "fail"
        : "pass",
      !passwordPolicy
        ? "No account password policy was visible."
        : `Minimum length ${(asNumber(passwordPolicy.MinimumPasswordLength) ?? 0)} with complexity requirements present=${[
            passwordPolicy.RequireSymbols,
            passwordPolicy.RequireNumbers,
            passwordPolicy.RequireUppercaseCharacters,
            passwordPolicy.RequireLowercaseCharacters,
          ].every((value) => value === true)}.`,
      ["FedRAMP IA-5(1)", "CMMC 3.5.7", "SOC 2 CC6.1", "CIS AWS 1.8"],
      { password_policy: passwordPolicy ?? {} },
    ),
    finding(
      "AWS-IAM-04",
      "Access key rotation",
      "high",
      staleAccessKeys.length > 0 ? "fail" : "pass",
      staleAccessKeys.length > 0
        ? `${staleAccessKeys.length} access keys are older than ${staleDays} days or unused beyond that threshold.`
        : `No sampled access key exceeded the ${staleDays}-day staleness threshold.`,
      ["FedRAMP IA-5(1)", "FedRAMP AC-2(3)", "CMMC 3.5.8", "CIS AWS 1.12"],
      { stale_access_keys: staleAccessKeys.slice(0, 25) },
    ),
    finding(
      "AWS-IAM-05",
      "Privileged role boundaries",
      "medium",
      rolesWithoutBoundaries.length > maxPrivilegedRoles ? "fail" : rolesWithoutBoundaries.length > 0 ? "warn" : "pass",
      rolesWithoutBoundaries.length > 0
        ? `${rolesWithoutBoundaries.length}/${privilegedRoles.length} privileged roles lack permission boundaries.`
        : "No sampled privileged role lacked a permission boundary.",
      ["FedRAMP AC-6(1)", "FedRAMP AC-6(2)", "CMMC 3.1.5", "CIS AWS 1.16"],
      {
        privileged_roles: privilegedRoles.length,
        roles_without_boundaries: rolesWithoutBoundaries.slice(0, 25).map((role) => role.RoleName ?? role.Arn),
        max_privileged_roles: maxPrivilegedRoles,
      },
    ),
    finding(
      "AWS-IAM-06",
      "Dormant IAM users",
      "low",
      dormantUsers.length > 0 ? "warn" : "pass",
      dormantUsers.length > 0
        ? `${dormantUsers.length} IAM users appear dormant beyond ${staleDays} days or without recent password activity.`
        : "No dormant IAM users were detected from the sampled password activity.",
      ["FedRAMP AC-2(3)", "CMMC 3.1.12", "SOC 2 CC6.2", "CIS AWS 1.12"],
      { dormant_users: dormantUsers.slice(0, 25) },
    ),
  ];

  // Control 4 (root sign-ins): CloudTrail LookupEvents for Username root within the lookback window.
  const rootEventList = rootEvents.value?.items ?? [];
  const rootConsoleLogins = rootEventList.filter((event) => asString(event.EventName) === "ConsoleLogin");
  const rootOtherEvents = rootEventList.filter((event) => asString(event.EventName) !== "ConsoleLogin");
  const undatedRootEvents = rootEventList.filter((event) => extractTimestamp(event.EventTime) === undefined);
  let rootStatus: AwsFinding["status"];
  let rootSummary: string;
  if (rootEvents.error) {
    rootStatus = "manual";
    rootSummary = `Root activity could not be read from CloudTrail LookupEvents (${rootEvents.error}); review root sign-in history in the CloudTrail console or IAM credential report.`;
  } else if (rootConsoleLogins.length > 0) {
    rootStatus = "fail";
    rootSummary = `${rootConsoleLogins.length} root ConsoleLogin event(s) were recorded in the last ${lookbackDays} days (region ${region}); root should not be used for daily or administrative tasks.`;
  } else if (rootOtherEvents.length > 0) {
    rootStatus = "warn";
    rootSummary = `No root ConsoleLogin events, but ${rootOtherEvents.length} other root API event(s) were recorded in the last ${lookbackDays} days (region ${region}); confirm each was a sanctioned root-only task.`;
  } else {
    rootStatus = "pass";
    rootSummary = `No CloudTrail events attributed to the root user were found in the last ${lookbackDays} days in region ${region}. Global sign-in events are recorded in us-east-1, so run there for console sign-in coverage.`;
  }
  const rootCaps: string[] = [];
  if (rootEvents.value?.truncated) rootCaps.push(`event lookup truncated at ${DEFAULT_EVENT_LIMIT}`);
  if (undatedRootEvents.length > 0) rootCaps.push(`${undatedRootEvents.length} event(s) without EventTime`);
  const rootVerdict = withCap(rootStatus, rootSummary, rootCaps);
  findings.push(finding(
    "AWS-IAM-07",
    "Root account activity",
    "high",
    rootVerdict.status,
    rootVerdict.summary,
    buildAwsMappings(4),
    {
      region,
      lookback_days: lookbackDays,
      window_start: lookbackStart.toISOString(),
      root_events: rootEventList.length,
      root_console_logins: sample(rootConsoleLogins.map((event) => ({ time: event.EventTime, source: event.EventSource }))),
      root_other_events: sample(rootOtherEvents.map((event) => ({ time: event.EventTime, name: event.EventName, source: event.EventSource }))),
      lookup_truncated: rootEvents.value?.truncated ?? false,
    },
  ));

  // Control 18 (least privilege): customer-managed policies with wildcard Action and Resource.
  const fullAdminAttached = policyRows.filter((row) => row.fullAdmin > 0 && row.attached);
  const fullAdminUnattached = policyRows.filter((row) => row.fullAdmin > 0 && !row.attached);
  const serviceWildcardPolicies = policyRows.filter((row) => row.fullAdmin === 0 && row.serviceWildcard > 0);
  const unreadablePolicies = policyRows.filter((row) => row.unreadable);
  let leastPrivilegeStatus: AwsFinding["status"];
  let leastPrivilegeSummary: string;
  if (customerPolicies.error) {
    leastPrivilegeStatus = "manual";
    leastPrivilegeSummary = `Customer-managed policies could not be listed (${customerPolicies.error}); review IAM policies for wildcard actions and resources manually.`;
  } else if (fullAdminAttached.length > 0) {
    leastPrivilegeStatus = "fail";
    leastPrivilegeSummary = `${fullAdminAttached.length}/${policyRows.length} customer-managed policies grant Allow with Action "*" and Resource "*" and are attached or used as boundaries.`;
  } else if (policyRows.length === 0) {
    leastPrivilegeStatus = "manual";
    leastPrivilegeSummary = "No customer-managed IAM policies exist to evaluate. Inline user, group, and role policies are not evaluated by this check; review them manually.";
  } else if (fullAdminUnattached.length > 0 || serviceWildcardPolicies.length > 0) {
    leastPrivilegeStatus = "warn";
    leastPrivilegeSummary = `${fullAdminUnattached.length} unattached customer-managed policies grant full "*":"*" access and ${serviceWildcardPolicies.length} grant service-wide wildcard actions on Resource "*"; scope them down or remove them.`;
  } else {
    leastPrivilegeStatus = "pass";
    leastPrivilegeSummary = `None of the ${policyRows.length} customer-managed policies grants Allow with wildcard Action and Resource. Inline policies are not evaluated by this check.`;
  }
  const leastPrivilegeCaps: string[] = [];
  if (unreadablePolicies.length > 0) leastPrivilegeCaps.push(`${unreadablePolicies.length} policy version(s) unreadable`);
  if (customerPolicies.value?.truncated) leastPrivilegeCaps.push(`policy inventory truncated at ${policyLimit}`);
  const leastPrivilegeVerdict = withCap(leastPrivilegeStatus, leastPrivilegeSummary, leastPrivilegeCaps);
  findings.push(finding(
    "AWS-IAM-08",
    "Customer-managed policy wildcards",
    "high",
    leastPrivilegeVerdict.status,
    leastPrivilegeVerdict.summary,
    buildAwsMappings(18),
    {
      customer_managed_policies: policyRows.length,
      full_admin_attached: sample(fullAdminAttached.map((row) => ({ name: row.name, attachment_count: row.attachment_count }))),
      full_admin_unattached: sample(fullAdminUnattached.map((row) => row.name)),
      service_wildcard_policies: sample(serviceWildcardPolicies.map((row) => row.name)),
      policies_unreadable: sample(unreadablePolicies.map((row) => row.name)),
      policy_inventory_truncated: customerPolicies.value?.truncated ?? false,
      inline_policies: "not assessed",
    },
  ));

  return {
    title: "AWS identity posture",
    summary: {
      users: users.length,
      users_without_mfa: usersWithoutMfa.length,
      stale_access_keys: staleAccessKeys.length,
      privileged_roles: privilegedRoles.length,
      roles_without_boundaries: rolesWithoutBoundaries.length,
      dormant_users: dormantUsers.length,
      root_console_logins: rootConsoleLogins.length,
      customer_managed_policies: policyRows.length,
      full_admin_policies_attached: fullAdminAttached.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function hasAnyDataEvents(selectors: JsonRecord): boolean {
  const eventSelectors = Array.isArray(selectors.EventSelectors) ? selectors.EventSelectors : [];
  const advanced = Array.isArray(selectors.AdvancedEventSelectors) ? selectors.AdvancedEventSelectors : [];
  return eventSelectors.some((selector) => {
    const item = asObject(selector);
    const resources = Array.isArray(item?.DataResources) ? item?.DataResources : [];
    return resources.length > 0;
  }) || advanced.length > 0;
}

export async function assessAwsLoggingDetection(
  client: Pick<
    AwsAuditorClient,
    "describeTrails" | "getTrailStatus" | "getEventSelectors" | "describeSecurityHub" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "describeConfigurationRecorderStatus" | "listDetectors" | "getDetector"
  >,
): Promise<AwsAssessmentResult> {
  const [trails, hub, standards, recorders, recorderStatuses, detectorIds] = await Promise.all([
    client.describeTrails(),
    client.describeSecurityHub(),
    client.getEnabledSecurityHubStandards().catch(() => []),
    client.describeConfigurationRecorders().catch(() => []),
    client.describeConfigurationRecorderStatus().catch(() => []),
    client.listDetectors().catch(() => []),
  ]);

  const trailDetails = await Promise.all(trails.map(async (trail) => {
    const nameOrArn = asString(trail.TrailARN) ?? asString(trail.Name) ?? "";
    const status = nameOrArn ? await client.getTrailStatus(nameOrArn).catch(() => ({})) : {};
    const selectors = nameOrArn ? await client.getEventSelectors(nameOrArn).catch(() => ({})) : {};
    return {
      Name: asString(trail.Name),
      TrailARN: asString(trail.TrailARN),
      IsMultiRegionTrail: trail.IsMultiRegionTrail === true,
      LogFileValidationEnabled: trail.LogFileValidationEnabled === true,
      status: asObject(status) ?? {},
      selectors: asObject(selectors) ?? {},
    } as JsonRecord;
  }));

  const goodTrails = trailDetails.filter((trail) =>
    trail.IsMultiRegionTrail === true
    && trail.LogFileValidationEnabled === true
    && asObject(trail.status)?.IsLogging === true,
  );
  const trailsWithDataEvents = trailDetails.filter((trail) => hasAnyDataEvents(asObject(trail.selectors) ?? {}));

  const configHealthy = recorders.some((recorder) => {
    const name = asString(recorder.name);
    const status = recorderStatuses.find((item) => asString(item.name) === name);
    return status?.recording === true;
  });

  const detectors = await Promise.all(detectorIds.map((detectorId) =>
    client.getDetector(detectorId).catch(() => ({} as JsonRecord)),
  ));
  const enabledDetectors = detectors.filter((detector) => asString(detector.Status) === "ENABLED");

  const findings = [
    finding(
      "AWS-LOG-01",
      "Multi-region CloudTrail with validation",
      "critical",
      goodTrails.length > 0 ? "pass" : "fail",
      goodTrails.length > 0
        ? `${goodTrails.length} CloudTrail trail(s) are multi-region, logging, and log-file validation enabled.`
        : "No multi-region CloudTrail trail with active logging and log-file validation was detected.",
      ["FedRAMP AU-2", "FedRAMP AU-9", "CMMC 3.3.1", "CIS AWS 3.1"],
      { trails: trailDetails.map((trail) => ({ name: trail.Name, is_multi_region: trail.IsMultiRegionTrail, validation: trail.LogFileValidationEnabled, is_logging: asObject(trail.status)?.IsLogging })) },
    ),
    finding(
      "AWS-LOG-02",
      "CloudTrail data events",
      "medium",
      trailsWithDataEvents.length > 0 ? "pass" : "warn",
      trailsWithDataEvents.length > 0
        ? `${trailsWithDataEvents.length} trail(s) capture data events or advanced event selectors.`
        : "No CloudTrail data event coverage was detected.",
      ["FedRAMP AU-12", "CMMC 3.3.1", "SOC 2 CC7.2", "CIS AWS 3.3"],
      { data_event_trails: trailsWithDataEvents.map((trail) => trail.Name ?? trail.TrailARN) },
    ),
    finding(
      "AWS-LOG-03",
      "Security Hub enablement",
      "high",
      hub && standards.length > 0 ? "pass" : hub ? "warn" : "fail",
      hub
        ? `${standards.length} enabled Security Hub standard subscription(s) were visible.`
        : "Security Hub does not appear enabled in the configured region.",
      ["FedRAMP CA-7", "FedRAMP SI-4", "SOC 2 CC7.1", "PCI-DSS 11.5.1"],
      { hub_enabled: Boolean(hub), standard_count: standards.length },
    ),
    finding(
      "AWS-LOG-04",
      "GuardDuty detectors",
      "high",
      enabledDetectors.length > 0 ? "pass" : "fail",
      enabledDetectors.length > 0
        ? `${enabledDetectors.length} GuardDuty detector(s) are enabled.`
        : "No enabled GuardDuty detector was detected.",
      ["FedRAMP SI-4", "FedRAMP IR-4", "SOC 2 CC7.2", "CIS AWS 1.1"],
      { detector_count: detectorIds.length, enabled_detectors: enabledDetectors.length },
    ),
    finding(
      "AWS-LOG-05",
      "AWS Config recording",
      "high",
      configHealthy ? "pass" : "fail",
      configHealthy
        ? `${recorders.length} configuration recorder(s) were visible with active recording.`
        : "No active AWS Config recorder was detected.",
      ["FedRAMP CM-2", "FedRAMP CM-6", "SOC 2 CC7.1", "CIS AWS 3.5"],
      {
        recorders: recorders.map((recorder) => ({ name: recorder.name, all_supported: asObject(recorder.recordingGroup)?.allSupported })),
        recorder_statuses: recorderStatuses,
      },
    ),
  ];

  return {
    title: "AWS logging and detection posture",
    summary: {
      trails: trailDetails.length,
      compliant_trails: goodTrails.length,
      security_hub_standards: standards.length,
      guardduty_detectors: detectorIds.length,
      enabled_guardduty_detectors: enabledDetectors.length,
      config_recorders: recorders.length,
    },
    findings,
  };
}

export type AwsOrgGuardrailsClient = Pick<
  AwsAuditorClient,
  | "describeOrganization"
  | "listAccounts"
  | "listScps"
  | "listPolicyTargets"
  | "listAnalyzers"
  | "listAccessAnalyzerFindings"
  | "listIdentityCenterInstances"
  | "listActiveAuditManagerAssessments"
  | "getSecurityAlternateContact"
>;

export async function assessAwsOrgGuardrails(
  client: AwsOrgGuardrailsClient,
  options: { maxFindings?: number } = {},
): Promise<AwsAssessmentResult> {
  const errors: string[] = [];
  const maxFindings = clampNumber(options.maxFindings, DEFAULT_MAX_FINDINGS, 1, 5000);
  const [organization, accounts, scps, analyzers, identityCenterInstances, auditAssessments, securityContact] = await Promise.all([
    client.describeOrganization().catch(() => null),
    client.listAccounts().catch(() => []),
    client.listScps().catch(() => []),
    client.listAnalyzers().catch(() => []),
    client.listIdentityCenterInstances().catch(() => []),
    attemptAwsRead("auditmanager:ListAssessments status=ACTIVE", () => client.listActiveAuditManagerAssessments(), errors),
    attemptAwsRead("account:GetAlternateContact SECURITY", () => client.getSecurityAlternateContact(), errors),
  ]);

  const scpTargets = await Promise.all(scps.map(async (policy) => ({
    policyId: asString(policy.Id) ?? "",
    name: asString(policy.Name) ?? asString(policy.Id) ?? "policy",
    targets: await client.listPolicyTargets(asString(policy.Id) ?? "").catch(() => []),
  })));
  const attachedScps = scpTargets.filter((policy) => policy.targets.length > 0);

  const activeAnalyzers = analyzers.filter((analyzer) => asString(analyzer.status) === "ACTIVE");
  const findingLists = await Promise.all(activeAnalyzers.map(async (analyzer) => ({
    analyzerArn: asString(analyzer.arn) ?? "",
    findings: await client.listAccessAnalyzerFindings(asString(analyzer.arn) ?? "", maxFindings).catch(() => []),
  })));
  const activeExternalFindings = findingLists.flatMap((item) => item.findings).filter((finding) => {
    const status = asString(finding.status)?.toUpperCase();
    return !status || status === "ACTIVE";
  });

  const findings = [
    finding(
      "AWS-ORG-01",
      "Organizations visibility",
      "medium",
      organization ? "pass" : "warn",
      organization
        ? `AWS Organizations is visible with ${accounts.length} account(s).`
        : "AWS Organizations data was not visible; this may be a standalone account or missing permissions.",
      ["FedRAMP PM-2", "SOC 2 CC2.1", "CIS AWS 1.1"],
      { organization: organization ?? {}, accounts: accounts.length },
    ),
    finding(
      "AWS-ORG-02",
      "Service control policies",
      "high",
      scps.length === 0 ? "warn" : attachedScps.length > 0 ? "pass" : "fail",
      scps.length === 0
        ? "No service control policies were visible."
        : attachedScps.length > 0
          ? `${attachedScps.length}/${scps.length} SCPs are attached to at least one target.`
          : "SCPs exist but none appeared attached to accounts or OUs.",
      ["FedRAMP AC-3", "FedRAMP CM-7", "SOC 2 CC6.8", "CIS AWS 1.20"],
      { scp_count: scps.length, attached_scp_count: attachedScps.length, sample: attachedScps.slice(0, 20) },
    ),
    finding(
      "AWS-ORG-03",
      "Access Analyzer enablement",
      "high",
      activeAnalyzers.length > 0 ? "pass" : "fail",
      activeAnalyzers.length > 0
        ? `${activeAnalyzers.length} active Access Analyzer instance(s) were visible.`
        : "No active IAM Access Analyzer instance was detected.",
      ["FedRAMP AC-3", "FedRAMP AC-6", "SOC 2 CC6.3", "CIS AWS 1.16"],
      { analyzers: analyzers },
    ),
    finding(
      "AWS-ORG-04",
      "External access findings",
      activeExternalFindings.length > 0 ? "high" : "low",
      activeExternalFindings.length > 0 ? "warn" : "pass",
      activeExternalFindings.length > 0
        ? `${activeExternalFindings.length} active Access Analyzer finding(s) indicate external or cross-account access to review.`
        : "No active Access Analyzer findings were visible in the sampled analyzers.",
      ["FedRAMP AC-3", "FedRAMP AC-4", "SOC 2 CC6.6", "CIS AWS 1.16"],
      { active_finding_count: activeExternalFindings.length, sample: activeExternalFindings.slice(0, 20) },
    ),
    finding(
      "AWS-ORG-05",
      "Identity Center visibility",
      "low",
      identityCenterInstances.length > 0 ? "pass" : "warn",
      identityCenterInstances.length > 0
        ? `${identityCenterInstances.length} IAM Identity Center instance(s) were visible.`
        : "No IAM Identity Center instance was visible from the configured region and credentials.",
      ["FedRAMP AC-2", "FedRAMP IA-2", "SOC 2 CC6.2", "PCI-DSS 8.4.2"],
      { identity_center_instances: identityCenterInstances.length },
    ),
  ];

  // Control 24: Audit Manager assessments actively collecting evidence.
  const activeAssessments = auditAssessments.value?.items ?? [];
  const undatedAssessments = activeAssessments.filter((assessment) => extractTimestamp(assessment.lastUpdated) === undefined && extractTimestamp(assessment.creationTime) === undefined);
  let auditStatus: AwsFinding["status"];
  let auditSummary: string;
  if (auditAssessments.error) {
    auditStatus = "manual";
    auditSummary = `AWS Audit Manager assessments could not be listed (${auditAssessments.error}). Audit Manager may not be set up in this region; verify in the Audit Manager console or record the control as not applicable.`;
  } else if (activeAssessments.length === 0) {
    auditStatus = "fail";
    auditSummary = "AWS Audit Manager is reachable but has no ACTIVE assessments collecting evidence; create an assessment from a framework or record the control as not applicable if evidence is collected elsewhere.";
  } else {
    auditStatus = "pass";
    auditSummary = `${activeAssessments.length} AWS Audit Manager assessment(s) are ACTIVE and collecting evidence.`;
  }
  const auditCaps: string[] = [];
  if (undatedAssessments.length > 0) auditCaps.push(`${undatedAssessments.length} assessment(s) without creation or update timestamps`);
  if (auditAssessments.value?.truncated) auditCaps.push(`assessment list truncated at ${DEFAULT_MAX_FINDINGS}`);
  const auditVerdict = withCap(auditStatus, auditSummary, auditCaps);
  findings.push(finding(
    "AWS-ORG-06",
    "Audit Manager active assessments",
    "medium",
    auditVerdict.status,
    auditVerdict.summary,
    buildAwsMappings(24),
    {
      active_assessments: activeAssessments.length,
      assessments: sample(activeAssessments.map((assessment) => ({ name: assessment.name, compliance_type: assessment.complianceType, last_updated: assessment.lastUpdated }))),
      list_truncated: auditAssessments.value?.truncated ?? false,
    },
  ));

  // Control 25: account security alternate contact.
  const contact = securityContact.value ?? undefined;
  const contactEmail = asString(contact?.EmailAddress);
  const contactPhone = asString(contact?.PhoneNumber);
  let contactStatus: AwsFinding["status"];
  let contactSummary: string;
  if (securityContact.error) {
    contactStatus = "manual";
    contactSummary = `The account SECURITY alternate contact could not be read (${securityContact.error}); verify it under Account settings in the console.`;
  } else if (securityContact.value === null) {
    contactStatus = "fail";
    contactSummary = "No SECURITY alternate contact is configured on the account (GetAlternateContact returned ResourceNotFoundException); AWS security notifications reach only the root email.";
  } else if (!contactEmail || !contactPhone) {
    contactStatus = "warn";
    contactSummary = `A SECURITY alternate contact exists but is missing ${!contactEmail ? "an email address" : "a phone number"}; complete the contact so security notifications are actionable.`;
  } else {
    contactStatus = "pass";
    contactSummary = `A SECURITY alternate contact is configured with a name, email address (${contactEmail.replace(/^[^@]+/, "***")}), and phone number. Billing and operations contacts are not assessed by this check.`;
  }
  findings.push(finding(
    "AWS-ORG-07",
    "Account security contact",
    "medium",
    contactStatus,
    contactSummary,
    buildAwsMappings(25),
    {
      security_contact_configured: securityContact.value !== null && securityContact.value !== undefined,
      name: asString(contact?.Name) ?? null,
      title: asString(contact?.Title) ?? null,
      email_domain: contactEmail?.includes("@") ? contactEmail.slice(contactEmail.indexOf("@")) : null,
      has_phone: Boolean(contactPhone),
      billing_and_operations_contacts: "not assessed",
    },
  ));

  return {
    title: "AWS organization guardrails",
    summary: {
      accounts: accounts.length,
      scps: scps.length,
      attached_scps: attachedScps.length,
      analyzers: analyzers.length,
      active_external_findings: activeExternalFindings.length,
      identity_center_instances: identityCenterInstances.length,
      audit_manager_active_assessments: activeAssessments.length,
      security_contact_configured: securityContact.value !== null && securityContact.value !== undefined,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

export interface AwsScopeOptions {
  regions?: string[];
  regionLimit?: number;
}

export interface AwsDataProtectionOptions extends AwsScopeOptions {
  bucketLimit?: number;
  keyLimit?: number;
  instanceLimit?: number;
}

export type AwsDataProtectionClient = Pick<
  AwsAuditorClient,
  | "getResolvedConfig"
  | "getCallerIdentity"
  | "describeRegions"
  | "getAccountPublicAccessBlock"
  | "listBuckets"
  | "getBucketPublicAccessBlock"
  | "getBucketPolicyStatus"
  | "getBucketEncryption"
  | "getBucketPolicy"
  | "getEbsEncryptionByDefault"
  | "describeDbInstances"
  | "listKmsKeys"
  | "describeKmsKey"
  | "getKeyRotationStatus"
>;

async function resolveAssessmentScope(
  client: Pick<AwsAuditorClient, "getResolvedConfig" | "describeRegions">,
  options: AwsScopeOptions,
  errors: string[],
): Promise<AwsRegionScope> {
  const regionLimit = clampNumber(options.regionLimit, DEFAULT_REGION_LIMIT, 1, 100);
  const requested = options.regions && options.regions.length > 0 ? options.regions : undefined;
  const described: AwsSurfaceResult<string[]> = requested
    ? {}
    : await attemptAwsRead("ec2:DescribeRegions", () => client.describeRegions(), errors);
  const scope = resolveRegionScope(requested, described, client.getResolvedConfig().region, regionLimit);
  if (scope.source === "configured-region-fallback") {
    errors.push(`Region scope fell back to ${scope.regions[0]} only: ${scope.error}`);
  } else if (scope.partial) {
    errors.push(`Region scope truncated to ${scope.regionsSeen} of ${scope.regionsTotal} regions by region_limit.`);
  }
  return scope;
}

function scopeEvidence(scope: AwsRegionScope): JsonRecord {
  return {
    regions_seen: scope.regionsSeen,
    regions_total: scope.regionsTotal,
    regions: scope.regions,
    partial: scope.partial,
    source: scope.source,
  };
}

function withCap(status: AwsFinding["status"], summary: string, reasons: string[]): { status: AwsFinding["status"]; summary: string } {
  if (status !== "pass" || reasons.length === 0) return { status, summary };
  return { status: "warn", summary: `${summary} Downgraded to warn: ${reasons.join("; ")}.` };
}

function sample<T>(items: T[], limit = 25): T[] {
  return items.slice(0, limit);
}

export async function assessAwsDataProtection(
  client: AwsDataProtectionClient,
  options: AwsDataProtectionOptions = {},
): Promise<AwsAssessmentResult> {
  const errors: string[] = [];
  const bucketLimit = clampNumber(options.bucketLimit, DEFAULT_BUCKET_LIMIT, 1, 10000);
  const keyLimit = clampNumber(options.keyLimit, DEFAULT_KEY_LIMIT, 1, 10000);
  const instanceLimit = clampNumber(options.instanceLimit, DEFAULT_INSTANCE_LIMIT, 1, 10000);
  const config = client.getResolvedConfig();
  const scope = await resolveAssessmentScope(client, options, errors);

  const identity = await attemptAwsRead("sts:GetCallerIdentity", () => client.getCallerIdentity(), errors);
  const accountId = asString(identity.value?.Account) ?? config.accountId;
  const accountBlock: AwsSurfaceResult<JsonRecord | null> = accountId
    ? await attemptAwsRead("s3control:GetPublicAccessBlock", () => client.getAccountPublicAccessBlock(accountId), errors)
    : { error: "s3control:GetPublicAccessBlock: skipped because the account id could not be determined" };
  if (!accountId) errors.push(accountBlock.error ?? "account id unknown");

  const bucketList = await attemptAwsRead("s3:ListBuckets", () => client.listBuckets(bucketLimit), errors);
  const buckets = bucketList.value?.items ?? [];
  const bucketsTruncated = bucketList.value?.truncated === true;
  if (bucketsTruncated) errors.push(`s3:ListBuckets: inventory truncated at bucket_limit ${bucketLimit}; verdicts cover the first ${bucketLimit} buckets only.`);

  const bucketDetails = await mapWithConcurrency(buckets, DEFAULT_CONCURRENCY, async (bucket) => {
    const name = asString(bucket.Name) ?? "";
    const [publicAccessBlock, policyStatus, encryption, policy] = await Promise.all([
      attemptAwsRead(`s3:GetPublicAccessBlock ${name}`, () => client.getBucketPublicAccessBlock(name), errors),
      attemptAwsRead(`s3:GetBucketPolicyStatus ${name}`, () => client.getBucketPolicyStatus(name), errors),
      attemptAwsRead(`s3:GetBucketEncryption ${name}`, () => client.getBucketEncryption(name), errors),
      attemptAwsRead(`s3:GetBucketPolicy ${name}`, () => client.getBucketPolicy(name), errors),
    ]);
    return { name, region: asString(bucket.BucketRegion), publicAccessBlock, policyStatus, encryption, policy };
  });

  const regionResults = await mapWithConcurrency(scope.regions, 4, async (region) => {
    const [ebs, rds, kmsKeys] = await Promise.all([
      attemptAwsRead(`ec2:GetEbsEncryptionByDefault ${region}`, () => client.getEbsEncryptionByDefault(region), errors),
      attemptAwsRead(`rds:DescribeDBInstances ${region}`, () => client.describeDbInstances(region, instanceLimit), errors),
      attemptAwsRead(`kms:ListKeys ${region}`, () => client.listKmsKeys(region, keyLimit), errors),
    ]);
    if (rds.value?.truncated) errors.push(`rds:DescribeDBInstances ${region}: inventory truncated at instance_limit ${instanceLimit}.`);
    if (kmsKeys.value?.truncated) errors.push(`kms:ListKeys ${region}: inventory truncated at key_limit ${keyLimit}.`);
    const keys = await mapWithConcurrency(kmsKeys.value?.items ?? [], DEFAULT_CONCURRENCY, async (key) => {
      const keyId = asString(key.KeyId) ?? asString(key.KeyArn) ?? "";
      const metadata = await attemptAwsRead(`kms:DescribeKey ${region}/${keyId}`, () => client.describeKmsKey(region, keyId), errors);
      const manager = asString(metadata.value?.KeyManager);
      const eligible = manager === "CUSTOMER"
        && asString(metadata.value?.KeyState) === "Enabled"
        && asString(metadata.value?.KeySpec) === "SYMMETRIC_DEFAULT"
        && asString(metadata.value?.Origin) === "AWS_KMS";
      const rotation = eligible
        ? await attemptAwsRead(`kms:GetKeyRotationStatus ${region}/${keyId}`, () => client.getKeyRotationStatus(region, keyId), errors)
        : undefined;
      return { region, keyId, manager, metadata, eligible, rotation };
    });
    return { region, ebs, rds, kmsKeys, keys };
  });

  // Control 11: S3 Block Public Access (account plus bucket).
  const accountFlags = publicAccessFlags(accountBlock.value ?? undefined);
  const accountConfigured = accountBlock.value !== null && accountBlock.value !== undefined;
  const accountFull = accountConfigured && allPublicAccessFlagsTrue(accountFlags);
  const publicAccessRows = bucketDetails.map((bucket) => {
    const flags = publicAccessFlags(bucket.publicAccessBlock.value ?? undefined);
    return {
      name: bucket.name,
      block_configured: bucket.publicAccessBlock.value !== null && bucket.publicAccessBlock.value !== undefined,
      flags,
      bucket_full: bucket.publicAccessBlock.value ? allPublicAccessFlagsTrue(flags) : false,
      is_public: boolFlag(bucket.policyStatus.value ?? undefined, "IsPublic"),
      unreadable: Boolean(bucket.publicAccessBlock.error || bucket.policyStatus.error),
    };
  });
  const publicPolicyBuckets = publicAccessRows.filter((row) => row.is_public === true);
  const uncoveredBuckets = publicAccessRows.filter((row) => !accountFull && !row.bucket_full && !row.unreadable);
  const unreadablePublicAccessBuckets = publicAccessRows.filter((row) => row.unreadable);
  const flagText = REQUIRED_PUBLIC_ACCESS_FLAGS.map((key) => `${key}=${accountFlags[key] ?? "unset"}`).join(", ");

  let publicAccessStatus: AwsFinding["status"];
  let publicAccessSummary: string;
  if (accountBlock.error) {
    publicAccessStatus = "manual";
    publicAccessSummary = `Account-level S3 Block Public Access could not be read (${accountBlock.error}). Capture the S3 console Block Public Access settings for account ${accountId ?? "unknown"} and every bucket manually.`;
  } else if (bucketList.error) {
    publicAccessStatus = "manual";
    publicAccessSummary = `Account-level flags: ${flagText}. The bucket inventory could not be read (${bucketList.error}), so bucket-level exposure is unverified.`;
  } else if (!accountConfigured) {
    publicAccessStatus = "fail";
    publicAccessSummary = `Account-level S3 Block Public Access is not configured (S3 Control returned NoSuchPublicAccessBlockConfiguration); ${uncoveredBuckets.length}/${buckets.length} buckets lack a full bucket-level block and ${publicPolicyBuckets.length} have public bucket policies.`;
  } else if (!accountFull) {
    if (uncoveredBuckets.length > 0 || publicPolicyBuckets.length > 0) {
      publicAccessStatus = "fail";
      publicAccessSummary = `Account-level Block Public Access is incomplete (${flagText}); ${uncoveredBuckets.length}/${buckets.length} buckets lack a full bucket-level block and ${publicPolicyBuckets.length} have public bucket policies.`;
    } else {
      publicAccessStatus = "warn";
      publicAccessSummary = `Account-level Block Public Access is incomplete (${flagText}), but all ${buckets.length} buckets block public access individually and no bucket policy is public.`;
    }
  } else if (publicPolicyBuckets.length > 0) {
    publicAccessStatus = "warn";
    publicAccessSummary = `Account-level Block Public Access is fully enabled, but ${publicPolicyBuckets.length} bucket polic${publicPolicyBuckets.length === 1 ? "y" : "ies"} still evaluate as public (restricted by RestrictPublicBuckets) and should be removed.`;
  } else {
    publicAccessStatus = "pass";
    publicAccessSummary = `Account-level Block Public Access is fully enabled (${flagText}) and none of the ${buckets.length} bucket policies evaluates as public.`;
  }
  const publicAccessCaps: string[] = [];
  if (unreadablePublicAccessBuckets.length > 0) publicAccessCaps.push(`${unreadablePublicAccessBuckets.length} bucket(s) could not be read`);
  if (bucketsTruncated) publicAccessCaps.push(`bucket inventory truncated at ${bucketLimit}`);
  const publicAccessVerdict = withCap(publicAccessStatus, publicAccessSummary, publicAccessCaps);

  // Control 12: encryption at rest defaults (EBS per region, S3 per bucket, RDS per instance).
  const ebsRows = regionResults.map((result) => ({
    region: result.region,
    EbsEncryptionByDefault: boolFlag(result.ebs.value, "EbsEncryptionByDefault"),
    error: result.ebs.error,
  }));
  const ebsOff = ebsRows.filter((row) => row.EbsEncryptionByDefault === false);
  const ebsUnknown = ebsRows.filter((row) => row.EbsEncryptionByDefault === undefined);
  const rdsInstances: Array<JsonRecord & { region: string }> = regionResults.flatMap((result) =>
    (result.rds.value?.items ?? []).map((instance) => ({ ...instance, region: result.region })),
  );
  const rdsUnencrypted = rdsInstances.filter((instance) => instance.StorageEncrypted === false);
  const rdsUnknown = rdsInstances.filter((instance) => typeof instance.StorageEncrypted !== "boolean");
  const rdsErrors = regionResults.filter((result) => result.rds.error);
  const rdsTruncated = regionResults.filter((result) => result.rds.value?.truncated === true);
  const bucketsWithoutSse = bucketDetails.filter((bucket) => {
    if (bucket.encryption.error) return false;
    const rules = Array.isArray(bucket.encryption.value?.Rules) ? bucket.encryption.value.Rules : [];
    return bucket.encryption.value === null || rules.length === 0 || rules.every((rule) => !asString(asObject(rule)?.SSEAlgorithm));
  });
  const bucketEncryptionUnreadable = bucketDetails.filter((bucket) => bucket.encryption.error);

  let encryptionStatus: AwsFinding["status"];
  let encryptionSummary: string;
  if (ebsRows.length > 0 && ebsUnknown.length === ebsRows.length) {
    encryptionStatus = "manual";
    encryptionSummary = `EBS default encryption could not be read in any of ${ebsRows.length} region(s) (${ebsRows[0].error ?? "flag missing"}); verify EBS, S3, and RDS encryption defaults in the console.`;
  } else if (bucketList.error) {
    encryptionStatus = "manual";
    encryptionSummary = `EBS default encryption is disabled in ${ebsOff.length}/${ebsRows.length} region(s) and ${rdsUnencrypted.length}/${rdsInstances.length} RDS instances are unencrypted, but the S3 bucket inventory could not be read (${bucketList.error}).`;
  } else if (ebsOff.length > 0 || rdsUnencrypted.length > 0 || bucketsWithoutSse.length > 0) {
    encryptionStatus = "fail";
    encryptionSummary = `EBS default encryption disabled in ${ebsOff.length}/${ebsRows.length} region(s); ${bucketsWithoutSse.length}/${buckets.length} buckets lack default server-side encryption; ${rdsUnencrypted.length}/${rdsInstances.length} RDS instances have StorageEncrypted=false.`;
  } else {
    encryptionStatus = "pass";
    encryptionSummary = `EBS encryption by default is enabled in all ${ebsRows.length - ebsUnknown.length} readable region(s), all ${buckets.length} buckets have default server-side encryption, and all ${rdsInstances.length} RDS instances report StorageEncrypted=true. EFS is not assessed by this check.`;
  }
  const encryptionCaps: string[] = [];
  if (ebsUnknown.length > 0) encryptionCaps.push(`EBS flag unreadable in ${ebsUnknown.length} region(s)`);
  if (rdsErrors.length > 0) encryptionCaps.push(`RDS unreadable in ${rdsErrors.length} region(s)`);
  if (rdsUnknown.length > 0) encryptionCaps.push(`${rdsUnknown.length} RDS instance(s) without a StorageEncrypted flag`);
  if (rdsTruncated.length > 0) encryptionCaps.push(`RDS inventory truncated in ${rdsTruncated.length} region(s)`);
  if (bucketEncryptionUnreadable.length > 0) encryptionCaps.push(`${bucketEncryptionUnreadable.length} bucket encryption configuration(s) unreadable`);
  if (bucketsTruncated) encryptionCaps.push(`bucket inventory truncated at ${bucketLimit}`);
  if (scope.partial) encryptionCaps.push(`only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`);
  const encryptionVerdict = withCap(encryptionStatus, encryptionSummary, encryptionCaps);

  // Control 13: TLS-only bucket policies (aws:SecureTransport deny).
  const transitRows = bucketDetails.map((bucket) => {
    const statements = bucket.policy.value ? normalizeStatements(bucket.policy.value) : [];
    return {
      name: bucket.name,
      has_policy: typeof bucket.policy.value === "string",
      enforces_tls: statements.some(statementDeniesInsecureTransport),
      unreadable: Boolean(bucket.policy.error),
    };
  });
  const transitMissing = transitRows.filter((row) => !row.enforces_tls && !row.unreadable);
  const transitUnreadable = transitRows.filter((row) => row.unreadable);

  let transitStatus: AwsFinding["status"];
  let transitSummary: string;
  if (bucketList.error) {
    transitStatus = "manual";
    transitSummary = `The S3 bucket inventory could not be read (${bucketList.error}); TLS-only bucket policies and load balancer TLS policies must be verified manually.`;
  } else if (buckets.length === 0) {
    transitStatus = "manual";
    transitSummary = "No S3 buckets exist to evaluate for aws:SecureTransport deny statements. Load balancer and API endpoint TLS policies are not assessed by this tool; verify them manually.";
  } else if (transitMissing.length > 0) {
    transitStatus = "fail";
    transitSummary = `${transitMissing.length}/${buckets.length} buckets have no policy statement denying requests with aws:SecureTransport=false. Load balancer and API endpoint TLS policies are not assessed by this tool.`;
  } else {
    transitStatus = "pass";
    transitSummary = `All ${buckets.length} buckets carry a Deny statement for aws:SecureTransport=false. Load balancer and API endpoint TLS policies are not assessed by this tool.`;
  }
  const transitCaps: string[] = [];
  if (transitUnreadable.length > 0) transitCaps.push(`${transitUnreadable.length} bucket polic${transitUnreadable.length === 1 ? "y" : "ies"} unreadable`);
  if (bucketsTruncated) transitCaps.push(`bucket inventory truncated at ${bucketLimit}`);
  const transitVerdict = withCap(transitStatus, transitSummary, transitCaps);

  // Control 22: customer-managed KMS key rotation.
  const keyRows = regionResults.flatMap((result) => result.keys);
  const kmsListErrors = regionResults.filter((result) => result.kmsKeys.error);
  const kmsListsAllFailed = regionResults.length > 0 && kmsListErrors.length === regionResults.length;
  const customerKeys = keyRows.filter((key) => key.manager === "CUSTOMER");
  const managerUnknown = keyRows.filter((key) => key.manager === undefined);
  const eligibleKeys = keyRows.filter((key) => key.eligible);
  const notRotating = eligibleKeys.filter((key) => boolFlag(key.rotation?.value, "KeyRotationEnabled") === false);
  const rotationUnknown = eligibleKeys.filter((key) => boolFlag(key.rotation?.value, "KeyRotationEnabled") === undefined);
  const ineligibleCustomerKeys = customerKeys.filter((key) => !key.eligible);
  const kmsTruncated = regionResults.filter((result) => result.kmsKeys.value?.truncated === true);

  let kmsStatus: AwsFinding["status"];
  let kmsSummary: string;
  if (kmsListsAllFailed) {
    kmsStatus = "manual";
    kmsSummary = `KMS keys could not be listed in any of ${regionResults.length} region(s) (${kmsListErrors[0]?.kmsKeys.error ?? "unknown error"}); verify customer-managed key rotation in the KMS console.`;
  } else if (notRotating.length > 0) {
    kmsStatus = "fail";
    kmsSummary = `${notRotating.length}/${eligibleKeys.length} enabled symmetric customer-managed keys have KeyRotationEnabled=false across ${scope.regionsSeen} region(s).`;
  } else if (customerKeys.length === 0 && managerUnknown.length === 0) {
    kmsStatus = "manual";
    kmsSummary = `No customer-managed KMS keys (KeyManager=CUSTOMER) were found among ${keyRows.length} key(s) in ${scope.regionsSeen} region(s). Record the control as not applicable only if workloads intentionally rely on AWS-managed keys.`;
  } else if (eligibleKeys.length === 0) {
    kmsStatus = "warn";
    kmsSummary = `${customerKeys.length} customer-managed key(s) exist but none is an enabled symmetric AWS_KMS-origin key, so automatic rotation cannot apply; verify manual rotation for asymmetric, HMAC, imported, or disabled keys.`;
  } else {
    kmsStatus = "pass";
    kmsSummary = `All ${eligibleKeys.length} enabled symmetric customer-managed keys report KeyRotationEnabled=true across ${scope.regionsSeen} region(s); ${ineligibleCustomerKeys.length} customer key(s) are out of scope for automatic rotation.`;
  }
  const kmsCaps: string[] = [];
  if (rotationUnknown.length > 0) kmsCaps.push(`${rotationUnknown.length} rotation status(es) unreadable`);
  if (managerUnknown.length > 0) kmsCaps.push(`${managerUnknown.length} key(s) without a readable KeyManager`);
  if (kmsListErrors.length > 0) kmsCaps.push(`ListKeys unreadable in ${kmsListErrors.length} region(s)`);
  if (kmsTruncated.length > 0) kmsCaps.push(`key inventory truncated in ${kmsTruncated.length} region(s)`);
  if (scope.partial) kmsCaps.push(`only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`);
  const kmsVerdict = withCap(kmsStatus, kmsSummary, kmsCaps);

  const findings = [
    finding(
      "AWS-DATA-11",
      "S3 Block Public Access",
      "critical",
      publicAccessVerdict.status,
      publicAccessVerdict.summary,
      buildAwsMappings(11),
      {
        account_id: accountId ?? null,
        account_block_configured: accountConfigured,
        account_flags: accountFlags,
        buckets: buckets.length,
        buckets_without_full_block: sample(uncoveredBuckets.map((row) => ({ name: row.name, flags: row.flags }))),
        buckets_with_public_policy: sample(publicPolicyBuckets.map((row) => row.name)),
        buckets_unreadable: sample(unreadablePublicAccessBuckets.map((row) => row.name)),
        bucket_inventory_truncated: bucketsTruncated,
      },
    ),
    finding(
      "AWS-DATA-12",
      "Encryption at rest defaults (EBS, S3, RDS)",
      "high",
      encryptionVerdict.status,
      encryptionVerdict.summary,
      buildAwsMappings(12),
      {
        ...scopeEvidence(scope),
        ebs_by_region: ebsRows,
        rds_instances: rdsInstances.length,
        rds_unencrypted: sample(rdsUnencrypted.map((instance) => ({ region: instance.region, id: instance.DBInstanceIdentifier, engine: instance.Engine }))),
        rds_without_flag: sample(rdsUnknown.map((instance) => instance.DBInstanceIdentifier)),
        buckets: buckets.length,
        buckets_without_default_encryption: sample(bucketsWithoutSse.map((bucket) => bucket.name)),
        buckets_encryption_unreadable: sample(bucketEncryptionUnreadable.map((bucket) => bucket.name)),
        efs: "not assessed",
      },
    ),
    finding(
      "AWS-DATA-13",
      "S3 TLS-only bucket policies (encryption in transit)",
      "high",
      transitVerdict.status,
      transitVerdict.summary,
      buildAwsMappings(13),
      {
        buckets: buckets.length,
        buckets_without_tls_deny: sample(transitMissing.map((row) => ({ name: row.name, has_policy: row.has_policy }))),
        buckets_policy_unreadable: sample(transitUnreadable.map((row) => row.name)),
        bucket_inventory_truncated: bucketsTruncated,
        load_balancer_tls: "not assessed",
      },
    ),
    finding(
      "AWS-DATA-22",
      "KMS customer-managed key rotation",
      "medium",
      kmsVerdict.status,
      kmsVerdict.summary,
      buildAwsMappings(22),
      {
        ...scopeEvidence(scope),
        keys: keyRows.length,
        customer_managed_keys: customerKeys.length,
        eligible_keys: eligibleKeys.length,
        keys_not_rotating: sample(notRotating.map((key) => ({ region: key.region, key_id: key.keyId }))),
        keys_rotation_unreadable: sample(rotationUnknown.map((key) => ({ region: key.region, key_id: key.keyId }))),
        keys_manager_unreadable: sample(managerUnknown.map((key) => ({ region: key.region, key_id: key.keyId }))),
        ineligible_customer_keys: sample(ineligibleCustomerKeys.map((key) => ({
          region: key.region,
          key_id: key.keyId,
          key_state: key.metadata.value?.KeyState,
          key_spec: key.metadata.value?.KeySpec,
          origin: key.metadata.value?.Origin,
        }))),
        regions_with_list_errors: kmsListErrors.map((result) => result.region),
      },
    ),
  ];

  return {
    title: "AWS data protection posture",
    summary: {
      account_id: accountId ?? "unknown",
      regions_seen: scope.regionsSeen,
      regions_total: scope.regionsTotal,
      buckets: buckets.length,
      buckets_without_full_block: uncoveredBuckets.length,
      buckets_with_public_policy: publicPolicyBuckets.length,
      buckets_without_default_encryption: bucketsWithoutSse.length,
      buckets_without_tls_deny: transitMissing.length,
      ebs_regions_without_default_encryption: ebsOff.length,
      rds_instances: rdsInstances.length,
      rds_unencrypted: rdsUnencrypted.length,
      customer_managed_keys: customerKeys.length,
      keys_not_rotating: notRotating.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function parsePortList(value: unknown): number[] | undefined {
  const raw = Array.isArray(value) ? value : asString(value)?.split(/[\s,]+/);
  if (!raw) return undefined;
  const ports = raw
    .map((item) => asNumber(item))
    .filter((port): port is number => port !== undefined && Number.isInteger(port) && port >= 0 && port <= 65535);
  return ports.length > 0 ? [...new Set(ports)] : undefined;
}

function protocolCoversPorts(protocol: string | undefined): "all" | "ports" | "none" {
  if (protocol === undefined) return "none";
  if (protocol === "-1" || protocol.toLowerCase() === "all") return "all";
  if (protocol === "6" || protocol === "17" || /^(tcp|udp)$/i.test(protocol)) return "ports";
  return "none";
}

function rangeCoversSensitivePort(from: number | undefined, to: number | undefined, sensitivePorts: number[]): number[] {
  if (from === undefined || to === undefined) return sensitivePorts;
  return sensitivePorts.filter((port) => port >= from && port <= to);
}

/** Inbound NACL entries that allow any IPv4 or IPv6 source to reach a sensitive port or every port. */
export function permissiveNaclEntries(acl: JsonRecord, sensitivePorts: number[]): JsonRecord[] {
  const entries = Array.isArray(acl.Entries) ? acl.Entries.map(asObject).filter((entry): entry is JsonRecord => Boolean(entry)) : [];
  const permissive: JsonRecord[] = [];
  for (const entry of entries) {
    if (entry.Egress !== false) continue;
    if (asString(entry.RuleAction)?.toLowerCase() !== "allow") continue;
    const anySource = asString(entry.CidrBlock) === ANY_IPV4 || asString(entry.Ipv6CidrBlock) === ANY_IPV6;
    if (!anySource) continue;
    const coverage = protocolCoversPorts(asString(entry.Protocol));
    if (coverage === "none") continue;
    const portRange = asObject(entry.PortRange);
    const exposedPorts = coverage === "all"
      ? sensitivePorts
      : rangeCoversSensitivePort(asNumber(portRange?.From), asNumber(portRange?.To), sensitivePorts);
    if (exposedPorts.length === 0) continue;
    permissive.push({
      RuleNumber: entry.RuleNumber,
      Protocol: entry.Protocol,
      CidrBlock: entry.CidrBlock,
      Ipv6CidrBlock: entry.Ipv6CidrBlock,
      PortRange: portRange ?? null,
      exposed_ports: coverage === "all" ? "all" : exposedPorts,
    });
  }
  return permissive;
}

/** Inbound security group permissions open to 0.0.0.0/0 or ::/0 on a sensitive port or every port. */
export function unrestrictedSecurityGroupRules(group: JsonRecord, sensitivePorts: number[]): JsonRecord[] {
  const permissions = Array.isArray(group.IpPermissions) ? group.IpPermissions.map(asObject).filter((item): item is JsonRecord => Boolean(item)) : [];
  const unrestricted: JsonRecord[] = [];
  for (const permission of permissions) {
    const ipv4 = (Array.isArray(permission.IpRanges) ? permission.IpRanges : []).some((range) => asString(asObject(range)?.CidrIp) === ANY_IPV4);
    const ipv6 = (Array.isArray(permission.Ipv6Ranges) ? permission.Ipv6Ranges : []).some((range) => asString(asObject(range)?.CidrIpv6) === ANY_IPV6);
    if (!ipv4 && !ipv6) continue;
    const coverage = protocolCoversPorts(asString(permission.IpProtocol));
    if (coverage === "none") continue;
    const exposedPorts = coverage === "all"
      ? sensitivePorts
      : rangeCoversSensitivePort(asNumber(permission.FromPort), asNumber(permission.ToPort), sensitivePorts);
    if (exposedPorts.length === 0) continue;
    unrestricted.push({
      IpProtocol: permission.IpProtocol,
      FromPort: permission.FromPort ?? null,
      ToPort: permission.ToPort ?? null,
      sources: [...(ipv4 ? [ANY_IPV4] : []), ...(ipv6 ? [ANY_IPV6] : [])],
      exposed_ports: coverage === "all" ? "all" : exposedPorts,
    });
  }
  return unrestricted;
}

export interface AwsNetworkSecurityOptions extends AwsScopeOptions {
  resourceLimit?: number;
  sensitivePorts?: number[];
}

export type AwsNetworkSecurityClient = Pick<
  AwsAuditorClient,
  "getResolvedConfig" | "describeRegions" | "describeVpcs" | "describeFlowLogs" | "describeNetworkAcls" | "describeSecurityGroups"
>;

export async function assessAwsNetworkSecurity(
  client: AwsNetworkSecurityClient,
  options: AwsNetworkSecurityOptions = {},
): Promise<AwsAssessmentResult> {
  const errors: string[] = [];
  const resourceLimit = clampNumber(options.resourceLimit, DEFAULT_RESOURCE_LIMIT, 1, 20000);
  const sensitivePorts = options.sensitivePorts && options.sensitivePorts.length > 0 ? options.sensitivePorts : DEFAULT_SENSITIVE_PORTS;
  const scope = await resolveAssessmentScope(client, options, errors);

  const regionResults = await mapWithConcurrency(scope.regions, 4, async (region) => {
    const [vpcs, flowLogs, acls, groups] = await Promise.all([
      attemptAwsRead(`ec2:DescribeVpcs ${region}`, () => client.describeVpcs(region, resourceLimit), errors),
      attemptAwsRead(`ec2:DescribeFlowLogs ${region}`, () => client.describeFlowLogs(region, resourceLimit), errors),
      attemptAwsRead(`ec2:DescribeNetworkAcls ${region}`, () => client.describeNetworkAcls(region, resourceLimit), errors),
      attemptAwsRead(`ec2:DescribeSecurityGroups ${region}`, () => client.describeSecurityGroups(region, resourceLimit), errors),
    ]);
    for (const [label, list] of [["DescribeVpcs", vpcs], ["DescribeFlowLogs", flowLogs], ["DescribeNetworkAcls", acls], ["DescribeSecurityGroups", groups]] as const) {
      if (list.value?.truncated) errors.push(`ec2:${label} ${region}: inventory truncated at resource_limit ${resourceLimit}.`);
    }
    return { region, vpcs, flowLogs, acls, groups };
  });

  // Control 14: every VPC has an ACTIVE flow log.
  const vpcRows = regionResults.flatMap((result) => {
    const vpcs = result.vpcs.value?.items ?? [];
    const flowLogs = result.flowLogs.value?.items ?? [];
    return vpcs.map((vpc) => {
      const vpcId = asString(vpc.VpcId) ?? "";
      const matching = flowLogs.filter((flowLog) => asString(flowLog.ResourceId) === vpcId);
      const active = matching.filter((flowLog) => asString(flowLog.FlowLogStatus) === "ACTIVE");
      const statusUnknown = matching.filter((flowLog) => asString(flowLog.FlowLogStatus) === undefined);
      return {
        region: result.region,
        vpc_id: vpcId,
        is_default: vpc.IsDefault === true,
        flow_logs: matching.length,
        active_flow_logs: active.length,
        traffic_types: active.map((flowLog) => asString(flowLog.TrafficType) ?? "unknown"),
        flow_logs_unreadable: result.flowLogs.error !== undefined,
        status_unknown: statusUnknown.length,
      };
    });
  });
  const vpcRegionErrors = regionResults.filter((result) => result.vpcs.error);
  const flowLogRegionErrors = regionResults.filter((result) => result.flowLogs.error && !result.vpcs.error);
  const vpcsAllUnreadable = regionResults.length > 0 && vpcRegionErrors.length === regionResults.length;
  const vpcsWithoutFlowLogs = vpcRows.filter((row) => row.active_flow_logs === 0 && !row.flow_logs_unreadable);
  const vpcsUnverified = vpcRows.filter((row) => row.flow_logs_unreadable || (row.active_flow_logs === 0 && row.status_unknown > 0));
  const vpcTruncated = regionResults.filter((result) => result.vpcs.value?.truncated || result.flowLogs.value?.truncated);

  let flowLogStatus: AwsFinding["status"];
  let flowLogSummary: string;
  if (vpcsAllUnreadable) {
    flowLogStatus = "manual";
    flowLogSummary = `VPCs could not be listed in any of ${regionResults.length} region(s) (${vpcRegionErrors[0]?.vpcs.error ?? "unknown error"}); verify VPC Flow Logs in the console.`;
  } else if (vpcsWithoutFlowLogs.length > 0) {
    flowLogStatus = "fail";
    flowLogSummary = `${vpcsWithoutFlowLogs.length}/${vpcRows.length} VPCs across ${scope.regionsSeen} region(s) have no flow log with FlowLogStatus=ACTIVE.`;
  } else if (vpcRows.length === 0) {
    flowLogStatus = "manual";
    flowLogSummary = `No VPCs were found in ${scope.regionsSeen} region(s), so there is nothing to log. Confirm the region scope and record the control as not applicable if the account runs no VPC workloads.`;
  } else if (vpcsUnverified.length === vpcRows.length) {
    flowLogStatus = "manual";
    flowLogSummary = `Flow logs could not be read for any of the ${vpcRows.length} VPCs (${flowLogRegionErrors[0]?.flowLogs.error ?? "FlowLogStatus missing"}); verify VPC Flow Logs in the console.`;
  } else {
    flowLogStatus = "pass";
    flowLogSummary = `All ${vpcRows.length} VPCs across ${scope.regionsSeen} region(s) have at least one flow log with FlowLogStatus=ACTIVE.`;
  }
  const flowLogCaps: string[] = [];
  if (vpcsUnverified.length > 0) flowLogCaps.push(`${vpcsUnverified.length} VPC(s) could not be verified`);
  if (vpcRegionErrors.length > 0) flowLogCaps.push(`DescribeVpcs unreadable in ${vpcRegionErrors.length} region(s)`);
  if (vpcTruncated.length > 0) flowLogCaps.push(`VPC or flow log inventory truncated in ${vpcTruncated.length} region(s)`);
  if (scope.partial) flowLogCaps.push(`only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`);
  const flowLogVerdict = withCap(flowLogStatus, flowLogSummary, flowLogCaps);

  // Control 20: network ACL inbound rules open to the world on sensitive ports.
  const aclRows = regionResults.flatMap((result) => (result.acls.value?.items ?? []).map((acl) => ({
    region: result.region,
    network_acl_id: asString(acl.NetworkAclId) ?? "",
    vpc_id: asString(acl.VpcId),
    is_default: acl.IsDefault === true,
    permissive_entries: permissiveNaclEntries(acl, sensitivePorts),
  })));
  const aclRegionErrors = regionResults.filter((result) => result.acls.error);
  const aclsAllUnreadable = regionResults.length > 0 && aclRegionErrors.length === regionResults.length;
  const permissiveAcls = aclRows.filter((row) => row.permissive_entries.length > 0);
  const aclTruncated = regionResults.filter((result) => result.acls.value?.truncated);

  let aclStatus: AwsFinding["status"];
  let aclSummary: string;
  if (aclsAllUnreadable) {
    aclStatus = "manual";
    aclSummary = `Network ACLs could not be listed in any of ${regionResults.length} region(s) (${aclRegionErrors[0]?.acls.error ?? "unknown error"}); review NACL inbound rules in the console.`;
  } else if (permissiveAcls.length > 0) {
    aclStatus = "fail";
    aclSummary = `${permissiveAcls.length}/${aclRows.length} network ACLs allow inbound traffic from ${ANY_IPV4} or ${ANY_IPV6} to sensitive ports (${sensitivePorts.join(", ")}) or to every port; ${permissiveAcls.filter((row) => row.is_default).length} of them are default NACLs.`;
  } else if (aclRows.length === 0) {
    aclStatus = "manual";
    aclSummary = `No network ACLs were found in ${scope.regionsSeen} region(s). Every VPC has a default NACL, so confirm the region scope and VPC inventory.`;
  } else {
    aclStatus = "pass";
    aclSummary = `None of the ${aclRows.length} network ACLs across ${scope.regionsSeen} region(s) allows inbound ${ANY_IPV4} or ${ANY_IPV6} traffic to sensitive ports (${sensitivePorts.join(", ")}).`;
  }
  const aclCaps: string[] = [];
  if (aclRegionErrors.length > 0) aclCaps.push(`DescribeNetworkAcls unreadable in ${aclRegionErrors.length} region(s)`);
  if (aclTruncated.length > 0) aclCaps.push(`NACL inventory truncated in ${aclTruncated.length} region(s)`);
  if (scope.partial) aclCaps.push(`only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`);
  const aclVerdict = withCap(aclStatus, aclSummary, aclCaps);

  // Control 21: security group inbound rules open to the world on sensitive ports.
  const groupRows = regionResults.flatMap((result) => (result.groups.value?.items ?? []).map((group) => ({
    region: result.region,
    group_id: asString(group.GroupId) ?? "",
    group_name: asString(group.GroupName),
    vpc_id: asString(group.VpcId),
    unrestricted_rules: unrestrictedSecurityGroupRules(group, sensitivePorts),
  })));
  const groupRegionErrors = regionResults.filter((result) => result.groups.error);
  const groupsAllUnreadable = regionResults.length > 0 && groupRegionErrors.length === regionResults.length;
  const unrestrictedGroups = groupRows.filter((row) => row.unrestricted_rules.length > 0);
  const groupTruncated = regionResults.filter((result) => result.groups.value?.truncated);

  let groupStatus: AwsFinding["status"];
  let groupSummary: string;
  if (groupsAllUnreadable) {
    groupStatus = "manual";
    groupSummary = `Security groups could not be listed in any of ${regionResults.length} region(s) (${groupRegionErrors[0]?.groups.error ?? "unknown error"}); review inbound rules in the console.`;
  } else if (unrestrictedGroups.length > 0) {
    groupStatus = "fail";
    groupSummary = `${unrestrictedGroups.length}/${groupRows.length} security groups allow inbound ${ANY_IPV4} or ${ANY_IPV6} traffic to sensitive ports (${sensitivePorts.join(", ")}) or to every port.`;
  } else if (groupRows.length === 0) {
    groupStatus = "manual";
    groupSummary = `No security groups were found in ${scope.regionsSeen} region(s). Every VPC has a default security group, so confirm the region scope and VPC inventory.`;
  } else {
    groupStatus = "pass";
    groupSummary = `None of the ${groupRows.length} security groups across ${scope.regionsSeen} region(s) allows inbound ${ANY_IPV4} or ${ANY_IPV6} traffic to sensitive ports (${sensitivePorts.join(", ")}).`;
  }
  const groupCaps: string[] = [];
  if (groupRegionErrors.length > 0) groupCaps.push(`DescribeSecurityGroups unreadable in ${groupRegionErrors.length} region(s)`);
  if (groupTruncated.length > 0) groupCaps.push(`security group inventory truncated in ${groupTruncated.length} region(s)`);
  if (scope.partial) groupCaps.push(`only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`);
  const groupVerdict = withCap(groupStatus, groupSummary, groupCaps);

  const findings = [
    finding(
      "AWS-NET-14",
      "VPC Flow Logs coverage",
      "medium",
      flowLogVerdict.status,
      flowLogVerdict.summary,
      buildAwsMappings(14),
      {
        ...scopeEvidence(scope),
        vpcs: vpcRows.length,
        vpcs_without_active_flow_logs: sample(vpcsWithoutFlowLogs.map((row) => ({ region: row.region, vpc_id: row.vpc_id, is_default: row.is_default, flow_logs: row.flow_logs }))),
        vpcs_unverified: sample(vpcsUnverified.map((row) => ({ region: row.region, vpc_id: row.vpc_id }))),
        regions_with_vpc_errors: vpcRegionErrors.map((result) => result.region),
        regions_with_flow_log_errors: flowLogRegionErrors.map((result) => result.region),
      },
    ),
    finding(
      "AWS-NET-20",
      "Network ACL inbound exposure",
      "medium",
      aclVerdict.status,
      aclVerdict.summary,
      buildAwsMappings(20),
      {
        ...scopeEvidence(scope),
        sensitive_ports: sensitivePorts,
        network_acls: aclRows.length,
        permissive_network_acls: sample(permissiveAcls.map((row) => ({ region: row.region, network_acl_id: row.network_acl_id, vpc_id: row.vpc_id, is_default: row.is_default, entries: row.permissive_entries.slice(0, 5) }))),
        regions_with_errors: aclRegionErrors.map((result) => result.region),
      },
    ),
    finding(
      "AWS-NET-21",
      "Security group inbound exposure",
      "high",
      groupVerdict.status,
      groupVerdict.summary,
      buildAwsMappings(21),
      {
        ...scopeEvidence(scope),
        sensitive_ports: sensitivePorts,
        security_groups: groupRows.length,
        unrestricted_security_groups: sample(unrestrictedGroups.map((row) => ({ region: row.region, group_id: row.group_id, group_name: row.group_name, vpc_id: row.vpc_id, rules: row.unrestricted_rules.slice(0, 5) }))),
        regions_with_errors: groupRegionErrors.map((result) => result.region),
      },
    ),
  ];

  return {
    title: "AWS network security posture",
    summary: {
      regions_seen: scope.regionsSeen,
      regions_total: scope.regionsTotal,
      vpcs: vpcRows.length,
      vpcs_without_active_flow_logs: vpcsWithoutFlowLogs.length,
      network_acls: aclRows.length,
      permissive_network_acls: permissiveAcls.length,
      security_groups: groupRows.length,
      unrestricted_security_groups: unrestrictedGroups.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: AwsAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.service,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `AWS access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AwsAssessmentResult): string {
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
  ].join("\n");
}

function countByStatus(findings: AwsFinding[]): Record<AwsFinding["status"], number> {
  const counts: Record<AwsFinding["status"], number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function severityRank(severity: AwsFinding["severity"]): number {
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
      return exhaustive;
    }
  }
}

function markdownEscape(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function mappingsForFramework(item: AwsFinding, framework: AwsFrameworkDescriptor): string[] {
  const prefix = `${framework.label} `;
  return item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length));
}

export function coveredAwsControls(findings: AwsFinding[]): number[] {
  const covered = new Set<number>();
  for (const item of findings) {
    for (const controlNumber of AWS_FINDING_CONTROLS[item.id] ?? []) covered.add(controlNumber);
  }
  return [...covered].sort((left, right) => left - right);
}

function buildExecutiveSummary(
  config: AwsResolvedConfig,
  assessments: AwsAssessmentResult[],
  errors: string[],
  generatedAt: Date,
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const covered = coveredAwsControls(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => (left.status === right.status ? severityRank(left.severity) - severityRank(right.severity) : left.status === "fail" ? -1 : 1))
    .slice(0, 10);
  const manual = findings.filter((item) => item.status === "manual");

  return [
    "# AWS Security Inspector Executive Summary",
    "",
    `- Region: ${config.region}`,
    `- Account hint: ${config.accountId ?? "not provided"}`,
    `- Generated: ${generatedAt.toISOString()}`,
    `- Source chain: ${config.sourceChain.join(" -> ")}`,
    `- Findings: ${findings.length}`,
    `- Spec controls covered: ${covered.length} of ${Object.keys(AWS_CONTROL_CATALOG).length} (${covered.join(", ")})`,
    "",
    "## Result Counts",
    "",
    `- Pass: ${counts.pass}`,
    `- Warn: ${counts.warn}`,
    `- Fail: ${counts.fail}`,
    `- Manual: ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
    ...(prioritized.length > 0
      ? prioritized.map((item) => `- ${item.id} ${item.title} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`)
      : ["- No failing or warning findings were generated."]),
    "",
    "## Manual Evidence Required",
    "",
    ...(manual.length > 0
      ? manual.map((item) => `- ${item.id} ${item.title}: ${item.summary}`)
      : ["- Every finding was decided from API evidence."]),
    ...(errors.length > 0 ? ["", "## Collection Warnings", "", ...errors.map((error) => `- ${error}`)] : []),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: AwsFinding[]): string {
  const header = ["Finding", "Controls", "Title", "Status", "Severity", ...AWS_FRAMEWORKS.map((framework) => framework.label)];
  return [
    "# Unified Compliance Matrix",
    "",
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...findings.map((item) => `| ${[
      item.id,
      (AWS_FINDING_CONTROLS[item.id] ?? []).join(", ") || "N/A",
      item.title,
      item.status,
      item.severity,
      ...AWS_FRAMEWORKS.map((framework) => mappingsForFramework(item, framework).join(", ") || "N/A"),
    ].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildFrameworkReport(framework: AwsFrameworkDescriptor, findings: AwsFinding[]): string {
  const scoped = findings.filter((item) => mappingsForFramework(item, framework).length > 0);
  if (scoped.length === 0) {
    return `# ${framework.label} Report\n\nNo mapped findings were generated for this framework.\n`;
  }
  const counts = countByStatus(scoped);
  return [
    `# ${framework.label} Report`,
    "",
    `- Mapped findings: ${scoped.length}`,
    `- Pass: ${counts.pass}, Warn: ${counts.warn}, Fail: ${counts.fail}, Manual: ${counts.manual}`,
    "",
    "| Finding | Title | Status | Severity | Mapping | Summary |",
    "| --- | --- | --- | --- | --- | --- |",
    ...scoped.map((item) => `| ${[
      item.id,
      item.title,
      item.status,
      item.severity,
      mappingsForFramework(item, framework).join(", "),
      item.summary,
    ].map(markdownEscape).join(" | ")} |`),
    "",
  ].join("\n");
}

function buildQuickReference(assessments: AwsAssessmentResult[], access: AwsAccessCheckResult, errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  return [
    "# AWS Audit Bundle Quick Reference",
    "",
    `Access check: ${access.status} (${access.surfaces.filter((surface) => surface.status === "readable").length}/${access.surfaces.length} surfaces readable)`,
    `Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    "## Where to look",
    "",
    "- `compliance/executive_summary.md`: prioritized findings, manual evidence list, and control coverage",
    "- `compliance/unified_compliance_matrix.md`: every finding mapped across FedRAMP, CMMC, SOC 2, CIS AWS, PCI-DSS, DISA STIG, IRAP, and ISMAP",
    "- `compliance/frameworks/*.md`: one report per framework",
    "- `analysis/findings.json`: normalized findings (id, title, severity, status, summary, evidence, mappings)",
    "- `analysis/<category>.json`: per-assessment summaries and collection errors",
    "- `core_data/access.json`: readable AWS audit surfaces",
    ...(errors.length > 0 ? ["- `_errors.log`: surfaces that failed or were truncated during collection"] : []),
    "",
    "## Findings by status",
    "",
    ...findings.map((item) => `- ${item.id} ${item.title}: ${item.status.toUpperCase()}`),
    "",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# AWS Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native AWS security inspector tools.",
    "",
    "## Contents",
    "",
    "- `QUICK_REFERENCE.md`: orientation and finding status list",
    "- `compliance/executive_summary.md`: prioritized audit summary and spec control coverage",
    "- `compliance/unified_compliance_matrix.md`: cross-framework mapping matrix",
    "- `compliance/frameworks/*.md`: per-framework reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible AWS audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: present only when some surfaces failed or were truncated",
    "",
    "Credentials are resolved through the AWS SDK chain and are never written to this bundle.",
    "",
  ].join("\n");
}

const ASSESSMENT_CATEGORIES = ["identity", "logging-detection", "org-guardrails", "data-protection", "network-security"] as const;

export async function exportAwsAuditBundle(
  client: AwsAuditorClient,
  config: AwsResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AwsAuditBundleResult> {
  const now = new Date();
  const access = await checkAwsAccess(client);
  const identity = await assessAwsIdentity(client, {
    userLimit: options.user_limit,
    staleDays: options.stale_days,
    roleLimit: options.role_limit,
    maxPrivilegedRoles: options.max_privileged_roles,
    lookbackDays: options.lookback_days,
    policyLimit: options.policy_limit,
  });
  const loggingDetection = await assessAwsLoggingDetection(client);
  const orgGuardrails = await assessAwsOrgGuardrails(client, {
    maxFindings: options.max_findings,
  });
  const dataProtection = await assessAwsDataProtection(client, {
    regions: options.regions,
    regionLimit: options.region_limit,
    bucketLimit: options.bucket_limit,
    keyLimit: options.key_limit,
    instanceLimit: options.instance_limit,
  });
  const networkSecurity = await assessAwsNetworkSecurity(client, {
    regions: options.regions,
    regionLimit: options.region_limit,
    resourceLimit: options.resource_limit,
    sensitivePorts: options.sensitive_ports,
  });

  const assessments = [identity, loggingDetection, orgGuardrails, dataProtection, networkSecurity];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors ?? []))];
  const counts = countByStatus(findings);
  const accountId = access.accountId ?? config.accountId ?? "aws-account";
  const targetName = safeDirName(`${accountId}-${config.region}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference(assessments, access, errors));
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    region: config.region,
    profile: config.profile ?? null,
    account_id: access.accountId ?? null,
    account_id_hint: config.accountId ?? null,
    source_chain: config.sourceChain,
    generated_at: now.toISOString(),
    findings: findings.length,
    controls_covered: coveredAwsControls(findings),
    controls_total: Object.keys(AWS_CONTROL_CATALOG).length,
    ...counts,
    options: {
      user_limit: options.user_limit ?? DEFAULT_USER_LIMIT,
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      role_limit: options.role_limit ?? DEFAULT_ROLE_LIMIT,
      max_privileged_roles: options.max_privileged_roles ?? DEFAULT_MAX_PRIVILEGED_ROLES,
      lookback_days: options.lookback_days ?? DEFAULT_ROOT_LOOKBACK_DAYS,
      policy_limit: options.policy_limit ?? DEFAULT_POLICY_LIMIT,
      max_findings: options.max_findings ?? DEFAULT_MAX_FINDINGS,
      regions: options.regions ?? null,
      region_limit: options.region_limit ?? DEFAULT_REGION_LIMIT,
      bucket_limit: options.bucket_limit ?? DEFAULT_BUCKET_LIMIT,
      key_limit: options.key_limit ?? DEFAULT_KEY_LIMIT,
      instance_limit: options.instance_limit ?? DEFAULT_INSTANCE_LIMIT,
      resource_limit: options.resource_limit ?? DEFAULT_RESOURCE_LIMIT,
      sensitive_ports: options.sensitive_ports ?? DEFAULT_SENSITIVE_PORTS,
    },
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const [index, category] of ASSESSMENT_CATEGORIES.entries()) {
    await writeSecureTextFile(outputDir, `analysis/${category}.json`, serializeJson(assessments[index]));
  }
  await writeSecureTextFile(outputDir, "analysis/summary.json", serializeJson({
    findings: findings.length,
    controls_covered: coveredAwsControls(findings),
    ...counts,
    categories: ASSESSMENT_CATEGORIES.map((category, index) => ({ category, ...countByStatus(assessments[index].findings) })),
  }));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, now));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of AWS_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.file}.md`, buildFrameworkReport(framework, findings));
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return {
    outputDir,
    zipPath,
    fileCount,
    findingCount: findings.length,
    errorCount: errors.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    region: asString(value.region),
    profile: asString(value.profile),
    account_id: asString(value.account_id),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    stale_days: asNumber(value.stale_days),
    role_limit: asNumber(value.role_limit),
    max_privileged_roles: asNumber(value.max_privileged_roles),
    lookback_days: asNumber(value.lookback_days),
    policy_limit: asNumber(value.policy_limit),
  };
}

function normalizeOrgGuardrailArgs(args: unknown): OrgGuardrailArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_findings: asNumber(value.max_findings),
  };
}

type ScopeArgs = CheckAccessArgs & {
  regions?: string[];
  region_limit?: number;
};

type DataProtectionArgs = ScopeArgs & {
  bucket_limit?: number;
  key_limit?: number;
  instance_limit?: number;
};

function normalizeScopeArgs(args: unknown): ScopeArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    regions: parseRegionList(value.regions),
    region_limit: asNumber(value.region_limit),
  };
}

function normalizeDataProtectionArgs(args: unknown): DataProtectionArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopeArgs(args),
    bucket_limit: asNumber(value.bucket_limit),
    key_limit: asNumber(value.key_limit),
    instance_limit: asNumber(value.instance_limit),
  };
}

type NetworkSecurityArgs = ScopeArgs & {
  resource_limit?: number;
  sensitive_ports?: number[];
};

function normalizeNetworkSecurityArgs(args: unknown): NetworkSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopeArgs(args),
    resource_limit: asNumber(value.resource_limit),
    sensitive_ports: parsePortList(value.sensitive_ports),
  };
}

const scopeParams = {
  regions: Type.Optional(Type.String({ description: "Comma-separated regions to assess. Defaults to every enabled region from EC2 DescribeRegions, falling back to the configured region." })),
  region_limit: Type.Optional(Type.Number({ description: `Maximum regions to assess before flagging a partial scope. Defaults to ${DEFAULT_REGION_LIMIT}.`, default: DEFAULT_REGION_LIMIT })),
};

const dataProtectionParams = {
  ...scopeParams,
  bucket_limit: Type.Optional(Type.Number({ description: `Maximum S3 buckets to inspect before flagging truncation. Defaults to ${DEFAULT_BUCKET_LIMIT}.`, default: DEFAULT_BUCKET_LIMIT })),
  key_limit: Type.Optional(Type.Number({ description: `Maximum KMS keys per region before flagging truncation. Defaults to ${DEFAULT_KEY_LIMIT}.`, default: DEFAULT_KEY_LIMIT })),
  instance_limit: Type.Optional(Type.Number({ description: `Maximum RDS instances per region before flagging truncation. Defaults to ${DEFAULT_INSTANCE_LIMIT}.`, default: DEFAULT_INSTANCE_LIMIT })),
};

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    user_limit: asNumber(value.user_limit),
    stale_days: asNumber(value.stale_days),
    role_limit: asNumber(value.role_limit),
    max_privileged_roles: asNumber(value.max_privileged_roles),
    lookback_days: asNumber(value.lookback_days),
    policy_limit: asNumber(value.policy_limit),
    max_findings: asNumber(value.max_findings),
    regions: parseRegionList(value.regions),
    region_limit: asNumber(value.region_limit),
    bucket_limit: asNumber(value.bucket_limit),
    key_limit: asNumber(value.key_limit),
    instance_limit: asNumber(value.instance_limit),
    resource_limit: asNumber(value.resource_limit),
    sensitive_ports: parsePortList(value.sensitive_ports),
  };
}

function createClient(args: CheckAccessArgs): AwsAuditorClient {
  return new AwsAuditorClient(resolveAwsConfiguration(args));
}

const authParams = {
  region: Type.Optional(Type.String({ description: `AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or ${DEFAULT_REGION}.` })),
  profile: Type.Optional(Type.String({ description: "AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain." })),
  account_id: Type.Optional(Type.String({ description: "Optional expected AWS account ID hint for operator context." })),
};

export function registerAwsTools(pi: any): void {
  pi.registerTool({
    name: "aws_check_access",
    label: "Check AWS audit access",
    description:
      "Validate read-only AWS audit access across IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, Organizations, and Identity Center surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAwsAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "aws_check_access", ...result });
      } catch (error) {
        return errorResult(
          `AWS access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_identity",
    label: "Assess AWS identity posture",
    description:
      "Assess AWS IAM hygiene, including root-account protection, IAM user MFA, password policy, access key rotation, dormant users, and privileged roles without permission boundaries.",
    parameters: Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum IAM users to sample. Defaults to 500.", default: 500 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for keys and dormant users. Defaults to 90.", default: 90 })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum IAM roles to inspect. Defaults to 500.", default: 500 })),
      max_privileged_roles: Type.Optional(Type.Number({ description: "Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5.", default: 5 })),
      lookback_days: Type.Optional(Type.Number({ description: "Days of CloudTrail history to search for root activity (LookupEvents keeps 90 days). Defaults to 90.", default: 90 })),
      policy_limit: Type.Optional(Type.Number({ description: "Maximum customer-managed IAM policies to inspect before flagging truncation. Defaults to 1000.", default: 1000 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessAwsIdentity(createClient(args), {
          userLimit: args.user_limit,
          staleDays: args.stale_days,
          roleLimit: args.role_limit,
          maxPrivilegedRoles: args.max_privileged_roles,
          lookbackDays: args.lookback_days,
          policyLimit: args.policy_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `AWS identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_logging_detection",
    label: "Assess AWS logging and detection",
    description:
      "Assess AWS CloudTrail, Security Hub, GuardDuty, and Config posture, including multi-region trail coverage, log validation, data events, standards enablement, and active recording.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: LoggingArgs) {
      try {
        const result = await assessAwsLoggingDetection(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "aws_assess_logging_detection", ...result });
      } catch (error) {
        return errorResult(
          `AWS logging and detection assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_logging_detection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_org_guardrails",
    label: "Assess AWS organization guardrails",
    description:
      "Assess AWS Organizations visibility, service control policies, Access Analyzer coverage, active external-access findings, and IAM Identity Center visibility.",
    parameters: Type.Object({
      ...authParams,
      max_findings: Type.Optional(Type.Number({ description: "Maximum Access Analyzer findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeOrgGuardrailArgs,
    async execute(_toolCallId: string, args: OrgGuardrailArgs) {
      try {
        const result = await assessAwsOrgGuardrails(createClient(args), {
          maxFindings: args.max_findings,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_org_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `AWS organization guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_org_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_data_protection",
    label: "Assess AWS data protection",
    description:
      "Assess AWS data protection posture: account and bucket S3 Block Public Access, EBS default encryption per region, S3 default encryption, RDS storage encryption, TLS-only bucket policies (aws:SecureTransport), and customer-managed KMS key rotation.",
    parameters: Type.Object({
      ...authParams,
      ...dataProtectionParams,
    }),
    prepareArguments: normalizeDataProtectionArgs,
    async execute(_toolCallId: string, args: DataProtectionArgs) {
      try {
        const result = await assessAwsDataProtection(createClient(args), {
          regions: args.regions,
          regionLimit: args.region_limit,
          bucketLimit: args.bucket_limit,
          keyLimit: args.key_limit,
          instanceLimit: args.instance_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_data_protection", ...result });
      } catch (error) {
        return errorResult(
          `AWS data protection assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_data_protection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_network_security",
    label: "Assess AWS network security",
    description:
      "Assess AWS network security posture per region: VPC Flow Logs coverage (DescribeFlowLogs versus DescribeVpcs), network ACL inbound rules open to 0.0.0.0/0 or ::/0 on sensitive ports, and security group inbound rules open to the world on sensitive ports.",
    parameters: Type.Object({
      ...authParams,
      ...scopeParams,
      resource_limit: Type.Optional(Type.Number({ description: `Maximum VPCs, flow logs, NACLs, or security groups per region before flagging truncation. Defaults to ${DEFAULT_RESOURCE_LIMIT}.`, default: DEFAULT_RESOURCE_LIMIT })),
      sensitive_ports: Type.Optional(Type.String({ description: `Comma-separated ports treated as sensitive. Defaults to ${DEFAULT_SENSITIVE_PORTS.join(",")}.`, default: DEFAULT_SENSITIVE_PORTS.join(",") })),
    }),
    prepareArguments: normalizeNetworkSecurityArgs,
    async execute(_toolCallId: string, args: NetworkSecurityArgs) {
      try {
        const result = await assessAwsNetworkSecurity(createClient(args), {
          regions: args.regions,
          regionLimit: args.region_limit,
          resourceLimit: args.resource_limit,
          sensitivePorts: args.sensitive_ports,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_network_security", ...result });
      } catch (error) {
        return errorResult(
          `AWS network security assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_network_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_export_audit_bundle",
    label: "Export AWS audit bundle",
    description:
      "Export an AWS audit package with access checks, identity findings, logging and detection findings, organization guardrails, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum IAM users to sample. Defaults to 500.", default: 500 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for keys and dormant users. Defaults to 90.", default: 90 })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum IAM roles to inspect. Defaults to 500.", default: 500 })),
      max_privileged_roles: Type.Optional(Type.Number({ description: "Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5.", default: 5 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Access Analyzer findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAwsConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAwsAuditBundle(new AwsAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "AWS audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "aws_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `AWS audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_export_audit_bundle" },
        );
      }
    },
  });
}
