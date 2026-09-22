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
import { fromIni, fromNodeProviderChain } from "@aws-sdk/credential-providers";
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
const DEFAULT_ACCOUNT_LIMIT = 1000;
const DEFAULT_TARGET_LIMIT = 1000;
const DEFAULT_ANALYZER_LIMIT = 100;
const DEFAULT_STANDARD_LIMIT = 100;
const DEFAULT_DETECTOR_LIMIT = 50;
/** Upper bound on pages walked per list call; a token that never stops advancing is reported as truncation. */
const MAX_PAGES_PER_LIST = 1000;
const DEFAULT_ROOT_LOOKBACK_DAYS = 90;
/** Global service events such as root ConsoleLogin are delivered to CloudTrail in us-east-1 only. */
export const ROOT_EVENT_REGION = "us-east-1";
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
  /** IAM action the probe issued, for example iam:ListUsers. */
  command: string;
  /** Region the probe was sent to. */
  region: string;
  status: "readable" | "not_readable";
  /** Items the probe saw; null until a read completes. */
  count: number | null;
  /** True when a paged probe stopped at its cap; null for unpaged probes and for reads that never completed. */
  truncated: boolean | null;
  /** Redacted description of the failure; absent for a readable probe. */
  error?: string;
  /** SDK error code of the failure (for example AccessDeniedException); null when the SDK reported none. */
  error_code?: string | null;
  /** HTTP status the failed request observed; null for transport failures. */
  http_status?: number | null;
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
  /** Redacted, labelled description of the failure. */
  error?: string;
  denied?: boolean;
  /** SDK error code of the failure, when the SDK reported one. */
  errorCode?: string;
  /** HTTP status the failed request observed, when the SDK reported one. */
  httpStatus?: number;
}

export interface AwsRegionScope {
  regions: string[];
  /** Enabled regions known to exist; null when the region list could not be read and only the configured region was assessed. */
  regionsTotal: number | null;
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

/** Shape of an error code (AccessDeniedException, NoSuchEntity, ENOTFOUND, com.amazonaws.x#Fault): one identifier, at most 64 characters. */
const ERROR_CODE_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,63}$/;
const UNKNOWN_ERROR_CODE = "UnknownError";

/**
 * The SDK error name. For a service error it is the response's <Code> element or __type field, so it is text
 * the server controls: it is accepted only when it is shaped like a code and survives the error-text scrub
 * unchanged (a bearer value or a token in that slot is neither), otherwise it renders as UnknownError. "" when
 * the error carries no name at all.
 */
function errorCode(error: unknown): string {
  if (error instanceof AwsApiError) return error.code;
  const object = asObject(error);
  const raw = asString(object?.name) ?? asString(object?.Code) ?? asString(object?.code) ?? "";
  if (raw === "") return "";
  return ERROR_CODE_PATTERN.test(raw) && redactErrorText(raw) === raw ? raw : UNKNOWN_ERROR_CODE;
}

function errorHttpStatus(error: unknown): number | undefined {
  if (error instanceof AwsApiError) return error.httpStatus;
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

const REDACTED_ERROR_VALUE = "[REDACTED]";
const CONFIGURED_SECRETS = new Set<string>();
const MIN_CONFIGURED_SECRET_LENGTH = 4;

/**
 * The forms a configured secret can take inside an error string: plain, JSON-escaped, URL-encoded, base64,
 * and base64url (rule 9 scrub boundary: a configured secret is removed whatever its shape, in every form).
 */
function configuredSecretForms(value: string): string[] {
  const forms = new Set<string>([
    value,
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
    Buffer.from(value, "utf8").toString("base64"),
    Buffer.from(value, "utf8").toString("base64url"),
  ]);
  return [...forms].filter((form) => form.length >= MIN_CONFIGURED_SECRET_LENGTH);
}

/** Secrets the running client was configured with or obtained; every recorded error string is scrubbed of them in every form. */
function registerConfiguredSecrets(...values: Array<string | undefined>): void {
  for (const value of values) {
    if (!value || value.length < MIN_CONFIGURED_SECRET_LENGTH) continue;
    for (const form of configuredSecretForms(value)) CONFIGURED_SECRETS.add(form);
  }
}

function escapeErrorRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Replaces every configured secret form wherever it appears; a form under eight characters only where it stands as a whole token. */
function scrubConfiguredSecrets(text: string): string {
  let scrubbed = text;
  for (const secret of [...CONFIGURED_SECRETS].sort((left, right) => right.length - left.length)) {
    scrubbed = secret.length >= 8
      ? scrubbed.split(secret).join(REDACTED_ERROR_VALUE)
      : scrubbed.replace(new RegExp(`(?<![A-Za-z0-9])${escapeErrorRegExp(secret)}(?![A-Za-z0-9])`, "g"), REDACTED_ERROR_VALUE);
  }
  return scrubbed;
}

const ERROR_CREDENTIAL_KEY_PATTERN =
  "[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth[_-]?key|auth[_-]?email|session(?:[_-]?id)?|sid|cookie|csrftoken|authorization|auth|signature|sig|nonce|credentials?|access[_-]?key|private[_-]?key|skey)";
// key=value, key: value, and "key":"value" pairs whose key names a credential; the value's shape decides below.
const ERROR_CREDENTIAL_PAIR_PATTERN = new RegExp(
  `\\b(${ERROR_CREDENTIAL_KEY_PATTERN})(["']?\\s*[=:]\\s*["']?)((?:(?:Bearer|Basic|Digest|Token|ApiKey)\\s+)?[^\\s"'&;,<>]+)`,
  "gi",
);
const TRAILING_PUNCTUATION_PATTERN = /[.!?:)]+$/;

const ERROR_SCHEME_PATTERN = "(?:Bearer|Basic|Digest|Negotiate|SSWS|Token|ApiKey|Api-Key)";
/**
 * A quoted value: the opening quote (plain, or JSON-escaped when the message was itself serialized) with its
 * quote character captured, the value up to the matching close quote (so it may hold spaces and the other quote
 * character), and the close quote. Both patterns below place it after two capturing groups, so the quote
 * character is group 4 and the close quote group 5.
 */
const ERROR_QUOTED_VALUE_PATTERN = String.raw`(\\?(["']))(?:(?!\\?\4)[^\n\\])+(\\?\4)`;
/**
 * Codex P1 (quoted header value). `X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization: Bearer "value"`,
 * `\"X-Auth-Key\":\"value\"`: with or without spaces, single or double quotes, plain or JSON-escaped. The quotes
 * delimit the carrier, so the quoted value is removed whole whatever its shape; the pair rule above stops at the
 * opening quote and would judge a short or name-shaped value ("key", "prod-key") as prose. The header name, the
 * separator, the scheme, and the quotes stay so the message remains diagnosable.
 */
const ERROR_QUOTED_CREDENTIAL_PATTERN = new RegExp(
  String.raw`\b(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\?["'])?\s*[=:]\s*(?:${ERROR_SCHEME_PATTERN}\s*)?)${ERROR_QUOTED_VALUE_PATTERN}`,
  "gi",
);
// A scheme word that is itself quoted (`"Token":"..."`, a JSON key) is a pair the rule above already handled.
const ERROR_QUOTED_SCHEME_PATTERN = new RegExp(String.raw`(?<!["'\\])\b(${ERROR_SCHEME_PATTERN})(\s*)${ERROR_QUOTED_VALUE_PATTERN}`, "gi");
const QUOTED_VALUE_REPLACEMENT = `$1$2$3${REDACTED_ERROR_VALUE}$5`;

/**
 * A value after a credential-named key is the credential (whatever its shape) when it is at least six
 * characters and is twelve or longer, carries a digit or a character that is not a letter, or changes case
 * inside the word. Short plain words after a colon ("InvalidAuthenticationToken: Access token has expired")
 * are prose and stay.
 */
function looksLikeCredentialValue(value: string): boolean {
  return value.length >= 6 && (value.length >= 12 || /\d/.test(value) || /[^A-Za-z]/.test(value) || /[a-z][A-Z]/.test(value));
}

function scrubCredentialPairs(text: string): string {
  return text.replace(ERROR_CREDENTIAL_PAIR_PATTERN, (match: string, key: string, separator: string, value: string) => {
    // A value the scheme rule already replaced ("Authorization: Bearer [REDACTED]") keeps its scheme name.
    if (value.includes(REDACTED_ERROR_VALUE)) return match;
    const core = value.replace(TRAILING_PUNCTUATION_PATTERN, "");
    return looksLikeCredentialValue(core) ? `${key}${separator}${REDACTED_ERROR_VALUE}${value.slice(core.length)}` : match;
  });
}

/**
 * Header carriers whose value is free form: Cookie and Set-Cookie (session values with their attributes) and
 * Cloudflare's legacy X-Auth-Key / X-Auth-Email pair (the global API key and its account; round 4 item F). The
 * value is removed whatever its shape. Where it ends follows the compound-line rule shared by every scrubber:
 * a quoted value (a plain or JSON-escaped quote) ends at its closing quote, so a closed value that holds `; Name:`
 * is one value and the quotes stay around the marker; an unquoted value, or a quoted one that is never closed,
 * ends at the `;` or `,` that introduces the next `Name:` header token on the line, at a `<` or `>` (the header
 * quoted inside markup), or at the end of the line, so the next header keeps its name and gets its own carrier
 * treatment. A value that is already the marker is left alone, so a second pass over a scrubbed message leaves
 * the text after the marker as it is.
 */
const HEADER_CARRIER_PATTERN = /\b(set-cookie|cookie|x-auth-key|x-auth-email)(\s*[:=]\s*)(?!\s*\[REDACTED\])/gi;
const HEADER_CARRIER_QUOTE_PATTERN = /^(\\?)(["'])/;
const NEXT_HEADER_TOKEN_PATTERN = /[;,]\s*[A-Za-z][A-Za-z0-9-]*\s*:/;
const MARKUP_STOP_PATTERN = /[<>]/;

/** The end of a free-form header value that starts at `start`, and the quote (plain or escaped) that encloses a closed quoted value. */
function headerCarrierValueEnd(text: string, start: number): { end: number; quote?: string } {
  const newline = text.indexOf("\n", start);
  const line = text.slice(start, newline === -1 ? text.length : newline);
  const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
  if (opening) {
    const close = line.indexOf(opening[0], opening[0].length);
    if (close !== -1) return { end: start + close + opening[0].length, quote: opening[0] };
  }
  const stops = [MARKUP_STOP_PATTERN.exec(line)?.index, NEXT_HEADER_TOKEN_PATTERN.exec(line)?.index].filter((index): index is number => index !== undefined);
  return { end: start + (stops.length > 0 ? Math.min(...stops) : line.length) };
}

function scrubHeaderCarriers(text: string): string {
  let scrubbed = "";
  let cursor = 0;
  for (const match of text.matchAll(HEADER_CARRIER_PATTERN)) {
    // A carrier name inside a value already consumed (`Cookie: "a; X-Auth-Key: b"`) is part of that value.
    if (match.index < cursor) continue;
    const valueStart = match.index + match[0].length;
    const { end, quote } = headerCarrierValueEnd(text, valueStart);
    if (end === valueStart) continue;
    scrubbed += text.slice(cursor, valueStart) + (quote === undefined ? REDACTED_ERROR_VALUE : `${quote}${REDACTED_ERROR_VALUE}${quote}`);
    cursor = end;
  }
  return scrubbed + text.slice(cursor);
}

const ERROR_TEXT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // The free-form header carriers (Cookie, Set-Cookie, X-Auth-Key, X-Auth-Email) run first in scrubHeaderCarriers,
  // so the shape rules below only ever see the marker.
  // Quoted header and pair values next, whatever their shape, so the scheme and pair rules see the marker.
  [ERROR_QUOTED_CREDENTIAL_PATTERN, QUOTED_VALUE_REPLACEMENT],
  [ERROR_QUOTED_SCHEME_PATTERN, QUOTED_VALUE_REPLACEMENT],
  // Authorization scheme values wherever they appear (headers, cookies, HTML, JSON messages); the value must be
  // long, carry a digit or base64 symbol, or change case inside the word, so prose such as "Basic authentication"
  // and "Bearer Token" stays.
  // Case-sensitive so the inner-case-change test means what it says (under /i, [a-z][A-Z] is any two letters).
  [/\b(Bearer|bearer|BEARER|Basic|basic|BASIC|Digest|digest|Negotiate|negotiate|SSWS|Token|token|TOKEN|ApiKey|apikey|APIKEY|Api-Key|api-key)\s+(?=[A-Za-z0-9\-._~+/=:]{16,}|[A-Za-z0-9\-._~+/=:]*[\d+/=]|[A-Za-z0-9\-._~+/=:]*[a-z][A-Z])[A-Za-z0-9\-._~+/=:]{6,}/g, `$1 ${REDACTED_ERROR_VALUE}`],
  // JWT-shaped strings.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED_ERROR_VALUE],
  // PEM blocks, whole or cut off.
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED_ERROR_VALUE],
  // AWS access key ids, 40-character secret access keys, long secret-shaped blobs, and hex digests.
  [/\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
  [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, REDACTED_ERROR_VALUE],
  // Long blobs must carry a digit so camelCase identifiers survive.
  [/(?<![A-Za-z0-9+_=-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_=-])/g, REDACTED_ERROR_VALUE],
  [/\b[a-f0-9]{32,}\b/gi, REDACTED_ERROR_VALUE],
];

// URL userinfo and query strings anywhere in the string, not only when the string starts with a URL.
const ERROR_URL_PATTERN = /\b(https?:\/\/)(?:[^\s/@"'<>]+@)?([^\s?#"'<>]+)(\?[^\s#"'<>]*)?/gi;

/**
 * Rule 9 scrub boundary for bare values. A run of 16 or more token characters is removed when it is shaped
 * like a token (base64 symbols, digits scattered through its letters, or casing that breaks into one- and
 * two-letter camelCase pieces) and kept when it is shaped like a name: "-" or "_" separated segments that are
 * each letters in any casing, digits alone, or letters with one digit group (`prod-us-east-2026`,
 * `AWSLambdaBasicExecutionRole`, `sha256`), an uppercase code, or a canonical UUID. "/", ".", ":", "@", and
 * whitespace end a run, so path segments, hostnames, ARNs, and emails are judged piece by piece. Opaque
 * identifiers whose shape is a token's are removed from error text as well; they travel in structured fields.
 */
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&]))?/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const MIN_LETTERS_FOR_CASING = 6;

const CAMEL_WORD_PATTERN = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g;
const MAX_SHORT_WORD_LENGTH = 2;

/**
 * Token-shaped casing. Split at camelCase boundaries, a name is words and acronyms of three letters or more
 * (`GetAccessKeyLastUsed`, `AWSLambdaBasicExecutionRole`, `getHTTPSUrl`), while a random run breaks into
 * one- and two-letter pieces (`bPxRfiCYcanaryKEYqm`: b, Px, C, KE). Two or more such pieces making up at
 * least a third of the words is the token signal; one short word (`GetEbsEncryptionByDefault`) is a name.
 */
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  const words = letters.match(CAMEL_WORD_PATTERN) ?? [];
  const shortWords = words.filter((word) => word.length <= MAX_SHORT_WORD_LENGTH).length;
  return shortWords >= 2 && shortWords * 3 >= words.length;
}

/** A "-" or "_" separated segment shaped like part of a name: empty, digits alone, or letters with at most one digit group and no token casing. */
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || /^\d+$/.test(segment)) return true;
  if (!/^[A-Za-z0-9]+$/.test(segment)) return false;
  if ((segment.match(/\d+/g) ?? []).length > 1) return false;
  return !hasTokenCasing(segment.replace(/\d+/g, ""));
}

function looksLikeToken(run: string): boolean {
  if (UUID_PATTERN.test(run) || UPPERCASE_CODE_PATTERN.test(run)) return false;
  if (/[+=]/.test(run)) return true;
  return run.split(/[-_]/).some((segment) => !isNameSegment(segment));
}

function scrubLongTokens(text: string): string {
  return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string) => (looksLikeToken(run) ? REDACTED_ERROR_VALUE : run));
}

/**
 * Rule 9 sink for error text. describeError() (every attemptAwsRead failure and every access probe) and
 * errorMessage() (tool-level failures) are the only conversions from a thrown SDK error to recorded text,
 * and both run this pass, so no path can carry a credential echoed by a request context, a proxy body, or
 * a URL into findings, summaries, access checks, or the bundle.
 */
export function redactErrorText(text: string): string {
  let scrubbed = scrubConfiguredSecrets(text);
  scrubbed = scrubbed.replace(ERROR_URL_PATTERN, (_match, scheme: string, hostPath: string, query?: string) =>
    `${scheme}${hostPath}${query ? `?${REDACTED_ERROR_VALUE}` : ""}`,
  );
  scrubbed = scrubHeaderCarriers(scrubbed);
  for (const [pattern, replacement] of ERROR_TEXT_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, replacement);
  }
  scrubbed = scrubCredentialPairs(scrubbed);
  return scrubLongTokens(scrubbed);
}

/** Content type of the response an SDK error carries, when the SDK attached one. */
function responseContentType(error: JsonRecord): string | undefined {
  const headers = asObject(asObject(error.$response)?.headers);
  if (!headers) return undefined;
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === "content-type");
  return asString(entry?.[1])?.split(";")[0]?.trim();
}

/**
 * The SDK attaches the raw body as $responseBodyText when a response could not be parsed as the service
 * protocol (for example a proxy's 502 HTML page). Such a body can echo request headers, so it is described by
 * content type and byte length only; a message that is itself markup is treated the same way.
 */
function nonJsonBodyNote(error: JsonRecord | undefined): string | undefined {
  if (!error) return undefined;
  const bodyText = typeof error.$responseBodyText === "string" ? error.$responseBodyText : undefined;
  const message = typeof error.message === "string" ? error.message : undefined;
  const body = bodyText ?? (message && /^\s*<(?:!doctype|html|\?xml)/i.test(message) ? message : undefined);
  if (body === undefined) return undefined;
  const contentType = responseContentType(error) ?? (/^\s*<(?:!doctype|html)/i.test(body) ? "text/html" : "unknown content type");
  return `non-JSON body (${contentType}, ${Buffer.byteLength(body, "utf8")} bytes)`;
}

/**
 * A parser's message quotes the text it could not parse (V8: `Unexpected token '<', "<html>..." is not valid
 * JSON`), so a SyntaxError raised by the SDK deserializer, a credential cache, or any JSON.parse in the chain is
 * never interpolated: the failure is described by the body note when the SDK attached the body, otherwise by
 * the error name alone.
 */
function isParseError(error: unknown): boolean {
  return error instanceof SyntaxError || asObject(error)?.name === "SyntaxError";
}

const PARSE_ERROR_NOTE = "response could not be parsed as the service protocol; the parser's message is not recorded because it quotes the body";

/**
 * Describes a thrown SDK error as "<code> (HTTP <status>): <message>" with every part scrubbed; the code
 * and status are kept so a failure names what the service answered without repeating request context.
 */
function describeError(error: unknown): string {
  // An AwsApiError was built by this function when the client threw it; its message is already the record.
  if (error instanceof AwsApiError) return error.message;
  const object = asObject(error);
  const code = errorCode(error);
  const status = errorHttpStatus(error);
  // An object without a message contributes nothing (never its "[object Object]" rendering); a primitive is its text.
  const rawMessage = asString(object?.$bodyNote)
    ?? nonJsonBodyNote(object)
    ?? (isParseError(error) ? PARSE_ERROR_NOTE : error instanceof Error ? error.message : asString(object?.message) ?? (object ? "" : String(error)));
  const message = code && rawMessage.startsWith(`${code}:`) ? rawMessage.slice(code.length + 1).trim() : rawMessage;
  const prefix = code
    ? (status !== undefined ? `${code} (HTTP ${status})` : code)
    : (status !== undefined ? `HTTP ${status}` : "");
  return redactErrorText(prefix && message ? `${prefix}: ${message}` : prefix || message);
}

/** Message of a tool-level failure, run through the same sink as every recorded read error. */
function errorMessage(error: unknown): string {
  return describeError(error);
}

/**
 * Thrown by every AwsAuditorClient read in place of the SDK's own error (rule 9, fixed-text client errors). The
 * SDK's message can quote the response body (its deserializer raises V8's SyntaxError, which quotes a window of
 * the text and the whole source when it is 21 characters or shorter) or echo request context, so a caller that
 * logs the thrown error would re-emit it; a scrub at the tool boundary does not protect that caller. This error
 * carries describeError()'s text and only the structured fields the classifiers read: the SDK error name as
 * `code` and the observed HTTP status. Nothing that can hold body text ($response, $responseBodyText, the
 * cause) is retained.
 */
export class AwsApiError extends Error {
  /** The SDK error name (for example AccessDeniedException, SyntaxError), or "" when the SDK error had none. */
  readonly code: string;
  /** HTTP status the request observed; undefined for transport failures (timeouts, connection errors). */
  readonly httpStatus: number | undefined;
  /** Kept in the SDK's shape so callers that read $metadata.httpStatusCode keep working; it holds numbers only. */
  readonly $metadata: { httpStatusCode?: number };

  constructor(cause: unknown) {
    super(describeError(cause));
    this.name = "AwsApiError";
    this.code = errorCode(cause);
    this.httpStatus = errorHttpStatus(cause);
    this.$metadata = this.httpStatus === undefined ? {} : { httpStatusCode: this.httpStatus };
  }
}

/** Errors the client throws as-is: already fixed text, and their types are part of the client's contract. */
function toAwsApiError(error: unknown): Error {
  if (error instanceof AwsApiError || error instanceof AwsCredentialProviderError) return error;
  return new AwsApiError(error);
}

type SdkClient = { send: (...args: any[]) => any; config?: unknown };

/**
 * The documented shape of a top-level output member: a list, a map or structure (which the service never answers
 * empty), a non-empty string, a boolean, or a string that is a JSON policy document carrying a Statement.
 */
export type AwsOutputMemberKind = "list" | "map" | "structure" | "string" | "boolean" | "policyDocument";

/**
 * The top-level output member each command the client sends is answered with, and its documented shape; a list
 * member is present (empty) even when the account holds nothing. When a command can answer with one of several
 * members, any one counts, and every one that is present must have its documented shape. A 2xx whose deserialized
 * output carries none of them, or carries one in another shape (a string where a list is documented, an empty
 * structure, bare text inside an XML list element the deserializer read as empty, a Policy that is not a policy
 * document), was not a service response (a proxy's HTML page, an empty body the SDK turns into an output without
 * members, a foreign document bound to a payload member) and is thrown as IncompleteResponse rather than read as
 * an empty inventory or a default (round 4 item A).
 */
export const AWS_REQUIRED_OUTPUT_MEMBERS: Readonly<Record<string, Readonly<Record<string, AwsOutputMemberKind>>>> = Object.freeze({
  GetCallerIdentity: { Account: "string" },
  GetAccountSummary: { SummaryMap: "map" },
  GetAccountPasswordPolicy: { PasswordPolicy: "structure" },
  ListUsers: { Users: "list" },
  ListMFADevices: { MFADevices: "list" },
  ListAccessKeys: { AccessKeyMetadata: "list" },
  GetAccessKeyLastUsed: { AccessKeyLastUsed: "structure" },
  GetAccountAuthorizationDetails: { RoleDetailList: "list", UserDetailList: "list", GroupDetailList: "list", Policies: "list" },
  ListPolicies: { Policies: "list" },
  GetPolicyVersion: { PolicyVersion: "structure" },
  LookupEvents: { Events: "list" },
  DescribeTrails: { trailList: "list" },
  GetTrailStatus: { IsLogging: "boolean" },
  GetEventSelectors: { TrailARN: "string", EventSelectors: "list", AdvancedEventSelectors: "list" },
  DescribeHub: { HubArn: "string" },
  GetEnabledStandards: { StandardsSubscriptions: "list" },
  DescribeConfigurationRecorders: { ConfigurationRecorders: "list" },
  DescribeConfigurationRecorderStatus: { ConfigurationRecordersStatus: "list" },
  ListDetectors: { DetectorIds: "list" },
  GetDetector: { Status: "string", ServiceRole: "string" },
  DescribeOrganization: { Organization: "structure" },
  ListAccounts: { Accounts: "list" },
  ListTargetsForPolicy: { Targets: "list" },
  ListAnalyzers: { analyzers: "list" },
  ListFindings: { findings: "list" },
  ListInstances: { Instances: "list" },
  ListAssessments: { assessmentMetadata: "list" },
  GetAlternateContact: { AlternateContact: "structure" },
  DescribeRegions: { Regions: "list" },
  GetPublicAccessBlock: { PublicAccessBlockConfiguration: "structure" },
  ListBuckets: { Buckets: "list" },
  GetBucketPolicyStatus: { PolicyStatus: "structure" },
  GetBucketEncryption: { ServerSideEncryptionConfiguration: "structure" },
  GetBucketPolicy: { Policy: "policyDocument" },
  GetEbsEncryptionByDefault: { EbsEncryptionByDefault: "boolean" },
  DescribeVpcs: { Vpcs: "list" },
  DescribeFlowLogs: { FlowLogs: "list" },
  DescribeNetworkAcls: { NetworkAcls: "list" },
  DescribeSecurityGroups: { SecurityGroups: "list" },
  DescribeDBInstances: { DBInstances: "list" },
  ListKeys: { Keys: "list" },
  DescribeKey: { KeyMetadata: "structure" },
  GetKeyRotationStatus: { KeyRotationEnabled: "boolean" },
});

/**
 * The XML element that carries a member when it is not the member's own name. Only the EC2 query protocol renames
 * its top-level members on the wire; the IAM, STS, and RDS query protocol and the S3 REST-XML protocol use the
 * member name.
 */
const EC2_XML_ELEMENT_NAMES: Readonly<Record<string, string>> = Object.freeze({
  Regions: "regionInfo",
  Vpcs: "vpcSet",
  FlowLogs: "flowLogSet",
  NetworkAcls: "networkAclSet",
  SecurityGroups: "securityGroupInfo",
  EbsEncryptionByDefault: "ebsEncryptionByDefault",
});

const INCOMPLETE_RESPONSE_CODE = "IncompleteResponse";

/**
 * What the raw HTTP response carried, recorded before the SDK deserializer consumed it. The body is held only until
 * the shape guard has inspected it for the request it belongs to and never enters an error.
 */
interface ObservedResponse {
  statusCode?: number;
  contentType?: string;
  bodyBytes?: number;
  body?: Uint8Array | string;
}

type StreamCollector = (stream: unknown) => Promise<Uint8Array>;

function headerValue(headers: unknown, name: string): string | undefined {
  const record = asObject(headers);
  if (!record) return undefined;
  const entry = Object.entries(record).find(([key]) => key.toLowerCase() === name);
  return asString(entry?.[1]);
}

/**
 * Deserialize-step middleware inner to the SDK's deserializer: it sees the raw response first, records its
 * status, content type, body length, and the body bytes, and hands the deserializer the same bytes. The shape
 * guard describes a 2xx the deserializer emptied by type and length alone and reads the body only to tell a list
 * element the deserializer read as empty from one that held bare text; the observation is dropped with the send.
 */
function observeResponseMiddleware(observed: ObservedResponse, streamCollector: StreamCollector | undefined) {
  return (next: (args: unknown) => Promise<unknown>) => async (args: unknown): Promise<unknown> => {
    const result = await next(args);
    const response = asObject(asObject(result)?.response);
    if (response) {
      observed.statusCode = asNumber(response.statusCode);
      observed.contentType = headerValue(response.headers, "content-type")?.split(";")[0]?.trim();
      const body = response.body;
      if (body === undefined || body === null) observed.bodyBytes = 0;
      else if (body instanceof Uint8Array) {
        observed.bodyBytes = body.byteLength;
        observed.body = body;
      } else if (typeof body === "string") {
        observed.bodyBytes = Buffer.byteLength(body, "utf8");
        observed.body = body;
      } else if (streamCollector) {
        const bytes = await streamCollector(body);
        observed.bodyBytes = bytes.byteLength;
        observed.body = bytes;
        response.body = bytes;
      }
    }
    return result;
  };
}

/** The content-type-and-length note for a body the guard refused; "not observed" when no HTTP response was seen (a patched send). */
function observedBodyNote(observed: ObservedResponse): string {
  if (observed.bodyBytes === undefined) return "body: not observed";
  if (observed.bodyBytes === 0) return "body: empty, 0 bytes";
  return `body: ${observed.contentType ?? "unknown content type"}, ${observed.bodyBytes} bytes`;
}

/**
 * Whether an error was raised by the SDK's deserializer for a response that was not a service error: the
 * deserialize step attaches the response to whatever it throws, and a service error (modeled or default) is
 * the only thing it throws that carries a fault. The type checks the deserializer runs on a documented member
 * (expectBoolean, expectString, parseBoolean, the XML parser) quote the offending value in their message.
 */
function isDeserializationFailure(error: unknown): boolean {
  const object = asObject(error);
  if (!object || object.$fault !== undefined) return false;
  return isParseError(error) || error instanceof TypeError || Object.prototype.hasOwnProperty.call(object, "$response");
}

/**
 * A deserializer failure described from the observed response rather than from the SDK error. The SDK's
 * deserializer raises V8's SyntaxError for a body that is not the service protocol and, in this SDK version,
 * attaches neither the body nor its content type to it; an HTML page in place of any answer (a proxy's error
 * page with a 502, an interstitial with a 200) is the same class. Both are recorded as the non-JSON body note
 * built from the content type and byte length the middleware measured. A member the deserializer refused to
 * read as its documented type (a string where a boolean is written, text inside a boolean element) is the
 * same failure as the shape guard's, named IncompleteResponse with the command and the body note; the SDK's
 * message, which quotes the value, is never recorded. Any other error passes through as-is.
 */
function withObservedBody(error: unknown, observed: ObservedResponse, command: unknown): unknown {
  if (observed.bodyBytes === undefined || error instanceof AwsApiError || error instanceof AwsCredentialProviderError) return error;
  const object = asObject(error);
  if (typeof object?.$responseBodyText === "string") return error;
  const htmlBody = observed.contentType !== undefined && /^text\/html$/i.test(observed.contentType);
  const status = errorHttpStatus(error) ?? observed.statusCode;
  const metadata = status === undefined ? {} : { httpStatusCode: status };
  if (isParseError(error) || htmlBody) {
    return {
      name: isParseError(error) ? "SyntaxError" : errorCode(error) || UNKNOWN_ERROR_CODE,
      $metadata: metadata,
      $bodyNote: `non-JSON body (${observed.contentType ?? "unknown content type"}, ${observed.bodyBytes} bytes)`,
    };
  }
  if (isDeserializationFailure(error)) {
    return {
      name: INCOMPLETE_RESPONSE_CODE,
      $metadata: metadata,
      $bodyNote: `${commandName(command)} answered with a value outside its documented shape (${observedBodyNote(observed)})`,
    };
  }
  return error;
}

function commandName(command: unknown): string {
  const constructor = (command as { constructor?: { name?: unknown } } | null)?.constructor;
  return (asString(constructor?.name) ?? "").replace(/Command$/, "");
}

/** The shape of a deserialized value in fixed words (never its content), for the guard's message. */
function describeValueShape(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return value.length === 0 ? "an empty list" : "a list";
  switch (typeof value) {
    case "string":
      return value.length === 0 ? "an empty string" : "a string";
    case "boolean":
      return "a boolean";
    case "number":
    case "bigint":
      return "a number";
    case "object":
      return Object.keys(value as object).length === 0 ? "an empty structure" : "a structure";
    default:
      return typeof value;
  }
}

/** A documented member kind in fixed words, for the guard's message. */
function describeMemberKind(kind: AwsOutputMemberKind): string {
  switch (kind) {
    case "list":
      return "a list";
    case "map":
      return "a map";
    case "structure":
      return "a structure";
    case "string":
      return "a string";
    case "boolean":
      return "a boolean";
    case "policyDocument":
      return "a policy document";
    default: {
      const exhaustive: never = kind;
      throw new Error(`unhandled output member kind ${String(exhaustive)}`);
    }
  }
}

/** Whether a string is a JSON policy document carrying a Statement (a list or a single statement). */
function isPolicyDocument(text: string): boolean {
  try {
    const statement = asObject(JSON.parse(text))?.Statement;
    return Array.isArray(statement) || asObject(statement) !== undefined;
  } catch {
    return false;
  }
}

/** Whether a deserialized member has its documented shape. */
function hasDocumentedShape(value: unknown, kind: AwsOutputMemberKind): boolean {
  switch (kind) {
    case "list":
      return Array.isArray(value);
    case "map":
    case "structure":
      return asObject(value) !== undefined && !Array.isArray(value) && Object.keys(value as object).length > 0;
    case "string":
      return typeof value === "string" && value.length > 0;
    case "boolean":
      return typeof value === "boolean";
    case "policyDocument":
      return typeof value === "string" && isPolicyDocument(value);
    default: {
      const exhaustive: never = kind;
      throw new Error(`unhandled output member kind ${String(exhaustive)}`);
    }
  }
}

const UTF8_BOM = [0xef, 0xbb, 0xbf];
const XML_WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);

/** The observed body as text when it opens as an XML document; undefined for any other body (JSON is never decoded) or when none was observed. */
function observedXmlText(observed: ObservedResponse): string | undefined {
  const body = observed.body;
  if (body === undefined) return undefined;
  if (typeof body === "string") return /^\uFEFF?\s*</.test(body) ? body : undefined;
  let offset = UTF8_BOM.every((byte, index) => body[index] === byte) ? UTF8_BOM.length : 0;
  while (offset < body.length && XML_WHITESPACE.has(body[offset] as number)) offset += 1;
  if (body[offset] !== 0x3c) return undefined;
  return Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString("utf8");
}

/** The content of the first `<name>` element in an XML document: "" when it is empty or self-closing, undefined when absent. */
function xmlElementContent(xml: string, name: string): string | undefined {
  const open = new RegExp(`<${name}(?:\\s[^>]*?)?(/?)>`).exec(xml);
  if (!open) return undefined;
  if (open[1] === "/") return "";
  const start = open.index + open[0].length;
  const end = xml.indexOf(`</${name}>`, start);
  return end === -1 ? undefined : xml.slice(start, end);
}

/**
 * Whether an XML body wrote a member the way its kind is documented. The SDK's XML deserializer reads bare text
 * inside a list element as an empty list, inside a map or structure element as an empty structure, and inside a
 * boolean element as false, so those shapes are only visible in the body: a list, map, or structure element must
 * be empty or hold child elements, and a boolean element must hold true or false. An element that is absent from
 * the body (a member the deserializer did not read from it) is not judged here.
 */
function xmlMemberHasDocumentedShape(xml: string, member: string, kind: AwsOutputMemberKind): boolean {
  const content = xmlElementContent(xml, EC2_XML_ELEMENT_NAMES[member] ?? member)?.trim();
  if (content === undefined) return true;
  switch (kind) {
    case "list":
    case "map":
    case "structure":
      return content === "" || /^<(?!!\[CDATA\[)/.test(content);
    case "boolean":
      return /^(?:true|false)$/i.test(content);
    case "string":
    case "policyDocument":
      return true;
    default: {
      const exhaustive: never = kind;
      throw new Error(`unhandled output member kind ${String(exhaustive)}`);
    }
  }
}

/**
 * The shape guard at the send boundary: a 2xx output that lacks every member the command is answered with, whose
 * body was empty or an HTML page, or whose present members are not in their documented shape (a string where a
 * list is documented, an empty structure, bare text inside an XML container or boolean element, a Policy that is
 * not a policy document) is an unreadable surface. It is thrown as an SDK-shaped error named IncompleteResponse
 * (the observed status, the command, the member, the shapes in fixed words, and the body note; never the body or
 * the value), which the caller turns into AwsApiError like any other failure, so the read renders manual or null
 * downstream instead of an empty inventory or a default.
 */
function assertOutputShape(command: unknown, output: unknown, observed: ObservedResponse): void {
  const name = commandName(command);
  const required = AWS_REQUIRED_OUTPUT_MEMBERS[name];
  // Every command the client sends is in the table (a test holds it to the source); anything else is not judged.
  if (!required) return;
  const record = asObject(output);
  const status = observed.statusCode ?? asNumber(asObject(record?.$metadata)?.httpStatusCode);
  const members = Object.keys(required);
  const present = members.filter((member) => record?.[member] !== undefined);
  const htmlBody = observed.contentType !== undefined && /^text\/html$/i.test(observed.contentType);
  let reason: string | undefined;
  if (present.length === 0 || observed.bodyBytes === 0 || htmlBody) {
    reason = `answered without its ${members.join("/")} member`;
  } else {
    const xml = observedXmlText(observed);
    for (const member of present) {
      const kind = required[member];
      const value = record?.[member];
      if (!hasDocumentedShape(value, kind)) {
        reason = `answered with its ${member} member as ${describeValueShape(value)} where ${describeMemberKind(kind)} is documented`;
        break;
      }
      if (xml !== undefined && !xmlMemberHasDocumentedShape(xml, member, kind)) {
        reason = `answered with bare text in its ${member} element where ${describeMemberKind(kind)} is documented`;
        break;
      }
    }
  }
  if (reason === undefined) return;
  const cause = {
    name: INCOMPLETE_RESPONSE_CODE,
    message: `${name} ${reason} (${observedBodyNote(observed)})`,
    $metadata: status === undefined ? {} : { httpStatusCode: status },
  };
  throw new AwsApiError(cause);
}

/**
 * Overrides send() on one SDK client instance so every error it throws is rethrown as AwsApiError and every
 * output it resolves passes the shape guard. The prototype's send is looked up on each call, so the instance
 * keeps following the SDK's implementation (or a test fixture's patch of it, which the observing middleware
 * never runs under); only the shape of the thrown error changes.
 */
function guardSdkClient<T extends SdkClient>(client: T): T {
  const prototype = Object.getPrototypeOf(client) as SdkClient;
  const streamCollector = asObject(client.config)?.streamCollector as StreamCollector | undefined;
  const guardedSend = async (command: unknown, ...rest: unknown[]): Promise<unknown> => {
    const observed: ObservedResponse = {};
    const stack = asObject(command)?.middlewareStack as { add?: (middleware: unknown, options: unknown) => void } | undefined;
    if (typeof stack?.add === "function") {
      stack.add(observeResponseMiddleware(observed, streamCollector), {
        step: "deserialize",
        priority: "low",
        name: "grclankerObserveResponse",
        tags: ["GRCLANKER_OBSERVE_RESPONSE"],
        override: true,
      });
    }
    try {
      const output = await prototype.send.apply(client, [command, ...rest]);
      assertOutputShape(command, output, observed);
      return output;
    } catch (error) {
      throw toAwsApiError(withObservedBody(error, observed, command));
    } finally {
      observed.body = undefined;
    }
  };
  Object.defineProperty(client, "send", { value: guardedSend, writable: true, configurable: true });
  return client;
}

type AwsCredentialProvider = ReturnType<typeof fromIni>;

const SDK_ERROR_NAME_PATTERN = /^[A-Za-z]+(?:Error|Exception)$/;
const SYSTEM_ERROR_CODE_PATTERN = /^E[A-Z]+$/;

/** The SDK error name (and a filesystem code such as ENOENT when present), each validated against a strict pattern so no free text rides along. */
function sdkErrorIdentity(cause: unknown): string {
  const record = asObject(cause);
  const name = asString(record?.name) ?? (cause instanceof Error ? cause.name : undefined);
  const code = asString(record?.code);
  return [
    name && SDK_ERROR_NAME_PATTERN.test(name) ? name : "UnknownError",
    code && SYSTEM_ERROR_CODE_PATTERN.test(code) ? code : undefined,
  ].filter(Boolean).join(" ");
}

/**
 * Raised in place of any error the credential provider chain throws (rule 9, config loader class). The SDK
 * parses the shared config and credentials files, SSO token caches, and credential_process output while it
 * resolves credentials, and a provider's message can quote that text. This error carries only the provider
 * name, the SDK error name (plus a filesystem code), and the paths of the files an operator should check,
 * never the provider's message.
 */
export class AwsCredentialProviderError extends Error {
  readonly provider: string;
  readonly code: string;

  constructor(provider: string, cause: unknown) {
    const identity = sdkErrorIdentity(cause);
    const credentialsFile = process.env.AWS_SHARED_CREDENTIALS_FILE || "~/.aws/credentials";
    const configFile = process.env.AWS_CONFIG_FILE || "~/.aws/config";
    super(
      `credentials could not be resolved by ${provider} (${identity}). The provider's message is not recorded because it can quote the shared config or credentials file; check the profile in ${credentialsFile} and ${configFile}.`,
    );
    this.name = "AwsCredentialProviderError";
    this.provider = provider;
    this.code = identity;
  }
}

/**
 * Wraps a provider so every failure while resolving credentials surfaces as AwsCredentialProviderError, and
 * registers the resolved secret access key and session token as configured secrets so an error string that
 * echoes either (whatever its shape, in any encoded form) is scrubbed.
 */
function guardCredentialProvider(provider: string, resolve: AwsCredentialProvider): AwsCredentialProvider {
  return async (options) => {
    let credentials;
    try {
      credentials = await resolve(options);
    } catch (error) {
      throw new AwsCredentialProviderError(provider, error);
    }
    registerConfiguredSecrets(credentials.secretAccessKey, credentials.sessionToken);
    return credentials;
  };
}

/**
 * The credential provider for the resolved configuration: the named profile through fromIni, otherwise the
 * same default chain the SDK would use (environment, shared files, SSO, process, container, and instance
 * metadata providers), both guarded so provider errors never reach an error string verbatim.
 */
function credentialProviderFor(config: AwsResolvedConfig): AwsCredentialProvider {
  return config.profile
    ? guardCredentialProvider(`fromIni (profile ${config.profile})`, fromIni({ profile: config.profile }))
    : guardCredentialProvider("fromNodeProviderChain (default credential chain)", fromNodeProviderChain({ clientConfig: { region: config.region } }));
}

/** The recorded line for a failed read: the command label, whether it was a denial, and the scrubbed error text. */
function readFailureLine(label: string, error: unknown): string {
  return `${label}: ${isAwsAccessDenied(error) ? "AccessDenied" : "error"} (${describeError(error)})`;
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
    const message = readFailureLine(label, error);
    errors.push(message);
    return { error: message, denied, errorCode: errorCode(error) || undefined, httpStatus: errorHttpStatus(error) };
  }
}

/** Renders a value only when its read completed; an unread inventory renders null rather than an empty default. */
function ifRead<T>(read: AwsSurfaceResult<unknown> | undefined, value: T): T | null {
  return read && !read.error ? value : null;
}

/** Truncation flag of a paged read; null until the read completes, so a denied list never renders as complete. */
function truncatedFlag(read: AwsSurfaceResult<AwsPagedList<unknown>> | undefined): boolean | null {
  return read?.value ? read.value.truncated : null;
}

/** Marker written in place of a dataset whose read failed, naming the command and what the service answered. */
function notCollectedMarker(command: string, read: AwsSurfaceResult<unknown>): JsonRecord {
  return {
    collected: false,
    command,
    error: read.error ?? null,
    error_code: read.errorCode ?? null,
    http_status: read.httpStatus ?? null,
  };
}

interface AwsPage<T> {
  items: T[];
  nextToken?: string;
}

/**
 * Walk a token-paginated AWS list to completion or `limit`. The walk also stops, and reports
 * `truncated: true`, when the service hands back the token it was just given (a stalled cursor
 * would otherwise loop forever) or when the page budget is spent, so no caller mistakes a
 * cut-short walk for a complete inventory.
 */
export async function paginateAwsList<T>(
  limit: number,
  fetchPage: (token: string | undefined, remaining: number) => Promise<AwsPage<T>>,
): Promise<AwsPagedList<T>> {
  const items: T[] = [];
  let token: string | undefined;
  for (let page = 0; page < MAX_PAGES_PER_LIST; page += 1) {
    const result = await fetchPage(token, Math.max(1, limit - items.length + 1));
    items.push(...result.items);
    if (items.length > limit) {
      items.length = limit;
      return { items, truncated: true };
    }
    const nextToken = asString(result.nextToken);
    if (!nextToken) return { items, truncated: false };
    if (nextToken === token) return { items, truncated: true };
    token = nextToken;
  }
  return { items, truncated: true };
}

/** Access key ids are credential identifiers; keep only the prefix and suffix so findings stay traceable without echoing them. */
export function maskAccessKeyId(accessKeyId: string): string {
  if (accessKeyId.length <= 8) return "****";
  return `${accessKeyId.slice(0, 4)}****${accessKeyId.slice(-4)}`;
}

/**
 * A server-assigned identifier for a read label, kept whole when the error-text scrub keeps it and otherwise
 * masked the way access key ids are. A GuardDuty detector id is 32 hex characters, a hex digest to the scrub,
 * and would render as [REDACTED] in the recorded line, which loses the detector and reads as though a secret
 * had been recorded; the masked form still names it.
 */
export function labelIdentifier(id: string): string {
  return redactErrorText(id) === id ? id : maskAccessKeyId(id);
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
  // The enabled-region list is unknown when DescribeRegions failed, so the total is null rather than the one region read.
  return {
    regions: [fallbackRegion],
    regionsTotal: null,
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

/**
 * Wire encoding of a policy document string. IAM (GetPolicyVersion, GetAccountAuthorizationDetails) returns
 * documents URL-encoded per RFC 3986; S3 GetBucketPolicy returns the policy as plain JSON text.
 */
export type PolicyDocumentEncoding = "iam-url-encoded" | "plain-json";

function parsePolicyJson(text: string): JsonRecord | undefined {
  try {
    return asObject(JSON.parse(text));
  } catch {
    return undefined;
  }
}

function parseUrlEncodedPolicyJson(text: string): JsonRecord | undefined {
  try {
    return asObject(JSON.parse(decodeURIComponent(text)));
  } catch {
    // A document that was not URL-encoded after all (or carries a stray %) is still readable as plain JSON.
    return parsePolicyJson(text);
  }
}

export function normalizePolicyDocument(policyDocument: unknown, encoding: PolicyDocumentEncoding): JsonRecord | undefined {
  if (typeof policyDocument !== "string") return asObject(policyDocument);
  switch (encoding) {
    case "iam-url-encoded":
      return parseUrlEncodedPolicyJson(policyDocument);
    case "plain-json":
      return parsePolicyJson(policyDocument);
    default: {
      const exhaustive: never = encoding;
      return exhaustive;
    }
  }
}

function normalizeStatements(policyDocument: unknown, encoding: PolicyDocumentEncoding): JsonRecord[] {
  const document = normalizePolicyDocument(policyDocument, encoding);
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
    const statements = normalizeStatements(item?.PolicyDocument, "iam-url-encoded");
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
  private readonly credentials: AwsCredentialProvider;
  private readonly ec2Clients = new Map<string, EC2Client>();
  private readonly rdsClients = new Map<string, RDSClient>();
  private readonly kmsClients = new Map<string, KMSClient>();
  private readonly cloudTrailClients = new Map<string, CloudTrailClient>();
  private readonly now: () => Date;

  constructor(
    private readonly config: AwsResolvedConfig,
    options: { now?: () => Date } = {},
  ) {
    const credentials = credentialProviderFor(config);
    const clientConfig = { region: config.region, credentials };
    this.credentials = credentials;
    // Every SDK client is guarded so the error a read throws is fixed text (AwsApiError), never the SDK's message.
    this.sts = guardSdkClient(new STSClient(clientConfig));
    this.iam = guardSdkClient(new IAMClient(clientConfig));
    this.cloudTrail = guardSdkClient(new CloudTrailClient(clientConfig));
    this.securityHub = guardSdkClient(new SecurityHubClient(clientConfig));
    this.configService = guardSdkClient(new ConfigServiceClient(clientConfig));
    this.guardDuty = guardSdkClient(new GuardDutyClient(clientConfig));
    this.organizations = guardSdkClient(new OrganizationsClient(clientConfig));
    this.accessAnalyzer = guardSdkClient(new AccessAnalyzerClient(clientConfig));
    this.ssoAdmin = guardSdkClient(new SSOAdminClient(clientConfig));
    this.s3 = guardSdkClient(new S3Client({ ...clientConfig, followRegionRedirects: true }));
    this.s3Control = guardSdkClient(new S3ControlClient(clientConfig));
    this.auditManager = guardSdkClient(new AuditManagerClient(clientConfig));
    this.account = guardSdkClient(new AccountClient(clientConfig));
    this.now = options.now ?? (() => new Date());
  }

  /** IAM ListPolicies with Scope Local (customer managed), paginated to completion up to limit. */
  async listCustomerManagedPolicies(limit = DEFAULT_POLICY_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (marker) => {
      const result = await this.iam.send(new ListIamPoliciesCommand({ Scope: "Local", OnlyAttached: false, Marker: marker, MaxItems: 100 }));
      return {
        items: (result.Policies ?? []).map((policy) => ({
          PolicyName: policy.PolicyName,
          Arn: policy.Arn,
          DefaultVersionId: policy.DefaultVersionId,
          AttachmentCount: policy.AttachmentCount,
          PermissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount,
        })),
        nextToken: result.IsTruncated ? result.Marker : undefined,
      };
    });
  }

  /** IAM GetPolicyVersion; the Document is URL-encoded JSON per the API reference. */
  async getPolicyVersionDocument(policyArn: string, versionId: string): Promise<JsonRecord | null> {
    const result = await this.iam.send(new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }));
    return normalizePolicyDocument(result.PolicyVersion?.Document, "iam-url-encoded") ?? null;
  }

  /**
   * CloudTrail LookupEvents filtered on Username root within the window (management events, 90-day history).
   * The lookup is regional; callers pass us-east-1 to see global sign-in events regardless of the configured region.
   */
  async lookupRootEvents(region: string, startTime: Date, endTime: Date, limit = DEFAULT_EVENT_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.cloudTrailFor(region).send(new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: "Username", AttributeValue: "root" }],
        StartTime: startTime,
        EndTime: endTime,
        MaxResults: 50,
        NextToken: nextToken,
      }));
      return {
        items: (result.Events ?? []).map((event) => ({
          EventId: event.EventId,
          EventName: event.EventName,
          EventTime: event.EventTime,
          EventSource: event.EventSource,
          Username: event.Username,
          ReadOnly: event.ReadOnly,
        })),
        nextToken: result.NextToken,
      };
    });
  }

  /** Audit Manager ListAssessments with status ACTIVE. */
  async listActiveAuditManagerAssessments(limit = DEFAULT_MAX_FINDINGS): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.auditManager.send(new ListAssessmentsCommand({ status: "ACTIVE", maxResults: 100, nextToken }));
      return {
        items: (result.assessmentMetadata ?? []).map((assessment) => ({
          id: assessment.id,
          name: assessment.name,
          status: assessment.status,
          complianceType: assessment.complianceType,
          creationTime: assessment.creationTime,
          lastUpdated: assessment.lastUpdated,
        })),
        nextToken: result.nextToken,
      };
    });
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
      client = guardSdkClient(new EC2Client({ region, credentials: this.credentials }));
      this.ec2Clients.set(region, client);
    }
    return client;
  }

  private cloudTrailFor(region: string): CloudTrailClient {
    if (region === this.config.region) return this.cloudTrail;
    let client = this.cloudTrailClients.get(region);
    if (!client) {
      client = guardSdkClient(new CloudTrailClient({ region, credentials: this.credentials }));
      this.cloudTrailClients.set(region, client);
    }
    return client;
  }

  private rdsFor(region: string): RDSClient {
    let client = this.rdsClients.get(region);
    if (!client) {
      client = guardSdkClient(new RDSClient({ region, credentials: this.credentials }));
      this.rdsClients.set(region, client);
    }
    return client;
  }

  private kmsFor(region: string): KMSClient {
    let client = this.kmsClients.get(region);
    if (!client) {
      client = guardSdkClient(new KMSClient({ region, credentials: this.credentials }));
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
    return paginateAwsList(limit, async (continuationToken, remaining) => {
      const result = await this.s3.send(new ListBucketsCommand({
        ContinuationToken: continuationToken,
        MaxBuckets: Math.min(1000, remaining),
      }));
      return {
        items: (result.Buckets ?? []).map((bucket) => ({ Name: bucket.Name, CreationDate: bucket.CreationDate, BucketRegion: bucket.BucketRegion })),
        nextToken: result.ContinuationToken,
      };
    });
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
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.ec2For(region).send(new DescribeVpcsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      return {
        items: (result.Vpcs ?? []).map((vpc) => ({ VpcId: vpc.VpcId, IsDefault: vpc.IsDefault, CidrBlock: vpc.CidrBlock, State: vpc.State })),
        nextToken: result.NextToken,
      };
    });
  }

  async describeFlowLogs(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.ec2For(region).send(new DescribeFlowLogsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      return {
        items: (result.FlowLogs ?? []).map((flowLog) => ({
          FlowLogId: flowLog.FlowLogId,
          ResourceId: flowLog.ResourceId,
          FlowLogStatus: flowLog.FlowLogStatus,
          TrafficType: flowLog.TrafficType,
          LogDestinationType: flowLog.LogDestinationType,
          LogDestination: flowLog.LogDestination,
          LogGroupName: flowLog.LogGroupName,
        })),
        nextToken: result.NextToken,
      };
    });
  }

  async describeNetworkAcls(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.ec2For(region).send(new DescribeNetworkAclsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      return {
        items: (result.NetworkAcls ?? []).map((acl) => ({
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
        })),
        nextToken: result.NextToken,
      };
    });
  }

  async describeSecurityGroups(region: string, limit = DEFAULT_RESOURCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.ec2For(region).send(new DescribeSecurityGroupsCommand({ NextToken: nextToken, MaxResults: 1000 }));
      return {
        items: (result.SecurityGroups ?? []).map((group) => ({
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
        })),
        nextToken: result.NextToken,
      };
    });
  }

  async describeDbInstances(region: string, limit = DEFAULT_INSTANCE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (marker) => {
      const result = await this.rdsFor(region).send(new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }));
      return {
        items: (result.DBInstances ?? []).map((instance) => ({
          DBInstanceIdentifier: instance.DBInstanceIdentifier,
          DBInstanceArn: instance.DBInstanceArn,
          Engine: instance.Engine,
          StorageEncrypted: instance.StorageEncrypted,
          KmsKeyId: instance.KmsKeyId,
        })),
        nextToken: result.Marker,
      };
    });
  }

  async listKmsKeys(region: string, limit = DEFAULT_KEY_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (marker) => {
      const result = await this.kmsFor(region).send(new ListKeysCommand({ Marker: marker, Limit: 1000 }));
      return {
        items: (result.Keys ?? []).map((key) => ({ KeyId: key.KeyId, KeyArn: key.KeyArn })),
        nextToken: result.Truncated ? result.NextMarker : undefined,
      };
    });
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

  /** IAM GetAccountPasswordPolicy; null when no policy exists (NoSuchEntity). Denials and other failures propagate to the caller. */
  async getPasswordPolicy(): Promise<JsonRecord | null> {
    try {
      const result = await this.iam.send(new GetAccountPasswordPolicyCommand({}));
      return asObject(result.PasswordPolicy) ?? null;
    } catch (error) {
      if (isErrorCode(error, "NoSuchEntity", "NoSuchEntityException")) return null;
      throw error;
    }
  }

  async listIamUsers(limit = DEFAULT_USER_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (marker, remaining) => {
      const result = await this.iam.send(new ListUsersCommand({ Marker: marker, MaxItems: Math.min(100, remaining) }));
      return {
        items: (result.Users ?? []).map((user) => ({
          UserName: user.UserName,
          Arn: user.Arn,
          CreateDate: user.CreateDate,
          PasswordLastUsed: user.PasswordLastUsed,
        })),
        nextToken: result.IsTruncated ? result.Marker : undefined,
      };
    });
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

  async getAccountAuthorizationDetails(limit = DEFAULT_ROLE_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (marker, remaining) => {
      const result = await this.iam.send(new GetAccountAuthorizationDetailsCommand({
        Filter: ["Role"],
        Marker: marker,
        MaxItems: Math.min(100, remaining),
      }));
      return {
        items: (result.RoleDetailList ?? []).map((role) => ({
          RoleName: role.RoleName,
          Arn: role.Arn,
          PermissionsBoundary: role.PermissionsBoundary,
          AttachedManagedPolicies: role.AttachedManagedPolicies,
          RolePolicyList: role.RolePolicyList,
        })),
        nextToken: result.IsTruncated ? result.Marker : undefined,
      };
    });
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

  /**
   * Security Hub DescribeHub; null when the hub is not enabled in the region (InvalidAccessException or
   * ResourceNotFoundException per the API reference). Denials and other failures propagate to the caller.
   */
  async describeSecurityHub(): Promise<JsonRecord | null> {
    try {
      const result = await this.securityHub.send(new DescribeHubCommand({}));
      return {
        HubArn: result.HubArn,
        AutoEnableControls: result.AutoEnableControls,
        SubscribedAt: result.SubscribedAt,
      };
    } catch (error) {
      if (isErrorCode(error, "InvalidAccessException", "ResourceNotFoundException")) return null;
      throw error;
    }
  }

  async getEnabledSecurityHubStandards(limit = DEFAULT_STANDARD_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.securityHub.send(new GetEnabledStandardsCommand({ MaxResults: 100, NextToken: nextToken }));
      return {
        items: (result.StandardsSubscriptions ?? []).map((standard) => ({
          StandardsArn: standard.StandardsArn,
          StandardsStatus: standard.StandardsStatus,
          StandardsSubscriptionArn: standard.StandardsSubscriptionArn,
        })),
        nextToken: result.NextToken,
      };
    });
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

  async listDetectors(limit = DEFAULT_DETECTOR_LIMIT): Promise<AwsPagedList<string>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.guardDuty.send(new ListDetectorsCommand({ MaxResults: 50, NextToken: nextToken }));
      return { items: result.DetectorIds ?? [], nextToken: result.NextToken };
    });
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

  async listAnalyzers(limit = DEFAULT_ANALYZER_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.accessAnalyzer.send(new ListAnalyzersCommand({ nextToken, maxResults: 100 }));
      return {
        items: (result.analyzers ?? []).map((analyzer) => ({
          arn: analyzer.arn,
          name: analyzer.name,
          type: analyzer.type,
          status: analyzer.status,
        })),
        nextToken: result.nextToken,
      };
    });
  }

  async listAccessAnalyzerFindings(analyzerArn: string, limit = DEFAULT_MAX_FINDINGS): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken, remaining) => {
      const result = await this.accessAnalyzer.send(new ListFindingsCommand({
        analyzerArn,
        maxResults: Math.min(100, remaining),
        nextToken,
      }));
      return {
        items: (result.findings ?? []).map((finding) => ({
          id: finding.id,
          status: finding.status,
          resourceType: finding.resourceType,
          resource: finding.resource,
          principal: finding.principal,
          condition: finding.condition,
        })),
        nextToken: result.nextToken,
      };
    });
  }

  /**
   * Organizations DescribeOrganization; null when the account is not part of an organization
   * (AWSOrganizationsNotInUseException). Denials and other failures propagate to the caller.
   */
  async describeOrganization(): Promise<JsonRecord | null> {
    try {
      const result = await this.organizations.send(new DescribeOrganizationCommand({}));
      return {
        Id: result.Organization?.Id,
        FeatureSet: result.Organization?.FeatureSet,
        ManagementAccountId: result.Organization?.MasterAccountId,
      };
    } catch (error) {
      if (isErrorCode(error, "AWSOrganizationsNotInUseException")) return null;
      throw error;
    }
  }

  async listAccounts(limit = DEFAULT_ACCOUNT_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken, remaining) => {
      const result = await this.organizations.send(new ListAccountsCommand({ NextToken: nextToken, MaxResults: Math.min(20, remaining) }));
      return {
        items: (result.Accounts ?? []).map((account) => ({
          Id: account.Id,
          Name: account.Name,
          Status: account.Status,
        })),
        nextToken: result.NextToken,
      };
    });
  }

  async listScps(limit = DEFAULT_POLICY_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.organizations.send(new ListPoliciesCommand({
        Filter: "SERVICE_CONTROL_POLICY",
        NextToken: nextToken,
        MaxResults: 20,
      }));
      return {
        items: (result.Policies ?? []).map((policy) => ({
          Id: policy.Id,
          Name: policy.Name,
          AwsManaged: policy.AwsManaged,
        })),
        nextToken: result.NextToken,
      };
    });
  }

  async listPolicyTargets(policyId: string, limit = DEFAULT_TARGET_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.organizations.send(new ListTargetsForPolicyCommand({
        PolicyId: policyId,
        NextToken: nextToken,
      }));
      return {
        items: (result.Targets ?? []).map((target) => ({
          TargetId: target.TargetId,
          Name: target.Name,
          Type: target.Type,
        })),
        nextToken: result.NextToken,
      };
    });
  }

  /** Identity Center ListInstances; an empty list means no instance is visible, while denials propagate to the caller. */
  async listIdentityCenterInstances(limit = DEFAULT_ANALYZER_LIMIT): Promise<AwsPagedList<JsonRecord>> {
    return paginateAwsList(limit, async (nextToken) => {
      const result = await this.ssoAdmin.send(new ListInstancesCommand({ MaxResults: 100, NextToken: nextToken }));
      return {
        items: (result.Instances ?? []).map((instance) => ({
          InstanceArn: instance.InstanceArn,
          IdentityStoreId: instance.IdentityStoreId,
        })),
        nextToken: result.NextToken,
      };
    });
  }
}

/** What a readable probe saw: the items counted and, for paged reads, whether the walk stopped at its cap. */
interface ProbeObservation {
  count: number | null;
  truncated: boolean | null;
}

async function surface(
  name: string,
  service: string,
  command: string,
  region: string,
  loader: () => Promise<unknown>,
  observe: (value: unknown) => ProbeObservation,
): Promise<AwsAccessSurface> {
  try {
    const value = await loader();
    return { name, service, command, region, status: "readable", ...observe(value) };
  } catch (error) {
    // A probe that never completed has no count and no truncation state; it names what the service answered instead.
    return {
      name,
      service,
      command,
      region,
      status: "not_readable",
      count: null,
      truncated: null,
      error: describeError(error),
      error_code: errorCode(error) || null,
      http_status: errorHttpStatus(error) ?? null,
    };
  }
}

export type AwsAccessCheckClient = Pick<
  AwsAuditorClient,
  "getCallerIdentity" | "getAccountSummary" | "listIamUsers" | "describeTrails" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "listDetectors" | "listAnalyzers" | "describeOrganization" | "listIdentityCenterInstances" | "getResolvedConfig"
> & Partial<Pick<
  AwsAuditorClient,
  "describeRegions" | "listBuckets" | "listKmsKeys" | "describeDbInstances" | "listActiveAuditManagerAssessments" | "getSecurityAlternateContact"
>>;

function pagedObservation(value: unknown): ProbeObservation {
  const record = asObject(value);
  const items = record?.items;
  return {
    count: Array.isArray(items) ? items.length : null,
    truncated: typeof record?.truncated === "boolean" ? record.truncated : null,
  };
}

function arrayObservation(value: unknown): ProbeObservation {
  return { count: Array.isArray(value) ? value.length : null, truncated: null };
}

function presenceObservation(value: unknown): ProbeObservation {
  return { count: value ? 1 : 0, truncated: null };
}

export async function checkAwsAccess(client: AwsAccessCheckClient): Promise<AwsAccessCheckResult> {
  const caller = await client.getCallerIdentity();
  const config = client.getResolvedConfig();
  const region = config.region;
  const optionalProbes: Array<Promise<AwsAccessSurface>> = [];
  if (client.describeRegions) {
    optionalProbes.push(surface("ec2_regions", "ec2", "ec2:DescribeRegions", region, () => client.describeRegions!(), arrayObservation));
  }
  if (client.listBuckets) {
    optionalProbes.push(surface("s3_buckets", "s3", "s3:ListBuckets", region, () => client.listBuckets!(1), pagedObservation));
  }
  if (client.listKmsKeys) {
    optionalProbes.push(surface("kms_keys", "kms", "kms:ListKeys", region, () => client.listKmsKeys!(region, 1), pagedObservation));
  }
  if (client.describeDbInstances) {
    optionalProbes.push(surface("rds_instances", "rds", "rds:DescribeDBInstances", region, () => client.describeDbInstances!(region, 1), pagedObservation));
  }
  if (client.listActiveAuditManagerAssessments) {
    optionalProbes.push(surface("audit_manager", "auditmanager", "auditmanager:ListAssessments", region, () => client.listActiveAuditManagerAssessments!(1), pagedObservation));
  }
  if (client.getSecurityAlternateContact) {
    optionalProbes.push(surface("account_contacts", "account", "account:GetAlternateContact", region, () => client.getSecurityAlternateContact!(), presenceObservation));
  }
  const surfaces = await Promise.all([
    surface("iam_summary", "iam", "iam:GetAccountSummary", region, () => client.getAccountSummary(), () => ({ count: 1, truncated: null })),
    surface("iam_users", "iam", "iam:ListUsers", region, () => client.listIamUsers(1), pagedObservation),
    surface("cloudtrail", "cloudtrail", "cloudtrail:DescribeTrails", region, () => client.describeTrails(), arrayObservation),
    surface("security_hub", "securityhub", "securityhub:GetEnabledStandards", region, () => client.getEnabledSecurityHubStandards(), pagedObservation),
    surface("config", "config", "config:DescribeConfigurationRecorders", region, () => client.describeConfigurationRecorders(), arrayObservation),
    surface("guardduty", "guardduty", "guardduty:ListDetectors", region, () => client.listDetectors(), pagedObservation),
    surface("access_analyzer", "access-analyzer", "access-analyzer:ListAnalyzers", region, () => client.listAnalyzers(), pagedObservation),
    surface("organizations", "organizations", "organizations:DescribeOrganization", region, () => client.describeOrganization(), presenceObservation),
    surface("identity_center", "sso-admin", "sso:ListInstances", region, () => client.listIdentityCenterInstances(), pagedObservation),
    ...optionalProbes,
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount === surfaces.length ? "healthy" : "limited";
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
        ? "Run aws_assess_identity, aws_assess_logging_detection, aws_assess_org_guardrails, aws_assess_data_protection, aws_assess_network_security, or aws_export_audit_bundle."
        : `Grant read-only access for the audit principal to the surfaces marked not_readable (${surfaces.filter((item) => item.status === "not_readable").map((item) => item.service).join(", ") || "none"}); unreadable surfaces render manual findings, never pass.`,
  };
}

function isServiceWildcardAction(value: unknown): boolean {
  const actions = Array.isArray(value) ? value.map(String) : typeof value === "string" ? [value] : [];
  return actions.some((action) => /^[a-z0-9-]+:\*$/i.test(action));
}

function classifyPolicyStatements(document: JsonRecord | null): { fullAdmin: number; serviceWildcard: number } {
  let fullAdmin = 0;
  let serviceWildcard = 0;
  for (const statement of normalizeStatements(document, "iam-url-encoded")) {
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

interface RootActivityLookup {
  result: AwsSurfaceResult<AwsPagedList<JsonRecord>>;
  /** Region the returned events were read from. */
  lookupRegion: string;
  /** Set when the us-east-1 lookup failed and the configured region was read instead. */
  globalLookupError?: string;
}

/**
 * Root ConsoleLogin is a global event delivered to us-east-1 only, so the lookup always runs there first.
 * When us-east-1 cannot be read and the configured region differs, the configured region is read as a
 * fallback; its verdict is capped at warn because console sign-ins remain unverified.
 */
async function lookupRootActivity(
  client: Pick<AwsIdentityClient, "lookupRootEvents">,
  configuredRegion: string,
  start: Date,
  end: Date,
  errors: string[],
): Promise<RootActivityLookup> {
  const global = await attemptAwsRead(
    `cloudtrail:LookupEvents Username=root ${ROOT_EVENT_REGION}`,
    () => client.lookupRootEvents(ROOT_EVENT_REGION, start, end, DEFAULT_EVENT_LIMIT),
    errors,
  );
  if (!global.error || configuredRegion === ROOT_EVENT_REGION) {
    return { result: global, lookupRegion: ROOT_EVENT_REGION };
  }
  const regional = await attemptAwsRead(
    `cloudtrail:LookupEvents Username=root ${configuredRegion}`,
    () => client.lookupRootEvents(configuredRegion, start, end, DEFAULT_EVENT_LIMIT),
    errors,
  );
  return { result: regional, lookupRegion: configuredRegion, globalLookupError: global.error };
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

  const [summaryRead, passwordPolicyRead, userListRead, roleListRead, rootActivity, customerPolicies] = await Promise.all([
    attemptAwsRead("iam:GetAccountSummary", () => client.getAccountSummary(), errors),
    attemptAwsRead("iam:GetAccountPasswordPolicy", () => client.getPasswordPolicy(), errors),
    attemptAwsRead("iam:ListUsers", () => client.listIamUsers(userLimit), errors),
    attemptAwsRead("iam:GetAccountAuthorizationDetails Filter=Role", () => client.getAccountAuthorizationDetails(roleLimit), errors),
    lookupRootActivity(client, region, lookbackStart, now, errors),
    attemptAwsRead("iam:ListPolicies Scope=Local", () => client.listCustomerManagedPolicies(policyLimit), errors),
  ]);
  const rootEvents = rootActivity.result;
  const summary = summaryRead.value ?? {};
  const passwordPolicy = passwordPolicyRead.value ?? null;
  const userList = userListRead.value ?? { items: [], truncated: false };
  const roleList = roleListRead.value ?? { items: [], truncated: false };
  const users = userList.items;
  const roles = roleList.items;
  if (userList.truncated) errors.push(`iam:ListUsers: inventory truncated at user_limit ${userLimit}; user verdicts cover the first ${userLimit} users only.`);
  if (roleList.truncated) errors.push(`iam:GetAccountAuthorizationDetails Filter=Role: inventory truncated at role_limit ${roleLimit}; role verdicts cover the first ${roleLimit} roles only.`);
  const userCaps = userList.truncated ? [`user inventory truncated at ${userLimit}`] : [];
  const roleCaps = roleList.truncated ? [`role inventory truncated at ${roleLimit}`] : [];

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
  const accountMfaEnabled = asNumber(summaryMap.AccountMFAEnabled);
  const accountAccessKeysPresent = asNumber(summaryMap.AccountAccessKeysPresent);

  const usersWithoutMfa: string[] = [];
  const mfaUnreadableUsers: string[] = [];
  const staleAccessKeys: Array<{ userName: string; accessKeyId: string; ageDays?: number }> = [];
  const keysUnreadableUsers: string[] = [];
  const lastUsedUnreadableKeys: string[] = [];
  const dormantUsers: string[] = [];
  let sampledKeys = 0;

  // Per-user reads are attempted individually so one denied user is named and capped instead of aborting the assessment.
  const userDetails = await mapWithConcurrency(users, DEFAULT_CONCURRENCY, async (user) => {
    const userName = asString(user.UserName) ?? "unknown";
    const [mfaDevices, accessKeys] = await Promise.all([
      attemptAwsRead(`iam:ListMFADevices ${userName}`, () => client.listMfaDevices(userName), errors),
      attemptAwsRead(`iam:ListAccessKeys ${userName}`, () => client.listAccessKeys(userName), errors),
    ]);
    const keys = await mapWithConcurrency(accessKeys.value ?? [], DEFAULT_CONCURRENCY, async (key) => {
      const accessKeyId = asString(key.AccessKeyId);
      if (!accessKeyId) return undefined;
      const lastUsed = await attemptAwsRead(`iam:GetAccessKeyLastUsed ${maskAccessKeyId(accessKeyId)}`, () => client.getAccessKeyLastUsed(accessKeyId), errors);
      return { accessKeyId, createDate: extractTimestamp(key.CreateDate), lastUsed };
    });
    return { userName, passwordAge: daysBetween(now, extractTimestamp(user.PasswordLastUsed)), mfaDevices, accessKeys, keys: keys.filter((key) => key !== undefined) };
  });

  for (const user of userDetails) {
    if (user.mfaDevices.error) mfaUnreadableUsers.push(user.userName);
    else if ((user.mfaDevices.value ?? []).length === 0) usersWithoutMfa.push(user.userName);

    if (user.accessKeys.error) keysUnreadableUsers.push(user.userName);
    for (const key of user.keys) {
      sampledKeys += 1;
      // A key whose last use could not be read is not judged: its creation date says nothing about use, so
      // substituting it would fail a named user on evidence the run never saw. The key is listed for review instead.
      if (key.lastUsed.error) {
        lastUsedUnreadableKeys.push(maskAccessKeyId(key.accessKeyId));
        continue;
      }
      // A key never used since creation carries no LastUsedDate and is judged by its age.
      const ageDays = daysBetween(now, extractTimestamp(key.lastUsed.value) ?? key.createDate);
      if (ageDays !== undefined && ageDays > staleDays) {
        staleAccessKeys.push({ userName: user.userName, accessKeyId: key.accessKeyId, ageDays });
      }
    }

    // Without password activity, a user is dormant only when it is known to hold no access keys; an unreadable key list is capped instead.
    if ((user.passwordAge !== undefined && user.passwordAge > staleDays) || (user.passwordAge === undefined && !user.accessKeys.error && user.keys.length === 0)) {
      dormantUsers.push(user.userName);
    }
  }

  // A count judged over a partially readable set is rendered beside the number judged, and is null when nothing was
  // judged, so "0 stale" never stands next to an unreadable remainder as if every key had been examined.
  const keysJudged = sampledKeys - lastUsedUnreadableKeys.length;
  const anyKeyNotJudged = lastUsedUnreadableKeys.length > 0 || keysUnreadableUsers.length > 0;
  const judgedKeys = <T>(value: T): T | null => (keysJudged === 0 && anyKeyNotJudged ? null : value);
  const usersMfaJudged = users.length - mfaUnreadableUsers.length;
  const judgedMfa = <T>(value: T): T | null => (usersMfaJudged === 0 && mfaUnreadableUsers.length > 0 ? null : value);

  const privilegedRoles = roles.filter(hasAdministratorPolicy);
  const rolesWithoutBoundaries = privilegedRoles.filter((role) => !role.PermissionsBoundary);
  const mfaCaps = [...userCaps];
  if (mfaUnreadableUsers.length > 0) mfaCaps.push(`ListMFADevices unreadable for ${mfaUnreadableUsers.length} user(s) (${sample(mfaUnreadableUsers, 10).join(", ")})`);
  const keyCaps = [...userCaps];
  if (keysUnreadableUsers.length > 0) keyCaps.push(`ListAccessKeys unreadable for ${keysUnreadableUsers.length} user(s) (${sample(keysUnreadableUsers, 10).join(", ")})`);
  const keyRotationCaps = [...keyCaps];
  if (lastUsedUnreadableKeys.length > 0) keyRotationCaps.push(`GetAccessKeyLastUsed unreadable for ${lastUsedUnreadableKeys.length} key(s) (${sample(lastUsedUnreadableKeys, 10).join(", ")}); those keys were not judged and need a manual last-used review`);

  let mfaStatus: AwsFinding["status"];
  let mfaSummary: string;
  if (userListRead.error) {
    mfaStatus = "manual";
    mfaSummary = `IAM users could not be listed (${userListRead.error}); review MFA coverage in the IAM console or credential report.`;
  } else if (usersWithoutMfa.length > 0) {
    mfaStatus = "fail";
    mfaSummary = `${usersWithoutMfa.length}/${users.length} IAM users are missing MFA.`;
  } else if (users.length > 0 && mfaUnreadableUsers.length === users.length) {
    mfaStatus = "manual";
    mfaSummary = `MFA devices could not be listed for any of the ${users.length} sampled IAM users (${errors.find((line) => line.startsWith("iam:ListMFADevices")) ?? "iam:ListMFADevices failed"}); review MFA coverage in the IAM credential report.`;
  } else {
    mfaStatus = "pass";
    mfaSummary = `All ${users.length - mfaUnreadableUsers.length} sampled IAM users with readable device lists have MFA devices.`;
  }
  const mfaVerdict = withCap(mfaStatus, mfaSummary, mfaCaps);

  let keyRotationStatus: AwsFinding["status"];
  let keyRotationSummary: string;
  if (userListRead.error) {
    keyRotationStatus = "manual";
    keyRotationSummary = `IAM users could not be listed (${userListRead.error}); review access key age in the IAM credential report.`;
  } else if (staleAccessKeys.length > 0) {
    keyRotationStatus = "fail";
    keyRotationSummary = `${staleAccessKeys.length} access keys are older than ${staleDays} days or unused beyond that threshold.`;
  } else if (users.length > 0 && keysUnreadableUsers.length === users.length) {
    keyRotationStatus = "manual";
    keyRotationSummary = `Access keys could not be listed for any of the ${users.length} sampled IAM users (${errors.find((line) => line.startsWith("iam:ListAccessKeys")) ?? "iam:ListAccessKeys failed"}); review key age in the IAM credential report.`;
  } else if (sampledKeys > 0 && lastUsedUnreadableKeys.length === sampledKeys) {
    keyRotationStatus = "manual";
    keyRotationSummary = `Last-used dates could not be read for any of the ${sampledKeys} sampled access key(s) (${errors.find((line) => line.startsWith("iam:GetAccessKeyLastUsed")) ?? "iam:GetAccessKeyLastUsed failed"}); no key was judged. Review key age and last use in the IAM credential report.`;
  } else {
    keyRotationStatus = "pass";
    keyRotationSummary = `No sampled access key exceeded the ${staleDays}-day staleness threshold.`;
  }
  const keyRotationVerdict = withCap(keyRotationStatus, keyRotationSummary, keyRotationCaps);

  let boundaryStatus: AwsFinding["status"];
  let boundarySummary: string;
  if (roleListRead.error) {
    boundaryStatus = "manual";
    boundarySummary = `IAM roles could not be read (${roleListRead.error}); review permission boundaries on privileged roles in the IAM console.`;
  } else if (rolesWithoutBoundaries.length > maxPrivilegedRoles) {
    boundaryStatus = "fail";
    boundarySummary = `${rolesWithoutBoundaries.length}/${privilegedRoles.length} privileged roles lack permission boundaries.`;
  } else if (rolesWithoutBoundaries.length > 0) {
    boundaryStatus = "warn";
    boundarySummary = `${rolesWithoutBoundaries.length}/${privilegedRoles.length} privileged roles lack permission boundaries.`;
  } else {
    boundaryStatus = "pass";
    boundarySummary = `No sampled privileged role lacked a permission boundary (${roles.length} roles read).`;
  }
  const boundaryVerdict = withCap(boundaryStatus, boundarySummary, roleCaps);

  let dormantStatus: AwsFinding["status"];
  let dormantSummary: string;
  if (userListRead.error) {
    dormantStatus = "manual";
    dormantSummary = `IAM users could not be listed (${userListRead.error}); review dormant users in the IAM credential report.`;
  } else if (dormantUsers.length > 0) {
    dormantStatus = "warn";
    dormantSummary = `${dormantUsers.length} IAM users appear dormant beyond ${staleDays} days or without recent password activity.`;
  } else {
    dormantStatus = "pass";
    dormantSummary = "No dormant IAM users were detected from the sampled password activity.";
  }
  const dormantVerdict = withCap(dormantStatus, dormantSummary, keyCaps);

  let rootMfaStatus: AwsFinding["status"];
  let rootMfaSummary: string;
  if (summaryRead.error) {
    rootMfaStatus = "manual";
    rootMfaSummary = `The IAM account summary could not be read (${summaryRead.error}); verify root MFA and the absence of root access keys under IAM > Dashboard.`;
  } else if (accountMfaEnabled !== 1 || (accountAccessKeysPresent ?? 0) > 0) {
    rootMfaStatus = "fail";
    rootMfaSummary = `Root MFA enabled=${accountMfaEnabled === 1}; root access keys present=${accountAccessKeysPresent ?? "unknown (AccountAccessKeysPresent missing from the summary)"}.`;
  } else {
    rootMfaStatus = "pass";
    rootMfaSummary = "Root account shows MFA enabled and no access keys present.";
  }

  const passwordComplexityPresent = [
    passwordPolicy?.RequireSymbols,
    passwordPolicy?.RequireNumbers,
    passwordPolicy?.RequireUppercaseCharacters,
    passwordPolicy?.RequireLowercaseCharacters,
  ].every((value) => value === true);
  const passwordMinimumLength = asNumber(passwordPolicy?.MinimumPasswordLength) ?? 0;
  let passwordStatus: AwsFinding["status"];
  let passwordSummary: string;
  if (passwordPolicyRead.error) {
    passwordStatus = "manual";
    passwordSummary = `The account password policy could not be read (${passwordPolicyRead.error}); verify it under IAM > Account settings.`;
  } else if (!passwordPolicy) {
    passwordStatus = "fail";
    passwordSummary = "No account password policy is configured (GetAccountPasswordPolicy returned NoSuchEntity).";
  } else {
    passwordStatus = passwordMinimumLength < 14 || !passwordComplexityPresent ? "fail" : "pass";
    passwordSummary = `Minimum length ${passwordMinimumLength} with complexity requirements present=${passwordComplexityPresent}.`;
  }

  const findings = [
    finding(
      "AWS-IAM-01",
      "Root account MFA and access keys",
      "critical",
      rootMfaStatus,
      rootMfaSummary,
      ["FedRAMP IA-2(1)", "FedRAMP AC-6(1)", "CMMC 3.1.5", "CIS AWS 1.4"],
      {
        summary_readable: !summaryRead.error,
        account_mfa_enabled: ifRead(summaryRead, accountMfaEnabled ?? null),
        account_access_keys_present: ifRead(summaryRead, accountAccessKeysPresent ?? null),
      },
    ),
    finding(
      "AWS-IAM-02",
      "IAM user MFA coverage",
      "high",
      mfaVerdict.status,
      mfaVerdict.summary,
      ["FedRAMP IA-2(1)", "FedRAMP IA-2(2)", "CMMC 3.5.3", "PCI-DSS 8.4.2"],
      {
        users_readable: !userListRead.error,
        user_count: ifRead(userListRead, users.length),
        users_mfa_judged: ifRead(userListRead, judgedMfa(usersMfaJudged)),
        users_without_mfa: ifRead(userListRead, judgedMfa(usersWithoutMfa.slice(0, 25))),
        users_mfa_unreadable: ifRead(userListRead, sample(mfaUnreadableUsers)),
        user_inventory_truncated: truncatedFlag(userListRead),
      },
    ),
    finding(
      "AWS-IAM-03",
      "Password policy strength",
      "high",
      passwordStatus,
      passwordSummary,
      ["FedRAMP IA-5(1)", "CMMC 3.5.7", "SOC 2 CC6.1", "CIS AWS 1.8"],
      {
        password_policy_readable: !passwordPolicyRead.error,
        password_policy_configured: ifRead(passwordPolicyRead, Boolean(passwordPolicy)),
        password_policy: ifRead(passwordPolicyRead, passwordPolicy),
      },
    ),
    finding(
      "AWS-IAM-04",
      "Access key rotation",
      "high",
      keyRotationVerdict.status,
      keyRotationVerdict.summary,
      ["FedRAMP IA-5(1)", "FedRAMP AC-2(3)", "CMMC 3.5.8", "CIS AWS 1.12"],
      {
        users_readable: !userListRead.error,
        // Zero keys were sampled because none could be listed, not because none exist, when every key list was unreadable.
        keys_sampled: users.length > 0 && keysUnreadableUsers.length === users.length ? null : ifRead(userListRead, sampledKeys),
        keys_judged: ifRead(userListRead, judgedKeys(keysJudged)),
        stale_access_keys: ifRead(userListRead, judgedKeys(staleAccessKeys.slice(0, 25).map((key) => ({ userName: key.userName, accessKeyId: maskAccessKeyId(key.accessKeyId), ageDays: key.ageDays })))),
        users_keys_unreadable: ifRead(userListRead, sample(keysUnreadableUsers)),
        keys_last_used_unreadable: ifRead(userListRead, sample(lastUsedUnreadableKeys)),
        user_inventory_truncated: truncatedFlag(userListRead),
      },
    ),
    finding(
      "AWS-IAM-05",
      "Privileged role boundaries",
      "medium",
      boundaryVerdict.status,
      boundaryVerdict.summary,
      ["FedRAMP AC-6(1)", "FedRAMP AC-6(2)", "CMMC 3.1.5", "CIS AWS 1.16"],
      {
        roles_readable: !roleListRead.error,
        roles_read: ifRead(roleListRead, roles.length),
        privileged_roles: ifRead(roleListRead, privilegedRoles.length),
        roles_without_boundaries: ifRead(roleListRead, rolesWithoutBoundaries.slice(0, 25).map((role) => role.RoleName ?? role.Arn)),
        max_privileged_roles: maxPrivilegedRoles,
        role_inventory_truncated: truncatedFlag(roleListRead),
      },
    ),
    finding(
      "AWS-IAM-06",
      "Dormant IAM users",
      "low",
      dormantVerdict.status,
      dormantVerdict.summary,
      ["FedRAMP AC-2(3)", "CMMC 3.1.12", "SOC 2 CC6.2", "CIS AWS 1.12"],
      {
        users_readable: !userListRead.error,
        dormant_users: ifRead(userListRead, dormantUsers.slice(0, 25)),
        users_keys_unreadable: ifRead(userListRead, sample(keysUnreadableUsers)),
        user_inventory_truncated: truncatedFlag(userListRead),
      },
    ),
  ];

  // Control 4 (root sign-ins): CloudTrail LookupEvents for Username root within the lookback window,
  // read from us-east-1 because root ConsoleLogin is a global event delivered only there.
  const rootLookupRegion = rootActivity.lookupRegion;
  const rootEventList = rootEvents.value?.items ?? [];
  const rootConsoleLogins = rootEventList.filter((event) => asString(event.EventName) === "ConsoleLogin");
  const rootOtherEvents = rootEventList.filter((event) => asString(event.EventName) !== "ConsoleLogin");
  const undatedRootEvents = rootEventList.filter((event) => extractTimestamp(event.EventTime) === undefined);
  let rootStatus: AwsFinding["status"];
  let rootSummary: string;
  if (rootEvents.error) {
    const attempted = rootActivity.globalLookupError ? `${rootActivity.globalLookupError}; ${rootEvents.error}` : rootEvents.error;
    rootStatus = "manual";
    rootSummary = `Root activity could not be read from CloudTrail LookupEvents (${attempted}); review root sign-in history in the CloudTrail console or IAM credential report.`;
  } else if (rootConsoleLogins.length > 0) {
    rootStatus = "fail";
    rootSummary = `${rootConsoleLogins.length} root ConsoleLogin event(s) were recorded in the last ${lookbackDays} days (lookup region ${rootLookupRegion}); root should not be used for daily or administrative tasks.`;
  } else if (rootOtherEvents.length > 0) {
    rootStatus = "warn";
    rootSummary = `No root ConsoleLogin events, but ${rootOtherEvents.length} other root API event(s) were recorded in the last ${lookbackDays} days (lookup region ${rootLookupRegion}); confirm each was a sanctioned root-only task.`;
  } else {
    rootStatus = "pass";
    rootSummary = `No CloudTrail events attributed to the root user were found in the last ${lookbackDays} days in ${rootLookupRegion}, the region that receives global console sign-in events.`;
  }
  const rootCaps: string[] = [];
  if (rootActivity.globalLookupError) {
    rootCaps.push(`${ROOT_EVENT_REGION} lookup failed (${rootActivity.globalLookupError}), so global console sign-in events are unverified and only ${rootLookupRegion} API activity was read`);
  }
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
      lookup_region: rootLookupRegion,
      global_event_region: ROOT_EVENT_REGION,
      global_lookup_error: rootActivity.globalLookupError ?? null,
      lookback_days: lookbackDays,
      window_start: lookbackStart.toISOString(),
      events_readable: !rootEvents.error,
      root_events: ifRead(rootEvents, rootEventList.length),
      root_console_logins: ifRead(rootEvents, sample(rootConsoleLogins.map((event) => ({ time: event.EventTime, source: event.EventSource })))),
      root_other_events: ifRead(rootEvents, sample(rootOtherEvents.map((event) => ({ time: event.EventTime, name: event.EventName, source: event.EventSource })))),
      lookup_truncated: truncatedFlag(rootEvents),
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
      policies_readable: !customerPolicies.error,
      customer_managed_policies: ifRead(customerPolicies, policyRows.length),
      full_admin_attached: ifRead(customerPolicies, sample(fullAdminAttached.map((row) => ({ name: row.name, attachment_count: row.attachment_count })))),
      full_admin_unattached: ifRead(customerPolicies, sample(fullAdminUnattached.map((row) => row.name))),
      service_wildcard_policies: ifRead(customerPolicies, sample(serviceWildcardPolicies.map((row) => row.name))),
      policies_unreadable: ifRead(customerPolicies, sample(unreadablePolicies.map((row) => row.name))),
      policy_inventory_truncated: truncatedFlag(customerPolicies),
      inline_policies: "not assessed",
    },
  ));

  return {
    title: "AWS identity posture",
    summary: {
      users: ifRead(userListRead, users.length),
      user_inventory_truncated: truncatedFlag(userListRead),
      users_mfa_judged: ifRead(userListRead, judgedMfa(usersMfaJudged)),
      users_without_mfa: ifRead(userListRead, judgedMfa(usersWithoutMfa.length)),
      keys_judged: ifRead(userListRead, judgedKeys(keysJudged)),
      stale_access_keys: ifRead(userListRead, judgedKeys(staleAccessKeys.length)),
      keys_last_used_unreadable: ifRead(userListRead, lastUsedUnreadableKeys.length),
      roles: ifRead(roleListRead, roles.length),
      role_inventory_truncated: truncatedFlag(roleListRead),
      privileged_roles: ifRead(roleListRead, privilegedRoles.length),
      roles_without_boundaries: ifRead(roleListRead, rolesWithoutBoundaries.length),
      dormant_users: ifRead(userListRead, dormantUsers.length),
      root_console_logins: ifRead(rootEvents, rootConsoleLogins.length),
      customer_managed_policies: ifRead(customerPolicies, policyRows.length),
      full_admin_policies_attached: ifRead(customerPolicies, fullAdminAttached.length),
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

export type AwsLoggingDetectionClient = Pick<
  AwsAuditorClient,
  "describeTrails" | "getTrailStatus" | "getEventSelectors" | "describeSecurityHub" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "describeConfigurationRecorderStatus" | "listDetectors" | "getDetector"
>;

export async function assessAwsLoggingDetection(client: AwsLoggingDetectionClient): Promise<AwsAssessmentResult> {
  const errors: string[] = [];
  const [trailList, hub, recorders, recorderStatuses, detectorIds] = await Promise.all([
    attemptAwsRead("cloudtrail:DescribeTrails", () => client.describeTrails(), errors),
    attemptAwsRead("securityhub:DescribeHub", () => client.describeSecurityHub(), errors),
    attemptAwsRead("config:DescribeConfigurationRecorders", () => client.describeConfigurationRecorders(), errors),
    attemptAwsRead("config:DescribeConfigurationRecorderStatus", () => client.describeConfigurationRecorderStatus(), errors),
    attemptAwsRead("guardduty:ListDetectors", () => client.listDetectors(), errors),
  ]);
  // Standards are only meaningful once the hub is known to be enabled; GetEnabledStandards fails on a disabled hub.
  const standards: AwsSurfaceResult<AwsPagedList<JsonRecord>> | undefined = hub.value
    ? await attemptAwsRead("securityhub:GetEnabledStandards", () => client.getEnabledSecurityHubStandards(), errors)
    : undefined;

  const trails = trailList.value ?? [];
  const trailDetails = await mapWithConcurrency(trails, DEFAULT_CONCURRENCY, async (trail) => {
    const nameOrArn = asString(trail.TrailARN) ?? asString(trail.Name) ?? "";
    const label = asString(trail.Name) ?? nameOrArn;
    const missing: AwsSurfaceResult<JsonRecord> = { error: "trail has neither Name nor TrailARN" };
    const [status, selectors] = nameOrArn
      ? await Promise.all([
          attemptAwsRead(`cloudtrail:GetTrailStatus ${label}`, () => client.getTrailStatus(nameOrArn), errors),
          attemptAwsRead(`cloudtrail:GetEventSelectors ${label}`, () => client.getEventSelectors(nameOrArn), errors),
        ])
      : [missing, missing];
    return {
      name: label,
      trailArn: asString(trail.TrailARN),
      isMultiRegion: trail.IsMultiRegionTrail === true,
      validation: trail.LogFileValidationEnabled === true,
      isLogging: boolFlag(status.value, "IsLogging"),
      statusError: status.error,
      hasDataEvents: selectors.value ? hasAnyDataEvents(selectors.value) : undefined,
      selectorsError: selectors.error,
    };
  });

  // Controls 6 and 7: a multi-region trail with log-file validation whose GetTrailStatus reports IsLogging=true.
  const goodTrails = trailDetails.filter((trail) => trail.isMultiRegion && trail.validation && trail.isLogging === true);
  const unverifiedTrails = trailDetails.filter((trail) => trail.isMultiRegion && trail.validation && trail.isLogging === undefined);
  const statusUnreadable = trailDetails.filter((trail) => trail.statusError);
  // A count over per-trail reads is unknown, not zero, when every trail's read failed.
  const trailStatusAllUnreadable = trailDetails.length > 0 && statusUnreadable.length === trailDetails.length;
  let trailStatus: AwsFinding["status"];
  let trailSummary: string;
  if (trailList.error) {
    trailStatus = "manual";
    trailSummary = `CloudTrail trails could not be listed (${trailList.error}); verify in the CloudTrail console that a multi-region trail with log-file validation is logging.`;
  } else if (goodTrails.length > 0) {
    trailStatus = "pass";
    trailSummary = `${goodTrails.length} of ${trails.length} CloudTrail trail(s) are multi-region, logging, and log-file validation enabled.`;
  } else if (unverifiedTrails.length > 0) {
    trailStatus = "manual";
    trailSummary = `${unverifiedTrails.length} multi-region trail(s) with log-file validation exist, but logging state could not be read (${unverifiedTrails[0].statusError ?? "IsLogging missing from GetTrailStatus"}); confirm IsLogging in the CloudTrail console.`;
  } else {
    trailStatus = "fail";
    trailSummary = `No multi-region CloudTrail trail with active logging and log-file validation was detected among ${trails.length} trail(s).`;
  }
  const trailCaps: string[] = [];
  if (statusUnreadable.length > 0) trailCaps.push(`GetTrailStatus unreadable for ${statusUnreadable.length} trail(s) (${statusUnreadable.map((trail) => trail.name).join(", ")})`);
  const trailVerdict = withCap(trailStatus, trailSummary, trailCaps);

  // Control 19: data events or advanced event selectors on at least one trail.
  const trailsWithDataEvents = trailDetails.filter((trail) => trail.hasDataEvents === true);
  const selectorsUnreadable = trailDetails.filter((trail) => trail.selectorsError);
  const selectorsAllUnreadable = trailDetails.length > 0 && selectorsUnreadable.length === trailDetails.length;
  let dataEventStatus: AwsFinding["status"];
  let dataEventSummary: string;
  if (trailList.error) {
    dataEventStatus = "manual";
    dataEventSummary = `CloudTrail trails could not be listed (${trailList.error}); verify data event selectors in the CloudTrail console.`;
  } else if (trailsWithDataEvents.length > 0) {
    dataEventStatus = "pass";
    dataEventSummary = `${trailsWithDataEvents.length} of ${trails.length} trail(s) capture data events or advanced event selectors.`;
  } else if (selectorsUnreadable.length > 0) {
    dataEventStatus = "manual";
    dataEventSummary = `Event selectors could not be read for ${selectorsUnreadable.length} of ${trails.length} trail(s) (${selectorsUnreadable[0].selectorsError}); data event coverage is unverified.`;
  } else {
    dataEventStatus = "warn";
    dataEventSummary = `No CloudTrail data event coverage was detected across ${trails.length} trail(s).`;
  }
  const dataEventCaps: string[] = [];
  if (selectorsUnreadable.length > 0) dataEventCaps.push(`GetEventSelectors unreadable for ${selectorsUnreadable.length} trail(s) (${selectorsUnreadable.map((trail) => trail.name).join(", ")})`);
  const dataEventVerdict = withCap(dataEventStatus, dataEventSummary, dataEventCaps);

  // Control 8: Security Hub enabled with at least one standards subscription.
  const standardList = standards?.value?.items ?? [];
  let hubStatus: AwsFinding["status"];
  let hubSummary: string;
  if (hub.error) {
    hubStatus = "manual";
    hubSummary = `Security Hub could not be described (${hub.error}); verify Security Hub enablement and standards in the console for the configured region.`;
  } else if (!hub.value) {
    hubStatus = "fail";
    hubSummary = "Security Hub is not enabled in the configured region (DescribeHub reported the hub as not subscribed).";
  } else if (standards?.error) {
    hubStatus = "warn";
    hubSummary = `Security Hub is enabled, but enabled standards could not be listed (${standards.error}); verify standards subscriptions in the console.`;
  } else if (standardList.length === 0) {
    hubStatus = "warn";
    hubSummary = "Security Hub is enabled but no standards subscription is enabled.";
  } else {
    hubStatus = "pass";
    hubSummary = `Security Hub is enabled with ${standardList.length} enabled standard subscription(s).`;
  }
  const hubCaps: string[] = [];
  if (standards?.value?.truncated) hubCaps.push(`standards list truncated at ${DEFAULT_STANDARD_LIMIT}`);
  const hubVerdict = withCap(hubStatus, hubSummary, hubCaps);

  // Control 9: at least one GuardDuty detector with Status=ENABLED.
  const detectorList = detectorIds.value?.items ?? [];
  const detectors = await mapWithConcurrency(detectorList, DEFAULT_CONCURRENCY, async (detectorId) => ({
    id: detectorId,
    detail: await attemptAwsRead(`guardduty:GetDetector ${labelIdentifier(detectorId)}`, () => client.getDetector(detectorId), errors),
  }));
  const enabledDetectors = detectors.filter((detector) => asString(detector.detail.value?.Status) === "ENABLED");
  const unreadableDetectors = detectors.filter((detector) => detector.detail.error);
  const detectorsAllUnreadable = detectors.length > 0 && unreadableDetectors.length === detectors.length;
  let detectorStatus: AwsFinding["status"];
  let detectorSummary: string;
  if (detectorIds.error) {
    detectorStatus = "manual";
    detectorSummary = `GuardDuty detectors could not be listed (${detectorIds.error}); verify GuardDuty enablement in the console for the configured region.`;
  } else if (enabledDetectors.length > 0) {
    detectorStatus = "pass";
    detectorSummary = `${enabledDetectors.length} of ${detectorList.length} GuardDuty detector(s) are enabled.`;
  } else if (unreadableDetectors.length > 0) {
    detectorStatus = "manual";
    detectorSummary = `${detectorList.length} GuardDuty detector(s) exist, but GetDetector could not be read for ${unreadableDetectors.length} of them (${unreadableDetectors[0].detail.error}); enablement is unverified.`;
  } else {
    detectorStatus = "fail";
    detectorSummary = detectorList.length === 0
      ? "No GuardDuty detector exists in the configured region."
      : `${detectorList.length} GuardDuty detector(s) exist but none reports Status=ENABLED.`;
  }
  const detectorCaps: string[] = [];
  if (unreadableDetectors.length > 0) detectorCaps.push(`GetDetector unreadable for ${unreadableDetectors.length} detector(s)`);
  if (detectorIds.value?.truncated) detectorCaps.push(`detector list truncated at ${DEFAULT_DETECTOR_LIMIT}`);
  const detectorVerdict = withCap(detectorStatus, detectorSummary, detectorCaps);

  // Control 10: a configuration recorder whose status reports recording=true.
  const recorderList = recorders.value ?? [];
  const statusList = recorderStatuses.value ?? [];
  const recordingRecorders = recorderList.filter((recorder) => {
    const name = asString(recorder.name);
    return statusList.some((item) => asString(item.name) === name && item.recording === true);
  });
  let configStatus: AwsFinding["status"];
  let configSummary: string;
  if (recorders.error) {
    configStatus = "manual";
    configSummary = `AWS Config recorders could not be listed (${recorders.error}); verify the configuration recorder in the AWS Config console for the configured region.`;
  } else if (recorderList.length === 0) {
    configStatus = "fail";
    configSummary = "No AWS Config configuration recorder exists in the configured region.";
  } else if (recorderStatuses.error) {
    configStatus = "manual";
    configSummary = `${recorderList.length} configuration recorder(s) exist, but recording state could not be read (${recorderStatuses.error}); confirm recording=true in the AWS Config console.`;
  } else if (recordingRecorders.length > 0) {
    configStatus = "pass";
    configSummary = `${recordingRecorders.length} of ${recorderList.length} configuration recorder(s) report recording=true.`;
  } else {
    configStatus = "fail";
    configSummary = `${recorderList.length} configuration recorder(s) exist but none reports recording=true.`;
  }

  const findings = [
    finding(
      "AWS-LOG-01",
      "Multi-region CloudTrail with validation",
      "critical",
      trailVerdict.status,
      trailVerdict.summary,
      ["FedRAMP AU-2", "FedRAMP AU-9", "CMMC 3.3.1", "CIS AWS 3.1"],
      {
        trails_readable: !trailList.error,
        trails: ifRead(trailList, trailDetails.map((trail) => ({ name: trail.name, is_multi_region: trail.isMultiRegion, validation: trail.validation, is_logging: trail.isLogging ?? null, status_error: trail.statusError ?? null }))),
      },
    ),
    finding(
      "AWS-LOG-02",
      "CloudTrail data events",
      "medium",
      dataEventVerdict.status,
      dataEventVerdict.summary,
      ["FedRAMP AU-12", "CMMC 3.3.1", "SOC 2 CC7.2", "CIS AWS 3.3"],
      {
        trails_readable: !trailList.error,
        data_event_trails: selectorsAllUnreadable ? null : ifRead(trailList, trailsWithDataEvents.map((trail) => trail.name)),
        selectors_unreadable: ifRead(trailList, selectorsUnreadable.map((trail) => trail.name)),
      },
    ),
    finding(
      "AWS-LOG-03",
      "Security Hub enablement",
      "high",
      hubVerdict.status,
      hubVerdict.summary,
      ["FedRAMP CA-7", "FedRAMP SI-4", "SOC 2 CC7.1", "PCI-DSS 11.5.1"],
      {
        hub_readable: !hub.error,
        hub_enabled: ifRead(hub, Boolean(hub.value)),
        standards_readable: standards ? !standards.error : null,
        standard_count: ifRead(standards, standardList.length),
        standards_truncated: truncatedFlag(standards),
      },
    ),
    finding(
      "AWS-LOG-04",
      "GuardDuty detectors",
      "high",
      detectorVerdict.status,
      detectorVerdict.summary,
      ["FedRAMP SI-4", "FedRAMP IR-4", "SOC 2 CC7.2", "CIS AWS 1.1"],
      {
        detectors_readable: !detectorIds.error,
        detector_count: ifRead(detectorIds, detectorList.length),
        enabled_detectors: detectorsAllUnreadable ? null : ifRead(detectorIds, enabledDetectors.length),
        detectors_unreadable: ifRead(detectorIds, unreadableDetectors.map((detector) => detector.id)),
        detector_list_truncated: truncatedFlag(detectorIds),
      },
    ),
    finding(
      "AWS-LOG-05",
      "AWS Config recording",
      "high",
      configStatus,
      configSummary,
      ["FedRAMP CM-2", "FedRAMP CM-6", "SOC 2 CC7.1", "CIS AWS 3.5"],
      {
        recorders_readable: !recorders.error,
        recorder_status_readable: !recorderStatuses.error,
        recorders: ifRead(recorders, recorderList.map((recorder) => ({ name: recorder.name, all_supported: asObject(recorder.recordingGroup)?.allSupported ?? null }))),
        recorder_statuses: ifRead(recorderStatuses, statusList.map((status) => ({ name: status.name, recording: status.recording ?? null, last_status: status.lastStatus ?? null }))),
      },
    ),
  ];

  return {
    title: "AWS logging and detection posture",
    summary: {
      trails: ifRead(trailList, trailDetails.length),
      compliant_trails: trailStatusAllUnreadable ? null : ifRead(trailList, goodTrails.length),
      security_hub_enabled: ifRead(hub, Boolean(hub.value)),
      security_hub_standards: ifRead(standards, standardList.length),
      guardduty_detectors: ifRead(detectorIds, detectorList.length),
      enabled_guardduty_detectors: detectorsAllUnreadable ? null : ifRead(detectorIds, enabledDetectors.length),
      config_recorders: ifRead(recorders, recorderList.length),
      recording_config_recorders: recorders.error || recorderStatuses.error ? null : recordingRecorders.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
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
  const [organization, analyzers, identityCenterInstances, auditAssessments, securityContact] = await Promise.all([
    attemptAwsRead("organizations:DescribeOrganization", () => client.describeOrganization(), errors),
    attemptAwsRead("access-analyzer:ListAnalyzers", () => client.listAnalyzers(), errors),
    attemptAwsRead("sso:ListInstances", () => client.listIdentityCenterInstances(), errors),
    attemptAwsRead("auditmanager:ListAssessments status=ACTIVE", () => client.listActiveAuditManagerAssessments(), errors),
    attemptAwsRead("account:GetAlternateContact SECURITY", () => client.getSecurityAlternateContact(), errors),
  ]);
  // A standalone account (DescribeOrganization returned AWSOrganizationsNotInUseException) has no accounts or SCPs to
  // list; when the describe was denied the lists are still attempted because they are governed by separate IAM actions.
  const standalone = !organization.error && organization.value === null;
  const [accounts, scps] = standalone
    ? [undefined, undefined]
    : await Promise.all([
        attemptAwsRead("organizations:ListAccounts", () => client.listAccounts(), errors),
        attemptAwsRead("organizations:ListPolicies Filter=SERVICE_CONTROL_POLICY", () => client.listScps(), errors),
      ]);

  const accountList = accounts?.value?.items ?? [];
  const scpList = scps?.value?.items ?? [];
  const scpTargets = await mapWithConcurrency(scpList, DEFAULT_CONCURRENCY, async (policy) => {
    const policyId = asString(policy.Id) ?? "";
    const name = asString(policy.Name) ?? (policyId || "policy");
    return {
      policyId,
      name,
      targets: await attemptAwsRead(`organizations:ListTargetsForPolicy ${name}`, () => client.listPolicyTargets(policyId), errors),
    };
  });
  const attachedScps = scpTargets.filter((policy) => (policy.targets.value?.items.length ?? 0) > 0);
  const unreadableScps = scpTargets.filter((policy) => policy.targets.error);
  const truncatedScpTargets = scpTargets.filter((policy) => policy.targets.value?.truncated);
  // The attached count is unknown, not zero, when no SCP's target list could be read.
  const scpTargetsAllUnreadable = scpTargets.length > 0 && unreadableScps.length === scpTargets.length;

  const analyzerList = analyzers.value?.items ?? [];
  const activeAnalyzers = analyzerList.filter((analyzer) => asString(analyzer.status) === "ACTIVE");
  const findingLists = await mapWithConcurrency(activeAnalyzers, DEFAULT_CONCURRENCY, async (analyzer) => {
    const analyzerArn = asString(analyzer.arn) ?? "";
    const name = asString(analyzer.name) ?? analyzerArn;
    return {
      analyzerArn,
      name,
      findings: await attemptAwsRead(`access-analyzer:ListFindings ${name}`, () => client.listAccessAnalyzerFindings(analyzerArn, maxFindings), errors),
    };
  });
  const readableFindingLists = findingLists.filter((item) => !item.findings.error);
  const unreadableFindingLists = findingLists.filter((item) => item.findings.error);
  const truncatedFindingLists = findingLists.filter((item) => item.findings.value?.truncated);
  const findingListsAllUnreadable = findingLists.length > 0 && unreadableFindingLists.length === findingLists.length;
  const activeExternalFindings: JsonRecord[] = readableFindingLists
    .flatMap((item) => (item.findings.value?.items ?? []).map((entry): JsonRecord => ({ ...entry, analyzer: item.name })))
    .filter((entry) => {
      const status = asString(entry.status)?.toUpperCase();
      return !status || status === "ACTIVE";
    });
  const identityCenterList = identityCenterInstances.value?.items ?? [];

  // Control 16 (visibility): the organization itself plus its member account list.
  const organizationId = asString(organization.value?.Id) ?? "unknown";
  let orgStatus: AwsFinding["status"];
  let orgSummary: string;
  if (organization.error) {
    orgStatus = "manual";
    orgSummary = `AWS Organizations could not be described (${organization.error}); verify organization membership and guardrails in the Organizations console.`;
  } else if (standalone) {
    orgStatus = "warn";
    orgSummary = "AWS Organizations is not in use for this account (DescribeOrganization returned AWSOrganizationsNotInUseException); it is a standalone account without organization guardrails.";
  } else if (accounts?.error) {
    orgStatus = "pass";
    orgSummary = `AWS Organizations ${organizationId} is visible, but its member accounts could not be listed.`;
  } else {
    orgStatus = "pass";
    orgSummary = `AWS Organizations ${organizationId} is visible with ${accountList.length} account(s).`;
  }
  const orgCaps: string[] = [];
  if (accounts?.error) orgCaps.push(`member accounts unreadable (${accounts.error})`);
  if (accounts?.value?.truncated) orgCaps.push(`account list truncated at ${DEFAULT_ACCOUNT_LIMIT}`);
  const orgVerdict = withCap(orgStatus, orgSummary, orgCaps);

  // Control 16 (enforcement): SCPs attached to at least one root, OU, or account.
  let scpStatus: AwsFinding["status"];
  let scpSummary: string;
  if (standalone) {
    scpStatus = "warn";
    scpSummary = "The account is not part of an AWS Organization, so no service control policy applies to it; record the control as not applicable or bring the account under an organization with SCPs.";
  } else if (scps?.error) {
    scpStatus = "manual";
    scpSummary = `Service control policies could not be listed (${scps.error}); verify SCP attachments in the Organizations console.`;
  } else if (scpList.length === 0) {
    scpStatus = "warn";
    scpSummary = "No service control policies exist in the organization.";
  } else if (attachedScps.length > 0) {
    scpStatus = "pass";
    scpSummary = `${attachedScps.length}/${scpList.length} SCPs are attached to at least one root, OU, or account.`;
  } else if (unreadableScps.length > 0) {
    scpStatus = "manual";
    scpSummary = `${scpList.length} SCP(s) exist, but targets could not be read for ${unreadableScps.length} of them (${unreadableScps[0].targets.error}); attachment is unverified.`;
  } else {
    scpStatus = "fail";
    scpSummary = `${scpList.length} SCP(s) exist but none is attached to a root, OU, or account.`;
  }
  const scpCaps: string[] = [];
  if (unreadableScps.length > 0) scpCaps.push(`ListTargetsForPolicy unreadable for ${unreadableScps.length} SCP(s) (${unreadableScps.map((policy) => policy.name).join(", ")})`);
  if (scps?.value?.truncated) scpCaps.push(`SCP list truncated at ${DEFAULT_POLICY_LIMIT}`);
  if (truncatedScpTargets.length > 0) scpCaps.push(`target list truncated for ${truncatedScpTargets.length} SCP(s)`);
  const scpVerdict = withCap(scpStatus, scpSummary, scpCaps);

  // Control 15 (enablement): an analyzer with status ACTIVE.
  let analyzerStatus: AwsFinding["status"];
  let analyzerSummary: string;
  if (analyzers.error) {
    analyzerStatus = "manual";
    analyzerSummary = `IAM Access Analyzer analyzers could not be listed (${analyzers.error}); verify analyzer enablement in the IAM Access Analyzer console.`;
  } else if (activeAnalyzers.length > 0) {
    analyzerStatus = "pass";
    analyzerSummary = `${activeAnalyzers.length} of ${analyzerList.length} Access Analyzer instance(s) are ACTIVE.`;
  } else {
    analyzerStatus = "fail";
    analyzerSummary = `No active IAM Access Analyzer instance was detected (${analyzerList.length} analyzer(s) visible, none ACTIVE).`;
  }
  const analyzerCaps: string[] = [];
  if (analyzers.value?.truncated) analyzerCaps.push(`analyzer list truncated at ${DEFAULT_ANALYZER_LIMIT}`);
  const analyzerVerdict = withCap(analyzerStatus, analyzerSummary, analyzerCaps);

  // Control 15 (findings): active external-access findings across every readable ACTIVE analyzer.
  let externalStatus: AwsFinding["status"];
  let externalSummary: string;
  if (analyzers.error) {
    externalStatus = "manual";
    externalSummary = `IAM Access Analyzer analyzers could not be listed (${analyzers.error}), so external access findings could not be sampled; review findings in the IAM Access Analyzer console.`;
  } else if (activeAnalyzers.length === 0) {
    externalStatus = "manual";
    externalSummary = "No ACTIVE Access Analyzer instance was available to sample (see AWS-ORG-03), so external access findings could not be read; enable an analyzer or review cross-account access manually.";
  } else if (readableFindingLists.length === 0) {
    externalStatus = "manual";
    externalSummary = `Findings could not be read for any of the ${activeAnalyzers.length} active analyzer(s) (${unreadableFindingLists[0]?.findings.error ?? "unknown error"}); review findings in the IAM Access Analyzer console.`;
  } else if (activeExternalFindings.length > 0) {
    externalStatus = "warn";
    externalSummary = `${activeExternalFindings.length} active Access Analyzer finding(s) across ${readableFindingLists.length} analyzer(s) indicate external or cross-account access to review.`;
  } else {
    externalStatus = "pass";
    externalSummary = `No active Access Analyzer findings were visible in the ${readableFindingLists.length} sampled analyzer(s).`;
  }
  const externalCaps: string[] = [];
  if (unreadableFindingLists.length > 0) externalCaps.push(`ListFindings unreadable for ${unreadableFindingLists.length} analyzer(s) (${unreadableFindingLists.map((item) => item.name).join(", ")})`);
  if (truncatedFindingLists.length > 0) externalCaps.push(`findings truncated at ${maxFindings} for ${truncatedFindingLists.map((item) => item.name).join(", ")}`);
  const externalVerdict = withCap(externalStatus, externalSummary, externalCaps);

  // Control 23: an IAM Identity Center instance visible from the configured region.
  let identityCenterStatus: AwsFinding["status"];
  let identityCenterSummary: string;
  if (identityCenterInstances.error) {
    identityCenterStatus = "manual";
    identityCenterSummary = `IAM Identity Center instances could not be listed (${identityCenterInstances.error}); verify in the IAM Identity Center console.`;
  } else if (identityCenterList.length > 0) {
    identityCenterStatus = "pass";
    identityCenterSummary = `${identityCenterList.length} IAM Identity Center instance(s) were visible.`;
  } else {
    identityCenterStatus = "warn";
    identityCenterSummary = "No IAM Identity Center instance was visible from the configured region and credentials.";
  }
  const identityCenterCaps: string[] = [];
  if (identityCenterInstances.value?.truncated) identityCenterCaps.push(`instance list truncated at ${DEFAULT_ANALYZER_LIMIT}`);
  const identityCenterVerdict = withCap(identityCenterStatus, identityCenterSummary, identityCenterCaps);

  const findings = [
    finding(
      "AWS-ORG-01",
      "Organizations visibility",
      "medium",
      orgVerdict.status,
      orgVerdict.summary,
      ["FedRAMP PM-2", "SOC 2 CC2.1", "CIS AWS 1.1"],
      {
        organization_readable: !organization.error,
        standalone: ifRead(organization, standalone),
        organization: ifRead(organization, organization.value ?? null),
        accounts_readable: accounts ? !accounts.error : null,
        accounts: ifRead(accounts, accountList.length),
        account_list_truncated: truncatedFlag(accounts),
      },
    ),
    finding(
      "AWS-ORG-02",
      "Service control policies",
      "high",
      scpVerdict.status,
      scpVerdict.summary,
      ["FedRAMP AC-3", "FedRAMP CM-7", "SOC 2 CC6.8", "CIS AWS 1.20"],
      {
        scps_readable: scps ? !scps.error : null,
        scp_count: ifRead(scps, scpList.length),
        attached_scp_count: scpTargetsAllUnreadable ? null : ifRead(scps, attachedScps.length),
        scps_targets_unreadable: ifRead(scps, unreadableScps.map((policy) => policy.name)),
        scp_list_truncated: truncatedFlag(scps),
        sample: scpTargetsAllUnreadable ? null : ifRead(scps, attachedScps.slice(0, 20).map((policy) => ({ policyId: policy.policyId, name: policy.name, targets: policy.targets.value?.items ?? [] }))),
      },
    ),
    finding(
      "AWS-ORG-03",
      "Access Analyzer enablement",
      "high",
      analyzerVerdict.status,
      analyzerVerdict.summary,
      ["FedRAMP AC-3", "FedRAMP AC-6", "SOC 2 CC6.3", "CIS AWS 1.16"],
      { analyzers_readable: !analyzers.error, analyzers: ifRead(analyzers, analyzerList), analyzer_list_truncated: truncatedFlag(analyzers) },
    ),
    finding(
      "AWS-ORG-04",
      "External access findings",
      activeExternalFindings.length > 0 ? "high" : "low",
      externalVerdict.status,
      externalVerdict.summary,
      ["FedRAMP AC-3", "FedRAMP AC-4", "SOC 2 CC6.6", "CIS AWS 1.16"],
      {
        analyzers_readable: !analyzers.error,
        analyzers_sampled: findingListsAllUnreadable ? null : ifRead(analyzers, readableFindingLists.map((item) => item.name)),
        analyzers_findings_unreadable: ifRead(analyzers, unreadableFindingLists.map((item) => item.name)),
        analyzers_findings_truncated: ifRead(analyzers, truncatedFindingLists.map((item) => item.name)),
        active_finding_count: !analyzers.error && readableFindingLists.length > 0 ? activeExternalFindings.length : null,
        sample: ifRead(analyzers, activeExternalFindings.slice(0, 20)),
      },
    ),
    finding(
      "AWS-ORG-05",
      "Identity Center visibility",
      "low",
      identityCenterVerdict.status,
      identityCenterVerdict.summary,
      ["FedRAMP AC-2", "FedRAMP IA-2", "SOC 2 CC6.2", "PCI-DSS 8.4.2"],
      {
        instances_readable: !identityCenterInstances.error,
        identity_center_instances: ifRead(identityCenterInstances, identityCenterList.length),
        instance_list_truncated: truncatedFlag(identityCenterInstances),
      },
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
      assessments_readable: !auditAssessments.error,
      active_assessments: ifRead(auditAssessments, activeAssessments.length),
      assessments: ifRead(auditAssessments, sample(activeAssessments.map((assessment) => ({ name: assessment.name, compliance_type: assessment.complianceType, last_updated: assessment.lastUpdated ?? null })))),
      list_truncated: truncatedFlag(auditAssessments),
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
      contact_readable: !securityContact.error,
      security_contact_configured: ifRead(securityContact, contact !== undefined),
      has_name: ifRead(securityContact, Boolean(asString(contact?.Name))),
      has_title: ifRead(securityContact, Boolean(asString(contact?.Title))),
      email_domain: contactEmail?.includes("@") ? contactEmail.slice(contactEmail.indexOf("@")) : null,
      has_phone: ifRead(securityContact, Boolean(contactPhone)),
      billing_and_operations_contacts: "not assessed",
    },
  ));

  return {
    title: "AWS organization guardrails",
    summary: {
      organization_visible: ifRead(organization, Boolean(organization.value)),
      accounts: ifRead(accounts, accountList.length),
      scps: ifRead(scps, scpList.length),
      attached_scps: scpTargetsAllUnreadable ? null : ifRead(scps, attachedScps.length),
      analyzers: ifRead(analyzers, analyzerList.length),
      active_analyzers: ifRead(analyzers, activeAnalyzers.length),
      active_external_findings: !analyzers.error && readableFindingLists.length > 0 ? activeExternalFindings.length : null,
      identity_center_instances: ifRead(identityCenterInstances, identityCenterList.length),
      audit_manager_active_assessments: ifRead(auditAssessments, activeAssessments.length),
      security_contact_configured: ifRead(securityContact, contact !== undefined),
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
    scope_error: scope.error ?? null,
  };
}

/** Cap reason for a partial region scope; names the DescribeRegions failure when the scope fell back to one region. */
function scopeCap(scope: AwsRegionScope): string | undefined {
  if (!scope.partial) return undefined;
  if (scope.source === "configured-region-fallback") {
    return `only ${scope.regions[0]} was assessed because the enabled-region list could not be read (${scope.error})`;
  }
  return `only ${scope.regionsSeen} of ${scope.regionsTotal} regions assessed`;
}

function regionList(results: Array<{ region: string }>): string {
  return results.map((result) => result.region).join(", ");
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
  const accountBlockRead = !accountBlock.error;
  const accountFlags = publicAccessFlags(accountBlock.value ?? undefined);
  const accountConfigured = accountBlockRead && accountBlock.value !== null && accountBlock.value !== undefined;
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
  // Bucket-level fact only: which readable buckets do not block public access on their own.
  const bucketsWithoutOwnBlock = publicAccessRows.filter((row) => !row.bucket_full && !row.unreadable);
  // Coverage claim: a bucket is uncovered only when the account block is known not to cover it, so the list is
  // withheld (null) while the account-level read failed rather than naming every bucket that relies on it.
  const uncoveredBuckets = accountBlockRead ? bucketsWithoutOwnBlock.filter(() => !accountFull) : null;
  const unreadablePublicAccessBuckets = publicAccessRows.filter((row) => row.unreadable);
  const flagText = REQUIRED_PUBLIC_ACCESS_FLAGS.map((key) => `${key}=${accountFlags[key] ?? "unset"}`).join(", ");

  let publicAccessStatus: AwsFinding["status"];
  let publicAccessSummary: string;
  if (accountBlock.error) {
    publicAccessStatus = "manual";
    const bucketFact = bucketList.error
      ? `The bucket inventory could not be read either (${bucketList.error}).`
      : `${bucketsWithoutOwnBlock.length} of ${buckets.length} buckets do not block public access at the bucket level; whether the account block covers them is unknown.`;
    publicAccessSummary = `Account-level S3 Block Public Access could not be read (${accountBlock.error}). ${bucketFact} Capture the S3 console Block Public Access settings for account ${accountId ?? "unknown"} manually.`;
  } else if (bucketList.error) {
    publicAccessStatus = "manual";
    publicAccessSummary = `Account-level flags: ${flagText}. The bucket inventory could not be read (${bucketList.error}), so bucket-level exposure is unverified.`;
  } else if (!accountConfigured) {
    publicAccessStatus = "fail";
    publicAccessSummary = `Account-level S3 Block Public Access is not configured (S3 Control returned NoSuchPublicAccessBlockConfiguration); ${uncoveredBuckets?.length ?? 0}/${buckets.length} buckets lack a full bucket-level block and ${publicPolicyBuckets.length} have public bucket policies.`;
  } else if (!accountFull) {
    if ((uncoveredBuckets?.length ?? 0) > 0 || publicPolicyBuckets.length > 0) {
      publicAccessStatus = "fail";
      publicAccessSummary = `Account-level Block Public Access is incomplete (${flagText}); ${uncoveredBuckets?.length ?? 0}/${buckets.length} buckets lack a full bucket-level block and ${publicPolicyBuckets.length} have public bucket policies.`;
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
  if (unreadablePublicAccessBuckets.length > 0) publicAccessCaps.push(`${unreadablePublicAccessBuckets.length} bucket(s) could not be read (s3:GetPublicAccessBlock or s3:GetBucketPolicyStatus)`);
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
  const ebsAllUnknown = ebsRows.length > 0 && ebsUnknown.length === ebsRows.length;
  const rdsInstances: Array<JsonRecord & { region: string }> = regionResults.flatMap((result) =>
    (result.rds.value?.items ?? []).map((instance) => ({ ...instance, region: result.region })),
  );
  const rdsUnencrypted = rdsInstances.filter((instance) => instance.StorageEncrypted === false);
  const rdsUnknown = rdsInstances.filter((instance) => typeof instance.StorageEncrypted !== "boolean");
  const rdsErrors = regionResults.filter((result) => result.rds.error);
  const rdsAllFailed = regionResults.length > 0 && rdsErrors.length === regionResults.length;
  const rdsTruncated = regionResults.filter((result) => result.rds.value?.truncated === true);
  const bucketsWithoutSse = bucketDetails.filter((bucket) => {
    if (bucket.encryption.error) return false;
    const rules = Array.isArray(bucket.encryption.value?.Rules) ? bucket.encryption.value.Rules : [];
    return bucket.encryption.value === null || rules.length === 0 || rules.every((rule) => !asString(asObject(rule)?.SSEAlgorithm));
  });
  const bucketEncryptionUnreadable = bucketDetails.filter((bucket) => bucket.encryption.error);
  // The RDS clause is worded from what was read: an inventory that could not be listed anywhere is not "all 0 instances",
  // and an instance that did not report StorageEncrypted is never counted among those that reported it true (round 4 item B).
  const rdsReadableRegions = regionResults.length - rdsErrors.length;
  const rdsEncrypted = rdsInstances.length - rdsUnencrypted.length - rdsUnknown.length;
  const rdsClause = rdsAllFailed
    ? `RDS instances could not be listed in any of ${regionResults.length} region(s) (${rdsErrors[0]?.rds.error ?? "rds:DescribeDBInstances failed"})`
    : rdsUnencrypted.length > 0
      ? `${rdsUnencrypted.length}/${rdsInstances.length} RDS instances have StorageEncrypted=false`
      : rdsInstances.length === 0
        ? `no RDS instances exist in the ${rdsReadableRegions} readable region(s)`
        : rdsUnknown.length === 0
          ? `all ${rdsInstances.length} RDS instances in the ${rdsReadableRegions} readable region(s) report StorageEncrypted=true`
          : `${rdsEncrypted} of ${rdsInstances.length} RDS instances in the ${rdsReadableRegions} readable region(s) report StorageEncrypted=true; ${rdsUnknown.length} did not report the flag`;

  let encryptionStatus: AwsFinding["status"];
  let encryptionSummary: string;
  if (ebsRows.length > 0 && ebsUnknown.length === ebsRows.length) {
    encryptionStatus = "manual";
    encryptionSummary = `EBS default encryption could not be read in any of ${ebsRows.length} region(s) (${ebsRows[0].error ?? "flag missing"}); verify EBS, S3, and RDS encryption defaults in the console.`;
  } else if (bucketList.error) {
    encryptionStatus = "manual";
    encryptionSummary = `EBS default encryption is disabled in ${ebsOff.length}/${ebsRows.length} region(s) and ${rdsClause}, but the S3 bucket inventory could not be read (${bucketList.error}).`;
  } else if (ebsOff.length > 0 || rdsUnencrypted.length > 0 || bucketsWithoutSse.length > 0) {
    encryptionStatus = "fail";
    encryptionSummary = `EBS default encryption disabled in ${ebsOff.length}/${ebsRows.length} region(s); ${bucketsWithoutSse.length}/${buckets.length} buckets lack default server-side encryption; ${rdsClause}.`;
  } else {
    encryptionStatus = "pass";
    encryptionSummary = `EBS encryption by default is enabled in all ${ebsRows.length - ebsUnknown.length} readable region(s), all ${buckets.length} buckets have default server-side encryption, and ${rdsClause}. EFS is not assessed by this check.`;
  }
  const encryptionCaps: string[] = [];
  const scopeReason = scopeCap(scope);
  if (ebsUnknown.length > 0) encryptionCaps.push(`ec2:GetEbsEncryptionByDefault unreadable in ${ebsUnknown.length} region(s) (${regionList(ebsUnknown)})`);
  if (rdsErrors.length > 0) encryptionCaps.push(`rds:DescribeDBInstances unreadable in ${rdsErrors.length} region(s) (${regionList(rdsErrors)})`);
  if (rdsUnknown.length > 0) encryptionCaps.push(`${rdsUnknown.length} RDS instance(s) without a StorageEncrypted flag`);
  if (rdsTruncated.length > 0) encryptionCaps.push(`RDS inventory truncated in ${rdsTruncated.length} region(s) (${regionList(rdsTruncated)})`);
  if (bucketEncryptionUnreadable.length > 0) encryptionCaps.push(`s3:GetBucketEncryption unreadable for ${bucketEncryptionUnreadable.length} bucket(s)`);
  if (bucketsTruncated) encryptionCaps.push(`bucket inventory truncated at ${bucketLimit}`);
  if (scopeReason) encryptionCaps.push(scopeReason);
  const encryptionVerdict = withCap(encryptionStatus, encryptionSummary, encryptionCaps);

  // Control 13: TLS-only bucket policies (aws:SecureTransport deny). GetBucketPolicy returns plain JSON, not URL-encoded.
  const transitRows = bucketDetails.map((bucket) => {
    const statements = bucket.policy.value ? normalizeStatements(bucket.policy.value, "plain-json") : [];
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
  if (transitUnreadable.length > 0) transitCaps.push(`s3:GetBucketPolicy unreadable for ${transitUnreadable.length} bucket polic${transitUnreadable.length === 1 ? "y" : "ies"}`);
  if (bucketsTruncated) transitCaps.push(`bucket inventory truncated at ${bucketLimit}`);
  const transitVerdict = withCap(transitStatus, transitSummary, transitCaps);

  // Control 22: customer-managed KMS key rotation.
  const keyRows = regionResults.flatMap((result) => result.keys);
  const kmsListErrors = regionResults.filter((result) => result.kmsKeys.error);
  const kmsListsAllFailed = regionResults.length > 0 && kmsListErrors.length === regionResults.length;
  const customerKeys = keyRows.filter((key) => key.manager === "CUSTOMER");
  const managerUnknown = keyRows.filter((key) => key.manager === undefined);
  // Key classification counts are unknown, not zero, when DescribeKey failed for every listed key.
  const keyMetadataUnknown = kmsListsAllFailed || (keyRows.length > 0 && managerUnknown.length === keyRows.length);
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
  } else if (customerKeys.length === 0) {
    kmsStatus = "manual";
    kmsSummary = `No customer-managed KMS key could be confirmed: KeyManager could not be read for ${managerUnknown.length} of ${keyRows.length} key(s) (${managerUnknown[0]?.metadata.error ?? "kms:DescribeKey returned no KeyManager"}); verify customer-managed key rotation in the KMS console.`;
  } else if (eligibleKeys.length === 0) {
    kmsStatus = "warn";
    kmsSummary = `${customerKeys.length} customer-managed key(s) exist but none is an enabled symmetric AWS_KMS-origin key, so automatic rotation cannot apply; verify manual rotation for asymmetric, HMAC, imported, or disabled keys.`;
  } else {
    kmsStatus = "pass";
    kmsSummary = `All ${eligibleKeys.length} enabled symmetric customer-managed keys report KeyRotationEnabled=true across ${scope.regionsSeen} region(s); ${ineligibleCustomerKeys.length} customer key(s) are out of scope for automatic rotation.`;
  }
  const kmsCaps: string[] = [];
  if (rotationUnknown.length > 0) kmsCaps.push(`kms:GetKeyRotationStatus unreadable for ${rotationUnknown.length} key(s)`);
  if (managerUnknown.length > 0) kmsCaps.push(`kms:DescribeKey returned no readable KeyManager for ${managerUnknown.length} key(s)`);
  if (kmsListErrors.length > 0) kmsCaps.push(`kms:ListKeys unreadable in ${kmsListErrors.length} region(s) (${regionList(kmsListErrors)})`);
  if (kmsTruncated.length > 0) kmsCaps.push(`key inventory truncated in ${kmsTruncated.length} region(s) (${regionList(kmsTruncated)})`);
  if (scopeReason) kmsCaps.push(scopeReason);
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
        account_block_readable: accountBlockRead,
        account_block_configured: ifRead(accountBlock, accountConfigured),
        account_flags: accountBlockRead ? accountFlags : notCollectedMarker("s3control:GetPublicAccessBlock", accountBlock),
        buckets_readable: !bucketList.error,
        buckets: ifRead(bucketList, buckets.length),
        buckets_without_full_block: bucketList.error || uncoveredBuckets === null ? null : sample(uncoveredBuckets.map((row) => ({ name: row.name, flags: row.flags }))),
        buckets_without_bucket_level_block: ifRead(bucketList, sample(bucketsWithoutOwnBlock.map((row) => ({ name: row.name, flags: row.flags })))),
        buckets_with_public_policy: ifRead(bucketList, sample(publicPolicyBuckets.map((row) => row.name))),
        buckets_unreadable: ifRead(bucketList, sample(unreadablePublicAccessBuckets.map((row) => row.name))),
        bucket_inventory_truncated: truncatedFlag(bucketList),
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
        ebs_by_region: ebsRows.map((row) => ({ region: row.region, EbsEncryptionByDefault: row.EbsEncryptionByDefault ?? null, error: row.error ?? null })),
        rds_instances: rdsAllFailed ? null : rdsInstances.length,
        rds_unencrypted: rdsAllFailed ? null : sample(rdsUnencrypted.map((instance) => ({ region: instance.region, id: instance.DBInstanceIdentifier, engine: instance.Engine }))),
        rds_without_flag: rdsAllFailed ? null : sample(rdsUnknown.map((instance) => instance.DBInstanceIdentifier)),
        regions_with_rds_errors: rdsErrors.map((result) => result.region),
        buckets_readable: !bucketList.error,
        buckets: ifRead(bucketList, buckets.length),
        buckets_without_default_encryption: ifRead(bucketList, sample(bucketsWithoutSse.map((bucket) => bucket.name))),
        buckets_encryption_unreadable: ifRead(bucketList, sample(bucketEncryptionUnreadable.map((bucket) => bucket.name))),
        bucket_inventory_truncated: truncatedFlag(bucketList),
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
        buckets_readable: !bucketList.error,
        buckets: ifRead(bucketList, buckets.length),
        buckets_without_tls_deny: ifRead(bucketList, sample(transitMissing.map((row) => ({ name: row.name, has_policy: row.has_policy })))),
        buckets_policy_unreadable: ifRead(bucketList, sample(transitUnreadable.map((row) => row.name))),
        bucket_inventory_truncated: truncatedFlag(bucketList),
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
        keys: kmsListsAllFailed ? null : keyRows.length,
        customer_managed_keys: keyMetadataUnknown ? null : customerKeys.length,
        eligible_keys: keyMetadataUnknown ? null : eligibleKeys.length,
        keys_not_rotating: kmsListsAllFailed ? null : sample(notRotating.map((key) => ({ region: key.region, key_id: key.keyId }))),
        keys_rotation_unreadable: kmsListsAllFailed ? null : sample(rotationUnknown.map((key) => ({ region: key.region, key_id: key.keyId }))),
        keys_manager_unreadable: kmsListsAllFailed ? null : sample(managerUnknown.map((key) => ({ region: key.region, key_id: key.keyId }))),
        ineligible_customer_keys: kmsListsAllFailed ? null : sample(ineligibleCustomerKeys.map((key) => ({
          region: key.region,
          key_id: key.keyId,
          key_state: key.metadata.value?.KeyState ?? null,
          key_spec: key.metadata.value?.KeySpec ?? null,
          origin: key.metadata.value?.Origin ?? null,
        }))),
        key_inventory_truncated: kmsListsAllFailed ? null : kmsTruncated.length > 0,
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
      buckets: ifRead(bucketList, buckets.length),
      buckets_without_full_block: bucketList.error || uncoveredBuckets === null ? null : uncoveredBuckets.length,
      buckets_without_bucket_level_block: ifRead(bucketList, bucketsWithoutOwnBlock.length),
      buckets_with_public_policy: ifRead(bucketList, publicPolicyBuckets.length),
      buckets_without_default_encryption: ifRead(bucketList, bucketsWithoutSse.length),
      buckets_without_tls_deny: ifRead(bucketList, transitMissing.length),
      ebs_regions_without_default_encryption: ebsAllUnknown ? null : ebsOff.length,
      rds_instances: rdsAllFailed ? null : rdsInstances.length,
      rds_unencrypted: rdsAllFailed ? null : rdsUnencrypted.length,
      customer_managed_keys: keyMetadataUnknown ? null : customerKeys.length,
      keys_not_rotating: kmsListsAllFailed ? null : notRotating.length,
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
  // With no readable flow log list anywhere, the count of VPCs lacking an active flow log is unknown, not zero.
  const flowLogsAllUnreadable = regionResults.length > 0 && regionResults.every((result) => result.flowLogs.error);
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
  const scopeReason = scopeCap(scope);
  if (vpcsUnverified.length > 0) {
    const reasons = [
      ...(flowLogRegionErrors.length > 0 ? [`ec2:DescribeFlowLogs unreadable in ${regionList(flowLogRegionErrors)}`] : []),
      ...(vpcRows.some((row) => row.active_flow_logs === 0 && row.status_unknown > 0) ? ["FlowLogStatus missing from some flow logs"] : []),
    ];
    flowLogCaps.push(`${vpcsUnverified.length} VPC(s) could not be verified (${reasons.join("; ")})`);
  }
  if (vpcRegionErrors.length > 0) flowLogCaps.push(`ec2:DescribeVpcs unreadable in ${vpcRegionErrors.length} region(s) (${regionList(vpcRegionErrors)})`);
  if (vpcTruncated.length > 0) flowLogCaps.push(`VPC or flow log inventory truncated in ${vpcTruncated.length} region(s) (${regionList(vpcTruncated)})`);
  if (scopeReason) flowLogCaps.push(scopeReason);
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
  if (aclRegionErrors.length > 0) aclCaps.push(`ec2:DescribeNetworkAcls unreadable in ${aclRegionErrors.length} region(s) (${regionList(aclRegionErrors)})`);
  if (aclTruncated.length > 0) aclCaps.push(`NACL inventory truncated in ${aclTruncated.length} region(s) (${regionList(aclTruncated)})`);
  if (scopeReason) aclCaps.push(scopeReason);
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
  if (groupRegionErrors.length > 0) groupCaps.push(`ec2:DescribeSecurityGroups unreadable in ${groupRegionErrors.length} region(s) (${regionList(groupRegionErrors)})`);
  if (groupTruncated.length > 0) groupCaps.push(`security group inventory truncated in ${groupTruncated.length} region(s) (${regionList(groupTruncated)})`);
  if (scopeReason) groupCaps.push(scopeReason);
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
        vpcs: vpcsAllUnreadable ? null : vpcRows.length,
        vpcs_without_active_flow_logs: vpcsAllUnreadable || flowLogsAllUnreadable ? null : sample(vpcsWithoutFlowLogs.map((row) => ({ region: row.region, vpc_id: row.vpc_id, is_default: row.is_default, flow_logs: row.flow_logs }))),
        vpcs_unverified: vpcsAllUnreadable ? null : sample(vpcsUnverified.map((row) => ({ region: row.region, vpc_id: row.vpc_id }))),
        inventory_truncated: vpcsAllUnreadable ? null : vpcTruncated.length > 0,
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
        network_acls: aclsAllUnreadable ? null : aclRows.length,
        permissive_network_acls: aclsAllUnreadable ? null : sample(permissiveAcls.map((row) => ({ region: row.region, network_acl_id: row.network_acl_id, vpc_id: row.vpc_id, is_default: row.is_default, entries: row.permissive_entries.slice(0, 5) }))),
        inventory_truncated: aclsAllUnreadable ? null : aclTruncated.length > 0,
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
        security_groups: groupsAllUnreadable ? null : groupRows.length,
        unrestricted_security_groups: groupsAllUnreadable ? null : sample(unrestrictedGroups.map((row) => ({ region: row.region, group_id: row.group_id, group_name: row.group_name, vpc_id: row.vpc_id, rules: row.unrestricted_rules.slice(0, 5) }))),
        inventory_truncated: groupsAllUnreadable ? null : groupTruncated.length > 0,
        regions_with_errors: groupRegionErrors.map((result) => result.region),
      },
    ),
  ];

  return {
    title: "AWS network security posture",
    summary: {
      regions_seen: scope.regionsSeen,
      regions_total: scope.regionsTotal,
      vpcs: vpcsAllUnreadable ? null : vpcRows.length,
      vpcs_without_active_flow_logs: vpcsAllUnreadable || flowLogsAllUnreadable ? null : vpcsWithoutFlowLogs.length,
      network_acls: aclsAllUnreadable ? null : aclRows.length,
      permissive_network_acls: aclsAllUnreadable ? null : permissiveAcls.length,
      security_groups: groupsAllUnreadable ? null : groupRows.length,
      unrestricted_security_groups: groupsAllUnreadable ? null : unrestrictedGroups.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: AwsAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.command,
    surface.status,
    surface.count === null ? "-" : `${surface.count}${surface.truncated ? "+" : ""}`,
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `AWS access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Command", "Status", "Count", "Note"], rows),
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
      "Validate read-only AWS audit access across IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, Organizations, Identity Center, EC2, S3, KMS, RDS, Audit Manager, and Account surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAwsAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "aws_check_access", ...result });
      } catch (error) {
        return errorResult(
          `AWS access check failed: ${errorMessage(error)}`,
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
          `AWS identity assessment failed: ${errorMessage(error)}`,
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
          `AWS logging and detection assessment failed: ${errorMessage(error)}`,
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
          `AWS organization guardrail assessment failed: ${errorMessage(error)}`,
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
          `AWS data protection assessment failed: ${errorMessage(error)}`,
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
          `AWS network security assessment failed: ${errorMessage(error)}`,
          { tool: "aws_assess_network_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_export_audit_bundle",
    label: "Export AWS audit bundle",
    description:
      "Export an AWS audit package with the access check, identity, logging and detection, organization guardrail, data protection, and network security findings, an executive summary, a unified compliance matrix, per-framework reports, JSON analysis, an error log when collection was partial, and a zip archive named after the bundle directory.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum IAM users to sample. Defaults to 500.", default: 500 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for keys and dormant users. Defaults to 90.", default: 90 })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum IAM roles to inspect. Defaults to 500.", default: 500 })),
      max_privileged_roles: Type.Optional(Type.Number({ description: "Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5.", default: 5 })),
      lookback_days: Type.Optional(Type.Number({ description: "Days of CloudTrail history to search for root activity (LookupEvents keeps 90 days). Defaults to 90.", default: 90 })),
      policy_limit: Type.Optional(Type.Number({ description: "Maximum customer-managed IAM policies to inspect before flagging truncation. Defaults to 1000.", default: 1000 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Access Analyzer findings to sample. Defaults to 200.", default: 200 })),
      ...dataProtectionParams,
      resource_limit: Type.Optional(Type.Number({ description: `Maximum VPCs, flow logs, NACLs, or security groups per region before flagging truncation. Defaults to ${DEFAULT_RESOURCE_LIMIT}.`, default: DEFAULT_RESOURCE_LIMIT })),
      sensitive_ports: Type.Optional(Type.String({ description: `Comma-separated ports treated as sensitive. Defaults to ${DEFAULT_SENSITIVE_PORTS.join(",")}.`, default: DEFAULT_SENSITIVE_PORTS.join(",") })),
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
            `Collection errors: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
          ].join("\n"),
          {
            tool: "aws_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `AWS audit bundle export failed: ${errorMessage(error)}`,
          { tool: "aws_export_audit_bundle" },
        );
      }
    },
  });
}

/** The IncompleteResponse error the shape guard throws for a command, produced by the guard itself. */
function incompleteResponseError(command: string, observed: ObservedResponse, members: JsonRecord = {}): AwsApiError {
  try {
    assertOutputShape({ constructor: { name: `${command}Command` } }, { $metadata: { httpStatusCode: observed.statusCode }, ...members }, observed);
  } catch (error) {
    if (error instanceof AwsApiError) return error;
  }
  throw new Error(`the shape guard did not refuse ${command}`);
}

/**
 * Every fixed-text message this integration emits around a refused, failed, or unparseable read, rendered
 * with representative observed values by the same constants, error classes, and helpers the error sink uses
 * (GWS note 1). Each must survive redactErrorText unchanged, since every recorded string passes through it;
 * the fixed-text test holds this list to the scrub, and a message that does not survive is reworded rather
 * than exempted. AwsCredentialProviderError names the shared files from the environment at render time.
 */
export function awsFixedTexts(): readonly string[] {
  const html = "<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>";
  const maskedKey = maskAccessKeyId("AKIAEXAMPLE000000001");
  const denied = { name: "AccessDeniedException", message: "User is not authorized to perform this operation", $metadata: { httpStatusCode: 403 } };
  const noSuchEntity = { name: "NoSuchEntity", message: `The Access Key with id ${maskedKey} cannot be found.`, $metadata: { httpStatusCode: 404 } };
  const noBucketPolicy = { name: "NoSuchBucketPolicy", message: "The bucket policy does not exist", $metadata: { httpStatusCode: 404 } };
  const htmlPage = { name: "SyntaxError", $metadata: { httpStatusCode: 502 }, $bodyNote: `non-JSON body (text/html, ${Buffer.byteLength(html, "utf8")} bytes)` };
  const timeout = { name: "TimeoutError", message: "Request did not complete within 10000 ms" };
  const deniedError = new AwsApiError(denied);
  const notFoundError = new AwsApiError(noSuchEntity);
  const emptyBody = incompleteResponseError("ListUsers", { statusCode: 200, bodyBytes: 0 });
  const htmlBody = incompleteResponseError("GetCallerIdentity", { statusCode: 200, contentType: "text/html", bodyBytes: 512 });
  const missingMember = incompleteResponseError("DescribeVpcs", { statusCode: 200, contentType: "text/xml", bodyBytes: 240 });
  const unobserved = incompleteResponseError("GetAccountSummary", {});
  const stringList = incompleteResponseError("DescribeTrails", { statusCode: 200, contentType: "application/x-amz-json-1.1", bodyBytes: 33 }, { trailList: "not a list" });
  const emptyStructure = incompleteResponseError("GetPublicAccessBlock", { statusCode: 200, contentType: "application/xml", bodyBytes: 214 }, { PublicAccessBlockConfiguration: {} });
  const textInList = incompleteResponseError("ListUsers", { statusCode: 200, contentType: "text/xml", bodyBytes: 240, body: "<ListUsersResponse><ListUsersResult><Users>text</Users></ListUsersResult></ListUsersResponse>" }, { Users: [] });
  const textInBoolean = incompleteResponseError("GetEbsEncryptionByDefault", { statusCode: 200, contentType: "text/xml", bodyBytes: 180, body: "<GetEbsEncryptionByDefaultResponse><ebsEncryptionByDefault>text</ebsEncryptionByDefault></GetEbsEncryptionByDefaultResponse>" }, { EbsEncryptionByDefault: false });
  const notPolicy = incompleteResponseError("GetBucketPolicy", { statusCode: 200, bodyBytes: 512 }, { Policy: "<html></html>" });
  const refusedByDeserializer = toAwsApiError(withObservedBody(
    Object.defineProperty(new TypeError("Expected boolean, got string: value"), "$response", { value: {} }),
    { statusCode: 200, contentType: "application/x-amz-json-1.1", bodyBytes: 33 },
    { constructor: { name: "GetTrailStatusCommand" } },
  ));
  return Object.freeze([
    PARSE_ERROR_NOTE,
    nonJsonBodyNote({ $responseBodyText: html, $response: { headers: { "content-type": "text/html; charset=utf-8" } } }) ?? "",
    nonJsonBodyNote({ message: '<?xml version="1.0" encoding="UTF-8"?><Error/>' }) ?? "",
    observedBodyNote({}),
    observedBodyNote({ bodyBytes: 0 }),
    observedBodyNote({ contentType: "text/html", bodyBytes: 512 }),
    observedBodyNote({ bodyBytes: 512 }),
    deniedError.message,
    notFoundError.message,
    new AwsApiError(noBucketPolicy).message,
    new AwsApiError(htmlPage).message,
    new AwsApiError(new SyntaxError("Unexpected token '<', \"<html>\" is not valid JSON")).message,
    new AwsApiError(timeout).message,
    new AwsApiError({ $metadata: { httpStatusCode: 403 } }).message,
    new AwsApiError({ name: "not a code", message: "rejected", $metadata: { httpStatusCode: 403 } }).message,
    UNKNOWN_ERROR_CODE,
    emptyBody.message,
    htmlBody.message,
    missingMember.message,
    unobserved.message,
    stringList.message,
    emptyStructure.message,
    textInList.message,
    textInBoolean.message,
    notPolicy.message,
    refusedByDeserializer.message,
    new AwsCredentialProviderError("fromIni (profile audit)", { name: "CredentialsProviderError", code: "ENOENT" }).message,
    new AwsCredentialProviderError("fromIni (profile audit)", { name: "CredentialsProviderError", code: "EISDIR" }).message,
    new AwsCredentialProviderError("fromNodeProviderChain (default credential chain)", new Error("Could not load credentials from any providers")).message,
    readFailureLine("iam:ListUsers", deniedError),
    readFailureLine(`iam:GetAccessKeyLastUsed ${maskedKey}`, notFoundError),
    readFailureLine("ec2:DescribeVpcs us-east-1", missingMember),
    readFailureLine("ec2:DescribeRegions us-east-1", deniedError),
    readFailureLine("s3:GetBucketPolicy cloudtrail-logs-123456789012-us-east-1", new AwsApiError(noBucketPolicy)),
    readFailureLine("organizations:ListAccounts", new AwsApiError(htmlPage)),
    readFailureLine("sts:GetCallerIdentity", new AwsApiError(timeout)),
    readFailureLine("iam:GetAccountSummary", unobserved),
    readFailureLine(`guardduty:GetDetector ${labelIdentifier("12abc34d567e8fa901bc2d34e56789f0")}`, deniedError),
    readFailureLine(`guardduty:GetDetector ${labelIdentifier("detector-1")}`, deniedError),
    `Region scope fell back to us-east-1 only: ${readFailureLine("ec2:DescribeRegions", deniedError)}`,
    "Region scope truncated to 1 of 17 regions by region_limit.",
    `only us-east-1 was assessed because the enabled-region list could not be read (${readFailureLine("ec2:DescribeRegions", deniedError)})`,
    "only 1 of 17 regions assessed",
    `Downgraded to warn: only 1 of 17 regions assessed; ${readFailureLine(`iam:GetAccessKeyLastUsed ${maskedKey}`, deniedError)}.`,
    `MFA devices could not be listed for any of the 3 sampled IAM users (${readFailureLine("iam:ListMFADevices svc-deploy", deniedError)}); review MFA coverage in the IAM credential report.`,
    `Access keys could not be listed for any of the 3 sampled IAM users (${readFailureLine("iam:ListAccessKeys svc-deploy", deniedError)}); review key age in the IAM credential report.`,
    `Last-used dates could not be read for any of the 2 sampled access key(s) (${readFailureLine(`iam:GetAccessKeyLastUsed ${maskedKey}`, deniedError)}); no key was judged. Review key age and last use in the IAM credential report.`,
    `member accounts unreadable (${readFailureLine("organizations:ListAccounts", deniedError)})`,
    `RDS instances could not be listed in any of 1 region(s) (${readFailureLine("rds:DescribeDBInstances us-east-1", deniedError)})`,
    `No customer-managed KMS key could be confirmed: KeyManager could not be read for 2 of 2 key(s) (${readFailureLine("kms:DescribeKey us-east-1", deniedError)}); verify customer-managed key rotation in the KMS console.`,
    "Current AWS account could not be determined.",
    "14/15 AWS audit surfaces are readable.",
    "Requested account hint 123456789012 does not match caller account 210987654321.",
    "Grant read-only access for the audit principal to the surfaces marked not_readable (iam, ec2); unreadable surfaces render manual findings, never pass.",
  ]);
}
