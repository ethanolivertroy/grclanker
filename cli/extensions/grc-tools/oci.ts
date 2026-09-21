/**
 * OCI GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the oci-sec-inspector spec.
 * Transport and auth stay aligned with the official OCI CLI (API-key profiles
 * from ~/.oci/config); assessment, normalization, and export logic are native.
 *
 * Every CLI command, flag, and output field read here is traceable to the
 * official OCI CLI command reference and the REST API reference:
 * - CLI: https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/
 * - REST: https://docs.oracle.com/en-us/iaas/api/ (spec index at /en-us/iaas/api/specs/index.json)
 * The per-surface citations live next to each client method below.
 */
import { execFileSync, type ExecFileSyncOptionsWithStringEncoding } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type OciCommandRunner = (args: string[]) => string;

const DEFAULT_REGION = "us-ashburn-1";
const DEFAULT_PROFILE = "DEFAULT";
const DEFAULT_OUTPUT_DIR = "./export/oci";
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_LOOKBACK_DAYS = 7;
const DEFAULT_MAX_KEYS = 200;
const DEFAULT_MAX_POLICIES = 500;
const DEFAULT_MAX_COMPARTMENTS = 25;
const DEFAULT_MAX_BUCKETS = 100;
const DEFAULT_COMMAND_TIMEOUT_MS = 15_000;
const DEFAULT_COMMAND_MAX_BUFFER_BYTES = 64 * 1024 * 1024;
const AUDIT_RETENTION_REQUIRED_DAYS = 365;
const KEY_ROTATION_MAX_DAYS = 365;
const BASTION_MAX_TTL_SECONDS = 10_800;
/**
 * KeyShape.length is documented in bytes (AES 16, 24, 32; RSA 256, 384, 512;
 * ECDSA 32, 48, 66). Spec control 19 requires AES-256 or RSA-4096, so the
 * floors are 32 and 512 bytes. ECDSA is not named by the control text, so any
 * documented curveId (NIST_P256, NIST_P384, NIST_P521, all FIPS 186-4 curves)
 * is accepted and a missing or undocumented curve is weak.
 */
const KEY_MIN_LENGTH_BYTES = { AES: 32, RSA: 512 } as const;
const ECDSA_ACCEPTED_CURVES = ["NIST_P256", "NIST_P384", "NIST_P521"] as const;
const ECDSA_RULE = "ECDSA keys pass on any documented KeyShape.curveId (NIST_P256, NIST_P384, NIST_P521); spec control 19 names only the AES-256 and RSA-4096 floors.";
const BASTION_SESSION_MAX_HOURS = 8;
const PAR_LONG_LIVED_DAYS = 30;
const SENSITIVE_PORTS = [22, 3389, 1433, 3306, 5432];

/**
 * Documentation anchors for every surface this module reads.
 * CLI pages are under the OCI CLI command reference; REST pages are under the
 * OCI API reference. Field names are taken from the REST datatypes.
 */
export const OCI_SURFACE_DOCS = {
  compartments: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/compartment/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Compartment/ListCompartments",
    fields: ["id", "compartmentId", "name", "lifecycleState"],
  },
  users: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/user/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/User/ListUsers",
    fields: ["id", "name", "lifecycleState", "isMfaActivated", "capabilities.canUseConsolePassword"],
  },
  authenticationPolicy: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/authentication-policy/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/PasswordPolicy",
    fields: [
      "passwordPolicy.minimumPasswordLength",
      "passwordPolicy.isLowercaseCharactersRequired",
      "passwordPolicy.isUppercaseCharactersRequired",
      "passwordPolicy.isNumericCharactersRequired",
      "passwordPolicy.isSpecialCharactersRequired",
    ],
  },
  apiKeys: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/user/api-key/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/ApiKey",
    fields: ["fingerprint", "timeCreated", "lifecycleState"],
  },
  customerSecretKeys: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/customer-secret-key/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/CustomerSecretKeySummary",
    fields: ["id", "timeCreated", "lifecycleState"],
  },
  authTokens: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/auth-token/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/AuthToken",
    fields: ["id", "timeCreated", "lifecycleState"],
  },
  policies: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/policy/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Policy/ListPolicies",
    fields: ["id", "name", "statements", "lifecycleState"],
  },
  availabilityDomains: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/availability-domain/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains",
    fields: ["name"],
  },
  auditConfiguration: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/audit/config/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/Configuration/GetConfiguration",
    fields: ["retentionPeriodDays"],
  },
  auditEvents: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/audit/event/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/AuditEvent/ListEvents",
    fields: ["eventId", "eventTime"],
  },
  cloudGuardConfiguration: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/cloud-guard/configuration/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/Configuration/GetConfiguration",
    fields: ["status", "reportingRegion"],
  },
  cloudGuardTargets: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/cloud-guard/target/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/TargetSummary/ListTargets",
    fields: ["id", "lifecycleState", "recipeCount"],
  },
  cloudGuardProblems: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/cloud-guard/problem/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ProblemSummary/ListProblems",
    fields: ["id", "lifecycleDetail", "lifecycleState", "riskLevel"],
  },
  responderRecipes: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/cloud-guard/responder-recipe/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ResponderRecipeSummary/ListResponderRecipes",
    fields: ["id", "lifecycleState", "responderRules[].details.isEnabled"],
  },
  eventRules: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/events/rule/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/events/20181201/RuleSummary/ListRules",
    fields: ["id", "displayName", "condition", "isEnabled", "lifecycleState"],
  },
  securityLists: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityList/ListSecurityLists",
    fields: ["id", "displayName", "lifecycleState", "ingressSecurityRules[].source", "ingressSecurityRules[].protocol", "ingressSecurityRules[].tcpOptions.destinationPortRange.min", "ingressSecurityRules[].tcpOptions.destinationPortRange.max"],
  },
  networkSecurityGroups: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/ListNetworkSecurityGroups",
    fields: ["id", "displayName", "lifecycleState"],
  },
  networkSecurityGroupRules: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/rules/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityRule/ListNetworkSecurityGroupSecurityRules",
    fields: ["id", "direction", "source", "protocol", "isValid", "tcpOptions.destinationPortRange.min", "tcpOptions.destinationPortRange.max"],
  },
  internetGateways: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/internet-gateway/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/InternetGateway/ListInternetGateways",
    fields: ["id", "displayName", "isEnabled", "lifecycleState", "vcnId"],
  },
  bastions: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/bastion/bastion/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/BastionSummary/ListBastions",
    fields: ["id", "name", "lifecycleState"],
  },
  bastionDetail: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/bastion/bastion/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/Bastion/GetBastion",
    fields: ["maxSessionTtlInSeconds", "clientCidrBlockAllowList"],
  },
  bastionSessions: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/bastion/session/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/SessionSummary/ListSessions",
    fields: ["id", "lifecycleState", "timeCreated", "sessionTtlInSeconds"],
  },
  vaults: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/vault/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/key/release/VaultSummary/ListVaults",
    fields: ["id", "displayName", "compartmentId", "lifecycleState", "managementEndpoint"],
  },
  keys: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/key/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeySummary/ListKeys",
    fields: ["id", "displayName", "algorithm", "lifecycleState", "protectionMode"],
  },
  keyDetail: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/key/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/key/release/Key/GetKey",
    fields: ["keyShape.algorithm", "keyShape.length", "keyShape.curveId", "lifecycleState"],
  },
  keyVersions: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/key-version/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeyVersionSummary/ListKeyVersions",
    fields: ["id", "lifecycleState", "timeCreated"],
  },
  objectStorageNamespace: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os/ns/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Namespace/GetNamespace",
    fields: ["data (namespace string)"],
  },
  buckets: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os/bucket/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/BucketSummary/ListBuckets",
    fields: ["name", "namespace", "compartmentId"],
  },
  bucketDetail: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os/bucket/get.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Bucket/GetBucket",
    fields: ["name", "publicAccessType"],
  },
  preauthenticatedRequests: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os/preauth-request/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/PreauthenticatedRequestSummary/ListPreauthenticatedRequests",
    fields: ["id", "name", "accessType", "timeExpires"],
  },
  instances: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/instance/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Instance/ListInstances",
    fields: ["id", "displayName", "lifecycleState", "instanceOptions.areLegacyImdsEndpointsDisabled"],
  },
  volumes: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/bv/volume/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Volume/ListVolumes",
    fields: ["id", "displayName", "lifecycleState", "kmsKeyId"],
  },
  bootVolumes: {
    cli: "https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/bv/boot-volume/list.html",
    rest: "https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/BootVolume/ListBootVolumes",
    fields: ["id", "displayName", "lifecycleState", "kmsKeyId"],
  },
} as const;

export interface OciResolvedConfig {
  configFile: string;
  profile: string;
  region: string;
  tenancyOcid: string;
  compartmentOcid: string;
  sourceChain: string[];
}

export interface OciAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface OciAccessCheckResult {
  status: "healthy" | "limited";
  tenancyOcid: string;
  compartmentOcid: string;
  surfaces: OciAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type OciFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface OciFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: OciFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface OciAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: OciFinding[];
  errors: string[];
}

export interface OciAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type CheckAccessArgs = {
  config_file?: string;
  profile?: string;
  region?: string;
  tenancy_ocid?: string;
  compartment_ocid?: string;
};

type ScopeArgs = CheckAccessArgs & {
  max_compartments?: number;
};

type IdentityArgs = ScopeArgs & {
  stale_days?: number;
  max_keys?: number;
  max_policies?: number;
};

type LoggingArgs = ScopeArgs & {
  lookback_days?: number;
};

type GuardrailArgs = ScopeArgs & {
  max_buckets?: number;
  max_keys?: number;
};

type ExportAuditBundleArgs = IdentityArgs & GuardrailArgs & {
  output_dir?: string;
  lookback_days?: number;
};

export interface OciCollected<T> {
  ok: boolean;
  items: T[];
  error?: string;
}

export interface OciScopedCollection<T> {
  items: T[];
  readable: boolean;
  seenCompartments: number;
  totalCompartments: number;
  deniedCompartments: string[];
  truncated: boolean;
  errors: string[];
}

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
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
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
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

function upper(value: unknown): string {
  return asString(value)?.toUpperCase() ?? "";
}

export const REDACTED_MARKER = "[redacted]";

/**
 * Field names whose values are credential-bearing wherever they appear in an
 * OCI response: CustomerSecretKey.key and AuthToken.token (returned on
 * create), ApiKey.keyValue (public PEM, still dropped as verbose key material),
 * PreauthenticatedRequest.accessUri (a bearer URI), KMS key material and
 * wrapped keys, Vault secret bundles, and any private key or password field.
 * Keys are compared after lowercasing and stripping underscores and hyphens.
 */
const SENSITIVE_EXACT_KEYS = new Set([
  "accessuri",
  "authorization",
  "ciphertext",
  "clientsecret",
  "communitystring",
  "connectionstring",
  "credentials",
  "key",
  "keyfile",
  "keymaterial",
  "keyvalue",
  "passphrase",
  "password",
  "passwordhash",
  "plaintext",
  "plaintextchecksum",
  "privatekey",
  "privatekeypem",
  "secret",
  "secretbundle",
  "secretbundlecontent",
  "secretcontent",
  "secretkey",
  "securitytoken",
  "securitytokenfile",
  "sshprivatekey",
  "token",
  "userdata",
  "wrappedimportkey",
  "wrappedkey",
]);

const SENSITIVE_KEY_SUFFIXES = ["accessuri", "keymaterial", "passphrase", "password", "privatekey", "secret", "secretkey", "signature", "token", "wrappedkey"];

const SENSITIVE_TEXT_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /-----BEGIN[^-]*-----[\s\S]*?-----END[^-]*-----/g, replacement: "[redacted key material]" },
  { pattern: /-----BEGIN[^-]*-----[\s\S]*/g, replacement: "[redacted key material]" },
  { pattern: /\/p\/[A-Za-z0-9_+/=-]+\/n\//g, replacement: "/p/[redacted]/n/" },
  /**
   * OCI request signing always emits the parameter-list form
   * `Signature version="1",keyId="<tenancy>/<user>/<fingerprint>",algorithm="rsa-sha256",headers="...",signature="<base64>"`
   * (https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm); the whole list is
   * redacted because keyId identifies the tenancy, user, and key fingerprint and signature is the credential.
   */
  { pattern: /\bSignature\s+[A-Za-z]+\s*=\s*"[^"]*"(?:\s*,\s*[A-Za-z]+\s*=\s*"[^"]*")*/g, replacement: "Signature [redacted]" },
  { pattern: /\b(Signature|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/g, replacement: "$1 [redacted]" },
  { pattern: /\b(signature|keyId)\s*=\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi, replacement: `$1=${REDACTED_MARKER}` },
  { pattern: /--config-file\s+("[^"]*"|'[^']*'|\S+)/g, replacement: `--config-file ${REDACTED_MARKER}` },
  { pattern: /\b([A-Za-z_-]*(?:token|secret|signature|password|passphrase|key_file|keyfile|access_uri|accessuri)[A-Za-z_-]*)["']?\s*[=:]\s*("[^"]*"|'[^']*'|\S+)/gi, replacement: `$1=${REDACTED_MARKER}` },
];

function normalizeFieldName(key: string): string {
  return key.toLowerCase().replace(/[_-]/g, "");
}

export function isSensitiveFieldName(key: string): boolean {
  const normalized = normalizeFieldName(key);
  if (SENSITIVE_EXACT_KEYS.has(normalized)) return true;
  return SENSITIVE_KEY_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

export function redactSensitiveText(text: string): string {
  let result = text;
  for (const { pattern, replacement } of SENSITIVE_TEXT_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

/**
 * Deep-copies a value while replacing credential-bearing fields with a
 * redaction marker (the field name is kept so reviewers can see what was
 * dropped) and scrubbing key material or bearer URIs embedded in strings.
 */
export function redactSensitiveValues<T>(value: T): T {
  if (typeof value === "string") return redactSensitiveText(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactSensitiveValues(item)) as T;
  if (value && typeof value === "object") {
    const result: JsonRecord = {};
    for (const [key, entry] of Object.entries(value as JsonRecord)) {
      if (isSensitiveFieldName(key) && entry !== undefined && entry !== null && typeof entry !== "boolean" && typeof entry !== "number") {
        result[key] = REDACTED_MARKER;
      } else {
        result[key] = redactSensitiveValues(entry);
      }
    }
    return result as T;
  }
  return value;
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return redactSensitiveText(message).slice(0, 1000);
}

function finding(
  id: string,
  title: string,
  severity: OciFinding["severity"],
  status: OciFindingStatus,
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): OciFinding {
  return {
    id,
    title,
    severity,
    status,
    summary: redactSensitiveText(summary),
    evidence: evidence ? redactSensitiveValues(evidence) : undefined,
    mappings,
  };
}

/**
 * Projects a compartment record down to the documented fields the verdicts
 * read (OCI_SURFACE_DOCS.compartments.fields) so the raw snapshot never
 * carries tags, descriptions, or other tenancy configuration verbatim.
 */
export function projectCompartmentSnapshot(compartment: JsonRecord): JsonRecord {
  return {
    id: asString(compartment.id),
    compartmentId: asString(compartment.compartmentId),
    name: asString(compartment.name),
    lifecycleState: asString(compartment.lifecycleState),
  };
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
  return normalized || "oci";
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

export const OCI_COMMAND_RUNNER_OPTIONS: ExecFileSyncOptionsWithStringEncoding = {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  timeout: DEFAULT_COMMAND_TIMEOUT_MS,
  maxBuffer: DEFAULT_COMMAND_MAX_BUFFER_BYTES,
};

function defaultCommandRunner(args: string[]): string {
  return execFileSync("oci", args, OCI_COMMAND_RUNNER_OPTIONS).trim();
}

function parseIniSections(contents: string): Record<string, Record<string, string>> {
  const sections: Record<string, Record<string, string>> = {};
  let currentSection = "";
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      sections[currentSection] = sections[currentSection] ?? {};
      continue;
    }
    const eq = line.indexOf("=");
    if (eq === -1 || !currentSection) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    sections[currentSection] = sections[currentSection] ?? {};
    sections[currentSection][key] = value;
  }
  return sections;
}

function expandHome(pathname: string, env: NodeJS.ProcessEnv): string {
  if (pathname.startsWith("~/")) {
    const home = env.HOME ?? env.USERPROFILE;
    return home ? resolve(home, pathname.slice(2)) : pathname;
  }
  return pathname;
}

export function resolveOciConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  configLoader: (pathname: string) => string | undefined = (pathname) => {
    try {
      return readFileSync(pathname, "utf8");
    } catch {
      return undefined;
    }
  },
): OciResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = expandHome(
    asString(input.config_file)
      ?? asString(env.OCI_CONFIG_FILE)
      ?? "~/.oci/config",
    env,
  );
  if (asString(input.config_file)) sourceChain.push("arguments-config-file");
  else if (asString(env.OCI_CONFIG_FILE)) sourceChain.push("environment-config-file");
  else sourceChain.push("default-config-file");

  const profile = asString(input.profile)
    ?? asString(env.OCI_CLI_PROFILE)
    ?? DEFAULT_PROFILE;
  if (asString(input.profile)) sourceChain.push("arguments-profile");
  else if (asString(env.OCI_CLI_PROFILE)) sourceChain.push("environment-profile");
  else sourceChain.push("default-profile");

  const configText = configLoader(configFile);
  const section = configText ? parseIniSections(configText)[profile] ?? {} : {};

  const region = asString(input.region)
    ?? asString(env.OCI_REGION)
    ?? section.region
    ?? DEFAULT_REGION;
  if (asString(input.region)) sourceChain.push("arguments-region");
  else if (asString(env.OCI_REGION)) sourceChain.push("environment-region");
  else if (section.region) sourceChain.push("config-region");
  else sourceChain.push("default-region");

  const tenancyOcid = asString(input.tenancy_ocid)
    ?? asString(env.OCI_TENANCY_OCID)
    ?? section.tenancy;
  if (!tenancyOcid) {
    throw new Error(`Unable to resolve OCI tenancy OCID from arguments, environment, or ${configFile} profile ${profile}.`);
  }
  if (asString(input.tenancy_ocid)) sourceChain.push("arguments-tenancy");
  else if (asString(env.OCI_TENANCY_OCID)) sourceChain.push("environment-tenancy");
  else sourceChain.push("config-tenancy");

  const compartmentOcid = asString(input.compartment_ocid)
    ?? asString(env.OCI_COMPARTMENT_OCID)
    ?? tenancyOcid;
  if (asString(input.compartment_ocid)) sourceChain.push("arguments-compartment");
  else if (asString(env.OCI_COMPARTMENT_OCID)) sourceChain.push("environment-compartment");
  else sourceChain.push("default-compartment-tenancy");

  return {
    configFile,
    profile,
    region,
    tenancyOcid,
    compartmentOcid,
    sourceChain: [...new Set(sourceChain)],
  };
}

function describeSourceChain(config: OciResolvedConfig): string {
  return `OCI profile ${config.profile} in ${config.region}`;
}

function normalizeStatementText(statement: unknown): string {
  return asString(statement)?.toLowerCase().replace(/\s+/g, " ") ?? "";
}

function isBroadPolicy(statement: string): boolean {
  return statement.includes("manage all-resources")
    || (statement.includes(" to manage ") && statement.includes(" in tenancy"));
}

function flattenListResponse(payload: JsonRecord): JsonRecord[] {
  const data = payload.data;
  if (Array.isArray(data)) {
    return data.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  const object = asObject(data);
  return object ? [object] : [];
}

function cidrIsWorld(value: unknown): boolean {
  const text = asString(value);
  return text === "0.0.0.0/0" || text === "::/0";
}

/**
 * Returns true when a rule with the documented protocol and TCP destination
 * port range reaches any sensitive port. Protocol "6" is TCP and "all" is any
 * protocol (IANA protocol number strings per IngressSecurityRule.protocol);
 * an absent destinationPortRange means all ports.
 */
export function ruleReachesSensitivePort(rule: JsonRecord): boolean {
  const protocol = asString(rule.protocol)?.toLowerCase();
  if (protocol !== undefined && protocol !== "6" && protocol !== "all") return false;
  const tcpOptions = asObject(rule.tcpOptions);
  const range = asObject(tcpOptions?.destinationPortRange);
  if (!range) return true;
  const min = asNumber(range.min);
  const max = asNumber(range.max);
  if (min === undefined || max === undefined) return true;
  return SENSITIVE_PORTS.some((port) => port >= min && port <= max);
}

function isActiveLifecycle(item: JsonRecord): boolean {
  return upper(item.lifecycleState) === "ACTIVE";
}

/**
 * Wraps a single command so that CLI failures (non-zero exit, including the
 * documented NotAuthorizedOrNotFound 404 response) never masquerade as an
 * empty inventory.
 */
export async function collect<T>(load: () => Promise<T[]>): Promise<OciCollected<T>> {
  try {
    return { ok: true, items: await load() };
  } catch (error) {
    return { ok: false, items: [], error: errorMessage(error) };
  }
}

function collectionFromSingle<T>(collected: OciCollected<T>): OciScopedCollection<T> {
  return {
    items: collected.items,
    readable: collected.ok,
    seenCompartments: collected.ok ? 1 : 0,
    totalCompartments: 1,
    deniedCompartments: [],
    truncated: false,
    errors: collected.error ? [collected.error] : [],
  };
}

/**
 * Lists a compartment-scoped resource across every accessible compartment, up
 * to the compartment cap. Denied compartments and truncation are recorded so
 * verdicts can flag a partial view instead of passing on it.
 */
export async function collectAcrossCompartments<T>(
  surfaceName: string,
  compartments: JsonRecord[],
  maxCompartments: number,
  load: (compartmentId: string) => Promise<T[]>,
): Promise<OciScopedCollection<T>> {
  const active = compartments.filter((compartment) => asString(compartment.id) && upper(compartment.lifecycleState) !== "DELETED");
  const inspected = active.slice(0, maxCompartments);
  const items: T[] = [];
  const deniedCompartments: string[] = [];
  const errors: string[] = [];
  let readable = false;
  for (const compartment of inspected) {
    const compartmentId = asString(compartment.id) ?? "";
    const label = asString(compartment.name) ?? compartmentId;
    try {
      items.push(...await load(compartmentId));
      readable = true;
    } catch (error) {
      deniedCompartments.push(label);
      errors.push(`${surfaceName} in compartment ${label}: ${errorMessage(error)}`);
    }
  }
  return {
    items,
    readable,
    seenCompartments: inspected.length - deniedCompartments.length,
    totalCompartments: active.length,
    deniedCompartments,
    truncated: active.length > inspected.length,
    errors,
  };
}

function isPartial<T>(collection: OciScopedCollection<T>): boolean {
  return collection.truncated || collection.deniedCompartments.length > 0;
}

function partialNote<T>(collection: OciScopedCollection<T>): string {
  const parts: string[] = [];
  if (collection.truncated) {
    parts.push(`compartment cap hit (${collection.seenCompartments}/${collection.totalCompartments} compartments inspected)`);
  }
  if (collection.deniedCompartments.length > 0) {
    parts.push(`${collection.deniedCompartments.length} compartment(s) denied or unreadable`);
  }
  return parts.length > 0 ? ` Partial view: ${parts.join("; ")}; a pass verdict is withheld.` : "";
}

function unreadableSummary(surface: string, collection: OciScopedCollection<unknown>, evidenceToCollect: string): string {
  const cause = collection.errors[0] ?? "the OCI CLI returned no data";
  return `Manual: ${surface} could not be read (${cause}). Grant the inspect/read policy for this surface or collect ${evidenceToCollect} manually.`;
}

/**
 * Applies the shared verdict-safety rules: unreadable surfaces are manual,
 * empty inventories take the control-specific empty status, and partial
 * inventories never pass.
 */
export function scopedStatus<T>(
  collection: OciScopedCollection<T>,
  computed: OciFindingStatus,
  emptyStatus: OciFindingStatus,
): OciFindingStatus {
  if (!collection.readable) return "manual";
  const status = collection.items.length === 0 ? emptyStatus : computed;
  if (status === "pass" && isPartial(collection)) return "warn";
  return status;
}

function scopeEvidence<T>(collection: OciScopedCollection<T>): JsonRecord {
  return {
    readable: collection.readable,
    items_seen: collection.items.length,
    compartments_seen: collection.seenCompartments,
    compartments_total: collection.totalCompartments,
    denied_compartments: collection.deniedCompartments.slice(0, 25),
    compartments_truncated: collection.truncated,
  };
}

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<OciAccessSurface> {
  try {
    const value = await load();
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
      error: errorMessage(error),
    };
  }
}

export class OciAuditorClient {
  private readonly now: () => Date;

  constructor(
    private readonly config: OciResolvedConfig,
    private readonly commandRunner: OciCommandRunner = defaultCommandRunner,
    options: { now?: () => Date } = {},
  ) {
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): OciResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private buildBaseArgs(): string[] {
    return [
      "--config-file",
      this.config.configFile,
      "--profile",
      this.config.profile,
      "--region",
      this.config.region,
      "--output",
      "json",
    ];
  }

  private runJson(args: string[]): JsonRecord {
    const output = this.commandRunner([...this.buildBaseArgs(), ...args]);
    return output.trim().length > 0 ? (JSON.parse(output) as JsonRecord) : {};
  }

  /** OCI_SURFACE_DOCS.compartments; --all follows opc-next-page to completion. */
  async listCompartments(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "compartment", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
      "--access-level", "ACCESSIBLE",
      "--include-root", "true",
    ]));
  }

  /** OCI_SURFACE_DOCS.users */
  async listUsers(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "user", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.authenticationPolicy */
  async getAuthenticationPolicy(): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "iam", "authentication-policy", "get",
      "--compartment-id", this.config.tenancyOcid,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.apiKeys */
  async listApiKeys(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "user", "api-key", "list",
      "--user-id", userOcid,
    ]));
  }

  /** OCI_SURFACE_DOCS.customerSecretKeys */
  async listCustomerSecretKeys(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "customer-secret-key", "list",
      "--user-id", userOcid,
    ]));
  }

  /** OCI_SURFACE_DOCS.authTokens */
  async listAuthTokens(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "auth-token", "list",
      "--user-id", userOcid,
    ]));
  }

  /** OCI_SURFACE_DOCS.policies; ListPolicies has no subtree parameter, so callers iterate compartments. */
  async listPolicies(compartmentId: string = this.config.tenancyOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "policy", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.availabilityDomains */
  async listAvailabilityDomains(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "availability-domain", "list",
      "--compartment-id", this.config.tenancyOcid,
    ]));
  }

  /** OCI_SURFACE_DOCS.auditConfiguration */
  async getAuditConfiguration(): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "audit", "config", "get",
      "--compartment-id", this.config.tenancyOcid,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.auditEvents */
  async listAuditEvents(lookbackDays = DEFAULT_LOOKBACK_DAYS): Promise<JsonRecord[]> {
    const end = this.getNow();
    const start = new Date(end.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
    return flattenListResponse(this.runJson([
      "audit", "event", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--start-time", start.toISOString(),
      "--end-time", end.toISOString(),
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.cloudGuardConfiguration */
  async getCloudGuardConfiguration(): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "cloud-guard", "configuration", "get",
      "--compartment-id", this.config.tenancyOcid,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.cloudGuardTargets; ListTargets supports compartmentIdInSubtree and accessLevel. */
  async listCloudGuardTargets(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "target", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--compartment-id-in-subtree", "true",
      "--access-level", "ACCESSIBLE",
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.cloudGuardProblems; lifecycleDetail OPEN filters to unresolved problems. */
  async listCloudGuardProblems(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "problem", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--compartment-id-in-subtree", "true",
      "--access-level", "ACCESSIBLE",
      "--lifecycle-detail", "OPEN",
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.responderRecipes */
  async listResponderRecipes(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "responder-recipe", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--compartment-id-in-subtree", "true",
      "--access-level", "ACCESSIBLE",
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.eventRules; ListRules has no subtree parameter (limit max 50, --all pages). */
  async listEventRules(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "events", "rule", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.securityLists; ListSecurityLists has no subtree parameter. */
  async listSecurityLists(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "security-list", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.networkSecurityGroups; ListNetworkSecurityGroups has no subtree parameter. */
  async listNetworkSecurityGroups(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "nsg", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.networkSecurityGroupRules; the CLI flag is --nsg-id and --direction INGRESS is a documented enum. */
  async listNetworkSecurityGroupRules(nsgOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "nsg", "rules", "list",
      "--nsg-id", nsgOcid,
      "--direction", "INGRESS",
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.internetGateways; ListInternetGateways has no subtree parameter. */
  async listInternetGateways(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "internet-gateway", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.bastions */
  async listBastions(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bastion", "bastion", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.bastionDetail; BastionSummary omits TTL and CIDR fields, so each bastion is fetched. */
  async getBastion(bastionOcid: string): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "bastion", "bastion", "get",
      "--bastion-id", bastionOcid,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.bastionSessions */
  async listBastionSessions(bastionOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bastion", "session", "list",
      "--bastion-id", bastionOcid,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.vaults */
  async listVaults(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "kms", "management", "vault", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.keys; KMS management calls target the vault managementEndpoint via the global --endpoint flag. */
  async listKeys(vault: JsonRecord): Promise<JsonRecord[]> {
    const managementEndpoint = asString(vault.managementEndpoint);
    const compartmentId = asString(vault.compartmentId) ?? this.config.compartmentOcid;
    if (!managementEndpoint) {
      throw new Error(`Vault ${asString(vault.id) ?? "unknown"} did not expose managementEndpoint.`);
    }
    return flattenListResponse(this.runJson([
      "kms", "management", "key", "list",
      "--endpoint", managementEndpoint,
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.keyDetail; keyShape (algorithm, length in bytes, curveId) exists only on the Key datatype returned by GetKey. */
  async getKey(vault: JsonRecord, keyOcid: string): Promise<JsonRecord | null> {
    const managementEndpoint = asString(vault.managementEndpoint);
    if (!managementEndpoint) {
      throw new Error(`Vault ${asString(vault.id) ?? "unknown"} did not expose managementEndpoint.`);
    }
    return asObject(this.runJson([
      "kms", "management", "key", "get",
      "--endpoint", managementEndpoint,
      "--key-id", keyOcid,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.keyVersions */
  async listKeyVersions(vault: JsonRecord, keyOcid: string): Promise<JsonRecord[]> {
    const managementEndpoint = asString(vault.managementEndpoint);
    if (!managementEndpoint) {
      throw new Error(`Vault ${asString(vault.id) ?? "unknown"} did not expose managementEndpoint.`);
    }
    return flattenListResponse(this.runJson([
      "kms", "management", "key-version", "list",
      "--endpoint", managementEndpoint,
      "--key-id", keyOcid,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.objectStorageNamespace */
  async getObjectStorageNamespace(): Promise<string> {
    const response = this.runJson(["os", "ns", "get"]);
    return asString(response.data) ?? "";
  }

  /** OCI_SURFACE_DOCS.buckets */
  async listBuckets(namespaceName: string, compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "os", "bucket", "list",
      "--namespace-name", namespaceName,
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.bucketDetail; BucketSummary omits publicAccessType, so each bucket is fetched. */
  async getBucket(namespaceName: string, bucketName: string): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "os", "bucket", "get",
      "--namespace-name", namespaceName,
      "--bucket-name", bucketName,
    ]).data) ?? null;
  }

  /** OCI_SURFACE_DOCS.preauthenticatedRequests */
  async listPreauthenticatedRequests(namespaceName: string, bucketName: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "os", "preauth-request", "list",
      "--namespace-name", namespaceName,
      "--bucket-name", bucketName,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.instances; ListInstances limit max 100, --all pages. */
  async listInstances(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "compute", "instance", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.volumes; ListVolumes requires compartmentId and pages at limit 100. */
  async listVolumes(compartmentId: string = this.config.compartmentOcid): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bv", "volume", "list",
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  /** OCI_SURFACE_DOCS.bootVolumes; ListBootVolumes requires both availabilityDomain and compartmentId. */
  async listBootVolumes(compartmentId: string, availabilityDomain: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bv", "boot-volume", "list",
      "--compartment-id", compartmentId,
      "--availability-domain", availabilityDomain,
      "--all",
    ]));
  }
}

export type OciAccessClient = Pick<
  OciAuditorClient,
  "getResolvedConfig" | "listCompartments" | "listUsers" | "getAuthenticationPolicy" | "getAuditConfiguration" | "listAuditEvents" | "getCloudGuardConfiguration" | "listSecurityLists" | "listVaults" | "getObjectStorageNamespace" | "listBuckets" | "listInstances"
>;

export async function checkOciAccess(client: OciAccessClient): Promise<OciAccessCheckResult> {
  const config = client.getResolvedConfig();
  const count = (value: unknown) => (Array.isArray(value) ? value.length : undefined);
  const namespaceLoader = async () => {
    const namespace = await client.getObjectStorageNamespace();
    if (!namespace) throw new Error("Object Storage namespace was empty.");
    return client.listBuckets(namespace, config.compartmentOcid);
  };
  const surfaces = await Promise.all([
    surface("compartments", "iam", () => client.listCompartments(), count),
    surface("users", "iam", () => client.listUsers(), count),
    surface("authentication_policy", "iam", () => client.getAuthenticationPolicy(), () => 1),
    surface("audit_configuration", "audit", () => client.getAuditConfiguration(), () => 1),
    surface("audit_events", "audit", () => client.listAuditEvents(1), count),
    surface("cloud_guard_configuration", "cloud-guard", () => client.getCloudGuardConfiguration(), () => 1),
    surface("security_lists", "network", () => client.listSecurityLists(config.compartmentOcid), count),
    surface("vaults", "kms", () => client.listVaults(config.compartmentOcid), count),
    surface("object_storage", "os", namespaceLoader, count),
    surface("compute_instances", "compute", () => client.listInstances(config.compartmentOcid), count),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 7 ? "healthy" : "limited";
  const notes = [
    `Authenticated via ${describeSourceChain(config)}.`,
    `Using OCI config ${config.configFile} profile ${config.profile}.`,
    `${readableCount}/${surfaces.length} OCI audit surfaces are readable.`,
    "Unreadable surfaces render their controls as manual, never pass.",
  ];

  return {
    status,
    tenancyOcid: config.tenancyOcid,
    compartmentOcid: config.compartmentOcid,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run oci_assess_identity, oci_assess_logging_detection, oci_assess_tenancy_guardrails, oci_assess_compute_and_storage, or oci_export_audit_bundle."
        : "Install and configure the OCI CLI profile or supply explicit tenancy/profile arguments with read-only inspect permissions.",
  };
}

function computeCompartmentDepth(compartments: JsonRecord[]): number {
  const parents = new Map<string, string | undefined>();
  for (const compartment of compartments) {
    const id = asString(compartment.id);
    if (id) parents.set(id, asString(compartment.compartmentId));
  }
  let maxDepth = compartments.length > 0 ? 1 : 0;
  for (const id of parents.keys()) {
    let depth = 1;
    let cursor = parents.get(id);
    const visited = new Set<string>([id]);
    while (cursor && parents.has(cursor) && !visited.has(cursor)) {
      visited.add(cursor);
      depth += 1;
      cursor = parents.get(cursor);
    }
    maxDepth = Math.max(maxDepth, depth);
  }
  return maxDepth;
}

async function loadCompartmentScope(
  client: Pick<OciAuditorClient, "listCompartments">,
): Promise<OciCollected<JsonRecord>> {
  return collect(() => client.listCompartments());
}

export type OciIdentityClient = Pick<
  OciAuditorClient,
  "getNow" | "getAuthenticationPolicy" | "listUsers" | "listApiKeys" | "listCustomerSecretKeys" | "listAuthTokens" | "listPolicies" | "listCompartments"
>;

export async function assessOciIdentity(
  client: OciIdentityClient,
  options: {
    staleDays?: number;
    maxKeys?: number;
    maxPolicies?: number;
    maxCompartments?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const now = client.getNow();
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const maxKeys = clampNumber(options.maxKeys, DEFAULT_MAX_KEYS, 1, 5000);
  const maxPolicies = clampNumber(options.maxPolicies, DEFAULT_MAX_POLICIES, 1, 5000);
  const maxCompartments = clampNumber(options.maxCompartments, DEFAULT_MAX_COMPARTMENTS, 1, 500);
  const errors: string[] = [];

  const authPolicy = await collect(async () => {
    const policy = await client.getAuthenticationPolicy();
    return policy ? [policy] : [];
  });
  const users = await collect(() => client.listUsers());
  const compartments = await loadCompartmentScope(client);
  for (const collected of [authPolicy, users, compartments]) {
    if (collected.error) errors.push(collected.error);
  }

  const passwordPolicy = asObject(authPolicy.items[0]?.passwordPolicy);
  const minLength = asNumber(passwordPolicy?.minimumPasswordLength);
  const complexityFlags = [
    asBoolean(passwordPolicy?.isLowercaseCharactersRequired),
    asBoolean(passwordPolicy?.isUppercaseCharactersRequired),
    asBoolean(passwordPolicy?.isNumericCharactersRequired),
    asBoolean(passwordPolicy?.isSpecialCharactersRequired),
  ];
  const complexitySatisfied = complexityFlags.every((flag) => flag === true);
  let passwordStatus: OciFindingStatus;
  let passwordSummary: string;
  if (!authPolicy.ok) {
    passwordStatus = "manual";
    passwordSummary = `Manual: oci iam authentication-policy get failed (${authPolicy.error}). Collect the tenancy password policy from the console.`;
  } else if (!passwordPolicy || minLength === undefined) {
    passwordStatus = "manual";
    passwordSummary = "Manual: the authentication policy response did not include passwordPolicy.minimumPasswordLength; verify the password policy in the console.";
  } else if (minLength >= 14 && complexitySatisfied) {
    passwordStatus = "pass";
    passwordSummary = `Minimum password length ${minLength} with lowercase, uppercase, numeric, and special characters required. Expiration is not exposed by the PasswordPolicy datatype (see OCI-IAM-06).`;
  } else {
    passwordStatus = "fail";
    passwordSummary = `Minimum password length ${minLength}, complexity fully required=${complexitySatisfied}. Expiration is not exposed by the PasswordPolicy datatype (see OCI-IAM-06).`;
  }

  const activeUsers = users.items.filter(isActiveLifecycle);
  const consoleUsers = activeUsers.filter((user) => asBoolean(asObject(user.capabilities)?.canUseConsolePassword) === true);
  const usersWithoutMfa = consoleUsers.filter((user) => asBoolean(user.isMfaActivated) === false).map((user) => asString(user.name) ?? asString(user.id) ?? "unknown");
  const usersWithUnknownMfa = consoleUsers.filter((user) => asBoolean(user.isMfaActivated) === undefined).map((user) => asString(user.name) ?? asString(user.id) ?? "unknown");
  let mfaStatus: OciFindingStatus;
  let mfaSummary: string;
  if (!users.ok) {
    mfaStatus = "manual";
    mfaSummary = `Manual: oci iam user list failed (${users.error}). Export the user list with MFA status from the console.`;
  } else if (activeUsers.length === 0) {
    mfaStatus = "manual";
    mfaSummary = "Manual: no active IAM users were returned. Tenancies using identity domains manage users and MFA in the domain sign-on policy; verify there.";
  } else if (consoleUsers.length === 0) {
    mfaStatus = "manual";
    mfaSummary = `Manual: none of the ${activeUsers.length} active IAM users can use a console password, so console MFA is not applicable; verify federated MFA at the identity provider.`;
  } else if (usersWithoutMfa.length > 0) {
    mfaStatus = "fail";
    mfaSummary = `${usersWithoutMfa.length}/${consoleUsers.length} console-capable users have isMfaActivated=false.`;
  } else if (usersWithUnknownMfa.length > 0) {
    mfaStatus = "warn";
    mfaSummary = `${usersWithUnknownMfa.length}/${consoleUsers.length} console-capable users did not report isMfaActivated; those users cannot be counted as compliant.`;
  } else {
    mfaStatus = "pass";
    mfaSummary = `All ${consoleUsers.length} console-capable IAM users report isMfaActivated=true.`;
  }

  const staleCredentials: Array<{ kind: string; user: string; id?: string; ageDays: number }> = [];
  const undatedCredentials: Array<{ kind: string; user: string; id?: string }> = [];
  const credentialErrors: string[] = [];
  let credentialsSeen = 0;
  let credentialCapHit = false;
  let usersInspected = 0;
  for (const user of activeUsers) {
    const userOcid = asString(user.id);
    if (!userOcid) continue;
    if (credentialsSeen >= maxKeys) {
      credentialCapHit = true;
      break;
    }
    usersInspected += 1;
    const userName = asString(user.name) ?? userOcid;
    const loaders: Array<{ kind: string; idKey: string; load: () => Promise<JsonRecord[]> }> = [
      { kind: "api_key", idKey: "fingerprint", load: () => client.listApiKeys(userOcid) },
      { kind: "customer_secret_key", idKey: "id", load: () => client.listCustomerSecretKeys(userOcid) },
      { kind: "auth_token", idKey: "id", load: () => client.listAuthTokens(userOcid) },
    ];
    for (const loader of loaders) {
      if (credentialsSeen >= maxKeys) {
        credentialCapHit = true;
        break;
      }
      const collected = await collect(loader.load);
      if (!collected.ok) {
        credentialErrors.push(`${loader.kind} for ${userName}: ${collected.error}`);
        continue;
      }
      for (const item of collected.items.filter(isActiveLifecycle)) {
        if (credentialsSeen >= maxKeys) {
          credentialCapHit = true;
          break;
        }
        credentialsSeen += 1;
        const ageDays = daysBetween(now, extractTimestamp(item.timeCreated));
        if (ageDays === undefined) {
          undatedCredentials.push({ kind: loader.kind, user: userName, id: asString(item[loader.idKey]) });
        } else if (ageDays > staleDays) {
          staleCredentials.push({ kind: loader.kind, user: userName, id: asString(item[loader.idKey]), ageDays: Number(ageDays.toFixed(1)) });
        }
      }
    }
  }
  errors.push(...credentialErrors);
  let credentialStatus: OciFindingStatus;
  let credentialSummary: string;
  if (!users.ok) {
    credentialStatus = "manual";
    credentialSummary = `Manual: the user inventory could not be read (${users.error}), so API keys, customer secret keys, and auth tokens were not inspected.`;
  } else if (activeUsers.length === 0) {
    credentialStatus = "manual";
    credentialSummary = "Manual: no active IAM users were returned, so no long-lived credentials could be inspected.";
  } else if (credentialErrors.length > 0 && credentialsSeen === 0) {
    credentialStatus = "manual";
    credentialSummary = `Manual: credential listings failed for every user (${credentialErrors[0]}).`;
  } else if (staleCredentials.length > 0) {
    credentialStatus = "fail";
    credentialSummary = `${staleCredentials.length} active API keys, customer secret keys, or auth tokens exceeded ${staleDays} days.`;
  } else if (credentialCapHit || credentialErrors.length > 0 || undatedCredentials.length > 0) {
    credentialStatus = "warn";
    const capNote = credentialCapHit
      ? ` Credential cap ${maxKeys} hit: ${credentialsSeen} credentials seen across ${usersInspected}/${activeUsers.length} active users; the total is unknown because enumeration stopped at the cap.`
      : "";
    credentialSummary = `No stale credentials among ${credentialsSeen} inspected, but the view is incomplete: cap hit=${credentialCapHit}, listing errors=${credentialErrors.length}, undated credentials=${undatedCredentials.length}.${capNote}`;
  } else {
    credentialStatus = "pass";
    credentialSummary = `None of the ${credentialsSeen} active API keys, customer secret keys, or auth tokens exceeded ${staleDays} days.`;
  }

  const policyScope = compartments.ok
    ? await collectAcrossCompartments("iam policy list", compartments.items, maxCompartments, (compartmentId) => client.listPolicies(compartmentId))
    : collectionFromSingle<JsonRecord>({ ok: false, items: [], error: compartments.error });
  errors.push(...policyScope.errors);
  const activePolicies = policyScope.items.filter(isActiveLifecycle);
  const policies = activePolicies.slice(0, maxPolicies);
  const policyCapHit = activePolicies.length > maxPolicies;
  const policyCapNote = policyCapHit ? ` Policy cap ${maxPolicies} hit: ${policies.length}/${activePolicies.length} active policies inspected; a pass verdict is withheld.` : "";
  const broadPolicies = policies.filter((policy) => asArray(policy.statements).some((statement) => isBroadPolicy(normalizeStatementText(statement))));
  const policyComputed: OciFindingStatus = broadPolicies.length > 0 ? "warn" : (policyCapHit ? "warn" : "pass");
  const policyStatus = scopedStatus(policyScope, policyComputed, "manual");
  let policySummary: string;
  if (!policyScope.readable) {
    policySummary = unreadableSummary("IAM policies", policyScope, "the policy statements");
  } else if (policyScope.items.length === 0) {
    policySummary = "Manual: no IAM policies were returned even though every tenancy has a root administrators policy; verify the inspect policies permission and review statements manually.";
  } else if (broadPolicies.length > 0) {
    policySummary = `${broadPolicies.length}/${policies.length} active policies contain tenancy-wide manage statements.${policyCapNote}${partialNote(policyScope)}`;
  } else {
    policySummary = `None of the ${policies.length} active policies contain tenancy-wide manage statements.${policyCapNote}${partialNote(policyScope)}`;
  }

  const activeCompartments = compartments.items.filter(isActiveLifecycle);
  const nonRootCompartments = activeCompartments.filter((compartment) => asString(compartment.id) !== asString(compartment.compartmentId) && asString(compartment.compartmentId) !== undefined && parentIsCompartment(compartment, activeCompartments));
  const maxDepth = computeCompartmentDepth(activeCompartments);
  let compartmentStatus: OciFindingStatus;
  let compartmentSummary: string;
  if (!compartments.ok) {
    compartmentStatus = "manual";
    compartmentSummary = `Manual: oci iam compartment list failed (${compartments.error}); collect the compartment tree from the console.`;
  } else if (nonRootCompartments.length === 0) {
    compartmentStatus = "fail";
    compartmentSummary = "The tenancy is flat: no active non-root compartments were returned, so resources are not isolated by compartment.";
  } else {
    compartmentStatus = "pass";
    compartmentSummary = `${nonRootCompartments.length} active non-root compartments with maximum observed depth ${maxDepth}.`;
  }

  const findings = [
    finding(
      "OCI-IAM-01",
      "IAM password policy length and complexity",
      "high",
      passwordStatus,
      passwordSummary,
      ["FedRAMP IA-5", "CMMC L2 3.5.7", "SOC 2 CC6.1", "CIS OCI 1.1", "PCI-DSS 8.3.6", "STIG SRG-APP-000166", "IRAP ISM-0421", "ISMAP AM-03"],
      { password_policy: passwordPolicy ?? null, source: OCI_SURFACE_DOCS.authenticationPolicy.rest },
    ),
    finding(
      "OCI-IAM-06",
      "IAM password expiration (manual)",
      "medium",
      "manual",
      "Manual: the IAM PasswordPolicy datatype exposes only length, character-class, and username-containment settings; verify the 90-day expiration in the identity domain password policy.",
      ["FedRAMP IA-5", "CMMC L2 3.5.7", "SOC 2 CC6.1", "CIS OCI 1.1", "PCI-DSS 8.3.6", "STIG SRG-APP-000166", "IRAP ISM-0421", "ISMAP AM-03"],
      { reference: OCI_SURFACE_DOCS.authenticationPolicy.rest, documented_fields: OCI_SURFACE_DOCS.authenticationPolicy.fields },
    ),
    finding(
      "OCI-IAM-02",
      "Console MFA enforcement",
      "high",
      mfaStatus,
      mfaSummary,
      ["FedRAMP IA-2(1)", "CMMC L2 3.5.3", "SOC 2 CC6.1", "CIS OCI 1.2", "PCI-DSS 8.4.2", "STIG SRG-APP-000149", "IRAP ISM-1401", "ISMAP AM-04"],
      { active_users: activeUsers.length, console_users: consoleUsers.length, users_without_mfa: usersWithoutMfa.slice(0, 25), users_with_unknown_mfa: usersWithUnknownMfa.slice(0, 25) },
    ),
    finding(
      "OCI-IAM-03",
      "API key, customer secret key, and auth token rotation",
      "high",
      credentialStatus,
      credentialSummary,
      ["FedRAMP IA-5(1)", "CMMC L2 3.5.8", "SOC 2 CC6.1", "CIS OCI 1.7", "CIS OCI 1.8", "CIS OCI 1.9", "PCI-DSS 8.6.3", "STIG SRG-APP-000174", "IRAP ISM-1590", "ISMAP AM-05"],
      {
        credentials_seen: credentialsSeen,
        credential_cap_hit: credentialCapHit,
        credential_cap: maxKeys,
        credentials_total: credentialCapHit ? null : credentialsSeen,
        users_inspected: usersInspected,
        users_total: activeUsers.length,
        stale_credentials: staleCredentials.slice(0, 25),
        undated_credentials: undatedCredentials.slice(0, 25),
        listing_errors: credentialErrors.slice(0, 10),
      },
    ),
    finding(
      "OCI-IAM-04",
      "Broad IAM policies",
      "high",
      policyStatus,
      policySummary,
      ["FedRAMP AC-6", "CMMC L2 3.1.5", "SOC 2 CC6.3", "CIS OCI 1.14", "PCI-DSS 7.2.1", "STIG SRG-APP-000340", "IRAP ISM-0432", "ISMAP AC-01"],
      { ...scopeEvidence(policyScope), policy_cap_hit: policyCapHit, policy_cap: maxPolicies, policies_seen: policies.length, policies_total: activePolicies.length, broad_policies: broadPolicies.slice(0, 25).map((policy) => ({ name: policy.name, statements: policy.statements })) },
    ),
    finding(
      "OCI-IAM-05",
      "Compartment hierarchy depth",
      "medium",
      compartmentStatus,
      compartmentSummary,
      ["FedRAMP AC-4", "CMMC L2 3.13.1", "SOC 2 CC6.1", "CIS OCI 1.3", "PCI-DSS 1.3.1", "STIG SRG-APP-000039", "IRAP ISM-1416", "ISMAP AC-02"],
      { active_compartments: activeCompartments.length, non_root_compartments: nonRootCompartments.length, max_depth: maxDepth },
    ),
  ];

  return {
    title: "OCI identity posture",
    summary: {
      active_users: activeUsers.length,
      console_users: consoleUsers.length,
      users_without_mfa: usersWithoutMfa.length,
      credentials_seen: credentialsSeen,
      stale_credentials: staleCredentials.length,
      undated_credentials: undatedCredentials.length,
      policies_seen: policies.length,
      broad_policies: broadPolicies.length,
      non_root_compartments: nonRootCompartments.length,
      max_compartment_depth: maxDepth,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function parentIsCompartment(compartment: JsonRecord, compartments: JsonRecord[]): boolean {
  const parent = asString(compartment.compartmentId);
  return compartments.some((candidate) => asString(candidate.id) === parent) || parent?.startsWith("ocid1.tenancy") === true;
}

export type OciLoggingClient = Pick<
  OciAuditorClient,
  "getCloudGuardConfiguration" | "listCloudGuardTargets" | "listCloudGuardProblems" | "listResponderRecipes" | "getAuditConfiguration" | "listAuditEvents" | "listEventRules" | "listCompartments"
>;

function responderRecipeHasEnabledRule(recipe: JsonRecord): boolean {
  return asArray(recipe.responderRules).some((rule) => asBoolean(asObject(asObject(rule)?.details)?.isEnabled) === true);
}

function eventRuleTargetsCriticalChange(rule: JsonRecord): boolean {
  const condition = normalizeStatementText(rule.condition);
  return condition.includes("com.oraclecloud.identitycontrolplane")
    || condition.includes("com.oraclecloud.virtualnetwork")
    || condition.includes("policy")
    || condition.includes("identity")
    || condition.includes("network");
}

export async function assessOciLoggingDetection(
  client: OciLoggingClient,
  options: {
    lookbackDays?: number;
    maxCompartments?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 90);
  const maxCompartments = clampNumber(options.maxCompartments, DEFAULT_MAX_COMPARTMENTS, 1, 500);
  const errors: string[] = [];

  const cloudGuardConfig = await collect(async () => {
    const configuration = await client.getCloudGuardConfiguration();
    return configuration ? [configuration] : [];
  });
  const targets = await collect(() => client.listCloudGuardTargets());
  const problems = await collect(() => client.listCloudGuardProblems());
  const responderRecipes = await collect(() => client.listResponderRecipes());
  const auditConfig = await collect(async () => {
    const configuration = await client.getAuditConfiguration();
    return configuration ? [configuration] : [];
  });
  const auditEvents = await collect(() => client.listAuditEvents(lookbackDays));
  const compartments = await loadCompartmentScope(client);
  for (const collected of [cloudGuardConfig, targets, problems, responderRecipes, auditConfig, auditEvents, compartments]) {
    if (collected.error) errors.push(collected.error);
  }

  const cloudGuardStatus = upper(cloudGuardConfig.items[0]?.status);
  const cloudGuardEnabled = cloudGuardStatus === "ENABLED";
  const activeTargets = targets.items.filter(isActiveLifecycle);
  let enabledStatus: OciFindingStatus;
  let enabledSummary: string;
  if (!cloudGuardConfig.ok) {
    enabledStatus = "manual";
    enabledSummary = `Manual: oci cloud-guard configuration get failed (${cloudGuardConfig.error}); confirm Cloud Guard enablement in the console.`;
  } else if (!cloudGuardStatus) {
    enabledStatus = "manual";
    enabledSummary = "Manual: the Cloud Guard configuration response did not include status; confirm enablement in the console.";
  } else if (!cloudGuardEnabled) {
    enabledStatus = "fail";
    enabledSummary = `Cloud Guard configuration status is ${cloudGuardStatus}.`;
  } else if (!targets.ok) {
    enabledStatus = "manual";
    enabledSummary = `Cloud Guard is ENABLED but oci cloud-guard target list failed (${targets.error}); confirm target coverage manually.`;
  } else if (activeTargets.length === 0) {
    enabledStatus = "fail";
    enabledSummary = "Cloud Guard is ENABLED but no ACTIVE targets were returned, so no compartment is monitored.";
  } else {
    enabledStatus = "pass";
    enabledSummary = `Cloud Guard is ENABLED (reporting region ${asString(cloudGuardConfig.items[0]?.reportingRegion) ?? "unknown"}) with ${activeTargets.length} ACTIVE targets.`;
  }

  const openProblems = problems.items.filter((problem) => upper(problem.lifecycleDetail) === "OPEN" || upper(problem.lifecycleDetail) === "");
  const highRiskProblems = openProblems.filter((problem) => ["CRITICAL", "HIGH"].includes(upper(problem.riskLevel)));
  let problemStatus: OciFindingStatus;
  let problemSummary: string;
  if (!problems.ok) {
    problemStatus = "manual";
    problemSummary = `Manual: oci cloud-guard problem list failed (${problems.error}); export open problems from the Cloud Guard console.`;
  } else if (!cloudGuardEnabled) {
    problemStatus = "manual";
    problemSummary = "Manual: Cloud Guard is not confirmed ENABLED, so an empty problem list is not evidence; enable Cloud Guard or review problems after enablement.";
  } else if (highRiskProblems.length > 0) {
    problemStatus = "fail";
    problemSummary = `${openProblems.length} OPEN Cloud Guard problems, including ${highRiskProblems.length} at CRITICAL or HIGH riskLevel.`;
  } else if (openProblems.length > 0) {
    problemStatus = "warn";
    problemSummary = `${openProblems.length} OPEN Cloud Guard problems at MEDIUM or lower riskLevel.`;
  } else {
    problemStatus = "pass";
    problemSummary = "No OPEN Cloud Guard problems were returned while Cloud Guard is ENABLED with active targets (emptiness is compliant here).";
  }

  const activeResponders = responderRecipes.items.filter(isActiveLifecycle);
  const activeRespondersWithRules = activeResponders.filter(responderRecipeHasEnabledRule);
  let responderStatus: OciFindingStatus;
  let responderSummary: string;
  if (!responderRecipes.ok) {
    responderStatus = "manual";
    responderSummary = `Manual: oci cloud-guard responder-recipe list failed (${responderRecipes.error}); review responder recipes in the console.`;
  } else if (!cloudGuardEnabled) {
    responderStatus = "manual";
    responderSummary = "Manual: Cloud Guard is not confirmed ENABLED, so responder recipes cannot be evaluated.";
  } else if (activeResponders.length === 0) {
    responderStatus = "fail";
    responderSummary = "No ACTIVE Cloud Guard responder recipes were returned.";
  } else if (activeRespondersWithRules.length === 0) {
    responderStatus = "fail";
    responderSummary = `${activeResponders.length} ACTIVE responder recipes, but none has a responder rule with details.isEnabled=true.`;
  } else {
    responderStatus = "pass";
    responderSummary = `${activeRespondersWithRules.length}/${activeResponders.length} ACTIVE responder recipes have at least one enabled responder rule.`;
  }

  const retentionDays = asNumber(auditConfig.items[0]?.retentionPeriodDays);
  let retentionStatus: OciFindingStatus;
  let retentionSummary: string;
  if (!auditConfig.ok) {
    retentionStatus = "manual";
    retentionSummary = `Manual: oci audit config get failed (${auditConfig.error}); read the audit retention period from the console (Governance, Audit, Settings).`;
  } else if (retentionDays === undefined) {
    retentionStatus = "manual";
    retentionSummary = "Manual: the audit configuration response did not include retentionPeriodDays; verify retention in the console.";
  } else if (retentionDays >= AUDIT_RETENTION_REQUIRED_DAYS) {
    retentionStatus = "pass";
    retentionSummary = `Audit retentionPeriodDays is ${retentionDays} (required ${AUDIT_RETENTION_REQUIRED_DAYS}).`;
  } else {
    retentionStatus = "fail";
    retentionSummary = `Audit retentionPeriodDays is ${retentionDays}; the control requires ${AUDIT_RETENTION_REQUIRED_DAYS}.`;
  }

  const datedEvents = auditEvents.items.filter((event) => extractTimestamp(event.eventTime) !== undefined);
  let eventStatus: OciFindingStatus;
  let eventSummary: string;
  if (!auditEvents.ok) {
    eventStatus = "manual";
    eventSummary = `Manual: oci audit event list failed (${auditEvents.error}); confirm the read audit-events policy and export events manually.`;
  } else if (datedEvents.length === 0) {
    eventStatus = "warn";
    eventSummary = `No dated audit events were returned for the last ${lookbackDays} days in the scoped compartment; emptiness is treated as a warning, not compliance.`;
  } else {
    eventStatus = "pass";
    eventSummary = `${datedEvents.length} audit events with eventTime were visible over the last ${lookbackDays} days.`;
  }

  const ruleScope = compartments.ok
    ? await collectAcrossCompartments("events rule list", compartments.items, maxCompartments, (compartmentId) => client.listEventRules(compartmentId))
    : collectionFromSingle<JsonRecord>({ ok: false, items: [], error: compartments.error });
  errors.push(...ruleScope.errors);
  const enabledRules = ruleScope.items.filter((rule) => asBoolean(rule.isEnabled) === true && upper(rule.lifecycleState) === "ACTIVE");
  const criticalRules = enabledRules.filter(eventRuleTargetsCriticalChange);
  const ruleComputed: OciFindingStatus = criticalRules.length > 0 ? "pass" : "fail";
  const ruleStatus = scopedStatus(ruleScope, ruleComputed, "fail");
  let ruleSummary: string;
  if (!ruleScope.readable) {
    ruleSummary = unreadableSummary("event rules", ruleScope, "the Events rule inventory");
  } else if (ruleScope.items.length === 0) {
    ruleSummary = `No Events rules exist in the ${ruleScope.seenCompartments} inspected compartments; emptiness fails this control because no change notification exists.${partialNote(ruleScope)}`;
  } else if (criticalRules.length === 0) {
    ruleSummary = `${enabledRules.length} enabled ACTIVE rules, none with a condition referencing identity, policy, or network event types.${partialNote(ruleScope)}`;
  } else {
    ruleSummary = `${criticalRules.length} enabled ACTIVE rules reference identity, policy, or network event types.${partialNote(ruleScope)}`;
  }

  const findings = [
    finding(
      "OCI-LOG-01",
      "Cloud Guard enabled with active targets",
      "high",
      enabledStatus,
      enabledSummary,
      ["FedRAMP SI-4", "CMMC L2 3.14.6", "SOC 2 CC7.2", "CIS OCI 3.1", "PCI-DSS 11.5.1", "STIG SRG-APP-000516", "IRAP ISM-0120", "ISMAP SO-01"],
      { configuration_status: cloudGuardStatus || null, active_targets: activeTargets.length, total_targets: targets.items.length, targets_readable: targets.ok },
    ),
    finding(
      "OCI-LOG-02",
      "Open Cloud Guard problems",
      "high",
      problemStatus,
      problemSummary,
      ["FedRAMP SI-4(5)", "CMMC L2 3.14.7", "SOC 2 CC7.3", "CIS OCI 3.2", "PCI-DSS 11.5.1.1", "STIG SRG-APP-000516", "IRAP ISM-0123", "ISMAP SO-02"],
      { open_problems: openProblems.length, high_risk_problems: highRiskProblems.length, problems_readable: problems.ok },
    ),
    finding(
      "OCI-LOG-03",
      "Responder recipe activation",
      "medium",
      responderStatus,
      responderSummary,
      ["FedRAMP IR-4", "CMMC L2 3.6.1", "SOC 2 CC7.4", "CIS OCI 3.3", "PCI-DSS 12.10.5", "STIG SRG-APP-000516", "IRAP ISM-0125", "ISMAP IR-01"],
      { active_responder_recipes: activeResponders.length, active_recipes_with_enabled_rules: activeRespondersWithRules.length, total_responder_recipes: responderRecipes.items.length },
    ),
    finding(
      "OCI-LOG-06",
      "Audit log retention",
      "high",
      retentionStatus,
      retentionSummary,
      ["FedRAMP AU-11", "CMMC L2 3.3.1", "SOC 2 CC7.2", "CIS OCI 3.4", "PCI-DSS 10.7.1", "STIG SRG-APP-000515", "IRAP ISM-0859", "ISMAP LG-01"],
      { retention_period_days: retentionDays ?? null, required_days: AUDIT_RETENTION_REQUIRED_DAYS, source: OCI_SURFACE_DOCS.auditConfiguration.rest },
    ),
    finding(
      "OCI-LOG-04",
      "Audit event visibility",
      "medium",
      eventStatus,
      eventSummary,
      [],
      { audit_events: auditEvents.items.length, dated_audit_events: datedEvents.length, lookback_days: lookbackDays, role: "supporting evidence for control 11; not a spec control, so no framework mappings" },
    ),
    finding(
      "OCI-LOG-05",
      "Event rules for critical operations",
      "medium",
      ruleStatus,
      ruleSummary,
      ["FedRAMP AU-12", "CMMC L2 3.3.1", "SOC 2 CC7.2", "CIS OCI 3.5", "PCI-DSS 10.6.1", "STIG SRG-APP-000492", "IRAP ISM-0580", "ISMAP LG-02"],
      { ...scopeEvidence(ruleScope), enabled_rules: enabledRules.length, critical_event_rules: criticalRules.length },
    ),
  ];

  return {
    title: "OCI logging and detection posture",
    summary: {
      cloud_guard_status: cloudGuardStatus || "unknown",
      active_cloud_guard_targets: activeTargets.length,
      open_cloud_guard_problems: openProblems.length,
      high_risk_cloud_guard_problems: highRiskProblems.length,
      active_responder_recipes: activeResponders.length,
      audit_retention_days: retentionDays ?? "unknown",
      audit_events: datedEvents.length,
      critical_event_rules: criticalRules.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

type KeyAlgorithm = "AES" | "RSA" | "ECDSA" | "UNKNOWN";

function keyAlgorithmOf(value: unknown): KeyAlgorithm {
  const text = upper(value);
  return text === "AES" || text === "RSA" || text === "ECDSA" ? text : "UNKNOWN";
}

/**
 * Judges a documented KeyShape (algorithm, length in bytes, curveId) against
 * spec control 19. Returns undefined when the key meets the floors.
 */
export function judgeKeyShape(shape: JsonRecord): { algorithm?: string; lengthBytes?: number; curveId?: string; reason: string } | undefined {
  const algorithm = keyAlgorithmOf(shape.algorithm);
  const lengthBytes = asNumber(shape.length);
  const curveId = asString(shape.curveId);
  const detail = { algorithm: asString(shape.algorithm), lengthBytes, curveId };
  switch (algorithm) {
    case "AES":
      if (lengthBytes === undefined) return { ...detail, reason: "keyShape.length missing for an AES key" };
      return lengthBytes < KEY_MIN_LENGTH_BYTES.AES ? { ...detail, reason: `AES-${lengthBytes * 8} is below the AES-256 floor` } : undefined;
    case "RSA":
      if (lengthBytes === undefined) return { ...detail, reason: "keyShape.length missing for an RSA key" };
      return lengthBytes < KEY_MIN_LENGTH_BYTES.RSA ? { ...detail, reason: `RSA-${lengthBytes * 8} is below the RSA-4096 floor` } : undefined;
    case "ECDSA":
      return curveId && (ECDSA_ACCEPTED_CURVES as readonly string[]).includes(curveId)
        ? undefined
        : { ...detail, reason: "ECDSA curveId missing or outside the documented NIST_P256/NIST_P384/NIST_P521 enum" };
    case "UNKNOWN":
      return { ...detail, reason: "algorithm outside the documented AES/RSA/ECDSA enum or missing" };
    default: {
      const exhaustive: never = algorithm;
      return exhaustive;
    }
  }
}

export type OciGuardrailClient = Pick<
  OciAuditorClient,
  "getNow" | "listCompartments" | "listSecurityLists" | "listNetworkSecurityGroups" | "listNetworkSecurityGroupRules" | "listInternetGateways" | "listBastions" | "getBastion" | "listBastionSessions" | "listVaults" | "listKeys" | "getKey" | "listKeyVersions" | "getObjectStorageNamespace" | "listBuckets" | "getBucket" | "listPreauthenticatedRequests"
>;

export async function assessOciTenancyGuardrails(
  client: OciGuardrailClient,
  options: {
    maxCompartments?: number;
    maxBuckets?: number;
    maxKeys?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const now = client.getNow();
  const maxCompartments = clampNumber(options.maxCompartments, DEFAULT_MAX_COMPARTMENTS, 1, 500);
  const maxBuckets = clampNumber(options.maxBuckets, DEFAULT_MAX_BUCKETS, 1, 5000);
  const maxKeys = clampNumber(options.maxKeys, DEFAULT_MAX_KEYS, 1, 5000);
  const errors: string[] = [];
  const compartments = await loadCompartmentScope(client);
  if (compartments.error) errors.push(compartments.error);
  const scoped = <T>(name: string, load: (compartmentId: string) => Promise<T[]>) => (compartments.ok
    ? collectAcrossCompartments(name, compartments.items, maxCompartments, load)
    : Promise.resolve(collectionFromSingle<T>({ ok: false, items: [], error: compartments.error })));

  const securityLists = await scoped("network security-list list", (compartmentId) => client.listSecurityLists(compartmentId));
  const nsgs = await scoped("network nsg list", (compartmentId) => client.listNetworkSecurityGroups(compartmentId));
  const internetGateways = await scoped("network internet-gateway list", (compartmentId) => client.listInternetGateways(compartmentId));
  const bastions = await scoped("bastion bastion list", (compartmentId) => client.listBastions(compartmentId));
  const vaults = await scoped("kms management vault list", (compartmentId) => client.listVaults(compartmentId));
  for (const collection of [securityLists, nsgs, internetGateways, bastions, vaults]) errors.push(...collection.errors);

  const permissiveSecurityLists = securityLists.items.filter((securityList) => asArray(securityList.ingressSecurityRules).some((rule) => {
    const item = asObject(rule);
    return item !== undefined && cidrIsWorld(item.source) && ruleReachesSensitivePort(item);
  }));
  const securityListStatus = scopedStatus(securityLists, permissiveSecurityLists.length > 0 ? "fail" : "pass", "manual");
  const securityListSummary = !securityLists.readable
    ? unreadableSummary("security lists", securityLists, "VCN security list ingress rules")
    : securityLists.items.length === 0
      ? `Manual: no security lists exist in the ${securityLists.seenCompartments} inspected compartments, so no VCN ingress posture could be judged; confirm networking is out of scope.${partialNote(securityLists)}`
      : permissiveSecurityLists.length > 0
        ? `${permissiveSecurityLists.length}/${securityLists.items.length} security lists allow 0.0.0.0/0 or ::/0 ingress to a sensitive port (22, 3389, 1433, 3306, 5432).${partialNote(securityLists)}`
        : `None of the ${securityLists.items.length} security lists allow world ingress to a sensitive port.${partialNote(securityLists)}`;

  const permissiveNsgRules: Array<{ nsgId: string; ruleId?: string; source?: string; isValid?: boolean }> = [];
  let nsgRuleErrors = 0;
  let nsgRulesSeen = 0;
  let nsgInvalidRules = 0;
  for (const nsg of nsgs.items) {
    const nsgId = asString(nsg.id);
    if (!nsgId) continue;
    const rules = await collect(() => client.listNetworkSecurityGroupRules(nsgId));
    if (!rules.ok) {
      nsgRuleErrors += 1;
      errors.push(`nsg rules list for ${nsgId}: ${rules.error}`);
      continue;
    }
    for (const rule of rules.items) {
      nsgRulesSeen += 1;
      const isValid = asBoolean(rule.isValid);
      if (isValid === false) nsgInvalidRules += 1;
      if (upper(rule.direction) === "INGRESS" && cidrIsWorld(rule.source) && ruleReachesSensitivePort(rule)) {
        permissiveNsgRules.push({ nsgId, ruleId: asString(rule.id), source: asString(rule.source), isValid });
      }
    }
  }
  const nsgComputed: OciFindingStatus = permissiveNsgRules.length > 0 ? "fail" : nsgRuleErrors > 0 ? "warn" : "pass";
  const nsgEmptyStatus: OciFindingStatus = securityLists.readable && securityLists.items.length > 0 ? "pass" : "manual";
  const nsgStatus = scopedStatus(nsgs, nsgComputed, nsgEmptyStatus);
  const nsgSummary = !nsgs.readable
    ? unreadableSummary("network security groups", nsgs, "NSG ingress rules")
    : nsgs.items.length === 0
      ? (nsgEmptyStatus === "pass"
        ? `No network security groups exist while ${securityLists.items.length} security lists were readable; emptiness is compliant because no NSG rule can expose a port.${partialNote(nsgs)}`
        : "Manual: no network security groups and no readable security lists were found, so networking posture could not be judged.")
      : permissiveNsgRules.length > 0
        ? `${permissiveNsgRules.length} INGRESS NSG rules allow world access to a sensitive port across ${nsgs.items.length} NSGs.${partialNote(nsgs)}`
        : `No INGRESS NSG rule across ${nsgs.items.length} NSGs allows world access to a sensitive port${nsgRuleErrors > 0 ? `, but ${nsgRuleErrors} NSG rule listings failed` : ""}.${partialNote(nsgs)}`;

  const enabledGateways = internetGateways.items.filter((gateway) => asBoolean(gateway.isEnabled) === true && upper(gateway.lifecycleState) !== "TERMINATED");
  const gatewayEmptyStatus: OciFindingStatus = securityLists.readable && securityLists.items.length > 0 ? "pass" : "manual";
  const gatewayStatus = scopedStatus(internetGateways, enabledGateways.length > 0 ? "warn" : "pass", gatewayEmptyStatus);
  const gatewaySummary = !internetGateways.readable
    ? unreadableSummary("internet gateways", internetGateways, "internet gateway and subnet route associations")
    : internetGateways.items.length === 0
      ? (gatewayEmptyStatus === "pass"
        ? `No internet gateways exist in the inspected compartments while VCN security lists were readable.${partialNote(internetGateways)}`
        : "Manual: no internet gateways and no readable security lists were found; confirm networking scope.")
      : enabledGateways.length > 0
        ? `${enabledGateways.length}/${internetGateways.items.length} internet gateways have isEnabled=true; review the attached subnets' security lists and route tables.${partialNote(internetGateways)}`
        : `${internetGateways.items.length} internet gateways exist but none has isEnabled=true.${partialNote(internetGateways)}`;

  const weakBastions: Array<{ bastionId: string; maxSessionTtlInSeconds?: number; clientCidrBlockAllowList?: unknown[] }> = [];
  const exposedBastions: Array<{ bastionId: string; maxSessionTtlInSeconds?: number; clientCidrBlockAllowList?: unknown[] }> = [];
  const longRunningSessions: Array<{ bastionId: string; sessionId?: string; ageHours?: number; sessionTtlInSeconds?: number }> = [];
  const undatedSessions: Array<{ bastionId: string; sessionId?: string }> = [];
  let bastionDetailErrors = 0;
  for (const bastionSummary of bastions.items.filter(isActiveLifecycle)) {
    const bastionId = asString(bastionSummary.id);
    if (!bastionId) continue;
    const detail = await collect(async () => {
      const bastion = await client.getBastion(bastionId);
      return bastion ? [bastion] : [];
    });
    const bastion = detail.items[0];
    if (!detail.ok || !bastion) {
      bastionDetailErrors += 1;
      errors.push(`bastion get for ${bastionId}: ${detail.error ?? "empty response"}`);
    } else {
      const ttl = asNumber(bastion.maxSessionTtlInSeconds);
      const allowList = asArray(bastion.clientCidrBlockAllowList);
      const worldOpen = allowList.some(cidrIsWorld);
      const ttlTooLong = ttl !== undefined && ttl > BASTION_MAX_TTL_SECONDS;
      if (worldOpen && ttlTooLong) {
        exposedBastions.push({ bastionId, maxSessionTtlInSeconds: ttl, clientCidrBlockAllowList: allowList.slice(0, 10) });
      } else if (ttl === undefined || ttlTooLong || allowList.length === 0 || worldOpen) {
        weakBastions.push({ bastionId, maxSessionTtlInSeconds: ttl, clientCidrBlockAllowList: allowList.slice(0, 10) });
      }
    }
    const sessions = await collect(() => client.listBastionSessions(bastionId));
    if (!sessions.ok) {
      bastionDetailErrors += 1;
      errors.push(`bastion session list for ${bastionId}: ${sessions.error}`);
      continue;
    }
    for (const session of sessions.items.filter(isActiveLifecycle)) {
      const ageDays = daysBetween(now, extractTimestamp(session.timeCreated));
      const ttl = asNumber(session.sessionTtlInSeconds);
      if (ageDays === undefined) {
        undatedSessions.push({ bastionId, sessionId: asString(session.id) });
      } else if (ageDays * 24 > BASTION_SESSION_MAX_HOURS || (ttl !== undefined && ttl > BASTION_MAX_TTL_SECONDS)) {
        longRunningSessions.push({ bastionId, sessionId: asString(session.id), ageHours: Number((ageDays * 24).toFixed(1)), sessionTtlInSeconds: ttl });
      }
    }
  }
  const bastionComputed: OciFindingStatus = longRunningSessions.length > 0 || exposedBastions.length > 0
    ? "fail"
    : weakBastions.length > 0 || bastionDetailErrors > 0 || undatedSessions.length > 0
      ? "warn"
      : "pass";
  const bastionStatus = scopedStatus(bastions, bastionComputed, "manual");
  const bastionSummary = !bastions.readable
    ? unreadableSummary("bastions", bastions, "bastion TTL, CIDR allow lists, and active sessions")
    : bastions.items.length === 0
      ? `Manual: no bastions exist in the ${bastions.seenCompartments} inspected compartments; verify how administrative access reaches private hosts.${partialNote(bastions)}`
      : `${exposedBastions.length} bastions combine a world CIDR allow list (0.0.0.0/0 or ::/0) with TTL above ${BASTION_MAX_TTL_SECONDS}s (fail), ${weakBastions.length} bastions have TTL above ${BASTION_MAX_TTL_SECONDS}s or an empty/world CIDR allow list, ${longRunningSessions.length} ACTIVE sessions exceed ${BASTION_SESSION_MAX_HOURS}h, ${undatedSessions.length} sessions lack timeCreated, ${bastionDetailErrors} detail reads failed.${partialNote(bastions)}`;

  const weakKeys: Array<{ vault?: string; key_name?: string; algorithm?: string; lengthBytes?: number; curveId?: string; daysSinceRotation?: number; reason: string }> = [];
  const undatedKeys: Array<{ vault?: string; key_name?: string }> = [];
  let keysTotal = 0;
  let keysSeen = 0;
  let keysJudged = 0;
  let keyCapHit = false;
  let keyReadErrors = 0;
  let keyDetailErrors = 0;
  for (const vault of vaults.items.filter(isActiveLifecycle)) {
    const keys = await collect(() => client.listKeys(vault));
    if (!keys.ok) {
      keyReadErrors += 1;
      errors.push(`kms key list for vault ${asString(vault.id) ?? "unknown"}: ${keys.error}`);
      continue;
    }
    const enabledKeys = keys.items.filter((item) => upper(item.lifecycleState) === "ENABLED");
    keysTotal += enabledKeys.length;
    for (const key of enabledKeys) {
      if (keysSeen >= maxKeys) {
        keyCapHit = true;
        break;
      }
      keysSeen += 1;
      const keyId = asString(key.id);
      const label = { vault: asString(vault.displayName) ?? asString(vault.id), key_name: asString(key.displayName) ?? keyId };
      if (!keyId) {
        keyDetailErrors += 1;
        errors.push(`kms key get skipped: a KeySummary in vault ${label.vault ?? "unknown"} had no id.`);
        continue;
      }
      const detail = await collect(async () => {
        const record = await client.getKey(vault, keyId);
        return record ? [record] : [];
      });
      const shape = asObject(detail.items[0]?.keyShape);
      if (!detail.ok || !shape) {
        keyDetailErrors += 1;
        errors.push(`kms key get for ${keyId}: ${detail.error ?? "response did not include keyShape"}`);
      } else {
        keysJudged += 1;
        const verdict = judgeKeyShape(shape);
        if (verdict) weakKeys.push({ ...label, ...verdict });
      }
      const versions = await collect(() => client.listKeyVersions(vault, keyId));
      if (!versions.ok) {
        keyReadErrors += 1;
        errors.push(`kms key-version list for ${keyId}: ${versions.error}`);
        undatedKeys.push(label);
        continue;
      }
      const newest = versions.items
        .filter((version) => upper(version.lifecycleState) === "ENABLED")
        .map((version) => extractTimestamp(version.timeCreated))
        .filter((value): value is string => value !== undefined)
        .sort()
        .at(-1);
      const rotationDays = daysBetween(now, newest);
      if (rotationDays === undefined) {
        undatedKeys.push(label);
      } else if (rotationDays > KEY_ROTATION_MAX_DAYS) {
        weakKeys.push({ ...label, algorithm: asString(shape?.algorithm), daysSinceRotation: Number(rotationDays.toFixed(1)), reason: `newest enabled key version older than ${KEY_ROTATION_MAX_DAYS} days` });
      }
    }
  }
  const keyCapNote = keyCapHit ? ` Key cap ${maxKeys} hit: ${keysSeen}/${keysTotal} ENABLED keys inspected; a pass verdict is withheld.` : "";
  let keyComputed: OciFindingStatus;
  if (weakKeys.length > 0) {
    keyComputed = "fail";
  } else if (keysTotal === 0 || keysJudged === 0) {
    keyComputed = "manual";
  } else if (keyDetailErrors > 0 || keyReadErrors > 0 || keyCapHit || undatedKeys.length > 0) {
    keyComputed = "warn";
  } else {
    keyComputed = "pass";
  }
  const keyStatus = scopedStatus(vaults, keyComputed, "manual");
  let keySummary: string;
  if (!vaults.readable) {
    keySummary = unreadableSummary("vaults", vaults, "vault key shapes (algorithm, length, curve) and key version history");
  } else if (vaults.items.length === 0) {
    keySummary = `Manual: no vaults exist in the ${vaults.seenCompartments} inspected compartments; customer-managed key hygiene cannot be judged.${partialNote(vaults)}`;
  } else if (keysTotal === 0) {
    keySummary = `Manual: ${vaults.items.length} vaults exist but no ENABLED keys were listed${keyReadErrors > 0 ? ` and ${keyReadErrors} key list reads failed` : ""}; confirm customer-managed keys are in use.${partialNote(vaults)}`;
  } else if (keysJudged === 0) {
    keySummary = `Manual: none of the ${keysSeen} ENABLED keys could be read with kms key get (${keyDetailErrors} reads failed: ${errors.find((entry) => entry.startsWith("kms key get")) ?? "no keyShape returned"}); grant the read keys permission or collect keyShape.length and curveId manually.${partialNote(vaults)}`;
  } else {
    keySummary = `${keysJudged}/${keysTotal} ENABLED keys judged from Key.keyShape: ${weakKeys.length} weak (AES below ${KEY_MIN_LENGTH_BYTES.AES * 8} bits, RSA below ${KEY_MIN_LENGTH_BYTES.RSA * 8} bits, ECDSA outside the documented curves, or newest enabled version older than ${KEY_ROTATION_MAX_DAYS} days), ${undatedKeys.length} without a dated enabled version, ${keyDetailErrors} key get reads failed, ${keyReadErrors} key or version list reads failed. ${ECDSA_RULE}${keyCapNote}${partialNote(vaults)}`;
  }

  const publicBuckets: Array<{ bucket: string; publicAccessType?: string }> = [];
  const longLivedPars: Array<{ bucket: string; id?: string; expires?: string; daysUntilExpiry?: number }> = [];
  const undatedPars: Array<{ bucket: string; id?: string }> = [];
  let bucketsSeen = 0;
  let bucketCapHit = false;
  let bucketDetailErrors = 0;
  const namespace = await collect(async () => {
    const value = await client.getObjectStorageNamespace();
    return value ? [value] : [];
  });
  const namespaceName = namespace.items[0];
  const buckets = namespaceName
    ? await scoped("os bucket list", (compartmentId) => client.listBuckets(namespaceName, compartmentId))
    : collectionFromSingle<JsonRecord>({ ok: false, items: [], error: namespace.error ?? "Object Storage namespace was empty." });
  errors.push(...buckets.errors);
  if (namespaceName) {
    for (const bucketSummary of buckets.items) {
      const bucketName = asString(bucketSummary.name);
      if (!bucketName) continue;
      if (bucketsSeen >= maxBuckets) {
        bucketCapHit = true;
        break;
      }
      bucketsSeen += 1;
      const detail = await collect(async () => {
        const bucket = await client.getBucket(namespaceName, bucketName);
        return bucket ? [bucket] : [];
      });
      const bucket = detail.items[0];
      if (!detail.ok || !bucket) {
        bucketDetailErrors += 1;
        errors.push(`os bucket get for ${bucketName}: ${detail.error ?? "empty response"}`);
      } else {
        const access = asString(bucket.publicAccessType);
        if (access !== "NoPublicAccess") {
          publicBuckets.push({ bucket: bucketName, publicAccessType: access });
        }
      }
      const pars = await collect(() => client.listPreauthenticatedRequests(namespaceName, bucketName));
      if (!pars.ok) {
        bucketDetailErrors += 1;
        errors.push(`os preauth-request list for ${bucketName}: ${pars.error}`);
        continue;
      }
      for (const par of pars.items) {
        const expires = extractTimestamp(par.timeExpires);
        const daysUntilExpiry = expires ? -1 * (daysBetween(now, expires) ?? 0) : undefined;
        if (!expires || daysUntilExpiry === undefined) {
          undatedPars.push({ bucket: bucketName, id: asString(par.id) });
        } else if (daysUntilExpiry > PAR_LONG_LIVED_DAYS) {
          longLivedPars.push({ bucket: bucketName, id: asString(par.id), expires, daysUntilExpiry: Number(daysUntilExpiry.toFixed(1)) });
        }
      }
    }
  }
  const bucketComputed: OciFindingStatus = publicBuckets.length > 0
    ? "fail"
    : longLivedPars.length > 0 || undatedPars.length > 0 || bucketDetailErrors > 0 || bucketCapHit
      ? "warn"
      : "pass";
  const bucketStatus = scopedStatus(buckets, bucketComputed, "manual");
  const bucketSummary = !buckets.readable
    ? unreadableSummary("Object Storage buckets", buckets, "bucket public access settings and pre-authenticated requests")
    : buckets.items.length === 0
      ? `Manual: no buckets exist in the ${buckets.seenCompartments} inspected compartments; confirm Object Storage is out of scope.${partialNote(buckets)}`
      : `${bucketsSeen} buckets inspected: ${publicBuckets.length} with publicAccessType other than NoPublicAccess, ${longLivedPars.length} PARs expiring more than ${PAR_LONG_LIVED_DAYS} days out, ${undatedPars.length} PARs without timeExpires, ${bucketDetailErrors} detail reads failed.${bucketCapHit ? ` Bucket cap ${maxBuckets} hit: ${bucketsSeen}/${buckets.items.length} buckets inspected; a pass verdict is withheld.` : ""}${partialNote(buckets)}`;

  const findings = [
    finding(
      "OCI-GRD-01",
      "Security list ingress exposure",
      "high",
      securityListStatus,
      securityListSummary,
      ["FedRAMP SC-7", "CMMC L2 3.13.1", "SOC 2 CC6.6", "CIS OCI 2.1", "PCI-DSS 1.3.1", "STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP NW-01"],
      { ...scopeEvidence(securityLists), permissive_security_lists: permissiveSecurityLists.slice(0, 25).map((item) => asString(item.id) ?? asString(item.displayName)) },
    ),
    finding(
      "OCI-GRD-02",
      "Network security group ingress exposure",
      "high",
      nsgStatus,
      nsgSummary,
      ["FedRAMP SC-7", "CMMC L2 3.13.1", "SOC 2 CC6.6", "CIS OCI 2.2", "PCI-DSS 1.3.2", "STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP NW-01"],
      { ...scopeEvidence(nsgs), nsg_rules_seen: nsgRulesSeen, nsg_rules_is_valid_false: nsgInvalidRules, permissive_nsg_rules: permissiveNsgRules.slice(0, 25), nsg_rule_errors: nsgRuleErrors },
    ),
    finding(
      "OCI-GRD-03",
      "Internet gateway exposure",
      "medium",
      gatewayStatus,
      gatewaySummary,
      ["FedRAMP SC-7(5)", "CMMC L2 3.13.6", "SOC 2 CC6.6", "CIS OCI 2.3", "PCI-DSS 1.3.1", "STIG SRG-APP-000383", "IRAP ISM-1417", "ISMAP NW-02"],
      { ...scopeEvidence(internetGateways), enabled_internet_gateways: enabledGateways.slice(0, 25).map((gateway) => asString(gateway.id)) },
    ),
    finding(
      "OCI-GRD-04",
      "Bastion session controls and active sessions",
      "medium",
      bastionStatus,
      bastionSummary,
      ["FedRAMP AC-17", "FedRAMP AC-17(1)", "CMMC L2 3.1.12", "SOC 2 CC6.1", "SOC 2 CC6.2", "CIS OCI 2.8", "CIS OCI 2.9", "PCI-DSS 8.6.1", "STIG SRG-APP-000190", "IRAP ISM-1506", "ISMAP AC-03"],
      { ...scopeEvidence(bastions), exposed_bastions: exposedBastions.slice(0, 25), weak_bastions: weakBastions.slice(0, 25), long_running_sessions: longRunningSessions.slice(0, 25), undated_sessions: undatedSessions.slice(0, 25), detail_errors: bastionDetailErrors },
    ),
    finding(
      "OCI-GRD-05",
      "Vault key rotation and algorithm",
      "medium",
      keyStatus,
      keySummary,
      ["FedRAMP SC-12(1)", "FedRAMP SC-13", "CMMC L2 3.13.10", "CMMC L2 3.13.11", "SOC 2 CC6.1", "CIS OCI 4.1", "CIS OCI 4.2", "PCI-DSS 3.6.4", "PCI-DSS 3.6.1", "STIG SRG-APP-000514", "IRAP ISM-0490", "IRAP ISM-0457", "ISMAP CR-01", "ISMAP CR-02"],
      {
        ...scopeEvidence(vaults),
        keys_total: keysTotal,
        keys_seen: keysSeen,
        keys_judged: keysJudged,
        key_cap: maxKeys,
        key_cap_hit: keyCapHit,
        key_detail_errors: keyDetailErrors,
        key_read_errors: keyReadErrors,
        length_floor_bytes: { ...KEY_MIN_LENGTH_BYTES },
        ecdsa_accepted_curves: [...ECDSA_ACCEPTED_CURVES],
        weak_keys: weakKeys.slice(0, 25),
        undated_keys: undatedKeys.slice(0, 25),
        source: OCI_SURFACE_DOCS.keyDetail.rest,
      },
    ),
    finding(
      "OCI-GRD-06",
      "Object Storage public access and pre-authenticated requests",
      "high",
      bucketStatus,
      bucketSummary,
      ["FedRAMP AC-3", "CMMC L2 3.1.1", "CMMC L2 3.1.2", "SOC 2 CC6.1", "CIS OCI 5.1", "CIS OCI 5.2", "PCI-DSS 1.3.6", "PCI-DSS 7.2.2", "STIG SRG-APP-000033", "IRAP ISM-0405", "ISMAP DS-01", "ISMAP DS-02"],
      { ...scopeEvidence(buckets), buckets_seen: bucketsSeen, buckets_total: buckets.items.length, bucket_cap: maxBuckets, bucket_cap_hit: bucketCapHit, public_buckets: publicBuckets.slice(0, 25), long_lived_pars: longLivedPars.slice(0, 25), undated_pars: undatedPars.slice(0, 25), detail_errors: bucketDetailErrors },
    ),
  ];

  return {
    title: "OCI tenancy guardrails",
    summary: {
      compartments_inspected: securityLists.seenCompartments,
      compartments_total: securityLists.totalCompartments,
      permissive_security_lists: permissiveSecurityLists.length,
      permissive_nsg_rules: permissiveNsgRules.length,
      enabled_internet_gateways: enabledGateways.length,
      exposed_bastions: exposedBastions.length,
      weak_bastions: weakBastions.length,
      long_running_sessions: longRunningSessions.length,
      weak_vault_keys: weakKeys.length,
      public_buckets: publicBuckets.length,
      long_lived_pars: longLivedPars.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

export type OciComputeStorageClient = Pick<
  OciAuditorClient,
  "listCompartments" | "listAvailabilityDomains" | "listInstances" | "listVolumes" | "listBootVolumes"
>;

export async function assessOciComputeAndStorage(
  client: OciComputeStorageClient,
  options: {
    maxCompartments?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const maxCompartments = clampNumber(options.maxCompartments, DEFAULT_MAX_COMPARTMENTS, 1, 500);
  const errors: string[] = [];
  const compartments = await loadCompartmentScope(client);
  if (compartments.error) errors.push(compartments.error);
  const scoped = <T>(name: string, load: (compartmentId: string) => Promise<T[]>) => (compartments.ok
    ? collectAcrossCompartments(name, compartments.items, maxCompartments, load)
    : Promise.resolve(collectionFromSingle<T>({ ok: false, items: [], error: compartments.error })));

  const instances = await scoped("compute instance list", (compartmentId) => client.listInstances(compartmentId));
  const volumes = await scoped("bv volume list", (compartmentId) => client.listVolumes(compartmentId));
  const availabilityDomains = await collect(() => client.listAvailabilityDomains());
  if (availabilityDomains.error) errors.push(availabilityDomains.error);
  const adNames = availabilityDomains.items.map((domain) => asString(domain.name)).filter((name): name is string => Boolean(name));
  const bootVolumes = availabilityDomains.ok && adNames.length > 0
    ? await scoped("bv boot-volume list", async (compartmentId) => {
      const results: JsonRecord[] = [];
      for (const adName of adNames) results.push(...await client.listBootVolumes(compartmentId, adName));
      return results;
    })
    : collectionFromSingle<JsonRecord>({ ok: false, items: [], error: availabilityDomains.error ?? "No availability domains were returned, so boot volumes could not be listed." });
  for (const collection of [instances, volumes, bootVolumes]) errors.push(...collection.errors);

  const liveInstances = instances.items.filter((instance) => upper(instance.lifecycleState) !== "TERMINATED" && upper(instance.lifecycleState) !== "TERMINATING");
  const legacyImdsInstances = liveInstances.filter((instance) => asBoolean(asObject(instance.instanceOptions)?.areLegacyImdsEndpointsDisabled) !== true);
  const imdsComputed: OciFindingStatus = legacyImdsInstances.length > 0 ? "fail" : "pass";
  const imdsStatus = scopedStatus(instances, liveInstances.length === 0 ? "manual" : imdsComputed, "manual");
  const imdsSummary = !instances.readable
    ? unreadableSummary("compute instances", instances, "instance metadata service settings")
    : liveInstances.length === 0
      ? `Manual: no live compute instances exist in the ${instances.seenCompartments} inspected compartments; confirm compute is out of scope.${partialNote(instances)}`
      : legacyImdsInstances.length > 0
        ? `${legacyImdsInstances.length}/${liveInstances.length} live instances do not report instanceOptions.areLegacyImdsEndpointsDisabled=true (false or absent counts as legacy IMDSv1 allowed).${partialNote(instances)}`
        : `All ${liveInstances.length} live instances report instanceOptions.areLegacyImdsEndpointsDisabled=true.${partialNote(instances)}`;

  const judgeVolumes = (collection: OciScopedCollection<JsonRecord>, label: string) => {
    const live = collection.items.filter((volume) => upper(volume.lifecycleState) !== "TERMINATED" && upper(volume.lifecycleState) !== "TERMINATING");
    const oracleManaged = live.filter((volume) => asString(volume.kmsKeyId) === undefined);
    const computed: OciFindingStatus = oracleManaged.length > 0 ? "fail" : "pass";
    const status = scopedStatus(collection, live.length === 0 ? "manual" : computed, "manual");
    const summary = !collection.readable
      ? unreadableSummary(label, collection, `${label} encryption key assignments`)
      : live.length === 0
        ? `Manual: no live ${label} exist in the ${collection.seenCompartments} inspected compartments; confirm block storage is out of scope.${partialNote(collection)}`
        : oracleManaged.length > 0
          ? `${oracleManaged.length}/${live.length} live ${label} have no kmsKeyId and therefore use Oracle-managed encryption keys.${partialNote(collection)}`
          : `All ${live.length} live ${label} carry a customer-managed kmsKeyId.${partialNote(collection)}`;
    return { status, summary, live: live.length, oracleManaged: oracleManaged.slice(0, 25).map((volume) => asString(volume.id) ?? asString(volume.displayName)) };
  };
  const blockVolumes = judgeVolumes(volumes, "block volumes");
  const boot = judgeVolumes(bootVolumes, "boot volumes");

  const findings = [
    finding(
      "OCI-CMP-01",
      "Instance metadata service v2 only",
      "high",
      imdsStatus,
      imdsSummary,
      ["FedRAMP CM-7", "CMMC L2 3.4.7", "SOC 2 CC6.1", "CIS OCI 2.10", "PCI-DSS 2.2.1", "STIG SRG-APP-000141", "IRAP ISM-1418", "ISMAP CM-01"],
      { ...scopeEvidence(instances), live_instances: liveInstances.length, legacy_imds_instances: legacyImdsInstances.slice(0, 25).map((instance) => asString(instance.id) ?? asString(instance.displayName)), source: OCI_SURFACE_DOCS.instances.rest },
    ),
    finding(
      "OCI-CMP-02",
      "Block volume customer-managed key encryption",
      "medium",
      blockVolumes.status,
      blockVolumes.summary,
      ["FedRAMP SC-28", "CMMC L2 3.13.16", "SOC 2 CC6.1", "CIS OCI 4.3", "PCI-DSS 3.4.1", "STIG SRG-APP-000429", "IRAP ISM-1080", "ISMAP CR-03"],
      { ...scopeEvidence(volumes), live_volumes: blockVolumes.live, oracle_managed_volumes: blockVolumes.oracleManaged, source: OCI_SURFACE_DOCS.volumes.rest },
    ),
    finding(
      "OCI-CMP-03",
      "Boot volume customer-managed key encryption",
      "medium",
      boot.status,
      boot.summary,
      ["FedRAMP SC-28", "CMMC L2 3.13.16", "SOC 2 CC6.1", "CIS OCI 4.3", "PCI-DSS 3.4.1", "STIG SRG-APP-000429", "IRAP ISM-1080", "ISMAP CR-03"],
      { ...scopeEvidence(bootVolumes), availability_domains: adNames, live_boot_volumes: boot.live, oracle_managed_boot_volumes: boot.oracleManaged, source: OCI_SURFACE_DOCS.bootVolumes.rest },
    ),
  ];

  return {
    title: "OCI compute and storage posture",
    summary: {
      compartments_inspected: instances.seenCompartments,
      compartments_total: instances.totalCompartments,
      live_instances: liveInstances.length,
      legacy_imds_instances: legacyImdsInstances.length,
      live_block_volumes: blockVolumes.live,
      oracle_managed_block_volumes: blockVolumes.oracleManaged.length,
      live_boot_volumes: boot.live,
      oracle_managed_boot_volumes: boot.oracleManaged.length,
      collection_errors: errors.length,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: OciAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `OCI access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: OciAssessmentResult): string {
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
  const errorLines = result.errors.length > 0
    ? ["", "Collection errors:", ...result.errors.slice(0, 20).map((error) => `- ${error}`)]
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

function countByStatus(findings: OciFinding[]): Record<OciFindingStatus, number> {
  const counts: Record<OciFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(config: OciResolvedConfig, assessments: OciAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const lines = [
    "# OCI Audit Bundle Executive Summary",
    "",
    `Region: ${config.region}`,
    `Tenancy: ${config.tenancyOcid}`,
    `Scope compartment: ${config.compartmentOcid}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual controls: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  const priority = findings.filter((item) => item.status === "fail" || item.status === "warn").slice(0, 10);
  if (priority.length === 0) lines.push("- No failing or warning findings were generated.");
  for (const item of priority) lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`);
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "");
    for (const error of errors.slice(0, 50)) lines.push(`- ${error}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: OciFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# OCI Unified Compliance Matrix",
    "",
    "Status semantics: PASS is only asserted from readable, complete inventories; MANUAL means the surface was unreadable, out of scope, or not exposed by the API.",
    "",
    formatTable(["Finding", "Severity", "Status", "Title", "Mappings"], rows),
    "",
  ].join("\n");
}

const FRAMEWORK_REPORTS: Array<{ prefix: string; path: string; title: string }> = [
  { prefix: "FedRAMP", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { prefix: "CMMC", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC Level 2 Compliance Report" },
  { prefix: "SOC 2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { prefix: "CIS OCI", path: "compliance/cis_oci/cis_oci_benchmark_report.md", title: "CIS OCI Foundations Benchmark Report" },
  { prefix: "PCI-DSS", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { prefix: "STIG", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { prefix: "IRAP", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { prefix: "ISMAP", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

function buildFrameworkReport(title: string, prefix: string, findings: OciFinding[]): string {
  const rows = findings
    .map((item) => ({ item, controls: item.mappings.filter((mapping) => mapping.startsWith(`${prefix} `)) }))
    .filter((entry) => entry.controls.length > 0)
    .map((entry) => [
      entry.controls.map((control) => control.slice(prefix.length + 1)).join(", "),
      entry.item.id,
      entry.item.status.toUpperCase(),
      entry.item.title,
      entry.item.summary,
    ]);
  return [
    `# ${title}`,
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    rows.length > 0
      ? formatTable([`${prefix} control`, "Finding", "Status", "Title", "Summary"], rows)
      : "No findings map to this framework.",
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# OCI Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw OCI CLI JSON snapshots used during this assessment (no credentials are written).",
    "- `analysis/` contains normalized findings (`findings.json`) and one JSON summary per assessment category.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- MANUAL findings mark surfaces that were unreadable, out of scope, or not exposed by the API; never treat them as compliant.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# OCI Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native OCI tools.",
    "",
    "## Contents",
    "",
    "- `QUICK_REFERENCE.md`: reading order and layout",
    "- `compliance/executive_summary.md`: prioritized audit summary",
    "- `compliance/unified_compliance_matrix.md`: framework mapping matrix",
    "- `compliance/<framework>/*.md`: one report per mapped framework",
    "- `analysis/findings.json` and `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/*.json`: raw access inventory and compartment snapshot",
    "- `metadata.json`: non-secret run metadata (the config file path is redacted; only the profile name is kept)",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "The OCI CLI is used for authenticated API transport, but credentials are not written to this bundle: signing keys, auth tokens,",
    "customer secret keys, pre-authenticated request URIs, key material, and secret bundles are dropped or replaced with [redacted] at collection time,",
    "and raw snapshots are projected to the documented fields the verdicts read.",
    "",
  ].join("\n");
}

export async function exportOciAuditBundle(
  client: OciAccessClient & OciIdentityClient & OciLoggingClient & OciGuardrailClient & OciComputeStorageClient,
  config: OciResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<OciAuditBundleResult> {
  const access = await checkOciAccess(client);
  const identity = await assessOciIdentity(client, {
    staleDays: options.stale_days,
    maxKeys: options.max_keys,
    maxPolicies: options.max_policies,
    maxCompartments: options.max_compartments,
  });
  const loggingDetection = await assessOciLoggingDetection(client, {
    lookbackDays: options.lookback_days,
    maxCompartments: options.max_compartments,
  });
  const tenancyGuardrails = await assessOciTenancyGuardrails(client, {
    maxCompartments: options.max_compartments,
    maxBuckets: options.max_buckets,
    maxKeys: options.max_keys,
  });
  const computeStorage = await assessOciComputeAndStorage(client, {
    maxCompartments: options.max_compartments,
  });
  const compartments = await collect(() => client.listCompartments());

  const assessments = [identity, loggingDetection, tenancyGuardrails, computeStorage];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];
  if (compartments.error) errors.push(compartments.error);
  const targetName = safeDirName(`${config.tenancyOcid}-${config.region}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  const bundleAccess: OciAccessCheckResult = {
    ...access,
    notes: access.notes.map((note) => note.replace(/^Using OCI config .* profile /, `Using OCI config ${REDACTED_MARKER} profile `)),
  };
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    config_file: REDACTED_MARKER,
    profile: config.profile,
    region: config.region,
    tenancy_ocid: config.tenancyOcid,
    compartment_ocid: config.compartmentOcid,
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      max_keys: options.max_keys ?? DEFAULT_MAX_KEYS,
      max_policies: options.max_policies ?? DEFAULT_MAX_POLICIES,
      max_compartments: options.max_compartments ?? DEFAULT_MAX_COMPARTMENTS,
      max_buckets: options.max_buckets ?? DEFAULT_MAX_BUCKETS,
      lookback_days: options.lookback_days ?? DEFAULT_LOOKBACK_DAYS,
    },
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(redactSensitiveValues(bundleAccess)));
  await writeSecureTextFile(outputDir, "core_data/compartments.json", serializeJson(compartments.items.map(projectCompartmentSnapshot)));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/logging-detection.json", serializeJson(loggingDetection));
  await writeSecureTextFile(outputDir, "analysis/tenancy-guardrails.json", serializeJson(tenancyGuardrails));
  await writeSecureTextFile(outputDir, "analysis/compute-storage.json", serializeJson(computeStorage));
  await writeSecureTextFile(outputDir, "analysis/summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeSecureTextFile(outputDir, report.path, buildFrameworkReport(report.title, report.prefix, findings));
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
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
    config_file: asString(value.config_file),
    profile: asString(value.profile),
    region: asString(value.region),
    tenancy_ocid: asString(value.tenancy_ocid),
    compartment_ocid: asString(value.compartment_ocid),
  };
}

function normalizeScopeArgs(args: unknown): ScopeArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_compartments: asNumber(value.max_compartments),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopeArgs(args),
    stale_days: asNumber(value.stale_days),
    max_keys: asNumber(value.max_keys),
    max_policies: asNumber(value.max_policies),
  };
}

function normalizeLoggingArgs(args: unknown): LoggingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopeArgs(args),
    lookback_days: asNumber(value.lookback_days),
  };
}

function normalizeGuardrailArgs(args: unknown): GuardrailArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeScopeArgs(args),
    max_buckets: asNumber(value.max_buckets),
    max_keys: asNumber(value.max_keys),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    ...normalizeGuardrailArgs(args),
    lookback_days: asNumber(value.lookback_days),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): OciAuditorClient {
  return new OciAuditorClient(resolveOciConfiguration(args));
}

const authParams = {
  config_file: Type.Optional(Type.String({ description: "OCI config file path. Defaults to OCI_CONFIG_FILE or ~/.oci/config." })),
  profile: Type.Optional(Type.String({ description: `OCI config profile. Defaults to OCI_CLI_PROFILE or ${DEFAULT_PROFILE}.` })),
  region: Type.Optional(Type.String({ description: `OCI region override. Defaults to OCI_REGION, config profile region, or ${DEFAULT_REGION}.` })),
  tenancy_ocid: Type.Optional(Type.String({ description: "Explicit OCI tenancy OCID. Defaults to OCI_TENANCY_OCID or config profile tenancy." })),
  compartment_ocid: Type.Optional(Type.String({ description: "Compartment OCID to scope audit event and access-check reads. Defaults to OCI_COMPARTMENT_OCID or the tenancy OCID." })),
};

const scopeParams = {
  ...authParams,
  max_compartments: Type.Optional(Type.Number({ description: `Maximum accessible compartments to inspect for compartment-scoped resources. Defaults to ${DEFAULT_MAX_COMPARTMENTS}; hitting the cap withholds pass verdicts.`, default: DEFAULT_MAX_COMPARTMENTS })),
};

export function registerOciTools(pi: any): void {
  pi.registerTool({
    name: "oci_check_access",
    label: "Check OCI audit access",
    description:
      "Validate OCI CLI-backed read-only access across IAM, Audit, Cloud Guard, Networking, Vault, Object Storage, and Compute surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkOciAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "oci_check_access", ...result });
      } catch (error) {
        return errorResult(
          `OCI access check failed: ${errorMessage(error)}`,
          { tool: "oci_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_identity",
    label: "Assess OCI identity posture",
    description:
      "Assess OCI IAM posture across password policy strength, MFA coverage, API and secret credential rotation, broad policies, and compartment hierarchy depth.",
    parameters: Type.Object({
      ...scopeParams,
      stale_days: Type.Optional(Type.Number({ description: "Credential staleness threshold in days. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum API/secret credentials to inspect. Defaults to 200.", default: 200 })),
      max_policies: Type.Optional(Type.Number({ description: "Maximum IAM policies to inspect for broad statements. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessOciIdentity(createClient(args), {
          staleDays: args.stale_days,
          maxKeys: args.max_keys,
          maxPolicies: args.max_policies,
          maxCompartments: args.max_compartments,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `OCI identity assessment failed: ${errorMessage(error)}`,
          { tool: "oci_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_logging_detection",
    label: "Assess OCI logging and detection",
    description:
      "Assess OCI Cloud Guard enablement, targets, problems, and responder recipes, audit log retention, audit event visibility, and event rule coverage for critical tenancy changes.",
    parameters: Type.Object({
      ...scopeParams,
      lookback_days: Type.Optional(Type.Number({ description: "Audit event lookback window in days. Defaults to 7.", default: 7 })),
    }),
    prepareArguments: normalizeLoggingArgs,
    async execute(_toolCallId: string, args: LoggingArgs) {
      try {
        const result = await assessOciLoggingDetection(createClient(args), {
          lookbackDays: args.lookback_days,
          maxCompartments: args.max_compartments,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_logging_detection", ...result });
      } catch (error) {
        return errorResult(
          `OCI logging and detection assessment failed: ${errorMessage(error)}`,
          { tool: "oci_assess_logging_detection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_tenancy_guardrails",
    label: "Assess OCI tenancy guardrails",
    description:
      "Assess OCI network, bastion, vault, and object-storage guardrails across accessible compartments, including sensitive-port exposure, bastion controls, vault key hygiene, and public bucket risk.",
    parameters: Type.Object({
      ...scopeParams,
      max_buckets: Type.Optional(Type.Number({ description: `Maximum buckets to fetch for public access and PAR checks. Defaults to ${DEFAULT_MAX_BUCKETS}.`, default: DEFAULT_MAX_BUCKETS })),
      max_keys: Type.Optional(Type.Number({ description: `Maximum ENABLED vault keys to fetch with kms key get across all vaults. Defaults to ${DEFAULT_MAX_KEYS}; hitting the cap withholds pass.`, default: DEFAULT_MAX_KEYS })),
    }),
    prepareArguments: normalizeGuardrailArgs,
    async execute(_toolCallId: string, args: GuardrailArgs) {
      try {
        const result = await assessOciTenancyGuardrails(createClient(args), {
          maxCompartments: args.max_compartments,
          maxBuckets: args.max_buckets,
          maxKeys: args.max_keys,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_tenancy_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `OCI tenancy guardrail assessment failed: ${errorMessage(error)}`,
          { tool: "oci_assess_tenancy_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_compute_and_storage",
    label: "Assess OCI compute and storage",
    description:
      "Assess OCI compute instances for IMDSv2-only metadata access and block and boot volumes for customer-managed key encryption across accessible compartments and availability domains.",
    parameters: Type.Object(scopeParams),
    prepareArguments: normalizeScopeArgs,
    async execute(_toolCallId: string, args: ScopeArgs) {
      try {
        const result = await assessOciComputeAndStorage(createClient(args), {
          maxCompartments: args.max_compartments,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_compute_and_storage", ...result });
      } catch (error) {
        return errorResult(
          `OCI compute and storage assessment failed: ${errorMessage(error)}`,
          { tool: "oci_assess_compute_and_storage" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_export_audit_bundle",
    label: "Export OCI audit bundle",
    description:
      "Export an OCI audit package with access checks, identity, logging and detection, tenancy guardrail, and compute and storage findings, compliance reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...scopeParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      stale_days: Type.Optional(Type.Number({ description: "Credential staleness threshold in days. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum API/secret credentials to inspect and, for the guardrail assessment, maximum ENABLED vault keys fetched with kms key get. Defaults to 200; hitting either cap withholds pass.", default: 200 })),
      max_policies: Type.Optional(Type.Number({ description: "Maximum IAM policies to inspect for broad statements. Defaults to 500.", default: 500 })),
      max_buckets: Type.Optional(Type.Number({ description: `Maximum buckets to fetch. Defaults to ${DEFAULT_MAX_BUCKETS}.`, default: DEFAULT_MAX_BUCKETS })),
      lookback_days: Type.Optional(Type.Number({ description: "Audit event lookback window in days. Defaults to 7.", default: 7 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveOciConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportOciAuditBundle(new OciAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "OCI audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "oci_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `OCI audit bundle export failed: ${errorMessage(error)}`,
          { tool: "oci_export_audit_bundle" },
        );
      }
    },
  });
}
