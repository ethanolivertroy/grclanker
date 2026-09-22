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
const DEFAULT_ENVIRONMENT_INVENTORY_LIMIT = 1000;
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
// Only 8081 (http.port) and 8082 (https.port) are exposed externally by the shared load balancer. 8091 and 8092 are the
// dedicated load balancer back-end ports whose default rules are scoped to the local VPC CIDR, so open ingress on them fails.
const CLOUDHUB_STANDARD_INGRESS_PORTS = new Set([8081, 8082]);

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
// Tested against key names normalized to lowercase with underscores, hyphens, and spaces removed, so camelCase and
// snake_case variants (apiKey, api_key, signing-key) all match.
const SECRET_KEY_PATTERN = /secret|password|passwd|token|privatekey|authorization|apikey|accesskey|credential|textkey|signingkey|community|hash|presharedkey|registrationkey/;
// Keys whose string values are URLs (alert webhookUrl, callback and redirect targets); the exported value keeps scheme and host only
// because tokens travel in the path and query of such targets.
const URL_KEY_PATTERN = /(url|uri)s?$/;
const REDACTED = "[REDACTED]";
const MIN_REMEMBERED_SECRET_LENGTH = 4;
const KNOWN_SECRETS = new Set<string>();
const URL_IN_TEXT_PATTERN = /\b(https?:\/\/)(?:([^\s/?#@"'<>]+)@)?([^\s/?#"'<>]+)([^\s?#"'<>]*)(\?[^\s#"'<>]*)?(#[^\s"'<>]*)?/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const AUTHORIZATION_VALUE_PATTERN = /\b(bearer|basic|digest|negotiate|ntlm)\s+([A-Za-z0-9\-._~+/!]{8,}=*)/gi;
const SECRET_ASSIGNMENT_PATTERN = /\b([\w-]*(?:session|token|secret|password|passwd|pwd|api[_-]?key|apikey|credential|assertion|signature|sid|jsessionid)[\w-]*=)([^\s"'&;,<>]+)/gi;
const SECRET_FIELD_PATTERN = /(?<![\w/.-])((?:api[\s_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|session[_-]?token|bearer[_-]?token|token|client[_-]?secret|secret|password|passwd|pwd|authorization|set-cookie|cookie|session[_-]?id|jsessionid|sid|assertion|signature|credential)["']?\s*:\s*["']?)([^\s"'&;,<>]+)/gi;
const MAX_REDACTION_DEPTH = 32;
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
  servername?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  authorized?: boolean;
  authorizationError?: string;
}

export type MulesoftCertificateProbe = (host: string, timeoutMs: number, servername?: string) => Promise<MulesoftCertificateSummary>;

export interface MulesoftPage {
  items: JsonRecord[];
  total?: number;
  truncated: boolean;
  limit: number;
}

export type MulesoftListResult = JsonRecord[] | MulesoftPage;

/**
 * The only field carrying response text is the message (status line, method and path, and either
 * Anypoint's documented message, error_description, error, or errors[0].message, or the opaque-body
 * note); it is scrubbed in the constructor so no throw site can hand an unredacted body to a catch
 * block. `endpoint` is the request path, recorded so a not-collected marker can name the request.
 */
export class MulesoftApiError extends Error {
  readonly status: number;
  readonly endpoint?: string;

  constructor(status: number, message: string, endpoint?: string) {
    super(scrubErrorText(message));
    this.name = "MulesoftApiError";
    this.status = status;
    this.endpoint = endpoint;
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

/**
 * The single sink every recorded error string passes through (collect() dataset errors and the errors
 * arrays, access-check surfaces, _errors.log); it re-applies the redaction pass so a message built
 * outside MulesoftApiError cannot bypass it.
 */
function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

/**
 * The unanchored redaction pass every error string receives, once in MulesoftApiError and again at
 * the sink (errorMessage): every secret any client in this process has seen, then credential shapes
 * (URL userinfo, query strings, and fragments anywhere in the text, JWT-shaped strings, Authorization
 * scheme values, and cookie, query, or field assignments whose name suggests a credential).
 */
function scrubErrorText(text: string, secrets: Iterable<string | undefined> = KNOWN_SECRETS): string {
  let scrubbed = text;
  for (const secret of secrets) {
    if (secret && secret.length >= MIN_REMEMBERED_SECRET_LENGTH) scrubbed = scrubbed.split(secret).join(REDACTED);
  }
  return scrubbed
    .replace(URL_IN_TEXT_PATTERN, (_match, scheme: string, userinfo: string | undefined, host: string, path: string, query?: string, fragment?: string) =>
      `${scheme}${userinfo ? `${REDACTED}@` : ""}${host}${path}${query ? `?${REDACTED}` : ""}${fragment ? `#${REDACTED}` : ""}`)
    .replace(JWT_PATTERN, REDACTED)
    .replace(AUTHORIZATION_VALUE_PATTERN, (match: string, scheme: string, value: string) => (/^[a-z]+$/.test(value) ? match : `${scheme} ${REDACTED}`))
    .replace(SECRET_ASSIGNMENT_PATTERN, (_match, assignment: string) => `${assignment}${REDACTED}`)
    .replace(SECRET_FIELD_PATTERN, (_match, field: string) => `${field}${REDACTED}`);
}

function rememberSecrets(...values: Array<string | undefined>): void {
  for (const value of values) {
    if (value && value.length >= MIN_REMEMBERED_SECRET_LENGTH) KNOWN_SECRETS.add(value);
  }
}

/** A URL reduced to scheme and host: alert webhooks and callback targets carry tokens in their path and query. */
export function reduceUrl(value: string): string {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return REDACTED;
  }
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

// Runtime Manager (ARM) wraps each server and alert as {"data":[{"data":{...}}]}; merge the inner record over the outer one.
function unwrapDataEnvelope(items: JsonRecord[]): JsonRecord[] {
  return items.map((item) => {
    const inner = asObject(item.data);
    if (!inner) return item;
    const outer = Object.fromEntries(Object.entries(item).filter(([key]) => key !== "data"));
    return { ...outer, ...inner };
  });
}

function isPage(value: unknown): value is MulesoftPage {
  const object = asObject(value);
  return object !== undefined && Array.isArray(object.items) && typeof object.truncated === "boolean";
}

export function toPage(value: MulesoftListResult | undefined): MulesoftPage {
  if (isPage(value)) return value;
  const items = asRecordArray(value ?? []);
  return { items, total: items.length, truncated: false, limit: items.length };
}

function capPage(page: MulesoftPage, limit: number): MulesoftPage {
  if (page.items.length <= limit) return page;
  return { items: page.items.slice(0, limit), total: page.total ?? page.items.length, truncated: true, limit };
}

function pageTotalLabel(page: MulesoftPage): string {
  return page.total === undefined ? "an unknown total" : `${page.total} total`;
}

function truncationNote(label: string, page: MulesoftPage): string | undefined {
  if (!page.truncated) return undefined;
  return `${label} list truncated at ${page.items.length} of ${pageTotalLabel(page)}`;
}

function isSecretKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(key.toLowerCase().replace(/[-_\s]/g, ""));
}

function isUrlKey(key: string): boolean {
  return URL_KEY_PATTERN.test(key.toLowerCase().replace(/[-_\s]/g, ""));
}

function redactUrlQuery(text: string): string {
  if (!/^https?:\/\/[^?]+\?/i.test(text)) return text;
  return text.replace(/([?&])([^=&#]+)=([^&#]*)/g, (match, separator: string, key: string) => (
    isSecretKey(key) ? `${separator}${key}=${REDACTED}` : match
  ));
}

function isSecretNamedPair(object: JsonRecord): boolean {
  if (!("value" in object)) return false;
  const name = asString(object.name) ?? asString(object.key);
  return name !== undefined && isSecretKey(name);
}

function redactedValue(entry: unknown): unknown {
  return entry === null || entry === undefined || typeof entry === "boolean" ? entry : REDACTED;
}

const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/** The value under a URL-named key: absolute URLs (alone or in a list) are reduced to scheme and host; anything else is redacted as usual. */
function reducedUrlValue(entry: unknown, depth: number): unknown {
  if (typeof entry === "string") return ABSOLUTE_URL_PATTERN.test(entry) ? reduceUrl(entry) : redactUrlQuery(entry);
  if (Array.isArray(entry)) return entry.map((item) => reducedUrlValue(item, depth + 1));
  return redactSnapshot(entry, depth + 1);
}

export function redactSnapshot(value: unknown, depth = 0): unknown {
  if (depth > MAX_REDACTION_DEPTH) return REDACTED;
  if (typeof value === "string") return redactUrlQuery(value);
  if (Array.isArray(value)) return value.map((item) => redactSnapshot(item, depth + 1));
  const object = asObject(value);
  if (!object) return value;
  const secretPair = isSecretNamedPair(object);
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    output[key] = isSecretKey(key) || (secretPair && key === "value")
      ? redactedValue(entry)
      : isUrlKey(key)
        ? reducedUrlValue(entry, depth)
        : redactSnapshot(entry, depth + 1);
  }
  return output;
}

/** Kept for callers that pass explicit secrets; it is the same pass as scrubErrorText over those secrets plus every remembered one. */
export function redactSecretText(text: string, secrets: Array<string | undefined> = []): string {
  return scrubErrorText(text, [...secrets, ...KNOWN_SECRETS]);
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

const MAX_AUDIT_DIR_SUFFIX = 50;

export function auditBundleZipPath(outputDir: string): string {
  return `${outputDir}.zip`;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const candidates = [preferredName, ...Array.from({ length: MAX_AUDIT_DIR_SUFFIX - 1 }, (_, index) => `${preferredName}-${index + 2}`)];
  for (const name of candidates) {
    const candidate = resolveSecureOutputPath(root, name);
    if (existsSync(candidate) || existsSync(auditBundleZipPath(candidate))) continue;
    mkdirSync(candidate, { recursive: true, mode: 0o700 });
    await chmod(candidate, 0o700);
    return candidate;
  }
  throw new Error(`Unable to allocate an unused output directory under ${root}: ${MAX_AUDIT_DIR_SUFFIX} bundle names are already taken.`);
}

async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, content, { encoding: "utf8", mode: 0o600 });
}

async function createZipArchive(sourceDir: string, zipPath: string): Promise<void> {
  if (existsSync(zipPath)) {
    throw new Error(`Refusing to overwrite existing archive: ${zipPath}`);
  }
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

/**
 * A non-JSON error body (a proxy or WAF page) is described by shape only; its text is never
 * copied into an error string because those strings land in the bundle's error log.
 */
function anypointErrorDetail(payload: unknown, response: Response, rawText: string): string {
  const object = asObject(payload);
  const documented = object
    ? [
      asString(object.message),
      asString(object.error_description),
      asString(object.error),
      asString(getNestedValue(object, ["errors", "0", "message"])),
    ].filter((item): item is string => Boolean(item)).join("; ")
    : "";
  const detail = documented || describeOpaqueBody(response, rawText, payload === undefined ? "non-JSON body" : "JSON body without a recognized error field");
  return detail ? `: ${detail}` : "";
}

/**
 * A response body without a recognizable Anypoint error field is described by content type and byte
 * length only, whatever its content type; its text is never sliced into an error string.
 */
function describeOpaqueBody(response: Response, rawText: string, kind: string): string {
  if (rawText.length === 0) return "";
  const contentType = response.headers.get("content-type")?.split(";")[0]?.trim() || "unknown content type";
  return `${kind} (${contentType}, ${Buffer.byteLength(rawText, "utf8")} bytes)`;
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

// rejectUnauthorized stays false so a certificate with an untrusted or incomplete chain can still be read and dated;
// socket.authorized and authorizationError record whether the chain validated against the auditor's trust store.
export function defaultCertificateProbe(host: string, timeoutMs: number, servername = host, port = 443): Promise<MulesoftCertificateSummary> {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = tlsConnect({ host, port, servername, rejectUnauthorized: false }, () => {
      const certificate = socket.getPeerCertificate();
      const rawAuthorizationError: unknown = socket.authorizationError;
      socket.end();
      resolvePromise({
        host,
        servername,
        subject: certificateName(certificate.subject),
        issuer: certificateName(certificate.issuer),
        validFrom: asString(certificate.valid_from),
        validTo: asString(certificate.valid_to),
        authorized: socket.authorized === true,
        authorizationError: rawAuthorizationError
          ? (rawAuthorizationError instanceof Error ? rawAuthorizationError.message : String(rawAuthorizationError))
          : undefined,
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
    rememberSecrets(config.clientSecret, config.password, config.token);
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
            + anypointErrorDetail(payload, response, rawText),
          ),
          pathLabel,
        );
      } catch (error) {
        if (error instanceof MulesoftApiError) throw error;
        if (attempt < this.maxRetries) {
          await this.sleepImpl(this.retryDelayMs(undefined, attempt));
          continue;
        }
        if (error instanceof Error && error.name === "AbortError") {
          throw new Error(`Anypoint request to ${method} ${pathLabel} timed out after ${this.config.timeoutMs} ms`);
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
    rememberSecrets(accessToken);
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

  async listOffset(path: string, options: ListOptions = {}): Promise<MulesoftPage> {
    const limit = clampNumber(options.limit, DEFAULT_LIST_LIMIT, 1, 100_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_SIZE, 1, 250);
    const collectionKeys = options.collectionKeys ?? ["data"];
    const items: JsonRecord[] = [];
    let offset = 0;
    let total: number | undefined;
    let truncated = false;

    for (;;) {
      const requested = Math.min(pageSize, limit - items.length);
      const payload = await this.get(path, { ...(options.query ?? {}), limit: requested, offset }, options.headers);
      const pageItems = extractCollection(payload, collectionKeys);
      total = asNumber(asObject(payload)?.total) ?? total;
      items.push(...pageItems.slice(0, limit - items.length));
      offset += pageItems.length;

      if (pageItems.length === 0) {
        // An empty page below a server-reported total means the remainder was never delivered.
        truncated = total !== undefined && offset < total;
        break;
      }
      if (total !== undefined && offset >= total) break;
      if (items.length >= limit) {
        truncated = total !== undefined
          ? total > items.length
          : await this.hasMoreItems(path, options, collectionKeys, offset);
        break;
      }
    }

    return { items, total, truncated, limit };
  }

  private async hasMoreItems(path: string, options: ListOptions, collectionKeys: string[], offset: number): Promise<boolean> {
    const payload = await this.get(path, { ...(options.query ?? {}), limit: 1, offset }, options.headers);
    return extractCollection(payload, collectionKeys).length > 0;
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

  async listIdentityProviders(): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/identityProviders"));
  }

  async getIdentityProviderSettings(): Promise<JsonRecord> {
    return asObject(await this.get(this.orgPath("/identityProviderSettings"))) ?? {};
  }

  async listMembers(limit = DEFAULT_USER_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/members"), { limit });
  }

  async listMfaExemptUsers(limit = DEFAULT_USER_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/users"), { query: { mfaVerificationExcluded: true }, limit });
  }

  async listRoleGroups(limit = DEFAULT_LIST_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/rolegroups"), { limit });
  }

  async listRoleGroupRoles(roleGroupId: string, limit = DEFAULT_LIST_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath(`/rolegroups/${encodeURIComponent(roleGroupId)}/roles`), { limit });
  }

  async listRoleGroupUsers(roleGroupId: string, limit = DEFAULT_USER_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath(`/rolegroups/${encodeURIComponent(roleGroupId)}/users`), { limit });
  }

  async listEnvironments(limit = DEFAULT_ENVIRONMENT_INVENTORY_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/environments"), { limit });
  }

  // hide_managed defaults to true on the Access Management API and would silently drop managed connected apps from the inventory.
  async listConnectedApplications(limit = DEFAULT_LIST_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath("/connectedApplications"), { query: { includeUsage: true, hide_managed: false }, limit });
  }

  async listConnectedApplicationScopes(clientId: string): Promise<MulesoftPage> {
    return this.listOffset(this.orgPath(`/connectedApplications/${encodeURIComponent(clientId)}/scopes`));
  }

  async listManagedApis(environmentId: string, limit = DEFAULT_API_LIMIT): Promise<MulesoftPage> {
    const assets = await this.listOffset(
      `/apimanager/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}/apis`,
      { collectionKeys: ["assets"], limit },
    );
    const apis: JsonRecord[] = [];
    for (const asset of assets.items) {
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
    return {
      items: apis.slice(0, limit),
      total: assets.truncated || apis.length > limit ? undefined : apis.length,
      truncated: assets.truncated || apis.length > limit,
      limit,
    };
  }

  async listApiPolicies(environmentId: string, apiId: string): Promise<JsonRecord[]> {
    const payload = await this.get(
      `/apimanager/api/v1/organizations/${encodeURIComponent(this.config.organizationId)}/environments/${encodeURIComponent(environmentId)}/apis/${encodeURIComponent(apiId)}/policies`,
      { fullInfo: false },
    );
    return extractCollection(payload, ["policies", "data"]);
  }

  async listExchangeAssets(limit = DEFAULT_LIST_LIMIT): Promise<MulesoftPage> {
    return this.listOffset("/exchange/api/v2/assets/search", { limit, pageSize: 100 });
  }

  // retrieveStatistics defaults to false, which leaves workers.recentStatistics (CPU) out of every application record.
  async listCloudhubApplications(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/cloudhub/api/v2/applications", { retrieveStatistics: true }, this.environmentHeaders(environmentId)));
  }

  async listCloudhubAlerts(environmentId: string): Promise<JsonRecord[]> {
    return extractCollection(await this.get("/cloudhub/api/v2/alerts", {}, this.environmentHeaders(environmentId)));
  }

  async listVpcs(limit = DEFAULT_VPC_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(`/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/vpcs`, { limit });
  }

  async getVpc(vpcId: string): Promise<JsonRecord> {
    return asObject(await this.get(`/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/vpcs/${encodeURIComponent(vpcId)}`)) ?? {};
  }

  async listLoadBalancers(limit = DEFAULT_LOAD_BALANCER_LIMIT): Promise<MulesoftPage> {
    return this.listOffset(
      `/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/loadbalancers`,
      { limit, query: { shortFormat: false } },
    );
  }

  // The per-DLB resource is where docs.mulesoft.com/cloudhub/lb-cert-validation documents defaultCipherSuite.
  async getLoadBalancer(vpcId: string, loadBalancerId: string): Promise<JsonRecord> {
    return asObject(await this.get(
      `/cloudhub/api/organizations/${encodeURIComponent(this.config.organizationId)}/vpcs/${encodeURIComponent(vpcId)}/loadbalancers/${encodeURIComponent(loadBalancerId)}`,
    )) ?? {};
  }

  async probeCertificate(host: string, servername?: string): Promise<MulesoftCertificateSummary> {
    return this.certificateProbe(host, this.config.timeoutMs, servername ?? host);
  }

  async listHybridServers(environmentId: string): Promise<JsonRecord[]> {
    return unwrapDataEnvelope(extractCollection(await this.get("/hybrid/api/v1/servers", {}, this.environmentHeaders(environmentId))));
  }

  async listHybridAlerts(environmentId: string): Promise<JsonRecord[]> {
    return unwrapDataEnvelope(extractCollection(await this.get("/hybrid/api/v1/alerts", {}, this.environmentHeaders(environmentId))));
  }

  async listAuditPlatforms(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(`/audit/v2/organizations/${encodeURIComponent(this.config.organizationId)}/platforms`));
  }

  async getAuditRetentionSettings(): Promise<JsonRecord[]> {
    return extractCollection(await this.get(`/audit/v2/organizations/${encodeURIComponent(this.config.organizationId)}/retentionSettings`));
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
  "getResolvedConfig" | "getOrganizationHierarchy" | "listEnvironments" | "listManagedApis" | "listApiPolicies" | "listExchangeAssets"
>;

type RuntimeClient = Pick<
  MulesoftApiClient,
  | "getResolvedConfig"
  | "getOrganizationHierarchy"
  | "listEnvironments"
  | "listCloudhubApplications"
  | "listVpcs"
  | "getVpc"
  | "listLoadBalancers"
  | "getLoadBalancer"
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
  | "getOrganizationHierarchy"
  | "listEnvironments"
  | "listAuditPlatforms"
  | "getAuditRetentionSettings"
  | "queryAuditLogs"
  | "listCloudhubAlerts"
  | "listHybridAlerts"
  | "listCloudhubApplications"
>;

type AccessClient = IdentityClient & ApiGatewayClient & RuntimeClient & AuditClient & Pick<MulesoftApiClient, "getCurrentUser">;

export type MulesoftBundleClient = AccessClient;

interface Collected<T> {
  label: string;
  value: T;
  error?: string;
  httpStatus?: number;
  /** Path of the request that failed; absent when the read succeeded or no request was made. */
  endpoint?: string;
  /** Set when the read was never requested because its parent list failed; names the parent and its failure. */
  skipped?: string;
  /** Label of the parent source whose failure caused the skip. */
  skippedParent?: string;
}

/**
 * Written to core_data (and into each category's snapshots) in place of a dataset that was denied,
 * errored, or never requested, so a bundle consumer cannot mistake a failed read for an empty
 * inventory. A readable dataset with no items keeps its array shape.
 */
export interface NotCollectedMarker {
  collected: false;
  dataset: string;
  status: number | null;
  endpoint: string | null;
  error: string;
}

/** A dataset assembled from several reads of which some failed: the collected items plus one entry per failed read. */
export interface PartiallyCollectedSnapshot {
  collected: "partial";
  dataset: string;
  failed_reads: Array<{ read: string; status: number | null; endpoint: string | null; error: string }>;
  items: unknown;
}

function sourceCollected(source: Collected<unknown>): boolean {
  return !source.error && !source.skipped;
}

function sourceFailure(source: Collected<unknown>): string {
  return source.error ?? `not requested: ${source.skipped}`;
}

function notCollectedMarker(source: Collected<unknown>): NotCollectedMarker {
  return {
    collected: false,
    dataset: source.label,
    status: source.httpStatus ?? null,
    endpoint: source.endpoint ?? null,
    error: sourceFailure(source),
  };
}

/**
 * The exported view of a dataset: the redacted value when its source was read, a not-collected marker
 * when it was denied, errored, or skipped, and a partial snapshot when it merges several reads of which
 * only some failed (so the items that were read are kept beside the failures).
 */
export function snapshotOf(source: Collected<unknown>, value: unknown, reads: Array<Collected<unknown>> = []): unknown {
  if (sourceCollected(source)) return redactSnapshot(value);
  const succeeded = reads.filter(sourceCollected);
  if (succeeded.length === 0) return notCollectedMarker(source);
  // When every child read succeeded the failure sits on the merged source itself (an unread parent).
  const failedReads = reads.some((read) => !sourceCollected(read)) ? reads.filter((read) => !sourceCollected(read)) : [source];
  return {
    collected: "partial",
    dataset: source.label,
    failed_reads: failedReads.map((read) => ({
      read: read.label,
      status: read.httpStatus ?? null,
      endpoint: read.endpoint ?? null,
      error: sourceFailure(read),
    })),
    items: redactSnapshot(value),
  } satisfies PartiallyCollectedSnapshot;
}

/** A count, list, or flag derived from one or more reads renders null when any of them was not answered. */
function derived<T>(value: T, ...sources: Array<Collected<unknown>>): T | null {
  return sources.every(sourceCollected) ? value : null;
}

/**
 * The partial-view notes of a summary: the notes when there are any, null when a source was not read at
 * all (the view is absent rather than partial), and [] only when every source was read completely.
 */
function partialViewOf(notes: Array<string | undefined>, ...sources: Array<Collected<unknown>>): string[] | null {
  const present = notes.filter((note): note is string => Boolean(note));
  if (present.length > 0) return present;
  return sources.every(sourceCollected) ? [] : null;
}

interface Verdict {
  status: MulesoftFindingStatus;
  summary: string;
  evidence?: JsonRecord;
}

interface EvaluationInputs {
  primary: Array<Collected<unknown>>;
  secondary?: Array<Collected<unknown>>;
  partial?: Array<string | undefined>;
}

async function collect<T>(label: string, fallback: T, load: () => Promise<T>, errors: string[]): Promise<Collected<T>> {
  try {
    return { label, value: await load() };
  } catch (error) {
    const message = errorMessage(error);
    errors.push(`${label}: ${message}`);
    return {
      label,
      value: fallback,
      error: message,
      httpStatus: error instanceof MulesoftApiError ? error.status : undefined,
      endpoint: error instanceof MulesoftApiError ? error.endpoint : undefined,
    };
  }
}

/** A read that was never requested because the list it depends on failed; the reason names that parent. */
function skippedSource<T>(label: string, parent: Collected<unknown>, fallback: T): Collected<T> {
  const reason = parent.error
    ? `the ${parent.label} read failed (${parent.error}), so there were no ${parent.label} to scope the ${label} read`
    : `the ${parent.label} read was not requested (${parent.skipped}), so there were no ${parent.label} to scope the ${label} read`;
  return { label, value: fallback, skipped: reason, skippedParent: parent.label, httpStatus: parent.httpStatus };
}

async function collectPage(label: string, load: () => Promise<MulesoftListResult>, errors: string[]): Promise<Collected<MulesoftPage>> {
  const collected = await collect<MulesoftListResult>(label, [], load, errors);
  return { ...collected, value: toPage(collected.value) };
}

function readySource(label: string): Collected<undefined> {
  return { label, value: undefined };
}

function failedSource(label: string, error: string): Collected<undefined> {
  return { label, value: undefined, error };
}

/**
 * Combine per-item reads into one source. When the parent list the reads depend on was not collected,
 * the merged source is skipped and names that parent, so an empty set of reads is never mistaken for
 * a successful empty read.
 */
function mergeSources(label: string, sources: Array<Collected<unknown>>, parent?: Collected<unknown>): Collected<undefined> {
  if (parent && !sourceCollected(parent)) {
    if (sources.length === 0) return skippedSource(label, parent, undefined);
    // Some parents were read and their children requested; the children of the unread parents were not.
    return {
      label,
      value: undefined,
      error: `${label} reads were requested only for the ${parent.label} that were read (${sourceFailure(parent)})`,
      httpStatus: parent.httpStatus,
      endpoint: parent.endpoint,
      skippedParent: parent.label,
    };
  }
  const failed = sources.filter((source) => !sourceCollected(source));
  if (failed.length === 0) return readySource(label);
  const detail = failed.slice(0, 3).map((source) => `${source.label}: ${sourceFailure(source)}`).join("; ");
  return {
    label,
    value: undefined,
    error: `${failed.length} of ${sources.length} reads failed (${detail}${failed.length > 3 ? "; ..." : ""})`,
    httpStatus: failed[0].httpStatus,
    endpoint: failed[0].endpoint,
  };
}

function describeFailure(source: Collected<unknown>): string {
  if (source.skipped) return `${source.label} was not requested because ${source.skipped}`;
  const status = source.httpStatus;
  const cause = status === 401 || status === 403
    ? `the credential lacks permission (HTTP ${status})`
    : status === 404
      ? "the endpoint is unavailable on this control plane or plan (HTTP 404)"
      : "the read errored";
  return `${source.label} could not be read, ${cause}: ${source.error}`;
}

function verdict(status: MulesoftFindingStatus, summary: string, evidence?: JsonRecord): Verdict {
  return { status, summary, evidence };
}

function evaluate(
  number: number,
  inputs: EvaluationInputs,
  evidenceToCollect: string,
  compute: () => Verdict,
): MulesoftFinding {
  const failures = [...inputs.primary, ...(inputs.secondary ?? [])].filter((source) => !sourceCollected(source));
  // A read skipped because its parent failed is reported through the parent when both feed this finding.
  const cascaded = (source: Collected<unknown>): boolean =>
    source.skippedParent !== undefined && failures.some((failure) => failure.label === source.skippedParent);
  const primaryFailures = inputs.primary.filter((source) => !sourceCollected(source) && !cascaded(source));
  const secondaryFailures = (inputs.secondary ?? []).filter((source) => !sourceCollected(source) && !cascaded(source));
  const unreadableSources = [...primaryFailures, ...secondaryFailures].map(describeFailure);
  const partialView = (inputs.partial ?? []).filter((note): note is string => Boolean(note));

  if (primaryFailures.length > 0) {
    // A list that was never read has no partial view to report; null says so where [] would claim a complete empty read.
    return finding(
      number,
      "manual",
      `Could not evaluate: ${primaryFailures.map(describeFailure).join("; ")}. ${evidenceToCollect}`,
      { unreadable_sources: unreadableSources, partial_view: partialView.length > 0 ? partialView : null },
    );
  }

  const result = compute();
  const evidence: JsonRecord = { ...(result.evidence ?? {}) };
  if (unreadableSources.length > 0) evidence.unreadable_sources = unreadableSources;
  if (partialView.length > 0) evidence.partial_view = partialView;

  if (secondaryFailures.length > 0) {
    const causes = secondaryFailures.map(describeFailure).join("; ");
    if (result.status === "fail") {
      return finding(number, "fail", `${result.summary} Note: ${causes}; the evidence may be incomplete.`, evidence);
    }
    return finding(number, "manual", `Could not confirm: ${causes}. ${evidenceToCollect} Partial evidence: ${result.summary}`, evidence);
  }

  if (partialView.length > 0) {
    const note = `Partial view: ${partialView.join("; ")}.`;
    if (result.status === "pass") {
      return finding(number, "warn", `${note} ${result.summary} The unseen items were not evaluated, so the control cannot pass on this sample.`, evidence);
    }
    return finding(number, result.status, `${result.summary} ${note}`, evidence);
  }

  return finding(number, result.status, result.summary, evidence);
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

function hasEnvironmentType(environment: JsonRecord): boolean {
  return asBoolean(environment.isProduction) !== undefined || asString(environment.type) !== undefined;
}

interface EnvironmentSample {
  source: Collected<MulesoftPage>;
  all: JsonRecord[];
  sampled: JsonRecord[];
  excludedByFilter: JsonRecord[];
  excludedByLimit: JsonRecord[];
  partialNotes: string[];
}

function describeExcludedEnvironments(environments: JsonRecord[]): string {
  const production = environments.filter(isProductionEnvironment).length;
  return `${environments.length} environment(s) (${production} production): ${sample(environments.map(environmentLabel), 5).join(", ")}`;
}

async function sampleEnvironments(
  client: Pick<MulesoftApiClient, "getResolvedConfig" | "listEnvironments">,
  limit: number,
  errors: string[],
): Promise<EnvironmentSample> {
  const config = client.getResolvedConfig();
  const source = await collectPage("environments", () => client.listEnvironments(), errors);
  const all = source.value.items;
  const matching = all.filter((environment) => matchesEnvironmentFilter(environment, config.environmentFilter));
  const excludedByFilter = all.filter((environment) => !matching.includes(environment));
  const sorted = [...matching].sort((left, right) => Number(isProductionEnvironment(right)) - Number(isProductionEnvironment(left)));
  const sampled = sorted.slice(0, limit);
  const excludedByLimit = sorted.slice(limit);
  const partialNotes: string[] = [];
  const inventoryTruncation = truncationNote("environment", source.value);
  if (inventoryTruncation) {
    partialNotes.push(`the ${inventoryTruncation}, so unseen environments (which may include production) were not sampled`);
  }
  if (excludedByFilter.length > 0) {
    partialNotes.push(`the environment filter excluded ${describeExcludedEnvironments(excludedByFilter)}`);
  }
  if (excludedByLimit.length > 0) {
    partialNotes.push(`the environment limit of ${limit} excluded ${describeExcludedEnvironments(excludedByLimit)}`);
  }
  return { source, all, sampled, excludedByFilter, excludedByLimit, partialNotes };
}

function productionSampleNote(environments: EnvironmentSample): string {
  const productionTotal = environments.all.filter(isProductionEnvironment).length;
  const productionSampled = environments.sampled.filter(isProductionEnvironment).length;
  return `${productionSampled} of ${productionTotal} production environment(s) sampled`;
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

function scopeName(scope: JsonRecord): string {
  return asString(scope.scope) ?? asString(scope.name) ?? "scope";
}

function connectedAppScopeNames(app: JsonRecord, contextScopes: JsonRecord[]): string[] {
  return [...new Set([...asStringList(app.scopes), ...contextScopes.map(scopeName)])];
}

function isServiceConnectedApp(app: JsonRecord): boolean {
  return asStringList(app.grant_types).some((grant) => grant === "client_credentials");
}

function providerType(provider: JsonRecord): string {
  return asString(getNestedValue(provider, ["type", "name"])) ?? asString(provider.type) ?? "unknown";
}

function providerIsDisabled(provider: JsonRecord): boolean {
  return asBoolean(provider.enabled) === false
    || asBoolean(provider.disabled) === true
    || /disabled|inactive/i.test(asString(provider.status) ?? "");
}

function businessGroupScopeNote(hierarchy: JsonRecord): string | undefined {
  return asBoolean(hierarchy.isRoot) === false
    ? "this organization is a business group (isRoot=false), so root-level settings and sibling business groups are outside the view"
    : undefined;
}

// Root scope is only established by isRoot=true on a readable hierarchy; a failed read or a missing flag leaves the scope unknown.
function organizationScopeNote(hierarchy: Collected<JsonRecord>): string | undefined {
  if (hierarchy.error) {
    return `${describeFailure(hierarchy)}, so it is unknown whether this organization is a business group with root settings and sibling groups outside the view`;
  }
  if (asBoolean(hierarchy.value.isRoot) === undefined) {
    return "the organization hierarchy did not expose isRoot, so it is unknown whether this organization is a business group with root settings and sibling groups outside the view";
  }
  return businessGroupScopeNote(hierarchy.value);
}

interface OrganizationScope {
  source: Collected<JsonRecord>;
  note?: string;
}

async function collectOrganizationScope(
  client: Pick<MulesoftApiClient, "getOrganizationHierarchy">,
  errors: string[],
): Promise<OrganizationScope> {
  const source = await collect<JsonRecord>("organization_hierarchy", {}, () => client.getOrganizationHierarchy(), errors);
  return { source, note: organizationScopeNote(source) };
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

  const organization = await collect<JsonRecord>("organization", {}, () => client.getOrganization(), errors);
  const hierarchy = await collect<JsonRecord>("organization_hierarchy", {}, () => client.getOrganizationHierarchy(), errors);
  const identityProviders = await collectPage("identity_providers", () => client.listIdentityProviders(), errors);
  const identityProviderSettings = await collect<JsonRecord>("identity_provider_settings", {}, () => client.getIdentityProviderSettings(), errors);
  const members = await collectPage("members", () => client.listMembers(userLimit), errors);
  const mfaExemptUsers = await collectPage("mfa_exempt_users", () => client.listMfaExemptUsers(userLimit), errors);
  const roleGroups = await collectPage("role_groups", () => client.listRoleGroups(), errors);
  const environments = await collectPage("environments", () => client.listEnvironments(), errors);
  const connectedApps = await collectPage("connected_applications", () => client.listConnectedApplications(), errors);

  const roleGroupDetails: Array<{ roleGroup: JsonRecord; roles: Collected<MulesoftPage>; users?: Collected<MulesoftPage> }> = [];
  for (const roleGroup of roleGroups.value.items) {
    const id = roleGroupId(roleGroup);
    const name = roleGroupName(roleGroup);
    if (!id) {
      roleGroupDetails.push({ roleGroup, roles: { ...failedSource(`role_group_roles:${name}`, "role group has no id"), value: toPage([]) } });
      continue;
    }
    const roles = await collectPage(`role_group_roles:${name}`, () => client.listRoleGroupRoles(id), errors);
    const users = isOrgAdminRoleGroup(roleGroup, roles.value.items)
      ? await collectPage(`role_group_users:${name}`, () => client.listRoleGroupUsers(id), errors)
      : undefined;
    roleGroupDetails.push({ roleGroup, roles, users });
  }
  const roleGroupRolesSource = mergeSources("role_group_roles", roleGroupDetails.map((detail) => detail.roles), roleGroups);
  const adminUsersSource = mergeSources("role_group_users", roleGroupDetails.flatMap((detail) => (detail.users ? [detail.users] : [])), roleGroups);

  const connectedAppScopes: Array<{ app: JsonRecord; scopes: Collected<MulesoftPage> }> = [];
  for (const app of connectedApps.value.items) {
    const clientId = asString(app.client_id);
    const name = connectedAppName(app);
    const scopes = clientId
      ? await collectPage(`connected_app_scopes:${name}`, () => client.listConnectedApplicationScopes(clientId), errors)
      : { ...failedSource(`connected_app_scopes:${name}`, "connected app has no client_id"), value: toPage([]) };
    connectedAppScopes.push({ app, scopes });
  }
  const scopesSource = mergeSources("connected_app_scopes", connectedAppScopes.map((item) => item.scopes), connectedApps);

  const providers = identityProviders.value.items;
  const providerSummaries = providers.map((provider) => ({
    name: asString(provider.name) ?? asString(provider.provider_id) ?? "identity provider",
    type: providerType(provider),
    disabled: providerIsDisabled(provider),
  }));
  const activeProviders = providers.filter((provider) => !providerIsDisabled(provider));
  const allowNewNonSsoUsers = asBoolean(identityProviderSettings.value.allow_new_non_sso_users);
  const isFederated = asBoolean(organization.value.isFederated) ?? asBoolean(hierarchy.value.isFederated);
  const scopeNote = organizationScopeNote(hierarchy);

  const exemptReturned = mfaExemptUsers.value.items;
  const exemptFlagged = exemptReturned.filter((user) => asBoolean(user.mfaVerificationExcluded) === true);
  const exemptUnflagged = exemptReturned.filter((user) => asBoolean(user.mfaVerificationExcluded) !== true);

  const roleGroupItems = roleGroups.value.items;
  const adminGroups = roleGroupDetails.filter((detail) => isOrgAdminRoleGroup(detail.roleGroup, detail.roles.value.items));
  const adminUsers = new Map<string, string>();
  for (const detail of adminGroups) {
    for (const user of detail.users?.value.items ?? []) {
      const id = asString(user.id) ?? memberLabel(user);
      adminUsers.set(id, memberLabel(user));
    }
  }
  const adminUsersTruncated = adminGroups.some((detail) => detail.users?.value.truncated === true);

  const overPrivilegedGroups = roleGroupDetails
    .filter((detail) => !isBuiltInAdminGroup(detail.roleGroup) && detail.roles.value.items.some((role) => ORG_ADMIN_ROLE_PATTERN.test(roleName(role))))
    .map((detail) => roleGroupName(detail.roleGroup));
  const broadGroups = roleGroupDetails
    .filter((detail) => detail.roles.value.items.length > maxRolesPerGroup)
    .map((detail) => ({ role_group: roleGroupName(detail.roleGroup), roles: detail.roles.value.items.length }));
  const truncatedRoleGroups = roleGroupDetails
    .filter((detail) => detail.roles.value.truncated)
    .map((detail) => roleGroupName(detail.roleGroup));

  const allAssignments = roleGroupDetails.flatMap((detail) =>
    detail.roles.value.items.map((role) => ({ roleGroup: roleGroupName(detail.roleGroup), role })),
  );
  const environmentScopedAssignments = allAssignments.filter((item) => assignmentEnvironmentId(item.role) !== undefined);
  const orgWideEnvironmentRoles = allAssignments.filter((item) =>
    assignmentEnvironmentId(item.role) === undefined
    && ENVIRONMENT_ROLE_PATTERN.test(roleName(item.role))
    && !ORG_ADMIN_ROLE_PATTERN.test(roleName(item.role)),
  );

  const environmentItems = environments.value.items;
  const productionEnvironments = environmentItems.filter(isProductionEnvironment);
  const sandboxEnvironments = environmentItems.filter((environment) => !isProductionEnvironment(environment));
  const untypedEnvironments = environmentItems.filter((environment) => !hasEnvironmentType(environment));
  const misclassifiedEnvironments = environmentItems.filter((environment) => {
    const name = environmentLabel(environment);
    const production = isProductionEnvironment(environment);
    return (PRODUCTION_NAME_PATTERN.test(name) && !production) || (NON_PRODUCTION_NAME_PATTERN.test(name) && production);
  });

  const connectedAppItems = connectedApps.value.items;
  const scopedApps = connectedAppScopes.map((item) => ({
    name: connectedAppName(item.app),
    service: isServiceConnectedApp(item.app),
    scopes: connectedAppScopeNames(item.app, item.scopes.value.items),
  }));
  const adminScoped = scopedApps.filter((item) => item.scopes.some((scope) => ADMIN_SCOPE_PATTERN.test(scope)));
  const adminScopedApps = adminScoped.filter((item) => item.service).map((item) => item.name);
  const adminScopedDelegatedApps = adminScoped.filter((item) => !item.service).map((item) => item.name);
  const broadScopedApps = scopedApps
    .filter((item) => item.scopes.length > maxConnectedAppScopes)
    .map((item) => ({ app: item.name, scopes: item.scopes.length }));
  const truncatedScopeApps = connectedAppScopes.filter((item) => item.scopes.value.truncated).map((item) => connectedAppName(item.app));

  const now = Date.now();
  const staleThreshold = now - staleDays * DAY_MS;
  const appsWithUsageDate = connectedAppItems.filter((app) => connectedAppLastUsed(app) !== undefined);
  const appsWithoutUsageDate = connectedAppItems.filter((app) => connectedAppLastUsed(app) === undefined);
  const staleApps = appsWithUsageDate.filter((app) => (connectedAppLastUsed(app) as Date).getTime() < staleThreshold);
  const disabledApps = connectedAppItems.filter((app) => asBoolean(app.enabled) === false);

  const subOrganizations = asRecordArray(hierarchy.value.subOrganizations);
  const canCreateSubOrgs = asBoolean(getNestedValue(organization.value, ["entitlements", "createSubOrgs"]));
  const isRoot = asBoolean(hierarchy.value.isRoot);

  const findings: MulesoftFinding[] = [
    evaluate(
      1,
      { primary: [identityProviders, organization], secondary: [identityProviderSettings], partial: [scopeNote, truncationNote("identity provider", identityProviders.value)] },
      "Export Access Management > Identity Providers (type and status) and the organization SSO settings as evidence.",
      () => {
        const evidence = {
          identity_providers: providerSummaries,
          active_identity_providers: activeProviders.length,
          is_federated: isFederated ?? null,
          allow_new_non_sso_users: allowNewNonSsoUsers ?? null,
        };
        if (providers.length === 0) {
          return verdict("fail", "No external identity provider is configured (the identityProviders read succeeded and returned zero providers); users authenticate with Anypoint Platform passwords. Zero providers is treated as fail.", evidence);
        }
        if (activeProviders.length === 0) {
          return verdict("fail", `${providers.length} identity provider(s) exist but every one is disabled, so SSO is not enforced.`, evidence);
        }
        if (isFederated !== true) {
          return verdict("warn", `${activeProviders.length} active identity provider(s) configured (${activeProviders.map(providerType).join(", ")}), but the organization isFederated flag is ${isFederated === undefined ? "absent" : "false"}, so SSO enforcement cannot be confirmed from the API.`, evidence);
        }
        if (allowNewNonSsoUsers === undefined) {
          return verdict("warn", `${activeProviders.length} active identity provider(s) configured and the organization is federated, but identity provider settings did not expose allow_new_non_sso_users; confirm non-SSO user creation is disabled.`, evidence);
        }
        if (allowNewNonSsoUsers) {
          return verdict("warn", `${activeProviders.length} active identity provider(s) configured and the organization is federated, but new non-SSO users are still allowed.`, evidence);
        }
        return verdict("pass", `${activeProviders.length} active identity provider(s) configured (${activeProviders.map(providerType).join(", ")}), the organization isFederated flag is true, and non-SSO user creation is not allowed.`, evidence);
      },
    ),
    evaluate(
      2,
      {
        primary: [mfaExemptUsers],
        partial: [truncationNote("MFA-exempt users", mfaExemptUsers.value), truncationNote("members", members.value), scopeNote],
      },
      "Capture the Access Management > Organization > multi-factor authentication setting, or the external identity provider MFA policy, as evidence.",
      () => {
        const evidence = {
          mfa_exempt_users: sample(exemptFlagged.map(memberLabel)),
          users_returned_without_flag: sample(exemptUnflagged.map(memberLabel)),
          members_sampled: members.value.items.length,
          is_federated: isFederated ?? null,
        };
        if (exemptFlagged.length > 0) {
          return verdict("fail", `${exemptFlagged.length} user(s) carry mfaVerificationExcluded=true and are excluded from MFA verification.`, evidence);
        }
        if (exemptUnflagged.length > 0) {
          return verdict("warn", `${exemptUnflagged.length} user(s) were returned by the mfaVerificationExcluded=true query but the response did not include the mfaVerificationExcluded flag; confirm each exemption in Access Management > Users.`, evidence);
        }
        return verdict("manual", "No MFA-exempt users are visible. Zero exemptions is treated as manual rather than pass because the organization-wide MFA requirement is not exposed by the Access Management API: capture the Access Management > Organization > multi-factor authentication setting, or the external identity provider MFA policy, as evidence.", evidence);
      },
    ),
    evaluate(
      3,
      {
        primary: [roleGroups, roleGroupRolesSource, adminUsersSource],
        partial: [
          truncationNote("role groups", roleGroups.value),
          truncatedRoleGroups.length > 0 ? `role assignments truncated for ${truncatedRoleGroups.join(", ")}` : undefined,
          adminUsersTruncated ? `admin role group membership truncated at ${adminUsers.size} users` : undefined,
          scopeNote,
        ],
      },
      "Export Access Management > Users filtered by the Organization Administrator permission and record the member count.",
      () => {
        const evidence = {
          admin_role_groups: adminGroups.map((detail) => roleGroupName(detail.roleGroup)),
          admin_users: sample([...adminUsers.values()]),
          admin_user_count: adminUsers.size,
          max_admins: maxAdmins,
          members_sampled: members.value.items.length,
        };
        if (roleGroupItems.length === 0) {
          return verdict("manual", "Zero role groups were returned even though the read succeeded; every organization has a built-in Organization Administrators group, so the credential sees a scoped-down view. Zero role groups is treated as manual.", evidence);
        }
        if (adminGroups.length === 0) {
          return verdict("manual", `No Organization Administrator or Organization Owner role group was visible among ${roleGroupItems.length} role group(s), so admin membership could not be counted. Treated as manual.`, evidence);
        }
        if (adminUsers.size > maxAdmins) {
          return verdict("fail", `${adminUsers.size} organization administrator(s) exceed the threshold of ${maxAdmins}.`, evidence);
        }
        return verdict("pass", `${adminUsers.size} organization administrator(s) across ${adminGroups.length} admin role group(s), within the threshold of ${maxAdmins}.`, evidence);
      },
    ),
    evaluate(
      4,
      {
        primary: [roleGroups, roleGroupRolesSource],
        partial: [
          truncationNote("role groups", roleGroups.value),
          truncatedRoleGroups.length > 0 ? `role assignments truncated for ${truncatedRoleGroups.join(", ")}` : undefined,
          scopeNote,
        ],
      },
      "Export each role group and its permissions from Access Management > Role Groups.",
      () => {
        const evidence = {
          role_groups: roleGroupItems.length,
          over_privileged_groups: sample(overPrivilegedGroups),
          broad_groups: sample(broadGroups),
          max_roles_per_group: maxRolesPerGroup,
        };
        if (roleGroupItems.length === 0) {
          return verdict("manual", "Zero role groups were returned even though the read succeeded, which indicates a scoped-down credential. Zero role groups is treated as manual.", evidence);
        }
        if (overPrivilegedGroups.length > 0) {
          return verdict("fail", `${overPrivilegedGroups.length} custom role group(s) grant Organization Administrator or Organization Owner roles.`, evidence);
        }
        if (broadGroups.length > 0) {
          return verdict("warn", `${broadGroups.length} role group(s) carry more than ${maxRolesPerGroup} role assignments.`, evidence);
        }
        return verdict("pass", `${roleGroupItems.length} role group(s) reviewed with no organization-wide admin grants outside the built-in administrators group.`, evidence);
      },
    ),
    evaluate(
      5,
      {
        primary: [roleGroups, roleGroupRolesSource],
        partial: [
          truncationNote("role groups", roleGroups.value),
          truncatedRoleGroups.length > 0 ? `role assignments truncated for ${truncatedRoleGroups.join(", ")}` : undefined,
          scopeNote,
        ],
      },
      "Export environment permissions per user from Access Management > Users > Permissions and confirm each grant names a specific environment.",
      () => {
        const evidence = {
          role_groups: roleGroupItems.length,
          environment_scoped_assignments: environmentScopedAssignments.length,
          org_wide_environment_roles: sample(orgWideEnvironmentRoles.map((item) => `${item.roleGroup}: ${roleName(item.role)}`)),
        };
        if (roleGroupItems.length === 0) {
          return verdict("manual", "Zero role groups were returned even though the read succeeded, so environment scoping could not be evaluated. Zero role groups is treated as manual.", evidence);
        }
        if (orgWideEnvironmentRoles.length > MAX_ORG_WIDE_ENVIRONMENT_ROLES) {
          return verdict("fail", `${orgWideEnvironmentRoles.length} environment-level role assignment(s) apply to all environments instead of a specific environment.`, evidence);
        }
        if (orgWideEnvironmentRoles.length > 0) {
          return verdict("warn", `${orgWideEnvironmentRoles.length} environment-level role assignment(s) apply to all environments instead of a specific environment.`, evidence);
        }
        if (environmentScopedAssignments.length === 0) {
          return verdict("manual", `No environment-level role assignments were found in ${roleGroupItems.length} role group(s), so environment permissions are either granted directly to users or absent; neither is visible through role groups. Zero assignments is treated as manual.`, evidence);
        }
        return verdict("pass", `${environmentScopedAssignments.length} environment role assignment(s) are scoped to specific environments and none apply organization-wide.`, evidence);
      },
    ),
    evaluate(
      6,
      { primary: [environments], partial: [truncationNote("environment", environments.value), scopeNote] },
      "Export Access Management > Environments with each environment's type and confirm production workloads do not share a sandbox environment.",
      () => {
        const evidence = {
          production_environments: sample(productionEnvironments.map(environmentLabel)),
          sandbox_environments: sample(sandboxEnvironments.map(environmentLabel)),
          misclassified_environments: sample(misclassifiedEnvironments.map(environmentLabel)),
          untyped_environments: sample(untypedEnvironments.map(environmentLabel)),
        };
        if (environmentItems.length === 0) {
          return verdict("manual", "Zero environments were returned even though the read succeeded; every organization has at least a Sandbox and Design environment, so the credential sees a scoped-down view. Zero environments is treated as manual.", evidence);
        }
        if (misclassifiedEnvironments.length > 0) {
          return verdict("fail", `${misclassifiedEnvironments.length} environment(s) have names that contradict their production or sandbox type.`, evidence);
        }
        if (untypedEnvironments.length > 0) {
          return verdict("warn", `${untypedEnvironments.length} environment(s) did not expose an isProduction or type flag, so their classification cannot be confirmed.`, evidence);
        }
        if (productionEnvironments.length === 0 || sandboxEnvironments.length === 0) {
          return verdict("warn", `Only ${productionEnvironments.length} production and ${sandboxEnvironments.length} sandbox environment(s) exist, so production workloads may share an environment with development.`, evidence);
        }
        return verdict("pass", `${productionEnvironments.length} production and ${sandboxEnvironments.length} sandbox environment(s) are typed separately.`, evidence);
      },
    ),
    evaluate(
      18,
      {
        primary: [connectedApps, scopesSource],
        partial: [
          truncationNote("connected apps", connectedApps.value),
          truncatedScopeApps.length > 0 ? `scope lists truncated for ${truncatedScopeApps.join(", ")}` : undefined,
          scopeNote,
        ],
      },
      "Export Access Management > Connected Apps with each app's scopes and grant type.",
      () => {
        const evidence = {
          connected_apps: connectedAppItems.length,
          connected_apps_total: connectedApps.value.total ?? connectedAppItems.length,
          managed_apps_included: true,
          service_apps: scopedApps.filter((item) => item.service).length,
          admin_scoped_apps: sample(adminScopedApps),
          admin_scoped_delegated_apps: sample(adminScopedDelegatedApps),
          broad_scoped_apps: sample(broadScopedApps),
          max_connected_app_scopes: maxConnectedAppScopes,
        };
        if (connectedAppItems.length === 0) {
          return verdict("manual", "Zero connected apps were returned for this organization. Zero apps is treated as manual rather than pass: confirm in Access Management > Connected Apps that no apps exist in child business groups either.", evidence);
        }
        if (adminScopedApps.length > 0) {
          return verdict("fail", `${adminScopedApps.length} client credentials connected app(s) hold administrative or full-access scopes.`, evidence);
        }
        if (adminScopedDelegatedApps.length > 0) {
          return verdict("warn", `${adminScopedDelegatedApps.length} user-delegated connected app(s) request the full or administrative scope; confirm each one needs the acting user's complete permissions.`, evidence);
        }
        if (broadScopedApps.length > 0) {
          return verdict("warn", `${broadScopedApps.length} connected app(s) hold more than ${maxConnectedAppScopes} scopes.`, evidence);
        }
        return verdict("pass", `${connectedAppItems.length} connected app(s) reviewed with scopes read for every app and no administrative scopes.`, evidence);
      },
    ),
    evaluate(
      19,
      { primary: [connectedApps], partial: [truncationNote("connected apps", connectedApps.value), scopeNote] },
      "Export the connected apps list with last-used timestamps from Access Management > Connected Apps and confirm each app is still required.",
      () => {
        const evidence = {
          connected_apps: connectedAppItems.length,
          connected_apps_total: connectedApps.value.total ?? connectedAppItems.length,
          managed_apps_included: true,
          apps_with_usage_data: appsWithUsageDate.length,
          apps_without_usage_date: sample(appsWithoutUsageDate.map(connectedAppName)),
          usage_data_source: "last_used, lastUsed, last_used_at, or usage.* on GET /organizations/{orgId}/connectedApplications?includeUsage=true; not part of the published schema, so absence is expected",
          stale_apps: sample(staleApps.map(connectedAppName)),
          disabled_apps: sample(disabledApps.map(connectedAppName)),
          stale_days: staleDays,
        };
        if (connectedAppItems.length === 0) {
          return verdict("manual", "Zero connected apps were returned for this organization. Zero apps is treated as manual rather than pass: confirm in Access Management > Connected Apps that no apps exist in child business groups either.", evidence);
        }
        if (staleApps.length > 0 || disabledApps.length > 0) {
          return verdict("warn", `${staleApps.length} connected app(s) unused for more than ${staleDays} days and ${disabledApps.length} disabled app(s) should be reviewed for removal.`, evidence);
        }
        if (appsWithoutUsageDate.length > 0) {
          return verdict("warn", `${appsWithoutUsageDate.length} of ${connectedAppItems.length} connected app(s) have no last-used timestamp and are not counted as active. The published organization connected apps schema does not include last-used data even with includeUsage=true (Anypoint shows it only in the per-user authorizations view), so this warning is the expected outcome on Anypoint Platform: review each app's usage in Access Management > Connected Apps and record the last-used dates manually.`, evidence);
        }
        return verdict("pass", `All ${connectedAppItems.length} connected app(s) have a last-used timestamp within the last ${staleDays} days.`, evidence);
      },
    ),
    evaluate(
      25,
      { primary: [hierarchy], secondary: [organization] },
      "Export the business group hierarchy from Access Management > Business Groups and confirm tenants or business units map to separate business groups.",
      () => {
        const evidence = {
          sub_organizations: sample(subOrganizations.map((item) => asString(item.name) ?? asString(item.id) ?? "business group")),
          can_create_sub_orgs: canCreateSubOrgs ?? null,
          is_root: isRoot ?? null,
        };
        if (isRoot === false) {
          return verdict("manual", "This organization is a business group (isRoot=false), so only its own children are visible and the tenant structure of the root organization is scoped out. Inspect the root organization hierarchy.", evidence);
        }
        if (subOrganizations.length === 0) {
          if (canCreateSubOrgs === false) {
            return verdict("manual", "No business groups exist and the createSubOrgs entitlement is false, so business groups are not available on this plan (not applicable). Confirm tenants are separated through separate organizations or environments.", evidence);
          }
          return verdict("manual", "No business groups exist. Confirm whether multiple business units or tenants share this organization; if they do, create business groups so ownership, environments, and permissions are isolated.", evidence);
        }
        if (canCreateSubOrgs === undefined) {
          return verdict("warn", `${subOrganizations.length} business group(s) exist but the organization did not expose the entitlements.createSubOrgs flag; confirm business group entitlement in Access Management > Organization.`, evidence);
        }
        return verdict("pass", `${subOrganizations.length} business group(s) separate teams or tenants under the root organization (createSubOrgs entitlement ${canCreateSubOrgs}).`, evidence);
      },
    ),
  ];

  return {
    category: "identity_access",
    title: "MuleSoft identity and access posture",
    // Counts derived from a list that was not read render null rather than the empty fallback's zero.
    summary: {
      organization_id: config.organizationId,
      identity_providers: derived(providers.length, identityProviders),
      identity_providers_truncated: derived(identityProviders.value.truncated, identityProviders),
      members_sampled: derived(members.value.items.length, members),
      members_total: derived(members.value.total ?? null, members),
      members_truncated: derived(members.value.truncated, members),
      mfa_exempt_users: derived(exemptFlagged.length, mfaExemptUsers),
      organization_admins: derived(adminUsers.size, roleGroups, roleGroupRolesSource, adminUsersSource),
      role_groups: derived(roleGroupItems.length, roleGroups),
      environments: derived(environmentItems.length, environments),
      connected_apps: derived(connectedAppItems.length, connectedApps),
      stale_connected_apps: derived(staleApps.length, connectedApps),
      business_groups: derived(subOrganizations.length, hierarchy),
      unreadable_sources: errors.length,
      inventories: describeSources(organization, hierarchy, identityProviders, identityProviderSettings, members, mfaExemptUsers, roleGroups, roleGroupRolesSource, adminUsersSource, environments, connectedApps, scopesSource),
    },
    findings,
    snapshots: {
      organization: snapshotOf(organization, organization.value),
      organization_hierarchy: snapshotOf(hierarchy, hierarchy.value),
      identity_providers: snapshotOf(identityProviders, providers),
      identity_provider_settings: snapshotOf(identityProviderSettings, identityProviderSettings.value),
      members: snapshotOf(members, members.value.items),
      mfa_exempt_users: snapshotOf(mfaExemptUsers, exemptReturned),
      role_groups: snapshotOf(roleGroups, roleGroupDetails.map((detail) => ({
        role_group: detail.roleGroup,
        roles: sourceCollected(detail.roles) ? detail.roles.value.items : notCollectedMarker(detail.roles),
        roles_truncated: derived(detail.roles.value.truncated, detail.roles),
        users: detail.users === undefined ? null : sourceCollected(detail.users) ? detail.users.value.items : notCollectedMarker(detail.users),
      }))),
      environments: snapshotOf(environments, environmentItems),
      connected_applications: snapshotOf(connectedApps, connectedAppScopes.map((item) => ({
        ...item.app,
        scopes: sourceCollected(item.scopes) ? item.scopes.value.items : notCollectedMarker(item.scopes),
      }))),
    },
    errors,
  };
}

/** One line per source stating whether it was read completely, partially, or not at all. */
function describeSources(...sources: Array<Collected<unknown>>): Record<string, string> {
  return Object.fromEntries(sources.map((source) => [source.label, describeSource(source)]));
}

function describeSource(source: Collected<unknown>): string {
  if (source.skipped) return `not requested (${source.skipped})`;
  if (source.error) return `unread (${source.error})`;
  if (isPage(source.value)) {
    return source.value.truncated
      ? `partial (${source.value.items.length} of ${pageTotalLabel(source.value)})`
      : `complete (${source.value.items.length} item${source.value.items.length === 1 ? "" : "s"})`;
  }
  if (Array.isArray(source.value)) return `complete (${source.value.length} item${source.value.length === 1 ? "" : "s"})`;
  return "complete";
}

function policyAssetId(policy: JsonRecord): string {
  return asString(firstDefined(policy, [
    ["assetId"],
    ["template", "assetId"],
    ["implementationAsset", "assetId"],
    ["policyTemplateId"],
  ])) ?? "policy";
}

function projectPolicyAsset(asset: unknown): JsonRecord | null {
  const record = asObject(asset);
  if (!record) return null;
  return {
    groupId: asString(record.groupId) ?? null,
    assetId: asString(record.assetId) ?? null,
    assetVersion: asString(record.assetVersion) ?? asString(record.version) ?? null,
  };
}

// configurationData carries the policy's own settings (JWT secrets, injected header values, client credentials),
// so the snapshot keeps a marker in its place rather than the tree.
function projectApiPolicy(policy: JsonRecord): JsonRecord {
  return {
    policyId: asString(policy.policyId) ?? asString(policy.id) ?? null,
    assetId: asString(policy.assetId) ?? null,
    assetVersion: asString(policy.assetVersion) ?? null,
    policyTemplateId: asString(policy.policyTemplateId) ?? null,
    template: projectPolicyAsset(policy.template),
    implementationAsset: projectPolicyAsset(policy.implementationAsset),
    disabled: asBoolean(policy.disabled) ?? null,
    order: asNumber(policy.order) ?? null,
    configurationData: policy.configurationData === undefined ? null : REDACTED,
  };
}

type PolicyState = "enabled" | "disabled" | "unknown";
type PolicyCoverage = "enforced" | "unknown_state" | "missing";

function policyState(policy: JsonRecord): PolicyState {
  const disabled = asBoolean(policy.disabled);
  if (disabled === true) return "disabled";
  if (disabled === false) return "enabled";
  return "unknown";
}

function policyCoverage(policies: JsonRecord[], pattern: RegExp): PolicyCoverage {
  const matching = policies.filter((policy) => pattern.test(policyAssetId(policy)));
  if (matching.some((policy) => policyState(policy) === "enabled")) return "enforced";
  if (matching.some((policy) => policyState(policy) === "unknown")) return "unknown_state";
  return "missing";
}

function apiLabel(api: JsonRecord): string {
  const name = asString(api.assetName) ?? asString(api.assetId) ?? asString(api.autodiscoveryInstanceName) ?? asString(api.id) ?? "api";
  const label = asString(api.instanceLabel);
  return label ? `${name} (${label})` : name;
}

interface ApiRecord {
  environment: JsonRecord;
  api: JsonRecord;
  policies: Collected<JsonRecord[]>;
}

function policyCoverageVerdict(
  records: ApiRecord[],
  environments: EnvironmentSample,
  pattern: RegExp,
  policyDescription: string,
  describeApis: (records: ApiRecord[]) => string[],
  evidenceKeyPrefix: string,
): Verdict {
  const production = records.filter((record) => isProductionEnvironment(record.environment));
  const nonProduction = records.filter((record) => !isProductionEnvironment(record.environment));
  const coverage = (record: ApiRecord) => policyCoverage(record.policies.value, pattern);
  const productionMissing = production.filter((record) => coverage(record) === "missing");
  const productionUnknown = production.filter((record) => coverage(record) === "unknown_state");
  const nonProductionMissing = nonProduction.filter((record) => coverage(record) === "missing");
  const evidence: JsonRecord = {
    apis_sampled: records.length,
    production_apis: production.length,
    production_environments_sampled: productionSampleNote(environments),
    [`production_without_${evidenceKeyPrefix}`]: describeApis(productionMissing),
    [`production_${evidenceKeyPrefix}_unknown_state`]: describeApis(productionUnknown),
    [`non_production_without_${evidenceKeyPrefix}`]: describeApis(nonProductionMissing),
  };

  if (records.length === 0) {
    return verdict("manual", `Zero managed API instances were visible in ${environments.sampled.length} sampled environment(s) (${productionSampleNote(environments)}). Zero instances cannot pass a policy-coverage control and is treated as manual: confirm in API Manager whether any APIs are managed.`, evidence);
  }
  if (productionMissing.length > 0) {
    return verdict("fail", `${productionMissing.length}/${production.length} production API instance(s) have no ${policyDescription}.`, evidence);
  }
  if (production.length === 0) {
    return verdict("manual", `${records.length} API instance(s) were sampled but none belong to a production environment (${productionSampleNote(environments)}), so production coverage cannot be asserted. Treated as manual.`, evidence);
  }
  if (productionUnknown.length > 0) {
    return verdict("warn", `${productionUnknown.length}/${production.length} production API instance(s) carry a matching ${policyDescription} whose disabled flag was not returned, so its enabled state is unknown.`, evidence);
  }
  if (nonProductionMissing.length > 0) {
    return verdict("warn", `All ${production.length} production API instance(s) enforce an enabled ${policyDescription}, but ${nonProductionMissing.length} non-production instance(s) do not.`, evidence);
  }
  return verdict("pass", `All ${records.length} sampled API instance(s) enforce an enabled ${policyDescription} (disabled=false confirmed on each).`, evidence);
}

export async function assessMulesoftApiGateway(
  client: ApiGatewayClient,
  options: MulesoftApiGatewayOptions = {},
): Promise<MulesoftAssessmentResult> {
  const config = client.getResolvedConfig();
  const errors: string[] = [];
  const environmentLimit = clampNumber(options.environmentLimit, DEFAULT_ENVIRONMENT_LIMIT, 1, 100);
  const apiLimit = clampNumber(options.apiLimit, DEFAULT_API_LIMIT, 1, 2000);

  const scope = await collectOrganizationScope(client, errors);
  const environments = await sampleEnvironments(client, environmentLimit, errors);
  const apiSources: Array<Collected<MulesoftPage>> = [];
  const apiRecords: ApiRecord[] = [];
  const apiPartialNotes: string[] = [];
  for (const environment of environments.sampled) {
    const environmentId = asString(environment.id);
    const label = environmentLabel(environment);
    if (!environmentId) {
      apiSources.push({ ...failedSource(`api_manager_apis:${label}`, "environment has no id"), value: toPage([]) });
      continue;
    }
    const remaining = apiLimit - apiRecords.length;
    if (remaining <= 0) {
      apiPartialNotes.push(`the API limit of ${apiLimit} was reached before sampling ${label}`);
      continue;
    }
    const apis = await collectPage(`api_manager_apis:${label}`, () => client.listManagedApis(environmentId, remaining), errors);
    apiSources.push(apis);
    const note = truncationNote(`${label} API instance`, apis.value);
    if (note) apiPartialNotes.push(note);
    for (const api of apis.value.items) {
      const apiId = asString(api.id);
      const policies: Collected<JsonRecord[]> = apiId
        ? await collect<JsonRecord[]>(`api_policies:${apiLabel(api)}`, [], () => client.listApiPolicies(environmentId, apiId), errors)
        : { label: `api_policies:${apiLabel(api)}`, value: [], error: "API instance has no id" };
      apiRecords.push({ environment, api, policies });
    }
  }
  const apisSource = mergeSources("api_manager_apis", apiSources, environments.source);
  const policiesSource = mergeSources("api_policies", apiRecords.map((record) => record.policies), apisSource);

  const exchangeAssets = await collectPage("exchange_assets", () => client.listExchangeAssets(), errors);
  const organizationAssets = exchangeAssets.value.items.filter((asset) => {
    const owner = asString(asset.organizationId);
    return owner === undefined || owner === config.organizationId;
  });

  const productionApis = apiRecords.filter((record) => isProductionEnvironment(record.environment));
  const productionWithoutAuth = productionApis.filter((record) => policyCoverage(record.policies.value, AUTHENTICATION_POLICY_PATTERN) === "missing");
  const productionWithoutRateLimit = productionApis.filter((record) => policyCoverage(record.policies.value, RATE_LIMIT_POLICY_PATTERN) === "missing");
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

  const describeApis = (records: ApiRecord[]) =>
    sample(records.map((record) => `${environmentLabel(record.environment)}: ${apiLabel(record.api)}`));
  const gatewayPartialNotes = [...environments.partialNotes, ...apiPartialNotes, scope.note];
  const gatewayInputs: EvaluationInputs = {
    primary: [environments.source, apisSource, policiesSource],
    partial: gatewayPartialNotes,
  };
  const apiInventoryFailure = [environments.source, apisSource].find((source) => !sourceCollected(source));

  const findings: MulesoftFinding[] = [
    evaluate(
      7,
      gatewayInputs,
      "Export each production API instance's applied policies from API Manager > API Administration > Policies.",
      () => policyCoverageVerdict(
        apiRecords,
        environments,
        AUTHENTICATION_POLICY_PATTERN,
        "authentication policy (client ID enforcement, JWT, OAuth, basic auth, SAML, or TLS)",
        describeApis,
        "authentication",
      ),
    ),
    evaluate(
      8,
      gatewayInputs,
      "Export each production API instance's applied policies from API Manager > API Administration > Policies and confirm a rate limiting or spike control policy is enabled.",
      () => policyCoverageVerdict(
        apiRecords,
        environments,
        RATE_LIMIT_POLICY_PATTERN,
        "rate limiting or spike control policy",
        describeApis,
        "rate_limiting",
      ),
    ),
    finding(
      9,
      "manual",
      apiInventoryFailure
        ? `Anypoint Platform does not expose client secret rotation timestamps, and the API inventory could not be evaluated: ${describeFailure(apiInventoryFailure)}. Export the active contracts from API Manager > API instance > Contracts and the client applications from Exchange > My Applications, then confirm each client secret was reset within the rotation period.`
        : `Anypoint Platform does not expose client secret rotation timestamps. Export the ${activeContracts} active contract(s) from API Manager > API instance > Contracts and the client applications from Exchange > My Applications, then confirm each client secret was reset within the rotation period.`,
      {
        active_contracts: apiInventoryFailure ? null : activeContracts,
        apis_sampled: apiInventoryFailure ? null : apiRecords.length,
        unreadable_sources: apiInventoryFailure ? [describeFailure(apiInventoryFailure)] : [],
        partial_view: partialViewOf(gatewayPartialNotes, environments.source, apisSource),
      },
    ),
    evaluate(
      20,
      { primary: [exchangeAssets], partial: [truncationNote("Exchange asset", exchangeAssets.value), scope.note] },
      "Export the API Governance conformance report and the Exchange publishing settings that require review before publication.",
      () => {
        const evidence = {
          assets: organizationAssets.length,
          public_assets: sample(publicAssets.map((asset) => asString(asset.name) ?? asString(asset.assetId) ?? "asset")),
          status_counts: assetStatusCounts,
          type_counts: assetTypeCounts,
        };
        if (organizationAssets.length === 0) {
          return verdict("manual", "Zero Exchange assets were visible for this organization. Zero assets is treated as manual: confirm in Exchange whether assets exist under this organization or its business groups, since Exchange Viewer may be granted per business group.", evidence);
        }
        if (publicAssets.length > 0) {
          return verdict("warn", `${publicAssets.length}/${organizationAssets.length} Exchange asset(s) are published to the public portal; confirm each public asset passed governance review.`, evidence);
        }
        return verdict("manual", `${organizationAssets.length} Exchange asset(s) inventoried and none are public. Exchange does not expose review approvals: export the API Governance conformance report and the publishing settings that require review before publication.`, evidence);
      },
    ),
  ];

  return {
    category: "api_gateway",
    title: "MuleSoft API gateway and Exchange posture",
    // Counts derived from a list that was not read render null rather than the empty fallback's zero.
    summary: {
      organization_id: config.organizationId,
      environments_visible: derived(environments.all.length, environments.source),
      environments_sampled: derived(environments.sampled.length, environments.source),
      apis_sampled: derived(apiRecords.length, environments.source, apisSource),
      production_apis: derived(productionApis.length, environments.source, apisSource),
      production_without_authentication: derived(productionWithoutAuth.length, environments.source, apisSource, policiesSource),
      production_without_rate_limiting: derived(productionWithoutRateLimit.length, environments.source, apisSource, policiesSource),
      active_contracts: derived(activeContracts, environments.source, apisSource),
      exchange_assets: derived(organizationAssets.length, exchangeAssets),
      public_exchange_assets: derived(publicAssets.length, exchangeAssets),
      partial_view: partialViewOf(gatewayPartialNotes, environments.source, apisSource, policiesSource, exchangeAssets),
      unreadable_sources: errors.length,
      inventories: describeSources(environments.source, apisSource, policiesSource, exchangeAssets),
    },
    findings,
    snapshots: {
      api_manager_apis: snapshotOf(apisSource, apiRecords.map((record) => ({
        environment: environmentLabel(record.environment),
        environment_id: asString(record.environment.id),
        api: record.api,
        policies: sourceCollected(record.policies) ? record.policies.value.map(projectApiPolicy) : notCollectedMarker(record.policies),
        policies_error: record.policies.error ?? null,
      })), apiSources),
      exchange_assets: snapshotOf(exchangeAssets, organizationAssets),
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

// The snapshot keeps only what the runtime verdicts read. Property values are never copied, since CloudHub returns
// plaintext values for every property that is not marked secure.
function projectCloudhubApplication(application: JsonRecord): JsonRecord {
  const properties = asObject(application.properties);
  const propertyOptions = asObject(application.propertiesOptions) ?? {};
  const workers = asObject(application.workers);
  const workerType = asObject(workers?.type);
  const version = asObject(application.muleVersion);
  return {
    id: asString(application.id) ?? null,
    domain: asString(application.domain) ?? null,
    name: asString(application.name) ?? null,
    status: asString(application.status) ?? null,
    region: asString(application.region) ?? null,
    muleVersion: version
      ? {
        version: asString(version.version) ?? null,
        endOfSupportDate: asString(version.endOfSupportDate) ?? null,
        endOfLifeDate: asString(version.endOfLifeDate) ?? null,
      }
      : asString(application.muleVersion) ?? null,
    runtimeVersion: asString(application.runtimeVersion) ?? null,
    workers: workers
      ? {
        amount: asNumber(workers.amount) ?? null,
        type: workerType ? { name: asString(workerType.name) ?? null, weight: asNumber(workerType.weight) ?? null } : null,
        recentStatistics: { cpu: workerCpu(application) ?? null },
      }
      : null,
    persistentQueues: asBoolean(application.persistentQueues) ?? null,
    persistentQueuesEncrypted: asBoolean(application.persistentQueuesEncrypted) ?? null,
    persistentQueuesEncryptionEnabled: asBoolean(application.persistentQueuesEncryptionEnabled) ?? null,
    properties: properties ? Object.fromEntries(Object.keys(properties).map((key) => [key, REDACTED])) : null,
    securePropertyKeys: properties
      ? Object.keys(properties).filter((key) => asBoolean(getNestedValue(propertyOptions, [key, "secure"])) === true)
      : null,
    insecureSensitiveProperties: insecureSensitiveProperties(application),
  };
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

// OpenSSL cipher-string review for a DLB defaultCipherSuite. Entries prefixed with ! or - are exclusions and are ignored.
const WEAK_CIPHER_PATTERN = /(^|-)(RC4|RC2|DES|3DES|DES-CBC3|NULL|EXPORT|EXP|MD5|aNULL|eNULL|ADH|AECDH|IDEA|SEED|LOW|MEDIUM|SSLv3|SSLv2|COMPLEMENTOFDEFAULT|COMPLEMENTOFALL)(-|$)/i;
const BROAD_CIPHER_KEYWORD_PATTERN = /^(ALL|DEFAULT|HIGH|TLSv1|TLSv1\.[0-2]|kRSA|aRSA|RSA|AES|AESGCM|SHA|SHA1|SHA256|SHA384|CAMELLIA|kEECDH|kEDH)$/i;
const FORWARD_SECRET_CIPHER_PATTERN = /^(ECDHE|DHE|EECDH|EDH|TLS_|TLS13-)/i;

interface CipherSuiteReview {
  suites: string[];
  weak: string[];
  broadKeywords: string[];
  nonForwardSecrecy: string[];
}

interface CipherReviewRecord {
  loadBalancer: JsonRecord;
  cipherSuite?: string;
  review?: CipherSuiteReview;
}

function reviewCipherSuite(value: string): CipherSuiteReview {
  const suites = value.split(/[:,\s]+/).map((entry) => entry.trim()).filter((entry) => entry && !entry.startsWith("!") && !entry.startsWith("-"));
  const weak = suites.filter((entry) => WEAK_CIPHER_PATTERN.test(entry));
  const broadKeywords = suites.filter((entry) => BROAD_CIPHER_KEYWORD_PATTERN.test(entry));
  const nonForwardSecrecy = suites.filter((entry) =>
    !weak.includes(entry) && !broadKeywords.includes(entry) && !FORWARD_SECRET_CIPHER_PATTERN.test(entry) && !/^\+/.test(entry),
  );
  return { suites, weak, broadKeywords, nonForwardSecrecy };
}

function loadBalancerCipherSuite(loadBalancer: JsonRecord): string | undefined {
  return asString(loadBalancer.defaultCipherSuite);
}

function daysUntil(date: Date, now: number): number {
  return Math.floor((date.getTime() - now) / DAY_MS);
}

interface CertificateProbeRecord {
  loadBalancer: JsonRecord;
  sslEndpoint?: string;
  servername?: string;
  certificate?: MulesoftCertificateSummary;
  error?: string;
}

interface CertificateProbeTarget {
  label?: string;
  servername: string;
}

// A DLB selects the certificate by SNI, so each sslEndpoints entry is probed with its own name; wildcard names fall back
// to a concrete SAN and then to the DLB domain, which yields the default SSL endpoint's certificate.
function certificateProbeTargets(loadBalancer: JsonRecord, host: string): CertificateProbeTarget[] {
  const endpoints = asRecordArray(loadBalancer.sslEndpoints);
  if (endpoints.length === 0) return [{ servername: host }];
  const seen = new Set<string>();
  const targets: CertificateProbeTarget[] = [];
  for (const endpoint of endpoints) {
    const names = [asString(endpoint.publicKeyCN), ...asStringList(endpoint.publicKeySANs)].filter((name): name is string => Boolean(name));
    const servername = names.find((name) => !name.includes("*")) ?? host;
    if (seen.has(servername)) continue;
    seen.add(servername);
    targets.push({ label: asString(endpoint.publicKeyLabel) ?? asString(endpoint.publicKeyCN) ?? servername, servername });
  }
  return targets.length > 0 ? targets : [{ servername: host }];
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

  const scope = await collectOrganizationScope(client, errors);
  const environments = await sampleEnvironments(client, environmentLimit, errors);
  const applicationSources: Array<Collected<JsonRecord[]>> = [];
  const serverSources: Array<Collected<JsonRecord[]>> = [];
  const mqRegionSources: Array<Collected<JsonRecord[]>> = [];
  const mqQueueSources: Array<Collected<JsonRecord[]>> = [];
  const mqClientSources: Array<Collected<JsonRecord[]>> = [];
  const secretGroupSources: Array<Collected<JsonRecord[]>> = [];
  const applications: Array<{ environment: JsonRecord; application: JsonRecord }> = [];
  const servers: Array<{ environment: JsonRecord; server: JsonRecord }> = [];
  const mqInventory: Array<{ environment: string; region: string; queues: JsonRecord[] }> = [];
  const mqClients: Array<{ environment: string; clients: JsonRecord[] }> = [];
  const secretGroupsByEnvironment: Array<{ environment: JsonRecord; secretGroups: JsonRecord[] }> = [];
  let applicationsDropped = 0;

  for (const environment of environments.sampled) {
    const environmentId = asString(environment.id);
    const label = environmentLabel(environment);
    if (!environmentId) {
      applicationSources.push({ label: `cloudhub_applications:${label}`, value: [], error: "environment has no id" });
      continue;
    }
    const environmentApplications = await collect<JsonRecord[]>(`cloudhub_applications:${label}`, [], () => client.listCloudhubApplications(environmentId), errors);
    applicationSources.push(environmentApplications);
    for (const application of environmentApplications.value) {
      if (applications.length >= applicationLimit) {
        applicationsDropped += 1;
        continue;
      }
      applications.push({ environment, application });
    }

    const environmentServers = await collect<JsonRecord[]>(`hybrid_servers:${label}`, [], () => client.listHybridServers(environmentId), errors);
    serverSources.push(environmentServers);
    servers.push(...environmentServers.value.map((server) => ({ environment, server })));

    const regions = await collect<JsonRecord[]>(`mq_regions:${label}`, [], () => client.listMqRegions(environmentId), errors);
    mqRegionSources.push(regions);
    for (const region of regions.value) {
      const regionId = asString(region.regionId) ?? asString(region.id);
      if (!regionId) {
        mqQueueSources.push({ label: `mq_queues:${label}`, value: [], error: "MQ region has no id" });
        continue;
      }
      const queues = await collect<JsonRecord[]>(`mq_queues:${label}:${regionId}`, [], () => client.listMqQueues(environmentId, regionId), errors);
      mqQueueSources.push(queues);
      mqInventory.push({ environment: label, region: regionId, queues: queues.value });
    }
    if (regions.value.length > 0) {
      const clients = await collect<JsonRecord[]>(`mq_clients:${label}`, [], () => client.listMqClients(environmentId), errors);
      mqClientSources.push(clients);
      mqClients.push({ environment: label, clients: clients.value });
    }

    const secretGroups = await collect<JsonRecord[]>(`secret_groups:${label}`, [], () => client.listSecretGroups(environmentId), errors);
    secretGroupSources.push(secretGroups);
    secretGroupsByEnvironment.push({ environment, secretGroups: secretGroups.value });
  }
  const applicationsSource = mergeSources("cloudhub_applications", applicationSources, environments.source);
  const serversSource = mergeSources("hybrid_servers", serverSources, environments.source);
  const mqRegionsSource = mergeSources("mq_regions", mqRegionSources, environments.source);
  const mqQueuesSource = mergeSources("mq_queues", mqQueueSources, mqRegionsSource);
  const mqClientsSource = mergeSources("mq_clients", mqClientSources, mqRegionsSource);
  const secretGroupsSource = mergeSources("secret_groups", secretGroupSources, environments.source);

  const vpcSummaries = await collectPage("vpcs", () => client.listVpcs(DEFAULT_VPC_LIMIT), errors);
  const vpcPage = capPage(vpcSummaries.value, DEFAULT_VPC_LIMIT);
  const vpcDetails: Array<Collected<JsonRecord>> = [];
  const vpcs: JsonRecord[] = [];
  for (const vpc of vpcPage.items) {
    const vpcId = asString(vpc.id);
    const vpcName = asString(vpc.name) ?? vpcId ?? "vpc";
    const detail: Collected<JsonRecord> = vpcId
      ? await collect<JsonRecord>(`vpc:${vpcName}`, {}, () => client.getVpc(vpcId), errors)
      : { label: `vpc:${vpcName}`, value: {}, error: "VPC has no id" };
    vpcDetails.push(detail);
    vpcs.push({ ...vpc, ...detail.value });
  }
  const vpcDetailsSource = mergeSources("vpc_details", vpcDetails, vpcSummaries);
  const vpcPartialNote = truncationNote("VPC", vpcPage);
  const vpcsWithoutRules = vpcs.filter((vpc) => !Array.isArray(vpc.firewallRules));

  const loadBalancerSource = await collectPage("load_balancers", () => client.listLoadBalancers(DEFAULT_LOAD_BALANCER_LIMIT), errors);
  const loadBalancerPage = capPage(loadBalancerSource.value, DEFAULT_LOAD_BALANCER_LIMIT);
  const loadBalancerDetails: Array<Collected<JsonRecord>> = [];
  const loadBalancers: JsonRecord[] = [];
  for (const summary of loadBalancerPage.items) {
    const vpcId = asString(summary.vpcId);
    const loadBalancerId = asString(summary.id);
    if (loadBalancerCipherSuite(summary) !== undefined || !vpcId || !loadBalancerId) {
      loadBalancers.push(summary);
      continue;
    }
    const detail = await collect<JsonRecord>(`load_balancer:${loadBalancerLabel(summary)}`, {}, () => client.getLoadBalancer(vpcId, loadBalancerId), errors);
    loadBalancerDetails.push(detail);
    loadBalancers.push({ ...summary, ...detail.value });
  }
  const loadBalancerDetailsSource = mergeSources("load_balancer_details", loadBalancerDetails, loadBalancerSource);
  const loadBalancerPartialNote = truncationNote("load balancer", loadBalancerPage);
  // Certificate probes read sslEndpoints from the merged record, so a failed detail read leaves endpoints unprobed.
  const loadBalancerDetailNote = loadBalancerDetailsSource.error
    ? `${describeFailure(loadBalancerDetailsSource)}, so SSL endpoints carried only by the detail record were not probed`
    : undefined;
  const certificateProbes: CertificateProbeRecord[] = [];
  for (const loadBalancer of loadBalancers) {
    const host = asString(loadBalancer.domain);
    if (!host) {
      certificateProbes.push({ loadBalancer, error: "Load balancer did not expose a domain to probe." });
      continue;
    }
    for (const target of certificateProbeTargets(loadBalancer, host)) {
      try {
        const certificate = await client.probeCertificate(host, target.servername);
        certificateProbes.push({ loadBalancer, sslEndpoint: target.label, servername: target.servername, certificate });
      } catch (error) {
        const message = errorMessage(error);
        errors.push(`certificate_probe:${host}${target.servername === host ? "" : `:${target.servername}`}: ${message}`);
        certificateProbes.push({ loadBalancer, sslEndpoint: target.label, servername: target.servername, error: message });
      }
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
  const missingRuntimeVersion = applicationRecords.filter((item) => muleVersion(item.application) === undefined);

  const applicationsWithoutWorkerData = applicationRecords.filter((item) => asObject(item.application.workers) === undefined);
  const oversizedApplications = applicationRecords.filter((item) => {
    const amount = workerAmount(item.application);
    const weight = workerWeight(item.application);
    const cpu = workerCpu(item.application);
    if (!item.production && (amount > 1 || (weight !== undefined && weight >= 2))) return true;
    return amount >= 4 && cpu !== undefined && cpu < 10;
  });
  const largeApplicationsWithoutCpu = applicationRecords.filter((item) =>
    workerAmount(item.application) >= 4 && workerCpu(item.application) === undefined && !oversizedApplications.includes(item),
  );

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
  const loadBalancersMissingFlags = loadBalancers.filter((item) => asBoolean(item.tlsv1) === undefined || asString(item.httpMode) === undefined);
  const cipherReviews: CipherReviewRecord[] = loadBalancers.map((item) => {
    const cipherSuite = loadBalancerCipherSuite(item);
    return { loadBalancer: item, cipherSuite, review: cipherSuite === undefined ? undefined : reviewCipherSuite(cipherSuite) };
  });
  const loadBalancersMissingCiphers = cipherReviews.filter((item) => item.review === undefined);
  const weakCipherLoadBalancers = cipherReviews.filter((item) => item.review !== undefined && item.review.weak.length > 0);
  const legacyCipherLoadBalancers = cipherReviews.filter((item) =>
    item.review !== undefined && item.review.weak.length === 0 && (item.review.nonForwardSecrecy.length > 0 || item.review.broadKeywords.length > 0),
  );

  const certificateResults = certificateProbes.map((probe) => {
    const validTo = probe.certificate?.validTo ? asDate(probe.certificate.validTo) : undefined;
    return {
      load_balancer: loadBalancerLabel(probe.loadBalancer),
      ssl_endpoint: probe.sslEndpoint ?? null,
      host: asString(probe.loadBalancer.domain) ?? null,
      servername: probe.servername ?? null,
      subject: probe.certificate?.subject ?? null,
      issuer: probe.certificate?.issuer ?? null,
      valid_to: validTo ? validTo.toISOString() : null,
      days_remaining: validTo ? daysUntil(validTo, now) : null,
      authorized: probe.certificate?.authorized ?? null,
      authorization_error: probe.certificate?.authorizationError ?? null,
      error: probe.error ?? (validTo ? null : "Certificate did not expose a validTo date."),
    };
  });
  const expiringCertificates = certificateResults.filter((item) => item.days_remaining !== null && item.days_remaining <= DEFAULT_CERTIFICATE_FAIL_DAYS);
  const warningCertificates = certificateResults.filter((item) =>
    item.days_remaining !== null && item.days_remaining > DEFAULT_CERTIFICATE_FAIL_DAYS && item.days_remaining <= certificateWarningDays,
  );
  const probedCertificates = certificateResults.filter((item) => item.days_remaining !== null);
  const undatedCertificates = certificateResults.filter((item) => item.days_remaining === null);
  const untrustedCertificates = probedCertificates.filter((item) => item.authorized !== true);
  const describeCertificate = (item: (typeof certificateResults)[number]) =>
    item.ssl_endpoint ? `${item.load_balancer} (${item.ssl_endpoint})` : item.load_balancer;

  const allQueues = mqInventory.flatMap((item) => item.queues.map((queue) => ({ environment: item.environment, region: item.region, queue })));
  const unencryptedQueues = allQueues.filter((item) => asBoolean(item.queue.encrypted) !== true);
  const totalMqClients = mqClients.reduce((total, item) => total + item.clients.length, 0);

  const productionSecretGroups = secretGroupsByEnvironment.filter((item) => isProductionEnvironment(item.environment));
  const productionWithoutSecretGroups = productionSecretGroups.filter((item) => item.secretGroups.length === 0);
  const totalSecretGroups = secretGroupsByEnvironment.reduce((total, item) => total + item.secretGroups.length, 0);
  const insecureProperties = applicationRecords
    .map((item) => ({ application: item.label, keys: insecureSensitiveProperties(item.application) }))
    .filter((item) => item.keys.length > 0);
  const applicationsWithoutPropertyData = applicationRecords.filter((item) => asObject(item.application.properties) === undefined);

  const disconnectedServers = servers.filter((item) => !isServerRunning(item.server));
  const describeServers = (records: Array<{ environment: JsonRecord; server: JsonRecord }>) =>
    sample(records.map((item) => `${environmentLabel(item.environment)}: ${serverLabel(item.server)} (${asString(item.server.status) ?? "unknown"})`));

  const environmentPartialNotes = [...environments.partialNotes, scope.note];
  const applicationPartialNotes = [
    ...environmentPartialNotes,
    applicationsDropped > 0 ? `the application limit of ${applicationLimit} left ${applicationsDropped} application(s) uninspected` : undefined,
  ];
  const applicationInputs: EvaluationInputs = { primary: [environments.source, applicationsSource], partial: applicationPartialNotes };
  const vpcInputs: EvaluationInputs = { primary: [vpcSummaries, vpcDetailsSource], partial: [vpcPartialNote, scope.note] };
  const loadBalancerTlsInputs: EvaluationInputs = { primary: [loadBalancerSource, loadBalancerDetailsSource], partial: [loadBalancerPartialNote, scope.note] };
  const loadBalancerInputs: EvaluationInputs = { primary: [loadBalancerSource], partial: [loadBalancerPartialNote, loadBalancerDetailNote, scope.note] };
  const zeroApplicationsSummary = `Zero CloudHub 1.0 applications were visible in ${environments.sampled.length} sampled environment(s). Zero applications is treated as manual: this tool inventories CloudHub 1.0 only, so if workloads run on CloudHub 2.0, Runtime Fabric, or hybrid servers, export their configuration from Runtime Manager.`;
  const noVpcSummary = "Zero CloudHub VPCs are visible, which is treated as manual. If applications run in CloudHub 2.0 private spaces or Runtime Fabric, export the private space firewall rules or cluster network policy from Runtime Manager as evidence.";
  const noLoadBalancerSummary = "No dedicated load balancers exist, so this control is not applicable and is recorded as manual: confirm whether applications are exposed through the shared load balancer or CloudHub 2.0 ingress, whose TLS configuration MuleSoft manages.";

  const findings: MulesoftFinding[] = [
    evaluate(
      10,
      applicationInputs,
      "Export Runtime Manager > Applications with each application's Mule runtime version and confirm every version is within MuleSoft standard support.",
      () => {
        const evidence = {
          applications: applicationRecords.length,
          unsupported_runtime: sample(unsupportedRuntime.map((item) => `${item.label} (${muleVersion(item.application) ?? "unknown"})`)),
          expiring_runtime: sample(expiringRuntime.map((item) => `${item.label} (${muleVersion(item.application) ?? "unknown"})`)),
          unknown_support_dates: unknownRuntimeSupport.length,
          missing_runtime_version: sample(missingRuntimeVersion.map((item) => item.label)),
          support_warning_days: supportWarningDays,
        };
        if (applicationRecords.length === 0) return verdict("manual", zeroApplicationsSummary, evidence);
        if (unsupportedRuntime.length > 0) {
          return verdict("fail", `${unsupportedRuntime.length}/${applicationRecords.length} CloudHub application(s) run a Mule runtime that is past end of support or on Mule 3.`, evidence);
        }
        if (expiringRuntime.length > 0) {
          return verdict("warn", `${expiringRuntime.length} CloudHub application(s) run a runtime reaching end of support within ${supportWarningDays} days.`, evidence);
        }
        if (missingRuntimeVersion.length > 0) {
          return verdict("warn", `${missingRuntimeVersion.length} CloudHub application(s) did not expose a Mule runtime version, so their support status is unknown and not counted as supported.`, evidence);
        }
        if (unknownRuntimeSupport.length > 0) {
          return verdict("warn", `${unknownRuntimeSupport.length} CloudHub application(s) did not expose an end of support date, so they are not counted as supported.`, evidence);
        }
        return verdict("pass", `All ${applicationRecords.length} CloudHub application(s) run supported Mule runtime versions with end of support dates in the future.`, evidence);
      },
    ),
    evaluate(
      11,
      applicationInputs,
      "Export Runtime Manager > Applications with worker count, worker size, and recent CPU utilization for each application.",
      () => {
        const evidence = {
          applications: applicationRecords.length,
          oversized_applications: sample(oversizedApplications.map((item) =>
            `${item.label}: ${workerAmount(item.application)} x ${asString(getNestedValue(item.application, ["workers", "type", "name"])) ?? "worker"}`,
          )),
          applications_without_worker_data: sample(applicationsWithoutWorkerData.map((item) => item.label)),
          applications_with_cpu_statistics: applicationRecords.filter((item) => workerCpu(item.application) !== undefined).length,
          large_applications_without_cpu_statistics: sample(largeApplicationsWithoutCpu.map((item) => item.label)),
        };
        if (applicationRecords.length === 0) return verdict("manual", zeroApplicationsSummary, evidence);
        if (oversizedApplications.length > 0) {
          return verdict("warn", `${oversizedApplications.length} CloudHub application(s) look over-provisioned (multiple or large workers in non-production, or four or more workers with CPU under 10 percent from workers.recentStatistics).`, evidence);
        }
        if (applicationsWithoutWorkerData.length > 0) {
          return verdict("warn", `${applicationsWithoutWorkerData.length} CloudHub application(s) did not expose worker sizing data, so their sizing could not be reviewed.`, evidence);
        }
        if (largeApplicationsWithoutCpu.length > 0) {
          return verdict("warn", `${largeApplicationsWithoutCpu.length} CloudHub application(s) run four or more workers but returned no recentStatistics.cpu even with retrieveStatistics=true, so their utilization could not be reviewed and is not counted as right-sized.`, evidence);
        }
        return verdict("pass", `${applicationRecords.length} CloudHub application(s) reviewed with worker sizing data present and no obvious over-provisioning.`, evidence);
      },
    ),
    evaluate(
      12,
      applicationInputs,
      "Export each application's persistent queue settings from Runtime Manager > Application > Settings and confirm encryption is enabled wherever persistent queues are on.",
      () => {
        const evidence = {
          applications: applicationRecords.length,
          persistent_queue_applications: persistentQueueApplications.length,
          unencrypted_queue_applications: sample(unencryptedQueueApplications.map((item) => item.label)),
        };
        if (applicationRecords.length === 0) return verdict("manual", zeroApplicationsSummary, evidence);
        if (persistentQueueApplications.length === 0) {
          return verdict("manual", `None of the ${applicationRecords.length} CloudHub application(s) enable persistent queues (persistentQueues is false or absent on every application), so encryption of persistent queues is not applicable and is recorded as manual rather than pass.`, evidence);
        }
        if (unencryptedQueueApplications.length > 0) {
          return verdict("fail", `${unencryptedQueueApplications.length}/${persistentQueueApplications.length} application(s) with persistent queues do not encrypt them.`, evidence);
        }
        return verdict("pass", `All ${persistentQueueApplications.length} application(s) with persistent queues encrypt them (persistentQueuesEncrypted=true confirmed).`, evidence);
      },
    ),
    evaluate(
      13,
      vpcInputs,
      "Export Runtime Manager > VPCs > Firewall Rules for every VPC and confirm each rule names a specific protocol, port range, and source network.",
      () => {
        const evidence = {
          vpcs: vpcs.length,
          firewall_rules: firewallRules.length,
          vpcs_without_firewall_rules: sample(vpcsWithoutRules.map((vpc) => asString(vpc.name) ?? asString(vpc.id) ?? "vpc")),
          all_protocol_rules: sample(allProtocolRules.map((item) => ruleLabel(item.vpc, item.rule))),
          wide_port_rules: sample(widePortRules.map((item) => ruleLabel(item.vpc, item.rule))),
          broad_cidr_rules: sample(broadCidrRules.map((item) => ruleLabel(item.vpc, item.rule))),
        };
        if (vpcs.length === 0) return verdict("manual", noVpcSummary, evidence);
        if (allProtocolRules.length > 0) {
          return verdict("fail", `${allProtocolRules.length} VPC firewall rule(s) allow all protocols.`, evidence);
        }
        if (vpcsWithoutRules.length > 0) {
          return verdict("manual", `${vpcsWithoutRules.length}/${vpcs.length} VPC(s) did not return a firewallRules list, so their rules are unknown and cannot be counted as restrictive.`, evidence);
        }
        if (widePortRules.length > 0 || broadCidrRules.length > 0) {
          return verdict("warn", `${widePortRules.length} firewall rule(s) span wide port ranges and ${broadCidrRules.length} allow CIDR blocks broader than /16.`, evidence);
        }
        return verdict("pass", `${firewallRules.length} firewall rule(s) across ${vpcs.length} VPC(s) are limited to specific ports and networks.`, evidence);
      },
    ),
    evaluate(
      14,
      vpcInputs,
      "Export Runtime Manager > VPCs > Firewall Rules for every VPC and confirm no inbound rule uses 0.0.0.0/0 or ::/0 outside the CloudHub HTTP listener ports.",
      () => {
        const evidence = {
          vpcs: vpcs.length,
          vpcs_without_firewall_rules: sample(vpcsWithoutRules.map((vpc) => asString(vpc.name) ?? asString(vpc.id) ?? "vpc")),
          open_non_standard_rules: sample(openNonStandardRules.map((item) => ruleLabel(item.vpc, item.rule))),
          open_standard_port_rules: sample(openStandardRules.map((item) => ruleLabel(item.vpc, item.rule))),
        };
        if (vpcs.length === 0) return verdict("manual", noVpcSummary, evidence);
        if (openNonStandardRules.length > 0) {
          return verdict("fail", `${openNonStandardRules.length} VPC firewall rule(s) allow 0.0.0.0/0 ingress on ports other than the externally exposed CloudHub listener ports 8081 and 8082 (8091 and 8092 are DLB back-end ports that must stay scoped to the VPC).`, evidence);
        }
        if (vpcsWithoutRules.length > 0) {
          return verdict("manual", `${vpcsWithoutRules.length}/${vpcs.length} VPC(s) did not return a firewallRules list, so open ingress cannot be ruled out.`, evidence);
        }
        if (openStandardRules.length > 0) {
          return verdict("warn", `${openStandardRules.length} VPC firewall rule(s) allow 0.0.0.0/0 ingress on the CloudHub listener ports 8081 or 8082; confirm the applications are intended to be internet-facing.`, evidence);
        }
        return verdict("pass", `No firewall rule across ${vpcs.length} VPC(s) with ${firewallRules.length} rule(s) allows 0.0.0.0/0 ingress.`, evidence);
      },
    ),
    evaluate(
      15,
      loadBalancerTlsInputs,
      "Export Runtime Manager > Load Balancers > each load balancer's TLS settings (tlsv1, tlsv13, httpMode) and the defaultCipherSuite from GET /cloudhub/api/organizations/{orgId}/vpcs/{vpcId}/loadbalancers/{dlbId} as evidence.",
      () => {
        const describeCiphers = (items: CipherReviewRecord[], pick: (review: CipherSuiteReview) => string[]) =>
          sample(items.flatMap((item) => (item.review ? [`${loadBalancerLabel(item.loadBalancer)}: ${pick(item.review).join(", ")}`] : [])));
        const evidence = {
          load_balancers: cipherReviews.map((item) => ({
            name: loadBalancerLabel(item.loadBalancer),
            http_mode: asString(item.loadBalancer.httpMode) ?? null,
            tlsv1: asBoolean(item.loadBalancer.tlsv1) ?? null,
            tlsv13: asBoolean(item.loadBalancer.tlsv13) ?? null,
            state: asString(item.loadBalancer.state) ?? null,
            default_cipher_suite: item.cipherSuite ?? null,
            cipher_suites: item.review?.suites.length ?? null,
            weak_ciphers: item.review?.weak ?? [],
            non_forward_secrecy_ciphers: item.review?.nonForwardSecrecy ?? [],
            broad_cipher_keywords: item.review?.broadKeywords ?? [],
          })),
          weak_cipher_pattern: "RC4, DES/3DES, NULL, EXPORT, MD5, anonymous (aNULL/ADH/AECDH), IDEA, SEED, LOW, MEDIUM, SSLv2/SSLv3",
        };
        if (loadBalancers.length === 0) return verdict("manual", noLoadBalancerSummary, evidence);
        if (tls10LoadBalancers.length > 0) {
          return verdict("fail", `${tls10LoadBalancers.length}/${loadBalancers.length} dedicated load balancer(s) still accept TLS 1.0 and 1.1.`, evidence);
        }
        if (weakCipherLoadBalancers.length > 0) {
          return verdict("fail", `${weakCipherLoadBalancers.length}/${loadBalancers.length} dedicated load balancer(s) have a defaultCipherSuite that still offers weak ciphers (${describeCiphers(weakCipherLoadBalancers, (review) => review.weak).join("; ")}); rotate to a suite such as NewDefault-v1 via PATCH /defaultCipherSuiteName.`, evidence);
        }
        if (plainHttpLoadBalancers.length > 0) {
          return verdict("warn", `${plainHttpLoadBalancers.length} dedicated load balancer(s) accept plain HTTP without redirecting to HTTPS.`, evidence);
        }
        if (loadBalancersMissingFlags.length > 0) {
          return verdict("warn", `${loadBalancersMissingFlags.length}/${loadBalancers.length} dedicated load balancer(s) did not return the tlsv1 or httpMode flags, so their TLS posture cannot be confirmed.`, evidence);
        }
        if (loadBalancersMissingCiphers.length > 0) {
          return verdict("warn", `${loadBalancersMissingCiphers.length}/${loadBalancers.length} dedicated load balancer(s) did not return defaultCipherSuite (${sample(loadBalancersMissingCiphers.map((item) => loadBalancerLabel(item.loadBalancer))).join(", ")}), so cipher strength cannot be confirmed and is not counted as strong.`, evidence);
        }
        if (legacyCipherLoadBalancers.length > 0) {
          return verdict("warn", `${legacyCipherLoadBalancers.length}/${loadBalancers.length} dedicated load balancer(s) have a defaultCipherSuite that includes non-forward-secret or broad OpenSSL groups (${describeCiphers(legacyCipherLoadBalancers, (review) => [...review.nonForwardSecrecy, ...review.broadKeywords]).join("; ")}); prefer ECDHE/DHE AES-GCM suites only.`, evidence);
        }
        return verdict("pass", `All ${loadBalancers.length} dedicated load balancer(s) report tlsv1=false, an httpMode that does not serve plain HTTP, and a defaultCipherSuite limited to forward-secret suites with no RC4, DES, NULL, EXPORT, or MD5 ciphers.`, evidence);
      },
    ),
    evaluate(
      16,
      loadBalancerInputs,
      "Open Runtime Manager > Load Balancers > certificates and record each SSL endpoint certificate's expiry date and issuing chain.",
      () => {
        const evidence = {
          certificates: certificateResults,
          certificates_probed: certificateResults.length,
          load_balancers: loadBalancers.length,
          fail_days: DEFAULT_CERTIFICATE_FAIL_DAYS,
          warning_days: certificateWarningDays,
          probe_note: "The TLS probe connects with rejectUnauthorized=false so untrusted chains can still be read; authorized and authorization_error record whether each chain validated against the auditor's trust store.",
        };
        if (loadBalancers.length === 0) return verdict("manual", noLoadBalancerSummary, evidence);
        if (expiringCertificates.length > 0) {
          return verdict("fail", `${expiringCertificates.length} dedicated load balancer certificate(s) are expired or expire within ${DEFAULT_CERTIFICATE_FAIL_DAYS} days (${sample(expiringCertificates.map(describeCertificate)).join(", ")}).`, evidence);
        }
        if (warningCertificates.length > 0) {
          return verdict("warn", `${warningCertificates.length} dedicated load balancer certificate(s) expire within ${certificateWarningDays} days (${sample(warningCertificates.map(describeCertificate)).join(", ")}).`, evidence);
        }
        if (probedCertificates.length === 0) {
          return verdict("manual", "None of the load balancer certificates could be dated over TLS. Open Runtime Manager > Load Balancers > certificates and record each certificate expiry date.", evidence);
        }
        if (undatedCertificates.length > 0) {
          return verdict("warn", `${undatedCertificates.length}/${certificateResults.length} dedicated load balancer certificate(s) could not be dated (probe failed or no validTo date) and are not counted as valid; record their expiry dates manually.`, evidence);
        }
        if (untrustedCertificates.length > 0) {
          const causes = sample(untrustedCertificates.map((item) => `${describeCertificate(item)}: ${item.authorization_error ?? "chain validation not reported"}`));
          return verdict("warn", `${untrustedCertificates.length}/${probedCertificates.length} dedicated load balancer certificate(s) are dated but their chain did not validate against the auditor's trust store (${causes.join("; ")}); a self-signed, expired-intermediate, or private-CA chain is not counted as valid, so confirm the chain in Runtime Manager.`, evidence);
        }
        return verdict("pass", `All ${probedCertificates.length} dedicated load balancer certificate(s) across ${loadBalancers.length} load balancer(s) were probed, validated against the auditor's trust store, and remain valid for more than ${certificateWarningDays} days.`, evidence);
      },
    ),
    evaluate(
      21,
      { primary: [environments.source, mqRegionsSource, mqQueuesSource], secondary: [mqClientsSource], partial: environmentPartialNotes },
      "Export Anypoint MQ client apps per environment and the MQ role assignments from Access Management, then confirm no client credential is shared across environments.",
      () => {
        const evidence = {
          environments_with_mq: [...new Set(mqInventory.map((item) => item.environment))],
          queues: allQueues.length,
          unencrypted_queues: sample(unencryptedQueues.map((item) => `${item.environment}/${item.region}: ${asString(item.queue.queueId) ?? "queue"}`)),
          mq_clients: mqClients.map((item) => ({ environment: item.environment, clients: item.clients.length })),
        };
        if (mqInventory.length === 0) {
          return verdict("manual", `Anypoint MQ returned zero regions in ${environments.sampled.length} sampled environment(s), so this control is not applicable and is recorded as manual: confirm in Anypoint MQ that no queues or client apps exist.`, evidence);
        }
        if (unencryptedQueues.length > 0) {
          return verdict("warn", `${unencryptedQueues.length}/${allQueues.length} Anypoint MQ queue(s) are not encrypted; MQ client apps are environment-scoped by design, so also confirm credentials are not shared across environments.`, evidence);
        }
        return verdict("manual", `${allQueues.length} queue(s) and ${totalMqClients} MQ client app(s) inventoried per environment. Confirm MQ client app credentials are not reused across environments and MQ roles are environment-scoped in Access Management.`, evidence);
      },
    ),
    evaluate(
      22,
      { primary: [environments.source, applicationsSource, secretGroupsSource], partial: applicationPartialNotes },
      "Export Secrets Manager > Secret Groups per production environment and each application's properties (with the secure flag) from Runtime Manager.",
      () => {
        const evidence = {
          secret_groups_by_environment: secretGroupsByEnvironment.map((item) => ({
            environment: environmentLabel(item.environment),
            production: isProductionEnvironment(item.environment),
            secret_groups: item.secretGroups.length,
          })),
          applications_with_property_data: applicationRecords.length - applicationsWithoutPropertyData.length,
          applications_without_property_data: sample(applicationsWithoutPropertyData.map((item) => item.label)),
          insecure_property_keys: sample(insecureProperties.map((item) => `${item.application}: ${item.keys.join(", ")}`)),
        };
        if (insecureProperties.length > 0) {
          return verdict("fail", `${insecureProperties.length} CloudHub application(s) expose sensitive-looking properties that are not marked secure.`, evidence);
        }
        if (applicationRecords.length === 0) return verdict("manual", zeroApplicationsSummary, evidence);
        if (productionSecretGroups.length === 0) {
          return verdict("manual", `No production environment was sampled (${productionSampleNote(environments)}), so Secrets Manager coverage cannot be confirmed. Treated as manual.`, evidence);
        }
        if (productionWithoutSecretGroups.length > 0) {
          return verdict("warn", `${productionWithoutSecretGroups.length} production environment(s) have no Secrets Manager secret groups.`, evidence);
        }
        if (applicationsWithoutPropertyData.length > 0) {
          return verdict("warn", `${applicationsWithoutPropertyData.length}/${applicationRecords.length} CloudHub application(s) did not return a properties object, so their configuration could not be checked for plaintext secrets.`, evidence);
        }
        return verdict("pass", `All ${productionSecretGroups.length} production environment(s) have Secrets Manager secret groups and every one of ${applicationRecords.length} application(s) returned properties with no insecure sensitive keys.`, evidence);
      },
    ),
    evaluate(
      23,
      { primary: [environments.source, serversSource], partial: environmentPartialNotes },
      "Export Runtime Manager > Servers for each environment and confirm every registered server reports RUNNING.",
      () => {
        const evidence = {
          servers: servers.length,
          disconnected_servers: describeServers(disconnectedServers),
          mule_versions: [...new Set(servers.map((item) => asString(item.server.muleVersion) ?? "unknown"))],
        };
        if (servers.length === 0) {
          return verdict("manual", `Zero hybrid runtime servers are registered in ${environments.sampled.length} sampled environment(s), so this control is not applicable and is recorded as manual: confirm in Runtime Manager > Servers that no on-premises runtimes are expected.`, evidence);
        }
        if (disconnectedServers.length === servers.length) {
          return verdict("fail", `All ${servers.length} hybrid runtime server(s) are disconnected or not reporting.`, evidence);
        }
        if (disconnectedServers.length > 0) {
          return verdict("warn", `${disconnectedServers.length}/${servers.length} hybrid runtime server(s) are not in RUNNING state.`, evidence);
        }
        return verdict("pass", `All ${servers.length} hybrid runtime server(s) are registered and reporting RUNNING.`, evidence);
      },
    ),
  ];

  return {
    category: "runtime_infrastructure",
    title: "MuleSoft runtime and infrastructure posture",
    // Counts derived from a list that was not read render null rather than the empty fallback's zero.
    summary: {
      organization_id: config.organizationId,
      environments_visible: derived(environments.all.length, environments.source),
      environments_sampled: derived(environments.sampled.length, environments.source),
      cloudhub_applications: derived(applicationRecords.length, environments.source, applicationsSource),
      applications_not_inspected: derived(applicationsDropped, environments.source, applicationsSource),
      unsupported_runtime_applications: derived(unsupportedRuntime.length, environments.source, applicationsSource),
      vpcs: derived(vpcs.length, vpcSummaries),
      firewall_rules: derived(firewallRules.length, vpcSummaries, vpcDetailsSource),
      load_balancers: derived(loadBalancers.length, loadBalancerSource),
      hybrid_servers: derived(servers.length, environments.source, serversSource),
      mq_queues: derived(allQueues.length, environments.source, mqRegionsSource, mqQueuesSource),
      secret_groups: derived(totalSecretGroups, environments.source, secretGroupsSource),
      partial_view: partialViewOf(
        [...applicationPartialNotes, vpcPartialNote, loadBalancerPartialNote],
        environments.source, applicationsSource, serversSource, mqRegionsSource, mqQueuesSource, mqClientsSource, secretGroupsSource, vpcSummaries, vpcDetailsSource, loadBalancerSource, loadBalancerDetailsSource,
      ),
      unreadable_sources: errors.length,
      inventories: describeSources(environments.source, applicationsSource, serversSource, mqRegionsSource, mqQueuesSource, mqClientsSource, secretGroupsSource, vpcSummaries, vpcDetailsSource, loadBalancerSource, loadBalancerDetailsSource),
    },
    findings,
    snapshots: {
      cloudhub_applications: snapshotOf(applicationsSource, applications.map((item) => ({
        environment: environmentLabel(item.environment),
        environment_id: asString(item.environment.id),
        application: projectCloudhubApplication(item.application),
      })), applicationSources),
      vpcs: snapshotOf(vpcSummaries, vpcs),
      load_balancers: snapshotOf(loadBalancerSource, loadBalancers),
      load_balancer_certificates: certificateResults,
      hybrid_servers: snapshotOf(serversSource, servers.map((item) => ({ environment: environmentLabel(item.environment), server: item.server })), serverSources),
      mq_queues: snapshotOf(mqQueuesSource, mqInventory, mqQueueSources),
      mq_clients: snapshotOf(mqClientsSource, mqClients, mqClientSources),
      secret_groups: snapshotOf(secretGroupsSource, secretGroupsByEnvironment.map((item) => ({
        environment: environmentLabel(item.environment),
        secret_groups: item.secretGroups,
      })), secretGroupSources),
    },
    errors,
  };
}

type AlertState = "enabled" | "disabled" | "unknown";

function alertState(alert: JsonRecord): AlertState {
  const enabled = asBoolean(alert.enabled);
  if (enabled === true) return "enabled";
  if (enabled === false) return "disabled";
  return "unknown";
}

function alertResources(alert: JsonRecord): string[] {
  return asStringList(firstDefined(alert, [["condition", "resources"], ["resources"]]));
}

function alertCoversApplication(alert: JsonRecord, domain: string): boolean {
  return alertResources(alert).some((resource) => resource === "*" || resource.toLowerCase() === domain.toLowerCase());
}

function auditEntrySummary(entry: JsonRecord): JsonRecord {
  return {
    timestamp: asString(firstDefined(entry, [["timestamp"], ["time"], ["createdAt"]])) ?? null,
    platform: asString(firstDefined(entry, [["platform"], ["product"]])) ?? null,
    action: asString(firstDefined(entry, [["action"], ["actionType"], ["type"]])) ?? null,
    object_type: asString(firstDefined(entry, [["objectType"], ["objectTypes", "0"]])) ?? null,
  };
}

interface AuditRetentionEntry {
  retention_period_days: number | null;
  effective_from: string | null;
}

interface AuditRetentionSummary {
  currentPeriodDays: number | null;
  scheduledChange: AuditRetentionEntry | null;
  entries: AuditRetentionEntry[];
}

// GET /audit/v2/organizations/{orgId}/retentionSettings returns every retention entry, including a
// scheduled future change (effectiveFrom at least seven days ahead). The entry in force is the latest
// one whose effectiveFrom is null or already past; a future entry is reported as a scheduled change.
function summarizeAuditRetention(entries: JsonRecord[], now: number): AuditRetentionSummary {
  const normalized: AuditRetentionEntry[] = entries.map((entry) => ({
    retention_period_days: asNumber(entry.retentionPeriod) ?? null,
    effective_from: asString(entry.effectiveFrom) ?? null,
  }));
  const effectiveTime = (entry: AuditRetentionEntry): number | undefined =>
    entry.effective_from === null ? Number.NEGATIVE_INFINITY : asDate(entry.effective_from)?.getTime();
  const inForce = normalized
    .filter((entry) => entry.retention_period_days !== null)
    .filter((entry) => {
      const time = effectiveTime(entry);
      return time !== undefined && time <= now;
    })
    .sort((left, right) => (effectiveTime(right) ?? 0) - (effectiveTime(left) ?? 0));
  const scheduled = normalized
    .filter((entry) => entry.retention_period_days !== null)
    .filter((entry) => {
      const time = effectiveTime(entry);
      return time !== undefined && time > now;
    })
    .sort((left, right) => (effectiveTime(left) ?? 0) - (effectiveTime(right) ?? 0));
  return {
    currentPeriodDays: inForce[0]?.retention_period_days ?? null,
    scheduledChange: scheduled[0] ?? null,
    entries: normalized,
  };
}

function auditRetentionNote(retention: AuditRetentionSummary, source: Collected<JsonRecord[]>): string {
  if (source.error) {
    return ` Retention settings could not be read (${source.error}); confirm the audit log retention period in Access Management > Settings of the root organization.`;
  }
  if (retention.currentPeriodDays === null) {
    return " Retention settings returned no retention period; confirm it in Access Management > Settings of the root organization.";
  }
  const scheduled = retention.scheduledChange
    ? `, changing to ${retention.scheduledChange.retention_period_days} days from ${retention.scheduledChange.effective_from}`
    : "";
  return ` Audit log retention is ${retention.currentPeriodDays} days${scheduled}.`;
}

interface AlertCoverage {
  environment: string;
  cloudhubAlerts: Collected<JsonRecord[]>;
  hybridAlerts: Collected<JsonRecord[]>;
  applications: Collected<JsonRecord[]>;
  enabledAlerts: JsonRecord[];
  unknownStateAlerts: JsonRecord[];
  uncoveredApplications: string[];
  unknownCoverageApplications: string[];
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

  const scope = await collectOrganizationScope(client, errors);
  const platforms = await collect<JsonRecord[]>("audit_platforms", [], () => client.listAuditPlatforms(), errors);
  const retentionSettings = await collect<JsonRecord[]>("audit_retention_settings", [], () => client.getAuditRetentionSettings(), errors);
  const retention = summarizeAuditRetention(retentionSettings.value, now);
  const startDate = new Date(now - lookbackHours * 60 * 60 * 1000).toISOString();
  const endDate = new Date(now).toISOString();
  const recentQuery = await collect<JsonRecord>("audit_query", {}, () => client.queryAuditLogs({ startDate, endDate, limit: AUDIT_QUERY_PAGE_LIMIT }), errors);
  const recentEntries = extractCollection(recentQuery.value);
  const recentTotal = asNumber(recentQuery.value.total);
  const fallbackRequested = !recentQuery.error && recentEntries.length === 0;
  const fallbackQuery: Collected<JsonRecord> = fallbackRequested
    ? await collect<JsonRecord>("audit_query_fallback", {}, () => client.queryAuditLogs({
      startDate: new Date(now - AUDIT_FALLBACK_LOOKBACK_DAYS * DAY_MS).toISOString(),
      endDate,
      limit: 1,
    }), errors)
    : { label: "audit_query_fallback", value: {} };
  const fallbackEntries = extractCollection(fallbackQuery.value);

  const environments = await sampleEnvironments(client, environmentLimit, errors);
  const environmentPartialNotes = [...environments.partialNotes, scope.note];
  const productionEnvironments = environments.sampled.filter(isProductionEnvironment);
  const alertCoverage: AlertCoverage[] = [];
  for (const environment of productionEnvironments) {
    const environmentId = asString(environment.id);
    const label = environmentLabel(environment);
    if (!environmentId) {
      const missing = { label: `alerts:${label}`, value: [] as JsonRecord[], error: "environment has no id" };
      alertCoverage.push({
        environment: label,
        cloudhubAlerts: missing,
        hybridAlerts: missing,
        applications: missing,
        enabledAlerts: [],
        unknownStateAlerts: [],
        uncoveredApplications: [],
        unknownCoverageApplications: [],
      });
      continue;
    }
    const cloudhubAlerts = await collect<JsonRecord[]>(`cloudhub_alerts:${label}`, [], () => client.listCloudhubAlerts(environmentId), errors);
    const hybridAlerts = await collect<JsonRecord[]>(`hybrid_alerts:${label}`, [], () => client.listHybridAlerts(environmentId), errors);
    const applications = await collect<JsonRecord[]>(`cloudhub_applications:${label}`, [], () => client.listCloudhubApplications(environmentId), errors);
    const allAlerts = [...cloudhubAlerts.value, ...hybridAlerts.value];
    const enabledAlerts = allAlerts.filter((alert) => alertState(alert) === "enabled");
    const unknownStateAlerts = allAlerts.filter((alert) => alertState(alert) === "unknown");
    const domains = applications.value.map(applicationLabel);
    const uncoveredApplications = domains.filter((domain) =>
      !enabledAlerts.some((alert) => alertCoversApplication(alert, domain))
      && !unknownStateAlerts.some((alert) => alertCoversApplication(alert, domain)));
    const unknownCoverageApplications = domains.filter((domain) =>
      !enabledAlerts.some((alert) => alertCoversApplication(alert, domain))
      && unknownStateAlerts.some((alert) => alertCoversApplication(alert, domain)));
    alertCoverage.push({
      environment: label,
      cloudhubAlerts,
      hybridAlerts,
      applications,
      enabledAlerts,
      unknownStateAlerts,
      uncoveredApplications,
      unknownCoverageApplications,
    });
  }
  const alertReads = alertCoverage.flatMap((item) => [item.cloudhubAlerts, item.hybridAlerts]);
  const alertsSource = mergeSources("alerts", alertReads, environments.source);
  const applicationsSource = mergeSources("cloudhub_applications", alertCoverage.map((item) => item.applications), environments.source);

  const environmentsWithoutAlerts = alertCoverage.filter((item) => item.enabledAlerts.length === 0 && item.unknownStateAlerts.length === 0);
  const environmentsWithOnlyUnknownAlerts = alertCoverage.filter((item) => item.enabledAlerts.length === 0 && item.unknownStateAlerts.length > 0);
  const uncoveredApplications = alertCoverage.flatMap((item) => item.uncoveredApplications.map((domain) => `${item.environment}: ${domain}`));
  const unknownCoverageApplications = alertCoverage.flatMap((item) => item.unknownCoverageApplications.map((domain) => `${item.environment}: ${domain}`));
  const totalProductionApplications = alertCoverage.reduce((total, item) => total + item.applications.value.length, 0);
  const totalEnabledAlerts = alertCoverage.reduce((total, item) => total + item.enabledAlerts.length, 0);
  const totalUnknownStateAlerts = alertCoverage.reduce((total, item) => total + item.unknownStateAlerts.length, 0);

  const findings: MulesoftFinding[] = [
    evaluate(
      17,
      { primary: [recentQuery, fallbackQuery], partial: [scope.note] },
      "Export Access Management > Audit Log for the review period, or grant the credential the Audit Log Viewer permission and rerun.",
      () => {
        const entriesInWindow = recentTotal ?? recentEntries.length;
        const evidence = {
          lookback_hours: lookbackHours,
          entries_in_window: entriesInWindow,
          entries_fetched: recentEntries.length,
          entries_in_fallback_window: fallbackRequested ? fallbackEntries.length : null,
          fallback_lookback_days: AUDIT_FALLBACK_LOOKBACK_DAYS,
          platforms: derived(platforms.value.map((platform) => asString(platform.name) ?? asString(platform.label) ?? "platform"), platforms),
          platforms_error: platforms.error ?? null,
          retention_period_days: retention.currentPeriodDays,
          retention_scheduled_change: derived(retention.scheduledChange, retentionSettings),
          retention_entries: derived(retention.entries, retentionSettings),
          retention_settings_error: retentionSettings.error ?? null,
          retention_settings_source: "GET /audit/v2/organizations/{orgId}/retentionSettings; evidence only, the verdict does not depend on it",
          recent_entries: sample(recentEntries.map(auditEntrySummary), 10),
        };
        const retentionNote = auditRetentionNote(retention, retentionSettings);
        if (recentEntries.length > 0) {
          const fetchedNote = entriesInWindow > recentEntries.length ? ` (${recentEntries.length} fetched)` : "";
          const platformsNote = platforms.error
            ? `; the audit platform list is unknown because ${describeFailure(platforms)}.`
            : ` across ${platforms.value.length} platform(s).`;
          return verdict("pass", `${entriesInWindow} audit log entr${entriesInWindow === 1 ? "y" : "ies"} recorded within the last ${lookbackHours} hours${fetchedNote}${platformsNote}${retentionNote}`, evidence);
        }
        if (fallbackEntries.length > 0) {
          return verdict("warn", `Audit logging is queryable but no entries were recorded in the last ${lookbackHours} hours; the most recent activity is older than that window.${retentionNote}`, evidence);
        }
        return verdict("fail", `Audit logging returned zero entries in the last ${AUDIT_FALLBACK_LOOKBACK_DAYS} days. Zero events is treated as fail: either the platform is not recording activity or the credential cannot see the entries; export Access Management > Audit Log to confirm.${retentionNote}`, evidence);
      },
    ),
    evaluate(
      24,
      { primary: [environments.source, alertsSource, applicationsSource], partial: environmentPartialNotes },
      "Export Runtime Manager > Alerts and Anypoint Monitoring > Alerts for each production environment and map every production application to at least one enabled alert.",
      () => {
        const evidence = {
          production_environments: alertCoverage.map((item) => ({
            environment: item.environment,
            cloudhub_alerts: derived(item.cloudhubAlerts.value.length, item.cloudhubAlerts),
            runtime_manager_alerts: derived(item.hybridAlerts.value.length, item.hybridAlerts),
            enabled_alerts: derived(item.enabledAlerts.length, item.cloudhubAlerts, item.hybridAlerts),
            unknown_state_alerts: derived(item.unknownStateAlerts.length, item.cloudhubAlerts, item.hybridAlerts),
            applications: derived(item.applications.value.length, item.applications),
            uncovered_applications: derived(sample(item.uncoveredApplications), item.applications, item.cloudhubAlerts, item.hybridAlerts),
            unknown_coverage_applications: derived(sample(item.unknownCoverageApplications), item.applications, item.cloudhubAlerts, item.hybridAlerts),
          })),
          environments_without_alerts: environmentsWithoutAlerts.map((item) => item.environment),
          production_environments_sampled: productionSampleNote(environments),
        };
        if (productionEnvironments.length === 0) {
          return verdict("manual", `No production environment was sampled (${productionSampleNote(environments)}), so alert coverage cannot be evaluated. Treated as manual.`, evidence);
        }
        if (environmentsWithoutAlerts.length > 0) {
          return verdict("fail", `${environmentsWithoutAlerts.length} production environment(s) have no enabled CloudHub or Runtime Manager alerts.`, evidence);
        }
        if (environmentsWithOnlyUnknownAlerts.length > 0) {
          return verdict("warn", `${environmentsWithOnlyUnknownAlerts.length} production environment(s) only have alerts whose enabled flag was not returned, so active alerting cannot be confirmed.`, evidence);
        }
        if (totalProductionApplications === 0) {
          return verdict("manual", `${totalEnabledAlerts} enabled alert(s) exist but zero CloudHub applications are deployed in the sampled production environment(s), so there is nothing for the alerts to cover. Treated as manual: if workloads run on CloudHub 2.0 or Runtime Fabric, export their Anypoint Monitoring alerts.`, evidence);
        }
        if (uncoveredApplications.length > 0) {
          return verdict("warn", `${uncoveredApplications.length} production application(s) are not covered by an enabled alert; Anypoint Monitoring advanced alerts must be exported manually.`, evidence);
        }
        if (unknownCoverageApplications.length > 0 || totalUnknownStateAlerts > 0) {
          return verdict("warn", `${unknownCoverageApplications.length} production application(s) are covered only by alerts whose enabled flag was not returned.`, evidence);
        }
        return verdict("pass", `${totalEnabledAlerts} enabled alert(s) (enabled=true confirmed) cover all ${totalProductionApplications} sampled production application(s); export Anypoint Monitoring advanced alerts manually if they are relied upon.`, evidence);
      },
    ),
  ];

  return {
    category: "audit_monitoring",
    title: "MuleSoft audit logging and monitoring posture",
    // Counts derived from a list that was not read render null rather than the empty fallback's zero.
    summary: {
      organization_id: config.organizationId,
      audit_platforms: derived(platforms.value.length, platforms),
      audit_entries_in_window: derived(recentTotal ?? recentEntries.length, recentQuery),
      audit_lookback_hours: lookbackHours,
      audit_retention_period_days: derived(retention.currentPeriodDays, retentionSettings),
      environments_visible: derived(environments.all.length, environments.source),
      environments_total: derived(environments.source.value.total ?? null, environments.source),
      environments_truncated: derived(environments.source.value.truncated, environments.source),
      production_environments: derived(productionEnvironments.length, environments.source),
      production_applications: derived(totalProductionApplications, environments.source, applicationsSource),
      enabled_alerts: derived(totalEnabledAlerts, environments.source, alertsSource),
      uncovered_production_applications: derived(uncoveredApplications.length, environments.source, applicationsSource, alertsSource),
      partial_view: partialViewOf(environmentPartialNotes, platforms, retentionSettings, recentQuery, environments.source, alertsSource, applicationsSource),
      unreadable_sources: errors.length,
      inventories: describeSources(platforms, retentionSettings, recentQuery, environments.source, alertsSource, applicationsSource),
    },
    findings,
    snapshots: {
      audit_platforms: snapshotOf(platforms, platforms.value),
      audit_retention_settings: snapshotOf(retentionSettings, retentionSettings.value),
      audit_log_recent: snapshotOf(recentQuery, recentEntries.map(auditEntrySummary)),
      alerts: snapshotOf(alertsSource, alertCoverage.map((item) => ({
        environment: item.environment,
        cloudhub_alerts: sourceCollected(item.cloudhubAlerts) ? item.cloudhubAlerts.value : notCollectedMarker(item.cloudhubAlerts),
        runtime_manager_alerts: sourceCollected(item.hybridAlerts) ? item.hybridAlerts.value : notCollectedMarker(item.hybridAlerts),
      })), alertReads),
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
  if (Array.isArray(value)) return value.length;
  if (isPage(value)) return value.items.length;
  return undefined;
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
  const environments = await sampleEnvironments(client, 1, errors);
  const environment = environments.sampled[0];
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
    "- `core_data/` contains the Anypoint Platform API responses used during this assessment, with secret-bearing fields redacted and URL-valued fields reduced to scheme and host; CloudHub application properties, API policy configuration, and audit log entries are projected to the fields the verdicts read.",
    "- A dataset that was denied, errored, or never requested (because the list it depends on failed) is written as `{ collected: false, dataset, status, endpoint, error }` instead of an empty list, so `[]` always means a readable list with no items; a dataset assembled from several reads of which some failed is written as `{ collected: \"partial\", failed_reads, items }`.",
    "- `analysis/findings.json` contains every normalized finding; `analysis/<category>.json` contains each assessment with its summary and an `inventories` map stating each source as complete, partial, unread, or not requested; counts derived from an unread or unrequested source render null rather than zero.",
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

  const zipPath = resolveSecureOutputPath(outputRoot, auditBundleZipPath(relative(realpathSync(outputRoot), outputDir)));
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
      "Export a MuleSoft Anypoint Platform audit package covering all 25 spec controls: redacted and projected API snapshots in core_data/ (denied or unrequested datasets written as not-collected markers), findings and category summaries in analysis/, executive summary, unified matrix, and per-framework reports in compliance/, a QUICK_REFERENCE.md, an _errors.log when collection partially fails, and a zip archive.",
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
