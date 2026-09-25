/**
 * Elastic (Elasticsearch and Kibana) security inspector tools for grclanker.
 *
 * Read-only posture assessment across authentication realms, TLS, RBAC,
 * API keys, audit logging, cluster hardening, data lifecycle, and Kibana
 * governance, mapped to the compliance frameworks in
 * specs/elastic-sec-inspector.spec.md.
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
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { parse as parseYaml, YAMLError } from "yaml";
import { createCredentialScrubber, isCredentialDataKey } from "./credential-scrub.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;
type ToolRegistrar = { registerTool: (definition: unknown) => unknown };

const DEFAULT_OUTPUT_DIR = "./export/elastic";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_MS = 250;
const DEFAULT_CLOUD_API_URL = "https://api.elastic-cloud.com";
const DEFAULT_CONFIG_DIR = ".elastic-sec-inspector";
const DEFAULT_CONFIG_FILE = "config.yaml";
const DEFAULT_API_KEY_LIMIT = 1000;
const DEFAULT_API_KEY_PAGE_SIZE = 100;
const DEFAULT_WATCH_LIMIT = 500;
const DEFAULT_WATCH_PAGE_SIZE = 100;
const DEFAULT_KIBANA_PAGE_SIZE = 100;
const DEFAULT_KIBANA_LIMIT = 1000;
const DEFAULT_MAX_API_KEY_AGE_DAYS = 90;
const DEFAULT_CERT_EXPIRY_WARNING_DAYS = 30;
const DEFAULT_MAX_SUPERUSERS = 2;
const DEFAULT_MAX_ENROLLMENT_KEYS_PER_POLICY = 3;
const MINIMUM_TLS_PROTOCOLS = new Set(["TLSv1.2", "TLSv1.3"]);
const DEFAULT_TLS_SUPPORTED_PROTOCOLS = "TLSv1.3,TLSv1.2,TLSv1.1 (TLSv1.2,TLSv1.1 when the JVM lacks TLSv1.3)";
const SECURE_REALM_TYPES = new Set(["ldap", "active_directory", "pki", "saml", "kerberos", "oidc", "jwt"]);
const SSO_REALM_TYPES = new Set(["saml", "oidc"]);
const PLATINUM_REALM_TYPES = new Set(["saml", "oidc", "kerberos", "jwt"]);
const GOLD_REALM_TYPES = new Set(["ldap", "active_directory", "pki"]);
const LICENSE_RANK: Record<string, number> = {
  basic: 0,
  standard: 1,
  gold: 2,
  platinum: 3,
  enterprise: 4,
  trial: 4,
};
const ACTIVE_LICENSE_STATUSES = new Set(["active", "valid"]);
const REQUIRED_AUDIT_EVENTS = ["authentication_failed", "access_denied", "security_config_change"];
const REQUIRED_CLUSTER_PRIVILEGES = [
  "monitor",
  "read_security",
  "manage_security",
  "manage_api_key",
  "read_pipeline",
  "manage_pipeline",
  "monitor_snapshot",
  "read_ilm",
  "manage_ilm",
  "read_slm",
  "manage_slm",
  "monitor_watcher",
];
const SECRET_KEY_PATTERN = /^(password|passwd|secret|secrets|client_secret|secret_key|secure_key|access_key|secret_access_key|api_key|apikey|token|tokens|access_token|refresh_token|bearer_token|private_key|bind_password|credential|credentials|authorization|cookie|set-cookie|session_token|service_token|passphrase|keystore_password|truststore_password)$/i;
const SECRET_KEY_SUFFIX_PATTERN = /(?:^|[._-]|[a-z0-9])(?:password|passwd|passphrase|secrets?|tokens?|api[_-]?keys?|private[_-]?keys?|credentials?)$/i;
const SECRET_FIELD_NAME_PATTERN = /(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|credential|passphrase)/i;
const TOKEN_LITERAL_PATTERN = /^(?:[A-Za-z0-9+/=_-]{32,})$/;
const MAX_REDACTION_DEPTH = 32;
const REDACTED = "[REDACTED]";
const MAX_ERROR_DETAIL_CHARS = 240;

export type ElasticFrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci-dss" | "stig" | "irap" | "ismap";

export const ELASTIC_FRAMEWORKS: ReadonlyArray<{ key: ElasticFrameworkKey; label: string; prefix: string }> = [
  { key: "fedramp", label: "FedRAMP", prefix: "FedRAMP " },
  { key: "cmmc", label: "CMMC", prefix: "CMMC " },
  { key: "soc2", label: "SOC 2", prefix: "SOC 2 " },
  { key: "cis", label: "CIS", prefix: "CIS " },
  { key: "pci-dss", label: "PCI-DSS", prefix: "PCI-DSS " },
  { key: "stig", label: "STIG", prefix: "STIG " },
  { key: "irap", label: "IRAP", prefix: "IRAP " },
  { key: "ismap", label: "ISMAP", prefix: "ISMAP " },
];

export interface ElasticControlDefinition {
  number: number;
  id: string;
  title: string;
  area: ElasticAssessmentArea;
  mappings: string[];
}

export type ElasticAssessmentArea =
  | "identity"
  | "access_control"
  | "transport_security"
  | "cluster_hardening"
  | "kibana";

function controlMappings(
  fedramp: string,
  cmmc: string,
  soc2: string,
  cis: string,
  pci: string,
  stig: string,
  irap: string,
  ismap: string,
): string[] {
  return [
    `FedRAMP ${fedramp}`,
    `CMMC ${cmmc}`,
    `SOC 2 ${soc2}`,
    `CIS ${cis}`,
    `PCI-DSS ${pci}`,
    `STIG ${stig}`,
    `IRAP ${irap}`,
    `ISMAP ${ismap}`,
  ];
}

function defineControl(
  number: number,
  title: string,
  area: ElasticAssessmentArea,
  mappings: string[],
): ElasticControlDefinition {
  return { number, id: `ELASTIC-${String(number).padStart(2, "0")}`, title, area, mappings };
}

export const ELASTIC_CONTROLS: ReadonlyArray<ElasticControlDefinition> = [
  defineControl(1, "Authentication realm configuration", "identity", controlMappings("IA-2", "AC.L2-3.1.1", "CC6.1", "1.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "CPS-04")),
  defineControl(2, "TLS enforcement on the transport layer", "transport_security", controlMappings("SC-8", "SC.L2-3.13.8", "CC6.7", "3.1", "4.1", "SRG-APP-000219", "ISM-0490", "CPS-09")),
  defineControl(3, "TLS enforcement on the HTTP layer", "transport_security", controlMappings("SC-8", "SC.L2-3.13.8", "CC6.7", "3.2", "4.1", "SRG-APP-000219", "ISM-0490", "CPS-09")),
  defineControl(4, "Minimum TLS protocol version", "transport_security", controlMappings("SC-8(1)", "SC.L2-3.13.8", "CC6.7", "3.3", "4.1", "SRG-APP-000219", "ISM-1369", "CPS-09")),
  defineControl(5, "Certificate expiration", "transport_security", controlMappings("SC-17", "SC.L2-3.13.10", "CC6.7", "3.4", "4.1", "SRG-APP-000175", "ISM-0490", "CPS-09")),
  defineControl(6, "Role-based access control", "access_control", controlMappings("AC-2", "AC.L2-3.1.1", "CC6.3", "6.1", "7.2.1", "SRG-APP-000033", "ISM-0432", "CPS-07")),
  defineControl(7, "Field-level security", "access_control", controlMappings("AC-3", "AC.L2-3.1.2", "CC6.3", "6.2", "7.2.2", "SRG-APP-000033", "ISM-0405", "CPS-07")),
  defineControl(8, "Document-level security", "access_control", controlMappings("AC-3", "AC.L2-3.1.2", "CC6.3", "6.3", "7.2.2", "SRG-APP-000033", "ISM-0405", "CPS-07")),
  defineControl(9, "API key management", "identity", controlMappings("IA-5", "IA.L2-3.5.2", "CC6.1", "5.1", "8.6.1", "SRG-APP-000175", "ISM-1590", "CPS-05")),
  defineControl(10, "API key privilege scope", "identity", controlMappings("AC-6", "AC.L2-3.1.5", "CC6.3", "5.2", "7.2.1", "SRG-APP-000340", "ISM-0432", "CPS-07")),
  defineControl(11, "Audit logging enabled", "cluster_hardening", controlMappings("AU-2", "AU.L2-3.3.1", "CC7.2", "8.1", "10.2.1", "SRG-APP-000089", "ISM-0580", "CPS-10")),
  defineControl(12, "Audit log output", "cluster_hardening", controlMappings("AU-9", "AU.L2-3.3.8", "CC7.2", "8.2", "10.5.1", "SRG-APP-000125", "ISM-0859", "CPS-10")),
  defineControl(13, "SAML/OIDC SSO configuration", "identity", controlMappings("IA-2", "AC.L2-3.1.1", "CC6.1", "1.2", "8.3.1", "SRG-APP-000148", "ISM-1557", "CPS-04")),
  defineControl(14, "Anonymous access disabled", "identity", controlMappings("AC-14", "AC.L2-3.1.1", "CC6.1", "1.3", "7.2.3", "SRG-APP-000033", "ISM-0432", "CPS-07")),
  defineControl(15, "Kibana space isolation", "kibana", controlMappings("AC-4", "AC.L2-3.1.3", "CC6.6", "6.4", "7.2.3", "SRG-APP-000039", "ISM-1148", "CPS-11")),
  defineControl(16, "Kibana role privileges", "kibana", controlMappings("AC-6", "AC.L2-3.1.5", "CC6.3", "6.5", "7.2.2", "SRG-APP-000340", "ISM-0432", "CPS-07")),
  defineControl(17, "Index lifecycle policies", "cluster_hardening", controlMappings("AU-11", "AU.L2-3.3.1", "CC7.4", "8.3", "3.1", "SRG-APP-000515", "ISM-0859", "CPS-10")),
  defineControl(18, "Snapshot encryption", "cluster_hardening", controlMappings("SC-28", "SC.L2-3.13.16", "CC6.7", "3.5", "3.4", "SRG-APP-000231", "ISM-0457", "CPS-09")),
  defineControl(19, "Cluster security settings", "cluster_hardening", controlMappings("CM-6", "CM.L2-3.4.2", "CC8.1", "10.1", "2.2", "SRG-APP-000386", "ISM-0380", "CPS-12")),
  defineControl(20, "Watcher and alerting security", "cluster_hardening", controlMappings("AU-5", "AU.L2-3.3.4", "CC7.3", "8.4", "10.6.1", "SRG-APP-000108", "ISM-0580", "CPS-10")),
  defineControl(21, "Fleet agent policy security", "kibana", controlMappings("CM-6", "CM.L2-3.4.2", "CC8.1", "10.2", "2.2", "SRG-APP-000386", "ISM-0380", "CPS-12")),
  defineControl(22, "Ingest pipeline security", "cluster_hardening", controlMappings("SC-28", "SC.L2-3.13.16", "CC6.7", "3.6", "3.4.1", "SRG-APP-000231", "ISM-0457", "CPS-09")),
  defineControl(23, "License level verification", "cluster_hardening", controlMappings("CM-8", "CM.L2-3.4.1", "CC8.1", "10.3", "6.3.2", "SRG-APP-000456", "ISM-1490", "CPS-12")),
];

export interface ElasticResolvedConfig {
  elasticsearchUrl: string;
  kibanaUrl?: string;
  kibanaSpaceId?: string;
  authMode: "api_key" | "basic" | "bearer";
  apiKey?: string;
  username?: string;
  password?: string;
  bearerToken?: string;
  cloudApiKey?: string;
  cloudApiUrl: string;
  timeoutMs: number;
  maxRetries: number;
  sourceChain: string[];
}

export type ElasticTarget = "elasticsearch" | "kibana" | "cloud";

export interface ElasticAccessSurface {
  name: string;
  target: ElasticTarget;
  /** Endpoint that was requested; null when the surface was never requested because its target is not configured. */
  endpoint: string | null;
  status: "readable" | "not_readable" | "not_configured";
  /** True only when the request was made and answered with a readable payload. */
  collected: boolean;
  /** HTTP status observed on a failing request; null when the surface was read, skipped, or failed before a response. */
  http_status: number | null;
  /** Record count of the readable payload; null when the surface was not collected. */
  count: number | null;
  /** Whether the readable listing was cut short; null when the surface was not collected or is not paged. */
  truncated: boolean | null;
  error?: string;
}

export interface ElasticAccessCheckResult {
  status: "healthy" | "limited";
  elasticsearchUrl: string;
  kibanaUrl?: string;
  cloudConfigured: boolean;
  authenticatedAs?: string;
  authenticationRealm?: string;
  surfaces: ElasticAccessSurface[];
  /** Missing privileges from the has_privileges probe; null when the probe itself failed. */
  missingClusterPrivileges: string[] | null;
  missingIndexPrivileges: string[] | null;
  privilegeProbe: "readable" | "not_readable" | "not_available";
  notes: string[];
  recommendedNextStep: string;
}

export interface ElasticFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail" | "manual";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface ElasticAssessmentResult {
  area: ElasticAssessmentArea;
  title: string;
  summary: JsonRecord;
  findings: ElasticFinding[];
  /** Datasets whose read failed, each naming the endpoint and the observed error. */
  errors: string[];
  /** Datasets that were never requested because their target is not configured. */
  not_collected: string[];
  /** Paged datasets whose collection stopped before the inventory was exhausted. */
  truncated: string[];
}

export interface ElasticAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
  /** Paged datasets whose collection stopped before the inventory was exhausted. */
  truncatedCount: number;
  /** Datasets never requested because their target is not configured. */
  notCollectedCount: number;
}

export interface ElasticPageInfo {
  seen: number;
  total?: number;
  truncated: boolean;
  pages: number;
}

export interface ElasticPagedList<T = JsonRecord> extends ElasticPageInfo {
  items: T[];
}

export interface ElasticDataset<T = unknown> {
  name: string;
  endpoint: string;
  target: ElasticTarget;
  data?: T;
  page?: ElasticPageInfo;
  error?: string;
  /** HTTP status observed on the failing request, when the failure was an HTTP response. */
  status?: number;
  skipped?: string;
}

export type ElasticDatasetName =
  | "authenticate"
  | "privileges"
  | "license"
  | "xpack_info"
  | "xpack_usage"
  | "cluster_settings"
  | "node_settings"
  | "ssl_certificates"
  | "users"
  | "roles"
  | "role_mappings"
  | "api_keys"
  | "ilm_status"
  | "ilm_policies"
  | "slm_status"
  | "slm_policies"
  | "snapshot_repositories"
  | "watches"
  | "ingest_pipelines"
  | "kibana_status"
  | "kibana_spaces"
  | "kibana_roles"
  | "fleet_agent_policies"
  | "fleet_outputs"
  | "fleet_enrollment_api_keys"
  | "fleet_server_hosts"
  | "detection_rules"
  | "alerting_rules"
  | "connectors"
  | "cloud_deployments";

export type ElasticSnapshot = Partial<Record<ElasticDatasetName, ElasticDataset>>;

export interface ElasticAssessmentOptions {
  apiKeyLimit?: number;
  maxApiKeyAgeDays?: number;
  maxSuperusers?: number;
  sensitiveIndexPatterns?: string[];
  tenantIndexPatterns?: string[];
  certExpiryWarningDays?: number;
  watchLimit?: number;
  kibanaLimit?: number;
  maxEnrollmentKeysPerPolicy?: number;
}

type CheckAccessArgs = {
  elasticsearch_url?: string;
  kibana_url?: string;
  space_id?: string;
  api_key?: string;
  username?: string;
  password?: string;
  bearer_token?: string;
  cloud_api_key?: string;
  cloud_api_url?: string;
  config_file?: string;
  timeout_seconds?: number;
};

type AssessmentArgs = CheckAccessArgs & {
  api_key_limit?: number;
  max_api_key_age_days?: number;
  max_superusers?: number;
  sensitive_index_patterns?: string[];
  tenant_index_patterns?: string[];
  cert_expiry_warning_days?: number;
  watch_limit?: number;
  kibana_limit?: number;
  max_enrollment_keys_per_policy?: number;
};

type ExportAuditBundleArgs = AssessmentArgs & {
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

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/^(true|1|yes|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(asString).filter((item): item is string => Boolean(item));
  }
  const single = asString(value);
  if (!single) return [];
  return single.split(",").map((item) => item.trim()).filter(Boolean);
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.username = "";
  parsed.password = "";
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
  return normalized || "elastic";
}

const PARSE_ERROR_NOTE = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";

/** JSON.parse quotes a window of the text it rejected, so a SyntaxError is recorded by name only, never by its message. */
function isParseError(error: unknown): boolean {
  return error instanceof SyntaxError || (error instanceof Error && error.name === "SyntaxError");
}

/** The message of any thrown value with the structural parse-error guard applied, before scrubbing. */
function errorMessage(error: unknown): string {
  if (isParseError(error)) return PARSE_ERROR_NOTE;
  return error instanceof Error ? error.message : String(error);
}

/** Tool-level sink: every message returned by a tool's catch block passes the unanchored scrub, whatever threw it. */
function toolErrorText(error: unknown): string {
  return scrubErrorText(errorMessage(error));
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

function bundleZipPathFor(outputDir: string): string {
  return `${outputDir}.zip`;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate) && !existsSync(bundleZipPathFor(candidate))) {
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

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
}

function encodeBase64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function decodeBase64(value: string): string | undefined {
  if (!/^[A-Za-z0-9+/=_-]+$/.test(value)) return undefined;
  try {
    const decoded = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return decoded.length > 0 && !decoded.includes("\uFFFD") ? decoded : undefined;
  } catch {
    return undefined;
  }
}

export function normalizeElasticApiKey(rawValue: string): string {
  const value = rawValue.trim();
  const decoded = decodeBase64(value);
  if (decoded && decoded.includes(":")) return value;
  if (value.includes(":") && !/\s/.test(value)) return encodeBase64(value);
  return value;
}

/**
 * The module's credential scrubber (see credential-scrub.ts for the boundary): carriers whatever the value's shape,
 * every configured secret registered by a client in every encoded form, real token shapes bare, and Elastic Cloud
 * API keys by their prefix.
 */
const credentialScrubber = createCredentialScrubber({ vendorPatterns: [/\bessu_[A-Za-z0-9+/=_-]{16,}/g] });

/**
 * The scrub applied to every error string before it is recorded anywhere (findings, summaries, analysis objects,
 * access surfaces, the bundle, tool results). Unanchored, idempotent, and independent of which client threw.
 */
export function scrubErrorText(text: string): string {
  return credentialScrubber.scrub(text);
}

type ElasticSecretConfig = Pick<ElasticResolvedConfig, "apiKey" | "password" | "bearerToken" | "cloudApiKey" | "username">;

/**
 * Registers a configuration's secrets with the module scrubber: the API key as configured, the secret half of its
 * decoded `id:api_key` form, the password, the bearer token, the cloud API key, and the `user:password` pair whose
 * base64 form is the Basic authorization value. The scrubber derives the base64, base64url, URL-encoded, and
 * JSON-escaped forms of each.
 */
function registerConfiguredSecrets(config: ElasticSecretConfig): void {
  credentialScrubber.registerSecrets([
    config.apiKey,
    config.password,
    config.bearerToken,
    config.cloudApiKey,
    config.username && config.password ? `${config.username}:${config.password}` : undefined,
    config.apiKey ? decodeBase64(config.apiKey)?.split(":")[1] : undefined,
  ]);
}

/** Scrubs an error string with the configuration's secrets registered first, so the text loses them in every form. */
export function redactSecrets(text: string, config: ElasticSecretConfig): string {
  registerConfiguredSecrets(config);
  return scrubErrorText(text);
}

/**
 * The record-key rule for collected Elastic data: the Elasticsearch settings vocabulary (`bind_password`,
 * `secure_password`, `keystore_password`, `client_secret`, a bare `key` under `ssl`, `tls`, `keystore`, or `secrets`,
 * with a flat dotted settings key such as `xpack.security.http.ssl.key` carrying its own parent segment) plus the
 * shared conservative rule (`token`, `credentials`, `hmac_key`, `shared_secret`, ...). `is_*` and `has_*` flags are
 * never credentials. The whole subtree under a matching key becomes the marker.
 */
function isSecretKey(key: string, parentKey: string | undefined): boolean {
  const segments = key.split(".");
  const last = segments[segments.length - 1] ?? key;
  if (/^(is|has)_/i.test(last)) return false;
  if (SECRET_KEY_PATTERN.test(last) || SECRET_KEY_SUFFIX_PATTERN.test(last) || isCredentialDataKey(key)) return true;
  // Flat dotted settings keys ("xpack.security.http.ssl.key") carry their own parent segment,
  // which takes precedence over the enclosing object key ("persistent").
  const parent = segments.length > 1 ? segments[segments.length - 2] : parentKey;
  return /^key$/i.test(last) && /^(ssl|tls|keystore|secrets)$/i.test(parent ?? "");
}

const SCHEME_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
// A value that is one URL and nothing else (`https://es.example.com:9200`, `ldaps://svc:pw@ldap.example.com:636`), as
// opposed to prose that mentions one.
const URL_VALUE_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;

function urlOrigin(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return REDACTED;
  }
}

/**
 * Reduces a collected value that is one URL to its origin (scheme and host). No Elastic verdict reads a URL field past
 * its scheme (plain-http checks on Fleet hosts and connector URLs), so the userinfo, path, query string, and fragment
 * of a URL value never reach an assess payload or the bundle, whichever field carries it. A URL embedded in free text
 * (a note, a description, an error detail kept in a record) is left to the shared pattern pass, which drops its
 * userinfo and replaces its query and fragment while keeping the scheme, host, and path that name the surface, as
 * every other module's data walker does.
 */
export function reduceUrlValueToOrigin(value: string): string {
  const trimmed = value.trim();
  return URL_VALUE_PATTERN.test(trimmed) ? urlOrigin(trimmed) : value;
}

/**
 * The data-side scrub every collected dataset passes through before it is assessed or written (see
 * credential-scrub.ts `scrubData`): the whole subtree under a secret-shaped key becomes the marker, `{name, value}`
 * pairs with a credential-shaped name lose their value, a string that is one URL keeps its origin only, and every
 * string runs through the module's pattern scrubber (carriers, configured secrets, token shapes, and the userinfo,
 * query, and fragment of a URL inside free text; shape rules off under identifier keys such as `id` or `ca_sha256`),
 * and nesting past the cap becomes the marker. Booleans and nulls pass through.
 */
export function redactSensitiveValues(value: unknown): unknown {
  return credentialScrubber.scrubData(value, {
    isCredentialKey: isSecretKey,
    transformString: reduceUrlValueToOrigin,
    maxDepth: MAX_REDACTION_DEPTH,
  });
}

/** Keeps only scheme and host of a URL-shaped value so paths and query strings carrying tokens never reach the bundle. */
function reduceUrlToOrigin(value: unknown): unknown {
  return typeof value === "string" ? reduceUrlValueToOrigin(value) : value;
}

const CONNECTOR_URL_KEYS = ["url", "webhookUrl", "apiUrl", "configUrl", "webhook_url", "api_url"];

/** A value stored under a URL key: its origin when it is a URL, the marker when it is a string of any other shape (a schemeless webhook path would keep its token), and unchanged otherwise. */
function reduceUrlKeyValue(value: unknown): unknown {
  if (typeof value !== "string") return value;
  return SCHEME_URL_PATTERN.test(value.trim()) ? urlOrigin(value.trim()) : REDACTED;
}

/** Copies the listed keys that are present on the record, so an absent field stays absent (never rendered as null). */
function pick(record: JsonRecord | undefined, keys: readonly string[]): JsonRecord {
  const out: JsonRecord = {};
  for (const key of keys) if (record !== undefined && record[key] !== undefined) out[key] = record[key];
  return out;
}

/** Keeps a `metadata` object down to its documented reserved and managed flags; free-form metadata is never copied. */
function projectMetadata(metadata: unknown): JsonRecord | undefined {
  const object = asObject(metadata);
  if (!object) return undefined;
  return pick(object, ["_reserved", "_deprecated", "managed", "managed_by"]);
}

/** Projects a role or API key role descriptor to the privilege fields the RBAC, FLS/DLS, and API key scope verdicts read. */
function projectRoleDescriptor(descriptor: unknown): JsonRecord {
  const role = asObject(descriptor) ?? {};
  const projected: JsonRecord = pick(role, ["cluster", "run_as"]);
  if (role.indices !== undefined) {
    projected.indices = asObjectArray(role.indices).map((entry) => ({
      ...pick(entry, ["names", "privileges", "allow_restricted_indices", "query"]),
      ...(asObject(entry.field_security) ? { field_security: pick(asObject(entry.field_security), ["grant", "except"]) } : {}),
    }));
  }
  if (role.applications !== undefined) {
    projected.applications = asObjectArray(role.applications).map((entry) => pick(entry, ["application", "privileges", "resources"]));
  }
  const metadata = projectMetadata(role.metadata);
  if (metadata) projected.metadata = metadata;
  return projected;
}

/** Projects a map of named records with the given per-entry projector, keeping the names as keys. */
function projectRecordMap(records: unknown, project: (entry: JsonRecord, name: string) => JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  for (const [name, value] of Object.entries(asObject(records) ?? {})) output[name] = project(asObject(value) ?? {}, name);
  return output;
}

/** Keeps the `xpack.security.*` settings the verdicts read (flattened when the API returned them nested); every other setting is dropped. */
function projectSettingsMap(settings: unknown): JsonRecord {
  const flat = flattenSettings(settings);
  const output: JsonRecord = {};
  for (const [key, value] of Object.entries(flat)) {
    if (/^(xpack\.security\.|xpack\.ssl\.|cluster\.name$|node\.name$|node\.roles$)/.test(key)) output[key] = value;
  }
  return output;
}

function projectAuthenticate(record: JsonRecord): JsonRecord {
  return {
    ...pick(record, ["username", "roles", "enabled", "authentication_type"]),
    ...(asObject(record.authentication_realm) ? { authentication_realm: pick(asObject(record.authentication_realm), ["name", "type"]) } : {}),
    ...(asObject(record.lookup_realm) ? { lookup_realm: pick(asObject(record.lookup_realm), ["name", "type"]) } : {}),
  };
}

/** Keeps the boolean grant map of a has-privileges response at any nesting (cluster, index, application). */
function projectGrantMap(value: unknown, depth = 0): unknown {
  if (typeof value === "boolean") return value;
  const object = asObject(value);
  if (!object || depth > 4) return undefined;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    const projected = projectGrantMap(entry, depth + 1);
    if (projected !== undefined) output[key] = projected;
  }
  return output;
}

function projectPrivileges(record: JsonRecord): JsonRecord {
  return {
    ...pick(record, ["username", "has_all_requested"]),
    ...(record.cluster !== undefined ? { cluster: projectGrantMap(record.cluster) ?? {} } : {}),
    ...(record.index !== undefined ? { index: projectGrantMap(record.index) ?? {} } : {}),
    ...(record.application !== undefined ? { application: projectGrantMap(record.application) ?? {} } : {}),
  };
}

const LICENSE_KEYS = ["status", "uid", "type", "mode", "issue_date", "issue_date_in_millis", "expiry_date", "expiry_date_in_millis", "start_date_in_millis", "max_nodes", "max_resource_units", "issued_to", "issuer"];

function projectLicense(record: JsonRecord): JsonRecord {
  return asObject(record.license) ? { license: pick(asObject(record.license), LICENSE_KEYS) } : {};
}

function projectXpackInfo(record: JsonRecord): JsonRecord {
  return {
    ...(asObject(record.build) ? { build: pick(asObject(record.build), ["hash", "date"]) } : {}),
    ...(asObject(record.license) ? { license: pick(asObject(record.license), LICENSE_KEYS) } : {}),
    ...(asObject(record.features) ? { features: projectRecordMap(record.features, (feature) => pick(feature, ["available", "enabled"])) } : {}),
  };
}

/** Keeps the security usage block whole (the verdicts read realms, roles, ssl, audit, ipfilter, anonymous, token and API key services, fips) and only the availability flags of every other feature. */
function projectXpackUsage(record: JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  for (const [feature, value] of Object.entries(record)) {
    const object = asObject(value);
    if (!object) continue;
    output[feature] = feature === "security" ? object : pick(object, ["available", "enabled"]);
  }
  return output;
}

function projectClusterSettings(record: JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  for (const section of ["persistent", "transient", "defaults"]) {
    if (record[section] !== undefined) output[section] = projectSettingsMap(record[section]);
  }
  return output;
}

function projectNodeSettings(record: JsonRecord): JsonRecord {
  return {
    ...(asObject(record._nodes) ? { _nodes: pick(asObject(record._nodes), ["total", "successful", "failed"]) } : {}),
    ...pick(record, ["cluster_name"]),
    ...(record.nodes !== undefined
      ? { nodes: projectRecordMap(record.nodes, (node) => ({ ...pick(node, ["name", "version", "roles"]), ...(node.settings !== undefined ? { settings: projectSettingsMap(node.settings) } : {}) })) }
      : {}),
  };
}

function projectSslCertificate(certificate: JsonRecord): JsonRecord {
  return pick(certificate, ["path", "format", "alias", "subject_dn", "serial_number", "has_private_key", "expiry", "issuer"]);
}

function projectUser(user: JsonRecord): JsonRecord {
  const metadata = projectMetadata(user.metadata);
  return { ...pick(user, ["username", "roles", "enabled"]), ...(metadata ? { metadata } : {}) };
}

function projectRoleMapping(mapping: JsonRecord): JsonRecord {
  const metadata = projectMetadata(mapping.metadata);
  return {
    ...pick(mapping, ["enabled", "roles", "rules"]),
    ...(Array.isArray(mapping.role_templates) ? { role_template_count: mapping.role_templates.length } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function projectApiKey(key: JsonRecord): JsonRecord {
  const metadata = projectMetadata(key.metadata);
  return {
    ...pick(key, ["id", "name", "type", "creation", "expiration", "invalidated", "invalidation", "username", "realm", "realm_type"]),
    ...(metadata ? { metadata } : {}),
    ...(key.role_descriptors !== undefined ? { role_descriptors: projectRecordMap(key.role_descriptors, projectRoleDescriptor) } : {}),
    ...(key.limited_by !== undefined ? { limited_by: asObjectArray(key.limited_by).map((entry) => projectRecordMap(entry, projectRoleDescriptor)) } : {}),
  };
}

const ROLLOVER_THRESHOLD_KEYS = ["max_age", "max_docs", "max_size", "max_primary_shard_size", "max_primary_shard_docs", "min_age", "min_docs", "min_size", "min_primary_shard_size", "min_primary_shard_docs"];

/** Keeps a phase's age and the names of its actions; only rollover keeps its thresholds, since no verdict reads another action's configuration. */
function projectIlmPhase(phase: JsonRecord): JsonRecord {
  return {
    ...pick(phase, ["min_age"]),
    ...(phase.actions !== undefined
      ? { actions: projectRecordMap(phase.actions, (action, name) => (name === "rollover" ? pick(action, ROLLOVER_THRESHOLD_KEYS) : {})) }
      : {}),
  };
}

function projectIlmPolicy(entry: JsonRecord): JsonRecord {
  const policy = asObject(entry.policy);
  const inUseBy = asObject(entry.in_use_by);
  return {
    ...pick(entry, ["version", "modified_date"]),
    ...(policy
      ? {
        policy: {
          ...(projectMetadata(policy._meta) ? { _meta: projectMetadata(policy._meta) } : {}),
          ...(policy.phases !== undefined ? { phases: projectRecordMap(policy.phases, projectIlmPhase) } : {}),
        },
      }
      : {}),
    ...(inUseBy ? { in_use_by: pick(inUseBy, ["indices", "data_streams", "composable_templates"]) } : {}),
  };
}

function projectSlmPolicy(entry: JsonRecord): JsonRecord {
  const policy = asObject(entry.policy);
  return {
    ...pick(entry, ["version", "modified_date", "modified_date_millis", "next_execution", "next_execution_millis", "repository"]),
    ...(policy
      ? {
        policy: {
          ...pick(policy, ["name", "schedule", "repository", "retention"]),
          ...(asObject(policy.config) ? { config: pick(asObject(policy.config), ["indices", "include_global_state", "ignore_unavailable", "partial"]) } : {}),
        },
      }
      : {}),
    ...(asObject(entry.last_success) ? { last_success: pick(asObject(entry.last_success), ["snapshot_name", "time"]) } : {}),
    ...(asObject(entry.last_failure) ? { last_failure: pick(asObject(entry.last_failure), ["snapshot_name", "time"]) } : {}),
  };
}

function projectSnapshotRepository(entry: JsonRecord): JsonRecord {
  const settings = asObject(entry.settings);
  return {
    ...pick(entry, ["type", "uuid"]),
    ...(settings
      ? {
        settings: {
          ...pick(settings, ["bucket", "container", "location", "base_path", "client", "server_side_encryption", "readonly", "compress"]),
          ...(settings.url !== undefined ? { url: reduceUrlKeyValue(settings.url) } : {}),
          ...(settings.endpoint !== undefined ? { endpoint: reduceUrlToOrigin(settings.endpoint) } : {}),
        },
      }
      : {}),
  };
}

function projectKibanaStatus(record: JsonRecord): JsonRecord {
  const overall = asObject(asObject(record.status)?.overall);
  return {
    ...pick(record, ["name", "uuid"]),
    ...(asObject(record.version) ? { version: pick(asObject(record.version), ["number", "build_hash", "build_number"]) } : {}),
    ...(overall ? { status: { overall: pick(overall, ["level", "state"]) } } : {}),
  };
}

function projectKibanaSpace(space: JsonRecord): JsonRecord {
  return pick(space, ["id", "name", "disabledFeatures", "_reserved", "solution"]);
}

function projectKibanaRole(role: JsonRecord): JsonRecord {
  const metadata = projectMetadata(role.metadata);
  return {
    ...pick(role, ["name"]),
    ...(metadata ? { metadata } : {}),
    ...(role.elasticsearch !== undefined ? { elasticsearch: projectRoleDescriptor(role.elasticsearch) } : {}),
    ...(role.kibana !== undefined ? { kibana: asObjectArray(role.kibana).map((entry) => pick(entry, ["base", "feature", "spaces"])) } : {}),
  };
}

function projectAgentPolicy(policy: JsonRecord): JsonRecord {
  return {
    ...pick(policy, ["id", "name", "namespace", "status", "revision", "updated_at", "agents", "is_protected", "is_managed", "is_default", "is_preconfigured", "monitoring_enabled", "data_output_id", "monitoring_output_id", "fleet_server_host_id", "download_source_id"]),
    ...(Array.isArray(policy.package_policies) ? { package_policy_count: policy.package_policies.length } : {}),
  };
}

/** Projects a Fleet output to its transport shape: origin-only hosts, CA trust fields, and whether TLS material is configured (never the material itself). */
function projectFleetOutput(output: JsonRecord): JsonRecord {
  const ssl = asObject(output.ssl);
  return {
    ...pick(output, ["id", "name", "type", "is_default", "is_default_monitoring", "is_preconfigured", "ca_sha256", "ca_trusted_fingerprint", "proxy_id", "preset"]),
    ...(output.hosts !== undefined ? { hosts: asStringList(output.hosts).map(reduceUrlKeyValue) } : {}),
    ...(ssl
      ? {
        ssl: {
          ...pick(ssl, ["verification_mode"]),
          certificate_authorities_count: asArray(ssl.certificate_authorities).length,
          certificate_present: ssl.certificate !== undefined,
          key_present: ssl.key !== undefined,
        },
      }
      : {}),
  };
}

function projectEnrollmentApiKey(key: JsonRecord): JsonRecord {
  return { ...pick(key, ["id", "active", "api_key_id", "name", "policy_id", "created_at"]), ...(key.api_key !== undefined ? { api_key: REDACTED } : {}) };
}

function projectFleetServerHost(host: JsonRecord): JsonRecord {
  return {
    ...pick(host, ["id", "name", "is_default", "is_preconfigured", "is_internal", "proxy_id"]),
    ...(host.host_urls !== undefined ? { host_urls: asStringList(host.host_urls).map(reduceUrlKeyValue) } : {}),
  };
}

/** Projects a Kibana rule action to its connector reference; parameters (message bodies, URLs) are never copied. */
function projectRuleAction(action: JsonRecord): JsonRecord {
  return {
    ...pick(action, ["id", "uuid", "group", "action_type_id", "connector_type_id"]),
    ...(asObject(action.frequency) ? { frequency: pick(asObject(action.frequency), ["summary", "notify_when", "notifyWhen", "throttle"]) } : {}),
  };
}

function projectDetectionRule(rule: JsonRecord): JsonRecord {
  return {
    ...pick(rule, ["id", "rule_id", "name", "enabled", "type", "severity", "risk_score", "interval", "from", "created_at", "updated_at", "version", "immutable"]),
    ...(rule.actions !== undefined ? { actions: asObjectArray(rule.actions).map(projectRuleAction) } : {}),
  };
}

function projectAlertingRule(rule: JsonRecord): JsonRecord {
  const executionStatus = asObject(rule.execution_status);
  return {
    ...pick(rule, ["id", "name", "rule_type_id", "consumer", "enabled", "schedule", "notify_when", "throttle", "mute_all", "created_at", "updated_at", "revision"]),
    ...(executionStatus ? { execution_status: pick(executionStatus, ["status", "last_execution_date"]) } : {}),
    ...(rule.actions !== undefined ? { actions: asObjectArray(rule.actions).map(projectRuleAction) } : {}),
  };
}

/**
 * Elastic Cloud gives a deployment's resources in two shapes. The listing the client reads, GET /api/v1/deployments
 * (DeploymentsListResponse), carries one array of `{ kind, ref_id, id, region, ... }`; the per-deployment read,
 * GET /api/v1/deployments/{id}, groups them per kind as arrays (`elasticsearch: [{ ref_id, id, region, info, ... }]`,
 * likewise kibana, apm, integrations_server, enterprise_search, appsearch). Both project to the per-kind map, each
 * element keeping its documented identity fields; an array element without a string kind and a per-kind value that is
 * not an array are dropped, and any other value is not a resource collection at all.
 */
function projectCloudResources(resources: unknown): JsonRecord | undefined {
  const projectResource = (resource: JsonRecord): JsonRecord => pick(resource, ["ref_id", "id", "region"]);
  if (Array.isArray(resources)) {
    const grouped: Record<string, JsonRecord[]> = {};
    for (const resource of asObjectArray(resources)) {
      const kind = typeof resource.kind === "string" ? resource.kind.trim() : "";
      if (kind) (grouped[kind] ??= []).push(projectResource(resource));
    }
    return grouped;
  }
  const perKind = asObject(resources);
  if (!perKind) return undefined;
  const output: JsonRecord = {};
  for (const [kind, value] of Object.entries(perKind)) {
    if (Array.isArray(value)) output[kind] = asObjectArray(value).map(projectResource);
  }
  return output;
}

function projectCloudDeployment(deployment: JsonRecord): JsonRecord {
  const metadata = asObject(deployment.metadata);
  const resources = projectCloudResources(deployment.resources);
  return {
    ...pick(deployment, ["id", "name", "alias", "healthy"]),
    ...(metadata ? { metadata: pick(metadata, ["last_modified", "system_owned", "hidden"]) } : {}),
    ...(resources ? { resources } : {}),
  };
}

/** Projects a Kibana connector to its identity, type, and origin-only URL fields; secrets and headers are dropped. */
function projectConnector(connector: JsonRecord): JsonRecord {
  const config = asObject(connector.config) ?? {};
  const projectedConfig: JsonRecord = {};
  for (const [key, value] of Object.entries(config)) {
    if (CONNECTOR_URL_KEYS.includes(key)) {
      projectedConfig[key] = reduceUrlKeyValue(value);
    } else if (/^(headers|hasAuth|has_auth|authType|auth_type|method|from|service|host|port|secure|index|executionTimeField|apiProvider|defaultModel|isDeprecated|usesTableApi|createIncidentUrl|getIncidentUrl|updateIncidentUrl|viewIncidentUrl)$/i.test(key)) {
      projectedConfig[key] = key.toLowerCase() === "headers" ? (asObject(value) ? Object.keys(asObject(value) ?? {}) : null) : /url$/i.test(key) ? reduceUrlKeyValue(value) : value;
    } else if (typeof value === "boolean" || typeof value === "number") {
      projectedConfig[key] = value;
    }
  }
  return {
    id: asString(connector.id) ?? null,
    name: asString(connector.name) ?? null,
    connector_type_id: asString(connector.connector_type_id) ?? asString(connector.actionTypeId) ?? null,
    is_preconfigured: asBoolean(connector.is_preconfigured) ?? null,
    is_deprecated: asBoolean(connector.is_deprecated) ?? null,
    is_missing_secrets: asBoolean(connector.is_missing_secrets) ?? null,
    is_system_action: asBoolean(connector.is_system_action) ?? null,
    referenced_by_count: asNumber(connector.referenced_by_count) ?? null,
    config: projectedConfig,
  };
}

/** Projects a Watcher watch to the action shape needed for the transport check: scheme, host, port, method, and whether auth is embedded. */
function projectWatch(watch: JsonRecord): JsonRecord {
  const definition = asObject(watch.watch) ?? watch;
  const actions: JsonRecord = {};
  for (const [name, rawAction] of Object.entries(asObject(definition.actions) ?? {})) {
    const action = asObject(rawAction) ?? {};
    const projected: JsonRecord = { types: Object.keys(action) };
    const webhook = asObject(action.webhook);
    if (webhook) {
      projected.webhook = {
        scheme: asString(webhook.scheme) ?? null,
        host: asString(webhook.host) ?? null,
        port: asNumber(webhook.port) ?? null,
        method: asString(webhook.method) ?? null,
        path: webhook.path === undefined ? null : REDACTED,
        params: webhook.params === undefined ? null : REDACTED,
        headers: asObject(webhook.headers) ? Object.keys(asObject(webhook.headers) ?? {}) : null,
        auth: asObject(webhook.auth) ? { types: Object.keys(asObject(webhook.auth) ?? {}), value: REDACTED } : null,
        body: webhook.body === undefined ? null : REDACTED,
      };
    }
    actions[name] = projected;
  }
  return {
    _id: asString(watch._id) ?? null,
    status: asObject(watch.status) ? { state: asObject(asObject(watch.status)?.state) ?? null } : null,
    trigger: asObject(definition.trigger) ?? null,
    action_count: Object.keys(actions).length,
    actions,
  };
}

/** Projects ingest pipeline processors to type, target field, and whether a set literal looks like a secret; literal values themselves are never copied. */
function projectPipelineProcessors(processors: unknown): unknown {
  if (!Array.isArray(processors)) return processors === undefined ? undefined : null;
  return processors.map((processor) => {
    const object = asObject(processor);
    if (!object) return null;
    const projected: JsonRecord = {};
    for (const [type, rawConfig] of Object.entries(object)) {
      const config = asObject(rawConfig) ?? {};
      const entry: JsonRecord = {
        field: asString(config.field) ?? null,
        target_field: asString(config.target_field) ?? null,
        ...(config.description !== undefined ? { has_description: true } : {}),
        ...(config.if !== undefined ? { has_condition: true } : {}),
        ...(config.ignore_failure !== undefined ? { ignore_failure: asBoolean(config.ignore_failure) ?? null } : {}),
      };
      if (type === "set") {
        entry.value_is_template = typeof config.value === "string" && config.value.includes("{{");
        entry.value_kind = config.value === undefined ? (config.copy_from !== undefined ? "copy_from" : null) : typeof config.value;
        entry.sensitive_literal = setProcessorLooksSensitive(config);
      }
      if (type === "script") {
        entry.lang = asString(config.lang) ?? null;
        entry.source_present = config.source !== undefined;
        entry.id = asString(config.id) ?? null;
      }
      if (type === "foreach" && config.processor !== undefined) entry.processor = asArray(projectPipelineProcessors([config.processor]))[0] ?? null;
      if (config.on_failure !== undefined) entry.on_failure = projectPipelineProcessors(config.on_failure);
      projected[type] = entry;
    }
    return projected;
  });
}

/** Projects the ingest pipeline inventory so processor configuration literals and free-text descriptions never reach the bundle. */
function projectPipelines(pipelines: JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  for (const [name, value] of Object.entries(pipelines)) {
    const entry = asObject(value) ?? {};
    output[name] = {
      has_description: entry.description !== undefined,
      version: asNumber(entry.version) ?? null,
      _meta: asObject(entry._meta) ? { managed: asBoolean(asObject(entry._meta)?.managed) ?? null, managed_by: asString(asObject(entry._meta)?.managed_by) ?? null } : null,
      processors: projectPipelineProcessors(entry.processors) ?? null,
      on_failure: projectPipelineProcessors(entry.on_failure) ?? null,
    };
  }
  return output;
}

interface ElasticConfigOverlay {
  elasticsearchUrl?: string;
  kibanaUrl?: string;
  kibanaSpaceId?: string;
  apiKey?: string;
  username?: string;
  password?: string;
  bearerToken?: string;
  cloudApiKey?: string;
  cloudApiUrl?: string;
  timeoutSeconds?: number;
}

function overlayKeys(source: JsonRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null && source[key] !== "") return source[key];
  }
  return undefined;
}

const ERRNO_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;

/**
 * Raised when the config file cannot be read or parsed. The file carries credentials, so the message is fixed text
 * built only from the path, an errno code validated against ERRNO_CODE_PATTERN, and a line number taken from the
 * parser's structured position: neither the filesystem's nor the parser's own message (which quotes the offending
 * source, and for an unresolved alias quotes the value with no key name) is ever interpolated.
 */
export class ElasticConfigFileError extends Error {
  readonly path: string;
  /** The errno code of a read failure, or INVALID_YAML for a parse failure. */
  readonly code: string;
  /** The parser's structured line for a parse failure; undefined for a read failure or a non-parser throw. */
  readonly line: number | undefined;

  constructor(step: "read" | "parse", path: string, code: string | undefined, line?: number) {
    super(step === "read"
      ? `Unable to read Elastic config file ${path}${code ? ` (${code})` : ""}`
      : `Unable to parse Elastic config file: invalid YAML in ${path}${line !== undefined ? ` at line ${line}` : ""}`);
    this.name = "ElasticConfigFileError";
    this.path = path;
    this.code = code ?? "UNKNOWN";
    this.line = line;
  }
}

/** The errno code of a filesystem error, only when it has the strict E[A-Z0-9_] shape; anything else is dropped. */
function errnoCode(error: unknown): string | undefined {
  const code = asString(asObject(error)?.code);
  return code && ERRNO_CODE_PATTERN.test(code) ? code : undefined;
}

/** The line a YAMLError points at; every other thrown value (for example the ReferenceError of an unresolved alias) has none. */
function yamlErrorLine(error: unknown): number | undefined {
  return error instanceof YAMLError ? error.linePos?.[0]?.line : undefined;
}

/** Read step of the config loader: any filesystem failure surfaces as fixed text with the validated errno code only. */
function readConfigSource(location: string): string {
  try {
    return readFileSync(location, "utf8");
  } catch (error) {
    throw new ElasticConfigFileError("read", location, errnoCode(error));
  }
}

/** Parse step of the config loader: every thrown value, parser error class or not, becomes fixed text with at most a line number. */
function parseConfigYaml(location: string, source: string): unknown {
  try {
    return parseYaml(source);
  } catch (error) {
    throw new ElasticConfigFileError("parse", location, "INVALID_YAML", yamlErrorLine(error));
  }
}

/**
 * Loads the config file overlay. A missing default file is simply absent; a path named explicitly (argument or
 * environment) that cannot be read is an error, so a typo in the path is not silently ignored.
 */
function overlayFromConfigFile(location: string, explicit: boolean): ElasticConfigOverlay | undefined {
  if (!explicit && !existsSync(location)) return undefined;
  const parsed = asObject(parseConfigYaml(location, readConfigSource(location))) ?? {};
  const elasticsearch = asObject(parsed.elasticsearch) ?? {};
  const kibana = asObject(parsed.kibana) ?? {};
  const cloud = asObject(parsed.cloud) ?? {};
  return {
    elasticsearchUrl: asString(overlayKeys(parsed, "url", "elasticsearch_url", "elasticsearch-url", "elasticsearchUrl") ?? overlayKeys(elasticsearch, "url")),
    kibanaUrl: asString(overlayKeys(parsed, "kibana_url", "kibana-url", "kibanaUrl") ?? overlayKeys(kibana, "url")),
    kibanaSpaceId: asString(overlayKeys(parsed, "space_id", "space-id", "spaceId") ?? overlayKeys(kibana, "space_id", "space")),
    apiKey: asString(overlayKeys(parsed, "api_key", "api-key", "apiKey") ?? overlayKeys(elasticsearch, "api_key", "api-key", "apiKey")),
    username: asString(overlayKeys(parsed, "username") ?? overlayKeys(elasticsearch, "username")),
    password: asString(overlayKeys(parsed, "password") ?? overlayKeys(elasticsearch, "password")),
    bearerToken: asString(overlayKeys(parsed, "bearer_token", "bearer-token", "bearerToken", "token") ?? overlayKeys(elasticsearch, "bearer_token", "token")),
    cloudApiKey: asString(overlayKeys(parsed, "cloud_api_key", "cloud-api-key", "cloudApiKey") ?? overlayKeys(cloud, "api_key", "api-key", "apiKey")),
    cloudApiUrl: asString(overlayKeys(parsed, "cloud_api_url", "cloud-api-url", "cloudApiUrl") ?? overlayKeys(cloud, "url")),
    timeoutSeconds: asNumber(overlayKeys(parsed, "timeout", "timeout_seconds", "timeout-seconds", "timeoutSeconds")),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): ElasticConfigOverlay {
  return {
    elasticsearchUrl: asString(env.ELASTIC_URL) ?? asString(env.ELASTICSEARCH_URL),
    kibanaUrl: asString(env.KIBANA_URL),
    kibanaSpaceId: asString(env.KIBANA_SPACE_ID),
    apiKey: asString(env.ELASTIC_API_KEY),
    username: asString(env.ELASTIC_USERNAME),
    password: asString(env.ELASTIC_PASSWORD),
    bearerToken: asString(env.ELASTIC_BEARER_TOKEN),
    cloudApiKey: asString(env.ELASTIC_CLOUD_API_KEY),
    cloudApiUrl: asString(env.ELASTIC_CLOUD_API_URL),
    timeoutSeconds: asNumber(env.ELASTIC_TIMEOUT),
  };
}

function overlayFromArgs(input: JsonRecord): ElasticConfigOverlay {
  return {
    elasticsearchUrl: asString(input.elasticsearch_url) ?? asString(input.url) ?? asString(input.elastic_url),
    kibanaUrl: asString(input.kibana_url),
    kibanaSpaceId: asString(input.space_id),
    apiKey: asString(input.api_key),
    username: asString(input.username),
    password: asString(input.password),
    bearerToken: asString(input.bearer_token),
    cloudApiKey: asString(input.cloud_api_key),
    cloudApiUrl: asString(input.cloud_api_url),
    timeoutSeconds: asNumber(input.timeout_seconds),
  };
}

function overlaySuppliesCredentials(overlay: ElasticConfigOverlay): boolean {
  return Boolean(overlay.apiKey || (overlay.username && overlay.password) || overlay.bearerToken);
}

function applyOverlay(base: ElasticConfigOverlay, overlay: ElasticConfigOverlay | undefined): ElasticConfigOverlay {
  if (!overlay) return base;
  const credentials = overlaySuppliesCredentials(overlay)
    ? { apiKey: overlay.apiKey, username: overlay.username, password: overlay.password, bearerToken: overlay.bearerToken }
    : {
      apiKey: overlay.apiKey ?? base.apiKey,
      username: overlay.username ?? base.username,
      password: overlay.password ?? base.password,
      bearerToken: overlay.bearerToken ?? base.bearerToken,
    };
  return {
    elasticsearchUrl: overlay.elasticsearchUrl ?? base.elasticsearchUrl,
    kibanaUrl: overlay.kibanaUrl ?? base.kibanaUrl,
    kibanaSpaceId: overlay.kibanaSpaceId ?? base.kibanaSpaceId,
    ...credentials,
    cloudApiKey: overlay.cloudApiKey ?? base.cloudApiKey,
    cloudApiUrl: overlay.cloudApiUrl ?? base.cloudApiUrl,
    timeoutSeconds: overlay.timeoutSeconds ?? base.timeoutSeconds,
  };
}

function overlayHasValues(overlay: ElasticConfigOverlay): boolean {
  return Object.values(overlay).some((value) => value !== undefined);
}

export function resolveElasticConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { cwd?: string; homeDir?: string } = {},
): ElasticResolvedConfig {
  const cwd = options.cwd ?? process.cwd();
  const homeDir = options.homeDir ?? homedir();
  const sourceChain: string[] = [];
  let merged: ElasticConfigOverlay = {};

  const explicitConfigFile = asString(input.config_file) ?? asString(env.ELASTIC_SEC_INSPECTOR_CONFIG);
  const configPath = explicitConfigFile
    ? resolve(cwd, explicitConfigFile)
    : join(homeDir, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE);
  const fileOverlay = overlayFromConfigFile(configPath, explicitConfigFile !== undefined);
  if (fileOverlay && overlayHasValues(fileOverlay)) {
    merged = applyOverlay(merged, fileOverlay);
    sourceChain.push(explicitConfigFile ? `config:${explicitConfigFile}` : `config:~/${DEFAULT_CONFIG_DIR}/${DEFAULT_CONFIG_FILE}`);
  }

  const envOverlay = overlayFromEnv(env);
  if (overlayHasValues(envOverlay)) {
    merged = applyOverlay(merged, envOverlay);
    sourceChain.push("environment");
  }

  const argsOverlay = overlayFromArgs(input);
  if (overlayHasValues(argsOverlay)) {
    merged = applyOverlay(merged, argsOverlay);
    sourceChain.push("arguments");
  }

  if (!merged.elasticsearchUrl) {
    throw new Error(
      "Elasticsearch URL is required. Set ELASTIC_URL, configure url in ~/.elastic-sec-inspector/config.yaml, or pass elasticsearch_url explicitly.",
    );
  }

  const apiKey = merged.apiKey ? normalizeElasticApiKey(merged.apiKey) : undefined;
  const authMode: ElasticResolvedConfig["authMode"] | undefined = apiKey
    ? "api_key"
    : merged.username && merged.password
      ? "basic"
      : merged.bearerToken
        ? "bearer"
        : undefined;
  if (!authMode) {
    throw new Error(
      "Elastic credentials are required. Set ELASTIC_API_KEY, or ELASTIC_USERNAME and ELASTIC_PASSWORD, or ELASTIC_BEARER_TOKEN (or pass api_key, username and password, or bearer_token).",
    );
  }

  return {
    elasticsearchUrl: normalizeBaseUrl(merged.elasticsearchUrl),
    kibanaUrl: merged.kibanaUrl ? normalizeBaseUrl(merged.kibanaUrl) : undefined,
    kibanaSpaceId: merged.kibanaSpaceId && merged.kibanaSpaceId !== "default" ? merged.kibanaSpaceId : undefined,
    authMode,
    apiKey,
    username: merged.username,
    password: merged.password,
    bearerToken: merged.bearerToken,
    cloudApiKey: merged.cloudApiKey,
    cloudApiUrl: normalizeBaseUrl(merged.cloudApiUrl ?? DEFAULT_CLOUD_API_URL),
    timeoutMs: parseTimeoutSeconds(merged.timeoutSeconds),
    maxRetries: DEFAULT_MAX_RETRIES,
    sourceChain: sourceChain.length > 0 ? sourceChain : ["defaults"],
  };
}

export class ElasticRequestError extends Error {
  readonly status: number;
  readonly target: ElasticTarget;

  constructor(message: string, status: number, target: ElasticTarget) {
    // The constructor is the last stop before the message can escape, so the unanchored scrub runs here as well as at the sink.
    super(scrubErrorText(message));
    this.name = "ElasticRequestError";
    this.status = status;
    this.target = target;
  }
}

/**
 * Extracts only the documented error fields of the Elasticsearch, Kibana, and
 * Elastic Cloud JSON error shapes; anything else in the body is never echoed.
 * The summary is scrubbed (configured secrets in every encoding, then every
 * credential carrier) before it is cut to length, so a secret straddling the
 * cut cannot leave an unmatched fragment behind. The truncation note leads the
 * detail rather than trailing it: a cut can end inside a quoted carrier, and a
 * later scrub would read a trailing note as that carrier's value.
 */
function elasticErrorSummary(payload: unknown, config: ElasticSecretConfig): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const error = asObject(object.error);
  const cloudErrors = asObjectArray(object.errors).map((entry) => [asString(entry.code), asString(entry.message)].filter(Boolean).join(" ")).filter(Boolean);
  const candidates = [
    asString(error?.reason),
    asString(error?.type),
    asString(object.message),
    typeof object.error === "string" ? object.error : undefined,
    cloudErrors.length > 0 ? cloudErrors.join("; ") : undefined,
    asString(object.statusCode) ? `statusCode ${asString(object.statusCode)}` : undefined,
  ];
  const summary = candidates.filter((item): item is string => Boolean(item)).join(": ");
  if (!summary) return undefined;
  const scrubbed = redactSecrets(summary, config);
  return scrubbed.length > MAX_ERROR_DETAIL_CHARS ? `(detail truncated to ${MAX_ERROR_DETAIL_CHARS} characters) ${scrubbed.slice(0, MAX_ERROR_DETAIL_CHARS)}` : scrubbed;
}

/**
 * The documented container of a 2xx body, checked before a payload is accepted: an object carrying one of its
 * documented keys (or every one of them, for a document whose keys are all guaranteed and whose names are common
 * enough on foreign pages that one match proves nothing), a map whose every entry is an object carrying one of the
 * documented entry keys (an empty map is a documented answer: no role mappings, no repositories), an array of
 * objects, or an object whose documented key holds an array. An empty body, a non-JSON body, or JSON of any other
 * shape is recorded as a failed read of the request with the status the server sent, never as an empty inventory, so
 * the dependent verdicts go manual instead of passing or failing on data that was never observed.
 */
export type ElasticResponseShape =
  | { kind: "object"; keys: readonly string[]; all?: boolean }
  | { kind: "map"; entryKeys: readonly string[] }
  | { kind: "array" }
  | { kind: "list"; key: string };

export function matchesResponseShape(payload: unknown, shape: ElasticResponseShape): boolean {
  switch (shape.kind) {
    case "object": {
      const record = asObject(payload);
      if (record === undefined) return false;
      return shape.all ? shape.keys.every((key) => record[key] !== undefined) : shape.keys.some((key) => record[key] !== undefined);
    }
    case "map": {
      const record = asObject(payload);
      if (!record) return false;
      return Object.values(record).every((entry) => {
        const item = asObject(entry);
        return item !== undefined && shape.entryKeys.some((key) => item[key] !== undefined);
      });
    }
    case "array":
      return Array.isArray(payload) && payload.every((entry) => asObject(entry) !== undefined);
    case "list": {
      const record = asObject(payload);
      return record !== undefined && Array.isArray(record[shape.key]);
    }
    default: {
      const exhaustive: never = shape;
      throw new Error(`Unsupported Elastic response shape: ${String(exhaustive)}`);
    }
  }
}

/** Fixed text naming the documented shape; nothing from the body enters it. */
export function describeResponseShape(shape: ElasticResponseShape): string {
  switch (shape.kind) {
    case "object":
      return `JSON object with ${shape.all ? "all" : "any"} of ${shape.keys.join(", ")}`;
    case "map":
      return `JSON object of named entries each carrying any of ${shape.entryKeys.join(", ")}`;
    case "array":
      return "JSON array of objects";
    case "list":
      return `JSON object with an array under ${shape.key}`;
    default: {
      const exhaustive: never = shape;
      throw new Error(`Unsupported Elastic response shape: ${String(exhaustive)}`);
    }
  }
}

const ARRAY_SHAPE: ElasticResponseShape = { kind: "array" };
const ITEMS_SHAPE: ElasticResponseShape = { kind: "list", key: "items" };
const OPERATION_MODE_SHAPE: ElasticResponseShape = { kind: "object", keys: ["operation_mode"] };
const AUTHENTICATE_SHAPE: ElasticResponseShape = { kind: "object", keys: ["username", "roles"] };
const HAS_PRIVILEGES_SHAPE: ElasticResponseShape = { kind: "object", keys: ["has_all_requested", "cluster", "index", "application"] };
const LICENSE_SHAPE: ElasticResponseShape = { kind: "object", keys: ["license"] };
const XPACK_INFO_SHAPE: ElasticResponseShape = { kind: "object", keys: ["features", "license", "build"] };
const XPACK_USAGE_SHAPE: ElasticResponseShape = { kind: "object", keys: ["security", "monitoring", "watcher", "ml", "ilm", "sql", "rollup", "graph"] };
const CLUSTER_SETTINGS_SHAPE: ElasticResponseShape = { kind: "object", keys: ["persistent", "transient", "defaults"] };
const NODE_SETTINGS_SHAPE: ElasticResponseShape = { kind: "object", keys: ["nodes", "_nodes"] };
const USERS_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["username", "roles", "enabled"] };
const ROLES_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["cluster", "indices", "applications", "run_as", "metadata", "transient_metadata"] };
const ROLE_MAPPINGS_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["enabled", "roles", "role_templates", "rules", "metadata"] };
const ILM_POLICIES_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["policy", "version", "modified_date", "in_use_by"] };
const SLM_POLICIES_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["policy", "version", "modified_date", "modified_date_millis", "next_execution", "next_execution_millis", "repository", "schedule"] };
const SNAPSHOT_REPOSITORIES_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["type", "settings", "uuid"] };
const INGEST_PIPELINES_SHAPE: ElasticResponseShape = { kind: "map", entryKeys: ["processors", "description", "version", "_meta", "on_failure"] };
/** Both status formats (v7 and v8) always carry all four; `status` alone is a common foreign status-page key. */
const KIBANA_STATUS_SHAPE: ElasticResponseShape = { kind: "object", keys: ["name", "uuid", "version", "status"], all: true };

function contentTypeLabel(response: Response): string {
  const raw = response.headers.get("content-type");
  return raw ? raw.split(";")[0].trim().toLowerCase() || "unknown content type" : "unknown content type";
}

/** Describes a body that is not a documented JSON error shape by status, media type, and length only. */
function describeOpaqueBody(response: Response, rawText: string, parsedJson: boolean): string {
  const bytes = Buffer.byteLength(rawText, "utf8");
  return parsedJson
    ? `${response.status} ${response.statusText}: JSON body without a documented error field (${contentTypeLabel(response)}, ${bytes} bytes, not echoed)`
    : `${response.status} ${response.statusText}: non-JSON body (${contentTypeLabel(response)}, ${bytes} bytes, not echoed)`;
}

function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

function retryDelayMs(attempt: number, retryAfterHeader: string | null): number {
  const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : Number.NaN;
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0) {
    return Math.min(retryAfterSeconds * 1000, 30_000);
  }
  return Math.min(DEFAULT_RETRY_BASE_MS * 2 ** attempt, 10_000);
}

export class ElasticApiClient {
  private readonly config: ElasticResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: (ms: number) => Promise<void>;

  constructor(
    config: ElasticResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      sleepImpl?: (ms: number) => Promise<void>;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? ((ms: number) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    // The configured secrets are scrubbed from every recorded error string in every encoded form from here on.
    registerConfiguredSecrets(config);
  }

  getResolvedConfig(): ElasticResolvedConfig {
    return this.config;
  }

  hasKibana(): boolean {
    return Boolean(this.config.kibanaUrl);
  }

  hasCloud(): boolean {
    return Boolean(this.config.cloudApiKey);
  }

  private baseUrlFor(target: ElasticTarget): string {
    switch (target) {
      case "elasticsearch":
        return this.config.elasticsearchUrl;
      case "kibana":
        if (!this.config.kibanaUrl) throw new Error("KIBANA_URL is not configured.");
        return this.config.kibanaUrl;
      case "cloud":
        return this.config.cloudApiUrl;
      default: {
        const exhaustive: never = target;
        throw new Error(`Unsupported Elastic target: ${String(exhaustive)}`);
      }
    }
  }

  private authorizationHeader(target: ElasticTarget): string {
    if (target === "cloud") {
      if (!this.config.cloudApiKey) throw new Error("ELASTIC_CLOUD_API_KEY is not configured.");
      return `ApiKey ${this.config.cloudApiKey}`;
    }
    switch (this.config.authMode) {
      case "api_key":
        return `ApiKey ${this.config.apiKey}`;
      case "basic":
        return `Basic ${encodeBase64(`${this.config.username}:${this.config.password}`)}`;
      case "bearer":
        return `Bearer ${this.config.bearerToken}`;
      default: {
        const exhaustive: never = this.config.authMode;
        throw new Error(`Unsupported Elastic auth mode: ${String(exhaustive)}`);
      }
    }
  }

  buildUrl(target: ElasticTarget, path: string, query: JsonRecord = {}): string {
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const spacePrefix = target === "kibana" && this.config.kibanaSpaceId && normalizedPath.startsWith("/api/")
      ? `/s/${encodeURIComponent(this.config.kibanaSpaceId)}`
      : "";
    const url = new URL(`${this.baseUrlFor(target)}${spacePrefix}${normalizedPath}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  async request(
    target: ElasticTarget,
    path: string,
    options: { shape: ElasticResponseShape; method?: "GET" | "POST"; query?: JsonRecord; body?: unknown },
  ): Promise<unknown> {
    const method = options.method ?? "GET";
    const url = this.buildUrl(target, path, options.query ?? {});
    const headers = new Headers();
    headers.set("accept", "application/json");
    headers.set("authorization", this.authorizationHeader(target));
    if (target === "kibana") headers.set("kbn-xsrf", "true");
    if (options.body !== undefined) headers.set("content-type", "application/json");

    for (let attempt = 0; ; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const response = await this.fetchImpl(url, {
          method,
          headers,
          body: options.body === undefined ? undefined : JSON.stringify(options.body),
          signal: controller.signal,
        });
        if (isRetryableStatus(response.status) && attempt < this.config.maxRetries) {
          await this.sleepImpl(retryDelayMs(attempt, response.headers.get("retry-after")));
          continue;
        }
        const rawText = await response.text();
        let payload: unknown = {};
        let parsedJson = true;
        if (rawText.length > 0) {
          try {
            payload = JSON.parse(rawText);
          } catch {
            parsedJson = false;
          }
        }
        if (!response.ok) {
          const detail = (parsedJson ? elasticErrorSummary(payload, this.config) : undefined) ?? describeOpaqueBody(response, rawText, parsedJson);
          throw new ElasticRequestError(
            redactSecrets(`${target} request ${method} ${path} failed (${response.status} ${response.statusText}): ${detail}`, this.config),
            response.status,
            target,
          );
        }
        // A success status is not a success by itself. An empty body, a portal or proxy page, or JSON of some other
        // shape is not an empty inventory; each is a failed read of this request with the status the server sent.
        const silentSuccess = rawText.length === 0
          ? `${response.status} ${response.statusText}: empty body (0 bytes)`
          : !parsedJson
            ? describeOpaqueBody(response, rawText, false)
            : matchesResponseShape(payload, options.shape)
              ? undefined
              : `${response.status} ${response.statusText}: JSON body that is not the documented ${describeResponseShape(options.shape)} (${contentTypeLabel(response)}, ${Buffer.byteLength(rawText, "utf8")} bytes, not echoed)`;
        if (silentSuccess !== undefined) {
          throw new ElasticRequestError(
            redactSecrets(`${target} request ${method} ${path} returned a ${silentSuccess}; the endpoint is not serving the JSON API`, this.config),
            response.status,
            target,
          );
        }
        return payload;
      } catch (error) {
        if (error instanceof ElasticRequestError) throw error;
        const aborted = error instanceof Error && error.name === "AbortError";
        if (!aborted && attempt < this.config.maxRetries && isNetworkError(error)) {
          await this.sleepImpl(retryDelayMs(attempt, null));
          continue;
        }
        throw new Error(redactSecrets(
          aborted
            ? `${target} request ${method} ${path} timed out after ${this.config.timeoutMs}ms`
            : `${target} request ${method} ${path} failed: ${errorMessage(error)}`,
          this.config,
        ));
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  async esGet(path: string, shape: ElasticResponseShape, query: JsonRecord = {}): Promise<unknown> {
    return this.request("elasticsearch", path, { shape, query });
  }

  async esPost(path: string, shape: ElasticResponseShape, body: unknown, query: JsonRecord = {}): Promise<unknown> {
    return this.request("elasticsearch", path, { shape, method: "POST", body, query });
  }

  async kibanaGet(path: string, shape: ElasticResponseShape, query: JsonRecord = {}): Promise<unknown> {
    return this.request("kibana", path, { shape, query });
  }

  async cloudGet(path: string, shape: ElasticResponseShape, query: JsonRecord = {}): Promise<unknown> {
    return this.request("cloud", path, { shape, query });
  }

  async listKibanaPages(
    path: string,
    options: { perPageParam: "perPage" | "per_page"; itemsKey: "items" | "data"; limit?: number; query?: JsonRecord } ,
  ): Promise<ElasticPagedList> {
    const limit = clampNumber(options.limit, DEFAULT_KIBANA_LIMIT, 1, 10_000);
    const perPage = Math.min(DEFAULT_KIBANA_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    for (let page = 1; items.length < limit; page += 1) {
      const payload = asObject(await this.kibanaGet(path, { kind: "list", key: options.itemsKey }, {
        ...(options.query ?? {}),
        page,
        [options.perPageParam]: perPage,
      })) ?? {};
      pages += 1;
      const pageItems = asObjectArray(payload[options.itemsKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      total = asNumber(payload.total) ?? total;
      if (pageItems.length === 0 || pageItems.length < perPage || (total !== undefined && items.length >= total)) {
        exhausted = true;
        break;
      }
    }
    return pagedList(items, total, pages, exhausted);
  }

  async authenticate(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/_authenticate", AUTHENTICATE_SHAPE)) ?? {};
  }

  async hasPrivileges(clusterPrivileges: string[] = REQUIRED_CLUSTER_PRIVILEGES): Promise<JsonRecord> {
    return asObject(await this.esPost("/_security/user/_has_privileges", HAS_PRIVILEGES_SHAPE, {
      cluster: clusterPrivileges,
      index: [{ names: [".security*"], privileges: ["read"], allow_restricted_indices: true }],
    })) ?? {};
  }

  async getLicense(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_license", LICENSE_SHAPE)) ?? {};
  }

  async getXpackInfo(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_xpack", XPACK_INFO_SHAPE)) ?? {};
  }

  async getXpackUsage(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_xpack/usage", XPACK_USAGE_SHAPE)) ?? {};
  }

  async getClusterSettings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_cluster/settings", CLUSTER_SETTINGS_SHAPE, { include_defaults: true, flat_settings: true })) ?? {};
  }

  async getNodeSettings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_nodes/settings", NODE_SETTINGS_SHAPE, { flat_settings: true })) ?? {};
  }

  async listSslCertificates(): Promise<JsonRecord[]> {
    return asObjectArray(await this.esGet("/_ssl/certificates", ARRAY_SHAPE));
  }

  async listUsers(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/user", USERS_SHAPE)) ?? {};
  }

  async listRoles(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/role", ROLES_SHAPE)) ?? {};
  }

  async listRoleMappings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/role_mapping", ROLE_MAPPINGS_SHAPE)) ?? {};
  }

  async listApiKeys(limit = DEFAULT_API_KEY_LIMIT, pageSize = DEFAULT_API_KEY_PAGE_SIZE): Promise<ElasticPagedList> {
    const maxItems = clampNumber(limit, DEFAULT_API_KEY_LIMIT, 1, 10_000);
    const size = Math.min(clampNumber(pageSize, DEFAULT_API_KEY_PAGE_SIZE, 1, 10_000), maxItems);
    const items: JsonRecord[] = [];
    let searchAfter: unknown[] | undefined;
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    let cursorMissing = false;
    while (items.length < maxItems) {
      const payload = asObject(await this.esPost("/_security/_query/api_key", { kind: "list", key: "api_keys" }, {
        size,
        sort: [{ creation: { order: "asc" } }, { name: { order: "asc" } }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      }, { with_limited_by: true })) ?? {};
      pages += 1;
      const pageItems = asObjectArray(payload.api_keys);
      items.push(...pageItems.slice(0, maxItems - items.length));
      total = asNumber(payload.total) ?? total;
      if (pageItems.length < size || (total !== undefined && items.length >= total)) {
        exhausted = true;
        break;
      }
      const last = pageItems[pageItems.length - 1];
      searchAfter = last ? asArray(last._sort) : undefined;
      if (!searchAfter || searchAfter.length === 0) {
        // A full page without a search_after cursor cannot be continued, so the remainder is unknown.
        cursorMissing = true;
        break;
      }
    }
    const page = pagedList(items, total, pages, exhausted);
    return cursorMissing ? { ...page, truncated: true } : page;
  }

  async getIlmStatus(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ilm/status", OPERATION_MODE_SHAPE)) ?? {};
  }

  async listIlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ilm/policy", ILM_POLICIES_SHAPE)) ?? {};
  }

  async getSlmStatus(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_slm/status", OPERATION_MODE_SHAPE)) ?? {};
  }

  async listSlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_slm/policy", SLM_POLICIES_SHAPE)) ?? {};
  }

  async listSnapshotRepositories(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_snapshot/_all", SNAPSHOT_REPOSITORIES_SHAPE)) ?? {};
  }

  async listWatches(limit = DEFAULT_WATCH_LIMIT): Promise<ElasticPagedList> {
    const maxItems = clampNumber(limit, DEFAULT_WATCH_LIMIT, 1, 10_000);
    const size = Math.min(DEFAULT_WATCH_PAGE_SIZE, maxItems);
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    for (let from = 0; items.length < maxItems; from += size) {
      const payload = asObject(await this.esPost("/_watcher/_query/watches", { kind: "list", key: "watches" }, { from, size })) ?? {};
      pages += 1;
      const pageItems = asObjectArray(payload.watches);
      items.push(...pageItems.slice(0, maxItems - items.length));
      total = asNumber(payload.count) ?? total;
      if (pageItems.length < size || (total !== undefined && items.length >= total)) {
        exhausted = true;
        break;
      }
    }
    return pagedList(items, total, pages, exhausted);
  }

  async listIngestPipelines(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ingest/pipeline", INGEST_PIPELINES_SHAPE)) ?? {};
  }

  async getKibanaStatus(): Promise<JsonRecord> {
    return asObject(await this.kibanaGet("/api/status", KIBANA_STATUS_SHAPE)) ?? {};
  }

  async listSpaces(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/spaces/space", ARRAY_SHAPE));
  }

  async listKibanaRoles(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/security/role", ARRAY_SHAPE));
  }

  async listAgentPolicies(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/fleet/agent_policies", { perPageParam: "perPage", itemsKey: "items", limit });
  }

  async listFleetOutputs(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    const cap = clampNumber(limit, DEFAULT_KIBANA_LIMIT, 1, 10_000);
    const payload = asObject(await this.kibanaGet("/api/fleet/outputs", ITEMS_SHAPE)) ?? {};
    const outputs = asObjectArray(payload.items);
    return pagedList(outputs.slice(0, cap), asNumber(payload.total) ?? outputs.length, 1, outputs.length <= cap);
  }

  async listEnrollmentApiKeys(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    const page = await this.listKibanaPages("/api/fleet/enrollment_api_keys", { perPageParam: "perPage", itemsKey: "items", limit });
    return { ...page, items: page.items.map((item) => ({ ...item, api_key: item.api_key === undefined ? undefined : "[REDACTED]" })) };
  }

  async listFleetServerHosts(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    const cap = clampNumber(limit, DEFAULT_KIBANA_LIMIT, 1, 10_000);
    const payload = asObject(await this.kibanaGet("/api/fleet/fleet_server_hosts", ITEMS_SHAPE)) ?? {};
    const hosts = asObjectArray(payload.items);
    return pagedList(hosts.slice(0, cap), asNumber(payload.total) ?? hosts.length, 1, hosts.length <= cap);
  }

  async listDetectionRules(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/detection_engine/rules/_find", { perPageParam: "per_page", itemsKey: "data", limit });
  }

  async listAlertingRules(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/alerting/rules/_find", { perPageParam: "per_page", itemsKey: "data", limit });
  }

  async listConnectors(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/actions/connectors", ARRAY_SHAPE));
  }

  async listCloudDeployments(): Promise<JsonRecord[]> {
    return asObjectArray(asObject(await this.cloudGet("/api/v1/deployments", { kind: "list", key: "deployments" }))?.deployments);
  }
}

function isNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /fetch failed|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|socket hang up/i.test(`${error.message} ${String((error as { cause?: unknown }).cause ?? "")}`);
}

function pagedList(items: JsonRecord[], total: number | undefined, pages: number, exhausted: boolean): ElasticPagedList {
  const truncated = total !== undefined ? items.length < total : !exhausted;
  return { items, total, truncated, pages, seen: items.length };
}

function asPagedList(value: unknown): ElasticPagedList | undefined {
  const object = asObject(value);
  if (!object || !Array.isArray(object.items) || typeof object.truncated !== "boolean") return undefined;
  const items = asObjectArray(object.items);
  return {
    items,
    total: asNumber(object.total),
    truncated: object.truncated,
    pages: asNumber(object.pages) ?? 1,
    seen: asNumber(object.seen) ?? items.length,
  };
}

export type ElasticReader = Pick<
  ElasticApiClient,
  | "getResolvedConfig"
  | "authenticate"
  | "hasPrivileges"
  | "getLicense"
  | "getXpackInfo"
  | "getXpackUsage"
  | "getClusterSettings"
  | "getNodeSettings"
  | "listSslCertificates"
  | "listUsers"
  | "listRoles"
  | "listRoleMappings"
  | "listApiKeys"
  | "getIlmStatus"
  | "listIlmPolicies"
  | "getSlmStatus"
  | "listSlmPolicies"
  | "listSnapshotRepositories"
  | "listWatches"
  | "listIngestPipelines"
  | "getKibanaStatus"
  | "listSpaces"
  | "listKibanaRoles"
  | "listAgentPolicies"
  | "listFleetOutputs"
  | "listEnrollmentApiKeys"
  | "listFleetServerHosts"
  | "listDetectionRules"
  | "listAlertingRules"
  | "listConnectors"
  | "listCloudDeployments"
>;

export type ElasticPartialReader = Pick<ElasticReader, "getResolvedConfig"> & Partial<Omit<ElasticReader, "getResolvedConfig">>;

interface DatasetSpec {
  name: ElasticDatasetName;
  target: ElasticTarget;
  endpoint: string;
  load: (client: ElasticPartialReader, options: ElasticAssessmentOptions) => Promise<unknown>;
}

function requireMethod<K extends keyof Omit<ElasticReader, "getResolvedConfig">>(
  client: ElasticPartialReader,
  method: K,
): ElasticReader[K] {
  const candidate = client[method];
  if (typeof candidate !== "function") {
    throw new Error(`Elastic client does not implement ${method}.`);
  }
  return candidate.bind(client) as ElasticReader[K];
}

const DATASET_SPECS: Record<ElasticDatasetName, DatasetSpec> = {
  authenticate: { name: "authenticate", target: "elasticsearch", endpoint: "GET /_security/_authenticate", load: (client) => requireMethod(client, "authenticate")() },
  privileges: { name: "privileges", target: "elasticsearch", endpoint: "POST /_security/user/_has_privileges", load: (client) => requireMethod(client, "hasPrivileges")() },
  license: { name: "license", target: "elasticsearch", endpoint: "GET /_license", load: (client) => requireMethod(client, "getLicense")() },
  xpack_info: { name: "xpack_info", target: "elasticsearch", endpoint: "GET /_xpack", load: (client) => requireMethod(client, "getXpackInfo")() },
  xpack_usage: { name: "xpack_usage", target: "elasticsearch", endpoint: "GET /_xpack/usage", load: (client) => requireMethod(client, "getXpackUsage")() },
  cluster_settings: { name: "cluster_settings", target: "elasticsearch", endpoint: "GET /_cluster/settings?include_defaults=true&flat_settings=true", load: (client) => requireMethod(client, "getClusterSettings")() },
  node_settings: { name: "node_settings", target: "elasticsearch", endpoint: "GET /_nodes/settings?flat_settings=true", load: (client) => requireMethod(client, "getNodeSettings")() },
  ssl_certificates: { name: "ssl_certificates", target: "elasticsearch", endpoint: "GET /_ssl/certificates", load: (client) => requireMethod(client, "listSslCertificates")() },
  users: { name: "users", target: "elasticsearch", endpoint: "GET /_security/user", load: (client) => requireMethod(client, "listUsers")() },
  roles: { name: "roles", target: "elasticsearch", endpoint: "GET /_security/role", load: (client) => requireMethod(client, "listRoles")() },
  role_mappings: { name: "role_mappings", target: "elasticsearch", endpoint: "GET /_security/role_mapping", load: (client) => requireMethod(client, "listRoleMappings")() },
  api_keys: { name: "api_keys", target: "elasticsearch", endpoint: "POST /_security/_query/api_key?with_limited_by=true", load: (client, options) => requireMethod(client, "listApiKeys")(options.apiKeyLimit) },
  ilm_status: { name: "ilm_status", target: "elasticsearch", endpoint: "GET /_ilm/status", load: (client) => requireMethod(client, "getIlmStatus")() },
  ilm_policies: { name: "ilm_policies", target: "elasticsearch", endpoint: "GET /_ilm/policy", load: (client) => requireMethod(client, "listIlmPolicies")() },
  slm_status: { name: "slm_status", target: "elasticsearch", endpoint: "GET /_slm/status", load: (client) => requireMethod(client, "getSlmStatus")() },
  slm_policies: { name: "slm_policies", target: "elasticsearch", endpoint: "GET /_slm/policy", load: (client) => requireMethod(client, "listSlmPolicies")() },
  snapshot_repositories: { name: "snapshot_repositories", target: "elasticsearch", endpoint: "GET /_snapshot/_all", load: (client) => requireMethod(client, "listSnapshotRepositories")() },
  watches: { name: "watches", target: "elasticsearch", endpoint: "POST /_watcher/_query/watches", load: (client, options) => requireMethod(client, "listWatches")(options.watchLimit) },
  ingest_pipelines: { name: "ingest_pipelines", target: "elasticsearch", endpoint: "GET /_ingest/pipeline", load: (client) => requireMethod(client, "listIngestPipelines")() },
  kibana_status: { name: "kibana_status", target: "kibana", endpoint: "GET /api/status", load: (client) => requireMethod(client, "getKibanaStatus")() },
  kibana_spaces: { name: "kibana_spaces", target: "kibana", endpoint: "GET /api/spaces/space", load: (client) => requireMethod(client, "listSpaces")() },
  kibana_roles: { name: "kibana_roles", target: "kibana", endpoint: "GET /api/security/role", load: (client) => requireMethod(client, "listKibanaRoles")() },
  fleet_agent_policies: { name: "fleet_agent_policies", target: "kibana", endpoint: "GET /api/fleet/agent_policies", load: (client, options) => requireMethod(client, "listAgentPolicies")(options.kibanaLimit) },
  fleet_outputs: { name: "fleet_outputs", target: "kibana", endpoint: "GET /api/fleet/outputs", load: (client, options) => requireMethod(client, "listFleetOutputs")(options.kibanaLimit) },
  fleet_enrollment_api_keys: { name: "fleet_enrollment_api_keys", target: "kibana", endpoint: "GET /api/fleet/enrollment_api_keys", load: (client, options) => requireMethod(client, "listEnrollmentApiKeys")(options.kibanaLimit) },
  fleet_server_hosts: { name: "fleet_server_hosts", target: "kibana", endpoint: "GET /api/fleet/fleet_server_hosts", load: (client, options) => requireMethod(client, "listFleetServerHosts")(options.kibanaLimit) },
  detection_rules: { name: "detection_rules", target: "kibana", endpoint: "GET /api/detection_engine/rules/_find", load: (client, options) => requireMethod(client, "listDetectionRules")(options.kibanaLimit) },
  alerting_rules: { name: "alerting_rules", target: "kibana", endpoint: "GET /api/alerting/rules/_find", load: (client, options) => requireMethod(client, "listAlertingRules")(options.kibanaLimit) },
  connectors: { name: "connectors", target: "kibana", endpoint: "GET /api/actions/connectors", load: (client) => requireMethod(client, "listConnectors")() },
  cloud_deployments: { name: "cloud_deployments", target: "cloud", endpoint: "GET /api/v1/deployments", load: (client) => requireMethod(client, "listCloudDeployments")() },
};

export const ELASTIC_AREA_DATASETS: Record<ElasticAssessmentArea, ElasticDatasetName[]> = {
  identity: ["node_settings", "cluster_settings", "xpack_usage", "license", "privileges", "roles", "role_mappings", "api_keys"],
  access_control: ["license", "xpack_usage", "users", "roles", "role_mappings"],
  transport_security: ["node_settings", "cluster_settings", "xpack_usage", "ssl_certificates"],
  cluster_hardening: [
    "node_settings",
    "cluster_settings",
    "xpack_usage",
    "xpack_info",
    "license",
    "roles",
    "ilm_status",
    "ilm_policies",
    "slm_status",
    "slm_policies",
    "snapshot_repositories",
    "watches",
    "ingest_pipelines",
    "kibana_spaces",
    "connectors",
    "alerting_rules",
    "detection_rules",
  ],
  kibana: [
    "kibana_status",
    "kibana_spaces",
    "kibana_roles",
    "fleet_agent_policies",
    "fleet_outputs",
    "fleet_enrollment_api_keys",
    "fleet_server_hosts",
  ],
};

export const ELASTIC_ALL_DATASETS = Object.keys(DATASET_SPECS) as ElasticDatasetName[];

function targetConfigured(config: ElasticResolvedConfig, target: ElasticTarget): string | undefined {
  switch (target) {
    case "elasticsearch":
      return undefined;
    case "kibana":
      return config.kibanaUrl ? undefined : "KIBANA_URL is not configured";
    case "cloud":
      return config.cloudApiKey ? undefined : "ELASTIC_CLOUD_API_KEY is not configured";
    default: {
      const exhaustive: never = target;
      throw new Error(`Unsupported Elastic target: ${String(exhaustive)}`);
    }
  }
}

export async function collectElasticSnapshot(
  client: ElasticPartialReader,
  names: ElasticDatasetName[],
  options: ElasticAssessmentOptions = {},
): Promise<ElasticSnapshot> {
  const config = client.getResolvedConfig();
  const snapshot: ElasticSnapshot = {};
  await Promise.all([...new Set(names)].map(async (name) => {
    const spec = DATASET_SPECS[name];
    const skipped = targetConfigured(config, spec.target);
    if (skipped) {
      snapshot[name] = { name, target: spec.target, endpoint: spec.endpoint, skipped };
      return;
    }
    try {
      const loaded = await spec.load(client, options);
      const paged = asPagedList(loaded);
      snapshot[name] = {
        name,
        target: spec.target,
        endpoint: spec.endpoint,
        data: redactSensitiveValues(projectDataset(name, paged ? paged.items : loaded)),
        ...(paged ? { page: { seen: paged.seen, total: paged.total, truncated: paged.truncated, pages: paged.pages } } : {}),
      };
    } catch (error) {
      snapshot[name] = {
        name,
        target: spec.target,
        endpoint: spec.endpoint,
        error: redactSecrets(errorMessage(error), config),
        ...(error instanceof ElasticRequestError ? { status: error.status } : {}),
      };
    }
  }));
  return snapshot;
}

/**
 * Applies the per-dataset projection before anything is stored or assessed: every dataset is reduced to the documented
 * fields its verdicts read, so descriptions, notes, metadata, rule queries and parameters, policy overrides, output
 * YAML, and every other free-form carrier are dropped rather than scrubbed. The data-side scrub then runs over what
 * remains. A dataset whose payload is not the documented container (guarded at the client) projects to itself.
 */
export function projectDataset(name: ElasticDatasetName, data: unknown): unknown {
  const record = asObject(data);
  const projectObject = (project: (record: JsonRecord) => JsonRecord): unknown => (record ? project(record) : data);
  const projectMap = (project: (entry: JsonRecord, key: string) => JsonRecord): unknown => (record ? projectRecordMap(record, project) : data);
  const projectList = (project: (entry: JsonRecord) => JsonRecord): unknown => (Array.isArray(data) ? asObjectArray(data).map(project) : data);
  switch (name) {
    case "authenticate":
      return projectObject(projectAuthenticate);
    case "privileges":
      return projectObject(projectPrivileges);
    case "license":
      return projectObject(projectLicense);
    case "xpack_info":
      return projectObject(projectXpackInfo);
    case "xpack_usage":
      return projectObject(projectXpackUsage);
    case "cluster_settings":
      return projectObject(projectClusterSettings);
    case "node_settings":
      return projectObject(projectNodeSettings);
    case "ssl_certificates":
      return projectList(projectSslCertificate);
    case "users":
      return projectMap(projectUser);
    case "roles":
      return projectMap(projectRoleDescriptor);
    case "role_mappings":
      return projectMap(projectRoleMapping);
    case "api_keys":
      return projectList(projectApiKey);
    case "ilm_status":
    case "slm_status":
      return projectObject((status) => pick(status, ["operation_mode"]));
    case "ilm_policies":
      return projectMap(projectIlmPolicy);
    case "slm_policies":
      return projectMap(projectSlmPolicy);
    case "snapshot_repositories":
      return projectMap(projectSnapshotRepository);
    case "watches":
      return projectList(projectWatch);
    case "ingest_pipelines":
      return projectObject(projectPipelines);
    case "kibana_status":
      return projectObject(projectKibanaStatus);
    case "kibana_spaces":
      return projectList(projectKibanaSpace);
    case "kibana_roles":
      return projectList(projectKibanaRole);
    case "fleet_agent_policies":
      return projectList(projectAgentPolicy);
    case "fleet_outputs":
      return projectList(projectFleetOutput);
    case "fleet_enrollment_api_keys":
      return projectList(projectEnrollmentApiKey);
    case "fleet_server_hosts":
      return projectList(projectFleetServerHost);
    case "detection_rules":
      return projectList(projectDetectionRule);
    case "alerting_rules":
      return projectList(projectAlertingRule);
    case "connectors":
      return projectList(projectConnector);
    case "cloud_deployments":
      return projectList(projectCloudDeployment);
    default: {
      const exhaustive: never = name;
      throw new Error(`Unsupported Elastic dataset: ${String(exhaustive)}`);
    }
  }
}

export function listSnapshotErrors(snapshot: ElasticSnapshot): string[] {
  return Object.values(snapshot)
    .filter((dataset): dataset is ElasticDataset => Boolean(dataset?.error))
    .map((dataset) => `${dataset.name} (${dataset.endpoint}): ${dataset.error}`);
}

/** Lists datasets that were never requested because their target (Kibana or Elastic Cloud) is not configured. */
export function listSnapshotSkips(snapshot: ElasticSnapshot): string[] {
  return Object.values(snapshot)
    .filter((dataset): dataset is ElasticDataset => Boolean(dataset?.skipped))
    .map((dataset) => `${dataset.name}: not requested, ${dataset.skipped}`);
}

/** Lists paged datasets whose collection stopped before the inventory was exhausted. */
export function listSnapshotTruncations(snapshot: ElasticSnapshot): string[] {
  return Object.values(snapshot)
    .filter((dataset): dataset is ElasticDataset => Boolean(dataset && dataset.error === undefined && dataset.skipped === undefined && dataset.page?.truncated))
    .map((dataset) => `${dataset.name} (${dataset.endpoint}): truncated after ${dataset.page?.seen} of ${dataset.page?.total ?? "an unknown total"} across ${dataset.page?.pages} page(s)`);
}

function datasetData<T = unknown>(snapshot: ElasticSnapshot, name: ElasticDatasetName): T | undefined {
  const dataset = snapshot[name];
  return dataset && dataset.error === undefined && dataset.skipped === undefined ? dataset.data as T : undefined;
}

function datasetProblem(snapshot: ElasticSnapshot, name: ElasticDatasetName): string | undefined {
  const dataset = snapshot[name];
  if (!dataset) return `${name} was not collected`;
  return dataset.error ?? dataset.skipped;
}

function datasetPage(snapshot: ElasticSnapshot, name: ElasticDatasetName): ElasticPageInfo | undefined {
  const dataset = snapshot[name];
  return dataset && dataset.error === undefined && dataset.skipped === undefined ? dataset.page : undefined;
}

function dependencyProblems(snapshot: ElasticSnapshot, names: ElasticDatasetName[]): string[] {
  return names
    .map((name) => {
      const problem = datasetProblem(snapshot, name);
      if (!problem) return undefined;
      // A dataset that was never requested (not configured, or not part of this run) names no
      // endpoint, because no request was observed.
      if (!snapshot[name]) return `${name}: not collected in this run`;
      return snapshot[name]?.skipped ? `${name}: not requested, ${problem}` : `${name} (${DATASET_SPECS[name].endpoint}): ${problem}`;
    })
    .filter((item): item is string => Boolean(item));
}

function truncationNotes(snapshot: ElasticSnapshot, names: ElasticDatasetName[]): string[] {
  return names
    .map((name) => {
      const page = datasetPage(snapshot, name);
      if (!page?.truncated) return undefined;
      return `${name} is truncated (${page.seen} of ${page.total ?? "an unknown total"} seen across ${page.pages} page(s); raise the collection limit)`;
    })
    .filter((item): item is string => Boolean(item));
}

function emptyInventoryProblem(snapshot: ElasticSnapshot, name: ElasticDatasetName, size: number | undefined, reason: string): string | undefined {
  if (size !== 0 || datasetProblem(snapshot, name)) return undefined;
  return `${name} (${DATASET_SPECS[name].endpoint}) returned zero entries although ${reason}, so the view is treated as restricted`;
}

interface VerdictGuard {
  /** Essential inventories that could not be read; the verdict becomes manual. */
  problems: string[];
  /** Inventories read only partially (truncated, capped, or single-node views); the verdict is capped at warn. */
  partial: string[];
  /** Secondary inventories that could not be read but are not essential; the verdict is capped at warn and the summary names them. */
  unchecked?: string[];
  collect: string;
}

interface Verdict {
  status: ElasticFinding["status"];
  summary: string;
  evidence?: JsonRecord;
}

function guardedFinding(
  number: number,
  severity: ElasticFinding["severity"],
  computed: Verdict,
  guard: VerdictGuard,
): ElasticFinding {
  const unchecked = guard.unchecked ?? [];
  const evidence: JsonRecord = {
    ...(computed.evidence ?? {}),
    /** What the readable sources alone showed, before the guard demoted the verdict. */
    observed_status: computed.status,
    unreadable_sources: guard.problems,
    partial_sources: guard.partial,
    unchecked_sources: unchecked,
  };
  if (computed.status === "fail") {
    // A violation observed in readable inventories is a real finding and stays fail (evaluators
    // never derive a fail from an unread inventory's fallback); the unread sources are still named
    // and, when essential, the summary says what a human must collect to complete the picture.
    const notes = [...guard.problems, ...guard.partial, ...unchecked];
    const collect = guard.problems.length > 0 ? ` The picture is incomplete until a human collects: ${guard.collect}` : "";
    return finding(number, severity, "fail", notes.length > 0 ? `${computed.summary} Additional sources were unreadable or partial: ${notes.join("; ")}.${collect}` : computed.summary, {
      ...evidence,
      ...(guard.problems.length > 0 ? { manual_evidence: guard.collect } : {}),
    });
  }
  if (guard.problems.length > 0) {
    return manualFinding(
      number,
      severity,
      `Verdict is unknown because required evidence could not be read: ${guard.problems.join("; ")}. Observed from readable sources: ${computed.summary}`,
      guard.collect,
      evidence,
    );
  }
  if (guard.partial.length > 0 || unchecked.length > 0) {
    const reasons = [
      ...(guard.partial.length > 0 ? [`the inventory is partial: ${guard.partial.join("; ")}`] : []),
      ...(unchecked.length > 0 ? [`these inventories were not checked because they could not be read: ${unchecked.join("; ")}`] : []),
    ];
    return finding(
      number,
      severity,
      computed.status === "manual" ? "manual" : "warn",
      `${computed.summary} Verdict is capped at warn because ${reasons.join(", and ")}.`,
      evidence,
    );
  }
  return finding(number, severity, computed.status, computed.summary, evidence);
}

/** Lists the unreadable datasets among the supplied secondaries so a finding can name what it did not check. */
function uncheckedSources(snapshot: ElasticSnapshot, names: ElasticDatasetName[]): string[] {
  return dependencyProblems(snapshot, names);
}

function datasetReadable(snapshot: ElasticSnapshot, name: ElasticDatasetName): boolean {
  const dataset = snapshot[name];
  return Boolean(dataset && dataset.error === undefined && dataset.skipped === undefined);
}

/** True only when the dataset was read and its pagination (if any) ran to completion. */
function datasetComplete(snapshot: ElasticSnapshot, name: ElasticDatasetName): boolean {
  return datasetReadable(snapshot, name) && datasetPage(snapshot, name)?.truncated !== true;
}

/** Renders a value only when the inventory it derives from was read; otherwise null so unread never looks like zero or empty. */
function whenRead<T>(readable: boolean, value: T): T | null {
  return readable ? value : null;
}

/** Renders a count from an inventory that was read; unread inventories render null rather than 0. */
function countWhenRead(readable: boolean, count: number): number | null {
  return readable ? count : null;
}

/**
 * The count of records observed in an inventory: a positive count is a real observation and renders (a lower bound
 * while the listing stopped short, which the inventory state beside it records); zero is asserted only from a listing
 * read to completion and renders null from a read that stopped or failed, so an absence is never derived from a
 * partial inventory.
 */
function observedCount(complete: boolean, count: number): number | null {
  return count > 0 || complete ? count : null;
}

/**
 * Renders a list of named principals (users, keys, roles, policies) only when
 * the inventory proving the property was read completely; denied or partial
 * sets render null so no principal is asserted as violating or compliant
 * from data that was not fully seen.
 */
function principalsWhenComplete<T>(complete: boolean, items: T[], cap = 25): T[] | null {
  return complete ? items.slice(0, cap) : null;
}

/**
 * Describes what an inventory contributed: read completely, read partially, or not read at all.
 * `extraPartial` is `true` when a source outside pagination proves the view partial (a single-node
 * view, a credential that only sees its own keys) and `null` when that could not be determined, in
 * which case `complete` renders null rather than defaulting to true.
 */
function inventoryState(snapshot: ElasticSnapshot, name: ElasticDatasetName, seen: number | undefined, extraPartial: boolean | null = false): JsonRecord {
  const readable = datasetReadable(snapshot, name);
  const page = datasetPage(snapshot, name);
  const complete = !readable || page?.truncated === true || extraPartial === true ? false : extraPartial === null ? null : true;
  return {
    dataset: name,
    endpoint: snapshot[name]?.skipped ? null : DATASET_SPECS[name].endpoint,
    read: readable,
    complete,
    seen: readable ? seen ?? page?.seen ?? null : null,
    total: readable ? page?.total ?? seen ?? null : null,
    status: readable ? "readable" : snapshot[name]?.skipped ? "not_configured" : "not_readable",
  };
}

function nodeInventoryNotes(nodeSettings: JsonRecord | undefined): string[] {
  const header = asObject(nodeSettings?._nodes);
  if (!header) return [];
  const total = asNumber(header.total);
  const successful = asNumber(header.successful);
  const failed = asNumber(header.failed) ?? 0;
  if ((total !== undefined && successful !== undefined && successful < total) || failed > 0) {
    return [`node_settings covers ${successful ?? "?"} of ${total ?? "?"} nodes (${failed} failed to respond)`];
  }
  return [];
}

function licenseState(license: JsonRecord | undefined): { type?: string; status?: string; rank?: number; active?: boolean } {
  const info = asObject(license?.license);
  const type = asString(info?.type)?.toLowerCase();
  const status = asString(info?.status)?.toLowerCase();
  const rank = type ? LICENSE_RANK[type] : undefined;
  return { type, status, rank, active: status === undefined ? undefined : ACTIVE_LICENSE_STATUSES.has(status) };
}

function licenseSupports(state: ReturnType<typeof licenseState>, requiredRank: number): boolean | undefined {
  if (state.rank === undefined || state.active === undefined) return undefined;
  return state.active && state.rank >= requiredRank;
}

function flattenSettings(value: unknown, prefix = "", output: JsonRecord = {}): JsonRecord {
  const object = asObject(value);
  if (!object) return output;
  for (const [key, entry] of Object.entries(object)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    const nested = asObject(entry);
    if (nested && Object.keys(nested).length > 0) {
      flattenSettings(nested, fullKey, output);
    } else {
      output[fullKey] = entry;
    }
  }
  return output;
}

interface NodeSettingsEntry {
  id: string;
  name: string;
  version?: string;
  settings: JsonRecord;
}

interface SettingsView {
  available: boolean;
  nodes: NodeSettingsEntry[];
  persistent: JsonRecord;
  transient: JsonRecord;
  defaults: JsonRecord;
  get(key: string): unknown;
  perNode(key: string): Array<{ node: string; value: unknown }>;
  keys(): string[];
}

function buildSettingsView(nodeSettings: JsonRecord | undefined, clusterSettings: JsonRecord | undefined): SettingsView {
  const nodes: NodeSettingsEntry[] = Object.entries(asObject(nodeSettings?.nodes) ?? {}).map(([id, entry]) => {
    const node = asObject(entry) ?? {};
    return {
      id,
      name: asString(node.name) ?? id,
      version: asString(node.version),
      settings: flattenSettings(node.settings),
    };
  });
  const persistent = flattenSettings(clusterSettings?.persistent);
  const transient = flattenSettings(clusterSettings?.transient);
  const defaults = flattenSettings(clusterSettings?.defaults);
  const available = nodes.length > 0 || Object.keys(persistent).length + Object.keys(transient).length + Object.keys(defaults).length > 0;

  return {
    available,
    nodes,
    persistent,
    transient,
    defaults,
    get(key: string): unknown {
      if (transient[key] !== undefined) return transient[key];
      if (persistent[key] !== undefined) return persistent[key];
      for (const node of nodes) {
        if (node.settings[key] !== undefined) return node.settings[key];
      }
      return defaults[key];
    },
    perNode(key: string) {
      return nodes.map((node) => ({ node: node.name, value: node.settings[key] }));
    },
    keys(): string[] {
      const keys = new Set<string>();
      for (const node of nodes) for (const key of Object.keys(node.settings)) keys.add(key);
      for (const key of Object.keys(persistent)) keys.add(key);
      for (const key of Object.keys(transient)) keys.add(key);
      return [...keys];
    },
  };
}

interface RealmInfo {
  type: string;
  name: string;
  enabled: boolean;
  order?: number;
  settings: JsonRecord;
}

function parseRealms(view: SettingsView): RealmInfo[] {
  const realms = new Map<string, RealmInfo>();
  const pattern = /^xpack\.security\.authc\.realms\.([a-z_]+)\.([^.]+)\.(.+)$/;
  for (const key of view.keys()) {
    const match = pattern.exec(key);
    if (!match) continue;
    const [, type, name, setting] = match;
    const id = `${type}.${name}`;
    const realm = realms.get(id) ?? { type, name, enabled: true, settings: {} };
    realm.settings[setting] = view.get(key);
    if (setting === "enabled") realm.enabled = asBoolean(view.get(key)) !== false;
    if (setting === "order") realm.order = asNumber(view.get(key));
    realms.set(id, realm);
  }
  return [...realms.values()].sort((left, right) => (left.order ?? 999) - (right.order ?? 999));
}

function usageRealmTypes(usage: JsonRecord | undefined): string[] {
  const realms = asObject(getNestedValue(usage, ["security", "realms"])) ?? {};
  return Object.entries(realms)
    .filter(([, entry]) => asBoolean(asObject(entry)?.enabled) === true && asBoolean(asObject(entry)?.available) !== false)
    .map(([type]) => type);
}

function usageFlag(usage: JsonRecord | undefined, path: string[]): boolean | undefined {
  return asBoolean(getNestedValue(usage, ["security", ...path]));
}

function securityEnabledState(view: SettingsView, usage: JsonRecord | undefined, xpackInfo?: JsonRecord): { enabled: boolean | undefined; disabledNodes: string[]; source: string } {
  const disabledNodes = view.perNode("xpack.security.enabled").filter((entry) => asBoolean(entry.value) === false).map((entry) => entry.node);
  const fromSettings = asBoolean(view.get("xpack.security.enabled"));
  if (disabledNodes.length > 0) return { enabled: false, disabledNodes, source: "node settings" };
  if (fromSettings !== undefined) return { enabled: fromSettings, disabledNodes, source: "cluster or node settings" };
  const fromUsage = usageFlag(usage, ["enabled"]);
  if (fromUsage !== undefined) return { enabled: fromUsage, disabledNodes, source: "usage statistics" };
  const fromInfo = asBoolean(getNestedValue(xpackInfo, ["features", "security", "enabled"]));
  return { enabled: fromInfo, disabledNodes, source: fromInfo === undefined ? "not visible" : "xpack info" };
}

function settingsDependencyProblems(snapshot: ElasticSnapshot, view: SettingsView): string[] {
  const problems = dependencyProblems(snapshot, ["node_settings", "cluster_settings"]);
  if (problems.length === 0 && view.nodes.length === 0) {
    problems.push(`node_settings (${DATASET_SPECS.node_settings.endpoint}) returned no nodes, so per-node settings could not be verified`);
  }
  return problems;
}

function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function patternsOverlap(left: string, right: string): boolean {
  return wildcardToRegExp(left).test(right) || wildcardToRegExp(right).test(left);
}

function controlDefinition(number: number): ElasticControlDefinition {
  const control = ELASTIC_CONTROLS.find((item) => item.number === number);
  if (!control) throw new Error(`Unknown Elastic control ${number}`);
  return control;
}

function finding(
  number: number,
  severity: ElasticFinding["severity"],
  status: ElasticFinding["status"],
  summary: string,
  evidence?: JsonRecord,
): ElasticFinding {
  const control = controlDefinition(number);
  return {
    id: control.id,
    title: control.title,
    severity,
    status,
    summary,
    evidence: { spec_control: control.number, ...(evidence ?? {}) },
    mappings: [...control.mappings],
  };
}

function manualFinding(
  number: number,
  severity: ElasticFinding["severity"],
  reason: string,
  collect: string,
  evidence?: JsonRecord,
): ElasticFinding {
  return finding(number, severity, "manual", `${reason} Collect manually: ${collect}`, { ...(evidence ?? {}), manual_evidence: collect });
}

function isoDate(value: unknown): string | undefined {
  const millis = asNumber(value);
  if (millis !== undefined) return new Date(millis).toISOString();
  const text = asString(value);
  if (!text) return undefined;
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}

function daysBetween(fromMillis: number, toMillis: number): number {
  return Math.floor((toMillis - fromMillis) / 86_400_000);
}

function roleIsReserved(role: JsonRecord): boolean {
  return asBoolean(getNestedValue(role, ["metadata", "_reserved"])) === true;
}

function descriptorGrantsClusterAll(descriptor: JsonRecord): boolean {
  return asStringList(descriptor.cluster).some((privilege) => privilege === "all");
}

function descriptorGrantsWildcardIndexAll(descriptor: JsonRecord): boolean {
  return asObjectArray(descriptor.indices).some((entry) =>
    asStringList(entry.names).some((name) => name === "*" || name === "*,-.*")
    && asStringList(entry.privileges).some((privilege) => privilege === "all"),
  );
}

function descriptorIsSuperuserEquivalent(descriptor: JsonRecord): boolean {
  return descriptorGrantsClusterAll(descriptor) && descriptorGrantsWildcardIndexAll(descriptor);
}

function apiKeyIsFleetManaged(key: JsonRecord): boolean {
  const metadata = asObject(key.metadata) ?? {};
  return asString(metadata.managed_by) === "fleet" || asBoolean(metadata.managed) === true;
}

function apiKeySample(key: JsonRecord, extra: JsonRecord = {}): JsonRecord {
  return {
    id: asString(key.id),
    name: asString(key.name),
    username: asString(key.username),
    realm: asString(key.realm),
    creation: isoDate(key.creation),
    expiration: isoDate(key.expiration),
    fleet_managed: apiKeyIsFleetManaged(key),
    ...extra,
  };
}

function roleMappingReferencesRealm(mapping: JsonRecord, realm: RealmInfo): boolean {
  const rules = JSON.stringify(mapping.rules ?? {});
  return rules.includes(`"realm.name":"${realm.name}"`)
    || rules.includes(`"realm.type":"${realm.type}"`)
    || rules.includes(`"realm.name":"${realm.name.toLowerCase()}"`);
}

export function evaluateElasticIdentity(
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  now: number = Date.now(),
): ElasticAssessmentResult {
  const maxApiKeyAgeDays = clampNumber(options.maxApiKeyAgeDays, DEFAULT_MAX_API_KEY_AGE_DAYS, 1, 3650);
  const nodeSettings = datasetData<JsonRecord>(snapshot, "node_settings");
  const view = buildSettingsView(nodeSettings, datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const licenseData = datasetData<JsonRecord>(snapshot, "license");
  const license = licenseState(licenseData);
  const privileges = datasetData<JsonRecord>(snapshot, "privileges");
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const roleMappings = datasetData<JsonRecord>(snapshot, "role_mappings");
  const apiKeys = datasetData<JsonRecord[]>(snapshot, "api_keys");
  const findings: ElasticFinding[] = [];
  const settingsProblems = settingsDependencyProblems(snapshot, view);
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const security = securityEnabledState(view, usage);
  const settingsReadable = settingsProblems.length === 0;
  const usageReadable = usage !== undefined;
  const usageUnchecked = uncheckedSources(snapshot, ["xpack_usage"]);
  const rolesReadable = roles !== undefined;
  const roleMappingsReadable = roleMappings !== undefined;

  const allRealms = parseRealms(view);
  const realms = allRealms.filter((realm) => realm.enabled);
  const usageTypes = usageRealmTypes(usage);
  const realmTypes = new Set(realms.map((realm) => realm.type));
  const secureRealmTypes = [...realmTypes].filter((type) => SECURE_REALM_TYPES.has(type));
  const realmEvidence = allRealms.map((realm) => ({ type: realm.type, name: realm.name, order: realm.order ?? null, enabled: realm.enabled }));
  const realmCollect = "the xpack.security.authc.realms.* section of elasticsearch.yml from every node (including order and enabled flags), or the Elastic Cloud deployment security settings page.";
  const usageTypesLabel = usageReadable ? (usageTypes.join(", ") || "none enabled") : "unread";

  findings.push(guardedFinding(1, "high", {
    status: security.enabled === false
      ? "fail"
      : !settingsReadable
        ? "manual"
        : secureRealmTypes.length === 0
          ? "fail"
          : security.enabled === undefined
            ? "warn"
            : "pass",
    summary: security.enabled === false
      ? `xpack.security.enabled is false${security.disabledNodes.length > 0 ? ` on ${security.disabledNodes.join(", ")}` : ""}, so no authentication realm is enforced.`
      : !settingsReadable
        ? `realm settings were not readable (usage statistics report realm types: ${usageTypesLabel}).`
        : secureRealmTypes.length === 0
          ? `Only native/file style realms are enabled (${[...realmTypes].join(", ") || "none configured, so the implicit native and file realms apply"}); no LDAP, Active Directory, PKI, SAML, Kerberos, OIDC, or JWT realm is enabled.`
          : security.enabled === undefined
          ? `Secure realms are enabled (${secureRealmTypes.join(", ")}) but xpack.security.enabled was not visible in settings or usage statistics, so enforcement could not be confirmed.`
          : `Secure authentication realms are enabled beyond native/file: ${secureRealmTypes.join(", ")} (xpack.security.enabled confirmed true${usageReadable ? "; usage statistics agree" : ""}).`,
    evidence: {
      realms: whenRead(settingsReadable, realmEvidence),
      usage_realm_types: whenRead(usageReadable, usageTypes),
      secure_realm_types: whenRead(settingsReadable, secureRealmTypes),
      security_enabled: security.enabled ?? null,
      security_enabled_source: security.source,
    },
  }, { problems: settingsProblems, partial: nodeNotes, unchecked: usageUnchecked, collect: realmCollect }));

  const ssoRealms = realms.filter((realm) => SSO_REALM_TYPES.has(realm.type));
  const usageSso = usageTypes.filter((type) => SSO_REALM_TYPES.has(type));
  const ssoCollect = "the SAML or OIDC realm settings (attributes.principal, attributes.groups, claims.principal, claims.groups, authorization_realms), the role mappings that assign roles to SSO users (GET /_security/role_mapping), and the identity provider integration evidence.";
  if (!settingsReadable) {
    findings.push(manualFinding(13, "medium", `SSO realm settings could not be read: ${settingsProblems.join("; ")}.`, ssoCollect, {
      sso_realms: null,
      usage_sso_realm_types: whenRead(usageReadable, usageSso),
      role_mapping_count: countWhenRead(roleMappingsReadable, Object.keys(roleMappings ?? {}).length),
      unreadable_sources: settingsProblems,
      partial_sources: nodeNotes,
      unchecked_sources: usageUnchecked,
    }));
  } else if (ssoRealms.length === 0) {
    findings.push(manualFinding(
      13,
      "medium",
      usageSso.length > 0
        ? `Not applicable from settings: no enabled SAML or OIDC realm is configured on the inspected nodes, although usage statistics report ${usageSso.join(", ")} realms.`
        : usageReadable
          ? "Not applicable: no SAML or OIDC realm is enabled, so SSO attribute mapping and role assignment are scoped out of the API assessment."
          : `Not applicable from settings: no SAML or OIDC realm is enabled on the inspected nodes; usage statistics could not be read to cross-check (${usageUnchecked.join("; ")}).`,
      "confirmation that SSO is not required for this cluster, or the identity provider integration evidence if SSO is delivered outside Elasticsearch realms (for example Elastic Cloud SSO).",
      { sso_realms: [], usage_sso_realm_types: whenRead(usageReadable, usageSso), realms: realmEvidence, unreadable_sources: [], partial_sources: nodeNotes, unchecked_sources: usageUnchecked },
    ));
  } else {
    const mappingEntries = Object.entries(roleMappings ?? {}).map(([name, value]) => ({ name, mapping: asObject(value) ?? {} }));
    const ssoEvidence = ssoRealms.map((realm) => {
      const principal = asString(realm.settings["attributes.principal"]) ?? asString(realm.settings["claims.principal"]);
      const groups = asString(realm.settings["attributes.groups"]) ?? asString(realm.settings["claims.groups"]);
      const authorizationRealms = asStringList(realm.settings.authorization_realms);
      const mappings = mappingEntries
        .filter(({ mapping }) => asBoolean(mapping.enabled) !== false && roleMappingReferencesRealm(mapping, realm))
        .map(({ name }) => name);
      return {
        type: realm.type,
        name: realm.name,
        order: realm.order ?? null,
        principal_attribute: principal ?? null,
        groups_attribute: groups ?? null,
        authorization_realms: authorizationRealms,
        role_mappings: whenRead(roleMappingsReadable, mappings),
        has_role_assignment: roleMappingsReadable ? mappings.length > 0 || authorizationRealms.length > 0 : authorizationRealms.length > 0 ? true : null,
      };
    });
    const missingPrincipal = ssoEvidence.filter((entry) => !entry.principal_attribute);
    const withoutRoles = roleMappingsReadable ? ssoEvidence.filter((entry) => entry.has_role_assignment === false) : [];
    const ssoLicense = licenseSupports(license, LICENSE_RANK.platinum);
    const ssoProblems = [...dependencyProblems(snapshot, ["role_mappings", "license"])];
    findings.push(guardedFinding(13, "medium", {
      status: ssoLicense === false || missingPrincipal.length > 0 || withoutRoles.length > 0 || security.enabled === false
        ? "fail"
        : ssoLicense === undefined || security.enabled === undefined
          ? "warn"
          : "pass",
      summary: ssoLicense === false
        ? `${ssoRealms.length} SSO realm(s) are configured but the ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include SAML/OIDC single sign-on, so SSO is not functional.`
        : security.enabled === false
          ? "xpack.security.enabled is false, so SSO realms are not enforced."
          : withoutRoles.length > 0
            ? `${withoutRoles.length}/${ssoRealms.length} SSO realm(s) have zero enabled role mappings and no authorization_realms (${withoutRoles.map((entry) => `${entry.type}.${entry.name}`).join(", ")}); an SSO realm with no role assignment fails this control (mappings read: ${mappingEntries.length}).`
            : missingPrincipal.length > 0
              ? `${missingPrincipal.length}/${ssoRealms.length} SSO realm(s) lack a principal attribute or claim: ${missingPrincipal.map((entry) => `${entry.type}.${entry.name}`).join(", ")}.`
              : ssoLicense === undefined || security.enabled === undefined
                ? `${ssoRealms.length} SSO realm(s) define a principal attribute and role assignment, but ${ssoLicense === undefined ? `the license tier (${license.type ?? "unread"}, status ${license.status ?? "unread"}) could not be confirmed to include SSO` : "xpack.security.enabled was not visible"}, so enforcement is unconfirmed.`
                : `${ssoRealms.length} SSO realm(s) define a principal attribute and have enabled role mappings or authorization realms assigning roles (${mappingEntries.length} role mappings read; ${license.type} license supports SSO).`,
      evidence: {
        sso_realms: ssoEvidence,
        role_mapping_count: countWhenRead(roleMappingsReadable, mappingEntries.length),
        license_supports_sso: ssoLicense ?? null,
        security_enabled: security.enabled ?? null,
      },
    }, { problems: ssoProblems, partial: nodeNotes, collect: ssoCollect }));
  }

  const anonymousRoles = asStringList(view.get("xpack.security.authc.anonymous.roles"));
  const anonymousUsername = asString(view.get("xpack.security.authc.anonymous.username"));
  const anonymousAuthzException = asBoolean(view.get("xpack.security.authc.anonymous.authz_exception"));
  const usageAnonymous = usageFlag(usage, ["anonymous", "enabled"]);
  const anonymousEnabled = anonymousRoles.length > 0 || usageAnonymous === true;
  const anonymousRoleDescriptors = rolesReadable ? anonymousRoles.map((name) => asObject(roles?.[name]) ?? {}) : [];
  const broadAnonymous = anonymousRoles.includes("superuser")
    || anonymousRoleDescriptors.some((descriptor) => descriptorGrantsClusterAll(descriptor) || descriptorGrantsWildcardIndexAll(descriptor));
  const anonymousRoleProblems = anonymousRoles.length > 0 && !rolesReadable ? dependencyProblems(snapshot, ["roles"]) : [];
  findings.push(guardedFinding(14, "high", {
    status: security.enabled === false || broadAnonymous
      ? "fail"
      : anonymousEnabled || security.enabled === undefined
        ? "warn"
        : "pass",
    summary: security.enabled === false
      ? "xpack.security.enabled is false, so every request is effectively anonymous with full access."
      : broadAnonymous
        ? `Anonymous access is enabled with broad roles: ${anonymousRoles.join(", ")}.`
        : anonymousEnabled
          ? `Anonymous access is enabled with roles ${anonymousRoles.join(", ") || "(reported by usage statistics only)"}; confirm they only permit non-sensitive operations.`
          : security.enabled === undefined
            ? "No xpack.security.authc.anonymous.roles are configured, but xpack.security.enabled was not visible, so anonymous access could not be confirmed disabled."
            : `Anonymous access is disabled: xpack.security.authc.anonymous.roles is unset on every inspected node and xpack.security.enabled is true${usageReadable ? " (usage statistics agree that anonymous access is disabled)" : ""}; absence of anonymous roles is the compliant state for this control.`,
    evidence: {
      anonymous_enabled: whenRead(settingsReadable || usageAnonymous !== undefined, anonymousEnabled),
      anonymous_roles: whenRead(settingsReadable, anonymousRoles),
      anonymous_roles_grant_broad_access: settingsReadable && (anonymousRoles.length === 0 || rolesReadable) ? broadAnonymous : null,
      anonymous_username: anonymousUsername ?? null,
      anonymous_authz_exception: anonymousAuthzException ?? null,
      usage_anonymous_enabled: usageAnonymous ?? null,
      security_enabled: security.enabled ?? null,
    },
  }, {
    problems: [...settingsProblems, ...anonymousRoleProblems],
    partial: nodeNotes,
    unchecked: usageUnchecked,
    collect: "the xpack.security.authc.anonymous.* settings and xpack.security.enabled from elasticsearch.yml on every node, plus the role definitions of any anonymous roles (GET /_security/role).",
  }));

  const apiKeyPage = datasetPage(snapshot, "api_keys");
  const apiKeysReadable = apiKeys !== undefined;
  const apiKeyVisibility = apiKeyInventoryVisibility(privileges);
  const apiKeyProblems = dependencyProblems(snapshot, ["api_keys", "privileges"]);
  const apiKeyPartial = [
    ...truncationNotes(snapshot, ["api_keys"]),
    ...(apiKeyVisibility === false
      ? [`the credential lacks read_security, manage_api_key, and manage_security, so POST /_security/_query/api_key returns only its own keys (${apiKeys?.length ?? "an unknown number of"} seen of an unknown total)`]
      : []),
  ];
  const apiKeysComplete = apiKeysReadable && apiKeyProblems.length === 0 && apiKeyPartial.length === 0;
  // Completeness is known false when pagination or visibility proved the view partial, unknown (null)
  // when the visibility probe could not be read, and true only when both were observed.
  const apiKeysCompleteness: boolean | null = !apiKeysReadable ? null : apiKeyPartial.length > 0 ? false : apiKeyVisibility === undefined ? null : true;
  const apiKeyInventory = inventoryState(snapshot, "api_keys", apiKeys?.length, apiKeyVisibility === undefined ? null : apiKeyVisibility === false);
  const keyInventoryLabel = apiKeysReadable
    ? `${apiKeys.length} key(s) seen${apiKeyPage?.total !== undefined ? ` of ${apiKeyPage.total} total` : ""}`
    : "api_keys unread";
  const keys = apiKeys ?? [];
  const active = keys.filter((key) => asBoolean(key.invalidated) !== true && (asNumber(key.expiration) === undefined || (asNumber(key.expiration) ?? 0) > now));
  const invalidated = keys.filter((key) => asBoolean(key.invalidated) === true);
  const expired = keys.filter((key) => asBoolean(key.invalidated) !== true && asNumber(key.expiration) !== undefined && (asNumber(key.expiration) ?? 0) <= now);
  const withoutExpiration = active.filter((key) => asNumber(key.expiration) === undefined);
  const missingCreation = active.filter((key) => asNumber(key.creation) === undefined);
  const stale = active.filter((key) => {
    const creation = asNumber(key.creation);
    return creation !== undefined && daysBetween(creation, now) > maxApiKeyAgeDays;
  });
  const unmanagedWithoutExpiration = withoutExpiration.filter((key) => !apiKeyIsFleetManaged(key));
  const unmanagedStale = stale.filter((key) => !apiKeyIsFleetManaged(key));
  const fleetIssues = withoutExpiration.length + stale.length - unmanagedWithoutExpiration.length - unmanagedStale.length;
  const hygieneStatus: ElasticFinding["status"] = unmanagedWithoutExpiration.length > 0 || unmanagedStale.length > 0
    ? "fail"
    : fleetIssues > 0 || invalidated.length > 0 || expired.length > 0 || missingCreation.length > 0
      ? "warn"
      : "pass";
  const partialKeyLabel = `the api_keys inventory was not fully read (${keyInventoryLabel}), so violators are neither counted nor named`;
  findings.push(guardedFinding(9, "high", {
    status: hygieneStatus,
    summary: !apiKeysComplete
      ? hygieneStatus === "fail"
        ? `Among the API keys that were read, at least one active non-Fleet key has no expiration or is older than ${maxApiKeyAgeDays} days; ${partialKeyLabel}.`
        : hygieneStatus === "warn"
          ? `Among the API keys that were read, Fleet-managed keys lack expiration or exceed ${maxApiKeyAgeDays} days, keys report no creation date, or inactive keys linger; ${partialKeyLabel}.`
          : `No hygiene violation was observed among the API keys that were read, but ${partialKeyLabel}.`
      : hygieneStatus === "fail"
        ? `${unmanagedWithoutExpiration.length} active non-Fleet API key(s) have no expiration and ${unmanagedStale.length} are older than ${maxApiKeyAgeDays} days (${active.length} active, ${keyInventoryLabel}).`
        : hygieneStatus === "warn"
          ? `${fleetIssues} Fleet-managed key(s) lack expiration or exceed ${maxApiKeyAgeDays} days, ${missingCreation.length} active key(s) report no creation date and are not counted as fresh, and ${invalidated.length} invalidated plus ${expired.length} expired keys still linger (${active.length} active, ${keyInventoryLabel}).`
          : keys.length === 0
            ? `No API keys exist (${keyInventoryLabel} with full inventory visibility). This control concerns existing keys, so an empty inventory is compliant.`
            : `All ${active.length} active API keys carry an expiration, are newer than ${maxApiKeyAgeDays} days, report creation dates, and no inactive keys linger (${keyInventoryLabel}).`,
    evidence: {
      inventory: apiKeyInventory,
      inspected: countWhenRead(apiKeysComplete, keys.length),
      total_reported: whenRead(apiKeysReadable, apiKeyPage?.total ?? null),
      active: countWhenRead(apiKeysComplete, active.length),
      invalidated: countWhenRead(apiKeysComplete, invalidated.length),
      expired: countWhenRead(apiKeysComplete, expired.length),
      without_expiration: countWhenRead(apiKeysComplete, withoutExpiration.length),
      missing_creation_date: principalsWhenComplete(apiKeysComplete, missingCreation.map((key) => apiKeySample(key))),
      older_than_max_age: countWhenRead(apiKeysComplete, stale.length),
      max_api_key_age_days: maxApiKeyAgeDays,
      full_visibility: apiKeyVisibility ?? null,
      violation_observed: apiKeysReadable ? hygieneStatus !== "pass" : null,
      flagged: principalsWhenComplete(
        apiKeysComplete,
        [...unmanagedWithoutExpiration, ...unmanagedStale.filter((key) => !unmanagedWithoutExpiration.includes(key))]
          .map((key) => apiKeySample(key, { age_days: asNumber(key.creation) === undefined ? null : daysBetween(asNumber(key.creation) ?? now, now) })),
      ),
    },
  }, {
    problems: apiKeyProblems,
    partial: apiKeyPartial,
    collect: "the output of POST /_security/_query/api_key run by a principal with read_security or manage_api_key (all pages), and the API key rotation records.",
  }));

  const privileged: JsonRecord[] = [];
  let unverifiable = 0;
  for (const key of active) {
    const descriptors = Object.values(asObject(key.role_descriptors) ?? {}).map((item) => asObject(item) ?? {});
    if (descriptors.length === 0) {
      const limitedBy = asObjectArray(key.limited_by).flatMap((entry) => Object.entries(entry));
      if (limitedBy.length === 0) {
        unverifiable += 1;
        continue;
      }
      const inheritsSuperuser = limitedBy.some(([name, descriptor]) => name === "superuser" || descriptorIsSuperuserEquivalent(asObject(descriptor) ?? {}));
      if (inheritsSuperuser) privileged.push(apiKeySample(key, { reason: "inherits superuser-equivalent owner privileges", limited_by_roles: limitedBy.map(([name]) => name) }));
      continue;
    }
    if (descriptors.some(descriptorIsSuperuserEquivalent)) {
      privileged.push(apiKeySample(key, { reason: "role_descriptors grant cluster all and index all on *" }));
    } else if (descriptors.some(descriptorGrantsClusterAll)) {
      privileged.push(apiKeySample(key, { reason: "role_descriptors grant cluster all" }));
    }
  }
  const scopeStatus: ElasticFinding["status"] = privileged.length > 0 ? "fail" : unverifiable > 0 ? "warn" : "pass";
  findings.push(guardedFinding(10, "high", {
    status: scopeStatus,
    summary: !apiKeysComplete
      ? scopeStatus === "fail"
        ? `Among the API keys that were read, at least one active key carries superuser-equivalent or cluster-wide privileges; ${partialKeyLabel}.`
        : scopeStatus === "warn"
          ? `Among the API keys that were read, some active keys inherit owner privileges without a visible limited_by section (requires manage_api_key); ${partialKeyLabel}.`
          : `No over-privileged key was observed among the API keys that were read, but ${partialKeyLabel}.`
      : privileged.length > 0
        ? `${privileged.length}/${active.length} active API keys carry superuser-equivalent or cluster-wide privileges (${keyInventoryLabel}).`
        : unverifiable > 0
          ? `${unverifiable}/${active.length} active API keys inherit owner privileges but limited_by was not visible (requires manage_api_key), so their scope could not be verified.`
          : active.length === 0
            ? `No active API keys exist (${keyInventoryLabel} with full inventory visibility). This control concerns existing keys, so an empty inventory is compliant.`
            : `All ${active.length} active API keys are scoped below superuser-equivalent privileges (${keyInventoryLabel}).`,
    evidence: {
      inventory: apiKeyInventory,
      active: countWhenRead(apiKeysComplete, active.length),
      inspected: countWhenRead(apiKeysComplete, keys.length),
      total_reported: whenRead(apiKeysReadable, apiKeyPage?.total ?? null),
      privileged: principalsWhenComplete(apiKeysComplete, privileged),
      unverifiable: countWhenRead(apiKeysComplete, unverifiable),
      full_visibility: apiKeyVisibility ?? null,
      violation_observed: apiKeysReadable ? scopeStatus === "fail" : null,
    },
  }, {
    problems: apiKeyProblems,
    partial: apiKeyPartial,
    collect: "the role_descriptors and limited_by sections of every active API key (POST /_security/_query/api_key?with_limited_by=true, all pages, run with manage_api_key).",
  }));

  return {
    area: "identity",
    title: "Elastic identity and authentication",
    summary: {
      realm_types: whenRead(settingsReadable, [...realmTypes]),
      secure_realm_types: whenRead(settingsReadable, secureRealmTypes),
      security_enabled: security.enabled ?? null,
      anonymous_roles: whenRead(settingsReadable, anonymousRoles),
      api_keys_inspected: countWhenRead(apiKeysReadable, apiKeys?.length ?? 0),
      api_keys_total: whenRead(apiKeysReadable, apiKeyPage?.total ?? null),
      api_keys_complete: apiKeysCompleteness,
      api_key_full_visibility: apiKeyVisibility ?? null,
      role_mappings: countWhenRead(roleMappingsReadable, Object.keys(roleMappings ?? {}).length),
      license_type: whenRead(licenseData !== undefined, license.type ?? null),
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
    not_collected: listSnapshotSkips(snapshot),
    truncated: listSnapshotTruncations(snapshot),
  };
}

function apiKeyInventoryVisibility(privileges: JsonRecord | undefined): boolean | undefined {
  const cluster = asObject(privileges?.cluster);
  if (!cluster) return undefined;
  const granted = (name: string) => asBoolean(cluster[name]) === true;
  if (granted("read_security") || granted("manage_api_key") || granted("manage_security") || granted("all")) return true;
  if (cluster.read_security === undefined && cluster.manage_api_key === undefined && cluster.manage_security === undefined) return undefined;
  return false;
}

interface RoleIndexEntry {
  role: string;
  names: string[];
  privileges: string[];
  fieldSecurity?: JsonRecord;
  query?: unknown;
}

function roleIndexEntries(roles: JsonRecord): RoleIndexEntry[] {
  const entries: RoleIndexEntry[] = [];
  for (const [role, value] of Object.entries(roles)) {
    for (const entry of asObjectArray(asObject(value)?.indices)) {
      entries.push({
        role,
        names: asStringList(entry.names),
        privileges: asStringList(entry.privileges),
        fieldSecurity: asObject(entry.field_security),
        query: entry.query,
      });
    }
  }
  return entries;
}

interface RoleFeatureUsage {
  native: boolean | undefined;
  file: boolean | undefined;
}

function roleFeatureUsage(usage: JsonRecord | undefined, feature: "fls" | "dls"): RoleFeatureUsage {
  return {
    native: asBoolean(getNestedValue(usage, ["security", "roles", "native", feature])),
    file: asBoolean(getNestedValue(usage, ["security", "roles", "file", feature])),
  };
}

interface IndexRestrictionSources {
  rolesReadable: boolean;
  usageReadable: boolean;
  licenseReadable: boolean;
  problems: string[];
  unchecked: string[];
}

function evaluateIndexRestriction(
  number: number,
  label: string,
  restricted: RoleIndexEntry[],
  patterns: string[],
  license: ReturnType<typeof licenseState>,
  usageInUse: RoleFeatureUsage,
  sources: IndexRestrictionSources,
): ElasticFinding {
  const supported = licenseSupports(license, LICENSE_RANK.platinum);
  const restrictedRoles = [...new Set(restricted.map((entry) => entry.role))];
  const evidence: JsonRecord = {
    roles_with_restriction: principalsWhenComplete(sources.rolesReadable, restricted.map((entry) => ({ role: entry.role, indices: entry.names })), 50),
    roles_with_restriction_count: countWhenRead(sources.rolesReadable, restrictedRoles.length),
    usage_reports_in_use: whenRead(sources.usageReadable, { native_roles: usageInUse.native ?? null, file_roles: usageInUse.file ?? null }),
    license_type: whenRead(sources.licenseReadable, license.type ?? null),
    license_status: whenRead(sources.licenseReadable, license.status ?? null),
    license_supports_feature: supported ?? null,
    patterns,
  };
  const collect = `the role definitions (GET /_security/role), the license (GET /_license), and the list of indices holding sensitive or tenant data, then confirm which roles apply ${label} to them.`;
  const guard: VerdictGuard = { problems: sources.problems, partial: [], unchecked: sources.unchecked, collect };
  if (sources.problems.length === 0 && supported === false) {
    if (patterns.length > 0) {
      return guardedFinding(number, "medium", {
        status: "fail",
        summary: `The ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include ${label}, so the ${patterns.length} supplied index pattern(s) cannot be protected by it.`,
        evidence: { ...evidence, uncovered_patterns: patterns },
      }, guard);
    }
    return manualFinding(
      number,
      "medium",
      `Not applicable on this license tier: the ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include ${label}, so it cannot be enforced on this cluster.`,
      `evidence of compensating controls (separate indices or clusters per sensitivity level) or confirmation that no index requires ${label}.`,
      { ...evidence, unreadable_sources: [], partial_sources: [], unchecked_sources: sources.unchecked },
    );
  }
  if (patterns.length > 0) {
    if (sources.problems.length > 0) {
      return guardedFinding(number, "medium", {
        status: "manual",
        summary: `coverage of the ${patterns.length} supplied index pattern(s) by ${label} could not be evaluated.`,
        evidence: { ...evidence, uncovered_patterns: null },
      }, guard);
    }
    const uncovered = patterns.filter((pattern) => !restricted.some((entry) => entry.names.some((name) => patternsOverlap(name, pattern))));
    return guardedFinding(number, "medium", {
      status: uncovered.length > 0 ? "fail" : supported === true ? "pass" : "warn",
      summary: uncovered.length > 0
        ? `${uncovered.length}/${patterns.length} supplied index patterns have no role applying ${label}: ${uncovered.join(", ")}.`
        : supported === true
          ? `Every supplied index pattern (${patterns.join(", ")}) is covered by at least one role applying ${label} (${license.type} license supports it).`
          : `Every supplied index pattern (${patterns.join(", ")}) is covered by a role applying ${label}, but the license tier (${license.type ?? "unread"}, status ${license.status ?? "unread"}) could not be confirmed to include it.`,
      evidence: { ...evidence, uncovered_patterns: uncovered },
    }, guard);
  }
  return guardedFinding(number, "medium", {
    status: "warn",
    summary: !sources.rolesReadable
      ? `the role inventory could not be read and no index patterns were supplied, so ${label} coverage is unknown.`
      : restrictedRoles.length > 0
        ? `${restrictedRoles.length} role(s) apply ${label} (${restrictedRoles.slice(0, 10).join(", ")}), but no index patterns were supplied, so coverage of the sensitive indices could not be verified.`
        : `No role applies ${label} and no index patterns were supplied; identify indices holding sensitive or tenant data and confirm whether ${label} is required.`,
    evidence,
  }, guard);
}

export function evaluateElasticAccessControl(
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
): ElasticAssessmentResult {
  const maxSuperusers = clampNumber(options.maxSuperusers, DEFAULT_MAX_SUPERUSERS, 0, 1000);
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const users = datasetData<JsonRecord>(snapshot, "users");
  const roleMappings = datasetData<JsonRecord>(snapshot, "role_mappings");
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const licenseData = datasetData<JsonRecord>(snapshot, "license");
  const license = licenseState(licenseData);
  const findings: ElasticFinding[] = [];

  const roleEntries = Object.entries(roles ?? {}).map(([name, value]) => ({ name, role: asObject(value) ?? {} }));
  const userEntries = Object.entries(users ?? {}).map(([name, value]) => ({ name, user: asObject(value) ?? {} }));
  const mappingEntries = Object.entries(roleMappings ?? {});
  const customRoles = roleEntries.filter(({ role }) => !roleIsReserved(role));
  const clusterAllRoles = customRoles.filter(({ role }) => descriptorGrantsClusterAll(role)).map(({ name }) => name);
  const wildcardIndexRoles = customRoles.filter(({ role }) => descriptorGrantsWildcardIndexAll(role)).map(({ name }) => name);
  const broadRoles = [...new Set([...clusterAllRoles, ...wildcardIndexRoles])];
  const superusers = userEntries
    .filter(({ user }) => asBoolean(user.enabled) !== false && asStringList(user.roles).includes("superuser"))
    .map(({ name }) => name);
  const usersWithBroadRoles = userEntries
    .filter(({ user }) => asBoolean(user.enabled) !== false && asStringList(user.roles).some((role) => broadRoles.includes(role)))
    .map(({ name }) => name);
  const superuserMappings = mappingEntries
    .filter(([, value]) => asBoolean(asObject(value)?.enabled) !== false && asStringList(asObject(value)?.roles).some((role) => role === "superuser" || broadRoles.includes(role)))
    .map(([name]) => name);
  const roleInventoryProblems = [
    ...dependencyProblems(snapshot, ["roles"]),
    ...[emptyInventoryProblem(snapshot, "roles", roles ? roleEntries.length : undefined, "built-in roles such as superuser are always returned")].filter((item): item is string => Boolean(item)),
  ];
  const userInventoryProblems = [
    ...dependencyProblems(snapshot, ["users"]),
    ...[emptyInventoryProblem(snapshot, "users", users ? userEntries.length : undefined, "built-in users such as elastic are always returned")].filter((item): item is string => Boolean(item)),
  ];
  const mappingProblems = dependencyProblems(snapshot, ["role_mappings"]);
  const rbacProblems = [...roleInventoryProblems, ...userInventoryProblems, ...mappingProblems];
  const rolesComplete = roleInventoryProblems.length === 0;
  const usersComplete = userInventoryProblems.length === 0;
  const mappingsComplete = mappingProblems.length === 0;
  // A user holds a broad role only if both the user list and the role definitions were read.
  const userRoleJoinComplete = rolesComplete && usersComplete;
  const mappingRoleJoinComplete = rolesComplete && mappingsComplete;

  const rbacStatus: ElasticFinding["status"] = (usersComplete && superusers.length > maxSuperusers) || (userRoleJoinComplete && usersWithBroadRoles.length > 0)
    ? "fail"
    : (rolesComplete && broadRoles.length > 0) || (mappingRoleJoinComplete && superuserMappings.length > 0)
      ? "warn"
      : "pass";
  findings.push(guardedFinding(6, "high", {
    status: rbacStatus,
    summary: rbacStatus === "fail"
      ? `${superusers.length} native users hold superuser (threshold ${maxSuperusers}) and ${usersWithBroadRoles.length} users hold custom roles granting cluster all or index all on *.`
      : rbacStatus === "warn"
        ? `${broadRoles.length} custom role(s) grant cluster all or wildcard index all and ${mappingRoleJoinComplete ? superuserMappings.length : "an unknown number of"} role mapping(s) assign superuser or broad roles; no native user currently exceeds the superuser threshold.`
        : rbacProblems.length > 0
          ? "the readable inventories show no superuser overuse or broad custom roles, but the RBAC picture is incomplete."
          : `${roleEntries.length} roles, ${userEntries.length} users, and ${mappingEntries.length} role mappings reviewed; ${superusers.length} superuser holder(s) within threshold ${maxSuperusers}, no custom role grants cluster all or wildcard index all, and no role mapping assigns broad roles.`,
    evidence: {
      inventories: [
        inventoryState(snapshot, "roles", roleEntries.length),
        inventoryState(snapshot, "users", userEntries.length),
        inventoryState(snapshot, "role_mappings", mappingEntries.length),
      ],
      roles_reviewed: countWhenRead(rolesComplete, roleEntries.length),
      custom_roles: countWhenRead(rolesComplete, customRoles.length),
      users_reviewed: countWhenRead(usersComplete, userEntries.length),
      role_mappings_reviewed: countWhenRead(mappingsComplete, mappingEntries.length),
      superusers: principalsWhenComplete(usersComplete, superusers),
      superuser_count: countWhenRead(usersComplete, superusers.length),
      max_superusers: maxSuperusers,
      cluster_all_roles: principalsWhenComplete(rolesComplete, clusterAllRoles),
      wildcard_index_all_roles: principalsWhenComplete(rolesComplete, wildcardIndexRoles),
      users_with_broad_roles: principalsWhenComplete(userRoleJoinComplete, usersWithBroadRoles),
      superuser_role_mappings: principalsWhenComplete(mappingRoleJoinComplete, superuserMappings),
    },
  }, {
    problems: rbacProblems,
    partial: [],
    collect: "the role definitions (GET /_security/role), user list (GET /_security/user), and role mappings (GET /_security/role_mapping), then identify superuser holders and roles granting cluster all or index all on *.",
  }));

  const indexEntries = roles ? roleIndexEntries(roles) : [];
  const usageReadable = usage !== undefined;
  const licenseReadable = licenseData !== undefined;
  const restrictionSources: IndexRestrictionSources = {
    rolesReadable: rolesComplete,
    usageReadable,
    licenseReadable,
    problems: [...roleInventoryProblems, ...dependencyProblems(snapshot, ["license"])],
    unchecked: uncheckedSources(snapshot, ["xpack_usage"]),
  };
  const flsEntries = indexEntries.filter((entry) => entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0);
  const dlsEntries = indexEntries.filter((entry) => entry.query !== undefined && entry.query !== null && entry.query !== "");
  findings.push(evaluateIndexRestriction(7, "field-level security", flsEntries, options.sensitiveIndexPatterns ?? [], license, roleFeatureUsage(usage, "fls"), restrictionSources));
  findings.push(evaluateIndexRestriction(8, "document-level security", dlsEntries, options.tenantIndexPatterns ?? [], license, roleFeatureUsage(usage, "dls"), restrictionSources));

  return {
    area: "access_control",
    title: "Elastic role-based access control",
    summary: {
      roles_reviewed: countWhenRead(rolesComplete, roleEntries.length),
      users_reviewed: countWhenRead(usersComplete, userEntries.length),
      role_mappings_reviewed: countWhenRead(mappingsComplete, mappingEntries.length),
      superusers: countWhenRead(usersComplete, superusers.length),
      broad_custom_roles: countWhenRead(rolesComplete, broadRoles.length),
      roles_with_fls: countWhenRead(rolesComplete, new Set(flsEntries.map((entry) => entry.role)).size),
      roles_with_dls: countWhenRead(rolesComplete, new Set(dlsEntries.map((entry) => entry.role)).size),
      license_type: whenRead(licenseReadable, license.type ?? null),
      license_status: whenRead(licenseReadable, license.status ?? null),
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
    not_collected: listSnapshotSkips(snapshot),
    truncated: listSnapshotTruncations(snapshot),
  };
}

function nodeMajorVersions(view: SettingsView): number[] {
  return [...new Set(view.nodes
    .map((node) => asNumber(node.version?.split(".")[0]))
    .filter((value): value is number => value !== undefined))];
}

function perNodeBooleans(view: SettingsView, key: string): Array<{ node: string; value: boolean | undefined }> {
  return view.perNode(key).map((entry) => ({ node: entry.node, value: asBoolean(entry.value) }));
}

const AUDIT_ENABLED_KEY = "xpack.security.audit.enabled";

interface AuditEnabledResolution {
  clusterLevel: boolean | undefined;
  clusterLevelSource: "transient" | "persistent" | undefined;
  perNode: Array<{ node: string; nodeValue: boolean | undefined; effective: boolean | undefined; source: string }>;
}

function resolveAuditEnabled(view: SettingsView): AuditEnabledResolution {
  const transient = asBoolean(view.transient[AUDIT_ENABLED_KEY]);
  const persistent = asBoolean(view.persistent[AUDIT_ENABLED_KEY]);
  const clusterLevel = transient ?? persistent;
  const clusterLevelSource = transient !== undefined ? "transient" : persistent !== undefined ? "persistent" : undefined;
  const defaultValue = asBoolean(view.defaults[AUDIT_ENABLED_KEY]);
  const perNode = perNodeBooleans(view, AUDIT_ENABLED_KEY).map((entry) => {
    if (clusterLevel !== undefined) {
      return { node: entry.node, nodeValue: entry.value, effective: clusterLevel, source: `${clusterLevelSource} cluster settings` };
    }
    if (entry.value !== undefined) {
      return { node: entry.node, nodeValue: entry.value, effective: entry.value, source: "node settings" };
    }
    return { node: entry.node, nodeValue: undefined, effective: defaultValue, source: defaultValue === undefined ? "unset" : "cluster defaults" };
  });
  return { clusterLevel, clusterLevelSource, perNode };
}

function evaluateTlsLayer(
  number: number,
  layer: "transport" | "http",
  view: SettingsView,
  usage: JsonRecord | undefined,
  security: ReturnType<typeof securityEnabledState>,
  elasticsearchUrl: string | undefined,
  guard: VerdictGuard,
): ElasticFinding {
  const key = `xpack.security.${layer}.ssl.enabled`;
  const settingsReadable = guard.problems.length === 0;
  const usageReadable = usage !== undefined;
  const perNode = perNodeBooleans(view, key);
  const usageEnabled = usageFlag(usage, ["ssl", layer, "enabled"]);
  const effective = asBoolean(view.get(key));
  const urlIsPlainHttp = layer === "http" && Boolean(elasticsearchUrl && elasticsearchUrl.startsWith("http://"));
  const disabledNodes = perNode.filter((entry) => entry.value === false).map((entry) => entry.node);
  const unsetNodes = perNode.filter((entry) => entry.value === undefined).map((entry) => entry.node);
  const enabledNodes = perNode.filter((entry) => entry.value === true).map((entry) => entry.node);
  const verificationModes = layer === "transport"
    ? view.perNode("xpack.security.transport.ssl.verification_mode").map((entry) => ({ node: entry.node, value: asString(entry.value) ?? "full (default)" }))
    : [];
  const noVerificationNodes = verificationModes.filter((entry) => entry.value === "none").map((entry) => entry.node);
  const evidence: JsonRecord = {
    setting: key,
    per_node: whenRead(settingsReadable, perNode.map((entry) => ({ node: entry.node, value: entry.value ?? null }))),
    enabled_nodes: whenRead(settingsReadable, enabledNodes),
    disabled_nodes: whenRead(settingsReadable, disabledNodes),
    unset_nodes: whenRead(settingsReadable, unsetNodes),
    effective_setting: effective ?? null,
    usage_reported_enabled: whenRead(usageReadable, usageEnabled ?? null),
    security_enabled: security.enabled ?? null,
    ...(layer === "transport" ? { verification_mode_per_node: whenRead(settingsReadable, verificationModes) } : {}),
    ...(layer === "http" ? { elasticsearch_url_scheme: elasticsearchUrl ? new URL(elasticsearchUrl).protocol.replace(":", "") : null } : {}),
  };
  const layerLabel = layer === "transport" ? "Transport" : "HTTP";

  let computed: Verdict;
  if (security.enabled === false) {
    computed = { status: "fail", summary: `xpack.security.enabled is false${security.disabledNodes.length > 0 ? ` on ${security.disabledNodes.join(", ")}` : ""}, so ${layer} layer TLS is not enforced.` };
  } else if (urlIsPlainHttp) {
    computed = { status: "fail", summary: "The configured Elasticsearch URL uses plain http, so client-to-cluster traffic is unencrypted." };
  } else if (disabledNodes.length > 0) {
    computed = layer === "http" && elasticsearchUrl?.startsWith("https://")
      ? { status: "warn", summary: `xpack.security.http.ssl.enabled is false on ${disabledNodes.join(", ")} while the endpoint is served over https; confirm the upstream TLS terminator encrypts traffic to every node.` }
      : { status: "fail", summary: `${key} is false on ${disabledNodes.join(", ")}.` };
  } else if (unsetNodes.length > 0) {
    computed = {
      status: "warn",
      summary: `${key} is not explicitly set on ${unsetNodes.join(", ")} (the documented default is false) and ${usageEnabled === true ? "usage statistics report it enabled" : usageReadable ? "usage statistics do not confirm it" : "usage statistics could not be read"}; verify the effective value on every node.`,
    };
  } else if (enabledNodes.length === 0) {
    computed = { status: "warn", summary: `${key} was not observed as true on any node; verify the effective value on every node.` };
  } else if (security.enabled === undefined) {
    computed = { status: "warn", summary: `${layerLabel} layer TLS is enabled on all ${enabledNodes.length} node(s) but xpack.security.enabled was not visible, so enforcement could not be confirmed.` };
  } else if (noVerificationNodes.length > 0) {
    computed = { status: "warn", summary: `Transport TLS is enabled but xpack.security.transport.ssl.verification_mode is none on ${noVerificationNodes.join(", ")}, so node certificates are not validated.` };
  } else {
    computed = {
      status: "pass",
      summary: `${layerLabel} layer TLS is explicitly enabled on all ${enabledNodes.length} node(s) with xpack.security.enabled true${layer === "transport" ? ` and verification_mode ${[...new Set(verificationModes.map((entry) => entry.value))].join(", ")}` : ""}${usageEnabled === true ? "; usage statistics agree" : ""}.`,
    };
  }
  return guardedFinding(number, "critical", { ...computed, evidence }, guard);
}

function statusCeiling(status: ElasticFinding["status"], ceiling: ElasticFinding["status"]): ElasticFinding["status"] {
  const order: Record<ElasticFinding["status"], number> = { pass: 0, warn: 1, manual: 2, fail: 3 };
  return order[status] >= order[ceiling] ? status : ceiling;
}

export function evaluateElasticTransportSecurity(
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  now: number = Date.now(),
  elasticsearchUrl?: string,
): ElasticAssessmentResult {
  const warningDays = clampNumber(options.certExpiryWarningDays, DEFAULT_CERT_EXPIRY_WARNING_DAYS, 1, 365);
  const nodeSettings = datasetData<JsonRecord>(snapshot, "node_settings");
  const view = buildSettingsView(nodeSettings, datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const certificates = datasetData<JsonRecord[]>(snapshot, "ssl_certificates");
  const settingsProblems = settingsDependencyProblems(snapshot, view);
  const settingsReadable = settingsProblems.length === 0;
  const usageReadable = usage !== undefined;
  const usageUnchecked = uncheckedSources(snapshot, ["xpack_usage"]);
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const security = securityEnabledState(view, usage);
  const settingsGuard = (collect: string, unchecked: string[] = []): VerdictGuard => ({ problems: settingsProblems, partial: nodeNotes, unchecked, collect });
  const transportFinding = evaluateTlsLayer(2, "transport", view, usage, security, elasticsearchUrl, settingsGuard("xpack.security.transport.ssl.enabled and verification_mode from elasticsearch.yml on every node (or the Elastic Cloud deployment TLS configuration).", usageUnchecked));
  const httpFinding = evaluateTlsLayer(3, "http", view, usage, security, elasticsearchUrl, settingsGuard("xpack.security.http.ssl.enabled from elasticsearch.yml on every node (or the Elastic Cloud deployment TLS configuration).", usageUnchecked));
  const findings: ElasticFinding[] = [transportFinding, httpFinding];

  const protocolKeys = ["xpack.security.transport.ssl.supported_protocols", "xpack.security.http.ssl.supported_protocols"];
  const perNodeProtocols = view.nodes.map((node) => ({
    node: node.name,
    major: asNumber(node.version?.split(".")[0]) ?? null,
    protocols: Object.fromEntries(protocolKeys.map((key) => [key, asStringList(node.settings[key])])),
  }));
  const weakProtocols = [...new Set(perNodeProtocols.flatMap((entry) => Object.values(entry.protocols).flat()).filter((protocol) => !MINIMUM_TLS_PROTOCOLS.has(protocol)))];
  const unsetProtocolNodes = perNodeProtocols
    .map((entry) => ({ node: entry.node, unset_keys: protocolKeys.filter((key) => entry.protocols[key].length === 0) }))
    .filter((entry) => entry.unset_keys.length > 0);
  const majors = nodeMajorVersions(view);
  const tlsCeiling = statusCeiling(transportFinding.status, httpFinding.status);
  const protocolComputed: Verdict = weakProtocols.length > 0
    ? { status: "fail", summary: `Supported TLS protocols include versions below TLSv1.2: ${weakProtocols.join(", ")}.` }
    : tlsCeiling === "fail"
      ? { status: "fail", summary: "TLS is not enforced on every layer (see ELASTIC-02 and ELASTIC-03), so no minimum protocol version applies to the unencrypted traffic." }
      : unsetProtocolNodes.length > 0
        ? {
          status: "warn",
          summary: `supported_protocols is not explicitly set on ${unsetProtocolNodes.map((entry) => `${entry.node} (${entry.unset_keys.map((key) => key.replace("xpack.security.", "").replace(".ssl.supported_protocols", "")).join(" and ")} layer)`).join(", ")}; the documented default is ${DEFAULT_TLS_SUPPORTED_PROTOCOLS}, which permits TLSv1.1, so the TLSv1.2 floor is not enforced until the setting is restricted explicitly.`,
        }
        : tlsCeiling !== "pass"
          ? { status: statusCeiling("warn", tlsCeiling === "manual" ? "manual" : "warn"), summary: `TLS protocol settings are TLSv1.2 or newer on every node, but TLS enforcement itself is ${tlsCeiling} (see ELASTIC-02 and ELASTIC-03), so the protocol floor is not confirmed effective.` }
          : {
            status: "pass",
            summary: `Supported TLS protocols are explicitly restricted to ${[...new Set(perNodeProtocols.flatMap((entry) => Object.values(entry.protocols).flat()))].join(", ")} on both layers of all ${perNodeProtocols.length} node(s).`,
          };
  findings.push(guardedFinding(4, "high", {
    ...protocolComputed,
    evidence: {
      protocols_per_node: whenRead(settingsReadable, perNodeProtocols),
      weak_protocols: whenRead(settingsReadable, weakProtocols),
      unset_supported_protocols: whenRead(settingsReadable, unsetProtocolNodes),
      documented_default: DEFAULT_TLS_SUPPORTED_PROTOCOLS,
      node_major_versions: whenRead(settingsReadable, majors),
      tls_enforcement_status: tlsCeiling,
    },
  }, settingsGuard("xpack.security.transport.ssl.supported_protocols and xpack.security.http.ssl.supported_protocols from elasticsearch.yml on every node.")));

  const certificatesReadable = certificates !== undefined;
  const inventory = (certificates ?? []).map((certificate) => {
    const expiry = isoDate(certificate.expiry);
    const daysRemaining = expiry ? daysBetween(now, Date.parse(expiry)) : undefined;
    return {
      alias: asString(certificate.alias) ?? null,
      path: asString(certificate.path) ?? null,
      subject_dn: asString(certificate.subject_dn) ?? null,
      has_private_key: asBoolean(certificate.has_private_key) ?? null,
      expiry: expiry ?? null,
      days_remaining: daysRemaining ?? null,
    };
  }).sort((left, right) => (left.days_remaining ?? Number.MAX_SAFE_INTEGER) - (right.days_remaining ?? Number.MAX_SAFE_INTEGER));
  const expired = inventory.filter((entry) => entry.days_remaining !== null && entry.days_remaining < 0);
  const expiring = inventory.filter((entry) => entry.days_remaining !== null && entry.days_remaining >= 0 && entry.days_remaining < warningDays);
  const missingExpiry = inventory.filter((entry) => entry.expiry === null);
  const certificateProblems = [
    ...dependencyProblems(snapshot, ["ssl_certificates"]),
    ...[emptyInventoryProblem(snapshot, "ssl_certificates", certificates ? certificates.length : undefined, "a TLS-enabled node always reports its keystore and truststore certificates")].filter((item): item is string => Boolean(item)),
  ];
  const certificatesComplete = certificatesReadable && certificateProblems.length === 0;
  const nodeHeaderTotal = asNumber(asObject(nodeSettings?._nodes)?.total);
  const nodeTotal = nodeHeaderTotal ?? (nodeSettings !== undefined ? view.nodes.length : undefined);
  const certificatePartial = nodeSettings === undefined
    ? dependencyProblems(snapshot, ["node_settings"]).map((problem) => `${problem}; GET /_ssl/certificates reports only the node that handled the request, so without the node inventory certificates on other nodes are unknown`)
    : (nodeTotal ?? 0) > 1
      ? [`GET /_ssl/certificates reports only the node that handled the request, but the cluster has ${nodeTotal} nodes; run the check against each node to cover every keystore and truststore`]
      : [];
  findings.push(guardedFinding(5, "high", {
    status: expired.length > 0 ? "fail" : expiring.length > 0 || missingExpiry.length > 0 ? "warn" : "pass",
    summary: expired.length > 0
      ? `${expired.length} TLS certificate(s) have expired and ${expiring.length} expire within ${warningDays} days.`
      : expiring.length > 0 || missingExpiry.length > 0
        ? `${expiring.length}/${inventory.length} TLS certificate(s) expire within ${warningDays} days and ${missingExpiry.length} report no expiry date (not counted as valid).`
        : !certificatesReadable
          ? "the certificate inventory could not be read."
          : `All ${inventory.length} TLS certificates on the responding node report an expiry date and remain valid for at least ${warningDays} more days${nodeTotal === 1 ? " (single-node cluster, so the inventory is complete)" : ""}.`,
    evidence: {
      inventory: inventoryState(snapshot, "ssl_certificates", certificates?.length, nodeTotal === undefined ? null : nodeTotal > 1),
      certificates: principalsWhenComplete(certificatesComplete, inventory),
      certificate_count: countWhenRead(certificatesComplete, inventory.length),
      expired: countWhenRead(certificatesComplete, expired.length),
      expiring_soon: countWhenRead(certificatesComplete, expiring.length),
      missing_expiry: countWhenRead(certificatesComplete, missingExpiry.length),
      cert_expiry_warning_days: warningDays,
      nodes_in_cluster: nodeTotal ?? null,
      single_node_view: true,
    },
  }, {
    problems: certificateProblems,
    partial: certificatePartial,
    collect: "the output of GET /_ssl/certificates from every node (the API reports only the node that handles the request and requires the monitor cluster privilege), or the certificate inventory with expiry dates for every node keystore and truststore.",
  }));

  return {
    area: "transport_security",
    title: "Elastic transport and HTTP TLS",
    summary: {
      nodes_inspected: countWhenRead(nodeSettings !== undefined, view.nodes.length),
      security_enabled: security.enabled ?? null,
      transport_tls: asBoolean(view.get("xpack.security.transport.ssl.enabled")) ?? usageFlag(usage, ["ssl", "transport", "enabled"]) ?? null,
      http_tls: asBoolean(view.get("xpack.security.http.ssl.enabled")) ?? usageFlag(usage, ["ssl", "http", "enabled"]) ?? null,
      weak_protocols: whenRead(settingsReadable, weakProtocols),
      certificates: countWhenRead(certificatesReadable, certificates?.length ?? 0),
      usage_statistics_read: usageReadable,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
    not_collected: listSnapshotSkips(snapshot),
    truncated: listSnapshotTruncations(snapshot),
  };
}

const DEFAULT_AUDIT_INCLUDE = [
  "access_denied",
  "access_granted",
  "anonymous_access_denied",
  "authentication_failed",
  "connection_denied",
  "tampered_request",
  "run_as_denied",
  "run_as_granted",
  "security_config_change",
];

function pipelineProcessors(processors: unknown, collected: Array<{ type: string; config: JsonRecord }> = []): Array<{ type: string; config: JsonRecord }> {
  for (const processor of asObjectArray(processors)) {
    for (const [type, rawConfig] of Object.entries(processor)) {
      const config = asObject(rawConfig) ?? {};
      collected.push({ type, config });
      pipelineProcessors(config.on_failure, collected);
      if (config.processor) pipelineProcessors([config.processor], collected);
    }
  }
  return collected;
}

function setProcessorLooksSensitive(config: JsonRecord): boolean {
  if (config.sensitive_literal === true) return true;
  const field = asString(config.field) ?? "";
  const value = config.value;
  const literal = typeof value === "string" && !value.includes("{{");
  return literal && (SECRET_FIELD_NAME_PATTERN.test(field) || TOKEN_LITERAL_PATTERN.test(value));
}

function watchActionIssues(watch: JsonRecord): { insecureWebhooks: string[]; embeddedCredentials: string[] } {
  const insecureWebhooks: string[] = [];
  const embeddedCredentials: string[] = [];
  const actions = asObject(getNestedValue(watch, ["watch", "actions"])) ?? asObject(watch.actions) ?? {};
  for (const [actionName, rawAction] of Object.entries(actions)) {
    const webhook = asObject(asObject(rawAction)?.webhook);
    if (!webhook) continue;
    const scheme = (asString(webhook.scheme) ?? "http").toLowerCase();
    if (scheme !== "https") insecureWebhooks.push(actionName);
    if (asObject(webhook.auth)) embeddedCredentials.push(actionName);
  }
  return { insecureWebhooks, embeddedCredentials };
}

function connectorUrl(connector: JsonRecord): string | undefined {
  const config = asObject(connector.config) ?? {};
  return asString(config.url) ?? asString(config.webhookUrl) ?? asString(config.apiUrl) ?? asString(config.configUrl);
}

function requiredLicenseRankFor(realmTypes: Set<string>, usesFlsOrDls: boolean, auditEnabled: boolean, watchCount: number): Array<{ feature: string; rank: number }> {
  const requirements: Array<{ feature: string; rank: number }> = [];
  for (const type of realmTypes) {
    if (PLATINUM_REALM_TYPES.has(type)) requirements.push({ feature: `${type} realm`, rank: LICENSE_RANK.platinum });
    if (GOLD_REALM_TYPES.has(type)) requirements.push({ feature: `${type} realm`, rank: LICENSE_RANK.gold });
  }
  if (usesFlsOrDls) requirements.push({ feature: "field/document-level security", rank: LICENSE_RANK.platinum });
  if (auditEnabled) requirements.push({ feature: "audit logging", rank: LICENSE_RANK.gold });
  if (watchCount > 0) requirements.push({ feature: "Watcher", rank: LICENSE_RANK.gold });
  return requirements;
}

function licenseLabel(rank: number): string {
  return Object.entries(LICENSE_RANK).find(([name, value]) => value === rank && name !== "trial")?.[0] ?? String(rank);
}

function alertingSpaceScopeNotes(snapshot: ElasticSnapshot, spaces: JsonRecord[] | undefined, spaceId: string | undefined): string[] {
  if (snapshot.kibana_spaces?.skipped) return [];
  const queried = spaceId ?? "default";
  if (!spaces) {
    return [`Kibana connectors and rules were read from the ${queried} space only and the space list could not be read (${datasetProblem(snapshot, "kibana_spaces")}), so other spaces may hold additional connectors`];
  }
  if (spaces.length === 0) {
    return [`the Kibana space list returned zero spaces although the default space always exists, so the scope of the ${queried} space connector inventory is unknown`];
  }
  const others = spaces.map((space) => asString(space.id) ?? "?").filter((id) => id !== queried);
  if (others.length === 0) return [];
  return [`Kibana connectors and rules were read from the ${queried} space only; ${others.length} other space(s) exist (${others.slice(0, 10).join(", ")}), so set space_id to inspect each`];
}

export function evaluateElasticClusterHardening(
  snapshot: ElasticSnapshot,
  _options: ElasticAssessmentOptions = {},
  now: number = Date.now(),
  kibanaSpaceId?: string,
): ElasticAssessmentResult {
  const nodeSettings = datasetData<JsonRecord>(snapshot, "node_settings");
  const view = buildSettingsView(nodeSettings, datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const xpackInfo = datasetData<JsonRecord>(snapshot, "xpack_info");
  const licenseData = datasetData<JsonRecord>(snapshot, "license");
  const license = licenseState(licenseData);
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const ilmStatus = datasetData<JsonRecord>(snapshot, "ilm_status");
  const ilmPolicies = datasetData<JsonRecord>(snapshot, "ilm_policies");
  const slmStatus = datasetData<JsonRecord>(snapshot, "slm_status");
  const slmPolicies = datasetData<JsonRecord>(snapshot, "slm_policies");
  const repositories = datasetData<JsonRecord>(snapshot, "snapshot_repositories");
  const watches = datasetData<JsonRecord[]>(snapshot, "watches");
  const pipelines = datasetData<JsonRecord>(snapshot, "ingest_pipelines");
  const kibanaSpaces = datasetData<JsonRecord[]>(snapshot, "kibana_spaces");
  const connectors = datasetData<JsonRecord[]>(snapshot, "connectors");
  const alertingRules = datasetData<JsonRecord[]>(snapshot, "alerting_rules");
  const detectionRules = datasetData<JsonRecord[]>(snapshot, "detection_rules");
  const findings: ElasticFinding[] = [];
  const settingsProblems = settingsDependencyProblems(snapshot, view);
  const settingsReadable = settingsProblems.length === 0;
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const licenseProblems = dependencyProblems(snapshot, ["license"]);
  const licenseReadable = licenseData !== undefined;
  const usageReadable = usage !== undefined;
  const usageUnchecked = uncheckedSources(snapshot, ["xpack_usage"]);
  const security = securityEnabledState(view, usage, xpackInfo);

  const audit = resolveAuditEnabled(view);
  const auditEnabledNodes = audit.perNode.filter((entry) => entry.effective === true).map((entry) => entry.node);
  const auditDisabledNodes = audit.perNode.filter((entry) => entry.effective !== true).map((entry) => entry.node);
  const auditEnabled = audit.perNode.length > 0 && auditDisabledNodes.length === 0;
  const auditLicense = licenseSupports(license, LICENSE_RANK.gold);
  const includeSetting = asStringList(view.get("xpack.security.audit.logfile.events.include"));
  const excludeSetting = asStringList(view.get("xpack.security.audit.logfile.events.exclude"));
  const effectiveInclude = (includeSetting.length > 0 ? includeSetting : DEFAULT_AUDIT_INCLUDE).filter((event) => !excludeSetting.includes(event));
  const missingEvents = REQUIRED_AUDIT_EVENTS.filter((event) => !effectiveInclude.includes(event));
  const auditOutputs = asStringList(getNestedValue(usage, ["security", "audit", "outputs"]));
  const auditEvidence: JsonRecord = {
    setting: AUDIT_ENABLED_KEY,
    cluster_level_value: audit.clusterLevel ?? null,
    cluster_level_source: audit.clusterLevelSource ?? null,
    per_node: whenRead(settingsReadable, audit.perNode.map((entry) => ({ node: entry.node, node_value: entry.nodeValue ?? null, effective: entry.effective ?? null, source: entry.source }))),
    enabled_nodes: whenRead(settingsReadable, auditEnabledNodes),
    disabled_or_unset_nodes: whenRead(settingsReadable, auditDisabledNodes),
    audit_enabled: whenRead(settingsReadable, auditEnabled),
    usage_reported_enabled: whenRead(usageReadable, usageFlag(usage, ["audit", "enabled"]) ?? null),
    events_include: whenRead(settingsReadable, includeSetting),
    events_exclude: whenRead(settingsReadable, excludeSetting),
    effective_include: whenRead(settingsReadable, effectiveInclude),
    outputs: whenRead(usageReadable, auditOutputs),
    license_type: whenRead(licenseReadable, license.type ?? null),
    license_supports_audit: auditLicense ?? null,
    security_enabled: security.enabled ?? null,
  };
  const auditGuard: VerdictGuard = {
    problems: [...settingsProblems, ...licenseProblems],
    partial: nodeNotes,
    unchecked: usageUnchecked,
    collect: "xpack.security.audit.* settings from the cluster settings API (transient and persistent) and elasticsearch.yml on every node, the license tier (GET /_license), and a sample of <cluster>_audit.json.",
  };
  const auditOff = settingsReadable && !auditEnabled;
  const auditSourceLabel = audit.clusterLevelSource
    ? `${audit.clusterLevelSource} cluster settings`
    : "node settings";
  findings.push(guardedFinding(11, "high", {
    status: auditOff || security.enabled === false || auditLicense === false
      ? "fail"
      : missingEvents.length > 0 || security.enabled === undefined
        ? "warn"
        : "pass",
    summary: security.enabled === false
      ? "xpack.security.enabled is false, so security audit logging cannot record authentication or authorization events."
      : auditOff
        ? auditEnabledNodes.length === 0
          ? audit.clusterLevel === false
            ? `xpack.security.audit.enabled is false in ${auditSourceLabel}, which overrides elasticsearch.yml on every node, so security audit logging is disabled.`
            : "xpack.security.audit.enabled is not true in transient or persistent cluster settings or on any inspected node (the documented default is false), so security audit logging is disabled."
          : `Audit logging is enabled on ${auditEnabledNodes.join(", ")} but disabled or unset on ${auditDisabledNodes.join(", ")}, so events on those nodes are not recorded.`
        : auditLicense === false
          ? `xpack.security.audit.enabled is true but the ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include audit logging, so no audit trail is produced.`
          : missingEvents.length > 0
            ? `Audit logging is enabled on all ${auditEnabledNodes.length} node(s) but the effective event include list omits ${missingEvents.join(", ")}.`
            : security.enabled === undefined
              ? `Audit logging is enabled on all ${auditEnabledNodes.length} node(s) but xpack.security.enabled was not visible, so enforcement could not be confirmed.`
              : `Audit logging is enabled on all ${auditEnabledNodes.length} node(s) via ${auditSourceLabel} with authentication_failed, access_denied, and security_config_change events included (${license.type} license supports audit logging${usageReadable ? "; usage statistics agree" : ""}).`,
    evidence: { ...auditEvidence, missing_required_events: whenRead(settingsReadable, missingEvents) },
  }, auditGuard));
  const auditForwardCollect = "evidence that <cluster>_audit.json is shipped to a tamper-resistant destination (Filebeat or Elastic Agent elasticsearch.audit integration, or a SIEM) with retention and integrity controls.";
  const auditManualEvidence: JsonRecord = { ...auditEvidence, unreadable_sources: settingsProblems, partial_sources: nodeNotes, unchecked_sources: usageUnchecked };
  findings.push(auditOff || security.enabled === false
    ? guardedFinding(12, "medium", { status: "fail", summary: "Audit logging is disabled on at least one node, so no complete audit output exists to protect.", evidence: auditEvidence }, auditGuard)
    : !settingsReadable
      ? manualFinding(12, "medium", `Audit settings could not be read: ${settingsProblems.join("; ")}.`, auditForwardCollect, auditManualEvidence)
      : manualFinding(
        12,
        "medium",
        `Elasticsearch writes audit events only to the local logfile output (${usageReadable ? auditOutputs.join(", ") || "logfile" : "outputs unread because usage statistics could not be read"}) on each node; forwarding to a tamper-resistant store cannot be verified through the API.`,
        auditForwardCollect,
        auditManualEvidence,
      ));

  const ilmMode = asString(ilmStatus?.operation_mode)?.toUpperCase();
  const ilmReadable = ilmPolicies !== undefined;
  const policies = Object.entries(ilmPolicies ?? {}).map(([name, value]) => {
    const entry = asObject(value) ?? {};
    const phases = asObject(getNestedValue(entry, ["policy", "phases"])) ?? {};
    const inUseBy = asObject(entry.in_use_by);
    const inUse = inUseBy
      ? asArray(inUseBy.indices).length + asArray(inUseBy.data_streams).length + asArray(inUseBy.composable_templates).length > 0
      : true;
    return {
      name,
      in_use: inUse,
      has_delete_phase: Boolean(phases.delete),
      has_rollover: Boolean(getNestedValue(phases, ["hot", "actions", "rollover"])),
      delete_min_age: asString(getNestedValue(phases, ["delete", "min_age"])) ?? null,
      managed: name.startsWith(".") || asBoolean(getNestedValue(entry, ["policy", "_meta", "managed"])) === true,
    };
  });
  const inUseWithoutDelete = policies.filter((policy) => policy.in_use && !policy.has_delete_phase);
  const ilmProblems = dependencyProblems(snapshot, ["ilm_policies", "ilm_status"]);
  const ilmEmpty = ilmReadable && policies.length === 0;
  const ilmStopped = ilmStatus !== undefined && ilmMode !== "RUNNING";
  findings.push(guardedFinding(17, "medium", {
    status: ilmEmpty || ilmStopped ? "fail" : inUseWithoutDelete.length > 0 ? "warn" : "pass",
    summary: ilmEmpty
      ? "No index lifecycle policies exist (zero policies is a failure for this control because retention and deletion are not enforced through ILM)."
      : ilmStopped
        ? `ILM operation_mode is ${ilmMode ?? "unknown"} rather than RUNNING, so lifecycle policies are not executing.`
        : inUseWithoutDelete.length > 0
          ? `${inUseWithoutDelete.length}/${policies.length} in-use ILM policies have no delete phase: ${inUseWithoutDelete.slice(0, 10).map((policy) => policy.name).join(", ")}.`
          : ilmReadable
            ? `All ${policies.filter((policy) => policy.in_use).length} in-use ILM policies define a delete phase and ILM operation_mode is RUNNING.`
            : "the ILM policy inventory could not be read.",
    evidence: {
      inventories: [inventoryState(snapshot, "ilm_policies", policies.length), inventoryState(snapshot, "ilm_status", ilmStatus ? 1 : undefined)],
      operation_mode: ilmMode ?? null,
      policy_count: countWhenRead(ilmReadable, policies.length),
      in_use_without_delete_count: countWhenRead(ilmReadable, inUseWithoutDelete.length),
      policies: principalsWhenComplete(ilmReadable, policies, 50),
      without_rollover: principalsWhenComplete(ilmReadable, policies.filter((policy) => policy.in_use && !policy.has_rollover).map((policy) => policy.name)),
    },
  }, {
    problems: ilmProblems,
    partial: [],
    collect: "the ILM policy definitions (GET /_ilm/policy), the ILM status (GET /_ilm/status), and the retention schedule approved for each regulated data stream.",
  }));

  const reposReadable = repositories !== undefined;
  const slmReadable = slmPolicies !== undefined;
  const repoEntries = Object.entries(repositories ?? {}).map(([name, value]) => {
    const entry = asObject(value) ?? {};
    const type = asString(entry.type) ?? "unknown";
    const settings = asObject(entry.settings) ?? {};
    const encryption: "platform" | "server_side_encryption" | "manual" = type === "gcs" || type === "azure"
      ? "platform"
      : type === "s3" && asBoolean(settings.server_side_encryption) === true
        ? "server_side_encryption"
        : "manual";
    return { name, type, encryption, bucket: asString(settings.bucket) ?? asString(settings.container) ?? null, location: asString(settings.location) ?? null };
  });
  const slmEntries = Object.entries(slmPolicies ?? {}).map(([name, value]) => {
    const entry = asObject(value) ?? {};
    return {
      name,
      repository: asString(getNestedValue(entry, ["policy", "repository"])) ?? asString(entry.repository) ?? null,
      last_success: isoDate(getNestedValue(entry, ["last_success", "time"])) ?? null,
      last_failure: isoDate(getNestedValue(entry, ["last_failure", "time"])) ?? null,
      next_execution: isoDate(entry.next_execution_millis ?? entry.next_execution) ?? null,
    };
  });
  const slmMode = asString(slmStatus?.operation_mode)?.toUpperCase();
  const slmNeverSucceeded = slmEntries.filter((entry) => entry.last_success === null);
  const manualRepos = repoEntries.filter((repo) => repo.encryption === "manual");
  const snapshotProblems = dependencyProblems(snapshot, ["snapshot_repositories", "slm_policies", "slm_status"]);
  const snapshotEvidence: JsonRecord = {
    inventories: [
      inventoryState(snapshot, "snapshot_repositories", repoEntries.length),
      inventoryState(snapshot, "slm_policies", slmEntries.length),
      inventoryState(snapshot, "slm_status", slmStatus ? 1 : undefined),
    ],
    repository_count: countWhenRead(reposReadable, repoEntries.length),
    repositories: principalsWhenComplete(reposReadable, repoEntries, 50),
    slm_policy_count: countWhenRead(slmReadable, slmEntries.length),
    slm_policies: principalsWhenComplete(slmReadable, slmEntries, 50),
    slm_operation_mode: slmMode ?? null,
    slm_policies_without_last_success: principalsWhenComplete(slmReadable, slmNeverSucceeded.map((entry) => entry.name)),
  };
  const snapshotCollect = "the repository settings (GET /_snapshot/_all), storage encryption evidence for each bucket or filesystem, the SLM policies and status (GET /_slm/policy, GET /_slm/status), and the most recent successful snapshot per policy.";
  const reposEmpty = reposReadable && repoEntries.length === 0;
  const slmEmpty = slmReadable && slmEntries.length === 0;
  const slmStopped = slmStatus !== undefined && slmMode !== "RUNNING";
  if (snapshotProblems.length === 0 && !reposEmpty && !slmEmpty && !slmStopped && manualRepos.length > 0) {
    findings.push(manualFinding(
      18,
      "high",
      `${manualRepos.length}/${repoEntries.length} repositories (${manualRepos.map((repo) => `${repo.name}:${repo.type}`).join(", ")}) do not expose an encryption setting through the API.`,
      "bucket default-encryption or filesystem/disk encryption evidence for each listed repository (S3 repositories can also set server_side_encryption: true).",
      { ...snapshotEvidence, unreadable_sources: [], partial_sources: [], unchecked_sources: [] },
    ));
  } else {
    findings.push(guardedFinding(18, "high", {
      status: reposEmpty || slmEmpty || slmStopped ? "fail" : slmNeverSucceeded.length > 0 ? "warn" : "pass",
      summary: reposEmpty
        ? "No snapshot repositories are registered (zero repositories is a failure for this control because no encrypted backups or SLM policies can exist)."
        : slmEmpty
          ? `${repoEntries.length} snapshot repositories exist but zero snapshot lifecycle policies are defined, so scheduled encrypted backups are not enforced.`
          : slmStopped
            ? `SLM operation_mode is ${slmMode ?? "unknown"} rather than RUNNING, so snapshot lifecycle policies are not executing.`
            : slmNeverSucceeded.length > 0
              ? `${slmNeverSucceeded.length}/${slmEntries.length} SLM policies report no last_success time (${slmNeverSucceeded.map((entry) => entry.name).join(", ")}), so they are not counted as working backups.`
              : snapshotProblems.length > 0
                ? "the readable snapshot sources show no failure, but the repository, SLM policy, or SLM status inventory is incomplete."
                : `All ${repoEntries.length} snapshot repositories use encrypted storage, ${slmEntries.length} SLM policies report a last successful snapshot, and SLM operation_mode is RUNNING.`,
      evidence: snapshotEvidence,
    }, { problems: snapshotProblems, partial: [], collect: snapshotCollect }));
  }

  const passwordHashingSetting = asString(view.get("xpack.security.authc.password_hashing.algorithm"));
  const passwordHashing = passwordHashingSetting ?? "bcrypt (documented default, not explicitly set)";
  const apiKeyHashing = asString(view.get("xpack.security.authc.api_key.hashing.algorithm")) ?? "ssha256 (documented default)";
  const tokenService = asBoolean(view.get("xpack.security.authc.token.enabled")) ?? usageFlag(usage, ["token_service", "enabled"]);
  const apiKeyService = asBoolean(view.get("xpack.security.authc.api_key.enabled")) ?? usageFlag(usage, ["api_key_service", "enabled"]);
  const fipsMode = asBoolean(view.get("xpack.security.fips_mode.enabled")) ?? usageFlag(usage, ["fips_140", "enabled"]);
  const httpIpFilter = asBoolean(view.get("xpack.security.http.filter.enabled")) ?? usageFlag(usage, ["ipfilter", "http"]);
  const transportIpFilter = asBoolean(view.get("xpack.security.transport.filter.enabled")) ?? usageFlag(usage, ["ipfilter", "transport"]);
  const strongPasswordHashing = /^(bcrypt|pbkdf2)/i.test(passwordHashingSetting ?? "bcrypt");
  const securityPerNode = perNodeBooleans(view, "xpack.security.enabled");
  const clusterEvidence: JsonRecord = {
    security_enabled: security.enabled ?? null,
    security_enabled_source: security.source,
    security_enabled_per_node: whenRead(settingsReadable, securityPerNode.map((entry) => ({ node: entry.node, value: entry.value ?? null }))),
    password_hashing_algorithm: whenRead(settingsReadable, passwordHashing),
    password_hashing_explicit: whenRead(settingsReadable, passwordHashingSetting !== undefined),
    api_key_hashing_algorithm: whenRead(settingsReadable, apiKeyHashing),
    token_service_enabled: tokenService ?? null,
    api_key_service_enabled: apiKeyService ?? null,
    fips_mode_enabled: fipsMode ?? null,
    http_ip_filter_enabled: httpIpFilter ?? null,
    transport_ip_filter_enabled: transportIpFilter ?? null,
  };
  findings.push(guardedFinding(19, "high", {
    status: security.enabled === false ? "fail" : !strongPasswordHashing || security.enabled === undefined ? "warn" : "pass",
    summary: security.enabled === false
      ? `xpack.security.enabled is false${security.disabledNodes.length > 0 ? ` on ${security.disabledNodes.join(", ")}` : ""}, so authentication, authorization, and TLS enforcement are off.`
      : !strongPasswordHashing
        ? `Security is enabled but the password hashing algorithm is ${passwordHashing}; use a bcrypt or pbkdf2 variant.`
        : security.enabled === undefined
          ? "xpack.security.enabled was not visible in node settings, cluster settings, usage statistics, or xpack info, so security enforcement could not be confirmed."
          : `xpack.security.enabled is true (${security.source}) with ${passwordHashing} password hashing, API key hashing ${apiKeyHashing}, token service ${tokenService ?? "default"}, and API key service ${apiKeyService ?? "default"}.`,
    evidence: clusterEvidence,
  }, {
    problems: settingsProblems,
    partial: nodeNotes,
    unchecked: uncheckedSources(snapshot, ["xpack_usage", "xpack_info"]),
    collect: "the xpack.security.* section of elasticsearch.yml from every node plus GET /_cluster/settings?include_defaults=true.",
  }));

  const watchesComplete = datasetComplete(snapshot, "watches");
  const connectorsComplete = datasetComplete(snapshot, "connectors");
  const alertingRulesComplete = datasetComplete(snapshot, "alerting_rules");
  const detectionRulesComplete = datasetComplete(snapshot, "detection_rules");
  const rulesReadable = datasetReadable(snapshot, "alerting_rules") && datasetReadable(snapshot, "detection_rules");
  const watchIssues = (watches ?? []).map((watch) => ({ id: asString(watch._id) ?? "watch", ...watchActionIssues(watch) }));
  const insecureWatchActions = watchIssues.filter((watch) => watch.insecureWebhooks.length > 0);
  const credentialWatchActions = watchIssues.filter((watch) => watch.embeddedCredentials.length > 0);
  const insecureConnectors = (connectors ?? []).filter((connector) => (connectorUrl(connector) ?? "").startsWith("http://"));
  const connectorsMissingSecrets = (connectors ?? []).filter((connector) => asBoolean(connector.is_missing_secrets) === true);
  const rulesWithActions = (alertingRules ?? []).filter((rule) => asObjectArray(rule.actions).length > 0).length
    + (detectionRules ?? []).filter((rule) => asObjectArray(rule.actions).length > 0).length;
  const watcherLicensed = licenseSupports(license, LICENSE_RANK.gold);
  const watcherProblem = watches ? undefined : datasetProblem(snapshot, "watches");
  const watcherNotApplicable = !watches && watcherLicensed === false;
  const kibanaScopedOut = snapshot.connectors?.skipped;
  const connectorProblem = connectors ? undefined : datasetProblem(snapshot, "connectors");
  const spaceScopeNotes = alertingSpaceScopeNotes(snapshot, kibanaSpaces, kibanaSpaceId);
  const alertingProblems = [
    ...(watches || watcherNotApplicable ? [] : [`watches (${DATASET_SPECS.watches.endpoint}): ${watcherProblem}`]),
    ...(connectors || kibanaScopedOut ? [] : [`connectors (${DATASET_SPECS.connectors.endpoint}): ${connectorProblem}`]),
    ...(kibanaScopedOut ? [] : dependencyProblems(snapshot, ["alerting_rules", "detection_rules"])),
  ];
  const alertingPartial = [...truncationNotes(snapshot, ["watches", "alerting_rules", "detection_rules", "connectors"]), ...spaceScopeNotes];
  const alertingUnchecked = watches ? uncheckedSources(snapshot, ["license"]) : [];
  const alertingEvidence: JsonRecord = {
    inventories: [
      inventoryState(snapshot, "watches", watches?.length),
      inventoryState(snapshot, "connectors", connectors?.length),
      inventoryState(snapshot, "alerting_rules", alertingRules?.length),
      inventoryState(snapshot, "detection_rules", detectionRules?.length),
    ],
    // Inventory counts: zero from a listing that stopped early is unknown, not an absence (the inventories above say why).
    watches: observedCount(watchesComplete, watches?.length ?? 0),
    watcher_unreadable: watcherProblem ?? null,
    watcher_licensed: watcherLicensed ?? null,
    watcher_not_applicable: whenRead(licenseReadable, watcherNotApplicable),
    kibana_scoped_out: kibanaScopedOut ?? null,
    kibana_space_queried: kibanaSpaceId ?? "default",
    kibana_spaces_total: kibanaSpaces?.length ?? null,
    connectors: observedCount(connectorsComplete, connectors?.length ?? 0),
    connectors_unreadable: connectorProblem ?? null,
    alerting_rules: observedCount(alertingRulesComplete, alertingRules?.length ?? 0),
    detection_rules: observedCount(detectionRulesComplete, detectionRules?.length ?? 0),
    rules_with_actions: rulesReadable ? observedCount(alertingRulesComplete && detectionRulesComplete, rulesWithActions) : null,
    insecure_watch_webhooks: principalsWhenComplete(watchesComplete, insecureWatchActions.map((watch) => ({ id: watch.id, actions: watch.insecureWebhooks }))),
    watch_actions_with_embedded_credentials: principalsWhenComplete(watchesComplete, credentialWatchActions.map((watch) => ({ id: watch.id, actions: watch.embeddedCredentials }))),
    insecure_connectors: principalsWhenComplete(connectorsComplete, insecureConnectors.map((connector) => ({ id: asString(connector.id), name: asString(connector.name), type: asString(connector.connector_type_id), url: connectorUrl(connector) }))),
    connectors_missing_secrets: principalsWhenComplete(connectorsComplete, connectorsMissingSecrets.map((connector) => asString(connector.name) ?? asString(connector.id))),
  };
  const alertingCollect = kibanaScopedOut
    ? "the watch definitions (POST /_watcher/_query/watches) and the Kibana connector inventory from every space (configure KIBANA_URL so the connectors API can be queried, or export the connectors from each space), then confirm webhook destinations use https and credentials are stored as secrets."
    : "the watch definitions (POST /_watcher/_query/watches) and the Kibana connector inventory from every space (GET /api/actions/connectors in each space), then confirm webhook destinations use https and credentials are stored as secrets.";
  const alertingFailed = insecureWatchActions.length > 0 || insecureConnectors.length > 0;
  const alertingWarned = credentialWatchActions.length > 0 || connectorsMissingSecrets.length > 0;
  const alertingEmpty = (watches?.length ?? 0) === 0 && (connectors?.length ?? 0) === 0;
  // An empty read is an observed absence only when every listing behind it ran to completion; a page that stopped before
  // any watch or connector was read says nothing about whether alerting destinations exist.
  const alertingEmptyObserved = alertingEmpty && (watches === undefined || watchesComplete) && (connectors === undefined || connectorsComplete);
  const alertingManualEvidence: JsonRecord = { ...alertingEvidence, unreadable_sources: alertingProblems, partial_sources: alertingPartial, unchecked_sources: alertingUnchecked };
  if (!alertingFailed && alertingProblems.length === 0 && watcherNotApplicable && kibanaScopedOut) {
    findings.push(manualFinding(
      20,
      "medium",
      `Not applicable or scoped out: Watcher is not available on the ${license.type ?? "current"} license and Kibana is not configured (${kibanaScopedOut}), so no alerting destinations could be assessed.`,
      alertingCollect,
      alertingManualEvidence,
    ));
  } else if (!alertingFailed && alertingProblems.length === 0 && kibanaScopedOut) {
    findings.push(manualFinding(
      20,
      "medium",
      `Scoped out: Kibana is not configured (${kibanaScopedOut}), so only ${watches?.length ?? 0} watch(es) were reviewed${alertingWarned ? ` (${credentialWatchActions.length} embed basic-auth credentials)` : " and none use plain http webhooks"}; Kibana connectors and rule actions were not assessed.`,
      alertingCollect,
      alertingManualEvidence,
    ));
  } else if (!alertingFailed && alertingProblems.length === 0 && alertingEmpty && spaceScopeNotes.length > 0) {
    findings.push(manualFinding(
      20,
      "medium",
      `Zero watches and zero connectors were visible in the queried scope, but the connector inventory is space-scoped (${spaceScopeNotes.join("; ")}), so emptiness cannot be confirmed as compliant.`,
      alertingCollect,
      alertingManualEvidence,
    ));
  } else {
    findings.push(guardedFinding(20, "medium", {
      status: alertingFailed ? "fail" : alertingWarned || (alertingEmpty && !alertingEmptyObserved) ? "warn" : "pass",
      summary: alertingFailed
        ? `${insecureWatchActions.length} watch(es) and ${insecureConnectors.length} Kibana connector(s) send to plain http webhook destinations.`
        : alertingWarned
          ? `${credentialWatchActions.length} watch action(s) embed basic-auth credentials and ${connectorsMissingSecrets.length} connector(s) are missing secrets.`
          : alertingProblems.length > 0
            ? "the readable alerting inventories show no insecure destination, but the alerting picture is incomplete."
            : alertingEmptyObserved
              ? `Zero watches and zero connectors exist in the only Kibana space${watcherNotApplicable ? ` (Watcher is not available on the ${license.type} license)` : ""}; this passes because the control governs the security of existing alerting destinations and none exist.`
              : alertingEmpty
                ? "Zero watches and zero connectors were read before the listing stopped, so no alerting destination was assessed and their absence is not established."
                : `${watches?.length ?? 0} watches and ${connectors?.length ?? 0} connectors reviewed (${rulesWithActions} rules carry actions); all webhook destinations use https and no inline credentials were found${watcherNotApplicable ? `; Watcher is not available on the ${license.type} license, so only Kibana connectors were assessed` : ""}.`,
      evidence: alertingEvidence,
    }, { problems: alertingProblems, partial: alertingPartial, unchecked: alertingUnchecked, collect: alertingCollect }));
  }

  const pipelinesReadable = pipelines !== undefined;
  const pipelineEntries = Object.entries(pipelines ?? {}).map(([name, value]) => {
    const entry = asObject(value) ?? {};
    const processors = pipelineProcessors(entry.processors);
    return {
      name,
      managed: asBoolean(getNestedValue(entry, ["_meta", "managed"])) === true || name.startsWith("."),
      script_processors: processors.filter((processor) => processor.type === "script").length,
      sensitive_set_processors: processors.filter((processor) => processor.type === "set" && setProcessorLooksSensitive(processor.config)).map((processor) => asString(processor.config.field) ?? "value"),
    };
  });
  const customPipelines = pipelineEntries.filter((pipeline) => !pipeline.managed);
  const pipelinesWithSecrets = customPipelines.filter((pipeline) => pipeline.sensitive_set_processors.length > 0);
  const pipelinesWithScripts = customPipelines.filter((pipeline) => pipeline.script_processors > 0);
  const pipelineProblems = dependencyProblems(snapshot, ["ingest_pipelines"]);
  const pipelinesEmpty = emptyInventoryProblem(snapshot, "ingest_pipelines", pipelines ? pipelineEntries.length : undefined, "Elasticsearch ships managed pipelines (Fleet, logs, and behavioral analytics) in every supported release");
  const pipelinesComplete = pipelinesReadable && !pipelinesEmpty;
  const pipelineEvidence: JsonRecord = {
    inventory: inventoryState(snapshot, "ingest_pipelines", pipelineEntries.length),
    pipelines: countWhenRead(pipelinesReadable, pipelineEntries.length),
    custom_pipelines: countWhenRead(pipelinesReadable, customPipelines.length),
    managed_pipelines: countWhenRead(pipelinesReadable, pipelineEntries.length - customPipelines.length),
    pipelines_with_sensitive_set: principalsWhenComplete(pipelinesComplete, pipelinesWithSecrets),
    pipelines_with_scripts: principalsWhenComplete(pipelinesComplete, pipelinesWithScripts.map((pipeline) => pipeline.name)),
  };
  findings.push(guardedFinding(22, "medium", {
    status: pipelinesWithSecrets.length > 0 ? "fail" : pipelinesWithScripts.length > 0 ? "warn" : "pass",
    summary: pipelinesWithSecrets.length > 0
      ? `${pipelinesWithSecrets.length} custom ingest pipeline(s) set sensitive-looking literal values: ${pipelinesWithSecrets.slice(0, 10).map((pipeline) => pipeline.name).join(", ")}.`
      : pipelinesWithScripts.length > 0
        ? `${pipelinesWithScripts.length}/${customPipelines.length} custom ingest pipeline(s) use script processors; review them for data exposure.`
        : pipelinesReadable
          ? `${pipelineEntries.length} ingest pipelines reviewed (${customPipelines.length} custom, ${pipelineEntries.length - customPipelines.length} managed); no script processors or hardcoded sensitive values in custom pipelines.`
          : "the ingest pipeline inventory could not be read.",
    evidence: pipelineEvidence,
  }, {
    problems: [...pipelineProblems, ...(pipelinesEmpty ? [pipelinesEmpty] : [])],
    partial: [],
    collect: "the pipeline definitions (GET /_ingest/pipeline) as an administrator and review script and set processors for hardcoded sensitive values.",
  }));

  const licenseInfo = asObject(licenseData?.license);
  const licenseExpiry = isoDate(licenseInfo?.expiry_date_in_millis ?? licenseInfo?.expiry_date);
  const realmTypes = new Set([...parseRealms(view).filter((realm) => realm.enabled).map((realm) => realm.type), ...usageRealmTypes(usage)]);
  const rolesReadable = roles !== undefined;
  const usesFlsOrDls = roles ? roleIndexEntries(roles).some((entry) => (entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0) || (entry.query !== undefined && entry.query !== null)) : false;
  // A partial watches read proves Watcher is in use from any collected row or a server count above zero; it never
  // proves the feature absent, so the requirement set stays incomplete and the read is named as partial.
  const watchesInUse = watches !== undefined ? Math.max(watches.length, datasetPage(snapshot, "watches")?.total ?? 0) : 0;
  const requirements = requiredLicenseRankFor(realmTypes, usesFlsOrDls, auditEnabled, watchesInUse);
  const licenseRank = license.rank;
  const unsupported = licenseRank === undefined ? [] : requirements.filter((requirement) => requirement.rank > licenseRank);
  const expiryDays = licenseExpiry ? daysBetween(now, Date.parse(licenseExpiry)) : undefined;
  const expiryMissing = licenseReadable && licenseExpiry === undefined && license.type !== "basic";
  const featureSourceProblems = [...settingsProblems, ...dependencyProblems(snapshot, ["roles"])];
  const featureSourcesUnchecked = uncheckedSources(snapshot, ["xpack_usage", "xpack_info"]).concat(watches || watcherNotApplicable ? [] : uncheckedSources(snapshot, ["watches"]));
  const featureSourcesPartial = truncationNotes(snapshot, ["watches"]);
  const requirementsComplete = settingsReadable && rolesReadable && usageReadable && (watchesComplete || watcherNotApplicable);
  // Below platinum the configured features decide coverage, so their sources are essential; at platinum or above every feature is covered and they only cross-check.
  const coverageEssential = license.rank === undefined || license.rank < LICENSE_RANK.platinum;
  const licenseEvidence: JsonRecord = {
    type: whenRead(licenseReadable, license.type ?? null),
    status: whenRead(licenseReadable, license.status ?? null),
    expiry: whenRead(licenseReadable, licenseExpiry ?? null),
    expiry_missing: whenRead(licenseReadable, expiryMissing),
    days_until_expiry: expiryDays ?? null,
    security_available: asBoolean(getNestedValue(xpackInfo, ["features", "security", "available"])) ?? null,
    security_enabled: asBoolean(getNestedValue(xpackInfo, ["features", "security", "enabled"])) ?? null,
    requirements_complete: requirementsComplete,
    required_features: requirements.map((requirement) => ({ feature: requirement.feature, minimum_license: licenseLabel(requirement.rank) })),
    unsupported_features: requirementsComplete && licenseReadable ? unsupported.map((item) => item.feature) : null,
  };
  findings.push(guardedFinding(23, "medium", {
    status: unsupported.length > 0 || license.active === false || (licenseReadable && license.type === undefined)
      ? "fail"
      : license.type === "trial" || (expiryDays !== undefined && expiryDays < 30) || expiryMissing || license.active === undefined
        ? "warn"
        : "pass",
    summary: licenseReadable && license.type === undefined
      ? "GET /_license returned no license type, so the subscription tier could not be determined."
      : unsupported.length > 0
        ? `The ${license.type} license does not cover configured features: ${unsupported.map((item) => `${item.feature} (needs ${licenseLabel(item.rank)})`).join(", ")}.`
        : license.active === false
          ? `The license status is ${license.status}.`
          : license.active === undefined
            ? licenseReadable ? `The ${license.type} license reports no status field, so it cannot be confirmed as active.` : "the license could not be read."
            : license.type === "trial"
              ? `A trial license is active${expiryDays !== undefined ? ` and expires in ${expiryDays} days` : ""}; security features will lapse when it ends.`
              : expiryMissing
                ? `The ${license.type} license is active but reports no expiry date, so its validity window cannot be confirmed.`
                : expiryDays !== undefined && expiryDays < 30
                  ? `The ${license.type} license expires in ${expiryDays} days.`
                  : `The ${license.type} license is active${expiryDays !== undefined ? ` (expires in ${expiryDays} days)` : ""} and covers every configured security feature (${requirements.length} requirement(s) checked).`,
    evidence: licenseEvidence,
  }, {
    problems: [...licenseProblems, ...(coverageEssential ? featureSourceProblems : [])],
    partial: [...nodeNotes, ...featureSourcesPartial],
    unchecked: [...(coverageEssential ? [] : featureSourceProblems), ...featureSourcesUnchecked],
    collect: "the output of GET /_license and the subscription tier that covers the configured realms, FLS/DLS, audit logging, and Watcher.",
  }));

  return {
    area: "cluster_hardening",
    title: "Elastic cluster hardening and data protection",
    summary: {
      audit_enabled: whenRead(settingsReadable, auditEnabled),
      audit_outputs: whenRead(usageReadable, auditOutputs),
      ilm_policies: countWhenRead(ilmReadable, Object.keys(ilmPolicies ?? {}).length),
      ilm_operation_mode: ilmMode ?? null,
      snapshot_repositories: countWhenRead(reposReadable, Object.keys(repositories ?? {}).length),
      slm_policies: countWhenRead(slmReadable, Object.keys(slmPolicies ?? {}).length),
      slm_operation_mode: slmMode ?? null,
      watches: observedCount(watchesComplete, watches?.length ?? 0),
      connectors: observedCount(connectorsComplete, connectors?.length ?? 0),
      alerting_rules: observedCount(alertingRulesComplete, alertingRules?.length ?? 0),
      detection_rules: observedCount(detectionRulesComplete, detectionRules?.length ?? 0),
      ingest_pipelines: countWhenRead(pipelinesReadable, Object.keys(pipelines ?? {}).length),
      license_type: whenRead(licenseReadable, license.type ?? null),
      license_status: whenRead(licenseReadable, license.status ?? null),
      security_enabled: security.enabled ?? null,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
    not_collected: listSnapshotSkips(snapshot),
    truncated: listSnapshotTruncations(snapshot),
  };
}

function kibanaRoleEntries(role: JsonRecord): Array<{ base: string[]; features: string[]; spaces: string[] }> {
  return asObjectArray(role.kibana).map((entry) => ({
    base: asStringList(entry.base),
    features: Object.keys(asObject(entry.feature) ?? {}),
    spaces: asStringList(entry.spaces),
  }));
}

function kibanaRoleIsReserved(role: JsonRecord): boolean {
  return asBoolean(getNestedValue(role, ["metadata", "_reserved"])) === true;
}

function hostListIsPlainHttp(hosts: unknown): string[] {
  return asStringList(hosts).filter((host) => host.toLowerCase().startsWith("http://"));
}

export function evaluateElasticKibana(
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  kibanaSpaceId?: string,
): ElasticAssessmentResult {
  const maxEnrollmentKeys = clampNumber(options.maxEnrollmentKeysPerPolicy, DEFAULT_MAX_ENROLLMENT_KEYS_PER_POLICY, 1, 1000);
  const status = datasetData<JsonRecord>(snapshot, "kibana_status");
  const spaces = datasetData<JsonRecord[]>(snapshot, "kibana_spaces");
  const roles = datasetData<JsonRecord[]>(snapshot, "kibana_roles");
  const agentPolicies = datasetData<JsonRecord[]>(snapshot, "fleet_agent_policies");
  const outputs = datasetData<JsonRecord[]>(snapshot, "fleet_outputs");
  const enrollmentKeys = datasetData<JsonRecord[]>(snapshot, "fleet_enrollment_api_keys");
  const fleetServerHosts = datasetData<JsonRecord[]>(snapshot, "fleet_server_hosts");
  const findings: ElasticFinding[] = [];
  const kibanaSkipped = snapshot.kibana_spaces?.skipped ?? snapshot.kibana_roles?.skipped;

  const rolesReadable = roles !== undefined;
  const spacesReadable = spaces !== undefined;
  const customRoles = (roles ?? []).filter((role) => !kibanaRoleIsReserved(role));
  const reservedRoles = (roles ?? []).length - customRoles.length;
  const globalAllRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).some((entry) => entry.spaces.includes("*") && entry.base.includes("all")))
    .map((role) => asString(role.name) ?? "role");
  const spaceScopedRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).some((entry) => entry.spaces.length > 0 && !entry.spaces.includes("*")))
    .map((role) => asString(role.name) ?? "role");
  const featureScopedRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).every((entry) => entry.base.length === 0 && entry.features.length > 0))
    .map((role) => asString(role.name) ?? "role");
  const spacesEmpty = emptyInventoryProblem(snapshot, "kibana_spaces", spaces?.length, "the default space always exists");
  const rolesEmpty = emptyInventoryProblem(snapshot, "kibana_roles", roles?.length, "Kibana always returns its reserved roles");
  const roleProblems = [...dependencyProblems(snapshot, ["kibana_roles"]), ...(rolesEmpty ? [rolesEmpty] : [])];
  const spaceProblems = [...dependencyProblems(snapshot, ["kibana_spaces"]), ...(spacesEmpty ? [spacesEmpty] : [])];
  const rolesComplete = rolesReadable && roleProblems.length === 0;
  const spacesComplete = spacesReadable && spaceProblems.length === 0;
  const roleEvidence: JsonRecord = {
    inventory: inventoryState(snapshot, "kibana_roles", roles?.length),
    roles_reviewed: roles?.length ?? null,
    custom_roles: countWhenRead(rolesReadable, customRoles.length),
    reserved_roles: countWhenRead(rolesReadable, reservedRoles),
    global_all_roles: principalsWhenComplete(rolesComplete, globalAllRoles),
    space_scoped_roles: principalsWhenComplete(rolesComplete, spaceScopedRoles),
    feature_scoped_roles: principalsWhenComplete(rolesComplete, featureScopedRoles),
    elasticsearch_cluster_all_roles: principalsWhenComplete(
      rolesComplete,
      customRoles
        .filter((role) => asStringList(getNestedValue(role, ["elasticsearch", "cluster"])).includes("all"))
        .map((role) => asString(role.name)),
    ),
  };

  if (kibanaSkipped) {
    // Kibana was never requested, so no endpoint is named here; the collect text asks for the configuration instead.
    const collect = "Kibana evidence manually or set KIBANA_URL so the Kibana API can be queried:";
    const skippedEvidence = (names: ElasticDatasetName[]): JsonRecord => ({
      inventories: names.map((name) => inventoryState(snapshot, name, undefined)),
      unreadable_sources: [],
      partial_sources: [],
      unchecked_sources: [],
      not_collected_sources: listSnapshotSkips(snapshot).filter((entry) => names.some((name) => entry.startsWith(`${name} (`))),
    });
    findings.push(manualFinding(15, "medium", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} the space list and the roles that scope privileges to individual spaces.`, skippedEvidence(["kibana_spaces", "kibana_roles"])));
    findings.push(manualFinding(16, "high", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} the Kibana role definitions and identify roles granting base all across all spaces.`, skippedEvidence(["kibana_roles"])));
    findings.push(manualFinding(21, "medium", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} the Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys.`, skippedEvidence(["fleet_agent_policies", "fleet_outputs", "fleet_server_hosts", "fleet_enrollment_api_keys"])));
  } else {
    const spaceEvidence = (spaces ?? []).map((space) => ({
      id: asString(space.id),
      name: asString(space.name),
      disabled_features: asStringList(space.disabledFeatures).length,
      reserved: asBoolean(space._reserved) ?? false,
    }));
    const spaceCount = spaces?.length ?? 0;
    findings.push(guardedFinding(15, "medium", {
      status: spaceCount <= 1
        ? "warn"
        : spaceScopedRoles.length > 0 && globalAllRoles.length === 0
          ? "pass"
          : "warn",
      summary: !spacesReadable || !rolesReadable
        ? "the space or role inventory could not be read, so space isolation is unknown."
        : spaceCount <= 1
          ? "Only the default space exists, so Kibana space isolation between teams is not in use; confirm whether multi-team separation is required."
          : spaceScopedRoles.length > 0 && globalAllRoles.length === 0
            ? `${spaceCount} spaces exist and ${spaceScopedRoles.length} custom role(s) scope privileges to specific spaces with no custom role granting all privileges across every space.`
            : `${spaceCount} spaces exist but ${spaceScopedRoles.length} role(s) are space-scoped and ${globalAllRoles.length} custom role(s) grant all privileges across every space.`,
      evidence: {
        inventories: [inventoryState(snapshot, "kibana_spaces", spaces?.length), inventoryState(snapshot, "kibana_roles", roles?.length)],
        space_count: countWhenRead(spacesReadable, spaceCount),
        spaces: principalsWhenComplete(spacesComplete, spaceEvidence, 50),
        space_scoped_roles: principalsWhenComplete(rolesComplete, spaceScopedRoles),
        global_all_roles: principalsWhenComplete(rolesComplete, globalAllRoles),
      },
    }, {
      problems: [...spaceProblems, ...roleProblems],
      partial: [],
      collect: "the space list (GET /api/spaces/space) and the roles that scope privileges to individual spaces.",
    }));

    findings.push(guardedFinding(16, "high", {
      status: globalAllRoles.length > 0 ? "fail" : customRoles.length === 0 ? "warn" : "pass",
      summary: globalAllRoles.length > 0
        ? `${globalAllRoles.length} custom Kibana role(s) grant base all privileges across every space: ${globalAllRoles.slice(0, 10).join(", ")}.`
        : !rolesReadable
          ? "the Kibana role inventory could not be read."
          : customRoles.length === 0
            ? `No custom Kibana roles exist (${reservedRoles} reserved roles only), so users rely on reserved roles such as kibana_admin or superuser and feature-level privilege separation is not implemented.`
            : `${customRoles.length} custom Kibana roles reviewed; none grants base all across every space (${featureScopedRoles.length} use feature-level privileges only).`,
      evidence: roleEvidence,
    }, {
      problems: roleProblems,
      partial: [],
      collect: "the Kibana role definitions (GET /api/security/role) and identify roles granting base all across all spaces.",
    }));

    const policiesComplete = datasetComplete(snapshot, "fleet_agent_policies");
    const outputsComplete = datasetComplete(snapshot, "fleet_outputs");
    const hostsComplete = datasetComplete(snapshot, "fleet_server_hosts");
    const keysComplete = datasetComplete(snapshot, "fleet_enrollment_api_keys");
    const insecureOutputs = (outputs ?? []).filter((output) => hostListIsPlainHttp(output.hosts).length > 0).map((output) => asString(output.name) ?? asString(output.id) ?? "output");
    const outputsWithoutTrust = (outputs ?? [])
      .filter((output) => asString(output.type) === "elasticsearch" && !asString(output.ca_sha256) && !asString(output.ca_trusted_fingerprint) && !asObject(output.ssl))
      .map((output) => asString(output.name) ?? asString(output.id) ?? "output");
    const insecureFleetServers = (fleetServerHosts ?? []).filter((host) => hostListIsPlainHttp(host.host_urls).length > 0).map((host) => asString(host.name) ?? asString(host.id) ?? "fleet-server");
    const unprotectedPolicies = (agentPolicies ?? []).filter((policy) => asBoolean(policy.is_protected) !== true).map((policy) => asString(policy.name) ?? asString(policy.id) ?? "policy");
    const activeKeys = (enrollmentKeys ?? []).filter((key) => asBoolean(key.active) !== false);
    const keysPerPolicy = new Map<string, number>();
    for (const key of activeKeys) {
      const policyId = asString(key.policy_id) ?? "unassigned";
      keysPerPolicy.set(policyId, (keysPerPolicy.get(policyId) ?? 0) + 1);
    }
    const crowdedPolicies = [...keysPerPolicy.entries()].filter(([, count]) => count > maxEnrollmentKeys).map(([policyId, count]) => ({ policy_id: policyId, active_keys: count }));
    const fleetProblems = dependencyProblems(snapshot, ["fleet_agent_policies", "fleet_outputs", "fleet_enrollment_api_keys", "fleet_server_hosts"]);
    const fleetPartial = truncationNotes(snapshot, ["fleet_agent_policies", "fleet_outputs", "fleet_enrollment_api_keys", "fleet_server_hosts"]);
    const enrollmentKeysReadable = enrollmentKeys !== undefined;
    const fleetEvidence: JsonRecord = {
      kibana_space_queried: kibanaSpaceId ?? "default",
      inventories: [
        inventoryState(snapshot, "fleet_agent_policies", agentPolicies?.length),
        inventoryState(snapshot, "fleet_outputs", outputs?.length),
        inventoryState(snapshot, "fleet_server_hosts", fleetServerHosts?.length),
        inventoryState(snapshot, "fleet_enrollment_api_keys", enrollmentKeys?.length),
      ],
      agent_policies: agentPolicies?.length ?? null,
      outputs: outputs?.length ?? null,
      fleet_server_hosts: fleetServerHosts?.length ?? null,
      enrollment_keys_active: countWhenRead(enrollmentKeysReadable, activeKeys.length),
      enrollment_keys_inactive: countWhenRead(enrollmentKeysReadable, (enrollmentKeys ?? []).length - activeKeys.length),
      insecure_outputs: principalsWhenComplete(outputsComplete, insecureOutputs),
      outputs_without_ca_trust: principalsWhenComplete(outputsComplete, outputsWithoutTrust),
      insecure_fleet_server_hosts: principalsWhenComplete(hostsComplete, insecureFleetServers),
      unprotected_policies: principalsWhenComplete(policiesComplete, unprotectedPolicies),
      unprotected_policy_count: countWhenRead(policiesComplete, unprotectedPolicies.length),
      policies_over_enrollment_key_threshold: principalsWhenComplete(keysComplete, crowdedPolicies),
      max_enrollment_keys_per_policy: maxEnrollmentKeys,
    };
    const fleetCollect = "Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys (GET /api/fleet/agent_policies, GET /api/fleet/outputs, GET /api/fleet/fleet_server_hosts, GET /api/fleet/enrollment_api_keys).";
    const fleetFailed = insecureOutputs.length > 0 || insecureFleetServers.length > 0;
    const fleetEmpty = agentPolicies !== undefined && agentPolicies.length === 0;
    const outputsEmpty = agentPolicies !== undefined && agentPolicies.length > 0 && outputs !== undefined && outputs.length === 0;
    if (!fleetFailed && fleetProblems.length === 0 && fleetEmpty) {
      findings.push(manualFinding(
        21,
        "medium",
        `Not applicable: zero Fleet agent policies exist in the ${kibanaSpaceId ?? "default"} space, so Fleet enrollment and output hardening has nothing to evaluate (emptiness is reported as manual, not pass).`,
        "confirmation that Fleet and Elastic Agent are not in use in any space, or the policies from the space where Fleet is managed.",
        { ...fleetEvidence, unreadable_sources: [], partial_sources: fleetPartial, unchecked_sources: [] },
      ));
    } else {
      findings.push(guardedFinding(21, "medium", {
        status: fleetFailed
          ? "fail"
          : unprotectedPolicies.length > 0 || crowdedPolicies.length > 0 || outputsWithoutTrust.length > 0 || outputsEmpty || (fleetServerHosts !== undefined && fleetServerHosts.length === 0)
            ? "warn"
            : "pass",
        summary: fleetFailed
          ? `${insecureOutputs.length} Fleet output(s) and ${insecureFleetServers.length} Fleet Server host(s) use plain http.`
          : fleetProblems.length > 0
            ? "the readable Fleet inventories show no plain-http destination, but the Fleet picture is incomplete."
            : outputsEmpty
              ? `${agentPolicies?.length ?? 0} agent policies exist but zero Fleet outputs were returned although Fleet always defines a default output, so output hardening could not be verified.`
              : (fleetServerHosts ?? []).length === 0
                ? `${agentPolicies?.length ?? 0} agent policies exist but no Fleet Server hosts are registered, so agent enrollment transport could not be verified.`
                : unprotectedPolicies.length > 0 || crowdedPolicies.length > 0 || outputsWithoutTrust.length > 0
                  ? `${unprotectedPolicies.length}/${agentPolicies?.length ?? 0} agent policies lack tamper protection (is_protected is not true), ${crowdedPolicies.length} policies exceed ${maxEnrollmentKeys} active enrollment keys, and ${outputsWithoutTrust.length} Elasticsearch outputs pin no CA trust.`
                  : `All ${agentPolicies?.length ?? 0} agent policies are tamper protected, ${outputs?.length ?? 0} outputs and ${fleetServerHosts?.length ?? 0} Fleet Server hosts use https with CA trust, and enrollment keys stay within ${maxEnrollmentKeys} per policy.`,
        evidence: fleetEvidence,
      }, { problems: fleetProblems, partial: fleetPartial, collect: fleetCollect }));
    }
  }

  return {
    area: "kibana",
    title: "Elastic Kibana governance and Fleet",
    summary: {
      kibana_configured: !kibanaSkipped,
      kibana_space: kibanaSpaceId ?? "default",
      kibana_version: asString(getNestedValue(status, ["version", "number"])) ?? null,
      kibana_status: asString(getNestedValue(status, ["status", "overall", "level"])) ?? asString(getNestedValue(status, ["status", "overall", "state"])) ?? null,
      spaces: spaces?.length ?? null,
      kibana_roles: roles?.length ?? null,
      global_all_roles: countWhenRead(rolesReadable, globalAllRoles.length),
      agent_policies: agentPolicies?.length ?? null,
      fleet_outputs: outputs?.length ?? null,
      fleet_server_hosts: fleetServerHosts?.length ?? null,
      enrollment_keys: enrollmentKeys?.length ?? null,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
    not_collected: listSnapshotSkips(snapshot),
    truncated: listSnapshotTruncations(snapshot),
  };
}

export function evaluateElasticArea(
  area: ElasticAssessmentArea,
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  context: { now?: number; elasticsearchUrl?: string; kibanaSpaceId?: string } = {},
): ElasticAssessmentResult {
  const now = context.now ?? Date.now();
  switch (area) {
    case "identity":
      return evaluateElasticIdentity(snapshot, options, now);
    case "access_control":
      return evaluateElasticAccessControl(snapshot, options);
    case "transport_security":
      return evaluateElasticTransportSecurity(snapshot, options, now, context.elasticsearchUrl);
    case "cluster_hardening":
      return evaluateElasticClusterHardening(snapshot, options, now, context.kibanaSpaceId);
    case "kibana":
      return evaluateElasticKibana(snapshot, options, context.kibanaSpaceId);
    default: {
      const exhaustive: never = area;
      throw new Error(`Unsupported Elastic assessment area: ${String(exhaustive)}`);
    }
  }
}

async function assessArea(
  area: ElasticAssessmentArea,
  client: ElasticPartialReader,
  options: ElasticAssessmentOptions,
): Promise<ElasticAssessmentResult> {
  const snapshot = await collectElasticSnapshot(client, ELASTIC_AREA_DATASETS[area], options);
  const config = client.getResolvedConfig();
  return evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl, kibanaSpaceId: config.kibanaSpaceId });
}

export async function assessElasticIdentity(client: ElasticPartialReader, options: ElasticAssessmentOptions = {}): Promise<ElasticAssessmentResult> {
  return assessArea("identity", client, options);
}

export async function assessElasticAccessControl(client: ElasticPartialReader, options: ElasticAssessmentOptions = {}): Promise<ElasticAssessmentResult> {
  return assessArea("access_control", client, options);
}

export async function assessElasticTransportSecurity(client: ElasticPartialReader, options: ElasticAssessmentOptions = {}): Promise<ElasticAssessmentResult> {
  return assessArea("transport_security", client, options);
}

export async function assessElasticClusterHardening(client: ElasticPartialReader, options: ElasticAssessmentOptions = {}): Promise<ElasticAssessmentResult> {
  return assessArea("cluster_hardening", client, options);
}

export async function assessElasticKibana(client: ElasticPartialReader, options: ElasticAssessmentOptions = {}): Promise<ElasticAssessmentResult> {
  return assessArea("kibana", client, options);
}

const CORE_ACCESS_SURFACES: ElasticDatasetName[] = [
  "authenticate",
  "license",
  "xpack_usage",
  "cluster_settings",
  "node_settings",
  "ssl_certificates",
  "users",
  "roles",
  "role_mappings",
  "api_keys",
];

const ACCESS_SURFACES: ElasticDatasetName[] = [
  ...CORE_ACCESS_SURFACES,
  "xpack_info",
  "ilm_status",
  "ilm_policies",
  "slm_status",
  "slm_policies",
  "snapshot_repositories",
  "watches",
  "ingest_pipelines",
  "kibana_status",
  "kibana_spaces",
  "kibana_roles",
  "fleet_agent_policies",
  "fleet_outputs",
  "fleet_enrollment_api_keys",
  "fleet_server_hosts",
  "detection_rules",
  "alerting_rules",
  "connectors",
  "cloud_deployments",
];

function datasetCount(dataset: ElasticDataset): number | undefined {
  if (Array.isArray(dataset.data)) return dataset.data.length;
  const object = asObject(dataset.data);
  if (!object) return undefined;
  if (dataset.name === "node_settings") return Object.keys(asObject(object.nodes) ?? {}).length;
  if (dataset.name === "users" || dataset.name === "roles" || dataset.name === "role_mappings" || dataset.name === "ilm_policies" || dataset.name === "slm_policies" || dataset.name === "snapshot_repositories" || dataset.name === "ingest_pipelines") {
    return Object.keys(object).length;
  }
  return 1;
}

function missingPrivilegeSummary(privileges: JsonRecord): { cluster: string[]; index: string[] } {
  const cluster = asObject(privileges.cluster) ?? {};
  const granted = (name: string) => asBoolean(cluster[name]) === true;
  const missing: string[] = [];
  if (!granted("monitor")) missing.push("monitor");
  if (!granted("read_security") && !granted("manage_security")) missing.push("read_security (or manage_security)");
  if (!granted("manage_api_key") && !granted("manage_security")) missing.push("manage_api_key (needed for API key limited_by visibility)");
  if (!granted("read_pipeline") && !granted("manage_pipeline")) missing.push("read_pipeline (or manage_pipeline)");
  if (!granted("monitor_snapshot")) missing.push("monitor_snapshot");
  if (!granted("read_ilm") && !granted("manage_ilm")) missing.push("read_ilm (or manage_ilm)");
  if (!granted("read_slm") && !granted("manage_slm")) missing.push("read_slm (or manage_slm)");
  if (!granted("monitor_watcher")) missing.push("monitor_watcher");
  const indexMissing: string[] = [];
  for (const [indexName, value] of Object.entries(asObject(privileges.index) ?? {})) {
    for (const [privilege, allowed] of Object.entries(asObject(value) ?? {})) {
      if (asBoolean(allowed) === false) indexMissing.push(`${indexName}:${privilege}`);
    }
  }
  return { cluster: missing, index: indexMissing };
}

export async function checkElasticAccess(client: ElasticPartialReader): Promise<ElasticAccessCheckResult> {
  const config = client.getResolvedConfig();
  const snapshot = await collectElasticSnapshot(client, ACCESS_SURFACES, { apiKeyLimit: 100, watchLimit: 100, kibanaLimit: 100 });
  const surfaces: ElasticAccessSurface[] = ACCESS_SURFACES.map((name) => {
    const dataset = snapshot[name] ?? { name, target: DATASET_SPECS[name].target, endpoint: DATASET_SPECS[name].endpoint, skipped: "not requested" };
    const collected = dataset.error === undefined && dataset.skipped === undefined;
    return {
      name,
      target: dataset.target,
      endpoint: dataset.skipped ? null : dataset.endpoint,
      status: dataset.skipped ? "not_configured" : dataset.error ? "not_readable" : "readable",
      collected,
      http_status: dataset.status ?? null,
      count: collected ? datasetCount(dataset) ?? null : null,
      truncated: collected ? dataset.page?.truncated ?? null : null,
      error: dataset.error ?? dataset.skipped,
    };
  });

  let privileges: JsonRecord | undefined;
  let privilegeError: string | undefined;
  const privilegeProbeAvailable = typeof client.hasPrivileges === "function";
  try {
    privileges = privilegeProbeAvailable ? await client.hasPrivileges?.() : undefined;
  } catch (error) {
    privilegeError = redactSecrets(errorMessage(error), config);
  }
  const missing = privileges ? missingPrivilegeSummary(privileges) : undefined;

  const authenticated = datasetData<JsonRecord>(snapshot, "authenticate");
  const coreReadable = CORE_ACCESS_SURFACES.every((name) => snapshot[name]?.error === undefined && snapshot[name]?.skipped === undefined);
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const configuredCount = surfaces.filter((surface) => surface.status !== "not_configured").length;
  const status: ElasticAccessCheckResult["status"] = coreReadable && missing !== undefined && missing.cluster.length === 0 ? "healthy" : "limited";
  const notes = [
    `Using Elasticsearch ${config.elasticsearchUrl} with ${config.authMode} authentication.`,
    config.kibanaUrl ? `Kibana ${config.kibanaUrl}${config.kibanaSpaceId ? ` (space ${config.kibanaSpaceId})` : ""} is configured.` : "Kibana is not configured (set KIBANA_URL to enable Kibana checks).",
    config.cloudApiKey ? `Elastic Cloud API ${config.cloudApiUrl} is configured.` : "Elastic Cloud API key is not configured (optional).",
    authenticated
      ? `Authenticated as ${asString(authenticated.username) ?? "unknown"} via ${asString(getNestedValue(authenticated, ["authentication_realm", "type"])) ?? "unknown"} realm with roles ${asStringList(authenticated.roles).join(", ") || "(none)"}.`
      : `Authentication probe failed: ${datasetProblem(snapshot, "authenticate")}.`,
    `${readableCount}/${configuredCount} configured audit surfaces are readable.`,
    ...(privilegeError ? [`Privilege probe failed, so missing privileges are unknown: ${privilegeError}`] : []),
    ...(!privilegeProbeAvailable ? ["Privilege probe not available on this client, so missing privileges are unknown."] : []),
    ...(missing && missing.cluster.length > 0 ? [`Missing cluster privileges: ${missing.cluster.join(", ")}.`] : []),
    ...(missing && missing.index.length > 0 ? [`Missing index privileges: ${missing.index.join(", ")}.`] : []),
  ];

  return {
    status,
    elasticsearchUrl: config.elasticsearchUrl,
    kibanaUrl: config.kibanaUrl,
    cloudConfigured: Boolean(config.cloudApiKey),
    authenticatedAs: asString(authenticated?.username),
    authenticationRealm: asString(getNestedValue(authenticated, ["authentication_realm", "type"])),
    surfaces,
    missingClusterPrivileges: missing?.cluster ?? null,
    missingIndexPrivileges: missing?.index ?? null,
    privilegeProbe: missing ? "readable" : privilegeError ? "not_readable" : "not_available",
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run elastic_assess_identity, elastic_assess_access_control, elastic_assess_transport_security, elastic_assess_cluster_hardening, elastic_assess_kibana, or elastic_export_audit_bundle."
      : "Grant the auditing principal the monitor, read_security (or manage_security), manage_api_key, read_pipeline, monitor_snapshot, read_ilm, read_slm, and monitor_watcher cluster privileges, and set KIBANA_URL for Kibana checks.",
  };
}

function formatAccessCheckText(result: ElasticAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.target,
    surface.status,
    surface.count === null ? "unknown" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `Elastic access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Target", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ElasticAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${value === null || value === undefined ? "unread" : Array.isArray(value) ? value.join(", ") || "(none)" : String(value)}`)
    .join("\n");

  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)] : []),
    ...(result.truncated.length > 0 ? ["", "Truncated inventories:", ...result.truncated.map((entry) => `- ${entry}`)] : []),
    ...(result.not_collected.length > 0 ? ["", "Not collected:", ...result.not_collected.map((entry) => `- ${entry}`)] : []),
  ].join("\n");
}

function countByStatus(findings: ElasticFinding[]): Record<ElasticFinding["status"], number> {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

function buildExecutiveSummary(config: ElasticResolvedConfig, assessments: ElasticAssessmentResult[], errors: string[], truncated: string[] = [], notCollected: string[] = []): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const severityOrder: Record<ElasticFinding["severity"], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  return [
    "# Elastic Security Audit: Executive Summary",
    "",
    `Elasticsearch: ${config.elasticsearchUrl}`,
    `Kibana: ${config.kibanaUrl ?? "not configured"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual controls: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    `- Collection errors: ${errors.length}${errors.length > 0 ? " (see _errors.log)" : ""}`,
    `- Truncated inventories: ${truncated.length}${truncated.length > 0 ? " (see collection_status.json)" : ""}`,
    `- Datasets not collected (target not configured): ${notCollected.length}`,
    "",
    ...(truncated.length > 0 ? ["## Truncated Inventories", "", ...truncated.map((entry) => `- ${entry}`), ""] : []),
    "## Assessment Areas",
    "",
    ...assessments.map((assessment) => {
      const areaCounts = countByStatus(assessment.findings);
      return `- ${assessment.title}: ${areaCounts.fail} fail, ${areaCounts.warn} warn, ${areaCounts.manual} manual, ${areaCounts.pass} pass`;
    }),
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((left, right) => severityOrder[left.severity] - severityOrder[right.severity])
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Required",
    "",
    ...(findings.filter((item) => item.status === "manual").length > 0
      ? findings.filter((item) => item.status === "manual").map((item) => `- ${item.id} ${item.title}: ${asString(item.evidence?.manual_evidence) ?? item.summary}`)
      : ["- None"]),
  ].join("\n");
}

function buildUnifiedMatrix(findings: ElasticFinding[]): string {
  const rows = findings.map((item) => {
    const control = ELASTIC_CONTROLS.find((entry) => entry.id === item.id);
    const cells = ELASTIC_FRAMEWORKS.map((framework) =>
      item.mappings.find((mapping) => mapping.startsWith(framework.prefix))?.slice(framework.prefix.length) ?? "-",
    );
    return [item.id, String(control?.number ?? ""), item.status.toUpperCase(), item.severity.toUpperCase(), item.title, ...cells];
  });
  return [
    "# Elastic Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Spec #", "Status", "Severity", "Control", ...ELASTIC_FRAMEWORKS.map((framework) => framework.label)], rows),
  ].join("\n");
}

function buildFrameworkReport(framework: { key: ElasticFrameworkKey; label: string; prefix: string }, findings: ElasticFinding[]): string {
  const rows = findings.map((item) => {
    const mapping = item.mappings.find((entry) => entry.startsWith(framework.prefix))?.slice(framework.prefix.length) ?? "-";
    return [mapping, item.id, item.status.toUpperCase(), item.severity.toUpperCase(), item.title, item.summary];
  }).sort((left, right) => left[0].localeCompare(right[0]));
  const counts = countByStatus(findings);
  return [
    `# ${framework.label} Control Report (Elastic)`,
    "",
    `Controls assessed: ${findings.length} (${counts.fail} fail, ${counts.warn} warn, ${counts.manual} manual, ${counts.pass} pass)`,
    "",
    formatTable([`${framework.label} Control`, "Finding", "Status", "Severity", "Title", "Summary"], rows),
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# Elastic Audit Bundle: Quick Reference",
    "",
    "This bundle was generated by grclanker's native Elastic security inspector tools (read-only).",
    "",
    "## Start Here",
    "",
    "1. `compliance/executive_summary.md`: prioritized findings and manual evidence list",
    "2. `compliance/unified_compliance_matrix.md`: every finding with FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP mappings",
    "3. `compliance/frameworks/<framework>.md`: one report per framework",
    "",
    "## Contents",
    "",
    "- `core_data/*.json`: API snapshots projected to the fields the checks read (secrets redacted, connector/watch/pipeline literals dropped, Fleet enrollment api_key values removed)",
    "- `collection_status.json`: per-dataset read status, HTTP status of failures, counts, and truncation; flags are null for datasets that were not read",
    "- `analysis/findings.json`: normalized findings for all 23 spec controls",
    "- `analysis/<area>.json`: per-area assessment output with summaries",
    "- `analysis/access.json`: readable surface inventory and missing privileges",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: appears only when some reads failed but the bundle still completed",
    "",
    "## Status Semantics",
    "",
    "- `pass`: API evidence shows the control is satisfied",
    "- `warn`: partially satisfied or not fully confirmable from the visible data",
    "- `fail`: API evidence shows the control is violated",
    "- `manual`: cannot be verified through the API; the summary states exactly what a human must collect",
    "",
    "## Reading Unread Data",
    "",
    "- A `core_data` file whose `collected` is false is a not-collected marker (`status` carries the observed HTTP status, `error` the redacted message); it is never an empty list",
    "- Counts, lists, and flags derived from an inventory that was denied, errored, or truncated render `null` in findings and summaries; `[]` and `0` always mean the inventory was read and is empty",
    "- Named principals (users, keys, roles, policies) are listed only from inventories that were read completely",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

/** Marker written in place of a list whenever the dataset was denied, errored, or never requested, so a consumer cannot mistake it for an empty inventory. */
export interface ElasticNotCollectedMarker {
  collected: false;
  status: number | "error" | "not-collected";
  /** The endpoint that failed; null when the dataset was never requested, so no unobserved endpoint is named. */
  endpoint: string | null;
  target: ElasticTarget;
  error: string | null;
  reason: "not_readable" | "not_configured";
}

function notCollectedMarker(dataset: ElasticDataset): ElasticNotCollectedMarker {
  return {
    collected: false,
    status: dataset.skipped ? "not-collected" : dataset.status ?? "error",
    endpoint: dataset.skipped ? null : dataset.endpoint,
    target: dataset.target,
    error: dataset.error ?? dataset.skipped ?? null,
    reason: dataset.skipped ? "not_configured" : "not_readable",
  };
}

/** Builds the core_data file for a dataset: the payload when it was read, or the not-collected marker when it was not. */
export function coreDataFile(dataset: ElasticDataset): JsonRecord {
  const collected = dataset.error === undefined && dataset.skipped === undefined;
  if (!collected) {
    const marker = notCollectedMarker(dataset);
    return { ...marker, page: null, data: marker };
  }
  return {
    collected: true,
    status: "readable",
    endpoint: dataset.endpoint,
    target: dataset.target,
    error: null,
    page: dataset.page ?? null,
    data: dataset.data ?? null,
  };
}

/** Per-dataset collection status; flags and counters render null for datasets whose read never completed. */
export function buildCollectionStatus(snapshot: ElasticSnapshot): JsonRecord {
  const datasets = Object.values(snapshot).filter((dataset): dataset is ElasticDataset => Boolean(dataset)).map((dataset) => {
    const collected = dataset.error === undefined && dataset.skipped === undefined;
    return {
      name: dataset.name,
      endpoint: dataset.skipped ? null : dataset.endpoint,
      target: dataset.target,
      status: collected ? "readable" : dataset.skipped ? "not_configured" : "not_readable",
      collected,
      http_status: dataset.status ?? null,
      count: collected ? datasetCount(dataset) ?? null : null,
      paged: collected ? dataset.page !== undefined : null,
      truncated: collected ? dataset.page?.truncated ?? null : null,
      seen: collected ? dataset.page?.seen ?? null : null,
      total: collected ? dataset.page?.total ?? null : null,
      pages: collected ? dataset.page?.pages ?? null : null,
      error: dataset.error ?? dataset.skipped ?? null,
    };
  });
  const collected = datasets.filter((dataset) => dataset.collected);
  return {
    datasets,
    totals: {
      datasets: datasets.length,
      readable: collected.length,
      not_readable: datasets.filter((dataset) => dataset.status === "not_readable").length,
      not_configured: datasets.filter((dataset) => dataset.status === "not_configured").length,
      truncated: collected.filter((dataset) => dataset.truncated === true).length,
      // Datasets that were never read cannot be classified as complete or truncated.
      truncation_unknown: datasets.length - collected.length,
    },
  };
}

export async function exportElasticAuditBundle(
  client: ElasticPartialReader,
  config: ElasticResolvedConfig,
  outputRoot: string,
  options: ElasticAssessmentOptions = {},
): Promise<ElasticAuditBundleResult> {
  const access = await checkElasticAccess(client);
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, options);
  const areas: ElasticAssessmentArea[] = ["identity", "access_control", "transport_security", "cluster_hardening", "kibana"];
  const assessments = areas.map((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl, kibanaSpaceId: config.kibanaSpaceId }));
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = listSnapshotErrors(snapshot);
  const truncated = listSnapshotTruncations(snapshot);
  const notCollected = listSnapshotSkips(snapshot);

  ensurePrivateDir(outputRoot);
  const clusterLabel = safeDirName(new URL(config.elasticsearchUrl).hostname);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${clusterLabel}-audit-bundle`);

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    elasticsearch_url: config.elasticsearchUrl,
    kibana_url: config.kibanaUrl ?? null,
    kibana_space_id: config.kibanaSpaceId ?? null,
    cloud_api_configured: Boolean(config.cloudApiKey),
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
    controls_covered: ELASTIC_CONTROLS.length,
  }));

  for (const dataset of Object.values(snapshot)) {
    if (!dataset) continue;
    await writeSecureTextFile(outputDir, `core_data/${dataset.name}.json`, serializeJson(coreDataFile(dataset)));
  }
  await writeSecureTextFile(outputDir, "collection_status.json", serializeJson(buildCollectionStatus(snapshot)));

  await writeSecureTextFile(outputDir, "analysis/access.json", serializeJson(access));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
  }

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments, errors, truncated, notCollected)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of ELASTIC_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.key}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }

  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = bundleZipPathFor(outputDir);
  if (existsSync(zipPath)) {
    throw new Error(`Refusing to overwrite an existing bundle archive: ${zipPath}`);
  }
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
    truncatedCount: truncated.length,
    notCollectedCount: notCollected.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    elasticsearch_url: asString(value.elasticsearch_url) ?? asString(value.url),
    kibana_url: asString(value.kibana_url),
    space_id: asString(value.space_id),
    api_key: asString(value.api_key),
    username: asString(value.username),
    password: asString(value.password),
    bearer_token: asString(value.bearer_token),
    cloud_api_key: asString(value.cloud_api_key),
    cloud_api_url: asString(value.cloud_api_url),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeAssessmentArgs(args: unknown): AssessmentArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    api_key_limit: asNumber(value.api_key_limit),
    max_api_key_age_days: asNumber(value.max_api_key_age_days),
    max_superusers: asNumber(value.max_superusers),
    sensitive_index_patterns: asStringList(value.sensitive_index_patterns),
    tenant_index_patterns: asStringList(value.tenant_index_patterns),
    cert_expiry_warning_days: asNumber(value.cert_expiry_warning_days),
    watch_limit: asNumber(value.watch_limit),
    kibana_limit: asNumber(value.kibana_limit),
    max_enrollment_keys_per_policy: asNumber(value.max_enrollment_keys_per_policy),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessmentArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function assessmentOptionsFromArgs(args: AssessmentArgs): ElasticAssessmentOptions {
  return {
    apiKeyLimit: args.api_key_limit,
    maxApiKeyAgeDays: args.max_api_key_age_days,
    maxSuperusers: args.max_superusers,
    sensitiveIndexPatterns: args.sensitive_index_patterns,
    tenantIndexPatterns: args.tenant_index_patterns,
    certExpiryWarningDays: args.cert_expiry_warning_days,
    watchLimit: args.watch_limit,
    kibanaLimit: args.kibana_limit,
    maxEnrollmentKeysPerPolicy: args.max_enrollment_keys_per_policy,
  };
}

function createClient(args: CheckAccessArgs): ElasticApiClient {
  return new ElasticApiClient(resolveElasticConfiguration(args));
}

const authParams = {
  elasticsearch_url: Type.Optional(Type.String({ description: "Elasticsearch base URL, for example https://es.example.com:9200. Defaults to ELASTIC_URL or the config file." })),
  kibana_url: Type.Optional(Type.String({ description: "Kibana base URL, for example https://kibana.example.com:5601. Defaults to KIBANA_URL. Kibana controls become manual findings when omitted." })),
  space_id: Type.Optional(Type.String({ description: "Kibana space ID for space-aware API paths (/s/{space}/api/...). Defaults to KIBANA_SPACE_ID or the default space." })),
  api_key: Type.Optional(Type.String({ description: "Elasticsearch API key as base64(id:api_key) or id:api_key. Defaults to ELASTIC_API_KEY. Prefer environment variables over arguments." })),
  username: Type.Optional(Type.String({ description: "Basic auth username. Defaults to ELASTIC_USERNAME." })),
  password: Type.Optional(Type.String({ description: "Basic auth password. Defaults to ELASTIC_PASSWORD. Prefer environment variables over arguments." })),
  bearer_token: Type.Optional(Type.String({ description: "OAuth2/SAML/OIDC bearer access token. Defaults to ELASTIC_BEARER_TOKEN." })),
  cloud_api_key: Type.Optional(Type.String({ description: "Elastic Cloud API key for deployment inventory. Defaults to ELASTIC_CLOUD_API_KEY (optional)." })),
  cloud_api_url: Type.Optional(Type.String({ description: `Elastic Cloud API base URL. Defaults to ELASTIC_CLOUD_API_URL or ${DEFAULT_CLOUD_API_URL}.` })),
  config_file: Type.Optional(Type.String({ description: "Path to a YAML config file. Defaults to ~/.elastic-sec-inspector/config.yaml." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to ELASTIC_TIMEOUT or 30.", default: 30 })),
};

const assessmentParams = {
  ...authParams,
  api_key_limit: Type.Optional(Type.Number({ description: "Maximum API keys to page through. Defaults to 1000.", default: DEFAULT_API_KEY_LIMIT })),
  max_api_key_age_days: Type.Optional(Type.Number({ description: "Maximum acceptable API key age in days before flagging. Defaults to 90.", default: DEFAULT_MAX_API_KEY_AGE_DAYS })),
  max_superusers: Type.Optional(Type.Number({ description: "Maximum acceptable native users holding superuser. Defaults to 2.", default: DEFAULT_MAX_SUPERUSERS })),
  sensitive_index_patterns: Type.Optional(Type.Array(Type.String(), { description: "Index patterns that must be covered by field-level security, for example customers-*." })),
  tenant_index_patterns: Type.Optional(Type.Array(Type.String(), { description: "Multi-tenant index patterns that must be covered by document-level security." })),
  cert_expiry_warning_days: Type.Optional(Type.Number({ description: "Days before certificate expiry that triggers a warning. Defaults to 30.", default: DEFAULT_CERT_EXPIRY_WARNING_DAYS })),
  watch_limit: Type.Optional(Type.Number({ description: "Maximum Watcher watches to inspect. Defaults to 500.", default: DEFAULT_WATCH_LIMIT })),
  kibana_limit: Type.Optional(Type.Number({ description: "Maximum items per paginated Kibana collection. Defaults to 1000.", default: DEFAULT_KIBANA_LIMIT })),
  max_enrollment_keys_per_policy: Type.Optional(Type.Number({ description: "Maximum active Fleet enrollment keys per agent policy before warning. Defaults to 3.", default: DEFAULT_MAX_ENROLLMENT_KEYS_PER_POLICY })),
};

function registerAssessmentTool(
  pi: ToolRegistrar,
  definition: {
    name: string;
    label: string;
    description: string;
    run: (client: ElasticApiClient, options: ElasticAssessmentOptions) => Promise<ElasticAssessmentResult>;
  },
): void {
  pi.registerTool({
    name: definition.name,
    label: definition.label,
    description: definition.description,
    parameters: Type.Object(assessmentParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const result = await definition.run(createClient(args), assessmentOptionsFromArgs(args));
        return textResult(formatAssessmentText(result), { tool: definition.name, ...result });
      } catch (error) {
        return errorResult(
          `${definition.label} failed: ${toolErrorText(error)}`,
          { tool: definition.name },
        );
      }
    },
  });
}

export function registerElasticTools(pi: any): void {
  pi.registerTool({
    name: "elastic_check_access",
    label: "Check Elastic audit access",
    description:
      "Validate read-only access to Elasticsearch security, cluster, license, ILM/SLM, snapshot, Watcher, and ingest surfaces plus optional Kibana (spaces, roles, Fleet, detection and alerting rules, connectors) and Elastic Cloud deployment APIs, and report missing cluster or index privileges.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkElasticAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "elastic_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Elastic access check failed: ${toolErrorText(error)}`,
          { tool: "elastic_check_access" },
        );
      }
    },
  });

  registerAssessmentTool(pi, {
    name: "elastic_assess_identity",
    label: "Assess Elastic identity and authentication",
    description:
      "Assess Elasticsearch authentication realms (spec controls 1, 13), anonymous access (14), and API key hygiene and privilege scope (9, 10) from node settings, usage statistics, role mappings, and the query API keys endpoint.",
    run: assessElasticIdentity,
  });

  registerAssessmentTool(pi, {
    name: "elastic_assess_access_control",
    label: "Assess Elastic role-based access control",
    description:
      "Assess Elasticsearch roles, users, and role mappings for superuser overuse and overly permissive privileges (spec control 6) plus field-level (7) and document-level (8) security coverage, optionally verified against supplied index patterns.",
    run: assessElasticAccessControl,
  });

  registerAssessmentTool(pi, {
    name: "elastic_assess_transport_security",
    label: "Assess Elastic TLS posture",
    description:
      "Assess transport and HTTP layer TLS enforcement (spec controls 2, 3), minimum TLS protocol versions (4), and TLS certificate expiration (5) from node settings, cluster defaults, usage statistics, and the SSL certificates API.",
    run: assessElasticTransportSecurity,
  });

  registerAssessmentTool(pi, {
    name: "elastic_assess_cluster_hardening",
    label: "Assess Elastic cluster hardening",
    description:
      "Assess audit logging and its output (spec controls 11, 12), ILM retention (17), snapshot repository encryption and SLM (18), cluster security settings (19), Watcher and Kibana alerting connector security (20), ingest pipeline exposure (22), and license coverage of configured security features (23).",
    run: assessElasticClusterHardening,
  });

  registerAssessmentTool(pi, {
    name: "elastic_assess_kibana",
    label: "Assess Kibana spaces, roles, and Fleet",
    description:
      "Assess Kibana space isolation (spec control 15), Kibana role privileges (16), and Fleet agent policy, output, Fleet Server, and enrollment key security (21). Produces manual findings when KIBANA_URL is not configured.",
    run: assessElasticKibana,
  });

  pi.registerTool({
    name: "elastic_export_audit_bundle",
    label: "Export Elastic audit bundle",
    description:
      "Export an Elastic audit package with raw API snapshots (core_data/), normalized findings for all 23 spec controls (analysis/), an executive summary, unified compliance matrix, per-framework reports (compliance/), QUICK_REFERENCE.md, _errors.log on partial failure, and a zip archive.",
    parameters: Type.Object({
      ...assessmentParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveElasticConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportElasticAuditBundle(new ElasticApiClient(config), config, outputRoot, assessmentOptionsFromArgs(args));
        return textResult(
          [
            "Elastic audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
            `Truncated inventories: ${result.truncatedCount}${result.truncatedCount > 0 ? " (see collection_status.json)" : ""}`,
            `Datasets not collected: ${result.notCollectedCount}`,
          ].join("\n"),
          {
            tool: "elastic_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
            truncated_count: result.truncatedCount,
            not_collected_count: result.notCollectedCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Elastic audit bundle export failed: ${toolErrorText(error)}`,
          { tool: "elastic_export_audit_bundle" },
        );
      }
    },
  });
}
