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
import { parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

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
const SECRET_KEY_PATTERN = /^(password|passwd|secret|client_secret|secret_key|secure_key|access_key|secret_access_key|api_key|apikey|token|access_token|refresh_token|bearer_token|private_key|bind_password|credential|credentials|authorization)$/i;
const SECRET_KEY_SUFFIX_PATTERN = /(?:^|[._-])(?:password|passwd|secret|token|api_?key|private_?key|credentials?)$/i;
const SECRET_FIELD_NAME_PATTERN = /(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|credential)/i;

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
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
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
  missingClusterPrivileges: string[];
  missingIndexPrivileges: string[];
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
  errors: string[];
}

export interface ElasticAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface ElasticDataset<T = unknown> {
  name: string;
  endpoint: string;
  target: ElasticTarget;
  data?: T;
  error?: string;
  skipped?: string;
}

export type ElasticDatasetName =
  | "authenticate"
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
  | "ilm_policies"
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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

export function redactSecrets(text: string, config: Pick<ElasticResolvedConfig, "apiKey" | "password" | "bearerToken" | "cloudApiKey" | "username">): string {
  let output = text;
  const secrets = [
    config.apiKey,
    config.password,
    config.bearerToken,
    config.cloudApiKey,
    config.username && config.password ? encodeBase64(`${config.username}:${config.password}`) : undefined,
  ].filter((item): item is string => Boolean(item && item.length >= 4));
  for (const secret of secrets) {
    output = output.split(secret).join("[REDACTED]");
  }
  return output
    .replace(/(authorization\s*[:=]\s*)(?:apikey|basic|bearer)\s+\S+/gi, "$1[REDACTED]")
    .replace(/((?:api[_-]?key|password|secret|token)["']?\s*[:=]\s*["']?)([^"',\s}]+)/gi, "$1[REDACTED]");
}

function isSecretKey(key: string, parentKey: string | undefined): boolean {
  const segments = key.split(".");
  const last = segments[segments.length - 1] ?? key;
  if (SECRET_KEY_PATTERN.test(last) || SECRET_KEY_SUFFIX_PATTERN.test(last)) return true;
  return /^key$/i.test(last) && /^ssl$/i.test(parentKey ?? segments[segments.length - 2] ?? "");
}

export function redactSensitiveValues(value: unknown, depth = 0, parentKey?: string): unknown {
  if (depth > 12) return value;
  if (Array.isArray(value)) return value.map((item) => redactSensitiveValues(item, depth + 1, parentKey));
  const object = asObject(value);
  if (!object) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(object)) {
    if (isSecretKey(key, parentKey) && (typeof entry === "string" || typeof entry === "number")) {
      output[key] = "[REDACTED]";
    } else {
      output[key] = redactSensitiveValues(entry, depth + 1, key);
    }
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

function overlayFromConfigFile(location: string): ElasticConfigOverlay | undefined {
  if (!existsSync(location)) return undefined;
  const parsed = asObject(parseYaml(readFileSync(location, "utf8"))) ?? {};
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
  const fileOverlay = overlayFromConfigFile(configPath);
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
    super(message);
    this.name = "ElasticRequestError";
    this.status = status;
    this.target = target;
  }
}

function elasticErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const error = asObject(object.error);
  const candidates = [
    asString(error?.reason),
    asString(error?.type),
    asString(object.message),
    typeof object.error === "string" ? object.error : undefined,
    asString(object.statusCode) ? `statusCode ${asString(object.statusCode)}` : undefined,
  ];
  return candidates.filter((item): item is string => Boolean(item)).join(": ") || undefined;
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
    options: { method?: "GET" | "POST"; query?: JsonRecord; body?: unknown } = {},
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
        if (rawText.length > 0) {
          try {
            payload = JSON.parse(rawText);
          } catch {
            payload = { message: rawText.slice(0, 240) };
          }
        }
        if (!response.ok) {
          const detail = elasticErrorSummary(payload) ?? rawText.slice(0, 240);
          throw new ElasticRequestError(
            redactSecrets(
              `${target} request ${method} ${path} failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
              this.config,
            ),
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

  async esGet(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("elasticsearch", path, { query });
  }

  async esPost(path: string, body: unknown, query: JsonRecord = {}): Promise<unknown> {
    return this.request("elasticsearch", path, { method: "POST", body, query });
  }

  async kibanaGet(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("kibana", path, { query });
  }

  async cloudGet(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("cloud", path, { query });
  }

  async listKibanaPages(
    path: string,
    options: { perPageParam: "perPage" | "per_page"; itemsKey: "items" | "data"; limit?: number; query?: JsonRecord } ,
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_KIBANA_LIMIT, 1, 10_000);
    const perPage = Math.min(DEFAULT_KIBANA_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    for (let page = 1; items.length < limit; page += 1) {
      const payload = asObject(await this.kibanaGet(path, {
        ...(options.query ?? {}),
        page,
        [options.perPageParam]: perPage,
      })) ?? {};
      const pageItems = asObjectArray(payload[options.itemsKey]);
      items.push(...pageItems.slice(0, limit - items.length));
      const total = asNumber(payload.total);
      if (pageItems.length === 0 || pageItems.length < perPage || (total !== undefined && items.length >= total)) break;
    }
    return items;
  }

  async authenticate(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/_authenticate")) ?? {};
  }

  async hasPrivileges(clusterPrivileges: string[] = REQUIRED_CLUSTER_PRIVILEGES): Promise<JsonRecord> {
    return asObject(await this.esPost("/_security/user/_has_privileges", {
      cluster: clusterPrivileges,
      index: [{ names: [".security*"], privileges: ["read"], allow_restricted_indices: true }],
    })) ?? {};
  }

  async getLicense(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_license")) ?? {};
  }

  async getXpackInfo(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_xpack")) ?? {};
  }

  async getXpackUsage(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_xpack/usage")) ?? {};
  }

  async getClusterSettings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_cluster/settings", { include_defaults: true, flat_settings: true })) ?? {};
  }

  async getNodeSettings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_nodes/settings", { flat_settings: true })) ?? {};
  }

  async listSslCertificates(): Promise<JsonRecord[]> {
    return asObjectArray(await this.esGet("/_ssl/certificates"));
  }

  async listUsers(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/user")) ?? {};
  }

  async listRoles(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/role")) ?? {};
  }

  async listRoleMappings(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_security/role_mapping")) ?? {};
  }

  async listApiKeys(limit = DEFAULT_API_KEY_LIMIT): Promise<JsonRecord[]> {
    const maxItems = clampNumber(limit, DEFAULT_API_KEY_LIMIT, 1, 10_000);
    const size = Math.min(DEFAULT_API_KEY_PAGE_SIZE, maxItems);
    const items: JsonRecord[] = [];
    let searchAfter: unknown[] | undefined;
    while (items.length < maxItems) {
      const payload = asObject(await this.esPost("/_security/_query/api_key", {
        size,
        sort: [{ creation: { order: "asc" } }, { name: { order: "asc" } }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      }, { with_limited_by: true })) ?? {};
      const pageItems = asObjectArray(payload.api_keys);
      items.push(...pageItems.slice(0, maxItems - items.length));
      const last = pageItems[pageItems.length - 1];
      searchAfter = last ? asArray(last._sort) : undefined;
      if (pageItems.length < size || !searchAfter || searchAfter.length === 0) break;
    }
    return items;
  }

  async listIlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ilm/policy")) ?? {};
  }

  async listSlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_slm/policy")) ?? {};
  }

  async listSnapshotRepositories(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_snapshot/_all")) ?? {};
  }

  async listWatches(limit = DEFAULT_WATCH_LIMIT): Promise<JsonRecord[]> {
    const maxItems = clampNumber(limit, DEFAULT_WATCH_LIMIT, 1, 10_000);
    const size = Math.min(DEFAULT_WATCH_PAGE_SIZE, maxItems);
    const items: JsonRecord[] = [];
    for (let from = 0; items.length < maxItems; from += size) {
      const payload = asObject(await this.esPost("/_watcher/_query/watches", { from, size })) ?? {};
      const pageItems = asObjectArray(payload.watches);
      items.push(...pageItems.slice(0, maxItems - items.length));
      const total = asNumber(payload.count);
      if (pageItems.length < size || (total !== undefined && items.length >= total)) break;
    }
    return items;
  }

  async listIngestPipelines(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ingest/pipeline")) ?? {};
  }

  async getKibanaStatus(): Promise<JsonRecord> {
    return asObject(await this.kibanaGet("/api/status")) ?? {};
  }

  async listSpaces(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/spaces/space"));
  }

  async listKibanaRoles(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/security/role"));
  }

  async listAgentPolicies(limit = DEFAULT_KIBANA_LIMIT): Promise<JsonRecord[]> {
    return this.listKibanaPages("/api/fleet/agent_policies", { perPageParam: "perPage", itemsKey: "items", limit });
  }

  async listFleetOutputs(): Promise<JsonRecord[]> {
    return asObjectArray(asObject(await this.kibanaGet("/api/fleet/outputs"))?.items);
  }

  async listEnrollmentApiKeys(limit = DEFAULT_KIBANA_LIMIT): Promise<JsonRecord[]> {
    const items = await this.listKibanaPages("/api/fleet/enrollment_api_keys", { perPageParam: "perPage", itemsKey: "items", limit });
    return items.map((item) => ({ ...item, api_key: item.api_key === undefined ? undefined : "[REDACTED]" }));
  }

  async listFleetServerHosts(limit = DEFAULT_KIBANA_LIMIT): Promise<JsonRecord[]> {
    return this.listKibanaPages("/api/fleet/fleet_server_hosts", { perPageParam: "perPage", itemsKey: "items", limit });
  }

  async listDetectionRules(limit = DEFAULT_KIBANA_LIMIT): Promise<JsonRecord[]> {
    return this.listKibanaPages("/api/detection_engine/rules/_find", { perPageParam: "per_page", itemsKey: "data", limit });
  }

  async listAlertingRules(limit = DEFAULT_KIBANA_LIMIT): Promise<JsonRecord[]> {
    return this.listKibanaPages("/api/alerting/rules/_find", { perPageParam: "per_page", itemsKey: "data", limit });
  }

  async listConnectors(): Promise<JsonRecord[]> {
    return asObjectArray(await this.kibanaGet("/api/actions/connectors"));
  }

  async listCloudDeployments(): Promise<JsonRecord[]> {
    return asObjectArray(asObject(await this.cloudGet("/api/v1/deployments"))?.deployments);
  }
}

function isNetworkError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /fetch failed|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|socket hang up/i.test(`${error.message} ${String((error as { cause?: unknown }).cause ?? "")}`);
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
  | "listIlmPolicies"
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
  ilm_policies: { name: "ilm_policies", target: "elasticsearch", endpoint: "GET /_ilm/policy", load: (client) => requireMethod(client, "listIlmPolicies")() },
  slm_policies: { name: "slm_policies", target: "elasticsearch", endpoint: "GET /_slm/policy", load: (client) => requireMethod(client, "listSlmPolicies")() },
  snapshot_repositories: { name: "snapshot_repositories", target: "elasticsearch", endpoint: "GET /_snapshot/_all", load: (client) => requireMethod(client, "listSnapshotRepositories")() },
  watches: { name: "watches", target: "elasticsearch", endpoint: "POST /_watcher/_query/watches", load: (client, options) => requireMethod(client, "listWatches")(options.watchLimit) },
  ingest_pipelines: { name: "ingest_pipelines", target: "elasticsearch", endpoint: "GET /_ingest/pipeline", load: (client) => requireMethod(client, "listIngestPipelines")() },
  kibana_status: { name: "kibana_status", target: "kibana", endpoint: "GET /api/status", load: (client) => requireMethod(client, "getKibanaStatus")() },
  kibana_spaces: { name: "kibana_spaces", target: "kibana", endpoint: "GET /api/spaces/space", load: (client) => requireMethod(client, "listSpaces")() },
  kibana_roles: { name: "kibana_roles", target: "kibana", endpoint: "GET /api/security/role", load: (client) => requireMethod(client, "listKibanaRoles")() },
  fleet_agent_policies: { name: "fleet_agent_policies", target: "kibana", endpoint: "GET /api/fleet/agent_policies", load: (client, options) => requireMethod(client, "listAgentPolicies")(options.kibanaLimit) },
  fleet_outputs: { name: "fleet_outputs", target: "kibana", endpoint: "GET /api/fleet/outputs", load: (client) => requireMethod(client, "listFleetOutputs")() },
  fleet_enrollment_api_keys: { name: "fleet_enrollment_api_keys", target: "kibana", endpoint: "GET /api/fleet/enrollment_api_keys", load: (client, options) => requireMethod(client, "listEnrollmentApiKeys")(options.kibanaLimit) },
  fleet_server_hosts: { name: "fleet_server_hosts", target: "kibana", endpoint: "GET /api/fleet/fleet_server_hosts", load: (client, options) => requireMethod(client, "listFleetServerHosts")(options.kibanaLimit) },
  detection_rules: { name: "detection_rules", target: "kibana", endpoint: "GET /api/detection_engine/rules/_find", load: (client, options) => requireMethod(client, "listDetectionRules")(options.kibanaLimit) },
  alerting_rules: { name: "alerting_rules", target: "kibana", endpoint: "GET /api/alerting/rules/_find", load: (client, options) => requireMethod(client, "listAlertingRules")(options.kibanaLimit) },
  connectors: { name: "connectors", target: "kibana", endpoint: "GET /api/actions/connectors", load: (client) => requireMethod(client, "listConnectors")() },
  cloud_deployments: { name: "cloud_deployments", target: "cloud", endpoint: "GET /api/v1/deployments", load: (client) => requireMethod(client, "listCloudDeployments")() },
};

export const ELASTIC_AREA_DATASETS: Record<ElasticAssessmentArea, ElasticDatasetName[]> = {
  identity: ["node_settings", "cluster_settings", "xpack_usage", "roles", "role_mappings", "api_keys"],
  access_control: ["license", "xpack_usage", "users", "roles", "role_mappings"],
  transport_security: ["node_settings", "cluster_settings", "xpack_usage", "ssl_certificates"],
  cluster_hardening: [
    "node_settings",
    "cluster_settings",
    "xpack_usage",
    "xpack_info",
    "license",
    "roles",
    "ilm_policies",
    "slm_policies",
    "snapshot_repositories",
    "watches",
    "ingest_pipelines",
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
      const data = await spec.load(client, options);
      snapshot[name] = { name, target: spec.target, endpoint: spec.endpoint, data: redactSensitiveValues(data) };
    } catch (error) {
      snapshot[name] = {
        name,
        target: spec.target,
        endpoint: spec.endpoint,
        error: redactSecrets(errorMessage(error), config),
      };
    }
  }));
  return snapshot;
}

export function listSnapshotErrors(snapshot: ElasticSnapshot): string[] {
  return Object.values(snapshot)
    .filter((dataset): dataset is ElasticDataset => Boolean(dataset?.error))
    .map((dataset) => `${dataset.name} (${dataset.endpoint}): ${dataset.error}`);
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
  const view = buildSettingsView(datasetData<JsonRecord>(snapshot, "node_settings"), datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const roleMappings = datasetData<JsonRecord>(snapshot, "role_mappings");
  const apiKeys = datasetData<JsonRecord[]>(snapshot, "api_keys");
  const findings: ElasticFinding[] = [];

  const realms = parseRealms(view).filter((realm) => realm.enabled);
  const usageTypes = usageRealmTypes(usage);
  const realmTypes = new Set([...realms.map((realm) => realm.type), ...usageTypes]);
  const secureRealmTypes = [...realmTypes].filter((type) => SECURE_REALM_TYPES.has(type));
  const realmEvidence = realms.map((realm) => ({ type: realm.type, name: realm.name, order: realm.order ?? null }));

  if (!view.available && !usage) {
    findings.push(manualFinding(
      1,
      "high",
      `Realm settings could not be read (${datasetProblem(snapshot, "node_settings")}; ${datasetProblem(snapshot, "xpack_usage")}).`,
      "the xpack.security.authc.realms.* section of elasticsearch.yml from every node, or the Elastic Cloud deployment security settings page.",
    ));
  } else {
    findings.push(finding(
      1,
      "high",
      secureRealmTypes.length > 0 ? "pass" : "fail",
      secureRealmTypes.length > 0
        ? `Secure authentication realms are configured beyond native/file: ${secureRealmTypes.join(", ")}.`
        : `Only native/file style realms are visible (${[...realmTypes].join(", ") || "none"}); no LDAP, Active Directory, PKI, SAML, Kerberos, OIDC, or JWT realm is enabled.`,
      { realms: realmEvidence, usage_realm_types: usageTypes, secure_realm_types: secureRealmTypes },
    ));
  }

  if (!view.available && !usage) {
    findings.push(manualFinding(
      13,
      "medium",
      "Realm settings could not be read, so SSO attribute mapping was not evaluated.",
      "the SAML or OIDC realm settings (attributes.principal, attributes.groups, claims.principal, claims.groups, authorization_realms) and the role mappings that assign roles to SSO users.",
    ));
  } else {
    const ssoRealms = realms.filter((realm) => SSO_REALM_TYPES.has(realm.type));
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
        principal_attribute: principal ?? null,
        groups_attribute: groups ?? null,
        authorization_realms: authorizationRealms,
        role_mappings: mappings,
        complete: Boolean(principal) && (mappings.length > 0 || authorizationRealms.length > 0),
      };
    });
    const incomplete = ssoEvidence.filter((entry) => !entry.complete);
    const usageSso = usageTypes.filter((type) => SSO_REALM_TYPES.has(type));
    findings.push(finding(
      13,
      "medium",
      ssoRealms.length === 0
        ? (usageSso.length > 0 ? "warn" : "warn")
        : incomplete.length === 0 && roleMappings !== undefined
          ? "pass"
          : "warn",
      ssoRealms.length === 0
        ? usageSso.length > 0
          ? `Usage statistics report ${usageSso.join(", ")} realms but their settings were not visible, so attribute mapping and role assignment were not verified.`
          : "No SAML or OIDC realm is configured, so SSO attribute mapping and role assignment could not be evaluated."
        : incomplete.length === 0 && roleMappings !== undefined
          ? `${ssoRealms.length} SSO realm(s) define a principal attribute and have role mappings or authorization realms assigning roles.`
          : roleMappings === undefined
            ? `${ssoRealms.length} SSO realm(s) found but role mappings could not be read (${datasetProblem(snapshot, "role_mappings")}).`
            : `${incomplete.length}/${ssoRealms.length} SSO realm(s) lack a principal attribute or any role mapping: ${incomplete.map((entry) => `${entry.type}.${entry.name}`).join(", ")}.`,
      { sso_realms: ssoEvidence, role_mapping_count: mappingEntries.length },
    ));
  }

  const anonymousRoles = asStringList(view.get("xpack.security.authc.anonymous.roles"));
  const anonymousUsername = asString(view.get("xpack.security.authc.anonymous.username"));
  const usageAnonymous = usageFlag(usage, ["anonymous", "enabled"]);
  if (!view.available && usageAnonymous === undefined) {
    findings.push(manualFinding(
      14,
      "high",
      "Anonymous access settings could not be read.",
      "the xpack.security.authc.anonymous.* settings from elasticsearch.yml on every node.",
    ));
  } else {
    const anonymousEnabled = anonymousRoles.length > 0 || usageAnonymous === true;
    const anonymousRoleDescriptors = anonymousRoles.map((name) => asObject(roles?.[name]) ?? {});
    const broadAnonymous = anonymousRoles.includes("superuser")
      || anonymousRoleDescriptors.some((descriptor) => descriptorGrantsClusterAll(descriptor) || descriptorGrantsWildcardIndexAll(descriptor));
    findings.push(finding(
      14,
      "high",
      !anonymousEnabled ? "pass" : broadAnonymous ? "fail" : "warn",
      !anonymousEnabled
        ? "Anonymous access is disabled (no xpack.security.authc.anonymous.roles configured)."
        : broadAnonymous
          ? `Anonymous access is enabled with broad roles: ${anonymousRoles.join(", ")}.`
          : `Anonymous access is enabled with roles ${anonymousRoles.join(", ") || "(reported by usage statistics)"}; confirm they only permit non-sensitive operations.`,
      { anonymous_enabled: anonymousEnabled, anonymous_roles: anonymousRoles, anonymous_username: anonymousUsername ?? null, usage_anonymous_enabled: usageAnonymous ?? null },
    ));
  }

  if (!apiKeys) {
    const reason = `API keys could not be read (${datasetProblem(snapshot, "api_keys")}).`;
    findings.push(manualFinding(9, "high", reason, "the output of GET /_security/_query/api_key run by a principal with read_security or manage_api_key, and the API key rotation records.", { api_key_limit: options.apiKeyLimit ?? DEFAULT_API_KEY_LIMIT }));
    findings.push(manualFinding(10, "high", reason, "the role_descriptors and limited_by sections of every active API key (GET /_security/_query/api_key?with_limited_by=true).", {}));
  } else {
    const active = apiKeys.filter((key) => asBoolean(key.invalidated) !== true && (asNumber(key.expiration) === undefined || (asNumber(key.expiration) ?? 0) > now));
    const invalidated = apiKeys.filter((key) => asBoolean(key.invalidated) === true);
    const expired = apiKeys.filter((key) => asBoolean(key.invalidated) !== true && asNumber(key.expiration) !== undefined && (asNumber(key.expiration) ?? 0) <= now);
    const withoutExpiration = active.filter((key) => asNumber(key.expiration) === undefined);
    const stale = active.filter((key) => {
      const creation = asNumber(key.creation);
      return creation !== undefined && daysBetween(creation, now) > maxApiKeyAgeDays;
    });
    const unmanagedWithoutExpiration = withoutExpiration.filter((key) => !apiKeyIsFleetManaged(key));
    const unmanagedStale = stale.filter((key) => !apiKeyIsFleetManaged(key));
    const fleetIssues = withoutExpiration.length + stale.length - unmanagedWithoutExpiration.length - unmanagedStale.length;
    const status: ElasticFinding["status"] = unmanagedWithoutExpiration.length > 0 || unmanagedStale.length > 0
      ? "fail"
      : fleetIssues > 0 || invalidated.length > 0 || expired.length > 0
        ? "warn"
        : "pass";
    findings.push(finding(
      9,
      "high",
      status,
      status === "fail"
        ? `${unmanagedWithoutExpiration.length} active non-Fleet API key(s) have no expiration and ${unmanagedStale.length} are older than ${maxApiKeyAgeDays} days (${active.length} active of ${apiKeys.length} inspected).`
        : status === "warn"
          ? `Only Fleet-managed keys lack expiration or exceed ${maxApiKeyAgeDays} days (${fleetIssues}), with ${invalidated.length} invalidated and ${expired.length} expired keys still present.`
          : `All ${active.length} active API keys have expirations within ${maxApiKeyAgeDays} days of creation and no inactive keys linger.`,
      {
        inspected: apiKeys.length,
        active: active.length,
        invalidated: invalidated.length,
        expired: expired.length,
        without_expiration: withoutExpiration.length,
        older_than_max_age: stale.length,
        max_api_key_age_days: maxApiKeyAgeDays,
        flagged: [...unmanagedWithoutExpiration, ...unmanagedStale.filter((key) => !unmanagedWithoutExpiration.includes(key))]
          .slice(0, 25)
          .map((key) => apiKeySample(key, { age_days: asNumber(key.creation) === undefined ? null : daysBetween(asNumber(key.creation) ?? now, now) })),
      },
    ));

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
    findings.push(finding(
      10,
      "high",
      privileged.length > 0 ? "fail" : unverifiable > 0 ? "warn" : "pass",
      privileged.length > 0
        ? `${privileged.length}/${active.length} active API keys carry superuser-equivalent or cluster-wide privileges.`
        : unverifiable > 0
          ? `${unverifiable}/${active.length} active API keys inherit owner privileges but limited_by was not visible (requires manage_api_key), so their scope could not be verified.`
          : `All ${active.length} active API keys are scoped below superuser-equivalent privileges.`,
      { active: active.length, privileged: privileged.slice(0, 25), unverifiable },
    ));
  }

  return {
    area: "identity",
    title: "Elastic identity and authentication",
    summary: {
      realm_types: [...realmTypes],
      secure_realm_types: secureRealmTypes,
      anonymous_roles: anonymousRoles,
      api_keys_inspected: apiKeys?.length ?? 0,
      role_mappings: Object.keys(roleMappings ?? {}).length,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
  };
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

function evaluateIndexRestriction(
  number: number,
  label: string,
  restricted: RoleIndexEntry[],
  patterns: string[],
  licenseSupports: boolean | undefined,
  usageCount: number | undefined,
  unreadable: string | undefined,
): ElasticFinding {
  if (unreadable) {
    return manualFinding(number, "medium", `Roles could not be read (${unreadable}).`, `the role definitions (GET /_security/role) and confirm which roles apply ${label} to sensitive indices.`);
  }
  const restrictedRoles = [...new Set(restricted.map((entry) => entry.role))];
  const evidence: JsonRecord = {
    roles_with_restriction: restricted.slice(0, 50).map((entry) => ({ role: entry.role, indices: entry.names })),
    usage_count: usageCount ?? null,
    license_supports_feature: licenseSupports ?? null,
    patterns,
  };
  if (licenseSupports === false) {
    return finding(number, "medium", patterns.length > 0 ? "fail" : "warn", `The active license does not include ${label}, so it cannot be enforced on this cluster.`, evidence);
  }
  if (patterns.length > 0) {
    const uncovered = patterns.filter((pattern) => !restricted.some((entry) => entry.names.some((name) => patternsOverlap(name, pattern))));
    return finding(
      number,
      "medium",
      uncovered.length === 0 ? "pass" : "fail",
      uncovered.length === 0
        ? `Every supplied index pattern (${patterns.join(", ")}) is covered by at least one role applying ${label}.`
        : `${uncovered.length}/${patterns.length} supplied index patterns have no role applying ${label}: ${uncovered.join(", ")}.`,
      { ...evidence, uncovered_patterns: uncovered },
    );
  }
  return finding(
    number,
    "medium",
    restrictedRoles.length > 0 ? "pass" : "warn",
    restrictedRoles.length > 0
      ? `${restrictedRoles.length} role(s) apply ${label}: ${restrictedRoles.slice(0, 10).join(", ")}. Pass index patterns to verify coverage of specific sensitive indices.`
      : `No role applies ${label}. Identify indices holding sensitive or tenant data and confirm whether ${label} is required.`,
    evidence,
  );
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
  const license = datasetData<JsonRecord>(snapshot, "license");
  const licenseType = asString(getNestedValue(license, ["license", "type"]))?.toLowerCase();
  const licenseRank = licenseType ? LICENSE_RANK[licenseType] : undefined;
  const platinumSupported = licenseRank === undefined ? undefined : licenseRank >= LICENSE_RANK.platinum;
  const findings: ElasticFinding[] = [];

  const roleEntries = Object.entries(roles ?? {}).map(([name, value]) => ({ name, role: asObject(value) ?? {} }));
  const userEntries = Object.entries(users ?? {}).map(([name, value]) => ({ name, user: asObject(value) ?? {} }));
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
  const superuserMappings = Object.entries(roleMappings ?? {})
    .filter(([, value]) => asBoolean(asObject(value)?.enabled) !== false && asStringList(asObject(value)?.roles).some((role) => role === "superuser" || broadRoles.includes(role)))
    .map(([name]) => name);

  if (!roles) {
    findings.push(manualFinding(6, "high", `Roles could not be read (${datasetProblem(snapshot, "roles")}).`, "the role definitions (GET /_security/role), user list (GET /_security/user), and role mappings, then identify superuser holders and roles granting cluster all or index all on *."));
  } else {
    const status: ElasticFinding["status"] = superusers.length > maxSuperusers || usersWithBroadRoles.length > 0
      ? "fail"
      : broadRoles.length > 0 || superuserMappings.length > 0
        ? "warn"
        : "pass";
    findings.push(finding(
      6,
      "high",
      status,
      status === "fail"
        ? `${superusers.length} native users hold superuser (threshold ${maxSuperusers}) and ${usersWithBroadRoles.length} users hold custom roles granting cluster all or index all on *.`
        : status === "warn"
          ? `${broadRoles.length} custom role(s) grant cluster all or wildcard index all and ${superuserMappings.length} role mapping(s) assign superuser or broad roles; no native user currently exceeds the superuser threshold.`
          : `${roleEntries.length} roles reviewed; ${superusers.length} superuser holder(s) within threshold ${maxSuperusers} and no custom role grants cluster all or wildcard index all.`,
      {
        roles_reviewed: roleEntries.length,
        custom_roles: customRoles.length,
        users_reviewed: userEntries.length,
        superusers,
        max_superusers: maxSuperusers,
        cluster_all_roles: clusterAllRoles,
        wildcard_index_all_roles: wildcardIndexRoles,
        users_with_broad_roles: usersWithBroadRoles.slice(0, 25),
        superuser_role_mappings: superuserMappings,
        users_unreadable: users ? null : datasetProblem(snapshot, "users"),
      },
    ));
  }

  const indexEntries = roles ? roleIndexEntries(roles) : [];
  findings.push(evaluateIndexRestriction(
    7,
    "field-level security",
    indexEntries.filter((entry) => entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0),
    options.sensitiveIndexPatterns ?? [],
    platinumSupported,
    asNumber(getNestedValue(usage, ["security", "roles", "native", "fls"])),
    roles ? undefined : datasetProblem(snapshot, "roles"),
  ));
  findings.push(evaluateIndexRestriction(
    8,
    "document-level security",
    indexEntries.filter((entry) => entry.query !== undefined && entry.query !== null && entry.query !== ""),
    options.tenantIndexPatterns ?? [],
    platinumSupported,
    asNumber(getNestedValue(usage, ["security", "roles", "native", "dls"])),
    roles ? undefined : datasetProblem(snapshot, "roles"),
  ));

  return {
    area: "access_control",
    title: "Elastic role-based access control",
    summary: {
      roles_reviewed: roleEntries.length,
      users_reviewed: userEntries.length,
      superusers: superusers.length,
      broad_custom_roles: broadRoles.length,
      roles_with_fls: new Set(indexEntries.filter((entry) => entry.fieldSecurity).map((entry) => entry.role)).size,
      roles_with_dls: new Set(indexEntries.filter((entry) => entry.query !== undefined && entry.query !== null).map((entry) => entry.role)).size,
      license_type: licenseType ?? null,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
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

function evaluateTlsLayer(
  number: number,
  layer: "transport" | "http",
  view: SettingsView,
  usage: JsonRecord | undefined,
  elasticsearchUrl: string | undefined,
): ElasticFinding {
  const key = `xpack.security.${layer}.ssl.enabled`;
  const perNode = perNodeBooleans(view, key);
  const usageEnabled = usageFlag(usage, ["ssl", layer, "enabled"]);
  const effective = asBoolean(view.get(key));
  const securityEnabled = asBoolean(view.get("xpack.security.enabled")) ?? usageFlag(usage, ["enabled"]);
  const observed = perNode.filter((entry) => entry.value !== undefined);
  const urlIsPlainHttp = layer === "http" && Boolean(elasticsearchUrl && elasticsearchUrl.startsWith("http://"));
  const evidence: JsonRecord = {
    setting: key,
    per_node: perNode.map((entry) => ({ node: entry.node, value: entry.value ?? null })),
    effective_setting: effective ?? null,
    usage_reported_enabled: usageEnabled ?? null,
    security_enabled: securityEnabled ?? null,
    ...(layer === "http" ? { elasticsearch_url_scheme: elasticsearchUrl ? new URL(elasticsearchUrl).protocol.replace(":", "") : null } : {}),
  };

  if (!view.available && usageEnabled === undefined) {
    return manualFinding(number, "critical", `The ${layer} TLS setting could not be read.`, `${key} from elasticsearch.yml on every node (or the Elastic Cloud deployment TLS configuration).`, evidence);
  }
  if (securityEnabled === false) {
    return finding(number, "critical", "fail", `xpack.security.enabled is false, so ${layer} layer TLS is not enforced.`, evidence);
  }
  if (urlIsPlainHttp) {
    return finding(number, "critical", "fail", `The configured Elasticsearch URL uses plain http, so client-to-cluster traffic is unencrypted.`, evidence);
  }
  const disabledNodes = observed.filter((entry) => entry.value === false).map((entry) => entry.node);
  if (disabledNodes.length > 0 || (observed.length === 0 && (effective === false || usageEnabled === false))) {
    if (layer === "http" && elasticsearchUrl?.startsWith("https://")) {
      return finding(number, "critical", "warn", `xpack.security.http.ssl.enabled is false on ${disabledNodes.length || "the"} node(s) while the endpoint is served over https; confirm the upstream TLS terminator encrypts traffic to every node.`, { ...evidence, disabled_nodes: disabledNodes });
    }
    return finding(number, "critical", "fail", `${key} is false${disabledNodes.length > 0 ? ` on ${disabledNodes.join(", ")}` : ""}.`, { ...evidence, disabled_nodes: disabledNodes });
  }
  const enabledSomewhere = observed.some((entry) => entry.value === true) || effective === true || usageEnabled === true;
  if (!enabledSomewhere) {
    return finding(number, "critical", "warn", `${key} was not explicitly set and usage statistics did not confirm ${layer} TLS; verify the effective value on every node.`, evidence);
  }
  const verificationMode = layer === "transport" ? asString(view.get("xpack.security.transport.ssl.verification_mode")) : undefined;
  if (verificationMode === "none") {
    return finding(number, "critical", "warn", "Transport TLS is enabled but xpack.security.transport.ssl.verification_mode is none, so node certificates are not validated.", { ...evidence, verification_mode: verificationMode });
  }
  return finding(number, "critical", "pass", `${layer === "transport" ? "Transport" : "HTTP"} layer TLS is enabled${observed.length > 0 ? ` on all ${observed.length} node(s)` : ""}.`, { ...evidence, verification_mode: verificationMode ?? null });
}

export function evaluateElasticTransportSecurity(
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  now: number = Date.now(),
  elasticsearchUrl?: string,
): ElasticAssessmentResult {
  const warningDays = clampNumber(options.certExpiryWarningDays, DEFAULT_CERT_EXPIRY_WARNING_DAYS, 1, 365);
  const view = buildSettingsView(datasetData<JsonRecord>(snapshot, "node_settings"), datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const certificates = datasetData<JsonRecord[]>(snapshot, "ssl_certificates");
  const findings: ElasticFinding[] = [
    evaluateTlsLayer(2, "transport", view, usage, elasticsearchUrl),
    evaluateTlsLayer(3, "http", view, usage, elasticsearchUrl),
  ];

  const protocolKeys = ["xpack.security.transport.ssl.supported_protocols", "xpack.security.http.ssl.supported_protocols"];
  const protocolEvidence = protocolKeys.map((key) => ({ setting: key, value: asStringList(view.get(key)) }));
  const configured = protocolEvidence.filter((entry) => entry.value.length > 0);
  const weakProtocols = [...new Set(configured.flatMap((entry) => entry.value.filter((protocol) => !MINIMUM_TLS_PROTOCOLS.has(protocol))))];
  const majors = nodeMajorVersions(view);
  if (!view.available) {
    findings.push(manualFinding(4, "high", "TLS protocol settings could not be read.", "xpack.security.transport.ssl.supported_protocols and xpack.security.http.ssl.supported_protocols from elasticsearch.yml on every node.", { protocols: protocolEvidence }));
  } else if (weakProtocols.length > 0) {
    findings.push(finding(4, "high", "fail", `Supported TLS protocols include versions below TLSv1.2: ${weakProtocols.join(", ")}.`, { protocols: protocolEvidence, weak_protocols: weakProtocols, node_major_versions: majors }));
  } else if (configured.length < protocolKeys.length && majors.some((major) => major < 8)) {
    findings.push(finding(4, "high", "warn", "supported_protocols is not explicitly set on every layer and at least one node runs Elasticsearch 7.x, whose defaults can include TLSv1.1.", { protocols: protocolEvidence, node_major_versions: majors }));
  } else {
    findings.push(finding(
      4,
      "high",
      "pass",
      configured.length === protocolKeys.length
        ? `Supported TLS protocols are restricted to ${[...new Set(configured.flatMap((entry) => entry.value))].join(", ")}.`
        : "supported_protocols uses the Elasticsearch 8.x default of TLSv1.3 and TLSv1.2 where not explicitly set.",
      { protocols: protocolEvidence, node_major_versions: majors },
    ));
  }

  if (!certificates) {
    findings.push(manualFinding(5, "high", `TLS certificates could not be read (${datasetProblem(snapshot, "ssl_certificates")}).`, "the output of GET /_ssl/certificates (requires the monitor cluster privilege) or the certificate inventory with expiry dates for every node keystore and truststore.", { cert_expiry_warning_days: warningDays }));
  } else {
    const inventory = certificates.map((certificate) => {
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
    findings.push(finding(
      5,
      "high",
      expired.length > 0 ? "fail" : expiring.length > 0 ? "warn" : inventory.length === 0 ? "warn" : "pass",
      expired.length > 0
        ? `${expired.length} TLS certificate(s) have expired and ${expiring.length} expire within ${warningDays} days.`
        : expiring.length > 0
          ? `${expiring.length}/${inventory.length} TLS certificate(s) expire within ${warningDays} days.`
          : inventory.length === 0
            ? "No TLS certificates were reported by the cluster; confirm keystores are configured."
            : `All ${inventory.length} TLS certificates are valid for at least ${warningDays} more days.`,
      { certificates: inventory.slice(0, 25), expired: expired.length, expiring_soon: expiring.length, cert_expiry_warning_days: warningDays },
    ));
  }

  return {
    area: "transport_security",
    title: "Elastic transport and HTTP TLS",
    summary: {
      nodes_inspected: view.nodes.length,
      transport_tls: asBoolean(view.get("xpack.security.transport.ssl.enabled")) ?? usageFlag(usage, ["ssl", "transport", "enabled"]) ?? null,
      http_tls: asBoolean(view.get("xpack.security.http.ssl.enabled")) ?? usageFlag(usage, ["ssl", "http", "enabled"]) ?? null,
      weak_protocols: weakProtocols,
      certificates: certificates?.length ?? 0,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
  };
}

const DEFAULT_AUDIT_INCLUDE = [
  "access_denied",
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
  const field = asString(config.field) ?? "";
  const value = config.value;
  const literal = typeof value === "string" && !value.includes("{{");
  return literal && (SECRET_FIELD_NAME_PATTERN.test(field) || /^(?:[A-Za-z0-9+/=_-]{32,})$/.test(value));
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

export function evaluateElasticClusterHardening(
  snapshot: ElasticSnapshot,
  _options: ElasticAssessmentOptions = {},
  now: number = Date.now(),
): ElasticAssessmentResult {
  const view = buildSettingsView(datasetData<JsonRecord>(snapshot, "node_settings"), datasetData<JsonRecord>(snapshot, "cluster_settings"));
  const usage = datasetData<JsonRecord>(snapshot, "xpack_usage");
  const xpackInfo = datasetData<JsonRecord>(snapshot, "xpack_info");
  const license = datasetData<JsonRecord>(snapshot, "license");
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const ilmPolicies = datasetData<JsonRecord>(snapshot, "ilm_policies");
  const slmPolicies = datasetData<JsonRecord>(snapshot, "slm_policies");
  const repositories = datasetData<JsonRecord>(snapshot, "snapshot_repositories");
  const watches = datasetData<JsonRecord[]>(snapshot, "watches");
  const pipelines = datasetData<JsonRecord>(snapshot, "ingest_pipelines");
  const connectors = datasetData<JsonRecord[]>(snapshot, "connectors");
  const alertingRules = datasetData<JsonRecord[]>(snapshot, "alerting_rules");
  const detectionRules = datasetData<JsonRecord[]>(snapshot, "detection_rules");
  const findings: ElasticFinding[] = [];

  const auditPerNode = perNodeBooleans(view, "xpack.security.audit.enabled");
  const auditEnabled = auditPerNode.some((entry) => entry.value === true)
    || asBoolean(view.get("xpack.security.audit.enabled")) === true
    || usageFlag(usage, ["audit", "enabled"]) === true;
  const auditVisible = view.available || usageFlag(usage, ["audit", "enabled"]) !== undefined;
  const includeSetting = asStringList(view.get("xpack.security.audit.logfile.events.include"));
  const excludeSetting = asStringList(view.get("xpack.security.audit.logfile.events.exclude"));
  const effectiveInclude = (includeSetting.length > 0 ? includeSetting : DEFAULT_AUDIT_INCLUDE).filter((event) => !excludeSetting.includes(event));
  const missingEvents = REQUIRED_AUDIT_EVENTS.filter((event) => !effectiveInclude.includes(event));
  const auditOutputs = asStringList(getNestedValue(usage, ["security", "audit", "outputs"]));
  const auditEvidence: JsonRecord = {
    per_node: auditPerNode.map((entry) => ({ node: entry.node, value: entry.value ?? null })),
    usage_reported_enabled: usageFlag(usage, ["audit", "enabled"]) ?? null,
    events_include: includeSetting,
    events_exclude: excludeSetting,
    effective_include: effectiveInclude,
    outputs: auditOutputs,
  };
  if (!auditVisible) {
    findings.push(manualFinding(11, "high", "Audit settings could not be read.", "xpack.security.audit.* settings from elasticsearch.yml on every node and a sample of <cluster>_audit.json.", auditEvidence));
    findings.push(manualFinding(12, "medium", "Audit settings could not be read.", "evidence that <cluster>_audit.json is shipped to a tamper-resistant destination (Filebeat or Elastic Agent elasticsearch.audit integration, or a SIEM) with retention and integrity controls.", auditEvidence));
  } else {
    const disabledNodes = auditPerNode.filter((entry) => entry.value === false).map((entry) => entry.node);
    findings.push(finding(
      11,
      "high",
      !auditEnabled ? "fail" : disabledNodes.length > 0 || missingEvents.length > 0 ? "warn" : "pass",
      !auditEnabled
        ? "xpack.security.audit.enabled is not true on any node, so security audit logging is disabled."
        : disabledNodes.length > 0
          ? `Audit logging is disabled on ${disabledNodes.join(", ")} while enabled elsewhere.`
          : missingEvents.length > 0
            ? `Audit logging is enabled but the effective event include list omits ${missingEvents.join(", ")}.`
            : `Audit logging is enabled with authentication, access_denied, and security_config_change events included.`,
      { ...auditEvidence, disabled_nodes: disabledNodes, missing_required_events: missingEvents },
    ));
    if (!auditEnabled) {
      findings.push(finding(12, "medium", "fail", "Audit logging is disabled, so no audit output exists to protect.", auditEvidence));
    } else {
      findings.push(manualFinding(
        12,
        "medium",
        `Elasticsearch writes audit events only to the local logfile output (${auditOutputs.join(", ") || "logfile"}) on each node; forwarding to a tamper-resistant store cannot be verified through the API.`,
        "evidence that <cluster>_audit.json is shipped to a tamper-resistant destination (Filebeat or Elastic Agent elasticsearch.audit integration, or a SIEM) with retention and integrity controls.",
        auditEvidence,
      ));
    }
  }

  if (!ilmPolicies) {
    findings.push(manualFinding(17, "medium", `ILM policies could not be read (${datasetProblem(snapshot, "ilm_policies")}).`, "the ILM policy definitions (GET /_ilm/policy) and the retention schedule approved for each regulated data stream."));
  } else {
    const policies = Object.entries(ilmPolicies).map(([name, value]) => {
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
    findings.push(finding(
      17,
      "medium",
      policies.length === 0 ? "fail" : inUseWithoutDelete.length > 0 ? "warn" : "pass",
      policies.length === 0
        ? "No index lifecycle policies exist, so retention and deletion are not enforced through ILM."
        : inUseWithoutDelete.length > 0
          ? `${inUseWithoutDelete.length}/${policies.length} in-use ILM policies have no delete phase: ${inUseWithoutDelete.slice(0, 10).map((policy) => policy.name).join(", ")}.`
          : `All ${policies.filter((policy) => policy.in_use).length} in-use ILM policies define a delete phase.`,
      {
        policies: policies.slice(0, 50),
        without_rollover: policies.filter((policy) => policy.in_use && !policy.has_rollover).map((policy) => policy.name).slice(0, 25),
      },
    ));
  }

  if (!repositories) {
    findings.push(manualFinding(18, "high", `Snapshot repositories could not be read (${datasetProblem(snapshot, "snapshot_repositories")}).`, "the repository settings (GET /_snapshot/_all), storage encryption evidence for each bucket or filesystem, and the SLM policies (GET /_slm/policy)."));
  } else {
    const repoEntries = Object.entries(repositories).map(([name, value]) => {
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
    const slmCount = Object.keys(slmPolicies ?? {}).length;
    const manualRepos = repoEntries.filter((repo) => repo.encryption === "manual");
    const evidence = { repositories: repoEntries, slm_policies: slmCount, slm_unreadable: slmPolicies ? null : datasetProblem(snapshot, "slm_policies") };
    if (repoEntries.length === 0) {
      findings.push(finding(18, "high", "fail", "No snapshot repositories are registered, so no encrypted backups or SLM policies exist.", evidence));
    } else if (slmPolicies && slmCount === 0) {
      findings.push(finding(18, "high", "fail", `${repoEntries.length} snapshot repositories exist but no snapshot lifecycle policy is defined.`, evidence));
    } else if (manualRepos.length > 0) {
      findings.push(manualFinding(
        18,
        "high",
        `${manualRepos.length}/${repoEntries.length} repositories (${manualRepos.map((repo) => `${repo.name}:${repo.type}`).join(", ")}) do not expose an encryption setting through the API.`,
        "bucket default-encryption or filesystem/disk encryption evidence for each listed repository (S3 repositories can also set server_side_encryption: true).",
        evidence,
      ));
    } else {
      findings.push(finding(18, "high", "pass", `All ${repoEntries.length} snapshot repositories use encrypted storage and ${slmCount} SLM policies are defined.`, evidence));
    }
  }

  const securityEnabled = asBoolean(view.get("xpack.security.enabled")) ?? usageFlag(usage, ["enabled"]) ?? asBoolean(getNestedValue(xpackInfo, ["features", "security", "enabled"]));
  const passwordHashing = asString(view.get("xpack.security.authc.password_hashing.algorithm")) ?? "bcrypt";
  const apiKeyHashing = asString(view.get("xpack.security.authc.api_key.hashing.algorithm")) ?? "ssha256";
  const tokenService = asBoolean(view.get("xpack.security.authc.token.enabled")) ?? usageFlag(usage, ["token_service", "enabled"]);
  const apiKeyService = asBoolean(view.get("xpack.security.authc.api_key.enabled")) ?? usageFlag(usage, ["api_key_service", "enabled"]);
  const fipsMode = asBoolean(view.get("xpack.security.fips_mode.enabled")) ?? usageFlag(usage, ["fips_140", "enabled"]);
  const httpIpFilter = asBoolean(view.get("xpack.security.http.filter.enabled")) ?? usageFlag(usage, ["ipfilter", "http"]);
  const transportIpFilter = asBoolean(view.get("xpack.security.transport.filter.enabled")) ?? usageFlag(usage, ["ipfilter", "transport"]);
  const strongPasswordHashing = /^(bcrypt|pbkdf2)/i.test(passwordHashing);
  const clusterEvidence: JsonRecord = {
    security_enabled: securityEnabled ?? null,
    password_hashing_algorithm: passwordHashing,
    api_key_hashing_algorithm: apiKeyHashing,
    token_service_enabled: tokenService ?? null,
    api_key_service_enabled: apiKeyService ?? null,
    fips_mode_enabled: fipsMode ?? null,
    http_ip_filter_enabled: httpIpFilter ?? null,
    transport_ip_filter_enabled: transportIpFilter ?? null,
  };
  if (!view.available && !usage) {
    findings.push(manualFinding(19, "high", "Cluster security settings could not be read.", "the xpack.security.* section of elasticsearch.yml from every node plus GET /_cluster/settings?include_defaults=true.", clusterEvidence));
  } else {
    findings.push(finding(
      19,
      "high",
      securityEnabled === false ? "fail" : !strongPasswordHashing ? "warn" : "pass",
      securityEnabled === false
        ? "xpack.security.enabled is false, so authentication, authorization, and TLS enforcement are off."
        : !strongPasswordHashing
          ? `Security is enabled but the password hashing algorithm is ${passwordHashing}; use a bcrypt or pbkdf2 variant.`
          : `Security is enabled with ${passwordHashing} password hashing, API key hashing ${apiKeyHashing}, token service ${tokenService ?? "default"}, and API key service ${apiKeyService ?? "default"}.`,
      clusterEvidence,
    ));
  }

  const watchIssues = (watches ?? []).map((watch) => ({ id: asString(watch._id) ?? "watch", ...watchActionIssues(watch) }));
  const insecureWatchActions = watchIssues.filter((watch) => watch.insecureWebhooks.length > 0);
  const credentialWatchActions = watchIssues.filter((watch) => watch.embeddedCredentials.length > 0);
  const insecureConnectors = (connectors ?? []).filter((connector) => (connectorUrl(connector) ?? "").startsWith("http://"));
  const connectorsMissingSecrets = (connectors ?? []).filter((connector) => asBoolean(connector.is_missing_secrets) === true);
  const rulesWithActions = (alertingRules ?? []).filter((rule) => asObjectArray(rule.actions).length > 0).length
    + (detectionRules ?? []).filter((rule) => asObjectArray(rule.actions).length > 0).length;
  const watcherProblem = watches ? undefined : datasetProblem(snapshot, "watches");
  const connectorProblem = connectors ? undefined : datasetProblem(snapshot, "connectors");
  const alertingEvidence: JsonRecord = {
    watches: watches?.length ?? null,
    watcher_unreadable: watcherProblem ?? null,
    connectors: connectors?.length ?? null,
    connectors_unreadable: connectorProblem ?? null,
    alerting_rules: alertingRules?.length ?? null,
    detection_rules: detectionRules?.length ?? null,
    rules_with_actions: rulesWithActions,
    insecure_watch_webhooks: insecureWatchActions.slice(0, 25).map((watch) => ({ id: watch.id, actions: watch.insecureWebhooks })),
    watch_actions_with_embedded_credentials: credentialWatchActions.slice(0, 25).map((watch) => ({ id: watch.id, actions: watch.embeddedCredentials })),
    insecure_connectors: insecureConnectors.slice(0, 25).map((connector) => ({ id: asString(connector.id), name: asString(connector.name), type: asString(connector.connector_type_id), url: connectorUrl(connector) })),
    connectors_missing_secrets: connectorsMissingSecrets.slice(0, 25).map((connector) => asString(connector.name) ?? asString(connector.id)),
  };
  if (!watches && !connectors) {
    findings.push(manualFinding(20, "medium", `Neither Watcher (${watcherProblem}) nor Kibana connectors (${connectorProblem}) could be read.`, "the watch definitions (GET /_watcher/_query/watches) and Kibana connector inventory (GET /api/actions/connectors), then confirm webhook destinations use https and credentials are stored as secrets.", alertingEvidence));
  } else {
    findings.push(finding(
      20,
      "medium",
      insecureWatchActions.length > 0 || insecureConnectors.length > 0
        ? "fail"
        : credentialWatchActions.length > 0 || connectorsMissingSecrets.length > 0
          ? "warn"
          : "pass",
      insecureWatchActions.length > 0 || insecureConnectors.length > 0
        ? `${insecureWatchActions.length} watch(es) and ${insecureConnectors.length} Kibana connector(s) send to plain http webhook destinations.`
        : credentialWatchActions.length > 0 || connectorsMissingSecrets.length > 0
          ? `${credentialWatchActions.length} watch action(s) embed basic-auth credentials and ${connectorsMissingSecrets.length} connector(s) are missing secrets.`
          : `${watches?.length ?? 0} watches and ${connectors?.length ?? 0} connectors reviewed; all webhook destinations use https and no inline credentials were found${watcherProblem ? ` (Watcher not readable: ${watcherProblem})` : ""}.`,
      alertingEvidence,
    ));
  }

  if (!pipelines) {
    findings.push(manualFinding(22, "medium", `Ingest pipelines could not be read (${datasetProblem(snapshot, "ingest_pipelines")}).`, "the pipeline definitions (GET /_ingest/pipeline) and review script and set processors for hardcoded sensitive values."));
  } else {
    const pipelineEntries = Object.entries(pipelines).map(([name, value]) => {
      const entry = asObject(value) ?? {};
      const processors = pipelineProcessors(entry.processors);
      return {
        name,
        managed: asBoolean(getNestedValue(entry, ["_meta", "managed"])) === true || name.startsWith("."),
        script_processors: processors.filter((processor) => processor.type === "script").length,
        sensitive_set_processors: processors.filter((processor) => processor.type === "set" && setProcessorLooksSensitive(processor.config)).map((processor) => asString(processor.config.field) ?? "value"),
      };
    });
    const custom = pipelineEntries.filter((pipeline) => !pipeline.managed);
    const withSecrets = custom.filter((pipeline) => pipeline.sensitive_set_processors.length > 0);
    const withScripts = custom.filter((pipeline) => pipeline.script_processors > 0);
    findings.push(finding(
      22,
      "medium",
      withSecrets.length > 0 ? "fail" : withScripts.length > 0 ? "warn" : "pass",
      withSecrets.length > 0
        ? `${withSecrets.length} custom ingest pipeline(s) set sensitive-looking literal values: ${withSecrets.slice(0, 10).map((pipeline) => pipeline.name).join(", ")}.`
        : withScripts.length > 0
          ? `${withScripts.length}/${custom.length} custom ingest pipeline(s) use script processors; review them for data exposure.`
          : `${pipelineEntries.length} ingest pipelines reviewed (${custom.length} custom); no script processors or hardcoded sensitive values in custom pipelines.`,
      {
        pipelines: pipelineEntries.length,
        custom_pipelines: custom.length,
        managed_pipelines: pipelineEntries.length - custom.length,
        pipelines_with_sensitive_set: withSecrets.slice(0, 25),
        pipelines_with_scripts: withScripts.slice(0, 25).map((pipeline) => pipeline.name),
      },
    ));
  }

  const licenseInfo = asObject(license?.license);
  const licenseType = asString(licenseInfo?.type)?.toLowerCase();
  const licenseStatus = asString(licenseInfo?.status);
  const licenseExpiry = isoDate(licenseInfo?.expiry_date_in_millis ?? licenseInfo?.expiry_date);
  const realmTypes = new Set([...parseRealms(view).filter((realm) => realm.enabled).map((realm) => realm.type), ...usageRealmTypes(usage)]);
  const usesFlsOrDls = roles ? roleIndexEntries(roles).some((entry) => (entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0) || (entry.query !== undefined && entry.query !== null)) : false;
  const requirements = requiredLicenseRankFor(realmTypes, usesFlsOrDls, auditEnabled, watches?.length ?? 0);
  const licenseRank = licenseType ? LICENSE_RANK[licenseType] : undefined;
  const unsupported = licenseRank === undefined ? [] : requirements.filter((requirement) => requirement.rank > licenseRank);
  const expiryDays = licenseExpiry ? daysBetween(now, Date.parse(licenseExpiry)) : undefined;
  const licenseEvidence: JsonRecord = {
    type: licenseType ?? null,
    status: licenseStatus ?? null,
    expiry: licenseExpiry ?? null,
    days_until_expiry: expiryDays ?? null,
    security_available: asBoolean(getNestedValue(xpackInfo, ["features", "security", "available"])) ?? null,
    security_enabled: asBoolean(getNestedValue(xpackInfo, ["features", "security", "enabled"])) ?? null,
    required_features: requirements.map((requirement) => ({ feature: requirement.feature, minimum_license: licenseLabel(requirement.rank) })),
  };
  if (!license) {
    findings.push(manualFinding(23, "medium", `License could not be read (${datasetProblem(snapshot, "license")}).`, "the output of GET /_license and the subscription tier that covers the configured realms, FLS/DLS, audit logging, and Watcher.", licenseEvidence));
  } else {
    findings.push(finding(
      23,
      "medium",
      unsupported.length > 0 || (licenseStatus !== undefined && licenseStatus !== "active")
        ? "fail"
        : licenseType === "trial" || (expiryDays !== undefined && expiryDays < 30)
          ? "warn"
          : "pass",
      unsupported.length > 0
        ? `The ${licenseType} license does not cover configured features: ${unsupported.map((item) => `${item.feature} (needs ${licenseLabel(item.rank)})`).join(", ")}.`
        : licenseStatus !== undefined && licenseStatus !== "active"
          ? `The license status is ${licenseStatus}.`
          : licenseType === "trial"
            ? `A trial license is active${expiryDays !== undefined ? ` and expires in ${expiryDays} days` : ""}; security features will lapse when it ends.`
            : expiryDays !== undefined && expiryDays < 30
              ? `The ${licenseType} license expires in ${expiryDays} days.`
              : `The ${licenseType ?? "current"} license covers every configured security feature (${requirements.length} requirement(s) checked).`,
      { ...licenseEvidence, unsupported_features: unsupported.map((item) => item.feature) },
    ));
  }

  return {
    area: "cluster_hardening",
    title: "Elastic cluster hardening and data protection",
    summary: {
      audit_enabled: auditEnabled,
      audit_outputs: auditOutputs,
      ilm_policies: Object.keys(ilmPolicies ?? {}).length,
      snapshot_repositories: Object.keys(repositories ?? {}).length,
      slm_policies: Object.keys(slmPolicies ?? {}).length,
      watches: watches?.length ?? 0,
      connectors: connectors?.length ?? 0,
      ingest_pipelines: Object.keys(pipelines ?? {}).length,
      license_type: licenseType ?? null,
      security_enabled: securityEnabled ?? null,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
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

  const customRoles = (roles ?? []).filter((role) => !kibanaRoleIsReserved(role));
  const globalAllRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).some((entry) => entry.spaces.includes("*") && entry.base.includes("all")))
    .map((role) => asString(role.name) ?? "role");
  const spaceScopedRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).some((entry) => entry.spaces.length > 0 && !entry.spaces.includes("*")))
    .map((role) => asString(role.name) ?? "role");
  const featureScopedRoles = customRoles
    .filter((role) => kibanaRoleEntries(role).every((entry) => entry.base.length === 0 && entry.features.length > 0))
    .map((role) => asString(role.name) ?? "role");

  if (kibanaSkipped) {
    const collect = "Kibana evidence manually or set KIBANA_URL so the API can be queried:";
    findings.push(manualFinding(15, "medium", `Kibana is not configured (${kibanaSkipped}).`, `${collect} the space list (GET /api/spaces/space) and the roles that scope privileges to individual spaces.`));
    findings.push(manualFinding(16, "high", `Kibana is not configured (${kibanaSkipped}).`, `${collect} the Kibana role definitions (GET /api/security/role) and identify roles granting base all across all spaces.`));
    findings.push(manualFinding(21, "medium", `Kibana is not configured (${kibanaSkipped}).`, `${collect} Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys (GET /api/fleet/agent_policies, /api/fleet/outputs, /api/fleet/fleet_server_hosts, /api/fleet/enrollment_api_keys).`));
  } else {
    if (!spaces) {
      findings.push(manualFinding(15, "medium", `Kibana spaces could not be read (${datasetProblem(snapshot, "kibana_spaces")}).`, "the space list (GET /api/spaces/space) and the roles that scope privileges to individual spaces."));
    } else {
      const spaceEvidence = spaces.map((space) => ({
        id: asString(space.id),
        name: asString(space.name),
        disabled_features: asStringList(space.disabledFeatures).length,
        reserved: asBoolean(space._reserved) ?? false,
      }));
      findings.push(finding(
        15,
        "medium",
        spaces.length <= 1
          ? "warn"
          : roles && spaceScopedRoles.length > 0 && globalAllRoles.length === 0
            ? "pass"
            : "warn",
        spaces.length <= 1
          ? "Only the default space exists, so Kibana space isolation between teams is not in use; confirm whether multi-team separation is required."
          : !roles
            ? `${spaces.length} spaces exist but Kibana roles could not be read (${datasetProblem(snapshot, "kibana_roles")}), so isolation enforcement was not verified.`
            : spaceScopedRoles.length > 0 && globalAllRoles.length === 0
              ? `${spaces.length} spaces exist and ${spaceScopedRoles.length} custom role(s) scope privileges to specific spaces with no custom role granting all privileges across every space.`
              : `${spaces.length} spaces exist but ${spaceScopedRoles.length} role(s) are space-scoped and ${globalAllRoles.length} custom role(s) grant all privileges across every space.`,
        { spaces: spaceEvidence, space_scoped_roles: spaceScopedRoles.slice(0, 25), global_all_roles: globalAllRoles.slice(0, 25) },
      ));
    }

    if (!roles) {
      findings.push(manualFinding(16, "high", `Kibana roles could not be read (${datasetProblem(snapshot, "kibana_roles")}).`, "the Kibana role definitions (GET /api/security/role) and identify roles granting base all across all spaces."));
    } else {
      findings.push(finding(
        16,
        "high",
        globalAllRoles.length > 0 ? "fail" : "pass",
        globalAllRoles.length > 0
          ? `${globalAllRoles.length} custom Kibana role(s) grant base all privileges across every space: ${globalAllRoles.slice(0, 10).join(", ")}.`
          : `${customRoles.length} custom Kibana roles reviewed; none grants base all across every space (${featureScopedRoles.length} use feature-level privileges only).`,
        {
          roles_reviewed: roles.length,
          custom_roles: customRoles.length,
          global_all_roles: globalAllRoles.slice(0, 25),
          feature_scoped_roles: featureScopedRoles.slice(0, 25),
          elasticsearch_cluster_all_roles: customRoles
            .filter((role) => asStringList(getNestedValue(role, ["elasticsearch", "cluster"])).includes("all"))
            .map((role) => asString(role.name))
            .slice(0, 25),
        },
      ));
    }

    if (!agentPolicies) {
      findings.push(manualFinding(21, "medium", `Fleet agent policies could not be read (${datasetProblem(snapshot, "fleet_agent_policies")}).`, "Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys (GET /api/fleet/agent_policies, /api/fleet/outputs, /api/fleet/fleet_server_hosts, /api/fleet/enrollment_api_keys)."));
    } else {
      const insecureOutputs = (outputs ?? []).filter((output) => hostListIsPlainHttp(output.hosts).length > 0).map((output) => asString(output.name) ?? asString(output.id) ?? "output");
      const outputsWithoutTrust = (outputs ?? [])
        .filter((output) => asString(output.type) === "elasticsearch" && !asString(output.ca_sha256) && !asString(output.ca_trusted_fingerprint) && !asObject(output.ssl))
        .map((output) => asString(output.name) ?? asString(output.id) ?? "output");
      const insecureFleetServers = (fleetServerHosts ?? []).filter((host) => hostListIsPlainHttp(host.host_urls).length > 0).map((host) => asString(host.name) ?? asString(host.id) ?? "fleet-server");
      const unprotectedPolicies = agentPolicies.filter((policy) => asBoolean(policy.is_protected) !== true).map((policy) => asString(policy.name) ?? asString(policy.id) ?? "policy");
      const activeKeys = (enrollmentKeys ?? []).filter((key) => asBoolean(key.active) !== false);
      const keysPerPolicy = new Map<string, number>();
      for (const key of activeKeys) {
        const policyId = asString(key.policy_id) ?? "unassigned";
        keysPerPolicy.set(policyId, (keysPerPolicy.get(policyId) ?? 0) + 1);
      }
      const crowdedPolicies = [...keysPerPolicy.entries()].filter(([, count]) => count > maxEnrollmentKeys).map(([policyId, count]) => ({ policy_id: policyId, active_keys: count }));
      const evidence: JsonRecord = {
        agent_policies: agentPolicies.length,
        outputs: outputs?.length ?? null,
        fleet_server_hosts: fleetServerHosts?.length ?? null,
        enrollment_keys_active: activeKeys.length,
        enrollment_keys_inactive: (enrollmentKeys ?? []).length - activeKeys.length,
        insecure_outputs: insecureOutputs,
        outputs_without_ca_trust: outputsWithoutTrust,
        insecure_fleet_server_hosts: insecureFleetServers,
        unprotected_policies: unprotectedPolicies.slice(0, 25),
        policies_over_enrollment_key_threshold: crowdedPolicies,
        max_enrollment_keys_per_policy: maxEnrollmentKeys,
      };
      if (agentPolicies.length === 0) {
        findings.push(finding(21, "medium", "pass", "No Fleet agent policies exist, so Fleet enrollment and output hardening is not applicable.", evidence));
      } else {
        findings.push(finding(
          21,
          "medium",
          insecureOutputs.length > 0 || insecureFleetServers.length > 0
            ? "fail"
            : unprotectedPolicies.length > 0 || crowdedPolicies.length > 0 || outputsWithoutTrust.length > 0
              ? "warn"
              : "pass",
          insecureOutputs.length > 0 || insecureFleetServers.length > 0
            ? `${insecureOutputs.length} Fleet output(s) and ${insecureFleetServers.length} Fleet Server host(s) use plain http.`
            : unprotectedPolicies.length > 0 || crowdedPolicies.length > 0 || outputsWithoutTrust.length > 0
              ? `${unprotectedPolicies.length}/${agentPolicies.length} agent policies lack tamper protection, ${crowdedPolicies.length} policies exceed ${maxEnrollmentKeys} active enrollment keys, and ${outputsWithoutTrust.length} Elasticsearch outputs pin no CA trust.`
              : `All ${agentPolicies.length} agent policies are tamper protected, outputs and Fleet Server hosts use https with CA trust, and enrollment keys stay within ${maxEnrollmentKeys} per policy.`,
          evidence,
        ));
      }
    }
  }

  return {
    area: "kibana",
    title: "Elastic Kibana governance and Fleet",
    summary: {
      kibana_configured: !kibanaSkipped,
      kibana_version: asString(getNestedValue(status, ["version", "number"])) ?? null,
      kibana_status: asString(getNestedValue(status, ["status", "overall", "level"])) ?? asString(getNestedValue(status, ["status", "overall", "state"])) ?? null,
      spaces: spaces?.length ?? 0,
      kibana_roles: roles?.length ?? 0,
      global_all_roles: globalAllRoles.length,
      agent_policies: agentPolicies?.length ?? 0,
      fleet_outputs: outputs?.length ?? 0,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
  };
}

export function evaluateElasticArea(
  area: ElasticAssessmentArea,
  snapshot: ElasticSnapshot,
  options: ElasticAssessmentOptions = {},
  context: { now?: number; elasticsearchUrl?: string } = {},
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
      return evaluateElasticClusterHardening(snapshot, options, now);
    case "kibana":
      return evaluateElasticKibana(snapshot, options);
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
  return evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: client.getResolvedConfig().elasticsearchUrl });
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
  "ilm_policies",
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
    const dataset = snapshot[name] ?? { name, target: DATASET_SPECS[name].target, endpoint: DATASET_SPECS[name].endpoint, error: "not collected" };
    return {
      name,
      target: dataset.target,
      endpoint: dataset.endpoint,
      status: dataset.skipped ? "not_configured" : dataset.error ? "not_readable" : "readable",
      count: dataset.error || dataset.skipped ? undefined : datasetCount(dataset),
      error: dataset.error ?? dataset.skipped,
    };
  });

  let privileges: JsonRecord | undefined;
  let privilegeError: string | undefined;
  try {
    privileges = typeof client.hasPrivileges === "function" ? await client.hasPrivileges() : undefined;
  } catch (error) {
    privilegeError = redactSecrets(errorMessage(error), config);
  }
  const missing = privileges ? missingPrivilegeSummary(privileges) : { cluster: [], index: [] };

  const authenticated = datasetData<JsonRecord>(snapshot, "authenticate");
  const coreReadable = CORE_ACCESS_SURFACES.every((name) => snapshot[name]?.error === undefined && snapshot[name]?.skipped === undefined);
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const configuredCount = surfaces.filter((surface) => surface.status !== "not_configured").length;
  const status: ElasticAccessCheckResult["status"] = coreReadable && missing.cluster.length === 0 ? "healthy" : "limited";
  const notes = [
    `Using Elasticsearch ${config.elasticsearchUrl} with ${config.authMode} authentication.`,
    config.kibanaUrl ? `Kibana ${config.kibanaUrl}${config.kibanaSpaceId ? ` (space ${config.kibanaSpaceId})` : ""} is configured.` : "Kibana is not configured (set KIBANA_URL to enable Kibana checks).",
    config.cloudApiKey ? `Elastic Cloud API ${config.cloudApiUrl} is configured.` : "Elastic Cloud API key is not configured (optional).",
    authenticated
      ? `Authenticated as ${asString(authenticated.username) ?? "unknown"} via ${asString(getNestedValue(authenticated, ["authentication_realm", "type"])) ?? "unknown"} realm with roles ${asStringList(authenticated.roles).join(", ") || "(none)"}.`
      : `Authentication probe failed: ${datasetProblem(snapshot, "authenticate")}.`,
    `${readableCount}/${configuredCount} configured audit surfaces are readable.`,
    ...(privilegeError ? [`Privilege probe failed: ${privilegeError}`] : []),
    ...(missing.cluster.length > 0 ? [`Missing cluster privileges: ${missing.cluster.join(", ")}.`] : []),
    ...(missing.index.length > 0 ? [`Missing index privileges: ${missing.index.join(", ")}.`] : []),
  ];

  return {
    status,
    elasticsearchUrl: config.elasticsearchUrl,
    kibanaUrl: config.kibanaUrl,
    cloudConfigured: Boolean(config.cloudApiKey),
    authenticatedAs: asString(authenticated?.username),
    authenticationRealm: asString(getNestedValue(authenticated, ["authentication_realm", "type"])),
    surfaces,
    missingClusterPrivileges: missing.cluster,
    missingIndexPrivileges: missing.index,
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
    surface.count === undefined ? "-" : String(surface.count),
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
    .map(([key, value]) => `- ${key}: ${Array.isArray(value) ? value.join(", ") || "(none)" : String(value)}`)
    .join("\n");

  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((error) => `- ${error}`)] : []),
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

function buildExecutiveSummary(config: ElasticResolvedConfig, assessments: ElasticAssessmentResult[], errors: string[]): string {
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
    "",
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
    "- `core_data/*.json`: raw API snapshots (secrets redacted, Fleet enrollment api_key values removed)",
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
    "Credentials are never written into the bundle.",
  ].join("\n");
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
  const assessments = areas.map((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl }));
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = listSnapshotErrors(snapshot);

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
    await writeSecureTextFile(outputDir, `core_data/${dataset.name}.json`, serializeJson({
      endpoint: dataset.endpoint,
      target: dataset.target,
      error: dataset.error ?? null,
      skipped: dataset.skipped ?? null,
      data: dataset.data ?? null,
    }));
  }

  await writeSecureTextFile(outputDir, "analysis/access.json", serializeJson(access));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson(assessment));
  }

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments, errors)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of ELASTIC_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${framework.key}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }

  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${clusterLabel}-audit-bundle.zip`);
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
  return new ElasticApiClient(resolveElasticConfiguration(args as JsonRecord));
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
  pi: any,
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
          `${definition.label} failed: ${errorMessage(error)}`,
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
          `Elastic access check failed: ${errorMessage(error)}`,
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
        const config = resolveElasticConfiguration(args as JsonRecord);
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
          ].join("\n"),
          {
            tool: "elastic_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Elastic audit bundle export failed: ${errorMessage(error)}`,
          { tool: "elastic_export_audit_bundle" },
        );
      }
    },
  });
}
