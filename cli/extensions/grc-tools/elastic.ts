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
  ): Promise<ElasticPagedList> {
    const limit = clampNumber(options.limit, DEFAULT_KIBANA_LIMIT, 1, 10_000);
    const perPage = Math.min(DEFAULT_KIBANA_PAGE_SIZE, limit);
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    for (let page = 1; items.length < limit; page += 1) {
      const payload = asObject(await this.kibanaGet(path, {
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

  async listApiKeys(limit = DEFAULT_API_KEY_LIMIT): Promise<ElasticPagedList> {
    const maxItems = clampNumber(limit, DEFAULT_API_KEY_LIMIT, 1, 10_000);
    const size = Math.min(DEFAULT_API_KEY_PAGE_SIZE, maxItems);
    const items: JsonRecord[] = [];
    let searchAfter: unknown[] | undefined;
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    while (items.length < maxItems) {
      const payload = asObject(await this.esPost("/_security/_query/api_key", {
        size,
        sort: [{ creation: { order: "asc" } }, { name: { order: "asc" } }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      }, { with_limited_by: true })) ?? {};
      pages += 1;
      const pageItems = asObjectArray(payload.api_keys);
      items.push(...pageItems.slice(0, maxItems - items.length));
      total = asNumber(payload.total) ?? total;
      const last = pageItems[pageItems.length - 1];
      searchAfter = last ? asArray(last._sort) : undefined;
      if (pageItems.length < size || !searchAfter || searchAfter.length === 0 || (total !== undefined && items.length >= total)) {
        exhausted = true;
        break;
      }
    }
    return pagedList(items, total, pages, exhausted);
  }

  async getIlmStatus(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ilm/status")) ?? {};
  }

  async listIlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_ilm/policy")) ?? {};
  }

  async getSlmStatus(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_slm/status")) ?? {};
  }

  async listSlmPolicies(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_slm/policy")) ?? {};
  }

  async listSnapshotRepositories(): Promise<JsonRecord> {
    return asObject(await this.esGet("/_snapshot/_all")) ?? {};
  }

  async listWatches(limit = DEFAULT_WATCH_LIMIT): Promise<ElasticPagedList> {
    const maxItems = clampNumber(limit, DEFAULT_WATCH_LIMIT, 1, 10_000);
    const size = Math.min(DEFAULT_WATCH_PAGE_SIZE, maxItems);
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let pages = 0;
    let exhausted = false;
    for (let from = 0; items.length < maxItems; from += size) {
      const payload = asObject(await this.esPost("/_watcher/_query/watches", { from, size })) ?? {};
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

  async listAgentPolicies(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/fleet/agent_policies", { perPageParam: "perPage", itemsKey: "items", limit });
  }

  async listFleetOutputs(): Promise<JsonRecord[]> {
    return asObjectArray(asObject(await this.kibanaGet("/api/fleet/outputs"))?.items);
  }

  async listEnrollmentApiKeys(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    const page = await this.listKibanaPages("/api/fleet/enrollment_api_keys", { perPageParam: "perPage", itemsKey: "items", limit });
    return { ...page, items: page.items.map((item) => ({ ...item, api_key: item.api_key === undefined ? undefined : "[REDACTED]" })) };
  }

  async listFleetServerHosts(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/fleet/fleet_server_hosts", { perPageParam: "perPage", itemsKey: "items", limit });
  }

  async listDetectionRules(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
    return this.listKibanaPages("/api/detection_engine/rules/_find", { perPageParam: "per_page", itemsKey: "data", limit });
  }

  async listAlertingRules(limit = DEFAULT_KIBANA_LIMIT): Promise<ElasticPagedList> {
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
  fleet_outputs: { name: "fleet_outputs", target: "kibana", endpoint: "GET /api/fleet/outputs", load: (client) => requireMethod(client, "listFleetOutputs")() },
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
        data: redactSensitiveValues(paged ? paged.items : loaded),
        ...(paged ? { page: { seen: paged.seen, total: paged.total, truncated: paged.truncated, pages: paged.pages } } : {}),
      };
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

function datasetPage(snapshot: ElasticSnapshot, name: ElasticDatasetName): ElasticPageInfo | undefined {
  const dataset = snapshot[name];
  return dataset && dataset.error === undefined && dataset.skipped === undefined ? dataset.page : undefined;
}

function dependencyProblems(snapshot: ElasticSnapshot, names: ElasticDatasetName[]): string[] {
  return names
    .map((name) => {
      const problem = datasetProblem(snapshot, name);
      return problem ? `${name} (${DATASET_SPECS[name].endpoint}): ${problem}` : undefined;
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
  problems: string[];
  partial: string[];
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
  const evidence: JsonRecord = {
    ...(computed.evidence ?? {}),
    unreadable_sources: guard.problems,
    partial_sources: guard.partial,
  };
  if (computed.status === "fail") {
    const notes = [...guard.problems, ...guard.partial];
    return finding(number, severity, "fail", notes.length > 0 ? `${computed.summary} Additional sources were unreadable or partial: ${notes.join("; ")}.` : computed.summary, evidence);
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
  if (guard.partial.length > 0) {
    return finding(
      number,
      severity,
      computed.status === "manual" ? "manual" : "warn",
      `${computed.summary} Verdict is capped at warn because the inventory is partial: ${guard.partial.join("; ")}.`,
      evidence,
    );
  }
  return finding(number, severity, computed.status, computed.summary, evidence);
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
  return { type, status, rank, active: status === undefined ? undefined : status === "active" };
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
  const license = licenseState(datasetData<JsonRecord>(snapshot, "license"));
  const privileges = datasetData<JsonRecord>(snapshot, "privileges");
  const roles = datasetData<JsonRecord>(snapshot, "roles");
  const roleMappings = datasetData<JsonRecord>(snapshot, "role_mappings");
  const apiKeys = datasetData<JsonRecord[]>(snapshot, "api_keys");
  const findings: ElasticFinding[] = [];
  const settingsProblems = settingsDependencyProblems(snapshot, view);
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const security = securityEnabledState(view, usage);

  const allRealms = parseRealms(view);
  const realms = allRealms.filter((realm) => realm.enabled);
  const usageTypes = usageRealmTypes(usage);
  const realmTypes = new Set(realms.map((realm) => realm.type));
  const secureRealmTypes = [...realmTypes].filter((type) => SECURE_REALM_TYPES.has(type));
  const realmEvidence = allRealms.map((realm) => ({ type: realm.type, name: realm.name, order: realm.order ?? null, enabled: realm.enabled }));
  const realmCollect = "the xpack.security.authc.realms.* section of elasticsearch.yml from every node (including order and enabled flags), or the Elastic Cloud deployment security settings page.";

  const realmsReadable = settingsProblems.length === 0;
  findings.push(guardedFinding(1, "high", {
    status: security.enabled === false
      ? "fail"
      : !realmsReadable
        ? "manual"
        : secureRealmTypes.length === 0
          ? "fail"
          : security.enabled === undefined
            ? "warn"
            : "pass",
    summary: security.enabled === false
      ? `xpack.security.enabled is false${security.disabledNodes.length > 0 ? ` on ${security.disabledNodes.join(", ")}` : ""}, so no authentication realm is enforced.`
      : !realmsReadable
        ? `realm settings were not readable (usage statistics report realm types: ${usageTypes.join(", ") || "none"}).`
        : secureRealmTypes.length === 0
          ? `Only native/file style realms are enabled (${[...realmTypes].join(", ") || "none configured, so the implicit native and file realms apply"}); no LDAP, Active Directory, PKI, SAML, Kerberos, OIDC, or JWT realm is enabled.`
          : security.enabled === undefined
          ? `Secure realms are enabled (${secureRealmTypes.join(", ")}) but xpack.security.enabled was not visible in settings or usage statistics, so enforcement could not be confirmed.`
          : `Secure authentication realms are enabled beyond native/file: ${secureRealmTypes.join(", ")} (xpack.security.enabled confirmed true).`,
    evidence: { realms: realmEvidence, usage_realm_types: usageTypes, secure_realm_types: secureRealmTypes, security_enabled: security.enabled ?? null },
  }, { problems: settingsProblems, partial: nodeNotes, collect: realmCollect }));

  const ssoRealms = realms.filter((realm) => SSO_REALM_TYPES.has(realm.type));
  const usageSso = usageTypes.filter((type) => SSO_REALM_TYPES.has(type));
  const ssoCollect = "the SAML or OIDC realm settings (attributes.principal, attributes.groups, claims.principal, claims.groups, authorization_realms), the role mappings that assign roles to SSO users (GET /_security/role_mapping), and the identity provider integration evidence.";
  if (settingsProblems.length > 0) {
    findings.push(manualFinding(13, "medium", `SSO realm settings could not be read: ${settingsProblems.join("; ")}.`, ssoCollect, { unreadable_sources: settingsProblems }));
  } else if (ssoRealms.length === 0) {
    findings.push(manualFinding(
      13,
      "medium",
      usageSso.length > 0
        ? `Not applicable from settings: no enabled SAML or OIDC realm is configured on the inspected nodes, although usage statistics report ${usageSso.join(", ")} realms.`
        : "Not applicable: no SAML or OIDC realm is enabled, so SSO attribute mapping and role assignment are scoped out of the API assessment.",
      "confirmation that SSO is not required for this cluster, or the identity provider integration evidence if SSO is delivered outside Elasticsearch realms (for example Elastic Cloud SSO).",
      { sso_realms: [], usage_sso_realm_types: usageSso, realms: realmEvidence },
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
        role_mappings: mappings,
        has_role_assignment: mappings.length > 0 || authorizationRealms.length > 0,
      };
    });
    const missingPrincipal = ssoEvidence.filter((entry) => !entry.principal_attribute);
    const withoutRoles = roleMappings ? ssoEvidence.filter((entry) => !entry.has_role_assignment) : [];
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
                ? `${ssoRealms.length} SSO realm(s) define a principal attribute and role assignment, but ${ssoLicense === undefined ? `the license tier (${license.type ?? "unknown"}, status ${license.status ?? "unknown"}) could not be confirmed to include SSO` : "xpack.security.enabled was not visible"}, so enforcement is unconfirmed.`
                : `${ssoRealms.length} SSO realm(s) define a principal attribute and have enabled role mappings or authorization realms assigning roles (${mappingEntries.length} role mappings read; ${license.type} license supports SSO).`,
      evidence: { sso_realms: ssoEvidence, role_mapping_count: mappingEntries.length, license_supports_sso: ssoLicense ?? null, security_enabled: security.enabled ?? null },
    }, { problems: ssoProblems, partial: nodeNotes, collect: ssoCollect }));
  }

  const anonymousRoles = asStringList(view.get("xpack.security.authc.anonymous.roles"));
  const anonymousUsername = asString(view.get("xpack.security.authc.anonymous.username"));
  const anonymousAuthzException = asBoolean(view.get("xpack.security.authc.anonymous.authz_exception"));
  const usageAnonymous = usageFlag(usage, ["anonymous", "enabled"]);
  const anonymousEnabled = anonymousRoles.length > 0 || usageAnonymous === true;
  const anonymousRoleDescriptors = anonymousRoles.map((name) => asObject(roles?.[name]) ?? {});
  const broadAnonymous = anonymousRoles.includes("superuser")
    || anonymousRoleDescriptors.some((descriptor) => descriptorGrantsClusterAll(descriptor) || descriptorGrantsWildcardIndexAll(descriptor));
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
            : "Anonymous access is disabled: xpack.security.authc.anonymous.roles is unset on every inspected node and xpack.security.enabled is true (absence of anonymous roles is the compliant state for this control).",
    evidence: {
      anonymous_enabled: anonymousEnabled,
      anonymous_roles: anonymousRoles,
      anonymous_username: anonymousUsername ?? null,
      anonymous_authz_exception: anonymousAuthzException ?? null,
      usage_anonymous_enabled: usageAnonymous ?? null,
      security_enabled: security.enabled ?? null,
    },
  }, { problems: settingsProblems, partial: nodeNotes, collect: "the xpack.security.authc.anonymous.* settings and xpack.security.enabled from elasticsearch.yml on every node." }));

  const apiKeyPage = datasetPage(snapshot, "api_keys");
  const apiKeyVisibility = apiKeyInventoryVisibility(privileges);
  const apiKeyProblems = dependencyProblems(snapshot, ["api_keys", "privileges"]);
  const apiKeyPartial = [
    ...truncationNotes(snapshot, ["api_keys"]),
    ...(apiKeyVisibility === false
      ? [`the credential lacks read_security, manage_api_key, and manage_security, so POST /_security/_query/api_key returns only its own keys (${apiKeys?.length ?? 0} seen of an unknown total)`]
      : []),
  ];
  const keyInventoryLabel = `${apiKeys?.length ?? 0} key(s) seen${apiKeyPage?.total !== undefined ? ` of ${apiKeyPage.total} total` : ""}`;
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
  findings.push(guardedFinding(9, "high", {
    status: hygieneStatus,
    summary: hygieneStatus === "fail"
      ? `${unmanagedWithoutExpiration.length} active non-Fleet API key(s) have no expiration and ${unmanagedStale.length} are older than ${maxApiKeyAgeDays} days (${active.length} active, ${keyInventoryLabel}).`
      : hygieneStatus === "warn"
        ? `${fleetIssues} Fleet-managed key(s) lack expiration or exceed ${maxApiKeyAgeDays} days, ${missingCreation.length} active key(s) report no creation date and are not counted as fresh, and ${invalidated.length} invalidated plus ${expired.length} expired keys still linger (${active.length} active, ${keyInventoryLabel}).`
        : keys.length === 0
          ? `No API keys exist (${keyInventoryLabel} with full inventory visibility). This control concerns existing keys, so an empty inventory is compliant.`
          : `All ${active.length} active API keys carry an expiration, are newer than ${maxApiKeyAgeDays} days, report creation dates, and no inactive keys linger (${keyInventoryLabel}).`,
    evidence: {
      inspected: keys.length,
      total_reported: apiKeyPage?.total ?? null,
      active: active.length,
      invalidated: invalidated.length,
      expired: expired.length,
      without_expiration: withoutExpiration.length,
      missing_creation_date: missingCreation.slice(0, 25).map((key) => apiKeySample(key)),
      older_than_max_age: stale.length,
      max_api_key_age_days: maxApiKeyAgeDays,
      full_visibility: apiKeyVisibility ?? null,
      flagged: [...unmanagedWithoutExpiration, ...unmanagedStale.filter((key) => !unmanagedWithoutExpiration.includes(key))]
        .slice(0, 25)
        .map((key) => apiKeySample(key, { age_days: asNumber(key.creation) === undefined ? null : daysBetween(asNumber(key.creation) ?? now, now) })),
    },
  }, {
    problems: apiKeyProblems,
    partial: apiKeyPartial,
    collect: "the output of GET /_security/_query/api_key run by a principal with read_security or manage_api_key (all pages), and the API key rotation records.",
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
  findings.push(guardedFinding(10, "high", {
    status: privileged.length > 0 ? "fail" : unverifiable > 0 ? "warn" : "pass",
    summary: privileged.length > 0
      ? `${privileged.length}/${active.length} active API keys carry superuser-equivalent or cluster-wide privileges (${keyInventoryLabel}).`
      : unverifiable > 0
        ? `${unverifiable}/${active.length} active API keys inherit owner privileges but limited_by was not visible (requires manage_api_key), so their scope could not be verified.`
        : active.length === 0
          ? `No active API keys exist (${keyInventoryLabel} with full inventory visibility). This control concerns existing keys, so an empty inventory is compliant.`
          : `All ${active.length} active API keys are scoped below superuser-equivalent privileges (${keyInventoryLabel}).`,
    evidence: { active: active.length, inspected: keys.length, total_reported: apiKeyPage?.total ?? null, privileged: privileged.slice(0, 25), unverifiable, full_visibility: apiKeyVisibility ?? null },
  }, {
    problems: apiKeyProblems,
    partial: apiKeyPartial,
    collect: "the role_descriptors and limited_by sections of every active API key (GET /_security/_query/api_key?with_limited_by=true, all pages, run with manage_api_key).",
  }));

  return {
    area: "identity",
    title: "Elastic identity and authentication",
    summary: {
      realm_types: [...realmTypes],
      secure_realm_types: secureRealmTypes,
      security_enabled: security.enabled ?? null,
      anonymous_roles: anonymousRoles,
      api_keys_inspected: apiKeys?.length ?? 0,
      api_keys_total: apiKeyPage?.total ?? null,
      api_key_full_visibility: apiKeyVisibility ?? null,
      role_mappings: Object.keys(roleMappings ?? {}).length,
    },
    findings: findings.sort((left, right) => left.id.localeCompare(right.id)),
    errors: listSnapshotErrors(snapshot),
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

function evaluateIndexRestriction(
  number: number,
  label: string,
  restricted: RoleIndexEntry[],
  patterns: string[],
  license: ReturnType<typeof licenseState>,
  usageCount: number | undefined,
  problems: string[],
): ElasticFinding {
  const supported = licenseSupports(license, LICENSE_RANK.platinum);
  const restrictedRoles = [...new Set(restricted.map((entry) => entry.role))];
  const evidence: JsonRecord = {
    roles_with_restriction: restricted.slice(0, 50).map((entry) => ({ role: entry.role, indices: entry.names })),
    usage_count: usageCount ?? null,
    license_type: license.type ?? null,
    license_status: license.status ?? null,
    license_supports_feature: supported ?? null,
    patterns,
  };
  const collect = `the role definitions (GET /_security/role), the license (GET /_license), and the list of indices holding sensitive or tenant data, then confirm which roles apply ${label} to them.`;
  if (problems.length === 0 && supported === false) {
    if (patterns.length > 0) {
      return finding(number, "medium", "fail", `The ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include ${label}, so the ${patterns.length} supplied index pattern(s) cannot be protected by it.`, evidence);
    }
    return manualFinding(
      number,
      "medium",
      `Not applicable on this license tier: the ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include ${label}, so it cannot be enforced on this cluster.`,
      `evidence of compensating controls (separate indices or clusters per sensitivity level) or confirmation that no index requires ${label}.`,
      evidence,
    );
  }
  if (patterns.length > 0) {
    if (problems.length > 0) {
      return guardedFinding(number, "medium", {
        status: "manual",
        summary: `coverage of the ${patterns.length} supplied index pattern(s) by ${label} could not be evaluated.`,
        evidence: { ...evidence, uncovered_patterns: null },
      }, { problems, partial: [], collect });
    }
    const uncovered = patterns.filter((pattern) => !restricted.some((entry) => entry.names.some((name) => patternsOverlap(name, pattern))));
    return guardedFinding(number, "medium", {
      status: uncovered.length > 0 ? "fail" : supported === true ? "pass" : "warn",
      summary: uncovered.length > 0
        ? `${uncovered.length}/${patterns.length} supplied index patterns have no role applying ${label}: ${uncovered.join(", ")}.`
        : supported === true
          ? `Every supplied index pattern (${patterns.join(", ")}) is covered by at least one role applying ${label} (${license.type} license supports it).`
          : `Every supplied index pattern (${patterns.join(", ")}) is covered by a role applying ${label}, but the license tier (${license.type ?? "unknown"}, status ${license.status ?? "unknown"}) could not be confirmed to include it.`,
      evidence: { ...evidence, uncovered_patterns: uncovered },
    }, { problems, partial: [], collect });
  }
  return guardedFinding(number, "medium", {
    status: "warn",
    summary: restrictedRoles.length > 0
      ? `${restrictedRoles.length} role(s) apply ${label} (${restrictedRoles.slice(0, 10).join(", ")}), but no index patterns were supplied, so coverage of the sensitive indices could not be verified.`
      : `No role applies ${label} and no index patterns were supplied; identify indices holding sensitive or tenant data and confirm whether ${label} is required.`,
    evidence,
  }, { problems, partial: [], collect });
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
  const license = licenseState(datasetData<JsonRecord>(snapshot, "license"));
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
  const roleInventoryProblems = [
    ...dependencyProblems(snapshot, ["roles"]),
    ...[emptyInventoryProblem(snapshot, "roles", roles ? roleEntries.length : undefined, "built-in roles such as superuser are always returned")].filter((item): item is string => Boolean(item)),
  ];
  const rbacProblems = [
    ...roleInventoryProblems,
    ...dependencyProblems(snapshot, ["users", "role_mappings"]),
    ...[emptyInventoryProblem(snapshot, "users", users ? userEntries.length : undefined, "built-in users such as elastic are always returned")].filter((item): item is string => Boolean(item)),
  ];

  const rbacStatus: ElasticFinding["status"] = (users && superusers.length > maxSuperusers) || usersWithBroadRoles.length > 0
    ? "fail"
    : broadRoles.length > 0 || superuserMappings.length > 0
      ? "warn"
      : "pass";
  findings.push(guardedFinding(6, "high", {
    status: rbacStatus,
    summary: rbacStatus === "fail"
      ? `${superusers.length} native users hold superuser (threshold ${maxSuperusers}) and ${usersWithBroadRoles.length} users hold custom roles granting cluster all or index all on *.`
      : rbacStatus === "warn"
        ? `${broadRoles.length} custom role(s) grant cluster all or wildcard index all and ${superuserMappings.length} role mapping(s) assign superuser or broad roles; no native user currently exceeds the superuser threshold.`
        : `${roleEntries.length} roles, ${userEntries.length} users, and ${Object.keys(roleMappings ?? {}).length} role mappings reviewed; ${superusers.length} superuser holder(s) within threshold ${maxSuperusers}, no custom role grants cluster all or wildcard index all, and no role mapping assigns broad roles.`,
    evidence: {
      roles_reviewed: roleEntries.length,
      custom_roles: customRoles.length,
      users_reviewed: userEntries.length,
      role_mappings_reviewed: Object.keys(roleMappings ?? {}).length,
      superusers,
      max_superusers: maxSuperusers,
      cluster_all_roles: clusterAllRoles,
      wildcard_index_all_roles: wildcardIndexRoles,
      users_with_broad_roles: usersWithBroadRoles.slice(0, 25),
      superuser_role_mappings: superuserMappings,
    },
  }, {
    problems: rbacProblems,
    partial: [],
    collect: "the role definitions (GET /_security/role), user list (GET /_security/user), and role mappings (GET /_security/role_mapping), then identify superuser holders and roles granting cluster all or index all on *.",
  }));

  const indexEntries = roles ? roleIndexEntries(roles) : [];
  const flsProblems = [...roleInventoryProblems, ...dependencyProblems(snapshot, ["license"])];
  findings.push(evaluateIndexRestriction(
    7,
    "field-level security",
    indexEntries.filter((entry) => entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0),
    options.sensitiveIndexPatterns ?? [],
    license,
    asNumber(getNestedValue(usage, ["security", "roles", "native", "fls"])),
    flsProblems,
  ));
  findings.push(evaluateIndexRestriction(
    8,
    "document-level security",
    indexEntries.filter((entry) => entry.query !== undefined && entry.query !== null && entry.query !== ""),
    options.tenantIndexPatterns ?? [],
    license,
    asNumber(getNestedValue(usage, ["security", "roles", "native", "dls"])),
    flsProblems,
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
      license_type: license.type ?? null,
      license_status: license.status ?? null,
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
  security: ReturnType<typeof securityEnabledState>,
  elasticsearchUrl: string | undefined,
  guard: VerdictGuard,
): ElasticFinding {
  const key = `xpack.security.${layer}.ssl.enabled`;
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
    per_node: perNode.map((entry) => ({ node: entry.node, value: entry.value ?? null })),
    enabled_nodes: enabledNodes,
    disabled_nodes: disabledNodes,
    unset_nodes: unsetNodes,
    effective_setting: effective ?? null,
    usage_reported_enabled: usageEnabled ?? null,
    security_enabled: security.enabled ?? null,
    ...(layer === "transport" ? { verification_mode_per_node: verificationModes } : {}),
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
      summary: `${key} is not explicitly set on ${unsetNodes.join(", ")} (the documented default is false) and ${usageEnabled === true ? "usage statistics report it enabled" : "usage statistics do not confirm it"}; verify the effective value on every node.`,
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
      summary: `${layerLabel} layer TLS is explicitly enabled on all ${enabledNodes.length} node(s) with xpack.security.enabled true${layer === "transport" ? ` and verification_mode ${[...new Set(verificationModes.map((entry) => entry.value))].join(", ")}` : ""}.`,
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
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const security = securityEnabledState(view, usage);
  const settingsGuard = (collect: string): VerdictGuard => ({ problems: settingsProblems, partial: nodeNotes, collect });
  const transportFinding = evaluateTlsLayer(2, "transport", view, usage, security, elasticsearchUrl, settingsGuard("xpack.security.transport.ssl.enabled and verification_mode from elasticsearch.yml on every node (or the Elastic Cloud deployment TLS configuration)."));
  const httpFinding = evaluateTlsLayer(3, "http", view, usage, security, elasticsearchUrl, settingsGuard("xpack.security.http.ssl.enabled from elasticsearch.yml on every node (or the Elastic Cloud deployment TLS configuration)."));
  const findings: ElasticFinding[] = [transportFinding, httpFinding];

  const protocolKeys = ["xpack.security.transport.ssl.supported_protocols", "xpack.security.http.ssl.supported_protocols"];
  const perNodeProtocols = view.nodes.map((node) => ({
    node: node.name,
    major: asNumber(node.version?.split(".")[0]) ?? null,
    protocols: Object.fromEntries(protocolKeys.map((key) => [key, asStringList(node.settings[key])])),
  }));
  const weakProtocols = [...new Set(perNodeProtocols.flatMap((entry) => Object.values(entry.protocols).flat()).filter((protocol) => !MINIMUM_TLS_PROTOCOLS.has(protocol)))];
  const unsafeDefaultNodes = perNodeProtocols
    .filter((entry) => Object.values(entry.protocols).some((list) => list.length === 0) && (entry.major === null || entry.major < 8))
    .map((entry) => entry.node);
  const majors = nodeMajorVersions(view);
  const tlsCeiling = statusCeiling(transportFinding.status, httpFinding.status);
  const protocolComputed: Verdict = weakProtocols.length > 0
    ? { status: "fail", summary: `Supported TLS protocols include versions below TLSv1.2: ${weakProtocols.join(", ")}.` }
    : tlsCeiling === "fail"
      ? { status: "fail", summary: "TLS is not enforced on every layer (see ELASTIC-02 and ELASTIC-03), so no minimum protocol version applies to the unencrypted traffic." }
      : unsafeDefaultNodes.length > 0
        ? { status: "warn", summary: `supported_protocols is not explicitly set on every layer for ${unsafeDefaultNodes.join(", ")}, which run Elasticsearch 7.x or an unknown version whose defaults can include TLSv1.1.` }
        : tlsCeiling !== "pass"
          ? { status: statusCeiling("warn", tlsCeiling === "manual" ? "manual" : "warn"), summary: `TLS protocol settings are TLSv1.2 or newer on every node, but TLS enforcement itself is ${tlsCeiling} (see ELASTIC-02 and ELASTIC-03), so the protocol floor is not confirmed effective.` }
          : {
            status: "pass",
            summary: perNodeProtocols.every((entry) => Object.values(entry.protocols).every((list) => list.length > 0))
              ? `Supported TLS protocols are explicitly restricted to ${[...new Set(perNodeProtocols.flatMap((entry) => Object.values(entry.protocols).flat()))].join(", ")} on all ${perNodeProtocols.length} node(s).`
              : `Every node runs Elasticsearch 8.x, whose documented default supported_protocols is TLSv1.3 and TLSv1.2, and no node configures a weaker protocol (explicit settings: ${perNodeProtocols.filter((entry) => Object.values(entry.protocols).every((list) => list.length > 0)).length}/${perNodeProtocols.length} nodes).`,
          };
  findings.push(guardedFinding(4, "high", {
    ...protocolComputed,
    evidence: { protocols_per_node: perNodeProtocols, weak_protocols: weakProtocols, node_major_versions: majors, tls_enforcement_status: tlsCeiling },
  }, settingsGuard("xpack.security.transport.ssl.supported_protocols and xpack.security.http.ssl.supported_protocols from elasticsearch.yml on every node.")));

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
  const nodeTotal = asNumber(asObject(nodeSettings?._nodes)?.total) ?? view.nodes.length;
  const certificatePartial = nodeSettings === undefined
    ? ["GET /_ssl/certificates reports only the node that handled the request and the node inventory could not be read, so certificates on other nodes are unknown"]
    : nodeTotal > 1
      ? [`GET /_ssl/certificates reports only the node that handled the request, but the cluster has ${nodeTotal} nodes; run the check against each node to cover every keystore and truststore`]
      : [];
  findings.push(guardedFinding(5, "high", {
    status: expired.length > 0 ? "fail" : expiring.length > 0 || missingExpiry.length > 0 ? "warn" : "pass",
    summary: expired.length > 0
      ? `${expired.length} TLS certificate(s) have expired and ${expiring.length} expire within ${warningDays} days.`
      : expiring.length > 0 || missingExpiry.length > 0
        ? `${expiring.length}/${inventory.length} TLS certificate(s) expire within ${warningDays} days and ${missingExpiry.length} report no expiry date (not counted as valid).`
        : `All ${inventory.length} TLS certificates on the responding node report an expiry date and remain valid for at least ${warningDays} more days${nodeTotal === 1 ? " (single-node cluster, so the inventory is complete)" : ""}.`,
    evidence: { certificates: inventory.slice(0, 25), expired: expired.length, expiring_soon: expiring.length, missing_expiry: missingExpiry.length, cert_expiry_warning_days: warningDays, nodes_in_cluster: nodeTotal, single_node_view: true },
  }, {
    problems: certificateProblems,
    partial: certificatePartial,
    collect: "the output of GET /_ssl/certificates from every node (the API reports only the node that handles the request and requires the monitor cluster privilege), or the certificate inventory with expiry dates for every node keystore and truststore.",
  }));

  return {
    area: "transport_security",
    title: "Elastic transport and HTTP TLS",
    summary: {
      nodes_inspected: view.nodes.length,
      security_enabled: security.enabled ?? null,
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
  const nodeNotes = nodeInventoryNotes(nodeSettings);
  const licenseProblems = dependencyProblems(snapshot, ["license"]);
  const security = securityEnabledState(view, usage, xpackInfo);

  const auditPerNode = perNodeBooleans(view, "xpack.security.audit.enabled");
  const auditEnabledNodes = auditPerNode.filter((entry) => entry.value === true).map((entry) => entry.node);
  const auditDisabledNodes = auditPerNode.filter((entry) => entry.value !== true).map((entry) => entry.node);
  const auditEnabled = auditPerNode.length > 0 && auditDisabledNodes.length === 0;
  const auditLicense = licenseSupports(license, LICENSE_RANK.gold);
  const includeSetting = asStringList(view.get("xpack.security.audit.logfile.events.include"));
  const excludeSetting = asStringList(view.get("xpack.security.audit.logfile.events.exclude"));
  const effectiveInclude = (includeSetting.length > 0 ? includeSetting : DEFAULT_AUDIT_INCLUDE).filter((event) => !excludeSetting.includes(event));
  const missingEvents = REQUIRED_AUDIT_EVENTS.filter((event) => !effectiveInclude.includes(event));
  const auditOutputs = asStringList(getNestedValue(usage, ["security", "audit", "outputs"]));
  const auditEvidence: JsonRecord = {
    per_node: auditPerNode.map((entry) => ({ node: entry.node, value: entry.value ?? null })),
    enabled_nodes: auditEnabledNodes,
    disabled_or_unset_nodes: auditDisabledNodes,
    usage_reported_enabled: usageFlag(usage, ["audit", "enabled"]) ?? null,
    events_include: includeSetting,
    events_exclude: excludeSetting,
    effective_include: effectiveInclude,
    outputs: auditOutputs,
    license_type: license.type ?? null,
    license_supports_audit: auditLicense ?? null,
    security_enabled: security.enabled ?? null,
  };
  const auditGuard: VerdictGuard = {
    problems: [...settingsProblems, ...licenseProblems],
    partial: nodeNotes,
    collect: "xpack.security.audit.* settings from elasticsearch.yml on every node, the license tier (GET /_license), and a sample of <cluster>_audit.json.",
  };
  const auditOff = settingsProblems.length === 0 && !auditEnabled;
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
          ? "xpack.security.audit.enabled is not explicitly true on any inspected node (the documented default is false), so security audit logging is disabled."
          : `Audit logging is enabled on ${auditEnabledNodes.join(", ")} but disabled or unset on ${auditDisabledNodes.join(", ")}, so events on those nodes are not recorded.`
        : auditLicense === false
          ? `xpack.security.audit.enabled is true but the ${license.type ?? "current"} license (status ${license.status ?? "unknown"}) does not include audit logging, so no audit trail is produced.`
          : missingEvents.length > 0
            ? `Audit logging is enabled on all ${auditEnabledNodes.length} node(s) but the effective event include list omits ${missingEvents.join(", ")}.`
            : security.enabled === undefined
              ? `Audit logging is enabled on all ${auditEnabledNodes.length} node(s) but xpack.security.enabled was not visible, so enforcement could not be confirmed.`
              : `Audit logging is explicitly enabled on all ${auditEnabledNodes.length} node(s) with authentication_failed, access_denied, and security_config_change events included (${license.type} license supports audit logging).`,
    evidence: { ...auditEvidence, missing_required_events: missingEvents },
  }, auditGuard));
  findings.push(auditOff || security.enabled === false
    ? guardedFinding(12, "medium", { status: "fail", summary: "Audit logging is disabled on at least one node, so no complete audit output exists to protect.", evidence: auditEvidence }, auditGuard)
    : settingsProblems.length > 0
      ? manualFinding(12, "medium", `Audit settings could not be read: ${settingsProblems.join("; ")}.`, "evidence that <cluster>_audit.json is shipped to a tamper-resistant destination (Filebeat or Elastic Agent elasticsearch.audit integration, or a SIEM) with retention and integrity controls.", auditEvidence)
      : manualFinding(
        12,
        "medium",
        `Elasticsearch writes audit events only to the local logfile output (${auditOutputs.join(", ") || "logfile"}) on each node; forwarding to a tamper-resistant store cannot be verified through the API.`,
        "evidence that <cluster>_audit.json is shipped to a tamper-resistant destination (Filebeat or Elastic Agent elasticsearch.audit integration, or a SIEM) with retention and integrity controls.",
        auditEvidence,
      ));

  const ilmMode = asString(ilmStatus?.operation_mode)?.toUpperCase();
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
  const ilmEmpty = ilmPolicies !== undefined && policies.length === 0;
  const ilmStopped = ilmStatus !== undefined && ilmMode !== "RUNNING";
  findings.push(guardedFinding(17, "medium", {
    status: ilmEmpty || ilmStopped ? "fail" : inUseWithoutDelete.length > 0 ? "warn" : "pass",
    summary: ilmEmpty
      ? "No index lifecycle policies exist (zero policies is a failure for this control because retention and deletion are not enforced through ILM)."
      : ilmStopped
        ? `ILM operation_mode is ${ilmMode ?? "unknown"} rather than RUNNING, so lifecycle policies are not executing.`
        : inUseWithoutDelete.length > 0
          ? `${inUseWithoutDelete.length}/${policies.length} in-use ILM policies have no delete phase: ${inUseWithoutDelete.slice(0, 10).map((policy) => policy.name).join(", ")}.`
          : `All ${policies.filter((policy) => policy.in_use).length} in-use ILM policies define a delete phase and ILM operation_mode is RUNNING.`,
    evidence: {
      operation_mode: ilmMode ?? null,
      policies: policies.slice(0, 50),
      without_rollover: policies.filter((policy) => policy.in_use && !policy.has_rollover).map((policy) => policy.name).slice(0, 25),
    },
  }, {
    problems: ilmProblems,
    partial: [],
    collect: "the ILM policy definitions (GET /_ilm/policy), the ILM status (GET /_ilm/status), and the retention schedule approved for each regulated data stream.",
  }));

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
    repositories: repoEntries,
    slm_policies: slmEntries,
    slm_operation_mode: slmMode ?? null,
    slm_policies_without_last_success: slmNeverSucceeded.map((entry) => entry.name),
  };
  const snapshotCollect = "the repository settings (GET /_snapshot/_all), storage encryption evidence for each bucket or filesystem, the SLM policies and status (GET /_slm/policy, GET /_slm/status), and the most recent successful snapshot per policy.";
  const reposEmpty = repositories !== undefined && repoEntries.length === 0;
  const slmEmpty = slmPolicies !== undefined && slmEntries.length === 0;
  const slmStopped = slmStatus !== undefined && slmMode !== "RUNNING";
  if (snapshotProblems.length === 0 && !reposEmpty && !slmEmpty && !slmStopped && manualRepos.length > 0) {
    findings.push(manualFinding(
      18,
      "high",
      `${manualRepos.length}/${repoEntries.length} repositories (${manualRepos.map((repo) => `${repo.name}:${repo.type}`).join(", ")}) do not expose an encryption setting through the API.`,
      "bucket default-encryption or filesystem/disk encryption evidence for each listed repository (S3 repositories can also set server_side_encryption: true).",
      snapshotEvidence,
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
    security_enabled_per_node: securityPerNode.map((entry) => ({ node: entry.node, value: entry.value ?? null })),
    password_hashing_algorithm: passwordHashing,
    password_hashing_explicit: passwordHashingSetting !== undefined,
    api_key_hashing_algorithm: apiKeyHashing,
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
    collect: "the xpack.security.* section of elasticsearch.yml from every node plus GET /_cluster/settings?include_defaults=true.",
  }));

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
  const alertingPartial = [...truncationNotes(snapshot, ["watches", "alerting_rules", "detection_rules"]), ...spaceScopeNotes];
  const alertingEvidence: JsonRecord = {
    watches: watches?.length ?? null,
    watcher_unreadable: watcherProblem ?? null,
    watcher_licensed: watcherLicensed ?? null,
    watcher_not_applicable: watcherNotApplicable,
    kibana_scoped_out: kibanaScopedOut ?? null,
    kibana_space_queried: kibanaSpaceId ?? "default",
    kibana_spaces_total: kibanaSpaces?.length ?? null,
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
  const alertingCollect = "the watch definitions (GET /_watcher/_query/watches) and the Kibana connector inventory from every space (GET /s/<space>/api/actions/connectors), then confirm webhook destinations use https and credentials are stored as secrets.";
  const alertingFailed = insecureWatchActions.length > 0 || insecureConnectors.length > 0;
  const alertingWarned = credentialWatchActions.length > 0 || connectorsMissingSecrets.length > 0;
  const alertingEmpty = (watches?.length ?? 0) === 0 && (connectors?.length ?? 0) === 0;
  if (!alertingFailed && alertingProblems.length === 0 && watcherNotApplicable && kibanaScopedOut) {
    findings.push(manualFinding(
      20,
      "medium",
      `Not applicable or scoped out: Watcher is not available on the ${license.type ?? "current"} license and Kibana is not configured (${kibanaScopedOut}), so no alerting destinations could be assessed.`,
      alertingCollect,
      alertingEvidence,
    ));
  } else if (!alertingFailed && alertingProblems.length === 0 && kibanaScopedOut) {
    findings.push(manualFinding(
      20,
      "medium",
      `Scoped out: Kibana is not configured (${kibanaScopedOut}), so only ${watches?.length ?? 0} watch(es) were reviewed${alertingWarned ? ` (${credentialWatchActions.length} embed basic-auth credentials)` : " and none use plain http webhooks"}; Kibana connectors and rule actions were not assessed.`,
      alertingCollect,
      alertingEvidence,
    ));
  } else if (!alertingFailed && alertingProblems.length === 0 && alertingEmpty && spaceScopeNotes.length > 0) {
    findings.push(manualFinding(
      20,
      "medium",
      `Zero watches and zero connectors were visible in the queried scope, but the connector inventory is space-scoped (${spaceScopeNotes.join("; ")}), so emptiness cannot be confirmed as compliant.`,
      alertingCollect,
      alertingEvidence,
    ));
  } else {
    findings.push(guardedFinding(20, "medium", {
      status: alertingFailed ? "fail" : alertingWarned ? "warn" : "pass",
      summary: alertingFailed
        ? `${insecureWatchActions.length} watch(es) and ${insecureConnectors.length} Kibana connector(s) send to plain http webhook destinations.`
        : alertingWarned
          ? `${credentialWatchActions.length} watch action(s) embed basic-auth credentials and ${connectorsMissingSecrets.length} connector(s) are missing secrets.`
          : alertingEmpty
            ? `Zero watches and zero connectors exist in the only Kibana space${watcherNotApplicable ? ` (Watcher is not available on the ${license.type} license)` : ""}; this passes because the control governs the security of existing alerting destinations and none exist.`
            : `${watches?.length ?? 0} watches and ${connectors?.length ?? 0} connectors reviewed (${rulesWithActions} rules carry actions); all webhook destinations use https and no inline credentials were found${watcherNotApplicable ? `; Watcher is not available on the ${license.type} license, so only Kibana connectors were assessed` : ""}.`,
      evidence: alertingEvidence,
    }, { problems: alertingProblems, partial: alertingPartial, collect: alertingCollect }));
  }

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
  const pipelineEvidence: JsonRecord = {
    pipelines: pipelineEntries.length,
    custom_pipelines: customPipelines.length,
    managed_pipelines: pipelineEntries.length - customPipelines.length,
    pipelines_with_sensitive_set: pipelinesWithSecrets.slice(0, 25),
    pipelines_with_scripts: pipelinesWithScripts.slice(0, 25).map((pipeline) => pipeline.name),
  };
  findings.push(guardedFinding(22, "medium", {
    status: pipelinesWithSecrets.length > 0 ? "fail" : pipelinesWithScripts.length > 0 ? "warn" : "pass",
    summary: pipelinesWithSecrets.length > 0
      ? `${pipelinesWithSecrets.length} custom ingest pipeline(s) set sensitive-looking literal values: ${pipelinesWithSecrets.slice(0, 10).map((pipeline) => pipeline.name).join(", ")}.`
      : pipelinesWithScripts.length > 0
        ? `${pipelinesWithScripts.length}/${customPipelines.length} custom ingest pipeline(s) use script processors; review them for data exposure.`
        : `${pipelineEntries.length} ingest pipelines reviewed (${customPipelines.length} custom, ${pipelineEntries.length - customPipelines.length} managed); no script processors or hardcoded sensitive values in custom pipelines.`,
    evidence: pipelineEvidence,
  }, {
    problems: [...pipelineProblems, ...(pipelinesEmpty ? [pipelinesEmpty] : [])],
    partial: [],
    collect: "the pipeline definitions (GET /_ingest/pipeline) as an administrator and review script and set processors for hardcoded sensitive values.",
  }));

  const licenseInfo = asObject(licenseData?.license);
  const licenseExpiry = isoDate(licenseInfo?.expiry_date_in_millis ?? licenseInfo?.expiry_date);
  const realmTypes = new Set([...parseRealms(view).filter((realm) => realm.enabled).map((realm) => realm.type), ...usageRealmTypes(usage)]);
  const usesFlsOrDls = roles ? roleIndexEntries(roles).some((entry) => (entry.fieldSecurity && Object.keys(entry.fieldSecurity).length > 0) || (entry.query !== undefined && entry.query !== null)) : false;
  const requirements = requiredLicenseRankFor(realmTypes, usesFlsOrDls, auditEnabled, watches?.length ?? 0);
  const unsupported = license.rank === undefined ? [] : requirements.filter((requirement) => requirement.rank > (license.rank as number));
  const expiryDays = licenseExpiry ? daysBetween(now, Date.parse(licenseExpiry)) : undefined;
  const expiryMissing = licenseData !== undefined && licenseExpiry === undefined && license.type !== "basic";
  const coverageProblems = license.rank !== undefined && license.rank >= LICENSE_RANK.platinum
    ? []
    : [...settingsProblems, ...dependencyProblems(snapshot, ["roles"])];
  const licenseEvidence: JsonRecord = {
    type: license.type ?? null,
    status: license.status ?? null,
    expiry: licenseExpiry ?? null,
    expiry_missing: expiryMissing,
    days_until_expiry: expiryDays ?? null,
    security_available: asBoolean(getNestedValue(xpackInfo, ["features", "security", "available"])) ?? null,
    security_enabled: asBoolean(getNestedValue(xpackInfo, ["features", "security", "enabled"])) ?? null,
    required_features: requirements.map((requirement) => ({ feature: requirement.feature, minimum_license: licenseLabel(requirement.rank) })),
    unsupported_features: unsupported.map((item) => item.feature),
  };
  findings.push(guardedFinding(23, "medium", {
    status: unsupported.length > 0 || license.active === false || (licenseData !== undefined && license.type === undefined)
      ? "fail"
      : license.type === "trial" || (expiryDays !== undefined && expiryDays < 30) || expiryMissing || license.active === undefined
        ? "warn"
        : "pass",
    summary: licenseData !== undefined && license.type === undefined
      ? "GET /_license returned no license type, so the subscription tier could not be determined."
      : unsupported.length > 0
        ? `The ${license.type} license does not cover configured features: ${unsupported.map((item) => `${item.feature} (needs ${licenseLabel(item.rank)})`).join(", ")}.`
        : license.active === false
          ? `The license status is ${license.status}.`
          : license.active === undefined
            ? `The ${license.type} license reports no status field, so it cannot be confirmed as active.`
            : license.type === "trial"
              ? `A trial license is active${expiryDays !== undefined ? ` and expires in ${expiryDays} days` : ""}; security features will lapse when it ends.`
              : expiryMissing
                ? `The ${license.type} license is active but reports no expiry date, so its validity window cannot be confirmed.`
                : expiryDays !== undefined && expiryDays < 30
                  ? `The ${license.type} license expires in ${expiryDays} days.`
                  : `The ${license.type} license is active${expiryDays !== undefined ? ` (expires in ${expiryDays} days)` : ""} and covers every configured security feature (${requirements.length} requirement(s) checked).`,
    evidence: licenseEvidence,
  }, {
    problems: [...licenseProblems, ...coverageProblems],
    partial: nodeNotes,
    collect: "the output of GET /_license and the subscription tier that covers the configured realms, FLS/DLS, audit logging, and Watcher.",
  }));

  return {
    area: "cluster_hardening",
    title: "Elastic cluster hardening and data protection",
    summary: {
      audit_enabled: auditEnabled,
      audit_outputs: auditOutputs,
      ilm_policies: Object.keys(ilmPolicies ?? {}).length,
      ilm_operation_mode: ilmMode ?? null,
      snapshot_repositories: Object.keys(repositories ?? {}).length,
      slm_policies: Object.keys(slmPolicies ?? {}).length,
      slm_operation_mode: slmMode ?? null,
      watches: watches?.length ?? 0,
      connectors: connectors?.length ?? 0,
      ingest_pipelines: Object.keys(pipelines ?? {}).length,
      license_type: license.type ?? null,
      license_status: license.status ?? null,
      security_enabled: security.enabled ?? null,
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
  const roleEvidence: JsonRecord = {
    roles_reviewed: roles?.length ?? null,
    custom_roles: customRoles.length,
    reserved_roles: reservedRoles,
    global_all_roles: globalAllRoles.slice(0, 25),
    space_scoped_roles: spaceScopedRoles.slice(0, 25),
    feature_scoped_roles: featureScopedRoles.slice(0, 25),
    elasticsearch_cluster_all_roles: customRoles
      .filter((role) => asStringList(getNestedValue(role, ["elasticsearch", "cluster"])).includes("all"))
      .map((role) => asString(role.name))
      .slice(0, 25),
  };

  if (kibanaSkipped) {
    const collect = "Kibana evidence manually or set KIBANA_URL so the API can be queried:";
    findings.push(manualFinding(15, "medium", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} the space list (GET /api/spaces/space) and the roles that scope privileges to individual spaces.`));
    findings.push(manualFinding(16, "high", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} the Kibana role definitions (GET /api/security/role) and identify roles granting base all across all spaces.`));
    findings.push(manualFinding(21, "medium", `Scoped out: Kibana is not configured (${kibanaSkipped}).`, `${collect} Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys (GET /api/fleet/agent_policies, /api/fleet/outputs, /api/fleet/fleet_server_hosts, /api/fleet/enrollment_api_keys).`));
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
      summary: spaceCount <= 1
        ? "Only the default space exists, so Kibana space isolation between teams is not in use; confirm whether multi-team separation is required."
        : spaceScopedRoles.length > 0 && globalAllRoles.length === 0
          ? `${spaceCount} spaces exist and ${spaceScopedRoles.length} custom role(s) scope privileges to specific spaces with no custom role granting all privileges across every space.`
          : `${spaceCount} spaces exist but ${spaceScopedRoles.length} role(s) are space-scoped and ${globalAllRoles.length} custom role(s) grant all privileges across every space.`,
      evidence: { spaces: spaceEvidence, space_scoped_roles: spaceScopedRoles.slice(0, 25), global_all_roles: globalAllRoles.slice(0, 25) },
    }, {
      problems: [...spaceProblems, ...roleProblems],
      partial: [],
      collect: "the space list (GET /api/spaces/space) and the roles that scope privileges to individual spaces.",
    }));

    findings.push(guardedFinding(16, "high", {
      status: globalAllRoles.length > 0 ? "fail" : customRoles.length === 0 ? "warn" : "pass",
      summary: globalAllRoles.length > 0
        ? `${globalAllRoles.length} custom Kibana role(s) grant base all privileges across every space: ${globalAllRoles.slice(0, 10).join(", ")}.`
        : customRoles.length === 0
          ? `No custom Kibana roles exist (${reservedRoles} reserved roles only), so users rely on reserved roles such as kibana_admin or superuser and feature-level privilege separation is not implemented.`
          : `${customRoles.length} custom Kibana roles reviewed; none grants base all across every space (${featureScopedRoles.length} use feature-level privileges only).`,
      evidence: roleEvidence,
    }, {
      problems: roleProblems,
      partial: [],
      collect: "the Kibana role definitions (GET /api/security/role) and identify roles granting base all across all spaces.",
    }));

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
    const fleetPartial = truncationNotes(snapshot, ["fleet_agent_policies", "fleet_enrollment_api_keys", "fleet_server_hosts"]);
    const fleetEvidence: JsonRecord = {
      kibana_space_queried: kibanaSpaceId ?? "default",
      agent_policies: agentPolicies?.length ?? null,
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
    const fleetCollect = "Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys (GET /api/fleet/agent_policies, /api/fleet/outputs, /api/fleet/fleet_server_hosts, /api/fleet/enrollment_api_keys).";
    const fleetFailed = insecureOutputs.length > 0 || insecureFleetServers.length > 0;
    const fleetEmpty = agentPolicies !== undefined && agentPolicies.length === 0;
    const outputsEmpty = agentPolicies !== undefined && agentPolicies.length > 0 && outputs !== undefined && outputs.length === 0;
    if (!fleetFailed && fleetProblems.length === 0 && fleetEmpty) {
      findings.push(manualFinding(
        21,
        "medium",
        `Not applicable: zero Fleet agent policies exist in the ${kibanaSpaceId ?? "default"} space, so Fleet enrollment and output hardening has nothing to evaluate (emptiness is reported as manual, not pass).`,
        "confirmation that Fleet and Elastic Agent are not in use in any space, or the policies from the space where Fleet is managed.",
        fleetEvidence,
      ));
    } else {
      findings.push(guardedFinding(21, "medium", {
        status: fleetFailed
          ? "fail"
          : unprotectedPolicies.length > 0 || crowdedPolicies.length > 0 || outputsWithoutTrust.length > 0 || outputsEmpty || (fleetServerHosts ?? []).length === 0
            ? "warn"
            : "pass",
        summary: fleetFailed
          ? `${insecureOutputs.length} Fleet output(s) and ${insecureFleetServers.length} Fleet Server host(s) use plain http.`
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
  const assessments = areas.map((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl, kibanaSpaceId: config.kibanaSpaceId }));
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
      page: dataset.page ?? null,
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
