/**
 * Snowflake security inspector tools for grclanker.
 *
 * Read-only posture checks executed through the Snowflake SQL REST API
 * (SHOW commands and SNOWFLAKE.ACCOUNT_USAGE views) with key-pair JWT or
 * OAuth bearer authentication.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  randomUUID,
  type KeyObject,
} from "node:crypto";
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
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;
type SqlRow = Record<string, string | null>;

const DEFAULT_OUTPUT_DIR = "./export/snowflake";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_STATEMENT_TIMEOUT_SECONDS = 120;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_MS = 500;
const DEFAULT_MAX_PARTITIONS = 50;
const DEFAULT_ROW_LIMIT = 20_000;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_STALE_USER_DAYS = 90;
const DEFAULT_FAILED_LOGIN_THRESHOLD = 10;
const DEFAULT_MAX_ACCOUNTADMINS = 3;
const DEFAULT_MAX_AUTO_SUSPEND_SECONDS = 600;
const DEFAULT_MAX_SESSION_IDLE_MINUTES = 60;
const DEFAULT_MIN_PASSWORD_LENGTH = 14;
const DEFAULT_MIN_RETENTION_DAYS = 1;
const JWT_LIFETIME_SECONDS = 55 * 60;
const JWT_REFRESH_SKEW_SECONDS = 60;
const FULL_VISIBILITY_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN"]);
const SYSTEM_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "ORGADMIN", "PUBLIC", "GLOBALORGADMIN"]);
const PRIVILEGED_SYSTEM_ROLES = new Set(["ACCOUNTADMIN", "SECURITYADMIN"]);
const SERVICE_USER_TYPES = new Set(["SERVICE", "LEGACY_SERVICE"]);
const SENSITIVE_OBJECT_DOMAINS = new Set([
  "TABLE",
  "VIEW",
  "SCHEMA",
  "DATABASE",
  "STAGE",
  "MATERIALIZED_VIEW",
  "MATERIALIZED VIEW",
  "EXTERNAL_TABLE",
  "EXTERNAL TABLE",
  "DYNAMIC_TABLE",
  "DYNAMIC TABLE",
  "STREAM",
]);
const ROUTINE_QUERY_TYPES = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "MERGE",
  "COPY",
  "UNLOAD",
  "CREATE_TABLE_AS_SELECT",
  "CALL",
];

export type SnowflakeTokenType = "KEYPAIR_JWT" | "OAUTH" | "PROGRAMMATIC_ACCESS_TOKEN";

export interface SnowflakeResolvedConfig {
  account: string;
  user: string;
  baseUrl: string;
  tokenType: SnowflakeTokenType;
  privateKeyPem?: string;
  privateKeyPassphrase?: string;
  token?: string;
  role?: string;
  warehouse?: string;
  database?: string;
  schema?: string;
  timeoutMs: number;
  statementTimeoutSeconds: number;
  pollIntervalMs: number;
  maxRetries: number;
  retryBaseMs: number;
  maxPartitions: number;
  rowLimit: number;
  connectionName?: string;
  sourceChain: string[];
}

export interface SnowflakeResultSet {
  statement: string;
  columns: string[];
  rows: SqlRow[];
  numRows: number;
  partitionCount: number;
  fetchedPartitions: number;
  truncated: boolean;
  statementHandle?: string;
}

export type SnowflakeStatementStatus = "ok" | "denied" | "error" | "timeout";

export interface SnowflakeStatementOutcome {
  key: string;
  statement: string;
  status: SnowflakeStatementStatus;
  columns: string[];
  rows: SqlRow[];
  numRows: number;
  partitionCount: number;
  fetchedPartitions: number;
  truncated: boolean;
  rowLimit?: number;
  error?: string;
}

export interface SnowflakeAccessSurface {
  name: string;
  statement: string;
  status: "readable" | "denied" | "error" | "timeout";
  rowCount?: number;
  error?: string;
}

export interface SnowflakeAccessCheckResult {
  status: "healthy" | "limited";
  account: string;
  user: string;
  role?: string;
  fullVisibility: boolean;
  surfaces: SnowflakeAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type SnowflakeFindingStatus = "pass" | "warn" | "fail" | "manual";
export type SnowflakeSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SnowflakeFinding {
  id: string;
  control: number;
  title: string;
  severity: SnowflakeSeverity;
  status: SnowflakeFindingStatus;
  summary: string;
  evidence: JsonRecord;
  mappings: string[];
}

export interface SnowflakeAssessmentResult {
  title: string;
  area: string;
  summary: JsonRecord;
  findings: SnowflakeFinding[];
  statements: SnowflakeStatementOutcome[];
}

export interface SnowflakeAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface SnowflakeAssessmentOptions {
  lookbackDays?: number;
  staleUserDays?: number;
  failedLoginThreshold?: number;
  maxAccountAdmins?: number;
  maxAutoSuspendSeconds?: number;
  maxSessionIdleMinutes?: number;
  minPasswordLength?: number;
  minRetentionDays?: number;
}

interface SessionContext {
  account?: string;
  user?: string;
  role?: string;
  warehouse?: string;
  region?: string;
  version?: string;
  outcome: SnowflakeStatementOutcome;
}

interface ControlDefinition {
  control: number;
  id: string;
  title: string;
  severity: SnowflakeSeverity;
  mappings: string[];
}

type SnowflakeQueryClient = Pick<SnowflakeSqlClient, "getResolvedConfig" | "execute">;

type CommonArgs = {
  account?: string;
  user?: string;
  private_key_path?: string;
  private_key?: string;
  private_key_passphrase?: string;
  token?: string;
  token_type?: string;
  role?: string;
  warehouse?: string;
  database?: string;
  schema?: string;
  base_url?: string;
  connection?: string;
  timeout_seconds?: number;
  statement_timeout_seconds?: number;
  row_limit?: number;
};

type AssessArgs = CommonArgs & {
  lookback_days?: number;
  stale_user_days?: number;
  failed_login_threshold?: number;
  max_accountadmins?: number;
  max_auto_suspend_seconds?: number;
  max_session_idle_minutes?: number;
  min_password_length?: number;
  min_retention_days?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

function mapping(
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

export const SNOWFLAKE_CONTROLS: Record<number, ControlDefinition> = {
  1: { control: 1, id: "SNOWFLAKE-01", title: "Network policy configured and applied to account", severity: "critical", mappings: mapping("SC-7", "SC.L2-3.13.1", "CC6.6", "4.1", "1.3.1", "SRG-APP-000383", "ISM-1284", "10.2.1") },
  2: { control: 2, id: "SNOWFLAKE-02", title: "Network policy IP allowlist is restrictive", severity: "critical", mappings: mapping("SC-7(5)", "SC.L2-3.13.6", "CC6.6", "4.4", "1.3.2", "SRG-APP-000383", "ISM-1284", "10.2.2") },
  3: { control: 3, id: "SNOWFLAKE-03", title: "MFA enforced for all human users", severity: "critical", mappings: mapping("IA-2(1)", "IA.L2-3.5.3", "CC6.1", "4.5", "8.3.2", "SRG-APP-000149", "ISM-1401", "8.2.2") },
  4: { control: 4, id: "SNOWFLAKE-04", title: "Password policy meets complexity requirements", severity: "high", mappings: mapping("IA-5(1)", "IA.L2-3.5.7", "CC6.1", "5.1", "8.2.3", "SRG-APP-000164", "ISM-0421", "8.2.3") },
  5: { control: 5, id: "SNOWFLAKE-05", title: "Key pair authentication used for service accounts", severity: "high", mappings: mapping("IA-5(2)", "IA.L2-3.5.10", "CC6.1", "4.6", "8.6.1", "SRG-APP-000177", "ISM-1557", "8.2.4") },
  6: { control: 6, id: "SNOWFLAKE-06", title: "SSO/SAML integration configured", severity: "high", mappings: mapping("IA-2(12)", "IA.L2-3.5.1", "CC6.1", "4.1", "8.3.1", "SRG-APP-000148", "ISM-1557", "8.2.1") },
  7: { control: 7, id: "SNOWFLAKE-07", title: "Role hierarchy follows least privilege", severity: "critical", mappings: mapping("AC-6(1)", "AC.L2-3.1.5", "CC6.3", "6.1", "7.1.1", "SRG-APP-000340", "ISM-1508", "8.1.2") },
  8: { control: 8, id: "SNOWFLAKE-08", title: "ACCOUNTADMIN role has minimal members", severity: "critical", mappings: mapping("AC-6(5)", "AC.L2-3.1.5", "CC6.3", "6.2", "7.1.2", "SRG-APP-000340", "ISM-1508", "8.1.3") },
  9: { control: 9, id: "SNOWFLAKE-09", title: "ACCOUNTADMIN not used for routine queries", severity: "high", mappings: mapping("AC-6(2)", "AC.L2-3.1.6", "CC6.3", "6.2", "7.1.2", "SRG-APP-000343", "ISM-1508", "8.1.3") },
  10: { control: 10, id: "SNOWFLAKE-10", title: "No direct object grants to users", severity: "medium", mappings: mapping("AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1") },
  11: { control: 11, id: "SNOWFLAKE-11", title: "Failed login monitoring", severity: "high", mappings: mapping("SI-4", "AU.L2-3.3.1", "CC7.2", "8.5", "10.2.4", "SRG-APP-000095", "ISM-0580", "12.1.1") },
  12: { control: 12, id: "SNOWFLAKE-12", title: "Stale users disabled", severity: "medium", mappings: mapping("AC-2(3)", "AC.L2-3.1.1", "CC6.2", "4.2", "8.1.4", "SRG-APP-000025", "ISM-1631", "8.1.4") },
  13: { control: 13, id: "SNOWFLAKE-13", title: "History and data retention configured", severity: "medium", mappings: mapping("AU-11", "AU.L2-3.3.1", "CC7.2", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "12.1.2") },
  14: { control: 14, id: "SNOWFLAKE-14", title: "Dynamic data masking policies applied", severity: "high", mappings: mapping("SC-28", "SC.L2-3.13.16", "CC6.1", "14.7", "3.4", "SRG-APP-000231", "ISM-0457", "10.1.2") },
  15: { control: 15, id: "SNOWFLAKE-15", title: "Row access policies applied", severity: "high", mappings: mapping("AC-3", "AC.L2-3.1.2", "CC6.1", "14.6", "7.1.1", "SRG-APP-000033", "ISM-0508", "8.1.1") },
  16: { control: 16, id: "SNOWFLAKE-16", title: "No PUBLIC grants on sensitive objects", severity: "high", mappings: mapping("AC-6", "AC.L2-3.1.1", "CC6.3", "6.1", "7.1.1", "SRG-APP-000033", "ISM-1508", "8.1.1") },
  17: { control: 17, id: "SNOWFLAKE-17", title: "Storage integration required for stages", severity: "high", mappings: mapping("AC-3", "AC.L2-3.1.2", "CC6.1", "14.2", "3.4.1", "SRG-APP-000033", "ISM-1284", "8.1.1") },
  18: { control: 18, id: "SNOWFLAKE-18", title: "Stage unload restrictions", severity: "medium", mappings: mapping("AC-4", "AC.L2-3.1.3", "CC6.6", "14.2", "3.4.1", "SRG-APP-000039", "ISM-1284", "8.1.3") },
  19: { control: 19, id: "SNOWFLAKE-19", title: "Time Travel retention for databases", severity: "medium", mappings: mapping("CP-9", "RE.L2-3.8.9", "CC6.5", "3.1", "3.1", "SRG-APP-000504", "ISM-1515", "7.1.1") },
  20: { control: 20, id: "SNOWFLAKE-20", title: "Tri-Secret Secure", severity: "high", mappings: mapping("SC-12(1)", "SC.L2-3.13.10", "CC6.7", "14.4", "3.5.2", "SRG-APP-000514", "ISM-0487", "10.1.1") },
  21: { control: 21, id: "SNOWFLAKE-21", title: "Customer-managed keys configured", severity: "high", mappings: mapping("SC-12(1)", "SC.L2-3.13.10", "CC6.7", "14.4", "3.5.2", "SRG-APP-000514", "ISM-0487", "10.1.1") },
  22: { control: 22, id: "SNOWFLAKE-22", title: "Outbound shares reviewed", severity: "medium", mappings: mapping("AC-4", "AC.L2-3.1.3", "CC6.6", "13.4", "7.1.2", "SRG-APP-000039", "ISM-1284", "8.1.3") },
  23: { control: 23, id: "SNOWFLAKE-23", title: "External functions and API integrations reviewed", severity: "medium", mappings: mapping("CM-7", "CM.L2-3.4.7", "CC6.6", "13.5", "2.2.2", "SRG-APP-000141", "ISM-1284", "6.1.1") },
  24: { control: 24, id: "SNOWFLAKE-24", title: "Warehouse auto-suspend configured", severity: "low", mappings: mapping("AC-12", "AC.L2-3.1.10", "CC6.1", "5.6", "8.1.8", "SRG-APP-000295", "ISM-1164", "8.3.1") },
  25: { control: 25, id: "SNOWFLAKE-25", title: "Session policies configured", severity: "medium", mappings: mapping("AC-12", "AC.L2-3.1.11", "CC6.1", "5.6", "8.1.8", "SRG-APP-000295", "ISM-1164", "8.3.1") },
};

export const SNOWFLAKE_FRAMEWORKS = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"] as const;

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
    if (/^(true|1|yes|y|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|n|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function upper(value: string | null | undefined): string {
  return (value ?? "").trim().toUpperCase();
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function parseSnowflakeTimestamp(value: string | null | undefined): Date | undefined {
  if (value === null || value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || /^null$/i.test(trimmed)) return undefined;
  const epochMatch = /^(-?\d+)(?:\.(\d+))?(?:\s+\d+)?$/.exec(trimmed);
  if (epochMatch) {
    const seconds = Number(epochMatch[1]);
    const fraction = epochMatch[2] ? Number(`0.${epochMatch[2]}`) : 0;
    if (Number.isFinite(seconds)) return new Date((seconds + fraction) * 1000);
  }
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : new Date(parsed);
}

function daysSince(date: Date, now: Date): number {
  return Math.floor((now.getTime() - date.getTime()) / 86_400_000);
}

function rowValue(row: SqlRow, ...names: string[]): string | null {
  for (const name of names) {
    if (name in row) return row[name];
    const lower = name.toLowerCase();
    if (lower in row) return row[lower];
    const upperName = name.toUpperCase();
    if (upperName in row) return row[upperName];
  }
  return null;
}

function rowBoolean(row: SqlRow, ...names: string[]): boolean | undefined {
  return asBoolean(rowValue(row, ...names));
}

function rowNumber(row: SqlRow, ...names: string[]): number | undefined {
  return asNumber(rowValue(row, ...names));
}

export function redactSecrets(text: string, secrets: Array<string | undefined> = []): string {
  let output = text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]")
    .replace(/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, "[REDACTED TOKEN]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]{8,}/g, "Bearer [REDACTED TOKEN]");
  for (const secret of secrets) {
    if (secret && secret.length >= 6) {
      output = output.split(secret).join("[REDACTED]");
    }
  }
  return output;
}

export function parseSimpleToml(text: string): Record<string, JsonRecord> {
  const sections: Record<string, JsonRecord> = { "": {} };
  let current = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const sectionMatch = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (sectionMatch) {
      current = sectionMatch[1].replace(/"/g, "").trim();
      sections[current] = sections[current] ?? {};
      continue;
    }
    const keyMatch = /^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
    if (!keyMatch) continue;
    sections[current][keyMatch[1]] = parseTomlValue(keyMatch[2].trim());
  }
  return sections;
}

function findClosingQuote(raw: string, quote: string, start: number): number {
  for (let index = start; index < raw.length; index += 1) {
    if (raw[index] === "\\" && quote === "\"") {
      index += 1;
      continue;
    }
    if (raw[index] === quote) return index;
  }
  return -1;
}

function parseTomlValue(raw: string): unknown {
  if (raw.startsWith("\"\"\"")) {
    const end = raw.indexOf("\"\"\"", 3);
    return end >= 0 ? raw.slice(3, end) : raw.slice(3);
  }
  if (raw.startsWith("\"")) {
    const end = findClosingQuote(raw, "\"", 1);
    const inner = end >= 0 ? raw.slice(1, end) : raw.slice(1);
    return inner.replace(/\\n/g, "\n").replace(/\\"/g, "\"").replace(/\\\\/g, "\\");
  }
  if (raw.startsWith("'")) {
    const end = findClosingQuote(raw, "'", 1);
    return end >= 0 ? raw.slice(1, end) : raw.slice(1);
  }
  const withoutComment = raw.replace(/\s+#.*$/, "").trim();
  if (/^(true|false)$/i.test(withoutComment)) return withoutComment.toLowerCase() === "true";
  const numeric = Number(withoutComment);
  if (withoutComment.length > 0 && Number.isFinite(numeric)) return numeric;
  return withoutComment;
}

export interface SnowflakeTomlConnection {
  name: string;
  values: JsonRecord;
  source: string;
}

export function loadSnowflakeTomlConnection(
  env: NodeJS.ProcessEnv = process.env,
  connectionName?: string,
  homeDirectory: string = homedir(),
): SnowflakeTomlConnection | undefined {
  const configDir = asString(env.SNOWFLAKE_HOME) ?? join(homeDirectory, ".snowflake");
  const configPath = join(configDir, "config.toml");
  const connectionsPath = join(configDir, "connections.toml");
  const configSections = existsSync(configPath) ? parseSimpleToml(readFileSync(configPath, "utf8")) : undefined;
  const name = connectionName
    ?? asString(env.SNOWFLAKE_CONNECTION_NAME)
    ?? asString(env.SNOWFLAKE_DEFAULT_CONNECTION_NAME)
    ?? asString(configSections?.[""]?.default_connection_name)
    ?? "default";

  if (existsSync(connectionsPath)) {
    const sections = parseSimpleToml(readFileSync(connectionsPath, "utf8"));
    const values = sections[name] ?? sections[`connections.${name}`];
    if (values) return { name, values, source: connectionsPath };
  }
  if (configSections) {
    const values = configSections[`connections.${name}`];
    if (values) return { name, values, source: configPath };
  }
  return undefined;
}

function expandHome(pathname: string, homeDirectory: string): string {
  if (pathname === "~") return homeDirectory;
  if (pathname.startsWith("~/")) return join(homeDirectory, pathname.slice(2));
  return pathname;
}

export function normalizeAccountHost(account: string): string {
  return account.trim().replace(/_/g, "-").toLowerCase();
}

export function normalizeJwtAccountIdentifier(account: string): string {
  let identifier = account.trim();
  if (identifier.toLowerCase().includes(".global")) {
    const hyphenIndex = identifier.indexOf("-");
    if (hyphenIndex > 0) identifier = identifier.slice(0, hyphenIndex);
  } else {
    const dotIndex = identifier.indexOf(".");
    if (dotIndex > 0) identifier = identifier.slice(0, dotIndex);
  }
  return identifier.toUpperCase();
}

function parseTokenType(value: string | undefined): SnowflakeTokenType | undefined {
  const normalized = upper(value);
  if (normalized === "KEYPAIR_JWT" || normalized === "SNOWFLAKE_JWT" || normalized === "JWT") return "KEYPAIR_JWT";
  if (normalized === "OAUTH") return "OAUTH";
  if (normalized === "PROGRAMMATIC_ACCESS_TOKEN" || normalized === "PAT") return "PROGRAMMATIC_ACCESS_TOKEN";
  return undefined;
}

export function resolveSnowflakeConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
  options: { homeDirectory?: string } = {},
): SnowflakeResolvedConfig {
  const homeDirectory = options.homeDirectory ?? homedir();
  const sourceChain: string[] = [];
  const explicitConnection = asString(input.connection);
  const toml = loadSnowflakeTomlConnection(env, explicitConnection, homeDirectory);
  const tomlValues = toml?.values ?? {};
  if (toml) sourceChain.push(`config-file:${toml.source}#${toml.name}`);

  const pick = (
    label: string,
    argValue: unknown,
    envKeys: string[],
    tomlKeys: string[],
  ): string | undefined => {
    const fromArgs = asString(argValue);
    if (fromArgs) {
      sourceChain.push(`arguments-${label}`);
      return fromArgs;
    }
    for (const key of envKeys) {
      const fromEnv = asString(env[key]);
      if (fromEnv) {
        sourceChain.push(`environment-${label}`);
        return fromEnv;
      }
    }
    for (const key of tomlKeys) {
      const fromToml = asString(tomlValues[key]);
      if (fromToml) {
        sourceChain.push(`config-file-${label}`);
        return fromToml;
      }
    }
    return undefined;
  };

  const account = pick("account", input.account, ["SNOWFLAKE_ACCOUNT"], ["account", "account_name", "accountname"]);
  if (!account) {
    throw new Error("SNOWFLAKE_ACCOUNT, an account argument, or a connections.toml account entry is required.");
  }
  const user = pick("user", input.user, ["SNOWFLAKE_USER"], ["user", "username"]);
  if (!user) {
    throw new Error("SNOWFLAKE_USER, a user argument, or a connections.toml user entry is required.");
  }

  const privateKeyPath = pick(
    "private-key-path",
    input.private_key_path,
    ["SNOWFLAKE_PRIVATE_KEY_PATH", "SNOWFLAKE_PRIVATE_KEY_FILE"],
    ["private_key_file", "private_key_path"],
  );
  const inlinePrivateKey = pick(
    "private-key",
    input.private_key,
    ["SNOWFLAKE_PRIVATE_KEY", "SNOWFLAKE_PRIVATE_KEY_RAW"],
    ["private_key_raw", "private_key"],
  );
  const privateKeyPassphrase = pick(
    "private-key-passphrase",
    input.private_key_passphrase,
    ["SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "PRIVATE_KEY_PASSPHRASE"],
    ["private_key_passphrase", "private_key_file_pwd"],
  );
  const token = pick("token", input.token, ["SNOWFLAKE_TOKEN", "SNOWFLAKE_OAUTH_TOKEN", "SNOWFLAKE_ACCESS_TOKEN"], ["token", "oauth_token"]);
  const authenticator = pick("authenticator", input.token_type, ["SNOWFLAKE_TOKEN_TYPE", "SNOWFLAKE_AUTHENTICATOR"], ["authenticator", "token_type"]);

  let privateKeyPem: string | undefined;
  if (inlinePrivateKey) {
    privateKeyPem = inlinePrivateKey.replace(/\\n/g, "\n");
  } else if (privateKeyPath) {
    const resolvedPath = expandHome(privateKeyPath, homeDirectory);
    if (!existsSync(resolvedPath)) {
      throw new Error(`Snowflake private key file was not found: ${resolvedPath}`);
    }
    privateKeyPem = readFileSync(resolvedPath, "utf8");
  }

  const explicitTokenType = parseTokenType(authenticator);
  let tokenType: SnowflakeTokenType;
  if (privateKeyPem && (!explicitTokenType || explicitTokenType === "KEYPAIR_JWT")) {
    tokenType = "KEYPAIR_JWT";
  } else if (token) {
    tokenType = explicitTokenType && explicitTokenType !== "KEYPAIR_JWT" ? explicitTokenType : "OAUTH";
  } else if (privateKeyPem) {
    tokenType = "KEYPAIR_JWT";
  } else {
    throw new Error(
      "Provide key-pair credentials (SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY) or a bearer token (SNOWFLAKE_TOKEN). Username/password authentication is not supported by the Snowflake SQL REST API.",
    );
  }

  const role = pick("role", input.role, ["SNOWFLAKE_ROLE"], ["role"]);
  const warehouse = pick("warehouse", input.warehouse, ["SNOWFLAKE_WAREHOUSE"], ["warehouse"]);
  const database = pick("database", input.database, ["SNOWFLAKE_DATABASE"], ["database"]);
  const schema = pick("schema", input.schema, ["SNOWFLAKE_SCHEMA"], ["schema"]);
  const host = pick("host", input.base_url, ["SNOWFLAKE_BASE_URL", "SNOWFLAKE_HOST"], ["host"]);
  const baseUrl = host
    ? (host.startsWith("http://") || host.startsWith("https://") ? host : `https://${host}`).replace(/\/+$/, "")
    : `https://${normalizeAccountHost(account)}.snowflakecomputing.com`;

  return {
    account,
    user,
    baseUrl,
    tokenType,
    privateKeyPem,
    privateKeyPassphrase,
    token,
    role,
    warehouse,
    database,
    schema,
    timeoutMs: clampNumber(asNumber(input.timeout_seconds) ?? asNumber(env.SNOWFLAKE_TIMEOUT), DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000,
    statementTimeoutSeconds: clampNumber(
      asNumber(input.statement_timeout_seconds) ?? asNumber(env.SNOWFLAKE_STATEMENT_TIMEOUT),
      DEFAULT_STATEMENT_TIMEOUT_SECONDS,
      5,
      3600,
    ),
    pollIntervalMs: clampNumber(asNumber(input.poll_interval_ms) ?? asNumber(env.SNOWFLAKE_POLL_INTERVAL_MS), DEFAULT_POLL_INTERVAL_MS, 0, 30_000),
    maxRetries: clampNumber(asNumber(input.max_retries), DEFAULT_MAX_RETRIES, 0, 10),
    retryBaseMs: clampNumber(asNumber(input.retry_base_ms), DEFAULT_RETRY_BASE_MS, 0, 30_000),
    maxPartitions: clampNumber(asNumber(input.max_partitions), DEFAULT_MAX_PARTITIONS, 1, 10_000),
    rowLimit: clampNumber(asNumber(input.row_limit), DEFAULT_ROW_LIMIT, 100, 1_000_000),
    connectionName: toml?.name,
    sourceChain: [...new Set(sourceChain)],
  };
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

export function computePublicKeyFingerprint(privateKey: KeyObject): string {
  const publicKeyDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(publicKeyDer).digest("base64")}`;
}

export function buildSnowflakeKeyPairJwt(
  config: Pick<SnowflakeResolvedConfig, "account" | "user" | "privateKeyPem" | "privateKeyPassphrase">,
  now: Date = new Date(),
  lifetimeSeconds: number = JWT_LIFETIME_SECONDS,
): { token: string; expiresAt: number; issuer: string; subject: string } {
  if (!config.privateKeyPem) {
    throw new Error("Snowflake key-pair authentication requires a private key.");
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({
      key: config.privateKeyPem,
      format: "pem",
      passphrase: config.privateKeyPassphrase,
    });
  } catch (error) {
    throw new Error(`Unable to load the Snowflake private key: ${redactSecrets(error instanceof Error ? error.message : String(error))}`);
  }
  const qualifiedUser = `${normalizeJwtAccountIdentifier(config.account)}.${config.user.trim().toUpperCase()}`;
  const issuer = `${qualifiedUser}.${computePublicKeyFingerprint(privateKey)}`;
  const issuedAt = Math.floor(now.getTime() / 1000);
  const expiresAt = issuedAt + Math.min(lifetimeSeconds, 3600);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({ iss: issuer, sub: qualifiedUser, iat: issuedAt, exp: expiresAt }));
  const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKey).toString("base64url");
  return { token: `${header}.${payload}.${signature}`, expiresAt: expiresAt * 1000, issuer, subject: qualifiedUser };
}

export class SnowflakeStatementError extends Error {
  readonly statusCode?: number;
  readonly sqlCode?: string;
  readonly sqlState?: string;
  readonly kind: "denied" | "error" | "timeout";

  constructor(message: string, options: { statusCode?: number; sqlCode?: string; sqlState?: string; kind?: "denied" | "error" | "timeout" } = {}) {
    super(message);
    this.name = "SnowflakeStatementError";
    this.statusCode = options.statusCode;
    this.sqlCode = options.sqlCode;
    this.sqlState = options.sqlState;
    this.kind = options.kind ?? classifyErrorMessage(message, options.statusCode);
  }
}

function classifyErrorMessage(message: string, statusCode?: number): "denied" | "error" | "timeout" {
  if (/insufficient privileges|not authorized|access control error|does not exist or not authorized|unauthorized|forbidden/i.test(message)) {
    return "denied";
  }
  if (statusCode === 401 || statusCode === 403) return "denied";
  if (/timed out|timeout|aborted|deadline/i.test(message)) return "timeout";
  return "error";
}

function extractApiError(payload: JsonRecord, status: number, statusText: string): string {
  const message = asString(payload.message) ?? asString(payload.error) ?? "";
  const code = asString(payload.code);
  const sqlState = asString(payload.sqlState);
  const detail = [code ? `code ${code}` : undefined, sqlState ? `sqlState ${sqlState}` : undefined].filter(Boolean).join(", ");
  return `Snowflake SQL API request failed (${status} ${statusText})${message ? `: ${message}` : ""}${detail ? ` [${detail}]` : ""}`;
}

export class SnowflakeSqlClient {
  private readonly config: SnowflakeResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private jwt?: { token: string; expiresAt: number };

  constructor(config: SnowflakeResolvedConfig, options: { fetchImpl?: FetchImpl; now?: () => Date } = {}) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): SnowflakeResolvedConfig {
    return this.config;
  }

  private getBearerToken(): string {
    if (this.config.tokenType === "KEYPAIR_JWT") {
      const nowMs = this.now().getTime();
      if (!this.jwt || this.jwt.expiresAt - JWT_REFRESH_SKEW_SECONDS * 1000 <= nowMs) {
        const built = buildSnowflakeKeyPairJwt(this.config, this.now());
        this.jwt = { token: built.token, expiresAt: built.expiresAt };
      }
      return this.jwt.token;
    }
    if (!this.config.token) {
      throw new Error("Snowflake bearer token is missing.");
    }
    return this.config.token;
  }

  private redact(message: string): string {
    return redactSecrets(message, [this.config.token, this.jwt?.token, this.config.privateKeyPassphrase]);
  }

  private async request(
    method: "GET" | "POST",
    pathname: string,
    body?: JsonRecord,
  ): Promise<{ status: number; statusText: string; payload: JsonRecord; headers: Headers }> {
    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const headers = new Headers({
          accept: "application/json",
          "content-type": "application/json",
          "user-agent": "grclanker-snowflake-inspector/1.0",
          authorization: `Bearer ${this.getBearerToken()}`,
          "x-snowflake-authorization-token-type": this.config.tokenType,
        });
        const response = await this.fetchImpl(`${this.config.baseUrl}${pathname}`, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        const rawText = await response.text();
        let payload: JsonRecord = {};
        if (rawText.length > 0) {
          try {
            payload = asObject(JSON.parse(rawText)) ?? { data: JSON.parse(rawText) };
          } catch {
            payload = { message: rawText.slice(0, 240) };
          }
        }
        const retryable = response.status === 429 || response.status >= 500;
        if (retryable && attempt < this.config.maxRetries && !(response.status === 429 && method === "GET" && asString(payload.statementHandle))) {
          attempt += 1;
          await sleep(this.retryDelay(attempt, response.headers));
          continue;
        }
        return { status: response.status, statusText: response.statusText, payload, headers: response.headers };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (controller.signal.aborted) {
          throw new SnowflakeStatementError(`Snowflake SQL API request timed out after ${this.config.timeoutMs}ms (${method} ${pathname})`, { kind: "timeout" });
        }
        if (error instanceof SnowflakeStatementError) throw error;
        if (attempt < this.config.maxRetries) {
          attempt += 1;
          await sleep(this.retryDelay(attempt));
          continue;
        }
        throw new SnowflakeStatementError(`Snowflake SQL API request failed (${method} ${pathname}): ${this.redact(message)}`);
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  private retryDelay(attempt: number, headers?: Headers): number {
    const retryAfter = asNumber(headers?.get("retry-after"));
    if (retryAfter !== undefined) return Math.min(retryAfter * 1000, 30_000);
    return Math.min(this.config.retryBaseMs * 2 ** (attempt - 1), 15_000);
  }

  async execute(statement: string, options: { timeoutSeconds?: number } = {}): Promise<SnowflakeResultSet> {
    assertReadOnlyStatement(statement);
    const body: JsonRecord = {
      statement,
      timeout: options.timeoutSeconds ?? this.config.statementTimeoutSeconds,
      resultSetMetaData: { format: "jsonv2" },
    };
    if (this.config.role) body.role = this.config.role;
    if (this.config.warehouse) body.warehouse = this.config.warehouse;
    if (this.config.database) body.database = this.config.database;
    if (this.config.schema) body.schema = this.config.schema;

    const submit = await this.request("POST", `/api/v2/statements?async=true&requestId=${randomUUID()}`, body);
    let payload = submit.payload;
    let status = submit.status;
    let statusText = submit.statusText;
    let handle = asString(payload.statementHandle);
    const statusUrl = asString(payload.statementStatusUrl) ?? (handle ? `/api/v2/statements/${handle}` : undefined);
    const deadline = this.now().getTime() + (options.timeoutSeconds ?? this.config.statementTimeoutSeconds) * 1000 + this.config.timeoutMs;

    while (status === 202 || (status === 429 && handle)) {
      if (!statusUrl) break;
      if (this.now().getTime() > deadline) {
        throw new SnowflakeStatementError(`Snowflake statement ${handle ?? ""} did not complete before the ${this.config.statementTimeoutSeconds}s statement timeout.`, { kind: "timeout" });
      }
      await sleep(this.pollDelay(submit.headers));
      const poll = await this.request("GET", statusUrl);
      payload = poll.payload;
      status = poll.status;
      statusText = poll.statusText;
      handle = asString(payload.statementHandle) ?? handle;
    }

    if (status !== 200) {
      throw new SnowflakeStatementError(this.redact(extractApiError(payload, status, statusText)), {
        statusCode: status,
        sqlCode: asString(payload.code),
        sqlState: asString(payload.sqlState),
      });
    }

    return this.materializeResultSet(statement, payload, handle);
  }

  private pollDelay(headers: Headers): number {
    const retryAfter = asNumber(headers.get("retry-after"));
    if (retryAfter !== undefined) return Math.min(retryAfter * 1000, 30_000);
    return this.config.pollIntervalMs;
  }

  private async materializeResultSet(statement: string, payload: JsonRecord, handle?: string): Promise<SnowflakeResultSet> {
    const metadata = asObject(payload.resultSetMetaData) ?? {};
    const columns = asArray(metadata.rowType)
      .map((column) => asString(asObject(column)?.name))
      .filter((name): name is string => Boolean(name));
    const partitionInfo = asArray(metadata.partitionInfo);
    const partitionCount = Math.max(partitionInfo.length, 1);
    const numRows = asNumber(metadata.numRows) ?? asArray(payload.data).length;
    const rawRows: unknown[][] = asArray(payload.data).map((row) => asArray(row));
    let fetchedPartitions = 1;

    if (handle) {
      const partitionsToFetch = Math.min(partitionCount, this.config.maxPartitions);
      for (let partition = 1; partition < partitionsToFetch; partition += 1) {
        const response = await this.request("GET", `/api/v2/statements/${handle}?partition=${partition}`);
        if (response.status !== 200) {
          throw new SnowflakeStatementError(this.redact(extractApiError(response.payload, response.status, response.statusText)), { statusCode: response.status });
        }
        rawRows.push(...asArray(response.payload.data).map((row) => asArray(row)));
        fetchedPartitions += 1;
      }
    }

    const rows: SqlRow[] = rawRows.map((values) => {
      const row: SqlRow = {};
      columns.forEach((column, index) => {
        const value = values[index];
        row[column] = value === null || value === undefined ? null : String(value);
      });
      return row;
    });

    return {
      statement,
      columns,
      rows,
      numRows,
      partitionCount,
      fetchedPartitions,
      truncated: fetchedPartitions < partitionCount || rows.length < numRows,
      statementHandle: handle,
    };
  }
}

const READ_ONLY_PREFIXES = ["SHOW ", "DESCRIBE ", "DESC ", "SELECT ", "WITH ", "EXPLAIN "];
const FORBIDDEN_STATEMENT_PATTERN = /\b(CREATE|ALTER|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE|MERGE|TRUNCATE|COPY|PUT|GET|REMOVE|CALL|USE|UNDROP|EXECUTE)\b/i;

export function assertReadOnlyStatement(statement: string): void {
  const normalized = statement.trim().replace(/\s+/g, " ").toUpperCase();
  if (!READ_ONLY_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    throw new Error(`Refusing to execute a non read-only Snowflake statement: ${statement.slice(0, 80)}`);
  }
  const firstWord = normalized.split(" ")[0];
  if (FORBIDDEN_STATEMENT_PATTERN.test(firstWord)) {
    throw new Error(`Refusing to execute a non read-only Snowflake statement: ${statement.slice(0, 80)}`);
  }
}

function accountUsageView(view: string): string {
  return `SNOWFLAKE.ACCOUNT_USAGE.${view}`;
}

export const SNOWFLAKE_STATEMENTS = {
  sessionContext: "SELECT CURRENT_ACCOUNT() AS ACCOUNT_NAME, CURRENT_USER() AS USER_NAME, CURRENT_ROLE() AS ROLE_NAME, CURRENT_WAREHOUSE() AS WAREHOUSE_NAME, CURRENT_REGION() AS REGION_NAME, CURRENT_VERSION() AS VERSION",
  showNetworkPolicies: "SHOW NETWORK POLICIES",
  accountNetworkPolicyParameter: "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT",
  networkPolicies: (limit: number) => `SELECT NAME, OWNER, ALLOWED_IP_LIST, BLOCKED_IP_LIST, CREATED, LAST_ALTERED FROM ${accountUsageView("NETWORK_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  policyReferences: (kind: string, limit: number) => `SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN, REF_COLUMN_NAME, TAG_NAME, POLICY_STATUS FROM ${accountUsageView("POLICY_REFERENCES")} WHERE POLICY_KIND = '${kind}' LIMIT ${limit}`,
  users: (limit: number) => `SELECT NAME, LOGIN_NAME, TYPE, DISABLED, HAS_PASSWORD, HAS_MFA, EXT_AUTHN_DUO, HAS_RSA_PUBLIC_KEY, HAS_PAT, HAS_WORKLOAD_IDENTITY, LAST_SUCCESS_LOGIN, PASSWORD_LAST_SET_TIME, CREATED_ON, DEFAULT_ROLE, OWNER FROM ${accountUsageView("USERS")} WHERE DELETED_ON IS NULL LIMIT ${limit}`,
  passwordPolicies: (limit: number) => `SELECT NAME, DATABASE, SCHEMA, OWNER, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_UPPER_CASE_CHARS, PASSWORD_MIN_LOWER_CASE_CHARS, PASSWORD_MIN_NUMERIC_CHARS, PASSWORD_MIN_SPECIAL_CHARS, PASSWORD_MIN_AGE_DAYS, PASSWORD_MAX_AGE_DAYS, PASSWORD_MAX_RETRIES, PASSWORD_LOCKOUT_TIME_MINS, PASSWORD_HISTORY FROM ${accountUsageView("PASSWORD_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  sessionPolicies: (limit: number) => `SELECT NAME, DATABASE, SCHEMA, OWNER, SESSION_IDLE_TIMEOUT_MINS, SESSION_UI_IDLE_TIMEOUT_MINS, SESSION_MAX_LIFESPAN_MINS, SESSION_UI_MAX_LIFESPAN_MINS FROM ${accountUsageView("SESSION_POLICIES")} WHERE DELETED IS NULL LIMIT ${limit}`,
  showIntegrations: "SHOW INTEGRATIONS",
  roleGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTED_TO, GRANTEE_NAME, GRANT_OPTION, GRANTED_BY FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_ON = 'ROLE' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  globalPrivilegeGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, GRANTED_TO, GRANTEE_NAME, GRANT_OPTION FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_ON = 'ACCOUNT' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  adminRoleGrantsToUsers: (limit: number) => `SELECT ROLE, GRANTEE_NAME, GRANTED_BY, CREATED_ON FROM ${accountUsageView("GRANTS_TO_USERS")} WHERE DELETED_ON IS NULL AND ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') LIMIT ${limit}`,
  roleUsageByQueries: (lookbackDays: number) => `SELECT ROLE_NAME, COUNT(*) AS QUERY_COUNT, COUNT(DISTINCT USER_NAME) AS USER_COUNT FROM ${accountUsageView("QUERY_HISTORY")} WHERE START_TIME >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) AND QUERY_TYPE IN (${ROUTINE_QUERY_TYPES.map((type) => `'${type}'`).join(", ")}) GROUP BY ROLE_NAME ORDER BY QUERY_COUNT DESC LIMIT 500`,
  directUserGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTEE_NAME FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTED_TO = 'USER' AND GRANTED_ON <> 'ROLE' LIMIT ${limit}`,
  publicGrants: (limit: number) => `SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTED_BY FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL AND GRANTEE_NAME = 'PUBLIC' AND GRANTED_TO IN ('ROLE', 'ACCOUNT ROLE') LIMIT ${limit}`,
  loginOutcomes: (lookbackDays: number) => `SELECT IS_SUCCESS, COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) GROUP BY IS_SUCCESS`,
  failedLogins: (lookbackDays: number) => `SELECT USER_NAME, CLIENT_IP, REPORTED_CLIENT_TYPE, COUNT(*) AS FAILURE_COUNT, MAX(ERROR_MESSAGE) AS LAST_ERROR FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -${lookbackDays}, CURRENT_TIMESTAMP()) AND IS_SUCCESS = 'NO' GROUP BY USER_NAME, CLIENT_IP, REPORTED_CLIENT_TYPE ORDER BY FAILURE_COUNT DESC LIMIT 500`,
  accessHistoryProbe: `SELECT COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("ACCESS_HISTORY")} WHERE QUERY_START_TIME >= DATEADD(day, -7, CURRENT_TIMESTAMP())`,
  dataRetentionParameter: "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT",
  showWarehouses: "SHOW WAREHOUSES",
  maskingPolicyCount: `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("MASKING_POLICIES")} WHERE DELETED IS NULL`,
  rowAccessPolicyCount: `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("ROW_ACCESS_POLICIES")} WHERE DELETED IS NULL`,
  tagReferenceSummary: `SELECT TAG_DATABASE, TAG_SCHEMA, TAG_NAME, COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("TAG_REFERENCES")} GROUP BY TAG_DATABASE, TAG_SCHEMA, TAG_NAME ORDER BY REFERENCE_COUNT DESC LIMIT 200`,
  stageParameters: "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%' IN ACCOUNT",
  unloadParameters: "SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%' IN ACCOUNT",
  showDatabases: "SHOW DATABASES",
  showShares: "SHOW SHARES",
  showReplicationGroups: "SHOW REPLICATION GROUPS",
} as const;

function emptyOutcome(key: string, statement: string): SnowflakeStatementOutcome {
  return { key, statement, status: "ok", columns: [], rows: [], numRows: 0, partitionCount: 1, fetchedPartitions: 1, truncated: false };
}

export async function collectStatement(
  client: SnowflakeQueryClient,
  key: string,
  statement: string,
  rowLimit?: number,
): Promise<SnowflakeStatementOutcome> {
  try {
    const result = await client.execute(statement);
    const hitRowLimit = rowLimit !== undefined && result.rows.length >= rowLimit;
    return {
      key,
      statement,
      status: "ok",
      columns: result.columns,
      rows: result.rows,
      numRows: result.numRows,
      partitionCount: result.partitionCount,
      fetchedPartitions: result.fetchedPartitions,
      truncated: result.truncated || hitRowLimit,
      rowLimit,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const kind = error instanceof SnowflakeStatementError ? error.kind : classifyErrorMessage(message);
    return {
      ...emptyOutcome(key, statement),
      status: kind,
      error: redactSecrets(message),
    };
  }
}

async function collectSessionContext(client: SnowflakeQueryClient): Promise<SessionContext> {
  const outcome = await collectStatement(client, "session_context", SNOWFLAKE_STATEMENTS.sessionContext);
  const row = outcome.rows[0] ?? {};
  return {
    account: rowValue(row, "ACCOUNT_NAME") ?? undefined,
    user: rowValue(row, "USER_NAME") ?? undefined,
    role: rowValue(row, "ROLE_NAME") ?? undefined,
    warehouse: rowValue(row, "WAREHOUSE_NAME") ?? undefined,
    region: rowValue(row, "REGION_NAME") ?? undefined,
    version: rowValue(row, "VERSION") ?? undefined,
    outcome,
  };
}

function effectiveRole(config: SnowflakeResolvedConfig, session: SessionContext): string | undefined {
  return upper(session.role) || upper(config.role) || undefined;
}

function hasFullVisibility(role: string | undefined): boolean {
  return Boolean(role && FULL_VISIBILITY_ROLES.has(role));
}

function describeOutcomeProblem(outcome: SnowflakeStatementOutcome): string {
  switch (outcome.status) {
    case "ok":
      return "";
    case "denied":
      return `${outcome.key} was denied (insufficient privileges): ${outcome.error ?? "no detail"}`;
    case "timeout":
      return `${outcome.key} timed out: ${outcome.error ?? "no detail"}`;
    case "error":
      return `${outcome.key} failed: ${outcome.error ?? "no detail"}`;
    default: {
      const exhaustive: never = outcome.status;
      return String(exhaustive);
    }
  }
}

function truncationNote(outcomes: SnowflakeStatementOutcome[]): string | undefined {
  const truncated = outcomes.filter((outcome) => outcome.status === "ok" && outcome.truncated);
  if (truncated.length === 0) return undefined;
  return truncated
    .map((outcome) =>
      outcome.rowLimit !== undefined && outcome.rows.length >= outcome.rowLimit
        ? `${outcome.key} hit the ${outcome.rowLimit}-row limit (${outcome.rows.length} rows seen)`
        : `${outcome.key} returned ${outcome.fetchedPartitions}/${outcome.partitionCount} partitions (${outcome.rows.length}/${outcome.numRows} rows seen)`,
    )
    .join("; ");
}

function finding(
  control: number,
  status: SnowflakeFindingStatus,
  summary: string,
  evidence: JsonRecord = {},
): SnowflakeFinding {
  const definition = SNOWFLAKE_CONTROLS[control];
  return {
    id: definition.id,
    control,
    title: definition.title,
    severity: definition.severity,
    status,
    summary,
    evidence,
    mappings: definition.mappings,
  };
}

/**
 * Wraps a verdict so that failed, denied, or timed-out statements become
 * manual findings and truncated inventories can never pass outright.
 */
function evaluateControl(
  control: number,
  required: SnowflakeStatementOutcome[],
  manualEvidence: string,
  evaluate: () => { status: SnowflakeFindingStatus; summary: string; evidence?: JsonRecord },
  options: { optional?: SnowflakeStatementOutcome[] } = {},
): SnowflakeFinding {
  const problems = required.filter((outcome) => outcome.status !== "ok");
  const statementEvidence = {
    statements: [...required, ...(options.optional ?? [])].map((outcome) => ({
      key: outcome.key,
      status: outcome.status,
      rows: outcome.rows.length,
      truncated: outcome.truncated,
      error: outcome.error,
    })),
  };
  if (problems.length > 0) {
    return finding(
      control,
      "manual",
      `Unknown: ${problems.map(describeOutcomeProblem).join("; ")}. Collect manually: ${manualEvidence}`,
      statementEvidence,
    );
  }
  const verdict = evaluate();
  const truncation = truncationNote(required);
  const evidence = { ...(verdict.evidence ?? {}), ...statementEvidence };
  if (truncation && verdict.status === "pass") {
    return finding(control, "warn", `${verdict.summary} Partial inventory: ${truncation}; the verdict cannot be pass on a partial result.`, { ...evidence, partial_inventory: truncation });
  }
  if (truncation) {
    return finding(control, verdict.status, `${verdict.summary} Partial inventory: ${truncation}.`, { ...evidence, partial_inventory: truncation });
  }
  return finding(control, verdict.status, verdict.summary, evidence);
}

function partialVisibilityNote(role: string | undefined, subject: string): string {
  return `The active role ${role ?? "(unknown)"} lacks MANAGE GRANTS, so ${subject} may list only objects granted to that role.`;
}

function isHumanUser(row: SqlRow): boolean {
  const type = upper(rowValue(row, "TYPE"));
  return type === "" || type === "PERSON" || type === "NULL";
}

function isServiceUser(row: SqlRow): boolean {
  return SERVICE_USER_TYPES.has(upper(rowValue(row, "TYPE")));
}

function isDisabledUser(row: SqlRow): boolean {
  return rowBoolean(row, "DISABLED") === true;
}

function userName(row: SqlRow): string {
  return rowValue(row, "NAME") ?? rowValue(row, "LOGIN_NAME") ?? "(unnamed)";
}

function parseIpList(value: string | null): string[] {
  if (!value) return [];
  return value
    .replace(/^\[|\]$/g, "")
    .split(",")
    .map((entry) => entry.replace(/["']/g, "").trim())
    .filter((entry) => entry.length > 0);
}

function isPermissiveCidr(entry: string): boolean {
  const normalized = entry.trim();
  if (normalized === "0.0.0.0/0" || normalized === "0.0.0.0" || normalized === "::/0") return true;
  const cidrMatch = /\/(\d{1,3})$/.exec(normalized);
  return Boolean(cidrMatch && Number(cidrMatch[1]) < 8);
}

function parameterValue(outcome: SnowflakeStatementOutcome, key: string): { value?: string; level?: string; found: boolean } {
  const row = outcome.rows.find((candidate) => upper(rowValue(candidate, "key")) === key.toUpperCase());
  if (!row) return { found: false };
  return { value: rowValue(row, "value") ?? undefined, level: rowValue(row, "level") ?? undefined, found: true };
}

export async function checkSnowflakeAccess(client: SnowflakeQueryClient): Promise<SnowflakeAccessCheckResult> {
  const config = client.getResolvedConfig();
  const session = await collectSessionContext(client);
  const probes: Array<[string, string]> = [
    ["show_network_policies", SNOWFLAKE_STATEMENTS.showNetworkPolicies],
    ["show_parameters", SNOWFLAKE_STATEMENTS.accountNetworkPolicyParameter],
    ["show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations],
    ["show_warehouses", SNOWFLAKE_STATEMENTS.showWarehouses],
    ["show_databases", SNOWFLAKE_STATEMENTS.showDatabases],
    ["show_shares", SNOWFLAKE_STATEMENTS.showShares],
    ["show_replication_groups", SNOWFLAKE_STATEMENTS.showReplicationGroups],
    ["account_usage_users", `SELECT COUNT(*) AS USER_COUNT FROM ${accountUsageView("USERS")} WHERE DELETED_ON IS NULL`],
    ["account_usage_login_history", `SELECT COUNT(*) AS EVENT_COUNT FROM ${accountUsageView("LOGIN_HISTORY")} WHERE EVENT_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP())`],
    ["account_usage_query_history", `SELECT COUNT(*) AS QUERY_COUNT FROM ${accountUsageView("QUERY_HISTORY")} WHERE START_TIME >= DATEADD(day, -1, CURRENT_TIMESTAMP())`],
    ["account_usage_access_history", SNOWFLAKE_STATEMENTS.accessHistoryProbe],
    ["account_usage_grants_to_roles", `SELECT COUNT(*) AS GRANT_COUNT FROM ${accountUsageView("GRANTS_TO_ROLES")} WHERE DELETED_ON IS NULL`],
    ["account_usage_grants_to_users", `SELECT COUNT(*) AS GRANT_COUNT FROM ${accountUsageView("GRANTS_TO_USERS")} WHERE DELETED_ON IS NULL`],
    ["account_usage_network_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("NETWORK_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_password_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("PASSWORD_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_session_policies", `SELECT COUNT(*) AS POLICY_COUNT FROM ${accountUsageView("SESSION_POLICIES")} WHERE DELETED IS NULL`],
    ["account_usage_masking_policies", SNOWFLAKE_STATEMENTS.maskingPolicyCount],
    ["account_usage_row_access_policies", SNOWFLAKE_STATEMENTS.rowAccessPolicyCount],
    ["account_usage_policy_references", `SELECT COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("POLICY_REFERENCES")}`],
    ["account_usage_tag_references", `SELECT COUNT(*) AS REFERENCE_COUNT FROM ${accountUsageView("TAG_REFERENCES")}`],
  ];

  const surfaces: SnowflakeAccessSurface[] = [toSurface("session_context", session.outcome)];
  for (const [name, statement] of probes) {
    surfaces.push(toSurface(name, await collectStatement(client, name, statement)));
  }

  const role = effectiveRole(config, session);
  const readable = surfaces.filter((surface) => surface.status === "readable").length;
  const accountUsageReadable = surfaces.filter((surface) => surface.name.startsWith("account_usage_") && surface.status === "readable").length;
  const status = session.outcome.status === "ok" && accountUsageReadable >= 10 && readable >= surfaces.length - 3 ? "healthy" : "limited";
  const notes = [
    `Using Snowflake account ${session.account ?? config.account} via ${config.baseUrl} (${config.tokenType}).`,
    `Authenticated as ${session.user ?? config.user} with role ${role ?? "(default role)"}${session.warehouse ? ` and warehouse ${session.warehouse}` : ""}.`,
    `${readable}/${surfaces.length} Snowflake audit surfaces are readable; ${accountUsageReadable} ACCOUNT_USAGE views responded.`,
  ];
  if (!hasFullVisibility(role)) {
    notes.push(partialVisibilityNote(role, "SHOW commands"));
  }
  if (config.sourceChain.length > 0) {
    notes.push(`Credential sources: ${config.sourceChain.join(", ")}.`);
  }

  return {
    status,
    account: session.account ?? config.account,
    user: session.user ?? config.user,
    role,
    fullVisibility: hasFullVisibility(role),
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run snowflake_assess_network_and_authentication, snowflake_assess_access_control, snowflake_assess_monitoring_and_lifecycle, snowflake_assess_data_protection, or snowflake_export_audit_bundle."
        : "Grant the audit role IMPORTED PRIVILEGES on the SNOWFLAKE database plus MANAGE GRANTS (or use SECURITYADMIN/ACCOUNTADMIN) and a small warehouse, then re-run snowflake_check_access.",
  };
}

function toSurface(name: string, outcome: SnowflakeStatementOutcome): SnowflakeAccessSurface {
  switch (outcome.status) {
    case "ok":
      return { name, statement: outcome.statement, status: "readable", rowCount: outcome.rows.length };
    case "denied":
      return { name, statement: outcome.statement, status: "denied", error: outcome.error };
    case "timeout":
      return { name, statement: outcome.statement, status: "timeout", error: outcome.error };
    case "error":
      return { name, statement: outcome.statement, status: "error", error: outcome.error };
    default: {
      const exhaustive: never = outcome.status;
      return exhaustive;
    }
  }
}

function summarizeStatuses(findings: SnowflakeFinding[]): JsonRecord {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

export async function assessSnowflakeNetworkAndAuthentication(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const minPasswordLength = clampNumber(options.minPasswordLength, DEFAULT_MIN_PASSWORD_LENGTH, 8, 256);
  const maxSessionIdleMinutes = clampNumber(options.maxSessionIdleMinutes, DEFAULT_MAX_SESSION_IDLE_MINUTES, 1, 1440);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const showNetworkPolicies = await collectStatement(client, "show_network_policies", SNOWFLAKE_STATEMENTS.showNetworkPolicies);
  const networkParameter = await collectStatement(client, "account_network_policy_parameter", SNOWFLAKE_STATEMENTS.accountNetworkPolicyParameter);
  const networkReferences = await collectStatement(client, "network_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("NETWORK_POLICY", limit), limit);
  const networkPolicies = await collectStatement(client, "network_policies", SNOWFLAKE_STATEMENTS.networkPolicies(limit), limit);
  const users = await collectStatement(client, "users", SNOWFLAKE_STATEMENTS.users(limit), limit);
  const passwordPolicies = await collectStatement(client, "password_policies", SNOWFLAKE_STATEMENTS.passwordPolicies(limit), limit);
  const passwordReferences = await collectStatement(client, "password_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("PASSWORD_POLICY", limit), limit);
  const integrations = await collectStatement(client, "show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations);
  const sessionPolicies = await collectStatement(client, "session_policies", SNOWFLAKE_STATEMENTS.sessionPolicies(limit), limit);
  const sessionReferences = await collectStatement(client, "session_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("SESSION_POLICY", limit), limit);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(1, [showNetworkPolicies, networkParameter, networkReferences], "Snowsight Admin > Security > Network Policies: confirm a policy exists and is activated for the account (SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT).", () => {
    const policyNames = showNetworkPolicies.rows.map((row) => rowValue(row, "name")).filter((name): name is string => Boolean(name));
    const accountParameter = parameterValue(networkParameter, "NETWORK_POLICY");
    const accountAttached = Boolean(accountParameter.value) && upper(accountParameter.level) === "ACCOUNT";
    const userAttachments = networkReferences.rows.filter((row) => upper(rowValue(row, "REF_ENTITY_DOMAIN")) === "USER");
    const evidence = {
      policy_count: policyNames.length,
      policies: policyNames.slice(0, 25),
      account_policy: accountParameter.value ?? null,
      account_policy_level: accountParameter.level ?? null,
      user_level_attachments: userAttachments.length,
    };
    if (policyNames.length === 0 && accountAttached && !hasFullVisibility(role)) {
      return { status: "warn", summary: `The account parameter reports network policy ${accountParameter.value} activated at ACCOUNT level, but SHOW NETWORK POLICIES returned zero policies under role ${role ?? "(unknown)"}; confirm the policy definition as ACCOUNTADMIN.`, evidence };
    }
    if (policyNames.length === 0) {
      return { status: "fail", summary: `SHOW NETWORK POLICIES returned zero policies; an empty inventory fails this control.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW NETWORK POLICIES")}`}`, evidence };
    }
    if (accountAttached) {
      return { status: "pass", summary: `Network policy ${accountParameter.value} is activated at ACCOUNT level (${policyNames.length} policies defined, ${userAttachments.length} user-level attachments).`, evidence };
    }
    if (userAttachments.length > 0) {
      return { status: "warn", summary: `${policyNames.length} network policies exist and ${userAttachments.length} user-level attachments were found, but no policy is activated at ACCOUNT level.`, evidence };
    }
    return { status: "fail", summary: `${policyNames.length} network policies exist but none is activated at ACCOUNT level and no user-level attachment was found in POLICY_REFERENCES.`, evidence };
  }));

  findings.push(evaluateControl(2, [networkPolicies], "Snowsight Admin > Security > Network Policies: review ALLOWED_IP_LIST entries for 0.0.0.0/0 or very broad CIDR ranges.", () => {
    const permissive: string[] = [];
    const emptyAllowLists: string[] = [];
    for (const row of networkPolicies.rows) {
      const name = rowValue(row, "NAME") ?? "(unnamed)";
      const allowed = parseIpList(rowValue(row, "ALLOWED_IP_LIST"));
      if (allowed.length === 0) emptyAllowLists.push(name);
      if (allowed.some(isPermissiveCidr)) permissive.push(name);
    }
    const evidence = { policy_count: networkPolicies.rows.length, permissive_policies: permissive, policies_without_allowed_ips: emptyAllowLists };
    if (networkPolicies.rows.length === 0) {
      return { status: "fail", summary: "NETWORK_POLICIES returned zero active policies, so no IP allowlist restricts access; an empty inventory fails this control.", evidence };
    }
    if (permissive.length > 0) {
      return { status: "fail", summary: `${permissive.length}/${networkPolicies.rows.length} network policies allow 0.0.0.0/0 or a CIDR broader than /8: ${permissive.slice(0, 10).join(", ")}.`, evidence };
    }
    if (emptyAllowLists.length === networkPolicies.rows.length) {
      return { status: "warn", summary: `All ${networkPolicies.rows.length} network policies have an empty ALLOWED_IP_LIST; they may rely on network rules that this view does not expose, so review the rules manually.`, evidence };
    }
    return { status: "pass", summary: `All ${networkPolicies.rows.length} network policies define restrictive allowlists without 0.0.0.0/0 entries.`, evidence };
  }));

  findings.push(evaluateControl(3, [users], "Snowsight Admin > Users & Roles: confirm MFA enrollment (HAS_MFA) for every enabled person user with a password, or an authentication policy with MFA_ENROLLMENT = REQUIRED.", () => {
    const humans = users.rows.filter((row) => isHumanUser(row) && !isDisabledUser(row));
    const passwordHumans = humans.filter((row) => rowBoolean(row, "HAS_PASSWORD") === true);
    const withoutMfa = passwordHumans.filter((row) => rowBoolean(row, "HAS_MFA") !== true && rowBoolean(row, "EXT_AUTHN_DUO") !== true);
    const unknownFlags = passwordHumans.filter((row) => rowBoolean(row, "HAS_MFA") === undefined && rowBoolean(row, "EXT_AUTHN_DUO") === undefined);
    const evidence = {
      enabled_human_users: humans.length,
      password_human_users: passwordHumans.length,
      users_without_mfa: withoutMfa.slice(0, 50).map(userName),
      users_with_unknown_mfa_flags: unknownFlags.length,
    };
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; MFA coverage cannot be established from an empty inventory (check ACCOUNT_USAGE latency and IMPORTED PRIVILEGES).", evidence };
    }
    if (passwordHumans.length === 0) {
      return { status: "pass", summary: `No enabled person users hold a password (${humans.length} enabled person users rely on SSO, key pair, or other factors), so password MFA enforcement is not applicable and no unprotected password login exists.`, evidence };
    }
    if (withoutMfa.length > 0) {
      return { status: "fail", summary: `${withoutMfa.length}/${passwordHumans.length} enabled person users with passwords have neither HAS_MFA nor EXT_AUTHN_DUO set: ${withoutMfa.slice(0, 10).map(userName).join(", ")}.`, evidence };
    }
    return { status: "pass", summary: `All ${passwordHumans.length} enabled person users with passwords report HAS_MFA or EXT_AUTHN_DUO = true.`, evidence };
  }));

  findings.push(evaluateControl(4, [passwordPolicies, passwordReferences], "Snowsight or SHOW PASSWORD POLICIES plus DESCRIBE PASSWORD POLICY: confirm an account-level password policy with length, complexity, retry, and lockout settings.", () => {
    const accountRefs = passwordReferences.rows.filter((row) => upper(rowValue(row, "REF_ENTITY_DOMAIN")) === "ACCOUNT");
    const attachedNames = new Set(accountRefs.map((row) => upper(rowValue(row, "POLICY_NAME"))));
    const weak: string[] = [];
    let strongAttached = 0;
    for (const row of passwordPolicies.rows) {
      const name = rowValue(row, "NAME") ?? "(unnamed)";
      const minLength = rowNumber(row, "PASSWORD_MIN_LENGTH") ?? 0;
      const complexity = [
        rowNumber(row, "PASSWORD_MIN_UPPER_CASE_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_LOWER_CASE_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_NUMERIC_CHARS") ?? 0,
        rowNumber(row, "PASSWORD_MIN_SPECIAL_CHARS") ?? 0,
      ];
      const retries = rowNumber(row, "PASSWORD_MAX_RETRIES");
      const strong = minLength >= minPasswordLength && complexity.every((value) => value >= 1) && retries !== undefined && retries <= 10;
      if (!strong) weak.push(name);
      if (strong && attachedNames.has(upper(name))) strongAttached += 1;
    }
    const evidence = {
      policy_count: passwordPolicies.rows.length,
      account_level_attachments: accountRefs.map((row) => rowValue(row, "POLICY_NAME")),
      weak_policies: weak,
      min_password_length_threshold: minPasswordLength,
    };
    if (passwordPolicies.rows.length === 0) {
      return { status: "fail", summary: "PASSWORD_POLICIES returned zero policies, so only Snowflake defaults apply; an empty inventory fails this control.", evidence };
    }
    if (accountRefs.length === 0) {
      return { status: "fail", summary: `${passwordPolicies.rows.length} password policies exist but POLICY_REFERENCES shows none attached at ACCOUNT level.`, evidence };
    }
    if (strongAttached === 0) {
      return { status: "warn", summary: `Account-level password policy is attached but does not meet the threshold (min length ${minPasswordLength}, one of each character class, retries <= 10): ${weak.join(", ")}.`, evidence };
    }
    return { status: "pass", summary: `An account-level password policy is attached and meets complexity thresholds (${accountRefs.length} account attachments, ${passwordPolicies.rows.length} policies).`, evidence };
  }));

  findings.push(evaluateControl(5, [users], "Snowsight Admin > Users & Roles: confirm service users (TYPE = SERVICE or LEGACY_SERVICE) have RSA public keys and no passwords.", () => {
    const serviceUsers = users.rows.filter((row) => isServiceUser(row) && !isDisabledUser(row));
    const withoutKey = serviceUsers.filter((row) => rowBoolean(row, "HAS_RSA_PUBLIC_KEY") !== true && rowBoolean(row, "HAS_WORKLOAD_IDENTITY") !== true);
    const withPassword = serviceUsers.filter((row) => rowBoolean(row, "HAS_PASSWORD") === true);
    const evidence = {
      service_users: serviceUsers.length,
      service_users_without_key_pair: withoutKey.slice(0, 50).map(userName),
      service_users_with_password: withPassword.slice(0, 50).map(userName),
    };
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; service account authentication cannot be assessed from an empty inventory.", evidence };
    }
    if (serviceUsers.length === 0) {
      return { status: "manual", summary: `None of the ${users.rows.length} users are typed SERVICE or LEGACY_SERVICE; classify automation accounts with TYPE = SERVICE and confirm each uses key-pair or workload identity authentication.`, evidence };
    }
    if (withoutKey.length > 0 || withPassword.length > 0) {
      return { status: "fail", summary: `${withoutKey.length}/${serviceUsers.length} service users lack an RSA public key or workload identity and ${withPassword.length} still hold a password.`, evidence };
    }
    return { status: "pass", summary: `All ${serviceUsers.length} enabled service users authenticate with key pairs or workload identity and hold no password.`, evidence };
  }));

  findings.push(evaluateControl(6, [integrations], "SHOW SECURITY INTEGRATIONS in Snowsight: confirm an enabled SAML2 (or External OAuth) security integration and SCIM provisioning.", () => {
    const security = integrations.rows.filter((row) => upper(rowValue(row, "category")) === "SECURITY");
    const saml = security.filter((row) => /SAML2/i.test(rowValue(row, "type") ?? ""));
    const enabledSaml = saml.filter((row) => rowBoolean(row, "enabled") === true);
    const scim = security.filter((row) => /SCIM/i.test(rowValue(row, "type") ?? "") && rowBoolean(row, "enabled") === true);
    const evidence = {
      security_integrations: security.map((row) => ({ name: rowValue(row, "name"), type: rowValue(row, "type"), enabled: rowValue(row, "enabled") })),
      enabled_saml_integrations: enabledSaml.map((row) => rowValue(row, "name")),
      enabled_scim_integrations: scim.map((row) => rowValue(row, "name")),
    };
    const visibility = hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`;
    if (saml.length === 0) {
      return { status: hasFullVisibility(role) ? "fail" : "manual", summary: `No SAML2 security integration was visible (${security.length} security integrations seen); an empty inventory does not satisfy SSO.${visibility}`, evidence };
    }
    if (enabledSaml.length === 0) {
      return { status: "fail", summary: `${saml.length} SAML2 integrations exist but none reports enabled = true.`, evidence };
    }
    return { status: "pass", summary: `${enabledSaml.length} enabled SAML2 integration(s) found${scim.length > 0 ? ` with ${scim.length} enabled SCIM integration(s)` : "; no enabled SCIM integration was visible"}.`, evidence };
  }));

  findings.push(evaluateControl(25, [sessionPolicies, sessionReferences], "SHOW SESSION POLICIES and POLICY_REFERENCES: confirm an account-level session policy with idle timeouts.", () => {
    const accountRefs = sessionReferences.rows.filter((row) => upper(rowValue(row, "REF_ENTITY_DOMAIN")) === "ACCOUNT");
    const attached = new Set(accountRefs.map((row) => upper(rowValue(row, "POLICY_NAME"))));
    const compliantAttached = sessionPolicies.rows.filter((row) => {
      const idle = rowNumber(row, "SESSION_IDLE_TIMEOUT_MINS");
      const uiIdle = rowNumber(row, "SESSION_UI_IDLE_TIMEOUT_MINS");
      return attached.has(upper(rowValue(row, "NAME"))) && idle !== undefined && idle <= maxSessionIdleMinutes && (uiIdle === undefined || uiIdle <= maxSessionIdleMinutes);
    });
    const evidence = {
      policy_count: sessionPolicies.rows.length,
      account_level_attachments: accountRefs.map((row) => rowValue(row, "POLICY_NAME")),
      max_session_idle_minutes: maxSessionIdleMinutes,
      policies: sessionPolicies.rows.slice(0, 25).map((row) => ({ name: rowValue(row, "NAME"), idle: rowValue(row, "SESSION_IDLE_TIMEOUT_MINS"), ui_idle: rowValue(row, "SESSION_UI_IDLE_TIMEOUT_MINS") })),
    };
    if (sessionPolicies.rows.length === 0) {
      return { status: "fail", summary: "SESSION_POLICIES returned zero policies, so default 4-hour idle timeouts apply; an empty inventory fails this control.", evidence };
    }
    if (accountRefs.length === 0) {
      return { status: "fail", summary: `${sessionPolicies.rows.length} session policies exist but none is attached at ACCOUNT level.`, evidence };
    }
    if (compliantAttached.length === 0) {
      return { status: "warn", summary: `An account-level session policy is attached but its idle timeout exceeds ${maxSessionIdleMinutes} minutes or is unset.`, evidence };
    }
    return { status: "pass", summary: `Account-level session policy enforces idle timeouts within ${maxSessionIdleMinutes} minutes.`, evidence };
  }));

  return {
    title: "Snowflake network and authentication posture",
    area: "network-and-authentication",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      users_seen: users.rows.length,
      network_policies_seen: networkPolicies.rows.length,
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, showNetworkPolicies, networkParameter, networkReferences, networkPolicies, users, passwordPolicies, passwordReferences, integrations, sessionPolicies, sessionReferences],
  };
}

export async function assessSnowflakeAccessControl(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const maxAccountAdmins = clampNumber(options.maxAccountAdmins, DEFAULT_MAX_ACCOUNTADMINS, 1, 100);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const roleGrants = await collectStatement(client, "role_hierarchy_grants", SNOWFLAKE_STATEMENTS.roleGrants(limit), limit);
  const globalGrants = await collectStatement(client, "global_privilege_grants", SNOWFLAKE_STATEMENTS.globalPrivilegeGrants(limit), limit);
  const adminGrants = await collectStatement(client, "admin_role_grants_to_users", SNOWFLAKE_STATEMENTS.adminRoleGrantsToUsers(limit), limit);
  const roleUsage = await collectStatement(client, "role_usage_by_queries", SNOWFLAKE_STATEMENTS.roleUsageByQueries(lookbackDays));
  const directGrants = await collectStatement(client, "direct_user_grants", SNOWFLAKE_STATEMENTS.directUserGrants(limit), limit);
  const publicGrants = await collectStatement(client, "public_grants", SNOWFLAKE_STATEMENTS.publicGrants(limit), limit);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(7, [roleGrants, globalGrants], "Review the role graph in Snowsight (Admin > Users & Roles > Roles graph): no custom role should inherit ACCOUNTADMIN/SECURITYADMIN, every custom role should roll up to SYSADMIN, and MANAGE GRANTS should stay with SECURITYADMIN.", () => {
    const customRoles = new Set<string>();
    const grantedTo = new Map<string, Set<string>>();
    for (const row of roleGrants.rows) {
      const granted = upper(rowValue(row, "NAME"));
      const grantee = upper(rowValue(row, "GRANTEE_NAME"));
      if (!granted || !grantee) continue;
      if (!SYSTEM_ROLES.has(granted)) customRoles.add(granted);
      if (!SYSTEM_ROLES.has(grantee)) customRoles.add(grantee);
      const set = grantedTo.get(granted) ?? new Set<string>();
      set.add(grantee);
      grantedTo.set(granted, set);
    }
    const adminInheritedByCustom = [...PRIVILEGED_SYSTEM_ROLES].flatMap((adminRole) => [...(grantedTo.get(adminRole) ?? [])].filter((grantee) => !SYSTEM_ROLES.has(grantee)).map((grantee) => `${adminRole} -> ${grantee}`));
    const rolledUpToSysadmin = new Set<string>();
    const visit = (roleName: string, seen: Set<string>) => {
      for (const [granted, grantees] of grantedTo) {
        if (grantees.has(roleName) && !seen.has(granted)) {
          seen.add(granted);
          rolledUpToSysadmin.add(granted);
          visit(granted, seen);
        }
      }
    };
    visit("SYSADMIN", new Set());
    visit("ACCOUNTADMIN", new Set());
    const orphanRoles = [...customRoles].filter((custom) => !rolledUpToSysadmin.has(custom) && !(grantedTo.get(custom)?.size));
    const riskyGlobal = globalGrants.rows.filter((row) => {
      const grantee = upper(rowValue(row, "GRANTEE_NAME"));
      return !SYSTEM_ROLES.has(grantee) && /MANAGE GRANTS|CREATE USER|CREATE ROLE|MANAGE ACCOUNT|APPLY MASKING POLICY|APPLY ROW ACCESS POLICY|EXECUTE TASK|MONITOR USAGE|IMPORT SHARE/i.test(rowValue(row, "PRIVILEGE") ?? "");
    });
    const evidence = {
      role_to_role_grants: roleGrants.rows.length,
      custom_roles: customRoles.size,
      admin_roles_inherited_by_custom_roles: adminInheritedByCustom,
      custom_roles_not_rolled_up: orphanRoles.slice(0, 50),
      sensitive_global_privileges_on_custom_roles: riskyGlobal.slice(0, 50).map((row) => `${rowValue(row, "PRIVILEGE")} -> ${rowValue(row, "GRANTEE_NAME")}`),
    };
    if (roleGrants.rows.length === 0) {
      return { status: "manual", summary: "GRANTS_TO_ROLES returned zero role-to-role grants; a hierarchy cannot be evaluated from an empty graph (check ACCOUNT_USAGE latency and IMPORTED PRIVILEGES).", evidence };
    }
    if (adminInheritedByCustom.length > 0) {
      return { status: "fail", summary: `${adminInheritedByCustom.length} custom roles inherit ACCOUNTADMIN or SECURITYADMIN: ${adminInheritedByCustom.slice(0, 10).join(", ")}.`, evidence };
    }
    if (riskyGlobal.length > 0 || orphanRoles.length > 0) {
      return { status: "warn", summary: `${riskyGlobal.length} sensitive global privileges sit on custom roles and ${orphanRoles.length} custom roles do not roll up to SYSADMIN.`, evidence };
    }
    return { status: "pass", summary: `Role graph with ${customRoles.size} custom roles has no admin inheritance, no orphaned roles, and no sensitive global privileges on custom roles.`, evidence };
  }));

  findings.push(evaluateControl(8, [adminGrants], "SHOW GRANTS OF ROLE ACCOUNTADMIN in Snowsight: confirm at least two and no more than a handful of named users hold ACCOUNTADMIN.", () => {
    const accountAdmins = adminGrants.rows.filter((row) => upper(rowValue(row, "ROLE")) === "ACCOUNTADMIN").map((row) => rowValue(row, "GRANTEE_NAME") ?? "(unknown)");
    const securityAdmins = adminGrants.rows.filter((row) => upper(rowValue(row, "ROLE")) === "SECURITYADMIN").map((row) => rowValue(row, "GRANTEE_NAME") ?? "(unknown)");
    const evidence = { accountadmin_users: accountAdmins, securityadmin_users: securityAdmins, max_accountadmins: maxAccountAdmins };
    if (accountAdmins.length === 0) {
      return { status: "manual", summary: "GRANTS_TO_USERS shows zero ACCOUNTADMIN grantees; Snowflake always has at least one, so the view is latent or restricted and the membership must be confirmed manually.", evidence };
    }
    if (accountAdmins.length > maxAccountAdmins) {
      return { status: "fail", summary: `${accountAdmins.length} users hold ACCOUNTADMIN, above the threshold of ${maxAccountAdmins}: ${accountAdmins.slice(0, 10).join(", ")}.`, evidence };
    }
    if (accountAdmins.length === 1) {
      return { status: "warn", summary: `Only one user holds ACCOUNTADMIN (${accountAdmins[0]}); Snowflake recommends at least two to avoid lockout.`, evidence };
    }
    return { status: "pass", summary: `${accountAdmins.length} users hold ACCOUNTADMIN, within the threshold of ${maxAccountAdmins}.`, evidence };
  }));

  findings.push(evaluateControl(9, [roleUsage], `Query QUERY_HISTORY for the last ${lookbackDays} days grouped by ROLE_NAME and confirm ACCOUNTADMIN is not used for routine SELECT/DML workloads.`, () => {
    const total = roleUsage.rows.reduce((sum, row) => sum + (rowNumber(row, "QUERY_COUNT") ?? 0), 0);
    const adminRow = roleUsage.rows.find((row) => upper(rowValue(row, "ROLE_NAME")) === "ACCOUNTADMIN");
    const adminCount = adminRow ? rowNumber(adminRow, "QUERY_COUNT") ?? 0 : 0;
    const adminUsers = adminRow ? rowNumber(adminRow, "USER_COUNT") ?? 0 : 0;
    const share = total > 0 ? adminCount / total : 0;
    const evidence = { lookback_days: lookbackDays, routine_queries: total, accountadmin_queries: adminCount, accountadmin_users: adminUsers, accountadmin_share: Number(share.toFixed(4)) };
    if (total === 0) {
      return { status: "manual", summary: `QUERY_HISTORY shows zero routine queries in the last ${lookbackDays} days; usage cannot be assessed from an empty window (view latency is up to 45 minutes).`, evidence };
    }
    if (adminCount === 0) {
      return { status: "pass", summary: `ACCOUNTADMIN ran none of the ${total} routine queries in the last ${lookbackDays} days.`, evidence };
    }
    if (share >= 0.1 || adminCount >= 100) {
      return { status: "fail", summary: `ACCOUNTADMIN ran ${adminCount}/${total} routine queries (${(share * 100).toFixed(1)}%) across ${adminUsers} users in the last ${lookbackDays} days.`, evidence };
    }
    return { status: "warn", summary: `ACCOUNTADMIN ran ${adminCount}/${total} routine queries (${(share * 100).toFixed(1)}%) in the last ${lookbackDays} days; move that work to functional roles.`, evidence };
  }));

  findings.push(evaluateControl(10, [directGrants], "Review GRANTS_TO_ROLES WHERE GRANTED_TO = 'USER' in Snowsight and confirm no privileges are granted directly to users.", () => {
    const evidence = { direct_grants: directGrants.rows.length, samples: directGrants.rows.slice(0, 25).map((row) => `${rowValue(row, "PRIVILEGE")} ON ${rowValue(row, "GRANTED_ON")} ${rowValue(row, "NAME")} -> ${rowValue(row, "GRANTEE_NAME")}`) };
    if (directGrants.rows.length === 0) {
      return { status: "pass", summary: "GRANTS_TO_ROLES was readable and lists no privileges granted directly to users; for this control an empty result is the compliant state.", evidence };
    }
    return { status: "fail", summary: `${directGrants.rows.length} privileges are granted directly to users instead of roles.`, evidence };
  }));

  findings.push(evaluateControl(16, [publicGrants], "Review grants to the PUBLIC role in Snowsight and confirm no data objects are exposed to every user.", () => {
    const sensitive = publicGrants.rows.filter((row) => SENSITIVE_OBJECT_DOMAINS.has(upper(rowValue(row, "GRANTED_ON"))));
    const evidence = { public_grants: publicGrants.rows.length, sensitive_public_grants: sensitive.slice(0, 50).map((row) => `${rowValue(row, "PRIVILEGE")} ON ${rowValue(row, "GRANTED_ON")} ${rowValue(row, "NAME")}`) };
    if (publicGrants.rows.length === 0) {
      return { status: "pass", summary: "GRANTS_TO_ROLES was readable and lists no privileges granted to PUBLIC; for this control an empty result is the compliant state.", evidence };
    }
    if (sensitive.length > 0) {
      return { status: "fail", summary: `${sensitive.length}/${publicGrants.rows.length} PUBLIC grants target data objects (tables, views, schemas, databases, or stages).`, evidence };
    }
    return { status: "warn", summary: `${publicGrants.rows.length} PUBLIC grants exist on non-data objects (for example warehouses); review whether they are intentional.`, evidence };
  }));

  return {
    title: "Snowflake access control posture",
    area: "access-control",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      lookback_days: lookbackDays,
      role_grants_seen: roleGrants.rows.length,
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, roleGrants, globalGrants, adminGrants, roleUsage, directGrants, publicGrants],
  };
}

export async function assessSnowflakeMonitoringAndLifecycle(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const staleUserDays = clampNumber(options.staleUserDays, DEFAULT_STALE_USER_DAYS, 1, 3650);
  const failedLoginThreshold = clampNumber(options.failedLoginThreshold, DEFAULT_FAILED_LOGIN_THRESHOLD, 1, 100_000);
  const maxAutoSuspendSeconds = clampNumber(options.maxAutoSuspendSeconds, DEFAULT_MAX_AUTO_SUSPEND_SECONDS, 1, 86_400);
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 0, 90);
  const limit = config.rowLimit;
  const now = new Date();
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const loginOutcomes = await collectStatement(client, "login_outcomes", SNOWFLAKE_STATEMENTS.loginOutcomes(lookbackDays));
  const failedLogins = await collectStatement(client, "failed_logins", SNOWFLAKE_STATEMENTS.failedLogins(lookbackDays));
  const users = await collectStatement(client, "users", SNOWFLAKE_STATEMENTS.users(limit), limit);
  const retention = await collectStatement(client, "data_retention_parameter", SNOWFLAKE_STATEMENTS.dataRetentionParameter);
  const accessHistory = await collectStatement(client, "access_history_probe", SNOWFLAKE_STATEMENTS.accessHistoryProbe);
  const warehouses = await collectStatement(client, "show_warehouses", SNOWFLAKE_STATEMENTS.showWarehouses);

  const findings: SnowflakeFinding[] = [];

  findings.push(evaluateControl(11, [loginOutcomes, failedLogins], `Query LOGIN_HISTORY for the last ${lookbackDays} days (IS_SUCCESS = 'NO') and confirm failed logins are monitored and alerted.`, () => {
    const successes = loginOutcomes.rows.filter((row) => upper(rowValue(row, "IS_SUCCESS")) === "YES").reduce((sum, row) => sum + (rowNumber(row, "EVENT_COUNT") ?? 0), 0);
    const failures = loginOutcomes.rows.filter((row) => upper(rowValue(row, "IS_SUCCESS")) === "NO").reduce((sum, row) => sum + (rowNumber(row, "EVENT_COUNT") ?? 0), 0);
    const excessive = failedLogins.rows.filter((row) => (rowNumber(row, "FAILURE_COUNT") ?? 0) >= failedLoginThreshold);
    const evidence = {
      lookback_days: lookbackDays,
      successful_logins: successes,
      failed_logins: failures,
      threshold: failedLoginThreshold,
      excessive_sources: excessive.slice(0, 50).map((row) => ({ user: rowValue(row, "USER_NAME"), ip: rowValue(row, "CLIENT_IP"), failures: rowValue(row, "FAILURE_COUNT"), last_error: rowValue(row, "LAST_ERROR") })),
    };
    if (successes + failures === 0) {
      return { status: "manual", summary: `LOGIN_HISTORY returned zero events for the last ${lookbackDays} days; monitoring cannot be evaluated from an empty window (view latency is up to 2 hours).`, evidence };
    }
    if (excessive.length > 0) {
      return { status: "fail", summary: `${excessive.length} user/IP sources exceeded ${failedLoginThreshold} failed logins in ${lookbackDays} days (${failures} failures total).`, evidence };
    }
    return { status: "pass", summary: `${failures} failed logins across ${successes + failures} login events in ${lookbackDays} days; no source exceeded the ${failedLoginThreshold}-failure threshold.`, evidence };
  }));

  findings.push(evaluateControl(12, [users], `Review enabled users whose LAST_SUCCESS_LOGIN is older than ${staleUserDays} days or NULL and disable or remove them.`, () => {
    const humans = users.rows.filter((row) => isHumanUser(row) && !isDisabledUser(row));
    const stale: string[] = [];
    const neverOrUnknown: string[] = [];
    for (const row of humans) {
      const lastLogin = parseSnowflakeTimestamp(rowValue(row, "LAST_SUCCESS_LOGIN"));
      if (!lastLogin) {
        neverOrUnknown.push(userName(row));
        continue;
      }
      if (daysSince(lastLogin, now) > staleUserDays) stale.push(userName(row));
    }
    const evidence = { enabled_human_users: humans.length, stale_user_days: staleUserDays, stale_users: stale.slice(0, 50), users_without_login_timestamp: neverOrUnknown.slice(0, 50), users_without_login_timestamp_count: neverOrUnknown.length };
    if (users.rows.length === 0) {
      return { status: "manual", summary: "USERS returned zero rows; stale-user review cannot be performed on an empty inventory.", evidence };
    }
    if (stale.length > 0) {
      return { status: "fail", summary: `${stale.length}/${humans.length} enabled person users have not logged in for more than ${staleUserDays} days; ${neverOrUnknown.length} more have no LAST_SUCCESS_LOGIN and were not counted as active.`, evidence };
    }
    if (neverOrUnknown.length > 0) {
      return { status: "warn", summary: `No enabled person user exceeded ${staleUserDays} days since login, but ${neverOrUnknown.length}/${humans.length} have a NULL LAST_SUCCESS_LOGIN (never logged in or outside the one-year retention) and must be reviewed.`, evidence };
    }
    return { status: "pass", summary: `All ${humans.length} enabled person users logged in within ${staleUserDays} days.`, evidence };
  }));

  findings.push(evaluateControl(13, [retention], "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT and confirm ACCESS_HISTORY/QUERY_HISTORY (365-day fixed retention) are exported to long-term storage if longer retention is required.", () => {
    const parameter = parameterValue(retention, "DATA_RETENTION_TIME_IN_DAYS");
    const value = asNumber(parameter.value);
    const evidence = { data_retention_time_in_days: parameter.value ?? null, level: parameter.level ?? null, min_retention_days: minRetentionDays, access_history_readable: accessHistory.status === "ok", access_history_events_7d: accessHistory.rows[0] ? rowValue(accessHistory.rows[0], "EVENT_COUNT") : null };
    if (!parameter.found || value === undefined) {
      return { status: "manual", summary: "DATA_RETENTION_TIME_IN_DAYS was not present in the SHOW PARAMETERS output; confirm the account retention setting manually.", evidence };
    }
    if (value < minRetentionDays) {
      return { status: "fail", summary: `Account DATA_RETENTION_TIME_IN_DAYS is ${value}, below the ${minRetentionDays}-day threshold.`, evidence };
    }
    if (accessHistory.status !== "ok") {
      return { status: "warn", summary: `Account DATA_RETENTION_TIME_IN_DAYS is ${value}, but ACCESS_HISTORY was not readable (${accessHistory.status}); object access auditing needs Enterprise Edition and IMPORTED PRIVILEGES.`, evidence };
    }
    return { status: "pass", summary: `Account DATA_RETENTION_TIME_IN_DAYS is ${value} and ACCESS_HISTORY plus QUERY_HISTORY are readable with Snowflake's fixed 365-day retention.`, evidence };
  }, { optional: [accessHistory] }));

  findings.push(evaluateControl(24, [warehouses], `SHOW WAREHOUSES: confirm every warehouse has auto_suspend set to ${maxAutoSuspendSeconds} seconds or less.`, () => {
    const never: string[] = [];
    const tooLong: string[] = [];
    for (const row of warehouses.rows) {
      const name = rowValue(row, "name") ?? "(unnamed)";
      const autoSuspend = rowValue(row, "auto_suspend");
      const seconds = asNumber(autoSuspend);
      if (autoSuspend === null || /^null$/i.test(autoSuspend) || seconds === 0) {
        never.push(name);
      } else if (seconds === undefined || seconds > maxAutoSuspendSeconds) {
        tooLong.push(name);
      }
    }
    const evidence = { warehouses: warehouses.rows.length, never_suspend: never, auto_suspend_above_threshold: tooLong, max_auto_suspend_seconds: maxAutoSuspendSeconds };
    if (warehouses.rows.length === 0) {
      return { status: "manual", summary: `SHOW WAREHOUSES returned zero warehouses visible to role ${role ?? "(unknown)"}; confirm the inventory with a role that can see all warehouses.`, evidence };
    }
    if (never.length > 0) {
      return { status: "fail", summary: `${never.length}/${warehouses.rows.length} warehouses never auto-suspend: ${never.slice(0, 10).join(", ")}.`, evidence };
    }
    if (tooLong.length > 0) {
      return { status: "warn", summary: `${tooLong.length}/${warehouses.rows.length} warehouses auto-suspend after more than ${maxAutoSuspendSeconds} seconds.`, evidence };
    }
    return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `All ${warehouses.rows.length} visible warehouses auto-suspend within ${maxAutoSuspendSeconds} seconds.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW WAREHOUSES")}`}`, evidence };
  }));

  return {
    title: "Snowflake monitoring and lifecycle posture",
    area: "monitoring-and-lifecycle",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      lookback_days: lookbackDays,
      users_seen: users.rows.length,
      warehouses_seen: warehouses.rows.length,
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, loginOutcomes, failedLogins, users, retention, accessHistory, warehouses],
  };
}

export async function assessSnowflakeDataProtection(
  client: SnowflakeQueryClient,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAssessmentResult> {
  const config = client.getResolvedConfig();
  const minRetentionDays = clampNumber(options.minRetentionDays, DEFAULT_MIN_RETENTION_DAYS, 0, 90);
  const limit = config.rowLimit;
  const session = await collectSessionContext(client);
  const role = effectiveRole(config, session);

  const maskingCount = await collectStatement(client, "masking_policy_count", SNOWFLAKE_STATEMENTS.maskingPolicyCount);
  const maskingReferences = await collectStatement(client, "masking_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("MASKING_POLICY", limit), limit);
  const rowAccessCount = await collectStatement(client, "row_access_policy_count", SNOWFLAKE_STATEMENTS.rowAccessPolicyCount);
  const rowAccessReferences = await collectStatement(client, "row_access_policy_references", SNOWFLAKE_STATEMENTS.policyReferences("ROW_ACCESS_POLICY", limit), limit);
  const tagReferences = await collectStatement(client, "tag_references", SNOWFLAKE_STATEMENTS.tagReferenceSummary);
  const stageParameters = await collectStatement(client, "stage_parameters", SNOWFLAKE_STATEMENTS.stageParameters);
  const unloadParameters = await collectStatement(client, "unload_parameters", SNOWFLAKE_STATEMENTS.unloadParameters);
  const databases = await collectStatement(client, "show_databases", SNOWFLAKE_STATEMENTS.showDatabases);
  const shares = await collectStatement(client, "show_shares", SNOWFLAKE_STATEMENTS.showShares);
  const integrations = await collectStatement(client, "show_integrations", SNOWFLAKE_STATEMENTS.showIntegrations);
  const replicationGroups = await collectStatement(client, "show_replication_groups", SNOWFLAKE_STATEMENTS.showReplicationGroups);

  const findings: SnowflakeFinding[] = [];
  const tagSummary = tagReferences.status === "ok" ? tagReferences.rows.slice(0, 25).map((row) => ({ tag: `${rowValue(row, "TAG_DATABASE")}.${rowValue(row, "TAG_SCHEMA")}.${rowValue(row, "TAG_NAME")}`, references: rowValue(row, "REFERENCE_COUNT") })) : [];

  findings.push(evaluateControl(14, [maskingCount, maskingReferences], "Snowsight Data > Governance: confirm masking policies exist and are assigned to every sensitive column (POLICY_REFERENCES WHERE POLICY_KIND = 'MASKING_POLICY').", () => {
    const policies = rowNumber(maskingCount.rows[0] ?? {}, "POLICY_COUNT") ?? 0;
    const active = maskingReferences.rows.filter((row) => upper(rowValue(row, "POLICY_STATUS")) === "ACTIVE" || rowValue(row, "POLICY_STATUS") === null);
    const broken = maskingReferences.rows.length - active.length;
    const evidence = { masking_policies: policies, masking_references: maskingReferences.rows.length, references_with_problems: broken, tag_classification_summary: tagSummary, tag_references_readable: tagReferences.status === "ok" };
    if (policies === 0) {
      return { status: "fail", summary: "MASKING_POLICIES lists zero active masking policies, so no column is protected by dynamic data masking; an empty inventory fails this control.", evidence };
    }
    if (maskingReferences.rows.length === 0) {
      return { status: "fail", summary: `${policies} masking policies exist but POLICY_REFERENCES shows none assigned to any column or tag.`, evidence };
    }
    if (broken > 0) {
      return { status: "warn", summary: `${maskingReferences.rows.length} masking policy references exist but ${broken} are not ACTIVE (conflicting or mismatched assignments).`, evidence };
    }
    return { status: "pass", summary: `${policies} masking policies are assigned through ${maskingReferences.rows.length} active column or tag references${tagSummary.length > 0 ? ` alongside ${tagSummary.length} classification tags` : ""}.`, evidence };
  }, { optional: [tagReferences] }));

  findings.push(evaluateControl(15, [rowAccessCount, rowAccessReferences], "Snowsight Data > Governance: confirm row access policies exist and are assigned to sensitive tables (POLICY_REFERENCES WHERE POLICY_KIND = 'ROW_ACCESS_POLICY').", () => {
    const policies = rowNumber(rowAccessCount.rows[0] ?? {}, "POLICY_COUNT") ?? 0;
    const evidence = { row_access_policies: policies, row_access_references: rowAccessReferences.rows.length, protected_objects: rowAccessReferences.rows.slice(0, 25).map((row) => `${rowValue(row, "REF_DATABASE_NAME")}.${rowValue(row, "REF_SCHEMA_NAME")}.${rowValue(row, "REF_ENTITY_NAME")}`) };
    if (policies === 0) {
      return { status: "fail", summary: "ROW_ACCESS_POLICIES lists zero active policies, so no table has row-level security; an empty inventory fails this control.", evidence };
    }
    if (rowAccessReferences.rows.length === 0) {
      return { status: "fail", summary: `${policies} row access policies exist but none is assigned to a table or view.`, evidence };
    }
    return { status: "pass", summary: `${policies} row access policies protect ${rowAccessReferences.rows.length} table or view references.`, evidence };
  }));

  findings.push(evaluateControl(17, [stageParameters], "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%' IN ACCOUNT: confirm both creation and operation parameters are true.", () => {
    const creation = parameterValue(stageParameters, "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION");
    const operation = parameterValue(stageParameters, "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION");
    const evidence = { require_storage_integration_for_stage_creation: creation.value ?? null, require_storage_integration_for_stage_operation: operation.value ?? null };
    if (!creation.found && !operation.found) {
      return { status: "manual", summary: "Neither REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_* parameter appeared in SHOW PARAMETERS output; confirm them manually.", evidence };
    }
    const creationOn = asBoolean(creation.value) === true;
    const operationOn = asBoolean(operation.value) === true;
    if (creationOn && operationOn) {
      return { status: "pass", summary: "Storage integrations are required for both stage creation and stage operations.", evidence };
    }
    if (creationOn || operationOn) {
      return { status: "warn", summary: `Only one storage integration requirement is enabled (creation=${creation.value ?? "unset"}, operation=${operation.value ?? "unset"}).`, evidence };
    }
    return { status: "fail", summary: "Storage integrations are not required for stage creation or operations, so stages can use raw cloud credentials.", evidence };
  }));

  findings.push(evaluateControl(18, [unloadParameters], "SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%' IN ACCOUNT: confirm PREVENT_UNLOAD_TO_INLINE_URL and PREVENT_UNLOAD_TO_INTERNAL_STAGES are true.", () => {
    const inlineUrl = parameterValue(unloadParameters, "PREVENT_UNLOAD_TO_INLINE_URL");
    const internalStages = parameterValue(unloadParameters, "PREVENT_UNLOAD_TO_INTERNAL_STAGES");
    const evidence = { prevent_unload_to_inline_url: inlineUrl.value ?? null, prevent_unload_to_internal_stages: internalStages.value ?? null };
    if (!inlineUrl.found && !internalStages.found) {
      return { status: "manual", summary: "Neither PREVENT_UNLOAD_TO_* parameter appeared in SHOW PARAMETERS output; confirm them manually.", evidence };
    }
    const inlineOn = asBoolean(inlineUrl.value) === true;
    const internalOn = asBoolean(internalStages.value) === true;
    if (inlineOn && internalOn) {
      return { status: "pass", summary: "Unloads to inline URLs and internal stages are both prevented.", evidence };
    }
    if (inlineOn || internalOn) {
      return { status: "warn", summary: `Only one unload restriction is enabled (inline_url=${inlineUrl.value ?? "unset"}, internal_stages=${internalStages.value ?? "unset"}).`, evidence };
    }
    return { status: "fail", summary: "Neither PREVENT_UNLOAD_TO_INLINE_URL nor PREVENT_UNLOAD_TO_INTERNAL_STAGES is enabled.", evidence };
  }));

  findings.push(evaluateControl(19, [databases], `SHOW DATABASES: confirm retention_time is at least ${minRetentionDays} day(s) for every customer database.`, () => {
    const customer = databases.rows.filter((row) => !/IMPORTED DATABASE|APPLICATION/i.test(rowValue(row, "kind") ?? "") && upper(rowValue(row, "name")) !== "SNOWFLAKE");
    const below = customer.filter((row) => (asNumber(rowValue(row, "retention_time")) ?? 0) < minRetentionDays).map((row) => rowValue(row, "name") ?? "(unnamed)");
    const evidence = { databases_seen: databases.rows.length, customer_databases: customer.length, below_threshold: below.slice(0, 50), min_retention_days: minRetentionDays };
    if (databases.rows.length === 0) {
      return { status: "manual", summary: `SHOW DATABASES returned zero databases visible to role ${role ?? "(unknown)"}; confirm Time Travel retention with a role that can see all databases.`, evidence };
    }
    if (below.length > 0) {
      return { status: "fail", summary: `${below.length}/${customer.length} customer databases have retention_time below ${minRetentionDays}: ${below.slice(0, 10).join(", ")}.`, evidence };
    }
    return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `All ${customer.length} visible customer databases retain Time Travel for at least ${minRetentionDays} day(s).${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW DATABASES")}`}`, evidence };
  }));

  findings.push(finding(20, "manual", "Not verifiable through SQL: Tri-Secret Secure is enabled by Snowflake Support for Business Critical (or higher) accounts. Collect the Snowflake Support case or Snowsight Admin > Accounts edition evidence and the composite master key confirmation.", { edition_requirement: "Business Critical or higher", sql_verifiable: false }));

  findings.push(finding(21, "manual", "Not verifiable through SQL: customer-managed key enrollment is confirmed through Snowflake Support and your cloud KMS. SYSTEM$GET_SNOWFLAKE_PLATFORM_INFO() only returns VPC/VNet IDs, and SYSTEM$GET_CMK_KMS_KEY_POLICY, SYSTEM$GET_CMK_AKV_CONSENT_URL, and SYSTEM$GET_GCP_KMS_CMK_GRANT_ACCESS_CMD return setup templates. Collect the KMS key policy and rotation evidence from AWS KMS, Azure Key Vault, or Google Cloud KMS.", { edition_requirement: "Business Critical or higher", sql_verifiable: false }));

  findings.push(evaluateControl(22, [shares], "SHOW SHARES as ACCOUNTADMIN: review every OUTBOUND share, its consumer accounts (to column), and any listing_global_name exposure.", () => {
    const outbound = shares.rows.filter((row) => upper(rowValue(row, "kind")) === "OUTBOUND");
    const listings = outbound.filter((row) => Boolean(rowValue(row, "listing_global_name")));
    const evidence = {
      shares_seen: shares.rows.length,
      outbound_shares: outbound.slice(0, 50).map((row) => ({ name: rowValue(row, "name"), database: rowValue(row, "database_name"), to: rowValue(row, "to"), listing: rowValue(row, "listing_global_name") })),
      listing_backed_shares: listings.length,
      replication_groups_visible: replicationGroups.status === "ok" ? replicationGroups.rows.length : null,
    };
    if (shares.rows.length === 0 && !hasFullVisibility(role)) {
      return { status: "manual", summary: `SHOW SHARES returned zero rows under role ${role ?? "(unknown)"}; Snowflake returns empty results without the IMPORT SHARE privilege, so re-run as ACCOUNTADMIN to confirm there are no outbound shares.`, evidence };
    }
    if (outbound.length === 0 && !hasFullVisibility(role)) {
      return { status: "warn", summary: `SHOW SHARES under role ${role ?? "(unknown)"} lists ${shares.rows.length} shares and no OUTBOUND share, but the role lacks ACCOUNTADMIN visibility so outbound shares may be hidden; confirm as ACCOUNTADMIN.`, evidence };
    }
    if (outbound.length === 0) {
      return { status: "pass", summary: `SHOW SHARES was readable under ${role} and lists no OUTBOUND shares (${shares.rows.length} inbound shares seen); for this control an empty outbound inventory is compliant.`, evidence };
    }
    return { status: "warn", summary: `${outbound.length} OUTBOUND shares expose data to other accounts${listings.length > 0 ? ` and ${listings.length} are attached to marketplace or private listings` : ""}; confirm each consumer is approved.`, evidence };
  }, { optional: [replicationGroups] }));

  findings.push(evaluateControl(23, [integrations], "SHOW API INTEGRATIONS and SHOW EXTERNAL ACCESS INTEGRATIONS: confirm every enabled integration and external function is approved.", () => {
    const external = integrations.rows.filter((row) => /^(API|EXTERNAL_ACCESS|EXTERNAL ACCESS)$/i.test(rowValue(row, "category") ?? "") || /API|EXTERNAL_ACCESS/i.test(rowValue(row, "type") ?? ""));
    const enabled = external.filter((row) => rowBoolean(row, "enabled") === true);
    const evidence = { integrations_seen: integrations.rows.length, external_integrations: external.map((row) => ({ name: rowValue(row, "name"), type: rowValue(row, "type"), category: rowValue(row, "category"), enabled: rowValue(row, "enabled") })) };
    if (integrations.rows.length === 0 && !hasFullVisibility(role)) {
      return { status: "manual", summary: `SHOW INTEGRATIONS returned zero rows under role ${role ?? "(unknown)"}; ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`, evidence };
    }
    if (enabled.length === 0) {
      return { status: hasFullVisibility(role) ? "pass" : "warn", summary: `No enabled API or external access integrations were found among ${integrations.rows.length} integrations; for this control an empty inventory is compliant when read with full visibility.${hasFullVisibility(role) ? "" : ` ${partialVisibilityNote(role, "SHOW INTEGRATIONS")}`}`, evidence };
    }
    return { status: "warn", summary: `${enabled.length} enabled API or external access integrations allow outbound calls: ${enabled.slice(0, 10).map((row) => rowValue(row, "name")).join(", ")}; confirm each is approved.`, evidence };
  }));

  return {
    title: "Snowflake data protection posture",
    area: "data-protection",
    summary: {
      account: session.account ?? config.account,
      role: role ?? null,
      full_visibility: hasFullVisibility(role),
      databases_seen: databases.rows.length,
      shares_seen: shares.rows.length,
      ...summarizeStatuses(findings),
    },
    findings,
    statements: [session.outcome, maskingCount, maskingReferences, rowAccessCount, rowAccessReferences, tagReferences, stageParameters, unloadParameters, databases, shares, integrations, replicationGroups],
  };
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "snowflake";
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
  if (relativeTarget === ".." || relativeTarget.startsWith(`..${join("/")}`) || relativeTarget.startsWith("..")) {
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
  for (let index = 0; index < 50; index += 1) {
    const suffix = index === 0 ? "" : `-${index + 1}`;
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
  await chmod(zipPath, 0o600);
}

async function countFilesRecursively(rootDir: string): Promise<number> {
  let total = 0;
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) total += await countFilesRecursively(pathname);
    else if (entry.isFile()) total += 1;
  }
  return total;
}

function formatAccessCheckText(result: SnowflakeAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.rowCount === undefined ? "-" : String(surface.rowCount),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);
  return [
    `Snowflake access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Rows", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SnowflakeAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary.length > 160 ? `${item.summary.slice(0, 157)}...` : item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  const problems = result.statements.filter((statement) => statement.status !== "ok");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(problems.length > 0 ? ["", "Statements that did not complete:", ...problems.map((problem) => `- ${describeOutcomeProblem(problem)}`)] : []),
  ].join("\n");
}

function frameworkPrefix(framework: (typeof SNOWFLAKE_FRAMEWORKS)[number]): string {
  return `${framework} `;
}

function buildFrameworkReport(framework: (typeof SNOWFLAKE_FRAMEWORKS)[number], findings: SnowflakeFinding[]): string {
  const rows = findings.map((item) => [
    item.mappings.find((entry) => entry.startsWith(frameworkPrefix(framework)))?.slice(framework.length + 1) ?? "-",
    item.id,
    item.status.toUpperCase(),
    item.severity.toUpperCase(),
    item.title,
  ]);
  return [
    `# ${framework} Mapping Report`,
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    formatTable([`${framework} Requirement`, "Finding", "Status", "Severity", "Title"], rows),
    "",
    "Statuses: PASS (evidence observed), WARN (partial or review needed), FAIL (control not met), MANUAL (evidence must be collected by a human).",
  ].join("\n");
}

function buildUnifiedMatrix(findings: SnowflakeFinding[]): string {
  const rows = findings.map((item) => [item.id, item.status.toUpperCase(), item.title, ...SNOWFLAKE_FRAMEWORKS.map((framework) => item.mappings.find((entry) => entry.startsWith(frameworkPrefix(framework)))?.slice(framework.length + 1) ?? "-")]);
  return ["# Unified Compliance Matrix", "", formatTable(["Finding", "Status", "Title", ...SNOWFLAKE_FRAMEWORKS], rows)].join("\n");
}

function buildExecutiveSummary(config: SnowflakeResolvedConfig, access: SnowflakeAccessCheckResult, assessments: SnowflakeAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = summarizeStatuses(findings);
  return [
    "# Snowflake Security Inspector Executive Summary",
    "",
    `Account: ${access.account}`,
    `Authenticated as: ${access.user} (role ${access.role ?? "default"}, ${config.tokenType})`,
    `Generated: ${new Date().toISOString()}`,
    `Access check: ${access.status}${access.fullVisibility ? "" : " (partial visibility: role lacks MANAGE GRANTS)"}`,
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
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function severityRank(severity: SnowflakeSeverity): number {
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

function buildQuickReference(result: { outputDir: string }, assessments: SnowflakeAssessmentResult[], errorCount: number): string {
  return [
    "# Snowflake Evidence Bundle Quick Reference",
    "",
    `Bundle directory: ${basename(result.outputDir)}`,
    "",
    "## Contents",
    "",
    "- `core_data/*.json`: raw result sets for every SHOW command and ACCOUNT_USAGE query (statement, columns, rows, partition metadata)",
    "- `analysis/findings.json`: all normalized findings with framework mappings",
    "- `analysis/<area>.json`: per-assessment summaries and findings",
    "- `compliance/executive_summary.md`: prioritized readout",
    "- `compliance/unified_compliance_matrix.md`: one row per finding across every framework",
    "- `compliance/<framework>.md`: framework-specific mapping reports",
    "- `core_data/access_check.json`: readable surface inventory",
    "- `metadata.json`: non-secret run metadata",
    errorCount > 0 ? "- `_errors.log`: statements that were denied, failed, or timed out during collection" : "- `_errors.log`: not written because every statement completed",
    "",
    "## Assessments",
    "",
    ...assessments.map((assessment) => `- ${assessment.title}: ${assessment.findings.length} findings (${JSON.stringify(summarizeStatuses(assessment.findings))})`),
    "",
    "Credentials, tokens, and private keys are never written into the bundle.",
  ].join("\n");
}

export async function exportSnowflakeAuditBundle(
  client: SnowflakeQueryClient,
  config: SnowflakeResolvedConfig,
  outputRoot: string,
  options: SnowflakeAssessmentOptions = {},
): Promise<SnowflakeAuditBundleResult> {
  const access = await checkSnowflakeAccess(client);
  const assessments = [
    await assessSnowflakeNetworkAndAuthentication(client, options),
    await assessSnowflakeAccessControl(client, options),
    await assessSnowflakeMonitoringAndLifecycle(client, options),
    await assessSnowflakeDataProtection(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const statements = assessments.flatMap((assessment) => assessment.statements);
  const failedStatements = statements.filter((statement) => statement.status !== "ok");

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, `${safeDirName(access.account || config.account)}-audit-bundle`);

  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    account: access.account,
    user: access.user,
    role: access.role ?? null,
    token_type: config.tokenType,
    base_url: config.baseUrl,
    source_chain: config.sourceChain,
    statement_count: statements.length,
    failed_statement_count: failedStatements.length,
  }));
  await writeSecureTextFile(outputDir, "core_data/access_check.json", serializeJson(access));
  const seenKeys = new Set<string>();
  for (const assessment of assessments) {
    for (const statement of assessment.statements) {
      const fileKey = seenKeys.has(statement.key) ? `${assessment.area}-${statement.key}` : statement.key;
      seenKeys.add(statement.key);
      await writeSecureTextFile(outputDir, `core_data/${safeDirName(fileKey)}.json`, serializeJson(statement));
    }
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.json`, serializeJson({ title: assessment.title, summary: assessment.summary, findings: assessment.findings }));
    await writeSecureTextFile(outputDir, `analysis/${assessment.area}.md`, `${formatAssessmentText(assessment)}\n`);
  }
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, access, assessments)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of SNOWFLAKE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${safeDirName(framework)}.md`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference({ outputDir }, assessments, failedStatements.length)}\n`);
  if (failedStatements.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${failedStatements.map((statement) => `[${statement.status}] ${statement.key}: ${statement.error ?? "no detail"}\n  ${statement.statement}`).join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: failedStatements.length,
  };
}

function normalizeCommonArgs(args: unknown): CommonArgs {
  const value = asObject(args) ?? {};
  return {
    account: asString(value.account),
    user: asString(value.user),
    private_key_path: asString(value.private_key_path),
    private_key: asString(value.private_key),
    private_key_passphrase: asString(value.private_key_passphrase),
    token: asString(value.token),
    token_type: asString(value.token_type),
    role: asString(value.role),
    warehouse: asString(value.warehouse),
    database: asString(value.database),
    schema: asString(value.schema),
    base_url: asString(value.base_url),
    connection: asString(value.connection),
    timeout_seconds: asNumber(value.timeout_seconds),
    statement_timeout_seconds: asNumber(value.statement_timeout_seconds),
    row_limit: asNumber(value.row_limit),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCommonArgs(args),
    lookback_days: asNumber(value.lookback_days),
    stale_user_days: asNumber(value.stale_user_days),
    failed_login_threshold: asNumber(value.failed_login_threshold),
    max_accountadmins: asNumber(value.max_accountadmins),
    max_auto_suspend_seconds: asNumber(value.max_auto_suspend_seconds),
    max_session_idle_minutes: asNumber(value.max_session_idle_minutes),
    min_password_length: asNumber(value.min_password_length),
    min_retention_days: asNumber(value.min_retention_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function toAssessmentOptions(args: AssessArgs): SnowflakeAssessmentOptions {
  return {
    lookbackDays: args.lookback_days,
    staleUserDays: args.stale_user_days,
    failedLoginThreshold: args.failed_login_threshold,
    maxAccountAdmins: args.max_accountadmins,
    maxAutoSuspendSeconds: args.max_auto_suspend_seconds,
    maxSessionIdleMinutes: args.max_session_idle_minutes,
    minPasswordLength: args.min_password_length,
    minRetentionDays: args.min_retention_days,
  };
}

function createClient(args: CommonArgs): SnowflakeSqlClient {
  return new SnowflakeSqlClient(resolveSnowflakeConfiguration(args as JsonRecord));
}

const authParams = {
  account: Type.Optional(Type.String({ description: "Snowflake account identifier (orgname-accountname or legacy locator). Defaults to SNOWFLAKE_ACCOUNT or the connections.toml entry." })),
  user: Type.Optional(Type.String({ description: "Snowflake user name. Defaults to SNOWFLAKE_USER or the connections.toml entry." })),
  private_key_path: Type.Optional(Type.String({ description: "Path to the RSA private key (PKCS#8 PEM) for key-pair JWT auth. Defaults to SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY_FILE." })),
  private_key: Type.Optional(Type.String({ description: "Inline RSA private key PEM. Defaults to SNOWFLAKE_PRIVATE_KEY or SNOWFLAKE_PRIVATE_KEY_RAW." })),
  private_key_passphrase: Type.Optional(Type.String({ description: "Passphrase for an encrypted private key. Defaults to SNOWFLAKE_PRIVATE_KEY_PASSPHRASE or PRIVATE_KEY_PASSPHRASE." })),
  token: Type.Optional(Type.String({ description: "OAuth access token or programmatic access token. Defaults to SNOWFLAKE_TOKEN." })),
  token_type: Type.Optional(Type.String({ description: "Bearer token type: OAUTH (default for tokens), PROGRAMMATIC_ACCESS_TOKEN, or KEYPAIR_JWT. Defaults to SNOWFLAKE_TOKEN_TYPE or SNOWFLAKE_AUTHENTICATOR." })),
  role: Type.Optional(Type.String({ description: "Role for the statements (read-only audit role, SECURITYADMIN, or ACCOUNTADMIN). Defaults to SNOWFLAKE_ROLE." })),
  warehouse: Type.Optional(Type.String({ description: "Warehouse for ACCOUNT_USAGE queries (X-Small recommended). Defaults to SNOWFLAKE_WAREHOUSE." })),
  database: Type.Optional(Type.String({ description: "Optional session database. Defaults to SNOWFLAKE_DATABASE." })),
  schema: Type.Optional(Type.String({ description: "Optional session schema. Defaults to SNOWFLAKE_SCHEMA." })),
  base_url: Type.Optional(Type.String({ description: "Override the SQL API base URL (for example a PrivateLink host). Defaults to https://<account>.snowflakecomputing.com." })),
  connection: Type.Optional(Type.String({ description: "Connection name in ~/.snowflake/connections.toml or config.toml. Defaults to SNOWFLAKE_CONNECTION_NAME, default_connection_name, or 'default'." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout per request in seconds. Defaults to 30.", default: 30 })),
  statement_timeout_seconds: Type.Optional(Type.Number({ description: "Server-side statement timeout in seconds. Defaults to 120.", default: 120 })),
  row_limit: Type.Optional(Type.Number({ description: "Row limit for ACCOUNT_USAGE inventory queries; hitting it flags a partial result. Defaults to 20000.", default: 20000 })),
};

const thresholdParams = {
  lookback_days: Type.Optional(Type.Number({ description: "History window in days for LOGIN_HISTORY and QUERY_HISTORY. Defaults to 30.", default: 30 })),
  stale_user_days: Type.Optional(Type.Number({ description: "Days since last login before a user is stale. Defaults to 90.", default: 90 })),
  failed_login_threshold: Type.Optional(Type.Number({ description: "Failed logins per user/IP that trigger a failure. Defaults to 10.", default: 10 })),
  max_accountadmins: Type.Optional(Type.Number({ description: "Maximum acceptable ACCOUNTADMIN members. Defaults to 3.", default: 3 })),
  max_auto_suspend_seconds: Type.Optional(Type.Number({ description: "Maximum acceptable warehouse auto_suspend in seconds. Defaults to 600.", default: 600 })),
  max_session_idle_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable session idle timeout in minutes. Defaults to 60.", default: 60 })),
  min_password_length: Type.Optional(Type.Number({ description: "Minimum password length expected from the account password policy. Defaults to 14.", default: 14 })),
  min_retention_days: Type.Optional(Type.Number({ description: "Minimum Time Travel retention in days. Defaults to 1.", default: 1 })),
};

function registerAssessTool(
  pi: any,
  name: string,
  label: string,
  description: string,
  assess: (client: SnowflakeSqlClient, options: SnowflakeAssessmentOptions) => Promise<SnowflakeAssessmentResult>,
): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object({ ...authParams, ...thresholdParams }),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await assess(createClient(args), toAssessmentOptions(args));
        return textResult(formatAssessmentText(result), { tool: name, ...result });
      } catch (error) {
        return errorResult(`${label} failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: name });
      }
    },
  });
}

export function registerSnowflakeTools(pi: any): void {
  pi.registerTool({
    name: "snowflake_check_access",
    label: "Check Snowflake audit access",
    description:
      "Validate read-only Snowflake SQL API access (key-pair JWT or OAuth) across SHOW NETWORK POLICIES, SHOW PARAMETERS, SHOW INTEGRATIONS, SHOW WAREHOUSES, SHOW DATABASES, SHOW SHARES, SHOW REPLICATION GROUPS, and the ACCOUNT_USAGE views used by the assessments, reporting denied surfaces and partial visibility.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCommonArgs,
    async execute(_toolCallId: string, args: CommonArgs) {
      try {
        const result = await checkSnowflakeAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "snowflake_check_access", ...result });
      } catch (error) {
        return errorResult(`Snowflake access check failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: "snowflake_check_access" });
      }
    },
  });

  registerAssessTool(
    pi,
    "snowflake_assess_network_and_authentication",
    "Assess Snowflake network and authentication",
    "Assess spec controls 1-6 and 25: network policy activation, IP allowlist restrictiveness, MFA for person users, account password policy, key-pair auth for service users, SAML2/SCIM integrations, and account session policies. Statements that fail or return partial inventories yield manual or warn verdicts, never pass.",
    assessSnowflakeNetworkAndAuthentication,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_access_control",
    "Assess Snowflake access control",
    "Assess spec controls 7-10 and 16: role hierarchy least privilege, ACCOUNTADMIN membership, ACCOUNTADMIN routine query usage, direct grants to users, and PUBLIC grants on data objects, using GRANTS_TO_ROLES, GRANTS_TO_USERS, and QUERY_HISTORY.",
    assessSnowflakeAccessControl,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_monitoring_and_lifecycle",
    "Assess Snowflake monitoring and lifecycle",
    "Assess spec controls 11-13 and 24: failed login monitoring from LOGIN_HISTORY, stale person users (NULL last login is reported separately and never counted as active), data retention parameter plus ACCESS_HISTORY readability, and warehouse auto-suspend.",
    assessSnowflakeMonitoringAndLifecycle,
  );
  registerAssessTool(
    pi,
    "snowflake_assess_data_protection",
    "Assess Snowflake data protection",
    "Assess spec controls 14-15 and 17-23: masking and row access policy assignment, storage integration and unload parameters, Time Travel retention, Tri-Secret Secure and customer-managed keys (manual evidence), outbound shares and listings, and API or external access integrations.",
    assessSnowflakeDataProtection,
  );

  pi.registerTool({
    name: "snowflake_export_audit_bundle",
    label: "Export Snowflake audit bundle",
    description:
      "Export a Snowflake evidence bundle with raw result sets (core_data), normalized findings and per-area analysis, compliance reports for FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP, a QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a paired zip archive that never overwrites a prior bundle.",
    parameters: Type.Object({
      ...authParams,
      ...thresholdParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveSnowflakeConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSnowflakeAuditBundle(new SnowflakeSqlClient(config), config, outputRoot, toAssessmentOptions(args));
        return textResult(
          [
            "Snowflake audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Statements with errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "snowflake_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(`Snowflake audit bundle export failed: ${redactSecrets(error instanceof Error ? error.message : String(error))}`, { tool: "snowflake_export_audit_bundle" });
      }
    },
  });
}
