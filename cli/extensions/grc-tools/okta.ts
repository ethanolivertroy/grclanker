/**
 * Okta GRC assessment tools.
 *
 * Native TypeScript implementation that borrows assessment intent from the
 * older okta-inspector project while staying aligned with the official
 * okta-cli-client configuration model and Okta Management API coverage.
 */
import { createHash, createPrivateKey, randomUUID, sign as signData } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readFile, readdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { parse as parseYaml } from "yaml";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type OktaAuthMode = "SSWS" | "PrivateKey";
type OktaFindingStatus = "Pass" | "Partial" | "Fail" | "Manual" | "Info";
type OktaSeverity = "critical" | "high" | "medium" | "low" | "info";
type FrameworkKey =
  | "fedramp"
  | "disa_stig"
  | "irap"
  | "ismap"
  | "soc2"
  | "pci_dss"
  | "general";

const DEFAULT_OUTPUT_DIR = "./export/okta";
const PAGE_LIMIT = 200;
const LOOKBACK_DAYS = 30;
const TOKEN_SKEW_MS = 60 * 1000;
const DEFAULT_RATE_LIMIT_RETRIES = 4;
const DAYS_90_MS = 90 * 24 * 60 * 60 * 1000;
const DEFAULT_OKTA_READ_SCOPES = [
  "okta.users.read",
  "okta.groups.read",
  "okta.apps.read",
  "okta.authenticators.read",
  "okta.authorizationServers.read",
  "okta.idps.read",
  "okta.trustedOrigins.read",
  "okta.policies.read",
  "okta.logs.read",
  "okta.eventHooks.read",
  "okta.logStreams.read",
  "okta.orgs.read",
  "okta.networkZones.read",
  "okta.behaviors.read",
  "okta.deviceAssurance.read",
  "okta.roles.read",
  "okta.apiTokens.read",
  "okta.threatInsights.read",
];
const OKTA_AUTH_PROBE_PATHS = [
  { key: "users", path: "/api/v1/users?limit=1" },
  { key: "policies", path: "/api/v1/policies?type=OKTA_SIGN_ON&limit=1" },
  { key: "logs", path: "/api/v1/logs?limit=1" },
  { key: "roles", path: "/api/v1/iam/assignees/users?limit=1" },
  { key: "api_tokens", path: "/api/v1/api-tokens?limit=1" },
];
const ADMIN_GROUP_NAME_PATTERN = /(admin|administrator|privileged|help.?desk|security|access)/i;
const STRONG_AUTHENTICATOR_PATTERN = /(okta_verify|fastpass|webauthn|fido2|smart[_ -]?card|certificate|piv|cac)/i;
const CERTIFICATE_PATTERN = /(smart[_ -]?card|certificate|piv|cac|x509)/i;

type RawConfigArgs = {
  org_url?: string;
  config_file?: string;
  auth_mode?: string;
  api_token?: string;
  client_id?: string;
  private_key?: string;
  private_key_id?: string;
  client_assertion?: string;
  scopes?: string[];
};

type CheckAccessArgs = RawConfigArgs;

type AssessmentArgs = RawConfigArgs;

type ExportArgs = RawConfigArgs & {
  output_dir?: string;
};

type OktaConfigOverlay = {
  orgUrl?: string;
  authMode?: OktaAuthMode;
  token?: string;
  clientId?: string;
  privateKey?: string;
  privateKeyId?: string;
  clientAssertion?: string;
  scopes?: string[];
};

export interface OktaResolvedConfig {
  orgUrl: string;
  authMode: OktaAuthMode;
  token?: string;
  clientId?: string;
  privateKey?: string;
  privateKeyId?: string;
  clientAssertion?: string;
  scopes: string[];
  sourceChain: string[];
}

type OktaEndpointStatus = "ok" | "forbidden" | "unauthorized" | "error";

export interface OktaAccessProbe {
  key: string;
  path: string;
  status: OktaEndpointStatus;
  detail: string;
}

export interface OktaAccessCheckResult {
  organization: string;
  authMode: OktaAuthMode;
  sourceChain: string[];
  status: "healthy" | "limited";
  probes: OktaAccessProbe[];
  recommendedNextStep: string;
  notes: string[];
}

interface FrameworkMap {
  fedramp: string[];
  disa_stig: string[];
  irap: string[];
  ismap: string[];
  soc2: string[];
  pci_dss: string[];
  general: string[];
}

interface CheckDefinition {
  id: string;
  title: string;
  category: "authentication" | "admin_access" | "integrations" | "monitoring";
  severity: OktaSeverity;
  frameworks: FrameworkMap;
}

export interface OktaFinding {
  id: string;
  title: string;
  category: CheckDefinition["category"];
  status: OktaFindingStatus;
  severity: OktaSeverity;
  summary: string;
  evidence: string[];
  recommendation: string;
  manualNote?: string;
  frameworks: FrameworkMap;
}

export interface OktaAssessmentResult {
  category: CheckDefinition["category"];
  findings: OktaFinding[];
  summary: Record<OktaFindingStatus, number>;
  text: string;
  snapshotSummary: Record<string, number | string>;
}

interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
}

interface OktaAuthenticationData {
  signOnPolicies: CollectedDataset<JsonRecord[]>;
  signOnPolicyRules: CollectedDataset<Record<string, JsonRecord[]>>;
  passwordPolicies: CollectedDataset<JsonRecord[]>;
  passwordPolicyRules: CollectedDataset<Record<string, JsonRecord[]>>;
  mfaPolicies: CollectedDataset<JsonRecord[]>;
  accessPolicies: CollectedDataset<JsonRecord[]>;
  accessPolicyRules: CollectedDataset<Record<string, JsonRecord[]>>;
  authenticators: CollectedDataset<JsonRecord[]>;
  idps: CollectedDataset<JsonRecord[]>;
  authorizationServers: CollectedDataset<JsonRecord[]>;
  defaultAuthorizationServer: CollectedDataset<JsonRecord | null>;
  orgFactors: CollectedDataset<JsonRecord[]>;
}

interface OktaAdminAccessData {
  usersWithRoleAssignments: CollectedDataset<JsonRecord[]>;
  userRoles: CollectedDataset<Record<string, JsonRecord[]>>;
  groups: CollectedDataset<JsonRecord[]>;
  privilegedGroups: CollectedDataset<JsonRecord[]>;
  privilegedGroupRoles: CollectedDataset<Record<string, JsonRecord[]>>;
  privilegedGroupMembers: CollectedDataset<Record<string, JsonRecord[]>>;
}

interface OktaIntegrationData {
  apps: CollectedDataset<JsonRecord[]>;
  trustedOrigins: CollectedDataset<JsonRecord[]>;
  networkZones: CollectedDataset<JsonRecord[]>;
  accessPolicies: CollectedDataset<JsonRecord[]>;
  accessPolicyRules: CollectedDataset<Record<string, JsonRecord[]>>;
  signOnPolicies: CollectedDataset<JsonRecord[]>;
  signOnPolicyRules: CollectedDataset<Record<string, JsonRecord[]>>;
  idps: CollectedDataset<JsonRecord[]>;
  authorizationServers: CollectedDataset<JsonRecord[]>;
}

interface OktaMonitoringData {
  eventHooks: CollectedDataset<JsonRecord[]>;
  logStreams: CollectedDataset<JsonRecord[]>;
  systemLogs: CollectedDataset<JsonRecord[]>;
  behaviors: CollectedDataset<JsonRecord[]>;
  threatInsight: CollectedDataset<JsonRecord | null>;
  apiTokens: CollectedDataset<JsonRecord[]>;
  deviceAssurance: CollectedDataset<JsonRecord[]>;
}

interface OktaAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type FetchImpl = typeof fetch;

type OktaTokenCacheEntry = {
  token?: string;
  expiresAt?: number;
  pending?: Promise<string>;
};

const tokenCache = new Map<string, OktaTokenCacheEntry>();

const OKTA_CHECKS: Record<string, CheckDefinition> = {
  "OKTA-AUTH-001": {
    id: "OKTA-AUTH-001",
    title: "Phishing-resistant authenticators",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2(11)"],
      disa_stig: ["V-273190", "V-273191"],
      irap: ["ISM-0974"],
      ismap: ["A.9.4.2"],
      soc2: ["CC6.1"],
      pci_dss: ["8.2.1"],
      general: ["phishing-resistant MFA"],
    },
  },
  "OKTA-AUTH-002": {
    id: "OKTA-AUTH-002",
    title: "Administrator MFA enforcement",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-2(1)"],
      disa_stig: ["V-273193", "V-273194"],
      irap: ["ISM-0974"],
      ismap: ["A.9.4.2"],
      soc2: ["CC6.1"],
      pci_dss: ["8.3.1"],
      general: ["admin MFA"],
    },
  },
  "OKTA-AUTH-003": {
    id: "OKTA-AUTH-003",
    title: "Password complexity",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-5"],
      disa_stig: ["V-273195", "V-273196", "V-273197", "V-273198", "V-273199"],
      irap: ["ISM-0421"],
      ismap: ["A.9.2.4"],
      soc2: [],
      pci_dss: ["8.3.6"],
      general: ["password complexity"],
    },
  },
  "OKTA-AUTH-004": {
    id: "OKTA-AUTH-004",
    title: "Password aging and history",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-5"],
      disa_stig: ["V-273200", "V-273201", "V-273209"],
      irap: ["ISM-0421"],
      ismap: ["A.9.4.3"],
      soc2: [],
      pci_dss: ["8.3.9"],
      general: ["password rotation"],
    },
  },
  "OKTA-AUTH-005": {
    id: "OKTA-AUTH-005",
    title: "Password lockout threshold",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-7"],
      disa_stig: ["V-273189"],
      irap: ["ISM-1173"],
      ismap: ["A.9.4.3"],
      soc2: [],
      pci_dss: ["8.2.6"],
      general: ["lockout policy"],
    },
  },
  "OKTA-AUTH-006": {
    id: "OKTA-AUTH-006",
    title: "Session idle timeout",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-11"],
      disa_stig: ["V-273186", "V-273187"],
      irap: ["ISM-1546"],
      ismap: ["A.9.4.2"],
      soc2: ["CC6.6"],
      pci_dss: ["8.2.8"],
      general: ["session idle timeout"],
    },
  },
  "OKTA-AUTH-007": {
    id: "OKTA-AUTH-007",
    title: "Session lifetime and persistent cookie controls",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-12"],
      disa_stig: ["V-273203", "V-273206"],
      irap: ["ISM-1546"],
      ismap: ["A.9.4.2"],
      soc2: ["CC6.6"],
      pci_dss: [],
      general: ["session lifetime"],
    },
  },
  "OKTA-AUTH-008": {
    id: "OKTA-AUTH-008",
    title: "Certificate or PIV/CAC authentication",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-5(2)"],
      disa_stig: ["V-273204", "V-273207"],
      irap: ["ISM-0974"],
      ismap: ["A.9.4.2"],
      soc2: [],
      pci_dss: [],
      general: ["certificate authentication"],
    },
  },
  "OKTA-ADMIN-001": {
    id: "OKTA-ADMIN-001",
    title: "Super admin assignments are constrained",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6"],
      disa_stig: [],
      irap: ["ISM-1175"],
      ismap: ["A.9.2.2"],
      soc2: ["CC6.3"],
      pci_dss: ["7.2.1"],
      general: ["least privilege"],
    },
  },
  "OKTA-ADMIN-002": {
    id: "OKTA-ADMIN-002",
    title: "Inactive privileged accounts",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-2", "AC-2(3)"],
      disa_stig: ["V-273188"],
      irap: ["ISM-1175"],
      ismap: ["A.9.2.1"],
      soc2: ["CC6.2"],
      pci_dss: [],
      general: ["inactive accounts"],
    },
  },
  "OKTA-ADMIN-003": {
    id: "OKTA-ADMIN-003",
    title: "Privileged group assignments are bounded",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-6"],
      disa_stig: [],
      irap: ["ISM-1175"],
      ismap: ["A.9.2.2"],
      soc2: ["CC6.3"],
      pci_dss: ["7.2.1"],
      general: ["privileged groups"],
    },
  },
  "OKTA-INTEG-001": {
    id: "OKTA-INTEG-001",
    title: "Trusted origins hygiene",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-3", "SC-7"],
      disa_stig: [],
      irap: [],
      ismap: ["A.13.1.1"],
      soc2: ["CC6.6"],
      pci_dss: [],
      general: ["trusted origins"],
    },
  },
  "OKTA-INTEG-002": {
    id: "OKTA-INTEG-002",
    title: "Network zones are configured",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-17", "AC-19"],
      disa_stig: [],
      irap: [],
      ismap: ["A.13.1.1"],
      soc2: ["CC6.6"],
      pci_dss: [],
      general: ["network zones"],
    },
  },
  "OKTA-INTEG-003": {
    id: "OKTA-INTEG-003",
    title: "OIDC application grant hygiene",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-3"],
      disa_stig: [],
      irap: [],
      ismap: ["A.9.1.2"],
      soc2: ["CC6.1"],
      pci_dss: ["7.2.1"],
      general: ["oauth grants"],
    },
  },
  "OKTA-INTEG-004": {
    id: "OKTA-INTEG-004",
    title: "Risk-based and contextual access controls",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2(12)"],
      disa_stig: [],
      irap: ["ISM-0974"],
      ismap: ["A.9.2.2"],
      soc2: ["CC6.8"],
      pci_dss: [],
      general: ["risk-based access"],
    },
  },
  "OKTA-INTEG-005": {
    id: "OKTA-INTEG-005",
    title: "Application inventory hygiene",
    category: "integrations",
    severity: "low",
    frameworks: {
      fedramp: ["CM-8"],
      disa_stig: [],
      irap: [],
      ismap: ["A.8.1.1"],
      soc2: ["CC2.1"],
      pci_dss: [],
      general: ["application inventory"],
    },
  },
  "OKTA-MON-001": {
    id: "OKTA-MON-001",
    title: "Log offloading and external monitoring",
    category: "monitoring",
    severity: "high",
    frameworks: {
      fedramp: ["AU-4", "AU-6"],
      disa_stig: ["V-273202"],
      irap: ["ISM-0407"],
      ismap: ["A.12.4.1"],
      soc2: [],
      pci_dss: [],
      general: ["log offloading"],
    },
  },
  "OKTA-MON-002": {
    id: "OKTA-MON-002",
    title: "System log visibility",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-3"],
      disa_stig: [],
      irap: ["ISM-0407"],
      ismap: ["A.12.4.1"],
      soc2: [],
      pci_dss: [],
      general: ["audit trail"],
    },
  },
  "OKTA-MON-003": {
    id: "OKTA-MON-003",
    title: "ThreatInsight posture",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["SI-4"],
      disa_stig: [],
      irap: ["ISM-0974"],
      ismap: ["A.12.6.1"],
      soc2: ["CC7.2"],
      pci_dss: [],
      general: ["threat detection"],
    },
  },
  "OKTA-MON-004": {
    id: "OKTA-MON-004",
    title: "Behavior detection coverage",
    category: "monitoring",
    severity: "low",
    frameworks: {
      fedramp: ["SI-4"],
      disa_stig: [],
      irap: ["ISM-0974"],
      ismap: ["A.12.6.1"],
      soc2: ["CC7.2"],
      pci_dss: [],
      general: ["behavior detection"],
    },
  },
  "OKTA-MON-005": {
    id: "OKTA-MON-005",
    title: "API token hygiene",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-5", "AU-6"],
      disa_stig: [],
      irap: [],
      ismap: ["A.9.2.4"],
      soc2: ["CC6.2"],
      pci_dss: ["8.2.7"],
      general: ["token management"],
    },
  },
  "OKTA-MON-006": {
    id: "OKTA-MON-006",
    title: "Device assurance policy coverage",
    category: "monitoring",
    severity: "low",
    frameworks: {
      fedramp: ["CM-7"],
      disa_stig: [],
      irap: [],
      ismap: ["A.12.6.2"],
      soc2: ["CC6.7"],
      pci_dss: [],
      general: ["device assurance"],
    },
  },
};

export function clearOktaTokenCacheForTests(): void {
  tokenCache.clear();
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function normalizeStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((entry) => asString(entry))
      .filter((entry): entry is string => Boolean(entry));
  }

  const raw = asString(value);
  if (!raw) return [];
  return raw
    .split(/[,\n ]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeOrgUrl(value: string): string {
  const trimmed = value.trim();
  const raw = trimmed.startsWith("http://") || trimmed.startsWith("https://")
    ? trimmed
    : `https://${trimmed}`;
  const url = new URL(raw);
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function daysAgoIso(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function parseLinkHeaderNext(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/i);
  return match?.[1] ?? null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodePemEscapes(value: string): string {
  return value.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

function buildTokenCacheKey(config: OktaResolvedConfig): string {
  return createHash("sha256")
    .update(config.orgUrl)
    .update("\0")
    .update(config.authMode)
    .update("\0")
    .update(config.clientId ?? "")
    .update("\0")
    .update((config.scopes ?? []).join(" "))
    .digest("hex");
}

function buildClientAssertion(config: OktaResolvedConfig): string {
  if (config.clientAssertion) return config.clientAssertion;
  if (!config.clientId || !config.privateKey) {
    throw new Error(
      "Okta PrivateKey auth requires client_id plus either private_key or client_assertion.",
    );
  }

  const privateKey = createPrivateKey(decodePemEscapes(config.privateKey));
  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new Error(
      "Okta PrivateKey auth currently supports RSA private keys directly. For other key types, pass client_assertion explicitly.",
    );
  }

  const header: JsonRecord = {
    alg: "RS256",
    typ: "JWT",
  };
  if (config.privateKeyId) {
    header.kid = config.privateKeyId;
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: `${config.orgUrl}/oauth2/v1/token`,
    iss: config.clientId,
    sub: config.clientId,
    exp: now + 300,
    iat: now,
    jti: randomUUID(),
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signData("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

function normalizeAuthMode(value: string | undefined): OktaAuthMode | undefined {
  if (!value) return undefined;
  if (value.toLowerCase() === "ssws") return "SSWS";
  if (value.toLowerCase() === "privatekey") return "PrivateKey";
  return undefined;
}

function applyOverlay(base: OktaConfigOverlay, overlay: OktaConfigOverlay | undefined): OktaConfigOverlay {
  if (!overlay) return base;
  return {
    orgUrl: overlay.orgUrl ?? base.orgUrl,
    authMode: overlay.authMode ?? base.authMode,
    token: overlay.token ?? base.token,
    clientId: overlay.clientId ?? base.clientId,
    privateKey: overlay.privateKey ?? base.privateKey,
    privateKeyId: overlay.privateKeyId ?? base.privateKeyId,
    clientAssertion: overlay.clientAssertion ?? base.clientAssertion,
    scopes: overlay.scopes && overlay.scopes.length > 0 ? overlay.scopes : base.scopes,
  };
}

function overlayFromArgs(args: RawConfigArgs): OktaConfigOverlay {
  return {
    orgUrl: asString(args.org_url),
    authMode: normalizeAuthMode(asString(args.auth_mode)),
    token: asString(args.api_token),
    clientId: asString(args.client_id),
    privateKey: asString(args.private_key),
    privateKeyId: asString(args.private_key_id),
    clientAssertion: asString(args.client_assertion),
    scopes: normalizeStringArray(args.scopes),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): OktaConfigOverlay {
  return {
    orgUrl: asString(env.OKTA_CLIENT_ORGURL),
    authMode: normalizeAuthMode(asString(env.OKTA_CLIENT_AUTHORIZATIONMODE)),
    token: asString(env.OKTA_CLIENT_TOKEN),
    clientId: asString(env.OKTA_CLIENT_CLIENTID),
    privateKey: asString(env.OKTA_CLIENT_PRIVATEKEY),
    privateKeyId: asString(env.OKTA_CLIENT_PRIVATEKEYID),
    clientAssertion: asString(env.OKTA_CLIENT_CLIENTASSERTION),
    scopes: normalizeStringArray(env.OKTA_CLIENT_SCOPES),
  };
}

async function readOktaYamlOverlay(location: string): Promise<OktaConfigOverlay | undefined> {
  if (!existsSync(location)) return undefined;
  const raw = await readFile(location, "utf8");
  const parsed = parseYaml(raw) as JsonRecord;
  const client = asRecord(asRecord(parsed.okta).client);
  return {
    orgUrl: asString(client.orgUrl),
    authMode: normalizeAuthMode(asString(client.authorizationMode)),
    token: asString(client.token),
    clientId: asString(client.clientId),
    privateKey: asString(client.privateKey),
    privateKeyId: asString(client.privateKeyId),
    clientAssertion: asString(client.clientAssertion),
    scopes: normalizeStringArray(client.scopes),
  };
}

function hasExplicitArgs(args: RawConfigArgs): boolean {
  return Boolean(
    args.org_url ||
      args.config_file ||
      args.auth_mode ||
      args.api_token ||
      args.client_id ||
      args.private_key ||
      args.private_key_id ||
      args.client_assertion ||
      (args.scopes && args.scopes.length > 0),
  );
}

export async function resolveOktaConfiguration(
  args: RawConfigArgs = {},
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
  homeDir: string = homedir(),
): Promise<OktaResolvedConfig> {
  let merged: OktaConfigOverlay = {
    authMode: "SSWS",
    scopes: [],
  };
  const sourceChain: string[] = [];

  const homeConfigPath = join(homeDir, ".okta", "okta.yaml");
  const projectConfigPath = resolve(cwd, ".okta.yaml");

  if (args.config_file) {
    const explicitPath = resolve(cwd, args.config_file);
    const explicitOverlay = await readOktaYamlOverlay(explicitPath);
    if (explicitOverlay) {
      merged = applyOverlay(merged, explicitOverlay);
      sourceChain.push(`config:${relative(cwd, explicitPath) || explicitPath}`);
    }
  } else {
    const homeOverlay = await readOktaYamlOverlay(homeConfigPath);
    if (homeOverlay) {
      merged = applyOverlay(merged, homeOverlay);
      sourceChain.push("home:.okta/okta.yaml");
    }
    const projectOverlay = await readOktaYamlOverlay(projectConfigPath);
    if (projectOverlay) {
      merged = applyOverlay(merged, projectOverlay);
      sourceChain.push("project:.okta.yaml");
    }
  }

  const envOverlay = overlayFromEnv(env);
  if (
    envOverlay.orgUrl ||
    envOverlay.authMode ||
    envOverlay.token ||
    envOverlay.clientId ||
    envOverlay.privateKey ||
    envOverlay.privateKeyId ||
    envOverlay.clientAssertion ||
    (envOverlay.scopes && envOverlay.scopes.length > 0)
  ) {
    merged = applyOverlay(merged, envOverlay);
    sourceChain.push("environment");
  }

  if (hasExplicitArgs(args)) {
    merged = applyOverlay(merged, overlayFromArgs(args));
    sourceChain.push("arguments");
  }

  if (!merged.orgUrl) {
    throw new Error(
      "Okta org URL is required. Set OKTA_CLIENT_ORGURL, configure .okta.yaml, or pass org_url explicitly.",
    );
  }

  const authMode = merged.authMode ?? "SSWS";
  const scopes = merged.scopes && merged.scopes.length > 0 ? merged.scopes : DEFAULT_OKTA_READ_SCOPES;
  const config: OktaResolvedConfig = {
    orgUrl: normalizeOrgUrl(merged.orgUrl),
    authMode,
    token: merged.token,
    clientId: merged.clientId,
    privateKey: merged.privateKey,
    privateKeyId: merged.privateKeyId,
    clientAssertion: merged.clientAssertion,
    scopes,
    sourceChain: sourceChain.length > 0 ? sourceChain : ["defaults"],
  };

  if (config.authMode === "SSWS" && !config.token) {
    throw new Error(
      "Okta SSWS auth requires an API token. Set OKTA_CLIENT_TOKEN, configure token in .okta.yaml, or pass api_token explicitly.",
    );
  }

  if (config.authMode === "PrivateKey") {
    if (!config.clientId) {
      throw new Error(
        "Okta PrivateKey auth requires client_id. Set OKTA_CLIENT_CLIENTID, configure clientId in .okta.yaml, or pass client_id explicitly.",
      );
    }
    if (!config.privateKey && !config.clientAssertion) {
      throw new Error(
        "Okta PrivateKey auth requires private_key or client_assertion. Set OKTA_CLIENT_PRIVATEKEY, configure privateKey in .okta.yaml, or pass private_key explicitly.",
      );
    }
  }

  return config;
}

function normalizeAssessmentArgs(args: unknown): AssessmentArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      org_url: asString(value.org_url) ?? asString(value.orgUrl),
      config_file: asString(value.config_file) ?? asString(value.configFile),
      auth_mode: asString(value.auth_mode) ?? asString(value.authMode),
      api_token: asString(value.api_token) ?? asString(value.apiToken),
      client_id: asString(value.client_id) ?? asString(value.clientId),
      private_key: asString(value.private_key) ?? asString(value.privateKey),
      private_key_id: asString(value.private_key_id) ?? asString(value.privateKeyId),
      client_assertion: asString(value.client_assertion) ?? asString(value.clientAssertion),
      scopes: normalizeStringArray(value.scopes),
    };
  }

  return {};
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const base = normalizeAssessmentArgs(args);
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      ...base,
      output_dir: asString(value.output_dir) ?? asString(value.outputDir),
    };
  }
  return base;
}

function makeUrl(config: OktaResolvedConfig, pathOrUrl: string): string {
  if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")) {
    return pathOrUrl;
  }
  return `${config.orgUrl}${pathOrUrl}`;
}

async function readErrorDetail(response: Response): Promise<string> {
  const text = await response.text();
  if (!text) return "";
  try {
    const parsed = JSON.parse(text) as JsonRecord;
    const errors = asArray(parsed.errorCauses).map((entry) => asRecord(entry));
    const summaries = errors.map((entry) => asString(entry.errorSummary)).filter(Boolean);
    const detail =
      asString(parsed.error_description) ??
      asString(parsed.errorSummary) ??
      (summaries.length > 0 ? summaries.join("; ") : undefined);
    return detail ?? text;
  } catch {
    return text;
  }
}

function retryDelayFromResponse(response: Response): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, 15_000);
    }
  }

  const reset = response.headers.get("x-rate-limit-reset");
  if (reset) {
    const epochSeconds = Number(reset);
    if (Number.isFinite(epochSeconds)) {
      const delta = epochSeconds * 1000 - Date.now();
      return Math.min(Math.max(delta, 250), 15_000);
    }
  }

  return 1000;
}

export class OktaAuditorClient {
  private readonly config: OktaResolvedConfig;
  private readonly fetchImpl: FetchImpl;

  constructor(config: OktaResolvedConfig, options?: { fetchImpl?: FetchImpl }) {
    this.config = config;
    this.fetchImpl = options?.fetchImpl ?? fetch;
  }

  private async getAccessToken(): Promise<string> {
    if (this.config.authMode !== "PrivateKey") {
      throw new Error("Bearer access tokens are only used for PrivateKey mode.");
    }

    const cacheKey = buildTokenCacheKey(this.config);
    const entry = tokenCache.get(cacheKey) ?? {};
    if (entry.token && entry.expiresAt && Date.now() + TOKEN_SKEW_MS < entry.expiresAt) {
      return entry.token;
    }
    if (entry.pending) {
      return entry.pending;
    }

    const pending = (async () => {
      const clientAssertion = buildClientAssertion(this.config);
      const body = new URLSearchParams({
        grant_type: "client_credentials",
        scope: this.config.scopes.join(" "),
        client_id: this.config.clientId ?? "",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: clientAssertion,
      });

      const response = await this.fetchImpl(`${this.config.orgUrl}/oauth2/v1/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: body.toString(),
      });

      if (!response.ok) {
        const detail = await readErrorDetail(response);
        throw new Error(
          `Okta OAuth token request failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
        );
      }

      const payload = (await response.json()) as JsonRecord;
      const accessToken = asString(payload.access_token);
      if (!accessToken) {
        throw new Error("Okta OAuth token response did not include access_token.");
      }

      const expiresIn = asNumber(payload.expires_in) ?? 3600;
      tokenCache.set(cacheKey, {
        token: accessToken,
        expiresAt: Date.now() + expiresIn * 1000,
      });
      return accessToken;
    })();

    tokenCache.set(cacheKey, { ...entry, pending });

    try {
      const token = await pending;
      return token;
    } finally {
      const latest = tokenCache.get(cacheKey) ?? {};
      delete latest.pending;
      tokenCache.set(cacheKey, latest);
    }
  }

  private async authHeader(): Promise<string> {
    if (this.config.authMode === "SSWS") {
      return `SSWS ${this.config.token ?? ""}`;
    }
    const token = await this.getAccessToken();
    return `Bearer ${token}`;
  }

  private async request(
    pathOrUrl: string,
    init: RequestInit = {},
    attempt = 0,
  ): Promise<Response> {
    const headers = new Headers(init.headers ?? {});
    headers.set("accept", "application/json");
    if (!headers.has("authorization")) {
      headers.set("authorization", await this.authHeader());
    }

    const response = await this.fetchImpl(makeUrl(this.config, pathOrUrl), {
      ...init,
      headers,
    });

    if (response.status === 429 && attempt < DEFAULT_RATE_LIMIT_RETRIES) {
      await delay(retryDelayFromResponse(response));
      return this.request(pathOrUrl, init, attempt + 1);
    }

    if (response.status === 401 && this.config.authMode === "PrivateKey" && attempt < 1) {
      const cacheKey = buildTokenCacheKey(this.config);
      tokenCache.delete(cacheKey);
      return this.request(pathOrUrl, init, attempt + 1);
    }

    if (!response.ok) {
      const detail = await readErrorDetail(response);
      throw new Error(
        `Okta API request failed for ${pathOrUrl} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
      );
    }

    return response;
  }

  async getJson<T>(pathOrUrl: string): Promise<T> {
    const response = await this.request(pathOrUrl);
    return (await response.json()) as T;
  }

  async tryGetJson<T>(pathOrUrl: string): Promise<T | null> {
    try {
      return await this.getJson<T>(pathOrUrl);
    } catch (error) {
      if (error instanceof Error && /\(404 /.test(error.message)) {
        return null;
      }
      throw error;
    }
  }

  async listPaginated(pathOrUrl: string): Promise<JsonRecord[]> {
    const results: JsonRecord[] = [];
    let nextUrl: string | null = pathOrUrl;

    while (nextUrl) {
      const response = await this.request(nextUrl);
      const payload = (await response.json()) as unknown;
      if (Array.isArray(payload)) {
        results.push(...payload.map((entry) => asRecord(entry)));
      } else {
        throw new Error(`Expected array response from ${pathOrUrl}`);
      }
      nextUrl = parseLinkHeaderNext(response.headers.get("link"));
    }

    return results;
  }

  async listPolicies(type: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/policies?type=${encodeURIComponent(type)}&limit=${PAGE_LIMIT}`);
  }

  async listPolicyRules(policyId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/policies/${encodeURIComponent(policyId)}/rules?limit=${PAGE_LIMIT}`);
  }

  async listAuthenticators(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/authenticators?limit=${PAGE_LIMIT}`);
  }

  async listUsers(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/users?limit=${PAGE_LIMIT}`);
  }

  async listGroups(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/groups?limit=${PAGE_LIMIT}`);
  }

  async listGroupUsers(groupId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/groups/${encodeURIComponent(groupId)}/users?limit=${PAGE_LIMIT}`);
  }

  async listGroupRoles(groupId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/groups/${encodeURIComponent(groupId)}/roles?limit=${PAGE_LIMIT}`);
  }

  async listApps(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/apps?limit=${PAGE_LIMIT}`);
  }

  async listIdps(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/idps?limit=${PAGE_LIMIT}`);
  }

  async listTrustedOrigins(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/trustedOrigins?limit=${PAGE_LIMIT}`);
  }

  async listNetworkZones(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/zones?limit=${PAGE_LIMIT}`);
  }

  async listAuthorizationServers(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/authorizationServers?limit=${PAGE_LIMIT}`);
  }

  async getDefaultAuthorizationServer(): Promise<JsonRecord | null> {
    return this.tryGetJson<JsonRecord>("/api/v1/authorizationServers/default");
  }

  async listOrgFactors(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/org/factors?limit=${PAGE_LIMIT}`);
  }

  async listEventHooks(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/eventHooks?limit=${PAGE_LIMIT}`);
  }

  async listLogStreams(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/logStreams?limit=${PAGE_LIMIT}`);
  }

  async listSystemLogs(): Promise<JsonRecord[]> {
    const since = encodeURIComponent(daysAgoIso(LOOKBACK_DAYS));
    return this.listPaginated(`/api/v1/logs?since=${since}&limit=${PAGE_LIMIT}`);
  }

  async listBehaviors(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/behaviors?limit=${PAGE_LIMIT}`);
  }

  async getThreatInsight(): Promise<JsonRecord | null> {
    return this.tryGetJson<JsonRecord>("/api/v1/threats/configuration");
  }

  async listApiTokens(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/api-tokens?limit=${PAGE_LIMIT}`);
  }

  async listDeviceAssurancePolicies(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/device-assurances?limit=${PAGE_LIMIT}`);
  }

  async listUsersWithRoleAssignments(): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/iam/assignees/users?limit=${PAGE_LIMIT}`);
  }

  async listUserRoles(userId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/api/v1/users/${encodeURIComponent(userId)}/roles?limit=${PAGE_LIMIT}`);
  }
}

async function collectArrayDataset(
  fetcher: () => Promise<JsonRecord[]>,
): Promise<CollectedDataset<JsonRecord[]>> {
  try {
    const data = await fetcher();
    return { data };
  } catch (error) {
    return { data: [], error: error instanceof Error ? error.message : String(error) };
  }
}

async function collectObjectDataset<T>(
  fetcher: () => Promise<T>,
  fallback: T,
): Promise<CollectedDataset<T>> {
  try {
    const data = await fetcher();
    return { data };
  } catch (error) {
    return { data: fallback, error: error instanceof Error ? error.message : String(error) };
  }
}

async function collectPolicyRuleMap(
  client: Pick<OktaAuditorClient, "listPolicyRules">,
  policies: JsonRecord[],
): Promise<CollectedDataset<Record<string, JsonRecord[]>>> {
  const data: Record<string, JsonRecord[]> = {};
  const errors: string[] = [];

  for (const policy of policies) {
    const policyId = asString(policy.id);
    if (!policyId) continue;
    try {
      data[policyId] = await client.listPolicyRules(policyId);
    } catch (error) {
      errors.push(`${policyId}: ${error instanceof Error ? error.message : String(error)}`);
      data[policyId] = [];
    }
  }

  return {
    data,
    error: errors.length > 0 ? errors.join("; ") : undefined,
  };
}

export async function collectOktaAuthenticationData(
  client: Pick<
    OktaAuditorClient,
    | "listPolicies"
    | "listPolicyRules"
    | "listAuthenticators"
    | "listIdps"
    | "listAuthorizationServers"
    | "getDefaultAuthorizationServer"
    | "listOrgFactors"
  >,
): Promise<OktaAuthenticationData> {
  const signOnPolicies = await collectArrayDataset(() => client.listPolicies("OKTA_SIGN_ON"));
  const passwordPolicies = await collectArrayDataset(() => client.listPolicies("PASSWORD"));
  const mfaPolicies = await collectArrayDataset(() => client.listPolicies("MFA_ENROLL"));
  const accessPolicies = await collectArrayDataset(() => client.listPolicies("ACCESS_POLICY"));

  const signOnPolicyRules = await collectPolicyRuleMap(client, signOnPolicies.data);
  const passwordPolicyRules = await collectPolicyRuleMap(client, passwordPolicies.data);
  const accessPolicyRules = await collectPolicyRuleMap(client, accessPolicies.data);

  return {
    signOnPolicies,
    signOnPolicyRules,
    passwordPolicies,
    passwordPolicyRules,
    mfaPolicies,
    accessPolicies,
    accessPolicyRules,
    authenticators: await collectArrayDataset(() => client.listAuthenticators()),
    idps: await collectArrayDataset(() => client.listIdps()),
    authorizationServers: await collectArrayDataset(() => client.listAuthorizationServers()),
    defaultAuthorizationServer: await collectObjectDataset(
      () => client.getDefaultAuthorizationServer(),
      null,
    ),
    orgFactors: await collectArrayDataset(() => client.listOrgFactors()),
  };
}

export async function collectOktaAdminAccessData(
  client: Pick<
    OktaAuditorClient,
    "listUsersWithRoleAssignments" | "listUserRoles" | "listGroups" | "listGroupRoles" | "listGroupUsers"
  >,
): Promise<OktaAdminAccessData> {
  const usersWithRoleAssignments = await collectArrayDataset(() => client.listUsersWithRoleAssignments());
  const userRoles: Record<string, JsonRecord[]> = {};
  const userRoleErrors: string[] = [];

  for (const user of usersWithRoleAssignments.data) {
    const userId = asString(user.id);
    if (!userId) continue;
    try {
      userRoles[userId] = await client.listUserRoles(userId);
    } catch (error) {
      userRoleErrors.push(`${userId}: ${error instanceof Error ? error.message : String(error)}`);
      userRoles[userId] = [];
    }
  }

  const groups = await collectArrayDataset(() => client.listGroups());
  const privilegedGroups = groups.data.filter((group) =>
    ADMIN_GROUP_NAME_PATTERN.test(
      asString(asRecord(group.profile).name) ?? asString(group.name) ?? "",
    ),
  );

  const privilegedGroupRoles: Record<string, JsonRecord[]> = {};
  const privilegedGroupMembers: Record<string, JsonRecord[]> = {};
  const groupRoleErrors: string[] = [];
  const groupMemberErrors: string[] = [];

  for (const group of privilegedGroups.slice(0, 25)) {
    const groupId = asString(group.id);
    if (!groupId) continue;
    try {
      privilegedGroupRoles[groupId] = await client.listGroupRoles(groupId);
    } catch (error) {
      groupRoleErrors.push(`${groupId}: ${error instanceof Error ? error.message : String(error)}`);
      privilegedGroupRoles[groupId] = [];
    }
    try {
      privilegedGroupMembers[groupId] = await client.listGroupUsers(groupId);
    } catch (error) {
      groupMemberErrors.push(`${groupId}: ${error instanceof Error ? error.message : String(error)}`);
      privilegedGroupMembers[groupId] = [];
    }
  }

  return {
    usersWithRoleAssignments,
    userRoles: {
      data: userRoles,
      error: userRoleErrors.length > 0 ? userRoleErrors.join("; ") : undefined,
    },
    groups,
    privilegedGroups: { data: privilegedGroups },
    privilegedGroupRoles: {
      data: privilegedGroupRoles,
      error: groupRoleErrors.length > 0 ? groupRoleErrors.join("; ") : undefined,
    },
    privilegedGroupMembers: {
      data: privilegedGroupMembers,
      error: groupMemberErrors.length > 0 ? groupMemberErrors.join("; ") : undefined,
    },
  };
}

export async function collectOktaIntegrationData(
  client: Pick<
    OktaAuditorClient,
    | "listApps"
    | "listTrustedOrigins"
    | "listNetworkZones"
    | "listPolicies"
    | "listPolicyRules"
    | "listIdps"
    | "listAuthorizationServers"
  >,
): Promise<OktaIntegrationData> {
  const accessPolicies = await collectArrayDataset(() => client.listPolicies("ACCESS_POLICY"));
  const signOnPolicies = await collectArrayDataset(() => client.listPolicies("OKTA_SIGN_ON"));

  return {
    apps: await collectArrayDataset(() => client.listApps()),
    trustedOrigins: await collectArrayDataset(() => client.listTrustedOrigins()),
    networkZones: await collectArrayDataset(() => client.listNetworkZones()),
    accessPolicies,
    accessPolicyRules: await collectPolicyRuleMap(client, accessPolicies.data),
    signOnPolicies,
    signOnPolicyRules: await collectPolicyRuleMap(client, signOnPolicies.data),
    idps: await collectArrayDataset(() => client.listIdps()),
    authorizationServers: await collectArrayDataset(() => client.listAuthorizationServers()),
  };
}

export async function collectOktaMonitoringData(
  client: Pick<
    OktaAuditorClient,
    | "listEventHooks"
    | "listLogStreams"
    | "listSystemLogs"
    | "listBehaviors"
    | "getThreatInsight"
    | "listApiTokens"
    | "listDeviceAssurancePolicies"
  >,
): Promise<OktaMonitoringData> {
  return {
    eventHooks: await collectArrayDataset(() => client.listEventHooks()),
    logStreams: await collectArrayDataset(() => client.listLogStreams()),
    systemLogs: await collectArrayDataset(() => client.listSystemLogs()),
    behaviors: await collectArrayDataset(() => client.listBehaviors()),
    threatInsight: await collectObjectDataset(() => client.getThreatInsight(), null),
    apiTokens: await collectArrayDataset(() => client.listApiTokens()),
    deviceAssurance: await collectArrayDataset(() => client.listDeviceAssurancePolicies()),
  };
}

function buildFinding(
  id: keyof typeof OKTA_CHECKS,
  status: OktaFindingStatus,
  summary: string,
  evidence: string[],
  recommendation: string,
  options?: {
    severity?: OktaSeverity;
    manualNote?: string;
  },
): OktaFinding {
  const definition = OKTA_CHECKS[id];
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    status,
    severity: options?.severity ?? definition.severity,
    summary,
    evidence,
    recommendation,
    manualNote: options?.manualNote,
    frameworks: definition.frameworks,
  };
}

function summarizeFindings(findings: OktaFinding[]): Record<OktaFindingStatus, number> {
  return findings.reduce<Record<OktaFindingStatus, number>>(
    (summary, finding) => {
      summary[finding.status] += 1;
      return summary;
    },
    { Pass: 0, Partial: 0, Fail: 0, Manual: 0, Info: 0 },
  );
}

function buildAssessmentText(
  title: string,
  organization: string,
  findings: OktaFinding[],
  snapshotSummary: Record<string, number | string>,
): string {
  const summary = summarizeFindings(findings);
  const header = [
    `${title} for ${organization}`,
    `Pass: ${summary.Pass}  Partial: ${summary.Partial}  Fail: ${summary.Fail}  Manual: ${summary.Manual}  Info: ${summary.Info}`,
  ];

  const summaryLines = Object.entries(snapshotSummary).map(([key, value]) => {
    const label = key.replace(/_/g, " ");
    return `${label}: ${value}`;
  });

  const rows = findings.map((finding) => [
    finding.title,
    finding.status,
    finding.severity,
    finding.summary,
  ]);

  return [
    ...header,
    "",
    ...summaryLines,
    "",
    formatTable(["Check", "Status", "Severity", "Summary"], rows),
  ].join("\n");
}

function getRuleSet(ruleMap: Record<string, JsonRecord[]>, policies: JsonRecord[]): JsonRecord[] {
  return policies.flatMap((policy) => {
    const policyId = asString(policy.id);
    return policyId ? ruleMap[policyId] ?? [] : [];
  });
}

function getPolicyNames(policies: JsonRecord[]): string[] {
  return policies.map((policy) => asString(policy.name) ?? "").filter(Boolean);
}

function getSessionSignals(rules: JsonRecord[]): {
  idleTimeouts: number[];
  lifetimes: number[];
  persistentCookies: boolean[];
} {
  const idleTimeouts: number[] = [];
  const lifetimes: number[] = [];
  const persistentCookies: boolean[] = [];

  for (const rule of rules) {
    const session = asRecord(asRecord(asRecord(rule.actions).signon).session);
    const idle = asNumber(session.maxSessionIdleMinutes);
    const lifetime = asNumber(session.maxSessionLifetimeMinutes);
    const persistentCookie = session.usePersistentCookie;

    if (idle !== undefined) idleTimeouts.push(idle);
    if (lifetime !== undefined) lifetimes.push(lifetime);
    if (typeof persistentCookie === "boolean") persistentCookies.push(persistentCookie);
  }

  return { idleTimeouts, lifetimes, persistentCookies };
}

function analyzePasswordPolicies(policies: JsonRecord[]) {
  const details = policies.map((policy) => {
    const settings = asRecord(asRecord(policy.settings).password);
    const complexity = asRecord(settings.complexity);
    const age = asRecord(settings.age);
    const lockout = asRecord(settings.lockout);

    return {
      name: asString(policy.name) ?? asString(policy.id) ?? "Unnamed policy",
      minLength: asNumber(complexity.minLength) ?? 0,
      requireUppercase: Boolean(complexity.useUpperCase),
      requireLowercase: Boolean(complexity.useLowerCase),
      requireNumber: Boolean(complexity.useNumber),
      requireSymbol: Boolean(complexity.useSymbol),
      maxAge: asNumber(age.maxAgeDays) ?? 0,
      historyCount: asNumber(age.historyCount) ?? 0,
      maxAttempts: asNumber(lockout.maxAttempts) ?? 0,
    };
  });

  return details;
}

function appUsesRiskSignal(rule: JsonRecord): boolean {
  const conditions = asRecord(rule.conditions);
  return (
    Object.keys(asRecord(conditions.risk)).length > 0 ||
    Object.keys(asRecord(conditions.riskScore)).length > 0 ||
    Object.keys(asRecord(conditions.device)).length > 0 ||
    Object.keys(asRecord(conditions.authContext)).length > 0 ||
    Object.keys(asRecord(conditions.network)).length > 0
  );
}

function isActiveAuthenticator(auth: JsonRecord): boolean {
  return (asString(auth.status) ?? "").toUpperCase() === "ACTIVE";
}

function authenticatorLabel(auth: JsonRecord): string {
  return [
    asString(auth.key),
    asString(auth.name),
    asString(auth.type),
  ]
    .filter(Boolean)
    .join(" / ");
}

function roleName(role: JsonRecord): string {
  return (
    asString(role.label) ??
    asString(role.type) ??
    asString(role.name) ??
    asString(role.id) ??
    "UNKNOWN_ROLE"
  );
}

function isSuperAdmin(role: JsonRecord): boolean {
  return /super_admin/i.test(roleName(role));
}

function userLastLogin(user: JsonRecord): string | undefined {
  const profile = asRecord(user.profile);
  return asString(user.lastLogin) ?? asString(profile.lastLogin);
}

function daysSince(iso: string | undefined): number | null {
  if (!iso) return null;
  const timestamp = Date.parse(iso);
  if (Number.isNaN(timestamp)) return null;
  return Math.floor((Date.now() - timestamp) / (24 * 60 * 60 * 1000));
}

function listErrors(datasets: Array<CollectedDataset<unknown>>): string[] {
  return datasets.map((dataset) => dataset.error).filter((value): value is string => Boolean(value));
}

export function assessOktaAuthentication(
  data: OktaAuthenticationData,
  config: OktaResolvedConfig,
): OktaAssessmentResult {
  const findings: OktaFinding[] = [];
  const activeAuthenticators = data.authenticators.data.filter(isActiveAuthenticator);
  const strongAuthenticators = activeAuthenticators.filter((auth) =>
    STRONG_AUTHENTICATOR_PATTERN.test(authenticatorLabel(auth).toLowerCase()),
  );
  const certAuthenticators = activeAuthenticators.filter((auth) =>
    CERTIFICATE_PATTERN.test(authenticatorLabel(auth).toLowerCase()),
  );
  const certIdps = data.idps.data.filter((idp) =>
    CERTIFICATE_PATTERN.test(
      `${asString(idp.type) ?? ""} ${asString(idp.name) ?? ""}`.toLowerCase(),
    ),
  );
  const policyNames = [
    ...getPolicyNames(data.accessPolicies.data),
    ...getPolicyNames(data.signOnPolicies.data),
  ];
  const adminPolicyCount = policyNames.filter((name) => /admin console|dashboard/i.test(name)).length;

  if (strongAuthenticators.some((auth) => /webauthn|fido2|smart[_ -]?card|certificate|piv|cac/i.test(authenticatorLabel(auth).toLowerCase()))) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-001",
        "Pass",
        `${strongAuthenticators.length} strong authenticators are active.`,
        strongAuthenticators.map((auth) => `Active: ${authenticatorLabel(auth)}`),
        "Keep phishing-resistant authenticators enabled and verify enrollment policy coverage.",
      ),
    );
  } else if (strongAuthenticators.length > 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-001",
        "Partial",
        "Strong authenticators are present, but phishing-resistant coverage needs manual confirmation.",
        strongAuthenticators.map((auth) => `Active: ${authenticatorLabel(auth)}`),
        "Confirm whether the available authenticators satisfy phishing-resistant MFA requirements for the scoped environment.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "OKTA-AUTH-001",
        "Fail",
        "No active phishing-resistant authenticators were detected.",
        ["Active authenticators did not include WebAuthn, FIDO2, smart card, or certificate-based options."],
        "Enable phishing-resistant authenticators and align enrollment policy with the required assurance level.",
      ),
    );
  }

  if (adminPolicyCount > 0 && strongAuthenticators.length > 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-002",
        "Pass",
        `${adminPolicyCount} admin or dashboard policies were found alongside strong authenticators.`,
        policyNames
          .filter((name) => /admin console|dashboard/i.test(name))
          .map((name) => `Policy: ${name}`),
        "Verify the policy rules enforce MFA for all administrator entry points.",
        {
          manualNote:
            "Policy-name matching is automated, but individual rule enforcement should still be reviewed in the Okta console for final sign-off.",
        },
      ),
    );
  } else if (data.mfaPolicies.data.length > 0 || strongAuthenticators.length > 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-002",
        "Partial",
        "MFA-related controls exist, but explicit admin console policy coverage was not fully demonstrated.",
        [
          `MFA enrollment policies: ${data.mfaPolicies.data.length}`,
          `Strong authenticators: ${strongAuthenticators.length}`,
          `Admin/dashboard policies: ${adminPolicyCount}`,
        ],
        "Add or verify explicit Okta Admin Console and Dashboard policies that require MFA.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "OKTA-AUTH-002",
        "Fail",
        "No clear evidence of administrator MFA enforcement was found.",
        [
          `MFA enrollment policies: ${data.mfaPolicies.data.length}`,
          `Admin/dashboard policies: ${adminPolicyCount}`,
        ],
        "Configure explicit MFA enforcement for administrator and dashboard access paths.",
      ),
    );
  }

  const passwordPolicies = analyzePasswordPolicies(data.passwordPolicies.data);
  if (passwordPolicies.length === 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-003",
        "Fail",
        "No password policies were returned.",
        ["Password policy data was unavailable or empty."],
        "Configure and verify password policies before relying on Okta for regulated authentication flows.",
      ),
    );
    findings.push(
      buildFinding(
        "OKTA-AUTH-004",
        "Fail",
        "No password policy age or history controls were returned.",
        ["Password policy data was unavailable or empty."],
        "Configure password age and history settings in Okta password policies.",
      ),
    );
    findings.push(
      buildFinding(
        "OKTA-AUTH-005",
        "Fail",
        "No password lockout controls were returned.",
        ["Password policy data was unavailable or empty."],
        "Configure account lockout thresholds in Okta password policies.",
      ),
    );
  } else {
    const complexityPass = passwordPolicies.filter(
      (policy) =>
        policy.minLength >= 12 &&
        policy.requireUppercase &&
        policy.requireLowercase &&
        policy.requireNumber &&
        policy.requireSymbol,
    );
    const complexityStatus: OktaFindingStatus =
      complexityPass.length === passwordPolicies.length
        ? "Pass"
        : complexityPass.length > 0
          ? "Partial"
          : "Fail";
    findings.push(
      buildFinding(
        "OKTA-AUTH-003",
        complexityStatus,
        `${complexityPass.length} of ${passwordPolicies.length} password policies meet the grclanker baseline.`,
        passwordPolicies.map(
          (policy) =>
            `${policy.name}: min=${policy.minLength}, upper=${policy.requireUppercase}, lower=${policy.requireLowercase}, number=${policy.requireNumber}, symbol=${policy.requireSymbol}`,
        ),
        "Raise minimum length and require mixed-case, numeric, and symbol complexity across all active password policies.",
      ),
    );

    const ageHistoryPass = passwordPolicies.filter(
      (policy) => policy.maxAge > 0 && policy.maxAge <= 90 && policy.historyCount >= 5,
    );
    const ageHistoryStatus: OktaFindingStatus =
      ageHistoryPass.length === passwordPolicies.length
        ? "Pass"
        : ageHistoryPass.length > 0
          ? "Partial"
          : "Fail";
    findings.push(
      buildFinding(
        "OKTA-AUTH-004",
        ageHistoryStatus,
        `${ageHistoryPass.length} of ${passwordPolicies.length} password policies meet age/history expectations.`,
        passwordPolicies.map(
          (policy) =>
            `${policy.name}: maxAge=${policy.maxAge || "unset"} days, history=${policy.historyCount}`,
        ),
        "Set password maximum age to 90 days or less where required and retain at least five previous passwords.",
      ),
    );

    const lockoutPass = passwordPolicies.filter(
      (policy) => policy.maxAttempts > 0 && policy.maxAttempts <= 6,
    );
    const lockoutStatus: OktaFindingStatus =
      lockoutPass.length === passwordPolicies.length
        ? "Pass"
        : lockoutPass.length > 0
          ? "Partial"
          : "Fail";
    findings.push(
      buildFinding(
        "OKTA-AUTH-005",
        lockoutStatus,
        `${lockoutPass.length} of ${passwordPolicies.length} password policies lock after six attempts or fewer.`,
        passwordPolicies.map(
          (policy) => `${policy.name}: maxAttempts=${policy.maxAttempts || "unset"}`,
        ),
        "Reduce password lockout thresholds to six attempts or fewer across active password policies.",
      ),
    );
  }

  const sessionRules = getRuleSet(data.signOnPolicyRules.data, data.signOnPolicies.data);
  const sessionSignals = getSessionSignals(sessionRules);
  if (sessionSignals.idleTimeouts.length === 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-006",
        "Manual",
        "Session idle timeout values were not returned in the sign-on rule payloads.",
        ["Sign-on policy rules should be reviewed manually for idle timeout coverage."],
        "Verify maxSessionIdleMinutes values in sign-on rules for administrator-facing apps.",
      ),
    );
  } else {
    const badIdle = sessionSignals.idleTimeouts.filter((value) => value > 15);
    findings.push(
      buildFinding(
        "OKTA-AUTH-006",
        badIdle.length === 0 ? "Pass" : "Fail",
        badIdle.length === 0
          ? "All returned session idle timeouts are 15 minutes or less."
          : `${badIdle.length} session rules exceed the 15-minute idle timeout target.`,
        sessionSignals.idleTimeouts.map((value) => `Idle timeout: ${value} minutes`),
        "Reduce idle timeout values for administrator-facing sign-on rules to 15 minutes or less.",
      ),
    );
  }

  if (sessionSignals.lifetimes.length === 0 && sessionSignals.persistentCookies.length === 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-007",
        "Manual",
        "Session lifetime and persistent-cookie data were not returned in sign-on rules.",
        ["Sign-on rule session settings require manual validation."],
        "Review maxSessionLifetimeMinutes and usePersistentCookie settings in sign-on rules.",
      ),
    );
  } else {
    const badLifetime = sessionSignals.lifetimes.filter((value) => value > 1080);
    const persistentCookies = sessionSignals.persistentCookies.filter(Boolean);
    const status: OktaFindingStatus =
      badLifetime.length === 0 && persistentCookies.length === 0 ? "Pass" : "Fail";
    findings.push(
      buildFinding(
        "OKTA-AUTH-007",
        status,
        status === "Pass"
          ? "No session lifetime or persistent-cookie violations were detected."
          : "Some session rules exceed the 18-hour lifetime target or allow persistent cookies.",
        [
          ...sessionSignals.lifetimes.map((value) => `Lifetime: ${value} minutes`),
          ...sessionSignals.persistentCookies.map((value) => `Persistent cookie enabled: ${value}`),
        ],
        "Reduce maximum session lifetime to 18 hours or less and disable persistent cookies for sensitive sessions.",
      ),
    );
  }

  const isFederalTenant = /\.(okta\.gov|okta\.mil)$/i.test(new URL(config.orgUrl).hostname);
  if (certIdps.length > 0 || certAuthenticators.length > 0) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-008",
        "Pass",
        `Detected ${certIdps.length + certAuthenticators.length} certificate-oriented IdP or authenticator entries.`,
        [
          ...certIdps.map((idp) => `IdP: ${asString(idp.name) ?? asString(idp.id) ?? "unnamed"}`),
          ...certAuthenticators.map((auth) => `Authenticator: ${authenticatorLabel(auth)}`),
        ],
        "Keep certificate-based and smart-card options documented for scoped federal or DoD use cases.",
      ),
    );
  } else if (isFederalTenant) {
    findings.push(
      buildFinding(
        "OKTA-AUTH-008",
        "Fail",
        "No certificate-oriented authentication method was detected for a federal-domain tenant.",
        [`Org URL: ${config.orgUrl}`],
        "Validate whether PIV/CAC or certificate-based authentication is required for this tenant and configure it if so.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "OKTA-AUTH-008",
        "Manual",
        "No certificate-oriented authentication method was detected.",
        [`Org URL: ${config.orgUrl}`],
        "If this Okta tenant supports federal or smart-card requirements, verify whether certificate-based authentication should be added.",
      ),
    );
  }

  const snapshotSummary = {
    active_authenticators: activeAuthenticators.length,
    strong_authenticators: strongAuthenticators.length,
    password_policies: passwordPolicies.length,
    sign_on_policies: data.signOnPolicies.data.length,
    access_policies: data.accessPolicies.data.length,
    admin_dashboard_policies: adminPolicyCount,
    dataset_errors: listErrors([
      data.signOnPolicies,
      data.signOnPolicyRules,
      data.passwordPolicies,
      data.passwordPolicyRules,
      data.mfaPolicies,
      data.accessPolicies,
      data.accessPolicyRules,
      data.authenticators,
      data.idps,
      data.authorizationServers,
      data.defaultAuthorizationServer,
      data.orgFactors,
    ]).length,
  };

  return {
    category: "authentication",
    findings,
    summary: summarizeFindings(findings),
    text: buildAssessmentText(
      "Okta authentication assessment",
      new URL(config.orgUrl).hostname,
      findings,
      snapshotSummary,
    ),
    snapshotSummary,
  };
}

export function assessOktaAdminAccess(
  data: OktaAdminAccessData,
  config: OktaResolvedConfig,
): OktaAssessmentResult {
  const findings: OktaFinding[] = [];
  const privilegedUsers = data.usersWithRoleAssignments.data.map((user) => {
    const userId = asString(user.id) ?? "";
    const roles = data.userRoles.data[userId] ?? [];
    return {
      user,
      roles,
      roleNames: roles.map(roleName),
    };
  });
  const superAdmins = privilegedUsers.filter((entry) => entry.roles.some(isSuperAdmin));
  const stalePrivileged = privilegedUsers.filter((entry) => {
    const lastLoginDays = daysSince(userLastLogin(entry.user));
    const status = (asString(entry.user.status) ?? "").toUpperCase();
    return (lastLoginDays !== null && lastLoginDays > 90) || (status !== "" && status !== "ACTIVE");
  });

  const superAdminStatus: OktaFindingStatus =
    superAdmins.length <= 2 ? "Pass" : superAdmins.length <= 5 ? "Partial" : "Fail";
  findings.push(
    buildFinding(
      "OKTA-ADMIN-001",
      superAdminStatus,
      `${superAdmins.length} users hold SUPER_ADMIN.`,
      superAdmins.length > 0
        ? superAdmins.map((entry) => {
            const login =
              asString(asRecord(entry.user.profile).login) ??
              asString(entry.user.login) ??
              asString(entry.user.id) ??
              "unknown";
            return `${login}: ${entry.roleNames.join(", ")}`;
          })
        : ["No SUPER_ADMIN assignments were returned."],
      "Keep SUPER_ADMIN assignments tightly bounded and prefer scoped custom or standard roles for day-to-day administration.",
    ),
  );

  findings.push(
    buildFinding(
      "OKTA-ADMIN-002",
      stalePrivileged.length === 0 ? "Pass" : "Fail",
      stalePrivileged.length === 0
        ? "No stale or non-active privileged accounts were detected."
        : `${stalePrivileged.length} privileged accounts are stale or non-active.`,
      stalePrivileged.map((entry) => {
        const login =
          asString(asRecord(entry.user.profile).login) ??
          asString(entry.user.id) ??
          "unknown";
        return `${login}: status=${asString(entry.user.status) ?? "unknown"}, lastLogin=${userLastLogin(entry.user) ?? "never"}`;
      }),
      "Review privileged accounts that are suspended, deprovisioned, or inactive for more than 90 days and remove unnecessary access.",
    ),
  );

  const privilegedGroups = data.privilegedGroups.data.map((group) => {
    const groupId = asString(group.id) ?? "";
    const name = asString(asRecord(group.profile).name) ?? asString(group.name) ?? groupId;
    const roleCount = (data.privilegedGroupRoles.data[groupId] ?? []).length;
    const memberCount = (data.privilegedGroupMembers.data[groupId] ?? []).length;
    return { groupId, name, roleCount, memberCount };
  });

  const oversizedPrivilegedGroups = privilegedGroups.filter(
    (group) => group.roleCount > 0 && group.memberCount > 25,
  );

  findings.push(
    buildFinding(
      "OKTA-ADMIN-003",
      privilegedGroups.length === 0
        ? "Manual"
        : oversizedPrivilegedGroups.length === 0
          ? "Pass"
          : "Partial",
      privilegedGroups.length === 0
        ? "No admin-like groups were detected automatically."
        : oversizedPrivilegedGroups.length === 0
          ? "Detected privileged groups without oversized membership."
          : `${oversizedPrivilegedGroups.length} privileged groups have more than 25 members.`,
      privilegedGroups.map(
        (group) =>
          `${group.name}: roles=${group.roleCount}, members=${group.memberCount}`,
      ),
      "Review privileged group scoping and membership size so elevated access remains traceable and bounded.",
      privilegedGroups.length === 0
        ? {
            manualNote:
              "Admin-like groups are discovered by name pattern, so tenant-specific naming conventions should still be reviewed manually.",
          }
        : undefined,
    ),
  );

  const snapshotSummary = {
    privileged_users: privilegedUsers.length,
    super_admins: superAdmins.length,
    stale_privileged_users: stalePrivileged.length,
    privileged_groups_reviewed: privilegedGroups.length,
    dataset_errors: listErrors([
      data.usersWithRoleAssignments,
      data.userRoles,
      data.groups,
      data.privilegedGroupRoles,
      data.privilegedGroupMembers,
    ]).length,
  };

  return {
    category: "admin_access",
    findings,
    summary: summarizeFindings(findings),
    text: buildAssessmentText(
      "Okta admin-access assessment",
      new URL(config.orgUrl).hostname,
      findings,
      snapshotSummary,
    ),
    snapshotSummary,
  };
}

export function assessOktaIntegrations(
  data: OktaIntegrationData,
  config: OktaResolvedConfig,
): OktaAssessmentResult {
  const findings: OktaFinding[] = [];
  const trustedOrigins = data.trustedOrigins.data.map((origin) => {
    const originUrl =
      asString(origin.origin) ??
      asString(origin.url) ??
      asString(asRecord(origin.originInfo).origin) ??
      "";
    return {
      raw: origin,
      origin: originUrl,
      insecure: originUrl.startsWith("http://") || originUrl.includes("*"),
    };
  });
  const insecureOrigins = trustedOrigins.filter((origin) => origin.insecure);

  findings.push(
    buildFinding(
      "OKTA-INTEG-001",
      insecureOrigins.length > 0
        ? "Fail"
        : trustedOrigins.length > 0
          ? "Pass"
          : "Info",
      insecureOrigins.length > 0
        ? `${insecureOrigins.length} trusted origins appear overly broad or insecure.`
        : trustedOrigins.length > 0
          ? "Trusted origins are present and none matched insecure URL heuristics."
          : "No trusted origins were returned.",
      trustedOrigins.length > 0
        ? trustedOrigins.map((origin) => origin.origin)
        : ["No trusted origin data was returned."],
      "Review trusted origins for HTTP entries, wildcards, and other unnecessary cross-origin exposure.",
    ),
  );

  const customZones = data.networkZones.data.filter(
    (zone) => !Boolean(zone.system) && !/legacyipzone/i.test(asString(zone.name) ?? ""),
  );
  findings.push(
    buildFinding(
      "OKTA-INTEG-002",
      customZones.length > 0 ? "Pass" : "Partial",
      customZones.length > 0
        ? `${customZones.length} custom network zones were returned.`
        : "Only the system or legacy network zone was detected.",
      data.networkZones.data.map(
        (zone) =>
          `${asString(zone.name) ?? asString(zone.id) ?? "unnamed"}: system=${Boolean(zone.system)}`,
      ),
      "Define and use custom network zones when policy conditions depend on trusted source networks.",
    ),
  );

  const riskyApps: string[] = [];
  const inactiveApps = data.apps.data.filter((app) => (asString(app.status) ?? "").toUpperCase() !== "ACTIVE");

  for (const app of data.apps.data) {
    const name = asString(app.label) ?? asString(app.name) ?? asString(app.id) ?? "unnamed app";
    const oauthClient = asRecord(asRecord(asRecord(app.settings).oauthClient));
    const grantTypes = normalizeStringArray(oauthClient.grant_types);
    if (grantTypes.includes("password") || grantTypes.includes("implicit")) {
      riskyApps.push(`${name}: ${grantTypes.join(", ")}`);
    }
  }

  findings.push(
    buildFinding(
      "OKTA-INTEG-003",
      riskyApps.length === 0 ? "Pass" : "Fail",
      riskyApps.length === 0
        ? "No OIDC apps using password or implicit grants were detected."
        : `${riskyApps.length} OIDC apps use password or implicit grants.`,
      riskyApps.length > 0 ? riskyApps : ["No risky grant types detected in the returned app inventory."],
      "Remove password and implicit grants from OIDC applications unless there is a documented exception with compensating controls.",
    ),
  );

  const signOnRules = getRuleSet(data.signOnPolicyRules.data, data.signOnPolicies.data);
  const accessRules = getRuleSet(data.accessPolicyRules.data, data.accessPolicies.data);
  const riskAwareRules = [...signOnRules, ...accessRules].filter(appUsesRiskSignal);
  findings.push(
    buildFinding(
      "OKTA-INTEG-004",
      riskAwareRules.length > 0 ? "Pass" : customZones.length > 0 ? "Partial" : "Fail",
      riskAwareRules.length > 0
        ? `${riskAwareRules.length} policy rules include contextual, device, network, or risk conditions.`
        : customZones.length > 0
          ? "Custom zones exist, but policy rules with contextual access signals were not clearly returned."
          : "No contextual access rules or custom zones were detected.",
      riskAwareRules.length > 0
        ? riskAwareRules.map((rule) => asString(rule.name) ?? asString(rule.id) ?? "unnamed rule")
        : ["No sign-on or access rules with risk, device, or network conditions were returned."],
      "Use contextual access rules that incorporate risk, device, or network conditions for higher assurance scenarios.",
    ),
  );

  findings.push(
    buildFinding(
      "OKTA-INTEG-005",
      inactiveApps.length === 0 ? "Pass" : "Partial",
      inactiveApps.length === 0
        ? "All returned applications were active."
        : `${inactiveApps.length} applications were not in ACTIVE status.`,
      inactiveApps.length > 0
        ? inactiveApps.map(
            (app) =>
              `${asString(app.label) ?? asString(app.name) ?? asString(app.id) ?? "unnamed app"}: ${asString(app.status) ?? "unknown"}`,
          )
        : ["No inactive or non-active applications detected."],
      "Review inactive or restricted applications and confirm whether they should remain configured in the tenant.",
      { severity: "low" },
    ),
  );

  const snapshotSummary = {
    applications: data.apps.data.length,
    risky_oidc_apps: riskyApps.length,
    trusted_origins: trustedOrigins.length,
    insecure_trusted_origins: insecureOrigins.length,
    custom_network_zones: customZones.length,
    contextual_rules: riskAwareRules.length,
    inactive_apps: inactiveApps.length,
    dataset_errors: listErrors([
      data.apps,
      data.trustedOrigins,
      data.networkZones,
      data.accessPolicies,
      data.accessPolicyRules,
      data.signOnPolicies,
      data.signOnPolicyRules,
      data.idps,
      data.authorizationServers,
    ]).length,
  };

  return {
    category: "integrations",
    findings,
    summary: summarizeFindings(findings),
    text: buildAssessmentText(
      "Okta integration assessment",
      new URL(config.orgUrl).hostname,
      findings,
      snapshotSummary,
    ),
    snapshotSummary,
  };
}

function threatInsightMode(threatInsight: JsonRecord | null): string {
  if (!threatInsight) return "unknown";
  return (
    asString(threatInsight.action) ??
    asString(threatInsight.mode) ??
    asString(asRecord(threatInsight.settings).action) ??
    "unknown"
  );
}

export function assessOktaMonitoring(
  data: OktaMonitoringData,
  config: OktaResolvedConfig,
): OktaAssessmentResult {
  const findings: OktaFinding[] = [];
  const activeHooks = data.eventHooks.data.filter((hook) => (asString(hook.status) ?? "").toUpperCase() === "ACTIVE");
  const activeStreams = data.logStreams.data.filter((stream) => (asString(stream.status) ?? "").toUpperCase() === "ACTIVE");

  findings.push(
    buildFinding(
      "OKTA-MON-001",
      activeStreams.length > 0 ? "Pass" : activeHooks.length > 0 ? "Partial" : "Fail",
      activeStreams.length > 0
        ? `${activeStreams.length} active log streams were detected.`
        : activeHooks.length > 0
          ? `${activeHooks.length} active event hooks were detected, but no active log streams were returned.`
          : "No active log streams or event hooks were detected.",
      [
        ...activeStreams.map(
          (stream) => `Log stream: ${asString(stream.name) ?? asString(stream.id) ?? "unnamed"}`,
        ),
        ...activeHooks.map(
          (hook) => `Event hook: ${asString(hook.name) ?? asString(hook.id) ?? "unnamed"}`,
        ),
      ],
      "Route Okta audit data to an external monitoring or SIEM destination with durable retention.",
    ),
  );

  findings.push(
    buildFinding(
      "OKTA-MON-002",
      data.systemLogs.data.length > 0 ? "Pass" : data.systemLogs.error ? "Fail" : "Partial",
      data.systemLogs.data.length > 0
        ? `Retrieved ${data.systemLogs.data.length} recent system log events.`
        : data.systemLogs.error
          ? "System log data could not be retrieved."
          : "System log access succeeded but no recent events were returned.",
      data.systemLogs.data.slice(0, 5).map((entry) => {
        const published = asString(entry.published) ?? "unknown";
        const eventType = asString(entry.eventType) ?? "unknown";
        return `${published}: ${eventType}`;
      }),
      "Ensure the System Log API remains readable and that audit records are retained or forwarded to a downstream store.",
    ),
  );

  const insightMode = threatInsightMode(data.threatInsight.data);
  const threatStatus: OktaFindingStatus =
    insightMode === "block" ? "Pass" : insightMode === "audit" || insightMode === "log_only" ? "Partial" : "Fail";
  findings.push(
    buildFinding(
      "OKTA-MON-003",
      threatStatus,
      `ThreatInsight mode: ${insightMode}.`,
      [JSON.stringify(data.threatInsight.data ?? {})],
      "Use Okta ThreatInsight in at least audit mode, and prefer block mode when the deployment model supports it.",
    ),
  );

  findings.push(
    buildFinding(
      "OKTA-MON-004",
      data.behaviors.data.length > 0 ? "Pass" : "Partial",
      data.behaviors.data.length > 0
        ? `${data.behaviors.data.length} behavior rules were returned.`
        : "No behavior rules were returned.",
      data.behaviors.data.map(
        (behavior) => asString(behavior.name) ?? asString(behavior.id) ?? "unnamed behavior",
      ),
      "Review behavior rules that support risk-based detection and signal generation for authentication monitoring.",
      { severity: "low" },
    ),
  );

  const staleTokens = data.apiTokens.data.filter((token) => {
    const referenceDate =
      asString(token.lastUpdated) ??
      asString(token.lastUsed) ??
      asString(token.created) ??
      undefined;
    if (!referenceDate) return false;
    const age = Date.now() - Date.parse(referenceDate);
    return Number.isFinite(age) && age > DAYS_90_MS;
  });
  findings.push(
    buildFinding(
      "OKTA-MON-005",
      data.apiTokens.error
        ? "Manual"
        : staleTokens.length === 0
          ? "Pass"
          : "Partial",
      data.apiTokens.error
        ? "API token metadata was not readable with the current credentials."
        : staleTokens.length === 0
          ? "No stale API tokens were detected from the returned token inventory."
          : `${staleTokens.length} API tokens appear older than 90 days based on returned metadata.`,
      data.apiTokens.data.map((token) => {
        const label =
          asString(token.name) ??
          asString(token.id) ??
          asString(token.tokenId) ??
          "unnamed token";
        const updated =
          asString(token.lastUpdated) ??
          asString(token.lastUsed) ??
          asString(token.created) ??
          "unknown";
        return `${label}: ${updated}`;
      }),
      "Rotate long-lived SSWS tokens and prefer OAuth service apps with scoped short-lived access tokens where possible.",
      data.apiTokens.error
        ? {
            manualNote:
              "Token inventory requires okta.apiTokens.read. If your audit principal cannot read token metadata, validate token hygiene manually.",
          }
        : undefined,
    ),
  );

  findings.push(
    buildFinding(
      "OKTA-MON-006",
      data.deviceAssurance.data.length > 0 ? "Pass" : "Partial",
      data.deviceAssurance.data.length > 0
        ? `${data.deviceAssurance.data.length} device assurance policies were returned.`
        : "No device assurance policies were returned.",
      data.deviceAssurance.data.map(
        (policy) => asString(policy.displayName) ?? asString(policy.id) ?? "unnamed policy",
      ),
      "Use device assurance policies when your access decisions should incorporate platform or management posture.",
      { severity: "low" },
    ),
  );

  const snapshotSummary = {
    active_event_hooks: activeHooks.length,
    active_log_streams: activeStreams.length,
    system_log_events: data.systemLogs.data.length,
    behaviors: data.behaviors.data.length,
    threat_insight_mode: insightMode,
    api_tokens: data.apiTokens.data.length,
    stale_api_tokens: staleTokens.length,
    device_assurance_policies: data.deviceAssurance.data.length,
    dataset_errors: listErrors([
      data.eventHooks,
      data.logStreams,
      data.systemLogs,
      data.behaviors,
      data.threatInsight,
      data.apiTokens,
      data.deviceAssurance,
    ]).length,
  };

  return {
    category: "monitoring",
    findings,
    summary: summarizeFindings(findings),
    text: buildAssessmentText(
      "Okta monitoring assessment",
      new URL(config.orgUrl).hostname,
      findings,
      snapshotSummary,
    ),
    snapshotSummary,
  };
}

function buildConfigNotes(config: OktaResolvedConfig): string[] {
  const notes = [
    `Auth mode: ${config.authMode}`,
    `Config precedence resolved from: ${config.sourceChain.join(" -> ")}`,
  ];
  if (config.authMode === "PrivateKey") {
    notes.push(`OAuth scopes: ${config.scopes.join(", ")}`);
  }
  return notes;
}

export async function runOktaAccessCheck(
  client: Pick<OktaAuditorClient, "getJson">,
  config: OktaResolvedConfig,
): Promise<OktaAccessCheckResult> {
  const probes: OktaAccessProbe[] = [];

  for (const probe of OKTA_AUTH_PROBE_PATHS) {
    try {
      await client.getJson<JsonRecord[] | JsonRecord>(probe.path);
      probes.push({
        key: probe.key,
        path: probe.path,
        status: "ok",
        detail: "readable",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      probes.push({
        key: probe.key,
        path: probe.path,
        status: /\(403 /.test(message)
          ? "forbidden"
          : /\(401 /.test(message)
            ? "unauthorized"
            : "error",
        detail: message,
      });
    }
  }

  const okay = probes.filter((probe) => probe.status === "ok").length;
  const status = okay >= 3 ? "healthy" : "limited";

  return {
    organization: new URL(config.orgUrl).hostname,
    authMode: config.authMode,
    sourceChain: config.sourceChain,
    status,
    probes,
    recommendedNextStep:
      status === "healthy"
        ? "Start with okta_assess_authentication, then run the admin, integration, or monitoring assessments as needed."
        : "Use the probe details to fill missing read scopes or switch to a broader read-only Okta audit principal before running the deeper assessments.",
    notes: buildConfigNotes(config),
  };
}

function serializeJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function markdownEscapePipes(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function renderFrameworkList(values: string[]): string {
  return values.length > 0 ? values.join(", ") : "N/A";
}

function frameworkMatrixRow(finding: OktaFinding): string {
  return [
    finding.title,
    renderFrameworkList(finding.frameworks.fedramp),
    renderFrameworkList(finding.frameworks.disa_stig),
    renderFrameworkList(finding.frameworks.irap),
    renderFrameworkList(finding.frameworks.ismap),
    renderFrameworkList(finding.frameworks.soc2),
    renderFrameworkList(finding.frameworks.pci_dss),
    finding.status,
  ]
    .map(markdownEscapePipes)
    .join(" | ");
}

function frameworkSummary(findings: OktaFinding[], key: FrameworkKey): OktaFinding[] {
  return findings.filter((finding) => finding.frameworks[key].length > 0);
}

function buildFrameworkReport(title: string, findings: OktaFinding[], key: FrameworkKey): string {
  const scopedFindings = frameworkSummary(findings, key);
  if (scopedFindings.length === 0) {
    return `# ${title}\n\nNo mapped findings were generated for this framework.\n`;
  }

  const lines = [
    `# ${title}`,
    "",
    "| Check | Status | Severity | Control Mapping | Summary |",
    "| --- | --- | --- | --- | --- |",
  ];

  for (const finding of scopedFindings) {
    lines.push(
      [
        finding.title,
        finding.status,
        finding.severity,
        renderFrameworkList(finding.frameworks[key]),
        finding.summary,
      ]
        .map(markdownEscapePipes)
        .join(" | "),
    );
  }

  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: OktaFinding[]): string {
  const lines = [
    "# Unified Compliance Matrix",
    "",
    "| Check | FedRAMP | STIG | IRAP | ISMAP | SOC2 | PCI-DSS | Status |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ];

  for (const finding of findings) {
    lines.push(frameworkMatrixRow(finding));
  }

  return `${lines.join("\n")}\n`;
}

function buildExecutiveSummary(
  config: OktaResolvedConfig,
  assessments: OktaAssessmentResult[],
  errors: string[],
): string {
  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  const summary = summarizeFindings(allFindings);
  const critical = allFindings.filter((finding) => finding.status === "Fail").slice(0, 6);

  const lines = [
    "# Executive Summary",
    "",
    `- Organization: ${new URL(config.orgUrl).hostname}`,
    `- Auth mode: ${config.authMode}`,
    `- Config source chain: ${config.sourceChain.join(" -> ")}`,
    `- Findings: Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}`,
    "",
    "## Highest Priority Findings",
  ];

  if (critical.length === 0) {
    lines.push("- No failing findings were generated in this assessment set.");
  } else {
    for (const finding of critical) {
      lines.push(`- ${finding.title}: ${finding.summary}`);
    }
  }

  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings");
    for (const error of errors) {
      lines.push(`- ${error}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

function buildQuickReference(): string {
  return [
    "# Okta Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw Okta API responses used during this assessment.",
    "- `analysis/` contains normalized findings and category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Review manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
  ].join("\n");
}

function safeDirName(input: string): string {
  return input
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "okta-audit";
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
    relativeTarget === ".." ||
    relativeTarget.startsWith(`..${join("/")}`) ||
    relativeTarget.startsWith("..")
  ) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
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
    const archive = archiver("zip", { zlib: { level: 9 } });

    output.on("close", () => resolvePromise());
    output.on("error", rejectPromise);
    archive.on("error", rejectPromise);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    void archive.finalize();
  });
}

export async function exportOktaAuditBundle(
  client: Pick<
    OktaAuditorClient,
    | "listPolicies"
    | "listPolicyRules"
    | "listAuthenticators"
    | "listIdps"
    | "listAuthorizationServers"
    | "getDefaultAuthorizationServer"
    | "listOrgFactors"
    | "listUsersWithRoleAssignments"
    | "listUserRoles"
    | "listGroups"
    | "listGroupRoles"
    | "listGroupUsers"
    | "listApps"
    | "listTrustedOrigins"
    | "listNetworkZones"
    | "listEventHooks"
    | "listLogStreams"
    | "listSystemLogs"
    | "listBehaviors"
    | "getThreatInsight"
    | "listApiTokens"
    | "listDeviceAssurancePolicies"
  >,
  config: OktaResolvedConfig,
  outputRoot: string,
): Promise<OktaAuditBundleResult> {
  const authentication = await collectOktaAuthenticationData(client);
  const adminAccess = await collectOktaAdminAccessData(client);
  const integrations = await collectOktaIntegrationData(client);
  const monitoring = await collectOktaMonitoringData(client);

  const assessments = [
    assessOktaAuthentication(authentication, config),
    assessOktaAdminAccess(adminAccess, config),
    assessOktaIntegrations(integrations, config),
    assessOktaMonitoring(monitoring, config),
  ];

  const errors = [
    ...listErrors(Object.values(authentication)),
    ...listErrors(Object.values(adminAccess)),
    ...listErrors(Object.values(integrations)),
    ...listErrors(Object.values(monitoring)),
  ];

  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    safeDirName(`${new URL(config.orgUrl).hostname}-audit-bundle`),
  );
  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/sign_on_policies.json", authentication.signOnPolicies.data],
    ["core_data/sign_on_policy_rules.json", authentication.signOnPolicyRules.data],
    ["core_data/password_policies.json", authentication.passwordPolicies.data],
    ["core_data/password_policy_rules.json", authentication.passwordPolicyRules.data],
    ["core_data/mfa_enrollment_policies.json", authentication.mfaPolicies.data],
    ["core_data/access_policies.json", authentication.accessPolicies.data],
    ["core_data/access_policy_rules.json", authentication.accessPolicyRules.data],
    ["core_data/authenticators.json", authentication.authenticators.data],
    ["core_data/idps.json", authentication.idps.data],
    ["core_data/authorization_servers.json", authentication.authorizationServers.data],
    ["core_data/default_authorization_server.json", authentication.defaultAuthorizationServer.data],
    ["core_data/org_factors.json", authentication.orgFactors.data],
    ["core_data/users_with_role_assignments.json", adminAccess.usersWithRoleAssignments.data],
    ["core_data/user_roles.json", adminAccess.userRoles.data],
    ["core_data/groups.json", adminAccess.groups.data],
    ["core_data/privileged_group_roles.json", adminAccess.privilegedGroupRoles.data],
    ["core_data/privileged_group_members.json", adminAccess.privilegedGroupMembers.data],
    ["core_data/apps.json", integrations.apps.data],
    ["core_data/trusted_origins.json", integrations.trustedOrigins.data],
    ["core_data/network_zones.json", integrations.networkZones.data],
    ["core_data/event_hooks.json", monitoring.eventHooks.data],
    ["core_data/log_streams.json", monitoring.logStreams.data],
    ["core_data/system_logs_recent.json", monitoring.systemLogs.data],
    ["core_data/behaviors.json", monitoring.behaviors.data],
    ["core_data/threat_insight.json", monitoring.threatInsight.data],
    ["core_data/api_tokens.json", monitoring.apiTokens.data],
    ["core_data/device_assurance.json", monitoring.deviceAssurance.data],
  ];

  for (const [pathName, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathName, serializeJson(value));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(
      outputDir,
      `analysis/${assessment.category}.json`,
      serializeJson(assessment),
    );
  }

  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(allFindings));
  await writeSecureTextFile(
    outputDir,
    "compliance/executive_summary.md",
    buildExecutiveSummary(config, assessments, errors),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/unified_compliance_matrix.md",
    buildUnifiedMatrix(allFindings),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/fedramp/fedramp_compliance_report.md",
    buildFrameworkReport("FedRAMP / NIST 800-53 Compliance Report", allFindings, "fedramp"),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/disa_stig/stig_compliance_checklist.md",
    buildFrameworkReport("DISA STIG Compliance Checklist", allFindings, "disa_stig"),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/irap/irap_compliance_report.md",
    buildFrameworkReport("IRAP / ISM Compliance Report", allFindings, "irap"),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/irap/essential_eight_assessment.md",
    "# Essential Eight Assessment\n\nThis bundle keeps the multi-framework report structure, but Essential Eight remains a manual follow-on using the generated evidence.\n",
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/ismap/ismap_compliance_report.md",
    buildFrameworkReport("ISMAP / ISO 27001 Compliance Report", allFindings, "ismap"),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/soc2/soc2_compliance_report.md",
    buildFrameworkReport("SOC 2 Compliance Report", allFindings, "soc2"),
  );
  await writeSecureTextFile(
    outputDir,
    "compliance/pci_dss/pci_dss_compliance_report.md",
    buildFrameworkReport("PCI-DSS Compliance Report", allFindings, "pci_dss"),
  );
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());

  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", errors.join("\n"));
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);

  const files = await readdir(outputDir, { recursive: true });
  return {
    outputDir,
    zipPath,
    fileCount: files.length,
    findingCount: allFindings.length,
    errorCount: errors.length,
  };
}

function probeTable(probes: OktaAccessProbe[]): string {
  return formatTable(
    ["Surface", "Status", "Detail"],
    probes.map((probe) => [probe.key, probe.status, probe.detail]),
  );
}

function renderAssessmentToolResult(result: OktaAssessmentResult) {
  return textResult(result.text, {
    category: result.category,
    findings: result.findings,
    summary: result.summary,
    snapshot: result.snapshotSummary,
  });
}

function renderAccessCheck(result: OktaAccessCheckResult) {
  return textResult(
    [
      `Okta access check for ${result.organization}`,
      `Status: ${result.status}`,
      "",
      ...result.notes,
      "",
      probeTable(result.probes),
      "",
      result.recommendedNextStep,
    ].join("\n"),
    {
      organization: result.organization,
      auth_mode: result.authMode,
      source_chain: result.sourceChain,
      probes: result.probes,
      status: result.status,
    },
  );
}

function buildExportText(config: OktaResolvedConfig, result: OktaAuditBundleResult): string {
  return [
    `Exported Okta audit bundle for ${new URL(config.orgUrl).hostname}.`,
    `Output directory: ${result.outputDir}`,
    `Zip archive: ${result.zipPath}`,
    `Files written: ${result.fileCount}`,
    `Findings recorded: ${result.findingCount}`,
    `Collection warnings: ${result.errorCount}`,
  ].join("\n");
}

export function registerOktaTools(pi: any): void {
  const authParams = {
    org_url: Type.Optional(
      Type.String({
        description:
          "Optional Okta org URL or hostname. Falls back to Okta CLI-style config discovery from .okta.yaml, ~/.okta/okta.yaml, and environment variables.",
      }),
    ),
    config_file: Type.Optional(
      Type.String({
        description: "Optional path to an Okta YAML config file to use instead of the default discovery locations.",
      }),
    ),
    auth_mode: Type.Optional(
      Type.String({
        description: "Optional auth mode override. Supported: SSWS or PrivateKey.",
      }),
    ),
    api_token: Type.Optional(
      Type.String({
        description:
          "Optional Okta SSWS API token. Prefer OKTA_CLIENT_TOKEN or .okta.yaml when possible.",
      }),
    ),
    client_id: Type.Optional(
      Type.String({
        description:
          "Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode.",
      }),
    ),
    private_key: Type.Optional(
      Type.String({
        description:
          "Optional PEM private key for PrivateKey auth mode. Prefer OKTA_CLIENT_PRIVATEKEY or .okta.yaml when possible.",
      }),
    ),
    private_key_id: Type.Optional(
      Type.String({
        description: "Optional JWK key ID (kid) for the service-app private key.",
      }),
    ),
    client_assertion: Type.Optional(
      Type.String({
        description:
          "Optional prebuilt JWT client assertion. Use this if you do not want grclanker to sign the PrivateKey JWT for you.",
      }),
    ),
    scopes: Type.Optional(
      Type.Array(
        Type.String({
          description: "Optional Okta OAuth read scopes to request in PrivateKey mode.",
        }),
      ),
    ),
  } as const;

  pi.registerTool({
    name: "okta_check_access",
    label: "Check Okta audit access",
    description:
      "Validate Okta Management API access for a read-only audit principal and report which core GRC surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const result = await runOktaAccessCheck(client, config);
        return renderAccessCheck(result);
      } catch (error) {
        return errorResult(
          `Okta access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "okta_assess_authentication",
    label: "Assess Okta authentication posture",
    description:
      "Evaluate phishing-resistant MFA, password policies, session controls, and certificate-authentication readiness in Okta.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const data = await collectOktaAuthenticationData(client);
        return renderAssessmentToolResult(assessOktaAuthentication(data, config));
      } catch (error) {
        return errorResult(
          `Okta authentication assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_assess_authentication" },
        );
      }
    },
  });

  pi.registerTool({
    name: "okta_assess_admin_access",
    label: "Assess Okta admin access",
    description:
      "Review Okta privileged users, super-admin concentration, stale privileged accounts, and privileged group hygiene.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const data = await collectOktaAdminAccessData(client);
        return renderAssessmentToolResult(assessOktaAdminAccess(data, config));
      } catch (error) {
        return errorResult(
          `Okta admin-access assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_assess_admin_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "okta_assess_integrations",
    label: "Assess Okta integrations",
    description:
      "Review Okta applications, trusted origins, network zones, OAuth grant hygiene, and contextual access controls.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const data = await collectOktaIntegrationData(client);
        return renderAssessmentToolResult(assessOktaIntegrations(data, config));
      } catch (error) {
        return errorResult(
          `Okta integration assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_assess_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "okta_assess_monitoring",
    label: "Assess Okta monitoring",
    description:
      "Review Okta log offloading, System Log visibility, ThreatInsight, behavior rules, API token hygiene, and device assurance coverage.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: AssessmentArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const data = await collectOktaMonitoringData(client);
        return renderAssessmentToolResult(assessOktaMonitoring(data, config));
      } catch (error) {
        return errorResult(
          `Okta monitoring assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "okta_export_audit_bundle",
    label: "Export Okta audit bundle",
    description:
      "Export a multi-framework Okta audit package with raw API data, normalized findings, markdown reports, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(
        Type.String({
          description: "Optional output root. Defaults to ./export/okta.",
        }),
      ),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = await resolveOktaConfiguration(args);
        const client = new OktaAuditorClient(config);
        const outputRoot = resolve(process.cwd(), args.output_dir ?? DEFAULT_OUTPUT_DIR);
        const result = await exportOktaAuditBundle(client, config, outputRoot);
        return textResult(buildExportText(config, result), {
          tool: "okta_export_audit_bundle",
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          file_count: result.fileCount,
          finding_count: result.findingCount,
          error_count: result.errorCount,
        });
      } catch (error) {
        return errorResult(
          `Okta audit export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "okta_export_audit_bundle" },
        );
      }
    },
  });
}
