/**
 * GitHub GRC assessment tools.
 *
 * Native TypeScript implementation grounded in current official GitHub org,
 * rulesets, Actions, code security, and audit-log APIs. The first slice stays
 * read-only and organization-focused so GRC engineers can assess GitHub posture
 * with either a PAT or a GitHub App installation token.
 */
import { createPrivateKey, sign as signData } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type GitHubAuthMode = "pat" | "app";
type GitHubFindingStatus = "Pass" | "Partial" | "Fail" | "Manual" | "Info";
type GitHubSeverity = "critical" | "high" | "medium" | "low" | "info";
type FrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap"
  | "general";

const DEFAULT_OUTPUT_DIR = "./export/github";
const DEFAULT_LOOKBACK_DAYS = 30;
const API_VERSION = "2026-03-10";
const MAX_RETRIES = 4;
const PAGE_SIZE = 100;
const MAX_AUDIT_EVENTS = 200;
const INSTALLATION_TOKEN_SKEW_MS = 60 * 1000;

type RawConfigArgs = {
  organization?: string;
  enterprise?: string;
  auth_mode?: string;
  api_token?: string;
  app_id?: string;
  app_private_key?: string;
  app_private_key_path?: string;
  installation_id?: string | number;
  api_base_url?: string;
  graphql_url?: string;
  lookback_days?: number;
};

type GitHubConfigOverlay = {
  organization?: string;
  enterprise?: string;
  authMode?: GitHubAuthMode;
  apiToken?: string;
  appId?: string;
  appPrivateKey?: string;
  installationId?: string;
  apiBaseUrl?: string;
  graphqlUrl?: string;
  lookbackDays?: number;
};

export interface GitHubResolvedConfig {
  organization: string;
  enterprise?: string;
  authMode: GitHubAuthMode;
  apiToken?: string;
  appId?: string;
  appPrivateKey?: string;
  installationId?: string;
  apiBaseUrl: string;
  graphqlUrl: string;
  lookbackDays: number;
  sourceChain: string[];
}

export interface GitHubGraphqlError {
  type?: string;
  message: string;
  path?: Array<string | number>;
}

export interface GitHubGraphqlResult<T = JsonRecord> {
  data: T | null;
  errors: GitHubGraphqlError[];
}

type GitHubEndpointStatus = "ok" | "forbidden" | "unauthorized" | "error";

export interface GitHubAccessProbe {
  key: string;
  path: string;
  status: GitHubEndpointStatus;
  detail: string;
}

export interface GitHubAccessCheckResult {
  organization: string;
  authMode: GitHubAuthMode;
  status: "healthy" | "limited";
  sourceChain: string[];
  probes: GitHubAccessProbe[];
  notes: string[];
  recommendedNextStep: string;
}

interface FrameworkMap {
  fedramp: string[];
  cmmc: string[];
  soc2: string[];
  cis: string[];
  pci_dss: string[];
  disa_stig: string[];
  irap: string[];
  ismap: string[];
  general: string[];
}

interface CheckDefinition {
  id: string;
  title: string;
  category: "org_access" | "repo_protection" | "actions_security" | "code_security";
  severity: GitHubSeverity;
  frameworks: FrameworkMap;
}

export interface GitHubFinding {
  id: string;
  title: string;
  category: CheckDefinition["category"];
  status: GitHubFindingStatus;
  severity: GitHubSeverity;
  summary: string;
  evidence: string[];
  recommendation: string;
  manualNote?: string;
  frameworks: FrameworkMap;
}

export interface GitHubAssessmentResult {
  category: CheckDefinition["category"];
  findings: GitHubFinding[];
  summary: Record<GitHubFindingStatus, number>;
  snapshotSummary: Record<string, number | string>;
  text: string;
}

interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
}

interface GitHubOrgAccessData {
  org: CollectedDataset<JsonRecord | null>;
  members: CollectedDataset<JsonRecord[]>;
  adminMembers: CollectedDataset<JsonRecord[]>;
  outsideCollaborators: CollectedDataset<JsonRecord[]>;
  invitations: CollectedDataset<JsonRecord[]>;
  organizationRoles: CollectedDataset<JsonRecord[]>;
  credentialAuthorizations: CollectedDataset<JsonRecord[]>;
  auditLog: CollectedDataset<JsonRecord[]>;
  hooks: CollectedDataset<JsonRecord[]>;
  appInstallations: CollectedDataset<JsonRecord[]>;
}

interface GitHubRepoProtectionData {
  org: CollectedDataset<JsonRecord | null>;
  repositories: CollectedDataset<JsonRecord[]>;
  orgRulesets: CollectedDataset<JsonRecord[]>;
  repoRulesets: CollectedDataset<Record<string, JsonRecord[]>>;
  branchProtections: CollectedDataset<Record<string, JsonRecord | null>>;
}

interface GitHubActionsData {
  actionsPermissions: CollectedDataset<JsonRecord | null>;
  selectedActions: CollectedDataset<JsonRecord | null>;
  workflowPermissions: CollectedDataset<JsonRecord | null>;
  runnerGroups: CollectedDataset<JsonRecord[]>;
  runners: CollectedDataset<JsonRecord[]>;
}

interface GitHubCodeSecurityData {
  org: CollectedDataset<JsonRecord | null>;
  repositories: CollectedDataset<JsonRecord[]>;
  codeSecurityConfigurations: CollectedDataset<JsonRecord[]>;
}

interface GitHubAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type FetchImpl = typeof fetch;

type InstallationTokenCacheEntry = {
  token?: string;
  expiresAt?: number;
  pending?: Promise<string>;
};

const installationTokenCache = new Map<string, InstallationTokenCacheEntry>();

const GITHUB_ACCESS_PROBES = [
  { key: "organization", path: (org: string) => `/orgs/${org}` },
  { key: "repositories", path: (org: string) => `/orgs/${org}/repos?per_page=1` },
  { key: "audit_log", path: (org: string) => `/orgs/${org}/audit-log?per_page=1` },
  { key: "organization_roles", path: (org: string) => `/orgs/${org}/organization-roles?per_page=1` },
  { key: "rulesets", path: (org: string) => `/orgs/${org}/rulesets?per_page=1` },
  { key: "actions_permissions", path: (org: string) => `/orgs/${org}/actions/permissions` },
  { key: "code_security", path: (org: string) => `/orgs/${org}/code-security/configurations?per_page=1` },
] as const;

const GITHUB_CHECKS: Record<string, CheckDefinition> = {
  "GITHUB-ORG-001": {
    id: "GITHUB-ORG-001",
    title: "Organization requires 2FA",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-2(1)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["2.1"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["organization-wide MFA enforcement"],
    },
  },
  "GITHUB-ORG-002": {
    id: "GITHUB-ORG-002",
    title: "Default repository permission is constrained",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["2.4"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["least privilege for members"],
    },
  },
  "GITHUB-ORG-003": {
    id: "GITHUB-ORG-003",
    title: "Outside collaborators stay tightly reviewed",
    category: "org_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2", "AC-6"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["2.3"],
      pci_dss: ["7.2.1"],
      disa_stig: ["SRG-APP-000038"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["external access review"],
    },
  },
  "GITHUB-ORG-004": {
    id: "GITHUB-ORG-004",
    title: "Privileged organization access stays limited",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-5", "AC-6"],
      cmmc: ["3.1.4"],
      soc2: ["CC6.3"],
      cis: ["1.4"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000080"],
      irap: ["ISM-0421"],
      ismap: ["CPS.AC-6"],
      general: ["limit org administrators"],
    },
  },
  "GITHUB-ORG-005": {
    id: "GITHUB-ORG-005",
    title: "Audit-log visibility is available for review",
    category: "org_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-6"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.1"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1266"],
      ismap: ["CPS.AU-2"],
      general: ["admin activity visibility"],
    },
  },
  "GITHUB-REPO-001": {
    id: "GITHUB-REPO-001",
    title: "Repositories inherit ruleset-based guardrails",
    category: "repo_protection",
    severity: "high",
    frameworks: {
      fedramp: ["CM-3", "CM-5"],
      cmmc: ["3.4.1"],
      soc2: ["CC8.1"],
      cis: ["3.1"],
      pci_dss: ["6.2.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1848"],
      ismap: ["CPS.CM-3"],
      general: ["policy-as-code repo guardrails"],
    },
  },
  "GITHUB-REPO-002": {
    id: "GITHUB-REPO-002",
    title: "Default branches are protected",
    category: "repo_protection",
    severity: "high",
    frameworks: {
      fedramp: ["CM-5", "SI-7"],
      cmmc: ["3.4.2"],
      soc2: ["CC8.1"],
      cis: ["3.2"],
      pci_dss: ["6.3.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1891"],
      ismap: ["CPS.SI-7"],
      general: ["protected default branches"],
    },
  },
  "GITHUB-REPO-003": {
    id: "GITHUB-REPO-003",
    title: "Signed commits or equivalent integrity enforcement",
    category: "repo_protection",
    severity: "medium",
    frameworks: {
      fedramp: ["SI-7", "CM-5"],
      cmmc: ["3.4.8"],
      soc2: ["CC6.8"],
      cis: ["3.4"],
      pci_dss: ["6.3.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1892"],
      ismap: ["CPS.SI-7"],
      general: ["commit integrity"],
    },
  },
  "GITHUB-REPO-004": {
    id: "GITHUB-REPO-004",
    title: "Force-push and branch deletion bypass stay restricted",
    category: "repo_protection",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-5"],
      cmmc: ["3.4.1"],
      soc2: ["CC6.6"],
      cis: ["3.3"],
      pci_dss: ["6.2.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1833"],
      ismap: ["CPS.CM-5"],
      general: ["bypass restrictions"],
    },
  },
  "GITHUB-REPO-005": {
    id: "GITHUB-REPO-005",
    title: "Web commit signoff is required",
    category: "repo_protection",
    severity: "low",
    frameworks: {
      fedramp: ["CM-3"],
      cmmc: ["3.4.1"],
      soc2: ["CC8.1"],
      cis: ["3.5"],
      pci_dss: ["6.3.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1833"],
      ismap: ["CPS.CM-3"],
      general: ["authorship traceability"],
    },
  },
  "GITHUB-ACT-001": {
    id: "GITHUB-ACT-001",
    title: "Actions allowed-actions policy is constrained",
    category: "actions_security",
    severity: "high",
    frameworks: {
      fedramp: ["CM-7", "SA-12"],
      cmmc: ["3.4.6"],
      soc2: ["CC6.6"],
      cis: ["4.2"],
      pci_dss: ["6.2.4"],
      disa_stig: ["SRG-APP-000141"],
      irap: ["ISM-1835"],
      ismap: ["CPS.SA-12"],
      general: ["restrict third-party workflow code"],
    },
  },
  "GITHUB-ACT-002": {
    id: "GITHUB-ACT-002",
    title: "Workflow token defaults are read-only",
    category: "actions_security",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.1"],
      cis: ["4.4"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["least privilege workflow tokens"],
    },
  },
  "GITHUB-ACT-003": {
    id: "GITHUB-ACT-003",
    title: "Workflows cannot self-approve pull requests",
    category: "actions_security",
    severity: "high",
    frameworks: {
      fedramp: ["CM-5", "SA-11"],
      cmmc: ["3.4.1"],
      soc2: ["CC6.6"],
      cis: ["4.5"],
      pci_dss: ["6.2.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1891"],
      ismap: ["CPS.CM-5"],
      general: ["separation of duties in CI"],
    },
  },
  "GITHUB-ACT-004": {
    id: "GITHUB-ACT-004",
    title: "Self-hosted runners stay scoped and intentional",
    category: "actions_security",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-7", "SC-7"],
      cmmc: ["3.13.1"],
      soc2: ["CC6.6"],
      cis: ["4.6"],
      pci_dss: ["1.2.1"],
      disa_stig: ["SRG-APP-000141"],
      irap: ["ISM-1841"],
      ismap: ["CPS.SC-7"],
      general: ["runner isolation"],
    },
  },
  "GITHUB-ACT-005": {
    id: "GITHUB-ACT-005",
    title: "Actions enablement scope is deliberate",
    category: "actions_security",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-7"],
      cmmc: ["3.4.6"],
      soc2: ["CC6.6"],
      cis: ["4.1"],
      pci_dss: ["6.2.4"],
      disa_stig: ["SRG-APP-000141"],
      irap: ["ISM-1835"],
      ismap: ["CPS.CM-7"],
      general: ["limit where Actions runs"],
    },
  },
  "GITHUB-CODE-001": {
    id: "GITHUB-CODE-001",
    title: "Code security configurations exist at the org layer",
    category: "code_security",
    severity: "high",
    frameworks: {
      fedramp: ["RA-5", "SI-2"],
      cmmc: ["3.11.2"],
      soc2: ["CC7.1"],
      cis: ["6.1"],
      pci_dss: ["11.3.1"],
      disa_stig: ["SRG-APP-000456"],
      irap: ["ISM-1057"],
      ismap: ["CPS.RA-5"],
      general: ["centralized code security defaults"],
    },
  },
  "GITHUB-CODE-002": {
    id: "GITHUB-CODE-002",
    title: "Secret scanning defaults are enabled",
    category: "code_security",
    severity: "high",
    frameworks: {
      fedramp: ["SI-4", "SI-7"],
      cmmc: ["3.14.1"],
      soc2: ["CC7.1"],
      cis: ["6.5"],
      pci_dss: ["3.3.3"],
      disa_stig: ["SRG-APP-000206"],
      irap: ["ISM-1170"],
      ismap: ["CPS.SI-4"],
      general: ["secret detection"],
    },
  },
  "GITHUB-CODE-003": {
    id: "GITHUB-CODE-003",
    title: "Secret scanning push protection is enabled",
    category: "code_security",
    severity: "high",
    frameworks: {
      fedramp: ["SI-7"],
      cmmc: ["3.14.1"],
      soc2: ["CC7.1"],
      cis: ["6.5"],
      pci_dss: ["3.3.3"],
      disa_stig: ["SRG-APP-000206"],
      irap: ["ISM-1170"],
      ismap: ["CPS.SI-7"],
      general: ["prevent secret leaks before merge"],
    },
  },
  "GITHUB-CODE-004": {
    id: "GITHUB-CODE-004",
    title: "Dependabot and vulnerability defaults are enabled",
    category: "code_security",
    severity: "medium",
    frameworks: {
      fedramp: ["RA-5", "SI-2"],
      cmmc: ["3.11.2"],
      soc2: ["CC7.1"],
      cis: ["6.2"],
      pci_dss: ["6.3.3"],
      disa_stig: ["SRG-APP-000455"],
      irap: ["ISM-1057"],
      ismap: ["CPS.RA-5"],
      general: ["dependency vulnerability visibility"],
    },
  },
  "GITHUB-CODE-005": {
    id: "GITHUB-CODE-005",
    title: "Code scanning default setup is enabled",
    category: "code_security",
    severity: "medium",
    frameworks: {
      fedramp: ["RA-5", "SA-11"],
      cmmc: ["3.11.2"],
      soc2: ["CC7.1"],
      cis: ["6.3"],
      pci_dss: ["6.2.4"],
      disa_stig: ["SRG-APP-000455"],
      irap: ["ISM-1057"],
      ismap: ["CPS.SA-11"],
      general: ["default code scanning"],
    },
  },
};

function parseOptionalNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function trimToUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function safeLower(value: unknown): string | undefined {
  const trimmed = trimToUndefined(value);
  return trimmed ? trimmed.toLowerCase() : undefined;
}

function normalizeOrganization(value: string): string {
  return value.replace(/^https?:\/\/github\.com\//i, "").replace(/^\/+|\/+$/g, "");
}

function normalizeApiBaseUrl(value: string): string {
  const url = value.trim();
  if (/^https?:\/\//i.test(url)) {
    return url.replace(/\/+$/g, "");
  }
  return `https://${url.replace(/\/+$/g, "")}`;
}

function deriveGraphqlUrl(apiBaseUrl: string): string {
  if (/^https?:\/\/api\.github\.com$/i.test(apiBaseUrl)) {
    return "https://api.github.com/graphql";
  }
  return `${apiBaseUrl.replace(/\/api\/v3$/i, "/api")}/graphql`;
}

function normalizeAuthMode(value: unknown): GitHubAuthMode | undefined {
  const normalized = safeLower(value);
  if (!normalized) return undefined;
  if (normalized === "pat" || normalized === "token") return "pat";
  if (normalized === "app" || normalized === "githubapp" || normalized === "github_app") return "app";
  return undefined;
}

function mergeDefined<T extends Record<string, unknown>>(target: T, source: Partial<T>): void {
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) {
      (target as Record<string, unknown>)[key] = value;
    }
  }
}

function normalizeAssessmentArgs(args: unknown): RawConfigArgs {
  const value = (args ?? {}) as RawConfigArgs;
  return {
    organization: trimToUndefined(value.organization),
    enterprise: trimToUndefined(value.enterprise),
    auth_mode: trimToUndefined(value.auth_mode),
    api_token: trimToUndefined(value.api_token),
    app_id: trimToUndefined(value.app_id),
    app_private_key: trimToUndefined(value.app_private_key),
    app_private_key_path: trimToUndefined(value.app_private_key_path),
    installation_id: typeof value.installation_id === "number"
      ? value.installation_id
      : trimToUndefined(value.installation_id),
    api_base_url: trimToUndefined(value.api_base_url),
    graphql_url: trimToUndefined(value.graphql_url),
    lookback_days: parseOptionalNumber(value.lookback_days),
  };
}

function normalizeExportArgs(args: unknown): RawConfigArgs & { output_dir?: string } {
  const value = (args ?? {}) as RawConfigArgs & { output_dir?: string };
  return {
    ...normalizeAssessmentArgs(args),
    output_dir: trimToUndefined(value.output_dir),
  };
}

function encodeBase64Url(value: string | Uint8Array): string {
  const buffer = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function parseJsonSafely(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function summarizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function extractRecords(payload: unknown): JsonRecord[] {
  if (Array.isArray(payload)) {
    return payload.filter((item) => item && typeof item === "object") as JsonRecord[];
  }

  const record = asRecord(payload);
  const candidateKeys = [
    "repositories",
    "roles",
    "installations",
    "runner_groups",
    "runners",
    "hooks",
    "items",
    "data",
  ];

  for (const key of candidateKeys) {
    if (Array.isArray(record[key])) {
      return record[key].filter((item) => item && typeof item === "object") as JsonRecord[];
    }
  }

  const arrayValue = Object.values(record).find((value) => Array.isArray(value));
  return Array.isArray(arrayValue)
    ? arrayValue.filter((item) => item && typeof item === "object") as JsonRecord[]
    : [];
}

function listErrors(datasets: Array<CollectedDataset<unknown>>): string[] {
  return datasets.flatMap((dataset) => dataset.error ? [dataset.error] : []);
}

async function collectDataset<T>(
  fallback: T,
  fn: () => Promise<T>,
): Promise<CollectedDataset<T>> {
  try {
    return { data: await fn() };
  } catch (error) {
    return { data: fallback, error: summarizeError(error) };
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

class GitHubHttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "GitHubHttpError";
    this.status = status;
  }
}

export async function resolveGitHubConfiguration(
  args: RawConfigArgs = {},
  env: NodeJS.ProcessEnv = process.env,
): Promise<GitHubResolvedConfig> {
  const sourceChain: string[] = [];
  const overlay: GitHubConfigOverlay = {};

  const envOverlay: GitHubConfigOverlay = {};
  if (trimToUndefined(env.GITHUB_ORG) || trimToUndefined(env.GH_ORG)) {
    envOverlay.organization = trimToUndefined(env.GITHUB_ORG) ?? trimToUndefined(env.GH_ORG);
  }
  if (trimToUndefined(env.GITHUB_TOKEN) || trimToUndefined(env.GH_TOKEN)) {
    envOverlay.apiToken = trimToUndefined(env.GITHUB_TOKEN) ?? trimToUndefined(env.GH_TOKEN);
  }
  envOverlay.enterprise = trimToUndefined(env.GITHUB_ENTERPRISE);
  envOverlay.appId = trimToUndefined(env.GITHUB_APP_ID);
  envOverlay.installationId = trimToUndefined(env.GITHUB_APP_INSTALLATION_ID);
  envOverlay.apiBaseUrl = trimToUndefined(env.GITHUB_API_URL) ?? trimToUndefined(env.GITHUB_API_BASE_URL);
  envOverlay.graphqlUrl = trimToUndefined(env.GITHUB_GRAPHQL_URL);
  envOverlay.lookbackDays = parseOptionalNumber(env.GITHUB_LOOKBACK_DAYS);

  const privateKeyFromEnv = trimToUndefined(env.GITHUB_APP_PRIVATE_KEY);
  const privateKeyPathFromEnv = trimToUndefined(env.GITHUB_APP_PRIVATE_KEY_PATH);
  if (privateKeyFromEnv) {
    envOverlay.appPrivateKey = privateKeyFromEnv;
  } else if (privateKeyPathFromEnv) {
    envOverlay.appPrivateKey = readFileSync(resolve(privateKeyPathFromEnv), "utf8");
  }

  const inferredEnvMode = envOverlay.apiToken
    ? "pat"
    : (envOverlay.appId && envOverlay.appPrivateKey && envOverlay.installationId ? "app" : undefined);
  if (inferredEnvMode) {
    envOverlay.authMode = inferredEnvMode;
  }

  if (Object.values(envOverlay).some((value) => value !== undefined)) {
    mergeDefined(overlay as Record<string, unknown>, envOverlay as Record<string, unknown>);
    sourceChain.push("environment");
  }

  const argOverlay: GitHubConfigOverlay = {};
  argOverlay.organization = trimToUndefined(args.organization);
  argOverlay.enterprise = trimToUndefined(args.enterprise);
  argOverlay.authMode = normalizeAuthMode(args.auth_mode);
  argOverlay.apiToken = trimToUndefined(args.api_token);
  argOverlay.appId = trimToUndefined(args.app_id);
  argOverlay.installationId = typeof args.installation_id === "number"
    ? String(args.installation_id)
    : trimToUndefined(args.installation_id);
  argOverlay.apiBaseUrl = trimToUndefined(args.api_base_url);
  argOverlay.graphqlUrl = trimToUndefined(args.graphql_url);
  argOverlay.lookbackDays = parseOptionalNumber(args.lookback_days);
  if (trimToUndefined(args.app_private_key)) {
    argOverlay.appPrivateKey = trimToUndefined(args.app_private_key);
  } else if (trimToUndefined(args.app_private_key_path)) {
    argOverlay.appPrivateKey = readFileSync(resolve(trimToUndefined(args.app_private_key_path)!), "utf8");
  }

  if (Object.values(argOverlay).some((value) => value !== undefined)) {
    mergeDefined(overlay as Record<string, unknown>, argOverlay as Record<string, unknown>);
    sourceChain.push("arguments");
  }

  const authMode = overlay.authMode
    ?? (overlay.apiToken ? "pat" : (overlay.appId && overlay.appPrivateKey && overlay.installationId ? "app" : undefined));

  const organization = overlay.organization ? normalizeOrganization(overlay.organization) : undefined;
  if (!organization) {
    throw new Error(
      "GitHub organization is required. Set GITHUB_ORG or pass organization explicitly.",
    );
  }

  if (!authMode) {
    throw new Error(
      "GitHub auth is required. Set GITHUB_TOKEN / GH_TOKEN for PAT mode, or provide GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY(_PATH), and GITHUB_APP_INSTALLATION_ID for app mode.",
    );
  }

  if (authMode === "pat" && !overlay.apiToken) {
    throw new Error(
      "GitHub PAT auth requires an API token. Set GITHUB_TOKEN / GH_TOKEN or pass api_token explicitly.",
    );
  }

  if (authMode === "app") {
    if (!overlay.appId) {
      throw new Error(
        "GitHub App auth requires app_id. Set GITHUB_APP_ID or pass app_id explicitly.",
      );
    }
    if (!overlay.appPrivateKey) {
      throw new Error(
        "GitHub App auth requires a PEM private key. Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH, or pass app_private_key / app_private_key_path explicitly.",
      );
    }
    if (!overlay.installationId) {
      throw new Error(
        "GitHub App auth requires installation_id. Set GITHUB_APP_INSTALLATION_ID or pass installation_id explicitly.",
      );
    }
  }

  const apiBaseUrl = normalizeApiBaseUrl(overlay.apiBaseUrl ?? "https://api.github.com");
  return {
    organization,
    enterprise: overlay.enterprise ? normalizeOrganization(overlay.enterprise) : undefined,
    authMode,
    apiToken: overlay.apiToken,
    appId: overlay.appId,
    appPrivateKey: overlay.appPrivateKey,
    installationId: overlay.installationId,
    apiBaseUrl,
    graphqlUrl: overlay.graphqlUrl ? normalizeApiBaseUrl(overlay.graphqlUrl) : deriveGraphqlUrl(apiBaseUrl),
    lookbackDays: overlay.lookbackDays ?? DEFAULT_LOOKBACK_DAYS,
    sourceChain,
  };
}

function installationCacheKey(config: GitHubResolvedConfig): string {
  return `${config.apiBaseUrl}::${config.appId ?? ""}::${config.installationId ?? ""}`;
}

function buildGitHubAppJwt(config: GitHubResolvedConfig): string {
  if (!config.appId || !config.appPrivateKey) {
    throw new Error("GitHub App auth configuration is incomplete.");
  }
  const issuedAt = Math.floor(Date.now() / 1000) - 60;
  const expiresAt = issuedAt + (9 * 60);
  const header = encodeBase64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = encodeBase64Url(JSON.stringify({
    iat: issuedAt,
    exp: expiresAt,
    iss: config.appId,
  }));
  const signingInput = `${header}.${payload}`;
  const key = createPrivateKey(config.appPrivateKey);
  const signature = signData("RSA-SHA256", Buffer.from(signingInput), key);
  return `${signingInput}.${encodeBase64Url(signature)}`;
}

type RequestOptions = {
  method?: string;
  body?: unknown;
  allow404?: boolean;
  headers?: Record<string, string>;
};

type ResponseEnvelope<T> = {
  response: Response;
  payload: T | null;
  rawText: string;
};

export class GitHubAuditorClient {
  private readonly config: GitHubResolvedConfig;
  private readonly fetchImpl: FetchImpl;

  constructor(config: GitHubResolvedConfig, fetchImpl: FetchImpl = fetch) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  private async getInstallationToken(forceRefresh: boolean = false): Promise<string> {
    if (this.config.authMode !== "app" || !this.config.appId || !this.config.installationId) {
      throw new Error("GitHub App auth is not configured.");
    }

    const cacheKey = installationCacheKey(this.config);
    const existing = installationTokenCache.get(cacheKey) ?? {};
    const now = Date.now();
    if (!forceRefresh && existing.token && existing.expiresAt && now < existing.expiresAt - INSTALLATION_TOKEN_SKEW_MS) {
      return existing.token;
    }
    if (!forceRefresh && existing.pending) {
      return existing.pending;
    }

    const pending = (async () => {
      const jwt = buildGitHubAppJwt(this.config);
      const response = await this.fetchImpl(
        `${this.config.apiBaseUrl}/app/installations/${this.config.installationId}/access_tokens`,
        {
          method: "POST",
          headers: {
            Accept: "application/vnd.github+json",
            Authorization: `Bearer ${jwt}`,
            "User-Agent": "grclanker",
            "X-GitHub-Api-Version": API_VERSION,
          },
        },
      );

      const text = await response.text();
      const payload = parseJsonSafely(text) as JsonRecord | undefined;
      if (!response.ok || !payload || !asString(payload.token)) {
        const detail = asString(asRecord(payload).message) ?? response.statusText ?? text ?? "unknown error";
        throw new Error(
          `GitHub App installation token request failed (${response.status}): ${detail}`,
        );
      }

      const token = asString(payload.token)!;
      const expiresAt = Date.parse(asString(payload.expires_at) ?? "") || (Date.now() + (60 * 60 * 1000));
      installationTokenCache.set(cacheKey, { token, expiresAt });
      return token;
    })();

    installationTokenCache.set(cacheKey, { ...existing, pending });
    try {
      return await pending;
    } finally {
      const latest = installationTokenCache.get(cacheKey) ?? {};
      if (latest.pending === pending) {
        delete latest.pending;
        installationTokenCache.set(cacheKey, latest);
      }
    }
  }

  private async getAccessToken(forceRefresh: boolean = false): Promise<string> {
    if (this.config.authMode === "pat") {
      if (!this.config.apiToken) {
        throw new Error("GitHub PAT is not configured.");
      }
      return this.config.apiToken;
    }
    return this.getInstallationToken(forceRefresh);
  }

  private buildUrl(pathname: string): string {
    if (/^https?:\/\//i.test(pathname)) {
      return pathname;
    }
    const trimmed = pathname.startsWith("/") ? pathname : `/${pathname}`;
    return `${this.config.apiBaseUrl}${trimmed}`;
  }

  private async waitForRetry(response: Response, rawText: string, attempt: number): Promise<boolean> {
    if (attempt >= MAX_RETRIES) return false;
    if (!(response.status === 403 || response.status === 429)) return false;

    const retryAfterHeader = response.headers.get("retry-after");
    const remaining = response.headers.get("x-ratelimit-remaining");
    const resetHeader = response.headers.get("x-ratelimit-reset");
    const payload = parseJsonSafely(rawText);
    const message = asString(asRecord(payload).message)?.toLowerCase() ?? rawText.toLowerCase();
    const isRateLimited = response.status === 429
      || remaining === "0"
      || message.includes("secondary rate limit")
      || message.includes("rate limit");
    if (!isRateLimited) return false;

    let waitMs = 0;
    const retryAfterSeconds = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : Number.NaN;
    if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0) {
      waitMs = retryAfterSeconds * 1000;
    } else if (resetHeader) {
      const resetMs = (Number.parseInt(resetHeader, 10) * 1000) - Date.now();
      waitMs = Number.isFinite(resetMs) ? Math.max(resetMs, 0) : 0;
    } else {
      waitMs = 250 * (attempt + 1);
    }

    await delay(waitMs);
    return true;
  }

  async requestJson<T = unknown>(
    pathname: string,
    options: RequestOptions = {},
  ): Promise<ResponseEnvelope<T>> {
    let attempt = 0;
    let forceRefresh = false;

    while (attempt <= MAX_RETRIES) {
      const token = await this.getAccessToken(forceRefresh);
      const response = await this.fetchImpl(this.buildUrl(pathname), {
        method: options.method ?? (options.body ? "POST" : "GET"),
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "Content-Type": options.body ? "application/json" : "application/vnd.github+json",
          "User-Agent": "grclanker",
          "X-GitHub-Api-Version": API_VERSION,
          ...(options.headers ?? {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
      });

      const rawText = await response.text();
      const payload = rawText.length > 0 ? parseJsonSafely(rawText) as T | null : null;

      if (options.allow404 && response.status === 404) {
        return { response, payload: null, rawText };
      }

      if (response.ok) {
        return { response, payload, rawText };
      }

      if (response.status === 401 && this.config.authMode === "app" && !forceRefresh) {
        forceRefresh = true;
        attempt += 1;
        continue;
      }

      if (await this.waitForRetry(response, rawText, attempt)) {
        attempt += 1;
        continue;
      }

      const message = asString(asRecord(payload).message) ?? response.statusText ?? rawText ?? "request failed";
      throw new GitHubHttpError(response.status, message);
    }

    throw new Error(`GitHub request retries exhausted for ${pathname}`);
  }

  async graphql<T = JsonRecord>(
    query: string,
    variables: JsonRecord = {},
  ): Promise<GitHubGraphqlResult<T>> {
    const { payload } = await this.requestJson<JsonRecord>(this.config.graphqlUrl, {
      method: "POST",
      body: { query, variables },
    });
    const envelope = asRecord(payload);
    const errors = asArray(envelope.errors).map((entry) => {
      const record = asRecord(entry);
      return {
        type: asString(record.type),
        message: asString(record.message) ?? "GraphQL error without a message",
        path: Array.isArray(record.path) ? record.path as Array<string | number> : undefined,
      };
    });
    const data = envelope.data && typeof envelope.data === "object" ? envelope.data as T : null;
    return { data, errors };
  }

  async getOrganization(): Promise<JsonRecord> {
    const { payload } = await this.requestJson<JsonRecord>(`/orgs/${this.config.organization}`);
    return asRecord(payload);
  }

  async listMembers(role: "all" | "admin" = "all"): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/members?per_page=${PAGE_SIZE}&role=${role}`);
  }

  async listOutsideCollaborators(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/outside_collaborators?per_page=${PAGE_SIZE}`);
  }

  async listInvitations(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/invitations?per_page=${PAGE_SIZE}`);
  }

  async listOrganizationRoles(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/organization-roles?per_page=${PAGE_SIZE}`);
  }

  async listCredentialAuthorizations(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/credential-authorizations?per_page=${PAGE_SIZE}`);
  }

  async listAuditLog(lookbackDays: number = this.config.lookbackDays): Promise<JsonRecord[]> {
    const after = new Date(Date.now() - (lookbackDays * 24 * 60 * 60 * 1000)).toISOString();
    const records = await this.paginate(
      `/orgs/${this.config.organization}/audit-log?per_page=${PAGE_SIZE}&include=all&after=${encodeURIComponent(after)}`,
      MAX_AUDIT_EVENTS,
    );
    return records;
  }

  async listHooks(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/hooks?per_page=${PAGE_SIZE}`);
  }

  async listInstallations(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/installations?per_page=${PAGE_SIZE}`);
  }

  async listRepositories(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/repos?per_page=${PAGE_SIZE}&type=all`);
  }

  async listOrgRulesets(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/rulesets?per_page=${PAGE_SIZE}`);
  }

  async listRepoRulesets(owner: string, repo: string): Promise<JsonRecord[]> {
    return this.paginate(`/repos/${owner}/${repo}/rulesets?per_page=${PAGE_SIZE}`);
  }

  async getBranchProtection(owner: string, repo: string, branch: string): Promise<JsonRecord | null> {
    const { payload } = await this.requestJson<JsonRecord>(
      `/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}/protection`,
      { allow404: true },
    );
    return payload ? asRecord(payload) : null;
  }

  async getOrgActionsPermissions(): Promise<JsonRecord> {
    const { payload } = await this.requestJson<JsonRecord>(`/orgs/${this.config.organization}/actions/permissions`);
    return asRecord(payload);
  }

  async getOrgSelectedActions(): Promise<JsonRecord> {
    const { payload } = await this.requestJson<JsonRecord>(`/orgs/${this.config.organization}/actions/permissions/selected-actions`);
    return asRecord(payload);
  }

  async getOrgWorkflowPermissions(): Promise<JsonRecord> {
    const { payload } = await this.requestJson<JsonRecord>(`/orgs/${this.config.organization}/actions/permissions/workflow`);
    return asRecord(payload);
  }

  async listRunnerGroups(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/actions/runner-groups?per_page=${PAGE_SIZE}`);
  }

  async listRunners(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/actions/runners?per_page=${PAGE_SIZE}`);
  }

  async listCodeSecurityConfigurations(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/code-security/configurations?per_page=${PAGE_SIZE}`);
  }

  private async paginate(pathname: string, limit: number = Number.POSITIVE_INFINITY): Promise<JsonRecord[]> {
    const collected: JsonRecord[] = [];
    let nextPath: string | null = pathname;

    while (nextPath && collected.length < limit) {
      const { response, payload } = await this.requestJson(nextPath);
      const pageRecords = extractRecords(payload);
      for (const record of pageRecords) {
        collected.push(record);
        if (collected.length >= limit) break;
      }

      const linkHeader = response.headers.get("link");
      nextPath = parseNextLink(linkHeader);
    }

    return collected;
  }
}

export function clearGitHubTokenCacheForTests(): void {
  installationTokenCache.clear();
}

function parseNextLink(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/i);
  return match?.[1] ?? null;
}

function countByStatus(findings: GitHubFinding[]): Record<GitHubFindingStatus, number> {
  return findings.reduce<Record<GitHubFindingStatus, number>>(
    (summary, finding) => {
      summary[finding.status] += 1;
      return summary;
    },
    {
      Pass: 0,
      Partial: 0,
      Fail: 0,
      Manual: 0,
      Info: 0,
    },
  );
}

function buildFinding(
  id: string,
  status: GitHubFindingStatus,
  summary: string,
  evidence: string[],
  recommendation: string,
  manualNote?: string,
): GitHubFinding {
  const definition = GITHUB_CHECKS[id];
  return {
    id,
    title: definition.title,
    category: definition.category,
    status,
    severity: definition.severity,
    summary,
    evidence,
    recommendation,
    manualNote,
    frameworks: definition.frameworks,
  };
}

function findingTable(findings: GitHubFinding[]): string {
  return formatTable(
    ["Check", "Status", "Severity", "Title"],
    findings.map((finding) => [finding.id, finding.status, finding.severity, finding.title]),
  );
}

function buildAssessmentText(
  categoryLabel: string,
  organization: string,
  findings: GitHubFinding[],
): string {
  const summary = countByStatus(findings);
  return [
    `${categoryLabel} for ${organization}`,
    `Summary: Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}`,
    "",
    findingTable(findings),
    "",
    ...findings.map((finding) => [
      `${finding.id} — ${finding.summary}`,
      ...finding.evidence.map((line) => `  • ${line}`),
      `  Recommendation: ${finding.recommendation}`,
      finding.manualNote ? `  Manual note: ${finding.manualNote}` : "",
    ].filter(Boolean).join("\n")),
  ].join("\n");
}

function renderAssessmentToolResult(result: GitHubAssessmentResult) {
  return textResult(result.text, {
    category: result.category,
    findings: result.findings,
    summary: result.summary,
    snapshot_summary: result.snapshotSummary,
  });
}

function probeTable(probes: GitHubAccessProbe[]): string {
  return formatTable(
    ["Probe", "Status", "Detail"],
    probes.map((probe) => [probe.key, probe.status, probe.detail]),
  );
}

function renderAccessCheck(result: GitHubAccessCheckResult) {
  return textResult(
    [
      `GitHub access check for ${result.organization}`,
      `Status: ${result.status}`,
      `Auth mode: ${result.authMode}`,
      "",
      probeTable(result.probes),
      "",
      "Notes:",
      ...result.notes.map((note) => `- ${note}`),
      "",
      `Next step: ${result.recommendedNextStep}`,
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

function buildExportText(config: GitHubResolvedConfig, result: GitHubAuditBundleResult): string {
  return [
    `Exported GitHub audit bundle for ${config.organization}.`,
    `Output directory: ${result.outputDir}`,
    `Zip archive: ${result.zipPath}`,
    `Files written: ${result.fileCount}`,
    `Findings recorded: ${result.findingCount}`,
    `Collection warnings: ${result.errorCount}`,
  ].join("\n");
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "github-audit";
}

function frameworkMatrixRow(finding: GitHubFinding): string {
  const mappings = Object.entries(finding.frameworks)
    .filter(([, values]) => values.length > 0)
    .map(([key, values]) => `${key}: ${values.join(", ")}`)
    .join(" | ");
  return `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${mappings} |`;
}

function buildFrameworkReport(title: string, findings: GitHubFinding[], key: FrameworkKey): string {
  return [
    `# ${title}`,
    "",
    "| Check | Title | Status | Severity | Mapping |",
    "| --- | --- | --- | --- | --- |",
    ...findings
      .filter((finding) => finding.frameworks[key].length > 0)
      .map((finding) => `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${finding.frameworks[key].join(", ")} |`),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: GitHubFinding[]): string {
  return [
    "# Unified GitHub Compliance Matrix",
    "",
    "| Check | Title | Status | Severity | Mappings |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map(frameworkMatrixRow),
    "",
  ].join("\n");
}

function buildExecutiveSummary(
  config: GitHubResolvedConfig,
  assessments: GitHubAssessmentResult[],
  errors: string[],
): string {
  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  const summary = countByStatus(allFindings);
  return [
    "# GitHub Audit Executive Summary",
    "",
    `- Organization: ${config.organization}`,
    `- Auth mode: ${config.authMode}`,
    `- API base: ${config.apiBaseUrl}`,
    `- Lookback days: ${config.lookbackDays}`,
    `- Source chain: ${config.sourceChain.join(" -> ") || "direct"}`,
    "",
    "## Findings",
    "",
    `- Pass: ${summary.Pass}`,
    `- Partial: ${summary.Partial}`,
    `- Fail: ${summary.Fail}`,
    `- Manual: ${summary.Manual}`,
    `- Info: ${summary.Info}`,
    "",
    errors.length > 0
      ? [
        "## Collection warnings",
        "",
        ...errors.map((error) => `- ${error}`),
        "",
      ].join("\n")
      : "",
  ].filter(Boolean).join("\n");
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

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  worker: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(values.length);
  let index = 0;

  async function runWorker(): Promise<void> {
    while (true) {
      const current = index;
      index += 1;
      if (current >= values.length) return;
      results[current] = await worker(values[current], current);
    }
  }

  const workers = Array.from({ length: Math.max(1, Math.min(limit, values.length)) }, () => runWorker());
  await Promise.all(workers);
  return results;
}

function isArchivedRepo(repo: JsonRecord): boolean {
  return asBoolean(repo.archived) === true || asBoolean(repo.disabled) === true;
}

function repoKey(repo: JsonRecord): string {
  return asString(repo.full_name) ?? `${asString(repo.owner && asRecord(repo.owner).login) ?? ""}/${asString(repo.name) ?? ""}`;
}

function rulesetRuleTypes(ruleset: JsonRecord): Set<string> {
  const types = new Set<string>();
  for (const rule of asArray(ruleset.rules)) {
    const type = safeLower(asRecord(rule).type);
    if (type) types.add(type);
  }
  return types;
}

function isActiveRuleset(ruleset: JsonRecord): boolean {
  return safeLower(ruleset.enforcement) !== "disabled";
}

function hasRuleType(rulesets: JsonRecord[], type: string): boolean {
  return rulesets.some((ruleset) => isActiveRuleset(ruleset) && rulesetRuleTypes(ruleset).has(type));
}

function branchProtectionRequiresReviewsOrChecks(protection: JsonRecord | null): boolean {
  if (!protection) return false;
  return Boolean(protection.required_pull_request_reviews || protection.required_status_checks);
}

function branchProtectionRequiresSignatures(protection: JsonRecord | null): boolean {
  if (!protection) return false;
  const requiredSignatures = asRecord(protection.required_signatures);
  return asBoolean(requiredSignatures.enabled) === true;
}

function branchProtectionRestrictsBypass(protection: JsonRecord | null): boolean {
  if (!protection) return false;
  const allowForcePushes = asRecord(protection.allow_force_pushes);
  const allowDeletions = asRecord(protection.allow_deletions);
  const forcePushDisabled = asBoolean(allowForcePushes.enabled) !== true;
  const deletionDisabled = asBoolean(allowDeletions.enabled) !== true;
  return forcePushDisabled && deletionDisabled;
}

function featureEnabled(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    return ["enabled", "enforced", "active", "all", "configured", "on"].includes(value.toLowerCase());
  }
  if (value && typeof value === "object") {
    const record = asRecord(value);
    return featureEnabled(record.status) || featureEnabled(record.enabled) || featureEnabled(record.enforcement);
  }
  return false;
}

function selectPrimaryCodeSecurityConfigurations(configs: JsonRecord[]): JsonRecord[] {
  const defaults = configs.filter((config) =>
    asBoolean(config.default_for_new_repos) === true
    || asBoolean(config.default_for_new_repositories) === true
    || asBoolean(config.is_default) === true,
  );
  return defaults.length > 0 ? defaults : configs;
}

function buildFrameworkReports(findings: GitHubFinding[]): Record<string, string> {
  return {
    fedramp: buildFrameworkReport("FedRAMP / NIST 800-53 Report", findings, "fedramp"),
    cmmc: buildFrameworkReport("CMMC Report", findings, "cmmc"),
    soc2: buildFrameworkReport("SOC 2 Report", findings, "soc2"),
    cis: buildFrameworkReport("CIS GitHub Benchmark Report", findings, "cis"),
    pci_dss: buildFrameworkReport("PCI-DSS Report", findings, "pci_dss"),
    disa_stig: buildFrameworkReport("DISA STIG Report", findings, "disa_stig"),
    irap: buildFrameworkReport("IRAP Report", findings, "irap"),
    ismap: buildFrameworkReport("ISMAP Report", findings, "ismap"),
  };
}

async function buildBundleReadme(rootDir: string): Promise<void> {
  await writeSecureTextFile(
    rootDir,
    "README.md",
    [
      "# GitHub Audit Bundle Quick Reference",
      "",
      "- `core_data/` contains the raw GitHub API payloads collected for this assessment.",
      "- `analysis/` contains normalized findings in JSON and terminal-friendly markdown.",
      "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
      "",
      "This bundle is read-only evidence and analysis output. It does not contain GitHub write-capable credentials.",
    ].join("\n"),
  );
}

function countFilesInResult(entries: Array<string | { name: string }>): number {
  return entries.length;
}

function datasetSnapshotCount(dataset: CollectedDataset<unknown>): number | string {
  if (dataset.error) return "error";
  if (Array.isArray(dataset.data)) return dataset.data.length;
  if (dataset.data && typeof dataset.data === "object") return Object.keys(dataset.data as JsonRecord).length;
  if (dataset.data === null || dataset.data === undefined) return 0;
  return 1;
}

export async function runGitHubAccessCheck(
  client: Pick<
    GitHubAuditorClient,
    | "requestJson"
  >,
  config: GitHubResolvedConfig,
): Promise<GitHubAccessCheckResult> {
  const probes: GitHubAccessProbe[] = [];

  for (const probe of GITHUB_ACCESS_PROBES) {
    try {
      const result = await client.requestJson(probe.path(config.organization), { allow404: true });
      if (result.response.ok) {
        probes.push({ key: probe.key, path: probe.path(config.organization), status: "ok", detail: "readable" });
      } else if (result.response.status === 401) {
        probes.push({ key: probe.key, path: probe.path(config.organization), status: "unauthorized", detail: "credentials not authorized" });
      } else if (result.response.status === 403 || result.response.status === 404) {
        probes.push({ key: probe.key, path: probe.path(config.organization), status: "forbidden", detail: `not readable (${result.response.status})` });
      } else {
        probes.push({ key: probe.key, path: probe.path(config.organization), status: "error", detail: `unexpected response (${result.response.status})` });
      }
    } catch (error) {
      const status = error instanceof GitHubHttpError && error.status === 401
        ? "unauthorized"
        : (error instanceof GitHubHttpError && (error.status === 403 || error.status === 404) ? "forbidden" : "error");
      probes.push({
        key: probe.key,
        path: probe.path(config.organization),
        status,
        detail: summarizeError(error),
      });
    }
  }

  const okCount = probes.filter((probe) => probe.status === "ok").length;
  const notes = [
    config.authMode === "app"
      ? "GitHub App installation auth is enabled. Some org-admin endpoints may still require broader org or user-token access depending on how the app is installed."
      : "PAT auth is enabled. For orgs with SAML SSO, make sure the token is explicitly authorized for the organization.",
    "The access check is read-only. It confirms which org-level GRC surfaces are actually readable before the deeper assessments run.",
  ];

  return {
    organization: config.organization,
    authMode: config.authMode,
    status: okCount >= 4 ? "healthy" : "limited",
    sourceChain: config.sourceChain,
    probes,
    notes,
    recommendedNextStep: okCount >= 4
      ? "Run the focused GitHub assessment that matches the question, or export a full audit bundle if you need evidence artifacts."
      : "Fix the missing GitHub permissions first, then rerun github_check_access before trusting any compliance conclusion.",
  };
}

export async function collectGitHubOrgAccessData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listMembers"
    | "listOutsideCollaborators"
    | "listInvitations"
    | "listOrganizationRoles"
    | "listCredentialAuthorizations"
    | "listAuditLog"
    | "listHooks"
    | "listInstallations"
  >,
  config: GitHubResolvedConfig,
): Promise<GitHubOrgAccessData> {
  return {
    org: await collectDataset<JsonRecord | null>(null, () => client.getOrganization()),
    members: await collectDataset<JsonRecord[]>([], () => client.listMembers("all")),
    adminMembers: await collectDataset<JsonRecord[]>([], () => client.listMembers("admin")),
    outsideCollaborators: await collectDataset<JsonRecord[]>([], () => client.listOutsideCollaborators()),
    invitations: await collectDataset<JsonRecord[]>([], () => client.listInvitations()),
    organizationRoles: await collectDataset<JsonRecord[]>([], () => client.listOrganizationRoles()),
    credentialAuthorizations: await collectDataset<JsonRecord[]>([], () => client.listCredentialAuthorizations()),
    auditLog: await collectDataset<JsonRecord[]>([], () => client.listAuditLog(config.lookbackDays)),
    hooks: await collectDataset<JsonRecord[]>([], () => client.listHooks()),
    appInstallations: await collectDataset<JsonRecord[]>([], () => client.listInstallations()),
  };
}

export async function collectGitHubRepoProtectionData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listRepositories"
    | "listOrgRulesets"
    | "listRepoRulesets"
    | "getBranchProtection"
  >,
): Promise<GitHubRepoProtectionData> {
  const org = await collectDataset<JsonRecord | null>(null, () => client.getOrganization());
  const repositories = await collectDataset<JsonRecord[]>([], () => client.listRepositories());
  const orgRulesets = await collectDataset<JsonRecord[]>([], () => client.listOrgRulesets());

  const eligibleRepos = repositories.data.filter((repo) => !isArchivedRepo(repo));

  const repoRulesets = await collectDataset<Record<string, JsonRecord[]>>({}, async () => {
    const entries = await mapWithConcurrency(eligibleRepos, 6, async (repo) => {
      const owner = asString(asRecord(repo.owner).login) ?? "";
      const name = asString(repo.name) ?? "";
      const key = repoKey(repo);
      const rulesets = await client.listRepoRulesets(owner, name);
      return [key, rulesets] as const;
    });
    return Object.fromEntries(entries);
  });

  const branchProtections = await collectDataset<Record<string, JsonRecord | null>>({}, async () => {
    const entries = await mapWithConcurrency(eligibleRepos, 6, async (repo) => {
      const owner = asString(asRecord(repo.owner).login) ?? "";
      const name = asString(repo.name) ?? "";
      const key = repoKey(repo);
      const defaultBranch = asString(repo.default_branch);
      const protection = defaultBranch ? await client.getBranchProtection(owner, name, defaultBranch) : null;
      return [key, protection] as const;
    });
    return Object.fromEntries(entries);
  });

  return {
    org,
    repositories,
    orgRulesets,
    repoRulesets,
    branchProtections,
  };
}

export async function collectGitHubActionsData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrgActionsPermissions"
    | "getOrgSelectedActions"
    | "getOrgWorkflowPermissions"
    | "listRunnerGroups"
    | "listRunners"
  >,
): Promise<GitHubActionsData> {
  return {
    actionsPermissions: await collectDataset<JsonRecord | null>(null, () => client.getOrgActionsPermissions()),
    selectedActions: await collectDataset<JsonRecord | null>(null, () => client.getOrgSelectedActions()),
    workflowPermissions: await collectDataset<JsonRecord | null>(null, () => client.getOrgWorkflowPermissions()),
    runnerGroups: await collectDataset<JsonRecord[]>([], () => client.listRunnerGroups()),
    runners: await collectDataset<JsonRecord[]>([], () => client.listRunners()),
  };
}

export async function collectGitHubCodeSecurityData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listRepositories"
    | "listCodeSecurityConfigurations"
  >,
): Promise<GitHubCodeSecurityData> {
  return {
    org: await collectDataset<JsonRecord | null>(null, () => client.getOrganization()),
    repositories: await collectDataset<JsonRecord[]>([], () => client.listRepositories()),
    codeSecurityConfigurations: await collectDataset<JsonRecord[]>([], () => client.listCodeSecurityConfigurations()),
  };
}

export function assessGitHubOrgAccess(
  data: GitHubOrgAccessData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const org = data.org.data ?? null;
  const twoFactorRequired = asBoolean(org && asRecord(org).two_factor_requirement_enabled);
  const defaultRepoPermission = safeLower(org && asRecord(org).default_repository_permission) ?? "unknown";
  const outsideCollaboratorCount = data.outsideCollaborators.data.length;
  const adminCount = data.adminMembers.data.length;
  const roleAssignments = data.organizationRoles.data.length;
  const auditVisible = !data.auditLog.error;
  const auditEventCount = data.auditLog.data.length;

  const findings: GitHubFinding[] = [
    buildFinding(
      "GITHUB-ORG-001",
      twoFactorRequired === true ? "Pass" : (twoFactorRequired === false ? "Fail" : "Manual"),
      twoFactorRequired === true
        ? "The organization requires two-factor authentication for members."
        : (twoFactorRequired === false
          ? "The organization does not require two-factor authentication for members."
          : "The tool could not confirm whether two-factor authentication is required."),
      [
        twoFactorRequired !== undefined
          ? `two_factor_requirement_enabled = ${String(twoFactorRequired)}`
          : "Organization 2FA setting was not readable from the org profile response.",
      ],
      "Require 2FA at the organization level so member access cannot remain single-factor.",
      twoFactorRequired === undefined ? "Confirm the org-wide 2FA requirement manually if the token cannot read the field." : undefined,
    ),
    buildFinding(
      "GITHUB-ORG-002",
      defaultRepoPermission === "read" || defaultRepoPermission === "none"
        ? "Pass"
        : (defaultRepoPermission === "write" || defaultRepoPermission === "admin" ? "Fail" : "Manual"),
      defaultRepoPermission === "read" || defaultRepoPermission === "none"
        ? `Default repository permission is constrained to ${defaultRepoPermission}.`
        : (defaultRepoPermission === "write" || defaultRepoPermission === "admin"
          ? `Default repository permission is ${defaultRepoPermission}, which is broader than least-privilege defaults.`
          : "The tool could not confirm the organization's default repository permission."),
      [
        `default_repository_permission = ${defaultRepoPermission}`,
        `members = ${data.members.data.length}`,
      ],
      "Set the base member repository permission to read or none and grant elevated access intentionally via teams or roles.",
      defaultRepoPermission === "unknown" ? "Review the org settings page if the token cannot read default repository permissions." : undefined,
    ),
    buildFinding(
      "GITHUB-ORG-003",
      outsideCollaboratorCount === 0 ? "Pass" : (outsideCollaboratorCount <= 5 ? "Partial" : "Fail"),
      outsideCollaboratorCount === 0
        ? "No outside collaborators were found."
        : `${outsideCollaboratorCount} outside collaborator(s) are attached to the organization.`,
      [
        `outside_collaborators = ${outsideCollaboratorCount}`,
        `pending_invitations = ${data.invitations.data.length}`,
      ],
      "Review outside collaborators regularly and move durable access into managed org membership where possible.",
    ),
    buildFinding(
      "GITHUB-ORG-004",
      adminCount === 0 ? "Manual" : (adminCount <= 5 ? "Pass" : "Partial"),
      adminCount === 0
        ? "The tool did not find any explicit organization admins."
        : `${adminCount} org admin member(s) and ${roleAssignments} organization-role assignment(s) were identified.`,
      [
        `admin_members = ${adminCount}`,
        `organization_role_assignments = ${roleAssignments}`,
      ],
      "Keep org-admin membership small and use custom roles or teams for narrower delegated duties.",
      adminCount === 0 ? "If the org uses custom roles heavily, confirm owner/admin concentration through the web UI as a follow-up." : undefined,
    ),
    buildFinding(
      "GITHUB-ORG-005",
      auditVisible ? (auditEventCount > 0 ? "Pass" : "Info") : "Manual",
      auditVisible
        ? `The organization audit log is readable and returned ${auditEventCount} event(s) for the configured lookback window.`
        : "The tool could not read the organization audit log with the supplied credentials.",
      [
        auditVisible ? `audit_events_last_${config.lookbackDays}_days = ${auditEventCount}` : `audit_log_error = ${data.auditLog.error}`,
        `webhooks = ${data.hooks.data.length}`,
        `app_installations = ${data.appInstallations.data.length}`,
      ],
      "Ensure the audit log is readable to the audit principal and that recent org events are reviewed or forwarded into monitoring workflows.",
      !auditVisible ? "PATs with SSO authorization are often the safest path for this endpoint." : undefined,
    ),
  ];

  return {
    category: "org_access",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      members: datasetSnapshotCount(data.members),
      admin_members: datasetSnapshotCount(data.adminMembers),
      outside_collaborators: datasetSnapshotCount(data.outsideCollaborators),
      invitations: datasetSnapshotCount(data.invitations),
      audit_events: datasetSnapshotCount(data.auditLog),
      hooks: datasetSnapshotCount(data.hooks),
    },
    text: buildAssessmentText("GitHub org access assessment", config.organization, findings),
  };
}

export function assessGitHubRepoProtection(
  data: GitHubRepoProtectionData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const org = data.org.data ?? null;
  const orgRulesets = data.orgRulesets.data.filter(isActiveRuleset);
  const repos = data.repositories.data.filter((repo) => !isArchivedRepo(repo));

  let protectedCount = 0;
  let signedCount = 0;
  let bypassRestrictedCount = 0;
  let repoRulesetCoverage = 0;

  for (const repo of repos) {
    const key = repoKey(repo);
    const repoRulesets = (data.repoRulesets.data[key] ?? []).filter(isActiveRuleset);
    const protection = data.branchProtections.data[key] ?? null;
    const hasBranchProtection = branchProtectionRequiresReviewsOrChecks(protection);
    const hasRepoRules = repoRulesets.length > 0;
    if (hasBranchProtection || hasRepoRules) protectedCount += 1;
    if (hasRuleType(repoRulesets, "required_signatures") || branchProtectionRequiresSignatures(protection)) signedCount += 1;
    if (
      hasRuleType(repoRulesets, "non_fast_forward")
      || hasRuleType(repoRulesets, "deletion")
      || branchProtectionRestrictsBypass(protection)
    ) {
      bypassRestrictedCount += 1;
    }
    if (repoRulesets.length > 0) repoRulesetCoverage += 1;
  }

  const repoCount = repos.length;
  const webCommitSignoffRequired = asBoolean(org && asRecord(org).web_commit_signoff_required);

  const findings: GitHubFinding[] = [
    buildFinding(
      "GITHUB-REPO-001",
      orgRulesets.length > 0 || repoRulesetCoverage > 0
        ? (orgRulesets.length > 0 ? "Pass" : "Partial")
        : "Fail",
      orgRulesets.length > 0
        ? `${orgRulesets.length} active organization ruleset(s) were found.`
        : (repoRulesetCoverage > 0
          ? `${repoRulesetCoverage} repository-specific ruleset assignment(s) were found, but no org-wide rulesets were detected.`
          : "No active organization or repository rulesets were found."),
      [
        `active_org_rulesets = ${orgRulesets.length}`,
        `repos_with_repo_rulesets = ${repoRulesetCoverage}/${repoCount}`,
      ],
      "Use organization rulesets where possible so baseline branch protections are declarative and harder to drift.",
    ),
    buildFinding(
      "GITHUB-REPO-002",
      repoCount === 0 ? "Info" : (protectedCount === repoCount ? "Pass" : (protectedCount > 0 || orgRulesets.length > 0 ? "Partial" : "Fail")),
      repoCount === 0
        ? "No active repositories were found to assess."
        : `${protectedCount} of ${repoCount} active repositories showed branch protection or repo-level ruleset coverage.`,
      [
        `protected_or_ruleset_covered_repos = ${protectedCount}/${repoCount}`,
        `org_rulesets = ${orgRulesets.length}`,
      ],
      "Require pull requests and status checks on default branches across active repositories.",
      orgRulesets.length > 0 && protectedCount < repoCount
        ? "Org-wide rulesets exist, but this v1 check cannot prove which repos they target. Confirm org-ruleset targeting in the GitHub UI."
        : undefined,
    ),
    buildFinding(
      "GITHUB-REPO-003",
      repoCount === 0 ? "Info" : (signedCount === repoCount ? "Pass" : (signedCount > 0 ? "Partial" : "Fail")),
      repoCount === 0
        ? "No active repositories were found to assess commit-signature posture."
        : `${signedCount} of ${repoCount} active repositories showed signed-commit enforcement.`,
      [
        `signed_commit_enforced_repos = ${signedCount}/${repoCount}`,
      ],
      "Require signed commits or equivalent integrity enforcement for protected branches.",
    ),
    buildFinding(
      "GITHUB-REPO-004",
      repoCount === 0 ? "Info" : (bypassRestrictedCount === repoCount ? "Pass" : (bypassRestrictedCount > 0 ? "Partial" : "Fail")),
      repoCount === 0
        ? "No active repositories were found to assess bypass restrictions."
        : `${bypassRestrictedCount} of ${repoCount} active repositories showed force-push/deletion restrictions through rulesets or branch protection.`,
      [
        `repos_with_bypass_restrictions = ${bypassRestrictedCount}/${repoCount}`,
      ],
      "Restrict force pushes and branch deletions on protected branches so administrative bypass stays exceptional.",
    ),
    buildFinding(
      "GITHUB-REPO-005",
      webCommitSignoffRequired === true ? "Pass" : (webCommitSignoffRequired === false ? "Partial" : "Manual"),
      webCommitSignoffRequired === true
        ? "Web commit signoff is required at the organization level."
        : (webCommitSignoffRequired === false
          ? "Web commit signoff is not required at the organization level."
          : "The tool could not confirm the organization's web commit signoff setting."),
      [
        `web_commit_signoff_required = ${String(webCommitSignoffRequired)}`,
      ],
      "Require web commit signoff so browser-based changes retain author intent and acknowledgment.",
    ),
  ];

  return {
    category: "repo_protection",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      active_repositories: repoCount,
      active_org_rulesets: orgRulesets.length,
      protected_repositories: protectedCount,
      signed_commit_repositories: signedCount,
      bypass_restricted_repositories: bypassRestrictedCount,
    },
    text: buildAssessmentText("GitHub repository protection assessment", config.organization, findings),
  };
}

export function assessGitHubActionsSecurity(
  data: GitHubActionsData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const actionsPermissions = data.actionsPermissions.data ?? null;
  const selectedActions = data.selectedActions.data ?? null;
  const workflowPermissions = data.workflowPermissions.data ?? null;

  const enabledRepositories = safeLower(actionsPermissions && asRecord(actionsPermissions).enabled_repositories) ?? "unknown";
  const allowedActions = safeLower(actionsPermissions && asRecord(actionsPermissions).allowed_actions)
    ?? safeLower(selectedActions && asRecord(selectedActions).allowed_actions)
    ?? "unknown";
  const defaultWorkflowPermissions = safeLower(workflowPermissions && asRecord(workflowPermissions).default_workflow_permissions) ?? "unknown";
  const canApprove = asBoolean(workflowPermissions && asRecord(workflowPermissions).can_approve_pull_request_reviews);
  const runnerCount = data.runners.data.length;
  const runnerGroupCount = data.runnerGroups.data.length;
  const openRunnerGroups = data.runnerGroups.data.filter((group) => {
    const visibility = safeLower(group.visibility);
    const allowsPublicRepos = asBoolean(group.allows_public_repositories);
    return visibility === "all" || allowsPublicRepos === true;
  }).length;

  const findings: GitHubFinding[] = [
    buildFinding(
      "GITHUB-ACT-001",
      allowedActions === "selected" || allowedActions === "local_only"
        ? "Pass"
        : (allowedActions === "all" ? "Fail" : "Manual"),
      allowedActions === "selected" || allowedActions === "local_only"
        ? `Allowed GitHub Actions policy is constrained to ${allowedActions}.`
        : (allowedActions === "all"
          ? "Allowed GitHub Actions policy permits all external actions."
          : "The tool could not confirm the allowed-actions policy."),
      [
        `allowed_actions = ${allowedActions}`,
        selectedActions ? `patterns_allowed = ${asArray(asRecord(selectedActions).patterns_allowed).length}` : "selected-actions details unavailable",
      ],
      "Restrict Actions to selected and trusted sources rather than allowing arbitrary third-party workflow code.",
    ),
    buildFinding(
      "GITHUB-ACT-002",
      defaultWorkflowPermissions === "read" ? "Pass" : (defaultWorkflowPermissions === "write" ? "Fail" : "Manual"),
      defaultWorkflowPermissions === "read"
        ? "Default workflow token permissions are read-only."
        : (defaultWorkflowPermissions === "write"
          ? "Default workflow token permissions are write-enabled."
          : "The tool could not confirm default workflow token permissions."),
      [
        `default_workflow_permissions = ${defaultWorkflowPermissions}`,
      ],
      "Set the default workflow token permission level to read and grant write access only where needed per workflow.",
    ),
    buildFinding(
      "GITHUB-ACT-003",
      canApprove === false ? "Pass" : (canApprove === true ? "Fail" : "Manual"),
      canApprove === false
        ? "GitHub Actions workflows cannot approve pull-request reviews."
        : (canApprove === true
          ? "GitHub Actions workflows can approve pull-request reviews."
          : "The tool could not confirm whether workflows can approve pull-request reviews."),
      [
        `can_approve_pull_request_reviews = ${String(canApprove)}`,
      ],
      "Disable workflow-based pull-request approval so CI does not satisfy its own review gates.",
    ),
    buildFinding(
      "GITHUB-ACT-004",
      runnerCount === 0 ? "Pass" : (runnerGroupCount > 0 && openRunnerGroups === 0 ? "Pass" : "Partial"),
      runnerCount === 0
        ? "No self-hosted runners were found."
        : `${runnerCount} self-hosted runner(s) and ${runnerGroupCount} runner group(s) were found; ${openRunnerGroups} runner group(s) appear broadly exposed.`,
      [
        `self_hosted_runners = ${runnerCount}`,
        `runner_groups = ${runnerGroupCount}`,
        `open_runner_groups = ${openRunnerGroups}`,
      ],
      "Scope self-hosted runners to the smallest practical repository set and avoid broad public or org-wide exposure unless it is deliberate.",
      runnerCount > 0 ? "Review runner-group targeting and workflow restrictions manually for sensitive repos." : undefined,
    ),
    buildFinding(
      "GITHUB-ACT-005",
      enabledRepositories === "selected" ? "Pass" : (enabledRepositories === "all" ? "Partial" : "Manual"),
      enabledRepositories === "selected"
        ? "GitHub Actions is limited to selected repositories."
        : (enabledRepositories === "all"
          ? "GitHub Actions is enabled for all repositories in the organization."
          : "The tool could not confirm how broadly Actions is enabled."),
      [
        `enabled_repositories = ${enabledRepositories}`,
      ],
      "Use selected-repository enablement when you need tighter CI change control or a phased rollout.",
    ),
  ];

  return {
    category: "actions_security",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      runner_groups: datasetSnapshotCount(data.runnerGroups),
      runners: datasetSnapshotCount(data.runners),
      enabled_repositories: enabledRepositories,
      allowed_actions: allowedActions,
      default_workflow_permissions: defaultWorkflowPermissions,
    },
    text: buildAssessmentText("GitHub Actions security assessment", config.organization, findings),
  };
}

export function assessGitHubCodeSecurity(
  data: GitHubCodeSecurityData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const org = data.org.data ?? null;
  const configs = data.codeSecurityConfigurations.data;
  const primaryConfigs = selectPrimaryCodeSecurityConfigurations(configs);
  const secretScanningDefault = asBoolean(org && asRecord(org).secret_scanning_enabled_for_new_repositories)
    ?? primaryConfigs.some((entry) => featureEnabled(asRecord(entry).secret_scanning));
  const pushProtectionDefault = asBoolean(org && asRecord(org).secret_scanning_push_protection_enabled_for_new_repositories)
    ?? primaryConfigs.some((entry) => featureEnabled(asRecord(entry).secret_scanning_push_protection));
  const dependabotDefault = asBoolean(org && asRecord(org).dependabot_alerts_enabled_for_new_repositories)
    ?? primaryConfigs.some((entry) => featureEnabled(asRecord(entry).dependabot_alerts));
  const dependabotUpdatesDefault = asBoolean(org && asRecord(org).dependabot_security_updates_enabled_for_new_repositories)
    ?? primaryConfigs.some((entry) => featureEnabled(asRecord(entry).dependabot_security_updates));
  const codeScanningDefault = primaryConfigs.some((entry) => featureEnabled(asRecord(entry).code_scanning_default_setup));

  const findings: GitHubFinding[] = [
    buildFinding(
      "GITHUB-CODE-001",
      configs.length > 0 ? "Pass" : "Partial",
      configs.length > 0
        ? `${configs.length} code security configuration(s) were found at the organization layer.`
        : "No organization-level code security configurations were found.",
      [
        `code_security_configurations = ${configs.length}`,
        `primary_configurations = ${primaryConfigs.length}`,
      ],
      "Define code security configurations so repository defaults are managed centrally instead of relying only on ad hoc per-repo toggles.",
    ),
    buildFinding(
      "GITHUB-CODE-002",
      secretScanningDefault === true ? "Pass" : (secretScanningDefault === false ? "Fail" : "Manual"),
      secretScanningDefault === true
        ? "Secret scanning defaults are enabled for new repositories."
        : (secretScanningDefault === false
          ? "Secret scanning defaults are not enabled for new repositories."
          : "The tool could not confirm secret-scanning defaults."),
      [
        `secret_scanning_default = ${String(secretScanningDefault)}`,
      ],
      "Enable secret scanning by default for new repositories and align repo enrollment with an org security configuration when available.",
    ),
    buildFinding(
      "GITHUB-CODE-003",
      pushProtectionDefault === true ? "Pass" : (pushProtectionDefault === false ? "Fail" : "Manual"),
      pushProtectionDefault === true
        ? "Secret scanning push protection defaults are enabled."
        : (pushProtectionDefault === false
          ? "Secret scanning push protection defaults are not enabled."
          : "The tool could not confirm push-protection defaults."),
      [
        `push_protection_default = ${String(pushProtectionDefault)}`,
      ],
      "Enable push protection so secret exposures are blocked before they land in the repository history.",
    ),
    buildFinding(
      "GITHUB-CODE-004",
      dependabotDefault === true && dependabotUpdatesDefault === true
        ? "Pass"
        : ((dependabotDefault === true || dependabotUpdatesDefault === true) ? "Partial" : "Fail"),
      dependabotDefault === true && dependabotUpdatesDefault === true
        ? "Dependabot alerts and security updates are enabled by default."
        : `Dependabot defaults are incomplete (alerts=${String(dependabotDefault)}, security_updates=${String(dependabotUpdatesDefault)}).`,
      [
        `dependabot_alerts_default = ${String(dependabotDefault)}`,
        `dependabot_security_updates_default = ${String(dependabotUpdatesDefault)}`,
      ],
      "Enable both Dependabot alerts and security updates so vulnerable dependencies are surfaced and can be remediated quickly.",
    ),
    buildFinding(
      "GITHUB-CODE-005",
      codeScanningDefault ? "Pass" : "Partial",
      codeScanningDefault
        ? "Code scanning default setup is enabled through an organization configuration."
        : "The tool did not find code scanning default setup enabled in the available org security configurations.",
      [
        `code_scanning_default_setup = ${String(codeScanningDefault)}`,
      ],
      "Enable code scanning default setup where supported so repositories inherit baseline static-analysis coverage.",
    ),
  ];

  return {
    category: "code_security",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      code_security_configurations: configs.length,
      repositories: datasetSnapshotCount(data.repositories),
      secret_scanning_default: String(secretScanningDefault),
      push_protection_default: String(pushProtectionDefault),
      dependabot_default: `${String(dependabotDefault)}/${String(dependabotUpdatesDefault)}`,
      code_scanning_default_setup: String(codeScanningDefault),
    },
    text: buildAssessmentText("GitHub code security assessment", config.organization, findings),
  };
}

export async function exportGitHubAuditBundle(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listMembers"
    | "listOutsideCollaborators"
    | "listInvitations"
    | "listOrganizationRoles"
    | "listCredentialAuthorizations"
    | "listAuditLog"
    | "listHooks"
    | "listInstallations"
    | "listRepositories"
    | "listOrgRulesets"
    | "listRepoRulesets"
    | "getBranchProtection"
    | "getOrgActionsPermissions"
    | "getOrgSelectedActions"
    | "getOrgWorkflowPermissions"
    | "listRunnerGroups"
    | "listRunners"
    | "listCodeSecurityConfigurations"
  >,
  config: GitHubResolvedConfig,
  outputRoot: string,
): Promise<GitHubAuditBundleResult> {
  const orgAccess = await collectGitHubOrgAccessData(client, config);
  const repoProtection = await collectGitHubRepoProtectionData(client);
  const actions = await collectGitHubActionsData(client);
  const codeSecurity = await collectGitHubCodeSecurityData(client);

  const assessments = [
    assessGitHubOrgAccess(orgAccess, config),
    assessGitHubRepoProtection(repoProtection, config),
    assessGitHubActionsSecurity(actions, config),
    assessGitHubCodeSecurity(codeSecurity, config),
  ];

  const errors = [
    ...listErrors(Object.values(orgAccess)),
    ...listErrors(Object.values(repoProtection)),
    ...listErrors(Object.values(actions)),
    ...listErrors(Object.values(codeSecurity)),
  ];

  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    safeDirName(`${config.organization}-audit-bundle`),
  );

  await buildBundleReadme(outputDir);
  await writeSecureTextFile(outputDir, "config.json", serializeJson({
    organization: config.organization,
    auth_mode: config.authMode,
    api_base_url: config.apiBaseUrl,
    lookback_days: config.lookbackDays,
    source_chain: config.sourceChain,
  }));

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/org_access.json", orgAccess],
    ["core_data/repo_protection.json", repoProtection],
    ["core_data/actions_security.json", actions],
    ["core_data/code_security.json", codeSecurity],
  ];

  for (const [pathName, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathName, serializeJson(value));
  }

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
  }

  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(allFindings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(allFindings));

  const frameworkReports = buildFrameworkReports(allFindings);
  for (const [name, report] of Object.entries(frameworkReports)) {
    await writeSecureTextFile(outputDir, `compliance/frameworks/${name}.md`, `${report}\n`);
  }

  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);

  const files = await readdir(outputDir, { recursive: true });
  return {
    outputDir,
    zipPath,
    fileCount: countFilesInResult(files),
    findingCount: allFindings.length,
    errorCount: errors.length,
  };
}

export function registerGitHubTools(pi: any): void {
  const authParams = {
    organization: Type.Optional(
      Type.String({
        description:
          "GitHub organization login to assess. Falls back to GITHUB_ORG or GH_ORG.",
      }),
    ),
    auth_mode: Type.Optional(
      Type.String({
        description: "Optional auth mode override. Supported values: pat or app.",
      }),
    ),
    api_token: Type.Optional(
      Type.String({
        description: "Optional GitHub personal access token. Falls back to GITHUB_TOKEN or GH_TOKEN.",
      }),
    ),
    app_id: Type.Optional(
      Type.String({
        description: "Optional GitHub App ID for installation-token auth.",
      }),
    ),
    app_private_key: Type.Optional(
      Type.String({
        description: "Optional PEM private key for GitHub App auth.",
      }),
    ),
    app_private_key_path: Type.Optional(
      Type.String({
        description: "Optional path to a PEM private key file for GitHub App auth.",
      }),
    ),
    installation_id: Type.Optional(
      Type.Union([
        Type.String(),
        Type.Integer(),
      ], {
        description: "Optional GitHub App installation ID for installation-token auth.",
      }),
    ),
    enterprise: Type.Optional(
      Type.String({
        description: "Optional GitHub Enterprise slug for enterprise-level checks. Falls back to GITHUB_ENTERPRISE.",
      }),
    ),
    api_base_url: Type.Optional(
      Type.String({
        description: "Optional GitHub REST API base URL. Defaults to https://api.github.com and can be overridden for GHES-style deployments. Falls back to GITHUB_API_URL or GITHUB_API_BASE_URL.",
      }),
    ),
    graphql_url: Type.Optional(
      Type.String({
        description: "Optional GitHub GraphQL endpoint. Defaults to https://api.github.com/graphql (or HOSTNAME/api/graphql for GHES). Falls back to GITHUB_GRAPHQL_URL.",
      }),
    ),
    lookback_days: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: 180,
        description: "Optional org audit-log lookback window in days. Defaults to 30.",
      }),
    ),
  } as const;

  pi.registerTool({
    name: "github_check_access",
    label: "Check GitHub audit access",
    description:
      "Validate GitHub org-read access for a PAT or GitHub App and show which security-relevant org surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const result = await runGitHubAccessCheck(client, config);
        return renderAccessCheck(result);
      } catch (error) {
        return errorResult(
          `GitHub access check failed: ${summarizeError(error)}`,
          { tool: "github_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "github_assess_org_access",
    label: "Assess GitHub org access",
    description:
      "Review org-level access posture including 2FA enforcement, base permissions, outside collaborators, org roles, and audit-log visibility.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const data = await collectGitHubOrgAccessData(client, config);
        return renderAssessmentToolResult(assessGitHubOrgAccess(data, config));
      } catch (error) {
        return errorResult(
          `GitHub org-access assessment failed: ${summarizeError(error)}`,
          { tool: "github_assess_org_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "github_assess_repo_protection",
    label: "Assess GitHub repo protection",
    description:
      "Review GitHub repository rulesets, default-branch protection, signed-commit posture, and bypass restrictions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const data = await collectGitHubRepoProtectionData(client);
        return renderAssessmentToolResult(assessGitHubRepoProtection(data, config));
      } catch (error) {
        return errorResult(
          `GitHub repo-protection assessment failed: ${summarizeError(error)}`,
          { tool: "github_assess_repo_protection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "github_assess_actions_security",
    label: "Assess GitHub Actions security",
    description:
      "Review org-level Actions permissions, workflow-token defaults, self-approval posture, and self-hosted runner exposure.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const data = await collectGitHubActionsData(client);
        return renderAssessmentToolResult(assessGitHubActionsSecurity(data, config));
      } catch (error) {
        return errorResult(
          `GitHub Actions security assessment failed: ${summarizeError(error)}`,
          { tool: "github_assess_actions_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "github_assess_code_security",
    label: "Assess GitHub code security",
    description:
      "Review GitHub code-security configurations, secret scanning, push protection, Dependabot defaults, and code-scanning posture.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const data = await collectGitHubCodeSecurityData(client);
        return renderAssessmentToolResult(assessGitHubCodeSecurity(data, config));
      } catch (error) {
        return errorResult(
          `GitHub code-security assessment failed: ${summarizeError(error)}`,
          { tool: "github_assess_code_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "github_export_audit_bundle",
    label: "Export GitHub audit bundle",
    description:
      "Collect the focused GitHub org, repo, Actions, and code-security evidence set, then write a zipped multi-framework audit bundle to disk.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root for the GitHub audit bundle. Defaults to ${DEFAULT_OUTPUT_DIR}.`,
        }),
      ),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: RawConfigArgs & { output_dir?: string }) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const result = await exportGitHubAuditBundle(
          client,
          config,
          args.output_dir?.trim() || DEFAULT_OUTPUT_DIR,
        );
        return textResult(buildExportText(config, result), {
          organization: config.organization,
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          file_count: result.fileCount,
          finding_count: result.findingCount,
          error_count: result.errorCount,
        });
      } catch (error) {
        return errorResult(
          `GitHub audit export failed: ${summarizeError(error)}`,
          { tool: "github_export_audit_bundle" },
        );
      }
    },
  });
}
