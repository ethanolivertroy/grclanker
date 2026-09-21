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
const GRAPHQL_PAGE_SIZE = 100;
const MAX_GRAPHQL_PAGES = 50;

// Field names verified against https://docs.github.com/public/fpt/schema.docs.graphql
// (Organization.samlIdentityProvider, OrganizationIdentityProvider.externalIdentities,
// ExternalIdentity.samlIdentity/scimIdentity/user, Organization.requiresTwoFactorAuthentication).
const ORGANIZATION_SAML_QUERY = `
query GrclankerOrganizationSaml($login: String!, $first: Int!, $after: String) {
  organization(login: $login) {
    login
    requiresTwoFactorAuthentication
    samlIdentityProvider {
      ssoUrl
      issuer
      digestMethod
      signatureMethod
      externalIdentities(first: $first, after: $after, membersOnly: true) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes {
          guid
          samlIdentity { nameId username }
          scimIdentity { username }
          user { login }
        }
      }
    }
  }
}`;

// Organization.ipAllowListEnabledSetting, ipAllowListForInstalledAppsEnabledSetting,
// ipAllowListEntries (IpAllowListEntry.allowListValue/isActive/name/createdAt) per the public schema.
const ORGANIZATION_IP_ALLOW_LIST_QUERY = `
query GrclankerOrganizationIpAllowList($login: String!, $first: Int!, $after: String) {
  organization(login: $login) {
    login
    ipAllowListEnabledSetting
    ipAllowListForInstalledAppsEnabledSetting
    ipAllowListEntries(first: $first, after: $after) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes { allowListValue isActive name createdAt }
    }
  }
}`;

// Enterprise.ownerInfo (EnterpriseOwnerInfo) fields per the public schema. ownerInfo is visible to
// enterprise owners or their classic PATs with read:enterprise or admin:enterprise.
const ENTERPRISE_IDENTITY_QUERY = `
query GrclankerEnterpriseIdentity($slug: String!) {
  enterprise(slug: $slug) {
    slug
    ownerInfo {
      samlIdentityProvider { ssoUrl issuer }
      oidcProvider { providerType tenantId }
      twoFactorRequiredSetting
      affiliatedUsersWithTwoFactorDisabledExist
      ipAllowListEnabledSetting
      ipAllowListForInstalledAppsEnabledSetting
      ipAllowListUserLevelEnforcementEnabledSetting
    }
  }
}`;

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
  category: "org_access" | "repo_protection" | "actions_security" | "code_security" | "integrations";
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

export interface GitHubSamlIdentitySnapshot {
  requiresTwoFactorAuthentication: boolean | null;
  samlIdentityProvider: {
    ssoUrl: string | null;
    issuer: string | null;
    digestMethod: string | null;
    signatureMethod: string | null;
  } | null;
  externalIdentities: JsonRecord[];
  externalIdentitiesTotalCount: number | null;
  externalIdentitiesTruncated: boolean;
  errors: GitHubGraphqlError[];
}

export interface GitHubIpAllowListSnapshot {
  ipAllowListEnabledSetting: string | null;
  ipAllowListForInstalledAppsEnabledSetting: string | null;
  entries: JsonRecord[];
  entriesTotalCount: number | null;
  entriesTruncated: boolean;
  errors: GitHubGraphqlError[];
}

export interface GitHubEnterpriseIdentitySnapshot {
  slug: string;
  ownerInfo: JsonRecord | null;
  errors: GitHubGraphqlError[];
}

export interface GitHubPaginatedRecords {
  records: JsonRecord[];
  truncated: boolean;
}

export interface GitHubAuditLogSnapshot {
  events: JsonRecord[];
  truncated: boolean;
  limit: number;
  lookbackDays: number;
  createdSince: string;
  phrase: string;
}

interface GitHubOrgAccessData {
  org: CollectedDataset<JsonRecord | null>;
  members: CollectedDataset<JsonRecord[]>;
  adminMembers: CollectedDataset<JsonRecord[]>;
  twoFactorDisabledMembers: CollectedDataset<JsonRecord[]>;
  outsideCollaborators: CollectedDataset<JsonRecord[]>;
  invitations: CollectedDataset<JsonRecord[]>;
  organizationRoles: CollectedDataset<JsonRecord[]>;
  credentialAuthorizations: CollectedDataset<JsonRecord[]>;
  auditLog: CollectedDataset<GitHubAuditLogSnapshot>;
  hooks: CollectedDataset<JsonRecord[]>;
  appInstallations: CollectedDataset<JsonRecord[]>;
  samlIdentity: CollectedDataset<GitHubSamlIdentitySnapshot | null>;
  ipAllowList: CollectedDataset<GitHubIpAllowListSnapshot | null>;
  enterpriseIdentity: CollectedDataset<GitHubEnterpriseIdentitySnapshot | null>;
}

export interface GitHubBranchRulesEntry {
  rules: JsonRecord[] | null;
  error?: string;
}

interface GitHubRepoProtectionData {
  org: CollectedDataset<JsonRecord | null>;
  repositories: CollectedDataset<JsonRecord[]>;
  orgRulesets: CollectedDataset<JsonRecord[]>;
  repoRulesets: CollectedDataset<Record<string, JsonRecord[]>>;
  branchProtections: CollectedDataset<Record<string, JsonRecord | null>>;
  branchRules: CollectedDataset<Record<string, GitHubBranchRulesEntry>>;
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
  codeSecurityDefaults: CollectedDataset<JsonRecord[]>;
}

export interface GitHubRepoListEntry {
  items: JsonRecord[] | null;
  error?: string;
}

interface GitHubIntegrationsData {
  org: CollectedDataset<JsonRecord | null>;
  hooks: CollectedDataset<JsonRecord[]>;
  appInstallations: CollectedDataset<JsonRecord[]>;
  credentialAuthorizations: CollectedDataset<JsonRecord[]>;
  repositories: CollectedDataset<JsonRecord[]>;
  repoHooks: CollectedDataset<Record<string, GitHubRepoListEntry>>;
  deployKeys: CollectedDataset<Record<string, GitHubRepoListEntry>>;
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
  { key: "code_security_defaults", path: (org: string) => `/orgs/${org}/code-security/configurations/defaults` },
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
  "GITHUB-ORG-006": {
    id: "GITHUB-ORG-006",
    title: "SAML SSO is configured and members carry linked identities",
    category: "org_access",
    severity: "critical",
    frameworks: {
      fedramp: ["IA-2", "IA-8"],
      cmmc: ["AC.L2-3.1.1"],
      soc2: ["CC6.1"],
      cis: ["1.1.1"],
      pci_dss: ["8.3.1"],
      disa_stig: ["SRG-APP-000148"],
      irap: ["ISM-1557"],
      ismap: ["5.1.1"],
      general: ["single sign-on enforcement"],
    },
  },
  "GITHUB-ORG-007": {
    id: "GITHUB-ORG-007",
    title: "Enterprise-managed identity (EMU) governs member accounts",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-5"],
      cmmc: ["IA.L2-3.5.1"],
      soc2: ["CC6.1"],
      cis: ["1.1.3"],
      pci_dss: ["8.2.1"],
      disa_stig: ["SRG-APP-000163"],
      irap: ["ISM-1558"],
      ismap: ["5.1.3"],
      general: ["enterprise identity lifecycle"],
    },
  },
  "GITHUB-ORG-008": {
    id: "GITHUB-ORG-008",
    title: "IP allow list restricts organization access",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["SC-7", "AC-17"],
      cmmc: ["SC.L2-3.13.1"],
      soc2: ["CC6.1", "CC6.6"],
      cis: ["1.2.1"],
      pci_dss: ["1.3.1"],
      disa_stig: ["SRG-APP-000142"],
      irap: ["ISM-1416"],
      ismap: ["5.1.4"],
      general: ["network boundary for source access"],
    },
  },
  "GITHUB-ORG-009": {
    id: "GITHUB-ORG-009",
    title: "Members cannot create public repositories",
    category: "org_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-3", "AC-22"],
      cmmc: ["AC.L2-3.1.22"],
      soc2: ["CC6.1"],
      cis: ["1.3.2"],
      pci_dss: ["7.2.2"],
      disa_stig: ["SRG-APP-000211"],
      irap: ["ISM-0264"],
      ismap: ["5.2.2"],
      general: ["repository visibility defaults"],
    },
  },
  "GITHUB-ORG-010": {
    id: "GITHUB-ORG-010",
    title: "Private repository forking is restricted",
    category: "org_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-3", "AC-4"],
      cmmc: ["AC.L2-3.1.3"],
      soc2: ["CC6.1"],
      cis: ["1.3.3"],
      pci_dss: ["7.2.3"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0405"],
      ismap: ["5.2.3"],
      general: ["fork policy"],
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
  "GITHUB-REPO-006": {
    id: "GITHUB-REPO-006",
    title: "Default branches require approving pull request reviews",
    category: "repo_protection",
    severity: "high",
    frameworks: {
      fedramp: ["CM-3", "CM-5"],
      cmmc: ["CM.L2-3.4.5"],
      soc2: ["CC8.1"],
      cis: ["2.1.2"],
      pci_dss: ["6.5.2"],
      disa_stig: ["SRG-APP-000381"],
      irap: ["ISM-1525"],
      ismap: ["5.3.2"],
      general: ["peer review before merge"],
    },
  },
  "GITHUB-REPO-007": {
    id: "GITHUB-REPO-007",
    title: "Default branches require passing status checks",
    category: "repo_protection",
    severity: "high",
    frameworks: {
      fedramp: ["SI-7", "SA-11"],
      cmmc: ["SA.L2-3.13.10"],
      soc2: ["CC8.1"],
      cis: ["2.1.3"],
      pci_dss: ["6.5.3"],
      disa_stig: ["SRG-APP-000456"],
      irap: ["ISM-1525"],
      ismap: ["5.3.3"],
      general: ["automated verification before merge"],
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
  "GITHUB-INTEG-001": {
    id: "GITHUB-INTEG-001",
    title: "Webhooks use HTTPS, TLS verification, and a shared secret",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["SC-8", "SI-4"],
      cmmc: ["SC.L2-3.13.8"],
      soc2: ["CC6.7"],
      cis: ["4.1.2"],
      pci_dss: ["4.2.1"],
      disa_stig: ["SRG-APP-000439"],
      irap: ["ISM-1139"],
      ismap: ["5.5.2"],
      general: ["webhook transport security"],
    },
  },
  "GITHUB-INTEG-002": {
    id: "GITHUB-INTEG-002",
    title: "Deploy keys are read-only and rotated",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-5", "SC-12"],
      cmmc: ["IA.L2-3.5.10"],
      soc2: ["CC6.1", "CC6.6"],
      cis: ["5.2.1"],
      pci_dss: ["8.6.3"],
      disa_stig: ["SRG-APP-000175"],
      irap: ["ISM-1590"],
      ismap: ["5.6.3"],
      general: ["machine credential hygiene"],
    },
  },
  "GITHUB-INTEG-003": {
    id: "GITHUB-INTEG-003",
    title: "GitHub App installations hold least-privilege permissions",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6(10)", "CM-11"],
      cmmc: ["AC.L2-3.1.7"],
      soc2: ["CC6.3", "CC6.8"],
      cis: ["5.2.2"],
      pci_dss: ["6.3.2"],
      disa_stig: ["SRG-APP-000342"],
      irap: ["ISM-1490"],
      ismap: ["5.6.4"],
      general: ["third-party app least privilege"],
    },
  },
  "GITHUB-INTEG-004": {
    id: "GITHUB-INTEG-004",
    title: "OAuth application access is restricted",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-3", "AC-6"],
      cmmc: ["AC.L2-3.1.5"],
      soc2: ["CC6.6", "CC6.8"],
      cis: ["1.4.1"],
      pci_dss: ["6.3.2"],
      disa_stig: ["SRG-APP-000386"],
      irap: ["ISM-1490"],
      ismap: ["5.2.5"],
      general: ["third-party OAuth governance"],
    },
  },
  "GITHUB-INTEG-005": {
    id: "GITHUB-INTEG-005",
    title: "Package registry visibility is governed",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-3", "AC-22"],
      cmmc: ["AC.L2-3.1.22"],
      soc2: ["CC6.1"],
      cis: ["5.3.1"],
      pci_dss: ["7.2.6"],
      disa_stig: ["SRG-APP-000211"],
      irap: ["ISM-0264"],
      ismap: ["5.6.5"],
      general: ["package registry access"],
    },
  },
  "GITHUB-ORG-011": {
    id: "GITHUB-ORG-011",
    title: "Audit log streaming delivers events to an external SIEM",
    category: "org_access",
    severity: "high",
    frameworks: {
      fedramp: ["AU-2", "AU-6", "SI-4"],
      cmmc: ["AU.L2-3.3.1"],
      soc2: ["CC7.2", "CC7.3"],
      cis: ["4.1.1"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000095"],
      irap: ["ISM-0580"],
      ismap: ["5.5.1"],
      general: ["audit log streaming"],
    },
  },
  "GITHUB-CODE-006": {
    id: "GITHUB-CODE-006",
    title: "Repositories publish a security policy",
    category: "code_security",
    severity: "low",
    frameworks: {
      fedramp: ["PL-2", "IR-8"],
      cmmc: ["IR.L2-3.6.1"],
      soc2: ["CC2.2"],
      cis: ["3.1.4"],
      pci_dss: ["12.10.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0043"],
      ismap: ["5.4.4"],
      general: ["security policy"],
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
  if (error instanceof GitHubHttpError) {
    return `GitHub request failed (${error.status}): ${error.message}`;
  }
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

  async listTwoFactorDisabledMembers(): Promise<JsonRecord[]> {
    return this.paginate(`/orgs/${this.config.organization}/members?per_page=${PAGE_SIZE}&filter=2fa_disabled`);
  }

  async getSamlIdentitySnapshot(): Promise<GitHubSamlIdentitySnapshot> {
    const snapshot: GitHubSamlIdentitySnapshot = {
      requiresTwoFactorAuthentication: null,
      samlIdentityProvider: null,
      externalIdentities: [],
      externalIdentitiesTotalCount: null,
      externalIdentitiesTruncated: false,
      errors: [],
    };
    let after: string | null = null;
    let pages = 0;

    while (pages < MAX_GRAPHQL_PAGES) {
      const result: GitHubGraphqlResult<JsonRecord> = await this.graphql<JsonRecord>(ORGANIZATION_SAML_QUERY, {
        login: this.config.organization,
        first: GRAPHQL_PAGE_SIZE,
        after,
      });
      pages += 1;
      snapshot.errors.push(...result.errors);
      const organization = asRecord(asRecord(result.data).organization);
      if (pages === 1) {
        snapshot.requiresTwoFactorAuthentication = asBoolean(organization.requiresTwoFactorAuthentication) ?? null;
      }
      const provider = organization.samlIdentityProvider;
      if (!provider || typeof provider !== "object") {
        break;
      }
      const providerRecord = asRecord(provider);
      if (!snapshot.samlIdentityProvider) {
        snapshot.samlIdentityProvider = {
          ssoUrl: asString(providerRecord.ssoUrl) ?? null,
          issuer: asString(providerRecord.issuer) ?? null,
          digestMethod: asString(providerRecord.digestMethod) ?? null,
          signatureMethod: asString(providerRecord.signatureMethod) ?? null,
        };
      }
      const connection = asRecord(providerRecord.externalIdentities);
      snapshot.externalIdentitiesTotalCount = asNumber(connection.totalCount) ?? snapshot.externalIdentitiesTotalCount;
      snapshot.externalIdentities.push(...asArray(connection.nodes).map((node) => asRecord(node)));
      const step = advanceGraphqlPage(asRecord(connection.pageInfo), after, pages);
      if (step.truncated) {
        snapshot.externalIdentitiesTruncated = true;
      }
      if (!step.nextCursor) {
        break;
      }
      after = step.nextCursor;
    }

    if (collectionFellShort(snapshot.externalIdentitiesTotalCount, snapshot.externalIdentities.length)) {
      snapshot.externalIdentitiesTruncated = true;
    }
    return snapshot;
  }

  async getIpAllowListSnapshot(): Promise<GitHubIpAllowListSnapshot> {
    const snapshot: GitHubIpAllowListSnapshot = {
      ipAllowListEnabledSetting: null,
      ipAllowListForInstalledAppsEnabledSetting: null,
      entries: [],
      entriesTotalCount: null,
      entriesTruncated: false,
      errors: [],
    };
    let after: string | null = null;
    let pages = 0;

    while (pages < MAX_GRAPHQL_PAGES) {
      const result: GitHubGraphqlResult<JsonRecord> = await this.graphql<JsonRecord>(ORGANIZATION_IP_ALLOW_LIST_QUERY, {
        login: this.config.organization,
        first: GRAPHQL_PAGE_SIZE,
        after,
      });
      pages += 1;
      snapshot.errors.push(...result.errors);
      const organization = asRecord(asRecord(result.data).organization);
      if (pages === 1) {
        snapshot.ipAllowListEnabledSetting = asString(organization.ipAllowListEnabledSetting) ?? null;
        snapshot.ipAllowListForInstalledAppsEnabledSetting = asString(organization.ipAllowListForInstalledAppsEnabledSetting) ?? null;
      }
      const connection = asRecord(organization.ipAllowListEntries);
      snapshot.entriesTotalCount = asNumber(connection.totalCount) ?? snapshot.entriesTotalCount;
      snapshot.entries.push(...asArray(connection.nodes).map((node) => asRecord(node)));
      const step = advanceGraphqlPage(asRecord(connection.pageInfo), after, pages);
      if (step.truncated) {
        snapshot.entriesTruncated = true;
      }
      if (!step.nextCursor) {
        break;
      }
      after = step.nextCursor;
    }

    if (collectionFellShort(snapshot.entriesTotalCount, snapshot.entries.length)) {
      snapshot.entriesTruncated = true;
    }
    return snapshot;
  }

  async getEnterpriseIdentitySnapshot(): Promise<GitHubEnterpriseIdentitySnapshot | null> {
    if (!this.config.enterprise) {
      return null;
    }
    const result = await this.graphql<JsonRecord>(ENTERPRISE_IDENTITY_QUERY, { slug: this.config.enterprise });
    const enterprise = asRecord(asRecord(result.data).enterprise);
    const ownerInfo = enterprise.ownerInfo && typeof enterprise.ownerInfo === "object"
      ? asRecord(enterprise.ownerInfo)
      : null;
    return {
      slug: this.config.enterprise,
      ownerInfo,
      errors: result.errors,
    };
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

  // The audit log `after` parameter is an opaque pagination cursor, not a timestamp; the lookback
  // window is expressed through the documented search phrase syntax (`created:>=YYYY-MM-DD`).
  async listAuditLog(lookbackDays: number = this.config.lookbackDays): Promise<GitHubAuditLogSnapshot> {
    const window = buildAuditLogWindow(lookbackDays);
    const { records, truncated } = await this.paginateWithStatus(
      `/orgs/${this.config.organization}/audit-log?per_page=${PAGE_SIZE}&include=all&phrase=${encodeURIComponent(window.phrase)}`,
      MAX_AUDIT_EVENTS,
    );
    return {
      events: records.map(projectAuditLogEvent),
      truncated,
      limit: MAX_AUDIT_EVENTS,
      lookbackDays,
      createdSince: window.createdSince,
      phrase: window.phrase,
    };
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

  async listBranchRules(owner: string, repo: string, branch: string): Promise<JsonRecord[]> {
    return this.paginate(`/repos/${owner}/${repo}/rules/branches/${encodeURIComponent(branch)}?per_page=${PAGE_SIZE}`);
  }

  async listRepoHooks(owner: string, repo: string): Promise<JsonRecord[]> {
    return this.paginate(`/repos/${owner}/${repo}/hooks?per_page=${PAGE_SIZE}`);
  }

  async listDeployKeys(owner: string, repo: string): Promise<JsonRecord[]> {
    return this.paginate(`/repos/${owner}/${repo}/keys?per_page=${PAGE_SIZE}`);
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

  // code-security/get-default-configurations: each entry pairs default_for_new_repos
  // (public | private_and_internal | all) with the configuration applied to that visibility.
  async listCodeSecurityDefaultConfigurations(): Promise<JsonRecord[]> {
    const { payload } = await this.requestJson(`/orgs/${this.config.organization}/code-security/configurations/defaults`);
    return extractRecords(payload);
  }

  private async paginate(pathname: string): Promise<JsonRecord[]> {
    const { records } = await this.paginateWithStatus(pathname, Number.POSITIVE_INFINITY);
    return records;
  }

  // Follows Link rel="next" until exhaustion or the record limit. Truncated is true only when
  // records were actually left behind: a page record dropped at the limit, or a next link still
  // advertised once the limit is reached. Exactly `limit` records with no next link is complete.
  private async paginateWithStatus(pathname: string, limit: number): Promise<GitHubPaginatedRecords> {
    const collected: JsonRecord[] = [];
    let nextPath: string | null = pathname;
    let truncated = false;

    while (nextPath) {
      const { response, payload } = await this.requestJson(nextPath);
      const pageRecords = extractRecords(payload);
      for (const record of pageRecords) {
        if (collected.length >= limit) {
          truncated = true;
          break;
        }
        collected.push(record);
      }
      if (truncated) break;

      nextPath = parseNextLink(response.headers.get("link"));
      if (nextPath && collected.length >= limit) {
        truncated = true;
        break;
      }
    }

    return { records: collected, truncated };
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

interface GraphqlPageStep {
  nextCursor: string | null;
  truncated: boolean;
}

// PageInfo.endCursor is nullable in the schema, so hasNextPage: true can arrive without a cursor;
// that exit, a repeating cursor, and the page cap all leave records unfetched and must report truncated.
export function advanceGraphqlPage(pageInfo: JsonRecord, previousCursor: string | null, pagesFetched: number): GraphqlPageStep {
  if (asBoolean(pageInfo.hasNextPage) !== true) {
    return { nextCursor: null, truncated: false };
  }
  const endCursor = asString(pageInfo.endCursor) ?? null;
  if (!endCursor || endCursor === previousCursor || pagesFetched >= MAX_GRAPHQL_PAGES) {
    return { nextCursor: null, truncated: true };
  }
  return { nextCursor: endCursor, truncated: false };
}

export function collectionFellShort(totalCount: number | null, collectedCount: number): boolean {
  return totalCount !== null && Number.isFinite(totalCount) && totalCount > collectedCount;
}

export function buildAuditLogWindow(lookbackDays: number, now: Date = new Date()): { createdSince: string; phrase: string } {
  const days = Number.isFinite(lookbackDays) && lookbackDays > 0 ? Math.floor(lookbackDays) : 1;
  const since = new Date(now.getTime() - (days * 24 * 60 * 60 * 1000));
  const createdSince = since.toISOString().slice(0, 10);
  return { createdSince, phrase: `created:>=${createdSince}` };
}

export function emptyAuditLogSnapshot(lookbackDays: number): GitHubAuditLogSnapshot {
  const window = buildAuditLogWindow(lookbackDays);
  return {
    events: [],
    truncated: false,
    limit: MAX_AUDIT_EVENTS,
    lookbackDays,
    createdSince: window.createdSince,
    phrase: window.phrase,
  };
}

// Audit log events carry unconstrained bags (config, config_was, data, additionalProperties) that
// can hold webhook secrets and key material; only the identifying fields the verdicts read persist.
const AUDIT_LOG_EVENT_FIELDS = [
  "@timestamp",
  "created_at",
  "action",
  "operation_type",
  "actor",
  "actor_id",
  "user",
  "user_id",
  "org",
  "org_id",
  "repo",
  "repo_id",
  "business",
  "business_id",
  "_document_id",
] as const;

export function projectAuditLogEvent(event: JsonRecord): JsonRecord {
  return pickFields(event, AUDIT_LOG_EVENT_FIELDS);
}

function pickFields(record: JsonRecord, fields: readonly string[]): JsonRecord {
  const projected: JsonRecord = {};
  for (const field of fields) {
    if (record[field] !== undefined) {
      projected[field] = record[field];
    }
  }
  return projected;
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
      `${finding.id}: ${finding.summary}`,
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

function rulesIncludeType(rules: JsonRecord[], type: string): boolean {
  return rules.some((rule) => safeLower(rule.type) === type);
}

function branchProtectionRequiresSignatures(protection: JsonRecord | null): boolean {
  if (!protection) return false;
  const requiredSignatures = asRecord(protection.required_signatures);
  return asBoolean(requiredSignatures.enabled) === true;
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

async function buildBundleQuickReference(rootDir: string): Promise<void> {
  await writeSecureTextFile(
    rootDir,
    "QUICK_REFERENCE.md",
    [
      "# GitHub Audit Bundle Quick Reference",
      "",
      "- `core_data/` contains the raw GitHub API payloads collected for this assessment.",
      "- `analysis/` contains normalized findings in JSON (findings.json plus one file per assessment category).",
      "- `compliance/` contains the executive summary, unified matrix, and per-framework reports under frameworks/.",
      "- `_errors.log` is present only when one or more collectors failed; every finding that depended on a failed collector is Manual or Partial, never Pass.",
      "- The paired `.zip` next to this directory carries the same name, so a rerun allocates a new directory and archive instead of overwriting this one.",
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
    | "listTwoFactorDisabledMembers"
    | "listOutsideCollaborators"
    | "listInvitations"
    | "listOrganizationRoles"
    | "listCredentialAuthorizations"
    | "listAuditLog"
    | "listHooks"
    | "listInstallations"
    | "getSamlIdentitySnapshot"
    | "getIpAllowListSnapshot"
    | "getEnterpriseIdentitySnapshot"
  >,
  config: GitHubResolvedConfig,
): Promise<GitHubOrgAccessData> {
  return {
    org: await collectDataset<JsonRecord | null>(null, () => client.getOrganization()),
    members: await collectDataset<JsonRecord[]>([], () => client.listMembers("all")),
    adminMembers: await collectDataset<JsonRecord[]>([], () => client.listMembers("admin")),
    twoFactorDisabledMembers: await collectDataset<JsonRecord[]>([], () => client.listTwoFactorDisabledMembers()),
    outsideCollaborators: await collectDataset<JsonRecord[]>([], () => client.listOutsideCollaborators()),
    invitations: await collectDataset<JsonRecord[]>([], () => client.listInvitations()),
    organizationRoles: await collectDataset<JsonRecord[]>([], () => client.listOrganizationRoles()),
    credentialAuthorizations: await collectDataset<JsonRecord[]>([], () => client.listCredentialAuthorizations()),
    auditLog: await collectDataset<GitHubAuditLogSnapshot>(emptyAuditLogSnapshot(config.lookbackDays), () => client.listAuditLog(config.lookbackDays)),
    hooks: await collectDataset<JsonRecord[]>([], () => client.listHooks()),
    appInstallations: await collectDataset<JsonRecord[]>([], () => client.listInstallations()),
    samlIdentity: await collectDataset<GitHubSamlIdentitySnapshot | null>(null, () => client.getSamlIdentitySnapshot()),
    ipAllowList: await collectDataset<GitHubIpAllowListSnapshot | null>(null, () => client.getIpAllowListSnapshot()),
    enterpriseIdentity: await collectDataset<GitHubEnterpriseIdentitySnapshot | null>(null, () => client.getEnterpriseIdentitySnapshot()),
  };
}

function graphqlErrorsForPath(errors: GitHubGraphqlError[], segment: string): GitHubGraphqlError[] {
  return errors.filter((error) => (error.path ?? []).some((part) => part === segment) || (error.path ?? []).length === 0);
}

function describeGraphqlErrors(errors: GitHubGraphqlError[]): string {
  return errors.map((error) => `${error.type ?? "ERROR"}: ${error.message}`).join("; ");
}

function assessTwoFactor(data: GitHubOrgAccessData): GitHubFinding {
  const org = data.org.data ?? null;
  const twoFactorRequired = asBoolean(org && asRecord(org).two_factor_requirement_enabled);
  const disabledMembers = data.twoFactorDisabledMembers;
  const disabledLogins = disabledMembers.data.map((member) => asString(member.login) ?? "unknown");
  const evidence = [
    twoFactorRequired !== undefined
      ? `two_factor_requirement_enabled = ${String(twoFactorRequired)}`
      : `Organization 2FA setting was not readable from the org profile response${data.org.error ? ` (${data.org.error})` : ""}.`,
    disabledMembers.error
      ? `members?filter=2fa_disabled unreadable: ${disabledMembers.error} (the filter is documented as owner-only)`
      : `members_without_2fa = ${disabledLogins.length}${disabledLogins.length > 0 ? ` (${disabledLogins.slice(0, 10).join(", ")}${disabledLogins.length > 10 ? ", ..." : ""})` : ""}`,
  ];
  const recommendation = "Require 2FA at the organization level and remove or remediate every member the 2fa_disabled filter still returns.";

  if (twoFactorRequired === undefined) {
    return buildFinding(
      "GITHUB-ORG-001",
      "Manual",
      "The tool could not read the organization 2FA requirement, so the control is unverified.",
      evidence,
      recommendation,
      "Confirm the org-wide 2FA requirement in Settings > Authentication security with an org owner, and export the member list filtered to 2FA disabled.",
    );
  }
  if (twoFactorRequired === false) {
    return buildFinding(
      "GITHUB-ORG-001",
      "Fail",
      disabledMembers.error
        ? "The organization does not require two-factor authentication; member enumeration by 2FA status was also unreadable."
        : `The organization does not require two-factor authentication; ${disabledLogins.length} member(s) currently have 2FA disabled.`,
      evidence,
      recommendation,
    );
  }
  if (disabledMembers.error) {
    return buildFinding(
      "GITHUB-ORG-001",
      "Partial",
      "The organization requires 2FA, but the tool could not enumerate members without 2FA because the owner-only filter was not readable.",
      evidence,
      recommendation,
      "Run the assessment with an organization owner token (or owner-installed app) so the 2fa_disabled filter is honored, or export the member list from the org People page.",
    );
  }
  if (disabledLogins.length > 0) {
    return buildFinding(
      "GITHUB-ORG-001",
      "Fail",
      `The organization requires 2FA, yet ${disabledLogins.length} member(s) were returned by the 2fa_disabled filter.`,
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-ORG-001",
    "Pass",
    `The organization requires two-factor authentication and the 2fa_disabled member filter returned no members (${data.members.data.length} member(s) enumerated).`,
    evidence,
    recommendation,
  );
}

function assessSamlSso(data: GitHubOrgAccessData): GitHubFinding {
  const recommendation = "Configure SAML SSO (or enterprise-level SSO with EMU), require SSO for the organization, and make sure every member has a linked external identity.";
  const snapshot = data.samlIdentity.data;
  if (data.samlIdentity.error || !snapshot) {
    return buildFinding(
      "GITHUB-ORG-006",
      "Manual",
      "The tool could not query the organization SAML identity provider through GraphQL.",
      [`graphql_error = ${data.samlIdentity.error ?? "no data returned"}`],
      recommendation,
      "Confirm SAML SSO status in Settings > Authentication security with an org owner token that is SSO-authorized.",
    );
  }

  const providerErrors = graphqlErrorsForPath(snapshot.errors, "samlIdentityProvider");
  const enterpriseOwnerInfo = data.enterpriseIdentity.data?.ownerInfo ?? null;
  const enterpriseSaml = enterpriseOwnerInfo && asRecord(enterpriseOwnerInfo.samlIdentityProvider);
  const enterpriseOidc = enterpriseOwnerInfo && asRecord(enterpriseOwnerInfo.oidcProvider);
  const enterpriseIdentityConfigured = Boolean(
    (enterpriseSaml && Object.keys(enterpriseSaml).length > 0) || (enterpriseOidc && Object.keys(enterpriseOidc).length > 0),
  );
  const members = data.members;
  const memberCount = members.data.length;

  if (!snapshot.samlIdentityProvider) {
    if (providerErrors.length > 0) {
      return buildFinding(
        "GITHUB-ORG-006",
        "Manual",
        "GraphQL refused to return the organization SAML identity provider, so SSO status is unverified.",
        [`samlIdentityProvider errors = ${describeGraphqlErrors(providerErrors)}`],
        recommendation,
        "samlIdentityProvider is visible only to org owners, owner PATs with read:org or admin:org, or an app installation with members read access. Rerun with such a principal or confirm SSO in the org settings UI.",
      );
    }
    if (enterpriseIdentityConfigured) {
      return buildFinding(
        "GITHUB-ORG-006",
        "Pass",
        `No organization-level SAML provider exists, but the enterprise ${data.enterpriseIdentity.data?.slug ?? ""} carries an identity provider (${enterpriseOidc && Object.keys(enterpriseOidc).length > 0 ? "OIDC" : "SAML"}), which governs this organization.`,
        [
          "organization.samlIdentityProvider = null",
          `enterprise.ownerInfo.samlIdentityProvider = ${enterpriseSaml && Object.keys(enterpriseSaml).length > 0 ? JSON.stringify(enterpriseSaml) : "null"}`,
          `enterprise.ownerInfo.oidcProvider = ${enterpriseOidc && Object.keys(enterpriseOidc).length > 0 ? JSON.stringify(enterpriseOidc) : "null"}`,
        ],
        recommendation,
      );
    }
    return buildFinding(
      "GITHUB-ORG-006",
      "Fail",
      "No SAML identity provider is configured for the organization" + (data.enterpriseIdentity.data ? " or its enterprise." : "; no enterprise slug was supplied to check enterprise-level SSO."),
      [
        "organization.samlIdentityProvider = null",
        data.enterpriseIdentity.data
          ? `enterprise ${data.enterpriseIdentity.data.slug} ownerInfo = ${enterpriseOwnerInfo ? "readable, no identity provider" : `unreadable (${describeGraphqlErrors(data.enterpriseIdentity.data.errors) || "no ownerInfo"})`}`
          : "enterprise = not configured (set GITHUB_ENTERPRISE to evaluate enterprise-level SSO)",
      ],
      recommendation,
    );
  }

  const linked = snapshot.externalIdentities.filter((identity) => {
    const user = asRecord(identity.user);
    return asString(user.login) !== undefined && Object.keys(asRecord(identity.samlIdentity)).length > 0;
  });
  const linkedLogins = new Set(linked.map((identity) => asString(asRecord(identity.user).login)?.toLowerCase()));
  const unlinkedMembers = members.data
    .map((member) => asString(member.login) ?? "")
    .filter((login) => login.length > 0 && !linkedLogins.has(login.toLowerCase()));
  const evidence = [
    `samlIdentityProvider.ssoUrl = ${snapshot.samlIdentityProvider.ssoUrl ?? "null"}`,
    `samlIdentityProvider.issuer = ${snapshot.samlIdentityProvider.issuer ?? "null"}`,
    `external_identities_linked_to_members = ${linked.length} (totalCount ${snapshot.externalIdentitiesTotalCount ?? "unknown"}${snapshot.externalIdentitiesTruncated ? ", truncated" : ""})`,
    members.error ? `members unreadable: ${members.error}` : `members = ${memberCount}, members_without_saml_identity = ${unlinkedMembers.length}${unlinkedMembers.length > 0 ? ` (${unlinkedMembers.slice(0, 10).join(", ")}${unlinkedMembers.length > 10 ? ", ..." : ""})` : ""}`,
    "Note: the public GraphQL schema exposes SAML configuration and identity links, not a separate 'require SSO' flag; complete linkage is the observable proxy.",
  ];

  if (members.error || snapshot.externalIdentitiesTruncated || providerErrors.length > 0) {
    return buildFinding(
      "GITHUB-ORG-006",
      "Partial",
      "SAML SSO is configured, but the member-to-identity comparison is incomplete (member list unreadable, identities truncated, or partial GraphQL errors).",
      [...evidence, ...(providerErrors.length > 0 ? [`graphql errors = ${describeGraphqlErrors(providerErrors)}`] : [])],
      recommendation,
      "Compare the SSO identity list with the member list in the org settings UI to confirm every member is linked.",
    );
  }
  if (memberCount === 0) {
    return buildFinding(
      "GITHUB-ORG-006",
      "Partial",
      "SAML SSO is configured, but zero members were enumerated, so identity linkage could not be demonstrated.",
      evidence,
      recommendation,
    );
  }
  if (unlinkedMembers.length > 0) {
    return buildFinding(
      "GITHUB-ORG-006",
      "Partial",
      `SAML SSO is configured, but ${unlinkedMembers.length} of ${memberCount} member(s) have no linked SAML identity, which indicates SSO is not enforced for them.`,
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-ORG-006",
    "Pass",
    `SAML SSO is configured and all ${memberCount} member(s) carry a linked SAML identity.`,
    evidence,
    recommendation,
  );
}

function assessEnterpriseManagedUsers(data: GitHubOrgAccessData): GitHubFinding {
  const recommendation = "Use Enterprise Managed Users (or at minimum an enterprise-level identity provider) so member accounts are provisioned and deprovisioned by the corporate IdP.";
  if (!data.enterpriseIdentity.data && !data.enterpriseIdentity.error) {
    return buildFinding(
      "GITHUB-ORG-007",
      "Manual",
      "Scoped out: no enterprise slug was configured, so enterprise identity management could not be evaluated.",
      ["enterprise = not configured (set GITHUB_ENTERPRISE or pass enterprise)"],
      recommendation,
      "Provide the enterprise slug and rerun, or confirm in the enterprise settings whether Enterprise Managed Users is enabled.",
    );
  }
  if (data.enterpriseIdentity.error || !data.enterpriseIdentity.data) {
    return buildFinding(
      "GITHUB-ORG-007",
      "Manual",
      "The enterprise identity query failed, so EMU status is unverified.",
      [`graphql_error = ${data.enterpriseIdentity.error ?? "no data returned"}`],
      recommendation,
      "Rerun with an enterprise owner token (read:enterprise or admin:enterprise) or confirm EMU in the enterprise settings UI.",
    );
  }

  const snapshot = data.enterpriseIdentity.data;
  if (!snapshot.ownerInfo) {
    return buildFinding(
      "GITHUB-ORG-007",
      "Manual",
      `enterprise.ownerInfo for ${snapshot.slug} was not readable, so EMU status is unverified.`,
      [`graphql errors = ${describeGraphqlErrors(snapshot.errors) || "ownerInfo returned null"}`],
      recommendation,
      "ownerInfo is visible only to enterprise owners or their classic PATs with read:enterprise or admin:enterprise.",
    );
  }

  const oidc = asRecord(snapshot.ownerInfo.oidcProvider);
  const saml = asRecord(snapshot.ownerInfo.samlIdentityProvider);
  const evidence = [
    `enterprise = ${snapshot.slug}`,
    `ownerInfo.oidcProvider = ${Object.keys(oidc).length > 0 ? JSON.stringify(oidc) : "null"}`,
    `ownerInfo.samlIdentityProvider = ${Object.keys(saml).length > 0 ? JSON.stringify(saml) : "null"}`,
    "Note: the public schema has no EMU boolean; OIDC providers exist only for EMU enterprises, while enterprise SAML is shared by EMU and non-EMU enterprises.",
  ];
  if (Object.keys(oidc).length > 0) {
    return buildFinding(
      "GITHUB-ORG-007",
      "Pass",
      `Enterprise ${snapshot.slug} authenticates through an OIDC identity provider, which GitHub offers only for Enterprise Managed Users.`,
      evidence,
      recommendation,
    );
  }
  if (Object.keys(saml).length > 0) {
    return buildFinding(
      "GITHUB-ORG-007",
      "Partial",
      `Enterprise ${snapshot.slug} has an enterprise-level SAML provider; the API cannot distinguish EMU from enterprise SAML, so confirm the account model manually.`,
      evidence,
      recommendation,
      "Check the enterprise Identity provider settings page: EMU enterprises show managed user provisioning (SCIM) and members with the enterprise shortcode suffix.",
    );
  }
  return buildFinding(
    "GITHUB-ORG-007",
    "Fail",
    `Enterprise ${snapshot.slug} has no enterprise-level identity provider, so member accounts are not enterprise managed.`,
    evidence,
    recommendation,
  );
}

function assessIpAllowList(data: GitHubOrgAccessData): GitHubFinding {
  const recommendation = "Enable the organization IP allow list with the corporate egress ranges, and enable it for installed GitHub Apps as well.";
  const snapshot = data.ipAllowList.data;
  if (data.ipAllowList.error || !snapshot) {
    return buildFinding(
      "GITHUB-ORG-008",
      "Manual",
      "The tool could not query IP allow list settings through GraphQL.",
      [`graphql_error = ${data.ipAllowList.error ?? "no data returned"}`],
      recommendation,
      "Confirm the IP allow list in Settings > Security > Authentication security with an org owner.",
    );
  }
  const errors = snapshot.errors;
  if (!snapshot.ipAllowListEnabledSetting) {
    return buildFinding(
      "GITHUB-ORG-008",
      "Manual",
      "GraphQL did not return ipAllowListEnabledSetting, so the IP allow list state is unverified.",
      [`graphql errors = ${describeGraphqlErrors(errors) || "field missing from response"}`],
      recommendation,
      "Rerun with an org owner principal or confirm the setting in the organization security settings UI.",
    );
  }
  const activeEntries = snapshot.entries.filter((entry) => asBoolean(entry.isActive) === true);
  const evidence = [
    `ipAllowListEnabledSetting = ${snapshot.ipAllowListEnabledSetting}`,
    `ipAllowListForInstalledAppsEnabledSetting = ${snapshot.ipAllowListForInstalledAppsEnabledSetting ?? "null"}`,
    `ip_allow_list_entries = ${snapshot.entries.length} (active ${activeEntries.length}, totalCount ${snapshot.entriesTotalCount ?? "unknown"}${snapshot.entriesTruncated ? ", truncated" : ""})`,
    ...activeEntries.slice(0, 10).map((entry) => `entry ${asString(entry.allowListValue) ?? "?"} (${asString(entry.name) ?? "unnamed"}, created ${asString(entry.createdAt) ?? "unknown"})`),
  ];
  if (snapshot.ipAllowListEnabledSetting !== "ENABLED") {
    return buildFinding(
      "GITHUB-ORG-008",
      "Fail",
      `The organization IP allow list is ${snapshot.ipAllowListEnabledSetting}.`,
      evidence,
      recommendation,
    );
  }
  if (errors.length > 0 || snapshot.entriesTruncated) {
    return buildFinding(
      "GITHUB-ORG-008",
      "Partial",
      "The IP allow list is enabled, but the entry inventory is incomplete (GraphQL errors or truncation), so coverage cannot be confirmed.",
      [...evidence, ...(errors.length > 0 ? [`graphql errors = ${describeGraphqlErrors(errors)}`] : [])],
      recommendation,
    );
  }
  if (activeEntries.length === 0) {
    return buildFinding(
      "GITHUB-ORG-008",
      "Partial",
      "The IP allow list is enabled but has no active entries; GitHub does not restrict access until at least one active entry exists.",
      evidence,
      recommendation,
    );
  }
  if (snapshot.ipAllowListForInstalledAppsEnabledSetting !== "ENABLED") {
    return buildFinding(
      "GITHUB-ORG-008",
      "Partial",
      `The IP allow list is enabled with ${activeEntries.length} active entries, but it is not applied to installed GitHub Apps.`,
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-ORG-008",
    "Pass",
    `The IP allow list is enabled with ${activeEntries.length} active entries and also applies to installed GitHub Apps.`,
    evidence,
    recommendation,
  );
}

// Deferred automation: audit log streaming configuration is an enterprise-level GHEC resource
// (GET /enterprises/{enterprise}/audit-log/streams, enterprise-admin/get-audit-log-streams) that
// needs an enterprise owner principal; the organization API has no streaming field.
function assessAuditLogStreaming(config: GitHubResolvedConfig): GitHubFinding {
  const enterprise = config.enterprise?.trim();
  return buildFinding(
    "GITHUB-ORG-011",
    "Manual",
    enterprise
      ? `Audit log streaming for enterprise ${enterprise} is not yet read by this tool, so SIEM delivery is unverified.`
      : "Audit log streaming is configured at the enterprise level and no enterprise slug was supplied, so SIEM delivery is unverified.",
    [
      `enterprise = ${enterprise ?? "not configured (set GITHUB_ENTERPRISE)"}`,
      "Deferred collector: GET /enterprises/{enterprise}/audit-log/streams (GitHub Enterprise Cloud, enterprise owner).",
      "GITHUB-ORG-005 covers organization audit log visibility only; it does not prove forwarding.",
    ],
    "Configure audit log streaming to the SIEM at the enterprise level and confirm the stream is healthy.",
    "Export the enterprise audit log stream configurations (Enterprise settings > Audit log > Log streaming) and record the destination, status, and last delivery time.",
  );
}

function assessRepositoryVisibilityDefaults(data: GitHubOrgAccessData): GitHubFinding {
  const org = data.org.data ? asRecord(data.org.data) : null;
  const canCreatePublic = asBoolean(org?.members_can_create_public_repositories);
  const canCreatePrivate = asBoolean(org?.members_can_create_private_repositories);
  const canCreateInternal = asBoolean(org?.members_can_create_internal_repositories);
  const canCreateRepos = asBoolean(org?.members_can_create_repositories);
  const evidence = [
    `members_can_create_repositories = ${String(canCreateRepos)}`,
    `members_can_create_public_repositories = ${String(canCreatePublic)}`,
    `members_can_create_private_repositories = ${String(canCreatePrivate)}`,
    `members_can_create_internal_repositories = ${String(canCreateInternal)}`,
  ];
  const recommendation = "Restrict repository creation so members cannot create public repositories; allow private or internal creation only where the development model needs it.";
  if (canCreatePublic === undefined) {
    return buildFinding(
      "GITHUB-ORG-009",
      "Manual",
      "The repository creation policy fields were not present in the org response (they are returned only to org owners and admin:org tokens).",
      [...evidence, ...(data.org.error ? [`org error = ${data.org.error}`] : [])],
      recommendation,
      "Rerun with an org owner principal or confirm Member privileges > Repository creation in the org settings UI.",
    );
  }
  if (canCreatePublic) {
    return buildFinding(
      "GITHUB-ORG-009",
      "Fail",
      "Members can create public repositories, so source code can be published without an owner review.",
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-ORG-009",
    "Pass",
    `Members cannot create public repositories (private ${String(canCreatePrivate)}, internal ${String(canCreateInternal)}).`,
    evidence,
    recommendation,
  );
}

function assessForkPolicy(data: GitHubOrgAccessData): GitHubFinding {
  const org = data.org.data ? asRecord(data.org.data) : null;
  const canFork = asBoolean(org?.members_can_fork_private_repositories);
  const evidence = [`members_can_fork_private_repositories = ${String(canFork)}`];
  const recommendation = "Disable forking of private and internal repositories so copies of proprietary code cannot leave the organization boundary.";
  if (canFork === undefined) {
    return buildFinding(
      "GITHUB-ORG-010",
      "Manual",
      "The fork policy field was not present in the org response (it is returned only to org owners and admin:org tokens).",
      [...evidence, ...(data.org.error ? [`org error = ${data.org.error}`] : [])],
      recommendation,
      "Rerun with an org owner principal or confirm Member privileges > Repository forking in the org settings UI.",
    );
  }
  if (canFork) {
    return buildFinding(
      "GITHUB-ORG-010",
      "Fail",
      "Members can fork private repositories, so proprietary code can be copied outside the controlled repositories.",
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-ORG-010",
    "Pass",
    "Members cannot fork private repositories.",
    evidence,
    recommendation,
  );
}

export async function collectGitHubRepoProtectionData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listRepositories"
    | "listOrgRulesets"
    | "listRepoRulesets"
    | "getBranchProtection"
    | "listBranchRules"
  >,
): Promise<GitHubRepoProtectionData> {
  const org = await collectDataset<JsonRecord | null>(null, () => client.getOrganization());
  const repositories = await collectDataset<JsonRecord[]>([], () => client.listRepositories());
  const orgRulesets = await collectDataset<JsonRecord[]>([], () => client.listOrgRulesets());

  const eligibleRepos = repositories.data.filter((repo) => !isArchivedRepo(repo));

  const branchRules = await collectDataset<Record<string, GitHubBranchRulesEntry>>({}, async () => {
    const entries = await mapWithConcurrency(eligibleRepos, 6, async (repo) => {
      const owner = asString(asRecord(repo.owner).login) ?? "";
      const name = asString(repo.name) ?? "";
      const key = repoKey(repo);
      const defaultBranch = asString(repo.default_branch);
      if (!defaultBranch) {
        return [key, { rules: null, error: "repository has no default_branch" }] as const;
      }
      try {
        return [key, { rules: await client.listBranchRules(owner, name, defaultBranch) }] as const;
      } catch (error) {
        return [key, { rules: null, error: summarizeError(error) }] as const;
      }
    });
    return Object.fromEntries(entries);
  });

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
    branchRules,
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
    | "listCodeSecurityDefaultConfigurations"
  >,
): Promise<GitHubCodeSecurityData> {
  return {
    org: await collectDataset<JsonRecord | null>(null, () => client.getOrganization()),
    repositories: await collectDataset<JsonRecord[]>([], () => client.listRepositories()),
    codeSecurityConfigurations: await collectDataset<JsonRecord[]>([], () => client.listCodeSecurityConfigurations()),
    codeSecurityDefaults: await collectDataset<JsonRecord[]>([], () => client.listCodeSecurityDefaultConfigurations()),
  };
}

async function collectPerRepo(
  repos: JsonRecord[],
  fetchItems: (owner: string, name: string) => Promise<JsonRecord[]>,
): Promise<Record<string, GitHubRepoListEntry>> {
  const entries = await mapWithConcurrency(repos, 6, async (repo) => {
    const owner = asString(asRecord(repo.owner).login) ?? "";
    const name = asString(repo.name) ?? "";
    const key = repoKey(repo);
    try {
      return [key, { items: await fetchItems(owner, name) }] as const;
    } catch (error) {
      return [key, { items: null, error: summarizeError(error) }] as const;
    }
  });
  return Object.fromEntries(entries);
}

export async function collectGitHubIntegrationsData(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listHooks"
    | "listInstallations"
    | "listCredentialAuthorizations"
    | "listRepositories"
    | "listRepoHooks"
    | "listDeployKeys"
  >,
): Promise<GitHubIntegrationsData> {
  const org = await collectDataset<JsonRecord | null>(null, () => client.getOrganization());
  const hooks = await collectDataset<JsonRecord[]>([], () => client.listHooks());
  const appInstallations = await collectDataset<JsonRecord[]>([], () => client.listInstallations());
  const credentialAuthorizations = await collectDataset<JsonRecord[]>([], () => client.listCredentialAuthorizations());
  const repositories = await collectDataset<JsonRecord[]>([], () => client.listRepositories());
  const eligibleRepos = repositories.data.filter((repo) => !isArchivedRepo(repo));
  const repoHooks = await collectDataset<Record<string, GitHubRepoListEntry>>({}, () =>
    collectPerRepo(eligibleRepos, (owner, name) => client.listRepoHooks(owner, name)));
  const deployKeys = await collectDataset<Record<string, GitHubRepoListEntry>>({}, () =>
    collectPerRepo(eligibleRepos, (owner, name) => client.listDeployKeys(owner, name)));

  return {
    org,
    hooks,
    appInstallations,
    credentialAuthorizations,
    repositories,
    repoHooks,
    deployKeys,
  };
}

interface WebhookIssue {
  location: string;
  problems: string[];
}

// Webhook config fields follow the REST org-hook and webhook-config schemas: config.url,
// config.insecure_ssl ("0" or "1", string or number), and config.secret (returned masked when set).
function inspectWebhook(location: string, hook: JsonRecord): WebhookIssue | null {
  const config = asRecord(hook.config);
  const url = asString(config.url) ?? "";
  const insecureSsl = config.insecure_ssl;
  const problems: string[] = [];
  if (!/^https:\/\//i.test(url)) {
    problems.push(`url is not https (${url || "missing"})`);
  }
  if (insecureSsl === "1" || insecureSsl === 1) {
    problems.push("insecure_ssl=1 disables TLS certificate verification");
  }
  if (!asString(config.secret)) {
    problems.push("no secret configured, so deliveries cannot be authenticated");
  }
  return problems.length > 0 ? { location, problems } : null;
}

function assessWebhookSecurity(data: GitHubIntegrationsData): GitHubFinding {
  const recommendation = "Point every webhook at an HTTPS endpoint, keep insecure_ssl at 0, and configure a delivery secret so receivers can validate X-Hub-Signature-256.";
  if (data.hooks.error) {
    return buildFinding(
      "GITHUB-INTEG-001",
      "Manual",
      "The organization webhook list was not readable, so webhook security is unverified.",
      [`org hooks error = ${data.hooks.error}`],
      recommendation,
      "Organization webhooks require admin:org_hook (or an app with organization webhooks read). Rerun with such a principal or review Settings > Webhooks manually.",
    );
  }
  const orgHooks = data.hooks.data;
  const repoEntries = Object.entries(data.repoHooks.data);
  const repoHooksUnreadable = repoEntries.filter(([, entry]) => entry.items === null);
  const repoHookCount = repoEntries.reduce((total, [, entry]) => total + (entry.items?.length ?? 0), 0);
  const issues: WebhookIssue[] = [];
  for (const hook of orgHooks) {
    const issue = inspectWebhook(`org hook ${asString(hook.id) ?? asNumber(hook.id) ?? "?"}`, hook);
    if (issue) issues.push(issue);
  }
  for (const [repo, entry] of repoEntries) {
    for (const hook of entry.items ?? []) {
      const issue = inspectWebhook(`${repo} hook ${asString(hook.id) ?? asNumber(hook.id) ?? "?"}`, hook);
      if (issue) issues.push(issue);
    }
  }
  const evidence = [
    `org_webhooks = ${orgHooks.length}`,
    data.repositories.error
      ? `repository webhooks not enumerated: ${data.repositories.error}`
      : `repo_webhooks = ${repoHookCount} across ${repoEntries.length - repoHooksUnreadable.length} readable repositories${repoHooksUnreadable.length > 0 ? ` (${repoHooksUnreadable.length} repositories unreadable)` : ""}`,
    `webhooks_with_issues = ${issues.length}`,
    ...issues.slice(0, 10).map((issue) => `${issue.location}: ${issue.problems.join("; ")}`),
  ];
  if (issues.length > 0) {
    return buildFinding(
      "GITHUB-INTEG-001",
      "Fail",
      `${issues.length} webhook(s) use plain HTTP, disable TLS verification, or lack a secret.`,
      evidence,
      recommendation,
    );
  }
  if (data.repositories.error || repoHooksUnreadable.length > 0 || data.repoHooks.error) {
    return buildFinding(
      "GITHUB-INTEG-001",
      "Partial",
      "Every readable webhook is secure, but repository webhooks were only partially enumerated.",
      [...evidence, ...(data.repoHooks.error ? [`repo hooks error = ${data.repoHooks.error}`] : [])],
      recommendation,
      "Repository webhooks require admin access on each repository; review the unreadable repositories manually.",
    );
  }
  if (repoEntries.length === 0) {
    return buildFinding(
      "GITHUB-INTEG-001",
      "Partial",
      `${orgHooks.length === 0 ? "No organization webhooks exist" : `All ${orgHooks.length} organization webhook(s) are secure`}, but the repository inventory was empty, so the repository-level webhook sweep had no coverage.`,
      evidence,
      recommendation,
      "Confirm the principal can list the organization's repositories (an installation token only sees repositories it is installed on), then rerun.",
    );
  }
  if (orgHooks.length + repoHookCount === 0) {
    return buildFinding(
      "GITHUB-INTEG-001",
      "Pass",
      `No organization or repository webhooks exist across ${repoEntries.length} active repositories; an empty inventory is compliant because there is no webhook delivery path to secure.`,
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-INTEG-001",
    "Pass",
    `All ${orgHooks.length + repoHookCount} webhook(s) use HTTPS with TLS verification and a configured secret.`,
    evidence,
    recommendation,
  );
}

// Deploy key fields follow the REST deploy-key schema: read_only, created_at, last_used, title.
function assessDeployKeys(data: GitHubIntegrationsData, now: number): GitHubFinding {
  const recommendation = "Remove write-capable deploy keys in favor of GitHub Apps or fine-grained tokens, and rotate or delete deploy keys older than a year.";
  const org = data.org.data ? asRecord(data.org.data) : null;
  const deployKeysEnabled = asBoolean(org?.deploy_keys_enabled_for_repositories);
  if (deployKeysEnabled === false) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Pass",
      "Deploy keys are disabled for repositories at the organization level, so no repository can carry one.",
      ["deploy_keys_enabled_for_repositories = false"],
      recommendation,
    );
  }
  if (data.repositories.error) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Manual",
      "The repository list was not readable, so deploy keys could not be enumerated.",
      [`repositories error = ${data.repositories.error}`, `deploy_keys_enabled_for_repositories = ${String(deployKeysEnabled)}`],
      recommendation,
      "Rerun with a principal that can list repositories and read deploy keys (repository administration read).",
    );
  }
  const entries = Object.entries(data.deployKeys.data);
  const unreadable = entries.filter(([, entry]) => entry.items === null);
  const allKeys = entries.flatMap(([repo, entry]) => (entry.items ?? []).map((key) => ({ repo, key })));
  const writeKeys = allKeys.filter(({ key }) => asBoolean(key.read_only) === false);
  const staleCutoff = now - (365 * 24 * 60 * 60 * 1000);
  const undated = allKeys.filter(({ key }) => !asString(key.created_at) || Number.isNaN(Date.parse(asString(key.created_at) ?? "")));
  const stale = allKeys.filter(({ key }) => {
    const created = Date.parse(asString(key.created_at) ?? "");
    return Number.isFinite(created) && created < staleCutoff;
  });
  const evidence = [
    `deploy_keys_enabled_for_repositories = ${String(deployKeysEnabled)}`,
    `deploy_keys = ${allKeys.length} across ${entries.length - unreadable.length} readable repositories${unreadable.length > 0 ? ` (${unreadable.length} repositories unreadable)` : ""}`,
    `write_capable_keys = ${writeKeys.length}`,
    `keys_older_than_365_days = ${stale.length}`,
    `keys_without_created_at = ${undated.length}`,
    ...writeKeys.slice(0, 10).map(({ repo, key }) => `${repo}: write key "${asString(key.title) ?? "untitled"}" created ${asString(key.created_at) ?? "unknown"}`),
    ...stale.slice(0, 10).map(({ repo, key }) => `${repo}: stale key "${asString(key.title) ?? "untitled"}" created ${asString(key.created_at) ?? "unknown"}, last_used ${asString(key.last_used) ?? "unknown"}`),
  ];
  if (data.deployKeys.error) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Manual",
      "Deploy key enumeration failed before any repository could be read.",
      [...evidence, `deploy keys error = ${data.deployKeys.error}`],
      recommendation,
      "Review Settings > Deploy keys on each repository manually.",
    );
  }
  if (writeKeys.length > 0 || stale.length > 0) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Fail",
      `${writeKeys.length} write-capable and ${stale.length} stale deploy key(s) were found.`,
      evidence,
      recommendation,
    );
  }
  if (unreadable.length > 0 || undated.length > 0) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Partial",
      `No write-capable or stale deploy keys were found, but ${unreadable.length} repositories were unreadable and ${undated.length} key(s) carry no creation date.`,
      evidence,
      recommendation,
      "Review the unreadable repositories and undated keys manually.",
    );
  }
  if (entries.length === 0) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Partial",
      "The repository inventory was empty, so no deploy keys could be enumerated and the control is unverified.",
      evidence,
      recommendation,
      "Confirm the principal can list the organization's repositories (an installation token only sees repositories it is installed on), then rerun.",
    );
  }
  if (allKeys.length === 0) {
    return buildFinding(
      "GITHUB-INTEG-002",
      "Pass",
      `No deploy keys exist across ${entries.length} active repositories; an empty inventory is compliant because there is no key to rotate or over-scope.`,
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-INTEG-002",
    "Pass",
    `All ${allKeys.length} deploy key(s) are read-only and newer than 365 days.`,
    evidence,
    recommendation,
  );
}

const BROAD_APP_PERMISSIONS = new Set([
  "administration",
  "organization_administration",
  "members",
  "organization_hooks",
  "organization_personal_access_tokens",
  "organization_secrets",
  "secrets",
  "actions",
  "workflows",
  "contents",
]);

// Installation fields follow the REST installation and app-permissions schemas: permissions map
// (read, write, or admin per permission), repository_selection (all or selected), suspended_at,
// app_slug, created_at, updated_at.
function assessAppInstallations(data: GitHubIntegrationsData): GitHubFinding {
  const recommendation = "Grant GitHub Apps the minimum permissions, scope installations to selected repositories, and uninstall suspended or unused apps.";
  if (data.appInstallations.error) {
    return buildFinding(
      "GITHUB-INTEG-003",
      "Manual",
      "The GitHub App installation list was not readable, so app permissions are unverified.",
      [`installations error = ${data.appInstallations.error}`],
      recommendation,
      "Listing installations requires admin:read:org (or an app with organization administration read). Review Settings > GitHub Apps manually.",
    );
  }
  const installations = data.appInstallations.data;
  const excessive: string[] = [];
  const suspended: string[] = [];
  const undated: string[] = [];
  for (const installation of installations) {
    const slug = asString(installation.app_slug) ?? `installation ${asNumber(installation.id) ?? "?"}`;
    const permissions = asRecord(installation.permissions);
    const allRepos = safeLower(installation.repository_selection) === "all";
    const adminPermissions = Object.entries(permissions).filter(([, level]) => safeLower(level) === "admin").map(([name]) => name);
    const broadWrite = Object.entries(permissions)
      .filter(([name, level]) => BROAD_APP_PERMISSIONS.has(name) && safeLower(level) === "write")
      .map(([name]) => name);
    const orgAdminWrite = broadWrite.filter((name) => name === "organization_administration" || name === "administration" || name === "members");
    if (adminPermissions.length > 0 || orgAdminWrite.length > 0 || (allRepos && broadWrite.length > 0)) {
      excessive.push(`${slug}: repository_selection=${asString(installation.repository_selection) ?? "unknown"}, admin=[${adminPermissions.join(",")}], write=[${broadWrite.join(",")}]`);
    }
    if (asString(installation.suspended_at)) {
      suspended.push(`${slug} suspended_at ${asString(installation.suspended_at)}`);
    }
    if (!asString(installation.updated_at)) {
      undated.push(slug);
    }
  }
  const evidence = [
    `app_installations = ${installations.length}`,
    `installations_with_excessive_permissions = ${excessive.length}`,
    `suspended_installations = ${suspended.length}`,
    `installations_without_updated_at = ${undated.length}`,
    "Note: the installation schema has no last-used field, so inactivity beyond suspension must be judged from the audit log.",
    ...excessive.slice(0, 10),
    ...suspended.slice(0, 5),
  ];
  if (excessive.length > 0) {
    return buildFinding(
      "GITHUB-INTEG-003",
      "Fail",
      `${excessive.length} of ${installations.length} GitHub App installation(s) hold admin permissions, organization or repository administration write, or broad write across all repositories.`,
      evidence,
      recommendation,
    );
  }
  if (suspended.length > 0 || undated.length > 0) {
    return buildFinding(
      "GITHUB-INTEG-003",
      "Partial",
      `No installation is over-permissioned, but ${suspended.length} suspended and ${undated.length} undated installation(s) need review.`,
      evidence,
      recommendation,
    );
  }
  if (installations.length === 0) {
    return buildFinding(
      "GITHUB-INTEG-003",
      "Pass",
      "No GitHub Apps are installed on the organization; an empty inventory is compliant because no third-party app holds access.",
      evidence,
      recommendation,
    );
  }
  return buildFinding(
    "GITHUB-INTEG-003",
    "Pass",
    `All ${installations.length} GitHub App installation(s) stay within least-privilege permissions.`,
    evidence,
    recommendation,
  );
}

function assessOAuthRestrictions(data: GitHubIntegrationsData): GitHubFinding {
  const authorizations = data.credentialAuthorizations;
  const oauthAuthorizations = authorizations.data.filter((entry) => safeLower(entry.credential_type)?.includes("oauth"));
  return buildFinding(
    "GITHUB-INTEG-004",
    "Manual",
    "The OAuth application access restriction setting is not exposed by the REST organization schema or the GraphQL Organization type, so it must be confirmed in the organization settings UI.",
    [
      "Reference checked: organization-full (REST) and Organization (GraphQL) carry no field for third-party OAuth application access policy.",
      authorizations.error
        ? `credential_authorizations unreadable (GitHub Enterprise Cloud SAML orgs only): ${authorizations.error}`
        : `saml_credential_authorizations = ${authorizations.data.length} (oauth ${oauthAuthorizations.length})`,
      ...oauthAuthorizations.slice(0, 10).map((entry) => `${asString(entry.login) ?? "?"}: ${asString(entry.credential_type) ?? "?"} authorized ${asString(entry.credential_authorized_at) ?? "unknown"}`),
    ],
    "Enable 'Restrict access via third-party applications' under Settings > Third-party Access and review every approved OAuth app.",
    "Capture a screenshot of Settings > Third-party Access showing the access policy and the approved application list.",
  );
}

// Deferred automation: GET /orgs/{org}/packages requires a package_type query parameter per
// package ecosystem and read:packages, so the sweep is not yet wired into the collector.
function assessPackageRegistryAccess(): GitHubFinding {
  return buildFinding(
    "GITHUB-INTEG-005",
    "Manual",
    "Package registry visibility is not yet enumerated by this tool, so the control is unverified.",
    [
      "Deferred collector: GET /orgs/{org}/packages?package_type={npm|maven|rubygems|docker|nuget|container} (packages/list-packages-for-organization).",
      "Evidence to collect: each package's visibility field and, for private organizations, any package whose visibility is public.",
    ],
    "Keep packages private unless publication is intentional, and review package access inheritance from the owning repository.",
    "Run the packages listing per package_type with a principal that holds read:packages, or review Packages in the organization profile and record any public packages.",
  );
}

export function assessGitHubIntegrations(
  data: GitHubIntegrationsData,
  config: GitHubResolvedConfig,
  now: number = Date.now(),
): GitHubAssessmentResult {
  const findings: GitHubFinding[] = [
    assessWebhookSecurity(data),
    assessDeployKeys(data, now),
    assessAppInstallations(data),
    assessOAuthRestrictions(data),
    assessPackageRegistryAccess(),
  ];
  const deployKeyEntries = Object.values(data.deployKeys.data);
  return {
    category: "integrations",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      org_webhooks: datasetSnapshotCount(data.hooks),
      repo_webhooks: data.repoHooks.error ? "error" : Object.values(data.repoHooks.data).reduce((total, entry) => total + (entry.items?.length ?? 0), 0),
      deploy_keys: data.deployKeys.error ? "error" : deployKeyEntries.reduce((total, entry) => total + (entry.items?.length ?? 0), 0),
      app_installations: datasetSnapshotCount(data.appInstallations),
      credential_authorizations: datasetSnapshotCount(data.credentialAuthorizations),
    },
    text: buildAssessmentText("GitHub integrations assessment", config.organization, findings),
  };
}

export function assessGitHubOrgAccess(
  data: GitHubOrgAccessData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const org = data.org.data ?? null;
  const defaultRepoPermission = safeLower(org && asRecord(org).default_repository_permission) ?? "unknown";
  const outsideCollaboratorCount = data.outsideCollaborators.data.length;
  const outsideCollaboratorsUnreadable = Boolean(data.outsideCollaborators.error);
  const adminCount = data.adminMembers.data.length;
  const adminsUnreadable = Boolean(data.adminMembers.error);
  const roleAssignments = data.organizationRoles.data.length;
  const auditVisible = !data.auditLog.error;
  const auditEventCount = data.auditLog.data.events.length;
  const auditCapped = data.auditLog.data.truncated;
  const auditWindow = data.auditLog.data.phrase;

  const findings: GitHubFinding[] = [
    assessTwoFactor(data),
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
      outsideCollaboratorsUnreadable
        ? "Manual"
        : (outsideCollaboratorCount === 0 ? "Pass" : (outsideCollaboratorCount <= 5 ? "Partial" : "Fail")),
      outsideCollaboratorsUnreadable
        ? "The outside collaborator list was not readable, so external access is unverified."
        : (outsideCollaboratorCount === 0
          ? "No outside collaborators were found; an empty list is compliant because the control asks for minimal external access."
          : `${outsideCollaboratorCount} outside collaborator(s) are attached to the organization.`),
      [
        outsideCollaboratorsUnreadable
          ? `outside_collaborators error = ${data.outsideCollaborators.error}`
          : `outside_collaborators = ${outsideCollaboratorCount}`,
        data.invitations.error ? `pending_invitations error = ${data.invitations.error}` : `pending_invitations = ${data.invitations.data.length}`,
        "Note: the REST org object has no field for 'admin approval required for outside collaborators'; review that policy in Member privileges manually.",
      ],
      "Review outside collaborators regularly and move durable access into managed org membership where possible.",
      outsideCollaboratorsUnreadable
        ? "Rerun with an org owner principal (outside_collaborators requires admin:org) or export the outside collaborators page from the org People view."
        : "Confirm the 'repository invitations' member privilege requires owner approval for outside collaborators.",
    ),
    buildFinding(
      "GITHUB-ORG-004",
      adminsUnreadable || adminCount === 0 ? "Manual" : (adminCount <= 5 ? "Pass" : "Partial"),
      adminsUnreadable
        ? "The admin member list was not readable, so privileged access concentration is unverified."
        : (adminCount === 0
          ? "The tool did not find any explicit organization admins, which is unexpected because every organization has at least one owner."
          : `${adminCount} org admin member(s) and ${roleAssignments} organization-role assignment(s) were identified.`),
      [
        adminsUnreadable ? `admin_members error = ${data.adminMembers.error}` : `admin_members = ${adminCount}`,
        data.organizationRoles.error ? `organization_roles error = ${data.organizationRoles.error}` : `organization_role_assignments = ${roleAssignments}`,
      ],
      "Keep org-admin membership small and use custom roles or teams for narrower delegated duties.",
      adminsUnreadable || adminCount === 0 ? "Confirm owner/admin concentration through the org People page filtered by role." : undefined,
    ),
    buildFinding(
      "GITHUB-ORG-005",
      auditVisible ? (auditEventCount > 0 ? "Pass" : "Info") : "Manual",
      auditVisible
        ? `The organization audit log is readable and returned ${auditEventCount} event(s) for the configured lookback window${auditCapped ? ` (sample capped at ${MAX_AUDIT_EVENTS} events, so this is a visibility check, not a full population)` : ""}.`
        : "The tool could not read the organization audit log with the supplied credentials.",
      [
        auditVisible ? `audit_events_last_${config.lookbackDays}_days = ${auditEventCount}${auditCapped ? ` (capped at ${MAX_AUDIT_EVENTS}, more events exist)` : " (complete within the window)"}` : `audit_log_error = ${data.auditLog.error}`,
        `audit_log_window = phrase ${auditWindow} (include=all)`,
        data.hooks.error ? `webhooks error = ${data.hooks.error}` : `webhooks = ${data.hooks.data.length}`,
        data.appInstallations.error ? `app_installations error = ${data.appInstallations.error}` : `app_installations = ${data.appInstallations.data.length}`,
      ],
      "Ensure the audit log is readable to the audit principal and that recent org events are reviewed or forwarded into monitoring workflows.",
      !auditVisible ? "PATs with SSO authorization are often the safest path for this endpoint." : undefined,
    ),
    assessSamlSso(data),
    assessEnterpriseManagedUsers(data),
    assessIpAllowList(data),
    assessRepositoryVisibilityDefaults(data),
    assessForkPolicy(data),
    assessAuditLogStreaming(config),
  ];

  return {
    category: "org_access",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      members: datasetSnapshotCount(data.members),
      admin_members: datasetSnapshotCount(data.adminMembers),
      members_without_2fa: datasetSnapshotCount(data.twoFactorDisabledMembers),
      outside_collaborators: datasetSnapshotCount(data.outsideCollaborators),
      invitations: datasetSnapshotCount(data.invitations),
      audit_events: data.auditLog.error ? "error" : data.auditLog.data.events.length,
      hooks: datasetSnapshotCount(data.hooks),
      saml_external_identities: data.samlIdentity.error ? "error" : (data.samlIdentity.data?.externalIdentities.length ?? 0),
      ip_allow_list_entries: data.ipAllowList.error ? "error" : (data.ipAllowList.data?.entries.length ?? 0),
      enterprise: config.enterprise ?? "not configured",
    },
    text: buildAssessmentText("GitHub org access assessment", config.organization, findings),
  };
}

interface RepoProtectionPosture {
  key: string;
  requiresPullRequest: boolean;
  approvingReviewCount: number;
  requiresCodeOwnerReview: boolean;
  dismissesStaleReviews: boolean;
  requiresLastPushApproval: boolean;
  requiredStatusCheckCount: number;
  strictStatusChecks: boolean;
  requiresSignatures: boolean;
  blocksForcePush: boolean;
  blocksDeletion: boolean;
  adminEnforced: boolean | null;
  orgSourcedRules: number;
  repoSourcedRules: number;
  legacyProtection: boolean;
  unknown: boolean;
}

function ruleParameters(rule: JsonRecord): JsonRecord {
  return asRecord(rule.parameters);
}

// Field names follow the REST "Get branch protection" schema (branch-protection,
// protected-branch-pull-request-review, protected-branch-required-status-check) and the
// "Get rules for a branch" schema (repository-rule-detailed with ruleset_source_type).
function evaluateRepoProtection(
  key: string,
  protection: JsonRecord | null,
  rulesEntry: GitHubBranchRulesEntry | undefined,
  legacyUnknown: boolean,
): RepoProtectionPosture {
  const rules = rulesEntry?.rules ?? [];
  const rulesUnknown = !rulesEntry || rulesEntry.rules === null;
  const reviews = protection ? asRecord(protection.required_pull_request_reviews) : {};
  const legacyHasReviews = Boolean(protection && protection.required_pull_request_reviews);
  const statusChecks = protection ? asRecord(protection.required_status_checks) : {};
  const legacyContexts = asArray(statusChecks.contexts).length + asArray(statusChecks.checks).length;

  const pullRequestRules = rules.filter((rule) => safeLower(rule.type) === "pull_request");
  const statusCheckRules = rules.filter((rule) => safeLower(rule.type) === "required_status_checks");
  const ruleReviewCount = Math.max(0, ...pullRequestRules.map((rule) => asNumber(ruleParameters(rule).required_approving_review_count) ?? 0));
  const ruleStatusCheckCount = statusCheckRules.reduce(
    (total, rule) => total + asArray(ruleParameters(rule).required_status_checks).length,
    0,
  );

  return {
    key,
    requiresPullRequest: legacyHasReviews || pullRequestRules.length > 0,
    approvingReviewCount: Math.max(asNumber(reviews.required_approving_review_count) ?? 0, ruleReviewCount),
    requiresCodeOwnerReview: asBoolean(reviews.require_code_owner_reviews) === true
      || pullRequestRules.some((rule) => asBoolean(ruleParameters(rule).require_code_owner_review) === true),
    dismissesStaleReviews: asBoolean(reviews.dismiss_stale_reviews) === true
      || pullRequestRules.some((rule) => asBoolean(ruleParameters(rule).dismiss_stale_reviews_on_push) === true),
    requiresLastPushApproval: asBoolean(reviews.require_last_push_approval) === true
      || pullRequestRules.some((rule) => asBoolean(ruleParameters(rule).require_last_push_approval) === true),
    requiredStatusCheckCount: legacyContexts + ruleStatusCheckCount,
    strictStatusChecks: asBoolean(statusChecks.strict) === true
      || statusCheckRules.some((rule) => asBoolean(ruleParameters(rule).strict_required_status_checks_policy) === true),
    requiresSignatures: branchProtectionRequiresSignatures(protection) || rulesIncludeType(rules, "required_signatures"),
    blocksForcePush: (protection !== null && asBoolean(asRecord(protection.allow_force_pushes).enabled) !== true)
      || rulesIncludeType(rules, "non_fast_forward"),
    blocksDeletion: (protection !== null && asBoolean(asRecord(protection.allow_deletions).enabled) !== true)
      || rulesIncludeType(rules, "deletion"),
    adminEnforced: protection ? (asBoolean(asRecord(protection.enforce_admins).enabled) ?? null) : null,
    orgSourcedRules: rules.filter((rule) => safeLower(rule.ruleset_source_type) === "organization").length,
    repoSourcedRules: rules.filter((rule) => safeLower(rule.ruleset_source_type) === "repository").length,
    legacyProtection: protection !== null,
    unknown: rulesUnknown && (legacyUnknown || protection === null),
  };
}

function coverageStatus(
  compliant: number,
  total: number,
  unknown: number,
): GitHubFindingStatus {
  if (total === 0) return "Info";
  if (compliant === total && unknown === 0) return "Pass";
  if (compliant > 0 || unknown > 0) return "Partial";
  return "Fail";
}

function coverageSummary(label: string, compliant: number, total: number, unknown: number): string {
  if (total === 0) return `No active repositories were found to assess ${label}.`;
  const base = `${compliant} of ${total} active repositories ${label}`;
  return unknown > 0
    ? `${base}; ${unknown} repositories could not be evaluated because neither branch protection nor branch rules were readable.`
    : `${base}.`;
}

export function assessGitHubRepoProtection(
  data: GitHubRepoProtectionData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const org = data.org.data ?? null;
  const orgRulesets = data.orgRulesets.data.filter(isActiveRuleset);
  const repos = data.repositories.data.filter((repo) => !isArchivedRepo(repo));
  const repositoriesUnreadable = Boolean(data.repositories.error);
  const legacyUnknown = Boolean(data.branchProtections.error);
  const rulesDatasetUnknown = Boolean(data.branchRules.error);

  const postures = repos.map((repo) => {
    const key = repoKey(repo);
    return evaluateRepoProtection(
      key,
      legacyUnknown ? null : (data.branchProtections.data[key] ?? null),
      rulesDatasetUnknown ? undefined : data.branchRules.data[key],
      legacyUnknown,
    );
  });

  const repoCount = repos.length;
  const unknownCount = postures.filter((posture) => posture.unknown).length;
  const protectedCount = postures.filter((posture) => posture.requiresPullRequest && posture.blocksForcePush && posture.blocksDeletion).length;
  const adminEnforcedCount = postures.filter((posture) => posture.adminEnforced === true).length;
  const reviewCount = postures.filter((posture) => posture.approvingReviewCount >= 1).length;
  const codeOwnerCount = postures.filter((posture) => posture.requiresCodeOwnerReview).length;
  const dismissStaleCount = postures.filter((posture) => posture.dismissesStaleReviews).length;
  const lastPushApprovalCount = postures.filter((posture) => posture.requiresLastPushApproval).length;
  const statusCheckCount = postures.filter((posture) => posture.requiredStatusCheckCount >= 1).length;
  const strictCount = postures.filter((posture) => posture.strictStatusChecks).length;
  const signedCount = postures.filter((posture) => posture.requiresSignatures).length;
  const bypassRestrictedCount = postures.filter((posture) => posture.blocksForcePush && posture.blocksDeletion).length;
  const orgRuleCoveredCount = postures.filter((posture) => posture.orgSourcedRules > 0).length;
  const repoRuleCoveredCount = postures.filter((posture) => posture.repoSourcedRules > 0).length;
  const legacyCoveredCount = postures.filter((posture) => posture.legacyProtection).length;
  const webCommitSignoffRequired = asBoolean(org && asRecord(org).web_commit_signoff_required);

  const unreadableEvidence = [
    `repositories error = ${data.repositories.error}`,
  ];
  const unreadableNote = "Rerun with a principal that can list organization repositories (metadata read) or export the repository list from the org UI.";

  const repoScoped = (
    id: string,
    label: string,
    compliant: number,
    evidence: string[],
    recommendation: string,
    manualNote?: string,
  ): GitHubFinding => {
    if (repositoriesUnreadable) {
      return buildFinding(id, "Manual", `The repository list was not readable, so ${label} could not be evaluated.`, unreadableEvidence, recommendation, unreadableNote);
    }
    return buildFinding(
      id,
      coverageStatus(compliant, repoCount, unknownCount),
      coverageSummary(label, compliant, repoCount, unknownCount),
      [...evidence, ...(unknownCount > 0 ? [`repos_not_evaluable = ${unknownCount}`] : [])],
      recommendation,
      manualNote,
    );
  };

  const findings: GitHubFinding[] = [
    data.orgRulesets.error || repositoriesUnreadable
      ? buildFinding(
        "GITHUB-REPO-001",
        "Manual",
        "Organization rulesets or the repository list were not readable, so ruleset coverage is unverified.",
        [
          data.orgRulesets.error ? `org_rulesets error = ${data.orgRulesets.error}` : `active_org_rulesets = ${orgRulesets.length}`,
          ...(repositoriesUnreadable ? unreadableEvidence : []),
        ],
        "Use organization rulesets where possible so baseline branch protections are declarative and harder to drift.",
        "Confirm rulesets under Organization settings > Repository > Rulesets with an org owner.",
      )
      : buildFinding(
        "GITHUB-REPO-001",
        orgRulesets.length > 0
          ? (repoCount === 0 || orgRuleCoveredCount === repoCount ? "Pass" : "Partial")
          : (repoRuleCoveredCount > 0 ? "Partial" : "Fail"),
        orgRulesets.length > 0
          ? `${orgRulesets.length} active organization ruleset(s) exist and ${orgRuleCoveredCount} of ${repoCount} active default branches receive organization-sourced rules.`
          : (repoRuleCoveredCount > 0
            ? `${repoRuleCoveredCount} repositories receive repository-level rules, but no active organization rulesets exist.`
            : "No active organization rulesets exist and no default branch receives ruleset rules."),
        [
          `active_org_rulesets = ${orgRulesets.length}`,
          `repos_with_org_sourced_rules = ${orgRuleCoveredCount}/${repoCount}`,
          `repos_with_repo_sourced_rules = ${repoRuleCoveredCount}/${repoCount}`,
          `repos_with_legacy_branch_protection = ${legacyCoveredCount}/${repoCount}`,
        ],
        "Use organization rulesets where possible so baseline branch protections are declarative and harder to drift.",
      ),
    repoScoped(
      "GITHUB-REPO-002",
      "require pull requests and block force pushes and deletions on the default branch",
      protectedCount,
      [
        `protected_default_branches = ${protectedCount}/${repoCount}`,
        `admin_enforced_legacy_protections = ${adminEnforcedCount}/${legacyCoveredCount}`,
        `org_rulesets = ${orgRulesets.length}`,
      ],
      "Require pull requests, block force pushes and deletions, and enforce the rules for administrators on every default branch.",
      adminEnforcedCount < legacyCoveredCount ? "Some legacy branch protections do not set enforce_admins; ruleset bypass actors must be reviewed in the ruleset UI." : undefined,
    ),
    repoScoped(
      "GITHUB-REPO-003",
      "require signed commits on the default branch",
      signedCount,
      [`signed_commit_enforced_repos = ${signedCount}/${repoCount}`],
      "Require signed commits or equivalent integrity enforcement for protected branches.",
    ),
    repoScoped(
      "GITHUB-REPO-004",
      "block both force pushes and branch deletion on the default branch",
      bypassRestrictedCount,
      [`repos_with_bypass_restrictions = ${bypassRestrictedCount}/${repoCount}`],
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
    repoScoped(
      "GITHUB-REPO-006",
      "require at least one approving review on the default branch",
      reviewCount,
      [
        `repos_requiring_approving_review = ${reviewCount}/${repoCount}`,
        `repos_requiring_code_owner_review = ${codeOwnerCount}/${repoCount}`,
        `repos_dismissing_stale_reviews = ${dismissStaleCount}/${repoCount}`,
        `repos_requiring_last_push_approval = ${lastPushApprovalCount}/${repoCount}`,
        `repos_requiring_pull_request_without_review_count = ${postures.filter((posture) => posture.requiresPullRequest && posture.approvingReviewCount === 0).length}`,
      ],
      "Set required_approving_review_count to at least 1 (2 for sensitive repositories), require code owner review, dismiss stale approvals, and require last-push approval.",
    ),
    repoScoped(
      "GITHUB-REPO-007",
      "require at least one status check on the default branch",
      statusCheckCount,
      [
        `repos_requiring_status_checks = ${statusCheckCount}/${repoCount}`,
        `repos_with_strict_status_checks = ${strictCount}/${repoCount}`,
      ],
      "Require named CI status checks (with the strict up-to-date policy) before merging into default branches.",
    ),
  ];

  return {
    category: "repo_protection",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      active_repositories: repositoriesUnreadable ? "error" : repoCount,
      active_org_rulesets: data.orgRulesets.error ? "error" : orgRulesets.length,
      protected_repositories: protectedCount,
      review_required_repositories: reviewCount,
      status_check_required_repositories: statusCheckCount,
      signed_commit_repositories: signedCount,
      bypass_restricted_repositories: bypassRestrictedCount,
      repos_not_evaluable: unknownCount,
    },
    text: buildAssessmentText("GitHub repository protection assessment", config.organization, findings),
  };
}

function assessSelfHostedRunners(
  data: GitHubActionsData,
  runnerCount: number,
  runnerGroupCount: number,
  openRunnerGroups: number,
): GitHubFinding {
  const recommendation = "Scope self-hosted runners to the smallest practical repository set and avoid broad public or org-wide exposure unless it is deliberate.";
  const evidence = [
    data.runners.error ? `org runners unreadable: ${data.runners.error}` : `self_hosted_runners = ${runnerCount}`,
    data.runnerGroups.error ? `runner groups unreadable: ${data.runnerGroups.error}` : `runner_groups = ${runnerGroupCount}`,
    `open_runner_groups = ${openRunnerGroups}`,
  ];

  if (data.runners.error || data.runnerGroups.error) {
    return buildFinding(
      "GITHUB-ACT-004",
      "Manual",
      "The tool could not read the organization runner or runner-group inventory, so runner scoping is unverified.",
      evidence,
      recommendation,
      "Grant admin:org (or the Actions runners read permission on the App) and rerun, or export the runner and runner-group lists from Settings > Actions > Runners.",
    );
  }

  if (runnerCount === 0 && runnerGroupCount === 0) {
    return buildFinding(
      "GITHUB-ACT-004",
      "Info",
      "No organization-level self-hosted runners or runner groups are registered, so there is nothing to scope at the org layer. Repository-level runners are not enumerated by the org endpoint, so this is not a pass.",
      evidence,
      recommendation,
      "Confirm that no repository-level self-hosted runners exist, or enumerate them per repository.",
    );
  }

  const scoped = openRunnerGroups === 0;
  return buildFinding(
    "GITHUB-ACT-004",
    scoped ? "Pass" : "Partial",
    `${runnerCount} self-hosted runner(s) and ${runnerGroupCount} runner group(s) were found; ${openRunnerGroups} runner group(s) appear broadly exposed.`,
    evidence,
    recommendation,
    "Review runner-group targeting and workflow restrictions manually for sensitive repos.",
  );
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
    assessSelfHostedRunners(data, runnerCount, runnerGroupCount, openRunnerGroups),
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

// Deferred automation: per-repository security policy presence is exposed by GraphQL
// Repository.isSecurityPolicyEnabled and Repository.securityPolicyUrl; the sweep is not yet wired.
function assessSecurityPolicyPresence(data: GitHubCodeSecurityData): GitHubFinding {
  const repoCount = data.repositories.error ? "unknown" : String(data.repositories.data.length);
  return buildFinding(
    "GITHUB-CODE-006",
    "Manual",
    "Security policy (SECURITY.md) presence is not yet enumerated per repository, so the control is unverified.",
    [
      `repositories_in_scope = ${repoCount}`,
      "Deferred collector: GraphQL Repository.isSecurityPolicyEnabled and Repository.securityPolicyUrl per active repository.",
    ],
    "Publish a SECURITY.md (or an organization-level .github/SECURITY.md) so vulnerability reporting instructions are available for every repository.",
    "Query isSecurityPolicyEnabled for each active repository, or check the Security tab of each repository, and record the repositories without a policy.",
  );
}

type CodeSecurityDefaultStatus = "Pass" | "Partial" | "Fail" | "Manual";

interface CodeSecurityDefaultEvaluation {
  status: CodeSecurityDefaultStatus;
  detail: string;
  evidence: string[];
}

interface CodeSecurityFeature {
  label: string;
  configField: string;
  orgFlagField?: string;
}

interface CodeSecurityDefaultEntry {
  visibility: string;
  configuration: JsonRecord;
}

const CODE_SECURITY_DEFAULT_MANUAL_NOTE = "Confirm the default code security configurations in Settings > Code security > Configurations with an organization owner or security manager, or rerun with a principal that holds organization administration read access.";

function isEnforcedConfiguration(configuration: JsonRecord): boolean {
  const enforcement = asString(configuration.enforcement);
  return enforcement === "enforced" || enforcement === "enterprise_enforced";
}

function readCodeSecurityDefaultEntries(defaults: JsonRecord[]): CodeSecurityDefaultEntry[] {
  return defaults.map((entry) => ({
    visibility: asString(entry.default_for_new_repos) ?? "unspecified",
    configuration: asRecord(entry.configuration),
  }));
}

function describeDefaultEntry(entry: CodeSecurityDefaultEntry, configField: string): string {
  const configuration = entry.configuration;
  return `default_for_new_repos[${entry.visibility}] = ${asString(configuration.name) ?? "unnamed"} (id ${asNumber(configuration.id) ?? "?"}): ${configField} = ${String(configuration[configField] ?? "not returned")}, enforcement = ${asString(configuration.enforcement) ?? "not returned"}`;
}

function defaultsCoverAllVisibilities(entries: CodeSecurityDefaultEntry[]): boolean {
  const visibilities = new Set(entries.map((entry) => entry.visibility));
  return visibilities.has("all") || (visibilities.has("public") && visibilities.has("private_and_internal"));
}

// The organization-full *_enabled_for_new_repositories flags are deprecated ("use code security
// configurations instead") and owner-only, so the defaults endpoint is authoritative for what new
// repositories receive and the flags only corroborate; enforcement is read from the configuration.
function evaluateCodeSecurityDefault(data: GitHubCodeSecurityData, feature: CodeSecurityFeature): CodeSecurityDefaultEvaluation {
  const org = data.org.data ? asRecord(data.org.data) : null;
  const orgFlag = feature.orgFlagField && org ? asBoolean(org[feature.orgFlagField]) : undefined;
  const flagEvidence = feature.orgFlagField
    ? `${feature.orgFlagField} = ${orgFlag === undefined ? "not returned (deprecated, owner-only field)" : String(orgFlag)}`
    : null;
  const withFlag = (lines: string[]): string[] => (flagEvidence ? [...lines, flagEvidence] : lines);
  const defaultsDataset = data.codeSecurityDefaults;

  if (defaultsDataset.error) {
    const evidence = withFlag([`default configurations unreadable: ${defaultsDataset.error}`]);
    if (orgFlag === true) {
      return {
        status: "Partial",
        detail: `The deprecated organization flag reports ${feature.label} enabled for new repositories, but the default code security configurations are unreadable, so enforcement is unverified.`,
        evidence,
      };
    }
    if (orgFlag === false) {
      return { status: "Fail", detail: `The organization flag reports ${feature.label} disabled for new repositories and the default configurations are unreadable.`, evidence };
    }
    return { status: "Manual", detail: `The tool could not read the default code security configurations, so ${feature.label} defaults are unverified.`, evidence };
  }

  const entries = readCodeSecurityDefaultEntries(defaultsDataset.data);
  if (entries.length === 0) {
    const evidence = withFlag(["default_configurations = 0"]);
    if (orgFlag === true) {
      return {
        status: "Partial",
        detail: `The deprecated organization flag reports ${feature.label} enabled, but no default code security configuration applies to new repositories; configurations are the authoritative source, so the default is unverified.`,
        evidence,
      };
    }
    return { status: "Fail", detail: `No default code security configuration applies to new repositories, so ${feature.label} is not enabled by default.`, evidence };
  }

  const evidence = withFlag(entries.map((entry) => describeDefaultEntry(entry, feature.configField)));
  const enabledEntries = entries.filter((entry) => featureEnabled(entry.configuration[feature.configField]));
  const disabledEntries = entries.filter((entry) => !featureEnabled(entry.configuration[feature.configField]));
  if (enabledEntries.length === 0) {
    return { status: "Fail", detail: `The default code security configuration(s) do not enable ${feature.label} for new repositories.`, evidence };
  }
  if (disabledEntries.length > 0) {
    return {
      status: "Partial",
      detail: `${feature.label} is enabled by default for ${enabledEntries.map((entry) => entry.visibility).join(", ")} repositories only; the default for ${disabledEntries.map((entry) => entry.visibility).join(", ")} repositories leaves it off.`,
      evidence,
    };
  }
  if (!defaultsCoverAllVisibilities(entries)) {
    return {
      status: "Partial",
      detail: `${feature.label} is enabled by default for ${entries.map((entry) => entry.visibility).join(", ")} repositories only; no default configuration covers the other visibilities.`,
      evidence,
    };
  }
  const unenforced = enabledEntries.filter((entry) => !isEnforcedConfiguration(entry.configuration));
  if (unenforced.length > 0) {
    return {
      status: "Partial",
      detail: `${feature.label} is enabled by default, but the default configuration is ${unenforced.map((entry) => asString(entry.configuration.enforcement) ?? "missing enforcement").join(", ")}, so repository administrators can disable it.`,
      evidence,
    };
  }
  return {
    status: "Pass",
    detail: `${feature.label} is enabled and enforced by default for new ${entries.map((entry) => entry.visibility).join(", ")} repositories.`,
    evidence,
  };
}

function combineDefaultEvaluations(evaluations: CodeSecurityDefaultEvaluation[]): CodeSecurityDefaultStatus {
  const statuses = new Set(evaluations.map((evaluation) => evaluation.status));
  if (statuses.size === 1) {
    return evaluations[0].status;
  }
  if (statuses.has("Manual") && !statuses.has("Pass") && !statuses.has("Fail")) {
    return "Manual";
  }
  return "Partial";
}

export function assessGitHubCodeSecurity(
  data: GitHubCodeSecurityData,
  config: GitHubResolvedConfig,
): GitHubAssessmentResult {
  const configsDataset = data.codeSecurityConfigurations;
  const configs = configsDataset.data;
  const defaultsDataset = data.codeSecurityDefaults;
  const defaultEntries = defaultsDataset.error ? [] : readCodeSecurityDefaultEntries(defaultsDataset.data);
  const secretScanning = evaluateCodeSecurityDefault(data, {
    label: "secret scanning",
    configField: "secret_scanning",
    orgFlagField: "secret_scanning_enabled_for_new_repositories",
  });
  const pushProtection = evaluateCodeSecurityDefault(data, {
    label: "secret scanning push protection",
    configField: "secret_scanning_push_protection",
    orgFlagField: "secret_scanning_push_protection_enabled_for_new_repositories",
  });
  const dependabotAlerts = evaluateCodeSecurityDefault(data, {
    label: "Dependabot alerts",
    configField: "dependabot_alerts",
    orgFlagField: "dependabot_alerts_enabled_for_new_repositories",
  });
  const dependabotUpdates = evaluateCodeSecurityDefault(data, {
    label: "Dependabot security updates",
    configField: "dependabot_security_updates",
    orgFlagField: "dependabot_security_updates_enabled_for_new_repositories",
  });
  const codeScanning = evaluateCodeSecurityDefault(data, {
    label: "code scanning default setup",
    configField: "code_scanning_default_setup",
  });
  const dependabotStatus = combineDefaultEvaluations([dependabotAlerts, dependabotUpdates]);
  const unreadableSources = [
    data.org.error ? `organization profile unreadable: ${data.org.error}` : null,
    configsDataset.error ? `code security configurations unreadable: ${configsDataset.error}` : null,
  ].filter((entry): entry is string => entry !== null);
  const manualIf = (status: CodeSecurityDefaultStatus): string | undefined =>
    (status === "Manual" ? CODE_SECURITY_DEFAULT_MANUAL_NOTE : undefined);
  const configurationsStatus: GitHubFindingStatus = configsDataset.error
    ? "Manual"
    : (configs.length === 0
      ? "Fail"
      : (!defaultsDataset.error && defaultEntries.length === 0 ? "Partial" : "Pass"));
  const defaultsEvidence = defaultsDataset.error
    ? `default configurations unreadable: ${defaultsDataset.error}`
    : `default_configurations = ${defaultEntries.length}${defaultEntries.length > 0 ? ` (${defaultEntries.map((entry) => `${entry.visibility}: ${asString(entry.configuration.name) ?? "unnamed"}, enforcement ${asString(entry.configuration.enforcement) ?? "not returned"}`).join("; ")})` : ""}`;

  const findings: GitHubFinding[] = [
    buildFinding(
      "GITHUB-CODE-001",
      configurationsStatus,
      configsDataset.error
        ? "The tool could not read organization code security configurations, so the control is unverified."
        : (configs.length === 0
          ? "No organization-level code security configurations exist. An empty configuration list is a fail for this control because new repositories inherit no security baseline."
          : (configurationsStatus === "Partial"
            ? `${configs.length} code security configuration(s) exist, but none is applied to new repositories by default, so they act as pilots rather than an organization baseline.`
            : `${configs.length} code security configuration(s) were found at the organization layer and ${defaultEntries.length} default assignment(s) apply them to new repositories.`)),
      [
        configsDataset.error ? `code security configurations unreadable: ${configsDataset.error}` : `code_security_configurations = ${configs.length}`,
        defaultsEvidence,
        ...(configs.length > 0 ? configs.slice(0, 10).map((entry) => `configuration ${asString(entry.name) ?? "unnamed"} (id ${asNumber(entry.id) ?? "?"}): target_type ${asString(entry.target_type) ?? "?"}, enforcement ${asString(entry.enforcement) ?? "not returned"}`) : []),
      ],
      "Define code security configurations and set them as the default for new public and private repositories so the baseline is applied centrally instead of relying on ad hoc per-repo toggles.",
      configsDataset.error ? CODE_SECURITY_DEFAULT_MANUAL_NOTE : undefined,
    ),
    buildFinding(
      "GITHUB-CODE-002",
      secretScanning.status,
      secretScanning.detail,
      [...secretScanning.evidence, ...unreadableSources],
      "Enable secret scanning in the default code security configurations for every repository visibility and set the configuration to enforced.",
      manualIf(secretScanning.status),
    ),
    buildFinding(
      "GITHUB-CODE-003",
      pushProtection.status,
      pushProtection.detail,
      [...pushProtection.evidence, ...unreadableSources],
      "Enable push protection in the enforced default configurations so secret exposures are blocked before they land in the repository history.",
      manualIf(pushProtection.status),
    ),
    buildFinding(
      "GITHUB-CODE-004",
      dependabotStatus,
      dependabotStatus === "Pass"
        ? "Dependabot alerts and security updates are enabled and enforced by default for new repositories."
        : `Dependabot defaults are incomplete: alerts ${dependabotAlerts.status} (${dependabotAlerts.detail}) security updates ${dependabotUpdates.status} (${dependabotUpdates.detail})`,
      [
        ...dependabotAlerts.evidence,
        ...dependabotUpdates.evidence.filter((line) => !dependabotAlerts.evidence.includes(line)),
        ...unreadableSources,
      ],
      "Enable both Dependabot alerts and security updates in the enforced default configurations so vulnerable dependencies are surfaced and remediated.",
      manualIf(dependabotStatus),
    ),
    buildFinding(
      "GITHUB-CODE-005",
      codeScanning.status,
      codeScanning.detail,
      [...codeScanning.evidence, ...unreadableSources],
      "Enable code scanning default setup in the enforced default configurations so repositories inherit baseline static-analysis coverage.",
      manualIf(codeScanning.status),
    ),
    assessSecurityPolicyPresence(data),
  ];

  return {
    category: "code_security",
    findings,
    summary: countByStatus(findings),
    snapshotSummary: {
      code_security_configurations: configsDataset.error ? "error" : configs.length,
      default_configurations: defaultsDataset.error ? "error" : defaultEntries.length,
      repositories: datasetSnapshotCount(data.repositories),
      secret_scanning_default: secretScanning.status,
      push_protection_default: pushProtection.status,
      dependabot_default: `${dependabotAlerts.status}/${dependabotUpdates.status}`,
      code_scanning_default_setup: codeScanning.status,
    },
    text: buildAssessmentText("GitHub code security assessment", config.organization, findings),
  };
}

export async function exportGitHubAuditBundle(
  client: Pick<
    GitHubAuditorClient,
    | "getOrganization"
    | "listMembers"
    | "listTwoFactorDisabledMembers"
    | "getSamlIdentitySnapshot"
    | "getIpAllowListSnapshot"
    | "getEnterpriseIdentitySnapshot"
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
    | "listBranchRules"
    | "getOrgActionsPermissions"
    | "getOrgSelectedActions"
    | "getOrgWorkflowPermissions"
    | "listRunnerGroups"
    | "listRunners"
    | "listCodeSecurityConfigurations"
    | "listCodeSecurityDefaultConfigurations"
    | "listRepoHooks"
    | "listDeployKeys"
  >,
  config: GitHubResolvedConfig,
  outputRoot: string,
): Promise<GitHubAuditBundleResult> {
  const orgAccess = await collectGitHubOrgAccessData(client, config);
  const repoProtection = await collectGitHubRepoProtectionData(client);
  const actions = await collectGitHubActionsData(client);
  const codeSecurity = await collectGitHubCodeSecurityData(client);
  const integrations = await collectGitHubIntegrationsData(client);

  const assessments = [
    assessGitHubOrgAccess(orgAccess, config),
    assessGitHubRepoProtection(repoProtection, config),
    assessGitHubActionsSecurity(actions, config),
    assessGitHubCodeSecurity(codeSecurity, config),
    assessGitHubIntegrations(integrations, config),
  ];

  const errors = [
    ...listErrors(Object.values(orgAccess)),
    ...listErrors(Object.values(repoProtection)),
    ...listErrors(Object.values(actions)),
    ...listErrors(Object.values(codeSecurity)),
    ...listErrors(Object.values(integrations)),
  ];

  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    safeDirName(`${config.organization}-audit-bundle`),
  );

  await buildBundleQuickReference(outputDir);
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
    ["core_data/integrations.json", integrations],
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
      "Review org-level identity and access posture: 2FA enforcement and members without 2FA, SAML SSO and enterprise identity (EMU), IP allow list, base permissions, repository creation and fork policy, outside collaborators, org roles, and audit-log visibility.",
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
    name: "github_assess_integrations",
    label: "Assess GitHub integrations",
    description:
      "Review organization and repository webhook security (HTTPS, TLS verification, secrets), deploy key hygiene, GitHub App installation permissions, and OAuth application access evidence.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGitHubConfiguration(args);
        const client = new GitHubAuditorClient(config);
        const data = await collectGitHubIntegrationsData(client);
        return renderAssessmentToolResult(assessGitHubIntegrations(data, config));
      } catch (error) {
        return errorResult(
          `GitHub integrations assessment failed: ${summarizeError(error)}`,
          { tool: "github_assess_integrations" },
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
