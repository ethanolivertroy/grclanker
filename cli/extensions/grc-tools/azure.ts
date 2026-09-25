/**
 * Azure GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the azure-sec-inspector spec.
 * Read-only Microsoft Graph and Azure Resource Manager REST calls cover the
 * 25 spec controls across identity, monitoring, subscription guardrails,
 * data protection, and network/policy posture. Every endpoint, API version,
 * and field is traceable to the learn.microsoft.com page cited next to it.
 */
import { execFileSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type FetchImpl = typeof fetch;
type AzureCommandRunner = (command: string, args: string[]) => string | undefined;

const DEFAULT_OUTPUT_DIR = "./export/azure";
const DEFAULT_MAX_ASSIGNMENTS = 500;
const DEFAULT_MAX_MAILBOXES = 100;
const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;
const DAY_MS = 24 * 60 * 60 * 1000;
const STALE_GUEST_DAYS = 90;
const MIN_RETENTION_DAYS = 90;
const LONG_LIVED_CREDENTIAL_DAYS = 730;
const SECURITY_DEFAULTS_ENDPOINT = "GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy";
const MESSAGE_RULES_ENDPOINT = "GET /v1.0/users/{id}/mailFolders/inbox/messageRules";
const MAILBOX_RULES_PERMISSION = "MailboxSettings.Read (application)";

/**
 * Cloud endpoint sets. Public and US Government hosts:
 * https://learn.microsoft.com/en-us/graph/deployments
 * https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure
 * https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud
 *
 * The China cloud (operated by 21Vianet) is documented under two authority hosts:
 * login.chinacloudapi.cn on the Graph deployments page and
 * login.partner.microsoftonline.cn on the national cloud authentication page.
 * Both resolve to the same Graph and ARM endpoints.
 */
export interface AzureCloudEndpoints {
  name: "public" | "usgovernment" | "usgovernment-dod" | "china";
  authorityHost: string;
  graphBaseUrl: string;
  managementBaseUrl: string;
}

const CHINA_GRAPH_BASE_URL = "https://microsoftgraph.chinacloudapi.cn";
const CHINA_MANAGEMENT_BASE_URL = "https://management.chinacloudapi.cn";

export const AZURE_CLOUDS: Record<string, AzureCloudEndpoints> = {
  "login.microsoftonline.com": {
    name: "public",
    authorityHost: "https://login.microsoftonline.com",
    graphBaseUrl: "https://graph.microsoft.com",
    managementBaseUrl: "https://management.azure.com",
  },
  "login.microsoftonline.us": {
    name: "usgovernment",
    authorityHost: "https://login.microsoftonline.us",
    graphBaseUrl: "https://graph.microsoft.us",
    managementBaseUrl: "https://management.usgovcloudapi.net",
  },
  "login.chinacloudapi.cn": {
    name: "china",
    authorityHost: "https://login.chinacloudapi.cn",
    graphBaseUrl: CHINA_GRAPH_BASE_URL,
    managementBaseUrl: CHINA_MANAGEMENT_BASE_URL,
  },
  "login.partner.microsoftonline.cn": {
    name: "china",
    authorityHost: "https://login.partner.microsoftonline.cn",
    graphBaseUrl: CHINA_GRAPH_BASE_URL,
    managementBaseUrl: CHINA_MANAGEMENT_BASE_URL,
  },
};

/** Learn pages that document every request this module sends. */
export const AZURE_ENDPOINT_DOCS = {
  clientCredentials: "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow",
  organization: "https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0",
  conditionalAccess: "https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0",
  conditionalAccessPolicy: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0",
  conditionalAccessConditions: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0",
  conditionalAccessGrants: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0",
  userRegistrationDetails: "https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0",
  directoryRoles: "https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0",
  directoryRoleMembers: "https://learn.microsoft.com/en-us/graph/api/directoryrole-list-members?view=graph-rest-1.0",
  roleTemplates: "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference",
  securityDefaults: "https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0",
  securityDefaultsBehavior: "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
  servicePrincipals: "https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0",
  applications: "https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0",
  applicationResource: "https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0",
  passwordCredential: "https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0",
  keyCredential: "https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0",
  oauth2PermissionGrants: "https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0",
  oauth2PermissionGrantResource: "https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0",
  secureScores: "https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0",
  securityAlerts: "https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0",
  directoryAudits: "https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0",
  signIns: "https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0",
  users: "https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0",
  userResource: "https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0",
  signInActivity: "https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0",
  authorizationPolicy: "https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0",
  authorizationPolicyResource: "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0",
  riskyUsers: "https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0",
  riskyUserResource: "https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0",
  riskDetections: "https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0",
  subscribedSkus: "https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0",
  servicePlanNames: "https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference",
  roleEligibilitySchedules: "https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules?view=graph-rest-1.0",
  roleAssignmentSchedules: "https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentschedules?view=graph-rest-1.0",
  roleAssignmentScheduleResource: "https://learn.microsoft.com/en-us/graph/api/resources/unifiedroleassignmentschedule?view=graph-rest-1.0",
  expirationPattern: "https://learn.microsoft.com/en-us/graph/api/resources/expirationpattern?view=graph-rest-1.0",
  deviceCompliancePolicies: "https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0",
  managedDevices: "https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0",
  complianceState: "https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-compliancestate?view=graph-rest-1.0",
  sensitivityLabels: "https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-beta",
  sensitivityLabelResource: "https://learn.microsoft.com/en-us/graph/api/resources/security-sensitivitylabel?view=graph-rest-beta",
  informationProtectionResource: "https://learn.microsoft.com/en-us/graph/api/resources/security-informationprotection?view=graph-rest-beta",
  dlpPowerShell: "https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy",
  messageRules: "https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules?view=graph-rest-1.0",
  messageRuleActions: "https://learn.microsoft.com/en-us/graph/api/resources/messageruleactions?view=graph-rest-1.0",
  mailboxSettings: "https://learn.microsoft.com/en-us/graph/api/resources/mailboxsettings?view=graph-rest-1.0",
  transportRulePowerShell: "https://learn.microsoft.com/en-us/powershell/module/exchange/get-transportrule",
  setMailboxPowerShell: "https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailbox",
  sharepointSettings: "https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0",
  sharepointSettingsResource: "https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0",
  subscription: "https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get",
  defenderPricings: "https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list",
  diagnosticSettings: "https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list",
  logAnalyticsWorkspaces: "https://learn.microsoft.com/en-us/rest/api/loganalytics/workspaces/list",
  entraLogRetention: "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention",
  entraDiagnosticSettings: "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings",
  securityContacts: "https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list",
  securityContactsSpec: "https://github.com/Azure/azure-rest-api-specs/blob/main/specification/security/resource-manager/Microsoft.Security/Security/preview/2020-01-01-preview/securityContacts.json",
  roleAssignments: "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription",
  roleDefinitions: "https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list",
  networkWatchers: "https://learn.microsoft.com/en-us/rest/api/network-watcher/network-watchers/list-all",
  flowLogs: "https://learn.microsoft.com/en-us/rest/api/network-watcher/flow-logs/list",
  networkSecurityGroups: "https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all",
  keyVaults: "https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription",
  storageAccounts: "https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list",
  policyAssignments: "https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-assignments/list",
  policyStatesSummarize: "https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/summarize-for-subscription",
  builtInPolicies: "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies",
} as const;

/**
 * ARM api-versions, each taken from the request sample on the cited page.
 * securityContacts is the exception: the Learn page renders the composite
 * package moniker (2023-12-01-preview), but Microsoft.Security/securityContacts
 * is only defined in the 2020-01-01-preview (and 2017-08-01-preview) spec files,
 * so that is the version the resource provider accepts.
 */
export const AZURE_ARM_API_VERSIONS = {
  subscription: "2022-12-01",
  defenderPricings: "2024-01-01",
  diagnosticSettings: "2021-05-01-preview",
  securityContacts: "2020-01-01-preview",
  roleAssignments: "2022-04-01",
  roleDefinitions: "2022-04-01",
  networkWatchers: "2025-09-01",
  flowLogs: "2025-09-01",
  networkSecurityGroups: "2025-09-01",
  keyVaults: "2024-11-01",
  storageAccounts: "2026-06-01",
  logAnalyticsWorkspaces: "2026-03-01",
  policyAssignments: "2026-07-01",
  policyStatesSummarize: "2024-10-01",
} as const;

/** Role template IDs, https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference */
const PRIVILEGED_ROLE_TEMPLATE_IDS = new Map<string, string>([
  ["62e90394-69f5-4237-9190-012177145e10", "global administrator"],
  ["e8611ab8-c189-46e8-94e1-60213ab1f814", "privileged role administrator"],
  ["194ae4cb-b126-40b2-bd5b-6091b380977d", "security administrator"],
  ["b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "conditional access administrator"],
]);

/** guestUserRoleId values, https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0 */
const GUEST_ROLE_SAME_AS_MEMBER = "a0b1b346-4d3e-4e8b-98f8-753987be4970";
const GUEST_ROLE_LIMITED = "10dae51f-b6af-4016-8d66-8c2a99b929b3";
const GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b";

/** Built-in policy definition IDs, https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies */
const MANDATORY_POLICY_DEFINITIONS: Array<{ id: string; name: string }> = [
  { id: "e56962a6-4747-49cd-b67b-bf8b01975c4c", name: "Allowed locations" },
  { id: "871b6d14-10aa-478d-b590-94f262ecfa99", name: "Require a tag on resources" },
  { id: "cccc23c7-8427-4f53-ad12-b6a63eb452b3", name: "Allowed virtual machine size SKUs" },
];

const HIGH_PRIVILEGE_DELEGATED_SCOPES = [
  "directory.readwrite.all",
  "directory.accessasuser.all",
  "rolemanagement.readwrite.directory",
  "application.readwrite.all",
  "mail.readwrite",
  "mail.read",
  "mail.send",
  "files.readwrite.all",
  "user.readwrite.all",
  "group.readwrite.all",
];

const ADMIN_PORTS = [22, 3389, 3306, 1433];

export interface AzureResolvedConfig {
  tenantId: string;
  subscriptionId: string;
  graphToken: string;
  managementToken: string;
  sourceChain: string[];
  cloud?: AzureCloudEndpoints;
  clientCredentials?: { clientId: string; clientSecret: string };
}

export interface AzureAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  /** Items the probe saw; null when the probe never completed, so a denial is never mistaken for an empty inventory. */
  count?: number | null;
  /** True when the probe stopped at its page cap, so `count` is a floor rather than the inventory size; null when the probe never completed. */
  truncated?: boolean | null;
  /** Why a truncated probe stopped when the stop was not the page cap (a refused next link); fixed text. */
  truncation?: string;
  /** HTTP status the failing probe observed; null when the failure was not an HTTP response. */
  http_status?: number | null;
  /** URL (without query) of the request that failed, taken from the observed request. */
  request_url?: string | null;
  error?: string;
}

export interface AzureAccessCheckResult {
  status: "healthy" | "limited";
  tenantId: string;
  subscriptionId: string;
  surfaces: AzureAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type AzureFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface AzureFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: AzureFindingStatus;
  summary: string;
  control: number;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface AzureAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: AzureFinding[];
  errors: string[];
}

export interface AzureAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface AzurePage {
  items: JsonRecord[];
  truncated: boolean;
  seen: number;
  total?: number;
  /** Why the walk stopped early when the stop was not the item cap: fixed text, never the link that caused it. */
  truncation?: string;
}

type CheckAccessArgs = {
  tenant_id?: string;
  subscription_id?: string;
  graph_token?: string;
  management_token?: string;
  client_id?: string;
  client_secret?: string;
  authority_host?: string;
};

type SubscriptionArgs = CheckAccessArgs & {
  max_assignments?: number;
};

type DataProtectionArgs = CheckAccessArgs & {
  max_mailboxes?: number;
};

type ExportAuditBundleArgs = SubscriptionArgs & DataProtectionArgs & {
  output_dir?: string;
};

export type AzureFramework = "fedramp" | "cmmc" | "soc2" | "cis_azure" | "pci_dss" | "disa_stig" | "irap" | "ismap";

export const AZURE_FRAMEWORKS: Array<{ key: AzureFramework; label: string }> = [
  { key: "fedramp", label: "FedRAMP (NIST 800-53)" },
  { key: "cmmc", label: "CMMC 2.0" },
  { key: "soc2", label: "SOC 2" },
  { key: "cis_azure", label: "CIS Azure v2.1" },
  { key: "pci_dss", label: "PCI-DSS v4.0" },
  { key: "disa_stig", label: "DISA STIG" },
  { key: "irap", label: "IRAP" },
  { key: "ismap", label: "ISMAP" },
];

type ControlMapping = { name: string } & Record<AzureFramework, string>;

/** Section 5 of specs/azure-sec-inspector.spec.md. */
export const AZURE_CONTROL_MAPPINGS: Record<number, ControlMapping> = {
  1: { name: "Conditional Access", fedramp: "AC-2, AC-3, AC-7", cmmc: "AC.L2-3.1.1", soc2: "CC6.1, CC6.6", cis_azure: "1.2.1, 1.2.2", pci_dss: "7.2.1", disa_stig: "SRG-APP-000033", irap: "ISM-1401", ismap: "7.1.1" },
  2: { name: "MFA Enforcement", fedramp: "IA-2(1), IA-2(2)", cmmc: "IA.L2-3.5.3", soc2: "CC6.1", cis_azure: "1.1.1, 1.1.2, 1.1.3", pci_dss: "8.4.2", disa_stig: "SRG-APP-000149", irap: "ISM-1401", ismap: "7.2.1" },
  3: { name: "Secure Score", fedramp: "CA-7, SI-4", cmmc: "CA.L2-3.12.3", soc2: "CC7.1", cis_azure: "n/a", pci_dss: "11.5.1", disa_stig: "SRG-APP-000516", irap: "ISM-1228", ismap: "8.2.1" },
  4: { name: "Legacy Auth Blocked", fedramp: "AC-17, IA-2(6)", cmmc: "AC.L2-3.1.12", soc2: "CC6.1, CC6.7", cis_azure: "1.2.6", pci_dss: "8.2.1", disa_stig: "SRG-APP-000295", irap: "ISM-1557", ismap: "7.2.2" },
  5: { name: "Privileged Roles", fedramp: "AC-6(1), AC-6(5)", cmmc: "AC.L2-3.1.5", soc2: "CC6.1, CC6.3", cis_azure: "1.1.4, 1.23", pci_dss: "7.2.2", disa_stig: "SRG-APP-000340", irap: "ISM-1507", ismap: "7.1.2" },
  6: { name: "Guest User Access", fedramp: "AC-2, AC-3", cmmc: "AC.L2-3.1.1", soc2: "CC6.1, CC6.2", cis_azure: "1.14", pci_dss: "7.2.5", disa_stig: "SRG-APP-000033", irap: "ISM-1380", ismap: "7.1.3" },
  7: { name: "Sign-In Risk", fedramp: "IA-5(13), SI-4", cmmc: "IA.L2-3.5.2", soc2: "CC6.1, CC6.8", cis_azure: "1.2.3", pci_dss: "8.3.1", disa_stig: "SRG-APP-000516", irap: "ISM-0120", ismap: "7.2.3" },
  8: { name: "User Risk", fedramp: "IA-5(13), SI-4", cmmc: "IA.L2-3.5.2", soc2: "CC6.1, CC6.8", cis_azure: "1.2.4", pci_dss: "8.3.1", disa_stig: "SRG-APP-000516", irap: "ISM-0120", ismap: "7.2.4" },
  9: { name: "Device Compliance", fedramp: "CM-2, CM-6", cmmc: "CM.L2-3.4.1", soc2: "CC6.1, CC6.8", cis_azure: "n/a", pci_dss: "6.3.1", disa_stig: "SRG-APP-000383", irap: "ISM-1490", ismap: "6.3.1" },
  10: { name: "DLP Policies", fedramp: "MP-4, SC-28", cmmc: "SC.L2-3.13.16", soc2: "CC6.1, CC6.7", cis_azure: "n/a", pci_dss: "3.4.1", disa_stig: "SRG-APP-000231", irap: "ISM-0264", ismap: "6.2.1" },
  11: { name: "Sensitivity Labels", fedramp: "MP-4, SC-16", cmmc: "SC.L2-3.13.16", soc2: "CC6.1, CC6.5", cis_azure: "n/a", pci_dss: "3.4.1", disa_stig: "SRG-APP-000231", irap: "ISM-0264", ismap: "6.2.2" },
  12: { name: "NSG Rules", fedramp: "AC-4, SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.1, CC6.6", cis_azure: "6.1, 6.2", pci_dss: "1.3.1", disa_stig: "SRG-APP-000142", irap: "ISM-1416", ismap: "6.1.1" },
  13: { name: "Key Vault Access", fedramp: "SC-12, SC-28", cmmc: "SC.L2-3.13.10", soc2: "CC6.1, CC6.7", cis_azure: "8.1, 8.2, 8.5", pci_dss: "3.6.4", disa_stig: "SRG-APP-000231", irap: "ISM-0457", ismap: "6.2.3" },
  14: { name: "Storage Encryption", fedramp: "SC-8, SC-28", cmmc: "SC.L2-3.13.8", soc2: "CC6.1, CC6.7", cis_azure: "3.1, 3.7", pci_dss: "3.4.1, 4.1.1", disa_stig: "SRG-APP-000014", irap: "ISM-0457", ismap: "6.2.4" },
  15: { name: "Diagnostic Logging", fedramp: "AU-2, AU-3, AU-6", cmmc: "AU.L2-3.3.1", soc2: "CC7.2, CC7.3", cis_azure: "5.1.1, 5.1.2", pci_dss: "10.2.1", disa_stig: "SRG-APP-000089", irap: "ISM-0580", ismap: "8.1.1" },
  16: { name: "Defender Enabled", fedramp: "SI-4, IR-4", cmmc: "SI.L2-3.14.6", soc2: "CC7.2, CC7.3", cis_azure: "2.1.1 through 2.1.15", pci_dss: "11.5.1", disa_stig: "SRG-APP-000516", irap: "ISM-1228", ismap: "8.2.2" },
  17: { name: "RBAC Least Privilege", fedramp: "AC-6, AC-6(1)", cmmc: "AC.L2-3.1.5", soc2: "CC6.1, CC6.3", cis_azure: "1.23", pci_dss: "7.2.2", disa_stig: "SRG-APP-000342", irap: "ISM-1380", ismap: "7.1.4" },
  18: { name: "Security Contacts", fedramp: "IR-6, PM-2", cmmc: "IR.L2-3.6.2", soc2: "CC7.4", cis_azure: "2.1.19, 2.1.20", pci_dss: "12.10.5", disa_stig: "SRG-APP-000516", irap: "ISM-0072", ismap: "9.1.1" },
  19: { name: "Audit Log Retention", fedramp: "AU-9, AU-11", cmmc: "AU.L2-3.3.8", soc2: "CC7.2", cis_azure: "5.1.3, 5.2.6", pci_dss: "10.7.1", disa_stig: "SRG-APP-000125", irap: "ISM-0859", ismap: "8.1.2" },
  20: { name: "Mail Forwarding", fedramp: "AC-4, SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.1", cis_azure: "n/a", pci_dss: "1.3.4", disa_stig: "SRG-APP-000142", irap: "ISM-1416", ismap: "6.1.2" },
  21: { name: "External Sharing", fedramp: "AC-3, AC-4", cmmc: "AC.L2-3.1.3", soc2: "CC6.1, CC6.6", cis_azure: "n/a", pci_dss: "7.2.5", disa_stig: "SRG-APP-000033", irap: "ISM-0263", ismap: "6.1.3" },
  22: { name: "App Registrations", fedramp: "CM-7, IA-5", cmmc: "CM.L2-3.4.8", soc2: "CC6.1, CC6.2", cis_azure: "1.11", pci_dss: "8.6.3", disa_stig: "SRG-APP-000175", irap: "ISM-1590", ismap: "7.2.5" },
  23: { name: "Service Principals", fedramp: "AC-6, IA-4", cmmc: "AC.L2-3.1.5", soc2: "CC6.1, CC6.3", cis_azure: "n/a", pci_dss: "8.6.3", disa_stig: "SRG-APP-000340", irap: "ISM-1507", ismap: "7.2.6" },
  24: { name: "Network Watcher", fedramp: "AU-12, SI-4", cmmc: "AU.L2-3.3.1", soc2: "CC7.2", cis_azure: "6.4, 6.5", pci_dss: "10.2.1", disa_stig: "SRG-APP-000089", irap: "ISM-0580", ismap: "8.1.3" },
  25: { name: "Azure Policy", fedramp: "CM-2, CM-6", cmmc: "CM.L2-3.4.2", soc2: "CC6.1, CC8.1", cis_azure: "n/a", pci_dss: "6.3.1", disa_stig: "SRG-APP-000383", irap: "ISM-1490", ismap: "6.3.2" },
};

function frameworkMappings(control: number): string[] {
  const mapping = AZURE_CONTROL_MAPPINGS[control];
  if (!mapping) return [];
  return AZURE_FRAMEWORKS
    .filter((framework) => mapping[framework.key] !== "n/a")
    .map((framework) => `${framework.label} ${mapping[framework.key]}`);
}

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecords(value: unknown): JsonRecord[] {
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

function asLower(value: unknown): string | undefined {
  return asString(value)?.toLowerCase();
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

function parseIsoDate(value: unknown): Date | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function daysUntil(now: Date, value: unknown): number | undefined {
  const parsed = parseIsoDate(value);
  return parsed ? (parsed.getTime() - now.getTime()) / DAY_MS : undefined;
}

function daysSince(now: Date, value: unknown): number | undefined {
  const parsed = parseIsoDate(value);
  return parsed ? (now.getTime() - parsed.getTime()) / DAY_MS : undefined;
}

function round(value: number, digits = 1): number {
  return Number(value.toFixed(digits));
}

export function toPage(value: unknown): AzurePage {
  if (Array.isArray(value)) {
    const items = asRecords(value);
    return { items, truncated: false, seen: items.length };
  }
  const record = asObject(value);
  if (record && Array.isArray(record.items)) {
    const items = asRecords(record.items);
    const truncation = asString(record.truncation);
    return {
      items,
      truncated: record.truncated === true,
      seen: asNumber(record.seen) ?? items.length,
      total: asNumber(record.total),
      ...(truncation ? { truncation } : {}),
    };
  }
  return { items: [], truncated: false, seen: 0 };
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

// The words that name a credential. A key ends in one of them; isCredentialNamedKey below decides how the word may
// be attached to the rest of the key. `skey` and `ikey` are Duo's secret key and integration key (DUO_SKEY, DUO_IKEY),
// both configured secrets of that integration; there is no bare `key`, so KmsKeyId, ssh_key_name, and the like stay
// identifiers. The compound words (`session_token`, `client_secret`, `secret_access_key`, `secret_key`,
// `connection_string`, `ssh_key_data`) are the members an SDK response or a credential store carries, so they count
// in their PascalCase form too (`SessionToken`, `ClientSecret`, `SecretAccessKey`, `SecretKey`), where a PascalCase
// error code that merely ends in `Token` (`ExpiredToken`) does not; see isCredentialNamedKey. The bearer ids are the
// one override to the identifier suffix (CodeRabbit r4077259415 on #78, harness revision 3): a key ending in
// `secret_id` (a Vault AppRole secret id) or `token_id` (a token id is the token), or in a session id (`session_id`,
// `sid`, `sessid`, `jsessionid`, `PHPSESSID`), authenticates rather than identifies, so it is a credential key
// despite ending in `id` and its value goes whatever its shape, UUID included, while `client_id`, `tenant_id`,
// `access_key_id`, `key_id`, and `secret_name` keep theirs unless the value's own shape goes. A URL-valued webhook
// key (`webhook`, `webhook_url`) carries its token in the path, so the whole value goes; `webhook_count` is a count.
const ERROR_CREDENTIAL_WORDS =
  "token|secret[_.-]?id|token[_.-]?id|session[_.-]?token|access[_.-]?token|refresh[_.-]?token|id[_.-]?token|client[_.-]?secret|api[_.-]?secret|secret[_.-]?access[_.-]?key|secret[_.-]?key|secret|passw(?:or)?d|pwd|passphrase|api[_.-]?key|apikey|auth[_.-]?key|auth[_.-]?email|session(?:[_.-]?id)?|sessid|sid|cookie|csrftoken|authorization|auth|signature|sig|nonce|credentials?|access[_.-]?key|private[_.-]?key|ssh[_.-]?key[_.-]?data|skey|ikey|assertion|connection[_.-]?string|webhook(?:[_.-]?url)?";
const ERROR_CREDENTIAL_KEY_PATTERN = `[A-Za-z0-9_.-]*(?:${ERROR_CREDENTIAL_WORDS})`;

/**
 * Where a key may start: after a character that cannot be part of a key, or after a JSON escape (`\n`, `\t`,
 * `\u000a`) inside a serialized message, where the character before the key is the escape's last letter and
 * `\b` sees no boundary (reviewer D round 5 escapes). Never right after a backslash, so the escape letter is not
 * read as the first letter of the key (`\nExpiredToken:` is the error code, not a key `nExpiredToken`).
 */
const KEY_BOUNDARY_PATTERN = String.raw`(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))`;
/** Where a header name or a scheme word may start: the same boundaries, allowing a `.` or `-` before the name. */
const NAME_BOUNDARY_PATTERN = String.raw`(?:(?<![A-Za-z0-9_])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))`;

/**
 * The authorization scheme words, matched in any casing (harness revision 3, row B): the HTTP schemes, Okta's
 * SSWS, the Splunk and Snowflake header schemes, and SigV4. Under a credential-named key only an Authorization
 * header treats the word as a scheme in front of the value; under any other key the word is the value.
 */
const ERROR_SCHEME_WORDS = "Bearer|Basic|Digest|Negotiate|NTLM|OAuth|SSWS|Token|ApiKey|Api-Key|Splunk|Snowflake|AWS4-HMAC-SHA256";
const ERROR_SCHEME_PATTERN = `(?:${ERROR_SCHEME_WORDS})`;
/**
 * key=value and key: value pairs whose key ends in a credential word, wherever the key stands (after a flag
 * prefix `--`, `-D`, a path segment `kv/`, a parenthesis, or a comma: reviewer #78 row D). The value runs to
 * whitespace, a quote, `&`, `;`, `,`, a closing bracket, an angle bracket, or a backslash (the compound-line
 * rule), so a pair inside a query string, a header list, a JSON fragment, or a parenthesis keeps the text after
 * it; a marker inside the value (a URL whose query was already removed) is part of it. A value that is already
 * the marker is not a value, so a second pass over a scrubbed message changes nothing; scrubCredentialPairs
 * decides whether the key names a credential.
 */
const ERROR_CREDENTIAL_PAIR_PATTERN = new RegExp(
  `${KEY_BOUNDARY_PATTERN}(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\\\*["'])?\\s*[=:]\\s*["']?)((?:${ERROR_SCHEME_PATTERN}\\s+)?(?!\\[REDACTED\\])(?:\\[REDACTED\\]|[^\\s"'&;,<>)\\]}\\\\])+)`,
  "gi",
);
/** `--name value` (a CLI flag echoed in a spawned CLI's stderr, reviewer #78 row D): the next token is the value. */
const FLAG_CARRIER_PATTERN = new RegExp(`(?<![A-Za-z0-9_.-])--(${ERROR_CREDENTIAL_KEY_PATTERN})(\\s+)(?![-\\[])([^\\s"'&;,<>)\\]}\\\\]+)`, "gi");
const TRAILING_PUNCTUATION_PATTERN = /[.!?:)]+$/;

/**
 * A quoted value: the opening quote with the backslashes that escape it at its serialization depth (none when the
 * message is plain, one when it was serialized once, three when twice), the value up to the close quote at the
 * same depth (an escaped quote inside the value, `\"` inside `"..."`, is part of the value, as is a deeper
 * quote), and that close quote. Both patterns below place it after two capturing groups, so the backslashes are
 * group 4, the quote character group 5, the value group 6, and the close quote group 7.
 */
const ERROR_QUOTED_VALUE_PATTERN = String.raw`(?<!\\)((\\*)(["']))((?:(?!(?<!\\)\4\5)[^\n])+)((?<!\\)\4\5)`;
/**
 * Codex P1 (quoted header value). `X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization: Bearer "value"`,
 * `\"X-Auth-Key\":\"value\"`: with or without spaces, single or double quotes, plain or JSON-escaped. The quotes
 * delimit the carrier, so the quoted value is removed whole whatever its shape; the pair rule above stops at the
 * opening quote and would judge a short or name-shaped value ("key", "prod-key") as prose. The header name, the
 * separator, the scheme, and the quotes stay so the message remains diagnosable.
 */
const ERROR_QUOTED_CREDENTIAL_PATTERN = new RegExp(
  String.raw`${KEY_BOUNDARY_PATTERN}(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\*["'])?\s*[=:]\s*(?:${ERROR_SCHEME_PATTERN}\s*)?)${ERROR_QUOTED_VALUE_PATTERN}`,
  "gi",
);
// A scheme word that is itself quoted (`"Token":"..."`, a JSON key) or ends a compound key (`"x-api-key":`,
// `"settings.token":`) is a pair the rule above already handled.
const ERROR_QUOTED_SCHEME_PATTERN = new RegExp(String.raw`(?<!["'\\./-])\b(${ERROR_SCHEME_PATTERN})(\s*)${ERROR_QUOTED_VALUE_PATTERN}`, "gi");
const QUOTED_VALUE_REPLACEMENT = `$1$2$3${REDACTED_ERROR_VALUE}$7`;
/**
 * A quoted phrase that is a scheme word and one value (`"Bearer prod-token"`, `\"Token prod-key\"`, `'Basic abc'`):
 * the quotes delimit a header value being quoted, so the value goes whatever its shape (reviewer D round 5 depth
 * control, the quoted name-shaped bearer), where the same phrase bare in prose (`sent as Bearer prod-token`) is
 * judged by the scheme rule's shape test. A quoted phrase of several words after the scheme is prose and stays.
 */
const ERROR_QUOTED_SCHEME_PHRASE_PATTERN = new RegExp(
  String.raw`(?<!\\)((\\*)(["']))(${ERROR_SCHEME_PATTERN})(\s+)((?:(?!(?<!\\)\2\3)[^\s"'\\])+)((?<!\\)\2\3)`,
  "gi",
);
const QUOTED_SCHEME_PHRASE_REPLACEMENT = `$1$4$5${REDACTED_ERROR_VALUE}$7`;

const CREDENTIAL_KEY_WORD_PATTERN = new RegExp(`(?:${ERROR_CREDENTIAL_WORDS})$`, "i");
// Credential words that end too many ordinary words to count when glued to a lowercase prefix (`oauth`, `ssid`).
const WEAK_CREDENTIAL_WORD_PATTERN = /^(?:auth|sid|sig)$/i;
const PAIR_VALUE_SCHEME_PATTERN = new RegExp(`^${ERROR_SCHEME_PATTERN}\\s+`, "i");
const BARE_SCHEME_WORD_PATTERN = new RegExp(`^${ERROR_SCHEME_PATTERN}$`, "i");
/** The keys whose value is `<scheme> <credential>`: Authorization and Proxy-Authorization. */
const AUTHORIZATION_KEY_PATTERN = /authorization$/i;
const SCHEME_PARAMETER_PATTERN = /^([A-Za-z][A-Za-z0-9_-]*)=(?!=)/;

/**
 * Whether the value after a scheme word is a `name=value` parameter list (SigV4 `Credential=...`, `realm="api"`,
 * `OAuth oauth_consumer_key=...`) rather than one bearer credential: the name is shaped like a name segment by
 * segment (`oauth_consumer_key`, `x-amz-date`), and the `=` is followed by more text, or by the quote that opens
 * the parameter's value where the caller's value stopped (`uri="/dir"`, `Session="v"`: `quoteFollows`), or the
 * whole is not base64-length (`realm=` is a parameter; `cGFzc3dvcmQ=` is padding).
 */
function isSchemeParameterList(value: string, quoteFollows = false): boolean {
  const parameter = SCHEME_PARAMETER_PATTERN.exec(value);
  if (parameter === null || !isParameterName(parameter[1])) return false;
  return parameter[0].length < value.length || quoteFollows || value.length % 4 !== 0;
}

/** A parameter name: `-` or `_` separated segments that are each shaped like part of a name (see isNameSegment). */
function isParameterName(name: string): boolean {
  return name.split(/[-_]/).every((segment) => isNameSegment(segment));
}

/** Whether a quote, plain or behind the backslashes of its JSON escape, stands at `index` in `text`. */
function quoteOpensAt(text: string, index: number): boolean {
  let cursor = index;
  while (text[cursor] === "\\") cursor += 1;
  return text[cursor] === '"' || text[cursor] === "'";
}

/**
 * Whether a key names a credential (reviewer D round 5 baseline). It does when it is a credential word
 * (`password`, `Token`, `skey`, `SessionToken`), sets one off with `_`, `-`, or `.` (`DB_PASSWORD`,
 * `AZURE_CLIENT_SECRET`, `x-api-key`, `Proxy-Authorization`), or is a lowerCamelCase, lowercase, or uppercase
 * compound ending in one (`accessToken`, `clientSecret`, `dbpassword`, `ACCESSTOKEN`). A PascalCase identifier
 * that merely ends in the word (`InvalidAuthenticationToken`, `ExpiredToken`) is an error code or a type name,
 * and the text after its colon is prose. A key that names an identifier (`AWS_ACCESS_KEY_ID`, `AZURE_TENANT_ID`,
 * `CLOUDFLARE_EMAIL`) never ends in a credential word, so its value is judged by its own shape alone; the bearer
 * ids (`secret_id`, `token_id`, and the session ids, see ERROR_CREDENTIAL_WORDS) are credential words, so that
 * suffix test never reaches them.
 */
function isCredentialNamedKey(key: string): boolean {
  const word = CREDENTIAL_KEY_WORD_PATTERN.exec(key)?.[0];
  if (word === undefined) return false;
  const prefix = key.slice(0, key.length - word.length);
  if (prefix.length === 0 || /[_.-]$/.test(prefix)) return true;
  if (/^[A-Z]/.test(prefix) && /[a-z]/.test(prefix)) return false;
  return !WEAK_CREDENTIAL_WORD_PATTERN.test(word);
}

/**
 * The value of a pair whose key names a credential is the credential and is removed whatever its shape and
 * length (reviewer D round 5 baseline): `password=letmein`, `DB_PASSWORD=Sunshine`, `AZURE_CLIENT_SECRET: abc12`,
 * and `DUO_SKEY=p@ss` go the way `{"password":"letmein"}` already did. The key, the separator, and the sentence
 * punctuation after the value stay. Under an Authorization header a scheme word in front of the value stays
 * too, a scheme word standing alone ("sent as Authorization: Bearer") names the scheme and carries nothing, and
 * a parameter list after the scheme (SigV4 `Credential=..., SignedHeaders=..., Signature=...`) is judged pair by
 * pair so the region and the request scope stay (scrubAuthorizationParameters has already removed every
 * parameter value that is a proof, so this pass sees markers and the kept parameters). Under any other
 * credential key the scheme word is the value (CodeRabbit r4078025849 on #63: `sslPassword=splunk rejected`,
 * `db_password: token`), and the prose after it stays. A `--name value` flag is a pair whose separator is the space.
 */
function scrubCredentialPairs(text: string): string {
  const scrubbed = text.replace(ERROR_CREDENTIAL_PAIR_PATTERN, (match: string, key: string, separator: string, value: string, offset: number) => {
    if (!isCredentialNamedKey(key)) return match;
    const scheme = PAIR_VALUE_SCHEME_PATTERN.exec(value)?.[0] ?? "";
    const authorization = AUTHORIZATION_KEY_PATTERN.test(key);
    if (scheme.length > 0 && !authorization) {
      const word = scheme.trimEnd();
      return `${key}${separator}${REDACTED_ERROR_VALUE}${value.slice(word.length)}`;
    }
    const core = value.slice(scheme.length).replace(TRAILING_PUNCTUATION_PATTERN, "");
    if (core.length === 0) return match;
    const tail = value.slice(scheme.length + core.length);
    if (authorization) {
      if (BARE_SCHEME_WORD_PATTERN.test(core)) return match;
      if (isSchemeParameterList(core, quoteOpensAt(text, offset + match.length - tail.length))) {
        return `${key}${separator}${scheme}${scrubCredentialPairs(core)}${tail}`;
      }
    }
    return `${key}${separator}${scheme}${REDACTED_ERROR_VALUE}${tail}`;
  });
  return scrubbed.replace(FLAG_CARRIER_PATTERN, (match: string, key: string, space: string) =>
    isCredentialNamedKey(key) ? `--${key}${space}${REDACTED_ERROR_VALUE}` : match,
  );
}

/**
 * Header carriers whose value is free form: Cookie and Set-Cookie (session values with their attributes) and
 * Cloudflare's legacy X-Auth-Key / X-Auth-Email pair (the global API key and its account; round 4 item F). The
 * value is removed whatever its shape. Where it ends follows the compound-line rule shared by every scrubber:
 * a quoted value (a plain or JSON-escaped quote) ends at its closing quote, so a closed value that holds `; Name:`
 * is one value and the quotes stay around the marker; an unquoted value, or a quoted one that is never closed,
 * ends at the `;` or `,` that introduces the next `Name:` header token on the line (a name may hold dots,
 * `X.Api.Key:`), at a `<` or `>` (the header quoted inside markup), at a `"` that closes the JSON string and
 * container that carried the line (`"}`, `"]`), at a JSON-escaped line break (`\n`, `\r`, `\u000a`, `\u000d` as
 * backslash text, the end of the line inside a serialized message), or at the end of the line, so the next
 * header keeps its name and gets its own carrier treatment. A value that is already the marker is left alone,
 * so a second pass over a scrubbed message leaves the text after the marker as it is.
 *
 * The header name counts as a carrier at a line start, after any character that is not part of a name, and
 * after a JSON escape (reviewer D round 5 escapes): inside a serialized message the character before `Cookie`
 * is the escape's last letter (`\nCookie`, `\u000aCookie`), a word character to `\b`, and a boundary that
 * relied on `\b` left the free-form removal to the pair rule, which stops at the first `;` and judges every
 * later cookie pair on its own name and shape. After `--`, `.`, or `/` (plain or JSON-escaped) the name is a
 * flag, a property, or a path segment (`--x-auth-key=value -h db`, `-Dspring.datasource.x-auth-key=value`,
 * `kv/x-auth-key=value see log`), a pair whose value ends at the next space, so the pair rule takes it and the
 * text after the value stays.
 */
const HEADER_CARRIER_PATTERN = new RegExp(`(?:(?<![A-Za-z0-9_./-])|(?<=\\\\[nrtbfv])|(?<=\\\\u[0-9A-Fa-f]{4}))(set-cookie|cookie|x-auth-key|x-auth-email)(\\s*[:=]\\s*)(?!\\s*\\[REDACTED\\])`, "gi");
const HEADER_CARRIER_QUOTE_PATTERN = /^(\\*)(["'])/;
const NEXT_HEADER_TOKEN_PATTERN = /[;,]\s*[A-Za-z][A-Za-z0-9.-]*\s*:/;
const MARKUP_OR_JSON_CLOSE_PATTERN = /[<>]|"(?=\s*[}\]])/;
const ESCAPED_LINE_BREAK_PATTERN = /\\(?:[nr]|u000[aAdD])/;

/** The first occurrence of `quote` in `line` at or after `from` that is not escaped by a backslash before it, or -1. */
function closingQuoteIndex(line: string, quote: string, from: number): number {
  for (let index = line.indexOf(quote, from); index !== -1; index = line.indexOf(quote, index + 1)) {
    if (index === 0 || line[index - 1] !== "\\") return index;
  }
  return -1;
}

/** The end of a free-form header value that starts at `start`, and the quote (plain or escaped) that encloses a closed quoted value. */
function headerCarrierValueEnd(text: string, start: number): { end: number; quote?: string } {
  const newline = text.indexOf("\n", start);
  const line = text.slice(start, newline === -1 ? text.length : newline);
  const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
  if (opening) {
    const close = closingQuoteIndex(line, opening[0], opening[0].length);
    if (close !== -1) return { end: start + close + opening[0].length, quote: opening[0] };
  }
  // An unterminated quote is part of the value; the stops are searched after it.
  const skip = opening ? opening[0].length : 0;
  const rest = line.slice(skip);
  const stops = [MARKUP_OR_JSON_CLOSE_PATTERN.exec(rest)?.index, NEXT_HEADER_TOKEN_PATTERN.exec(rest)?.index, ESCAPED_LINE_BREAK_PATTERN.exec(rest)?.index].filter(
    (index): index is number => index !== undefined,
  );
  return { end: start + skip + (stops.length > 0 ? Math.min(...stops) : rest.length) };
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

/**
 * An Authorization or Proxy-Authorization header (any prefix the key rule accepts, any casing, plain or after a
 * JSON escape) whose value is a scheme word and a parameter list (CodeRabbit on #81, discussion_r4081238237):
 * `Authorization: Snowflake Token="..."`, `Authorization: Digest username="...", realm="...", nonce="...",
 * uri="...", response="..."`, `Authorization: OAuth oauth_token="..."`, any `<Scheme> <name>="..."` shape. The
 * match ends after the space that follows the scheme word, where the first parameter's name starts, and
 * scrubSchemeParameterList walks the list. A header value quoted whole (`Authorization: "Digest ..."`, a JSON
 * header object) is not this shape: the quoted-value rule below removes it whole.
 */
const AUTHORIZATION_PARAMETERS_PATTERN = new RegExp(
  String.raw`${KEY_BOUNDARY_PATTERN}([A-Za-z0-9_.-]*authorization)((?:\\*["'])?\s*[=:]\s*)(${ERROR_SCHEME_PATTERN})(\s+)(?=[A-Za-z])`,
  "gi",
);
/**
 * The parameters whose value describes the exchange rather than proves it, so they stay: Digest's `realm`,
 * `username`, `uri`, `qop`, `nc`, `algorithm`, `charset`, and `userhash` (RFC 7616), OAuth 1.0's consumer key (a
 * client identifier), signature method, timestamp, version, and callback (RFC 5849), and SigV4's `Credential`
 * (the access key id in front of the request scope, judged by the vendor prefix rule and the pair rule as before)
 * and `SignedHeaders`. Every other parameter is the proof or an opaque blob (`response`, `nonce`, `cnonce`,
 * `opaque`, `oauth_token`, `oauth_signature`, `oauth_nonce`, `Token`, `Session`, `value`) and its value becomes
 * the marker, quoted at any serialization depth or bare.
 */
const KEPT_SCHEME_PARAMETER_PATTERN =
  /^(?:realm|username|uri|qop|nc|algorithm|charset|userhash|oauth_consumer_key|oauth_signature_method|oauth_timestamp|oauth_version|oauth_callback|credential|signedheaders)$/i;
/**
 * The parameters whose name says the value is a proof wherever the list stands (CodeRabbit on #81,
 * discussion_r4081776771): Digest's `response`, a `signature` or `sig`, OAuth 1.0's `oauth_signature`, and the MAC
 * scheme's `mac`. In a challenge (see CHALLENGE_PARAMETERS_PATTERN) only these go; under an Authorization header
 * every parameter that is not kept goes, so this list never widens what that header gives up.
 */
const PROOF_SCHEME_PARAMETER_PATTERN = /^(?:response|signature|oauth_signature|mac|sig)$/i;
const REALM_PARAMETER_PATTERN = /^realm$/i;
/** Which values a parameter list gives up: every proof under an Authorization header, only the proof-named parameters in a challenge. */
type SchemeParameterListKind = "authorization" | "challenge";
const SCHEME_PARAMETER_NAME_PATTERN = /([A-Za-z][A-Za-z0-9_-]*)=(?!=)/y;
const SCHEME_PARAMETER_BARE_VALUE_PATTERN = /(?:\[REDACTED\]|[^\s"'&;,<>)\]}\\])+/y;
const SCHEME_PARAMETER_SEPARATOR_PATTERN = /\s*,\s*/y;

/**
 * Where the parameter value that starts at `start` ends, and the quote (plain or JSON-escaped) that encloses a
 * quoted value: a quoted value runs to its closing quote at the same depth on the same line (an escaped quote
 * inside it is part of it), a bare value ends where the pair rule's value ends. An unterminated quote or an
 * empty bare value is not a parameter value, so the list ends before it.
 */
function schemeParameterValueEnd(text: string, start: number): { end: number; quote?: string } | undefined {
  const newline = text.indexOf("\n", start);
  const line = text.slice(start, newline === -1 ? text.length : newline);
  const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
  if (opening) {
    const close = closingQuoteIndex(line, opening[0], opening[0].length);
    return close === -1 ? undefined : { end: start + close + opening[0].length, quote: opening[0] };
  }
  SCHEME_PARAMETER_BARE_VALUE_PATTERN.lastIndex = start;
  const bare = SCHEME_PARAMETER_BARE_VALUE_PATTERN.exec(text);
  return bare === null ? undefined : { end: start + bare[0].length };
}

/**
 * Walks the `name=value` parameter list that starts at `start`, the parameters separated by commas (RFC 7235),
 * each name shaped like a name (a base64 value with its padding, `cGFzc3dvcmQ=`, is no parameter). Under an
 * Authorization header a kept parameter passes whole and every other value becomes the marker; in a challenge
 * only a proof-named value does. The marker stands inside the value's own quotes, an empty value stays empty,
 * and a value that is already the marker is left as it is, so a second pass changes nothing. The list ends
 * before the first text that is not a parameter (prose, a `)`, the close of the JSON string that carried the
 * line, the `;` inside SigV4's `SignedHeaders=host;x-amz-date`), which the caller keeps; a separator with no
 * parameter after it is not consumed. Returns the end of the list, its scrubbed text, and whether a `realm`
 * parameter was among the parameters walked.
 */
function scrubSchemeParameterList(text: string, start: number, kind: SchemeParameterListKind): { end: number; replacement: string; realm: boolean } {
  let end = start;
  let replacement = "";
  let pending = "";
  let cursor = start;
  let realm = false;
  for (;;) {
    SCHEME_PARAMETER_NAME_PATTERN.lastIndex = cursor;
    const name = SCHEME_PARAMETER_NAME_PATTERN.exec(text);
    if (name === null || !isParameterName(name[1])) break;
    const valueStart = cursor + name[0].length;
    const value = schemeParameterValueEnd(text, valueStart);
    if (value === undefined) break;
    const quote = value.quote ?? "";
    const content = text.slice(valueStart + quote.length, value.end - quote.length);
    const kept =
      content.length === 0 || (kind === "authorization" ? KEPT_SCHEME_PARAMETER_PATTERN.test(name[1]) : !PROOF_SCHEME_PARAMETER_PATTERN.test(name[1]));
    if (REALM_PARAMETER_PATTERN.test(name[1])) realm = true;
    replacement += `${pending}${name[0]}${quote}${kept ? content : REDACTED_ERROR_VALUE}${quote}`;
    end = cursor = value.end;
    SCHEME_PARAMETER_SEPARATOR_PATTERN.lastIndex = cursor;
    const separator = SCHEME_PARAMETER_SEPARATOR_PATTERN.exec(text);
    if (separator === null) break;
    pending = separator[0];
    cursor += separator[0].length;
  }
  return { end, replacement, realm };
}

/**
 * Removes the proofs from every Authorization parameter list in the text (see AUTHORIZATION_PARAMETERS_PATTERN),
 * the header name, the scheme word, the parameter names, the kept parameters, their quotes, and the text after
 * the list staying. Runs before the quoted-value and scheme rules, which then see the marker where a proof
 * stood; a header name inside a list already walked (`Authorization: Digest opaque="Authorization: ..."`) is part
 * of that value.
 */
function scrubAuthorizationParameters(text: string): string {
  let scrubbed = "";
  let cursor = 0;
  for (const match of text.matchAll(AUTHORIZATION_PARAMETERS_PATTERN)) {
    if (match.index < cursor || !isCredentialNamedKey(match[1])) continue;
    const listStart = match.index + match[0].length;
    const { end, replacement } = scrubSchemeParameterList(text, listStart, "authorization");
    if (end === listStart) continue;
    scrubbed += text.slice(cursor, listStart) + replacement;
    cursor = end;
  }
  return scrubbed + text.slice(cursor);
}

/**
 * Where a parameter list that is not under an Authorization key may start (CodeRabbit on #81,
 * discussion_r4081776771): after a scheme word and its whitespace when a parameter follows (a WWW-Authenticate or
 * Proxy-Authenticate challenge, `Digest realm="api", nonce="n", response="..."` in prose or in a JSON string, any
 * casing), or at a `realm` parameter or a proof-named parameter standing on its own (`realm="api", nonce="n",
 * response="..."` as a data value, `response="...", realm="api"`). A list shaped like a challenge is not exempt
 * from the proof rule because the challenge names it: scrubChallengeParameters removes the proof-named values and
 * keeps the rest, where a list under an Authorization key has already given up every proof.
 */
const CHALLENGE_PARAMETERS_PATTERN = new RegExp(
  String.raw`(${NAME_BOUNDARY_PATTERN}(?:${ERROR_SCHEME_PATTERN})\s+)(?=[A-Za-z][A-Za-z0-9_-]*=(?!=))|${KEY_BOUNDARY_PATTERN}(?=(?:realm|response|signature|oauth_signature|mac|sig)=(?!=))`,
  "gi",
);

/**
 * Removes the proof-named values (see PROOF_SCHEME_PARAMETER_PATTERN) from every challenge-shaped parameter list in
 * the text: the list after a scheme word, whatever its parameters, and a bare list that holds a `realm` parameter,
 * before or after the proof. The scheme word, the parameter names, the other parameters (`realm`, `qop`,
 * `algorithm`, `opaque`, `error`, `error_description`), their quotes, and the text after the list stay, so
 * `WWW-Authenticate: Bearer realm="api"` and `Digest realm="api", qop="auth"` pass unchanged. A bare list with no
 * `realm` and no scheme word is data (`response="ok", status="done"`, `mac=aa:bb:cc:dd:ee:ff response=200`), as is
 * a `response` or `mac` field outside a parameter list (`"response": 403`). A list under an Authorization key has
 * already been walked by scrubAuthorizationParameters and holds markers where its proofs stood, which this pass
 * leaves as they are; a parameter name inside a value already walked is part of that value.
 */
function scrubChallengeParameters(text: string): string {
  let scrubbed = "";
  let cursor = 0;
  for (const match of text.matchAll(CHALLENGE_PARAMETERS_PATTERN)) {
    if (match.index < cursor) continue;
    const scheme: string | undefined = match[1];
    const listStart = match.index + match[0].length;
    const { end, replacement, realm } = scrubSchemeParameterList(text, listStart, "challenge");
    if (end === listStart || (scheme === undefined && !realm)) continue;
    scrubbed += text.slice(cursor, listStart) + replacement;
    cursor = end;
  }
  return scrubbed + text.slice(cursor);
}

/**
 * Whether the token after a bare scheme word in prose is a credential: long, or carrying a digit or a base64
 * symbol (padding included), or changing case inside the word, so prose such as "Basic authentication" and
 * "Bearer token is missing" stays. A `name=value` parameter list after the scheme (`Bearer realm="api"`, SigV4
 * `Credential=...`, `OAuth oauth_consumer_key=...`), its first value quoted (`quoteFollows`) or bare, is judged
 * parameter by parameter by scrubAuthorizationParameters, scrubChallengeParameters, and the pair rule, not as one
 * bearer value.
 */
function looksLikeSchemeCredential(value: string, quoteFollows = false): boolean {
  if (isSchemeParameterList(value, quoteFollows)) return false;
  return value.length >= 16 || /[\d+/=]/.test(value) || /[a-z][A-Z]/.test(value);
}

/** A pattern and its replacement: a string, or a callback typed as String.prototype.replace types it (the match, its groups, the offset, the text). */
type TextRule = readonly [RegExp, string | ((substring: string, ...args: any[]) => string)];

function applyTextRule(text: string, [pattern, replacement]: TextRule): string {
  return typeof replacement === "string" ? text.replace(pattern, replacement) : text.replace(pattern, replacement);
}

/**
 * Carrier rules: a value is removed because of what carries it (a quoted header or pair value, an authorization
 * scheme, a vendor token prefix, a JWT or PEM shape), not because of its own shape. The free-form header carriers
 * (Cookie, Set-Cookie, X-Auth-Key, X-Auth-Email) run first in scrubHeaderCarriers, the Authorization parameter
 * lists in scrubAuthorizationParameters, and the challenge proofs in scrubChallengeParameters, so these only ever
 * see the marker.
 */
const CARRIER_TEXT_PATTERNS: ReadonlyArray<TextRule> = [
  // Quoted header and pair values first, whatever their shape, so the scheme and pair rules see the marker. Under
  // an Authorization header a scheme word that opens the quoted value stays (`Authorization: "Bearer [REDACTED]"`).
  [
    ERROR_QUOTED_CREDENTIAL_PATTERN,
    (_match: string, key: string, separator: string, opening: string, _backslashes: string, _quote: string, content: string, closing: string) => {
      const scheme = AUTHORIZATION_KEY_PATTERN.test(key) ? PAIR_VALUE_SCHEME_PATTERN.exec(content)?.[0] ?? "" : "";
      return `${key}${separator}${opening}${scheme}${REDACTED_ERROR_VALUE}${closing}`;
    },
  ],
  [ERROR_QUOTED_SCHEME_PATTERN, QUOTED_VALUE_REPLACEMENT],
  [ERROR_QUOTED_SCHEME_PHRASE_PATTERN, QUOTED_SCHEME_PHRASE_REPLACEMENT],
  // Authorization scheme values wherever they appear (headers, cookies, HTML, JSON messages), in any casing of
  // the scheme word; looksLikeSchemeCredential keeps prose and parameter lists (a first parameter whose quoted
  // value follows the match included).
  [
    new RegExp(String.raw`${NAME_BOUNDARY_PATTERN}(${ERROR_SCHEME_PATTERN})\s+([A-Za-z0-9\-._~+/=:]{6,})`, "gi"),
    (match: string, scheme: string, value: string, offset: number, text: string) =>
      looksLikeSchemeCredential(value, quoteOpensAt(text, offset + match.length)) ? `${scheme} ${REDACTED_ERROR_VALUE}` : match,
  ],
  // Vendor token prefixes name the token type: AWS access key ids (long-term `AKIA`, temporary `ASIA`) and STS
  // bearer and context-specific credentials (`ABIA`, `ACCA`), Stripe secret and restricted keys, GitHub tokens,
  // Slack tokens. The prefix is the carrier, so these go from snapshots too (AWS evidence carries its access key
  // ids masked); the AWS unique ids of resources (roles, users, groups, policies) are bare shapes below.
  [/\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g, REDACTED_ERROR_VALUE],
  [/\b(?:gh[oprsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, REDACTED_ERROR_VALUE],
  [/\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g, REDACTED_ERROR_VALUE],
  // JWT-shaped strings.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED_ERROR_VALUE],
  // PEM blocks, whole or cut off.
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED_ERROR_VALUE],
];

/** Bare-shape rules: a value is removed for its own shape, wherever it stands. Error text only; a snapshot keeps its identifiers. */
const BARE_SHAPE_PATTERNS: ReadonlyArray<TextRule> = [
  // AWS unique ids of roles, users, groups, managed policies, policy versions, and public keys: opaque
  // identifiers in error text, resource names in a snapshot (an assumed-role principal is `AROA...:session`).
  [/\b(?:AROA|AIDA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
  // 40-character secret access keys, long secret-shaped blobs, and hex digests.
  [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, REDACTED_ERROR_VALUE],
  // Long blobs must carry a digit so camelCase identifiers survive.
  [/(?<![A-Za-z0-9+_=-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_=-])/g, REDACTED_ERROR_VALUE],
  [/\b[a-f0-9]{32,}\b/gi, REDACTED_ERROR_VALUE],
];

/**
 * URL userinfo, query, and fragment anywhere in the string, not only when the string starts with a URL: any
 * scheme (`https://`, `proxy://`), plain or with its slashes JSON-escaped (`https:\/\/`, reviewer #78 row C),
 * after a JSON escape as after any other boundary. The scheme, host, and path stay; the userinfo goes and the
 * query and the fragment each become the marker. The userinfo ends at the first `/`, `?`, or `#` as at
 * whitespace (CodeRabbit on #76), so an `@` inside a query or a fragment is not a userinfo boundary when the
 * authority before it is a host: `https://h?e=a@x.com&token=v` is host `h` with a query, which becomes the
 * marker whole. When that authority is not `host[:port]` (`svc:secret`, a password read up to a raw `?` or `#`
 * inside it) and an `@` follows in the run, the run up to that `@` is userinfo after all (scrubUrlMatch).
 */
const ERROR_URL_PATTERN = new RegExp(
  String.raw`(?:(?<![A-Za-z0-9+.\\-])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))([A-Za-z][A-Za-z0-9+.-]*:(?:\/\/|\\\/\\\/))(?:[^\s\/?#@"'<>\\]+@)?((?:[^\s?#"'<>\\]|\\\/)+)(\?(?:[^\s#"'<>\\]|\\\/)*)?(#(?:[^\s"'<>\\]|\\\/)*)?`,
  "g",
);
/** A URL authority that is `host[:port]`: a name or address, or a bracketed IPv6 address, with at most a numeric port. */
const HOST_AND_PORT_PATTERN = /^(?:\[[^\]\s]*\]|[^:\[\]@\\]+)(?::\d*)?$/;
/** The first path separator of a host-and-path run, plain or JSON-escaped. */
const PATH_START_PATTERN = /\\?\//;

/**
 * Renders one URL match: the userinfo is gone (the pattern never captures it) and the query and the fragment
 * are the marker. An authority that is not `host[:port]` followed by an `@` later in the run is a userinfo
 * whose password carried a raw `?` or `#`, so everything up to that `@` goes and the URL after it is rendered
 * on its own; with a valid authority the `@` belongs to the query or the fragment.
 */
function scrubUrlMatch(_match: string, scheme: string, hostPath: string, query?: string, fragment?: string): string {
  const pathStart = hostPath.search(PATH_START_PATTERN);
  const tail = `${query ?? ""}${fragment ?? ""}`;
  const at = tail.indexOf("@");
  if (pathStart === -1 && at !== -1 && !HOST_AND_PORT_PATTERN.test(hostPath)) {
    return `${scheme}${tail.slice(at + 1)}`.replace(ERROR_URL_PATTERN, scrubUrlMatch);
  }
  return `${scheme}${hostPath}${query ? `?${REDACTED_ERROR_VALUE}` : ""}${fragment ? `#${REDACTED_ERROR_VALUE}` : ""}`;
}

/**
 * Rule 9 scrub boundary for bare values. A run of 16 or more token characters is removed when it is shaped
 * like a token (base64 symbols, digits scattered through its letters, or casing that breaks into one- and
 * two-letter camelCase pieces) and kept when it is shaped like a name: "-" or "_" separated segments that are
 * each letters in any casing, digits alone, or letters with one digit group (`prod-us-east-2026`,
 * `AWSLambdaBasicExecutionRole`, `sha256`), an uppercase code, or a canonical UUID. "/", ".", ":", "@", and
 * whitespace end a run, so path segments, hostnames, ARNs, and emails are judged piece by piece. Opaque
 * identifiers whose shape is a token's are removed from error text as well; they travel in structured fields.
 */
// Trailing "=" is base64 padding only when a delimiter follows it; before a marker (`API_KEY=[REDACTED]`), a quote
// (`AWS_SECRET_ACCESS_KEY='[REDACTED]'`, `signature_method='ccg'`), an escape, or a path
// (`AWS_SHARED_CREDENTIALS_FILE=/home/audit/.aws/credentials`) it is the pair's separator, so the key keeps its name.
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&[/"'\\<]))?/g;
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
 * Rule 9 sink for error text. AzureApiError scrubs its own message and every recorded error string
 * (attempt results, access surfaces, tool results) passes through here again, so no path can carry a
 * credential echoed by an upstream error body, a transport error, or a URL into the audit output.
 */
export function redactErrorText(text: string): string {
  let scrubbed = scrubCarriers(text);
  for (const rule of BARE_SHAPE_PATTERNS) scrubbed = applyTextRule(scrubbed, rule);
  scrubbed = scrubCredentialPairs(scrubbed);
  return scrubLongTokens(scrubbed);
}

/** The carrier passes shared by error text and snapshot strings: configured secrets, URL userinfo, query, and fragment, header carriers, Authorization parameter lists, challenge proofs, quoted values, schemes, vendor token prefixes, JWT and PEM shapes. */
function scrubCarriers(text: string): string {
  let scrubbed = scrubConfiguredSecrets(text);
  scrubbed = scrubbed.replace(ERROR_URL_PATTERN, scrubUrlMatch);
  scrubbed = scrubHeaderCarriers(scrubbed);
  scrubbed = scrubAuthorizationParameters(scrubbed);
  scrubbed = scrubChallengeParameters(scrubbed);
  for (const rule of CARRIER_TEXT_PATTERNS) scrubbed = applyTextRule(scrubbed, rule);
  return scrubbed;
}

/**
 * Rule 9 data-side scrub for a string kept in a snapshot (reviewer D round 5 depth control): the carrier rules of
 * redactErrorText (the configured secrets in every encoded form, URL userinfo, query, and fragment strings, the free-form
 * header carriers, the proofs in Authorization parameter lists and in challenges, quoted header and pair values,
 * authorization schemes, vendor token prefixes, JWT and PEM shapes, and credential-named pairs) without its
 * bare-shape rules, so a value is removed for what carries it and an identifier, a digest, or a key id that is
 * data stays data.
 */
export function redactCarrierText(text: string): string {
  return scrubCredentialPairs(scrubCarriers(text));
}

/** Nesting past which an object or array in a snapshot is replaced by the marker; the value handed to the walker is depth 1. */
const SNAPSHOT_DEPTH_CAP = 32;
/**
 * Field names whose value in API data is a secret whatever its shape. Exact names, not the suffix rule of the error
 * text pair rule: a snapshot's own keys name collections about credentials (`tokens`, `credentials`,
 * `passwordCredentials`, `webauthncredentials`, `hardtoken`) that carry metadata, and those stay. The URL-valued
 * webhook keys are here because the token travels in the URL's path.
 */
const SNAPSHOT_SECRET_KEY_PATTERN =
  /^(?:secret[_-]?key|skey|secret|client[_-]?secret|api[_-]?secret|password|passwd|passphrase|private[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|secret[_-]?access[_-]?key|assertion|connection[_-]?string|authorization|cookie|set-cookie|x-auth-key|api[_-]?key|x-api-key|webhook(?:[_-]?url)?)$/i;
/**
 * The bearer-id override for snapshot keys (CodeRabbit r4077259415 on #78, harness revision 3): a key ending in
 * `secret_id` or `token_id`, any prefix, casing, and separator (`secret_id`, `VAULT_SECRET_ID`, `role_secret_id`,
 * `roleSecretId`, `token_id`, `tokenId`), holds a Vault AppRole secret id or a token id, which authenticates rather
 * than identifies, so its value is the marker whatever its shape; an `_id` key that identifies (`client_id`,
 * `tenant_id`, `key_id`, `user_id`) is data and stays.
 */
const SNAPSHOT_BEARER_ID_KEY_PATTERN = /(?:secret|token)[_-]?id$/i;

/** The snapshot walk behind scrubSnapshotValue and the integration's own data walkers: one key rule, one string rule, one cap. */
function scrubSnapshotTree(value: unknown, isSecretKey: (key: string) => boolean, depth: number): unknown {
  if (typeof value === "string") return redactCarrierText(value);
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Date) return value;
  if (depth > SNAPSHOT_DEPTH_CAP) return REDACTED_ERROR_VALUE;
  if (Array.isArray(value)) return value.map((entry) => scrubSnapshotTree(entry, isSecretKey, depth + 1));
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    output[key] = isSecretKey(key) ? snapshotMarkerFor(entry) : scrubSnapshotTree(entry, isSecretKey, depth + 1);
  }
  return output;
}

/** An absent or empty secret stays as it is (it reports that nothing was set); anything else is the marker. */
function snapshotMarkerFor(entry: unknown): unknown {
  return entry === undefined || entry === null || entry === "" ? entry : REDACTED_ERROR_VALUE;
}

/**
 * Rule 9 walk over a value about to be written to a bundle file or returned as data (reviewer D round 5 depth
 * control). Every string at every depth goes through redactCarrierText, so a carrier inside a benign-keyed string
 * (`detail: "Authorization: Bearer ..."`) is scrubbed in place with its siblings kept; a value under a secret
 * field name is the marker; an object or array nested past SNAPSHOT_DEPTH_CAP is the marker, so the depth of a
 * server-supplied tree bounds the work and nothing deeper than the cap is copied.
 */
export function scrubSnapshotValue(value: unknown): unknown {
  return scrubSnapshotTree(value, (key) => SNAPSHOT_SECRET_KEY_PATTERN.test(key) || SNAPSHOT_BEARER_ID_KEY_PATTERN.test(key), 1);
}

/**
 * A parser's message quotes the text it could not parse (V8: `Unexpected token '<', "<html>..." is not valid
 * JSON`), so a SyntaxError from any parse of a body or document is recorded by name only. Every JSON.parse in
 * this file already substitutes the status-and-length note in its own catch; this keeps the property even
 * for a parse failure that escapes one.
 */
function isParseError(error: unknown): boolean {
  return error instanceof SyntaxError || (typeof error === "object" && error !== null && (error as { name?: unknown }).name === "SyntaxError");
}

const PARSE_ERROR_NOTE = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";

/** The only way a thrown error becomes recorded text. */
function describeThrown(error: unknown): string {
  if (isParseError(error)) return PARSE_ERROR_NOTE;
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

const ERROR_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const TRANSPORT_CODE_PATTERN = /^E[A-Z_]{2,31}$/;
/** Detail for a rejection before any HTTP response: "no response (<name>: <scrubbed message> (<cause code>))". */
const NO_RESPONSE_PREFIX = "no response (";

/**
 * Describes a fetch rejection that produced no response (DNS, TLS, connection, timeout): the error's name when
 * it is not the plain Error, its scrubbed message, and the cause's network code (ENOTFOUND, ECONNREFUSED) when
 * it is one. Only the shape of the failure is kept; nothing is copied from a body because there was none.
 */
function describeNoResponse(error: unknown): string {
  const message = describeThrown(error);
  const name = error instanceof Error && ERROR_NAME_PATTERN.test(error.name) && error.name !== "Error" ? `${error.name}: ` : "";
  const cause = error instanceof Error ? (error as Error & { cause?: unknown }).cause : undefined;
  const code = cause instanceof Error || (typeof cause === "object" && cause !== null) ? (cause as { code?: unknown }).code : undefined;
  const codeText = typeof code === "string" && TRANSPORT_CODE_PATTERN.test(code) && !message.includes(code) ? ` (${code})` : "";
  return `${NO_RESPONSE_PREFIX}${name}${message}${codeText})`;
}

/** True when the recorded failure detail says the request produced no response at all. */
function isNoResponseFailure(result: { error: string; status?: number }): boolean {
  return result.status === undefined && describeTokenFailure(result).startsWith(NO_RESPONSE_PREFIX);
}

export class AzureApiError extends Error {
  constructor(
    message: string,
    readonly url: string,
    readonly status?: number,
  ) {
    super(redactErrorText(message));
    this.name = "AzureApiError";
  }
}

type Attempt<T> = { ok: true; value: T } | { ok: false; error: string; status?: number; url?: string };

/** The request URL without its query, so evidence names the observed request and never a token or filter value. */
function observedRequestUrl(error: unknown): string | undefined {
  if (!(error instanceof AzureApiError)) return undefined;
  return redactErrorText(error.url.split("?")[0]);
}

/** Why a server-supplied link is not followed. Each class renders as text that names the origins involved and never the link. */
type NextLinkRefusal = "foreign_origin" | "userinfo" | "unparseable";

/**
 * Same-origin rule for every URL taken from a response (`@odata.nextLink`, `nextLink`): resolved against the
 * configured base the way a browser would, so a relative link lands on the base and a protocol-relative
 * `//host/...` link names its own host, the link must keep the base's scheme, host, and port and carry no
 * userinfo. Anything else is refused before a request (and the bearer token) leaves for it.
 */
function nextLinkRefusal(target: string, base: string): NextLinkRefusal | undefined {
  let baseUrl: URL;
  let resolved: URL;
  try {
    baseUrl = new URL(base);
    resolved = new URL(target, baseUrl);
  } catch {
    return "unparseable";
  }
  if (resolved.username !== "" || resolved.password !== "") return "userinfo";
  if (resolved.origin === "null" || resolved.origin !== baseUrl.origin) return "foreign_origin";
  return undefined;
}

/**
 * The origin `target` names once resolved against `base`, as scheme, host, and port (`https://graph.microsoft.com:8443`)
 * or as the bare scheme of a URL without a host (`javascript:`, `data:`); undefined when it does not parse.
 */
function originLabel(target: string, base?: string): string | undefined {
  try {
    const url = new URL(target, base);
    return url.host.length > 0 ? `${url.protocol}//${url.host}` : url.protocol;
  } catch {
    return undefined;
  }
}

/**
 * The truncation reason recorded for a refused next link (harness revision 3, class 8): it names the configured
 * origin and, when the link resolved onto another one, that origin too (scheme, host, and port, or the bare
 * scheme of a `javascript:` or `data:` link), so the operator can see where the API tried to send the client.
 * Never the link itself: no path, query, fragment, or userinfo is recorded. A link on another origin and a
 * link with userinfo both parsed against the configured base (that is how they were classified), so their
 * origins are known; the unparseable class has no origin of its own to name.
 */
function nextLinkRefusalNote(refusal: NextLinkRefusal, target: string, base: string): string {
  const configuredOrigin = originLabel(base);
  const configured = configuredOrigin === undefined ? "the configured origin" : `the configured origin ${configuredOrigin}`;
  switch (refusal) {
    case "foreign_origin":
      return `the API advertised a next page on ${originLabel(target, base) ?? "another origin"} rather than ${configured}, so the link was not followed and no request was made for it`;
    case "userinfo": {
      const linkOrigin = originLabel(target, base);
      const where = linkOrigin === undefined || linkOrigin === configuredOrigin ? configured : `${linkOrigin} rather than ${configured}`;
      return `the API advertised a next page link carrying userinfo for ${where}, so the link was not followed and no request was made for it`;
    }
    case "unparseable":
      return `the API advertised a next page link that could not be parsed against ${configured}, so the link was not followed and no request was made for it`;
    default: {
      const exhaustive: never = refusal;
      return exhaustive;
    }
  }
}

/** Rendering of a request refused by the same-origin rule before it was made; the target itself is never recorded. */
const REQUEST_REFUSED_NOTE = "Request refused: the target is not on the configured origin, so no request was made.";

function resourceBase(cloud: AzureCloudEndpoints, resource: "graph" | "management"): string {
  return resource === "graph" ? cloud.graphBaseUrl : cloud.managementBaseUrl;
}

async function attempt<T>(load: () => Promise<T>): Promise<Attempt<T>> {
  try {
    return { ok: true, value: await load() };
  } catch (error) {
    const status = error instanceof AzureApiError ? error.status : undefined;
    return { ok: false, error: describeThrown(error), status, url: observedRequestUrl(error) };
  }
}

async function attemptPage(load: () => Promise<unknown>): Promise<Attempt<AzurePage>> {
  const result = await attempt(load);
  return result.ok ? { ok: true, value: toPage(result.value) } : result;
}

function finding(
  id: string,
  control: number,
  title: string,
  severity: AzureFinding["severity"],
  status: AzureFindingStatus,
  summary: string,
  evidence?: JsonRecord,
): AzureFinding {
  return { id, title, severity, status, summary, control, evidence, mappings: frameworkMappings(control) };
}

function describeFailure(result: { error: string; status?: number }): string {
  if (result.status === 401) return "401 Unauthorized";
  if (result.status === 403) return "403 Forbidden";
  if (result.status === 402) return "402 Payment Required (license)";
  return result.error.replace(/\s+/g, " ").slice(0, 160);
}

const TOKEN_ENDPOINT_SUFFIX = "/oauth2/v2.0/token";

/**
 * True when the recorded failure is the token request itself. Every resource read starts with
 * getToken, so a refused token means the finding's own endpoint was never requested and must
 * not be named as the request that failed.
 */
function isTokenRequestFailure(result: { url?: string }): boolean {
  return typeof result.url === "string" && result.url.endsWith(TOKEN_ENDPOINT_SUFFIX);
}

/** "POST /<tenant>/oauth2/v2.0/token", taken from the observed request URL rather than a constant. */
function tokenRequestLabel(result: { url?: string }): string {
  return `POST ${(result.url ?? "").replace(/^[a-z]+:\/\/[^/]+/i, "")}`;
}

/** Which API the finding's endpoint belongs to, from the documented endpoint label. */
function resourceApiFor(endpoint: string): string {
  return /\bMicrosoft\./.test(endpoint) ? "Azure Resource Manager" : "Microsoft Graph";
}

/** The failure detail without the "Token request failed:" prefix getToken adds, so it is not repeated after the request label. */
function describeTokenFailure(result: { error: string; status?: number }): string {
  return describeFailure(result).replace(/^Token request failed: /, "");
}

/**
 * "<request> returned 403 Forbidden" when a response arrived, "<request> received no response (...)" when the
 * request was rejected before any response, so a transport failure is never rendered as something the
 * endpoint returned.
 */
function requestOutcomeClause(request: string, result: { error: string; status?: number }): string {
  const detail = describeTokenFailure(result);
  return isNoResponseFailure(result) ? `${request} received ${detail}` : `${request} returned ${detail}`;
}

/** The host of the request that failed, taken from the observed URL, for the network remedy. */
function requestHost(result: { url?: string }): string {
  const match = /^[a-z]+:\/\/([^/?#]+)/i.exec(result.url ?? "");
  return match ? redactErrorText(match[1]) : "the endpoint";
}

/** The remedy for a failed token request: credentials when the endpoint answered, the network path when it did not. */
function tokenFailureRemedy(result: { error: string; status?: number; url?: string }): string {
  return isNoResponseFailure(result)
    ? `Restore network access to ${requestHost(result)} (DNS, TLS, proxy) so the token request receives a response`
    : "Fix the app registration's client credentials (tenant id, client id, client secret) so a token is issued";
}

/** Sentence and marker for a finding whose resource request never happened because the token request failed. */
function tokenFailureText(result: { error: string; status?: number; url?: string }, endpoint: string): { request: string; detail: string; outcome: string; remedy: string; api: string; marker: string } {
  const api = resourceApiFor(endpoint);
  const request = tokenRequestLabel(result);
  return {
    request,
    detail: describeTokenFailure(result),
    outcome: requestOutcomeClause(request, result),
    remedy: tokenFailureRemedy(result),
    api,
    marker: `not attempted: the token request failed, so no ${api} request was made`,
  };
}

/**
 * The error-log line for a failed read: "<request>: <detail>". When the token request was the one that failed
 * it is named instead of the finding's endpoint, as the outcome clause ("<request> returned <detail>") with the
 * note that no resource request was made: the token endpoint path ends in `token`, and a `path: value` pair
 * with a credential-named last segment loses its value to the error sink (harness revision 3, row D), so the
 * status is joined by "returned" rather than a colon.
 */
function failedReadNote(result: { error: string; status?: number; url?: string }, endpoint: string): string {
  if (isTokenRequestFailure(result)) {
    const token = tokenFailureText(result, endpoint);
    return `${token.outcome}; no ${token.api} request was made`;
  }
  return `${endpoint}: ${describeFailure(result)}`;
}

function manualForError(
  id: string,
  control: number,
  title: string,
  severity: AzureFinding["severity"],
  endpoint: string,
  requirement: string,
  evidenceToCollect: string,
  result: { error: string; status?: number; url?: string },
  docUrl: string,
  errors: string[],
): AzureFinding {
  errors.push(`${id} ${failedReadNote(result, endpoint)}`);
  if (isTokenRequestFailure(result)) {
    const token = tokenFailureText(result, endpoint);
    return finding(
      id,
      control,
      title,
      severity,
      "manual",
      `${token.outcome}, so no ${token.api} request was made for this finding. ${token.remedy}; the read then needs ${requirement}. Or collect ${evidenceToCollect} manually.`,
      {
        endpoint: token.request,
        http_status: result.status ?? null,
        request_url: result.url ?? null,
        error: result.error.slice(0, 300),
        resource_request: token.marker,
        required_access: requirement,
        evidence_to_collect: evidenceToCollect,
        documentation: [AZURE_ENDPOINT_DOCS.clientCredentials, docUrl],
      },
    );
  }
  const evidence = { endpoint, http_status: result.status ?? null, request_url: result.url ?? null, error: result.error.slice(0, 300), required_access: requirement, evidence_to_collect: evidenceToCollect, documentation: docUrl };
  if (isNoResponseFailure(result)) {
    // The request was made but nothing came back, so a missing permission cannot be inferred and is not recommended.
    return finding(
      id,
      control,
      title,
      severity,
      "manual",
      `${requestOutcomeClause(endpoint, result)}. Restore network access to ${requestHost(result)} (DNS, TLS, proxy) and re-run; the read needs ${requirement}. Or collect ${evidenceToCollect} manually.`,
      evidence,
    );
  }
  const detail = describeFailure(result);
  return finding(
    id,
    control,
    title,
    severity,
    "manual",
    `${endpoint} returned ${detail}. Grant ${requirement}, or collect ${evidenceToCollect} manually.`,
    evidence,
  );
}

function partialNote(page: AzurePage, label: string): string {
  if (!page.truncated) return "";
  const total = page.total !== undefined ? String(page.total) : "unknown";
  const reason = page.truncation ? `; ${page.truncation}` : "";
  return ` Inventory of ${label} is partial (${page.seen} seen of ${total} total${reason}); verdict capped at warn.`;
}

function capForPartial(status: AzureFindingStatus, ...pages: AzurePage[]): AzureFindingStatus {
  if (status === "pass" && pages.some((page) => page.truncated)) return "warn";
  return status;
}

function pageEvidence(page: AzurePage): JsonRecord {
  return { seen: page.seen, total: page.total ?? null, truncated: page.truncated, ...(page.truncation ? { truncation: page.truncation } : {}) };
}

/** Every JSON file the bundle writes goes through the snapshot walk first (rule 9 at every depth, with the cap). */
function serializeJson(value: unknown): string {
  return `${JSON.stringify(scrubSnapshotValue(value), null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "azure";
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
  for (let index = 1; index <= 50; index += 1) {
    const suffix = index === 1 ? "" : `-${index}`;
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

function defaultCommandRunner(command: string, args: string[]): string | undefined {
  try {
    const output = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: DEFAULT_COMMAND_TIMEOUT_MS,
    });
    const trimmed = output.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

export function resolveAzureCloud(authorityHost?: string, overrides: { graphHost?: string; managementHost?: string } = {}): AzureCloudEndpoints {
  const normalizedHost = (authorityHost ?? "login.microsoftonline.com")
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "")
    .toLowerCase();
  const known = AZURE_CLOUDS[normalizedHost];
  if (!known) {
    throw new Error(`Unsupported AZURE_AUTHORITY_HOST "${authorityHost}". Supported: ${Object.keys(AZURE_CLOUDS).join(", ")}.`);
  }
  const cloud: AzureCloudEndpoints = { ...known };
  if (overrides.graphHost) cloud.graphBaseUrl = `https://${overrides.graphHost.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`;
  if (overrides.managementHost) cloud.managementBaseUrl = `https://${overrides.managementHost.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`;
  return cloud;
}

export function resolveAzureConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  commandRunner: AzureCommandRunner = defaultCommandRunner,
): AzureResolvedConfig {
  const sourceChain: string[] = [];
  const cloud = resolveAzureCloud(asString(input.authority_host) ?? asString(env.AZURE_AUTHORITY_HOST), {
    graphHost: asString(env.AZURE_GRAPH_HOST),
    managementHost: asString(env.AZURE_MANAGEMENT_HOST),
  });

  const clientId = asString(input.client_id) ?? asString(env.AZURE_CLIENT_ID);
  const clientSecret = asString(input.client_secret) ?? asString(env.AZURE_CLIENT_SECRET);
  const certificatePath = asString(env.AZURE_CLIENT_CERTIFICATE_PATH);
  if (clientId && !clientSecret && certificatePath) {
    throw new Error("AZURE_CLIENT_CERTIFICATE_PATH is documented but certificate credentials are not implemented in this slice; use AZURE_CLIENT_SECRET or pass tokens.");
  }
  const clientCredentials = clientId && clientSecret ? { clientId, clientSecret } : undefined;
  const useCli = (command: string, args: string[]): string | undefined => (clientCredentials ? undefined : commandRunner(command, args));

  const tenantId = asString(input.tenant_id)
    ?? asString(env.AZURE_TENANT_ID)
    ?? useCli("az", ["account", "show", "--query", "tenantId", "-o", "tsv"]);
  if (asString(input.tenant_id)) sourceChain.push("arguments-tenant");
  else if (asString(env.AZURE_TENANT_ID)) sourceChain.push("environment-tenant");
  else if (tenantId) sourceChain.push("azure-cli-tenant");

  const subscriptionId = asString(input.subscription_id)
    ?? asString(env.AZURE_SUBSCRIPTION_ID)
    ?? useCli("az", ["account", "show", "--query", "id", "-o", "tsv"]);
  if (asString(input.subscription_id)) sourceChain.push("arguments-subscription");
  else if (asString(env.AZURE_SUBSCRIPTION_ID)) sourceChain.push("environment-subscription");
  else if (subscriptionId) sourceChain.push("azure-cli-subscription");

  const graphToken = asString(input.graph_token)
    ?? asString(env.AZURE_GRAPH_TOKEN)
    ?? useCli("az", [
      "account",
      "get-access-token",
      "--resource",
      `${cloud.graphBaseUrl}/`,
      "--query",
      "accessToken",
      "-o",
      "tsv",
      ...(tenantId ? ["--tenant", tenantId] : []),
    ]);
  if (asString(input.graph_token)) sourceChain.push("arguments-graph-token");
  else if (asString(env.AZURE_GRAPH_TOKEN)) sourceChain.push("environment-graph-token");
  else if (graphToken) sourceChain.push("azure-cli-graph-token");

  const managementToken = asString(input.management_token)
    ?? asString(env.AZURE_MANAGEMENT_TOKEN)
    ?? asString(env.AZURE_ACCESS_TOKEN)
    ?? useCli("az", [
      "account",
      "get-access-token",
      "--resource",
      `${cloud.managementBaseUrl}/`,
      "--query",
      "accessToken",
      "-o",
      "tsv",
      ...(tenantId ? ["--tenant", tenantId] : []),
      ...(subscriptionId ? ["--subscription", subscriptionId] : []),
    ]);
  if (asString(input.management_token)) sourceChain.push("arguments-management-token");
  else if (asString(env.AZURE_MANAGEMENT_TOKEN) || asString(env.AZURE_ACCESS_TOKEN)) {
    sourceChain.push("environment-management-token");
  } else if (managementToken) {
    sourceChain.push("azure-cli-management-token");
  }
  if (clientCredentials && (!graphToken || !managementToken)) sourceChain.push("client-credentials");

  if (!tenantId) throw new Error("Unable to resolve an Azure tenant ID from arguments, environment, or az account show.");
  if (!subscriptionId) throw new Error("Unable to resolve an Azure subscription ID from arguments, environment, or az account show.");
  if (!graphToken && !clientCredentials) throw new Error("Unable to resolve a Microsoft Graph access token from arguments, environment, az account get-access-token, or AZURE_CLIENT_ID/AZURE_CLIENT_SECRET.");
  if (!managementToken && !clientCredentials) throw new Error("Unable to resolve an Azure management access token from arguments, environment, az account get-access-token, or AZURE_CLIENT_ID/AZURE_CLIENT_SECRET.");

  return {
    tenantId,
    subscriptionId,
    graphToken: graphToken ?? "",
    managementToken: managementToken ?? "",
    sourceChain: [...new Set(sourceChain)],
    cloud,
    clientCredentials,
  };
}

function describeSourceChain(config: AzureResolvedConfig): string {
  return `Azure tenant ${config.tenantId} / subscription ${config.subscriptionId} (${config.cloud?.name ?? "public"} cloud)`;
}

function normalizeRoleName(value: unknown): string | undefined {
  return asLower(value);
}

function isPrivilegedDirectoryRole(name?: string): boolean {
  return [...PRIVILEGED_ROLE_TEMPLATE_IDS.values()].includes(name ?? "");
}

function isOwnerRole(name?: string): boolean {
  return name === "owner";
}

function isContributorRole(name?: string): boolean {
  return name === "contributor";
}

function roleDefinitionIdTail(value: string | undefined): string | undefined {
  return value?.split("/").at(-1)?.toLowerCase();
}

type SurfaceSummary = { count?: number; truncated?: boolean; truncation?: string };

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  summarize?: (value: unknown) => SurfaceSummary,
): Promise<AzureAccessSurface> {
  try {
    const value = await load();
    const summary = summarize?.(value) ?? {};
    return {
      name,
      service,
      status: "readable",
      count: summary.count,
      ...(summary.truncated ? { truncated: true } : {}),
      ...(summary.truncated && summary.truncation ? { truncation: summary.truncation } : {}),
    };
  } catch (error) {
    // A probe that never completed has no count or paging outcome; both stay null and the
    // status and URL are the ones the request observed.
    return {
      name,
      service,
      status: "not_readable",
      count: null,
      truncated: null,
      http_status: error instanceof AzureApiError ? error.status ?? null : null,
      request_url: observedRequestUrl(error) ?? null,
      error: describeThrown(error),
    };
  }
}

/** Keeps the page's truncated flag next to its count so a capped probe is never reported as the full inventory. */
function pageSummary(value: unknown): SurfaceSummary {
  if (Array.isArray(value)) return { count: value.length };
  const page = asObject(value);
  if (!page || !Array.isArray(page.items)) return {};
  return { count: page.items.length, truncated: page.truncated === true, truncation: asString(page.truncation) };
}

/**
 * One note per way the probes stopped short: surfaces that hit the probe page cap share the cap note, and
 * surfaces whose walk stopped for a recorded reason (a refused next link) share a note carrying that reason.
 */
function truncatedProbeNotes(surfaces: AzureAccessSurface[]): string[] {
  const capped = surfaces.filter((item) => item.truncated && !item.truncation).map((item) => item.name);
  const byReason = new Map<string, string[]>();
  for (const item of surfaces) {
    if (!item.truncated || !item.truncation) continue;
    byReason.set(item.truncation, [...(byReason.get(item.truncation) ?? []), item.name]);
  }
  return [
    ...(capped.length > 0 ? [`Probe counts for ${capped.join(", ")} stopped at the probe page cap and are lower bounds, not inventory sizes.`] : []),
    ...[...byReason.entries()].map(([reason, names]) => `Probe counts for ${names.join(", ")} are lower bounds, not inventory sizes: ${reason}.`),
  ];
}

/**
 * Reduces an error response body to its documented error envelope so bundle logs never
 * echo raw payloads: Graph and ARM return `{ error: { code, message } }`, the token
 * endpoint returns `{ error, error_description }`. Non-JSON bodies are dropped entirely.
 * https://learn.microsoft.com/en-us/graph/errors and
 * https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
 */
/**
 * Reduces an error response body to the vendor's documented fields: Graph/ARM `error.code` and
 * `error.message`, or the OAuth `error` and `error_description`. Any body that is not a JSON object,
 * whatever its content type claims, is described by status shape and length and never quoted.
 */
export function describeErrorBody(text: string, contentType?: string | null): string {
  if (!text.trim()) return "";
  const nonJson = `non-JSON body (${contentType?.split(";")[0]?.trim() || "unknown content type"}, ${Buffer.byteLength(text, "utf8")} bytes)`;
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    return nonJson;
  }
  const record = asObject(payload);
  if (!record) return nonJson;
  const envelope = asObject(record.error);
  if (envelope) {
    const code = asString(envelope.code);
    const message = clipVendorMessage(asString(envelope.message));
    return [code, message].filter(Boolean).join(": ") || "error body without code or message";
  }
  const oauthError = asString(record.error);
  if (oauthError) {
    const description = clipVendorMessage(asString(record.error_description));
    return description ? `${oauthError}: ${description}` : oauthError;
  }
  return "error body without code or message";
}

const VENDOR_MESSAGE_LIMIT = 160;

/**
 * Shortens a vendor's free-text error message for the recorded line. The scrub runs over the whole message
 * first and the cut falls on a whitespace boundary of the scrubbed text, so a credential that straddles the
 * cut is removed whole instead of leaving its first characters as a fragment too short for the bare-token
 * rule to recognise (round 4 item D).
 */
export function clipVendorMessage(message: string | undefined): string | undefined {
  if (message === undefined) return undefined;
  const scrubbed = redactErrorText(message.replace(/\s+/g, " ").trim());
  if (scrubbed.length <= VENDOR_MESSAGE_LIMIT) return scrubbed;
  const cut = scrubbed.lastIndexOf(" ", VENDOR_MESSAGE_LIMIT);
  return scrubbed.slice(0, cut > 0 ? cut : VENDOR_MESSAGE_LIMIT).trimEnd();
}

/**
 * Drops every secret-bearing credential property before a service principal or
 * application record is kept. Graph list responses carry passwordCredential.hint
 * (the first characters of the secret) and keyCredential.key; the findings only
 * read the schedule fields.
 * https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential and
 * https://learn.microsoft.com/en-us/graph/api/resources/keycredential
 */
export function projectCredentialCarrier(record: JsonRecord): JsonRecord {
  const { passwordCredentials, keyCredentials, ...rest } = record;
  return {
    ...rest,
    passwordCredentials: asRecords(passwordCredentials).map((credential) => ({
      keyId: credential.keyId ?? null,
      displayName: credential.displayName ?? null,
      startDateTime: credential.startDateTime ?? null,
      endDateTime: credential.endDateTime ?? null,
    })),
    keyCredentials: asRecords(keyCredentials).map((credential) => ({
      keyId: credential.keyId ?? null,
      displayName: credential.displayName ?? null,
      type: credential.type ?? null,
      usage: credential.usage ?? null,
      startDateTime: credential.startDateTime ?? null,
      endDateTime: credential.endDateTime ?? null,
    })),
  };
}

function projectPage(page: AzurePage, project: (record: JsonRecord) => JsonRecord): AzurePage {
  return { ...page, items: page.items.map(project) };
}

export class AzureAuditorClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private readonly cloud: AzureCloudEndpoints;
  private readonly tokenCache = new Map<string, { token: string; expiresAt: number }>();

  constructor(
    private readonly config: AzureResolvedConfig,
    options: { fetchImpl?: FetchImpl; now?: () => Date } = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.cloud = config.cloud ?? AZURE_CLOUDS["login.microsoftonline.com"];
    registerConfiguredSecrets(config.graphToken, config.managementToken, config.clientCredentials?.clientSecret);
  }

  getResolvedConfig(): AzureResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  getCloud(): AzureCloudEndpoints {
    return this.cloud;
  }

  /**
   * OAuth 2.0 client credentials grant.
   * https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
   */
  async getToken(resource: "graph" | "management"): Promise<string> {
    const explicit = resource === "graph" ? this.config.graphToken : this.config.managementToken;
    if (explicit) return explicit;
    const credentials = this.config.clientCredentials;
    if (!credentials) throw new Error(`No ${resource} token or client credentials are available.`);
    const cached = this.tokenCache.get(resource);
    if (cached && cached.expiresAt > this.now().getTime() + 60_000) return cached.token;

    const scopeBase = resource === "graph" ? this.cloud.graphBaseUrl : this.cloud.managementBaseUrl;
    const url = `${this.cloud.authorityHost}/${this.config.tenantId}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
      scope: `${scopeBase}/.default`,
      grant_type: "client_credentials",
    });
    // A rejection before any response (DNS, TLS, connection, timeout) is still the token request failing: it is
    // wrapped with the token URL so the findings name this request and state that no resource request was made,
    // instead of blaming the Graph or ARM endpoint that was never called.
    const response = await this.send(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }, "Token request failed: ");
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      const detail = describeErrorBody(text, response.headers.get("content-type"));
      throw new AzureApiError(`Token request failed: ${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`, url, response.status);
    }
    const payload = this.parseJsonBody(text, response, url, "Token request");
    const token = asString(payload.access_token);
    if (!token) throw new AzureApiError("Token response did not include access_token.", url);
    registerConfiguredSecrets(token);
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.tokenCache.set(resource, { token, expiresAt: this.now().getTime() + expiresIn * 1000 });
    return token;
  }

  /** A 2xx body that is not JSON (a proxy login page, an HTML error) is described by shape, never echoed. */
  private parseJsonBody(text: string, response: Response, url: string, label: string): JsonRecord {
    if (text.trim().length === 0) return {};
    try {
      return asObject(JSON.parse(text)) ?? {};
    } catch {
      throw new AzureApiError(`${label} returned ${response.status} ${response.statusText}: ${describeErrorBody(text, response.headers.get("content-type"))}`, url, response.status);
    }
  }

  /**
   * One fetch with its pre-response rejection wrapped: the observed URL and the shape of the failure travel in an
   * AzureApiError with no status, so `request_url` names the request that was actually made and `http_status`
   * stays null. Nothing is read from a body because none arrived.
   */
  private async send(url: string, init: RequestInit, prefix = ""): Promise<Response> {
    try {
      return await this.fetchImpl(url, init);
    } catch (error) {
      if (error instanceof AzureApiError) throw error;
      // A parser error raised inside the transport keeps its fixed note; anything else produced no response.
      throw new AzureApiError(`${prefix}${isParseError(error) ? PARSE_ERROR_NOTE : describeNoResponse(error)}`, url);
    }
  }

  private async requestJson(url: string, resource: "graph" | "management", init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<JsonRecord> {
    // The same-origin rule sits in front of the transport, so no URL that left the configured Graph or ARM
    // origin can be fetched with the bearer token, whichever path handed it in. The error names the configured
    // base, not the target.
    const base = resourceBase(this.cloud, resource);
    if (nextLinkRefusal(url, base)) throw new AzureApiError(REQUEST_REFUSED_NOTE, base);
    const token = await this.getToken(resource);
    const response = await this.send(url, {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
      ...(init.body ? { body: init.body } : {}),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      const detail = describeErrorBody(text, response.headers.get("content-type"));
      throw new AzureApiError(`${response.status} ${response.statusText}${detail ? `: ${detail}` : ""}`, url, response.status);
    }
    const text = await response.text();
    return this.parseJsonBody(text, response, url, "Request");
  }

  /**
   * Shared next-link walk for Graph and ARM. Every early exit reports `truncated: true`:
   * the item cap, a next link that repeats the page just fetched, an empty page that
   * still advertises a next link (both would otherwise loop forever), and a next link that
   * leaves the configured origin, which is refused before any request is made for it and
   * recorded as the page's `truncation` reason.
   */
  private async collectPages(
    firstUrl: string,
    base: string,
    limit: number,
    fetchPage: (url: string) => Promise<JsonRecord>,
    nextLinkOf: (response: JsonRecord) => string | undefined,
    totalOf?: (response: JsonRecord) => number | undefined,
  ): Promise<AzurePage> {
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let nextUrl: string | undefined = firstUrl;
    while (nextUrl) {
      const currentUrl: string = nextUrl;
      const response = await fetchPage(currentUrl);
      if (totalOf) total ??= totalOf(response);
      const pageItems = asRecords(response.value);
      items.push(...pageItems);
      const nextLink = nextLinkOf(response);
      if (!nextLink) break;
      const refusal = nextLinkRefusal(nextLink, base);
      if (refusal) {
        return { items: items.slice(0, limit), truncated: true, seen: Math.min(items.length, limit), total, truncation: nextLinkRefusalNote(refusal, nextLink, base) };
      }
      // Passed the rule, so it resolves onto the configured base (a relative link becomes absolute there).
      nextUrl = new URL(nextLink, base).toString();
      const stalled = nextUrl === currentUrl || pageItems.length === 0;
      if (stalled || items.length >= limit) {
        return { items: items.slice(0, limit), truncated: true, seen: Math.min(items.length, limit), total };
      }
    }
    return { items, truncated: false, seen: items.length, total: total ?? items.length };
  }

  /** Graph paging via @odata.nextLink, https://learn.microsoft.com/en-us/graph/paging */
  private async collectGraph(path: string, limit = 5000, headers: Record<string, string> = {}): Promise<AzurePage> {
    return this.collectPages(
      path.startsWith("http") ? path : `${this.cloud.graphBaseUrl}${path}`,
      this.cloud.graphBaseUrl,
      limit,
      (url) => this.requestJson(url, "graph", { headers }),
      (response) => asString(response["@odata.nextLink"]),
      (response) => asNumber(response["@odata.count"]),
    );
  }

  /** ARM paging via nextLink, https://learn.microsoft.com/en-us/rest/api/azure/ */
  private async collectArm(path: string, limit = 5000): Promise<AzurePage> {
    return this.collectPages(
      path.startsWith("http") ? path : `${this.cloud.managementBaseUrl}${path}`,
      this.cloud.managementBaseUrl,
      limit,
      (url) => this.requestJson(url, "management"),
      (response) => asString(response.nextLink),
    );
  }

  private graph(path: string): string {
    return `${this.cloud.graphBaseUrl}${path}`;
  }

  private arm(path: string): string {
    return `${this.cloud.managementBaseUrl}${path}`;
  }

  async getOrganization(): Promise<JsonRecord | null> {
    const page = await this.collectGraph("/v1.0/organization");
    return page.items[0] ?? null;
  }

  async listConditionalAccessPolicies(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/identity/conditionalAccess/policies");
  }

  async listUserRegistrationDetails(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/reports/authenticationMethods/userRegistrationDetails");
  }

  async listDirectoryRoles(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/directoryRoles");
  }

  async listDirectoryRoleMembers(roleId: string): Promise<AzurePage> {
    return this.collectGraph(`/v1.0/directoryRoles/${encodeURIComponent(roleId)}/members`);
  }

  async getSecurityDefaultsPolicy(): Promise<JsonRecord | null> {
    return this.requestJson(this.graph("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"), "graph");
  }

  async getAuthorizationPolicy(): Promise<JsonRecord | null> {
    return this.requestJson(this.graph("/v1.0/policies/authorizationPolicy"), "graph");
  }

  async listServicePrincipals(): Promise<AzurePage> {
    const page = await this.collectGraph("/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId,passwordCredentials,keyCredentials");
    return projectPage(page, projectCredentialCarrier);
  }

  async listApplications(): Promise<AzurePage> {
    const page = await this.collectGraph("/v1.0/applications?$top=999&$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$expand=owners($select=id)");
    return projectPage(page, projectCredentialCarrier);
  }

  async listOAuth2PermissionGrants(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/oauth2PermissionGrants");
  }

  /** List users caps $top at 500 whenever $select or $filter includes signInActivity. */
  async listGuestUsers(): Promise<AzurePage> {
    return this.collectGraph(
      "/v1.0/users?$filter=userType eq 'Guest'&$count=true&$top=500&$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState,signInActivity",
      5000,
      { ConsistencyLevel: "eventual" },
    );
  }

  async listMemberUsers(limit: number): Promise<AzurePage> {
    return this.collectGraph(
      "/v1.0/users?$filter=userType eq 'Member' and accountEnabled eq true&$count=true&$top=999&$select=id,userPrincipalName,mail",
      limit,
      { ConsistencyLevel: "eventual" },
    );
  }

  async listInboxMessageRules(userId: string): Promise<AzurePage> {
    return this.collectGraph(`/v1.0/users/${encodeURIComponent(userId)}/mailFolders/inbox/messageRules`);
  }

  async listRiskyUsers(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'");
  }

  async listRiskDetections(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/identityProtection/riskDetections?$top=500", 500);
  }

  async listSubscribedSkus(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/subscribedSkus");
  }

  async listRoleEligibilitySchedules(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/roleManagement/directory/roleEligibilitySchedules");
  }

  async listRoleAssignmentSchedules(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/roleManagement/directory/roleAssignmentSchedules?$filter=assignmentType eq 'Assigned'");
  }

  async listDeviceCompliancePolicies(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/deviceManagement/deviceCompliancePolicies");
  }

  async listManagedDevices(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/deviceManagement/managedDevices?$select=id,deviceName,complianceState,lastSyncDateTime");
  }

  /** The tenant-wide (application) sensitivity label list is documented only under /beta. */
  async listSensitivityLabels(): Promise<AzurePage> {
    return this.collectGraph("/beta/security/informationProtection/sensitivityLabels");
  }

  async getSharePointSettings(): Promise<JsonRecord | null> {
    return this.requestJson(this.graph("/v1.0/admin/sharepoint/settings"), "graph");
  }

  async listSecureScores(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/security/secureScores?$top=20", 20);
  }

  async listSecurityAlerts(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/security/alerts_v2?$top=50", 200);
  }

  async listDirectoryAudits(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/auditLogs/directoryAudits?$top=50", 200);
  }

  async listSignIns(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/auditLogs/signIns?$top=50", 200);
  }

  async getSubscription(): Promise<JsonRecord | null> {
    return this.requestJson(
      this.arm(`/subscriptions/${this.config.subscriptionId}?api-version=${AZURE_ARM_API_VERSIONS.subscription}`),
      "management",
    );
  }

  async listDefenderPricings(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Security/pricings?api-version=${AZURE_ARM_API_VERSIONS.defenderPricings}`);
  }

  async listDiagnosticSettings(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Insights/diagnosticSettings?api-version=${AZURE_ARM_API_VERSIONS.diagnosticSettings}`);
  }

  async listLogAnalyticsWorkspaces(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.OperationalInsights/workspaces?api-version=${AZURE_ARM_API_VERSIONS.logAnalyticsWorkspaces}`);
  }

  async listSecurityContacts(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=${AZURE_ARM_API_VERSIONS.securityContacts}`);
  }

  async listRoleAssignments(limit = DEFAULT_MAX_ASSIGNMENTS): Promise<AzurePage> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=${AZURE_ARM_API_VERSIONS.roleAssignments}&$filter=atScope()`,
      limit,
    );
  }

  async listRoleDefinitions(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?api-version=${AZURE_ARM_API_VERSIONS.roleDefinitions}`);
  }

  async listNetworkWatchers(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Network/networkWatchers?api-version=${AZURE_ARM_API_VERSIONS.networkWatchers}`);
  }

  async listFlowLogs(resourceGroupName: string, networkWatcherName: string): Promise<AzurePage> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/resourceGroups/${encodeURIComponent(resourceGroupName)}/providers/Microsoft.Network/networkWatchers/${encodeURIComponent(networkWatcherName)}/flowLogs?api-version=${AZURE_ARM_API_VERSIONS.flowLogs}`,
    );
  }

  async listNetworkSecurityGroups(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=${AZURE_ARM_API_VERSIONS.networkSecurityGroups}`);
  }

  async listKeyVaults(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=${AZURE_ARM_API_VERSIONS.keyVaults}`);
  }

  async listStorageAccounts(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=${AZURE_ARM_API_VERSIONS.storageAccounts}`);
  }

  async listPolicyAssignments(): Promise<AzurePage> {
    return this.collectArm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Authorization/policyAssignments?api-version=${AZURE_ARM_API_VERSIONS.policyAssignments}&$filter=atScope()`);
  }

  async summarizePolicyStates(): Promise<JsonRecord | null> {
    return this.requestJson(
      this.arm(`/subscriptions/${this.config.subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=${AZURE_ARM_API_VERSIONS.policyStatesSummarize}`),
      "management",
      { method: "POST" },
    );
  }
}

type IdentityClient = Pick<
  AzureAuditorClient,
  "getNow" | "listConditionalAccessPolicies" | "listUserRegistrationDetails" | "listDirectoryRoles" | "listDirectoryRoleMembers" | "getSecurityDefaultsPolicy" | "listServicePrincipals"
> & Partial<Pick<
  AzureAuditorClient,
  "getAuthorizationPolicy" | "listGuestUsers" | "listRiskyUsers" | "listRiskDetections" | "listSubscribedSkus" | "listRoleEligibilitySchedules" | "listRoleAssignmentSchedules" | "listApplications" | "listOAuth2PermissionGrants"
>>;

type MonitoringClient = Pick<
  AzureAuditorClient,
  "listSecureScores" | "listSecurityAlerts" | "listDirectoryAudits" | "listSignIns" | "listDefenderPricings" | "listDiagnosticSettings"
> & Partial<Pick<AzureAuditorClient, "listLogAnalyticsWorkspaces">>;

type GuardrailsClient = Pick<AzureAuditorClient, "listRoleAssignments" | "listRoleDefinitions" | "listSecurityContacts" | "listNetworkWatchers">;

type DataProtectionClient = Pick<
  AzureAuditorClient,
  "getNow" | "listConditionalAccessPolicies" | "listSubscribedSkus" | "listDeviceCompliancePolicies" | "listManagedDevices" | "listSensitivityLabels" | "listKeyVaults" | "listStorageAccounts" | "listMemberUsers" | "listInboxMessageRules" | "getSharePointSettings"
>;

type NetworkPolicyClient = Pick<AzureAuditorClient, "listNetworkSecurityGroups" | "listPolicyAssignments" | "summarizePolicyStates" | "listNetworkWatchers" | "listFlowLogs">;

function optionalCall<T>(method: (() => Promise<T>) | undefined, missing: string): () => Promise<T> {
  return method ?? (async () => {
    throw new Error(`not attempted: this client does not expose ${missing}, so no request was made.`);
  });
}

export async function checkAzureAccess(
  client: Pick<
    AzureAuditorClient,
    "getResolvedConfig" | "getOrganization" | "listConditionalAccessPolicies" | "listDirectoryRoles" | "listSecureScores" | "listDefenderPricings" | "listRoleAssignments" | "listDiagnosticSettings" | "listSecurityContacts"
  >,
): Promise<AzureAccessCheckResult> {
  const config = client.getResolvedConfig();
  const surfaces = await Promise.all([
    surface("organization", "graph", () => client.getOrganization(), () => ({ count: 1 })),
    surface("conditional_access", "graph", () => client.listConditionalAccessPolicies(), pageSummary),
    surface("directory_roles", "graph", () => client.listDirectoryRoles(), pageSummary),
    surface("secure_scores", "graph", () => client.listSecureScores(), pageSummary),
    surface("defender_pricings", "arm", () => client.listDefenderPricings(), pageSummary),
    surface("role_assignments", "arm", () => client.listRoleAssignments(25), pageSummary),
    surface("diagnostic_settings", "arm", () => client.listDiagnosticSettings(), pageSummary),
    surface("security_contacts", "arm", () => client.listSecurityContacts(), pageSummary),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 6 ? "healthy" : "limited";
  // A probe that failed at the token request never reached its resource; the note names the request that was made.
  const tokenFailures = surfaces.filter((item) => item.status === "not_readable" && isTokenRequestFailure({ url: item.request_url ?? undefined }));
  const tokenFailure = tokenFailures[0]
    ? { error: tokenFailures[0].error ?? "", status: tokenFailures[0].http_status ?? undefined, url: tokenFailures[0].request_url ?? undefined }
    : undefined;
  const tokenNote = tokenFailure
    ? `${requestOutcomeClause(tokenRequestLabel(tokenFailure), tokenFailure)}; no resource request was made for ${tokenFailures.map((item) => item.name).join(", ")}.`
    : undefined;
  const notes = [
    `Authenticated against ${describeSourceChain(config)}.`,
    `${readableCount}/${surfaces.length} Azure audit surfaces are readable.`,
    ...(tokenNote ? [tokenNote] : []),
    ...truncatedProbeNotes(surfaces),
  ];

  return {
    status,
    tenantId: config.tenantId,
    subscriptionId: config.subscriptionId,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run azure_assess_identity, azure_assess_monitoring, azure_assess_subscription_guardrails, azure_assess_data_protection, azure_assess_network_and_policy, or azure_export_audit_bundle."
        : tokenFailure
          ? isNoResponseFailure(tokenFailure)
            ? `${tokenFailureRemedy(tokenFailure)}, then re-run the access check.`
            : "Fix the app registration's client credentials (tenant id, client id, client secret) so the token request succeeds, then re-run the access check."
          : "Grant Microsoft Graph read permissions and Azure Reader/Security Reader roles for the audit principal.",
  };
}

function enabledPolicies(policies: JsonRecord[]): JsonRecord[] {
  return policies.filter((policy) => asLower(policy.state) === "enabled");
}

function reportOnlyPolicies(policies: JsonRecord[]): JsonRecord[] {
  return policies.filter((policy) => asLower(policy.state) === "enabledforreportingbutnotenforced");
}

function builtInControls(policy: JsonRecord): string[] {
  return asArray(asObject(policy.grantControls)?.builtInControls).map(asLower).filter((value): value is string => Boolean(value));
}

function conditionList(policy: JsonRecord, key: string): string[] {
  return asArray(asObject(policy.conditions)?.[key]).map(asLower).filter((value): value is string => Boolean(value));
}

function hasP2License(skus: JsonRecord[]): boolean {
  return skus.some((sku) => asRecords(sku.servicePlans).some((plan) => asString(plan.servicePlanName) === "AAD_PREMIUM_P2" && asLower(plan.provisioningStatus) === "success"));
}

function hasIntuneLicense(skus: JsonRecord[]): boolean {
  return skus.some((sku) => asRecords(sku.servicePlans).some((plan) => asString(plan.servicePlanName)?.startsWith("INTUNE_") && asLower(plan.provisioningStatus) === "success"));
}

function credentialSummary(now: Date, records: JsonRecord[], label: (record: JsonRecord) => string | undefined) {
  const expired: JsonRecord[] = [];
  const expiring: JsonRecord[] = [];
  const missingExpiry: JsonRecord[] = [];
  const longLived: JsonRecord[] = [];
  for (const record of records) {
    const name = label(record);
    for (const [credentialType, list] of [["password", record.passwordCredentials], ["key", record.keyCredentials]] as const) {
      for (const credential of asRecords(list)) {
        const remaining = daysUntil(now, credential.endDateTime);
        const entry = { owner: name, credentialType, endDateTime: asString(credential.endDateTime) ?? null, daysRemaining: remaining === undefined ? null : round(remaining) };
        if (remaining === undefined) missingExpiry.push(entry);
        else if (remaining < 0) expired.push(entry);
        else if (remaining <= 30) expiring.push(entry);
        const start = parseIsoDate(credential.startDateTime);
        const end = parseIsoDate(credential.endDateTime);
        if (start && end && (end.getTime() - start.getTime()) / DAY_MS > LONG_LIVED_CREDENTIAL_DAYS) longLived.push(entry);
      }
    }
  }
  return { expired, expiring, missingExpiry, longLived };
}

export async function assessAzureIdentity(client: IdentityClient): Promise<AzureAssessmentResult> {
  const now = client.getNow();
  const errors: string[] = [];
  const [policies, registrations, roles, securityDefaults, servicePrincipals, authorizationPolicy, guests, skus, riskyUsers, riskDetections, eligibilities, assignmentSchedules, applications, grants] = await Promise.all([
    attemptPage(() => client.listConditionalAccessPolicies()),
    attemptPage(() => client.listUserRegistrationDetails()),
    attemptPage(() => client.listDirectoryRoles()),
    attempt(() => client.getSecurityDefaultsPolicy()),
    attemptPage(() => client.listServicePrincipals()),
    attempt(optionalCall(client.getAuthorizationPolicy?.bind(client), "getAuthorizationPolicy")),
    attemptPage(optionalCall(client.listGuestUsers?.bind(client), "listGuestUsers")),
    attemptPage(optionalCall(client.listSubscribedSkus?.bind(client), "listSubscribedSkus")),
    attemptPage(optionalCall(client.listRiskyUsers?.bind(client), "listRiskyUsers")),
    attemptPage(optionalCall(client.listRiskDetections?.bind(client), "listRiskDetections")),
    attemptPage(optionalCall(client.listRoleEligibilitySchedules?.bind(client), "listRoleEligibilitySchedules")),
    attemptPage(optionalCall(client.listRoleAssignmentSchedules?.bind(client), "listRoleAssignmentSchedules")),
    attemptPage(optionalCall(client.listApplications?.bind(client), "listApplications")),
    attemptPage(optionalCall(client.listOAuth2PermissionGrants?.bind(client), "listOAuth2PermissionGrants")),
  ]);

  const findings: AzureFinding[] = [];
  const securityDefaultsEnabled = securityDefaults.ok && asObject(securityDefaults.value)?.isEnabled === true;
  const enabled = policies.ok ? enabledPolicies(policies.value.items) : [];
  const reportOnly = policies.ok ? reportOnlyPolicies(policies.value.items) : [];
  const mfaPolicies = enabled.filter((policy) => builtInControls(policy).includes("mfa"));
  const legacyAuthPolicies = enabled.filter((policy) => {
    const clientAppTypes = conditionList(policy, "clientAppTypes");
    return builtInControls(policy).includes("block") && (clientAppTypes.includes("exchangeactivesync") || clientAppTypes.includes("other"));
  });

  if (!policies.ok) {
    findings.push(manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", "GET /v1.0/identity/conditionalAccess/policies", "Policy.Read.All", "the Conditional Access policy export from the Entra admin center", policies, AZURE_ENDPOINT_DOCS.conditionalAccess, errors));
    findings.push(manualForError("AZURE-ID-02", 4, "Legacy authentication blocking", "high", "GET /v1.0/identity/conditionalAccess/policies", "Policy.Read.All", "the Conditional Access policies that block legacy clients", policies, AZURE_ENDPOINT_DOCS.conditionalAccess, errors));
  } else {
    // Security defaults are a secondary read: an enabled MFA or block policy satisfies the control on its own,
    // but when no such policy exists the verdict rests entirely on the defaults, so an unreadable read is manual, not fail.
    const defaultsFailure = securityDefaults.ok ? undefined : describeFailure(securityDefaults);
    const defaultsNote = securityDefaults.ok
      ? ""
      : isTokenRequestFailure(securityDefaults)
        ? ` Security defaults could not be read (${failedReadNote(securityDefaults, SECURITY_DEFAULTS_ENDPOINT)}).`
        : ` Security defaults could not be read (${requestOutcomeClause(SECURITY_DEFAULTS_ENDPOINT, securityDefaults)}).`;
    const defaultsEvidence = {
      security_defaults_enabled: securityDefaults.ok ? securityDefaultsEnabled : null,
      security_defaults_readable: securityDefaults.ok,
      security_defaults_http_status: securityDefaults.ok ? null : securityDefaults.status ?? null,
      security_defaults_request_url: securityDefaults.ok ? null : securityDefaults.url ?? null,
      security_defaults_error: defaultsFailure ?? null,
    };
    if (!securityDefaults.ok) errors.push(`AZURE-ID-01 ${failedReadNote(securityDefaults, SECURITY_DEFAULTS_ENDPOINT)}`);
    const policyEvidence = { total_policies: policies.value.items.length, enabled_policies: enabled.length, report_only_policies: reportOnly.length, mfa_policies: mfaPolicies.length, ...defaultsEvidence, ...pageEvidence(policies.value) };
    const baseline = mfaPolicies.length > 0 || securityDefaultsEnabled;
    if (!baseline && !securityDefaults.ok) {
      const manual = manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", SECURITY_DEFAULTS_ENDPOINT, "Policy.Read.All", "the security defaults setting from the Entra admin center together with the Conditional Access policy export", securityDefaults, AZURE_ENDPOINT_DOCS.securityDefaults, errors);
      findings.push({ ...manual, summary: `No enabled MFA Conditional Access policy was found and ${manual.summary}`, evidence: { ...manual.evidence, ...policyEvidence } });
    } else {
      findings.push(finding("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high",
        baseline ? capForPartial("pass", policies.value) : "fail",
        baseline
          ? `Strong authentication baseline is present via ${mfaPolicies.length} enabled MFA Conditional Access policies${securityDefaultsEnabled ? " and security defaults" : ""}.${reportOnly.length > 0 ? ` ${reportOnly.length} policies are report-only and were not counted.` : ""}${partialNote(policies.value, "Conditional Access policies")}${defaultsNote}`
          : policies.value.items.length === 0
            ? "Zero Conditional Access policies were returned and security defaults are off; empty inventory fails this control by intent."
            : `No enabled MFA Conditional Access policy or security defaults baseline was found (${reportOnly.length} report-only policies do not enforce).`,
        policyEvidence));
    }
    const legacyBlocked = legacyAuthPolicies.length > 0 || securityDefaultsEnabled;
    const legacyEvidence = { legacy_auth_block_policies: legacyAuthPolicies.length, ...defaultsEvidence, ...pageEvidence(policies.value) };
    if (!legacyBlocked && !securityDefaults.ok) {
      const manual = manualForError("AZURE-ID-02", 4, "Legacy authentication blocking", "high", SECURITY_DEFAULTS_ENDPOINT, "Policy.Read.All", "the security defaults setting from the Entra admin center together with the Conditional Access policies that block legacy clients", securityDefaults, AZURE_ENDPOINT_DOCS.securityDefaults, errors);
      findings.push({ ...manual, summary: `No enabled Conditional Access policy blocks exchangeActiveSync/other client app types and ${manual.summary}`, evidence: { ...manual.evidence, ...legacyEvidence } });
    } else {
      findings.push(finding("AZURE-ID-02", 4, "Legacy authentication blocking", "high",
        legacyBlocked ? capForPartial("pass", policies.value) : "fail",
        legacyBlocked
          ? `Legacy authentication is blocked via ${legacyAuthPolicies.length} enabled Conditional Access block policies targeting exchangeActiveSync/other clients${securityDefaultsEnabled ? " and security defaults" : ""}.${partialNote(policies.value, "Conditional Access policies")}${defaultsNote}`
          : "No enabled Conditional Access policy blocks exchangeActiveSync/other client app types and security defaults are off.",
        legacyEvidence));
    }
  }

  if (!registrations.ok) {
    findings.push(manualForError("AZURE-ID-03", 2, "MFA registration coverage", "high", "GET /v1.0/reports/authenticationMethods/userRegistrationDetails", "AuditLog.Read.All (Entra ID P1 or P2)", "the authentication methods registration report", registrations, AZURE_ENDPOINT_DOCS.userRegistrationDetails, errors));
  } else {
    const usersWithoutMfa = registrations.value.items.filter((item) => item.isMfaRegistered !== true);
    const ratio = registrations.value.items.length > 0 ? usersWithoutMfa.length / registrations.value.items.length : 1;
    const status: AzureFindingStatus = registrations.value.items.length === 0 ? "manual" : usersWithoutMfa.length === 0 ? capForPartial("pass", registrations.value) : ratio <= 0.1 ? "warn" : "fail";
    findings.push(finding("AZURE-ID-03", 2, "MFA registration coverage", "high", status,
      registrations.value.items.length === 0
        ? "The registration report returned zero users; an empty inventory cannot demonstrate MFA coverage, so this control needs manual confirmation."
        : usersWithoutMfa.length === 0
          ? `All ${registrations.value.items.length} reported users are registered for MFA.${partialNote(registrations.value, "users")}`
          : `${usersWithoutMfa.length}/${registrations.value.items.length} reported users are not registered for MFA.`,
      { users: registrations.value.items.length, users_without_mfa: usersWithoutMfa.length, ...pageEvidence(registrations.value) }));
  }

  let privilegedAssignments = 0;
  let globalAdmins = 0;
  let memberReadFailure: { error: string; status?: number } | undefined;
  let membersTruncated = false;
  if (roles.ok) {
    for (const role of roles.value.items) {
      const name = normalizeRoleName(role.displayName) ?? PRIVILEGED_ROLE_TEMPLATE_IDS.get(asLower(role.roleTemplateId) ?? "");
      const roleId = asString(role.id);
      if (!roleId || !isPrivilegedDirectoryRole(name)) continue;
      const members = await attemptPage(() => client.listDirectoryRoleMembers(roleId));
      if (!members.ok) {
        memberReadFailure = members;
        continue;
      }
      membersTruncated ||= members.value.truncated;
      privilegedAssignments += members.value.items.length;
      if (name === "global administrator") globalAdmins += members.value.items.length;
    }
  }
  if (!roles.ok) {
    findings.push(manualForError("AZURE-ID-04", 5, "Privileged directory role sprawl", "high", "GET /v1.0/directoryRoles", "RoleManagement.Read.Directory or Directory.Read.All", "the privileged role membership export", roles, AZURE_ENDPOINT_DOCS.directoryRoles, errors));
  } else if (memberReadFailure) {
    findings.push(manualForError("AZURE-ID-04", 5, "Privileged directory role sprawl", "high", "GET /v1.0/directoryRoles/{id}/members", "RoleManagement.Read.Directory or Directory.Read.All", "the privileged role membership export", memberReadFailure, AZURE_ENDPOINT_DOCS.directoryRoleMembers, errors));
  } else {
    const status: AzureFindingStatus = privilegedAssignments === 0
      ? "manual"
      : globalAdmins > 4 || privilegedAssignments > 10 ? "fail" : membersTruncated || roles.value.truncated ? "warn" : privilegedAssignments <= 5 ? "pass" : "warn";
    findings.push(finding("AZURE-ID-04", 5, "Privileged directory role sprawl", "high", status,
      privilegedAssignments === 0
        ? "Zero privileged role members were returned; every tenant has at least one Global Administrator, so this needs manual confirmation of read access."
        : `The tenant exposes ${globalAdmins} Global Administrators and ${privilegedAssignments} privileged role assignments (CIS recommends 2 to 4 Global Administrators).${membersTruncated ? " Member inventory is partial; verdict capped at warn." : ""}`,
      { global_administrators: globalAdmins, privileged_role_assignments: privilegedAssignments, activated_roles: roles.value.items.length, members_truncated: membersTruncated }));
  }

  if (!servicePrincipals.ok) {
    findings.push(manualForError("AZURE-ID-05", 23, "Service principal credential hygiene", "medium", "GET /v1.0/servicePrincipals", "Application.Read.All", "the service principal credential expiry export", servicePrincipals, AZURE_ENDPOINT_DOCS.servicePrincipals, errors));
  } else {
    const credentials = credentialSummary(now, servicePrincipals.value.items, (record) => asString(record.displayName));
    const status: AzureFindingStatus = servicePrincipals.value.items.length === 0
      ? "manual"
      : credentials.expired.length > 0 ? "fail" : credentials.expiring.length > 0 || credentials.missingExpiry.length > 0 || credentials.longLived.length > 0 ? "warn" : capForPartial("pass", servicePrincipals.value);
    findings.push(finding("AZURE-ID-05", 23, "Service principal credential hygiene", "medium", status,
      servicePrincipals.value.items.length === 0
        ? "Zero service principals were returned; tenants always contain first-party service principals, so this needs manual confirmation of read access."
        : `${credentials.expired.length} expired, ${credentials.expiring.length} expiring within 30 days, ${credentials.missingExpiry.length} without an endDateTime, and ${credentials.longLived.length} valid for more than ${LONG_LIVED_CREDENTIAL_DAYS} days across ${servicePrincipals.value.items.length} service principals.${partialNote(servicePrincipals.value, "service principals")}`,
      { expired: credentials.expired.slice(0, 25), expiring: credentials.expiring.slice(0, 25), missing_expiry: credentials.missingExpiry.length, long_lived: credentials.longLived.length, ...pageEvidence(servicePrincipals.value) }));
  }

  if (!eligibilities.ok) {
    findings.push(manualForError("AZURE-ID-06", 5, "Privileged Identity Management eligibility", "high", "GET /v1.0/roleManagement/directory/roleEligibilitySchedules", "RoleEligibilitySchedule.Read.Directory or RoleManagement.Read.Directory with an Entra ID P2 or Governance license", "the PIM eligible and active assignment export", eligibilities, AZURE_ENDPOINT_DOCS.roleEligibilitySchedules, errors));
  } else if (!assignmentSchedules.ok) {
    findings.push(manualForError("AZURE-ID-06", 5, "Privileged Identity Management eligibility", "high", "GET /v1.0/roleManagement/directory/roleAssignmentSchedules", "RoleAssignmentSchedule.Read.Directory or RoleManagement.Read.Directory with an Entra ID P2 or Governance license", "the PIM active assignment export", assignmentSchedules, AZURE_ENDPOINT_DOCS.roleAssignmentSchedules, errors));
  } else {
    const permanentPrivileged = assignmentSchedules.value.items.filter((schedule) => {
      const roleId = asLower(schedule.roleDefinitionId);
      const expiration = asObject(asObject(schedule.scheduleInfo)?.expiration);
      return asLower(schedule.assignmentType) === "assigned" && roleId !== undefined && PRIVILEGED_ROLE_TEMPLATE_IDS.has(roleId) && asLower(expiration?.type) === "noexpiration";
    });
    const status: AzureFindingStatus = eligibilities.value.items.length === 0 && permanentPrivileged.length === 0
      ? "manual"
      : permanentPrivileged.length > 2 ? "fail" : permanentPrivileged.length > 0 || eligibilities.value.items.length === 0 ? "warn" : capForPartial("pass", eligibilities.value, assignmentSchedules.value);
    findings.push(finding("AZURE-ID-06", 5, "Privileged Identity Management eligibility", "high", status,
      status === "manual"
        ? "Zero eligible and zero permanent privileged schedules were returned; confirm PIM is onboarded before treating this as compliant."
        : `${eligibilities.value.items.length} PIM eligible assignments and ${permanentPrivileged.length} permanent (Assigned, noExpiration) privileged role assignments were found.${partialNote(eligibilities.value, "eligibility schedules")}${partialNote(assignmentSchedules.value, "assignment schedules")}`,
      { eligible_assignments: eligibilities.value.items.length, permanent_privileged_assignments: permanentPrivileged.length, permanent_examples: permanentPrivileged.slice(0, 10).map((item) => ({ principalId: item.principalId, roleDefinitionId: item.roleDefinitionId })) }));
  }

  if (!authorizationPolicy.ok) {
    findings.push(manualForError("AZURE-ID-07", 6, "Guest access restrictions", "medium", "GET /v1.0/policies/authorizationPolicy", "Policy.Read.All", "the External collaboration settings page", authorizationPolicy, AZURE_ENDPOINT_DOCS.authorizationPolicy, errors));
  } else {
    const policy = asObject(authorizationPolicy.value) ?? {};
    const guestRole = asLower(policy.guestUserRoleId);
    const invitesFrom = asLower(policy.allowInvitesFrom);
    const restrictedInvites = invitesFrom === "none" || invitesFrom === "adminsandguestinviters";
    const status: AzureFindingStatus = guestRole === GUEST_ROLE_RESTRICTED && restrictedInvites
      ? "pass"
      : guestRole === GUEST_ROLE_SAME_AS_MEMBER || invitesFrom === "everyone" ? "fail" : guestRole === undefined ? "manual" : "warn";
    findings.push(finding("AZURE-ID-07", 6, "Guest access restrictions", "medium", status,
      guestRole === undefined
        ? "authorizationPolicy did not include guestUserRoleId; collect the External collaboration settings manually."
        : `guestUserRoleId is ${guestRole === GUEST_ROLE_RESTRICTED ? "restricted" : guestRole === GUEST_ROLE_LIMITED ? "limited (default)" : guestRole === GUEST_ROLE_SAME_AS_MEMBER ? "same as members" : guestRole} and allowInvitesFrom is ${invitesFrom ?? "unknown"}.`,
      { guestUserRoleId: policy.guestUserRoleId ?? null, allowInvitesFrom: policy.allowInvitesFrom ?? null }));
  }

  if (!guests.ok) {
    findings.push(manualForError("AZURE-ID-08", 6, "Guest account hygiene", "medium", "GET /v1.0/users?$filter=userType eq 'Guest'", "User.Read.All plus AuditLog.Read.All for signInActivity", "the guest user list with last sign-in dates", guests, AZURE_ENDPOINT_DOCS.users, errors));
  } else {
    const staleGuests: JsonRecord[] = [];
    const unknownActivity: JsonRecord[] = [];
    for (const guest of guests.value.items) {
      if (guest.accountEnabled === false) continue;
      const lastSignIn = asObject(guest.signInActivity)?.lastSignInDateTime;
      const age = daysSince(now, lastSignIn);
      const entry = { userPrincipalName: guest.userPrincipalName, lastSignInDateTime: asString(lastSignIn) ?? null, externalUserState: guest.externalUserState ?? null };
      if (age === undefined) unknownActivity.push(entry);
      else if (age > STALE_GUEST_DAYS) staleGuests.push(entry);
    }
    const status: AzureFindingStatus = staleGuests.length > 0 ? "fail" : unknownActivity.length > 0 ? "warn" : capForPartial("pass", guests.value);
    findings.push(finding("AZURE-ID-08", 6, "Guest account hygiene", "medium", status,
      guests.value.items.length === 0
        ? "No guest accounts exist; an empty guest inventory is compliant by intent."
        : `${guests.value.items.length} guests: ${staleGuests.length} enabled guests have not signed in for ${STALE_GUEST_DAYS}+ days and ${unknownActivity.length} have no lastSignInDateTime (never counted as active).${partialNote(guests.value, "guests")}`,
      { guests: guests.value.items.length, stale_guests: staleGuests.slice(0, 25), unknown_activity: unknownActivity.length, ...pageEvidence(guests.value) }));
  }

  const p2 = skus.ok ? hasP2License(skus.value.items) : undefined;
  const riskPolicy = (key: "signInRiskLevels" | "userRiskLevels", controls: string[]) => enabled.filter((policy) => {
    const levels = conditionList(policy, key);
    return (levels.includes("medium") || levels.includes("high")) && builtInControls(policy).some((control) => controls.includes(control));
  });
  const riskFinding = (id: string, control: number, title: string, key: "signInRiskLevels" | "userRiskLevels", controls: string[], remediationLabel: string) => {
    if (!policies.ok) return manualForError(id, control, title, "high", "GET /v1.0/identity/conditionalAccess/policies", "Policy.Read.All", `the risk-based Conditional Access policies`, policies, AZURE_ENDPOINT_DOCS.conditionalAccess, errors);
    if (!skus.ok) return manualForError(id, control, title, "high", "GET /v1.0/subscribedSkus", "Organization.Read.All", "the license inventory proving Entra ID P2", skus, AZURE_ENDPOINT_DOCS.subscribedSkus, errors);
    if (p2 !== true) {
      return finding(id, control, title, "high", "manual", `No AAD_PREMIUM_P2 service plan is provisioned; risk-based Conditional Access requires an Entra ID P2 license. Collect licensing evidence or document the compensating control.`, { entra_id_p2: false, documentation: AZURE_ENDPOINT_DOCS.servicePlanNames });
    }
    const matching = riskPolicy(key, controls);
    const reportOnlyMatching = reportOnly.filter((policy) => conditionList(policy, key).length > 0);
    return finding(id, control, title, "high", matching.length > 0 ? capForPartial("pass", policies.value) : "fail",
      matching.length > 0
        ? `${matching.length} enabled Conditional Access policies act on medium or high ${key} with ${remediationLabel}.${partialNote(policies.value, "Conditional Access policies")}`
        : `No enabled Conditional Access policy enforces ${remediationLabel} at medium or high ${key}${reportOnlyMatching.length > 0 ? ` (${reportOnlyMatching.length} matching policies are report-only)` : ""}.`,
      { enforcing_policies: matching.map((policy) => policy.displayName), report_only_policies: reportOnlyMatching.length, entra_id_p2: true });
  };
  findings.push(riskFinding("AZURE-ID-09", 7, "Sign-in risk policy", "signInRiskLevels", ["mfa", "block"], "MFA or block"));
  findings.push(riskFinding("AZURE-ID-10", 8, "User risk policy", "userRiskLevels", ["passwordchange", "block"], "password change or block"));

  if (!riskyUsers.ok) {
    findings.push(manualForError("AZURE-ID-11", 7, "Risky users and detections", "high", "GET /v1.0/identityProtection/riskyUsers", "IdentityRiskyUser.Read.All with an Entra ID P2 license", "the Identity Protection risky users report", riskyUsers, AZURE_ENDPOINT_DOCS.riskyUsers, errors));
  } else if (!riskDetections.ok) {
    findings.push(manualForError("AZURE-ID-11", 7, "Risky users and detections", "high", "GET /v1.0/identityProtection/riskDetections", "IdentityRiskEvent.Read.All with an Entra ID P2 license", "the Identity Protection risk detections report", riskDetections, AZURE_ENDPOINT_DOCS.riskDetections, errors));
  } else {
    const highRisk = riskyUsers.value.items.filter((user) => asLower(user.riskLevel) === "high");
    const status: AzureFindingStatus = highRisk.length > 0 ? "fail" : riskyUsers.value.items.length > 0 ? "warn" : capForPartial("pass", riskyUsers.value, riskDetections.value);
    findings.push(finding("AZURE-ID-11", 7, "Risky users and detections", "high", status,
      riskyUsers.value.items.length === 0
        ? `No users are currently atRisk or confirmedCompromised (${riskDetections.value.seen} recent risk detections); an empty risky-user list is compliant by intent.${partialNote(riskDetections.value, "risk detections")}`
        : `${riskyUsers.value.items.length} users are atRisk or confirmedCompromised, ${highRisk.length} at high risk, with ${riskDetections.value.seen} recent risk detections.`,
      { risky_users: riskyUsers.value.items.length, high_risk_users: highRisk.length, risk_detections: riskDetections.value.seen, ...pageEvidence(riskyUsers.value) }));
  }

  if (!applications.ok) {
    findings.push(manualForError("AZURE-ID-12", 22, "App registration credential and owner hygiene", "medium", "GET /v1.0/applications", "Application.Read.All", "the app registration credential and owner export", applications, AZURE_ENDPOINT_DOCS.applications, errors));
  } else {
    const credentials = credentialSummary(now, applications.value.items, (record) => asString(record.displayName));
    const ownerless = applications.value.items.filter((app) => Array.isArray(app.owners) && app.owners.length === 0);
    const status: AzureFindingStatus = applications.value.items.length === 0
      ? "manual"
      : credentials.expired.length > 0 ? "fail" : credentials.expiring.length > 0 || credentials.missingExpiry.length > 0 || credentials.longLived.length > 0 || ownerless.length > 0 ? "warn" : capForPartial("pass", applications.value);
    findings.push(finding("AZURE-ID-12", 22, "App registration credential and owner hygiene", "medium", status,
      applications.value.items.length === 0
        ? "Zero app registrations were returned; confirm Application.Read.All before treating the tenant as having no registrations."
        : `${applications.value.items.length} app registrations: ${credentials.expired.length} expired credentials, ${credentials.expiring.length} expiring within 30 days, ${credentials.missingExpiry.length} without endDateTime, ${credentials.longLived.length} valid beyond ${LONG_LIVED_CREDENTIAL_DAYS} days, ${ownerless.length} without owners.${partialNote(applications.value, "app registrations")}`,
      { applications: applications.value.items.length, expired: credentials.expired.slice(0, 25), expiring: credentials.expiring.slice(0, 25), missing_expiry: credentials.missingExpiry.length, long_lived: credentials.longLived.length, ownerless: ownerless.slice(0, 25).map((app) => app.displayName), ...pageEvidence(applications.value) }));
  }

  if (!grants.ok) {
    findings.push(manualForError("AZURE-ID-13", 22, "Tenant-wide delegated permission grants", "high", "GET /v1.0/oauth2PermissionGrants", "Directory.Read.All", "the enterprise application admin consent report", grants, AZURE_ENDPOINT_DOCS.oauth2PermissionGrants, errors));
  } else {
    const risky = grants.value.items.filter((grant) => {
      if (asLower(grant.consentType) !== "allprincipals") return false;
      const scopes = (asString(grant.scope) ?? "").toLowerCase().split(/\s+/);
      return scopes.some((scope) => HIGH_PRIVILEGE_DELEGATED_SCOPES.includes(scope));
    });
    const status: AzureFindingStatus = grants.value.items.length === 0 ? "manual" : risky.length > 0 ? "fail" : capForPartial("pass", grants.value);
    findings.push(finding("AZURE-ID-13", 22, "Tenant-wide delegated permission grants", "high", status,
      grants.value.items.length === 0
        ? "Zero oauth2PermissionGrants were returned; tenants with any consented enterprise application expose at least one grant, so confirm Directory.Read.All before treating the tenant as having no tenant-wide grants."
        : risky.length > 0
          ? `${risky.length} AllPrincipals grants include high-privilege delegated scopes.`
          : `No AllPrincipals grant carries a high-privilege delegated scope across ${grants.value.items.length} grants; zero risky grants is compliant by intent.${partialNote(grants.value, "permission grants")}`,
      { grants: grants.value.items.length, risky_grants: risky.slice(0, 25).map((grant) => ({ clientId: grant.clientId, scope: grant.scope })), ...pageEvidence(grants.value) }));
  }

  return {
    title: "Azure identity posture",
    // Every count derived from an unreadable inventory renders null, never the zero of its empty fallback.
    summary: {
      enabled_conditional_access_policies: policies.ok ? enabled.length : null,
      report_only_conditional_access_policies: policies.ok ? reportOnly.length : null,
      mfa_conditional_access_policies: policies.ok ? mfaPolicies.length : null,
      legacy_auth_block_policies: policies.ok ? legacyAuthPolicies.length : null,
      users_in_registration_report: registrations.ok ? registrations.value.items.length : null,
      global_administrators: roles.ok && !memberReadFailure ? globalAdmins : null,
      privileged_role_assignments: roles.ok && !memberReadFailure ? privilegedAssignments : null,
      guests: guests.ok ? guests.value.items.length : null,
      risky_users: riskyUsers.ok ? riskyUsers.value.items.length : null,
      app_registrations: applications.ok ? applications.value.items.length : null,
      security_defaults_enabled: securityDefaults.ok ? securityDefaultsEnabled : null,
      entra_id_p2_license: p2 ?? null,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

function diagnosticSettingHasEnabledLog(setting: JsonRecord): boolean {
  const properties = asObject(setting.properties) ?? {};
  return asRecords(properties.logs).some((log) => log.enabled === true);
}

function diagnosticSettingDestination(setting: JsonRecord): string | undefined {
  const properties = asObject(setting.properties) ?? {};
  return asString(properties.workspaceId) ?? asString(properties.storageAccountId) ?? asString(properties.eventHubAuthorizationRuleId);
}

export async function assessAzureMonitoring(client: MonitoringClient): Promise<AzureAssessmentResult> {
  const errors: string[] = [];
  const [secureScores, alerts, audits, signIns, defenderPricings, diagnosticSettings, workspaces] = await Promise.all([
    attemptPage(() => client.listSecureScores()),
    attemptPage(() => client.listSecurityAlerts()),
    attemptPage(() => client.listDirectoryAudits()),
    attemptPage(() => client.listSignIns()),
    attemptPage(() => client.listDefenderPricings()),
    attemptPage(() => client.listDiagnosticSettings()),
    attemptPage(optionalCall(client.listLogAnalyticsWorkspaces?.bind(client), "listLogAnalyticsWorkspaces")),
  ]);
  const findings: AzureFinding[] = [];

  const currentScore = secureScores.ok ? secureScores.value.items[0] : undefined;
  const currentScoreValue = asNumber(currentScore?.currentScore) ?? 0;
  const maxScoreValue = asNumber(currentScore?.maxScore) ?? 0;
  const secureScoreRatio = maxScoreValue > 0 ? currentScoreValue / maxScoreValue : 0;
  if (!secureScores.ok) {
    findings.push(manualForError("AZURE-MON-01", 3, "Secure Score posture", "medium", "GET /v1.0/security/secureScores", "SecurityEvents.Read.All", "the Microsoft Secure Score dashboard export", secureScores, AZURE_ENDPOINT_DOCS.secureScores, errors));
  } else {
    findings.push(finding("AZURE-MON-01", 3, "Secure Score posture", "medium",
      maxScoreValue <= 0 ? "manual" : secureScoreRatio >= 0.75 ? "pass" : secureScoreRatio >= 0.5 ? "warn" : "fail",
      maxScoreValue > 0
        ? `Current Secure Score is ${currentScoreValue}/${maxScoreValue} (${Math.round(secureScoreRatio * 100)}%).`
        : "Secure Score returned no scored records; collect the Secure Score dashboard manually.",
      { current_score: currentScoreValue, max_score: maxScoreValue, ratio: round(secureScoreRatio, 2) }));
  }

  if (!audits.ok) {
    findings.push(manualForError("AZURE-MON-02", 19, "Directory audit visibility", "medium", "GET /v1.0/auditLogs/directoryAudits", "AuditLog.Read.All", "the Entra audit log export", audits, AZURE_ENDPOINT_DOCS.directoryAudits, errors));
  } else {
    findings.push(finding("AZURE-MON-02", 19, "Directory audit visibility", "medium", audits.value.items.length > 0 ? "pass" : "warn",
      audits.value.items.length > 0 ? `${audits.value.seen} recent directory audit events were visible.` : "No directory audit events were returned in the sampled window; confirm audit logging manually.",
      { directory_audits: audits.value.seen }));
  }

  if (!signIns.ok) {
    findings.push(manualForError("AZURE-MON-03", 19, "Sign-in telemetry visibility", "medium", "GET /v1.0/auditLogs/signIns", "AuditLog.Read.All (Entra ID P1 or P2)", "the Entra sign-in log export", signIns, AZURE_ENDPOINT_DOCS.signIns, errors));
  } else {
    findings.push(finding("AZURE-MON-03", 19, "Sign-in telemetry visibility", "medium", signIns.value.items.length > 0 ? "pass" : "warn",
      signIns.value.items.length > 0 ? `${signIns.value.seen} recent sign-in events were visible.` : "No sign-in events were returned in the sampled window; confirm sign-in logging manually.",
      { sign_ins: signIns.value.seen }));
  }

  const standardPlans = defenderPricings.ok ? defenderPricings.value.items.filter((item) => asLower(asObject(item.properties)?.pricingTier) === "standard") : [];
  const totalPlans = defenderPricings.ok ? defenderPricings.value.items.length : 0;
  // The alerts read only annotates MON-04, but a failed read is still logged so the bundle names it.
  if (!alerts.ok) errors.push(`AZURE-MON-04 ${failedReadNote(alerts, "GET /v1.0/security/alerts_v2")}`);
  if (!defenderPricings.ok) {
    findings.push(manualForError("AZURE-MON-04", 16, "Defender for Cloud plan coverage", "high", "GET Microsoft.Security/pricings", "Security Reader on the subscription", "the Defender for Cloud environment settings page", defenderPricings, AZURE_ENDPOINT_DOCS.defenderPricings, errors));
  } else {
    findings.push(finding("AZURE-MON-04", 16, "Defender for Cloud plan coverage", "high",
      totalPlans === 0 ? "manual" : standardPlans.length === totalPlans ? capForPartial("pass", defenderPricings.value) : standardPlans.length > 0 ? "warn" : "fail",
      totalPlans > 0
        ? `${standardPlans.length}/${totalPlans} Defender for Cloud plans are on the Standard pricingTier.${partialNote(defenderPricings.value, "Defender plans")}`
        : "Zero Defender pricing records were returned; the API always lists every plan, so confirm access manually.",
      { standard_plans: standardPlans.length, total_plans: totalPlans, alerts_visible: alerts.ok ? alerts.value.seen : null, alerts_error: alerts.ok ? null : describeFailure(alerts), ...pageEvidence(defenderPricings.value) }));
  }

  const effectiveSettings = diagnosticSettings.ok ? diagnosticSettings.value.items.filter((setting) => diagnosticSettingHasEnabledLog(setting) && diagnosticSettingDestination(setting)) : [];
  if (!diagnosticSettings.ok) {
    findings.push(manualForError("AZURE-MON-05", 15, "Subscription diagnostic settings", "high", "GET Microsoft.Insights/diagnosticSettings", "Reader (Monitoring Reader) on the subscription", "the Activity log diagnostic settings page", diagnosticSettings, AZURE_ENDPOINT_DOCS.diagnosticSettings, errors));
  } else {
    findings.push(finding("AZURE-MON-05", 15, "Subscription diagnostic settings", "high", effectiveSettings.length > 0 ? capForPartial("pass", diagnosticSettings.value) : "fail",
      effectiveSettings.length > 0
        ? `${effectiveSettings.length}/${diagnosticSettings.value.items.length} subscription diagnostic settings have enabled log categories and a destination.${partialNote(diagnosticSettings.value, "diagnostic settings")}`
        : diagnosticSettings.value.items.length === 0
          ? "Zero subscription diagnostic settings exist; Activity Log is not exported (empty inventory fails by intent)."
          : `${diagnosticSettings.value.items.length} diagnostic settings exist but none has an enabled log category with a destination.`,
      { diagnostic_settings: diagnosticSettings.value.items.length, effective_settings: effectiveSettings.length, ...pageEvidence(diagnosticSettings.value) }));
  }

  if (!diagnosticSettings.ok) {
    findings.push(manualForError("AZURE-MON-06", 19, "Activity log retention depth", "high", "GET Microsoft.Insights/diagnosticSettings", "Reader on the subscription", "the Log Analytics retention configuration", diagnosticSettings, AZURE_ENDPOINT_DOCS.diagnosticSettings, errors));
  } else if (!workspaces.ok) {
    findings.push(manualForError("AZURE-MON-06", 19, "Activity log retention depth", "high", "GET Microsoft.OperationalInsights/workspaces", "Reader on the subscription", "the Log Analytics workspace retentionInDays setting", workspaces, AZURE_ENDPOINT_DOCS.logAnalyticsWorkspaces, errors));
  } else {
    const workspaceIds = new Set(effectiveSettings.map((setting) => asLower(asObject(setting.properties)?.workspaceId)).filter((value): value is string => Boolean(value)));
    const linked = workspaces.value.items.filter((workspace) => workspaceIds.has(asLower(workspace.id) ?? ""));
    const retention = linked.map((workspace) => ({ id: workspace.id, retentionInDays: asNumber(asObject(workspace.properties)?.retentionInDays) ?? null }));
    const compliant = retention.filter((item) => item.retentionInDays !== null && item.retentionInDays >= MIN_RETENTION_DAYS);
    const status: AzureFindingStatus = workspaceIds.size === 0
      ? "fail"
      : linked.length === 0 ? "manual" : compliant.length === retention.length ? capForPartial("pass", workspaces.value) : "fail";
    findings.push(finding("AZURE-MON-06", 19, "Activity log retention depth", "high", status,
      workspaceIds.size === 0
        ? "No enabled diagnostic setting sends the Activity Log to a Log Analytics workspace, so 90-day retention cannot be demonstrated."
        : linked.length === 0
          ? "The diagnostic settings reference workspaces outside this subscription; collect their retentionInDays manually."
          : `${compliant.length}/${retention.length} linked Log Analytics workspaces retain data for ${MIN_RETENTION_DAYS}+ days.${partialNote(workspaces.value, "workspaces")}`,
      { workspaces: retention, minimum_days: MIN_RETENTION_DAYS }));
  }

  findings.push(finding("AZURE-MON-07", 19, "Entra ID audit log export", "medium", "manual",
    "Entra ID retains audit and sign-in logs for 30 days at most (P1/P2); export via Entra diagnostic settings to Log Analytics, storage, or Event Hubs is configured in the Entra admin center and is not exposed through the Graph or ARM endpoints used here. Collect the Entra diagnostic settings page as evidence.",
    { retention_reference: AZURE_ENDPOINT_DOCS.entraLogRetention, configuration_reference: AZURE_ENDPOINT_DOCS.entraDiagnosticSettings }));

  return {
    title: "Azure monitoring posture",
    summary: {
      secure_score_ratio: secureScores.ok && maxScoreValue > 0 ? round(secureScoreRatio, 2) : null,
      directory_audits: audits.ok ? audits.value.seen : null,
      sign_ins: signIns.ok ? signIns.value.seen : null,
      defender_standard_plans: defenderPricings.ok ? standardPlans.length : null,
      defender_total_plans: defenderPricings.ok ? totalPlans : null,
      security_alerts: alerts.ok ? alerts.value.seen : null,
      effective_diagnostic_settings: diagnosticSettings.ok ? effectiveSettings.length : null,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

export async function assessAzureSubscriptionGuardrails(
  client: GuardrailsClient,
  options: { maxAssignments?: number } = {},
): Promise<AzureAssessmentResult> {
  const maxAssignments = clampNumber(options.maxAssignments, DEFAULT_MAX_ASSIGNMENTS, 1, 5000);
  const errors: string[] = [];
  const [roleAssignments, roleDefinitions, securityContacts, networkWatchers] = await Promise.all([
    attemptPage(() => client.listRoleAssignments(maxAssignments)),
    attemptPage(() => client.listRoleDefinitions()),
    attemptPage(() => client.listSecurityContacts()),
    attemptPage(() => client.listNetworkWatchers()),
  ]);
  const findings: AzureFinding[] = [];

  const roleMap = new Map<string, string>();
  if (roleDefinitions.ok) {
    for (const definition of roleDefinitions.value.items) {
      const id = roleDefinitionIdTail(asString(definition.id));
      const name = normalizeRoleName(asObject(definition.properties)?.roleName ?? definition.roleName);
      if (id && name) roleMap.set(id, name);
    }
  }

  const ownerAssignments: JsonRecord[] = [];
  const contributorAssignments: JsonRecord[] = [];
  const privilegedServicePrincipals: JsonRecord[] = [];
  if (roleAssignments.ok) {
    for (const assignment of roleAssignments.value.items) {
      const properties = asObject(assignment.properties) ?? {};
      const roleName = roleMap.get(roleDefinitionIdTail(asString(properties.roleDefinitionId)) ?? "");
      const principalType = asLower(properties.principalType);
      if (isOwnerRole(roleName)) ownerAssignments.push(assignment);
      if (isContributorRole(roleName)) contributorAssignments.push(assignment);
      if ((isOwnerRole(roleName) || isContributorRole(roleName)) && principalType === "serviceprincipal") {
        privilegedServicePrincipals.push(assignment);
      }
    }
  }

  const rbacManual = !roleAssignments.ok
    ? { endpoint: "GET Microsoft.Authorization/roleAssignments", result: roleAssignments, doc: AZURE_ENDPOINT_DOCS.roleAssignments }
    : !roleDefinitions.ok
      ? { endpoint: "GET Microsoft.Authorization/roleDefinitions", result: roleDefinitions, doc: AZURE_ENDPOINT_DOCS.roleDefinitions }
      : undefined;
  const rbacPages = roleAssignments.ok && roleDefinitions.ok ? [roleAssignments.value, roleDefinitions.value] : [];
  const noAssignments = roleAssignments.ok && roleAssignments.value.items.length === 0;
  const rbacFinding = (id: string, control: number, title: string, severity: AzureFinding["severity"], matches: JsonRecord[], warnMax: number, label: string, evidenceKey: string) => {
    if (rbacManual) return manualForError(id, control, title, severity, rbacManual.endpoint, "Reader on the subscription", "the IAM role assignment export", rbacManual.result, rbacManual.doc, errors);
    const status: AzureFindingStatus = noAssignments ? "manual" : matches.length > warnMax ? "fail" : matches.length > 0 ? "warn" : capForPartial("pass", ...rbacPages);
    return finding(id, control, title, severity, status,
      noAssignments
        ? "Zero role assignments were returned at subscription scope; every subscription has at least one, so confirm read access manually."
        : `${matches.length} ${label} were visible at subscription scope (${roleAssignments.ok ? roleAssignments.value.seen : 0} assignments inspected).${roleAssignments.ok ? partialNote(roleAssignments.value, "role assignments") : ""}`,
      { [evidenceKey]: matches.slice(0, 25), ...(roleAssignments.ok ? pageEvidence(roleAssignments.value) : {}) });
  };
  findings.push(rbacFinding("AZURE-SUB-01", 17, "Owner assignments at subscription scope", "high", ownerAssignments, 2, "Owner assignments", "owner_assignments"));
  findings.push(rbacFinding("AZURE-SUB-02", 17, "Contributor assignments at subscription scope", "medium", contributorAssignments, 5, "Contributor assignments", "contributor_assignments"));

  if (!securityContacts.ok) {
    findings.push(manualForError("AZURE-SUB-03", 18, "Security contacts configured", "medium", "GET Microsoft.Security/securityContacts", "Security Reader on the subscription", "the Defender for Cloud email notifications page", securityContacts, AZURE_ENDPOINT_DOCS.securityContacts, errors));
  } else {
    const configuredContacts = securityContacts.value.items.filter((contact) => Boolean(asString(asObject(contact.properties)?.emails)));
    findings.push(finding("AZURE-SUB-03", 18, "Security contacts configured", "medium", configuredContacts.length > 0 ? "pass" : "fail",
      configuredContacts.length > 0 ? `${configuredContacts.length} security contacts with emails are configured.` : "No security contact with emails is configured (empty inventory fails by intent).",
      { security_contacts: configuredContacts.length }));
  }

  if (!networkWatchers.ok) {
    findings.push(manualForError("AZURE-SUB-04", 24, "Network Watcher coverage", "medium", "GET Microsoft.Network/networkWatchers", "Reader on the subscription", "the Network Watcher regional enablement page", networkWatchers, AZURE_ENDPOINT_DOCS.networkWatchers, errors));
  } else {
    findings.push(finding("AZURE-SUB-04", 24, "Network Watcher coverage", "medium", networkWatchers.value.items.length > 0 ? capForPartial("pass", networkWatchers.value) : "warn",
      networkWatchers.value.items.length > 0
        ? `${networkWatchers.value.items.length} Network Watcher resources exist across the subscription; NSG flow log coverage is assessed by AZURE-NP-04.${partialNote(networkWatchers.value, "network watchers")}`
        : "No Network Watcher resources exist for the subscription.",
      { network_watchers: networkWatchers.value.items.length, regions: networkWatchers.value.items.map((item) => item.location).slice(0, 50) }));
  }

  if (rbacManual) {
    findings.push(manualForError("AZURE-SUB-05", 23, "Privileged service principals at subscription scope", "high", rbacManual.endpoint, "Reader on the subscription", "the IAM role assignment export filtered to service principals", rbacManual.result, rbacManual.doc, errors));
  } else {
    findings.push(finding("AZURE-SUB-05", 23, "Privileged service principals at subscription scope", "high",
      noAssignments ? "manual" : privilegedServicePrincipals.length > 0 ? "fail" : capForPartial("pass", ...rbacPages),
      noAssignments
        ? "Zero role assignments were returned; confirm read access before concluding no service principal holds Owner or Contributor."
        : privilegedServicePrincipals.length > 0
          ? `${privilegedServicePrincipals.length} service principals hold Owner or Contributor at subscription scope.`
          : `No service principal holds Owner or Contributor across ${roleAssignments.ok ? roleAssignments.value.seen : 0} inspected assignments.${roleAssignments.ok ? partialNote(roleAssignments.value, "role assignments") : ""}`,
      { privileged_service_principals: privilegedServicePrincipals.slice(0, 25) }));
  }

  return {
    title: "Azure subscription guardrails",
    summary: {
      owner_assignments: rbacManual ? null : ownerAssignments.length,
      contributor_assignments: rbacManual ? null : contributorAssignments.length,
      inspected_assignments: roleAssignments.ok ? roleAssignments.value.seen : null,
      network_watchers: networkWatchers.ok ? networkWatchers.value.items.length : null,
      privileged_service_principals: rbacManual ? null : privilegedServicePrincipals.length,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

export async function assessAzureDataProtection(
  client: DataProtectionClient,
  options: { maxMailboxes?: number } = {},
): Promise<AzureAssessmentResult> {
  const now = client.getNow();
  const maxMailboxes = clampNumber(options.maxMailboxes, DEFAULT_MAX_MAILBOXES, 1, 5000);
  const errors: string[] = [];
  const [policies, skus, compliancePolicies, devices, labels, vaults, storageAccounts, members, sharepoint] = await Promise.all([
    attemptPage(() => client.listConditionalAccessPolicies()),
    attemptPage(() => client.listSubscribedSkus()),
    attemptPage(() => client.listDeviceCompliancePolicies()),
    attemptPage(() => client.listManagedDevices()),
    attemptPage(() => client.listSensitivityLabels()),
    attemptPage(() => client.listKeyVaults()),
    attemptPage(() => client.listStorageAccounts()),
    attemptPage(() => client.listMemberUsers(maxMailboxes)),
    attempt(() => client.getSharePointSettings()),
  ]);
  const findings: AzureFinding[] = [];

  const intune = skus.ok ? hasIntuneLicense(skus.value.items) : undefined;
  if (!skus.ok) {
    findings.push(manualForError("AZURE-DP-01", 9, "Device compliance enforcement", "high", "GET /v1.0/subscribedSkus", "Organization.Read.All", "the license inventory proving Intune", skus, AZURE_ENDPOINT_DOCS.subscribedSkus, errors));
  } else if (intune !== true) {
    findings.push(finding("AZURE-DP-01", 9, "Device compliance enforcement", "high", "manual", "No INTUNE_* service plan is provisioned; device compliance requires an Intune license. Collect licensing evidence or document the compensating MDM control.", { intune_license: false, documentation: AZURE_ENDPOINT_DOCS.servicePlanNames }));
  } else if (!compliancePolicies.ok) {
    findings.push(manualForError("AZURE-DP-01", 9, "Device compliance enforcement", "high", "GET /v1.0/deviceManagement/deviceCompliancePolicies", "DeviceManagementConfiguration.Read.All with an Intune license", "the Intune compliance policy export", compliancePolicies, AZURE_ENDPOINT_DOCS.deviceCompliancePolicies, errors));
  } else if (!devices.ok) {
    findings.push(manualForError("AZURE-DP-01", 9, "Device compliance enforcement", "high", "GET /v1.0/deviceManagement/managedDevices", "DeviceManagementManagedDevices.Read.All with an Intune license", "the Intune managed device compliance report", devices, AZURE_ENDPOINT_DOCS.managedDevices, errors));
  } else if (!policies.ok) {
    findings.push(manualForError("AZURE-DP-01", 9, "Device compliance enforcement", "high", "GET /v1.0/identity/conditionalAccess/policies", "Policy.Read.All", "the Conditional Access policies requiring compliant devices", policies, AZURE_ENDPOINT_DOCS.conditionalAccess, errors));
  } else {
    const compliantDevicePolicies = enabledPolicies(policies.value.items).filter((policy) => builtInControls(policy).includes("compliantdevice"));
    const nonCompliant = devices.value.items.filter((device) => ["noncompliant", "conflict", "error"].includes(asLower(device.complianceState) ?? ""));
    const unknown = devices.value.items.filter((device) => !["compliant", "noncompliant", "conflict", "error", "ingraceperiod", "configmanager"].includes(asLower(device.complianceState) ?? ""));
    const status: AzureFindingStatus = compliancePolicies.value.items.length === 0
      ? "fail"
      : devices.value.items.length === 0
        ? "manual"
        : compliantDevicePolicies.length === 0 || nonCompliant.length > 0 ? "fail" : unknown.length > 0 ? "warn" : capForPartial("pass", compliancePolicies.value, devices.value, policies.value);
    findings.push(finding("AZURE-DP-01", 9, "Device compliance enforcement", "high", status,
      compliancePolicies.value.items.length === 0
        ? "Zero Intune device compliance policies exist (empty inventory fails by intent)."
        : devices.value.items.length === 0
          ? "Compliance policies exist but zero managed devices were returned; confirm enrollment before treating this as compliant."
          : `${compliancePolicies.value.items.length} compliance policies, ${nonCompliant.length}/${devices.value.items.length} devices noncompliant/conflict/error, ${unknown.length} with unknown complianceState, ${compliantDevicePolicies.length} enabled Conditional Access policies require a compliant device.${partialNote(devices.value, "managed devices")}`,
      { compliance_policies: compliancePolicies.value.items.length, devices: devices.value.items.length, noncompliant_devices: nonCompliant.length, unknown_state_devices: unknown.length, compliant_device_ca_policies: compliantDevicePolicies.length, ...pageEvidence(devices.value) }));
  }

  findings.push(finding("AZURE-DP-02", 10, "Data Loss Prevention policies", "medium", "manual",
    "Microsoft Graph exposes no DLP policy resource in v1.0 or beta (the beta security informationProtection resource lists only sensitivityLabels and labelPolicySettings). Collect Get-DlpCompliancePolicy and Get-DlpComplianceRule output from Security & Compliance PowerShell as evidence.",
    { graph_reference: AZURE_ENDPOINT_DOCS.informationProtectionResource, evidence_command: "Get-DlpCompliancePolicy | Format-List Name,Mode,Enabled,ExchangeLocation,SharePointLocation,OneDriveLocation", documentation: AZURE_ENDPOINT_DOCS.dlpPowerShell }));

  const betaCaveat = "Read from the Graph beta endpoint, which Microsoft may change without notice.";
  if (!labels.ok) {
    findings.push(manualForError("AZURE-DP-03", 11, "Sensitivity labels published", "medium", "GET /beta/security/informationProtection/sensitivityLabels", "InformationProtectionPolicy.Read.All with a Purview Information Protection license", "the sensitivity label policy export from the Purview portal", labels, AZURE_ENDPOINT_DOCS.sensitivityLabels, errors));
  } else {
    const active = labels.value.items.filter((label) => label.isActive === true);
    findings.push(finding("AZURE-DP-03", 11, "Sensitivity labels published", "medium", active.length > 0 ? capForPartial("pass", labels.value) : "fail",
      active.length > 0
        ? `${active.length}/${labels.value.items.length} sensitivity labels are active (${labels.value.items.filter((label) => label.hasProtection === true).length} apply protection). Label application to content is not exposed and stays a manual check. ${betaCaveat}${partialNote(labels.value, "labels")}`
        : labels.value.items.length === 0
          ? `Zero sensitivity labels are published (empty inventory fails by intent). ${betaCaveat}`
          : `${labels.value.items.length} labels exist but none is active. ${betaCaveat}`,
      { labels: labels.value.items.length, active_labels: active.length, endpoint: "GET /beta/security/informationProtection/sensitivityLabels", documentation: AZURE_ENDPOINT_DOCS.sensitivityLabels, ...pageEvidence(labels.value) }));
  }

  if (!vaults.ok) {
    findings.push(manualForError("AZURE-DP-04", 13, "Key Vault protection settings", "high", "GET Microsoft.KeyVault/vaults", "Reader on the subscription", "the Key Vault properties export", vaults, AZURE_ENDPOINT_DOCS.keyVaults, errors));
  } else {
    const missingProtection: string[] = [];
    const accessPolicyVaults: string[] = [];
    const openNetwork: string[] = [];
    for (const vault of vaults.value.items) {
      const properties = asObject(vault.properties) ?? {};
      const name = asString(vault.name) ?? "unknown";
      if (properties.enableSoftDelete !== true || properties.enablePurgeProtection !== true) missingProtection.push(name);
      if (properties.enableRbacAuthorization !== true && asRecords(properties.accessPolicies).length > 0) accessPolicyVaults.push(name);
      const defaultAction = asLower(asObject(properties.networkAcls)?.defaultAction);
      if (asLower(properties.publicNetworkAccess) !== "disabled" && defaultAction !== "deny") openNetwork.push(name);
    }
    const status: AzureFindingStatus = vaults.value.items.length === 0
      ? "manual"
      : missingProtection.length > 0 ? "fail" : accessPolicyVaults.length > 0 || openNetwork.length > 0 ? "warn" : capForPartial("pass", vaults.value);
    findings.push(finding("AZURE-DP-04", 13, "Key Vault protection settings", "high", status,
      vaults.value.items.length === 0
        ? "Zero Key Vaults were returned; confirm the subscription has none (Reader on every resource group) before treating this as not applicable."
        : `${vaults.value.items.length} vaults: ${missingProtection.length} lack enableSoftDelete and enablePurgeProtection, ${accessPolicyVaults.length} use access policies instead of RBAC, ${openNetwork.length} allow public network access without a Deny default.${partialNote(vaults.value, "vaults")}`,
      { vaults: vaults.value.items.length, missing_protection: missingProtection.slice(0, 25), access_policy_vaults: accessPolicyVaults.slice(0, 25), open_network: openNetwork.slice(0, 25), ...pageEvidence(vaults.value) }));
  }

  if (!storageAccounts.ok) {
    findings.push(manualForError("AZURE-DP-05", 14, "Storage account transport and access settings", "high", "GET Microsoft.Storage/storageAccounts", "Reader on the subscription", "the storage account configuration export", storageAccounts, AZURE_ENDPOINT_DOCS.storageAccounts, errors));
  } else {
    const httpAllowed: string[] = [];
    const publicBlob: string[] = [];
    const publicBlobUnset: string[] = [];
    const weakTls: string[] = [];
    let customerManagedKeys = 0;
    for (const account of storageAccounts.value.items) {
      const properties = asObject(account.properties) ?? {};
      const name = asString(account.name) ?? "unknown";
      if (properties.supportsHttpsTrafficOnly !== true) httpAllowed.push(name);
      if (properties.allowBlobPublicAccess === true) publicBlob.push(name);
      else if (properties.allowBlobPublicAccess !== false) publicBlobUnset.push(name);
      const tls = asString(properties.minimumTlsVersion);
      if (tls !== "TLS1_2" && tls !== "TLS1_3") weakTls.push(name);
      if (asLower(asObject(properties.encryption)?.keySource) === "microsoft.keyvault") customerManagedKeys += 1;
    }
    const status: AzureFindingStatus = storageAccounts.value.items.length === 0
      ? "manual"
      : httpAllowed.length > 0 || publicBlob.length > 0 ? "fail" : weakTls.length > 0 || publicBlobUnset.length > 0 ? "warn" : capForPartial("pass", storageAccounts.value);
    findings.push(finding("AZURE-DP-05", 14, "Storage account transport and access settings", "high", status,
      storageAccounts.value.items.length === 0
        ? "Zero storage accounts were returned; confirm the subscription has none before treating this as not applicable."
        : `${storageAccounts.value.items.length} storage accounts: ${httpAllowed.length} without supportsHttpsTrafficOnly, ${publicBlob.length} with allowBlobPublicAccess true, ${publicBlobUnset.length} without an explicit allowBlobPublicAccess false, ${weakTls.length} below TLS1_2, ${customerManagedKeys} using customer-managed keys.${partialNote(storageAccounts.value, "storage accounts")}`,
      { storage_accounts: storageAccounts.value.items.length, http_allowed: httpAllowed.slice(0, 25), public_blob_access: publicBlob.slice(0, 25), public_blob_unset: publicBlobUnset.slice(0, 25), weak_tls: weakTls.slice(0, 25), customer_managed_keys: customerManagedKeys, ...pageEvidence(storageAccounts.value) }));
  }

  if (!members.ok) {
    findings.push(manualForError("AZURE-DP-06", 20, "Inbox forwarding rules", "high", "GET /v1.0/users?$filter=userType eq 'Member'", "User.Read.All and MailboxSettings.Read", "the inbox rule export for every mailbox", members, AZURE_ENDPOINT_DOCS.users, errors));
  } else {
    const forwardingRules: JsonRecord[] = [];
    let mailboxesRead = 0;
    let mailboxesDenied = 0;
    let mailboxesErrored = 0;
    let permissionFailure: { error: string; status?: number } | undefined;
    let otherFailure: { error: string; status?: number } | undefined;
    let tokenFailure: { error: string; status?: number; url?: string } | undefined;
    for (const user of members.value.items) {
      const userId = asString(user.id);
      if (!userId) continue;
      const rules = await attemptPage(() => client.listInboxMessageRules(userId));
      if (!rules.ok) {
        // A refused token (expired mid-run) is not a mailbox permission gap: no mailbox request was made and none can be.
        if (isTokenRequestFailure(rules)) {
          tokenFailure = rules;
          break;
        }
        if (rules.status === 401 || rules.status === 403) {
          mailboxesDenied += 1;
          permissionFailure = rules;
        } else {
          mailboxesErrored += 1;
          otherFailure = rules;
        }
        continue;
      }
      mailboxesRead += 1;
      for (const rule of rules.value.items) {
        if (rule.isEnabled === false) continue;
        const actions = asObject(rule.actions) ?? {};
        if (asArray(actions.forwardTo).length > 0 || asArray(actions.redirectTo).length > 0 || asArray(actions.forwardAsAttachmentTo).length > 0) {
          forwardingRules.push({ user: user.userPrincipalName, rule: rule.displayName });
        }
      }
    }
    const mailboxesUnreadable = mailboxesDenied + mailboxesErrored;
    if (tokenFailure) {
      findings.push(manualForError("AZURE-DP-06", 20, "Inbox forwarding rules", "high", MESSAGE_RULES_ENDPOINT, MAILBOX_RULES_PERMISSION, "the inbox rule export for every mailbox", tokenFailure, AZURE_ENDPOINT_DOCS.messageRules, errors));
    } else if (permissionFailure && mailboxesRead === 0) {
      findings.push(manualForError("AZURE-DP-06", 20, "Inbox forwarding rules", "high", MESSAGE_RULES_ENDPOINT, MAILBOX_RULES_PERMISSION, "the inbox rule export for every mailbox", permissionFailure, AZURE_ENDPOINT_DOCS.messageRules, errors));
    } else {
      // A denied subset is a permission gap on those mailboxes, not a licensing quirk; only non-permission
      // errors (typically 404 for users without an Exchange mailbox) are described that way.
      if (permissionFailure) errors.push(`AZURE-DP-06 ${MESSAGE_RULES_ENDPOINT}: ${describeFailure(permissionFailure)} on ${mailboxesDenied} of ${mailboxesRead + mailboxesUnreadable} mailboxes`);
      if (otherFailure) errors.push(`AZURE-DP-06 ${MESSAGE_RULES_ENDPOINT}: ${describeFailure(otherFailure)} on ${mailboxesErrored} of ${mailboxesRead + mailboxesUnreadable} mailboxes`);
      const unreadableNotes = [
        mailboxesDenied > 0 && permissionFailure ? `${mailboxesDenied} denied with ${describeFailure(permissionFailure)}, so ${MAILBOX_RULES_PERMISSION} is missing for those mailboxes and their rules were not inspected` : "",
        mailboxesErrored > 0 && otherFailure ? `${mailboxesErrored} returned a non-permission error (${describeFailure(otherFailure)}; commonly users without an Exchange mailbox)` : "",
      ].filter(Boolean);
      const partial = members.value.truncated || mailboxesUnreadable > 0;
      const status: AzureFindingStatus = members.value.items.length === 0
        ? "manual"
        : forwardingRules.length > 0 ? "fail" : partial ? "warn" : "pass";
      const unreadableSummary = mailboxesUnreadable > 0
        ? ` (${mailboxesUnreadable} unreadable: ${unreadableNotes.join("; ")}${status === "warn" ? "; verdict capped at warn" : ""})`
        : "";
      findings.push(finding("AZURE-DP-06", 20, "Inbox forwarding rules", "high", status,
        members.value.items.length === 0
          ? "Zero enabled member users were returned; confirm User.Read.All before treating mailboxes as clean."
          : `${forwardingRules.length} enabled inbox rules forward or redirect mail across ${mailboxesRead} readable mailboxes${unreadableSummary}.${partialNote(members.value, "member users")}`,
        {
          mailboxes_read: mailboxesRead,
          mailboxes_unreadable: mailboxesUnreadable,
          mailboxes_permission_denied: mailboxesDenied,
          mailboxes_other_errors: mailboxesErrored,
          permission_failure: permissionFailure ? { endpoint: MESSAGE_RULES_ENDPOINT, http_status: permissionFailure.status ?? null, required_access: MAILBOX_RULES_PERMISSION, error: permissionFailure.error.slice(0, 300) } : null,
          other_failure: otherFailure ? { endpoint: MESSAGE_RULES_ENDPOINT, http_status: otherFailure.status ?? null, error: otherFailure.error.slice(0, 300) } : null,
          forwarding_rules: forwardingRules.slice(0, 25),
          ...pageEvidence(members.value),
        }));
    }
  }

  findings.push(finding("AZURE-DP-07", 20, "Mailbox-level forwarding and transport rules", "high", "manual",
    "Graph mailboxSettings exposes no forwarding property and transport rules are not exposed through Graph. Collect Get-Mailbox ForwardingSmtpAddress/ForwardingAddress/DeliverToMailboxAndForward and Get-TransportRule output from Exchange Online PowerShell.",
    { graph_reference: AZURE_ENDPOINT_DOCS.mailboxSettings, evidence_commands: ["Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Format-List UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward", "Get-TransportRule | Format-List Name,State,RedirectMessageTo,BlindCopyTo,AddToRecipients"], documentation: [AZURE_ENDPOINT_DOCS.setMailboxPowerShell, AZURE_ENDPOINT_DOCS.transportRulePowerShell] }));

  if (!sharepoint.ok) {
    findings.push(manualForError("AZURE-DP-08", 21, "SharePoint external sharing", "medium", "GET /v1.0/admin/sharepoint/settings", "SharePointTenantSettings.Read.All", "the SharePoint admin center sharing settings page", sharepoint, AZURE_ENDPOINT_DOCS.sharepointSettings, errors));
  } else {
    const settings = asObject(sharepoint.value) ?? {};
    const capability = asLower(settings.sharingCapability);
    const domainMode = asLower(settings.sharingDomainRestrictionMode);
    const resharing = settings.isResharingByExternalUsersEnabled === true;
    let status: AzureFindingStatus;
    if (capability === undefined) status = "manual";
    else if (capability === "disabled" || capability === "existingexternalusersharingonly") status = resharing ? "warn" : "pass";
    else if (capability === "externalusersharingonly") status = domainMode === "allowlist" && !resharing ? "pass" : "warn";
    else status = "fail";
    findings.push(finding("AZURE-DP-08", 21, "SharePoint external sharing", "medium", status,
      capability === undefined
        ? "sharepointSettings did not include sharingCapability; collect the sharing settings manually."
        : `sharingCapability is ${capability}, sharingDomainRestrictionMode is ${domainMode ?? "none"}, resharing by external users is ${resharing ? "enabled" : "disabled"}. Teams guest access is not exposed through Graph v1.0 and stays a manual check.`,
      { sharingCapability: settings.sharingCapability ?? null, sharingDomainRestrictionMode: settings.sharingDomainRestrictionMode ?? null, isResharingByExternalUsersEnabled: settings.isResharingByExternalUsersEnabled ?? null, documentation: AZURE_ENDPOINT_DOCS.sharepointSettingsResource }));
  }

  return {
    title: "Azure data and endpoint protection",
    summary: {
      intune_license: intune ?? null,
      compliance_policies: compliancePolicies.ok ? compliancePolicies.value.items.length : null,
      managed_devices: devices.ok ? devices.value.items.length : null,
      sensitivity_labels: labels.ok ? labels.value.items.length : null,
      key_vaults: vaults.ok ? vaults.value.items.length : null,
      storage_accounts: storageAccounts.ok ? storageAccounts.value.items.length : null,
      mailboxes_sampled: members.ok ? members.value.items.length : null,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

function portRangeCoversAdminPort(range: string): boolean {
  const value = range.trim();
  if (value === "*") return true;
  const [startText, endText] = value.split("-");
  const start = Number(startText);
  const end = endText === undefined ? start : Number(endText);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return false;
  return ADMIN_PORTS.some((port) => port >= start && port <= end);
}

function isAnySource(prefix: string | undefined): boolean {
  const value = prefix?.toLowerCase();
  return value === "*" || value === "internet" || value === "any" || value === "0.0.0.0/0" || value === "0.0.0.0" || value === "/0" || value === "::/0";
}

export function isExposedAdminRule(rule: JsonRecord): boolean {
  const properties = asObject(rule.properties) ?? {};
  if (asLower(properties.access) !== "allow" || asLower(properties.direction) !== "inbound") return false;
  const protocol = asLower(properties.protocol);
  if (protocol !== "*" && protocol !== "tcp") return false;
  const sources = [asString(properties.sourceAddressPrefix), ...asArray(properties.sourceAddressPrefixes).map(asString)];
  if (!sources.some(isAnySource)) return false;
  const ports = [asString(properties.destinationPortRange), ...asArray(properties.destinationPortRanges).map(asString)].filter((value): value is string => Boolean(value));
  return ports.some(portRangeCoversAdminPort);
}

/** Resource ID shape from the Network Watchers - List All response sample. */
const NETWORK_WATCHER_ID_PATTERN = /^\/subscriptions\/[^/]+\/resourceGroups\/([^/]+)\/providers\/Microsoft\.Network\/networkWatchers\/([^/]+)$/i;

export function parseNetworkWatcherId(id: unknown): { resourceGroupName: string; networkWatcherName: string } | undefined {
  const match = asString(id)?.match(NETWORK_WATCHER_ID_PATTERN);
  return match ? { resourceGroupName: match[1], networkWatcherName: match[2] } : undefined;
}

function combinePages(pages: AzurePage[]): AzurePage {
  const totals = pages.map((page) => page.total);
  const truncation = pages.map((page) => page.truncation).find((reason): reason is string => Boolean(reason));
  return {
    items: pages.flatMap((page) => page.items),
    truncated: pages.some((page) => page.truncated),
    seen: pages.reduce((sum, page) => sum + page.seen, 0),
    total: totals.every((total): total is number => total !== undefined) ? totals.reduce((sum, total) => sum + total, 0) : undefined,
    ...(truncation ? { truncation } : {}),
  };
}

function isNetworkSecurityGroupId(value: string): boolean {
  return value.includes("/providers/microsoft.network/networksecuritygroups/");
}

export async function assessAzureNetworkAndPolicy(client: NetworkPolicyClient): Promise<AzureAssessmentResult> {
  const errors: string[] = [];
  const [nsgs, assignments, summary, watchers] = await Promise.all([
    attemptPage(() => client.listNetworkSecurityGroups()),
    attemptPage(() => client.listPolicyAssignments()),
    attempt(() => client.summarizePolicyStates()),
    attemptPage(() => client.listNetworkWatchers()),
  ]);
  const findings: AzureFinding[] = [];

  if (!nsgs.ok) {
    findings.push(manualForError("AZURE-NP-01", 12, "Unrestricted inbound admin ports", "critical", "GET Microsoft.Network/networkSecurityGroups", "Reader on the subscription", "the NSG inbound rule export", nsgs, AZURE_ENDPOINT_DOCS.networkSecurityGroups, errors));
  } else {
    const exposed: JsonRecord[] = [];
    for (const nsg of nsgs.value.items) {
      for (const rule of asRecords(asObject(nsg.properties)?.securityRules)) {
        if (isExposedAdminRule(rule)) {
          const properties = asObject(rule.properties) ?? {};
          exposed.push({ nsg: nsg.name, rule: rule.name, destinationPortRange: properties.destinationPortRange ?? properties.destinationPortRanges, sourceAddressPrefix: properties.sourceAddressPrefix ?? properties.sourceAddressPrefixes, priority: properties.priority });
        }
      }
    }
    findings.push(finding("AZURE-NP-01", 12, "Unrestricted inbound admin ports", "critical",
      nsgs.value.items.length === 0 ? "manual" : exposed.length > 0 ? "fail" : capForPartial("pass", nsgs.value),
      nsgs.value.items.length === 0
        ? "Zero network security groups were returned; confirm the subscription has none before treating this as not applicable."
        : exposed.length > 0
          ? `${exposed.length} inbound Allow rules expose ports ${ADMIN_PORTS.join("/")} to any source across ${nsgs.value.items.length} NSGs.`
          : `No inbound Allow rule exposes ports ${ADMIN_PORTS.join("/")} to any source across ${nsgs.value.items.length} NSGs.${partialNote(nsgs.value, "NSGs")}`,
      { network_security_groups: nsgs.value.items.length, exposed_rules: exposed.slice(0, 25), admin_ports: ADMIN_PORTS, ...pageEvidence(nsgs.value) }));
  }

  const flowLogPages: AzurePage[] = [];
  let flowLogFailure: { error: string; status?: number } | undefined;
  const unparsedWatchers: string[] = [];
  if (watchers.ok && nsgs.ok) {
    for (const watcher of watchers.value.items) {
      const parsed = parseNetworkWatcherId(watcher.id);
      if (!parsed) {
        unparsedWatchers.push(asString(watcher.name) ?? asString(watcher.id) ?? "unknown");
        continue;
      }
      const page = await attemptPage(() => client.listFlowLogs(parsed.resourceGroupName, parsed.networkWatcherName));
      if (!page.ok) {
        flowLogFailure = page;
        break;
      }
      flowLogPages.push(page.value);
    }
  }
  const flowLogPage = combinePages(flowLogPages);
  if (!watchers.ok) {
    findings.push(manualForError("AZURE-NP-04", 24, "NSG flow logs enabled", "medium", "GET Microsoft.Network/networkWatchers", "Reader on the subscription", "the flow logs page of every Network Watcher", watchers, AZURE_ENDPOINT_DOCS.networkWatchers, errors));
  } else if (!nsgs.ok) {
    findings.push(manualForError("AZURE-NP-04", 24, "NSG flow logs enabled", "medium", "GET Microsoft.Network/networkSecurityGroups", "Reader on the subscription", "the NSG inventory with flow log status", nsgs, AZURE_ENDPOINT_DOCS.networkSecurityGroups, errors));
  } else if (flowLogFailure) {
    findings.push(manualForError("AZURE-NP-04", 24, "NSG flow logs enabled", "medium", "GET Microsoft.Network/networkWatchers/{networkWatcherName}/flowLogs", "Reader on the Network Watcher resource group", "the flow logs page of every Network Watcher", flowLogFailure, AZURE_ENDPOINT_DOCS.flowLogs, errors));
  } else if (unparsedWatchers.length > 0) {
    errors.push(`AZURE-NP-04 GET Microsoft.Network/networkWatchers: ${unparsedWatchers.length} watcher ids did not match the documented resource ID shape`);
    findings.push(finding("AZURE-NP-04", 24, "NSG flow logs enabled", "medium", "manual",
      `${unparsedWatchers.length} Network Watcher ids did not match the documented /subscriptions/{id}/resourceGroups/{rg}/providers/Microsoft.Network/networkWatchers/{name} shape, so their flow logs were not read; collect the flow logs page manually.`,
      { unparsed_watchers: unparsedWatchers.slice(0, 25), documentation: AZURE_ENDPOINT_DOCS.networkWatchers }));
  } else {
    const flowLogs = flowLogPage.items;
    const enabledTargets = new Set<string>();
    let disabledFlowLogs = 0;
    const details: JsonRecord[] = [];
    for (const flowLog of flowLogs) {
      const properties = asObject(flowLog.properties) ?? {};
      const target = asLower(properties.targetResourceId);
      const retentionPolicy = asObject(properties.retentionPolicy);
      if (properties.enabled === true && target) enabledTargets.add(target);
      else disabledFlowLogs += 1;
      details.push({ name: flowLog.name ?? null, targetResourceId: properties.targetResourceId ?? null, enabled: properties.enabled ?? null, retention_days: asNumber(retentionPolicy?.days) ?? null, retention_enabled: retentionPolicy?.enabled ?? null, provisioningState: properties.provisioningState ?? null });
    }
    const uncovered = nsgs.value.items.filter((nsg) => !enabledTargets.has(asLower(nsg.id) ?? ""));
    const covered = nsgs.value.items.length - uncovered.length;
    const nonNsgTargets = [...enabledTargets].filter((target) => !isNetworkSecurityGroupId(target)).length;
    const pages = [nsgs.value, watchers.value, flowLogPage];
    const status: AzureFindingStatus = nsgs.value.items.length === 0
      ? "manual"
      : uncovered.length === 0 ? capForPartial("pass", ...pages) : covered > 0 ? "warn" : "fail";
    findings.push(finding("AZURE-NP-04", 24, "NSG flow logs enabled", "medium", status,
      nsgs.value.items.length === 0
        ? "Zero network security groups were returned; confirm the subscription has none before treating flow logging as not applicable."
        : watchers.value.items.length === 0
          ? `${nsgs.value.items.length} NSGs exist but no Network Watcher resource exists, so no flow log can be enabled.`
          : `${covered}/${nsgs.value.items.length} NSGs have an enabled flow log (${flowLogs.length} flow logs across ${watchers.value.items.length} Network Watchers, ${disabledFlowLogs} disabled or without a target, ${nonNsgTargets} enabled flow logs target other resource types and are not credited to an NSG). Retention policy values are reported as evidence, not judged.${partialNote(nsgs.value, "NSGs")}${partialNote(watchers.value, "network watchers")}${partialNote(flowLogPage, "flow logs")}`,
      { network_security_groups: nsgs.value.items.length, covered_nsgs: covered, uncovered_nsgs: uncovered.slice(0, 25).map((nsg) => nsg.name ?? nsg.id), network_watchers: watchers.value.items.length, flow_logs: flowLogs.length, disabled_flow_logs: disabledFlowLogs, non_nsg_targets: nonNsgTargets, flow_log_details: details.slice(0, 25), ...pageEvidence(flowLogPage) }));
  }

  if (!assignments.ok) {
    findings.push(manualForError("AZURE-NP-02", 25, "Azure Policy assignments enforced", "medium", "GET Microsoft.Authorization/policyAssignments", "Reader on the subscription", "the Azure Policy assignments export", assignments, AZURE_ENDPOINT_DOCS.policyAssignments, errors));
  } else {
    const enforced = assignments.value.items.filter((item) => asLower(asObject(item.properties)?.enforcementMode) !== "donotenforce");
    const mandatoryPresent = MANDATORY_POLICY_DEFINITIONS.filter((definition) => assignments.value.items.some((item) => (asLower(asObject(item.properties)?.policyDefinitionId) ?? "").endsWith(definition.id)));
    const mandatoryNotSeen = MANDATORY_POLICY_DEFINITIONS.filter((item) => !mandatoryPresent.includes(item)).map((item) => item.name);
    // A truncated page cannot prove absence: the unseen built-ins are reported as not seen, and only a
    // complete page states which mandatory definitions are missing.
    const pageComplete = !assignments.value.truncated;
    findings.push(finding("AZURE-NP-02", 25, "Azure Policy assignments enforced", "medium",
      assignments.value.items.length === 0 ? "fail" : enforced.length === 0 ? "fail" : enforced.length < assignments.value.items.length ? "warn" : capForPartial("pass", assignments.value),
      assignments.value.items.length === 0
        ? "Zero Azure Policy assignments apply at subscription scope (empty inventory fails by intent)."
        : `${enforced.length}/${assignments.value.items.length} policy assignments use enforcementMode Default; mandatory built-ins present: ${mandatoryPresent.map((item) => item.name).join(", ") || "none"}${pageComplete ? "" : `; ${mandatoryNotSeen.length} mandatory built-ins were not seen on the truncated page and may exist among the unseen assignments`}.${partialNote(assignments.value, "policy assignments")}`,
      {
        assignments: assignments.value.items.length,
        enforced: enforced.length,
        do_not_enforce: assignments.value.items.length - enforced.length,
        mandatory_present: mandatoryPresent.map((item) => item.name),
        mandatory_missing: pageComplete ? mandatoryNotSeen : null,
        mandatory_not_seen: pageComplete ? null : mandatoryNotSeen,
        ...pageEvidence(assignments.value),
      }));
  }

  if (!summary.ok) {
    findings.push(manualForError("AZURE-NP-03", 25, "Azure Policy compliance state", "medium", "POST Microsoft.PolicyInsights/policyStates/latest/summarize", "Reader on the subscription", "the Azure Policy compliance dashboard export", summary, AZURE_ENDPOINT_DOCS.policyStatesSummarize, errors));
  } else {
    const results = asObject(asRecords(asObject(summary.value)?.value)[0]?.results) ?? {};
    const nonCompliantResources = asNumber(results.nonCompliantResources);
    const nonCompliantPolicies = asNumber(results.nonCompliantPolicies);
    findings.push(finding("AZURE-NP-03", 25, "Azure Policy compliance state", "medium",
      nonCompliantResources === undefined || nonCompliantPolicies === undefined ? "manual" : nonCompliantPolicies === 0 ? "pass" : "warn",
      nonCompliantResources === undefined || nonCompliantPolicies === undefined
        ? "The policy state summary did not include nonCompliantResources/nonCompliantPolicies; collect the compliance dashboard manually."
        : `${nonCompliantResources} non-compliant resources across ${nonCompliantPolicies} non-compliant policies.`,
      { non_compliant_resources: nonCompliantResources ?? null, non_compliant_policies: nonCompliantPolicies ?? null }));
  }

  return {
    title: "Azure network and policy posture",
    summary: {
      network_security_groups: nsgs.ok ? nsgs.value.items.length : null,
      network_watchers: watchers.ok ? watchers.value.items.length : null,
      flow_logs: watchers.ok && nsgs.ok && !flowLogFailure ? flowLogPage.seen : null,
      policy_assignments: assignments.ok ? assignments.value.items.length : null,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: AzureAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : `${surfaceItem.count}${surfaceItem.truncated ? "+ (capped)" : ""}`,
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Azure access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AzureAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    String(item.control),
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
    formatTable(["Finding", "Spec", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Errors:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function countByStatus(findings: AzureFinding[]): Record<AzureFindingStatus, number> {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

function buildExecutiveSummary(config: AzureResolvedConfig, assessments: AzureAssessmentResult[], generatedAt: string): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const coveredControls = new Set(findings.map((item) => item.control));
  return [
    "# Azure Audit Bundle",
    "",
    `Tenant: ${config.tenantId}`,
    `Subscription: ${config.subscriptionId}`,
    `Cloud: ${config.cloud?.name ?? "public"}`,
    `Generated: ${generatedAt}`,
    "",
    "## Result Counts",
    "",
    `- Failed findings: ${counts.fail}`,
    `- Warning findings: ${counts.warn}`,
    `- Manual findings: ${counts.manual}`,
    `- Passing findings: ${counts.pass}`,
    `- Spec controls covered: ${coveredControls.size} of 25`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .slice(0, 15)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Needed",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedComplianceMatrix(findings: AzureFinding[]): string {
  const rows = findings.map((item) => {
    const mapping = AZURE_CONTROL_MAPPINGS[item.control];
    return [
      item.id,
      String(item.control),
      item.status.toUpperCase(),
      item.title,
      ...AZURE_FRAMEWORKS.map((framework) => mapping?.[framework.key] ?? "n/a"),
    ];
  });
  return [
    "# Unified Compliance Matrix",
    "",
    "Each finding maps to a spec control (1 to 25) whose framework references come from section 5 of specs/azure-sec-inspector.spec.md.",
    "",
    formatTable(["Finding", "Spec", "Status", "Title", ...AZURE_FRAMEWORKS.map((framework) => framework.label)], rows),
  ].join("\n");
}

function buildFrameworkReport(framework: { key: AzureFramework; label: string }, findings: AzureFinding[]): string {
  const relevant = findings.filter((item) => AZURE_CONTROL_MAPPINGS[item.control]?.[framework.key] !== "n/a");
  const counts = countByStatus(relevant);
  const rows = relevant.map((item) => [
    AZURE_CONTROL_MAPPINGS[item.control]?.[framework.key] ?? "n/a",
    item.id,
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  return [
    `# ${framework.label} Report`,
    "",
    `Findings mapped: ${relevant.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    formatTable(["Requirement", "Finding", "Status", "Title", "Summary"], rows),
  ].join("\n");
}

function buildQuickReference(result: { assessments: AzureAssessmentResult[]; errors: string[] }): string {
  const findings = result.assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  return [
    "# Quick Reference",
    "",
    `Findings: ${findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    "## Layout",
    "",
    "- `core_data/`: raw access-check inventory and run metadata (no tokens)",
    "- `analysis/`: normalized findings and per-assessment JSON",
    "- `compliance/executive_summary.md`: prioritized summary",
    "- `compliance/unified_compliance_matrix.md`: finding to framework matrix",
    "- `compliance/<framework>.md`: one report per framework in the spec mapping table",
    "- `_errors.log`: present only when an API call failed; each entry names the finding that rendered manual or recorded the failure in its evidence",
    "",
    "## Status semantics",
    "",
    "- pass: evidence collected and compliant",
    "- warn: compliant with caveats, partial inventory, or missing dates",
    "- fail: evidence collected and non-compliant (including empty inventories where emptiness fails by intent)",
    "- manual: endpoint errored, license or service absent, or the API does not expose the control",
    "",
    "## Fail and manual findings",
    "",
    ...findings.filter((item) => item.status !== "pass").map((item) => `- ${item.id} [${item.status}]: ${item.title}`),
    ...(result.errors.length > 0 ? ["", "## Errors", "", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Azure Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Azure tools.",
    "",
    "## Contents",
    "",
    "- `QUICK_REFERENCE.md`: layout, status semantics, and open findings",
    "- `summary.md`: combined human-readable assessment output",
    "- `compliance/`: executive summary, unified compliance matrix, per-framework reports",
    "- `analysis/`: normalized findings and assessment details as JSON",
    "- `core_data/`: accessible Azure audit surface inventory and non-secret run metadata",
    "- `_errors.log`: API failures recorded during the run, each named in the affected finding (only on partial failure)",
    "",
    "Resolved access tokens and client secrets are never written to this bundle. Service principal and app registration",
    "credentials are reduced to their schedule fields (keyId, start, end, type) before they are kept, and API error bodies are",
    "reduced to their documented error code and message.",
  ].join("\n");
}

export async function exportAzureAuditBundle(
  client: AzureAuditorClient,
  config: AzureResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AzureAuditBundleResult> {
  const access = await checkAzureAccess(client);
  const identity = await assessAzureIdentity(client);
  const monitoring = await assessAzureMonitoring(client);
  const subscriptionGuardrails = await assessAzureSubscriptionGuardrails(client, { maxAssignments: options.max_assignments });
  const dataProtection = await assessAzureDataProtection(client, { maxMailboxes: options.max_mailboxes });
  const networkAndPolicy = await assessAzureNetworkAndPolicy(client);

  const assessments = [identity, monitoring, subscriptionGuardrails, dataProtection, networkAndPolicy];
  const { findings, errors } = mergeAssessments("Azure audit bundle", assessments);
  const generatedAt = new Date().toISOString();
  const targetName = safeDirName(`${config.tenantId}-${config.subscriptionId}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference({ assessments, errors }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "core_data/metadata.json", serializeJson({
    tenant_id: config.tenantId,
    subscription_id: config.subscriptionId,
    cloud: config.cloud?.name ?? "public",
    source_chain: config.sourceChain,
    generated_at: generatedAt,
    options: {
      max_assignments: options.max_assignments ?? DEFAULT_MAX_ASSIGNMENTS,
      max_mailboxes: options.max_mailboxes ?? DEFAULT_MAX_MAILBOXES,
    },
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/monitoring.json", serializeJson(monitoring));
  await writeSecureTextFile(outputDir, "analysis/subscription-guardrails.json", serializeJson(subscriptionGuardrails));
  await writeSecureTextFile(outputDir, "analysis/data-protection.json", serializeJson(dataProtection));
  await writeSecureTextFile(outputDir, "analysis/network-and-policy.json", serializeJson(networkAndPolicy));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedComplianceMatrix(findings));
  for (const framework of AZURE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.key}.md`, buildFrameworkReport(framework, findings));
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
    tenant_id: asString(value.tenant_id),
    subscription_id: asString(value.subscription_id),
    graph_token: asString(value.graph_token),
    management_token: asString(value.management_token),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    authority_host: asString(value.authority_host),
  };
}

function normalizeSubscriptionArgs(args: unknown): SubscriptionArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_assignments: asNumber(value.max_assignments),
  };
}

function normalizeDataProtectionArgs(args: unknown): DataProtectionArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_mailboxes: asNumber(value.max_mailboxes),
  };
}

export function mergeAssessments(title: string, assessments: AzureAssessmentResult[]): AzureAssessmentResult {
  return {
    title,
    summary: Object.assign({}, ...assessments.map((assessment) => assessment.summary)),
    findings: assessments.flatMap((assessment) => assessment.findings),
    errors: assessments.flatMap((assessment) => assessment.errors),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeSubscriptionArgs(args),
    ...normalizeDataProtectionArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): AzureAuditorClient {
  return new AzureAuditorClient(resolveAzureConfiguration(args));
}

const authParams = {
  tenant_id: Type.Optional(Type.String({ description: "Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show." })),
  subscription_id: Type.Optional(Type.String({ description: "Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show." })),
  graph_token: Type.Optional(Type.String({ description: "Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN, client credentials, or az account get-access-token." })),
  management_token: Type.Optional(Type.String({ description: "Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN, client credentials, or az account get-access-token." })),
  client_id: Type.Optional(Type.String({ description: "App registration client ID for the OAuth 2.0 client credentials flow. Defaults to AZURE_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "Client secret for the client credentials flow. Defaults to AZURE_CLIENT_SECRET." })),
  authority_host: Type.Optional(Type.String({ description: "Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), login.chinacloudapi.cn or login.partner.microsoftonline.cn (China). Defaults to AZURE_AUTHORITY_HOST." })),
};

const maxMailboxesParam = Type.Optional(Type.Number({ description: `Maximum member mailboxes to inspect for inbox forwarding rules. Defaults to ${DEFAULT_MAX_MAILBOXES}.`, default: DEFAULT_MAX_MAILBOXES }));
const maxAssignmentsParam = Type.Optional(Type.Number({ description: "Maximum ARM role assignments to sample. Defaults to 500.", default: 500 }));

export function registerAzureTools(pi: any): void {
  pi.registerTool({
    name: "azure_check_access",
    label: "Check Azure audit access",
    description:
      "Validate read-only Azure audit access across Entra ID, Microsoft Graph security surfaces, and subscription-level ARM posture endpoints.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAzureAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "azure_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Azure access check failed: ${describeThrown(error)}`,
          { tool: "azure_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_identity",
    label: "Assess Azure identity posture",
    description:
      "Assess Entra ID posture: Conditional Access MFA and legacy auth, MFA registration, privileged roles and PIM, guest access, sign-in and user risk policies, risky users, app registration credentials, and tenant-wide consent grants.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessAzureIdentity(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "azure_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Azure identity assessment failed: ${describeThrown(error)}`,
          { tool: "azure_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_monitoring",
    label: "Assess Azure monitoring posture",
    description:
      "Assess Secure Score, directory audit and sign-in visibility, Defender for Cloud plan coverage, subscription diagnostic settings, and Log Analytics retention depth.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessAzureMonitoring(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "azure_assess_monitoring", ...result });
      } catch (error) {
        return errorResult(
          `Azure monitoring assessment failed: ${describeThrown(error)}`,
          { tool: "azure_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_subscription_guardrails",
    label: "Assess Azure subscription guardrails",
    description:
      "Assess Azure subscription guardrails: Owner and Contributor sprawl at subscription scope, Defender for Cloud security contacts, Network Watcher presence, and service principals holding Owner or Contributor.",
    parameters: Type.Object({ ...authParams, max_assignments: maxAssignmentsParam }),
    prepareArguments: normalizeSubscriptionArgs,
    async execute(_toolCallId: string, args: SubscriptionArgs) {
      try {
        const result = await assessAzureSubscriptionGuardrails(createClient(args), { maxAssignments: args.max_assignments });
        return textResult(formatAssessmentText(result), { tool: "azure_assess_subscription_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `Azure subscription guardrail assessment failed: ${describeThrown(error)}`,
          { tool: "azure_assess_subscription_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_data_protection",
    label: "Assess Azure data and endpoint protection",
    description:
      "Assess Intune device compliance, DLP policy evidence, sensitivity labels (Graph beta), Key Vault soft delete, purge protection, RBAC and network ACLs, storage HTTPS-only, public blob access and TLS, inbox forwarding rules, and SharePoint external sharing.",
    parameters: Type.Object({ ...authParams, max_mailboxes: maxMailboxesParam }),
    prepareArguments: normalizeDataProtectionArgs,
    async execute(_toolCallId: string, args: DataProtectionArgs) {
      try {
        const result = await assessAzureDataProtection(createClient(args), { maxMailboxes: args.max_mailboxes });
        return textResult(formatAssessmentText(result), { tool: "azure_assess_data_protection", ...result });
      } catch (error) {
        return errorResult(
          `Azure data protection assessment failed: ${describeThrown(error)}`,
          { tool: "azure_assess_data_protection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_network_and_policy",
    label: "Assess Azure network and policy posture",
    description:
      "Assess NSG inbound rules exposing admin ports to any source, NSG flow log coverage per Network Watcher, Azure Policy assignment enforcement, and Azure Policy compliance state.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessAzureNetworkAndPolicy(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "azure_assess_network_and_policy", ...result });
      } catch (error) {
        return errorResult(
          `Azure network and policy assessment failed: ${describeThrown(error)}`,
          { tool: "azure_assess_network_and_policy" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_export_audit_bundle",
    label: "Export Azure audit bundle",
    description:
      "Export an Azure audit package with access checks, all five assessments, per-framework compliance reports, JSON analysis, an errors log on partial failure, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_assignments: maxAssignmentsParam,
      max_mailboxes: maxMailboxesParam,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAzureConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAzureAuditBundle(new AzureAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "Azure audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Errors logged: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "azure_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Azure audit bundle export failed: ${describeThrown(error)}`,
          { tool: "azure_export_audit_bundle" },
        );
      }
    },
  });
}

/**
 * Every fixed-text message this integration emits around a refused, failed, or unparseable read, rendered
 * with representative observed values by the same constants and helpers the error sink uses (GWS note 1).
 * Each must survive redactErrorText unchanged, since every recorded string passes through it; the fixed-text
 * test holds this list to the scrub, and a message that does not survive is reworded rather than exempted.
 */
export function azureFixedTexts(): readonly string[] {
  const tokenUrl = "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token";
  const html = "<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>";
  const graphDeniedBody = JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation." } });
  const mailboxDeniedBody = JSON.stringify({ error: { code: "ErrorAccessDenied", message: "Access is denied. Check credentials and try again." } });
  const invalidClientBody = JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
  const graphDenied = { error: `403 Forbidden: ${describeErrorBody(graphDeniedBody, "application/json")}`, status: 403, url: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" };
  const mailboxDenied = { error: `403 Forbidden: ${describeErrorBody(mailboxDeniedBody, "application/json")}`, status: 403, url: "https://graph.microsoft.com/v1.0/users/user-2026@contoso.example/mailFolders/inbox/messageRules" };
  const mailboxMissing = { error: `404 Not Found: ${describeErrorBody(JSON.stringify({ error: { code: "ErrorItemNotFound", message: "The specified object was not found in the store." } }), "application/json")}`, status: 404 };
  const tokenDenied = { error: "Token request failed: 403 Forbidden", status: 403, url: tokenUrl };
  const tokenInvalid = { error: `Token request failed: 401 Unauthorized: ${describeErrorBody(invalidClientBody, "application/json")}`, status: 401, url: tokenUrl };
  // Rejections before any response, rendered the way send() wraps them: the token request and a Graph request.
  const dnsFailure = Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("getaddrinfo ENOTFOUND login.microsoftonline.com"), { code: "ENOTFOUND" }) });
  const timeout = Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
  const tokenNoResponse = { error: `Token request failed: ${describeNoResponse(dnsFailure)}`, url: tokenUrl };
  const graphNoResponse = { error: describeNoResponse(timeout), url: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" };
  const conditionalAccess = "GET /v1.0/identity/conditionalAccess/policies";
  const pricings = "GET /subscriptions/sub-123/providers/Microsoft.Security/pricings";
  const errors: string[] = [];
  const evidence = "the Conditional Access policy export from the Entra admin center";
  const findings = [
    manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", conditionalAccess, "Policy.Read.All", evidence, graphDenied, AZURE_ENDPOINT_DOCS.conditionalAccess, errors),
    manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", conditionalAccess, "Policy.Read.All", evidence, tokenInvalid, AZURE_ENDPOINT_DOCS.conditionalAccess, errors),
    manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", conditionalAccess, "Policy.Read.All", evidence, tokenNoResponse, AZURE_ENDPOINT_DOCS.conditionalAccess, errors),
    manualForError("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", conditionalAccess, "Policy.Read.All", evidence, graphNoResponse, AZURE_ENDPOINT_DOCS.conditionalAccess, errors),
    manualForError("AZURE-MON-05", 10, "Defender for Cloud plans", "high", pricings, "Security Reader", "the Defender for Cloud plan list", tokenDenied, AZURE_ENDPOINT_DOCS.defenderPricings, errors),
    manualForError("AZURE-MON-05", 10, "Defender for Cloud plans", "high", pricings, "Security Reader", "the Defender for Cloud plan list", tokenNoResponse, AZURE_ENDPOINT_DOCS.defenderPricings, errors),
    manualForError("AZURE-DP-06", 20, "Inbox forwarding rules", "high", MESSAGE_RULES_ENDPOINT, MAILBOX_RULES_PERMISSION, "the inbox rule export for every mailbox", mailboxDenied, AZURE_ENDPOINT_DOCS.messageRules, errors),
  ];
  const surfaceNames = ["organization", "conditional_access", "directory_roles", "secure_scores", "defender_pricings", "role_assignments", "diagnostic_settings", "security_contacts"];
  // Refused next links rendered for every origin shape the rule can meet: another host, port, or scheme, a
  // scheme without a host, an IP literal, userinfo on the configured host and on another, and a link that
  // does not parse. The link's path, query, fragment, and userinfo never reach the note. The first entry is
  // the foreign-host note and the sixth the userinfo note, reused by the partial and probe renderings below.
  const graphBase = "https://graph.microsoft.com";
  const refusalNotes = [
    nextLinkRefusalNote("foreign_origin", "https://evil.example/v1.0/identity/conditionalAccess/policies?$skiptoken=next-page", graphBase),
    nextLinkRefusalNote("foreign_origin", "https://graph.microsoft.com:8443/v1.0/identity/conditionalAccess/policies", graphBase),
    nextLinkRefusalNote("foreign_origin", "http://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", graphBase),
    nextLinkRefusalNote("foreign_origin", "javascript:alert(1)", graphBase),
    nextLinkRefusalNote("foreign_origin", "https://[::1]:8443/v1.0/identity/conditionalAccess/policies", graphBase),
    nextLinkRefusalNote("userinfo", "https://svc:placeholder@graph.microsoft.com/v1.0/identity/conditionalAccess/policies", graphBase),
    nextLinkRefusalNote("userinfo", "https://svc:placeholder@evil.example/v1.0/identity/conditionalAccess/policies", graphBase),
    nextLinkRefusalNote("unparseable", "https://[bad/v1.0/identity/conditionalAccess/policies", graphBase),
  ];
  return Object.freeze([
    PARSE_ERROR_NOTE,
    describeErrorBody(html, "text/html; charset=utf-8"),
    describeErrorBody("upstream unavailable", null),
    describeErrorBody("{}", "application/json"),
    graphDenied.error,
    mailboxDenied.error,
    mailboxMissing.error,
    tokenDenied.error,
    tokenInvalid.error,
    `Token request failed: 502 Bad Gateway: ${describeErrorBody(html, "text/html")}`,
    "Token response did not include access_token.",
    `Request returned 200 OK: ${describeErrorBody(html, "text/html")}`,
    `Token request returned 200 OK: ${describeErrorBody(html, "text/html")}`,
    "No graph token or client credentials are available.",
    describeFailure({ error: "", status: 401 }),
    describeFailure({ error: "", status: 403 }),
    describeFailure({ error: "", status: 402 }),
    tokenFailureText(tokenDenied, conditionalAccess).marker,
    tokenFailureText(tokenDenied, pricings).marker,
    failedReadNote(graphDenied, SECURITY_DEFAULTS_ENDPOINT),
    failedReadNote(tokenDenied, SECURITY_DEFAULTS_ENDPOINT),
    failedReadNote(tokenInvalid, SECURITY_DEFAULTS_ENDPOINT),
    ...findings.map((item) => item.summary),
    ...errors,
    `Security defaults could not be read (${SECURITY_DEFAULTS_ENDPOINT} returned ${describeFailure(graphDenied)}).`,
    `Security defaults could not be read (${failedReadNote(tokenDenied, SECURITY_DEFAULTS_ENDPOINT)}).`,
    `AZURE-DP-06 ${MESSAGE_RULES_ENDPOINT}: ${describeFailure(mailboxDenied)} on 3 of 12 mailboxes`,
    `3 denied with ${describeFailure(mailboxDenied)}, so ${MAILBOX_RULES_PERMISSION} is missing for those mailboxes and their rules were not inspected`,
    `2 returned a non-permission error (${describeFailure(mailboxMissing)}; commonly users without an Exchange mailbox)`,
    "not attempted: this client does not expose listNetworkWatchers, so no request was made.",
    partialNote({ items: [], seen: 100, total: undefined, truncated: true }, "Conditional Access policies").trim(),
    partialNote({ items: [], seen: 25, total: 40, truncated: true }, "role assignments").trim(),
    ...refusalNotes,
    REQUEST_REFUSED_NOTE,
    partialNote({ items: [], seen: 5, total: undefined, truncated: true, truncation: refusalNotes[0] }, "Conditional Access policies").trim(),
    ...truncatedProbeNotes([
      { name: "conditional_access", service: "graph", status: "readable", count: 5, truncated: true, truncation: refusalNotes[0] },
      { name: "role_assignments", service: "arm", status: "readable", count: 1, truncated: true, truncation: refusalNotes[5] },
    ]),
    "Member inventory is partial; verdict capped at warn.",
    "6/8 Azure audit surfaces are readable.",
    `${tokenRequestLabel(tokenDenied)} returned ${describeTokenFailure(tokenDenied)}; no resource request was made for ${surfaceNames.join(", ")}.`,
    `${requestOutcomeClause(tokenRequestLabel(tokenNoResponse), tokenNoResponse)}; no resource request was made for ${surfaceNames.join(", ")}.`,
    tokenNoResponse.error,
    graphNoResponse.error,
    failedReadNote(tokenNoResponse, SECURITY_DEFAULTS_ENDPOINT),
    `Security defaults could not be read (${requestOutcomeClause(SECURITY_DEFAULTS_ENDPOINT, graphNoResponse)}).`,
    "Probe counts for role_assignments stopped at the probe page cap and are lower bounds, not inventory sizes.",
    "Fix the app registration's client credentials (tenant id, client id, client secret) so the token request succeeds, then re-run the access check.",
    `${tokenFailureRemedy(tokenNoResponse)}, then re-run the access check.`,
    "Grant Microsoft Graph read permissions and Azure Reader/Security Reader roles for the audit principal.",
  ]);
}
