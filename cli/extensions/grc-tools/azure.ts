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

/**
 * Cloud endpoint sets. Public and US Government hosts:
 * https://learn.microsoft.com/en-us/graph/deployments
 * https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure
 * https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud
 */
export interface AzureCloudEndpoints {
  name: "public" | "usgovernment" | "usgovernment-dod" | "china";
  authorityHost: string;
  graphBaseUrl: string;
  managementBaseUrl: string;
}

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
    graphBaseUrl: "https://microsoftgraph.chinacloudapi.cn",
    managementBaseUrl: "https://management.chinacloudapi.cn",
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
  sensitivityLabels: "https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-1.0",
  sensitivityLabelResource: "https://learn.microsoft.com/en-us/graph/api/resources/security-sensitivitylabel?view=graph-rest-1.0",
  informationProtectionResource: "https://learn.microsoft.com/en-us/graph/api/resources/security-informationprotection?view=graph-rest-1.0",
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
  roleAssignments: "https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription",
  roleDefinitions: "https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list",
  networkWatchers: "https://learn.microsoft.com/en-us/rest/api/network-watcher/network-watchers/list-all",
  networkSecurityGroups: "https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all",
  keyVaults: "https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription",
  storageAccounts: "https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list",
  policyAssignments: "https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-assignments/list",
  policyStatesSummarize: "https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/summarize-for-subscription",
  builtInPolicies: "https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies",
} as const;

/** ARM api-versions, each taken from the request sample on the cited page. */
export const AZURE_ARM_API_VERSIONS = {
  subscription: "2022-12-01",
  defenderPricings: "2024-01-01",
  diagnosticSettings: "2021-05-01-preview",
  securityContacts: "2023-12-01-preview",
  roleAssignments: "2022-04-01",
  roleDefinitions: "2022-04-01",
  networkWatchers: "2025-09-01",
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
  count?: number;
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
    return {
      items,
      truncated: record.truncated === true,
      seen: asNumber(record.seen) ?? items.length,
      total: asNumber(record.total),
    };
  }
  return { items: [], truncated: false, seen: 0 };
}

export class AzureApiError extends Error {
  constructor(
    message: string,
    readonly url: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "AzureApiError";
  }
}

type Attempt<T> = { ok: true; value: T } | { ok: false; error: string; status?: number };

async function attempt<T>(load: () => Promise<T>): Promise<Attempt<T>> {
  try {
    return { ok: true, value: await load() };
  } catch (error) {
    const status = error instanceof AzureApiError ? error.status : undefined;
    return { ok: false, error: error instanceof Error ? error.message : String(error), status };
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

function manualForError(
  id: string,
  control: number,
  title: string,
  severity: AzureFinding["severity"],
  endpoint: string,
  requirement: string,
  evidenceToCollect: string,
  result: { error: string; status?: number },
  docUrl: string,
  errors: string[],
): AzureFinding {
  const detail = describeFailure(result);
  errors.push(`${id} ${endpoint}: ${detail}`);
  return finding(
    id,
    control,
    title,
    severity,
    "manual",
    `${endpoint} returned ${detail}. Grant ${requirement}, or collect ${evidenceToCollect} manually.`,
    { endpoint, http_status: result.status ?? null, error: result.error.slice(0, 300), required_access: requirement, evidence_to_collect: evidenceToCollect, documentation: docUrl },
  );
}

function partialNote(page: AzurePage, label: string): string {
  if (!page.truncated) return "";
  const total = page.total !== undefined ? String(page.total) : "unknown";
  return ` Inventory of ${label} is partial (${page.seen} seen of ${total} total); verdict capped at warn.`;
}

function capForPartial(status: AzureFindingStatus, ...pages: AzurePage[]): AzureFindingStatus {
  if (status === "pass" && pages.some((page) => page.truncated)) return "warn";
  return status;
}

function pageEvidence(page: AzurePage): JsonRecord {
  return { seen: page.seen, total: page.total ?? null, truncated: page.truncated };
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

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<AzureAccessSurface> {
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
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function pageCount(value: unknown): number | undefined {
  if (Array.isArray(value)) return value.length;
  const page = asObject(value);
  return page && Array.isArray(page.items) ? page.items.length : undefined;
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
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      throw new AzureApiError(`Token request failed: ${response.status} ${response.statusText}${text ? `: ${text.slice(0, 160)}` : ""}`, url, response.status);
    }
    const payload = asObject(JSON.parse(text)) ?? {};
    const token = asString(payload.access_token);
    if (!token) throw new AzureApiError("Token response did not include access_token.", url);
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.tokenCache.set(resource, { token, expiresAt: this.now().getTime() + expiresIn * 1000 });
    return token;
  }

  private async requestJson(url: string, resource: "graph" | "management", init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<JsonRecord> {
    const token = await this.getToken(resource);
    const response = await this.fetchImpl(url, {
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
      throw new AzureApiError(`${response.status} ${response.statusText}${text ? `: ${text.slice(0, 160)}` : ""}`, url, response.status);
    }
    const text = await response.text();
    return text.trim().length > 0 ? (JSON.parse(text) as JsonRecord) : {};
  }

  /** Graph paging via @odata.nextLink, https://learn.microsoft.com/en-us/graph/paging */
  private async collectGraph(path: string, limit = 5000, headers: Record<string, string> = {}): Promise<AzurePage> {
    const items: JsonRecord[] = [];
    let total: number | undefined;
    let nextUrl: string | undefined = path.startsWith("http") ? path : `${this.cloud.graphBaseUrl}${path}`;
    while (nextUrl) {
      const response = await this.requestJson(nextUrl, "graph", { headers });
      total ??= asNumber(response["@odata.count"]);
      items.push(...asRecords(response.value));
      nextUrl = asString(response["@odata.nextLink"]);
      if (nextUrl && items.length >= limit) {
        return { items: items.slice(0, limit), truncated: true, seen: Math.min(items.length, limit), total };
      }
    }
    return { items, truncated: false, seen: items.length, total: total ?? items.length };
  }

  /** ARM paging via nextLink, https://learn.microsoft.com/en-us/rest/api/azure/ */
  private async collectArm(path: string, limit = 5000): Promise<AzurePage> {
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = path.startsWith("http") ? path : `${this.cloud.managementBaseUrl}${path}`;
    while (nextUrl) {
      const response = await this.requestJson(nextUrl, "management");
      items.push(...asRecords(response.value));
      nextUrl = asString(response.nextLink);
      if (nextUrl && items.length >= limit) {
        return { items: items.slice(0, limit), truncated: true, seen: Math.min(items.length, limit), total: undefined };
      }
    }
    return { items, truncated: false, seen: items.length, total: items.length };
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
    return this.collectGraph("/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId,passwordCredentials,keyCredentials");
  }

  async listApplications(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/applications?$top=999&$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$expand=owners($select=id)");
  }

  async listOAuth2PermissionGrants(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/oauth2PermissionGrants");
  }

  async listGuestUsers(): Promise<AzurePage> {
    return this.collectGraph(
      "/v1.0/users?$filter=userType eq 'Guest'&$count=true&$top=999&$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState,signInActivity",
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

  async listSensitivityLabels(): Promise<AzurePage> {
    return this.collectGraph("/v1.0/security/informationProtection/sensitivityLabels");
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

type NetworkPolicyClient = Pick<AzureAuditorClient, "listNetworkSecurityGroups" | "listPolicyAssignments" | "summarizePolicyStates">;

function optionalCall<T>(method: (() => Promise<T>) | undefined, missing: string): () => Promise<T> {
  return method ?? (async () => {
    throw new Error(`${missing} is not available on this client.`);
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
    surface("organization", "graph", () => client.getOrganization(), () => 1),
    surface("conditional_access", "graph", () => client.listConditionalAccessPolicies(), pageCount),
    surface("directory_roles", "graph", () => client.listDirectoryRoles(), pageCount),
    surface("secure_scores", "graph", () => client.listSecureScores(), pageCount),
    surface("defender_pricings", "arm", () => client.listDefenderPricings(), pageCount),
    surface("role_assignments", "arm", () => client.listRoleAssignments(25), pageCount),
    surface("diagnostic_settings", "arm", () => client.listDiagnosticSettings(), pageCount),
    surface("security_contacts", "arm", () => client.listSecurityContacts(), pageCount),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 6 ? "healthy" : "limited";
  const notes = [
    `Authenticated against ${describeSourceChain(config)}.`,
    `${readableCount}/${surfaces.length} Azure audit surfaces are readable.`,
  ];

  return {
    status,
    tenantId: config.tenantId,
    subscriptionId: config.subscriptionId,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run azure_assess_identity, azure_assess_monitoring, azure_assess_subscription_guardrails, or azure_export_audit_bundle."
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
    const baseline = mfaPolicies.length > 0 || securityDefaultsEnabled;
    findings.push(finding("AZURE-ID-01", 1, "Conditional Access MFA baseline", "high",
      baseline ? capForPartial("pass", policies.value) : "fail",
      baseline
        ? `Strong authentication baseline is present via ${mfaPolicies.length} enabled MFA Conditional Access policies${securityDefaultsEnabled ? " and security defaults" : ""}.${reportOnly.length > 0 ? ` ${reportOnly.length} policies are report-only and were not counted.` : ""}${partialNote(policies.value, "Conditional Access policies")}`
        : policies.value.items.length === 0
          ? "Zero Conditional Access policies were returned and security defaults are off; empty inventory fails this control by intent."
          : `No enabled MFA Conditional Access policy or security defaults baseline was found (${reportOnly.length} report-only policies do not enforce).`,
      { total_policies: policies.value.items.length, enabled_policies: enabled.length, report_only_policies: reportOnly.length, mfa_policies: mfaPolicies.length, security_defaults_enabled: securityDefaultsEnabled, security_defaults_readable: securityDefaults.ok, ...pageEvidence(policies.value) }));
    const legacyBlocked = legacyAuthPolicies.length > 0 || securityDefaultsEnabled;
    findings.push(finding("AZURE-ID-02", 4, "Legacy authentication blocking", "high",
      legacyBlocked ? capForPartial("pass", policies.value) : "fail",
      legacyBlocked
        ? `Legacy authentication is blocked via ${legacyAuthPolicies.length} enabled Conditional Access block policies targeting exchangeActiveSync/other clients${securityDefaultsEnabled ? " and security defaults" : ""}.${partialNote(policies.value, "Conditional Access policies")}`
        : "No enabled Conditional Access policy blocks exchangeActiveSync/other client app types and security defaults are off.",
      { legacy_auth_block_policies: legacyAuthPolicies.length, security_defaults_enabled: securityDefaultsEnabled, ...pageEvidence(policies.value) }));
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
    findings.push(finding("AZURE-ID-13", 22, "Tenant-wide delegated permission grants", "high", risky.length > 0 ? "fail" : capForPartial("pass", grants.value),
      risky.length > 0
        ? `${risky.length} AllPrincipals grants include high-privilege delegated scopes.`
        : `No AllPrincipals grant carries a high-privilege delegated scope across ${grants.value.items.length} grants; zero risky grants is compliant by intent.${partialNote(grants.value, "permission grants")}`,
      { grants: grants.value.items.length, risky_grants: risky.slice(0, 25).map((grant) => ({ clientId: grant.clientId, scope: grant.scope })), ...pageEvidence(grants.value) }));
  }

  return {
    title: "Azure identity posture",
    summary: {
      enabled_conditional_access_policies: enabled.length,
      report_only_conditional_access_policies: reportOnly.length,
      mfa_conditional_access_policies: mfaPolicies.length,
      legacy_auth_block_policies: legacyAuthPolicies.length,
      users_in_registration_report: registrations.ok ? registrations.value.items.length : null,
      global_administrators: globalAdmins,
      privileged_role_assignments: privilegedAssignments,
      guests: guests.ok ? guests.value.items.length : null,
      risky_users: riskyUsers.ok ? riskyUsers.value.items.length : null,
      app_registrations: applications.ok ? applications.value.items.length : null,
      security_defaults_enabled: securityDefaultsEnabled,
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
  if (!defenderPricings.ok) {
    findings.push(manualForError("AZURE-MON-04", 16, "Defender for Cloud plan coverage", "high", "GET Microsoft.Security/pricings", "Security Reader on the subscription", "the Defender for Cloud environment settings page", defenderPricings, AZURE_ENDPOINT_DOCS.defenderPricings, errors));
  } else {
    findings.push(finding("AZURE-MON-04", 16, "Defender for Cloud plan coverage", "high",
      totalPlans === 0 ? "manual" : standardPlans.length === totalPlans ? "pass" : standardPlans.length > 0 ? "warn" : "fail",
      totalPlans > 0
        ? `${standardPlans.length}/${totalPlans} Defender for Cloud plans are on the Standard pricingTier.`
        : "Zero Defender pricing records were returned; the API always lists every plan, so confirm access manually.",
      { standard_plans: standardPlans.length, total_plans: totalPlans, alerts_visible: alerts.ok ? alerts.value.seen : null, alerts_error: alerts.ok ? null : describeFailure(alerts) }));
  }

  const effectiveSettings = diagnosticSettings.ok ? diagnosticSettings.value.items.filter((setting) => diagnosticSettingHasEnabledLog(setting) && diagnosticSettingDestination(setting)) : [];
  if (!diagnosticSettings.ok) {
    findings.push(manualForError("AZURE-MON-05", 15, "Subscription diagnostic settings", "high", "GET Microsoft.Insights/diagnosticSettings", "Reader (Monitoring Reader) on the subscription", "the Activity log diagnostic settings page", diagnosticSettings, AZURE_ENDPOINT_DOCS.diagnosticSettings, errors));
  } else {
    findings.push(finding("AZURE-MON-05", 15, "Subscription diagnostic settings", "high", effectiveSettings.length > 0 ? "pass" : "fail",
      effectiveSettings.length > 0
        ? `${effectiveSettings.length}/${diagnosticSettings.value.items.length} subscription diagnostic settings have enabled log categories and a destination.`
        : diagnosticSettings.value.items.length === 0
          ? "Zero subscription diagnostic settings exist; Activity Log is not exported (empty inventory fails by intent)."
          : `${diagnosticSettings.value.items.length} diagnostic settings exist but none has an enabled log category with a destination.`,
      { diagnostic_settings: diagnosticSettings.value.items.length, effective_settings: effectiveSettings.length }));
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
      secure_score_ratio: round(secureScoreRatio, 2),
      directory_audits: audits.ok ? audits.value.seen : null,
      sign_ins: signIns.ok ? signIns.value.seen : null,
      defender_standard_plans: standardPlans.length,
      defender_total_plans: totalPlans,
      security_alerts: alerts.ok ? alerts.value.seen : null,
      effective_diagnostic_settings: effectiveSettings.length,
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
        ? `${networkWatchers.value.items.length} Network Watcher resources exist across the subscription; NSG flow log status is not read and stays a manual check.${partialNote(networkWatchers.value, "network watchers")}`
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
      owner_assignments: ownerAssignments.length,
      contributor_assignments: contributorAssignments.length,
      inspected_assignments: roleAssignments.ok ? roleAssignments.value.seen : null,
      network_watchers: networkWatchers.ok ? networkWatchers.value.items.length : null,
      privileged_service_principals: privilegedServicePrincipals.length,
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
    "Microsoft Graph v1.0 exposes no DLP policy resource (the security informationProtection resource lists only sensitivityLabels and labelPolicySettings). Collect Get-DlpCompliancePolicy and Get-DlpComplianceRule output from Security & Compliance PowerShell as evidence.",
    { graph_reference: AZURE_ENDPOINT_DOCS.informationProtectionResource, evidence_command: "Get-DlpCompliancePolicy | Format-List Name,Mode,Enabled,ExchangeLocation,SharePointLocation,OneDriveLocation", documentation: AZURE_ENDPOINT_DOCS.dlpPowerShell }));

  if (!labels.ok) {
    findings.push(manualForError("AZURE-DP-03", 11, "Sensitivity labels published", "medium", "GET /v1.0/security/informationProtection/sensitivityLabels", "InformationProtectionPolicy.Read.All with a Purview Information Protection license", "the sensitivity label policy export from the Purview portal", labels, AZURE_ENDPOINT_DOCS.sensitivityLabels, errors));
  } else {
    const active = labels.value.items.filter((label) => label.isActive === true);
    findings.push(finding("AZURE-DP-03", 11, "Sensitivity labels published", "medium", active.length > 0 ? capForPartial("pass", labels.value) : "fail",
      active.length > 0
        ? `${active.length}/${labels.value.items.length} sensitivity labels are active (${labels.value.items.filter((label) => label.hasProtection === true).length} apply protection). Label application to content is not exposed and stays a manual check.${partialNote(labels.value, "labels")}`
        : labels.value.items.length === 0
          ? "Zero sensitivity labels are published (empty inventory fails by intent)."
          : `${labels.value.items.length} labels exist but none is active.`,
      { labels: labels.value.items.length, active_labels: active.length, ...pageEvidence(labels.value) }));
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
    let mailboxesUnreadable = 0;
    let permissionFailure: { error: string; status?: number } | undefined;
    for (const user of members.value.items) {
      const userId = asString(user.id);
      if (!userId) continue;
      const rules = await attemptPage(() => client.listInboxMessageRules(userId));
      if (!rules.ok) {
        mailboxesUnreadable += 1;
        if (rules.status === 401 || rules.status === 403) permissionFailure = rules;
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
    if (permissionFailure && mailboxesRead === 0) {
      findings.push(manualForError("AZURE-DP-06", 20, "Inbox forwarding rules", "high", "GET /v1.0/users/{id}/mailFolders/inbox/messageRules", "MailboxSettings.Read (application)", "the inbox rule export for every mailbox", permissionFailure, AZURE_ENDPOINT_DOCS.messageRules, errors));
    } else {
      const partial = members.value.truncated || mailboxesUnreadable > 0;
      const status: AzureFindingStatus = members.value.items.length === 0
        ? "manual"
        : forwardingRules.length > 0 ? "fail" : partial ? "warn" : "pass";
      findings.push(finding("AZURE-DP-06", 20, "Inbox forwarding rules", "high", status,
        members.value.items.length === 0
          ? "Zero enabled member users were returned; confirm User.Read.All before treating mailboxes as clean."
          : `${forwardingRules.length} enabled inbox rules forward or redirect mail across ${mailboxesRead} readable mailboxes (${mailboxesUnreadable} unreadable, likely without an Exchange mailbox).${partialNote(members.value, "member users")}`,
        { mailboxes_read: mailboxesRead, mailboxes_unreadable: mailboxesUnreadable, forwarding_rules: forwardingRules.slice(0, 25), ...pageEvidence(members.value) }));
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

export async function assessAzureNetworkAndPolicy(client: NetworkPolicyClient): Promise<AzureAssessmentResult> {
  const errors: string[] = [];
  const [nsgs, assignments, summary] = await Promise.all([
    attemptPage(() => client.listNetworkSecurityGroups()),
    attemptPage(() => client.listPolicyAssignments()),
    attempt(() => client.summarizePolicyStates()),
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

  if (!assignments.ok) {
    findings.push(manualForError("AZURE-NP-02", 25, "Azure Policy assignments enforced", "medium", "GET Microsoft.Authorization/policyAssignments", "Reader on the subscription", "the Azure Policy assignments export", assignments, AZURE_ENDPOINT_DOCS.policyAssignments, errors));
  } else {
    const enforced = assignments.value.items.filter((item) => asLower(asObject(item.properties)?.enforcementMode) !== "donotenforce");
    const mandatoryPresent = MANDATORY_POLICY_DEFINITIONS.filter((definition) => assignments.value.items.some((item) => (asLower(asObject(item.properties)?.policyDefinitionId) ?? "").endsWith(definition.id)));
    findings.push(finding("AZURE-NP-02", 25, "Azure Policy assignments enforced", "medium",
      assignments.value.items.length === 0 ? "fail" : enforced.length === 0 ? "fail" : enforced.length < assignments.value.items.length ? "warn" : capForPartial("pass", assignments.value),
      assignments.value.items.length === 0
        ? "Zero Azure Policy assignments apply at subscription scope (empty inventory fails by intent)."
        : `${enforced.length}/${assignments.value.items.length} policy assignments use enforcementMode Default; mandatory built-ins present: ${mandatoryPresent.map((item) => item.name).join(", ") || "none"}.${partialNote(assignments.value, "policy assignments")}`,
      { assignments: assignments.value.items.length, enforced: enforced.length, do_not_enforce: assignments.value.items.length - enforced.length, mandatory_present: mandatoryPresent.map((item) => item.name), mandatory_missing: MANDATORY_POLICY_DEFINITIONS.filter((item) => !mandatoryPresent.includes(item)).map((item) => item.name), ...pageEvidence(assignments.value) }));
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
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
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
    "- `_errors.log`: present only when an API call failed and a finding was rendered manual",
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
    "- `_errors.log`: API failures that produced manual findings (only on partial failure)",
    "",
    "Resolved access tokens and client secrets are never written to this bundle.",
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
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors);
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

function normalizeGuardrailArgs(args: unknown): SubscriptionArgs & DataProtectionArgs {
  return { ...normalizeSubscriptionArgs(args), ...normalizeDataProtectionArgs(args) };
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
  authority_host: Type.Optional(Type.String({ description: "Authority host: login.microsoftonline.com (default), login.microsoftonline.us (US Government), or login.chinacloudapi.cn. Defaults to AZURE_AUTHORITY_HOST." })),
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
          `Azure access check failed: ${error instanceof Error ? error.message : String(error)}`,
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
          `Azure identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
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
          `Azure monitoring assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_subscription_guardrails",
    label: "Assess Azure subscription and tenant guardrails",
    description:
      "Assess Azure subscription guardrails (RBAC sprawl, security contacts, Network Watcher, privileged service principals), network and policy posture (NSG admin-port exposure, Azure Policy enforcement and compliance), and data and endpoint protection (Intune compliance, DLP and sensitivity labels, Key Vault, storage, inbox forwarding, SharePoint sharing).",
    parameters: Type.Object({ ...authParams, max_assignments: maxAssignmentsParam, max_mailboxes: maxMailboxesParam }),
    prepareArguments: normalizeGuardrailArgs,
    async execute(_toolCallId: string, args: SubscriptionArgs & DataProtectionArgs) {
      try {
        const client = createClient(args);
        const result = mergeAssessments("Azure subscription and tenant guardrails", [
          await assessAzureSubscriptionGuardrails(client, { maxAssignments: args.max_assignments }),
          await assessAzureNetworkAndPolicy(client),
          await assessAzureDataProtection(client, { maxMailboxes: args.max_mailboxes }),
        ]);
        return textResult(formatAssessmentText(result), { tool: "azure_assess_subscription_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `Azure subscription guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_assess_subscription_guardrails" },
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
          `Azure audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_export_audit_bundle" },
        );
      }
    },
  });
}
