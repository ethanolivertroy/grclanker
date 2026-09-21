import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  readdirSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AZURE_ARM_API_VERSIONS,
  AzureApiError,
  AzureAuditorClient,
  assessAzureDataProtection,
  assessAzureIdentity,
  assessAzureMonitoring,
  assessAzureNetworkAndPolicy,
  assessAzureSubscriptionGuardrails,
  checkAzureAccess,
  describeErrorBody,
  exportAzureAuditBundle,
  isExposedAdminRule,
  parseNetworkWatcherId,
  projectCredentialCarrier,
  resolveAzureCloud,
  resolveAzureConfiguration,
  redactErrorText,
  resolveSecureOutputPath,
  toPage,
} from "../dist/extensions/grc-tools/azure.js";
import {
  CANARY_URL,
  HTML_BODY_NOTE,
  REDACTED_CANARY_URL,
  assertNoCanaries,
  assertNoCanariesInFiles,
  assertRedactionCases,
  htmlCanaryBody,
  jsonCanaryMessage,
} from "./helpers/error-canaries.mjs";
import { getRegisteredToolSummaries, groupRegisteredTools } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW = new Date("2026-04-16T00:00:00.000Z");
const ASSESSORS = [
  ["identity", (client) => assessAzureIdentity(client)],
  ["monitoring", (client) => assessAzureMonitoring(client)],
  ["subscription_guardrails", (client) => assessAzureSubscriptionGuardrails(client)],
  ["data_protection", (client) => assessAzureDataProtection(client)],
  ["network_and_policy", (client) => assessAzureNetworkAndPolicy(client)],
];
const CLIENT_METHODS = [
  "listConditionalAccessPolicies", "listUserRegistrationDetails", "listDirectoryRoles", "listDirectoryRoleMembers", "getSecurityDefaultsPolicy",
  "listServicePrincipals", "getAuthorizationPolicy", "listGuestUsers", "listSubscribedSkus", "listRiskyUsers", "listRiskDetections",
  "listRoleEligibilitySchedules", "listRoleAssignmentSchedules", "listApplications", "listOAuth2PermissionGrants", "listSecureScores",
  "listSecurityAlerts", "listDirectoryAudits", "listSignIns", "listDefenderPricings", "listDiagnosticSettings", "listLogAnalyticsWorkspaces",
  "listRoleAssignments", "listRoleDefinitions", "listSecurityContacts", "listNetworkWatchers", "listFlowLogs", "listDeviceCompliancePolicies", "listManagedDevices",
  "listSensitivityLabels", "listKeyVaults", "listStorageAccounts", "listMemberUsers", "listInboxMessageRules", "getSharePointSettings",
  "listNetworkSecurityGroups", "listPolicyAssignments", "summarizePolicyStates", "getOrganization", "getSubscription",
];
const NSG_ID = "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1";
const WATCHER_ID = "/subscriptions/sub-123/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus";
const ENABLED_FLOW_LOG = {
  name: "nsg-1-flowlog",
  type: "Microsoft.Network/networkWatchers/FlowLogs",
  properties: {
    enabled: true,
    targetResourceId: NSG_ID,
    storageId: "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1",
    retentionPolicy: { days: 90, enabled: true },
    provisioningState: "Succeeded",
  },
};

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    tenantId: "tenant-123",
    subscriptionId: "sub-123",
    graphToken: "graph-token",
    managementToken: "arm-token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

/** A real AzureApiError so attempt() sees status 403 the way requestJson produces it. */
function forbidden() {
  return new azureModule.AzureApiError("403 Forbidden: Insufficient privileges", "https://graph.microsoft.com/v1.0/denied", 403);
}

function clientWith(overrides = {}, base = {}) {
  const client = { getResolvedConfig: () => sampleConfig(), getNow: () => NOW };
  for (const method of CLIENT_METHODS) {
    client[method] = base[method] ?? (async () => []);
  }
  return Object.assign(client, overrides);
}

function forbiddenClient() {
  const client = { getResolvedConfig: () => sampleConfig(), getNow: () => NOW };
  for (const method of CLIENT_METHODS) {
    client[method] = async () => {
      const { AzureApiError } = azureModule;
      throw new AzureApiError("403 Forbidden: Insufficient privileges", `https://graph.microsoft.com/${method}`, 403);
    };
  }
  return client;
}

const azureModule = await import("../dist/extensions/grc-tools/azure.js");

const CA_MFA = { id: "ca-mfa", displayName: "Require MFA", state: "enabled", grantControls: { builtInControls: ["mfa"] }, conditions: { clientAppTypes: ["all"] } };
const CA_LEGACY = { id: "ca-legacy", displayName: "Block legacy", state: "enabled", grantControls: { builtInControls: ["block"] }, conditions: { clientAppTypes: ["exchangeActiveSync", "other"] } };
const CA_SIGNIN_RISK = { id: "ca-signin", displayName: "Sign-in risk MFA", state: "enabled", grantControls: { builtInControls: ["mfa"] }, conditions: { signInRiskLevels: ["medium", "high"] } };
const CA_USER_RISK = { id: "ca-user", displayName: "User risk password change", state: "enabled", grantControls: { builtInControls: ["passwordChange"] }, conditions: { userRiskLevels: ["high"] } };
const CA_COMPLIANT_DEVICE = { id: "ca-device", displayName: "Require compliant device", state: "enabled", grantControls: { builtInControls: ["compliantDevice"] }, conditions: {} };
const P2_SKUS = [{ skuPartNumber: "EMSPREMIUM", servicePlans: [{ servicePlanName: "AAD_PREMIUM_P2", provisioningStatus: "Success" }, { servicePlanName: "INTUNE_A", provisioningStatus: "Success" }] }];

function compliantClient() {
  return clientWith({
    async getOrganization() { return { id: "org-1" }; },
    async listConditionalAccessPolicies() { return [CA_MFA, CA_LEGACY, CA_SIGNIN_RISK, CA_USER_RISK, CA_COMPLIANT_DEVICE]; },
    async listUserRegistrationDetails() { return [{ userPrincipalName: "alice@example.com", isMfaRegistered: true }]; },
    async listDirectoryRoles() { return [{ id: "ga", displayName: "Global Administrator", roleTemplateId: "62e90394-69f5-4237-9190-012177145e10" }]; },
    async listDirectoryRoleMembers() { return [{ id: "user-1" }, { id: "user-2" }]; },
    async getSecurityDefaultsPolicy() { return { isEnabled: false }; },
    async listServicePrincipals() { return [{ displayName: "App", passwordCredentials: [{ startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" }], keyCredentials: [] }]; },
    async getAuthorizationPolicy() { return { guestUserRoleId: "2af84b1e-32c8-42b7-82bc-daa82404023b", allowInvitesFrom: "adminsAndGuestInviters" }; },
    async listGuestUsers() { return [{ id: "g1", userPrincipalName: "guest#EXT#@example.com", userType: "Guest", accountEnabled: true, signInActivity: { lastSignInDateTime: "2026-04-01T00:00:00Z" } }]; },
    async listSubscribedSkus() { return P2_SKUS; },
    async listRiskyUsers() { return []; },
    async listRiskDetections() { return [{ id: "rd-1", riskLevel: "low", riskState: "remediated" }]; },
    async listRoleEligibilitySchedules() { return [{ id: "elig-1", roleDefinitionId: "62e90394-69f5-4237-9190-012177145e10", principalId: "user-1" }]; },
    async listRoleAssignmentSchedules() { return [{ id: "as-1", assignmentType: "Assigned", roleDefinitionId: "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", principalId: "user-9", scheduleInfo: { expiration: { type: "noExpiration" } } }]; },
    async listApplications() { return [{ id: "app-1", displayName: "Automation", createdDateTime: "2025-01-01T00:00:00Z", signInAudience: "AzureADMyOrg", owners: [{ id: "user-1" }], passwordCredentials: [{ startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" }], keyCredentials: [] }]; },
    async listOAuth2PermissionGrants() { return [{ id: "grant-1", clientId: "sp-1", consentType: "AllPrincipals", scope: "User.Read openid profile" }]; },
    async listSecureScores() { return [{ currentScore: 70, maxScore: 80 }]; },
    async listSecurityAlerts() { return []; },
    async listDirectoryAudits() { return [{ id: "audit-1" }]; },
    async listSignIns() { return [{ id: "signin-1" }]; },
    async listDefenderPricings() { return [{ name: "VirtualMachines", properties: { pricingTier: "Standard" } }]; },
    async listDiagnosticSettings() { return [{ id: "diag-1", properties: { workspaceId: "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law", logs: [{ category: "Administrative", enabled: true }] } }]; },
    async listLogAnalyticsWorkspaces() { return [{ id: "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law", properties: { retentionInDays: 365 } }]; },
    async listRoleAssignments() { return [{ properties: { roleDefinitionId: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/reader-role", principalType: "User" } }]; },
    async listRoleDefinitions() { return [{ id: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/reader-role", properties: { roleName: "Reader" } }]; },
    async listSecurityContacts() { return [{ properties: { emails: "soc@example.com" } }]; },
    async listNetworkWatchers() { return [{ id: WATCHER_ID, name: "NetworkWatcher_eastus", location: "eastus" }]; },
    async listFlowLogs() { return [ENABLED_FLOW_LOG]; },
    async listDeviceCompliancePolicies() { return [{ id: "cp-1", displayName: "Windows baseline" }]; },
    async listManagedDevices() { return [{ id: "dev-1", complianceState: "compliant" }]; },
    async listSensitivityLabels() { return [{ id: "label-1", name: "Confidential", isActive: true, hasProtection: true }]; },
    async listKeyVaults() { return [{ name: "kv1", properties: { enableSoftDelete: true, enablePurgeProtection: true, enableRbacAuthorization: true, publicNetworkAccess: "Disabled", networkAcls: { defaultAction: "Deny" } } }]; },
    async listStorageAccounts() { return [{ name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: false, minimumTlsVersion: "TLS1_2", encryption: { keySource: "Microsoft.Keyvault" } } }]; },
    async listMemberUsers() { return [{ id: "user-1", userPrincipalName: "alice@example.com" }]; },
    async listInboxMessageRules() { return [{ id: "rule-1", displayName: "Archive", isEnabled: true, actions: { moveToFolder: "archive" } }]; },
    async getSharePointSettings() { return { sharingCapability: "existingExternalUserSharingOnly", sharingDomainRestrictionMode: "allowList", isResharingByExternalUsersEnabled: false }; },
    async listNetworkSecurityGroups() { return [{ id: NSG_ID, name: "nsg-1", properties: { securityRules: [{ name: "allow-https", properties: { access: "Allow", direction: "Inbound", protocol: "Tcp", sourceAddressPrefix: "Internet", destinationPortRange: "443" } }] } }]; },
    async listPolicyAssignments() { return [{ name: "locations", properties: { enforcementMode: "Default", policyDefinitionId: "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c" } }]; },
    async summarizePolicyStates() { return { value: [{ results: { nonCompliantResources: 0, nonCompliantPolicies: 0 } }] }; },
  });
}

function statusesById(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

const ALWAYS_MANUAL = new Set(["AZURE-MON-07", "AZURE-DP-02", "AZURE-DP-07"]);

test("resolveAzureConfiguration prefers explicit args over environment defaults", () => {
  const resolved = resolveAzureConfiguration(
    { tenant_id: "tenant-arg", subscription_id: "sub-arg", graph_token: "graph-arg", management_token: "arm-arg" },
    { AZURE_TENANT_ID: "tenant-env", AZURE_SUBSCRIPTION_ID: "sub-env", AZURE_GRAPH_TOKEN: "graph-env", AZURE_MANAGEMENT_TOKEN: "arm-env" },
    () => undefined,
  );

  assert.equal(resolved.tenantId, "tenant-arg");
  assert.equal(resolved.subscriptionId, "sub-arg");
  assert.equal(resolved.graphToken, "graph-arg");
  assert.equal(resolved.managementToken, "arm-arg");
  assert.equal(resolved.cloud.name, "public");
  assert.ok(resolved.sourceChain.includes("arguments-tenant"));
  assert.ok(resolved.sourceChain.includes("arguments-subscription"));
});

test("resolveAzureConfiguration accepts client credentials without az CLI and maps sovereign clouds", () => {
  let cliCalls = 0;
  const resolved = resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-env", AZURE_SUBSCRIPTION_ID: "sub-env", AZURE_CLIENT_ID: "client-env", AZURE_CLIENT_SECRET: "secret-env", AZURE_AUTHORITY_HOST: "login.microsoftonline.us" },
    () => { cliCalls += 1; return undefined; },
  );
  assert.equal(cliCalls, 0);
  assert.equal(resolved.clientCredentials.clientId, "client-env");
  assert.ok(resolved.sourceChain.includes("client-credentials"));
  assert.equal(resolved.cloud.graphBaseUrl, "https://graph.microsoft.us");
  assert.equal(resolved.cloud.managementBaseUrl, "https://management.usgovcloudapi.net");
  assert.equal(resolveAzureCloud("https://login.chinacloudapi.cn/").managementBaseUrl, "https://management.chinacloudapi.cn");
  assert.throws(() => resolveAzureCloud("login.example.invalid"), /Unsupported AZURE_AUTHORITY_HOST/);
});

test("resolveAzureCloud accepts both documented China authority hosts", async () => {
  // login.chinacloudapi.cn comes from the Graph deployments page; login.partner.microsoftonline.cn from the national cloud authentication page.
  for (const host of ["login.chinacloudapi.cn", "login.partner.microsoftonline.cn", "https://login.partner.microsoftonline.cn/"]) {
    const cloud = resolveAzureCloud(host);
    assert.equal(cloud.name, "china", host);
    assert.equal(cloud.graphBaseUrl, "https://microsoftgraph.chinacloudapi.cn", host);
    assert.equal(cloud.managementBaseUrl, "https://management.chinacloudapi.cn", host);
  }
  assert.equal(resolveAzureCloud("login.partner.microsoftonline.cn").authorityHost, "https://login.partner.microsoftonline.cn");
  assert.equal(resolveAzureCloud("login.chinacloudapi.cn").authorityHost, "https://login.chinacloudapi.cn");

  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url, init });
    if (url.endsWith("/oauth2/v2.0/token")) return new Response(JSON.stringify({ access_token: "cn-token", expires_in: 3599 }), { status: 200 });
    return new Response(JSON.stringify({ value: [] }), { status: 200 });
  };
  const config = resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-cn", AZURE_SUBSCRIPTION_ID: "sub-cn", AZURE_CLIENT_ID: "client-cn", AZURE_CLIENT_SECRET: "secret-cn", AZURE_AUTHORITY_HOST: "login.partner.microsoftonline.cn" },
    () => undefined,
  );
  await new AzureAuditorClient(config, { fetchImpl, now: () => NOW }).listSubscribedSkus();
  assert.equal(requests[0].url, "https://login.partner.microsoftonline.cn/tenant-cn/oauth2/v2.0/token");
  assert.equal(new URLSearchParams(requests[0].init.body).get("scope"), "https://microsoftgraph.chinacloudapi.cn/.default");
  assert.equal(requests[1].url, "https://microsoftgraph.chinacloudapi.cn/v1.0/subscribedSkus");
  assert.throws(
    () => resolveAzureConfiguration({}, { AZURE_TENANT_ID: "t", AZURE_SUBSCRIPTION_ID: "s", AZURE_CLIENT_ID: "c", AZURE_CLIENT_CERTIFICATE_PATH: "/tmp/cert.pem" }, () => undefined),
    /certificate credentials are not implemented/,
  );
});

test("AzureAuditorClient acquires tokens via the documented client credentials grant per cloud", async () => {
  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url, init });
    if (url.endsWith("/oauth2/v2.0/token")) {
      return new Response(JSON.stringify({ token_type: "Bearer", expires_in: 3599, access_token: `token-for-${new URLSearchParams(init.body).get("scope")}` }), { status: 200 });
    }
    return new Response(JSON.stringify({ value: [{ id: "org-1" }] }), { status: 200 });
  };
  const config = resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-1", AZURE_SUBSCRIPTION_ID: "sub-1", AZURE_CLIENT_ID: "client-1", AZURE_CLIENT_SECRET: "secret-1", AZURE_AUTHORITY_HOST: "login.microsoftonline.us" },
    () => undefined,
  );
  const client = new AzureAuditorClient(config, { fetchImpl, now: () => NOW });
  await client.getOrganization();
  await client.getSubscription();

  const tokenRequests = requests.filter((item) => item.url.endsWith("/oauth2/v2.0/token"));
  assert.equal(tokenRequests.length, 2);
  assert.equal(tokenRequests[0].url, "https://login.microsoftonline.us/tenant-1/oauth2/v2.0/token");
  assert.equal(tokenRequests[0].init.method, "POST");
  assert.equal(tokenRequests[0].init.headers["Content-Type"], "application/x-www-form-urlencoded");
  const body = new URLSearchParams(tokenRequests[0].init.body);
  assert.equal(body.get("grant_type"), "client_credentials");
  assert.equal(body.get("client_id"), "client-1");
  assert.equal(body.get("client_secret"), "secret-1");
  assert.equal(body.get("scope"), "https://graph.microsoft.us/.default");
  assert.equal(new URLSearchParams(tokenRequests[1].init.body).get("scope"), "https://management.usgovcloudapi.net/.default");
  assert.equal(requests[1].url, "https://graph.microsoft.us/v1.0/organization");
  assert.equal(requests[1].init.headers.Authorization, "Bearer token-for-https://graph.microsoft.us/.default");
  assert.equal(requests[3].url, `https://management.usgovcloudapi.net/subscriptions/sub-1?api-version=${AZURE_ARM_API_VERSIONS.subscription}`);
});

// Prototype members that do not issue a Graph or ARM request; every other client method must appear in the URL assertions below.
const NON_REQUEST_CLIENT_MEMBERS = new Set(["constructor", "getToken", "parseJsonBody", "getResolvedConfig", "getNow", "getCloud", "requestJson", "collectPages", "collectGraph", "collectArm", "graph", "arm"]);

test("AzureAuditorClient sends the documented request URL and API version for every request method", async () => {
  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url, init });
    return new Response(JSON.stringify({ value: [] }), { status: 200 });
  };
  const client = new AzureAuditorClient(sampleConfig(), { fetchImpl, now: () => NOW });
  const sub = "https://management.azure.com/subscriptions/sub-123";
  const graph = "https://graph.microsoft.com/v1.0";
  const graphBeta = "https://graph.microsoft.com/beta";
  const expectations = [
    ["getOrganization", () => client.getOrganization(), `${graph}/organization`],
    ["listConditionalAccessPolicies", () => client.listConditionalAccessPolicies(), `${graph}/identity/conditionalAccess/policies`],
    ["listUserRegistrationDetails", () => client.listUserRegistrationDetails(), `${graph}/reports/authenticationMethods/userRegistrationDetails`],
    ["listDirectoryRoles", () => client.listDirectoryRoles(), `${graph}/directoryRoles`],
    ["listDirectoryRoleMembers", () => client.listDirectoryRoleMembers("role 1"), `${graph}/directoryRoles/role%201/members`],
    ["getSecurityDefaultsPolicy", () => client.getSecurityDefaultsPolicy(), `${graph}/policies/identitySecurityDefaultsEnforcementPolicy`],
    ["getAuthorizationPolicy", () => client.getAuthorizationPolicy(), `${graph}/policies/authorizationPolicy`],
    ["listServicePrincipals", () => client.listServicePrincipals(), `${graph}/servicePrincipals?$top=100&$select=id,displayName,appId,passwordCredentials,keyCredentials`],
    ["listApplications", () => client.listApplications(), `${graph}/applications?$top=999&$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$expand=owners($select=id)`],
    ["listOAuth2PermissionGrants", () => client.listOAuth2PermissionGrants(), `${graph}/oauth2PermissionGrants`],
    // List users caps $top at 500 when $select includes signInActivity; the plain member list keeps the 999 maximum.
    ["listGuestUsers", () => client.listGuestUsers(), `${graph}/users?$filter=userType eq 'Guest'&$count=true&$top=500&$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState,signInActivity`],
    ["listMemberUsers", () => client.listMemberUsers(10), `${graph}/users?$filter=userType eq 'Member' and accountEnabled eq true&$count=true&$top=999&$select=id,userPrincipalName,mail`],
    ["listInboxMessageRules", () => client.listInboxMessageRules("user-1"), `${graph}/users/user-1/mailFolders/inbox/messageRules`],
    ["listRiskyUsers", () => client.listRiskyUsers(), `${graph}/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'`],
    ["listRiskDetections", () => client.listRiskDetections(), `${graph}/identityProtection/riskDetections?$top=500`],
    ["listSubscribedSkus", () => client.listSubscribedSkus(), `${graph}/subscribedSkus`],
    ["listRoleEligibilitySchedules", () => client.listRoleEligibilitySchedules(), `${graph}/roleManagement/directory/roleEligibilitySchedules`],
    ["listRoleAssignmentSchedules", () => client.listRoleAssignmentSchedules(), `${graph}/roleManagement/directory/roleAssignmentSchedules?$filter=assignmentType eq 'Assigned'`],
    ["listDeviceCompliancePolicies", () => client.listDeviceCompliancePolicies(), `${graph}/deviceManagement/deviceCompliancePolicies`],
    ["listManagedDevices", () => client.listManagedDevices(), `${graph}/deviceManagement/managedDevices?$select=id,deviceName,complianceState,lastSyncDateTime`],
    // The tenant-wide sensitivity label list is documented only under /beta.
    ["listSensitivityLabels", () => client.listSensitivityLabels(), `${graphBeta}/security/informationProtection/sensitivityLabels`],
    ["getSharePointSettings", () => client.getSharePointSettings(), `${graph}/admin/sharepoint/settings`],
    ["listSecureScores", () => client.listSecureScores(), `${graph}/security/secureScores?$top=20`],
    ["listSecurityAlerts", () => client.listSecurityAlerts(), `${graph}/security/alerts_v2?$top=50`],
    ["listDirectoryAudits", () => client.listDirectoryAudits(), `${graph}/auditLogs/directoryAudits?$top=50`],
    ["listSignIns", () => client.listSignIns(), `${graph}/auditLogs/signIns?$top=50`],
    ["getSubscription", () => client.getSubscription(), `${sub}?api-version=2022-12-01`],
    ["listDefenderPricings", () => client.listDefenderPricings(), `${sub}/providers/Microsoft.Security/pricings?api-version=2024-01-01`],
    ["listDiagnosticSettings", () => client.listDiagnosticSettings(), `${sub}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`],
    ["listLogAnalyticsWorkspaces", () => client.listLogAnalyticsWorkspaces(), `${sub}/providers/Microsoft.OperationalInsights/workspaces?api-version=2026-03-01`],
    // Microsoft.Security/securityContacts is defined only in the 2020-01-01-preview and 2017-08-01-preview spec files.
    ["listSecurityContacts", () => client.listSecurityContacts(), `${sub}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview`],
    ["listRoleAssignments", () => client.listRoleAssignments(), `${sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`],
    ["listRoleDefinitions", () => client.listRoleDefinitions(), `${sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01`],
    ["listNetworkWatchers", () => client.listNetworkWatchers(), `${sub}/providers/Microsoft.Network/networkWatchers?api-version=2025-09-01`],
    ["listFlowLogs", () => client.listFlowLogs("rg1", "nw1"), `${sub}/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/nw1/flowLogs?api-version=2025-09-01`],
    ["listNetworkSecurityGroups", () => client.listNetworkSecurityGroups(), `${sub}/providers/Microsoft.Network/networkSecurityGroups?api-version=2025-09-01`],
    ["listKeyVaults", () => client.listKeyVaults(), `${sub}/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01`],
    ["listStorageAccounts", () => client.listStorageAccounts(), `${sub}/providers/Microsoft.Storage/storageAccounts?api-version=2026-06-01`],
    ["listPolicyAssignments", () => client.listPolicyAssignments(), `${sub}/providers/Microsoft.Authorization/policyAssignments?api-version=2026-07-01&$filter=atScope()`],
    ["summarizePolicyStates", () => client.summarizePolicyStates(), `${sub}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2024-10-01`],
  ];

  const requestMethods = Object.getOwnPropertyNames(AzureAuditorClient.prototype).filter((name) => !NON_REQUEST_CLIENT_MEMBERS.has(name)).sort();
  assert.deepEqual(expectations.map(([name]) => name).sort(), requestMethods, "every request method needs a URL assertion");
  assert.equal(AZURE_ARM_API_VERSIONS.securityContacts, "2020-01-01-preview");
  assert.equal(AZURE_ARM_API_VERSIONS.flowLogs, AZURE_ARM_API_VERSIONS.networkWatchers);

  for (const [name, call, expectedUrl] of expectations) {
    requests.length = 0;
    await call();
    assert.equal(requests.length, 1, name);
    assert.equal(requests[0].url, expectedUrl, name);
    assert.equal(requests[0].init.method ?? "GET", name === "summarizePolicyStates" ? "POST" : "GET", name);
  }
  requests.length = 0;
  await client.listGuestUsers();
  assert.equal(requests[0].init.headers.ConsistencyLevel, "eventual");
  requests.length = 0;
  await client.listMemberUsers(10);
  assert.equal(requests[0].init.headers.ConsistencyLevel, "eventual");
});

test("pagination follows @odata.nextLink and nextLink to completion and records truncation", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.includes("page=2")) return new Response(JSON.stringify({ value: [{ id: "b" }] }), { status: 200 });
    if (url.includes("graph")) return new Response(JSON.stringify({ "@odata.count": 2, value: [{ id: "a" }], "@odata.nextLink": "https://graph.microsoft.com/v1.0/subscribedSkus?page=2" }), { status: 200 });
    return new Response(JSON.stringify({ value: [{ id: "arm-a" }], nextLink: "https://management.azure.com/next?page=2" }), { status: 200 });
  };
  const client = new AzureAuditorClient(sampleConfig(), { fetchImpl, now: () => NOW });
  const graphPage = await client.listSubscribedSkus();
  assert.deepEqual(graphPage.items.map((item) => item.id), ["a", "b"]);
  assert.equal(graphPage.truncated, false);
  assert.equal(graphPage.total, 2);
  const armPage = await client.listKeyVaults();
  assert.deepEqual(armPage.items.map((item) => item.id), ["arm-a", "b"]);
  assert.equal(armPage.truncated, false);

  const capped = await client.listRoleAssignments(1);
  assert.equal(capped.truncated, true);
  assert.equal(capped.seen, 1);
  const guardrails = await assessAzureSubscriptionGuardrails({
    listRoleAssignments: async () => capped,
    listRoleDefinitions: async () => [],
    listSecurityContacts: async () => [{ properties: { emails: "soc@example.com" } }],
    listNetworkWatchers: async () => [],
  });
  const owner = guardrails.findings.find((item) => item.id === "AZURE-SUB-01");
  assert.equal(owner.status, "warn");
  assert.match(owner.summary, /partial \(1 seen of unknown total\)/);
  assert.equal(toPage([{ id: 1 }]).truncated, false);
});

test("rule 10: a next link that repeats or arrives with an empty page exits as truncated instead of looping", async () => {
  const graphCalls = [];
  const repeating = new AzureAuditorClient(sampleConfig(), {
    fetchImpl: async (url) => {
      graphCalls.push(url);
      // The server keeps handing back the same page URL; without a guard this walk never ends.
      return new Response(JSON.stringify({ value: [{ id: `sku-${graphCalls.length}` }], "@odata.nextLink": "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=same" }), { status: 200 });
    },
    now: () => NOW,
  });
  const repeated = await repeating.listSubscribedSkus();
  assert.equal(graphCalls.length, 2, "the first page follows the link once, the repeat stops the walk");
  assert.equal(repeated.truncated, true);
  assert.equal(repeated.seen, 2);
  assert.deepEqual(repeated.items.map((item) => item.id), ["sku-1", "sku-2"]);

  const armCalls = [];
  const emptyPages = new AzureAuditorClient(sampleConfig(), {
    fetchImpl: async (url) => {
      armCalls.push(url);
      if (armCalls.length === 1) return new Response(JSON.stringify({ value: [{ id: "kv-1" }], nextLink: "https://management.azure.com/next?page=2" }), { status: 200 });
      // Each later page is empty but still advertises a fresh next link.
      return new Response(JSON.stringify({ value: [], nextLink: `https://management.azure.com/next?page=${armCalls.length + 1}` }), { status: 200 });
    },
    now: () => NOW,
  });
  const empty = await emptyPages.listKeyVaults();
  assert.equal(armCalls.length, 2);
  assert.equal(empty.truncated, true);
  assert.deepEqual(empty.items.map((item) => item.id), ["kv-1"]);

  // A truncated walk from either guard still demotes the consuming verdict through capForPartial.
  const guardrails = await assessAzureSubscriptionGuardrails({
    listRoleAssignments: async () => repeated,
    listRoleDefinitions: async () => [],
    listSecurityContacts: async () => [{ properties: { emails: "soc@example.com" } }],
    listNetworkWatchers: async () => [],
  });
  assert.equal(guardrails.findings.find((item) => item.id === "AZURE-SUB-01").status, "warn");
});

test("rule 9: API error bodies are reduced to the documented error envelope before they reach messages, evidence, or logs", async () => {
  assert.equal(describeErrorBody(""), "");
  assert.equal(describeErrorBody(JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation.", innerError: { "request-id": "req-1", date: "2026-04-16" } } })), "Authorization_RequestDenied: Insufficient privileges to complete the operation.");
  assert.equal(describeErrorBody(JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided.", trace_id: "trace-1", correlation_id: "corr-1" })), "invalid_client: AADSTS7000215: Invalid client secret provided.");
  const htmlBody = "<html>Bad gateway, request Authorization: Bearer leaked-token</html>";
  assert.equal(describeErrorBody(htmlBody, "text/html; charset=utf-8"), `non-JSON body (text/html, ${htmlBody.length} bytes)`);
  assert.equal(describeErrorBody(htmlBody), `non-JSON body (unknown content type, ${htmlBody.length} bytes)`);
  assert.equal(describeErrorBody("[1,2,3]", "application/json"), "non-JSON body (application/json, 7 bytes)", "a JSON body that is not an object is described by shape too");
  assert.equal(describeErrorBody(JSON.stringify({ unexpected: "shape", token: "leaked-token" })), "error body without code or message");
  assertRedactionCases(assert, redactErrorText);
  assert.equal(
    new AzureApiError(`403 Forbidden: AuthorizationFailed: see ${CANARY_URL} for the denied scope`, "https://management.azure.com/x", 403).message,
    "403 Forbidden: AuthorizationFailed: see https://api.example.com/v1/x?[REDACTED] for the denied scope",
    "AzureApiError scrubs its own message",
  );

  const leakedMarker = "LEAKED-REQUEST-CONTEXT";
  const fetchImpl = async (url) => {
    if (url.endsWith("/oauth2/v2.0/token")) {
      return new Response(JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided.", trace_id: leakedMarker }), { status: 401, statusText: "Unauthorized" });
    }
    return new Response(JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation.", innerError: { echo: leakedMarker } } }), { status: 403, statusText: "Forbidden" });
  };
  const tokenClient = new AzureAuditorClient(sampleConfig(), { fetchImpl, now: () => NOW });
  await assert.rejects(tokenClient.listSubscribedSkus(), (error) => {
    assert.equal(error.name, "AzureApiError");
    assert.equal(error.status, 403);
    assert.equal(error.message, "403 Forbidden: Authorization_RequestDenied: Insufficient privileges to complete the operation.");
    assert.ok(!error.message.includes(leakedMarker));
    return true;
  });
  const credentialConfig = resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-1", AZURE_SUBSCRIPTION_ID: "sub-1", AZURE_CLIENT_ID: "client-1", AZURE_CLIENT_SECRET: "secret-value-1" },
    () => undefined,
  );
  await assert.rejects(new AzureAuditorClient(credentialConfig, { fetchImpl, now: () => NOW }).getOrganization(), (error) => {
    assert.equal(error.message, "Token request failed: 401 Unauthorized: invalid_client: AADSTS7000215: Invalid client secret provided.");
    assert.ok(!error.message.includes(leakedMarker));
    assert.ok(!error.message.includes("secret-value-1"));
    return true;
  });
});

test("rule 9: service principal and application credential records keep only schedule fields at collection time", async () => {
  const rawCredential = { keyId: "k1", displayName: "automation", hint: "Abc", secretText: "FAKE-SECRET-TEXT", customKeyIdentifier: "Y3Vz", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" };
  const rawKey = { keyId: "k2", displayName: "cert", type: "AsymmetricX509Cert", usage: "Verify", key: "FAKE-KEY-BLOB", customKeyIdentifier: "dGh1bWI=", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" };
  const projected = projectCredentialCarrier({ id: "sp-1", displayName: "App", appId: "app-1", passwordCredentials: [rawCredential], keyCredentials: [rawKey] });
  assert.deepEqual(projected, {
    id: "sp-1",
    displayName: "App",
    appId: "app-1",
    passwordCredentials: [{ keyId: "k1", displayName: "automation", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" }],
    keyCredentials: [{ keyId: "k2", displayName: "cert", type: "AsymmetricX509Cert", usage: "Verify", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" }],
  });
  assert.deepEqual(projectCredentialCarrier({ id: "sp-2" }), { id: "sp-2", passwordCredentials: [], keyCredentials: [] });

  const fetchImpl = async () => new Response(JSON.stringify({ value: [{ id: "sp-1", displayName: "App", appId: "app-1", passwordCredentials: [rawCredential], keyCredentials: [rawKey] }] }), { status: 200 });
  const client = new AzureAuditorClient(sampleConfig(), { fetchImpl, now: () => NOW });
  for (const page of [await client.listServicePrincipals(), await client.listApplications()]) {
    const serialized = JSON.stringify(page);
    for (const secret of ["Abc", "FAKE-SECRET-TEXT", "FAKE-KEY-BLOB", "hint", "secretText", "customKeyIdentifier"]) {
      assert.ok(!serialized.includes(secret), `${secret} survived collection`);
    }
    assert.equal(page.items[0].passwordCredentials[0].endDateTime, "2026-12-01T00:00:00Z");
  }
  // The projected shape still drives the credential hygiene verdicts.
  const identity = await assessAzureIdentity(clientWith({ ...compliantClient(), listServicePrincipals: () => client.listServicePrincipals(), listApplications: () => client.listApplications() }));
  assert.equal(identity.findings.find((item) => item.id === "AZURE-ID-05").status, "pass");
  assert.equal(identity.findings.find((item) => item.id === "AZURE-ID-12").status, "pass");
});

test("checkAzureAccess reports readable audit surfaces", async () => {
  const client = clientWith({
    async getOrganization() { return { id: "org-1" }; },
    async listConditionalAccessPolicies() { return [{ id: "ca-1" }]; },
    async listDirectoryRoles() { return [{ id: "role-1" }]; },
    async listSecureScores() { return [{ currentScore: 45, maxScore: 60 }]; },
    async listDefenderPricings() { return { items: [{ id: "pricing-1" }], truncated: false, seen: 1 }; },
    async listRoleAssignments() { return [{ id: "assignment-1" }]; },
    async listDiagnosticSettings() { return [{ id: "diag-1" }]; },
    async listSecurityContacts() { return [{ id: "contact-1" }]; },
  });

  const result = await checkAzureAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.equal(result.surfaces.find((surface) => surface.name === "defender_pricings").count, 1);
  assert.equal(result.surfaces.find((surface) => surface.name === "defender_pricings").truncated, undefined);
  assert.ok(result.notes.every((note) => !note.includes("probe page cap")));
  assert.match(result.recommendedNextStep, /azure_assess_subscription_guardrails/);
  assert.match(result.recommendedNextStep, /azure_assess_data_protection, azure_assess_network_and_policy/);
});

test("rule 10: checkAzureAccess keeps the truncated flag on a capped probe so its count reads as a floor", async () => {
  let requestedLimit;
  const client = clientWith({
    ...compliantClient(),
    async listRoleAssignments(limit) {
      requestedLimit = limit;
      return { items: Array.from({ length: limit }, (_, index) => ({ id: `assignment-${index}` })), truncated: true, seen: limit, total: undefined };
    },
  });
  const result = await checkAzureAccess(client);
  assert.equal(requestedLimit, 25);
  const assignments = result.surfaces.find((surface) => surface.name === "role_assignments");
  assert.equal(assignments.status, "readable");
  assert.equal(assignments.count, 25);
  assert.equal(assignments.truncated, true);
  assert.ok(result.notes.some((note) => /role_assignments stopped at the probe page cap and are lower bounds/.test(note)));
  assert.equal(result.surfaces.find((surface) => surface.name === "security_contacts").truncated, undefined);
});

test("rule 10: AZURE-MON-04 and AZURE-MON-05 cap at warn on a truncated pricing or diagnostic settings page", async () => {
  const baseline = statusesById(await assessAzureMonitoring(compliantClient()));
  assert.equal(baseline["AZURE-MON-04"], "pass");
  assert.equal(baseline["AZURE-MON-05"], "pass");

  const truncated = clientWith({
    ...compliantClient(),
    async listDefenderPricings() { return { items: [{ name: "VirtualMachines", properties: { pricingTier: "Standard" } }], truncated: true, seen: 1 }; },
    async listDiagnosticSettings() { return { items: [{ id: "diag-1", properties: { workspaceId: "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law", logs: [{ category: "Administrative", enabled: true }] } }], truncated: true, seen: 1, total: 3 }; },
  });
  const result = await assessAzureMonitoring(truncated);
  const pricing = result.findings.find((item) => item.id === "AZURE-MON-04");
  assert.equal(pricing.status, "warn");
  assert.match(pricing.summary, /1\/1 Defender for Cloud plans are on the Standard pricingTier\. Inventory of Defender plans is partial \(1 seen of unknown total\); verdict capped at warn\./);
  assert.equal(pricing.evidence.truncated, true);
  const diagnostics = result.findings.find((item) => item.id === "AZURE-MON-05");
  assert.equal(diagnostics.status, "warn");
  assert.match(diagnostics.summary, /Inventory of diagnostic settings is partial \(1 seen of 3 total\); verdict capped at warn\./);
  assert.deepEqual({ seen: diagnostics.evidence.seen, total: diagnostics.evidence.total, truncated: diagnostics.evidence.truncated }, { seen: 1, total: 3, truncated: true });
  // A non-compliant page is still fail or warn on its own merits, never masked by the cap.
  const mixed = clientWith({ ...compliantClient(), async listDefenderPricings() { return { items: [{ properties: { pricingTier: "Standard" } }, { properties: { pricingTier: "Free" } }], truncated: true, seen: 2 }; } });
  assert.equal((await assessAzureMonitoring(mixed)).findings.find((item) => item.id === "AZURE-MON-04").status, "warn");
});

test("assessAzureIdentity flags weak auth baseline and privileged role sprawl", async () => {
  const client = clientWith({
    async listConditionalAccessPolicies() { return [CA_MFA]; },
    async listUserRegistrationDetails() {
      return [
        { userPrincipalName: "alice@example.com", isMfaRegistered: true },
        { userPrincipalName: "bob@example.com", isMfaRegistered: false },
      ];
    },
    async listDirectoryRoles() {
      return [
        { id: "ga", displayName: "Global Administrator" },
        { id: "sec", displayName: "Security Administrator" },
      ];
    },
    async listDirectoryRoleMembers(roleId) {
      return roleId === "ga"
        ? [{ id: "user-1" }, { id: "user-2" }, { id: "user-3" }, { id: "user-4" }, { id: "user-5" }]
        : [{ id: "user-6" }];
    },
    async getSecurityDefaultsPolicy() { return { isEnabled: false }; },
    async listServicePrincipals() {
      return [{ displayName: "App One", passwordCredentials: [{ endDateTime: "2026-04-20T00:00:00Z" }], keyCredentials: [] }];
    },
  });

  const result = await assessAzureIdentity(client);
  const statuses = statusesById(result);
  assert.equal(statuses["AZURE-ID-01"], "pass");
  // Legacy auth without a block policy or security defaults is a fail; the former display-name heuristic was removed.
  assert.equal(statuses["AZURE-ID-02"], "fail");
  assert.equal(statuses["AZURE-ID-03"], "fail");
  assert.equal(statuses["AZURE-ID-04"], "fail");
  assert.equal(statuses["AZURE-ID-05"], "warn");
});

test("assessAzureMonitoring classifies score, telemetry, and defender coverage", async () => {
  const client = clientWith({
    async listSecureScores() { return [{ currentScore: 40, maxScore: 80 }]; },
    async listSecurityAlerts() { return [{ id: "alert-1" }]; },
    async listDirectoryAudits() { return [{ id: "audit-1" }]; },
    async listSignIns() { return []; },
    async listDefenderPricings() { return [{ properties: { pricingTier: "Standard" } }, { properties: { pricingTier: "Free" } }]; },
    async listDiagnosticSettings() { return []; },
  });

  const result = await assessAzureMonitoring(client);
  const statuses = statusesById(result);
  assert.equal(statuses["AZURE-MON-01"], "warn");
  assert.equal(statuses["AZURE-MON-02"], "pass");
  assert.equal(statuses["AZURE-MON-03"], "warn");
  assert.equal(statuses["AZURE-MON-04"], "warn");
  assert.equal(statuses["AZURE-MON-05"], "fail");
  assert.equal(statuses["AZURE-MON-06"], "fail");
  assert.equal(statuses["AZURE-MON-07"], "manual");
});

test("assessAzureSubscriptionGuardrails flags RBAC and missing contacts", async () => {
  const client = {
    async listRoleAssignments() {
      return [
        { properties: { roleDefinitionId: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/owner-role", principalType: "User" } },
        { properties: { roleDefinitionId: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/contrib-role", principalType: "ServicePrincipal" } },
      ];
    },
    async listRoleDefinitions() {
      return [
        { id: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/owner-role", properties: { roleName: "Owner" } },
        { id: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/contrib-role", properties: { roleName: "Contributor" } },
      ];
    },
    async listSecurityContacts() { return []; },
    async listNetworkWatchers() { return []; },
  };

  const result = await assessAzureSubscriptionGuardrails(client);
  const statuses = statusesById(result);
  assert.equal(statuses["AZURE-SUB-01"], "warn");
  assert.equal(statuses["AZURE-SUB-02"], "warn");
  assert.equal(statuses["AZURE-SUB-03"], "fail");
  assert.equal(statuses["AZURE-SUB-04"], "warn");
  assert.equal(statuses["AZURE-SUB-05"], "fail");
});

test("assessAzureDataProtection and assessAzureNetworkAndPolicy detect misconfigurations", async () => {
  const client = clientWith({
    async listConditionalAccessPolicies() { return [CA_MFA]; },
    async listSubscribedSkus() { return P2_SKUS; },
    async listDeviceCompliancePolicies() { return [{ id: "cp-1" }]; },
    async listManagedDevices() { return [{ id: "d1", complianceState: "noncompliant" }, { id: "d2", complianceState: "compliant" }]; },
    async listSensitivityLabels() { return [{ id: "l1", isActive: false }]; },
    async listKeyVaults() { return [{ name: "kv-open", properties: { enableSoftDelete: true, enablePurgeProtection: false, accessPolicies: [{ objectId: "x" }] } }]; },
    async listStorageAccounts() { return [{ name: "st-http", properties: { supportsHttpsTrafficOnly: false, allowBlobPublicAccess: true, minimumTlsVersion: "TLS1_0" } }]; },
    async listMemberUsers() { return [{ id: "u1", userPrincipalName: "alice@example.com" }]; },
    async listInboxMessageRules() { return [{ displayName: "Leak", isEnabled: true, actions: { forwardTo: [{ emailAddress: { address: "ext@example.net" } }] } }]; },
    async getSharePointSettings() { return { sharingCapability: "externalUserAndGuestSharing", sharingDomainRestrictionMode: "none" }; },
    async listNetworkSecurityGroups() {
      return [{ name: "nsg-1", properties: { securityRules: [{ name: "rdp", properties: { access: "Allow", direction: "Inbound", protocol: "*", sourceAddressPrefix: "*", destinationPortRanges: ["3380-3390"] } }] } }];
    },
    async listPolicyAssignments() { return [{ name: "audit", properties: { enforcementMode: "DoNotEnforce", policyDefinitionId: "/providers/Microsoft.Authorization/policyDefinitions/abc" } }]; },
    async summarizePolicyStates() { return { value: [{ results: { nonCompliantResources: 4, nonCompliantPolicies: 2 } }] }; },
  });

  const data = statusesById(await assessAzureDataProtection(client));
  assert.equal(data["AZURE-DP-01"], "fail");
  assert.equal(data["AZURE-DP-02"], "manual");
  assert.equal(data["AZURE-DP-03"], "fail");
  assert.equal(data["AZURE-DP-04"], "fail");
  assert.equal(data["AZURE-DP-05"], "fail");
  assert.equal(data["AZURE-DP-06"], "fail");
  assert.equal(data["AZURE-DP-07"], "manual");
  assert.equal(data["AZURE-DP-08"], "fail");

  const network = statusesById(await assessAzureNetworkAndPolicy(client));
  assert.equal(network["AZURE-NP-01"], "fail");
  assert.equal(network["AZURE-NP-02"], "fail");
  assert.equal(network["AZURE-NP-03"], "warn");
  // An NSG exists but the subscription has no Network Watcher, so no flow log can exist.
  assert.equal(network["AZURE-NP-04"], "fail");
  assert.equal(isExposedAdminRule({ properties: { access: "Deny", direction: "Inbound", protocol: "*", sourceAddressPrefix: "*", destinationPortRange: "22" } }), false);
  assert.equal(isExposedAdminRule({ properties: { access: "Allow", direction: "Outbound", protocol: "*", sourceAddressPrefix: "*", destinationPortRange: "22" } }), false);
  assert.equal(isExposedAdminRule({ properties: { access: "Allow", direction: "Inbound", protocol: "Udp", sourceAddressPrefix: "*", destinationPortRange: "22" } }), false);
  assert.equal(isExposedAdminRule({ properties: { access: "Allow", direction: "Inbound", protocol: "Tcp", sourceAddressPrefix: "10.0.0.0/8", destinationPortRange: "22" } }), false);
});

test("verdict safety 1: every 403 renders manual naming the endpoint, access, and evidence (fixture a)", async () => {
  for (const [name, run] of ASSESSORS) {
    const result = await run(forbiddenClient());
    assert.ok(result.findings.length > 0, name);
    for (const item of result.findings) {
      assert.equal(item.status, "manual", `${name} ${item.id}`);
      if (!ALWAYS_MANUAL.has(item.id)) {
        assert.match(item.summary, /403 Forbidden/, item.id);
        assert.ok(item.evidence.endpoint, item.id);
        assert.ok(item.evidence.required_access, item.id);
        assert.ok(item.evidence.evidence_to_collect, item.id);
      }
    }
    assert.ok(result.errors.length > 0, name);
  }
});

test("verdict safety 2: empty inventories never pass by default (fixture b)", async () => {
  const emptyClient = clientWith({
    async getSecurityDefaultsPolicy() { return { isEnabled: false }; },
    async getAuthorizationPolicy() { return {}; },
    async getSharePointSettings() { return {}; },
    async summarizePolicyStates() { return { value: [] }; },
  });
  // AZURE-ID-13 used to pass on an empty grant list; it now renders manual like ID-05 and ID-12 because emptiness usually means a read problem.
  const compliantByIntent = new Set(["AZURE-ID-08", "AZURE-ID-11"]);
  const expectedFail = new Set(["AZURE-ID-01", "AZURE-ID-02", "AZURE-MON-05", "AZURE-MON-06", "AZURE-SUB-03", "AZURE-DP-03", "AZURE-NP-02"]);
  for (const [name, run] of ASSESSORS) {
    const result = await run(emptyClient);
    for (const item of result.findings) {
      if (compliantByIntent.has(item.id)) {
        assert.equal(item.status, "pass", `${name} ${item.id}`);
        assert.match(item.summary, /compliant by intent/, item.id);
      } else if (expectedFail.has(item.id)) {
        assert.equal(item.status, "fail", `${name} ${item.id}`);
      } else {
        assert.ok(["manual", "warn"].includes(item.status), `${name} ${item.id} was ${item.status}`);
      }
    }
  }
  const grants = (await assessAzureIdentity(emptyClient)).findings.find((item) => item.id === "AZURE-ID-13");
  assert.equal(grants.status, "manual");
  assert.match(grants.summary, /Zero oauth2PermissionGrants were returned/);
  assert.match(grants.summary, /Directory\.Read\.All/);
  const flowLogs = (await assessAzureNetworkAndPolicy(emptyClient)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.equal(flowLogs.status, "manual");
  assert.match(flowLogs.summary, /Zero network security groups were returned/);
});

test("verdict safety 3: missing licenses render manual naming the license, never pass", async () => {
  const noLicense = clientWith(compliantClient(), {});
  noLicense.listSubscribedSkus = async () => [{ skuPartNumber: "O365_BUSINESS", servicePlans: [{ servicePlanName: "EXCHANGE_S_STANDARD", provisioningStatus: "Success" }] }];
  const identity = statusesById(await assessAzureIdentity(noLicense));
  const identityResult = await assessAzureIdentity(noLicense);
  assert.equal(identity["AZURE-ID-09"], "manual");
  assert.equal(identity["AZURE-ID-10"], "manual");
  assert.match(identityResult.findings.find((item) => item.id === "AZURE-ID-09").summary, /Entra ID P2/);
  const data = await assessAzureDataProtection(noLicense);
  assert.equal(data.findings.find((item) => item.id === "AZURE-DP-01").status, "manual");
  assert.match(data.findings.find((item) => item.id === "AZURE-DP-01").summary, /Intune license/);

  const p2Forbidden = clientWith(compliantClient(), {});
  p2Forbidden.listRiskyUsers = async () => { throw forbidden(); };
  const risky = (await assessAzureIdentity(p2Forbidden)).findings.find((item) => item.id === "AZURE-ID-11");
  assert.equal(risky.status, "manual");
  assert.match(risky.summary, /Entra ID P2/);
});

test("verdict safety 4: items without dates are never counted fresh or active and cap at warn", async () => {
  const client = clientWith(compliantClient(), {});
  client.listServicePrincipals = async () => [{ displayName: "No expiry", passwordCredentials: [{ endDateTime: null }], keyCredentials: [] }];
  client.listApplications = async () => [{ id: "a", displayName: "No expiry app", owners: [{ id: "o" }], passwordCredentials: [{ keyId: "k" }], keyCredentials: [] }];
  client.listGuestUsers = async () => [{ id: "g", userPrincipalName: "g@ext", accountEnabled: true, signInActivity: { lastSignInDateTime: null } }];
  const statuses = statusesById(await assessAzureIdentity(client));
  assert.equal(statuses["AZURE-ID-05"], "warn");
  assert.equal(statuses["AZURE-ID-12"], "warn");
  assert.equal(statuses["AZURE-ID-08"], "warn");
});

test("verdict safety 5: partial inventories are flagged with seen and total counts and never pass (fixture c)", async () => {
  const partial = clientWith(compliantClient(), {});
  partial.listGuestUsers = async () => ({ items: [{ id: "g", accountEnabled: true, signInActivity: { lastSignInDateTime: "2026-04-01T00:00:00Z" } }], truncated: true, seen: 1, total: 40 });
  partial.listKeyVaults = async () => ({ items: [{ name: "kv1", properties: { enableSoftDelete: true, enablePurgeProtection: true, enableRbacAuthorization: true, publicNetworkAccess: "Disabled" } }], truncated: true, seen: 1 });
  partial.listStorageAccounts = async () => { throw forbidden(); };
  partial.listNetworkSecurityGroups = async () => ({ items: [], truncated: true, seen: 0 });
  partial.listApplications = async () => ({ items: [{ id: "a", displayName: "x", owners: [{ id: "o" }], passwordCredentials: [{ startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" }] }], truncated: true, seen: 1, total: 900 });
  partial.listPolicyAssignments = async () => ({ items: [{ properties: { enforcementMode: "Default", policyDefinitionId: "/x" } }], truncated: true, seen: 1 });

  const identity = await assessAzureIdentity(partial);
  const guests = identity.findings.find((item) => item.id === "AZURE-ID-08");
  assert.equal(guests.status, "warn");
  assert.match(guests.summary, /1 seen of 40 total/);
  assert.equal(identity.findings.find((item) => item.id === "AZURE-ID-12").status, "warn");
  const data = await assessAzureDataProtection(partial);
  assert.equal(data.findings.find((item) => item.id === "AZURE-DP-04").status, "warn");
  assert.equal(data.findings.find((item) => item.id === "AZURE-DP-05").status, "manual");
  const network = await assessAzureNetworkAndPolicy(partial);
  assert.notEqual(network.findings.find((item) => item.id === "AZURE-NP-01").status, "pass");
  assert.equal(network.findings.find((item) => item.id === "AZURE-NP-02").status, "warn");
  assert.notEqual(network.findings.find((item) => item.id === "AZURE-NP-04").status, "pass");

  const partialFlowLogs = clientWith(compliantClient(), {});
  partialFlowLogs.listFlowLogs = async () => ({ items: [ENABLED_FLOW_LOG], truncated: true, seen: 1, total: 3 });
  const flowLogs = (await assessAzureNetworkAndPolicy(partialFlowLogs)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.equal(flowLogs.status, "warn");
  assert.match(flowLogs.summary, /Inventory of flow logs is partial \(1 seen of 3 total\)/);
  assert.equal(flowLogs.evidence.truncated, true);
});

test("AZURE-NP-04 reads flow logs per Network Watcher and judges enabled targetResourceId coverage", async () => {
  const calls = [];
  const client = clientWith(compliantClient(), {});
  const secondNsgId = "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-2";
  client.listNetworkSecurityGroups = async () => [{ id: NSG_ID, name: "nsg-1", properties: {} }, { id: secondNsgId, name: "nsg-2", properties: {} }];
  client.listNetworkWatchers = async () => [
    { id: WATCHER_ID, name: "NetworkWatcher_eastus", location: "eastus" },
    { id: "/subscriptions/sub-123/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_westus", name: "NetworkWatcher_westus", location: "westus" },
  ];
  client.listFlowLogs = async (resourceGroupName, networkWatcherName) => {
    calls.push([resourceGroupName, networkWatcherName]);
    return networkWatcherName === "NetworkWatcher_eastus"
      ? [ENABLED_FLOW_LOG, { name: "disabled", properties: { enabled: false, targetResourceId: secondNsgId, retentionPolicy: { days: 0, enabled: false } } }]
      : [{ name: "vnet", properties: { enabled: true, targetResourceId: "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1" } }];
  };

  const partialCoverage = (await assessAzureNetworkAndPolicy(client)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.deepEqual(calls, [["NetworkWatcherRG", "NetworkWatcher_eastus"], ["NetworkWatcherRG", "NetworkWatcher_westus"]]);
  assert.equal(partialCoverage.status, "warn");
  assert.match(partialCoverage.summary, /1\/2 NSGs have an enabled flow log \(3 flow logs across 2 Network Watchers, 1 disabled or without a target, 1 enabled flow logs target other resource types/);
  assert.deepEqual(partialCoverage.evidence.uncovered_nsgs, ["nsg-2"]);
  assert.equal(partialCoverage.evidence.flow_log_details[0].retention_days, 90);
  assert.equal(partialCoverage.control, 24);

  client.listFlowLogs = async () => [ENABLED_FLOW_LOG, { ...ENABLED_FLOW_LOG, name: "nsg-2-flowlog", properties: { ...ENABLED_FLOW_LOG.properties, targetResourceId: secondNsgId.toUpperCase() } }];
  assert.equal((await assessAzureNetworkAndPolicy(client)).findings.find((item) => item.id === "AZURE-NP-04").status, "pass");

  client.listFlowLogs = async () => [];
  const uncovered = (await assessAzureNetworkAndPolicy(client)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.equal(uncovered.status, "fail");
  assert.match(uncovered.summary, /0\/2 NSGs have an enabled flow log/);

  client.listFlowLogs = async () => { throw forbidden(); };
  const denied = (await assessAzureNetworkAndPolicy(client)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /networkWatchers\/\{networkWatcherName\}\/flowLogs returned 403 Forbidden/);
  assert.match(denied.evidence.documentation, /flow-logs\/list/);

  client.listFlowLogs = async () => [ENABLED_FLOW_LOG];
  client.listNetworkWatchers = async () => [{ id: "nw-1", name: "odd", location: "eastus" }];
  const unparsed = (await assessAzureNetworkAndPolicy(client)).findings.find((item) => item.id === "AZURE-NP-04");
  assert.equal(unparsed.status, "manual");
  assert.deepEqual(unparsed.evidence.unparsed_watchers, ["odd"]);

  assert.deepEqual(parseNetworkWatcherId(WATCHER_ID), { resourceGroupName: "NetworkWatcherRG", networkWatcherName: "NetworkWatcher_eastus" });
  assert.equal(parseNetworkWatcherId("/subscriptions/sub/providers/Microsoft.Network/networkWatchers/nw"), undefined);
});

test("AZURE-DP-03 reads the beta sensitivity label endpoint and states the beta caveat", async () => {
  const labels = (await assessAzureDataProtection(compliantClient())).findings.find((item) => item.id === "AZURE-DP-03");
  assert.equal(labels.status, "pass");
  assert.match(labels.summary, /Graph beta endpoint/);
  assert.equal(labels.evidence.endpoint, "GET /beta/security/informationProtection/sensitivityLabels");
  assert.match(labels.evidence.documentation, /view=graph-rest-beta/);

  const denied = clientWith(compliantClient(), {});
  denied.listSensitivityLabels = async () => { throw forbidden(); };
  const manual = (await assessAzureDataProtection(denied)).findings.find((item) => item.id === "AZURE-DP-03");
  assert.equal(manual.status, "manual");
  assert.equal(manual.evidence.endpoint, "GET /beta/security/informationProtection/sensitivityLabels");
});

/**
 * Rule 1 corollary: every verdict that reads more than one inventory is denied one secondary at a time while the
 * primary and everything else stay healthy. The named findings must render manual (naming the endpoint) or the
 * stated status, and no other finding may move off the compliant baseline.
 */
const SECONDARY_DENIALS = [
  { method: "getSecurityDefaultsPolicy", assessor: assessAzureIdentity, expect: { "AZURE-ID-01": "pass", "AZURE-ID-02": "pass" }, nullFields: ["security_defaults_enabled"], note: /Security defaults could not be read \(GET \/v1\.0\/policies\/identitySecurityDefaultsEnforcementPolicy returned 403 Forbidden\)/ },
  { method: "listDirectoryRoleMembers", assessor: assessAzureIdentity, expect: { "AZURE-ID-04": "manual" }, nullFields: ["global_administrators", "privileged_role_assignments"], endpoint: "GET /v1.0/directoryRoles/{id}/members" },
  { method: "listRoleEligibilitySchedules", assessor: assessAzureIdentity, expect: { "AZURE-ID-06": "manual" }, endpoint: "GET /v1.0/roleManagement/directory/roleEligibilitySchedules" },
  { method: "listRoleAssignmentSchedules", assessor: assessAzureIdentity, expect: { "AZURE-ID-06": "manual" }, endpoint: "GET /v1.0/roleManagement/directory/roleAssignmentSchedules" },
  { method: "listSubscribedSkus", assessor: assessAzureIdentity, expect: { "AZURE-ID-09": "manual", "AZURE-ID-10": "manual" }, nullFields: ["entra_id_p2_license"], endpoint: "GET /v1.0/subscribedSkus" },
  { method: "listRiskDetections", assessor: assessAzureIdentity, expect: { "AZURE-ID-11": "manual" }, endpoint: "GET /v1.0/identityProtection/riskDetections" },
  { method: "listSecurityAlerts", assessor: assessAzureMonitoring, expect: { "AZURE-MON-04": "pass" }, nullFields: ["security_alerts"], evidence: (item) => assert.equal(item.evidence.alerts_error, "403 Forbidden") },
  { method: "listLogAnalyticsWorkspaces", assessor: assessAzureMonitoring, expect: { "AZURE-MON-06": "manual" }, endpoint: "GET Microsoft.OperationalInsights/workspaces" },
  { method: "listRoleDefinitions", assessor: assessAzureSubscriptionGuardrails, expect: { "AZURE-SUB-01": "manual", "AZURE-SUB-02": "manual", "AZURE-SUB-05": "manual" }, nullFields: ["owner_assignments", "contributor_assignments", "privileged_service_principals"], endpoint: "GET Microsoft.Authorization/roleDefinitions" },
  { method: "listSubscribedSkus", assessor: assessAzureDataProtection, expect: { "AZURE-DP-01": "manual" }, nullFields: ["intune_license"], endpoint: "GET /v1.0/subscribedSkus" },
  { method: "listDeviceCompliancePolicies", assessor: assessAzureDataProtection, expect: { "AZURE-DP-01": "manual" }, nullFields: ["compliance_policies"], endpoint: "GET /v1.0/deviceManagement/deviceCompliancePolicies" },
  { method: "listManagedDevices", assessor: assessAzureDataProtection, expect: { "AZURE-DP-01": "manual" }, nullFields: ["managed_devices"], endpoint: "GET /v1.0/deviceManagement/managedDevices" },
  { method: "listInboxMessageRules", assessor: assessAzureDataProtection, expect: { "AZURE-DP-06": "manual" }, endpoint: "GET /v1.0/users/{id}/mailFolders/inbox/messageRules" },
  { method: "listNetworkWatchers", assessor: assessAzureNetworkAndPolicy, expect: { "AZURE-NP-04": "manual" }, nullFields: ["network_watchers", "flow_logs"], endpoint: "GET Microsoft.Network/networkWatchers" },
  { method: "listFlowLogs", assessor: assessAzureNetworkAndPolicy, expect: { "AZURE-NP-04": "manual" }, nullFields: ["flow_logs"], endpoint: "GET Microsoft.Network/networkWatchers/{networkWatcherName}/flowLogs" },
];

test("rule 1 corollary: denying one secondary read at a time never passes the dependent finding silently and never moves unrelated findings", async () => {
  const baselines = new Map();
  for (const assessor of new Set(SECONDARY_DENIALS.map((scenario) => scenario.assessor))) {
    baselines.set(assessor, statusesById(await assessor(compliantClient())));
  }

  for (const scenario of SECONDARY_DENIALS) {
    const label = `${scenario.method} -> ${Object.keys(scenario.expect).join(",")}`;
    const client = clientWith({ ...compliantClient(), [scenario.method]: async () => { throw forbidden(); } });
    const result = await scenario.assessor(client);
    const statuses = statusesById(result);
    const baseline = baselines.get(scenario.assessor);
    for (const [id, status] of Object.entries(scenario.expect)) {
      const item = result.findings.find((entry) => entry.id === id);
      assert.equal(item.status, status, `${label}: ${id} was ${item.status}: ${item.summary}`);
      if (status === "manual") {
        assert.match(item.summary, /403 Forbidden/, `${label}: ${id}`);
        assert.ok(item.evidence.required_access, `${label}: ${id} names the access to grant`);
        if (scenario.endpoint) assert.equal(item.evidence.endpoint, scenario.endpoint, `${label}: ${id}`);
        assert.ok(result.errors.some((error) => error.startsWith(`${id} `) && error.includes("403 Forbidden")), `${label}: ${id} recorded in errors`);
      }
      if (scenario.note) assert.match(item.summary, scenario.note, `${label}: ${id}`);
      scenario.evidence?.(item);
    }
    for (const [id, status] of Object.entries(baseline)) {
      if (id in scenario.expect) continue;
      assert.equal(statuses[id], status, `${label}: unrelated ${id} moved from ${status} to ${statuses[id]}`);
    }
    for (const field of scenario.nullFields ?? []) {
      assert.equal(result.summary[field], null, `${label}: summary ${field} must be null, not a value derived from the empty fallback`);
    }
  }
});

test("rule 1 corollary: every assessment summary renders null, never zero, for an inventory whose read failed", async () => {
  const cases = [
    [assessAzureIdentity, "listConditionalAccessPolicies", ["enabled_conditional_access_policies", "report_only_conditional_access_policies", "mfa_conditional_access_policies", "legacy_auth_block_policies"]],
    [assessAzureIdentity, "listDirectoryRoles", ["global_administrators", "privileged_role_assignments"]],
    [assessAzureIdentity, "listGuestUsers", ["guests"]],
    [assessAzureMonitoring, "listSecureScores", ["secure_score_ratio"]],
    [assessAzureMonitoring, "listDefenderPricings", ["defender_standard_plans", "defender_total_plans"]],
    [assessAzureMonitoring, "listDiagnosticSettings", ["effective_diagnostic_settings"]],
    [assessAzureMonitoring, "listDirectoryAudits", ["directory_audits"]],
    [assessAzureSubscriptionGuardrails, "listRoleAssignments", ["owner_assignments", "contributor_assignments", "inspected_assignments", "privileged_service_principals"]],
    [assessAzureNetworkAndPolicy, "listNetworkSecurityGroups", ["network_security_groups", "flow_logs"]],
    [assessAzureNetworkAndPolicy, "listPolicyAssignments", ["policy_assignments"]],
    [assessAzureDataProtection, "listKeyVaults", ["key_vaults"]],
    [assessAzureDataProtection, "listMemberUsers", ["mailboxes_sampled"]],
  ];
  for (const [assessor, method, fields] of cases) {
    const result = await assessor(clientWith({ ...compliantClient(), [method]: async () => { throw forbidden(); } }));
    for (const field of fields) {
      assert.equal(result.summary[field], null, `${assessor.name} with ${method} denied: summary ${field} is null`);
    }
  }
});

test("rule 1 corollary: AZURE-ID-01 and AZURE-ID-02 never call security defaults off when the read failed", async () => {
  const defaultsDenied = clientWith({ ...compliantClient(), getSecurityDefaultsPolicy: async () => { throw forbidden(); } });
  const withPolicies = await assessAzureIdentity(defaultsDenied);
  for (const id of ["AZURE-ID-01", "AZURE-ID-02"]) {
    const item = withPolicies.findings.find((entry) => entry.id === id);
    assert.equal(item.status, "pass", id);
    assert.doesNotMatch(item.summary, /security defaults are off/, id);
    assert.match(item.summary, /Security defaults could not be read \(GET \/v1\.0\/policies\/identitySecurityDefaultsEnforcementPolicy returned 403 Forbidden\)\./, id);
    assert.equal(item.evidence.security_defaults_readable, false, id);
    assert.equal(item.evidence.security_defaults_enabled, false, id);
    assert.equal(item.evidence.security_defaults_error, "403 Forbidden", id);
  }
  assert.deepEqual(withPolicies.errors, ["AZURE-ID-01 GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy: 403 Forbidden"]);

  // With no qualifying Conditional Access policy the verdict rests on the unreadable read: manual, not a false fail.
  const noPolicies = clientWith({ ...compliantClient(), getSecurityDefaultsPolicy: async () => { throw forbidden(); }, listConditionalAccessPolicies: async () => [] });
  const unknown = await assessAzureIdentity(noPolicies);
  const mfa = unknown.findings.find((entry) => entry.id === "AZURE-ID-01");
  assert.equal(mfa.status, "manual");
  assert.match(mfa.summary, /^No enabled MFA Conditional Access policy was found and GET \/v1\.0\/policies\/identitySecurityDefaultsEnforcementPolicy returned 403 Forbidden\. Grant Policy\.Read\.All/);
  assert.doesNotMatch(mfa.summary, /security defaults are off/);
  assert.equal(mfa.evidence.endpoint, "GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy");
  assert.equal(mfa.evidence.total_policies, 0);
  assert.equal(mfa.evidence.security_defaults_readable, false);
  const legacy = unknown.findings.find((entry) => entry.id === "AZURE-ID-02");
  assert.equal(legacy.status, "manual");
  assert.match(legacy.summary, /^No enabled Conditional Access policy blocks exchangeActiveSync\/other client app types and GET \/v1\.0\/policies\/identitySecurityDefaultsEnforcementPolicy returned 403 Forbidden\./);
  assert.doesNotMatch(legacy.summary, /security defaults are off/);

  // A readable "off" answer with no policies still fails with the original wording.
  const off = clientWith({ ...compliantClient(), listConditionalAccessPolicies: async () => [] });
  const offResult = await assessAzureIdentity(off);
  assert.equal(offResult.findings.find((entry) => entry.id === "AZURE-ID-01").status, "fail");
  assert.match(offResult.findings.find((entry) => entry.id === "AZURE-ID-01").summary, /security defaults are off/);
  assert.match(offResult.findings.find((entry) => entry.id === "AZURE-ID-02").summary, /security defaults are off/);
  assert.equal(offResult.errors.length, 0);
});

test("rule 1 corollary: AZURE-DP-06 reports denied mailboxes as a MailboxSettings.Read gap, separately from mailboxes without Exchange", async () => {
  const users = [
    { id: "u-ok", userPrincipalName: "alice@example.com" },
    { id: "u-denied", userPrincipalName: "bob@example.com" },
    { id: "u-nomailbox", userPrincipalName: "svc@example.com" },
  ];
  const notFound = () => new azureModule.AzureApiError("404 Not Found: MailboxNotEnabledForRESTAPI", "https://graph.microsoft.com/v1.0/users/u-nomailbox/mailFolders/inbox/messageRules", 404);
  const client = clientWith({
    ...compliantClient(),
    listMemberUsers: async () => users,
    listInboxMessageRules: async (userId) => {
      if (userId === "u-denied") throw forbidden();
      if (userId === "u-nomailbox") throw notFound();
      return [{ id: "rule-1", displayName: "Archive", isEnabled: true, actions: { moveToFolder: "archive" } }];
    },
  });
  const result = await assessAzureDataProtection(client);
  const rules = result.findings.find((item) => item.id === "AZURE-DP-06");
  assert.equal(rules.status, "warn");
  assert.doesNotMatch(rules.summary, /likely without an Exchange mailbox/);
  assert.match(rules.summary, /0 enabled inbox rules forward or redirect mail across 1 readable mailboxes \(2 unreadable: 1 denied with 403 Forbidden, so MailboxSettings\.Read \(application\) is missing for those mailboxes and their rules were not inspected; 1 returned a non-permission error \(404 Not Found: MailboxNotEnabledForRESTAPI; commonly users without an Exchange mailbox\); verdict capped at warn\)\./);
  assert.equal(rules.evidence.mailboxes_read, 1);
  assert.equal(rules.evidence.mailboxes_unreadable, 2);
  assert.equal(rules.evidence.mailboxes_permission_denied, 1);
  assert.equal(rules.evidence.mailboxes_other_errors, 1);
  assert.deepEqual(rules.evidence.permission_failure, { endpoint: "GET /v1.0/users/{id}/mailFolders/inbox/messageRules", http_status: 403, required_access: "MailboxSettings.Read (application)", error: "403 Forbidden: Insufficient privileges" });
  assert.deepEqual(result.errors, [
    "AZURE-DP-06 GET /v1.0/users/{id}/mailFolders/inbox/messageRules: 403 Forbidden on 1 of 3 mailboxes",
    "AZURE-DP-06 GET /v1.0/users/{id}/mailFolders/inbox/messageRules: 404 Not Found: MailboxNotEnabledForRESTAPI on 1 of 3 mailboxes",
  ]);
  assert.deepEqual(rules.evidence.other_failure, { endpoint: "GET /v1.0/users/{id}/mailFolders/inbox/messageRules", http_status: 404, error: "404 Not Found: MailboxNotEnabledForRESTAPI" });

  // Only non-permission failures keep the "no Exchange mailbox" explanation; the failed read is still logged so the bundle names it.
  const onlyMissing = clientWith({ ...compliantClient(), listMemberUsers: async () => users.slice(0, 1).concat(users.slice(2)), listInboxMessageRules: async (userId) => { if (userId === "u-nomailbox") throw notFound(); return []; } });
  const missingResult = await assessAzureDataProtection(onlyMissing);
  const missing = missingResult.findings.find((item) => item.id === "AZURE-DP-06");
  assert.equal(missing.status, "warn");
  assert.match(missing.summary, /\(1 unreadable: 1 returned a non-permission error \(404 Not Found: MailboxNotEnabledForRESTAPI; commonly users without an Exchange mailbox\); verdict capped at warn\)/);
  assert.equal(missing.evidence.permission_failure, null);
  assert.deepEqual(missingResult.errors, ["AZURE-DP-06 GET /v1.0/users/{id}/mailFolders/inbox/messageRules: 404 Not Found: MailboxNotEnabledForRESTAPI on 1 of 2 mailboxes"]);

  // Forwarding rules found alongside a denied subset still fail, and the denial stays named without the warn cap text.
  const leaking = clientWith({ ...compliantClient(), listMemberUsers: async () => users.slice(0, 2), listInboxMessageRules: async (userId) => { if (userId === "u-denied") throw forbidden(); return [{ displayName: "Leak", isEnabled: true, actions: { forwardTo: [{ emailAddress: { address: "ext@example.net" } }] } }]; } });
  const leak = (await assessAzureDataProtection(leaking)).findings.find((item) => item.id === "AZURE-DP-06");
  assert.equal(leak.status, "fail");
  assert.match(leak.summary, /1 denied with 403 Forbidden, so MailboxSettings\.Read \(application\) is missing/);
  assert.doesNotMatch(leak.summary, /verdict capped at warn/);
});

test("azure_assess_data_protection and azure_assess_network_and_policy are registered under the Azure group", () => {
  const tools = getRegisteredToolSummaries();
  const azureTools = tools.filter((tool) => tool.group === "Azure").map((tool) => tool.name).sort();
  assert.deepEqual(azureTools, [
    "azure_assess_data_protection",
    "azure_assess_identity",
    "azure_assess_monitoring",
    "azure_assess_network_and_policy",
    "azure_assess_subscription_guardrails",
    "azure_check_access",
    "azure_export_audit_bundle",
  ]);
  const group = groupRegisteredTools(tools).find((entry) => entry.group === "Azure");
  assert.equal(group.tools.length, 7);
  const guardrails = tools.find((tool) => tool.name === "azure_assess_subscription_guardrails");
  assert.ok(!guardrails.parameterSummaries.some((parameter) => parameter.name === "max_mailboxes"));
  const dataProtection = tools.find((tool) => tool.name === "azure_assess_data_protection");
  assert.ok(dataProtection.parameterSummaries.some((parameter) => parameter.name === "max_mailboxes"));
});

test("verdict safety 6: documented flags drive the verdict", async () => {
  const client = clientWith(compliantClient(), {});
  client.listConditionalAccessPolicies = async () => [{ ...CA_MFA, state: "enabledForReportingButNotEnforced" }, { ...CA_LEGACY, state: "enabledForReportingButNotEnforced" }];
  const identity = statusesById(await assessAzureIdentity(client));
  assert.equal(identity["AZURE-ID-01"], "fail");
  assert.equal(identity["AZURE-ID-02"], "fail");

  const unsetFlags = clientWith(compliantClient(), {});
  unsetFlags.listKeyVaults = async () => [{ name: "kv", properties: { enableSoftDelete: true } }];
  unsetFlags.listStorageAccounts = async () => [{ name: "st", properties: { supportsHttpsTrafficOnly: true, minimumTlsVersion: "TLS1_2" } }];
  unsetFlags.listDiagnosticSettings = async () => [{ id: "diag", properties: { workspaceId: "/w", logs: [{ category: "Administrative", enabled: false }] } }];
  const data = statusesById(await assessAzureDataProtection(unsetFlags));
  assert.equal(data["AZURE-DP-04"], "fail");
  assert.equal(data["AZURE-DP-05"], "warn");
  const monitoring = statusesById(await assessAzureMonitoring(unsetFlags));
  assert.equal(monitoring["AZURE-MON-05"], "fail");

  const defaults = clientWith(compliantClient(), {});
  defaults.getSecurityDefaultsPolicy = async () => ({ isEnabled: true });
  defaults.listConditionalAccessPolicies = async () => [];
  const withDefaults = statusesById(await assessAzureIdentity(defaults));
  assert.equal(withDefaults["AZURE-ID-01"], "pass");
});

test("fully compliant fixture (d) passes every automatable control", async () => {
  const expectedManual = new Set([...ALWAYS_MANUAL]);
  for (const [name, run] of ASSESSORS) {
    const result = await run(compliantClient());
    assert.equal(result.errors.length, 0, name);
    for (const item of result.findings) {
      assert.equal(item.status, expectedManual.has(item.id) ? "manual" : "pass", `${name} ${item.id}: ${item.summary}`);
    }
  }
});

test("all 25 spec controls are covered by at least one finding", async () => {
  const controls = new Set();
  for (const [, run] of ASSESSORS) {
    for (const item of (await run(compliantClient())).findings) controls.add(item.control);
  }
  for (let control = 1; control <= 25; control += 1) assert.ok(controls.has(control), `control ${control}`);
});

test("exportAzureAuditBundle writes the shared layout, compliance reports, and archive", async () => {
  const base = createTempBase("grclanker-azure-export-");
  const result = await exportAzureAuditBundle(compliantClient(), sampleConfig(), base, { max_assignments: 25 });
  assert.ok(result.outputDir.startsWith(realpathSync(base)));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.errorCount, 0);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  // The prior reports/ folder moved to the shared compliance/ layout used across integrations.
  const executiveSummary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executiveSummary, /Azure Audit Bundle/);
  assert.match(executiveSummary, /Spec controls covered: 25 of 25/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8"), /FedRAMP/);
  for (const framework of ["fedramp", "cmmc", "soc2", "cis_azure", "pci_dss", "disa_stig", "irap", "ismap"]) {
    assert.ok(existsSync(join(result.outputDir, "compliance", `${framework}.md`)), framework);
  }
  assert.ok(existsSync(join(result.outputDir, "QUICK_REFERENCE.md")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "access.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "metadata.json")));
  const findingsJson = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.ok(Array.isArray(findingsJson));
  assert.equal(findingsJson.length, result.findingCount);
  assert.doesNotMatch(readFileSync(join(result.outputDir, "core_data", "metadata.json"), "utf8"), /graph-token|arm-token/);
});

const FAKE_AZURE_SECRETS = {
  clientSecret: "FAKE-CLIENT-SECRET-g7h8i9",
  graphToken: "FAKE-GRAPH-TOKEN-a1b2c3",
  managementToken: "FAKE-ARM-TOKEN-d4e5f6",
  passwordHint: "FAKEHINT9",
  secretText: "FAKE-SECRET-TEXT-j0k1l2",
  keyBlob: "FAKE-KEY-BLOB-m3n4o5",
  errorEcho: "FAKE-ERROR-ECHO-p6q7r8",
};

/** Routes a real AzureAuditorClient through Graph and ARM responses that carry every fake secret above. */
function secretBearingFetch() {
  const credentialCarrier = {
    id: "sp-1",
    appId: "app-1",
    displayName: "Automation",
    owners: [{ id: "user-1" }],
    passwordCredentials: [{ keyId: "k1", hint: FAKE_AZURE_SECRETS.passwordHint, secretText: FAKE_AZURE_SECRETS.secretText, startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-01T00:00:00Z" }],
    keyCredentials: [{ keyId: "k2", type: "AsymmetricX509Cert", usage: "Verify", key: FAKE_AZURE_SECRETS.keyBlob, startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" }],
  };
  return async (url, init = {}) => {
    if (url.endsWith("/oauth2/v2.0/token")) {
      const scope = new URLSearchParams(init.body).get("scope");
      return new Response(JSON.stringify({ token_type: "Bearer", expires_in: 3599, access_token: scope.startsWith("https://graph") ? FAKE_AZURE_SECRETS.graphToken : FAKE_AZURE_SECRETS.managementToken }), { status: 200 });
    }
    if (url.includes("/v1.0/organization")) return new Response(JSON.stringify({ value: [{ id: "org-1", displayName: "Contoso" }] }), { status: 200 });
    if (url.includes("/v1.0/servicePrincipals") || url.includes("/v1.0/applications")) return new Response(JSON.stringify({ value: [credentialCarrier] }), { status: 200 });
    if (url.includes("/v1.0/identity/conditionalAccess/policies")) return new Response(JSON.stringify({ value: [CA_MFA, CA_LEGACY] }), { status: 200 });
    if (url.includes("/policies/identitySecurityDefaultsEnforcementPolicy")) return new Response(JSON.stringify({ isEnabled: false }), { status: 200 });
    if (url.includes("Microsoft.KeyVault/vaults")) {
      return new Response(JSON.stringify({ error: { code: "AuthorizationFailed", message: "The client does not have authorization to perform action 'Microsoft.KeyVault/vaults/read'.", innerError: { echo: FAKE_AZURE_SECRETS.errorEcho } } }), { status: 403, statusText: "Forbidden" });
    }
    return new Response(JSON.stringify({ value: [] }), { status: 200 });
  };
}

test("rule 9: the exported bundle and its zip never contain tokens, the client secret, credential hints, key blobs, or raw error bodies", async () => {
  const config = resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-123", AZURE_SUBSCRIPTION_ID: "sub-123", AZURE_CLIENT_ID: "client-123", AZURE_CLIENT_SECRET: FAKE_AZURE_SECRETS.clientSecret },
    () => undefined,
  );
  const client = new AzureAuditorClient(config, { fetchImpl: secretBearingFetch(), now: () => NOW });
  const base = createTempBase("grclanker-azure-secrets-");
  const result = await exportAzureAuditBundle(client, config, base);

  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 20, `bundle wrote ${files.size} files`);
  assert.equal(zipEntries.size, files.size, "every bundle file is in the archive");
  assertSecretsAbsent(assert, files, Object.values(FAKE_AZURE_SECRETS), "bundle file");
  assertSecretsAbsent(assert, zipEntries, Object.values(FAKE_AZURE_SECRETS), "zip entry");
  for (const [name, text] of files) {
    assert.ok(!/"(hint|secretText|key|customKeyIdentifier)"\s*:/.test(text), `${name} carries a raw credential property`);
  }

  // The credential-bearing records were collected and judged, so the scan covered the live path rather than an empty fixture.
  const identity = JSON.parse(files.get("analysis/identity.json"));
  const hygiene = identity.findings.find((item) => item.id === "AZURE-ID-05");
  assert.equal(hygiene.status, "pass");
  assert.equal(hygiene.evidence.seen, 1);
  const errorsLog = files.get("_errors.log");
  assert.match(errorsLog, /AZURE-DP-04 GET Microsoft\.KeyVault\/vaults: 403 Forbidden/);
  const dataProtection = JSON.parse(files.get("analysis/data-protection.json"));
  const vaults = dataProtection.findings.find((item) => item.id === "AZURE-DP-04");
  assert.equal(vaults.status, "manual");
  assert.equal(vaults.evidence.error, "403 Forbidden: AuthorizationFailed: The client does not have authorization to perform action 'Microsoft.KeyVault/vaults/read'.");
  assert.doesNotMatch(files.get("core_data/metadata.json"), /client-123.*secret|access_token/i);
});

/** One key per documented surface: Graph paths, ARM paths, the two user lists (by $filter), and the token endpoint. */
function azureSurfaceKey(urlString) {
  const url = new URL(urlString);
  if (url.pathname === "/v1.0/users") return url.searchParams.get("$filter")?.includes("Guest") ? "/v1.0/users(guest)" : "/v1.0/users(member)";
  return url.pathname;
}

const AZURE_TOKEN_PATH = "/tenant-123/oauth2/v2.0/token";
const AZURE_SUB = "/subscriptions/sub-123";
const CANARY_WATCHER_ID = `${AZURE_SUB}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus`;

/** Healthy answers for every surface the access check and the five collectors read; dependent reads are reachable. */
function healthyAzureRoutes() {
  const list = (value) => () => new Response(JSON.stringify({ value }), { status: 200 });
  const object = (value) => () => new Response(JSON.stringify(value), { status: 200 });
  return {
    [AZURE_TOKEN_PATH]: () => new Response(JSON.stringify({ token_type: "Bearer", expires_in: 3599, access_token: "token-from-endpoint-1234567890" }), { status: 200 }),
    "/v1.0/organization": list([{ id: "org-1", displayName: "Contoso" }]),
    "/v1.0/identity/conditionalAccess/policies": list([CA_MFA, CA_LEGACY, CA_SIGNIN_RISK, CA_USER_RISK, CA_COMPLIANT_DEVICE]),
    "/v1.0/reports/authenticationMethods/userRegistrationDetails": list([{ id: "user-1", isMfaRegistered: true }]),
    "/v1.0/directoryRoles": list([{ id: "role-ga", displayName: "Global Administrator", roleTemplateId: "62e90394-69f5-4237-9190-012177145e10" }]),
    "/v1.0/directoryRoles/role-ga/members": list([{ id: "user-1" }, { id: "user-2" }]),
    "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": object({ isEnabled: false }),
    "/v1.0/policies/authorizationPolicy": object({ allowInvitesFrom: "adminsAndGuestInviters", defaultUserRolePermissions: { allowedToCreateApps: false } }),
    "/v1.0/servicePrincipals": list([]),
    "/v1.0/applications": list([]),
    "/v1.0/oauth2PermissionGrants": list([]),
    "/v1.0/users(guest)": list([]),
    "/v1.0/users(member)": list([{ id: "user-1", userPrincipalName: "user-1@contoso.example", mail: "user-1@contoso.example" }]),
    "/v1.0/users/user-1/mailFolders/inbox/messageRules": list([]),
    "/v1.0/identityProtection/riskyUsers": list([]),
    "/v1.0/identityProtection/riskDetections": list([]),
    "/v1.0/subscribedSkus": list([{ skuPartNumber: "EMSPREMIUM", servicePlans: [{ servicePlanName: "AAD_PREMIUM_P2", provisioningStatus: "Success" }, { servicePlanName: "INTUNE_A", provisioningStatus: "Success" }] }]),
    "/v1.0/roleManagement/directory/roleEligibilitySchedules": list([{ id: "el-1" }]),
    "/v1.0/roleManagement/directory/roleAssignmentSchedules": list([]),
    "/v1.0/deviceManagement/deviceCompliancePolicies": list([{ id: "cp-1" }]),
    "/v1.0/deviceManagement/managedDevices": list([{ id: "d-1", complianceState: "compliant", lastSyncDateTime: NOW.toISOString() }]),
    "/beta/security/informationProtection/sensitivityLabels": list([{ id: "label-1" }]),
    "/v1.0/admin/sharepoint/settings": object({ sharingCapability: "externalUserSharingOnly" }),
    "/v1.0/security/secureScores": list([{ currentScore: 80, maxScore: 100 }]),
    "/v1.0/security/alerts_v2": list([]),
    "/v1.0/auditLogs/directoryAudits": list([{ id: "audit-1" }]),
    "/v1.0/auditLogs/signIns": list([{ id: "signin-1" }]),
    [`${AZURE_SUB}/providers/Microsoft.Security/pricings`]: list([{ name: "VirtualMachines", properties: { pricingTier: "Standard" } }]),
    [`${AZURE_SUB}/providers/Microsoft.Insights/diagnosticSettings`]: list([]),
    [`${AZURE_SUB}/providers/Microsoft.OperationalInsights/workspaces`]: list([]),
    [`${AZURE_SUB}/providers/Microsoft.Security/securityContacts`]: list([{ properties: { emails: "secops@contoso.example" } }]),
    [`${AZURE_SUB}/providers/Microsoft.Authorization/roleAssignments`]: list([{ properties: { roleDefinitionId: "role-owner", principalType: "User" } }]),
    [`${AZURE_SUB}/providers/Microsoft.Authorization/roleDefinitions`]: list([{ name: "role-owner", properties: { roleName: "Owner" } }]),
    [`${AZURE_SUB}/providers/Microsoft.Network/networkWatchers`]: list([{ id: CANARY_WATCHER_ID, name: "NetworkWatcher_eastus", location: "eastus" }]),
    [`${AZURE_SUB}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus/flowLogs`]: list([ENABLED_FLOW_LOG]),
    [`${AZURE_SUB}/providers/Microsoft.Network/networkSecurityGroups`]: list([{ id: NSG_ID, name: "nsg-1", properties: { securityRules: [] } }]),
    [`${AZURE_SUB}/providers/Microsoft.KeyVault/vaults`]: list([]),
    [`${AZURE_SUB}/providers/Microsoft.Storage/storageAccounts`]: list([]),
    [`${AZURE_SUB}/providers/Microsoft.Authorization/policyAssignments`]: list([]),
    [`${AZURE_SUB}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize`]: list([]),
  };
}

function azureRoutedFetch(routes, seen = new Set()) {
  return async (url) => {
    const key = azureSurfaceKey(url);
    seen.add(key);
    const route = routes[key];
    if (!route) throw new Error(`Unexpected Azure request: ${url}`);
    return route();
  };
}

function canaryHtmlResponse() {
  return new Response(htmlCanaryBody(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function canaryJsonResponse(key) {
  const body = key === AZURE_TOKEN_PATH
    ? { error: "invalid_client", error_description: jsonCanaryMessage() }
    : { error: { code: "AuthorizationFailed", message: jsonCanaryMessage() } };
  return new Response(JSON.stringify(body), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
}

function canaryConfig() {
  return resolveAzureConfiguration(
    {},
    { AZURE_TENANT_ID: "tenant-123", AZURE_SUBSCRIPTION_ID: "sub-123", AZURE_CLIENT_ID: "client-123", AZURE_CLIENT_SECRET: "canary-client-secret-value-1" },
    () => undefined,
  );
}

async function runEveryAzureTool(client, config, outputRoot) {
  const access = await checkAzureAccess(client);
  const assessments = [];
  for (const [, assess] of ASSESSORS) assessments.push(await assess(client));
  const exported = await exportAzureAuditBundle(client, config, outputRoot);
  return { access, assessments, exported };
}

test("rule 9: a 502 HTML page or a JSON error message carrying credentials on any surface never reaches a probe, finding, summary, or bundle file", async () => {
  const config = canaryConfig();
  const outputRoot = createTempBase("grclanker-azure-canary-");

  // The healthy run proves the route table is the surface list: every route is requested and nothing else is.
  const healthySeen = new Set();
  const healthy = new AzureAuditorClient(config, { fetchImpl: azureRoutedFetch(healthyAzureRoutes(), healthySeen), now: () => NOW });
  const healthyRun = await runEveryAzureTool(healthy, config, outputRoot);
  assert.equal(healthyRun.exported.errorCount, 0, "the healthy fixture records no errors");
  const surfaces = Object.keys(healthyAzureRoutes());
  assert.deepEqual([...healthySeen].sort(), [...surfaces].sort(), "every documented surface is exercised by the access check, the collectors, or the export");
  const accessSurfaces = new Set();
  await checkAzureAccess(new AzureAuditorClient(config, { fetchImpl: azureRoutedFetch(healthyAzureRoutes(), accessSurfaces), now: () => NOW }));
  const collectorSurfaces = new Set();
  const collectorClient = new AzureAuditorClient(config, { fetchImpl: azureRoutedFetch(healthyAzureRoutes(), collectorSurfaces), now: () => NOW });
  for (const [, assess] of ASSESSORS) await assess(collectorClient);
  assert.equal(accessSurfaces.size, 9, "the access check probes eight surfaces plus the token endpoint");
  assert.ok(collectorSurfaces.size >= surfaces.length - 1, "every surface but the organization probe is read by a collector");

  for (const surface of surfaces) {
    for (const [variant, response, expectedNote] of [
      ["html", canaryHtmlResponse, HTML_BODY_NOTE],
      ["json", () => canaryJsonResponse(surface), REDACTED_CANARY_URL],
    ]) {
      const label = `${surface} (${variant})`;
      const client = new AzureAuditorClient(config, { fetchImpl: azureRoutedFetch({ ...healthyAzureRoutes(), [surface]: response }), now: () => NOW });
      const { access, assessments, exported } = await runEveryAzureTool(client, config, createTempBase("grclanker-azure-canary-"));

      assertNoCanaries(assert, access, `${label} check_access`);
      if (accessSurfaces.has(surface)) {
        const failed = access.surfaces.filter((entry) => entry.status === "not_readable");
        assert.ok(failed.length > 0, `${label}: the access check records the failing surface`);
        for (const entry of failed) assert.match(entry.error, expectedNote, `${label}: probe ${entry.name} carries the expected note`);
      }

      const recorded = [];
      for (const assessment of assessments) {
        assertNoCanaries(assert, assessment, `${label} ${assessment.title}`);
        recorded.push(...assessment.errors);
        for (const finding of assessment.findings) {
          for (const evidenceError of [finding.evidence?.error, finding.evidence?.alerts_error, finding.evidence?.permission_failure?.error, finding.evidence?.other_failure?.error]) {
            if (typeof evidenceError === "string") recorded.push(evidenceError);
          }
        }
      }
      if (collectorSurfaces.has(surface)) {
        assert.ok(recorded.length > 0, `${label}: the failing surface is recorded by a collector`);
      }
      if (variant === "html") {
        for (const error of recorded) assert.match(error, HTML_BODY_NOTE, `${label}: "${error}" carries the status-and-length note`);
      } else {
        // describeFailure drops the message for 401/402/403; wherever the message does survive, only the redacted URL may remain.
        for (const error of recorded.filter((entry) => entry.includes("api.example.com"))) {
          assert.match(error, REDACTED_CANARY_URL, `${label}: the JSON message survives only with its query redacted`);
        }
      }

      const files = readBundleFiles(exported.outputDir);
      assertNoCanariesInFiles(assert, files, `${label} bundle`);
      assertNoCanariesInFiles(assert, readZipEntries(exported.zipPath), `${label} zip`);
      if (recorded.length > 0) {
        assert.ok(exported.errorCount > 0, `${label}: the export logs the failed read`);
        if (variant === "html") assert.match(files.get("_errors.log"), /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes\)/);
      }
    }
  }
});

test("verdict safety 8: re-running the export never overwrites a prior bundle and logs errors on partial failure", async () => {
  const base = createTempBase("grclanker-azure-rerun-");
  const first = await exportAzureAuditBundle(compliantClient(), sampleConfig(), base);
  const marker = readFileSync(join(first.outputDir, "QUICK_REFERENCE.md"), "utf8");

  const failing = clientWith(compliantClient(), {});
  failing.listKeyVaults = async () => { throw forbidden(); };
  const second = await exportAzureAuditBundle(failing, sampleConfig(), base);
  assert.notEqual(second.outputDir, first.outputDir);
  assert.ok(second.outputDir.endsWith("-2"));
  assert.equal(readFileSync(join(first.outputDir, "QUICK_REFERENCE.md"), "utf8"), marker);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath));
  assert.equal(second.errorCount, 1);
  const errorsLog = readFileSync(join(second.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /AZURE-DP-04 GET Microsoft.KeyVault\/vaults: 403 Forbidden/);
  assert.equal(readdirSync(base).filter((entry) => entry.endsWith(".zip")).length, 2);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-azure-output-");
  const nested = resolveSecureOutputPath(base, "bundle");
  assert.ok(nested.startsWith(realpathSync(base)));

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const target = createTempBase("grclanker-azure-symlink-target-");
  const linked = join(base, "linked");
  symlinkSync(target, linked);
  assert.throws(() => resolveSecureOutputPath(base, "linked/out"), /Refusing to use symlinked parent directory/);
});
