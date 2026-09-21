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
  AzureAuditorClient,
  assessAzureDataProtection,
  assessAzureIdentity,
  assessAzureMonitoring,
  assessAzureNetworkAndPolicy,
  assessAzureSubscriptionGuardrails,
  checkAzureAccess,
  exportAzureAuditBundle,
  isExposedAdminRule,
  resolveAzureCloud,
  resolveAzureConfiguration,
  resolveSecureOutputPath,
  toPage,
} from "../dist/extensions/grc-tools/azure.js";

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
  "listRoleAssignments", "listRoleDefinitions", "listSecurityContacts", "listNetworkWatchers", "listDeviceCompliancePolicies", "listManagedDevices",
  "listSensitivityLabels", "listKeyVaults", "listStorageAccounts", "listMemberUsers", "listInboxMessageRules", "getSharePointSettings",
  "listNetworkSecurityGroups", "listPolicyAssignments", "summarizePolicyStates", "getOrganization",
];

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

function forbidden() {
  const error = new Error("403 Forbidden: Insufficient privileges");
  error.name = "AzureApiError";
  error.status = 403;
  return error;
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
    async listNetworkWatchers() { return [{ id: "nw-1", location: "eastus" }]; },
    async listDeviceCompliancePolicies() { return [{ id: "cp-1", displayName: "Windows baseline" }]; },
    async listManagedDevices() { return [{ id: "dev-1", complianceState: "compliant" }]; },
    async listSensitivityLabels() { return [{ id: "label-1", name: "Confidential", isActive: true, hasProtection: true }]; },
    async listKeyVaults() { return [{ name: "kv1", properties: { enableSoftDelete: true, enablePurgeProtection: true, enableRbacAuthorization: true, publicNetworkAccess: "Disabled", networkAcls: { defaultAction: "Deny" } } }]; },
    async listStorageAccounts() { return [{ name: "st1", properties: { supportsHttpsTrafficOnly: true, allowBlobPublicAccess: false, minimumTlsVersion: "TLS1_2", encryption: { keySource: "Microsoft.Keyvault" } } }]; },
    async listMemberUsers() { return [{ id: "user-1", userPrincipalName: "alice@example.com" }]; },
    async listInboxMessageRules() { return [{ id: "rule-1", displayName: "Archive", isEnabled: true, actions: { moveToFolder: "archive" } }]; },
    async getSharePointSettings() { return { sharingCapability: "existingExternalUserSharingOnly", sharingDomainRestrictionMode: "allowList", isResharingByExternalUsersEnabled: false }; },
    async listNetworkSecurityGroups() { return [{ name: "nsg-1", properties: { securityRules: [{ name: "allow-https", properties: { access: "Allow", direction: "Inbound", protocol: "Tcp", sourceAddressPrefix: "Internet", destinationPortRange: "443" } }] } }]; },
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

test("AzureAuditorClient sends the documented request URL and API version for every endpoint", async () => {
  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    requests.push({ url, init });
    return new Response(JSON.stringify({ value: [] }), { status: 200 });
  };
  const client = new AzureAuditorClient(sampleConfig(), { fetchImpl, now: () => NOW });
  const sub = "https://management.azure.com/subscriptions/sub-123";
  const graph = "https://graph.microsoft.com/v1.0";
  const expectations = [
    [() => client.listConditionalAccessPolicies(), `${graph}/identity/conditionalAccess/policies`],
    [() => client.listUserRegistrationDetails(), `${graph}/reports/authenticationMethods/userRegistrationDetails`],
    [() => client.listDirectoryRoles(), `${graph}/directoryRoles`],
    [() => client.listDirectoryRoleMembers("role 1"), `${graph}/directoryRoles/role%201/members`],
    [() => client.getSecurityDefaultsPolicy(), `${graph}/policies/identitySecurityDefaultsEnforcementPolicy`],
    [() => client.getAuthorizationPolicy(), `${graph}/policies/authorizationPolicy`],
    [() => client.listApplications(), `${graph}/applications?$top=999&$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$expand=owners($select=id)`],
    [() => client.listOAuth2PermissionGrants(), `${graph}/oauth2PermissionGrants`],
    [() => client.listGuestUsers(), `${graph}/users?$filter=userType eq 'Guest'&$count=true&$top=999&$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,externalUserState,signInActivity`],
    [() => client.listInboxMessageRules("user-1"), `${graph}/users/user-1/mailFolders/inbox/messageRules`],
    [() => client.listRiskyUsers(), `${graph}/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'`],
    [() => client.listRiskDetections(), `${graph}/identityProtection/riskDetections?$top=500`],
    [() => client.listSubscribedSkus(), `${graph}/subscribedSkus`],
    [() => client.listRoleEligibilitySchedules(), `${graph}/roleManagement/directory/roleEligibilitySchedules`],
    [() => client.listRoleAssignmentSchedules(), `${graph}/roleManagement/directory/roleAssignmentSchedules?$filter=assignmentType eq 'Assigned'`],
    [() => client.listDeviceCompliancePolicies(), `${graph}/deviceManagement/deviceCompliancePolicies`],
    [() => client.listManagedDevices(), `${graph}/deviceManagement/managedDevices?$select=id,deviceName,complianceState,lastSyncDateTime`],
    [() => client.listSensitivityLabels(), `${graph}/security/informationProtection/sensitivityLabels`],
    [() => client.getSharePointSettings(), `${graph}/admin/sharepoint/settings`],
    [() => client.listSecureScores(), `${graph}/security/secureScores?$top=20`],
    [() => client.listDefenderPricings(), `${sub}/providers/Microsoft.Security/pricings?api-version=2024-01-01`],
    [() => client.listDiagnosticSettings(), `${sub}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`],
    [() => client.listLogAnalyticsWorkspaces(), `${sub}/providers/Microsoft.OperationalInsights/workspaces?api-version=2026-03-01`],
    [() => client.listSecurityContacts(), `${sub}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview`],
    [() => client.listRoleAssignments(), `${sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`],
    [() => client.listRoleDefinitions(), `${sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01`],
    [() => client.listNetworkWatchers(), `${sub}/providers/Microsoft.Network/networkWatchers?api-version=2025-09-01`],
    [() => client.listNetworkSecurityGroups(), `${sub}/providers/Microsoft.Network/networkSecurityGroups?api-version=2025-09-01`],
    [() => client.listKeyVaults(), `${sub}/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01`],
    [() => client.listStorageAccounts(), `${sub}/providers/Microsoft.Storage/storageAccounts?api-version=2026-06-01`],
    [() => client.listPolicyAssignments(), `${sub}/providers/Microsoft.Authorization/policyAssignments?api-version=2026-07-01&$filter=atScope()`],
    [() => client.summarizePolicyStates(), `${sub}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2024-10-01`],
  ];
  for (const [call, expectedUrl] of expectations) {
    requests.length = 0;
    await call();
    assert.equal(requests[0].url, expectedUrl);
  }
  requests.length = 0;
  await client.listGuestUsers();
  assert.equal(requests[0].init.headers.ConsistencyLevel, "eventual");
  requests.length = 0;
  await client.summarizePolicyStates();
  assert.equal(requests[0].init.method, "POST");
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
  assert.match(result.recommendedNextStep, /azure_assess_data_protection/);
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
  const compliantByIntent = new Set(["AZURE-ID-08", "AZURE-ID-11", "AZURE-ID-13"]);
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
