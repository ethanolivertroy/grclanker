import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2Checks,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { AZURE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const DOCS = "https://learn.microsoft.com/en-us/graph/api/overview";
const ARM_DOCS = "https://learn.microsoft.com/en-us/rest/api/azure/";
const surfaces = [
  restSurface("conditional-access", "/v1.0/identity/conditionalAccess/policies", "Microsoft Graph", DOCS, ["id", "displayName", "state", "conditions", "grantControls"]),
  restSurface("security-defaults", "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", "Microsoft Graph", DOCS, ["isEnabled"]),
  restSurface("registration-details", "/v1.0/reports/authenticationMethods/userRegistrationDetails", "Microsoft Graph", DOCS, ["id", "userPrincipalName", "isMfaRegistered"]),
  restSurface("directory-roles", "/v1.0/directoryRoles", "Microsoft Graph", DOCS, ["id", "displayName", "roleTemplateId"]),
  restSurface("directory-role-members", "/v1.0/directoryRoles/{id}/members", "Microsoft Graph", DOCS, ["id", "userPrincipalName", "accountEnabled"]),
  restSurface("service-principals", "/v1.0/servicePrincipals", "Microsoft Graph", DOCS, ["id", "displayName", "passwordCredentials", "keyCredentials"]),
  restSurface("pim-eligibilities", "/v1.0/roleManagement/directory/roleEligibilitySchedules", "Microsoft Graph", DOCS, ["principalId", "roleDefinitionId", "scheduleInfo"]),
  restSurface("pim-assignments", "/v1.0/roleManagement/directory/roleAssignmentSchedules", "Microsoft Graph", DOCS, ["principalId", "roleDefinitionId", "assignmentType", "scheduleInfo"]),
  restSurface("authorization-policy", "/v1.0/policies/authorizationPolicy", "Microsoft Graph", DOCS, ["guestUserRoleId", "allowInvitesFrom"]),
  restSurface("guest-users", "/v1.0/users?$filter=userType eq 'Guest'", "Microsoft Graph", DOCS, ["id", "userPrincipalName", "accountEnabled", "signInActivity", "externalUserState"]),
  restSurface("subscribed-skus", "/v1.0/subscribedSkus", "Microsoft Graph", DOCS, ["skuPartNumber", "servicePlans"]),
  restSurface("risky-users", "/v1.0/identityProtection/riskyUsers", "Microsoft Graph", DOCS, ["id", "riskLevel", "riskState"]),
  restSurface("risk-detections", "/v1.0/identityProtection/riskDetections", "Microsoft Graph", DOCS, ["id", "riskLevel", "riskState", "detectedDateTime"]),
  restSurface("applications", "/v1.0/applications?$expand=owners", "Microsoft Graph", DOCS, ["id", "displayName", "passwordCredentials", "keyCredentials", "owners"]),
  restSurface("permission-grants", "/v1.0/oauth2PermissionGrants", "Microsoft Graph", DOCS, ["clientId", "consentType", "scope"]),
  restSurface("secure-scores", "/v1.0/security/secureScores", "Microsoft Graph", DOCS, ["currentScore", "maxScore"]),
  restSurface("directory-audits", "/v1.0/auditLogs/directoryAudits", "Microsoft Graph", DOCS, ["id", "activityDateTime", "activityDisplayName"]),
  restSurface("sign-ins", "/v1.0/auditLogs/signIns", "Microsoft Graph", DOCS, ["id", "createdDateTime", "status"]),
  restSurface("defender-pricings", "/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings", "Azure Resource Manager", ARM_DOCS, ["name", "properties.pricingTier"]),
  restSurface("diagnostic-settings", "/subscriptions/{subscriptionId}/providers/Microsoft.Insights/diagnosticSettings", "Azure Resource Manager", ARM_DOCS, ["properties.logs", "properties.workspaceId", "properties.storageAccountId", "properties.eventHubAuthorizationRuleId"]),
  restSurface("log-workspaces", "/subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/workspaces", "Azure Resource Manager", ARM_DOCS, ["id", "properties.retentionInDays"]),
  restSurface("role-assignments", "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments", "Azure Resource Manager", ARM_DOCS, ["id", "properties.roleDefinitionId", "properties.principalType"]),
  restSurface("role-definitions", "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions", "Azure Resource Manager", ARM_DOCS, ["id", "properties.roleName"]),
  restSurface("security-contacts", "/subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts", "Azure Resource Manager", ARM_DOCS, ["properties.emails"]),
  restSurface("network-watchers", "/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkWatchers", "Azure Resource Manager", ARM_DOCS, ["id", "name", "location"]),
  restSurface("compliance-policies", "/beta/deviceManagement/deviceCompliancePolicies", "Microsoft Graph", DOCS, ["id", "displayName"]),
  restSurface("managed-devices", "/v1.0/deviceManagement/managedDevices", "Microsoft Graph", DOCS, ["id", "deviceName", "complianceState"]),
  restSurface("sensitivity-labels", "/beta/security/informationProtection/sensitivityLabels", "Microsoft Graph", DOCS, ["id", "name", "isActive", "hasProtection"]),
  restSurface("key-vaults", "/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults", "Azure Resource Manager", ARM_DOCS, ["name", "properties.enableSoftDelete", "properties.enablePurgeProtection", "properties.enableRbacAuthorization", "properties.networkAcls"]),
  restSurface("storage-accounts", "/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts", "Azure Resource Manager", ARM_DOCS, ["name", "properties.supportsHttpsTrafficOnly", "properties.allowBlobPublicAccess", "properties.minimumTlsVersion", "properties.encryption.keySource"]),
  restSurface("member-users", "/v1.0/users?$filter=userType eq 'Member'", "Microsoft Graph", DOCS, ["id", "userPrincipalName", "accountEnabled"]),
  restSurface("message-rules", "/v1.0/users/{id}/mailFolders/inbox/messageRules", "Microsoft Graph", DOCS, ["id", "displayName", "isEnabled", "actions"]),
  restSurface("sharepoint-settings", "/v1.0/admin/sharepoint/settings", "Microsoft Graph", DOCS, ["sharingCapability", "sharingDomainRestrictionMode", "isResharingByExternalUsersEnabled"]),
  restSurface("network-security-groups", "/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups", "Azure Resource Manager", ARM_DOCS, ["id", "name", "properties.securityRules"]),
  restSurface("flow-logs", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/networkWatchers/{watcher}/flowLogs", "Azure Resource Manager", ARM_DOCS, ["name", "properties.enabled", "properties.targetResourceId", "properties.retentionPolicy"]),
  restSurface("policy-assignments", "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments", "Azure Resource Manager", ARM_DOCS, ["id", "properties.policyDefinitionId", "properties.enforcementMode"]),
  restSurface("policy-summary", "/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize", "Azure Resource Manager", ARM_DOCS, ["results.nonCompliantResources", "results.nonCompliantPolicies"], "POST"),
] as const;

type AzureRow = readonly [string, number, string, Batch2CheckRow["severity"], string[], Batch2CheckRow["emptyOutcome"]?];
const rows: readonly AzureRow[] = [
  ["AZURE-ID-01", 1, "Conditional Access MFA baseline", "high", ["conditional-access", "security-defaults"], "fail"],
  ["AZURE-ID-02", 4, "Legacy authentication blocking", "high", ["conditional-access", "security-defaults"], "fail"],
  ["AZURE-ID-03", 2, "MFA registration coverage", "high", ["registration-details"], "manual"],
  ["AZURE-ID-04", 5, "Privileged directory role sprawl", "high", ["directory-roles", "directory-role-members"], "manual"],
  ["AZURE-ID-05", 23, "Service principal credential hygiene", "medium", ["service-principals"], "manual"],
  ["AZURE-ID-06", 5, "Privileged Identity Management eligibility", "high", ["pim-eligibilities", "pim-assignments"], "manual"],
  ["AZURE-ID-07", 6, "Guest access restrictions", "medium", ["authorization-policy"], "manual"],
  ["AZURE-ID-08", 6, "Guest account hygiene", "medium", ["guest-users"], "pass"],
  ["AZURE-ID-09", 7, "Sign-in risk policy", "high", ["conditional-access", "subscribed-skus"], "fail"],
  ["AZURE-ID-10", 8, "User risk policy", "high", ["conditional-access", "subscribed-skus"], "fail"],
  ["AZURE-ID-11", 7, "Risky users and detections", "high", ["risky-users", "risk-detections"], "pass"],
  ["AZURE-ID-12", 22, "App registration credential and owner hygiene", "medium", ["applications"], "manual"],
  ["AZURE-ID-13", 22, "Tenant-wide delegated permission grants", "high", ["permission-grants"], "manual"],
  ["AZURE-MON-01", 3, "Secure Score posture", "medium", ["secure-scores"], "manual"],
  ["AZURE-MON-02", 19, "Directory audit visibility", "medium", ["directory-audits"], "warn"],
  ["AZURE-MON-03", 19, "Sign-in telemetry visibility", "medium", ["sign-ins"], "warn"],
  ["AZURE-MON-04", 16, "Defender for Cloud plan coverage", "high", ["defender-pricings"], "manual"],
  ["AZURE-MON-05", 15, "Subscription diagnostic settings", "high", ["diagnostic-settings"], "fail"],
  ["AZURE-MON-06", 19, "Activity log retention depth", "high", ["diagnostic-settings", "log-workspaces"], "fail"],
  ["AZURE-MON-07", 19, "Entra ID audit log export", "medium", [], "manual"],
  ["AZURE-SUB-01", 17, "Owner assignments at subscription scope", "high", ["role-assignments", "role-definitions"], "manual"],
  ["AZURE-SUB-02", 17, "Contributor assignments at subscription scope", "medium", ["role-assignments", "role-definitions"], "manual"],
  ["AZURE-SUB-03", 18, "Security contacts configured", "medium", ["security-contacts"], "fail"],
  ["AZURE-SUB-04", 24, "Network Watcher coverage", "medium", ["network-watchers"], "warn"],
  ["AZURE-SUB-05", 23, "Privileged service principals at subscription scope", "high", ["role-assignments", "role-definitions"], "manual"],
  ["AZURE-DP-01", 9, "Device compliance enforcement", "high", ["subscribed-skus", "compliance-policies", "managed-devices", "conditional-access"], "fail"],
  ["AZURE-DP-02", 10, "Data Loss Prevention policies", "medium", [], "manual"],
  ["AZURE-DP-03", 11, "Sensitivity labels published", "medium", ["sensitivity-labels"], "fail"],
  ["AZURE-DP-04", 13, "Key Vault protection settings", "high", ["key-vaults"], "manual"],
  ["AZURE-DP-05", 14, "Storage account transport and access settings", "high", ["storage-accounts"], "manual"],
  ["AZURE-DP-06", 20, "Inbox forwarding rules", "high", ["member-users", "message-rules"], "manual"],
  ["AZURE-DP-07", 20, "Mailbox-level forwarding and transport rules", "high", [], "manual"],
  ["AZURE-DP-08", 21, "SharePoint external sharing", "medium", ["sharepoint-settings"], "manual"],
  ["AZURE-NP-01", 12, "Unrestricted inbound admin ports", "critical", ["network-security-groups"], "manual"],
  ["AZURE-NP-02", 25, "Azure Policy assignments enforced", "medium", ["policy-assignments"], "fail"],
  ["AZURE-NP-03", 25, "Azure Policy compliance state", "medium", ["policy-summary"], "manual"],
  ["AZURE-NP-04", 24, "NSG flow logs enabled", "medium", ["network-security-groups", "network-watchers", "flow-logs"], "manual"],
] as const;

const owner = (id: string): string => id.startsWith("AZURE-ID-")
  ? "azure_assess_identity"
  : id.startsWith("AZURE-MON-")
    ? "azure_assess_monitoring"
    : id.startsWith("AZURE-SUB-")
      ? "azure_assess_subscription_guardrails"
      : id.startsWith("AZURE-DP-")
        ? "azure_assess_data_protection"
        : "azure_assess_network_and_policy";

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces, emptyOutcome]) => ({
  id,
  control,
  title,
  severity,
  owner: owner(id),
  surfaces: sourceSurfaces,
  manualOnly: sourceSurfaces.length === 0,
  emptyOutcome,
  decision: `Evaluate ${title} from the declared raw vendor fields and complete collector cardinalities: a proved violation takes precedence, unreadable or missing dependencies return manual, incomplete evidence or review predicates warn, and pass requires complete readable evidence with no violation.`,
})));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const AZURE_RUNTIME_BEHAVIOR = [
  "Microsoft Graph and Azure Resource Manager are collected independently; a token-request failure marks the dependent resource call not attempted.",
  "Certificate credentials, mailbox forwarding settings outside inbox rules, transport rules, and Entra diagnostic-export configuration are not implemented and remain explicit follow-ups.",
  "Every list verdict uses complete seen and total cardinalities; arrays retained in finding evidence are presentation samples only.",
] as const;

export const AZURE_SPEC = buildBatchIntegrationSpec({
  slug: "azure-sec-inspector",
  displayName: "Azure Security Inspector",
  vendor: "Microsoft",
  category: "cloud",
  summary: "Portable contract for the shipped Microsoft Entra ID, Microsoft Graph, and Azure Resource Manager security assessments.",
  sourceModule: "cli/extensions/grc-tools/azure.ts",
  baseServices: ["Microsoft Graph", "Azure Resource Manager", "Microsoft identity platform"],
  authentication: AZURE_AUTH_RESOLVER,
  permissions: [
    { id: "graph-read-permissions", kind: "oauth-scope", value: "Documented Microsoft Graph application read permissions named by each failed surface", unlocks: surfaces.filter((surface) => surface.service === "Microsoft Graph").map((surface) => surface.id) },
    { id: "azure-reader", kind: "role", value: "Reader plus Security Reader and Monitoring Reader where required", unlocks: surfaces.filter((surface) => surface.service === "Azure Resource Manager").map((surface) => surface.id) },
    { id: "entra-premium", kind: "license", value: "Entra ID P1/P2 or Governance for reports, risk, and PIM surfaces", unlocks: ["registration-details", "risky-users", "risk-detections", "pim-eligibilities", "pim-assignments"] },
  ],
  surfaces,
  checks,
  tools: {
    azure_check_access: [],
    azure_assess_identity: idsFor("azure_assess_identity"),
    azure_assess_monitoring: idsFor("azure_assess_monitoring"),
    azure_assess_subscription_guardrails: idsFor("azure_assess_subscription_guardrails"),
    azure_assess_data_protection: idsFor("azure_assess_data_protection"),
    azure_assess_network_and_policy: idsFor("azure_assess_network_and_policy"),
    azure_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces.filter((surface) => !["security-defaults", "authorization-policy", "sharepoint-settings", "policy-summary"].includes(surface.id)).map((surface) => surface.id),
    cursorFields: ["@odata.nextLink", "nextLink", "next_page_link", "totalCount"],
    pageSize: null,
    itemCap: null,
    pageCap: 100,
    totalSemantics: "Completion requires cursor exhaustion or reaching a declared total; a rejected next link, repeated cursor, empty page with a cursor, page cap, item cap, or missing total is partial.",
    stopConditions: ["Cursor exhausted", "Declared total reached", "Repeated cursor", "Empty page with cursor", "Cross-origin or user-information next link", "Page or item cap"],
  }],
  rateLimit: {
    documentedLimit: "Service and endpoint specific",
    retryHeaders: ["Retry-After", "x-ms-ratelimit-remaining-*"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and use bounded exponential retry; exhausted reads remain unreadable.",
  },
  runtimeBehavior: AZURE_RUNTIME_BEHAVIOR,
  knownGaps: ["Certificate authentication, managed identity, several mailbox and device surfaces, alternate reporters, and standalone binaries are not shipped."],
  sensitiveFields: ["client_secret", "graph_token", "management_token", "access_token", "authorization", "cookie"],
  credentialFormats: ["Microsoft OAuth bearer tokens", "OAuth client secrets", "Azure CLI token output"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "core_data/metadata.json", "core_data/access.json", "analysis/findings.json",
      "analysis/identity.json", "analysis/monitoring.json", "analysis/subscription-guardrails.json",
      "analysis/data-protection.json", "analysis/network-and-policy.json", "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md", "compliance/fedramp.md", "compliance/cmmc.md",
      "compliance/soc2.md", "compliance/cis_azure.md", "compliance/pci_dss.md",
      "compliance/disa_stig.md", "compliance/irap.md", "compliance/ismap.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new azure-audit-<UTC timestamp> directory and numeric suffix when either directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Azure audit directory.",
  }),
});
